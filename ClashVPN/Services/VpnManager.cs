using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using ClashVPN.Models;
using Windows.Networking.Vpn;
using Windows.Storage;

namespace ClashVPN.Services
{
    /// <summary>
    /// 管理 VPN 配置文件注册、连接、断开，以及节点选择逻辑。
    /// </summary>
    public class VpnManager
    {
        private const string ProfileName = "ClashVPN";
        private readonly VpnManagementAgent _agent = new VpnManagementAgent();

        // ── 连接 / 断开 ────────────────────────────────────────────────────

        /// <summary>当前 VPN 插件实际支持的协议类型。</summary>
        private static readonly System.Collections.Generic.HashSet<string> SupportedTypes =
            new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "ss", "shadowsocks", "socks5" };

        /// <summary>判断给定节点协议是否被当前插件支持。</summary>
        public static bool IsNodeSupported(ProxyNode node)
            => node != null && node.Type != null && SupportedTypes.Contains(node.Type);

        public async Task<bool> ConnectAsync(ProxyNode node)
        {
            // 协议未实现时给出明确错误，避免在插件内静默退化为 SOCKS5 后才失败。
            if (!IsNodeSupported(node))
                throw new NotSupportedException(
                    $"暂不支持的协议类型：{node?.Type ?? "未知"}（目前仅支持 SS / SOCKS5）");

            // 把节点信息写入 LocalSettings，让 Plugin 读取
            await SaveNodeToSettingsAsync(node);

            // 确保 VPN 配置文件存在
            await EnsureProfileAsync();

            var profiles = await _agent.GetProfilesAsync();
            VpnPlugInProfile target = null;
            foreach (var p in profiles)
            {
                var plug = p as VpnPlugInProfile;
                if (plug != null && plug.ProfileName == ProfileName)
                {
                    target = plug;
                    break;
                }
            }

            if (target == null)
                throw new Exception("VPN profile not found after creation");

            var status = await _agent.ConnectProfileAsync(target);
            return status == VpnManagementErrorStatus.Ok;
        }

        /// <summary>
        /// 查询本应用 VPN 配置当前是否处于已连接状态，用于在页面导航/重启后同步 UI。
        /// </summary>
        public async Task<bool> IsConnectedAsync()
        {
            try
            {
                var profiles = await _agent.GetProfilesAsync();
                foreach (var p in profiles)
                {
                    var plug = p as VpnPlugInProfile;
                    if (plug != null && plug.ProfileName == ProfileName)
                        return plug.ConnectionStatus == VpnManagementConnectionStatus.Connected;
                }
            }
            catch { /* 状态不可用时按未连接处理 */ }
            return false;
        }

        public async Task<bool> DisconnectAsync()
        {
            var profiles = await _agent.GetProfilesAsync();
            foreach (var p in profiles)
            {
                var plug = p as VpnPlugInProfile;
                if (plug != null && plug.ProfileName == ProfileName)
                {
                    var status = await _agent.DisconnectProfileAsync(plug);
                    return status == VpnManagementErrorStatus.Ok;
                }
            }
            return false;
        }

        // ── 节点选择逻辑 ───────────────────────────────────────────────────

        /// <summary>
        /// 从配置中解析出指定代理组的实际节点列表（展开嵌套组）。
        /// </summary>
        public List<ProxyNode> ResolveGroupNodes(ClashConfig config, string groupName)
        {
            var result = new List<ProxyNode>();

            ProxyGroup group = null;
            foreach (var g in config.ProxyGroups)
                if (g.Name == groupName) { group = g; break; }

            if (group == null) return result;

            foreach (var name in group.Proxies)
            {
                if (name == "DIRECT" || name == "REJECT") continue;

                // 先找 proxies
                ProxyNode node = null;
                foreach (var n in config.Proxies)
                    if (n.Name == name) { node = n; break; }

                if (node != null)
                {
                    result.Add(node);
                    continue;
                }

                // 递归展开子组
                var sub = ResolveGroupNodes(config, name);
                result.AddRange(sub);
            }

            return result;
        }

        /// <summary>
        /// 对节点列表做延迟测试，返回按延迟排序的结果。
        /// </summary>
        public async Task<List<(ProxyNode Node, int Ms)>> TestLatencyAsync(
            IEnumerable<ProxyNode> nodes, int timeoutMs = 3000)
        {
            var tasks = new List<Task<(ProxyNode, int)>>();

            foreach (var node in nodes)
            {
                tasks.Add(Task.Run(async () =>
                {
                    int ms = await PingNodeAsync(node, timeoutMs);
                    return (node, ms);
                }));
            }

            var results = await Task.WhenAll(tasks);
            var list    = new List<(ProxyNode, int)>(results);
            list.Sort((a, b) => a.Item2.CompareTo(b.Item2));
            return list;
        }

        private async Task<int> PingNodeAsync(ProxyNode node, int timeoutMs)
        {
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                using (var socket = new Windows.Networking.Sockets.StreamSocket())
                {
                    var cts = new System.Threading.CancellationTokenSource(timeoutMs);

                    await socket.ConnectAsync(
                        new Windows.Networking.HostName(node.Server),
                        node.Port.ToString())
                        .AsTask(cts.Token);

                    sw.Stop();
                    return (int)sw.ElapsedMilliseconds;
                }
            }
            catch { return int.MaxValue; }
        }

        // ── VPN Profile 管理 ───────────────────────────────────────────────

        private async Task EnsureProfileAsync()
        {
            var profiles = await _agent.GetProfilesAsync();
            foreach (var p in profiles)
            {
                var plug = p as VpnPlugInProfile;
                if (plug?.ProfileName == ProfileName) return;
            }

            // 新建配置文件
            var profile = new VpnPlugInProfile
            {
                ProfileName   = ProfileName,
                // PluginPackageFamilyName 必须指向"声明 windows.vpnPlugin 扩展的包"。
                // 本解决方案中插件（ClashVPN.Plugin）作为 WinRT 组件被打进同一个 App 包，
                // 且扩展点在 App 的 Package.appxmanifest 中声明，因此就是当前包的 PFN。
                // 若将来把插件拆成独立包，需改为该独立包的 PFN。
                VpnPluginPackageFamilyName = GetCurrentPackageFamilyName(),
                RequireVpnClientAppUI   = false,
            };

            var status = await _agent.AddProfileFromObjectAsync(profile);
            if (status != VpnManagementErrorStatus.Ok)
                throw new Exception($"Failed to register VPN profile: {status}");
        }

        private static string GetCurrentPackageFamilyName()
        {
            return Windows.ApplicationModel.Package.Current.Id.FamilyName;
        }

        // ── 持久化节点设置 ─────────────────────────────────────────────────

        private static async Task SaveNodeToSettingsAsync(ProxyNode node)
        {
            var s = ApplicationData.Current.LocalSettings.Values;
            s["proxy_host"]   = node.Server;
            s["proxy_port"]   = node.Port;
            // 凭据（用户名 / 密码）使用 DPAPI（LOCAL=user）加密后再落盘，
            // 避免在 LocalSettings 中以明文持久化。
            s["proxy_user"]   = await SecretStore.ProtectAsync(node.Username ?? string.Empty);
            s["proxy_pass"]   = await SecretStore.ProtectAsync(node.Password ?? string.Empty);
            s["proxy_type"]   = node.Type     ?? "socks5";
            s["proxy_name"]   = node.Name     ?? string.Empty;
            s["proxy_cipher"] = node.Cipher   ?? "aes-128-gcm";
        }

        public static (string Host, int Port, string Type, string Name) LoadCurrentNode()
        {
            var s = ApplicationData.Current.LocalSettings.Values;
            return (
                s.ContainsKey("proxy_host") && s["proxy_host"] is string h ? h : "",
                s.ContainsKey("proxy_port") ? SafeToInt(s["proxy_port"])   : 0,
                s.ContainsKey("proxy_type") && s["proxy_type"] is string t ? t : "",
                s.ContainsKey("proxy_name") && s["proxy_name"] is string n ? n : ""
            );
        }

        private static int SafeToInt(object value)
        {
            try { return Convert.ToInt32(value); }
            catch { return 0; }
        }
    }
}
