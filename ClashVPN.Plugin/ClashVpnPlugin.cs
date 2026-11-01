using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;

namespace ClashVPN.Plugin
{
    /// <summary>
    /// UWP VPN 插件主体。必须在 Windows Runtime Component 项目中，
    /// 并在 Package.appxmanifest 中声明 Extension Category="windows.vpnPlugin"。
    ///
    /// 工作原理：
    ///   系统把所有 IP 流量交给 OnVpnConnected，插件将 TCP 流量
    ///   经由 SOCKS5 代理转发；本地 DNS 请求直接通过 VpnChannel 的
    ///   namespace 管理功能拦截。
    /// </summary>
    public sealed class ClashVpnPlugin : IVpnPlugIn
    {
        // 节点信息由主 App 通过 ApplicationData 传入
        private string  _proxyHost;
        private int     _proxyPort;
        private string  _proxyUser;
        private string  _proxyPass;
        private string  _proxyType;     // ss / socks5 / http
        private string  _ssCipher;      // aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305

        private VpnChannel    _channel;
        private CancellationTokenSource _cts;
        private TcpSessionTracker _tracker;

        // 流量统计（累计字节数），定期写入 LocalSettings 供主 App 读取。
        private long _bytesUp;
        private long _bytesDown;
        private DateTime _lastStatsFlush = DateTime.MinValue;

        // ── IVpnPlugin 接口 ───────────────────────────────────────────────

        public void Connect(VpnChannel channel)
        {
            _channel = channel;
            _cts     = new CancellationTokenSource();

            try
            {
                LoadSettings();

                // 出站转发用的会话追踪器（按节点配置选择 SS / SOCKS5 等代理客户端）
                _tracker = new TcpSessionTracker(
                    _proxyHost, _proxyPort, _proxyType,
                    _proxyUser, _proxyPass, _ssCipher);

                // 重置本次会话的流量计数
                _bytesUp = 0;
                _bytesDown = 0;
                _lastStatsFlush = DateTime.MinValue;
                FlushTrafficStats();

                // 1. 告诉系统 VPN 的虚拟 IP 地址（随便分配一个不冲突的）
                var assignedAddr = new VpnRouteAssignment();
                assignedAddr.ExcludeLocalSubnets = true;

                var ipv4 = new VpnRoute(new HostName("0.0.0.0"), 0);   // 默认路由全部走 VPN
                assignedAddr.Ipv4InclusionRoutes.Add(ipv4);

                // 注意：当前未配置自定义 DNS 服务器。原先这里构造了一个 dnsServers
                // 列表但从未传给 StartWithMainTransport（死代码），已移除以免误导。
                // 若需 DNS 拦截，应通过 VpnDomainNameAssignment / namespace 策略接入。

                // 2. 建立主传输通道（到 SOCKS5 服务器的 TCP 连接）
                // 注意：不能用 .Wait()，否则会包成 AggregateException 且更易在
                // 受限的 VPN worker 线程上死锁；用 GetAwaiter().GetResult() 直接传播原始异常。
                var transport = new StreamSocket();
                transport.ConnectAsync(new HostName(_proxyHost), _proxyPort.ToString())
                         .AsTask().GetAwaiter().GetResult();

                channel.StartWithMainTransport(
                    new[] { new HostName("10.8.0.2") },     // 虚拟 IP
                    null,                                    // 虚拟 IPv6
                    null,                                    // 自定义 DNS 后缀
                    assignedAddr,
                    null,                                    // namespace 策略
                    1500,                                    // MTU
                    1500,
                    false,
                    transport
                );

                // 出站包由系统通过 Encapsulate 回调送入并转发；
                // 不再使用手动 poll 循环（旧 PacketLoopAsync 误用了 VpnChannel API）。
            }
            catch (Exception ex)
            {
                channel.TerminateConnection("Connect failed: " + ex.Message);
            }
        }

        public void Disconnect(VpnChannel channel)
        {
            _cts?.Cancel();
            channel.Stop();
        }

        public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
        {
            // 不需要保活包
            keepAlivePacket = null;
        }

        public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapulatedPackets)
        {
            // 出站 IP 包入口：解析 TCP 包并经代理转发（tun2socks 数据通路的发送侧）。
            // ⚠ 回程注入（把代理读到的数据封成 IP 包还给系统协议栈）尚未接通——
            //   见 TcpSessionTracker / BuildTcpPacket，属下一里程碑。
            //   当前版本可安装、可起 UI / 导入配置 / 延迟测试 / 注册并连接 VPN 配置，
            //   但全局透明转发尚不完整。
            while (packets.Size > 0)
            {
                var pkt = packets.RemoveAtBegin();
                byte[] raw = ReadBuffer(pkt.Buffer);

                var parsed = IpPacketParser.Parse(raw);
                if (parsed != null && parsed.Protocol == 6 /* TCP */)
                {
                    _bytesUp += raw.Length;
                    _ = _tracker?.ForwardAsync(parsed, raw);
                }
            }
            FlushTrafficStats();
        }

        public void Decapsulate(VpnChannel channel, VpnPacketBuffer encapBuffer,
                                VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend)
        {
            // 同样透传
            decapsulatedPackets.Append(encapBuffer);
        }

        // ── 流量统计 ──────────────────────────────────────────────────────

        /// <summary>
        /// 把累计流量写入 LocalSettings（节流：最多每秒一次），主 App 定时读取。
        /// </summary>
        private void FlushTrafficStats()
        {
            var now = DateTime.UtcNow;
            if ((now - _lastStatsFlush).TotalMilliseconds < 1000) return;
            _lastStatsFlush = now;

            try
            {
                var settings = Windows.Storage.ApplicationData.Current.LocalSettings.Values;
                settings["bytes_up"]   = _bytesUp;
                settings["bytes_down"] = _bytesDown;
            }
            catch { /* 写入失败不应影响数据转发 */ }
        }

        // ── 读取设置 ──────────────────────────────────────────────────────

        private void LoadSettings()
        {
            var settings = Windows.Storage.ApplicationData.Current.LocalSettings.Values;

            // ApplicationData 以 boxed object 往返；用安全转换避免 InvalidCastException
            // 在 VPN worker 线程上终止连接。
            _proxyHost = GetString(settings, "proxy_host",   "127.0.0.1");
            _proxyPort = GetInt   (settings, "proxy_port",   1080);
            // 凭据由主 App 以 DPAPI 加密写入，这里解密还原（兼容旧明文）。
            // 空串还原为 null，保持与旧行为一致（无认证场景）。
            _proxyUser = NullIfEmpty(SecretStore.Unprotect(GetString(settings, "proxy_user", null)));
            _proxyPass = NullIfEmpty(SecretStore.Unprotect(GetString(settings, "proxy_pass", null)));
            _proxyType = GetString(settings, "proxy_type",   "socks5");
            _ssCipher  = GetString(settings, "proxy_cipher", "aes-128-gcm");
        }

        private static string GetString(
            Windows.Foundation.Collections.IPropertySet settings, string key, string fallback)
        {
            return settings.ContainsKey(key) && settings[key] is string s ? s : fallback;
        }

        private static int GetInt(
            Windows.Foundation.Collections.IPropertySet settings, string key, int fallback)
        {
            if (!settings.ContainsKey(key)) return fallback;
            try { return Convert.ToInt32(settings[key]); }
            catch { return fallback; }
        }

        private static string NullIfEmpty(string s)
            => string.IsNullOrEmpty(s) ? null : s;

        // ── 工具 ──────────────────────────────────────────────────────────

        private static byte[] ReadBuffer(IBuffer buf)
        {
            var arr = new byte[buf.Length];
            Windows.Storage.Streams.DataReader.FromBuffer(buf).ReadBytes(arr);
            return arr;
        }
    }
}
