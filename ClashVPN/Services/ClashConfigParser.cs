using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using ClashVPN.Models;
using YamlDotNet.RepresentationModel;

namespace ClashVPN.Services
{
    /// <summary>
    /// 解析 Clash 格式的 YAML 配置文件。
    /// 不依赖 YamlDotNet 的反序列化器（UWP ARM 兼容性更好），
    /// 改用 RepresentationModel 手动遍历节点。
    /// </summary>
    public static class ClashConfigParser
    {
        // ── 入口 ──────────────────────────────────────────────────────────

        public static async Task<ClashConfig> ParseFileAsync(Windows.Storage.StorageFile file)
        {
            string yaml = await Windows.Storage.FileIO.ReadTextAsync(file);
            return Parse(yaml);
        }

        public static ClashConfig Parse(string yaml)
        {
            var stream = new YamlStream();
            stream.Load(new StringReader(yaml));

            if (stream.Documents.Count == 0)
                throw new FormatException("Empty YAML document");

            var root = stream.Documents[0].RootNode as YamlMappingNode
                       ?? throw new FormatException("Root node is not a mapping");

            var config = new ClashConfig();

            foreach (var entry in root.Children)
            {
                string key = Str(entry.Key);
                var val = entry.Value;

                switch (key)
                {
                    case "mixed-port":   config.MixedPort = Str(val);  break;
                    case "socks-port":   config.SocksPort = Str(val);  break;
                    case "port":         config.Port      = Str(val);  break;
                    case "allow-lan":    config.AllowLan  = Bool(val); break;
                    case "mode":         config.Mode      = Str(val);  break;
                    case "log-level":    config.LogLevel  = Str(val);  break;

                    case "proxies":
                        config.Proxies = ParseProxies(val as YamlSequenceNode);
                        break;

                    case "proxy-groups":
                        config.ProxyGroups = ParseGroups(val as YamlSequenceNode);
                        break;

                    case "rules":
                        config.Rules = ParseRules(val as YamlSequenceNode);
                        break;
                }
            }

            // 为每个 select 组设置默认选中第一个
            foreach (var g in config.ProxyGroups)
                if (g.Type == "select" && g.Proxies.Count > 0)
                    g.Selected = g.Proxies[0];

            return config;
        }

        // ── Proxies ───────────────────────────────────────────────────────

        private static List<ProxyNode> ParseProxies(YamlSequenceNode seq)
        {
            var list = new List<ProxyNode>();
            if (seq == null) return list;

            foreach (var item in seq.Children)
            {
                if (!(item is YamlMappingNode map)) continue;
                var node = new ProxyNode
                {
                    Name   = MapStr(map, "name"),
                    Type   = MapStr(map, "type")?.ToLowerInvariant(),
                    Server = MapStr(map, "server"),
                    Port   = MapInt(map, "port"),
                };

                switch (node.Type)
                {
                    case "ss":
                        node.Password = MapStr(map, "password");
                        node.Cipher   = MapStr(map, "cipher");
                        node.Udp      = MapBool(map, "udp");
                        break;

                    case "vmess":
                        node.Uuid    = MapStr(map, "uuid");
                        node.AlterId = MapInt(map, "alterId");
                        node.Cipher  = MapStr(map, "cipher") ?? "auto";
                        node.Network = MapStr(map, "network") ?? "tcp";
                        // tls
                        if (MapBool(map, "tls"))
                            node.Tls = new TlsOptions
                            {
                                Enabled        = true,
                                SkipCertVerify = MapBool(map, "skip-cert-verify"),
                                // SNI 缺省时回退到 server（与 Surge 解析器一致）
                                ServerName     = MapStr(map, "servername") ?? node.Server,
                            };
                        // ws-opts
                        if (map.Children.ContainsKey("ws-opts"))
                        {
                            var wo = map.Children[new YamlScalarNode("ws-opts")] as YamlMappingNode;
                            if (wo != null)
                                node.WsOpts = new WsOptions
                                {
                                    Path = MapStr(wo, "path"),
                                };
                        }
                        break;

                    case "trojan":
                        node.Password       = MapStr(map, "password");
                        node.SkipCertVerify = MapBool(map, "skip-cert-verify");
                        // SNI 缺省时回退到 server（与 Surge 解析器一致）
                        node.Sni            = MapStr(map, "sni") ?? node.Server;
                        break;

                    case "socks5":
                        node.Username = MapStr(map, "username");
                        node.Password = MapStr(map, "password");
                        node.Udp      = MapBool(map, "udp");
                        break;

                    case "http":
                        node.Username = MapStr(map, "username");
                        node.Password = MapStr(map, "password");
                        break;
                }

                list.Add(node);
            }

            return list;
        }

        // ── Proxy Groups ──────────────────────────────────────────────────

        private static List<ProxyGroup> ParseGroups(YamlSequenceNode seq)
        {
            var list = new List<ProxyGroup>();
            if (seq == null) return list;

            foreach (var item in seq.Children)
            {
                if (!(item is YamlMappingNode map)) continue;
                var g = new ProxyGroup
                {
                    Name     = MapStr(map, "name"),
                    Type     = MapStr(map, "type")?.ToLowerInvariant(),
                    Url      = MapStr(map, "url"),
                    Interval = MapInt(map, "interval"),
                };

                if (map.Children.ContainsKey("proxies"))
                {
                    var seq2 = map.Children[new YamlScalarNode("proxies")] as YamlSequenceNode;
                    if (seq2 != null)
                        foreach (var p in seq2.Children)
                            g.Proxies.Add(Str(p));
                }

                list.Add(g);
            }

            return list;
        }

        // ── Rules ─────────────────────────────────────────────────────────

        private static List<RuleEntry> ParseRules(YamlSequenceNode seq)
        {
            var list = new List<RuleEntry>();
            if (seq == null) return list;

            foreach (var item in seq.Children)
            {
                string raw = Str(item);
                var parts  = raw.Split(',');

                if (parts.Length == 2)      // MATCH,DIRECT  /  FINAL,DIRECT
                    list.Add(new RuleEntry { RuleType = parts[0].Trim(), Value = "", Target = parts[1].Trim() });
                else if (parts.Length >= 3)
                    list.Add(new RuleEntry { RuleType = parts[0].Trim(), Value = parts[1].Trim(), Target = parts[2].Trim() });
            }

            return list;
        }

        // ── 规则匹配（运行时） ─────────────────────────────────────────────

        /// <summary>
        /// 给定一个域名/IP，按配置的 Rules 找到目标代理组名。
        /// 返回 "DIRECT" / "REJECT" 或某个代理组名。
        /// </summary>
        public static string MatchRule(ClashConfig config, string host)
        {
            // 模式优先：global 全部走代理，direct 全部直连，rule（默认）才按规则匹配。
            string mode = config.Mode?.Trim().ToLowerInvariant();
            if (mode == "direct")
                return "DIRECT";
            if (mode == "global")
                return config.ProxyGroups.Count > 0 ? config.ProxyGroups[0].Name : "DIRECT";

            bool isIp = IsIpAddress(host);

            foreach (var rule in config.Rules)
            {
                bool hit = false;
                switch (rule.RuleType.ToUpperInvariant())
                {
                    case "DOMAIN":
                        hit = string.Equals(host, rule.Value, StringComparison.OrdinalIgnoreCase);
                        break;
                    case "DOMAIN-SUFFIX":
                        hit = host.EndsWith(rule.Value, StringComparison.OrdinalIgnoreCase)
                           || string.Equals(host, rule.Value, StringComparison.OrdinalIgnoreCase);
                        break;
                    case "DOMAIN-KEYWORD":
                        hit = host.IndexOf(rule.Value, StringComparison.OrdinalIgnoreCase) >= 0;
                        break;
                    case "IP-CIDR":
                        hit = isIp && IpInCidr(host, rule.Value);
                        break;
                    case "GEOIP":
                        // GeoIP 需要离线数据库，暂时只处理 CN
                        // 留空，后续集成 MaxMind
                        break;
                    case "MATCH":
                    case "FINAL":
                        hit = true;
                        break;
                }

                if (hit) return rule.Target;
            }

            return "DIRECT";
        }

        // ── 工具方法 ──────────────────────────────────────────────────────

        private static string Str(YamlNode n)
            => (n as YamlScalarNode)?.Value ?? string.Empty;

        private static bool Bool(YamlNode n)
        {
            string s = Str(n).ToLowerInvariant();
            return s == "true" || s == "yes" || s == "1";
        }

        private static string MapStr(YamlMappingNode map, string key)
        {
            var k = new YamlScalarNode(key);
            return map.Children.ContainsKey(k) ? Str(map.Children[k]) : null;
        }

        private static int MapInt(YamlMappingNode map, string key)
        {
            string s = MapStr(map, key);
            return int.TryParse(s, out int v) ? v : 0;
        }

        private static bool MapBool(YamlMappingNode map, string key)
        {
            string s = MapStr(map, key)?.ToLowerInvariant();
            return s == "true" || s == "yes" || s == "1";
        }

        private static bool IsIpAddress(string host)
        {
            System.Net.IPAddress addr;
            return System.Net.IPAddress.TryParse(host, out addr);
        }

        private static bool IpInCidr(string ip, string cidr)
        {
            try
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2) return false;
                var network  = System.Net.IPAddress.Parse(parts[0]);
                int prefix   = int.Parse(parts[1]);
                var addr     = System.Net.IPAddress.Parse(ip);

                byte[] netBytes  = network.GetAddressBytes();
                byte[] addrBytes = addr.GetAddressBytes();
                if (netBytes.Length != addrBytes.Length) return false;

                int fullBytes = prefix / 8;
                int remBits   = prefix % 8;

                for (int i = 0; i < fullBytes; i++)
                    if (netBytes[i] != addrBytes[i]) return false;

                if (remBits > 0)
                {
                    int mask = 0xFF << (8 - remBits) & 0xFF;
                    if ((netBytes[fullBytes] & mask) != (addrBytes[fullBytes] & mask)) return false;
                }

                return true;
            }
            catch { return false; }
        }
    }
}
