using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using ClashVPN.Models;
using Windows.Storage;

namespace ClashVPN.Services
{
    /// <summary>
    /// 解析 Surge / Surfboard INI 风格的 .conf 配置文件。
    /// 输出统一的 ClashConfig 模型，与 ClashConfigParser 共享同一套数据结构。
    ///
    /// 支持的 Proxy 类型：
    ///   ss   → Shadowsocks（encrypt-method / password）
    ///   vmess（Surge 4 风格）
    ///   trojan
    ///   socks5 / socks5-tls
    ///   http / https
    /// </summary>
    public static class SurgeConfigParser
    {
        // ── 入口 ──────────────────────────────────────────────────────────

        public static async Task<ClashConfig> ParseFileAsync(StorageFile file)
        {
            string text = await FileIO.ReadTextAsync(file);
            return Parse(text);
        }

        public static ClashConfig Parse(string text)
        {
            // 统一换行，去掉 \r
            text = text.Replace("\r\n", "\n").Replace("\r", "\n");

            var sections = SplitSections(text);
            var config   = new ClashConfig { Mode = "rule" };

            // [General]
            if (sections.ContainsKey("General"))
                ParseGeneral(sections["General"], config);

            // [Proxy]
            if (sections.ContainsKey("Proxy"))
                config.Proxies = ParseProxies(sections["Proxy"]);

            // [Proxy Group]
            if (sections.ContainsKey("Proxy Group"))
                config.ProxyGroups = ParseGroups(sections["Proxy Group"]);

            // [Rule]
            if (sections.ContainsKey("Rule"))
                config.Rules = ParseRules(sections["Rule"]);

            // 为 select 组设置默认选中
            foreach (var g in config.ProxyGroups)
                if (g.Type == "select" && g.Proxies.Count > 0 && g.Selected == null)
                    g.Selected = g.Proxies[0];

            return config;
        }

        // ── 分段 ──────────────────────────────────────────────────────────

        private static Dictionary<string, List<string>> SplitSections(string text)
        {
            var result  = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            string current = null;

            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.Trim();

                // 跳过空行和注释
                if (string.IsNullOrEmpty(line) || line.StartsWith("#") || line.StartsWith("//"))
                    continue;

                // 跳过 !MANAGED-CONFIG 头
                if (line.StartsWith("#!")) continue;

                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    current = line.Substring(1, line.Length - 2).Trim();
                    if (!result.ContainsKey(current))
                        result[current] = new List<string>();
                }
                else if (current != null)
                {
                    result[current].Add(line);
                }
            }

            return result;
        }

        // ── [General] ─────────────────────────────────────────────────────

        private static void ParseGeneral(List<string> lines, ClashConfig config)
        {
            foreach (string line in lines)
            {
                var kv = SplitKv(line);
                if (kv == null) continue;
                switch (kv.Item1.ToLowerInvariant())
                {
                    case "loglevel":   config.LogLevel  = kv.Item2; break;
                    case "allow-wifi-access":
                    case "allow-lan":  config.AllowLan  = kv.Item2.ToLower() == "true"; break;
                    case "mixed-port": config.MixedPort = kv.Item2; break;
                    case "socks-port": config.SocksPort = kv.Item2; break;
                    case "port":       config.Port      = kv.Item2; break;
                }
            }
        }

        // ── [Proxy] ───────────────────────────────────────────────────────

        /// <summary>
        /// Surge 代理行格式：
        ///   节点名 = 协议, 服务器, 端口[, key=value, ...]
        ///
        /// 示例：
        ///   香港 | 01 = ss, mm.good2026.com, 12911, encrypt-method=aes-128-gcm, password=xxx, tfo=true, udp-relay=true
        ///   美国 01   = vmess, 1.2.3.4, 443, username=uuid, tls=true, ws=true, ws-path=/ray
        /// </summary>
        private static List<ProxyNode> ParseProxies(List<string> lines)
        {
            var list = new List<ProxyNode>();

            foreach (string line in lines)
            {
                // 名称 = 剩余部分
                int eq = line.IndexOf('=');
                if (eq < 0) continue;

                string name    = line.Substring(0, eq).Trim();
                string rest    = line.Substring(eq + 1).Trim();
                var    parts   = SplitCommaRespectingQuotes(rest);

                if (parts.Count < 3) continue;

                string proto  = parts[0].Trim().ToLowerInvariant();
                string server = parts[1].Trim();
                string portStr= parts[2].Trim();

                if (!int.TryParse(portStr, out int port)) continue;

                // 解析剩余的 key=value 参数
                var opts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                for (int i = 3; i < parts.Count; i++)
                {
                    var kv = SplitKv(parts[i].Trim());
                    if (kv != null) opts[kv.Item1] = kv.Item2;
                }

                var node = new ProxyNode
                {
                    Name   = name,
                    Server = server,
                    Port   = port,
                };

                switch (proto)
                {
                    case "ss":
                    case "shadowsocks":
                        node.Type     = "ss";
                        node.Cipher   = opts.GetOr("encrypt-method", opts.GetOr("method", "aes-128-gcm"));
                        node.Password = opts.GetOr("password", "");
                        node.Udp      = opts.GetOr("udp-relay", "false").ToLower() == "true";
                        break;

                    case "vmess":
                        node.Type    = "vmess";
                        node.Uuid    = opts.GetOr("username", opts.GetOr("uuid", ""));
                        node.Cipher  = opts.GetOr("cipher", "auto");
                        node.Network = opts.GetOr("ws",  "false") == "true" ? "ws" : "tcp";
                        bool vmessTls = opts.GetOr("tls", "false").ToLower() == "true";
                        if (vmessTls)
                            node.Tls = new TlsOptions
                            {
                                Enabled        = true,
                                SkipCertVerify = opts.GetOr("skip-cert-verify", "false").ToLower() == "true",
                                ServerName     = opts.GetOr("sni", server),
                            };
                        if (node.Network == "ws")
                            node.WsOpts = new WsOptions { Path = opts.GetOr("ws-path", "/") };
                        break;

                    case "trojan":
                        node.Type           = "trojan";
                        node.Password       = opts.GetOr("password", "");
                        node.SkipCertVerify = opts.GetOr("skip-cert-verify", "false").ToLower() == "true";
                        node.Sni            = opts.GetOr("sni", server);
                        break;

                    case "socks5":
                    case "socks5-tls":
                        node.Type     = "socks5";
                        node.Username = opts.GetOr("username", "");
                        node.Password = opts.GetOr("password", "");
                        node.Udp      = opts.GetOr("udp-relay", "false").ToLower() == "true";
                        break;

                    case "http":
                    case "https":
                        node.Type     = "http";
                        node.Username = opts.GetOr("username", "");
                        node.Password = opts.GetOr("password", "");
                        break;

                    default:
                        // 未知协议，跳过
                        continue;
                }

                list.Add(node);
            }

            return list;
        }

        // ── [Proxy Group] ─────────────────────────────────────────────────

        /// <summary>
        /// Surge 代理组格式：
        ///   组名 = 类型, 节点1, 节点2, ...[, url=xxx, interval=xxx]
        ///
        /// 类型：select / url-test / fallback / load-balance / ssid
        /// </summary>
        private static List<ProxyGroup> ParseGroups(List<string> lines)
        {
            var list = new List<ProxyGroup>();

            foreach (string line in lines)
            {
                int eq = line.IndexOf('=');
                if (eq < 0) continue;

                string name  = line.Substring(0, eq).Trim();
                string rest  = line.Substring(eq + 1).Trim();
                var    parts = SplitCommaRespectingQuotes(rest);

                if (parts.Count < 1) continue;

                string type = parts[0].Trim().ToLowerInvariant();

                var group = new ProxyGroup
                {
                    Name = name,
                    Type = type,
                };

                for (int i = 1; i < parts.Count; i++)
                {
                    string item = parts[i].Trim();
                    if (item.StartsWith("url=", StringComparison.OrdinalIgnoreCase))
                        group.Url = item.Substring(4);
                    else if (item.StartsWith("interval=", StringComparison.OrdinalIgnoreCase))
                    {
                        if (int.TryParse(item.Substring(9), out int intv))
                            group.Interval = intv;
                    }
                    else if (!string.IsNullOrEmpty(item))
                        group.Proxies.Add(item);
                }

                if (group.Proxies.Count > 0)
                    group.Selected = group.Proxies[0];

                list.Add(group);
            }

            return list;
        }

        // ── [Rule] ────────────────────────────────────────────────────────

        /// <summary>
        /// Surge 规则格式：
        ///   RULE-TYPE,VALUE,POLICY[,no-resolve]
        ///
        /// 差异处理：
        ///   - USER-AGENT → 暂时跳过（VPN 层无法拦截）
        ///   - REJECT-TINYGIF / REJECT-DROP → 统一映射为 REJECT
        ///   - IP-CIDR6 → 保留（目前解析器不处理 IPv6，但存入模型）
        ///   - FINAL → 兼容（等同 MATCH）
        /// </summary>
        private static List<RuleEntry> ParseRules(List<string> lines)
        {
            var list = new List<RuleEntry>();

            foreach (string line in lines)
            {
                if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line)) continue;

                var parts = line.Split(',');
                if (parts.Length < 2) continue;

                string ruleType = parts[0].Trim().ToUpperInvariant();
                string value    = parts.Length > 1 ? parts[1].Trim() : "";
                string target   = parts.Length > 2 ? parts[2].Trim() : "";

                // 跳过 USER-AGENT（应用层规则，VPN 插件无法处理）
                if (ruleType == "USER-AGENT") continue;

                // REJECT-TINYGIF / REJECT-DROP → REJECT
                target = target.Replace("-TINYGIF", "").Replace("-DROP", "");

                // FINAL 只有一个参数（有时候 FINAL,Proxy 没有第三段）
                if (ruleType == "FINAL" || ruleType == "MATCH")
                {
                    list.Add(new RuleEntry { RuleType = "MATCH", Value = "", Target = value });
                    continue;
                }

                if (string.IsNullOrEmpty(target)) continue;

                list.Add(new RuleEntry
                {
                    RuleType = ruleType,
                    Value    = value,
                    Target   = target,
                });
            }

            return list;
        }

        // ── 工具方法 ──────────────────────────────────────────────────────

        /// <summary>"key = value" → Tuple(key, value)，处理等号两侧空格</summary>
        private static Tuple<string, string> SplitKv(string s)
        {
            int idx = s.IndexOf('=');
            if (idx < 0) return null;
            return Tuple.Create(
                s.Substring(0, idx).Trim(),
                s.Substring(idx + 1).Trim().Trim('"'));
        }

        /// <summary>
        /// 按逗号分割，但不分割引号内部的逗号。
        /// 例：a, b="x,y", c  →  ["a", "b=\"x,y\"", "c"]
        /// </summary>
        private static List<string> SplitCommaRespectingQuotes(string s)
        {
            var    result  = new List<string>();
            var    current = new System.Text.StringBuilder();
            bool   inQuote = false;

            foreach (char c in s)
            {
                if (c == '"') { inQuote = !inQuote; current.Append(c); }
                else if (c == ',' && !inQuote)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
                else current.Append(c);
            }

            if (current.Length > 0) result.Add(current.ToString());
            return result;
        }
    }

    // ── Dictionary 扩展 ───────────────────────────────────────────────────
    internal static class DictExtensions
    {
        public static string GetOr(this Dictionary<string, string> d, string key, string fallback)
            => d.ContainsKey(key) ? d[key] : fallback;
    }
}
