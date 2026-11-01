using System.Collections.Generic;

namespace ClashVPN.Models
{
    // ─── 顶层配置 ───────────────────────────────────────────────
    public class ClashConfig
    {
        public string MixedPort { get; set; }
        public string SocksPort { get; set; }
        public string Port { get; set; }
        public bool AllowLan { get; set; }
        public string Mode { get; set; }           // rule / global / direct
        public string LogLevel { get; set; }

        public List<ProxyNode>   Proxies      { get; set; } = new List<ProxyNode>();
        public List<ProxyGroup>  ProxyGroups  { get; set; } = new List<ProxyGroup>();
        public List<RuleEntry>   Rules        { get; set; } = new List<RuleEntry>();
    }

    // ─── 代理节点 ───────────────────────────────────────────────
    public class ProxyNode
    {
        public string Name     { get; set; }
        public string Type     { get; set; }   // ss / vmess / trojan / socks5 / http
        public string Server   { get; set; }
        public int    Port     { get; set; }

        // Shadowsocks
        public string Password { get; set; }
        public string Cipher   { get; set; }   // aes-128-gcm / chacha20-ietf-poly1305 ...
        public bool   Udp      { get; set; }

        // VMess
        public string Uuid     { get; set; }
        public int    AlterId  { get; set; }
        public string Network  { get; set; }   // tcp / ws / grpc
        public TlsOptions Tls  { get; set; }
        public WsOptions  WsOpts { get; set; }

        // Trojan
        public bool   SkipCertVerify { get; set; }
        public string Sni    { get; set; }

        // SOCKS5 / HTTP
        public string Username { get; set; }

        public override string ToString() => $"[{Type}] {Name}  {Server}:{Port}";
    }

    public class TlsOptions
    {
        public bool   Enabled        { get; set; }
        public bool   SkipCertVerify { get; set; }
        public string ServerName     { get; set; }
    }

    public class WsOptions
    {
        public string Path    { get; set; }
        public Dictionary<string, string> Headers { get; set; }
    }

    // ─── 代理组 ───────────────────────────────────────────────
    public class ProxyGroup
    {
        public string       Name     { get; set; }
        public string       Type     { get; set; }   // select / url-test / fallback / load-balance
        public List<string> Proxies  { get; set; } = new List<string>();
        public string       Url      { get; set; }
        public int          Interval { get; set; }

        /// <summary>当前选中的代理名（仅 select 类型有效）</summary>
        public string Selected { get; set; }

        public override string ToString() => $"[{Type}] {Name}  ({Proxies.Count} nodes)";
    }

    // ─── 规则条目 ──────────────────────────────────────────────
    public class RuleEntry
    {
        public string RuleType { get; set; }   // DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / GEOIP / MATCH / FINAL
        public string Value    { get; set; }
        public string Target   { get; set; }   // 代理组或 DIRECT / REJECT

        public override string ToString() => $"{RuleType},{Value},{Target}";
    }

    // ─── 连接状态 ──────────────────────────────────────────────
    public enum VpnConnectionState
    {
        Disconnected,
        Connecting,
        Connected,
        Disconnecting,
        Error
    }

    public class VpnStatus
    {
        public VpnConnectionState State      { get; set; }
        public string             NodeName   { get; set; }
        public string             ErrorMsg   { get; set; }
        public long               BytesUp    { get; set; }
        public long               BytesDown  { get; set; }
    }
}
