using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace ClashVPN.Plugin
{
    // ── IP 包解析 ─────────────────────────────────────────────────────────

    internal sealed class ParsedPacket
    {
        public byte   Version    { get; set; }   // 4 or 6
        public byte   Protocol   { get; set; }   // 6=TCP 17=UDP
        public string SrcIp      { get; set; }
        public string DstIp      { get; set; }
        public int    SrcPort    { get; set; }
        public int    DstPort    { get; set; }
        public byte[] Payload    { get; set; }   // TCP/UDP payload
        public byte[] RawPacket  { get; set; }
    }

    internal static class IpPacketParser
    {
        public static ParsedPacket Parse(byte[] raw)
        {
            if (raw == null || raw.Length < 20) return null;

            byte ver = (byte)(raw[0] >> 4);
            if (ver != 4) return null;   // 暂只处理 IPv4

            int  ihl      = (raw[0] & 0x0F) * 4;
            byte protocol = raw[9];
            string src = $"{raw[12]}.{raw[13]}.{raw[14]}.{raw[15]}";
            string dst = $"{raw[16]}.{raw[17]}.{raw[18]}.{raw[19]}";

            int srcPort = 0, dstPort = 0;
            byte[] payload = null;

            if (protocol == 6 && raw.Length >= ihl + 4)  // TCP
            {
                srcPort = (raw[ihl] << 8) | raw[ihl + 1];
                dstPort = (raw[ihl + 2] << 8) | raw[ihl + 3];
                int dataOffset = ((raw[ihl + 12] >> 4) & 0xF) * 4;
                int payStart   = ihl + dataOffset;
                if (raw.Length > payStart)
                {
                    payload = new byte[raw.Length - payStart];
                    Array.Copy(raw, payStart, payload, 0, payload.Length);
                }
                else payload = Array.Empty<byte>();
            }

            return new ParsedPacket
            {
                Version   = ver,
                Protocol  = protocol,
                SrcIp     = src,
                DstIp     = dst,
                SrcPort   = srcPort,
                DstPort   = dstPort,
                Payload   = payload,
                RawPacket = raw,
            };
        }

        /// <summary>
        /// 构造一个伪造的 TCP ACK IP 包，用于把数据注回给系统协议栈。
        /// 实际生产中需要精确的 SEQ/ACK 管理，这里给出框架。
        /// </summary>
        public static byte[] BuildTcpPacket(
            string srcIp, int srcPort,
            string dstIp, int dstPort,
            uint seqNum, uint ackNum,
            byte flags, byte[] data)
        {
            byte[] srcAddr = ToBytes(srcIp);
            byte[] dstAddr = ToBytes(dstIp);

            int totalLen = 20 + 20 + (data?.Length ?? 0);   // IP hdr + TCP hdr + data
            byte[] pkt   = new byte[totalLen];

            // IPv4 header
            pkt[0] = 0x45;                          // Ver=4, IHL=5
            pkt[1] = 0x00;                          // DSCP
            pkt[2] = (byte)(totalLen >> 8);
            pkt[3] = (byte)(totalLen & 0xFF);
            pkt[4] = 0; pkt[5] = 0;                 // ID
            pkt[6] = 0x40; pkt[7] = 0;              // DF flag
            pkt[8]  = 64;                            // TTL
            pkt[9]  = 6;                             // Protocol TCP
            // checksum at [10-11] - fill later
            srcAddr.CopyTo(pkt, 12);
            dstAddr.CopyTo(pkt, 16);
            FillIpChecksum(pkt);

            // TCP header
            pkt[20] = (byte)(srcPort >> 8); pkt[21] = (byte)(srcPort & 0xFF);
            pkt[22] = (byte)(dstPort >> 8); pkt[23] = (byte)(dstPort & 0xFF);
            pkt[24] = (byte)(seqNum >> 24); pkt[25] = (byte)(seqNum >> 16);
            pkt[26] = (byte)(seqNum >>  8); pkt[27] = (byte)(seqNum & 0xFF);
            pkt[28] = (byte)(ackNum >> 24); pkt[29] = (byte)(ackNum >> 16);
            pkt[30] = (byte)(ackNum >>  8); pkt[31] = (byte)(ackNum & 0xFF);
            pkt[32] = 0x50;                          // Data offset = 5 (20 bytes)
            pkt[33] = flags;
            pkt[34] = 0xFF; pkt[35] = 0xFF;         // Window
            // TCP checksum at [36-37]
            if (data != null && data.Length > 0)
                Array.Copy(data, 0, pkt, 40, data.Length);

            FillTcpChecksum(pkt, srcAddr, dstAddr);
            return pkt;
        }

        private static byte[] ToBytes(string ip)
        {
            var parts = ip.Split('.');
            return new byte[] {
                byte.Parse(parts[0]), byte.Parse(parts[1]),
                byte.Parse(parts[2]), byte.Parse(parts[3])
            };
        }

        private static void FillIpChecksum(byte[] pkt)
        {
            pkt[10] = pkt[11] = 0;
            ushort cs = Checksum(pkt, 0, 20);
            pkt[10] = (byte)(cs >> 8);
            pkt[11] = (byte)(cs & 0xFF);
        }

        private static void FillTcpChecksum(byte[] pkt, byte[] src, byte[] dst)
        {
            int tcpLen = pkt.Length - 20;
            pkt[36] = pkt[37] = 0;

            // Pseudo header: src dst 0x00 proto tcpLen
            var pseudo = new byte[12 + tcpLen];
            src.CopyTo(pseudo, 0);
            dst.CopyTo(pseudo, 4);
            pseudo[8] = 0; pseudo[9] = 6;
            pseudo[10] = (byte)(tcpLen >> 8);
            pseudo[11] = (byte)(tcpLen & 0xFF);
            Array.Copy(pkt, 20, pseudo, 12, tcpLen);

            ushort cs = Checksum(pseudo, 0, pseudo.Length);
            pkt[36] = (byte)(cs >> 8);
            pkt[37] = (byte)(cs & 0xFF);
        }

        private static ushort Checksum(byte[] buf, int offset, int length)
        {
            uint sum = 0;
            for (int i = offset; i < offset + length - 1; i += 2)
                sum += (uint)((buf[i] << 8) | buf[i + 1]);
            if (length % 2 != 0) sum += (uint)(buf[offset + length - 1] << 8);
            while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        public static readonly byte[] Empty = Array.Empty<byte>();
    }

    // ── TCP 会话追踪器 ────────────────────────────────────────────────────

    /// <summary>
    /// 维护一张"本地五元组 -> SOCKS5 连接"的映射表。
    /// 每当看到新的 TCP SYN，就建立一个到代理的 SOCKS5 连接；
    /// 后续该连接的数据直接转发。
    /// </summary>
    internal sealed class TcpSessionTracker
    {
        // 节点配置（由 ClashVpnPlugin 通过 LocalSettings 传入）
        private readonly string _proxyHost;
        private readonly int    _proxyPort;
        private readonly string _proxyType;     // ss / socks5 / http
        private readonly string _proxyUser;     // socks5 用户名 / ss 密码
        private readonly string _proxyPass;     // socks5 密码
        private readonly string _ssCipher;      // ss 加密方法

        // key: "srcIp:srcPort->dstIp:dstPort"
        private readonly ConcurrentDictionary<string, TcpSession> _sessions
            = new ConcurrentDictionary<string, TcpSession>();

        private readonly ConcurrentQueue<byte[]> _incomingQueue = new ConcurrentQueue<byte[]>();
        private readonly SemaphoreSlim _incomingSem = new SemaphoreSlim(0, int.MaxValue);

        public TcpSessionTracker(
            string proxyHost, int proxyPort,
            string proxyType,
            string user, string pass,
            string ssCipher = "aes-128-gcm")
        {
            _proxyHost = proxyHost;
            _proxyPort = proxyPort;
            _proxyType = (proxyType ?? "socks5").ToLowerInvariant();
            _proxyUser = user;
            _proxyPass = pass;
            _ssCipher  = ssCipher ?? "aes-128-gcm";
        }

        public async Task ForwardAsync(ParsedPacket pkt, byte[] raw)
        {
            string key       = $"{pkt.SrcIp}:{pkt.SrcPort}->{pkt.DstIp}:{pkt.DstPort}";
            byte   tcpFlags  = raw.Length > 33 ? raw[33] : (byte)0;
            bool   isSyn     = (tcpFlags & 0x02) != 0;
            bool   isFin     = (tcpFlags & 0x01) != 0;
            bool   isRst     = (tcpFlags & 0x04) != 0;

            if (isSyn && !_sessions.ContainsKey(key))
            {
                var session = new TcpSession(pkt.SrcIp, pkt.SrcPort, pkt.DstIp, pkt.DstPort);
                if (_sessions.TryAdd(key, session))
                {
                    _ = session.ConnectAndPipeAsync(
                            _proxyHost, _proxyPort, _proxyType,
                            _proxyUser, _proxyPass, _ssCipher,
                            data => EnqueueIncoming(data));
                }
            }

            if ((isFin || isRst) && _sessions.TryRemove(key, out var removed))
            {
                removed.Dispose();
                return;
            }

            if (_sessions.TryGetValue(key, out var s) && pkt.Payload?.Length > 0)
                await s.SendAsync(pkt.Payload);
        }

        private void EnqueueIncoming(byte[] data)
        {
            _incomingQueue.Enqueue(data);
            _incomingSem.Release();
        }

        public async Task<byte[]> ReceiveNextAsync(CancellationToken token)
        {
            await _incomingSem.WaitAsync(token);
            _incomingQueue.TryDequeue(out var data);
            return data;
        }
    }

    // ── 单条 TCP 会话 ─────────────────────────────────────────────────────

    internal sealed class TcpSession : IDisposable
    {
        public string SrcIp   { get; }
        public int    SrcPort { get; }
        public string DstIp   { get; }
        public int    DstPort { get; }

        // 代理客户端：SS 或 SOCKS5，用接口统一
        private IProxyClient _proxy;
        private bool _connected;
        private readonly SemaphoreSlim _sendLock = new SemaphoreSlim(1, 1);

        // 在代理握手完成前到达的数据先缓存，握手后按序补发，避免丢首段。
        private readonly System.Collections.Generic.Queue<byte[]> _pending
            = new System.Collections.Generic.Queue<byte[]>();

        public TcpSession(string srcIp, int srcPort, string dstIp, int dstPort)
        {
            SrcIp   = srcIp;
            SrcPort = srcPort;
            DstIp   = dstIp;
            DstPort = dstPort;
        }

        public async Task ConnectAndPipeAsync(
            string proxyHost, int proxyPort,
            string proxyType,
            string user, string pass, string ssCipher,
            Action<byte[]> onReceive)
        {
            try
            {
                // 根据节点类型选择客户端
                _proxy = CreateProxyClient(proxyHost, proxyPort, proxyType, user, pass, ssCipher);
                await _proxy.ConnectAsync(DstIp, DstPort);

                // 握手完成：标记已连接并按序补发握手前缓存的数据。
                await _sendLock.WaitAsync();
                try
                {
                    _connected = true;
                    while (_pending.Count > 0)
                    {
                        byte[] buffered = _pending.Dequeue();
                        await _proxy.WriteAsync(buffered);
                    }
                }
                finally { _sendLock.Release(); }

                while (true)
                {
                    byte[] data = await _proxy.ReadAsync(65535);
                    if (data == null || data.Length == 0) break;

                    byte[] ipPkt = IpPacketParser.BuildTcpPacket(
                        DstIp, DstPort, SrcIp, SrcPort,
                        seqNum: 1, ackNum: 1, flags: 0x18, data: data);

                    onReceive?.Invoke(ipPkt);
                }
            }
            catch (Exception ex)
            {
                // 连接失败/断开：记录便于诊断；会话由 TcpSessionTracker 在下次 FIN/RST 时清理。
                System.Diagnostics.Debug.WriteLine(
                    $"TcpSession to {DstIp}:{DstPort} failed: {ex.Message}");
            }
        }

        private static IProxyClient CreateProxyClient(
            string host, int port, string type,
            string user, string pass, string cipher)
        {
            switch (type)
            {
                case "ss":
                case "shadowsocks":
                    // user 字段在 SS 节点里存的是 password
                    return new ShadowsocksProxyAdapter(host, port, pass ?? user, cipher);

                case "socks5":
                    return new Socks5ProxyAdapter(host, port, user, pass);

                default:
                    // vmess / trojan / http 等协议尚未实现：明确报错，
                    // 不再静默退化为 SOCKS5（那会导致握手失败、只看到泛化的"连接失败"）。
                    throw new NotSupportedException(
                        $"Protocol '{type}' is not supported (only ss / socks5 are implemented)");
            }
        }

        public async Task SendAsync(byte[] data)
        {
            if (data == null || data.Length == 0) return;

            await _sendLock.WaitAsync();
            try
            {
                if (_connected && _proxy != null)
                {
                    await _proxy.WriteAsync(data);
                }
                else
                {
                    // 握手尚未完成：先缓存，待 ConnectAndPipeAsync 中按序补发。
                    _pending.Enqueue(data);
                }
            }
            finally { _sendLock.Release(); }
        }

        public void Dispose()
        {
            (_proxy as IDisposable)?.Dispose();
            _sendLock?.Dispose();
        }
    }

    // ── 代理客户端统一接口 ────────────────────────────────────────────────

    internal interface IProxyClient
    {
        Task ConnectAsync(string targetHost, int targetPort);
        Task<byte[]> ReadAsync(uint maxBytes);
        Task WriteAsync(byte[] data);
    }

    /// <summary>把 ShadowsocksClient 包装成 IProxyClient。</summary>
    internal sealed class ShadowsocksProxyAdapter : IProxyClient, IDisposable
    {
        private readonly ShadowsocksClient _ss;

        public ShadowsocksProxyAdapter(string host, int port, string password, string cipher)
            => _ss = new ShadowsocksClient(host, port, password, cipher);

        public Task ConnectAsync(string h, int p) => _ss.ConnectAsync(h, p);
        public Task<byte[]> ReadAsync(uint n)      => _ss.ReadAsync(n);
        public Task WriteAsync(byte[] d)           => _ss.WriteAsync(d);
        public void Dispose()                      => _ss.Dispose();
    }

    /// <summary>把 Socks5Client 包装成 IProxyClient。</summary>
    internal sealed class Socks5ProxyAdapter : IProxyClient, IDisposable
    {
        private readonly Socks5Client _s5;

        public Socks5ProxyAdapter(string host, int port, string user, string pass)
            => _s5 = new Socks5Client(host, port, user, pass);

        public Task ConnectAsync(string h, int p) => _s5.ConnectAsync(h, p);
        public Task<byte[]> ReadAsync(uint n)      => _s5.ReadAsync(n);
        public Task WriteAsync(byte[] d)           => _s5.WriteAsync(d);
        public void Dispose()                      => _s5.Dispose();
    }
}
