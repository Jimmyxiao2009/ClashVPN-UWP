using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;
using Buffer = System.Buffer;   // 消除与 Windows.Storage.Streams.Buffer 的二义

namespace ClashVPN.Plugin
{
    /// <summary>
    /// Shadowsocks AEAD 客户端（完整协议实现）。
    ///
    /// 支持的加密方法：
    ///   aes-128-gcm  → keyLen=16, saltLen=16
    ///   aes-256-gcm  → keyLen=32, saltLen=32
    ///   chacha20-ietf-poly1305 → keyLen=32, saltLen=32（ChaCha20Poly1305Cipher 真实实现）
    ///
    /// 协议格式（AEAD 2022 之前的旧格式，兼容所有主流服务端）：
    ///
    ///   握手（客户端→服务端）：
    ///     [salt(saltLen)] [加密的目标地址] [加密的数据流...]
    ///
    ///   每个加密 chunk：
    ///     [len_ciphertext(2+TAG)] [payload_ciphertext(N+TAG)]
    ///     nonce 每次 +1（小端序）
    ///
    ///   目标地址（SOCKS5 ATYP 格式，明文放在第一个 chunk 的 payload 里）：
    ///     ATYP(1) + ADDR + PORT(2)
    ///
    /// 参考：https://shadowsocks.org/doc/aead.html
    /// </summary>
    internal sealed class ShadowsocksClient : IDisposable
    {
        // ── 配置 ──────────────────────────────────────────────────────────

        private readonly string _server;
        private readonly int    _port;
        private readonly string _password;
        private readonly string _method;     // aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305

        private int    _keyLen;
        private int    _saltLen;

        // ── 运行时状态 ────────────────────────────────────────────────────

        private StreamSocket _socket;
        private DataWriter   _writer;
        private DataReader   _reader;

        // 加密方向（发送）
        private IAeadCipher _encCipher;
        private byte[]       _encNonce;   // 12 字节，每发一个 chunk +1

        // 解密方向（接收）
        private IAeadCipher _decCipher;
        private byte[]       _decNonce;
        private bool         _decReady;   // 是否已收到对端 salt 并初始化

        // 未消费的解密数据缓冲
        private readonly System.IO.MemoryStream _readBuf = new System.IO.MemoryStream();

        public ShadowsocksClient(string server, int port, string password, string method = "aes-128-gcm")
        {
            _server   = server;
            _port     = port;
            _password = password;
            _method   = method?.ToLowerInvariant() ?? "aes-128-gcm";
            SetKeyParams();
        }

        private void SetKeyParams()
        {
            switch (_method)
            {
                case "aes-256-gcm":
                case "chacha20-ietf-poly1305":
                case "chacha20-poly1305":        // 别名，等价 ietf 变体
                    _keyLen  = 32;
                    _saltLen = 32;
                    break;
                default:                         // aes-128-gcm
                    _keyLen  = 16;
                    _saltLen = 16;
                    break;
            }
        }

        /// <summary>按加密方法创建对应的 AEAD cipher（密钥已由 KDF 派生为正确长度）。</summary>
        private IAeadCipher CreateCipher(byte[] sessionKey)
        {
            switch (_method)
            {
                case "chacha20-ietf-poly1305":
                case "chacha20-poly1305":
                    return new ChaCha20Poly1305Cipher(sessionKey);   // 32 字节密钥
                default:
                    return new AesGcmCipher(sessionKey);             // aes-128/256-gcm
            }
        }

        // ── 连接 + 握手 ───────────────────────────────────────────────────

        /// <summary>
        /// 连接到 SS 服务端，并发送目标地址（建立隧道）。
        /// 之后可调用 ReadAsync / WriteAsync 进行透明数据收发。
        /// </summary>
        public async Task ConnectAsync(string targetHost, int targetPort)
        {
            _socket = new StreamSocket();
            await _socket.ConnectAsync(new HostName(_server), _port.ToString());

            _writer = new DataWriter(_socket.OutputStream);
            _reader = new DataReader(_socket.InputStream)
                      { InputStreamOptions = InputStreamOptions.Partial };

            // 1. 生成本端 salt，初始化加密器
            byte[] salt = GenerateRandom(_saltLen);
            byte[] sessionKey = ShadowsocksKdf.DeriveSessionKey(_password, salt, _keyLen);
            _encCipher = CreateCipher(sessionKey);
            _encNonce  = new byte[AesGcmCipher.NonceLen];  // 全零起始

            // 2. 构造目标地址 payload（SOCKS5 地址格式）
            byte[] addrPayload = BuildAddressPayload(targetHost, targetPort);

            // 3. 发送：salt + 加密的 addrPayload
            _writer.WriteBytes(salt);
            WriteChunk(addrPayload);
            await _writer.StoreAsync();
        }

        // ── 写（发送数据到远端） ──────────────────────────────────────────

        /// <summary>
        /// 将 data 分块加密后发送。
        /// 单块最大 0x3FFF（16383）字节（Shadowsocks 规范）。
        /// </summary>
        public async Task WriteAsync(byte[] data)
        {
            if (data == null || data.Length == 0) return;

            const int maxChunk = 0x3FFF;
            int offset = 0;

            while (offset < data.Length)
            {
                int take   = Math.Min(maxChunk, data.Length - offset);
                byte[] seg = new byte[take];
                Buffer.BlockCopy(data, offset, seg, 0, take);
                WriteChunk(seg);
                offset += take;
            }

            await _writer.StoreAsync();
        }

        /// <summary>
        /// 加密并写入一个 chunk：[len(2)+TAG(16)] [payload+TAG(16)]
        /// </summary>
        private void WriteChunk(byte[] payload)
        {
            // 长度字段（大端序，2 字节）
            ushort len    = (ushort)payload.Length;
            byte[] lenBuf = new byte[] { (byte)(len >> 8), (byte)(len & 0xFF) };

            byte[] encLen = _encCipher.Encrypt(_encNonce, lenBuf);
            AesGcmCipher.IncrementNonce(_encNonce);

            byte[] encPayload = _encCipher.Encrypt(_encNonce, payload);
            AesGcmCipher.IncrementNonce(_encNonce);

            _writer.WriteBytes(encLen);       // 2 + 16 = 18 字节
            _writer.WriteBytes(encPayload);   // len + 16 字节
        }

        // ── 读（接收远端数据） ────────────────────────────────────────────

        /// <summary>
        /// 读取并解密最多 maxBytes 字节的明文。
        /// 返回 null 表示连接已关闭。
        /// </summary>
        public async Task<byte[]> ReadAsync(uint maxBytes = 65535)
        {
            // 先消费内部缓冲
            if (_readBuf.Length - _readBuf.Position > 0)
                return DrainBuffer(maxBytes);

            // 初始化解密器（首次读时收取对端 salt）
            if (!_decReady)
                await InitDecryptor();

            // 读一个完整的 chunk
            byte[] payload = await ReadChunkAsync();
            if (payload == null) return null;

            if (payload.Length <= (int)maxBytes)
                return payload;

            // chunk 比请求大，缓存多余部分
            _readBuf.SetLength(0);
            _readBuf.Position = 0;
            _readBuf.Write(payload, (int)maxBytes, payload.Length - (int)maxBytes);
            _readBuf.Position = 0;

            byte[] result = new byte[maxBytes];
            Buffer.BlockCopy(payload, 0, result, 0, (int)maxBytes);
            return result;
        }

        /// <summary>首次读：从对端接收 salt，初始化解密器。</summary>
        private async Task InitDecryptor()
        {
            byte[] salt = await ReadExactAsync((uint)_saltLen);
            if (salt == null) throw new Exception("SS: connection closed while reading server salt");

            byte[] sessionKey = ShadowsocksKdf.DeriveSessionKey(_password, salt, _keyLen);
            _decCipher  = CreateCipher(sessionKey);
            _decNonce   = new byte[AesGcmCipher.NonceLen];
            _decReady   = true;
        }

        /// <summary>读并解密一个 chunk，返回明文 payload。</summary>
        private async Task<byte[]> ReadChunkAsync()
        {
            // 读长度字段密文：2 + 16 = 18 字节
            byte[] encLen = await ReadExactAsync(2 + AesGcmCipher.TagLen);
            if (encLen == null) return null;

            byte[] lenBuf = _decCipher.Decrypt(_decNonce, encLen);
            AesGcmCipher.IncrementNonce(_decNonce);

            ushort payloadLen = (ushort)((lenBuf[0] << 8) | lenBuf[1]);
            if (payloadLen > 0x3FFF)
                throw new Exception($"SS: invalid chunk length {payloadLen}");

            // 读 payload 密文：payloadLen + 16 字节
            byte[] encPayload = await ReadExactAsync((uint)(payloadLen + AesGcmCipher.TagLen));
            if (encPayload == null) return null;

            byte[] payload = _decCipher.Decrypt(_decNonce, encPayload);
            AesGcmCipher.IncrementNonce(_decNonce);

            return payload;
        }

        /// <summary>精确读取 count 字节，不足时持续等待。</summary>
        private async Task<byte[]> ReadExactAsync(uint count)
        {
            uint remaining = count;
            byte[] result  = new byte[count];
            int    offset  = 0;

            while (remaining > 0)
            {
                uint loaded = await _reader.LoadAsync(remaining);
                if (loaded == 0) return null;   // 连接关闭

                uint take = Math.Min(loaded, remaining);
                byte[] chunk = new byte[take];
                _reader.ReadBytes(chunk);
                Buffer.BlockCopy(chunk, 0, result, offset, (int)take);
                offset    += (int)take;
                remaining -= take;
            }

            return result;
        }

        private byte[] DrainBuffer(uint maxBytes)
        {
            long available = _readBuf.Length - _readBuf.Position;
            int  take      = (int)Math.Min(available, (long)maxBytes);
            byte[] result  = new byte[take];
            _readBuf.Read(result, 0, take);
            if (_readBuf.Position >= _readBuf.Length)
            {
                _readBuf.SetLength(0);
                _readBuf.Position = 0;
            }
            return result;
        }

        // ── 地址序列化 ────────────────────────────────────────────────────

        /// <summary>
        /// 构造 SOCKS5 风格的地址载荷（ATYP + ADDR + PORT）。
        /// 这是放在第一个 chunk payload 里的目标地址信息。
        /// </summary>
        private static byte[] BuildAddressPayload(string host, int port)
        {
            System.Net.IPAddress ip;
            var buf = new List<byte>();

            if (System.Net.IPAddress.TryParse(host, out ip))
            {
                byte[] addrBytes = ip.GetAddressBytes();
                if (addrBytes.Length == 4)
                {
                    buf.Add(0x01);  // IPv4
                    buf.AddRange(addrBytes);
                }
                else
                {
                    buf.Add(0x04);  // IPv6
                    buf.AddRange(addrBytes);
                }
            }
            else
            {
                // 域名
                byte[] hostBytes = Encoding.UTF8.GetBytes(host);
                buf.Add(0x03);
                buf.Add((byte)hostBytes.Length);
                buf.AddRange(hostBytes);
            }

            buf.Add((byte)(port >> 8));
            buf.Add((byte)(port & 0xFF));

            return buf.ToArray();
        }

        // ── 工具 ──────────────────────────────────────────────────────────

        private static byte[] GenerateRandom(int length)
        {
            var buf = Windows.Security.Cryptography.CryptographicBuffer
                             .GenerateRandom((uint)length);
            byte[] arr = new byte[length];
            Windows.Security.Cryptography.CryptographicBuffer.CopyToByteArray(buf, out arr);
            return arr;
        }

        public void Dispose()
        {
            _writer?.Dispose();
            _reader?.Dispose();
            _socket?.Dispose();
            _readBuf?.Dispose();
        }
    }
}
