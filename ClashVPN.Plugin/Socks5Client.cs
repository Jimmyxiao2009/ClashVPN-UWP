using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace ClashVPN.Plugin
{
    /// <summary>
    /// SOCKS5 客户端（RFC 1928 + RFC 1929 用户名密码认证）。
    /// 支持 CONNECT 命令（TCP 代理）。
    /// </summary>
    internal sealed class Socks5Client : IDisposable
    {
        private readonly string _server;
        private readonly int    _port;
        private readonly string _username;
        private readonly string _password;

        private StreamSocket        _socket;
        private DataWriter          _writer;
        private DataReader          _reader;

        public Socks5Client(string server, int port, string username = null, string password = null)
        {
            _server   = server;
            _port     = port;
            _username = username;
            _password = password;
        }

        // ── 握手 + CONNECT ────────────────────────────────────────────────

        /// <summary>
        /// 建立到 SOCKS5 服务器的连接，并发送 CONNECT 请求到目标 host:port。
        /// 完成后 socket 即可像直连一样读写。
        /// </summary>
        public async Task ConnectAsync(string targetHost, int targetPort)
        {
            _socket = new StreamSocket();
            await _socket.ConnectAsync(new HostName(_server), _port.ToString());

            _writer = new DataWriter(_socket.OutputStream)
                      { UnicodeEncoding = Windows.Storage.Streams.UnicodeEncoding.Utf8 };
            _reader = new DataReader(_socket.InputStream)  { InputStreamOptions = InputStreamOptions.Partial };

            await Handshake();
            await SendConnect(targetHost, targetPort);
        }

        // ── RFC 1928 握手 ─────────────────────────────────────────────────

        private async Task Handshake()
        {
            bool hasAuth = !string.IsNullOrEmpty(_username);

            // VER NMETHODS METHODS
            byte[] greeting = hasAuth
                ? new byte[] { 0x05, 0x02, 0x00, 0x02 }  // no-auth + user/pass
                : new byte[] { 0x05, 0x01, 0x00 };        // no-auth only

            _writer.WriteBytes(greeting);
            await _writer.StoreAsync();

            // 读服务器回应
            await _reader.LoadAsync(2);
            byte ver    = _reader.ReadByte();
            byte method = _reader.ReadByte();

            if (ver != 0x05)
                throw new Exception($"SOCKS5: bad version {ver}");

            if (method == 0xFF)
                throw new Exception("SOCKS5: no acceptable auth method");

            // 需要用户名密码认证
            if (method == 0x02)
            {
                if (!hasAuth)
                    throw new Exception("SOCKS5: server requires auth but none provided");

                await SendUserPassAuth();
            }
        }

        private async Task SendUserPassAuth()
        {
            byte[] user = Encoding.UTF8.GetBytes(_username);
            byte[] pass = Encoding.UTF8.GetBytes(_password ?? "");

            var buf = new byte[3 + user.Length + pass.Length];
            buf[0] = 0x01;                // sub-negotiation version
            buf[1] = (byte)user.Length;
            Array.Copy(user, 0, buf, 2, user.Length);
            buf[2 + user.Length] = (byte)pass.Length;
            Array.Copy(pass, 0, buf, 3 + user.Length, pass.Length);

            _writer.WriteBytes(buf);
            await _writer.StoreAsync();

            await _reader.LoadAsync(2);
            byte subVer = _reader.ReadByte();
            byte status = _reader.ReadByte();

            if (status != 0x00)
                throw new Exception("SOCKS5: authentication failed");
        }

        // ── CONNECT 请求 ──────────────────────────────────────────────────

        private async Task SendConnect(string host, int port)
        {
            bool isIp = System.Net.IPAddress.TryParse(host, out var ipAddr);

            var req = new System.Collections.Generic.List<byte>();
            req.Add(0x05);  // VER
            req.Add(0x01);  // CMD = CONNECT
            req.Add(0x00);  // RSV

            if (isIp && ipAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                req.Add(0x01);  // ATYP = IPv4
                req.AddRange(ipAddr.GetAddressBytes());
            }
            else if (isIp && ipAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                req.Add(0x04);  // ATYP = IPv6
                req.AddRange(ipAddr.GetAddressBytes());
            }
            else
            {
                // 域名
                byte[] hostBytes = Encoding.UTF8.GetBytes(host);
                req.Add(0x03);  // ATYP = DOMAINNAME
                req.Add((byte)hostBytes.Length);
                req.AddRange(hostBytes);
            }

            req.Add((byte)(port >> 8));
            req.Add((byte)(port & 0xFF));

            _writer.WriteBytes(req.ToArray());
            await _writer.StoreAsync();

            // 读响应头（最少 10 字节）
            await _reader.LoadAsync(4);
            byte rVer = _reader.ReadByte();
            byte rep  = _reader.ReadByte();
                         _reader.ReadByte(); // RSV
            byte atyp = _reader.ReadByte();

            if (rep != 0x00)
                throw new Exception($"SOCKS5 CONNECT failed, REP=0x{rep:X2}");

            // 跳过 BND.ADDR + BND.PORT
            switch (atyp)
            {
                case 0x01: await _reader.LoadAsync(4 + 2);  _reader.ReadBuffer(6);  break;
                case 0x04: await _reader.LoadAsync(16 + 2); _reader.ReadBuffer(18); break;
                case 0x03:
                    await _reader.LoadAsync(1);
                    byte len = _reader.ReadByte();
                    await _reader.LoadAsync((uint)(len + 2));
                    _reader.ReadBuffer((uint)(len + 2));
                    break;
            }

            // 握手完成，_socket 现在直连目标
        }

        // ── 读写 ──────────────────────────────────────────────────────────

        public async Task<byte[]> ReadAsync(uint maxBytes)
        {
            uint loaded = await _reader.LoadAsync(maxBytes);
            if (loaded == 0) return null;
            var buf = new byte[loaded];
            _reader.ReadBytes(buf);
            return buf;
        }

        public async Task WriteAsync(byte[] data)
        {
            _writer.WriteBytes(data);
            await _writer.StoreAsync();
        }

        public IInputStream  InputStream  => _socket?.InputStream;
        public IOutputStream OutputStream => _socket?.OutputStream;

        public void Dispose()
        {
            _writer?.Dispose();
            _reader?.Dispose();
            _socket?.Dispose();
        }
    }
}
