using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Buffer = System.Buffer;   // 消除与 Windows.Storage.Streams.Buffer 的二义

namespace ClashVPN.Plugin
{
    /// <summary>
    /// Shadowsocks AEAD 密钥派生。
    ///
    /// 流程：
    ///   1. EVP_BytesToKey(MD5, password) → masterKey（固定长度，取决于加密方法）
    ///   2. HKDF-SHA1(masterKey, salt, info="ss-subkey") → sessionKey（每连接一次）
    ///
    /// 参考：https://shadowsocks.org/doc/aead.html
    /// </summary>
    internal static class ShadowsocksKdf
    {
        private const string HkdfInfo = "ss-subkey";

        // ── 公开接口 ──────────────────────────────────────────────────────

        /// <summary>
        /// 根据密码字符串派生 masterKey，再结合 salt 生成 sessionKey。
        /// </summary>
        /// <param name="password">明文密码</param>
        /// <param name="salt">随机 salt（aes-128-gcm：16 字节；aes-256-gcm / chacha20：32 字节）</param>
        /// <param name="keyLen">目标密钥长度（字节）：aes-128-gcm=16，aes-256-gcm/chacha20=32</param>
        public static byte[] DeriveSessionKey(string password, byte[] salt, int keyLen)
        {
            byte[] masterKey = EvpBytesToKey(Encoding.UTF8.GetBytes(password), keyLen);
            return HkdfSha1(masterKey, salt, Encoding.UTF8.GetBytes(HkdfInfo), keyLen);
        }

        // ── EVP_BytesToKey（OpenSSL 兼容，count=1，无 salt） ──────────────

        /// <summary>
        /// OpenSSL EVP_BytesToKey：用 MD5 迭代扩展密码到所需长度。
        /// Shadowsocks 传统用法：EVP_BytesToKey(MD5, 1, password, NULL, keyLen)
        /// </summary>
        public static byte[] EvpBytesToKey(byte[] password, int keyLen)
        {
            var md5 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);

            var result = new System.Collections.Generic.List<byte>();
            byte[] prev = Array.Empty<byte>();

            while (result.Count < keyLen)
            {
                // D_i = MD5(D_{i-1} + password)
                byte[] input = new byte[prev.Length + password.Length];
                Buffer.BlockCopy(prev, 0, input, 0, prev.Length);
                Buffer.BlockCopy(password, 0, input, prev.Length, password.Length);

                IBuffer hash = md5.HashData(CryptographicBuffer.CreateFromByteArray(input));
                prev = hash.ToArray();
                result.AddRange(prev);
            }

            byte[] key = new byte[keyLen];
            Buffer.BlockCopy(result.ToArray(), 0, key, 0, keyLen);
            return key;
        }

        // ── HKDF-SHA1 ─────────────────────────────────────────────────────

        /// <summary>
        /// RFC 5869 HKDF，哈希算法固定为 SHA-1（Shadowsocks AEAD 规范）。
        /// Extract + Expand 两步完整实现。
        /// </summary>
        public static byte[] HkdfSha1(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            // Extract: PRK = HMAC-SHA1(salt, IKM)
            byte[] prk = HmacSha1(salt, ikm);

            // Expand: T(1) = HMAC-SHA1(PRK, info || 0x01)
            //         T(2) = HMAC-SHA1(PRK, T(1) || info || 0x02)  ...
            var okm    = new System.Collections.Generic.List<byte>();
            byte[] prev = Array.Empty<byte>();
            byte counter = 1;

            while (okm.Count < length)
            {
                byte[] input = new byte[prev.Length + info.Length + 1];
                Buffer.BlockCopy(prev,  0, input, 0,                prev.Length);
                Buffer.BlockCopy(info,  0, input, prev.Length,       info.Length);
                input[prev.Length + info.Length] = counter++;

                prev = HmacSha1(prk, input);
                okm.AddRange(prev);
            }

            byte[] result = new byte[length];
            Buffer.BlockCopy(okm.ToArray(), 0, result, 0, length);
            return result;
        }

        // ── HMAC-SHA1 ─────────────────────────────────────────────────────

        private static byte[] HmacSha1(byte[] key, byte[] message)
        {
            var mac      = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
            var keyBuf   = CryptographicBuffer.CreateFromByteArray(key);
            var cryptKey = mac.CreateKey(keyBuf);
            var msgBuf   = CryptographicBuffer.CreateFromByteArray(message);
            var result   = CryptographicEngine.Sign(cryptKey, msgBuf);
            return result.ToArray();
        }
    }
}
