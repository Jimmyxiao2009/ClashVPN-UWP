using System;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Buffer = System.Buffer;   // 消除与 Windows.Storage.Streams.Buffer 的二义

namespace ClashVPN.Plugin
{
    /// <summary>
    /// AES-128-GCM / AES-256-GCM 对称加解密，基于 WinRT CryptographicEngine。
    ///
    /// 使用 SymmetricAlgorithmNames.AesGcm（Windows 10 全版本可用）。
    /// Tag 长度固定 16 字节，Nonce 长度固定 12 字节（Shadowsocks 规范）。
    /// </summary>
    internal sealed class AesGcmCipher : IAeadCipher
    {
        public const int TagLen   = 16;
        public const int NonceLen = 12;

        private readonly CryptographicKey _key;
        private readonly SymmetricKeyAlgorithmProvider _provider;

        public AesGcmCipher(byte[] keyBytes)
        {
            if (keyBytes.Length != 16 && keyBytes.Length != 32)
                throw new ArgumentException("Key must be 16 or 32 bytes for AES-128/256-GCM");

            _provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);
            _key      = _provider.CreateSymmetricKey(
                            CryptographicBuffer.CreateFromByteArray(keyBytes));
        }

        // ── 加密 ──────────────────────────────────────────────────────────

        /// <summary>
        /// 加密 plaintext，输出 ciphertext + 16字节 tag（拼合在一起返回）。
        /// </summary>
        /// <param name="nonce">12 字节 nonce</param>
        /// <param name="plaintext">明文</param>
        /// <param name="aad">附加认证数据（可为 null）</param>
        /// <returns>ciphertext || tag（长度 = plaintext.Length + TagLen）</returns>
        public byte[] Encrypt(byte[] nonce, byte[] plaintext, byte[] aad = null)
        {
            ValidateNonce(nonce);

            IBuffer nonceBuf = CryptographicBuffer.CreateFromByteArray(nonce);
            IBuffer plainBuf = CryptographicBuffer.CreateFromByteArray(plaintext ?? Array.Empty<byte>());
            IBuffer aadBuf   = aad != null
                ? CryptographicBuffer.CreateFromByteArray(aad)
                : null;

            // WinRT AES-GCM 必须经认证加密 API 才能产生 16 字节 tag
            EncryptedAndAuthenticatedData enc =
                CryptographicEngine.EncryptAndAuthenticate(_key, plainBuf, nonceBuf, aadBuf);

            byte[] ct  = enc.EncryptedData.ToArray();
            byte[] tag = enc.AuthenticationTag.ToArray();   // 16 字节

            byte[] outBuf = new byte[ct.Length + tag.Length];
            Buffer.BlockCopy(ct,  0, outBuf, 0,         ct.Length);
            Buffer.BlockCopy(tag, 0, outBuf, ct.Length, tag.Length);
            return outBuf;   // ciphertext || tag
        }

        // ── 解密 ──────────────────────────────────────────────────────────

        /// <summary>
        /// 解密 ciphertext（包含末尾 16 字节 tag）。
        /// </summary>
        /// <param name="nonce">12 字节 nonce</param>
        /// <param name="ciphertextWithTag">密文 + tag（总长度 = plaintext.Length + TagLen）</param>
        /// <param name="aad">附加认证数据（可为 null）</param>
        /// <returns>明文，tag 验证失败则抛出异常</returns>
        public byte[] Decrypt(byte[] nonce, byte[] ciphertextWithTag, byte[] aad = null)
        {
            ValidateNonce(nonce);
            if (ciphertextWithTag == null || ciphertextWithTag.Length < TagLen)
                throw new ArgumentException("Ciphertext too short to contain tag");

            int ctLen = ciphertextWithTag.Length - TagLen;
            byte[] ct  = new byte[ctLen];
            byte[] tag = new byte[TagLen];
            Buffer.BlockCopy(ciphertextWithTag, 0,     ct,  0, ctLen);
            Buffer.BlockCopy(ciphertextWithTag, ctLen, tag, 0, TagLen);

            IBuffer nonceBuf  = CryptographicBuffer.CreateFromByteArray(nonce);
            IBuffer cipherBuf = CryptographicBuffer.CreateFromByteArray(ct);
            IBuffer tagBuf    = CryptographicBuffer.CreateFromByteArray(tag);
            IBuffer aadBuf    = aad != null
                ? CryptographicBuffer.CreateFromByteArray(aad)
                : null;

            try
            {
                // 认证解密：tag 验证失败会抛异常
                IBuffer result = CryptographicEngine.DecryptAndAuthenticate(
                    _key, cipherBuf, nonceBuf, tagBuf, aadBuf);
                return result.ToArray();
            }
            catch (Exception ex)
            {
                throw new CryptographicException("AES-GCM tag verification failed", ex);
            }
        }

        // ── Nonce 递增 ────────────────────────────────────────────────────

        /// <summary>
        /// 将 nonce 按小端序加一（Shadowsocks 规范：每个 chunk 后 nonce++）。
        /// </summary>
        public static void IncrementNonce(byte[] nonce)
        {
            for (int i = 0; i < nonce.Length; i++)
            {
                if (++nonce[i] != 0) break;
            }
        }

        private static void ValidateNonce(byte[] nonce)
        {
            if (nonce == null || nonce.Length != NonceLen)
                throw new ArgumentException($"Nonce must be exactly {NonceLen} bytes");
        }
    }

    // ── 自定义异常 ─────────────────────────────────────────────────────────
    internal class CryptographicException : Exception
    {
        public CryptographicException(string message, Exception inner) : base(message, inner) { }
    }
}
