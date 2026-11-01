using System;
using System.Numerics;

namespace ClashVPN.Plugin
{
    /// <summary>
    /// AEAD 加解密统一接口。AesGcmCipher / ChaCha20Poly1305Cipher 各实现一份，
    /// ShadowsocksClient 按节点的加密方法选用，对上层透明。
    /// Nonce 12 字节、Tag 16 字节（与 Shadowsocks AEAD 规范一致）。
    /// </summary>
    internal interface IAeadCipher
    {
        byte[] Encrypt(byte[] nonce, byte[] plaintext, byte[] aad = null);
        byte[] Decrypt(byte[] nonce, byte[] ciphertextWithTag, byte[] aad = null);
    }

    /// <summary>
    /// ChaCha20-Poly1305（IETF，RFC 8439）AEAD —— WinRT CryptographicEngine 不提供，
    /// 因此手写实现。用于 Shadowsocks 的 chacha20-ietf-poly1305 加密方法。
    ///
    /// 输出格式与 AesGcmCipher 对齐：Encrypt 返回 ciphertext||tag(16)，
    /// Decrypt 接收 ciphertext||tag 并在 tag 校验失败时抛 CryptographicException。
    ///
    /// 实现说明：ChaCha20 用 32 位字算术；Poly1305 用 BigInteger 做 mod(2^130-5)，
    /// 正确性优先，单 chunk ≤16KB，性能可接受；后续如需提速可换 26-bit limb 版。
    /// </summary>
    internal sealed class ChaCha20Poly1305Cipher : IAeadCipher
    {
        private const int KeyLen   = 32;
        private const int NonceLen = 12;
        private const int TagLen   = 16;

        private readonly uint[] _key = new uint[8];   // 256-bit key as 8 little-endian words

        public ChaCha20Poly1305Cipher(byte[] keyBytes)
        {
            if (keyBytes == null || keyBytes.Length != KeyLen)
                throw new ArgumentException("ChaCha20-Poly1305 key must be 32 bytes");
            for (int i = 0; i < 8; i++)
                _key[i] = ReadLe32(keyBytes, i * 4);
        }

        // ── AEAD 接口 ──────────────────────────────────────────────────────

        public byte[] Encrypt(byte[] nonce, byte[] plaintext, byte[] aad = null)
        {
            ValidateNonce(nonce);
            plaintext = plaintext ?? Array.Empty<byte>();

            byte[] otk = Poly1305KeyGen(nonce);
            byte[] ct  = ChaCha20Xor(nonce, 1, plaintext);   // counter 从 1 开始
            byte[] tag = Poly1305Mac(BuildMacData(aad, ct), otk);

            byte[] outBuf = new byte[ct.Length + TagLen];
            Buffer.BlockCopy(ct,  0, outBuf, 0,         ct.Length);
            Buffer.BlockCopy(tag, 0, outBuf, ct.Length, TagLen);
            return outBuf;
        }

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

            byte[] otk      = Poly1305KeyGen(nonce);
            byte[] expected = Poly1305Mac(BuildMacData(aad, ct), otk);
            if (!ConstantTimeEquals(expected, tag))
                throw new CryptographicException("ChaCha20-Poly1305 tag verification failed", null);

            return ChaCha20Xor(nonce, 1, ct);
        }

        // ── ChaCha20（RFC 8439 §2.3-2.4） ──────────────────────────────────

        private byte[] ChaCha20Xor(byte[] nonce, uint counter, byte[] data)
        {
            byte[] outBuf = new byte[data.Length];
            byte[] block  = new byte[64];
            int offset = 0;

            while (offset < data.Length)
            {
                ChaChaBlock(nonce, counter, block);
                int n = Math.Min(64, data.Length - offset);
                for (int i = 0; i < n; i++)
                    outBuf[offset + i] = (byte)(data[offset + i] ^ block[i]);
                offset  += n;
                counter += 1;
            }
            return outBuf;
        }

        private void ChaChaBlock(byte[] nonce, uint counter, byte[] outBlock)
        {
            uint[] s = new uint[16];
            // "expand 32-byte k"
            s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
            for (int i = 0; i < 8; i++) s[4 + i] = _key[i];
            s[12] = counter;
            s[13] = ReadLe32(nonce, 0);
            s[14] = ReadLe32(nonce, 4);
            s[15] = ReadLe32(nonce, 8);

            uint[] x = (uint[])s.Clone();
            for (int i = 0; i < 10; i++)   // 10 个双轮 = 20 轮
            {
                QuarterRound(x, 0, 4,  8, 12);
                QuarterRound(x, 1, 5,  9, 13);
                QuarterRound(x, 2, 6, 10, 14);
                QuarterRound(x, 3, 7, 11, 15);
                QuarterRound(x, 0, 5, 10, 15);
                QuarterRound(x, 1, 6, 11, 12);
                QuarterRound(x, 2, 7,  8, 13);
                QuarterRound(x, 3, 4,  9, 14);
            }

            for (int i = 0; i < 16; i++)
            {
                uint v = x[i] + s[i];
                outBlock[i * 4]     = (byte)v;
                outBlock[i * 4 + 1] = (byte)(v >> 8);
                outBlock[i * 4 + 2] = (byte)(v >> 16);
                outBlock[i * 4 + 3] = (byte)(v >> 24);
            }
        }

        private static void QuarterRound(uint[] x, int a, int b, int c, int d)
        {
            x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 16);
            x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 12);
            x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a],  8);
            x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c],  7);
        }

        private static uint Rotl(uint v, int n) => (v << n) | (v >> (32 - n));

        // ── Poly1305（RFC 8439 §2.5） ──────────────────────────────────────

        private byte[] Poly1305KeyGen(byte[] nonce)
        {
            byte[] block = new byte[64];
            ChaChaBlock(nonce, 0, block);   // counter=0 的 keystream 前 32 字节即一次性密钥
            byte[] otk = new byte[32];
            Buffer.BlockCopy(block, 0, otk, 0, 32);
            return otk;
        }

        private static readonly BigInteger P = (BigInteger.One << 130) - 5;
        private static readonly BigInteger Mask128 = (BigInteger.One << 128) - 1;

        private static byte[] Poly1305Mac(byte[] msg, byte[] key)
        {
            // r = key[0..16]，按规范 clamp
            byte[] rBytes = new byte[16];
            Buffer.BlockCopy(key, 0, rBytes, 0, 16);
            rBytes[3]  &= 15;  rBytes[7]  &= 15;  rBytes[11] &= 15;  rBytes[15] &= 15;
            rBytes[4]  &= 252; rBytes[8]  &= 252; rBytes[12] &= 252;
            BigInteger r = LeToBig(rBytes, 16);

            // s = key[16..32]
            byte[] sBytes = new byte[16];
            Buffer.BlockCopy(key, 16, sBytes, 0, 16);
            BigInteger s = LeToBig(sBytes, 16);

            BigInteger acc = BigInteger.Zero;
            int offset = 0;
            while (offset < msg.Length)
            {
                int n = Math.Min(16, msg.Length - offset);
                byte[] blk = new byte[n + 1];
                Buffer.BlockCopy(msg, offset, blk, 0, n);
                blk[n] = 1;                       // 追加 0x01 高位（满块即 2^128 位）
                acc = ((acc + LeToBig(blk, blk.Length)) * r) % P;
                offset += n;
            }

            acc = (acc + s) & Mask128;            // mod 2^128

            byte[] tag      = new byte[16];
            byte[] accBytes = acc.ToByteArray();  // 小端，可能带符号尾零字节
            for (int i = 0; i < 16 && i < accBytes.Length; i++)
                tag[i] = accBytes[i];
            return tag;
        }

        // ── 工具 ──────────────────────────────────────────────────────────

        /// <summary>把小端字节数组转为非负 BigInteger（追加 0x00 高位保证为正）。</summary>
        private static BigInteger LeToBig(byte[] data, int len)
        {
            byte[] tmp = new byte[len + 1];
            Buffer.BlockCopy(data, 0, tmp, 0, len);
            return new BigInteger(tmp);   // BigInteger(byte[]) 即小端解释
        }

        private static uint ReadLe32(byte[] b, int o)
            => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

        /// <summary>mac_data = aad || pad16(aad) || ct || pad16(ct) || le64(|aad|) || le64(|ct|)。</summary>
        private static byte[] BuildMacData(byte[] aad, byte[] ct)
        {
            aad = aad ?? Array.Empty<byte>();
            int aadPad = (16 - (aad.Length % 16)) % 16;
            int ctPad  = (16 - (ct.Length  % 16)) % 16;

            byte[] m = new byte[aad.Length + aadPad + ct.Length + ctPad + 16];
            int p = 0;
            Buffer.BlockCopy(aad, 0, m, p, aad.Length); p += aad.Length + aadPad;
            Buffer.BlockCopy(ct,  0, m, p, ct.Length);  p += ct.Length  + ctPad;
            WriteLe64(m, p, (ulong)aad.Length); p += 8;
            WriteLe64(m, p, (ulong)ct.Length);
            return m;
        }

        private static void WriteLe64(byte[] b, int o, ulong v)
        {
            for (int i = 0; i < 8; i++) { b[o + i] = (byte)v; v >>= 8; }
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static void ValidateNonce(byte[] nonce)
        {
            if (nonce == null || nonce.Length != NonceLen)
                throw new ArgumentException("Nonce must be exactly 12 bytes");
        }
    }
}
