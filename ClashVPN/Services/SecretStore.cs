using System;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.DataProtection;
using Windows.Storage.Streams;

namespace ClashVPN.Services
{
    /// <summary>
    /// 使用 Windows DPAPI（DataProtectionProvider，LOCAL=user）对敏感字符串
    /// （代理用户名 / 密码）做对称保护，避免在 LocalSettings 中以明文落盘。
    ///
    /// 加密结果以 Base64 字符串形式存储；解密端（VPN 插件）使用同样的描述符即可还原。
    /// 空字符串原样返回（无需保护），且 Unprotect 在收到非密文（如旧版本明文）时
    /// 回退为原值，保证兼容性。
    /// </summary>
    public static class SecretStore
    {
        private const string Descriptor = "LOCAL=user";
        // 用于识别密文的前缀，便于与旧版本明文区分。
        private const string Prefix = "dpapi:";

        public static async Task<string> ProtectAsync(string plaintext)
        {
            if (string.IsNullOrEmpty(plaintext)) return string.Empty;

            var provider = new DataProtectionProvider(Descriptor);
            IBuffer input  = CryptographicBuffer.ConvertStringToBinary(
                                plaintext, BinaryStringEncoding.Utf8);
            IBuffer output = await provider.ProtectAsync(input);
            return Prefix + CryptographicBuffer.EncodeToBase64String(output);
        }

        public static async Task<string> UnprotectAsync(string stored)
        {
            if (string.IsNullOrEmpty(stored)) return string.Empty;

            // 兼容旧版本：未加前缀的认为是明文，原样返回。
            if (!stored.StartsWith(Prefix, StringComparison.Ordinal))
                return stored;

            try
            {
                string b64 = stored.Substring(Prefix.Length);
                IBuffer input  = CryptographicBuffer.DecodeFromBase64String(b64);
                var provider   = new DataProtectionProvider();
                IBuffer output = await provider.UnprotectAsync(input);
                return CryptographicBuffer.ConvertBinaryToString(
                            BinaryStringEncoding.Utf8, output);
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
