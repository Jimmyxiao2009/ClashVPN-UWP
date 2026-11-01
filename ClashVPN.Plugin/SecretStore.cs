using System;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.DataProtection;
using Windows.Storage.Streams;

namespace ClashVPN.Plugin
{
    /// <summary>
    /// 与主 App 的 ClashVPN.Services.SecretStore 对应的解密端。
    /// 主 App 用 DPAPI（LOCAL=user）保护凭据并以 "dpapi:" + Base64 形式写入
    /// LocalSettings；插件在此还原为明文。Unprotect 不需要描述符。
    ///
    /// internal 类型不会被投影到 WinRT ABI，仅供组件内部使用。
    /// </summary>
    internal static class SecretStore
    {
        private const string Prefix = "dpapi:";

        /// <summary>同步解密（VPN worker 的 Connect 回调是同步的）。</summary>
        public static string Unprotect(string stored)
        {
            if (string.IsNullOrEmpty(stored)) return string.Empty;

            // 兼容旧版本明文（无前缀）。
            if (!stored.StartsWith(Prefix, StringComparison.Ordinal))
                return stored;

            try
            {
                string b64 = stored.Substring(Prefix.Length);
                IBuffer input  = CryptographicBuffer.DecodeFromBase64String(b64);
                var provider   = new DataProtectionProvider();
                IBuffer output = provider.UnprotectAsync(input).AsTask().GetAwaiter().GetResult();
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
