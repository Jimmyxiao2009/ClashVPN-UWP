using System;
using System.Threading.Tasks;
using ClashVPN.Models;
using Windows.Storage;

namespace ClashVPN.Services
{
    /// <summary>
    /// 自动识别配置文件格式并调用对应解析器。
    /// 支持：
    ///   - Clash YAML（.yaml / .yml）
    ///   - Surge / Surfboard INI（.conf）
    ///   - 纯文本订阅（Base64 编码的 SS URI 列表，todo）
    /// </summary>
    public static class ConfigLoader
    {
        public enum ConfigFormat { Unknown, ClashYaml, SurgeConf }

        public static async Task<ClashConfig> LoadFileAsync(StorageFile file)
        {
            string text = await FileIO.ReadTextAsync(file);
            return LoadText(text, file.Name);
        }

        public static async Task<ClashConfig> LoadFromUrlAsync(string url)
        {
            string text = await DownloadTextAsync(url);
            string name = TryGetFilename(url);
            return LoadText(text, name);
        }

        public static ClashConfig LoadText(string text, string hint = "")
        {
            var fmt = DetectFormat(text, hint);

            switch (fmt)
            {
                case ConfigFormat.ClashYaml:
                    return ClashConfigParser.Parse(text);

                case ConfigFormat.SurgeConf:
                    return SurgeConfigParser.Parse(text);

                default:
                    // 最后尝试 YAML，失败再试 Surge
                    try   { return ClashConfigParser.Parse(text); }
                    catch { return SurgeConfigParser.Parse(text); }
            }
        }

        // ── 格式检测 ──────────────────────────────────────────────────────

        public static ConfigFormat DetectFormat(string text, string hint = "")
        {
            // 1. 靠文件扩展名
            if (!string.IsNullOrEmpty(hint))
            {
                string lower = hint.ToLowerInvariant();
                if (lower.EndsWith(".yaml") || lower.EndsWith(".yml"))
                    return ConfigFormat.ClashYaml;
                if (lower.EndsWith(".conf"))
                    return ConfigFormat.SurgeConf;
            }

            // 2. 靠内容特征
            string head = text.Length > 2000 ? text.Substring(0, 2000) : text;

            // Surge 特征：[General] / [Proxy] / #!MANAGED-CONFIG
            if (head.Contains("[General]") || head.Contains("[Proxy]") ||
                head.Contains("#!MANAGED-CONFIG") || head.Contains("[Proxy Group]"))
                return ConfigFormat.SurgeConf;

            // Clash YAML 特征：proxies: / proxy-groups: / rules:
            if (head.Contains("proxies:") || head.Contains("proxy-groups:") ||
                head.Contains("mixed-port:"))
                return ConfigFormat.ClashYaml;

            return ConfigFormat.Unknown;
        }

        // ── HTTP 下载 ─────────────────────────────────────────────────────

        private static async Task<string> DownloadTextAsync(string url)
        {
            using (var client = new Windows.Web.Http.HttpClient())
            {
                // 模拟常见客户端 UA，避免订阅服务器返回错误格式
                client.DefaultRequestHeaders.Add("User-Agent",
                    "ClashMetaForAndroid/2.10.1 clash-meta");

                var response = await client.GetAsync(new Uri(url));
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync();
            }
        }

        private static string TryGetFilename(string url)
        {
            try
            {
                var uri  = new Uri(url);
                string path = uri.AbsolutePath;
                int    last = path.LastIndexOf('/');
                return last >= 0 ? path.Substring(last + 1) : path;
            }
            catch { return ""; }
        }
    }
}
