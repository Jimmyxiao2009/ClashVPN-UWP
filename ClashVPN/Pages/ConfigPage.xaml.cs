using System;
using System.Text;
using ClashVPN.Models;
using ClashVPN.Services;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;
using Windows.Web.Http;

namespace ClashVPN.Pages
{
    public sealed partial class ConfigPage : Page
    {
        public ConfigPage() => InitializeComponent();

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            RefreshSummary();
        }

        // ── 从文件导入 ────────────────────────────────────────────────────

        private async void OnImportFileClick(object sender, RoutedEventArgs e)
        {
            var picker = new FileOpenPicker
            {
                SuggestedStartLocation = PickerLocationId.Downloads,
            };
            picker.FileTypeFilter.Add(".yaml");
            picker.FileTypeFilter.Add(".yml");
            picker.FileTypeFilter.Add(".txt");

            StorageFile file = await picker.PickSingleFileAsync();
            if (file == null) return;

            await LoadFromFile(file);
        }

        private async System.Threading.Tasks.Task LoadFromFile(StorageFile file)
        {
            ShowError(null);
            LogBox.Text = "";

            try
            {
                Log($"正在读取：{file.Name}");
                string text = await FileIO.ReadTextAsync(file);
                Log($"文件大小：{Encoding.UTF8.GetByteCount(text)} 字节");

                var fmt = ConfigLoader.DetectFormat(text, file.Name);
                Log($"识别格式：{fmt}");

                var config = ConfigLoader.LoadText(text, file.Name);

                Log($"解析完成：{config.Proxies.Count} 个节点，{config.ProxyGroups.Count} 个代理组，{config.Rules.Count} 条规则");

                AppState.Current.Config         = config;
                AppState.Current.ConfigFileName = file.Name;

                RefreshSummary();
                Log("✓ 配置已加载成功");
            }
            catch (Exception ex)
            {
                Log($"✗ 解析失败：{ex.Message}");
                ShowError(ex.Message);
            }
        }

        // ── 从 URL 下载 ───────────────────────────────────────────────────

        private async void OnImportUrlClick(object sender, RoutedEventArgs e)
        {
            string url = UrlBox.Text?.Trim();
            if (string.IsNullOrEmpty(url))
            {
                ShowError("请输入有效的订阅链接");
                return;
            }

            // 仅允许 http/https 订阅链接，避免尝试无意义的 scheme。
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri parsedUri) ||
                (parsedUri.Scheme != "http" && parsedUri.Scheme != "https"))
            {
                ShowError("订阅链接必须以 http:// 或 https:// 开头");
                return;
            }

            ShowError(null);
            LogBox.Text = "";

            var btn = sender as Button;
            if (btn != null) btn.IsEnabled = false;   // 下载期间禁用按钮

            try
            {
                Log($"正在下载：{url}");

                var client = new HttpClient();   // 短期使用，交 GC 回收（C# 7.3 无 using 声明）
                client.DefaultRequestHeaders.Add("User-Agent", "ClashMetaForAndroid/2.10.1");

                var response = await client.GetAsync(parsedUri);
                response.EnsureSuccessStatusCode();

                string text = await response.Content.ReadAsStringAsync();
                Log($"下载完成，{Encoding.UTF8.GetByteCount(text)} 字节");

                var fmt = ConfigLoader.DetectFormat(text, url);
                Log($"识别格式：{fmt}");

                var config = ConfigLoader.LoadText(text, url);

                Log($"✓ {config.Proxies.Count} 节点，{config.ProxyGroups.Count} 代理组，{config.Rules.Count} 规则");

                AppState.Current.Config         = config;
                AppState.Current.ConfigFileName = parsedUri.Host;

                // 保存到本地供下次启动读取
                var local = ApplicationData.Current.LocalFolder;
                var saved = await local.CreateFileAsync("clash_config.yaml",
                                CreationCollisionOption.ReplaceExisting);
                await FileIO.WriteTextAsync(saved, text);
                Log("配置已缓存到本地");

                RefreshSummary();
            }
            catch (Exception ex)
            {
                Log($"✗ 失败：{ex.Message}");
                ShowError(ex.Message);
            }
            finally
            {
                if (btn != null) btn.IsEnabled = true;
            }
        }

        // ── 显示摘要 ──────────────────────────────────────────────────────

        private void RefreshSummary()
        {
            var config = AppState.Current.Config;
            if (config == null)
            {
                ConfigSummary.Text = "未加载配置文件";
                return;
            }

            var sb = new StringBuilder();
            sb.AppendLine($"文件：{AppState.Current.ConfigFileName}");
            sb.AppendLine($"模式：{config.Mode ?? "未指定"}");
            sb.AppendLine($"节点：{config.Proxies.Count} 个");
            sb.AppendLine($"代理组：{config.ProxyGroups.Count} 个");
            sb.AppendLine($"规则：{config.Rules.Count} 条");

            if (config.Proxies.Count > 0)
            {
                var types = new System.Collections.Generic.Dictionary<string, int>();
                foreach (var p in config.Proxies)
                {
                    string t = p.Type ?? "unknown";
                    types[t] = types.ContainsKey(t) ? types[t] + 1 : 1;
                }
                sb.Append("协议分布：");
                foreach (var kv in types)
                    sb.Append($"{kv.Key.ToUpperInvariant()}×{kv.Value}  ");
            }

            ConfigSummary.Text = sb.ToString().TrimEnd();
        }

        // ── 工具 ──────────────────────────────────────────────────────────

        private void Log(string msg)
        {
            LogBox.Text += msg + "\n";
        }

        private void ShowError(string msg)
        {
            if (string.IsNullOrEmpty(msg))
            {
                ErrorBorder.Visibility = Visibility.Collapsed;
            }
            else
            {
                ErrorText.Text         = msg;
                ErrorBorder.Visibility = Visibility.Visible;
            }
        }

        private void OnBackClick(object sender, RoutedEventArgs e)
        {
            if (Frame.CanGoBack) Frame.GoBack();
        }
    }
}
