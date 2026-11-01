using System;
using ClashVPN.Models;
using ClashVPN.Services;
using Windows.UI;
using Windows.UI.Core;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

namespace ClashVPN.Pages
{
    public sealed partial class HomePage : Page
    {
        private VpnManager    _vpn;
        private ClashConfig   _config;
        private ProxyNode     _selectedNode;
        private bool          _connected;
        private DispatcherTimer _timer;

        public HomePage()
        {
            InitializeComponent();
            _vpn = new VpnManager();
        }

        protected override async void OnNavigatedTo(NavigationEventArgs e)
        {
            _config = e.Parameter as ClashConfig
                      ?? AppState.Current.Config;

            RefreshConfigInfo();
            RefreshNodeLabel();
            StartTrafficTimer();

            // 与真实 VPN 状态同步，避免重启/返回后按钮状态错乱。
            await SyncConnectionStateAsync();
        }

        private async System.Threading.Tasks.Task SyncConnectionStateAsync()
        {
            try
            {
                bool connected = await _vpn.IsConnectedAsync();
                _connected = connected;
                if (connected)
                {
                    SetStatus(VpnConnectionState.Connected);
                    ConnectButton.Content = "断开";
                }
                else
                {
                    SetStatus(VpnConnectionState.Disconnected);
                    ConnectButton.Content = "连接";
                }
            }
            catch { /* 状态查询失败时保留默认 UI */ }
        }

        // ── 连接/断开 ─────────────────────────────────────────────────────

        private async void OnConnectClick(object sender, RoutedEventArgs e)
        {
            if (_connected)
            {
                await DoDisconnect();
            }
            else
            {
                if (_selectedNode == null)
                {
                    // 跳到节点页让用户选
                    Frame.Navigate(typeof(NodesPage));
                    return;
                }
                await DoConnect();
            }
        }

        private async System.Threading.Tasks.Task DoConnect()
        {
            ConnectButton.IsEnabled = false;
            SetStatus(VpnConnectionState.Connecting);

            try
            {
                bool ok = await _vpn.ConnectAsync(_selectedNode);
                if (ok)
                {
                    _connected = true;
                    SetStatus(VpnConnectionState.Connected);
                    ConnectButton.Content = "断开";
                }
                else
                {
                    SetStatus(VpnConnectionState.Error, "连接失败");
                }
            }
            catch (Exception ex)
            {
                SetStatus(VpnConnectionState.Error, ex.Message);
            }
            finally
            {
                ConnectButton.IsEnabled = true;
            }
        }

        private async System.Threading.Tasks.Task DoDisconnect()
        {
            ConnectButton.IsEnabled = false;
            SetStatus(VpnConnectionState.Disconnecting);

            try
            {
                await _vpn.DisconnectAsync();
                _connected = false;
                SetStatus(VpnConnectionState.Disconnected);
                ConnectButton.Content = "连接";
            }
            catch (Exception ex)
            {
                SetStatus(VpnConnectionState.Error, ex.Message);
            }
            finally
            {
                ConnectButton.IsEnabled = true;
            }
        }

        // ── 状态显示 ──────────────────────────────────────────────────────

        private void SetStatus(VpnConnectionState state, string extra = null)
        {
            switch (state)
            {
                case VpnConnectionState.Disconnected:
                    StatusLabel.Text = "未连接";
                    StatusEllipse.Stroke = new SolidColorBrush(Colors.Gray);
                    break;
                case VpnConnectionState.Connecting:
                    StatusLabel.Text = "连接中…";
                    StatusEllipse.Stroke = new SolidColorBrush(Colors.Orange);
                    break;
                case VpnConnectionState.Connected:
                    StatusLabel.Text = "已连接";
                    StatusEllipse.Stroke = new SolidColorBrush(Colors.Green);
                    break;
                case VpnConnectionState.Disconnecting:
                    StatusLabel.Text = "断开中…";
                    StatusEllipse.Stroke = new SolidColorBrush(Colors.Orange);
                    break;
                case VpnConnectionState.Error:
                    StatusLabel.Text = extra ?? "错误";
                    StatusEllipse.Stroke = new SolidColorBrush(Colors.Red);
                    break;
            }
        }

        // ── 流量统计定时刷新 ──────────────────────────────────────────────

        private void StartTrafficTimer()
        {
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += (s, e) => RefreshTraffic();
            _timer.Start();
        }

        private void RefreshTraffic()
        {
            // 插件把累计流量写入 LocalSettings（bytes_up / bytes_down），这里安全读取。
            var s = Windows.Storage.ApplicationData.Current.LocalSettings.Values;
            long up   = ReadLong(s, "bytes_up");
            long down = ReadLong(s, "bytes_down");

            AppState.Current.BytesUp   = up;
            AppState.Current.BytesDown = down;

            UploadLabel.Text   = FormatBytes(up);
            DownloadLabel.Text = FormatBytes(down);
        }

        private static long ReadLong(Windows.Foundation.Collections.IPropertySet s, string key)
        {
            if (!s.ContainsKey(key)) return 0;
            try { return Convert.ToInt64(s[key]); }
            catch { return 0; }
        }

        private static string FormatBytes(long b)
        {
            if (b < 1024)       return $"{b} B";
            if (b < 1024*1024)  return $"{b/1024.0:F1} KB";
            return $"{b/1024.0/1024.0:F1} MB";
        }

        // ── 配置信息 ──────────────────────────────────────────────────────

        private void RefreshConfigInfo()
        {
            if (_config == null) return;
            ConfigFileLabel.Text = AppState.Current.ConfigFileName ?? "已加载";
            NodeCountLabel.Text  = _config.Proxies.Count.ToString();
            RuleCountLabel.Text  = _config.Rules.Count.ToString();
        }

        private void RefreshNodeLabel()
        {
            _selectedNode = AppState.Current.SelectedNode;
            NodeLabel.Text = _selectedNode != null
                ? $"{_selectedNode.Name}  ({_selectedNode.Type.ToUpperInvariant()})"
                : "未选择节点 - 点击连接按钮选择";
        }

        // ── 导航 ──────────────────────────────────────────────────────────

        private void OnSettingsClick(object sender, RoutedEventArgs e)
            => Frame.Navigate(typeof(SettingsPage));

        private void NavHome_Click(object sender, RoutedEventArgs e)  { /* 已在主页 */ }
        private void NavNodes_Click(object sender, RoutedEventArgs e) => Frame.Navigate(typeof(NodesPage));
        private void NavConfig_Click(object sender, RoutedEventArgs e) => Frame.Navigate(typeof(ConfigPage));

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            _timer?.Stop();
        }
    }
}
