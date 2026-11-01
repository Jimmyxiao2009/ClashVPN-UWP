using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using ClashVPN.Models;
using ClashVPN.Services;
using Windows.UI;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

namespace ClashVPN.Pages
{
    public sealed partial class NodesPage : Page
    {
        private ClashConfig _config;
        private VpnManager  _vpn;
        private ObservableCollection<NodeViewModel> _nodes = new ObservableCollection<NodeViewModel>();

        public NodesPage()
        {
            InitializeComponent();
            _vpn = new VpnManager();
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            _config = AppState.Current.Config;
            if (_config == null) return;

            NodeList.ItemsSource = _nodes;

            // 填充代理组列表
            GroupCombo.Items.Clear();
            GroupCombo.Items.Add("── 所有节点 ──");
            foreach (var g in _config.ProxyGroups)
                GroupCombo.Items.Add(g.Name);

            GroupCombo.SelectedIndex = 0;
            LoadNodes(null);
        }

        // ── 节点加载 ──────────────────────────────────────────────────────

        private void OnGroupChanged(object sender, SelectionChangedEventArgs e)
        {
            if (GroupCombo.SelectedIndex <= 0)
                LoadNodes(null);
            else
                LoadNodes((string)GroupCombo.SelectedItem);
        }

        private void LoadNodes(string groupName)
        {
            _nodes.Clear();

            System.Collections.Generic.List<ProxyNode> proxies;

            if (groupName == null)
            {
                proxies = _config.Proxies;
            }
            else
            {
                proxies = _vpn.ResolveGroupNodes(_config, groupName);
            }

            foreach (var p in proxies)
                _nodes.Add(new NodeViewModel(p));
        }

        // ── 延迟测试 ──────────────────────────────────────────────────────

        private async void OnTestAllClick(object sender, RoutedEventArgs e)
        {
            var btn = sender as Button;
            if (btn != null) btn.IsEnabled = false;   // 测试期间禁用，避免重复触发/看似卡死
            try
            {
                var nodes = new System.Collections.Generic.List<ProxyNode>();
                foreach (var vm in _nodes) nodes.Add(vm.Node);

                var results = await _vpn.TestLatencyAsync(nodes, timeoutMs: 3000);
                var dict    = new System.Collections.Generic.Dictionary<string, int>();
                foreach (var (node, ms) in results)
                    dict[node.Name] = ms;

                foreach (var vm in _nodes)
                    if (dict.ContainsKey(vm.Name))
                        vm.SetLatency(dict[vm.Name]);
            }
            finally
            {
                if (btn != null) btn.IsEnabled = true;
            }
        }

        // ── 选择节点 ──────────────────────────────────────────────────────

        private void OnNodeClick(object sender, ItemClickEventArgs e)
        {
            if (!(e.ClickedItem is NodeViewModel vm)) return;

            AppState.Current.SelectedNode = vm.Node;

            // 标记选中
            foreach (var n in _nodes) n.IsSelected = false;
            vm.IsSelected = true;

            // 返回主页
            if (Frame.CanGoBack) Frame.GoBack();
        }

        private void OnBackClick(object sender, RoutedEventArgs e)
        {
            if (Frame.CanGoBack) Frame.GoBack();
        }
    }

    // ── ViewModel ─────────────────────────────────────────────────────────

    public class NodeViewModel : INotifyPropertyChanged
    {
        public ProxyNode Node { get; }
        public string Name   => Node.Name;
        public string Type   => Node.Type?.ToUpperInvariant() ?? "?";
        public string Server => Node.Server;
        public int    Port   => Node.Port;

        private int    _latencyMs  = -1;
        private bool   _isSelected;

        public NodeViewModel(ProxyNode node) { Node = node; }

        public string LatencyText
        {
            get
            {
                if (_latencyMs < 0)       return "–";
                if (_latencyMs == int.MaxValue) return "超时";
                return $"{_latencyMs} ms";
            }
        }

        public SolidColorBrush LatencyColor
        {
            get
            {
                if (_latencyMs < 0)                return new SolidColorBrush(Colors.Gray);
                if (_latencyMs == int.MaxValue)    return new SolidColorBrush(Colors.Red);
                if (_latencyMs < 150)              return new SolidColorBrush(Colors.Green);
                if (_latencyMs < 300)              return new SolidColorBrush(Colors.Orange);
                return new SolidColorBrush(Colors.Red);
            }
        }

        public bool IsSelected
        {
            get => _isSelected;
            set { _isSelected = value; OnPropertyChanged(nameof(IsSelected)); }
        }

        public void SetLatency(int ms)
        {
            _latencyMs = ms;
            OnPropertyChanged(nameof(LatencyText));
            OnPropertyChanged(nameof(LatencyColor));
        }

        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged(string name)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
