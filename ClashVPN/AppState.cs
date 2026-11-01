using ClashVPN.Models;

namespace ClashVPN
{
    /// <summary>
    /// 跨页面共享状态，替代全局静态变量。
    /// </summary>
    public class AppState
    {
        private static AppState _instance;
        public static AppState Current => _instance ?? (_instance = new AppState());

        public ClashConfig Config         { get; set; }
        public string      ConfigFileName { get; set; }
        public ProxyNode   SelectedNode   { get; set; }

        // 流量统计（由 VPN Plugin 写入 LocalSettings，主 App 定时读取）
        public long BytesUp   { get; set; }
        public long BytesDown { get; set; }
    }
}
