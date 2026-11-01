using System;
using ClashVPN.Pages;
using ClashVPN.Services;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Storage;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;

namespace ClashVPN
{
    sealed partial class App : Application
    {
        public App() { InitializeComponent(); Suspending += OnSuspending; }

        protected override async void OnLaunched(LaunchActivatedEventArgs e)
        {
            Frame rootFrame = Window.Current.Content as Frame;

            if (rootFrame == null)
            {
                rootFrame = new Frame();
                rootFrame.NavigationFailed += OnNavigationFailed;
                Window.Current.Content = rootFrame;
            }

            if (e.PrelaunchActivated) return;

            // 启动时尝试加载上次缓存的配置
            await TryLoadCachedConfig();

            if (rootFrame.Content == null)
                rootFrame.Navigate(typeof(HomePage), null);

            Window.Current.Activate();
        }

        private static async System.Threading.Tasks.Task TryLoadCachedConfig()
        {
            try
            {
                var local = ApplicationData.Current.LocalFolder;
                var file   = await local.GetFileAsync("clash_config.yaml");
                string text = await FileIO.ReadTextAsync(file);
                var config  = ConfigLoader.LoadText(text, file.Name);
                AppState.Current.Config         = config;
                AppState.Current.ConfigFileName = file.Name;
            }
            catch { /* 没有缓存，忽略 */ }
        }

        void OnNavigationFailed(object sender, NavigationFailedEventArgs e)
        {
            // 不再硬崩溃：记录失败并标记已处理，避免在发布版给用户一个无提示的闪退。
            System.Diagnostics.Debug.WriteLine(
                "Navigation failed for page " + e.SourcePageType?.FullName + ": " + e.Exception);
            e.Handled = true;
        }

        void OnSuspending(object sender, SuspendingEventArgs e)
        {
            var d = e.SuspendingOperation.GetDeferral();
            d.Complete();
        }
    }
}
