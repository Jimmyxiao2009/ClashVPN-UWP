using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;

namespace ClashVPN.Pages
{
    public sealed partial class SettingsPage : Page
    {
        public SettingsPage() => InitializeComponent();

        private void OnBackClick(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            if (Frame.CanGoBack) Frame.GoBack();
        }
    }
}
