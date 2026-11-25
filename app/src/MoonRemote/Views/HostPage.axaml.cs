using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using Lumen.UI.Controls;
using MoonRemote.ViewModels;

namespace MoonRemote.Views;

public partial class HostPage : UserControl
{
    public HostPage()
    {
        InitializeComponent();
        CancellationTokenSource? polling = null;
        Loaded += (_, _) =>
        {
            if (DataContext is not HostPageViewModel vm || polling != null) return;
            polling = new CancellationTokenSource();
            _ = vm.PollNetworkAsync(polling.Token);
        };
        Unloaded += (_, _) => { polling?.Cancel(); polling?.Dispose(); polling = null; };
    }

    private async void OnSignInClick(object? sender, RoutedEventArgs e)
    {
        var shell = this.GetVisualAncestors().OfType<AppShell>().FirstOrDefault();
        if (shell?.Navigate("devices") == true &&
            shell.CurrentPage is DevicesPage { DataContext: DevicesPageViewModel { IsSignedIn: false } devices } &&
            devices.SignInCommand.CanExecute(null))
            await devices.SignInCommand.ExecuteAsync(null);
    }
}
