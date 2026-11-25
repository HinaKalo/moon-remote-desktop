using MoonRemote.Views;
using MoonRemote.Services;
using Lumen.UI.Controls;
using Lumen.UI.Icons;

namespace MoonRemote.ViewModels;

public partial class MainWindowViewModel : ViewModelBase
{
    public string AppVersionText { get; } =
        $"v{typeof(MainWindowViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.1.0"}";

    /// <summary>Sidebar navigation. Each page is created lazily and cached by the AppShell.</summary>
    public IReadOnlyList<NavItem> NavItems { get; } =
    [
        NavItem.Header(OnboardingText.For("REMOTE", "远程控制")),
        new(OnboardingText.Devices, IconKind.Home, () => new DevicesPage { DataContext = new DevicesPageViewModel() }) { Tag = "devices" },
        new(OnboardingText.ThisPc, IconKind.Lock, () => new HostPage { DataContext = new HostPageViewModel() }),
        new(OnboardingText.For("Support", "远程协助"), IconKind.Users, () => new SupportPage { DataContext = new SupportPageViewModel() }),
        NavItem.Header(OnboardingText.For("SYSTEM", "系统")),
        new(OnboardingText.For("Settings", "设置"), IconKind.Settings, () => new SettingsPage { DataContext = new SettingsPageViewModel() }),
    ];
}
