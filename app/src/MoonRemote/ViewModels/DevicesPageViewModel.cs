using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MoonRemote.Models;
using MoonRemote.Services;
using MoonRemote.Views;

namespace MoonRemote.ViewModels;

public sealed partial class DevicesPageViewModel : ViewModelBase
{
    [ObservableProperty] private bool _isSignedIn;
    [ObservableProperty] private string _userDisplayName = OnboardingText.For("Not signed in", "未登录");
    [ObservableProperty] private string _statusMessage = OnboardingText.For("Sign in with your Moon account to see your devices.", "登录 Moon 账号后可查看设备。");
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _lanAddress = string.Empty;
    [ObservableProperty] private string _lanHostKey = string.Empty;
    [ObservableProperty] private string _deviceSearch = string.Empty;

    private readonly List<DeviceItem> _devices = [];

    public IEnumerable<DeviceItem> VisibleDevices
    {
        get
        {
            var filter = DeviceSearch.Trim();
            return _devices.Where(d => d.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                d.Id.Contains(filter, StringComparison.OrdinalIgnoreCase));
        }
    }
    public bool HasDevices => _devices.Count != 0;
    public bool NoSearchResults => HasDevices && !VisibleDevices.Any();

    public DevicesPageViewModel()
    {
        AppServices.EnsureInitialized();
        AppServices.Sso.SessionChanged += SyncSession;
        SyncSession();
        if (IsSignedIn)
        {
            _ = RefreshCommand.ExecuteAsync(null);
        }
    }

    partial void OnDeviceSearchChanged(string value) => UpdateVisibleDevices();

    private void UpdateVisibleDevices()
    {
        OnPropertyChanged(nameof(HasDevices));
        OnPropertyChanged(nameof(VisibleDevices));
        OnPropertyChanged(nameof(NoSearchResults));
    }

    private void SyncSession()
    {
        var s = AppServices.Sso.CurrentSession;
        IsSignedIn = s is not null;
        UserDisplayName = s is null ? OnboardingText.For("Not signed in", "未登录")
            : OnboardingText.For($"Signed in as {s.DisplayName}", $"已登录：{s.DisplayName}");
        if (!IsSignedIn)
        {
            _devices.Clear();
            DeviceSearch = string.Empty;
            UpdateVisibleDevices();
            StatusMessage = AppServices.Sso.SessionExpired
                ? OnboardingText.For("Your Moon session expired. Sign in again to reload your devices.", "Moon 登录已过期，请重新登录以加载设备。")
                : OnboardingText.For("Sign in with your Moon account to view and control your devices.", "登录 Moon 账号后即可查看和控制设备。");
        }
    }

    [RelayCommand]
    private async Task SignInAsync()
    {
        IsBusy = true;
        StatusMessage = OnboardingText.For("Complete Moon sign-in in your browser…", "请在浏览器中完成 Moon 登录…");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        try
        {
            await AppServices.Sso.SignInAsync(timeout.Token, status => StatusMessage = status);
            await RefreshAsync();
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            StatusMessage = OnboardingText.For("Sign-in timed out. Select Sign in with Moon SSO to try again.", "登录超时，请点击「登录 Moon 账号」重试。");
        }
        catch (Exception ex)
        {
            StatusMessage = OnboardingText.For($"Sign-in failed: {ex.Message}", $"登录失败。{ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task SignOutAsync()
    {
        IsBusy = true;
        try
        {
            await AppServices.Sso.SignOutAsync();
            StatusMessage = OnboardingText.For("Signed out.", "已退出登录。");
        }
        catch (Exception ex)
        {
            StatusMessage = $"Sign-out failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (!IsSignedIn) return;
        IsBusy = true;
        StatusMessage = OnboardingText.For("Loading devices…", "正在加载设备…");
        try
        {
            var list = await AppServices.Api.ListDevicesAsync();
            if (!IsSignedIn) return;
            _devices.Clear();
            _devices.AddRange(list);
            UpdateVisibleDevices();
            StatusMessage = list.Count == 0
                ? OnboardingText.For("No devices registered yet. Enable remote access on the This PC page.", "还没有注册设备。可在「本机被控」页启用远程控制。")
                : OnboardingText.For($"{list.Count} device(s), {list.Count(d => d.Online)} online.", $"共 {list.Count} 台设备，{list.Count(d => d.Online)} 台在线。");
        }
        catch (Exception ex)
        {
            if (IsSignedIn)
                StatusMessage = OnboardingText.For($"Failed to load devices. Select Refresh to retry. {ex.Message}", $"设备加载失败，请点击刷新重试。{ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ConnectDevice(DeviceItem? device)
    {
        if (device is null) return;
        if (device.Kind != "host")
        {
            StatusMessage = "Select a host to connect.";
            return;
        }
        ShowSession(new RemoteSessionViewModel(device));
    }

    private RemoteSessionWindow? _session;
    private void ShowSession(RemoteSessionViewModel model)
    {
        _session?.Close();
        _session = new RemoteSessionWindow { DataContext = model };
        _session.Closed += (_, _) => _session = null;
        _session.Show();
    }

    [RelayCommand]
    private void ConnectLan()
    {
        if (string.IsNullOrWhiteSpace(LanAddress) || string.IsNullOrWhiteSpace(LanHostKey))
        {
            StatusMessage = "Enter both host IP:port and host public key for direct LAN connection.";
            return;
        }
        ShowSession(new RemoteSessionViewModel(LanAddress.Trim(), LanAddress.Trim(), LanHostKey.Trim()));
    }

    [RelayCommand]
    private async Task RemoveDeviceAsync(DeviceItem? device)
    {
        if (device is null) return;
        IsBusy = true;
        try
        {
            await AppServices.Api.DeleteDeviceAsync(device.Id);
            _devices.Remove(device);
            UpdateVisibleDevices();
            StatusMessage = $"Removed {device.Name}.";
        }
        catch (Exception ex)
        {
            if (IsSignedIn)
                StatusMessage = $"Remove failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
