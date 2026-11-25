using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Lumen.UI.Services;
using MoonRemote.Services;

namespace MoonRemote.ViewModels;

public partial class SettingsPageViewModel : ViewModelBase
{
    [ObservableProperty] private int _themeIndex = (int)ThemeManager.Mode;
    [ObservableProperty] private string _serverUrl = AppConfig.ServerUrl;
    [ObservableProperty] private string _diagnosticsText = "Click 'Run Diagnostics' to inspect local EasyTier coexistence.";
    [ObservableProperty] private string _updateStatus = $"Current build: {UpdateService.CurrentVersionCode}";
    [ObservableProperty] private bool _canInstallUpdate;
    [ObservableProperty] private bool _hasFullInstaller;
    [ObservableProperty] private bool _isCheckingUpdate;
    private MoonRemote.Models.RelhubManifest? _pendingManifest;
    private MoonRemote.Models.RelhubManifest? _fullInstaller;

    public IReadOnlyList<AccentPreset> Accents => ThemeManager.AccentPresets;
    public string BrowserDownloadText => OnboardingText.For("Download in browser", "在浏览器下载");

    partial void OnThemeIndexChanged(int value) => ThemeManager.SetMode((ThemeMode)value);

    partial void OnServerUrlChanged(string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            AppConfig.ServerUrl = value.Trim();
    }

    [RelayCommand]
    private void SetAccent(AccentPreset preset) => ThemeManager.SetAccent(preset.Color);

    [RelayCommand]
    private void RunDiagnostics()
    {
        AppServices.EnsureInitialized();
        DiagnosticsText = AppServices.Native.Call("""{"method":"detect_easytier"}""");
    }

    [RelayCommand]
    private async Task CheckForUpdatesAsync()
    {
        AppServices.EnsureInitialized();
        IsCheckingUpdate = true;
        UpdateStatus = OnboardingText.For("Checking for updates…", "正在检查更新…");
        try
        {
            var res = await AppServices.Updates.CheckAsync();
            _pendingManifest = res.UpdateAvailable ? res.Manifest : null;
            _fullInstaller = res.FullInstallerFallback;
            HasFullInstaller = _fullInstaller is not null;
            CanInstallUpdate = res.UpdateAvailable;
            UpdateStatus = res.Message;
        }
        catch (Exception ex)
        {
            UpdateStatus = OnboardingText.For($"Update check failed. {ex.Message}", $"检查更新失败。{ex.Message}");
            CanInstallUpdate = false;
            HasFullInstaller = false;
        }
        finally
        {
            IsCheckingUpdate = false;
        }
    }

    [RelayCommand]
    private Task InstallUpdateAsync() => InstallAsync(_pendingManifest);

    [RelayCommand]
    private Task InstallFullUpdateAsync() => InstallAsync(_fullInstaller);

    [RelayCommand]
    private void OpenBrowserDownload()
    {
        var platform = HostRelease.IsManagedApp(UpdateService.CurrentVersionCode)
            ? UpdateService.SetupPlatform : UpdateService.FullPlatform;
        var url = UpdateService.BrowserDownloadUrl(platform, CanInstallUpdate ? _pendingManifest : null);
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            UpdateStatus = OnboardingText.For($"Open this download address in your browser. {url}", $"请在浏览器中打开下载地址。{url}");
        }
    }

    private async Task InstallAsync(MoonRemote.Models.RelhubManifest? manifest)
    {
        if (manifest is null || IsCheckingUpdate) return;
        IsCheckingUpdate = true;
        UpdateStatus = $"Downloading v{manifest.VersionName} ({manifest.Size / (1024.0 * 1024):0.1} MB)...";
        try
        {
            if (manifest.Platform == UpdateService.SetupPlatform ||
                manifest.Platform == UpdateService.SetupDeltaPlatform(UpdateService.CurrentVersionCode))
            {
                await AppServices.Updates.LaunchInstallerAsync(manifest);
                Environment.Exit(0);
                return;
            }
            if (HostRelease.IsManagedApp(UpdateService.CurrentVersionCode) && HostRelease.IsInstalled)
            {
                var code = manifest.VersionCode;
                UpdateStatus = "Installing the verified host release (administrator approval required)...";
                if (await ServicePipeClient.RunElevatedAsync($"--update-host {code}") != 0)
                    throw new IOException("Host upgrade failed. Check for updates and retry.");
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(HostRelease.AppFor(code))
                {
                    UseShellExecute = false,
                    WorkingDirectory = Path.GetDirectoryName(HostRelease.AppFor(code))!,
                });
                Environment.Exit(0);
                return;
            }
            var zip = await AppServices.Updates.DownloadAndVerifyAsync(manifest);
            UpdateStatus = "Verified SHA-256. Applying update and restarting...";
            UpdateService.StageAndLaunchUpdater(zip);
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            UpdateStatus = $"Update failed: {ex.Message}";
        }
        finally
        {
            IsCheckingUpdate = false;
        }
    }
}
