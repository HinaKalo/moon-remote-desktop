using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MoonRemote.Models;
using MoonRemote.Services;

namespace MoonRemote.ViewModels;

public sealed partial class HostPageViewModel : ViewModelBase
{
    [ObservableProperty] private bool _serviceRunning;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEnableHost))]
    private bool _isSignedIn;
    [ObservableProperty] private bool _isRegistered;
    [ObservableProperty] private bool _pinSet;
    [ObservableProperty] private bool _lanDirect;
    [ObservableProperty] private bool _callerIsAdmin;
    [ObservableProperty] private string _hostName = Environment.MachineName;
    [ObservableProperty] private string _pin = string.Empty;
    [ObservableProperty] private string _deviceId = "-";
    [ObservableProperty] private string _etStatus = OnboardingText.State("stopped");
    [ObservableProperty] private string _signalStatus = OnboardingText.State("disconnected");
    [ObservableProperty] private string _agentStatus = OnboardingText.State("not running");
    [ObservableProperty] private string _statusMessage = OnboardingText.For("Checking local host service…", "正在检查本机被控服务…");
    [ObservableProperty] private string _pinHint = OnboardingText.For("6 to 12 digits. Saved encrypted on this computer.", "请输入 6–12 位数字。PIN 会加密保存在本机。");
    [ObservableProperty] private string _saveButtonText = OnboardingText.For("Enable & Save PIN", "启用并保存 PIN");
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEnableHost))]
    private bool _isBusy;

    public bool CanEnableHost => IsSignedIn && !IsBusy;
    public string ServiceButtonText => HostRelease.IsInstalled
        ? OnboardingText.For("Start Host Service", "启动被控服务")
        : OnboardingText.InstallService;

    public HostPageViewModel()
    {
        AppServices.EnsureInitialized();
        AppServices.Sso.SessionChanged += SyncSession;
        SyncSession();
        _ = RefreshStatusCommand.ExecuteAsync(null);
    }

    private void SyncSession() => IsSignedIn = AppServices.Sso.IsSignedIn;

    [RelayCommand]
    private Task RefreshStatusAsync() => RefreshStatusCoreAsync(preserveMessage: false);

    private async Task RefreshStatusCoreAsync(bool preserveMessage)
    {
        IsBusy = true;
        try
        {
            var resp = await AppServices.Pipe.CallAsync("status");
            if (!resp.Ok || resp.Result is not { } r)
            {
                ServiceRunning = false;
                if (!preserveMessage)
                    StatusMessage = resp.Error?.Message ?? "Failed to read host service status.";
                return;
            }
            ServiceRunning = true;
            IsRegistered = r.TryGetProperty("registered", out var reg) && reg.GetBoolean();
            PinSet = r.TryGetProperty("pinSet", out var ps) && ps.GetBoolean();
            PinHint = PinSet
                ? OnboardingText.For("A PIN is saved. Enter a new 6–12 digit PIN to change it.", "已加密保存 PIN。输入新的 6–12 位数字可更改。")
                : OnboardingText.For("6 to 12 digits. Saved encrypted on this computer.", "请输入 6–12 位数字。PIN 会加密保存在本机。");
            SaveButtonText = IsRegistered ? OnboardingText.For("Update PIN", "更新 PIN") : OnboardingText.For("Enable & Save PIN", "启用并保存 PIN");
            LanDirect = r.TryGetProperty("lanDirect", out var ld) && ld.GetBoolean();
            CallerIsAdmin = r.TryGetProperty("callerIsAdmin", out var adm) && adm.GetBoolean();
            DeviceId = r.TryGetProperty("deviceId", out var did) && did.ValueKind == JsonValueKind.String ? did.GetString()! : "-";
            if (r.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(n.GetString()))
                HostName = n.GetString()!;

            ReadNetworkStatus(r);
            if (!preserveMessage)
            {
                StatusMessage = IsRegistered
                    ? OnboardingText.For($"Host active ({DeviceId}).", $"本机已注册（{DeviceId}）。")
                    : OnboardingText.For("The host service is running. Set a PIN to enable remote access.", "被控服务正在运行。设置 PIN 后即可启用远程控制。");
            }
        }
        catch (Exception ex)
        {
            ServiceRunning = false;
            if (!preserveMessage)
                StatusMessage = OnboardingText.For($"Host service unreachable: {ex.Message}", $"本机被控服务暂不可用。{ex.Message}");
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(ServiceButtonText));
        }
    }

    internal async Task PollNetworkAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                if (IsBusy) continue;
                try
                {
                    var status = await AppServices.Pipe.CallAsync("status", null, ct);
                    if (status.Ok && status.Result is { } r && !IsBusy) ReadNetworkStatus(r);
                }
                catch (IOException) { EtStatus = SignalStatus = AgentStatus = OnboardingText.State("unavailable"); }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }

    private void ReadNetworkStatus(JsonElement r)
    {
        if (r.TryGetProperty("live", out var live) && live.ValueKind == JsonValueKind.Object)
        {
            AgentStatus = OnboardingText.State(live.TryGetProperty("agent", out var ag) ? ag.GetString() ?? "unknown" : "unknown");
            if (live.TryGetProperty("network", out var net) && net.ValueKind == JsonValueKind.Object)
            {
                if (net.TryGetProperty("et", out var et) && et.TryGetProperty("state", out var es))
                    EtStatus = OnboardingText.State(es.GetString() ?? "unknown");
                if (net.TryGetProperty("signal", out var sig) && sig.TryGetProperty("state", out var ss))
                    SignalStatus = OnboardingText.State(ss.GetString() ?? "unknown");
            }
        }
    }

    [RelayCommand]
    private async Task EnableHostAndSetPinAsync()
    {
        if (Pin.Length < 6 || Pin.Length > 12 || !Pin.All(char.IsAsciiDigit))
        {
            StatusMessage = OnboardingText.For("PIN must be 6 to 12 digits.", "PIN 必须是 6–12 位数字。");
            return;
        }
        if (!AppServices.Sso.IsSignedIn || AppServices.Sso.CurrentSession is not { } session)
        {
            StatusMessage = OnboardingText.SignInFirst;
            return;
        }

        IsBusy = true;
        try
        {
            StatusMessage = "Starting local host service...";
            await AppServices.Pipe.EnsureServiceRunningAsync();

            // 1. Ask server for single-use registration challenge.
            var challenge = await AppServices.Api.RequestChallengeAsync();

            // 2. Ask service to sign challenge (requires admin; triggers one UAC prompt if needed).
            var signParams = JsonSerializer.Serialize(
                new SignRegistrationParams(challenge.Nonce, session.UserSub, "host"),
                AppJsonContext.Default.SignRegistrationParams);
            var signResp = await AppServices.Pipe.CallAsync("sign_registration", signParams);
            if (!signResp.Ok && signResp.Error?.Code == "forbidden")
            {
                StatusMessage = "Requesting administrator permission (one UAC prompt)...";
                var token = await AppServices.Sso.GetValidAccessTokenAsync()
                    ?? throw new InvalidOperationException("Sign in required.");
                var tmpPath = Path.Combine(Path.GetTempPath(), $"moonrd-elev-{Guid.NewGuid():N}.json");
                var errPath = tmpPath + ".err";
                var payload = JsonSerializer.Serialize(
                    new ElevatedSetupPayload(AppConfig.ServerUrl, token, session.UserSub, HostName.Trim(), Pin),
                    AppJsonContext.Default.ElevatedSetupPayload);
                await File.WriteAllTextAsync(tmpPath, payload);
                try
                {
                    var code = await ServicePipeClient.RunElevatedAsync($"--elevated-setup \"{tmpPath}\"");
                    if (code == 0)
                    {
                        Pin = string.Empty;
                        StatusMessage = "Remote access enabled and PIN saved.";
                    }
                    else
                    {
                        var detail = File.Exists(errPath) ? await File.ReadAllTextAsync(errPath) : $"exit code {code}";
                        StatusMessage = $"Elevated setup failed: {detail}";
                    }
                }
                finally
                {
                    try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
                    try { if (File.Exists(errPath)) File.Delete(errPath); } catch { }
                }
                await RefreshStatusCoreAsync(preserveMessage: true);
                return;
            }
            if (!signResp.Ok || signResp.Result is not { } sr)
            {
                StatusMessage = signResp.Error?.Message ?? "Service refused to sign registration.";
                return;
            }

            var pubKey = sr.GetProperty("publicKey").GetString()!;
            var sig = sr.GetProperty("signature").GetString()!;

            // 3. Register host with moon-remote-server.
            var reg = await AppServices.Api.RegisterDeviceAsync(new RegisterDeviceRequest(
                HostName.Trim(),
                "host",
                pubKey,
                challenge.Nonce,
                sig));

            // 4. Persist registration and PIN in the service.
            var completeParams = JsonSerializer.Serialize(
                new CompleteRegistrationParams(
                    AppConfig.ServerUrl,
                    reg.Device.Id,
                    session.UserSub,
                    reg.Device.Name,
                    reg.DeviceToken,
                    reg.RosterKey,
                    reg.RosterKeyId),
                AppJsonContext.Default.CompleteRegistrationParams);
            var done = await AppServices.Pipe.CallAsync("complete_registration", completeParams);
            if (!done.Ok)
            {
                StatusMessage = done.Error?.Message ?? "Failed to save host registration.";
                return;
            }

            var pinResp = await AppServices.Pipe.CallAsync(
                "set_pin",
                JsonSerializer.Serialize(new SetPinParams(Pin), AppJsonContext.Default.SetPinParams));
            if (!pinResp.Ok)
            {
                StatusMessage = pinResp.Error?.Message ?? "Failed to set PIN.";
                return;
            }

            Pin = string.Empty;
            StatusMessage = "Remote access enabled and PIN saved.";
            await RefreshStatusAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Setup failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ToggleLanDirectAsync()
    {
        IsBusy = true;
        try
        {
            var resp = await AppServices.Pipe.CallAsync(
                "set_lan_direct",
                JsonSerializer.Serialize(new SetLanDirectParams(LanDirect), AppJsonContext.Default.SetLanDirectParams));
            StatusMessage = resp.Ok ? $"LAN direct {(LanDirect ? "enabled" : "disabled")}." : (resp.Error?.Message ?? "Failed.");
            await RefreshStatusAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task InstallSystemServiceAsync()
    {
        IsBusy = true;
        StatusMessage = OnboardingText.For("Preparing the Windows host service (administrator approval required)…", "正在准备本机被控服务，需要管理员确认…");
        try
        {
            var code = await ServicePipeClient.InstallSystemServiceAsync();
            StatusMessage = code == 0
                ? OnboardingText.For("Windows host service started.", "本机被控服务已启动。")
                : OnboardingText.For($"Host service exited with code {code}.", $"被控服务启动失败，错误代码 {code}。");
            await RefreshStatusCoreAsync(preserveMessage: code != 0);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Install failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task UnregisterAsync()
    {
        IsBusy = true;
        try
        {
            var resp = await AppServices.Pipe.CallAsync("unregister");
            StatusMessage = resp.Ok ? "Host unregistered." : (resp.Error?.Message ?? "Unregister failed.");
            await RefreshStatusAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Unregister failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
