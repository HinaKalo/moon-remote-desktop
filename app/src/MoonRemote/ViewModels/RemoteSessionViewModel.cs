using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MoonRemote.Models;
using MoonRemote.Services;

namespace MoonRemote.ViewModels;

public sealed partial class RemoteSessionViewModel : ViewModelBase, IDisposable
{
    private readonly string _addr;
    private readonly string _hostPublicKey;
    private nint _hwnd;
    private readonly DeviceItem? _device;
    private readonly RememberedHost? _rememberedHost;
    private readonly CancellationTokenSource _closed = new();
    private string? _pendingPin;
    private string? _sessionId;
    private string? _viewerDeviceId;
    private HostPairing? _offeredPairing;
    private bool _rememberRequested;
    private bool _retryWithPin;
    private uint _presentedDisplayId;
    private uint _announcedDisplayId = 1;
    private bool _updatingDisplays;

    [ObservableProperty] private string _hostName;
    [ObservableProperty] private string _connectionState = "Connecting...";
    [ObservableProperty] private bool _showPinPrompt;
    [ObservableProperty] private bool _canReconnect;
    [ObservableProperty] private string _pinInput = string.Empty;
    [ObservableProperty] private bool _rememberDevice = true;
    [ObservableProperty] private bool _useControllerMouse = true;
    [ObservableProperty] private string _bannerMessage = string.Empty;
    [ObservableProperty] private DisplayInfo? _selectedDisplay;

    [ObservableProperty] private double _videoAspect = 16d / 9;
    [ObservableProperty] private bool _inputEnabled;
    [ObservableProperty] private bool _canSelectDisplay;
    private bool _displaySwitchSupported;

    public ObservableCollection<DisplayInfo> Displays { get; } = [];
    public bool CanRememberDevice => _rememberedHost is not null;

    public RemoteSessionViewModel(string hostName, string addr, string hostPublicKey)
    {
        _hostName = hostName;
        _addr = addr;
        _hostPublicKey = hostPublicKey;
        AppServices.Native.EventReceived += OnNativeEvent;
    }

    public RemoteSessionViewModel(DeviceItem device)
        : this(device.Name, "", device.PublicKey)
    {
        _device = device;
        if (OperatingSystem.IsWindows() && AppServices.Sso.CurrentSession is { } account)
        {
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MoonRemote");
            _rememberedHost = new RememberedHost(directory, AppConfig.ServerUrl, account.UserSub, device);
        }
    }

    public async Task AttachHwndAndConnectAsync(nint hwnd)
    {
        _hwnd = hwnd;
        CanReconnect = false;
        BannerMessage = string.Empty;
        ConnectionState = "Connecting…";
        if (_device is not null)
        {
            _offeredPairing = _rememberedHost?.Load();
            if (_offeredPairing is null) PromptForPin();
            else await ConnectDeviceAsync(_device, null);
            return;
        }
        // Generate an ephemeral viewer key if none persisted yet; in production this uses
        // the viewer device key registered with the server.
        var keyResp = AppServices.Native.Call("""{"method":"generate_device_key"}""");
        using var kdoc = JsonDocument.Parse(keyResp);
        if (!kdoc.RootElement.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
        {
            ConnectionState = "Native engine unavailable";
            CanReconnect = true;
            return;
        }
        var seed = kdoc.RootElement.GetProperty("result").GetProperty("seed").GetString()!;
        try
        {
            StartConnection(new FfiConnectParams(_addr, _hostPublicKey, seed, "viewer-local", Environment.MachineName, (ulong)_hwnd));
        }
        catch (IOException ex)
        {
            ConnectionState = "Could not connect";
            BannerMessage = ex.Message;
            CanReconnect = true;
        }
    }

    [RelayCommand]
    private Task ReconnectAsync() => CanReconnect && !_closed.IsCancellationRequested
        ? AttachHwndAndConnectAsync(_hwnd)
        : Task.CompletedTask;

    private void StartConnection(FfiConnectParams connection)
    {
        _sessionId = Guid.NewGuid().ToString("N");
        _viewerDeviceId = connection.ViewerDeviceId;
        _rememberRequested = false;
        _retryWithPin = false;
        var req = JsonSerializer.Serialize(
            new FfiRequest<FfiConnectParams>(
                "connect",
                connection with { ClientSessionId = _sessionId }),
            AppJsonContext.Default.FfiRequestFfiConnectParams);
        try { DeviceConnection.NativeResult(req); }
        catch
        {
            _sessionId = null;
            throw;
        }
    }

    [RelayCommand]
    private async Task SubmitPinAsync()
    {
        if (PinInput.Length is < 6 or > 12 || !PinInput.All(char.IsAsciiDigit)) return;
        var pin = PinInput;
        PinInput = string.Empty;
        ShowPinPrompt = false;
        BannerMessage = string.Empty;
        if (_sessionId is null && _device is not null)
        {
            await ConnectDeviceAsync(_device, pin);
            return;
        }
        SendPin(pin);
    }

    private async Task ConnectDeviceAsync(DeviceItem device, string? pin)
    {
        ShowPinPrompt = false;
        ConnectionState = "Connecting…";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_closed.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(35));
        try
        {
            var connection = await DeviceConnection.PrepareAsync(device, timeout.Token);
            timeout.Token.ThrowIfCancellationRequested();
            if (_offeredPairing is { } pairing && pairing.ViewerDeviceId != connection.ViewerDeviceId)
            {
                ForgetOfferedPairing();
                PromptForPin();
                return;
            }
            _pendingPin = pin;
            StartConnection(connection with
            {
                Hwnd = (ulong)_hwnd,
                PairingId = _offeredPairing?.Id,
                PairingKey = _offeredPairing?.Key,
            });
        }
        catch (OperationCanceledException) when (_closed.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _pendingPin = null;
            ConnectionState = "Could not connect";
            BannerMessage = ex is OperationCanceledException ? "Connection timed out." : ex.Message;
            CanReconnect = true;
        }
    }

    private void PromptForPin()
    {
        ShowPinPrompt = true;
        ConnectionState = "Enter host PIN";
    }

    private void ForgetOfferedPairing()
    {
        if (_offeredPairing is { } pairing) _rememberedHost?.Forget(pairing);
        _offeredPairing = null;
    }

    private void SendPin(string pin)
    {
        _rememberRequested = RememberDevice && CanRememberDevice;
        var req = JsonSerializer.Serialize(
            new FfiRequest<FfiSubmitPinParams>(
                "submit_pin",
                new FfiSubmitPinParams(pin, _rememberRequested, Environment.MachineName)),
            AppJsonContext.Default.FfiRequestFfiSubmitPinParams);
        try
        {
            DeviceConnection.NativeResult(req);
            ShowPinPrompt = false;
            ConnectionState = "Authenticating…";
        }
        catch (IOException ex)
        {
            BannerMessage = ex.Message;
            if (_device is not null) PromptForPin();
        }
    }

    [RelayCommand]
    private void SendCtrlAltDel() =>
        AppServices.Native.Call("""{"method":"send_special","params":{"kind":"ctrl_alt_del"}}""");

    [RelayCommand]
    private void LockHost() =>
        AppServices.Native.Call("""{"method":"send_special","params":{"kind":"lock"}}""");

    [RelayCommand]
    private void Disconnect() =>
        AppServices.Native.Call("""{"method":"disconnect"}""");

    public void SendPointer(uint x, uint y, int button, bool pressed, int wheelX, int wheelY)
    {
        if (_presentedDisplayId == 0 || !CanSelectDisplay && _displaySwitchSupported) return;
        var req = JsonSerializer.Serialize(
            new FfiRequest<FfiPointerParams>(
                "send_pointer",
                new FfiPointerParams(_presentedDisplayId, x, y, button, pressed, wheelX, wheelY)),
            AppJsonContext.Default.FfiRequestFfiPointerParams);
        AppServices.Native.Call(req);
    }

    public bool SendKey(uint scancode, bool pressed) => SendKey(new FfiKeyParams(scancode, false, pressed));

    public bool SendText(string text) => SendKey(new FfiKeyParams(0, false, false, text));

    private bool SendKey(FfiKeyParams key)
    {
        if (!InputEnabled) return false;
        var req = JsonSerializer.Serialize(
            new FfiRequest<FfiKeyParams>("send_key", key),
            AppJsonContext.Default.FfiRequestFfiKeyParams);
        using var response = JsonDocument.Parse(AppServices.Native.Call(req));
        return response.RootElement.TryGetProperty("ok", out var ok) && ok.GetBoolean();
    }

    partial void OnSelectedDisplayChanged(DisplayInfo? value)
    {
        if (_updatingDisplays || !CanSelectDisplay || value is null || value.Id == _presentedDisplayId) return;
        var req = JsonSerializer.Serialize(
            new FfiRequest<FfiSelectDisplayParams>(
                "select_display",
                new FfiSelectDisplayParams(value.Id)),
            AppJsonContext.Default.FfiRequestFfiSelectDisplayParams);
        try
        {
            DeviceConnection.NativeResult(req);
            CanSelectDisplay = false;
            ConnectionState = "Switching display…";
        }
        catch (Exception ex)
        {
            SelectConfirmedDisplay(_presentedDisplayId);
            BannerMessage = $"Could not switch display: {ex.Message}";
        }
    }

    private void SelectConfirmedDisplay(uint id)
    {
        _updatingDisplays = true;
        SelectedDisplay = Displays.FirstOrDefault(d => d.Id == id);
        _updatingDisplays = false;
    }

    private void OnNativeEvent(JsonDocument doc)
    {
        var root = doc.RootElement;
        var sessionId = root.TryGetProperty("clientSessionId", out var sid) ? sid.GetString() : null;
        if (sessionId is null) return;
        var type = root.TryGetProperty("type", out var t) ? t.GetString() : null;
        var raw = root.GetRawText();
        Dispatcher.UIThread.Post(() =>
        {
            if (_closed.IsCancellationRequested || sessionId != _sessionId) return;
            using var parsed = JsonDocument.Parse(raw);
            var r = parsed.RootElement;
            switch (type)
            {
                case "state" when r.TryGetProperty("state", out var state) && state.GetString() == "retrying_transport":
                    ConnectionState = "Retrying the network connection…";
                    break;
                case "need_secret":
                    if (_offeredPairing is not null)
                    {
                        ForgetOfferedPairing();
                        BannerMessage = "This host no longer recognizes the saved pairing. Enter its PIN again.";
                    }
                    if (_pendingPin is { } pin)
                    {
                        _pendingPin = null;
                        SendPin(pin);
                        break;
                    }
                    PromptForPin();
                    break;
                case "connected":
                    BannerMessage = string.Empty;
                    InputEnabled = true;
                    CanReconnect = false;
                    ShowPinPrompt = false;
                    ConnectionState = "Connected";
                    break;
                case "pairing_granted":
                    if (_rememberRequested && _rememberedHost is { } store && _viewerDeviceId is { } id)
                    {
                        _rememberRequested = false;
                        try
                        {
                            store.Save(new(id, r.GetProperty("pairingId").GetString()!, r.GetProperty("pairingKey").GetString()!));
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
                        {
                            BannerMessage = "Could not save the pairing on this PC. The host PIN will be needed next time.";
                        }
                    }
                    break;
                case "pairing_declined":
                    if (_rememberRequested)
                        BannerMessage = "The host could not save this pairing. Its PIN will be needed next time.";
                    _rememberRequested = false;
                    break;
                case "video_started":
                    ConnectionState = "Connected · video active";
                    if (r.TryGetProperty("width", out var width) && r.TryGetProperty("height", out var height) && height.GetUInt32() > 0)
                        VideoAspect = (double)width.GetUInt32() / height.GetUInt32();
                    _presentedDisplayId = r.TryGetProperty("displayId", out var displayed) ? displayed.GetUInt32() : _announcedDisplayId;
                    _displaySwitchSupported = r.TryGetProperty("canSwitchDisplay", out var switchable) && switchable.GetBoolean();
                    SelectConfirmedDisplay(_presentedDisplayId);
                    CanSelectDisplay = _displaySwitchSupported;
                    break;
                case "auth_failed":
                    BannerMessage = $"Authentication failed: {(r.TryGetProperty("reason", out var ar) ? ar.GetString() : "")}";
                    _retryWithPin = _device is not null && r.TryGetProperty("retryWithPin", out var retry) && retry.GetBoolean();
                    if (_retryWithPin && _offeredPairing is not null)
                    {
                        ForgetOfferedPairing();
                        BannerMessage = "The saved pairing could not be verified. Enter the host PIN again.";
                    }
                    break;
                case "notice":
                    BannerMessage = r.TryGetProperty("message", out var nm) ? nm.GetString() ?? "" : "";
                    break;
                case "displays":
                    if (r.TryGetProperty("displays", out var arr))
                    {
                        var list = JsonSerializer.Deserialize(arr.GetRawText(), AppJsonContext.Default.ListDisplayInfo);
                        if (list is not null)
                        {
                            _announcedDisplayId = r.GetProperty("activeId").GetUInt32();
                            _updatingDisplays = true;
                            Displays.Clear();
                            foreach (var d in list) Displays.Add(d);
                            SelectConfirmedDisplay(_announcedDisplayId);
                        }
                    }
                    break;
                case "disconnected":
                    bool promptAgain = _device is not null && (ShowPinPrompt || _retryWithPin);
                    _sessionId = null;
                    InputEnabled = false;
                    CanSelectDisplay = false;
                    _displaySwitchSupported = false;
                    _presentedDisplayId = 0;
                    _pendingPin = null;
                    ConnectionState = $"Disconnected ({(r.TryGetProperty("reason", out var dr) ? dr.GetString() : "closed")})";
                    ShowPinPrompt = false;
                    if (promptAgain) PromptForPin();
                    else CanReconnect = true;
                    break;
            }
        });
    }

    public void Dispose()
    {
        _closed.Cancel();
        _pendingPin = null;
        AppServices.Native.EventReceived -= OnNativeEvent;
        if (_sessionId is not null) Disconnect();
    }
}
