using System.Runtime.InteropServices;
using System.Text.Json;

namespace MoonRemote.Services;

/// <summary>
/// P/Invoke bridge to `moonrd_ffi.dll` (native viewer QUIC session, H.264 DXVA decode,
/// D3D11 HWND rendering, EasyTier diagnostics).
/// </summary>
public sealed partial class NativeBridge : IDisposable
{
    private const string DllName = "moonrd_ffi";
    private readonly CancellationTokenSource _cts = new();
    private bool _available;

    public event Action<JsonDocument>? EventReceived;
    public bool IsAvailable => _available;

    [LibraryImport(DllName)]
    private static partial int moonrd_init();

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr moonrd_call(string reqJson);

    [LibraryImport(DllName)]
    private static partial IntPtr moonrd_next_event(uint timeoutMs);

    [LibraryImport(DllName)]
    private static partial void moonrd_free_str(IntPtr ptr);

    [LibraryImport(DllName)]
    private static partial void moonrd_shutdown();

    public void Initialize()
    {
        try
        {
            _available = moonrd_init() == 0;
            if (_available)
            {
                _ = Task.Run(PumpEventsAsync, _cts.Token);
            }
        }
        catch (DllNotFoundException)
        {
            _available = false;
        }
    }

    public string Call(string requestJson)
    {
        if (!_available)
            return """{"ok":false,"error":"moonrd_ffi.dll not loaded"}""";
        var ptr = moonrd_call(requestJson);
        if (ptr == IntPtr.Zero)
            return """{"ok":false,"error":"null response"}""";
        try
        {
            return Marshal.PtrToStringUTF8(ptr) ?? "{}";
        }
        finally
        {
            moonrd_free_str(ptr);
        }
    }

    private async Task PumpEventsAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            var ptr = moonrd_next_event(200);
            if (ptr == IntPtr.Zero)
            {
                await Task.Delay(10, _cts.Token);
                continue;
            }
            string? json;
            try
            {
                json = Marshal.PtrToStringUTF8(ptr);
            }
            finally
            {
                moonrd_free_str(ptr);
            }
            if (!string.IsNullOrEmpty(json))
            {
                try
                {
                    using var doc = JsonDocument.Parse(json);
                    EventReceived?.Invoke(doc);
                }
                catch { }
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        if (_available)
        {
            try { moonrd_shutdown(); } catch { }
        }
        _cts.Dispose();
    }
}
