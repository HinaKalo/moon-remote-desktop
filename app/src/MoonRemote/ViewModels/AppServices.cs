using MoonRemote.Services;

namespace MoonRemote.ViewModels;

/// <summary>Shared application services for ViewModels.</summary>
public static class AppServices
{
    public static SsoService Sso { get; } = new();
    public static ServerApiClient Api { get; } = new(Sso);
    public static ServicePipeClient Pipe { get; } = new();
    public static NativeBridge Native { get; } = new();
    public static UpdateService Updates { get; } = new(Native);

    private static bool _initialized;

    public static void EnsureInitialized()
    {
        if (_initialized) return;
        _initialized = true;
        Native.Initialize();
    }
}
