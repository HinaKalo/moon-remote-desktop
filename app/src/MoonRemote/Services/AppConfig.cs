namespace MoonRemote.Services;

public static class AppConfig
{
    public const string DefaultServerUrl = "https://remote.moonl.cloud";
    public const string SsoIssuer = "https://sso.moonl.cloud";
    public const string DesktopClientId = "ms_PTyfu8NoBmsYspSFmqdu";
    public const string SsoScope = "openid profile offline_access";
    public const string SsoResource = "https://remote.moonl.cloud";
    public const string ReleaseBaseUrl = "https://release.moonl.cloud/v1/apps/moon-remote/windows-x64";

    public static string ServerUrl { get; set; } =
        Environment.GetEnvironmentVariable("MRD_SERVER_URL") is { Length: > 0 } u ? u : DefaultServerUrl;
}
