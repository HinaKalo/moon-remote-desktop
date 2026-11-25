using System.Globalization;

namespace MoonRemote.Services;

public static class OnboardingText
{
    public static bool IsChinese => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "zh";
    public static string For(string english, string chinese) => IsChinese ? chinese : english;

    public static string Devices => For("Devices", "设备");
    public static string ThisPc => For("This PC", "本机被控");
    public static string Account => For("Account", "账号");
    public static string YourDevices => For("Your Devices", "我的设备");
    public static string DeviceSummary => For("Connect to an online host on your account.", "可连接此账号下的在线被控电脑。");
    public static string SignIn => For("Sign in with Moon SSO", "登录 Moon 账号");
    public static string SignOut => For("Sign out", "退出登录");
    public static string Refresh => For("Refresh", "刷新");
    public static string RemoteAccess => For("Enable Remote Access", "启用远程控制");
    public static string HostSetupHint => For("Register this PC and set its connection PIN. Windows may ask for administrator approval.",
        "注册这台电脑并设置连接 PIN。Windows 可能要求管理员确认。");
    public static string VirtualNetwork => For("virtual network", "虚拟网络");
    public static string Presence => For("presence & invites", "在线状态与连接邀请");
    public static string Capture => For("capture & input", "画面与输入");
    public static string SignInFirst => For("Sign in with your Moon account before enabling remote access.", "请先登录 Moon 账号，再启用远程控制。");
    public static string HostName => For("Host Name", "被控电脑名称");
    public static string ConnectionPin => For("Connection PIN", "连接 PIN");
    public static string PinLength => For("6–12 digits", "6–12 位数字");
    public static string LanAccess => For("Allow direct LAN connections (private networks only)", "允许局域网直连（仅专用网络）");
    public static string InstallService => For("Install System Service", "安装被控服务");
    public static string Unregister => For("Unregister", "解除注册");
    public static string Signalling => For("Signalling", "信令连接");
    public static string SessionAgent => For("Session Agent", "会话代理");

    public static string State(string state) => !IsChinese ? state : state switch
    {
        "running" => "运行中",
        "connected" => "已连接",
        "unavailable" => "不可用",
        "connecting" or "starting" => "正在连接",
        "not running" or "stopped" => "未启动",
        "disconnected" => "未连接",
        "unknown" => "未知",
        _ => state,
    };
}
