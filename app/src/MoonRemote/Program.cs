using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Avalonia;
using Lumen.UI;
using MoonRemote.Models;
using MoonRemote.Services;

namespace MoonRemote;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args is ["--configure-installed-host"])
        {
            var dir = HostRelease.SetupDirectory(UpdateService.CurrentVersionCode);
            if (!string.Equals(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory), dir, StringComparison.OrdinalIgnoreCase))
                return 2;
            try
            {
                HostRelease.ActivateAsync(dir).GetAwaiter().GetResult();
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }
        if (args is ["--start-host-service"] && OperatingSystem.IsWindows() && HostRelease.IsInstalled)
        {
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                Path.Combine(Environment.SystemDirectory, "sc.exe"), "start MoonRemoteHost")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null) return 1;
            process.WaitForExit();
            return process.ExitCode == 1056 ? 0 : process.ExitCode; // service already running
        }
        if (args.Length == 2 && args[0] == "--update-host" && long.TryParse(args[1], out var build))
        {
            try
            {
                HostRelease.InstallAsync(build).GetAwaiter().GetResult();
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }
        if (args.Length >= 2 && args[0] == "--elevated-setup")
        {
            return RunElevatedSetupAsync(args[1]).GetAwaiter().GetResult();
        }
        try
        {
            ReleaseStorage.PruneDownloads(ReleaseStorage.Downloads, UpdateService.CurrentVersionCode, DateTime.UtcNow);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            System.Diagnostics.Debug.WriteLine(ex.Message);
        }
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return 0;
    }

    /// <summary>
    /// Headless elevated helper invoked with one UAC prompt when the host Windows service
    /// requires administrator rights for registration and PIN setup. Never opens a GUI window.
    /// </summary>
    private static async Task<int> RunElevatedSetupAsync(string payloadPath)
    {
        var errPath = payloadPath + ".err";
        try
        {
            var raw = await File.ReadAllTextAsync(payloadPath, Encoding.UTF8);
            try { File.Delete(payloadPath); } catch { }
            var p = JsonSerializer.Deserialize(raw, AppJsonContext.Default.ElevatedSetupPayload)
                ?? throw new InvalidDataException("Invalid setup payload.");

            var pipe = new ServicePipeClient();
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", p.AccessToken);
            var baseUrl = p.ServerUrl.TrimEnd('/');

            // 1. Validate & set PIN first (so weak PINs like 123456 fail cleanly before registering).
            var pinRequest = JsonSerializer.Serialize(new SetPinParams(p.Pin), AppJsonContext.Default.SetPinParams);
            var pinResp = await pipe.CallSystemAsync("set_pin", pinRequest);
            if (pinResp.Error?.Code == "forbidden" && HostRelease.IsInstalled)
            {
                // Old services queried the pipe caller before reading a request and rejected
                // even an elevated setup. Repair that installation under this same UAC grant.
                await HostRelease.InstallAsync(expectedCode: null);
                pinResp = await pipe.CallSystemAsync("set_pin", pinRequest);
            }
            if (!pinResp.Ok)
                throw new InvalidOperationException(pinResp.Error?.Message ?? "set_pin failed");

            // 2. Challenge
            using var chalResp = await http.PostAsync($"{baseUrl}/v1/devices/challenge", null);
            var chalBody = await chalResp.Content.ReadAsStringAsync();
            if (!chalResp.IsSuccessStatusCode)
                throw new InvalidOperationException($"challenge HTTP {(int)chalResp.StatusCode}: {chalBody}");
            var chal = JsonSerializer.Deserialize(chalBody, AppJsonContext.Default.ChallengeResponse)
                ?? throw new InvalidOperationException("Empty challenge response.");

            // 3. Sign with service's DPAPI device key (now running elevated as Admin).
            var signParams = JsonSerializer.Serialize(
                new SignRegistrationParams(chal.Nonce, p.UserSub, "host"),
                AppJsonContext.Default.SignRegistrationParams);
            var signResp = await pipe.CallSystemAsync("sign_registration", signParams);
            if (!signResp.Ok || signResp.Result is not { } sr)
                throw new InvalidOperationException(signResp.Error?.Message ?? "sign_registration failed");

            var pubKey = sr.GetProperty("publicKey").GetString()!;
            var sig = sr.GetProperty("signature").GetString()!;

            // 4. Register host with server.
            var regBody = JsonSerializer.Serialize(
                new RegisterDeviceRequest(p.HostName, "host", pubKey, chal.Nonce, sig),
                AppJsonContext.Default.RegisterDeviceRequest);
            using var regResp = await http.PostAsync(
                $"{baseUrl}/v1/devices",
                new StringContent(regBody, Encoding.UTF8, "application/json"));
            var regRespBody = await regResp.Content.ReadAsStringAsync();
            if (!regResp.IsSuccessStatusCode)
                throw new InvalidOperationException($"register HTTP {(int)regResp.StatusCode}: {regRespBody}");
            var reg = JsonSerializer.Deserialize(regRespBody, AppJsonContext.Default.RegisterDeviceResponse)
                ?? throw new InvalidOperationException("Empty register response.");

            // 5. Persist registration inside the service.
            var completeParams = JsonSerializer.Serialize(
                new CompleteRegistrationParams(
                    p.ServerUrl,
                    reg.Device.Id,
                    p.UserSub,
                    reg.Device.Name,
                    reg.DeviceToken,
                    reg.RosterKey,
                    reg.RosterKeyId),
                AppJsonContext.Default.CompleteRegistrationParams);
            var done = await pipe.CallSystemAsync("complete_registration", completeParams);
            if (!done.Ok)
                throw new InvalidOperationException(done.Error?.Message ?? "complete_registration failed");

            return 0;
        }
        catch (Exception ex)
        {
            try { File.Delete(payloadPath); } catch { }
            try { await File.WriteAllTextAsync(errPath, ex.Message, Encoding.UTF8); } catch { }
            return 1;
        }
    }

    // Also used by the Avalonia previewer.
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .UseLumen()
            .LogToTrace();
}
