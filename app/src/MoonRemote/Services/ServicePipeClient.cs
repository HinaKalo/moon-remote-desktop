using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using MoonRemote.Models;

namespace MoonRemote.Services;

/// <summary>
/// Line-delimited JSON-RPC client for `moonrd-service` (`\\.\pipe\moonrd-service`,
/// falling back to `\\.\pipe\moonrd-service-dev` when running in console mode).
/// </summary>
public sealed class ServicePipeClient
{
    public const string ProdPipeName = "moonrd-service";
    public const string DevPipeName = "moonrd-service-dev";
    private ulong _nextId;

    public Task<PipeResponse> CallAsync(string method, string? paramsJson = null, CancellationToken ct = default) =>
        CallAsync(HostRelease.IsInstalled ? [ProdPipeName] : [ProdPipeName, DevPipeName], method, paramsJson, ct);

    internal Task<PipeResponse> CallSystemAsync(string method, string paramsJson) =>
        CallAsync([ProdPipeName], method, paramsJson, CancellationToken.None);

    private async Task<PipeResponse> CallAsync(string[] pipeNames, string method, string? paramsJson, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _nextId);
        var line = BuildRequestLine(id, method, paramsJson);

        Exception? lastErr = null;
        foreach (var pipeName in pipeNames)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(1500, ct);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { NewLine = "\n", AutoFlush = true };
                using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
                await writer.WriteLineAsync(line.AsMemory(), ct);
                var respLine = await reader.ReadLineAsync(ct)
                    ?? throw new IOException("Service pipe closed without a response.");
                return ParseResponseLine(respLine);
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                lastErr = ex;
            }
        }
        throw new IOException("Host service is not running.", lastErr);
    }

    public static string BuildRequestLine(ulong id, string method, string? paramsJson = null)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteNumber("id", id);
            w.WriteString("method", method);
            if (!string.IsNullOrWhiteSpace(paramsJson))
            {
                w.WritePropertyName("params");
                using var doc = JsonDocument.Parse(paramsJson);
                doc.RootElement.WriteTo(w);
            }
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static PipeResponse ParseResponseLine(string line) =>
        JsonSerializer.Deserialize(line, AppJsonContext.Default.PipeResponse)
        ?? throw new InvalidDataException("Invalid pipe JSON response.");

    /// <summary>
    /// Ensures either the installed Windows service or a per-user background
    /// `moonrd-service.exe user` daemon is running and reachable on its named pipe.
    /// </summary>
    public async Task EnsureServiceRunningAsync(CancellationToken ct = default)
    {
        try
        {
            await CallAsync("status", null, ct);
            return;
        }
        catch (IOException) { }

        if (HostRelease.IsInstalled)
            throw new IOException(OnboardingText.For("Start the Windows host service from This PC, then retry.",
                "请在「本机被控」页启动已安装的被控服务，然后重试。"));

        var svcExe = Path.Combine(AppContext.BaseDirectory, "moonrd-service.exe");
        if (!File.Exists(svcExe))
            throw new IOException($"moonrd-service.exe not found in {AppContext.BaseDirectory}");

        Process.Start(new ProcessStartInfo(svcExe, "user")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        });

        var agentExe = Path.Combine(AppContext.BaseDirectory, "moonrd-agent.exe");
        if (File.Exists(agentExe))
        {
            Process.Start(new ProcessStartInfo(agentExe, "--dev")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }

        for (var i = 0; i < 20; i++)
        {
            await Task.Delay(200, ct);
            try
            {
                await CallAsync("status", null, ct);
                return;
            }
            catch (IOException) { }
        }
        throw new IOException("Started moonrd-service.exe but its named pipe did not become ready.");
    }

    /// <summary>Installs and starts `moonrd-service.exe` as a LocalSystem Windows service (one UAC prompt).</summary>
    public static async Task<int> InstallSystemServiceAsync(CancellationToken ct = default)
    {
        if (HostRelease.IsInstalled)
            return await RunElevatedAsync("--start-host-service", ct);

        var svcExe = Path.Combine(AppContext.BaseDirectory, "moonrd-service.exe");
        if (!File.Exists(svcExe))
            throw new IOException($"moonrd-service.exe not found in {AppContext.BaseDirectory}");
        using var proc = Process.Start(new ProcessStartInfo(svcExe, "install")
        {
            UseShellExecute = true,
            Verb = "runas",
        }) ?? throw new InvalidOperationException("Failed to start elevated service installer.");
        await proc.WaitForExitAsync(ct);
        return proc.ExitCode;
    }

    /// <summary>
    /// Relaunches the current executable elevated (one UAC prompt) to run an admin-gated
    /// host configuration step against `\\.\pipe\moonrd-service`.
    /// </summary>
    public static async Task<int> RunElevatedAsync(string args, CancellationToken ct = default)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Unknown executable path.");
        using var proc = Process.Start(new ProcessStartInfo(exe, args)
        {
            UseShellExecute = true,
            Verb = "runas",
        }) ?? throw new InvalidOperationException("Failed to start elevated helper.");
        await proc.WaitForExitAsync(ct);
        return proc.ExitCode;
    }
}
