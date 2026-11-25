using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using Microsoft.Win32;

namespace MoonRemote.Services;

/// <summary>Install a signed full bundle beside the running Windows service, then switch SCM to it.</summary>
internal static class HostRelease
{
    private static readonly string ProductRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "MoonRemote");
    private static readonly string Root = Path.Combine(ProductRoot, "releases");
    private static string DirectoryFor(long code) => Path.Combine(Root, code.ToString(System.Globalization.CultureInfo.InvariantCulture));
    internal static string AppFor(long code) => Path.Combine(DirectoryFor(code), "MoonRemote.exe");

    private static string? ServiceCommand => OperatingSystem.IsWindows()
        ? Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MoonRemoteHost", "ImagePath", null) as string
        : null;
    internal static bool IsInstalled => ServiceCommand is not null;
    internal static bool IsCurrent(long code) => string.Equals(ServiceCommand,
        $"\"{Path.Combine(DirectoryFor(code), "moonrd-service.exe")}\" run", StringComparison.OrdinalIgnoreCase);

    internal static string SetupDirectory(long code) => Path.Combine(
        ProductRoot, "installed", $"0.1.{code}");

    internal static bool IsSetupCurrent(long code) => string.Equals(ServiceCommand,
        $"\"{Path.Combine(SetupDirectory(code), "moonrd-service.exe")}\" run", StringComparison.OrdinalIgnoreCase);

    internal static bool IsSetupApp(long code) =>
        OperatingSystem.IsWindows() &&
        string.Equals(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory), SetupDirectory(code), StringComparison.OrdinalIgnoreCase) &&
        Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{7E4B6C9A-2F51-4B8E-9C3A-8D1A2B5E4F01}_is1",
            "DisplayVersion", null) as string == $"0.1.{code}";

    internal static bool IsManagedApp(long code) =>
        ReleaseStorage.SamePath(AppContext.BaseDirectory, SetupDirectory(code)) ||
        ReleaseStorage.SamePath(AppContext.BaseDirectory, DirectoryFor(code));

    internal static bool OwnsPortableService =>
        ReleaseStorage.SamePath(AppContext.BaseDirectory, ServiceDirectory(ServiceCommand));

    private static string? ServiceDirectory(string? command)
    {
        if (string.IsNullOrEmpty(command)) return null;
        var end = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return end < 0 ? null : Path.GetDirectoryName(command[..(end + 4)].Trim('"'));
    }

    // Called only by the UAC helper. Its only input is a build number. Download again into an
    // administrator-owned directory and authenticate there before SCM can run anything as SYSTEM.
    internal static async Task InstallAsync(long? expectedCode)
    {
        if (!IsInstalled) throw new InvalidOperationException("The Windows host service is not installed.");
        Directory.CreateDirectory(Root);
        using var installLock = OpenInstallLock();
        using var native = new NativeBridge();
        native.Initialize();
        var updates = new UpdateService(native);
        var release = await updates.CheckPlatformAsync(UpdateService.FullPlatform, CancellationToken.None);
        if (release?.Manifest is not { } manifest || manifest.VersionCode < UpdateService.CurrentVersionCode ||
            (expectedCode.HasValue && manifest.VersionCode != expectedCode))
            throw new InvalidOperationException("The stable release changed. Check for updates again.");

        var dest = DirectoryFor(manifest.VersionCode);
        if (!Directory.Exists(dest))
        {
            var staging = Directory.CreateDirectory(Path.Combine(Root, $"staging-{Guid.NewGuid():N}")).FullName;
            try
            {
                var archive = await updates.DownloadAndVerifyAsync(manifest, staging, CancellationToken.None);
                ZipFile.ExtractToDirectory(archive, staging);
                File.Delete(archive);
                foreach (var file in new[] { "MoonRemote.exe", "moonrd-service.exe", "moonrd-agent.exe", @"easytier\easytier-core.exe" })
                    if (!File.Exists(Path.Combine(staging, file))) throw new InvalidDataException($"Incomplete host release: {file}");
                Directory.Move(staging, dest);
            }
            finally
            {
                if (Directory.Exists(staging)) Directory.Delete(staging, true);
            }
        }
        await ActivateAndPruneAsync(dest);
    }

    internal static async Task ActivateAsync(string dest)
    {
        using var installLock = OpenInstallLock();
        await ActivateAndPruneAsync(dest);
    }

    private static FileStream OpenInstallLock() =>
        new(Path.Combine(ProductRoot, "install.lock"), FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);

    private static async Task ActivateAndPruneAsync(string dest)
    {
        var previous = ServiceDirectory(ServiceCommand);
        // Keep the old installation available for rollback. The service continues to use
        // its existing ProgramData identity, registration, and encrypted PIN.
        const string switchService = """
            $ErrorActionPreference = 'Stop'
            $svc = Get-CimInstance Win32_Service -Filter "Name='MoonRemoteHost'"
            if (!$svc) {
                & $env:MOONRD_NEW_SERVICE install
                if ($LASTEXITCODE -ne 0) {
                    $code = $LASTEXITCODE
                    $created = Get-CimInstance Win32_Service -Filter "Name='MoonRemoteHost'"
                    if ($created.PathName -eq ('"' + $env:MOONRD_NEW_SERVICE + '" run')) {
                        & $env:MOONRD_NEW_SERVICE uninstall
                    }
                    throw "Creating the host service failed ($code)."
                }
            }
            $old = $svc.PathName
            $wasRunning = $svc.State -eq 'Running'
            $target = '"' + $env:MOONRD_NEW_SERVICE + '" run'
            $oldMode = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }[[string]$svc.StartMode]
            function Set-Image($path, $mode) {
                $r = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ PathName = $path; StartMode = $mode }
                if ($r.ReturnValue -ne 0) { throw "Changing the host service path failed ($($r.ReturnValue))." }
            }
            try {
                if ($svc) {
                    Stop-Service MoonRemoteHost
                    Set-Image $target 'Automatic'
                    Start-Service MoonRemoteHost
                }
                $p = [IO.Pipes.NamedPipeClientStream]::new('.', 'moonrd-service', [IO.Pipes.PipeDirection]::InOut)
                try {
                    $p.Connect(10000)
                    $b = [Text.Encoding]::UTF8.GetBytes('{"id":1,"method":"status"}' + [char]10)
                    $p.Write($b,0,$b.Length)
                    $read = [IO.StreamReader]::new($p).ReadLineAsync()
                    if (!$read.Wait(10000)) { throw 'Host service timed out.' }
                    $status = $read.Result | ConvertFrom-Json
                    if (!$status.ok -or !$status.result.callerIsAdmin) { throw 'Host administrator check failed.' }
                } finally { $p.Dispose() }
            } catch {
                $cause = $_
                if ($svc) {
                    Stop-Service MoonRemoteHost
                    Set-Image $old $oldMode
                    if ($wasRunning) { Start-Service MoonRemoteHost }
                } else {
                    & $env:MOONRD_NEW_SERVICE uninstall
                }
                throw $cause
            }
            """;
        var ps = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true,
        };
        ps.ArgumentList.Add("-NoProfile");
        ps.ArgumentList.Add("-NonInteractive");
        ps.ArgumentList.Add("-EncodedCommand");
        ps.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(switchService)));
        ps.Environment["MOONRD_NEW_SERVICE"] = Path.Combine(dest, "moonrd-service.exe");
        using var proc = Process.Start(ps) ?? throw new IOException("Cannot start Windows service configuration.");
        var error = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        if (proc.ExitCode != 0) throw new IOException($"Windows service upgrade failed. {error}");
        if (!ReleaseStorage.SamePath(dest, ServiceDirectory(ServiceCommand))) return;

        try
        {
            var running = new List<string>();
            foreach (var name in new[] { "MoonRemote", "moonrd-service", "moonrd-agent", "moonrd-host", "easytier-core", "easytier-cli" })
            {
                foreach (var process in Process.GetProcessesByName(name))
                {
                    using (process)
                    {
                        if (process.MainModule?.FileName is { } file) running.Add(file);
                    }
                }
            }
            ReleaseStorage.PruneInstalled(ProductRoot, dest, previous, running);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Debug.WriteLine($"MoonRemote kept old release directories: {ex.Message}");
        }
    }
}
