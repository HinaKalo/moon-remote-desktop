using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MoonRemote.Models;

namespace MoonRemote.Services;

public sealed record UpdateCheckResult(
    bool UpdateAvailable,
    bool Mandatory,
    RelhubManifest? Manifest,
    string Message,
    RelhubManifest? FullInstallerFallback = null);

/// <summary>
/// Relhub auto-update client for `moon-remote` (`https://release.moonl.cloud`).
/// Verifies Ed25519 manifest signatures via `moonrd_ffi.dll` (pinned key
/// `k4thZR+OVYSGAT/9j5F39csgGqTL0t3X6GYdNCmuRI8=`), enforces size & SHA-256 caps,
/// and stages zip extraction with atomic swap + rollback.
/// </summary>
public sealed class UpdateService
{
    public const string RelhubBaseUrl = "https://release.moonl.cloud";
    public const string MirrorBaseUrl = "https://remote.moonl.cloud/updates";
    public const string AppId = "moon-remote";
    /// <summary>Legacy portable update channel.</summary>
    public const string PatchPlatform = "windows-x64-patch";
    /// <summary>Full self-contained bundle fallback (~65 MB).</summary>
    public const string FullPlatform = "windows-x64";
    public const string SetupPlatform = "windows-x64-setup";
    public const string Channel = "stable";
    public const long MaxPackageBytes = 512L * 1024 * 1024;

    /// <summary>Monotonic build versionCode (matches `git rev-list --count HEAD` at publish).</summary>
    public static long CurrentVersionCode { get; } = ParseVersionCode();

    private readonly HttpClient _http;
    private readonly NativeBridge _native;
    private string _preferredOrigin = RelhubBaseUrl;

    public UpdateService(NativeBridge native)
        : this(native, new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            { Timeout = TimeSpan.FromMinutes(5) })
    {
    }

    internal UpdateService(NativeBridge native, HttpClient http)
    {
        _native = native;
        _http = http;
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"moon-remote/{CurrentVersionCode}");
    }

    private static long ParseVersionCode()
    {
        var v = typeof(UpdateService).Assembly.GetName().Version;
        if (v is null) return 1;
        return Math.Max(1, v.Build > 0 ? v.Build : 1);
    }

    public static string BuildCheckUrl(string platform, long currentCode) =>
        RelhubBaseUrl + CheckPath(platform, currentCode);

    public static string BuildDownloadUrl(RelhubManifest manifest) =>
        RelhubBaseUrl + DownloadPath(manifest);

    internal static string BrowserDownloadUrl(string platform, RelhubManifest? manifest) =>
        MirrorBaseUrl + (manifest is not null
            ? DownloadPath(manifest)
            : $"/v1/apps/{AppId}/{platform}/latest/download");

    private static string CheckPath(string platform, long code) =>
        $"/v1/apps/{AppId}/check?platform={platform}&channel={Channel}&versionCode={code}";

    private static string DownloadPath(RelhubManifest manifest) =>
        $"/v1/apps/{AppId}/{manifest.Platform}/releases/{manifest.VersionCode}/download";

    internal async Task<HttpResponseMessage> FetchReleaseAsync(string path, HttpCompletionOption completion, CancellationToken ct)
    {
        var preferred = _preferredOrigin;
        var alternate = preferred == RelhubBaseUrl ? MirrorBaseUrl : RelhubBaseUrl;
        string? firstFailure = null;
        foreach (var origin in new[] { preferred, alternate })
        {
            using var connectionTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectionTimeout.CancelAfter(TimeSpan.FromSeconds(15));
            string failure;
            try
            {
                var response = await _http.GetAsync(origin + path, completion, connectionTimeout.Token);
                if (response.StatusCode is not (HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable
                    or HttpStatusCode.GatewayTimeout or HttpStatusCode.RequestTimeout))
                {
                    if (response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotFound)
                        _preferredOrigin = origin;
                    return response;
                }
                failure = $"HTTP {(int)response.StatusCode}";
                response.Dispose();
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                failure = OnboardingText.For("request timed out", "请求超时");
            }
            catch (HttpRequestException ex) when (!ct.IsCancellationRequested)
            {
                failure = ex.HttpRequestError == HttpRequestError.SecureConnectionError
                    ? $"TLS · {ex.GetBaseException().Message}"
                    : ex.GetBaseException().Message;
            }

            var issue = $"{new Uri(origin).Host} · {failure}";
            if (firstFailure is not null)
                throw new HttpRequestException(OnboardingText.For(
                    $"Both update addresses failed. {firstFailure}. {issue}",
                    $"两个更新地址均无法连接。{firstFailure}。{issue}"));
            firstFailure = issue;
        }
        throw new InvalidOperationException("No update address is configured.");
    }

    internal static string SetupDeltaPlatform(long baseCode) => $"{SetupPlatform}-{baseCode.ToString(System.Globalization.CultureInfo.InvariantCulture)}";

    internal static UpdateCheckResult ChooseInstaller(UpdateCheckResult full, UpdateCheckResult? delta) =>
        full.UpdateAvailable && full.Manifest is { } installer &&
        delta is { UpdateAvailable: true, Manifest: { } patch } &&
        patch.VersionCode == installer.VersionCode && patch.Size < installer.Size
            ? delta with { Mandatory = full.Mandatory, FullInstallerFallback = installer }
            : full;

    public async Task<UpdateCheckResult> CheckAsync(CancellationToken ct = default)
    {
        if (!HostRelease.IsManagedApp(CurrentVersionCode))
        {
            if (HostRelease.OwnsPortableService)
                return new(false, false, null, "This folder runs the Windows host service. Use the Windows installer to move it to a managed installation.");
            return await CheckPlatformAsync(FullPlatform, ct)
                ?? new(false, false, null, "No portable Windows release is available.");
        }

        var setup = await CheckPlatformAsync(SetupPlatform, ct);
        if (setup?.Manifest is { } installer)
        {
            if (setup.UpdateAvailable && HostRelease.IsSetupApp(CurrentVersionCode))
            {
                var delta = await CheckPlatformAsync(SetupDeltaPlatform(CurrentVersionCode), ct);
                return ChooseInstaller(setup, delta);
            }
            if (installer.VersionCode == CurrentVersionCode && !HostRelease.IsSetupCurrent(CurrentVersionCode))
                return setup with { UpdateAvailable = true, Message = $"Windows installer v{installer.VersionName} is available for this PC." };
            return setup;
        }
        if (HostRelease.IsInstalled)
        {
            var full = await CheckPlatformAsync(FullPlatform, ct)
                ?? throw new InvalidOperationException("No Windows host release is available.");
            if (!full.UpdateAvailable && full.Manifest?.VersionCode == CurrentVersionCode && !HostRelease.IsCurrent(CurrentVersionCode))
                return full with { UpdateAvailable = true, Message = "Install this build for the Windows host service (administrator approval required)." };
            return full;
        }
        // Older release servers may only offer the legacy portable archives.
        var patchRes = await CheckPlatformAsync(PatchPlatform, ct);
        if (patchRes is not null)
            return patchRes;
        var fullRes = await CheckPlatformAsync(FullPlatform, ct);
        return fullRes ?? new UpdateCheckResult(false, false, null, "No release published yet.");
    }

    internal async Task<UpdateCheckResult?> CheckPlatformAsync(string platform, CancellationToken ct)
    {
        using var resp = await FetchReleaseAsync(CheckPath(platform, CurrentVersionCode),
            HttpCompletionOption.ResponseContentRead, ct);
        if (resp.StatusCode == HttpStatusCode.NotFound)
        {
            var errBody = await resp.Content.ReadAsStringAsync(ct);
            if (errBody.Contains("\"not_found\"", StringComparison.Ordinal))
                return null;
            throw new InvalidOperationException("Update server returned unexpected 404.");
        }
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct);
        var parsed = JsonSerializer.Deserialize(body, AppJsonContext.Default.RelhubCheckResponse)
            ?? throw new InvalidDataException("Empty update check response.");
        var m = parsed.Manifest;

        if (m.App != AppId || m.Platform != platform || m.Channel != Channel)
            throw new InvalidOperationException($"Manifest target mismatch: {m.App}/{m.Platform}/{m.Channel}");
        if (m.Size <= 0 || m.Size > MaxPackageBytes)
            throw new InvalidOperationException($"Manifest package size out of bounds: {m.Size}");

        // Verify Ed25519 signature against the pinned relhub public key in moonrd_ffi.dll.
        var verifyReq = JsonSerializer.Serialize(
            new FfiRequest<RelhubManifest>("verify_relhub_manifest", m),
            AppJsonContext.Default.FfiRequestRelhubManifest);
        var verifyResp = _native.Call(verifyReq);
        using var vdoc = JsonDocument.Parse(verifyResp);
        if (!vdoc.RootElement.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
        {
            var reason = vdoc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "verification failed";
            throw new InvalidOperationException($"Update signature rejected: {reason}");
        }

        // Recompute verdict locally from the verified manifest (never trust unsigned flags).
        var available = m.VersionCode > CurrentVersionCode;
        var mandatory = available && m.MinVersionCode > CurrentVersionCode;
        var sizeMb = m.Size / (1024.0 * 1024.0);
        var kindLabel = platform switch
        {
            SetupPlatform => "Windows installer",
            PatchPlatform => "portable patch",
            _ when platform == SetupDeltaPlatform(CurrentVersionCode) => "incremental installer",
            _ => "full package",
        };
        var msg = available
            ? $"Update available: v{m.VersionName} (build {m.VersionCode}, {sizeMb:0.1} MB {kindLabel})"
            : $"Up to date (v{m.VersionName}, build {CurrentVersionCode}).";
        return new UpdateCheckResult(available, mandatory, m, msg);
    }

    public async Task<string> DownloadAndVerifyAsync(RelhubManifest manifest, CancellationToken ct = default)
    {
        return await DownloadAndVerifyAsync(manifest, ReleaseStorage.Downloads, ct);
    }

    internal async Task LaunchInstallerAsync(RelhubManifest manifest)
    {
        if (!(manifest.Platform == SetupPlatform || manifest.Platform == SetupDeltaPlatform(CurrentVersionCode)) ||
            !manifest.File.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Expected a Windows installer release.");
        var path = await DownloadAndVerifyAsync(manifest);
        // Keep the verified executable locked against replacement until Windows starts it.
        using var locked = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!Convert.ToHexString(await SHA256.HashDataAsync(locked)).Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The installer changed after download.");
        using var installer = Process.Start(new ProcessStartInfo(path) { UseShellExecute = true })
            ?? throw new IOException("Could not launch the Windows installer.");
    }

    internal async Task<string> DownloadAndVerifyAsync(RelhubManifest manifest, string dir, CancellationToken ct)
    {
        Directory.CreateDirectory(dir);
        var safeName = Path.GetFileName(manifest.File);
        var partPath = Path.Combine(dir, safeName + $".{Guid.NewGuid():N}.part");
        var finalPath = Path.Combine(dir, safeName);

        if (File.Exists(finalPath))
        {
            await using var cached = File.OpenRead(finalPath);
            if (cached.Length == manifest.Size &&
                Convert.ToHexString(await SHA256.HashDataAsync(cached, ct)).Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                return finalPath;
        }

        using var resp = await FetchReleaseAsync(DownloadPath(manifest), HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();

        try
        {
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;
            await using (var src = await resp.Content.ReadAsStreamAsync(ct))
            await using (var dst = File.Create(partPath))
            {
                var buf = new byte[64 * 1024];
                int n;
                while ((n = await src.ReadAsync(buf, ct)) > 0)
                {
                    total += n;
                    if (total > manifest.Size)
                        throw new InvalidDataException("Downloaded file exceeded manifest size.");
                    sha.AppendData(buf, 0, n);
                    await dst.WriteAsync(buf.AsMemory(0, n), ct);
                }
            }
            if (total != manifest.Size)
                throw new InvalidDataException($"Downloaded {total} bytes, expected {manifest.Size}.");

            var hex = Convert.ToHexStringLower(sha.GetHashAndReset());
            if (!string.Equals(hex, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("SHA-256 mismatch on downloaded update package.");
            }

            File.Move(partPath, finalPath, overwrite: true);
            return finalPath;
        }
        finally
        {
            if (File.Exists(partPath)) File.Delete(partPath);
        }
    }

    /// <summary>Apply a verified portable ZIP after the controller has exited.</summary>
    public static void StageAndLaunchUpdater(string zipPath)
    {
        if (HostRelease.IsManagedApp(CurrentVersionCode) || HostRelease.OwnsPortableService)
            throw new InvalidOperationException("Use the Windows installer to update this installation.");

        var appDir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        if (File.GetAttributes(appDir).HasFlag(FileAttributes.ReparsePoint))
            throw new IOException("Extract the portable app into a regular directory before updating.");
        var work = Path.Combine(appDir, $".moonremote-update-{Guid.NewGuid():N}");
        var staging = Path.Combine(work, "payload");
        Directory.CreateDirectory(work);
        try
        {
            ZipFile.ExtractToDirectory(zipPath, staging);
            if (!File.Exists(Path.Combine(staging, "MoonRemote.exe")))
                throw new InvalidDataException("The portable release did not contain MoonRemote.exe.");

            var ps = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = appDir,
            };
            ps.ArgumentList.Add("-NoProfile");
            ps.ArgumentList.Add("-NonInteractive");
            ps.ArgumentList.Add("-EncodedCommand");
            ps.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(PortableApplyScript)));
            ps.Environment["MOONRD_PORTABLE_APP"] = appDir;
            ps.Environment["MOONRD_PORTABLE_STAGE"] = work;
            ps.Environment["MOONRD_PORTABLE_PID"] = Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
            ps.Environment["MOONRD_PORTABLE_LOG"] = Path.Combine(ReleaseStorage.Downloads, "apply-update.log");
            using var apply = Process.Start(ps) ?? throw new IOException("Could not start the portable updater.");
        }
        catch
        {
            Directory.Delete(work, recursive: true);
            throw;
        }
    }

    private const string PortableApplyScript = """
        $ErrorActionPreference = 'Stop'
        $appDir = $env:MOONRD_PORTABLE_APP
        $work = $env:MOONRD_PORTABLE_STAGE
        if ([IO.Path]::GetDirectoryName($work) -ne $appDir -or
            [IO.Path]::GetFileName($work) -notmatch '^[.]moonremote-update-[0-9a-f]{32}$' -or
            (Get-Item -LiteralPath $work -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Invalid portable update staging directory.'
        }

        $exe = Join-Path $appDir 'MoonRemote.exe'
        $payload = Join-Path $work 'payload'
        $backups = Join-Path $work 'backup'
        $processed = [Collections.Generic.List[object]]::new()
        $keepBackups = $false
        $parentExited = $false
        function Log($message) {
            try { Add-Content -LiteralPath $env:MOONRD_PORTABLE_LOG -Value "$(Get-Date -Format o) $message" } catch {}
        }
        function Assert-RegularPath($path) {
            if (![IO.Path]::GetFullPath($path).StartsWith($appDir + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw "Invalid portable destination: $path"
            }
            while ($path -ne $appDir) {
                if (!(Test-Path -LiteralPath $path)) {
                    $path = Split-Path -Parent $path
                    continue
                }
                if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw "Cannot update linked path: $path"
                }
                $path = Split-Path -Parent $path
            }
        }

        try {
            $parentProcess = Get-Process -Id ([int]$env:MOONRD_PORTABLE_PID) -ErrorAction SilentlyContinue
            if ($parentProcess -and $parentProcess.Path -eq $exe) {
                Wait-Process -InputObject $parentProcess -Timeout 30
            }
            $parentExited = $true
            $service = Get-CimInstance Win32_Service -Filter "Name='MoonRemoteHost'"
            $image = $service.PathName
            if ($image -and $image.TrimStart('"').StartsWith($appDir + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'This folder runs the Windows host service. Update it with the Windows installer.'
            }
            $other = Get-Process MoonRemote -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -eq $exe } | Select-Object -First 1
            if ($other) {
                $parentExited = $false
                throw 'Close all MoonRemote windows running from this folder before retrying.'
            }

            foreach ($file in Get-ChildItem -LiteralPath $payload -Recurse -File) {
                $relative = $file.FullName.Substring($payload.Length + 1)
                $dest = Join-Path $appDir $relative
                Assert-RegularPath $dest
                $backup = $null
                if (Test-Path -LiteralPath $dest) {
                    $backup = Join-Path $backups $relative
                    [IO.Directory]::CreateDirectory((Split-Path -Parent $backup)) | Out-Null
                    [IO.File]::Move($dest, $backup)
                } else {
                    [IO.Directory]::CreateDirectory((Split-Path -Parent $dest)) | Out-Null
                }
                $processed.Add(@{ Dest = $dest; Backup = $backup })
                [IO.File]::Move($file.FullName, $dest)
            }
            Log 'Portable update applied.'
        } catch {
            Log "Portable update failed: $_"
            for ($i = $processed.Count - 1; $i -ge 0; $i--) {
                $item = $processed[$i]
                try {
                    [IO.File]::Delete($item.Dest)
                    if ($item.Backup) { [IO.File]::Move($item.Backup, $item.Dest) }
                } catch {
                    $keepBackups = $true
                    Log "Could not restore $($item.Dest): $_"
                }
            }
        } finally {
            if (!$keepBackups) {
                try { Remove-Item -LiteralPath $work -Recurse -Force } catch { Log "Cleanup failed: $_" }
            }
        }
        if ($parentExited -and !$keepBackups -and (Test-Path -LiteralPath $exe)) {
            Start-Process -FilePath $exe -WorkingDirectory $appDir
        }
        """;
}
