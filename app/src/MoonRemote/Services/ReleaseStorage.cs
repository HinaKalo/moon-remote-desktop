using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;

namespace MoonRemote.Services;

internal static partial class ReleaseStorage
{
    internal static string Downloads => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MoonRemote", "updates");

    internal static void PruneInstalled(string productRoot, string current, string? previous, IEnumerable<string> protectedPaths)
    {
        var root = new DirectoryInfo(Path.GetFullPath(productRoot));
        if (!IsPlainDirectory(root)) return;

        var versions = new List<(DirectoryInfo Directory, long Code)>();
        foreach (var layout in new[] { "installed", "releases" })
        {
            var container = new DirectoryInfo(Path.Combine(root.FullName, layout));
            if (!IsPlainDirectory(container)) continue;
            foreach (var dir in container.EnumerateDirectories())
            {
                var codeText = layout == "installed" && dir.Name.StartsWith("0.1.", StringComparison.Ordinal)
                    ? dir.Name[4..] : layout == "releases" ? dir.Name : "";
                if (IsPlainDirectory(dir) && long.TryParse(codeText, NumberStyles.None, CultureInfo.InvariantCulture, out var code)
                    && code > 0 && codeText == code.ToString(CultureInfo.InvariantCulture)
                    && File.Exists(Path.Combine(dir.FullName, "MoonRemote.exe"))
                    && File.Exists(Path.Combine(dir.FullName, "moonrd-service.exe")))
                    versions.Add((dir, code));
            }
        }

        var active = versions.Find(v => SamePath(v.Directory.FullName, current));
        if (active.Directory is null) return;
        var older = versions.Where(v => v.Code < active.Code).OrderByDescending(v => v.Code).ToList();
        var rollback = older.Find(v => SamePath(v.Directory.FullName, previous)).Directory
            ?? older.FirstOrDefault().Directory;
        var protectedFiles = protectedPaths.Select(Path.GetFullPath).ToArray();
        foreach (var (dir, _) in older)
        {
            if (SamePath(dir.FullName, rollback?.FullName) ||
                protectedFiles.Any(p => p.StartsWith(dir.FullName + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
                continue;
            TryRemoveTree(dir);
        }
    }

    internal static void PruneDownloads(string directory, long installedBuild, DateTime utcNow)
    {
        var cache = new DirectoryInfo(directory);
        if (!IsPlainDirectory(cache)) return;

        foreach (var file in cache.EnumerateFiles())
        {
            var match = PackageName().Match(file.Name);
            if (!match.Success || !long.TryParse(match.Groups[1].Value, CultureInfo.InvariantCulture, out var build)
                || build > installedBuild || file.LastWriteTimeUtc > utcNow.AddMinutes(-15) ||
                file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                continue;
            TryRemove(file.Delete);
        }

        // The pre-transactional portable updater used this fixed scratch directory.
        var legacyStaging = new DirectoryInfo(Path.Combine(cache.FullName, "staging"));
        if (IsPlainDirectory(legacyStaging) && legacyStaging.LastWriteTimeUtc < utcNow.AddHours(-1)
            && File.Exists(Path.Combine(legacyStaging.FullName, "MoonRemote.exe")))
            TryRemoveTree(legacyStaging);
    }

    internal static bool SamePath(string first, string? second) =>
        second is not null && string.Equals(Path.TrimEndingDirectorySeparator(first),
            Path.TrimEndingDirectorySeparator(second), StringComparison.OrdinalIgnoreCase);

    private static bool IsPlainDirectory(DirectoryInfo dir) =>
        dir.Exists && !dir.Attributes.HasFlag(FileAttributes.ReparsePoint);

    private static bool ContainsLink(DirectoryInfo directory)
    {
        foreach (var entry in directory.EnumerateFileSystemInfos())
        {
            if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                entry is DirectoryInfo child && ContainsLink(child))
                return true;
        }
        return false;
    }

    private static void TryRemoveTree(DirectoryInfo dir) => TryRemove(() =>
    {
        if (IsPlainDirectory(dir) && !ContainsLink(dir))
            dir.Delete(recursive: true);
    });

    private static void TryRemove(Action remove)
    {
        try { remove(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Debug.WriteLine($"MoonRemote update cleanup skipped a busy item: {ex.Message}");
        }
    }

    [GeneratedRegex(@"^moon-remote-0\.1\.(\d+)-windows-x64(?:-setup(?:-\d+)?\.exe|(?:-patch)?\.zip)(?:\.[0-9a-f]{32})?(?:\.part)?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PackageName();
}
