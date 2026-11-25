using MoonRemote.Services;
using Xunit;

namespace MoonRemote.Tests;

public sealed class ReleaseStorageTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("moonrd-release-test-").FullName;

    [Fact]
    public void PrunesInactiveHistoricalReleasesAcrossBothManagedLayouts()
    {
        var current = AddVersion("installed", "0.1.23");
        var rollback = AddVersion("installed", "0.1.21");
        var running = AddVersion("releases", "20");
        var pending = AddVersion("installed", "0.1.24");
        var foreign = AddVersion("installed", "portable-backup");
        var obsolete = AddVersion("installed", "0.1.22");
        var legacy = AddVersion("releases", "18");
        var incomplete = Directory.CreateDirectory(Path.Combine(_root, "installed", "0.1.15")).FullName;

        ReleaseStorage.PruneInstalled(_root, current, rollback, [Path.Combine(running, "MoonRemote.exe")]);

        Assert.All(new[] { current, rollback, running, pending, foreign, incomplete }, path => Assert.True(Directory.Exists(path)));
        Assert.False(Directory.Exists(obsolete));
        Assert.False(Directory.Exists(legacy));
    }

    [Fact]
    public void RepairingTheActiveVersionKeepsTheNewestOlderVersion()
    {
        var current = AddVersion("installed", "0.1.23");
        var previous = AddVersion("installed", "0.1.22");
        var obsolete = AddVersion("releases", "21");
        ReleaseStorage.PruneInstalled(_root, current, current, []);
        Assert.True(Directory.Exists(current));
        Assert.True(Directory.Exists(previous));
        Assert.False(Directory.Exists(obsolete));
    }

    [Fact]
    public void CacheCleanupKeepsUpcomingDownloadsAndUnrecognizedFiles()
    {
        var now = DateTime.UtcNow;
        var obsolete = AddFile(_root, "moon-remote-0.1.20-windows-x64-setup.exe", now.AddDays(-1));
        var downloaded = AddFile(_root, "moon-remote-0.1.23-windows-x64-setup-22.exe", now.AddMinutes(-1));
        var next = AddFile(_root, "moon-remote-0.1.24-windows-x64.zip", now.AddHours(-1));
        var notes = AddFile(_root, "notes.txt", now.AddDays(-1));
        var staging = Directory.CreateDirectory(Path.Combine(_root, "staging"));
        File.WriteAllText(Path.Combine(staging.FullName, "MoonRemote.exe"), "test");
        staging.LastWriteTimeUtc = now.AddHours(-2);

        ReleaseStorage.PruneDownloads(_root, 23, now);

        Assert.All(new[] { downloaded, next, notes }, path => Assert.True(File.Exists(path)));
        Assert.False(File.Exists(obsolete));
        Assert.False(Directory.Exists(staging.FullName));
    }

    private string AddVersion(string layout, string name)
    {
        var directory = Directory.CreateDirectory(Path.Combine(_root, layout, name)).FullName;
        File.WriteAllText(Path.Combine(directory, "MoonRemote.exe"), "app");
        File.WriteAllText(Path.Combine(directory, "moonrd-service.exe"), "host");
        return directory;
    }

    private static string AddFile(string directory, string name, DateTime modifiedUtc)
    {
        var path = Path.Combine(directory, name);
        File.WriteAllText(path, "test");
        File.SetLastWriteTimeUtc(path, modifiedUtc);
        return path;
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);
}
