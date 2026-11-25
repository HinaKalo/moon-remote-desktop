using MoonRemote.Models;
using MoonRemote.Services;
using Xunit;

namespace MoonRemote.Tests;

public sealed class IncrementalUpdateTests
{
    [Fact]
    public void SelectsSmallerInstallerForTheSameReleaseAndKeepsFullFallback()
    {
        var full = new UpdateCheckResult(true, true, Manifest(UpdateService.SetupPlatform, 22, 50), "Full");
        var delta = new UpdateCheckResult(true, false, Manifest(UpdateService.SetupDeltaPlatform(21), 22, 7), "Delta");

        var chosen = UpdateService.ChooseInstaller(full, delta);
        Assert.Equal(delta.Manifest, chosen.Manifest);
        Assert.Equal(full.Manifest, chosen.FullInstallerFallback);
        Assert.True(chosen.Mandatory);
        Assert.Equal("windows-x64-setup-21", chosen.Manifest!.Platform);
    }

    [Theory]
    [InlineData(21, 7, true)]
    [InlineData(23, 7, true)]
    [InlineData(22, 50, true)]
    [InlineData(22, 7, false)]
    public void KeepsFullInstallerWhenDeltaDoesNotMatch(long version, long size, bool offered)
    {
        var full = new UpdateCheckResult(true, false, Manifest(UpdateService.SetupPlatform, 22, 50), "Full");
        var delta = new UpdateCheckResult(offered, false, Manifest(UpdateService.SetupDeltaPlatform(21), version, size), "Delta");

        Assert.Equal(full, UpdateService.ChooseInstaller(full, delta));
        Assert.Equal(full, UpdateService.ChooseInstaller(full, null));
    }

    private static RelhubManifest Manifest(string platform, long code, long size) =>
        new(UpdateService.AppId, platform, UpdateService.Channel, code, $"0.1.{code}",
            "setup.exe", size, "", 0, null, "", "", "");
}
