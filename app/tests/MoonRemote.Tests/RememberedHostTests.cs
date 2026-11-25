using System.Text;
using System.Text.Json;
using MoonRemote.Models;
using MoonRemote.Services;
using Xunit;

namespace MoonRemote.Tests;

public sealed class RememberedHostTests
{
    [Fact]
    public void PairingSurvivesReopeningAndIsScopedToTheAccountAndHostKey()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = Directory.CreateTempSubdirectory("moonremote-pairing-");
        try
        {
            const string server = "https://example.test";
            var host = new DeviceItem("remote", "Office", "host", "host-key", true, false);
            var pairing = new HostPairing("viewer-device", Convert.ToBase64String(new byte[16]),
                Convert.ToBase64String(Enumerable.Repeat((byte)42, 32).ToArray()));
            new RememberedHost(directory.FullName, server, "account", host).Save(pairing);

            var recreated = new RememberedHost(directory.FullName, server + "/", "account", host);
            Assert.Equal(pairing, recreated.Load());
            var encrypted = File.ReadAllBytes(Assert.Single(directory.GetFiles()).FullName);
            Assert.DoesNotContain(pairing.Key, Encoding.UTF8.GetString(encrypted));
            Assert.Null(new RememberedHost(directory.FullName, server, "other-account", host).Load());
            Assert.Null(new RememberedHost(directory.FullName, server, "account", host with { PublicKey = "other-key" }).Load());
            Assert.Null(new RememberedHost(directory.FullName, server, "account", host with { Id = "other-host" }).Load());

            recreated.Forget(pairing);
            Assert.Null(recreated.Load());
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void NativeConnectionCarriesAStoredPairingAndSessionId()
    {
        var connect = new FfiConnectParams("127.0.0.1:47000", "host-key", "seed", "viewer", "PC", 0)
        {
            ClientSessionId = "session-id",
            PairingId = "pairing-id",
            PairingKey = "pairing-key",
        };
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(
            new FfiRequest<FfiConnectParams>("connect", connect), AppJsonContext.Default.FfiRequestFfiConnectParams));
        var args = json.RootElement.GetProperty("params");
        Assert.Equal("session-id", args.GetProperty("clientSessionId").GetString());
        Assert.Equal("pairing-id", args.GetProperty("pairingId").GetString());
        Assert.Equal("pairing-key", args.GetProperty("pairingKey").GetString());
    }
}
