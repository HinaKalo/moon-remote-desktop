using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Avalonia.Input;
using MoonRemote.Models;
using MoonRemote.Services;
using Xunit;

namespace MoonRemote.Tests;

public sealed class ProtocolAndSsoTests
{
    [Theory]
    [InlineData(PhysicalKey.A, 0x04u)]
    [InlineData(PhysicalKey.Backquote, 0x35u)]
    [InlineData(PhysicalKey.Digit1, 0x1eu)]
    [InlineData(PhysicalKey.Digit0, 0x27u)]
    [InlineData(PhysicalKey.ControlLeft, 0xe0u)]
    [InlineData(PhysicalKey.ControlRight, 0xe4u)]
    [InlineData(PhysicalKey.ArrowLeft, 0x50u)]
    [InlineData(PhysicalKey.None, 0u)]
    public void RemoteKeyboardUsesUsbHidCodes(PhysicalKey key, uint expected) =>
        Assert.Equal(expected, RemoteKeyboard.HidUsage(key));

    [Fact]
    public void KeyRequestCarriesCommittedUnicodeText()
    {
        const string text = "你好 한글 🌙";
        var request = new FfiRequest<FfiKeyParams>("send_key", new(0, false, false, text));
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(request, AppJsonContext.Default.FfiRequestFfiKeyParams));
        Assert.Equal(text, doc.RootElement.GetProperty("params").GetProperty("text").GetString());
    }

    [Fact]
    public void PkceChallengeMatchesSha256Base64Url()
    {
        var (verifier, challenge) = SsoService.CreatePkce();
        Assert.InRange(verifier.Length, 43, 128);
        var expected = SsoService.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        Assert.Equal(expected, challenge);
        Assert.DoesNotContain("+", challenge);
        Assert.DoesNotContain("/", challenge);
        Assert.DoesNotContain("=", challenge);
    }

    [Fact]
    public void PipeRequestAndResponseRoundTrip()
    {
        var paramsJson = JsonSerializer.Serialize(new SetPinParams("482916"), AppJsonContext.Default.SetPinParams);
        var req = ServicePipeClient.BuildRequestLine(7, "set_pin", paramsJson);
        using var doc = JsonDocument.Parse(req);
        Assert.Equal(7UL, doc.RootElement.GetProperty("id").GetUInt64());
        Assert.Equal("set_pin", doc.RootElement.GetProperty("method").GetString());
        Assert.Equal("482916", doc.RootElement.GetProperty("params").GetProperty("pin").GetString());

        var okResp = ServicePipeClient.ParseResponseLine("""{"id":7,"ok":true,"result":{"pinSet":true}}""");
        Assert.True(okResp.Ok);
        Assert.Equal(7UL, okResp.Id);
        Assert.True(okResp.Result!.Value.GetProperty("pinSet").GetBoolean());

        var errResp = ServicePipeClient.ParseResponseLine("""{"id":7,"ok":false,"error":{"code":"forbidden","message":"admin required"}}""");
        Assert.False(errResp.Ok);
        Assert.Equal("forbidden", errResp.Error!.Code);
    }

    [Fact]
    public void DeviceListDeserializesWithSourceGeneratedContext()
    {
        const string json = """{"devices":[{"id":"d1","name":"Office","kind":"host","publicKey":"AAAA","online":true,"self":false}]}""";
        var parsed = JsonSerializer.Deserialize(json, AppJsonContext.Default.DevicesResponse);
        Assert.NotNull(parsed);
        var dev = Assert.Single(parsed!.Devices);
        Assert.Equal("d1", dev.Id);
        Assert.Equal("Office", dev.Name);
        Assert.True(dev.Online);
    }

    [Fact]
    public void SsoClientIdMatchesRegisteredProductionDesktopClient()
    {
        Assert.Equal("ms_PTyfu8NoBmsYspSFmqdu", AppConfig.DesktopClientId);
        Assert.Equal("https://sso.moonl.cloud", AppConfig.SsoIssuer);
    }
}
