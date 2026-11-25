using System.Text.Json;
using System.Text.Json.Serialization;

namespace MoonRemote.Models;

public sealed record DeviceItem(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("publicKey")] string PublicKey,
    [property: JsonPropertyName("online")] bool Online,
    [property: JsonPropertyName("self")] bool IsSelf = false);

public sealed record DevicesResponse(
    [property: JsonPropertyName("devices")] List<DeviceItem> Devices);

public sealed record ChallengeResponse(
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("expiresAt")] string ExpiresAt);

public sealed record RegisterDeviceRequest(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("publicKey")] string PublicKey,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("signature")] string Signature);

public sealed record RegisterDeviceResponse(
    [property: JsonPropertyName("device")] DeviceItem Device,
    [property: JsonPropertyName("deviceToken")] string DeviceToken,
    [property: JsonPropertyName("rosterKey")] string RosterKey,
    [property: JsonPropertyName("rosterKeyId")] string RosterKeyId);

public sealed record SupportCodeResponse(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("session")] string Session,
    [property: JsonPropertyName("expiresAt")] string ExpiresAt);

public sealed record RedeemSupportRequest(
    [property: JsonPropertyName("code")] string Code);

public sealed record RedeemSupportResponse(
    [property: JsonPropertyName("session")] string Session,
    [property: JsonPropertyName("hostConn")] string HostConn,
    [property: JsonPropertyName("hostName")] string HostName);

public sealed record PipeRequest(
    [property: JsonPropertyName("id")] ulong Id,
    [property: JsonPropertyName("method")] string Method,
    [property: JsonPropertyName("params")] JsonElement? Params = null);

public sealed record PipeError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message);

public sealed record PipeResponse(
    [property: JsonPropertyName("id")] ulong Id,
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("result")] JsonElement? Result,
    [property: JsonPropertyName("error")] PipeError? Error);

public sealed record SsoSession(
    [property: JsonPropertyName("accessToken")] string AccessToken,
    [property: JsonPropertyName("refreshToken")] string? RefreshToken,
    [property: JsonPropertyName("expiresAtUtc")] DateTimeOffset ExpiresAtUtc,
    [property: JsonPropertyName("userSub")] string UserSub,
    [property: JsonPropertyName("displayName")] string DisplayName);

public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("refresh_token")] string? RefreshToken,
    [property: JsonPropertyName("expires_in")] int ExpiresIn);

public sealed record UserInfoResponse(
    [property: JsonPropertyName("sub")] string Sub,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("preferred_username")] string? PreferredUsername);

public sealed record DisplayInfo(
    [property: JsonPropertyName("id")] uint Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("width")] uint Width,
    [property: JsonPropertyName("height")] uint Height,
    [property: JsonPropertyName("primary")] bool Primary);

public sealed record SignRegistrationParams(string Nonce, string UserSub, string Kind);
public sealed record CompleteRegistrationParams(string ServerUrl, string DeviceId, string UserSub, string Name, string DeviceToken, string RosterKey, string RosterKeyId);
public sealed record SetPinParams(string Pin);
public sealed record SetLanDirectParams(bool Enabled);
public sealed record ElevatedSetupPayload(string ServerUrl, string AccessToken, string UserSub, string HostName, string Pin);

public sealed record ViewerIdentity(string Seed, string PublicKey, string Id, string Token);
public sealed record SignViewerRegistration(string Seed, string Nonce, string UserSub, string Kind);
public sealed record ViewerOverlay(string NetworkName, string Credential, string Ipv4, string[] Peers);
public sealed record FfiConnectParams(string Addr, string HostPublicKey, string ViewerSeed, string ViewerDeviceId, string ViewerDisplayName, ulong Hwnd, ViewerOverlay? Overlay = null, ushort? LocalRpcPort = null)
{
    public string? ClientSessionId { get; init; }
    public string? PairingId { get; init; }
    public string? PairingKey { get; init; }
}
public sealed record HostPairing(string ViewerDeviceId, string Id, string Key);
public sealed record FfiSubmitPinParams(string Pin, bool Remember, string Label);
public sealed record FfiPointerParams(uint DisplayId, uint X, uint Y, int Button, bool Pressed, int WheelX, int WheelY);
public sealed record FfiKeyParams(uint Scancode, bool Extended, bool Pressed, string Text = "");
public sealed record FfiSelectDisplayParams(uint Id);

public sealed record RelhubManifest(
    [property: JsonPropertyName("app")] string App,
    [property: JsonPropertyName("platform")] string Platform,
    [property: JsonPropertyName("channel")] string Channel,
    [property: JsonPropertyName("versionCode")] long VersionCode,
    [property: JsonPropertyName("versionName")] string VersionName,
    [property: JsonPropertyName("file")] string File,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("minVersionCode")] long MinVersionCode,
    [property: JsonPropertyName("notes")] string? Notes,
    [property: JsonPropertyName("publishedAt")] string PublishedAt,
    [property: JsonPropertyName("keyId")] string KeyId,
    [property: JsonPropertyName("signature")] string Signature);

public sealed record RelhubCheckResponse(
    [property: JsonPropertyName("manifest")] RelhubManifest Manifest);

public sealed record FfiRequest<T>(
    [property: JsonPropertyName("method")] string Method,
    [property: JsonPropertyName("params")] T Params);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(DeviceItem))]
[JsonSerializable(typeof(DevicesResponse))]
[JsonSerializable(typeof(ChallengeResponse))]
[JsonSerializable(typeof(RegisterDeviceRequest))]
[JsonSerializable(typeof(RegisterDeviceResponse))]
[JsonSerializable(typeof(SupportCodeResponse))]
[JsonSerializable(typeof(RedeemSupportRequest))]
[JsonSerializable(typeof(RedeemSupportResponse))]
[JsonSerializable(typeof(PipeRequest))]
[JsonSerializable(typeof(PipeResponse))]
[JsonSerializable(typeof(SsoSession))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(UserInfoResponse))]
[JsonSerializable(typeof(DisplayInfo))]
[JsonSerializable(typeof(List<DisplayInfo>))]
[JsonSerializable(typeof(SignRegistrationParams))]
[JsonSerializable(typeof(CompleteRegistrationParams))]
[JsonSerializable(typeof(SetPinParams))]
[JsonSerializable(typeof(SetLanDirectParams))]
[JsonSerializable(typeof(ElevatedSetupPayload))]
[JsonSerializable(typeof(RelhubManifest))]
[JsonSerializable(typeof(RelhubCheckResponse))]
[JsonSerializable(typeof(FfiRequest<RelhubManifest>))]
[JsonSerializable(typeof(FfiRequest<FfiConnectParams>))]
[JsonSerializable(typeof(ViewerIdentity))]
[JsonSerializable(typeof(HostPairing))]
[JsonSerializable(typeof(FfiRequest<SignViewerRegistration>))]
[JsonSerializable(typeof(ViewerOverlay))]
[JsonSerializable(typeof(FfiRequest<FfiSubmitPinParams>))]
[JsonSerializable(typeof(FfiRequest<FfiPointerParams>))]
[JsonSerializable(typeof(FfiRequest<FfiKeyParams>))]
[JsonSerializable(typeof(FfiRequest<FfiSelectDisplayParams>))]
public partial class AppJsonContext : JsonSerializerContext;
