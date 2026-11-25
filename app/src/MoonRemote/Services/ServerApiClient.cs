using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using MoonRemote.Models;

namespace MoonRemote.Services;

public sealed class ServerApiClient
{
    private readonly HttpClient _http;
    private readonly SsoService _sso;

    public ServerApiClient(SsoService sso)
        : this(sso, new HttpClient { Timeout = TimeSpan.FromSeconds(15) })
    {
    }

    internal ServerApiClient(SsoService sso, HttpClient http)
    {
        _sso = sso;
        _http = http;
    }

    private string BaseUrl => AppConfig.ServerUrl.TrimEnd('/');

    private async Task<HttpRequestMessage> AuthedAsync(HttpMethod method, string path, CancellationToken ct)
    {
        var token = await _sso.GetValidAccessTokenAsync(ct)
            ?? throw new InvalidOperationException("Sign in required.");
        return Authed(method, path, token);
    }

    private HttpRequestMessage Authed(HttpMethod method, string path, string token)
    {
        var req = new HttpRequestMessage(method, $"{BaseUrl}{path}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return req;
    }

    public async Task<List<DeviceItem>> ListDevicesAsync(CancellationToken ct = default)
    {
        using var req = await AuthedAsync(HttpMethod.Get, "/v1/devices", ct);
        using var resp = await _http.SendAsync(req, ct);
        if (resp.StatusCode == HttpStatusCode.Unauthorized)
        {
            var token = await _sso.GetValidAccessTokenAsync(req.Headers.Authorization!.Parameter, ct)
                ?? throw new InvalidOperationException("Sign in required.");
            using var retry = Authed(HttpMethod.Get, "/v1/devices", token);
            using var retryResp = await _http.SendAsync(retry, ct);
            return await ReadDevicesAsync(retryResp, ct);
        }
        return await ReadDevicesAsync(resp, ct);
    }

    private static async Task<List<DeviceItem>> ReadDevicesAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct);
        return JsonSerializer.Deserialize(body, AppJsonContext.Default.DevicesResponse)?.Devices
            ?? throw new InvalidOperationException("The device server returned an invalid list.");
    }

    public async Task<ChallengeResponse> RequestChallengeAsync(CancellationToken ct = default)
    {
        using var req = await AuthedAsync(HttpMethod.Post, "/v1/devices/challenge", ct);
        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct);
        return JsonSerializer.Deserialize(body, AppJsonContext.Default.ChallengeResponse)
            ?? throw new InvalidOperationException("Empty challenge response.");
    }

    public async Task<RegisterDeviceResponse> RegisterDeviceAsync(RegisterDeviceRequest payload, CancellationToken ct = default)
    {
        using var req = await AuthedAsync(HttpMethod.Post, "/v1/devices", ct);
        req.Content = new StringContent(
            JsonSerializer.Serialize(payload, AppJsonContext.Default.RegisterDeviceRequest),
            Encoding.UTF8,
            "application/json");
        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct);
        return JsonSerializer.Deserialize(body, AppJsonContext.Default.RegisterDeviceResponse)
            ?? throw new InvalidOperationException("Empty register response.");
    }

    public async Task DeleteDeviceAsync(string id, CancellationToken ct = default)
    {
        using var req = await AuthedAsync(HttpMethod.Delete, $"/v1/devices/{Uri.EscapeDataString(id)}", ct);
        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
    }

    public async Task<SupportCodeResponse> CreateSupportCodeAsync(CancellationToken ct = default)
    {
        using var req = await AuthedAsync(HttpMethod.Post, "/v1/support/codes", ct);
        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct);
        return JsonSerializer.Deserialize(body, AppJsonContext.Default.SupportCodeResponse)
            ?? throw new InvalidOperationException("Empty support code response.");
    }

    public async Task<RedeemSupportResponse> RedeemSupportCodeAsync(string code, CancellationToken ct = default)
    {
        using var req = await AuthedAsync(HttpMethod.Post, "/v1/support/redeem", ct);
        req.Content = new StringContent(
            JsonSerializer.Serialize(new RedeemSupportRequest(code), AppJsonContext.Default.RedeemSupportRequest),
            Encoding.UTF8,
            "application/json");
        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct);
        return JsonSerializer.Deserialize(body, AppJsonContext.Default.RedeemSupportResponse)
            ?? throw new InvalidOperationException("Empty redeem response.");
    }
}
