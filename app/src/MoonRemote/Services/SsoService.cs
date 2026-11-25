using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MoonRemote.Models;

namespace MoonRemote.Services;

/// <summary>
/// OAuth 2.0 Authorization Code + PKCE (S256) + RFC 9449 DPoP (ES256) sign-in against
/// sso.moonl.cloud using the registered desktop public client (ms_PTyfu8NoBmsYspSFmqdu).
/// </summary>
public sealed class SsoService
{
    private readonly HttpClient _http;
    private readonly string _sessionPath;
    private readonly string _sessionLockPath;
    private readonly ECDsa _dpopKey;
    private volatile SsoSession? _session;

    public event Action? SessionChanged;

    public SsoSession? CurrentSession => _session;
    public bool IsSignedIn => _session is not null;
    public bool SessionExpired { get; private set; }

    public SsoService()
        : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MoonRemote"),
            new HttpClient { Timeout = TimeSpan.FromSeconds(40) })
    {
    }

    internal SsoService(string dir, HttpClient http)
    {
        _http = http;
        Directory.CreateDirectory(dir);
        _sessionPath = Path.Combine(dir, "sso-session.json");
        _sessionLockPath = Path.Combine(dir, "sso-session.lock");
        _dpopKey = LoadOrCreateDpopKey(Path.Combine(dir, "dpop-p256.key"));
        LoadSaved();
    }

    private static ECDsa LoadOrCreateDpopKey(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var pkcs8 = File.ReadAllBytes(path);
                var ec = ECDsa.Create();
                ec.ImportPkcs8PrivateKey(pkcs8, out _);
                return ec;
            }
        }
        catch { }
        var created = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try { File.WriteAllBytes(path, created.ExportPkcs8PrivateKey()); } catch { }
        return created;
    }

    public static (string Verifier, string Challenge) CreatePkce()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64Url(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return (verifier, Base64Url(hash));
    }

    public static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public string ComputeDpopThumbprint()
    {
        var p = _dpopKey.ExportParameters(false);
        var x = Base64Url(p.Q.X!);
        var y = Base64Url(p.Q.Y!);
        // RFC 7638 canonical JWK JSON (lexicographical key order, no spaces).
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private string CreateDpopProof(string htm, string htu, string? nonce = null)
    {
        var p = _dpopKey.ExportParameters(false);
        var x = Base64Url(p.Q.X!);
        var y = Base64Url(p.Q.Y!);
        var header = $"{{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{x}\",\"y\":\"{y}\"}}}}";
        var jti = Base64Url(RandomNumberGenerator.GetBytes(16));
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var nonceField = string.IsNullOrEmpty(nonce) ? "" : $",\"nonce\":\"{nonce}\"";
        var payload = $"{{\"jti\":\"{jti}\",\"htm\":\"{htm}\",\"htu\":\"{htu}\",\"iat\":{iat}{nonceField}}}";

        var signingInput = $"{Base64Url(Encoding.UTF8.GetBytes(header))}.{Base64Url(Encoding.UTF8.GetBytes(payload))}";
        var sig = _dpopKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"{signingInput}.{Base64Url(sig)}";
    }

    private async Task<HttpResponseMessage> PostTokenWithDpopAsync(Dictionary<string, string> form, CancellationToken ct)
    {
        var tokenUrl = $"{AppConfig.SsoIssuer}/oauth/token";
        string? nonce = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
            {
                Content = new FormUrlEncodedContent(form),
            };
            req.Headers.Add("DPoP", CreateDpopProof("POST", tokenUrl, nonce));
            var resp = await _http.SendAsync(req, ct);
            if (resp.StatusCode == HttpStatusCode.BadRequest &&
                resp.Headers.TryGetValues("DPoP-Nonce", out var nonces) &&
                nonces.FirstOrDefault() is { Length: > 0 } serverNonce &&
                attempt == 0)
            {
                nonce = serverNonce;
                resp.Dispose();
                continue;
            }
            return resp;
        }
        throw new InvalidOperationException("DPoP nonce negotiation failed.");
    }

    public Task<SsoSession> SignInAsync(CancellationToken ct = default, Action<string>? reportProgress = null) =>
        SignInAsync(url => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }), ct, reportProgress);

    internal async Task<SsoSession> SignInAsync(Action<string> openBrowser, CancellationToken ct, Action<string>? reportProgress = null)
    {
        var (verifier, challenge) = CreatePkce();
        var state = Base64Url(RandomNumberGenerator.GetBytes(16));
        var dpopJkt = ComputeDpopThumbprint();

        using var listener = new HttpListener();
        var port = PickFreePort();
        var redirectUri = $"http://127.0.0.1:{port}/callback";
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var authUrl =
            $"{AppConfig.SsoIssuer}/oauth/authorize" +
            $"?response_type=code" +
            $"&client_id={Uri.EscapeDataString(AppConfig.DesktopClientId)}" +
            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
            $"&scope={Uri.EscapeDataString(AppConfig.SsoScope)}" +
            $"&resource={Uri.EscapeDataString(AppConfig.SsoResource)}" +
            $"&code_challenge={Uri.EscapeDataString(challenge)}" +
            $"&code_challenge_method=S256" +
            $"&dpop_jkt={Uri.EscapeDataString(dpopJkt)}" +
            $"&state={Uri.EscapeDataString(state)}";

        openBrowser(authUrl);

        HttpListenerContext callback;
        while (true)
        {
            callback = await listener.GetContextAsync().WaitAsync(ct);
            if (callback.Request.HttpMethod == "GET" && callback.Request.Url?.AbsolutePath == "/callback" &&
                callback.Request.QueryString["state"] == state)
                break;
            await ReplyToBrowserAsync(callback.Response, HttpStatusCode.BadRequest, "Invalid Moon Remote callback", "");
        }

        SsoSession session;
        try
        {
            var query = callback.Request.QueryString;
            if (query["error"] is { Length: > 0 } error)
                throw new InvalidOperationException($"SSO returned error: {error} ({query["error_description"]})");
            if (query["code"] is not { Length: > 0 } code)
                throw new InvalidOperationException("The Moon SSO callback did not contain an authorization code.");

            reportProgress?.Invoke(OnboardingText.For("Browser authorized. Exchanging the sign-in code…", "浏览器已授权，正在换取登录令牌…"));
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = AppConfig.DesktopClientId,
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = verifier,
                ["resource"] = AppConfig.SsoResource,
            };
            var tok = await RunSignInStepAsync(
                async () =>
                {
                    using var tokenResp = await PostTokenWithDpopAsync(form, ct);
                    tokenResp.EnsureSuccessStatusCode();
                    var tokenJson = await tokenResp.Content.ReadAsStringAsync(ct);
                    return JsonSerializer.Deserialize(tokenJson, AppJsonContext.Default.TokenResponse);
                },
                OnboardingText.For("exchanging the sign-in code", "换取登录令牌"), ct);
            if (tok is null || string.IsNullOrEmpty(tok.AccessToken) || tok.ExpiresIn <= 0)
                throw new InvalidOperationException("Moon SSO returned an invalid token response.");

            reportProgress?.Invoke(OnboardingText.For("Reading your Moon account…", "正在读取 Moon 账号资料…"));
            var (sub, name) = await RunSignInStepAsync(
                () => FetchSignInUserInfoAsync(tok.AccessToken, ct),
                OnboardingText.For("reading the Moon account profile", "读取账号资料"), ct);
            session = new SsoSession(tok.AccessToken, tok.RefreshToken, RefreshAt(tok.ExpiresIn), sub, name);
            using (await LockSessionAsync(ct))
            {
                Persist(session);
                SessionExpired = false;
                _session = session;
            }
        }
        catch (Exception ex)
        {
            await ReplyToBrowserAsync(callback.Response, HttpStatusCode.BadGateway,
                OnboardingText.For("Moon Remote sign-in failed", "Moon Remote 登录未完成"),
                ex.Message);
            throw;
        }

        SessionChanged?.Invoke();
        await ReplyToBrowserAsync(callback.Response, HttpStatusCode.OK,
            OnboardingText.For("Signed in to Moon Remote", "已登录 Moon Remote"),
            OnboardingText.For("Return to the app to continue.", "请返回应用继续操作。"));
        return session;
    }

    private async Task<(string Sub, string Name)> FetchSignInUserInfoAsync(string accessToken, CancellationToken ct)
    {
        try { return await FetchUserInfoAsync(accessToken, ct); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        catch (HttpRequestException ex) when (ex.StatusCode is HttpStatusCode.BadGateway or
            HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout) { }
        return await FetchUserInfoAsync(accessToken, ct);
    }

    private static async Task<T> RunSignInStepAsync<T>(Func<Task<T>> request, string step, CancellationToken ct)
    {
        try { return await request(); }
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException(OnboardingText.For(
                $"Moon SSO timed out while {step}. Try signing in again.",
                $"Moon SSO 在{step}时超时，请重试登录。"), ex);
        }
        catch (HttpRequestException ex)
        {
            throw new HttpRequestException(OnboardingText.For(
                $"Could not reach Moon SSO while {step}. {ex.Message}",
                $"在{step}时未能连接 Moon SSO。{ex.Message}"), ex);
        }
    }

    private static async Task ReplyToBrowserAsync(HttpListenerResponse response, HttpStatusCode status, string heading, string detail)
    {
        using var replyTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            var html = $"<!doctype html><meta charset=\"utf-8\"><body style='font-family:sans-serif;padding:2rem'><h2>{WebUtility.HtmlEncode(heading)}</h2><p>{WebUtility.HtmlEncode(detail)}</p></body>";
            var bytes = Encoding.UTF8.GetBytes(html);
            response.StatusCode = (int)status;
            response.Headers["Cache-Control"] = "no-store";
            response.Headers["Referrer-Policy"] = "no-referrer";
            response.ContentType = "text/html; charset=utf-8";
            response.ContentLength64 = bytes.Length;
            await response.OutputStream.WriteAsync(bytes, replyTimeout.Token);
        }
        catch (Exception ex) when (ex is IOException or HttpListenerException or OperationCanceledException) { }
        finally { response.Close(); }
    }

    public Task<string?> GetValidAccessTokenAsync(CancellationToken ct = default) =>
        GetValidAccessTokenAsync(null, ct);

    internal async Task<string?> GetValidAccessTokenAsync(string? rejectedToken, CancellationToken ct)
    {
        var initial = _session;
        if (initial is null) return null;
        if (CanUse(initial, rejectedToken)) return initial.AccessToken;

        using var sessionLock = await LockSessionAsync(ct);
        var session = _session;
        if (session is null || session.UserSub != initial.UserSub) return null;
        if (CanUse(session, rejectedToken)) return session.AccessToken;

        // Another instance may already have rotated the saved refresh token.
        var saved = ReadSaved();
        if (saved is null || saved.UserSub != session.UserSub)
        {
            SetSignedOut(expired: true);
            return null;
        }
        if (saved.RefreshToken != session.RefreshToken || saved.AccessToken != session.AccessToken)
            _session = session = saved;

        if (CanUse(session, rejectedToken)) return session.AccessToken;
        if (string.IsNullOrEmpty(session.RefreshToken))
        {
            DeleteSaved();
            SetSignedOut(expired: true);
            return null;
        }

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = AppConfig.DesktopClientId,
            ["refresh_token"] = session.RefreshToken,
            ["resource"] = AppConfig.SsoResource,
        };
        using var renewalTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        renewalTimeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var resp = await PostTokenWithDpopAsync(form, renewalTimeout.Token);
        if (!resp.IsSuccessStatusCode)
        {
            if (resp.StatusCode == HttpStatusCode.BadRequest &&
                await IsInvalidGrantAsync(resp, ct))
            {
                DeleteSaved();
                SetSignedOut(expired: true);
                return null;
            }

            throw new HttpRequestException($"Moon SSO could not renew your session (HTTP {(int)resp.StatusCode}).",
                null, resp.StatusCode);
        }

        var tok = JsonSerializer.Deserialize(await resp.Content.ReadAsStringAsync(ct), AppJsonContext.Default.TokenResponse);
        if (tok is null || string.IsNullOrEmpty(tok.AccessToken) || tok.ExpiresIn <= 0)
            throw new InvalidOperationException("Moon SSO returned an invalid token response.");

        var updated = session with
        {
            AccessToken = tok.AccessToken,
            RefreshToken = string.IsNullOrEmpty(tok.RefreshToken) ? session.RefreshToken : tok.RefreshToken,
            ExpiresAtUtc = RefreshAt(tok.ExpiresIn),
        };
        Persist(updated);
        _session = updated;
        return updated.AccessToken;
    }

    private static bool CanUse(SsoSession session, string? rejectedToken) =>
        !string.IsNullOrEmpty(session.AccessToken) && session.AccessToken != rejectedToken &&
        session.ExpiresAtUtc > DateTimeOffset.UtcNow;

    private static DateTimeOffset RefreshAt(int expiresIn) =>
        DateTimeOffset.UtcNow.AddSeconds(expiresIn - Math.Min(30, expiresIn / 2));

    private static async Task<bool> IsInvalidGrantAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            return json.RootElement.ValueKind == JsonValueKind.Object &&
                json.RootElement.TryGetProperty("error", out var error) &&
                error.ValueKind == JsonValueKind.String && error.GetString() == "invalid_grant";
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public async Task SignOutAsync()
    {
        using (await LockSessionAsync())
        {
            if (ReadSaved()?.UserSub == _session?.UserSub)
                File.Delete(_sessionPath);
            SessionExpired = false;
            _session = null;
        }
        SessionChanged?.Invoke();
    }

    private void DeleteSaved()
    {
        try { File.Delete(_sessionPath); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private void SetSignedOut(bool expired)
    {
        SessionExpired = expired;
        _session = null;
        SessionChanged?.Invoke();
    }

    private async Task<(string Sub, string Name)> FetchUserInfoAsync(string accessToken, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{AppConfig.SsoIssuer}/oauth/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var info = JsonSerializer.Deserialize(await resp.Content.ReadAsStringAsync(ct), AppJsonContext.Default.UserInfoResponse)
            ?? throw new InvalidOperationException("Empty userinfo response.");
        return (info.Sub, info.Name ?? info.PreferredUsername ?? info.Sub);
    }

    private void Persist(SsoSession session)
    {
        var temp = $"{_sessionPath}.{Guid.NewGuid():N}.tmp";
        var json = JsonSerializer.Serialize(session, AppJsonContext.Default.SsoSession);
        try
        {
            File.WriteAllText(temp, json, Encoding.UTF8);
            File.Move(temp, _sessionPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    private void LoadSaved()
    {
        try { _session = ReadSaved(); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private SsoSession? ReadSaved()
    {
        try
        {
            using var stream = new FileStream(_sessionPath, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            return JsonSerializer.Deserialize(reader.ReadToEnd(), AppJsonContext.Default.SsoSession);
        }
        catch (FileNotFoundException) { return null; }
        catch (JsonException) { return null; }
    }

    private async Task<FileStream> LockSessionAsync(CancellationToken ct = default)
    {
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(_sessionLockPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
            }
            catch (IOException ex) when ((ex.HResult & 0xffff) is 32 or 33)
            {
                if (elapsed.Elapsed >= TimeSpan.FromSeconds(35))
                    throw new IOException("Moon Remote is still renewing this session in another window. Try again shortly.", ex);
                await Task.Delay(75, ct);
            }
        }
    }

    private static int PickFreePort()
    {
        using var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }
}
