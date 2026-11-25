using System.Net;
using System.Text.Json;
using MoonRemote.Models;
using MoonRemote.Services;
using Xunit;

namespace MoonRemote.Tests;

public sealed class SessionRecoveryTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("moonremote-sso-").FullName;
    private string SessionPath => Path.Combine(_dir, "sso-session.json");

    [Fact]
    public async Task TwoInstancesRenewAnExpiredSessionOnlyOnce()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var requests = 0;
        using var client = new HttpClient(new StubHandler(async () =>
        {
            Interlocked.Increment(ref requests);
            started.TrySetResult();
            await release.Task;
            return NewToken();
        }));
        var sso = LoadSession(client);
        var otherInstance = new SsoService(_dir, client);

        var first = sso.GetValidAccessTokenAsync();
        await started.Task;
        var second = otherInstance.GetValidAccessTokenAsync();
        release.SetResult();

        Assert.Equal(new[] { "fresh-access", "fresh-access" }, await Task.WhenAll(first, second));
        Assert.Equal(1, requests);
        Assert.Equal("fresh-refresh", new SsoService(_dir, client).CurrentSession!.RefreshToken);
    }

    [Fact]
    public async Task InvalidGrantClearsTheCachedAccountAndSignalsReauthentication()
    {
        using var client = new HttpClient(new StubHandler(() => Task.FromResult(
            Response(HttpStatusCode.BadRequest, """{"error":"invalid_grant"}"""))));
        var sso = LoadSession(client);
        var notifications = 0;
        sso.SessionChanged += () => notifications++;

        Assert.Null(await sso.GetValidAccessTokenAsync());
        Assert.True(sso.SessionExpired);
        Assert.False(sso.IsSignedIn);
        Assert.False(File.Exists(SessionPath));
        Assert.Equal(1, notifications);
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.BadRequest)]
    public async Task UnavailableSsoKeepsTheSessionForRetry(HttpStatusCode status)
    {
        var requests = 0;
        using var client = new HttpClient(new StubHandler(() => Task.FromResult(
            ++requests == 1 ? Response(status, "<html>upstream error</html>") : NewToken())));
        var sso = LoadSession(client);

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => sso.GetValidAccessTokenAsync());
        Assert.Equal(status, error.StatusCode);
        Assert.True(sso.IsSignedIn);
        Assert.False(sso.SessionExpired);
        Assert.True(File.Exists(SessionPath));
        Assert.Equal("fresh-access", await sso.GetValidAccessTokenAsync());
    }

    [Fact]
    public async Task SignOutDuringRenewalDoesNotRestoreTheSession()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var client = new HttpClient(new StubHandler(async () =>
        {
            await release.Task;
            return NewToken();
        }));
        var sso = LoadSession(client);
        var pending = sso.GetValidAccessTokenAsync();

        var signOut = sso.SignOutAsync();
        release.SetResult();

        Assert.Equal("fresh-access", await pending);
        await signOut;
        Assert.False(sso.IsSignedIn);
        Assert.False(File.Exists(SessionPath));
    }

    [Fact]
    public async Task DeviceListRetriesUnauthorizedWithANewToken()
    {
        using var ssoClient = new HttpClient(new StubHandler(() => Task.FromResult(NewToken())));
        var sso = LoadSession(ssoClient, expired: false);
        var requests = 0;
        using var apiClient = new HttpClient(new StubHandler(request =>
        {
            Assert.Equal("/v1/devices", request.RequestUri!.AbsolutePath);
            Assert.Equal(++requests == 1 ? "saved-access" : "fresh-access", request.Headers.Authorization!.Parameter);
            return Task.FromResult(requests == 1
                ? Response(HttpStatusCode.Unauthorized, "{}")
                : Response(HttpStatusCode.OK, """{"devices":[{"id":"d1","name":"Office","kind":"host","publicKey":"AAAA","online":true,"self":false}]}"""));
        }));

        var device = Assert.Single(await new ServerApiClient(sso, apiClient).ListDevicesAsync());
        Assert.Equal("d1", device.Id);
        Assert.Equal(2, requests);
    }

    private SsoService LoadSession(HttpClient client, bool expired = true)
    {
        var session = new SsoSession("saved-access", "saved-refresh",
            DateTimeOffset.UtcNow.AddMinutes(expired ? -5 : 5), "test-user", "Test account");
        File.WriteAllText(SessionPath, JsonSerializer.Serialize(session, AppJsonContext.Default.SsoSession));
        return new SsoService(_dir, client);
    }

    private static HttpResponseMessage NewToken() => Response(HttpStatusCode.OK,
        """{"access_token":"fresh-access","refresh_token":"fresh-refresh","expires_in":600}""");

    private static HttpResponseMessage Response(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body) };

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public StubHandler(Func<Task<HttpResponseMessage>> respond) : this(_ => respond()) { }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            respond(request);
    }
}
