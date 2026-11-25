using System.Net;
using System.Web;
using MoonRemote.Services;
using Xunit;

namespace MoonRemote.Tests;

public sealed class SignInCallbackTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("moonrd-oauth-test-").FullName;

    [Fact]
    public async Task BrowserSuccessWaitsForTheSavedDesktopSession()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exchange = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var userInfoRequests = 0;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var client = new HttpClient(new StubHandler(async (request, ct) =>
        {
            if (request.Method == HttpMethod.Post)
            {
                entered.SetResult();
                await exchange.Task.WaitAsync(ct);
                return Reply(HttpStatusCode.OK, """{"access_token":"test","refresh_token":"test-renewal","expires_in":600}""");
            }
            return ++userInfoRequests == 1
                ? Reply(HttpStatusCode.ServiceUnavailable, "")
                : Reply(HttpStatusCode.OK, """{"sub":"test-sub","name":"Test User"}""");
        }));
        using var browser = new HttpClient(new HttpClientHandler { UseProxy = false });
        var sso = new SsoService(_directory, client);
        var url = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var signIn = sso.SignInAsync(url.SetResult, timeout.Token);
        var (callback, state) = await CallbackAsync(url.Task, signIn, timeout.Token);
        using var noise = await browser.GetAsync($"{callback}?state=wrong&code=wrong", timeout.Token);
        Assert.Equal(HttpStatusCode.BadRequest, noise.StatusCode);

        var request = browser.GetAsync($"{callback}?state={state}&code=test", timeout.Token);
        await entered.Task.WaitAsync(timeout.Token);
        Assert.False(request.IsCompleted);
        Assert.False(sso.IsSignedIn);
        exchange.SetResult();

        using var response = await request;
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(sso.IsSignedIn);
        Assert.Equal("Test User", (await signIn).DisplayName);
        Assert.True(File.Exists(Path.Combine(_directory, "sso-session.json")));
        Assert.Equal(2, userInfoRequests);
    }

    [Fact]
    public async Task BrowserShowsTheTokenExchangeTimeoutWithoutReusingTheCode()
    {
        var exchanges = 0;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var client = new HttpClient(new StubHandler((_, _) =>
        {
            exchanges++;
            throw new TaskCanceledException();
        }));
        using var browser = new HttpClient(new HttpClientHandler { UseProxy = false });
        var sso = new SsoService(_directory, client);
        var url = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var signIn = sso.SignInAsync(url.SetResult, timeout.Token);
        var (callback, state) = await CallbackAsync(url.Task, signIn, timeout.Token);
        using var response = await browser.GetAsync($"{callback}?state={state}&code=test", timeout.Token);
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Contains(OnboardingText.For("sign-in failed", "登录未完成"), await response.Content.ReadAsStringAsync(timeout.Token));
        var error = await Assert.ThrowsAsync<TimeoutException>(() => signIn);
        Assert.Contains(OnboardingText.For("exchanging the sign-in code", "换取登录令牌"), error.Message);
        Assert.False(sso.IsSignedIn);
        Assert.Equal(1, exchanges);
    }

    private static async Task<(string Callback, string State)> CallbackAsync(Task<string> url, Task signIn, CancellationToken ct)
    {
        if (await Task.WhenAny(url, signIn).WaitAsync(ct) == signIn)
            await signIn;
        var query = HttpUtility.ParseQueryString(new Uri(await url.WaitAsync(ct)).Query);
        return (query["redirect_uri"]!, query["state"]!);
    }

    private static HttpResponseMessage Reply(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body) };

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
}
