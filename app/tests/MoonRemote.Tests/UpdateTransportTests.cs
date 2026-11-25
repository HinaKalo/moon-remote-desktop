using System.Net;
using MoonRemote.Services;
using Xunit;

namespace MoonRemote.Tests;

public sealed class UpdateTransportTests
{
    private const string Path = "/v1/apps/moon-remote/check?platform=windows-x64&channel=stable&versionCode=23";

    [Fact]
    public async Task TlsFailureFallsBackToTheFixedHttpsMirror()
    {
        var requests = new List<string>();
        using var native = new NativeBridge();
        using var http = new HttpClient(new StubHandler((request, _) =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            requests.Add(url);
            if (url == UpdateService.RelhubBaseUrl + Path)
                throw new HttpRequestException(HttpRequestError.SecureConnectionError, "TLS failed");
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        var service = new UpdateService(native, http);

        using var first = await service.FetchReleaseAsync(Path, HttpCompletionOption.ResponseContentRead, default);
        using var second = await service.FetchReleaseAsync(Path, HttpCompletionOption.ResponseHeadersRead, default);

        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(new[]
        {
            UpdateService.RelhubBaseUrl + Path,
            UpdateService.MirrorBaseUrl + Path,
            UpdateService.MirrorBaseUrl + Path,
        }, requests);
    }

    [Fact]
    public async Task MissingPackageIsNotRetriedAgainstTheMirror()
    {
        var attempts = 0;
        using var native = new NativeBridge();
        using var http = new HttpClient(new StubHandler((_, _) =>
        {
            attempts++;
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var service = new UpdateService(native, http);
        using var response = await service.FetchReleaseAsync(Path, HttpCompletionOption.ResponseContentRead, default);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task BothOriginsFailingReportsEachAddress()
    {
        using var native = new NativeBridge();
        using var http = new HttpClient(new StubHandler((_, _) =>
            throw new HttpRequestException(HttpRequestError.SecureConnectionError, "TLS failed")));
        var service = new UpdateService(native, http);
        var error = await Assert.ThrowsAsync<HttpRequestException>(
            () => service.FetchReleaseAsync(Path, HttpCompletionOption.ResponseContentRead, default));
        Assert.Contains("release.moonl.cloud", error.Message);
        Assert.Contains("remote.moonl.cloud", error.Message);
        Assert.Contains("TLS failed", error.Message);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(send(request, ct));
    }
}
