using System.Buffers;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MoonRemote.Models;
using MoonRemote.ViewModels;

namespace MoonRemote.Services;

internal static class DeviceConnection
{
    internal static async Task<FfiConnectParams> PrepareAsync(DeviceItem target, CancellationToken ct)
    {
        if (target.Kind != "host") throw new InvalidOperationException("This device is a controller, not a host.");
        var session = AppServices.Sso.CurrentSession ?? throw new InvalidOperationException("Sign in to connect.");
        var server = AppConfig.ServerUrl.TrimEnd('/');
        var viewer = await GetIdentityAsync(server, session.UserSub, ct);
        using var http = new HttpClient { BaseAddress = new Uri(server + "/"), Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Device", viewer.Token);
        var endpoint = await InviteAsync(http, target.Id, ct);
        // Device list responses to SSO users do not set the device-token-only "self" flag.
        // Only substitute loopback when both the registered device ID and pinned key match.
        bool local = false;
        ushort? rpc = null;
        try
        {
            var status = await AppServices.Pipe.CallAsync("status", null, ct);
            local = status.Ok && status.Result is { } r && r.GetProperty("deviceId").GetString() == target.Id
                && r.GetProperty("publicKey").GetString() == target.PublicKey;
            if (!local && status.Result is { } host && host.GetProperty("userSub").GetString() == session.UserSub
                && host.GetProperty("serverUrl").GetString()?.TrimEnd('/') == server
                && host.GetProperty("live").GetProperty("network").GetProperty("et").TryGetProperty("rpcPort", out var port)
                && port.TryGetUInt16(out var n) && n > 0) rpc = n;
        }
        catch (IOException) { } // A controller-only PC need not have a running host.
        ViewerOverlay? overlay = null;
        if (!local && rpc == null)
        {
            using var req = new StringContent("{\"occupied\":[]}", Encoding.UTF8, "application/json");
            using var resp = await http.PostAsync("v1/et/credential", req, ct);
            resp.EnsureSuccessStatusCode();
            overlay = JsonSerializer.Deserialize(await resp.Content.ReadAsStringAsync(ct), AppJsonContext.Default.ViewerOverlay)
                ?? throw new IOException("Empty viewer network credential.");
        }
        var addr = new IPEndPoint(local ? IPAddress.Loopback : endpoint.Address, endpoint.Port);
        return new FfiConnectParams(addr.ToString(), target.PublicKey, viewer.Seed, viewer.Id, Environment.MachineName, 0, overlay, rpc);
    }

    private static async Task<ViewerIdentity> GetIdentityAsync(string server, string subject, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MoonRemote");
        Directory.CreateDirectory(dir);
        var account = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(server + "\n" + subject)));
        var path = Path.Combine(dir, $"viewer-{account}.bin");
        using var guard = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
        if (File.Exists(path))
        {
            var clear = ProtectedData.Unprotect(await File.ReadAllBytesAsync(path, ct), null, DataProtectionScope.CurrentUser);
            var cached = JsonSerializer.Deserialize(clear, AppJsonContext.Default.ViewerIdentity) ?? throw new IOException("Invalid viewer identity.");
            var devices = await AppServices.Api.ListDevicesAsync(ct);
            if (devices.Any(d => d.Id == cached.Id && d.PublicKey == cached.PublicKey && d.Kind == "viewer")) return cached;
        }
        var key = NativeResult("""{"method":"generate_device_key"}""");
        var seed = key.GetProperty("seed").GetString()!;
        var challenge = await AppServices.Api.RequestChallengeAsync(ct);
        var sign = new FfiRequest<SignViewerRegistration>("sign_registration", new(seed, challenge.Nonce, subject, "viewer"));
        var signed = NativeResult(JsonSerializer.Serialize(sign, AppJsonContext.Default.FfiRequestSignViewerRegistration));
        var pub = signed.GetProperty("publicKey").GetString()!;
        var registered = await AppServices.Api.RegisterDeviceAsync(new RegisterDeviceRequest(Environment.MachineName + " (controller)",
            "viewer", pub, challenge.Nonce, signed.GetProperty("signature").GetString()!), ct);
        var identity = new ViewerIdentity(seed, pub, registered.Device.Id, registered.DeviceToken);
        var sealedBytes = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(identity, AppJsonContext.Default.ViewerIdentity), null, DataProtectionScope.CurrentUser);
        await File.WriteAllBytesAsync(path + ".tmp", sealedBytes, ct);
        File.Move(path + ".tmp", path, true);
        return identity;
    }

    internal static JsonElement NativeResult(string request)
    {
        using var doc = JsonDocument.Parse(AppServices.Native.Call(request));
        var root = doc.RootElement;
        if (!root.GetProperty("ok").GetBoolean()) throw new IOException(root.GetProperty("error").GetString());
        return root.GetProperty("result").Clone();
    }

    private static async Task<IPEndPoint> InviteAsync(HttpClient http, string hostId, CancellationToken ct)
    {
        using var response = await http.PostAsync("v1/signal/ticket", null, ct);
        response.EnsureSuccessStatusCode();
        using var ticket = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var uri = new UriBuilder(new Uri(http.BaseAddress!, "v1/signal"))
        {
            Scheme = http.BaseAddress!.Scheme == "https" ? "wss" : "ws",
            Query = "ticket=" + Uri.EscapeDataString(ticket.RootElement.GetProperty("ticket").GetString()!),
        };
        using var ws = new ClientWebSocket();
        await ws.ConnectAsync(uri.Uri, ct);
        string id = Guid.NewGuid().ToString("N");
        var invite = new ArrayBufferWriter<byte>();
        using (var w = new Utf8JsonWriter(invite))
        {
            w.WriteStartObject();
            w.WriteString("type", "invite");
            w.WriteString("session", id);
            w.WriteString("to", hostId);
            w.WriteEndObject();
        }
        await ws.SendAsync(invite.WrittenMemory, WebSocketMessageType.Text, true, ct);
        var buffer = new byte[4096];
        while (true)
        {
            using var message = new MemoryStream();
            ValueWebSocketReceiveResult frame;
            do
            {
                frame = await ws.ReceiveAsync(buffer.AsMemory(), ct);
                if (frame.MessageType == WebSocketMessageType.Close) throw new IOException("Signalling closed before the host replied.");
                if (message.Length + frame.Count > 65536) throw new IOException("Oversized signalling reply.");
                message.Write(buffer, 0, frame.Count);
            } while (!frame.EndOfMessage);
            using var doc = JsonDocument.Parse(message.ToArray());
            var msg = doc.RootElement;
            if (!msg.TryGetProperty("session", out var sid) || sid.GetString() != id) continue;
            string? type = msg.GetProperty("type").GetString();
            if (type == "error") throw new IOException("Signalling: " + msg.GetProperty("code").GetString());
            if (!msg.TryGetProperty("from", out var from) || from.GetString() != hostId) continue;
            var data = msg.GetProperty("data");
            if (type == "reject") throw new IOException("Host: " + data.GetProperty("reason").GetString());
            if (type == "quic-endpoint" && IPAddress.TryParse(data.GetProperty("ipv4").GetString(), out var addr)
                && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                && data.GetProperty("port").TryGetUInt16(out var port) && port != 0)
                return new IPEndPoint(addr, port);
        }
    }
}
