using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MoonRemote.Models;

namespace MoonRemote.Services;

internal sealed class RememberedHost
{
    private readonly string _path;
    private readonly byte[] _scope;

    public RememberedHost(string directory, string server, string account, DeviceItem host)
    {
        _scope = SHA256.HashData(Encoding.UTF8.GetBytes($"{server.TrimEnd('/')}\n{account}\n{host.Id}\n{host.PublicKey}"));
        _path = Path.Combine(directory, $"pairing-{Convert.ToHexString(_scope)}.bin");
    }

    public HostPairing? Load()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var data = ProtectedData.Unprotect(File.ReadAllBytes(_path), _scope, DataProtectionScope.CurrentUser);
            var pairing = JsonSerializer.Deserialize(data, AppJsonContext.Default.HostPairing);
            return Valid(pairing) ? pairing : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or JsonException)
        {
            return null;
        }
    }

    public void Save(HostPairing pairing)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (!Valid(pairing)) throw new CryptographicException("The host supplied an invalid pairing.");
        var data = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(pairing, AppJsonContext.Default.HostPairing),
            _scope, DataProtectionScope.CurrentUser);
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temp = _path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temp, data);
            File.Move(temp, _path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    public void Forget(HostPairing pairing)
    {
        if (Load() != pairing) return;
        try { File.Delete(_path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static bool Valid(HostPairing? pairing)
    {
        Span<byte> buffer = stackalloc byte[32];
        return pairing is { ViewerDeviceId.Length: > 0 } &&
            Convert.TryFromBase64String(pairing.Id ?? "", buffer, out var idBytes) && idBytes == 16 &&
            Convert.TryFromBase64String(pairing.Key ?? "", buffer, out var keyBytes) && keyBytes == 32;
    }
}
