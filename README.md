# Moon Remote Desktop

A remote-control product for Windows in the style of Chrome Remote Desktop:

- **Desktop app** (Windows x64): controller and host in one app. UI is [Lumen.UI](../CSharpGUIFramework) on Avalonia; the media core and host service are Rust.
- **Web controller** at remote.moonl.cloud (WebRTC), which also links to the Windows download.
- Accounts via sso.moonl.cloud; each host also requires a **PIN**, verified end-to-end with SPAKE2 so the server never sees it.
- Same-account devices connect over a bundled **EasyTier** companion process. Network credentials are issued short-lived by the server and are never built into the client. A user's own EasyTier install is left untouched.
- Optional LAN direct mode when the server is unreachable.
- Releases are published to release.moonl.cloud.

The full design is in [docs/architecture.md](docs/architecture.md); the session protocol is in [proto/moonrd.proto](proto/moonrd.proto).

## Layout

| Path | What |
| --- | --- |
| `app/` | C# Lumen desktop app (`MoonRemote.slnx`) |
| `core/` | Rust workspace: media core, host service, EasyTier supervisor (`moonrd-et`) |
| `server/` | Go control plane (`moon-remote-server`) and, later, the web controller |
| `proto/` | Session protocol shared by Rust and TypeScript |
| `scripts/` | Build and release scripts |
| `spikes/` | Phase 0 technical spike reports (`REPORT.md`; the throwaway spike code is not published) |

## Build

Needs .NET 10 SDK, Rust 1.91+ (MSVC), and Go 1.27+.

```powershell
./scripts/fetch-easytier.ps1      # pinned EasyTier v2.7.1, checksum-verified, Npcap-free (third_party/, git-ignored)
./scripts/build.ps1               # clippy + test core, vet + test + build server, build app
./scripts/build.ps1 -Only app
dotnet run --project app/src/MoonRemote
```

With `third_party/easytier/windows-x86_64` present, `build.ps1` also runs the EasyTier integration tests (real nodes, credential issue/join/revoke).

## Third-party code

RustDesk (AGPL-3.0) is used only as an architectural reference; none of its code is copied. EasyTier (LGPL-3.0) is shipped as an unmodified separate executable.
