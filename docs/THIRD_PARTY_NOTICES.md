# Third-Party Notices

Moon Remote Desktop includes or dynamically invokes the following third-party software.

## EasyTier (LGPL-3.0)

- **Component:** `easytier-core.exe`, `easytier-cli.exe` (pinned v2.7.1)
- **License:** GNU Lesser General Public License v3.0 (LGPL-3.0)
- **Source:** https://github.com/EasyTier/EasyTier
- **Usage:** Distributed unmodified as separate companion executables invoked over process boundaries (`--rpc-portal`). Moon Remote Desktop does not bundle Npcap's `Packet.dll`; an empty stub (`core/crates/packet-stub`) is supplied in its place because Moon Remote operates in `--no-tun` mode. Users may also configure a custom `easytier-core` path in Settings.

## Rust Core Dependencies

- **quinn** — Apache-2.0 / MIT (https://github.com/quinn-rs/quinn)
- **rustls** — Apache-2.0 / ISC / MIT (https://github.com/rustls/rustls)
- **spake2** (RustCrypto) — Apache-2.0 / MIT (https://github.com/RustCrypto/PAKEs)
- **argon2** (RustCrypto) — Apache-2.0 / MIT (https://github.com/RustCrypto/password-hashes)
- **ed25519-dalek** — BSD-3-Clause (https://github.com/dalek-cryptography/curve25519-dalek)
- **tokio** — MIT (https://github.com/tokio-rs/tokio)
- **windows-rs** — Apache-2.0 / MIT (https://github.com/microsoft/windows-rs)
- **prost** — Apache-2.0 (https://github.com/tokio-rs/prost)
- **reqwest** — Apache-2.0 / MIT (https://github.com/seanmonstar/reqwest)
- **tokio-tungstenite** — MIT (https://github.com/snapview/tokio-tungstenite)

## Desktop UI Dependencies (.NET)

- **Avalonia UI** — MIT (https://github.com/AvaloniaUI/Avalonia)
- **Lumen.UI** — MIT
- **CommunityToolkit.Mvvm** — MIT (https://github.com/CommunityToolkit/dotnet)

## Web Controller Dependencies (TypeScript)

- **@noble/curves** — MIT (https://github.com/paulmillr/noble-curves)
- **@noble/hashes** — MIT (https://github.com/paulmillr/noble-hashes)
- **Vite** — MIT (https://github.com/vitejs/vite)
