# EasyTier Phase 0a spike — report

Date: 2026-11-20 · Machine: Windows 11 Pro 26200, non-admin user (one approved elevated run for the TUN case) ·
Binaries: official zips from github.com/EasyTier, checksums verified (see §1).
All scripts are in this folder; raw outputs in `out/` (gitignored, they contain throwaway keys of dead test networks).

## Verdict

| # | Question | Verdict |
|---|----------|---------|
| 1 | Version to pin, core vs mini | **GO: pin easytier-core v2.7.1** (pre-release). Credentials exist since v2.6.0, so 2.7.x isn't strictly required, but 2.7.1 is needed for the device-side launch mode we want (see §1). **easytier-mini: NO-GO.** |
| 2 | Server-issued credential → join → revoke | **GO.** Works end to end via `easytier-cli -o json credential …`. Correction to the plan: the joiner does **not** use `--credential-file`; see §2. |
| 3 | No-TUN controller reaching the host through a runtime port forward | **GO for no-TUN on both sides** (QUIC 20/20 echoes, 4 MiB bulk, no admin anywhere). `--no-tun` runs without admin: **yes**. With a TUN host: **inconclusive.** The adapter comes up, but the forward failed in the single-machine test (§3). |
| 4 | Running next to the user's own EasyTier | **GO with the isolated flag set.** Tested next to the user's real `easytier-gui` service; before/after detection diff was empty. Default-flag instances do conflict (§4). |
| 5 | `Packet.dll` | **Do not ship it.** It is Npcap 1.79 (not redistributable without an Npcap OEM licence). But core and cli **hard-import it**, so ship a replacement: either a no-op stub (built and verified here) or a source build without `faketcp` (§5). |
| — | Fallback (easytier-web + webhook) | Not needed. Assessed briefly in §6; it is worse for the "no secret in the client" requirement. |

**Recommended pin:** EasyTier **v2.7.1**, tag commit `0d9c52b1`, published 2026-11-16 as a pre-release.
- `easytier-windows-x86_64-v2.7.1.zip`: sha256 `6279ce18906f345345780b2f0c507125fcae861a54c45cc62efe58d5312de46b`
- `easytier-linux-x86_64-v2.7.1.zip` (server): sha256 `8dc4f8576c7a4978c1f000630014b75ec88d172f6cb10935e72092ddd5ec7a9a`

Both come from the release's `SHA256SUMS`. Move to the first 2.7.x that GitHub marks "Latest" once it ships.

---

## 1. Version and core vs mini

Evidence (`gh release list -R EasyTier/EasyTier`):

```
v2.7.1  Pre-release  2026-11-16      v2.6.4  Latest  2026-05-12
v2.7.0  Pre-release  2026-10-06      v2.6.0..v2.6.3 Pre-release (EasyTier marks most releases pre-release)
easytier-mini: v2.7.0 Pre-release, v2.7.0-preview.2 "Latest"
```

- **Credentials since v2.6.0.** The v2.6.0 notes say secure mode "first introduced in v2.6.0… admin nodes can issue temporary credentials" (#1808). `easytier/docs/credential_peer.md` is absent at v2.5.0 and present from v2.6.0.
- Checksums: the v2.7.1 zip matched `SHA256SUMS`. The mini v2.7.0 zip matched its `SHA256SUMS` (`36ba20e9…`). v2.6.4 has no `SHA256SUMS` file; its zip matched the GitHub asset digest `sha256:27af91e2…`.

**v2.6.4 vs v2.7.1, measured here:**

| | v2.6.4 (Latest) | v2.7.1 (pre-release) |
|---|---|---|
| `credential generate/revoke/list` | yes | yes, plus `credential peers` |
| `generate` JSON `expiry_unix` | **number** | **string** (proto3 int64 mapping). The Go client must accept both. |
| Credential in TOML `[secure_mode]` | **fails** ("local public key is not set"; with the pubkey added: "invalid proof and unknown credential") | works; the public key is derived |
| Runtime `port-forward add` | works on a flag-launched node (credential via `ET_CREDENTIAL`) | rejected on flag/env-launched nodes ("configuration file is read-only"); works when launched from a writable `-c` TOML (§3) |
| Forwarded QUIC bulk (same host, relayed) | ~183 Mbit/s | ~430–545 Mbit/s |
| Fixes relevant to us | — | QUIC reorder, secure-relay, port-forward listener hot reload (#2710), Windows TUN restart/name reuse (#2773), heartbeat replay (#2718) |

**easytier-mini v2.7.0 is a NO-GO** (`mini-test.sh`, `out/run-mini.out`):
- Credential join and revoke work, and it does not import `packet.dll` (4.6 MB exe plus `wintun.dll`).
- It **ignores `rpc_portal`** and always binds `127.0.0.1:15888` (log: `RPC: 127.0.0.1:15888`), which is the user's default EasyTier port. That is a hard conflict.
- It ignores `[[port_forward]]` (the QUIC dial through a static forward timed out), and the RPC is unreachable on the port we asked for, so there is no runtime port-forward either.
- Its CLI is only `--config/--config-server/--machine-id/--hostname/--secure-mode`, and its README calls it a "POC".

## 2. Credential issue → join → revoke (`cred-test.sh`, `cred-expiry-test.sh`)

Topology: admin node A (holds `network_secret`) and joiner B (credential only). All `--no-tun` on 127.0.0.1.

**Correction to the plan:** `--credential-file` is the **admin-side store** ("credential storage path, to keep generated credentials across admin restarts"). A joiner uses `--credential <base64 private key>`, the env var `ET_CREDENTIAL`, or `[secure_mode] local_private_key` in its TOML. `--credential` implies `--secure-mode`.

### CLI/JSON shapes for the Go server (v2.7.1)

```
easytier-cli -p 127.0.0.1:<rpc> -o json credential generate --ttl 86400 --credential-id dev-0001 \
    --groups mrd-devices --allow-relay [--reusable false] [--allowed-proxy-cidrs a,b]
{ "credential_id": "dev-0001",
  "credential_secret": "<44-char base64 X25519 private key>",
  "expiry_unix": "1795267640" }          # string in 2.7.1, number in 2.6.4
```

- Generating again with the same `--credential-id` returns the **same** secret and expiry (idempotent, safe to retry). Renewal therefore needs a **new** id, e.g. `<deviceId>.<epoch>`.

```
easytier-cli … -o json credential list
{ "credentials": [ { "credential_id": "dev-0001", "groups": ["mrd-devices"], "allow_relay": true,
    "expiry_unix": "1795267640", "reusable": true,
    "public_key_fingerprint": "30e9e45b…f5bf85" } ] }      # list is "{}" when empty;
                                                        # groups/allow_relay omitted when default
easytier-cli … -o json credential peers                 # 2.7.x only
{ "credentials": [ { "credential_id": "dev-0001",
    "peers": [ { "peer_id": 1974832667, "ipv4": "10.250.7.2", "ipv6": null, "hostname": "spikeB" } ] } ] }
easytier-cli … -o json credential revoke dev-0001   →   { "success": true }
easytier-cli … -o json peer list                     →   [ { "cidr","ipv4","hostname","cost":"p2p|relay(2)|Local",
                                                           "lat_ms","loss_rate","rx_bytes","tx_bytes","tunnel_proto",
                                                           "nat_type","id","version" } ]
```

Admin store file (`--credential-file`, JSON map keyed by credential id; it survives an admin restart):

```json
{ "dev-long": { "pubkey": "<base64>", "secret": "<base64 private key>", "groups": ["mrd-devices"],
                "allow_relay": true, "allowed_proxy_cidrs": [], "reusable": false,
                "expiry_unix": 1795267778, "created_at_unix": 1795181378 } }
```

The store holds the device **private** keys, so it must sit in the server's protected data dir. The server also needs the public key for 2.6.x clients' TOML; it is in this file.

### Observed behaviour

| Step | Result |
|---|---|
| Join | B joined with only `ET_CREDENTIAL` (no secret on argv). `peer list` shows it `p2p`, B's `node` shows `"is_credential_peer": true`, and `credential peers` lists it. |
| Revoke | A logged `removing untrusted peer… disconnecting untrusted peer` **≈1 s after revoke**, and B disappeared from A's peers. |
| Reconnect after revoke | Refused: `authentication failed: invalid proof and unknown credential`. **B retries every ~1 s forever**, and A logs an ERROR each time. EtSupervisor must treat this error as "credential dead": stop, back off, and fetch a new credential. |
| TTL expiry | A peer on a 30 s credential was **dropped at expiry** and its entry vanished from `list`. Renewal needs overlap: issue new → restart the companion with the new key → revoke the old one. A restart costs a reconnect of about 1–2 s. |
| `--reusable false` | A second process holding the same credential got a TCP session but no routes and was reset. One credential per device, `reusable=false`. |
| v2.6.4 | Same flow passes. |

**Secret exposure via RPC.** `easytier-cli node` returns the full running config in clear: `network_secret` on the admin node (verified with a marker secret) and `local_private_key` on credential nodes. Logs are redacted (0 hits). Anyone who can open the RPC port can read them, so:
- The server's per-network RPC must be loopback-only on a trusted host.
- On clients, the credential is readable by any local process. That is acceptable only because it is a per-device, revocable, short-lived key.

## 3. Port forward and `--no-tun` (`portfwd-test.sh`, `quicprobe/`, `tun-host-test.ps1`)

Setup:
- `quicprobe` is a minimal quic-go echo server/client built offline from the local module cache.
- H = host, K = controller, A = admin/relay.
- On K: `easytier-cli -p <K> port-forward add udp 127.0.0.1:47001 10.250.7.2:47000`.

| Case | Result |
|---|---|
| H `--no-tun`, server on `127.0.0.1:47000`; K `--no-tun` | **PASS.** `handshake ok`, `echo 20/20 ok`, 4 MiB bulk at 430–545 Mbit/s (relay(2) through A, same host). After `port-forward remove`, the dial fails. With H killed, the dial fails, so the path really goes through H. |
| Same, stub `Packet.dll` binaries | **PASS** (516 Mbit/s). |
| H with TUN, non-admin | Instance fails and **the process exits**: `WinTun: Failed to take device installation mutex: Access denied` → `Failed to create adapter`. No adapter is left behind. |
| H with TUN, elevated (approved), server on `10.250.7.2:47000` and on `0.0.0.0:47000` | Adapter `moonrdspike0` came up (10.250.7.2/24, category Private, route 10.250.7.0/24), and the K→H relay was up. **The QUIC dial timed out in both passes, with no errors logged.** Possible causes: the same-host loop (TUN adapter and overlay on one machine) or Windows filtering; unexplained. **Re-test on two machines** in the Phase 1 E2E. |

Why no-TUN on the host works: this is designed behaviour, not luck. `easytier-core/src/gateway/proxy/udp_proxy_engine.rs` has a `no_tun_local_virtual_ip` branch: on a `--no-tun` node, UDP sent to **its own virtual IP** is proxied to `127.0.0.1:<dst_port>` (the server saw the peer as `127.0.0.1:<ephemeral>`).

**Recommendation: run the companion `--no-tun` on both host and controller.**
- No admin, no wintun, no adapter, and no firewall rules.
- Nothing to collide with the user's `et_*`.
- The host's QUIC server listens on `127.0.0.1:<port>`.

TUN stays an optional later mode (needed only for features like subnet routing).

**Exposure caveat.** In no-TUN mode **every loopback UDP port on the host is reachable by any member of the network**. A second, unrelated `127.0.0.1:47005` server was reachable through a forward. The members are only the same account's devices plus the server node, but it still must be closed:
- `--udp-whitelist` (compiled into an inbound ACL chain: allow listed ports, then drop 0-65535) blocked the stray port.
- It **also broke the allowed flow**. With `47000` the dial failed. With `40000-47004` the handshake passed but bulk stalled.
- **Open item for Phase 0b:** restrict this with 2.7's dynamic ACLs/groups (credentials already carry `--groups`), or find out why the whitelist interferes.
- TCP to loopback was not tested.

**Runtime port-forward mechanics (2.7.1).** `port-forward add/remove/list` work only if the instance was started from a **writable** TOML via `-c` **and** no network option is given on argv or env (source: `easytier/src/core.rs`; merging any `NetworkOptions`, including `ET_CREDENTIAL` or `--secure-mode`, sets `READ_ONLY`).
- Process-level flags are fine on argv: `--rpc-portal*` and logging.
- Each patch is **written back into the TOML**, which contains the credential, so keep the file in a user-only ACL'd directory. Do not delete it after start as the plan assumed.
- Alternative: static `--port-forward` flags plus a companion restart on change.
- List JSON shape:

```json
{ "cfgs": [ { "bind_addr": {"port":47001,"ipv4":{"addr":2130706433}},
              "dst_addr":  {"port":47000,"ipv4":{"addr":184157954}}, "socket_type":"UDP" } ] }
```

  `socket_type` is omitted for TCP. Addresses are u32.

**Other runtime facts.**
- `--bind-device` defaults to true. Connectors then bind to physical NICs and cannot reach `127.0.0.1` peers (os error 10049). That only matters for local tests.
- Nodes request **UPnP/NAT-PMP mappings on the LAN gateway by default.** Observed: `udp port mapping established backend="nat-pmp"`. Mappings are renewed every 240 s and removed on clean shutdown.
  - The spike's force-killed nodes left a few short-lived UDP mappings on this router; they expire on their own.
  - Recommend `--disable-upnp` by default.
- Hostname defaults to the Windows computer name, which every peer sees. Always set `hostname`.

## 4. Coexistence with the user's EasyTier (`coexist-test.sh`, `detect-existing.ps1`)

This machine has a live user install, so the test ran against the real thing (read-only), not just a simulation:
- Service `easytier-gui`, running as LocalSystem, binary `%LOCALAPPDATA%\easytier-gui\easytier-gui.exe --config-dir … --rpc-portal 127.0.0.1:15999 --daemon`, GUI 2.7.0.
- TCP 11010 and UDP 11010/11011 on all interfaces.
- Adapter `et_1`.

| Check | Result |
|---|---|
| Simulated user instance with **default flags** (`--network-name … --no-tun`, no rpc/listeners) | **Fails to start:** `required listener failed to start: failed to listen on tcp://0.0.0.0:11010` (the real user instance holds it). Defaults cannot coexist, so `--no-listener` is mandatory. |
| `--rpc-portal 0` ("random") | Binds **`0.0.0.0:15888` first** (default whitelist 127.0.0.0/8 and ::1; a LAN probe was rejected). That would steal the user's default CLI port. **Never use 0.** The supervisor must pick a free port itself. |
| Our instance: `-c moonrd.toml` (instance `moonrd`, `dev_name=moonrd0`, `listeners=[]`, no_tun) + `--rpc-portal 127.0.0.1:<free> --rpc-portal-whitelist 127.0.0.1/32` | Only socket opened: TCP `127.0.0.1:<rpc>`. It joined the spike network. |
| The user's install during and after | RPC 15999 still readable (same peer count). `et_1` Up. `detect-existing.ps1` JSON before vs after: **NO DIFF.** |
| TUN run (elevated) next to `et_1` | Ours used its own name, GUID and mutex. EasyTier added 2 per-exe and 8 per-adapter firewall rules ("EasyTier moonrdspike0 - TCP/UDP/ICMP/ALL Protocol (In/Outbound)"), all in group `EasyTier` (the user's group too). Cleanup removed only ours: the user's rule count went 10 → 22 → 10, and the orphaned wintun device was removed with `pnputil`. |

### Detection signals for an existing install (implemented in `detect-existing.ps1`, runs non-admin)

1. **Services:** name or display name contains `easytier`, or ImagePath contains `easytier`.
   - Known names: `easytier-gui` (GUI daemon) and `easytier` (default of `easytier-cli service install`). `EasyTierService` is used by third-party installers.
   - Parse `--rpc-portal` from ImagePath.
2. **Processes:** `easytier-core.exe`, `easytier-gui.exe`, `easytier-mini.exe`, `easytier-web*.exe`. ExecutablePath is unreadable for SYSTEM processes when not elevated.
3. **Ports:**
   - TCP listen 15888 (core default RPC; mini is fixed there) and 15999 (GUI service RPC, seen here).
   - TCP and UDP 11010; UDP 11011; 11011/11012 for ws/wss/wg with port-only listeners.
   - Map each to its owning process.
4. **Adapters:**
   - Name `et_N`. 2.7.x assigns `et_1` upward (`reserve_tun_name`: `for index in 1..`); older builds used `et_0`. Description `"<name> Tunnel"`.
   - Robust check: `InterfaceGuid == uuidv5(NAMESPACE_URL, "https://easytier.rs/wintun/" + lower(name))`. Verified True for `et_1`.
5. **Mutex:** `Global\EasyTier.TunName.<uuidv5(NAMESPACE_URL, lower(name))>`, created with SDDL `D:(A;;0x00100000;;;WD)`, so anyone can open it with SYNCHRONIZE. Probed for `et_0..9` and found `et_1`.
6. **Firewall:** rules in group `EasyTier`, named `EasyTier <exe path> (Inbound|Outbound)` and `EasyTier <adapter> - <proto> Protocol (…)`.
7. **Footprints:**
   - `%LOCALAPPDATA%\easytier-gui`, `%APPDATA%\com.kkrainbow.easytier\config.d`, `%LOCALAPPDATA%\com.kkrainbow.easytier\logs`.
   - Uninstall key "easytier-gui" with DisplayVersion.
8. **Foreign RPC (optional):** `peer list -o json` gives the local cidr and version.
   - **Never call `node` on a foreign RPC**: its `config` field contains the user's network secret.

## 5. `Packet.dll` and which DLLs are needed

| File in the Windows zip | What it is | Needed for us? |
|---|---|---|
| `Packet.dll` (220 032 B, sha256 `c7c03a87…eacac`, same in 2.6.4 and 2.7.1) | **Npcap 1.79** "The Packet API for Windows". © Insecure.Com LLC, Authenticode-signed by *Nmap Software LLC*. | Imported by `easytier-core.exe` **and** `easytier-cli.exe` as a normal (not delay-load) import of 11 functions: `PacketOpenAdapter, PacketSetHwFilter, PacketSetBuff, PacketSetMinToCopy, PacketAllocatePacket, PacketInitPacket, PacketFreePacket, PacketCloseAdapter, PacketReceivePacket, PacketGetAdapterNames, PacketSendPacket`. Without it neither exe starts: `error while loading shared libraries: packet.dll`, exit 127. |
| `wintun.dll` 0.14.1 | WireGuard LLC, signed | Only for TUN mode. Redistributable unmodified under Wintun's prebuilt-binaries licence; confirm the text for THIRD_PARTY_NOTICES. |
| `WinDivert64.sys` 2.2 | WinDivert driver | Only for `--enable-udp-broadcast-relay`. Do not ship. |
| `easytier-web*.exe` | config server/UI | Do not ship on clients. |

**Provenance.**
- The DLL is committed in the EasyTier repo at `easytier/third_party/{x86_64,i686,arm64}/Packet.dll`, next to `Packet.lib`. It was added in commit `28cd6da5`, "Add fake tcp tunnel (experimental) (#1673)", 2025-12-24.
- `.github/workflows/core.yml:309` copies `third_party/<arch>/*.dll|*.sys` into the zip.
- It is pulled in only by the **`faketcp`** cargo feature (`dep:pnet_datalink`), which is on by default.

**Licence.**
- The Npcap LICENSE says Npcap "is not open source software and may not be redistributed" without an OEM licence.
- The free licence is limited to installation on five systems. Redistribution needs the Npcap OEM Redistribution License.
- **We must not ship it.**

**Ways out (EasyTier stays unmodified, so LGPL-3.0 stays simple):**
- **A. No-op stub `Packet.dll`.** Our own code, in `packet-stub/`: an 11-function Rust cdylib, 110 KB, sha256 `9b9afdf9…f8ea9`.
  - Verified with the official v2.7.1 core and cli: `--version`, the credential flow, the no-TUN QUIC forward (516 Mbit/s), and the elevated TUN pass (the adapter came up).
  - Only `faketcp` breaks, and we don't use it.
  - Cheapest option. Recommended for now.
- **B. Build core and cli from the unmodified v2.7.1 tag** with default features minus `faketcp`, so there is no packet.dll import at all. Cleaner long term.
  - Not built in this spike: it would download the crate graph.
  - Phase 0b task: confirm it builds and that `pe_imports.py` shows no `packet.dll`.
- Not an option: easytier-mini (§1).

**Files to ship for our use:**
- `easytier-core.exe` and `easytier-cli.exe` from the pinned zip, plus our `Packet.dll` (A) or our build (B).
- `wintun.dll` only if TUN mode is ever enabled.
- Use `pe_imports.py <exe>` in CI to assert the import list.

## 6. Fallback: easytier-web config server + webhook (assessed, not run)

How it would work:
- `easytier-web` has `--webhook-url` ("token validation and event delivery… incoming tokens are validated via this webhook"), plus `--webhook-secret`, `--internal-auth-token` and `--web-instance-id`.
- Clients would run `easytier-core --config-server udp://remote.moonl.cloud:22020/<sso-token> --machine-id <id>`, and our Go server would validate the token in the webhook.

Why it is worse:
- The config server **pushes the full instance config to the client**. With a plain `network_secret` network, the secret lands on the client and in its RPC `node` output, which violates the hard requirement.
- It is only acceptable in combination with secure-mode credentials, and then it adds nothing over §2.
- It also adds a UDP 22020 service and a DB.

Verdict: keep it as a documented contingency only.

## 7. Recommended flag sets (v2.7.1)

**Server, one process per active SSO network on Linux, systemd.** Untested on Linux; the flags are the ones verified on Windows here.

```
easytier-core --instance-name mrd-<uidhash> --network-name mrd-<uidhash> --network-secret <from DB, via env ET_NETWORK_SECRET>
  --secure-mode --credential-file /var/lib/moonrd/et/mrd-<uidhash>/credentials.json
  --hostname mrd-server -i 10.250.<n>.1/24 --no-tun
  --listeners tcp://0.0.0.0:<port> udp://0.0.0.0:<port>        # plus wss behind Caddy if needed
  --rpc-portal 127.0.0.1:<per-network port> --rpc-portal-whitelist 127.0.0.1/32
  --disable-upnp --private-mode true --console-log-level warn
issue:  easytier-cli -p 127.0.0.1:<port> -o json credential generate --ttl 86400 --credential-id <deviceId>.<epoch> --groups mrd-devices --allow-relay --reusable false
revoke: easytier-cli -p … -o json credential revoke <id>    (also revoke the previous id after each renewal)
```

**Device companion, host and controller alike, non-admin.** Launch with a writable TOML; argv carries only process-level flags.

```
easytier-core.exe -c %LOCALAPPDATA%\MoonRemote\et\moonrd.toml
  --rpc-portal 127.0.0.1:<free port picked by EtSupervisor, never 0/15888/15999>
  --rpc-portal-whitelist 127.0.0.1/32 --console-log-level warn
```

```toml
instance_name = "moonrd"
hostname = "<device short id>"          # not the PC name
ipv4 = "10.250.<n>.<m>/24"              # server-assigned
listeners = []                          # == --no-listener
[network_identity]
network_name = "mrd-<uidhash>"          # no network_secret
[[peer]]
uri = "tcp://remote.moonl.cloud:<port>" # + udp://…
[secure_mode]
enabled = true
local_private_key = "<credential_secret>"
local_public_key = "<pubkey>"           # optional on 2.7.1, required by 2.6.x
[flags]
dev_name = "moonrd0"
no_tun = true
# disable_upnp: the TOML key name is not verified here; --disable-upnp is a network option
#               and would make the file read-only if passed on argv
```

- File ACL: the current user only. It also receives the runtime `[[port_forward]]` entries.
- Controller: `easytier-cli -p <rpc> port-forward add udp 127.0.0.1:<local> <hostVirtualIp>:<quicPort>` per session; `remove` afterwards.
- Host: the QUIC server binds `127.0.0.1:<quicPort>`.
- Supervision: poll `peer list -o json`. On log or CLI `authentication failed: invalid proof and unknown credential`, stop and re-enrol. Renew before `expiry_unix`.

## 8. Open items for Phase 0b / Phase 1

1. Two-machine re-test, including a **TUN host** (single-host TUN forward failed, cause unknown) and real NAT/P2P. A Windows Firewall prompt for non-admin `easytier-core` on first UDP bind was not observed with STUN disabled here; check it with STUN enabled.
2. Close the no-TUN loopback exposure with dynamic ACL/groups, or explain the `--udp-whitelist` interference. Test TCP too.
3. Find the TOML key for `disable_upnp` and `private_mode` (or confirm they are flags-only) without making the config read-only.
4. Choose stub `Packet.dll` (A) or a feature-trimmed source build (B). Add an import-list check to `fetch-easytier.ps1`.
5. Mixed-version interop (server 2.7.1, client 2.7.x) is untested. Pin the same version on both sides.

## Files

| File | Purpose |
|---|---|
| `lib.sh` | Shared helpers (start/stop spike nodes by binary path only; `ET_VER`, `ET_BIN` overrides) |
| `cred-test.sh` | Q2: generate, join with `ET_CREDENTIAL`, revoke, rejoin refused |
| `cred-expiry-test.sh` | Q2: store file, admin restart, TTL expiry, `--reusable false` |
| `portfwd-test.sh` | Q3: runtime port forward plus QUIC (`HOST_MODE=notun\|tun`, `QBIND`, `H_EXTRA`) |
| `tun-host-test.ps1` | Q3: elevated TUN host run with full cleanup (adapter and our firewall rules only) |
| `coexist-test.sh` | Q4: default-flag conflict, isolated instance, before/after diff |
| `detect-existing.ps1` | Q4: read-only detection of an existing install (`-ProbeRpc`, `-Json`) |
| `mini-test.sh` | Q1/Q5: easytier-mini capability check |
| `pe_imports.py` | Q5: PE import and delay-import lister (stdlib) |
| `packet-stub/` | Q5: no-op `Packet.dll` replacement (Rust cdylib, no deps) |
| `quicprobe/` | QUIC echo/bulk probe (quic-go, built offline) |
| `vendor/`, `run/`, `out/` | Downloads, runtime logs, outputs (gitignored) |
