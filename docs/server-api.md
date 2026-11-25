# moon-remote-server API (v1)

Base URL: `https://remote.moonl.cloud`. All bodies are JSON (`Content-Type: application/json`, 64 KiB max, unknown fields rejected). Errors are `{"error": "<code>", "message": "..."}`.

## Authentication

| Caller | Header | Used by |
| --- | --- | --- |
| User | `Authorization: Bearer <access token>` from sso.moonl.cloud; `DPoP <token>` + `DPoP: <proof>` once the token is DPoP-bound | desktop UI, web client |
| Device | `Authorization: Device mrdd_<token>` | host service, desktop UI acting as its installation |
| Dev (local only) | `Authorization: Dev <sub>[;<name>]` | `MRD_DEV=1` on loopback |

User tokens are checked by `internal/rsauth` (ported from the Phase 0c spike; details in `spikes/sso-dpop/REPORT.md`):
- **Token checks:** signature against the issuer's JWKS, `typ=at+jwt`, `iss`, `exp`/`nbf`, and `aud`, which must contain one of `MRD_SSO_CLIENT_IDS` or the public URL.
- **Client allowlist:** the `client_id` must be in `MRD_SSO_CLIENT_IDS`.
- **DPoP:** if the token is DPoP-bound, the DPoP proof is checked too. moon-sso issues **Bearer-only** access tokens today (only refresh tokens are DPoP-bound), so clients send `Bearer`.
- **Display name:** taken from the issuer's userinfo endpoint with the caller's token, and cached per user for 1 h. If userinfo fails, the stored name is kept.

Clients should request the `resource` `https://remote.moonl.cloud` at login.

## Endpoints

| Method & path | Who | Purpose |
| --- | --- | --- |
| `GET /healthz` | anyone | liveness |
| `GET /v1/info` | anyone | `{service, version, ssoIssuer, windowsDownload, protocolVersion}` |
| `POST /v1/devices/challenge` | user | `{nonce, expiresAt}` (single-use, 2 min, bound to the user) |
| `POST /v1/devices` | user | register an installation (below) |
| `GET /v1/devices` | user, device | `{devices: [{id, name, kind, publicKey, createdAt, lastSeenAt, online, self?}]}` |
| `PATCH /v1/devices/{id}` | user | `{name}` → 204 |
| `DELETE /v1/devices/{id}` | user, or the device itself | revokes EasyTier access, closes its signalling connections, deletes → 204. `502 revoke_failed` keeps the device so the user can retry |
| `GET /v1/roster` | device | signed roster for LAN mode (below) |
| `POST /v1/et/credential` | device | `{occupied: ["192.168.1.0/24", …]}` → EasyTier grant (below) |
| `GET /v1/turn` | user, device | `{iceServers: [...], expiresAt}`: STUN plus coturn REST credentials |
| `POST /v1/signal/ticket` | user, device | `{ticket, expiresAt}`: single-use, 30 s |
| `GET /v1/signal?ticket=…` | ticket holder | WebSocket signalling (below) |

### Device registration

1. The device generates an Ed25519 key pair once and keeps the private key local (DPAPI).
2. `POST /v1/devices/challenge` returns a `nonce`.
3. The device signs these exact bytes, with `\n` as the separator:
   ```
   moonrd/device-register/v1
   <nonce>
   <user sub>
   <kind: host|viewer>
   <publicKey base64>
   ```
4. Send `POST /v1/devices` with `{name, kind, publicKey, nonce, signature}`. The response (201) is `{device, deviceToken, rosterKey, rosterKeyId}`.
   - `deviceToken` is shown only once. The server stores only its SHA-256.
   - Pin `rosterKey`, the server's Ed25519 key for verifying rosters.

Error codes:
- `400`: `bad_nonce`, `bad_signature`, `bad_name`, `bad_kind`, `bad_public_key`.
- `409`: `already_registered`, `too_many_devices` (an account can have at most 253 devices).

The nonce is spent even when the attempt fails.

### Roster (LAN mode)

The response is `{roster, signature, keyId}`.
- `roster` is base64 of JSON in this shape: `{"v":1,"userSub","iat","exp","devices":[{id,name,kind,publicKey}]}`.
- `signature` is an Ed25519 signature over **the decoded bytes exactly as received**.

A roster is valid for 14 days. A host in LAN mode accepts only controllers whose key appears in a roster that verifies against the pinned key and has not expired. The reference verifier is `roster.Verify` in `server/internal/roster`.

### EasyTier grant

The response is `{networkName, credential, expiresAt, peers, ipv4}`. For example `ipv4` is `10.250.17.3/24` and `peers` is `["tcp://remote.moonl.cloud:21017","udp://remote.moonl.cloud:21017"]`.

**Network and addresses**
- Each account gets its own network: a /24 inside `10.250.0.0/16`, chosen to avoid the ranges the first device reports as `occupied`. The server's node is `.1`.
- Each account network has its own server-side `easytier-core` (EasyTier v2.7.1) on its own public port from `MRD_ET_PORTS`. That node holds the network secret and signs device credentials.
- A later device whose local ranges overlap gets `409 subnet_conflict`.

**The credential**
- `credential` is the device's X25519 private key and lasts 24 h. Renew it at about 75%: request a new one, restart the companion with it, and the server keeps the previous key valid.
- The server keeps the **two newest** credentials per device and revokes older ones. Deleting the device revokes all of them, and EasyTier disconnects it within about 1 s.
- **Using it:** put it in the companion's TOML as `[secure_mode] local_private_key`. `moonrd-et::config::CompanionConfig` writes that file. Never put it on argv, and never send it anywhere but the companion.

Returns `503 et_unavailable` when EasyTier is not configured on the server.

### Signalling WebSocket

Text frames of JSON, at most 64 KiB each. Each connection may send 50 messages/s, with bursts up to 200; going over closes it.

**Server → client**
- `{"type":"welcome","conn":"<conn id>","device":"<device id or empty>"}`
- `{"type":"presence-snapshot","list":["<online device id>", …]}`
- `{"type":"presence","device":"<id>","online":true|false}`: sent to the same account's connections
- Relayed messages: `{"type", "from":"<device id>", "fromConn", "fromName", "session", "data"}`
- `{"type":"error","code":"peer_offline|bad_target|unknown_type|bad_json","session"}`

**Client → server**
- `{"type", "to":"<device id>" | "toConn":"<conn id>", "session":"<id>", "data":{…}}`
- Exactly one of `to` / `toConn`. Web viewers have no device id, so replies to them use `toConn`.
- Relayed types: `invite`, `accept`, `reject`, `sdp`, `ice`, `quic-endpoint`, `bye`.
- Messages only reach connections of the **same account**. A target that is offline and a target in another account get the same `peer_offline`.

## Server configuration

| Variable | Meaning |
| --- | --- |
| `MRD_LISTEN` | bind address, default `127.0.0.1:8621` (Caddy in front) |
| `MRD_PUBLIC_URL`, `MRD_SSO_ISSUER`, `MRD_RELEASE_URL`, `MRD_RELEASE_APP` | URLs, defaults for production. `MRD_PUBLIC_URL` is also the DPoP `htu` base, so it must be the external origin |
| `MRD_SSO_CLIENT_IDS` | comma list of accepted OAuth client ids: the desktop and web `ms_…` ids (required). Both clients must be `subject_type=public` so a user has one `sub` across them; see `spikes/sso-dpop/REPORT.md` §6 |
| `MRD_DSN_FILE` | file containing the MySQL DSN (required) |
| `MRD_MASTER_KEY_FILE` | base64 32 bytes, seals EasyTier network secrets (required) |
| `MRD_ROSTER_KEY_FILE` | base64 32-byte Ed25519 seed, signs rosters (required) |
| `MRD_TURN_SECRET_FILE` + `MRD_TURN_URLS`, `MRD_STUN_URLS` | coturn `static-auth-secret` and ICE URLs |
| `MRD_ET_CORE`, `MRD_ET_CLI` | paths to the pinned `easytier-core` / `easytier-cli` (all `MRD_ET_*` set together, or none) |
| `MRD_ET_DATA_DIR` | private dir (0700): per-network credential store (contains device private keys) and node log |
| `MRD_ET_PUBLIC_HOST`, `MRD_ET_PORTS` | host devices dial and the public port range, e.g. `21000-21999`, one port per account network, TCP+UDP open in the firewall |
| `MRD_ALLOWED_ORIGINS` | extra browser origins for the WebSocket |
| `MRD_DEV=1` | local dev: Dev auth, memory store, throwaway keys; loopback only. With `MRD_SSO_CLIENT_IDS` set, real tokens (e.g. from the local SSO testbed) are accepted alongside `Dev` |

Building needs `GOPRIVATE=sso.moonl.cloud` (`scripts/build.ps1` sets it), because the moon-sso SDK is served from `https://sso.moonl.cloud/goproxy`.

Commands:
- `moon-remote-server migrate` applies migrations.
- `moon-remote-server keygen` prints a fresh key for the key files.
