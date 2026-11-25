# Phase 0c spike: moon-sso tokens + DPoP at the moon-remote resource server

Date: 2026-11-20. Status: **done**. `go test` passes, and both clients called the protected endpoint successfully on the local testbed.

## TL;DR

1. **Reuse, don't reimplement, access-token validation.** The moon-sso Go SDK (`sso.moonl.cloud/sdk/go`) already does discovery, JWKS caching, key rotation, `typ=at+jwt`, signature, `iss`, `exp/nbf/iat` and `aud` checks in `Client.VerifyAccessToken`. `rsauth` wraps it and adds the parts the SDK lacks: a client allowlist, the resource-server DPoP check, WWW-Authenticate challenges and an Echo v5 adapter.
2. **moon-sso access tokens are *not* DPoP-bound today.** DPoP binds only the **refresh token** of public clients. Access tokens have no `cnf`, `token_type` is `Bearer`, and all three client SDKs send `Authorization: Bearer` to APIs (sdk-spec §3: "资源请求仍然用 `Authorization: Bearer`"). So the RS DPoP path (htm/htu/iat/jti replay/ath/`cnf.jkt`) is built and unit-tested, but **no real moon-sso token exercises it**. It is forward-compatible code and stays dormant until moon-sso starts issuing bound access tokens. `RequireDPoP` must stay `false` until then.
3. **The audience must be a client allowlist, not only a resource URI.** In-app login (`/oauth/authorize-challenge`) ignores `resource`, so its tokens carry `aud=[client_id]` only. Redirect logins that pass `resource` get `aud=[client_id, resource]`, and the resource survives refresh. moon-sso accepts any absolute URI as `resource`, so `resource` in `aud` proves nothing by itself. The real gate is `client_id ∈ {desktop, web}`.
4. **Both production clients need `subject_type=public` set by an SSO admin.** Clients created in the developer portal default to *pairwise* `sub` keyed by client id. Desktop and web would then see different `sub` values for the same user, and there is no shared-sector setting.

## 1. What moon-sso already ships

| Piece | Where | Reusable for moon-remote-server? |
|---|---|---|
| `Client.VerifyAccessToken(ctx, tok, aud...)` | `sdk/go/jwt.go` | **Yes, used.** JWKS from discovery, cached 1 h. Unknown `kid` triggers a forced refetch at most every 30 s (rotation). A failed refetch falls back to the stale set. Checks `typ=at+jwt`, ES256/RS256, `iss`, `exp`/`nbf`/`iat` with 60 s leeway, and `aud ∋` any of the given audiences. |
| `web.Bearer(client, h, aud...)` | `sdk/go/web/web.go` | Not used. It is net/http only, has no client allowlist and no DPoP, and returns a fixed error body. `rsauth` is effectively `web.Bearer` plus those parts. |
| DPoP verifier | `server/internal/oidc/dpop.go` | **No.** It is an `internal` package, so it can't be imported, and it is AS-specific (server nonces, no `ath`). `rsauth/dpop.go` follows its structure. |
| `@moon-sso/node` `resource.ts` | `sdk/typescript/packages/node` | Not relevant (Go backend). |

The spike builds against the local SDK with `replace sso.moonl.cloud/sdk/go => ../../../moon-sso/sdk/go`. Production fetches the module from the SSO's own Go module proxy (`go get sso.moonl.cloud/sdk/go`, `GOPRIVATE=sso.moonl.cloud`).

## 2. Evidence that access tokens are Bearer-only

- `server/internal/oidc/tokens.go` `mintAccess` never sets `Cnf`. The field exists in `AccessClaims` but is always nil.
- `server/internal/oidc/token.go` `buildResponse` sets `TokenType: "Bearer"`. The DPoP `jkt` is stored on the refresh-token family only (`bindJKT` for public clients).
- Client SDKs: .NET `MoonSsoAuthHandler`, TS `createAuthorizedFetch` (`headers.set('Authorization', 'Bearer ...')`) and Go `dpopState.proof` (no `ath`) send no proof on resource requests.
- Observed in the e2e runs: every token showed `cnf=none` and the RS logged `scheme=Bearer`, including `test-native-dpop` and `test-spa`, which *require* DPoP.

**Consequence:** a leaked access token can be replayed by anyone until it expires. The default lifetime is `AccessTokenMinutes=10`, and an admin can set 60–3600 s per client. The refresh token is the long-lived secret, and it *is* key-bound (DPAPI on desktop, non-extractable WebCrypto key in the browser).

True sender-constrained access tokens would need moon-sso changes (we did not make them; moon-sso is out of scope here):
1. `mintAccess` sets `cnf.jkt` when the token request carried a DPoP proof.
2. The token endpoint returns `token_type=DPoP`.
3. The SDK auth handlers send `Authorization: DPoP` plus a per-request proof with `ath`.

If the moon-sso owner does this, flip `RequireDPoP` on. The RS side is already done and tested.

## 3. The middleware (`rsauth`)

```go
sso, _ := moonsso.NewClient(moonsso.Config{Issuer: "https://sso.moonl.cloud", ClientID: "moon-remote-server"}) // ClientID unused
v, _ := rsauth.New(rsauth.Config{
    SSO:            sso,
    Audiences:      []string{desktopClientID, webClientID, "https://remote.moonl.cloud"},
    AllowedClients: []string{desktopClientID, webClientID},
    PublicURL:      "https://remote.moonl.cloud", // htu base; never taken from Host behind the proxy
    // RequireDPoP: false (see §2), Replay: shared store when >1 replica
})
api := e.Group("/api", v.Echo())           // Echo v5
p := rsauth.PrincipalFrom(c.Request().Context()) // Subject, ClientID, Scopes, SID, JKT, Scheme, Claims
```

Decision table, applied after the SDK token check:

| Token | Scheme | Result |
|---|---|---|
| unbound | `Bearer` | accept (today's moon-sso path); reject if `RequireDPoP` |
| unbound | `DPoP` | 401 `invalid_token` "token is not DPoP-bound" (RFC 9449 §7.1) |
| `cnf.jkt` | `Bearer` | 401 `invalid_token`, DPoP challenge (RFC 9449 §7.2) |
| `cnf.jkt` | `DPoP` | check proof: exactly one `DPoP` header ≤ 8 KiB; `typ=dpop+jwt`; asymmetric alg allowlist (ES256/ES384/RS256/PS256/EdDSA, the same list the SSO advertises; never `none`/HS*); embedded public JWK; signature; `jti`; `htm` = method; `htu` = PublicURL + path (scheme/host/default-port normalized, query ignored); `iat` within −60 s/+10 s; `ath` = b64url(SHA-256(token)); JWK thumbprint = `cnf.jkt`; `jkt|jti` not seen within the iat window |

Other details:
- Errors return 401 with `WWW-Authenticate: Bearer|DPoP realm=…, error=…, error_description=…` (plus `algs` for DPoP); malformed headers return 400. A bare 401 advertises both schemes.
- The replay cache is bounded and in-process. When full, it fails closed and evicts only expired entries. With more than one replica, swap in Redis `SET NX PX`; the `ReplayCache` interface is already there.
- No DPoP nonce at the RS. It is optional in RFC 9449, and the iat window plus the jti cache cover replay.

Files: `rsauth/rsauth.go` (verifier, policy, HTTP), `rsauth/dpop.go` (proof check, replay cache), `rsauth/echo.go` (Echo v5 adapter), `cmd/demo-rs` (Echo v5 stand-in for moon-remote-server with `GET /api/whoami`; also serves the browser page).

## 4. Tests (`go test -race ./...`: 17 tests, 39 including subtests, all pass)

Full output: `e2e/results/go-test.txt`. The tests use a fake issuer (`httptest`) that serves discovery and JWKS and signs ES256 tokens.

- **Token:** valid Bearer; resource audience; expired; nbf in the future; wrong `iss`; wrong `aud`; client not in the allowlist; `typ≠at+jwt` (ID token); **wrong signing key with the same kid** (forged signature); garbage; empty `sub`; missing or malformed Authorization.
- **JWKS:** 20 requests cause 1 discovery fetch and 1 JWKS fetch; **rotation** to `k2` causes exactly one refetch, and old-key tokens stay valid while `k1` is still published; **unknown kid** is rejected after one forced refetch, and a flood of unknown kids makes no further fetches (30 s backoff).
- **DPoP:** bound token plus a valid proof is accepted (also with case- and port-normalized htu); **replay of the same proof is rejected**; a replayed proof past the window is rejected for its age; **wrong DPoP key (jkt ≠ cnf)**; proof signed by a key other than its embedded JWK; wrong htm; wrong htu path or host; htu using the internal host instead of the public URL; stale, future or missing iat; missing jti; **`ath` of another token**; missing ath; wrong typ; no proof; two proofs; `alg=none`; bound token sent as Bearer (with and without a proof); unbound token sent as DPoP; `RequireDPoP` rejects Bearer.
- **Misc:** the replay cache fails closed when full and evicts expired entries; Echo v5 adapter; config validation.

## 5. End-to-end against the local testbed (recorded)

Setup: testbed `server/bin/testbed.exe -config ../.secrets/testbed/config.toml` (the `dev` config in the testbed's doc comment fails with `signing key …: crypto: decryption failed`). `demo-rs` runs on `http://127.0.0.1:18700` and allows clients `test-native, test-native-dpop, test-spa`. User: `alice`. Logs are in `e2e/results/`.

| Client | Flow | Token `aud` / `cnf` | RS result |
|---|---|---|---|
| .NET `MoonSso.Desktop` 1.0.0, `test-native-dpop` (DPoP required) | `LoginWithBrowserAsync`: PKCE, `dpop_jkt`, `resource`, real loopback listener on `127.0.0.1:<random>/callback`. The browser step is automated through the testbed's `/__test/authorize`. | `["test-native-dpop","http://127.0.0.1:18700"]` / none | 200; after `RefreshAsync` (DPoP-bound refresh) 200 with the new token; no token 401; tampered token 401 |
| .NET, `test-native` | `LoginWithPasswordAsync` (in-app, first-party) | `["test-native"]` / none | 200, 200 after refresh, 401, 401 |
| `@moon-sso/browser` in the Claude desktop built-in browser (Chromium 156), `test-spa` (DPoP required) | `sso.login({extraParams:{resource}})`: testbed login page, then `handleRedirectCallback` (one `use_dpop_nonce` 400 and retry, as expected) | `["test-spa","http://127.0.0.1:18700"]` / none | `sso.fetch('/api/whoami')` 200; no token 401; tampered 401; DPoP scheme on unbound token 401 "token is not DPoP-bound" |
| same, `test-spa` | `sso.signIn()` (in-app) | `["test-spa"]` / none | 200 |

The same user got the same `sub` (`8F_91pBG8QTqj4kvF6RJpw`) across all three clients, because the testbed clients are `public` (see §6, note 1).

To reproduce:
1. Start the testbed as above.
2. `go build -o demo-rs.exe ./cmd/demo-rs && ./demo-rs.exe -sdk-dist C:/develop/moon-sso/sdk/typescript/packages/browser/dist`
3. In `e2e/dotnet`, run `dotnet run -- --mode browser|password --client <id>` with `MOON_SSO_TEST_USER`/`MOON_SSO_TEST_PASSWORD` set to the sdk-spec §8 fixture.
4. Open `http://127.0.0.1:18700/`.

The .NET project restores `MoonSso.Desktop` from `moon-sso/sdk/dotnet/artifacts`, so nothing is built inside the moon-sso tree.

## 6. OAuth clients to register in production (sso.moonl.cloud), not yet registered

Two public clients. Fields marked *admin* are not in the developer-portal form; an SSO admin sets them in the admin console (`AdminFlags`).

| | **Moon Remote Desktop** | **Moon Remote Web** |
|---|---|---|
| Portal kind | `native` (public, `token_endpoint_auth_method=none`) | `spa` (public web, `none`) |
| Grants (implied by kind) | `authorization_code`, `refresh_token` | `authorization_code`, `refresh_token` |
| Redirect URIs | `http://127.0.0.1/callback` (loopback; port ignored; what MoonSso.Desktop uses) | `https://remote.moonl.cloud/auth/callback`¹ (exact match; its origin also becomes the CORS origin the SSO allows for token, challenge and account calls) |
| Post-logout redirect URIs | none (desktop only revokes) | `https://remote.moonl.cloud/` |
| Scopes | `openid profile offline_access` | `openid profile offline_access` |
| `require_dpop` (portal) | **on** (the SDK always sends DPoP; enforcing it means no unbound refresh tokens can be issued) | **on** |
| *admin* `subject_type` | **`public`** (required, see note 1) | **`public`** |
| *admin* `first_party` + `skip_consent` | on (own app, no consent screen) | on |
| *admin* `native_login` (in-app password login) | off unless the Lumen UI gets its own login form; system browser is the default | off (use the redirect flow) |
| *admin* access-token TTL | default (10 min) | default (10 min) |
| Backchannel logout / webhook | none | none |
| Authorization request | pass `Resource = "https://remote.moonl.cloud"` (`AuthorizationOptions.Resource`) | pass `extraParams: { resource: "https://remote.moonl.cloud" }` |

¹ This assumes the SPA is served from the same origin as the API. Then the RS needs no CORS. If the web client lives elsewhere, its origin replaces this, and the RS needs CORS for `Authorization` (and later `DPoP`) headers.

Resulting RS config: `Audiences = [<desktop client_id>, <web client_id>, "https://remote.moonl.cloud"]`, `AllowedClients = [<desktop client_id>, <web client_id>]`, `PublicURL = "https://remote.moonl.cloud"`, `RequireDPoP = false`. The client ids are `ms_…` values assigned at registration.

Notes:
1. **Subject.** Portal clients default to `pairwise` with sector = client id (`clients.go`: `SubjectType: "pairwise"`; `provider.go` `pairwise`). There is no sector-id field. With pairwise subjects, desktop and web would get different `sub` values for one user, and the RS could not key hosts or devices by user. An admin must set `public` on both clients.
2. **Optional third client.** A confidential `moon-remote-server` (kind `web` or `service`) is needed only if the server should react to SSO-side events: back-channel logout, or a webhook on `user.disabled`/`user.deleted`/`user.password_changed` to tear down live remote sessions. Token validation does not need it. Decide in Phase 1.
3. Local development needs no registration. Use the testbed fixtures, or DCR (`/__test/iat` + `/oauth/register`, then `/__test/clients/{id}/trust`).

## 7. Risks and follow-ups for Phase 1

- **Revocation lag.** Validation is local, so a revoked session's access token keeps working for up to its TTL (10 min). Long-lived remote-desktop sessions (signaling WebSocket, WebRTC) should check `exp` when a session opens, re-authenticate on reconnect, and, if instant kill matters, consume SSO events (note 2 above). Introspection per request is not recommended.
- **Bearer-only tokens** (§2). Raise with the moon-sso owner whether to issue `cnf`-bound access tokens. Until then, DPoP protects only refresh tokens.
- **Replay cache** is in-process. Replace it with a shared store before running more than one replica (only matters once bound tokens exist).
- **SDK JWKS lock.** The Go SDK fetches JWKS while holding its cache mutex, so during a refetch all verifications wait (15 s HTTP timeout worst case). This is acceptable; the stale-set fallback covers SSO outages.
- **`PublicURL` must be configured.** The DPoP `htu` is rebuilt from config, not from `Host`/`X-Forwarded-*`. A test covers that an internal-host htu is rejected.
- The .NET SDK's API `HttpClient` sends no User-Agent (the RS log shows `ua=""`). This is cosmetic.
- Testbed: the `-config ../.secrets/dev/config.toml` invocation in `cmd/testbed/main.go` doesn't start against the current test DB; `.secrets/testbed/config.toml` does.
