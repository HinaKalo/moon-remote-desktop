# Session protocol and authentication

Message types are in [proto/moonrd.proto](../proto/moonrd.proto). This page covers how a session is authenticated and carried. Code: `core/crates/moonrd-session` (transport-independent) and `core/crates/moonrd-transport` (QUIC).

## Layers

| Layer | Native ↔ native (same account, EasyTier or LAN) | Browser / support session |
| --- | --- | --- |
| Transport | QUIC (quinn), TLS 1.3 with **raw public keys** (RFC 7250) | WebRTC (Phase 6): DTLS-SRTP video track + data channel |
| Peer identity | device Ed25519 keys: viewer pins the host's key from the device list; host accepts keys on its allow list (account devices / signed roster) | none at transport level (browser certs are ephemeral) |
| Channel binding | SHA-256 over 32 bytes of TLS exporter `EXPORTER-moonrd-v1-binding` | SHA-256 over both DTLS fingerprints |
| Session auth | SPAKE2 with PIN or pairing key | SPAKE2 with PIN (web) or support code |
| Messages | `Envelope`, varint length-delimited on the control stream | `Envelope` on the data channel |

## Handshake

Implemented as two sans-IO state machines in `moonrd-session/src/handshake.rs` (`HostHandshake`, `ViewerHandshake`). The caller moves `Envelope`s between them and the transport.

```
viewer → host   Hello            (kind, offered methods, device id, pairing_id?)
host   → viewer HelloAck         (chosen method, pin_salt, argon2 params)  + AuthMessage.spake2_message
viewer → host   AuthMessage.spake2_message + AuthMessage.key_confirmation
host   → viewer AuthMessage.key_confirmation
host   → viewer AuthResult       (support sessions: only after the host user consents)
```

A refusal is `HelloAck` with method `UNSPECIFIED` followed by `AuthResult(NOT_ALLOWED | LOCKED_OUT)`, sent without running SPAKE2.

**Host: method choice**
- **Remote access:** use the pairing if the viewer offers one and the host has it for **that device id**. Otherwise use the PIN, if one is set and the viewer offers it. Otherwise `NOT_ALLOWED`.
- **Support:** only with an active support code, and only by that code. A PIN is never accepted for support.
- **Transport identity:** with QUIC, the viewer's device id is proven by its raw public key. A `Hello` claiming a different id is refused before any PIN attempt is spent.

**Lockout**
- The host counts each PIN attempt as failed **before running SPAKE2**, persists that, and clears the counter only on success (`lockout.rs`).
- It allows 5 consecutive failures, then locks out for 30 s, doubling each time up to 1 h.
- Parallel or abandoned attempts don't get free guesses, and a restart doesn't reset the count.
- If the lockout state can't be persisted, the attempt is refused (fail closed).

**Viewer checks**
- The viewer accepts success only if the host's key confirmation verified. `AuthResult OK` alone is not trusted.
- It rejects a method it didn't offer (downgrade) and Argon2 parameters outside 8–256 MiB / 1–10 passes.
- A malformed PIN entry (wrong length) is caught locally and can be retried without spending a host attempt.

**Closing after a final message**
- Dropping a quinn connection discards data the peer hasn't received yet.
- So after sending a refusal or failure, the host calls `ControlStream::finish_and_flush` before closing. A test covers this, and it fails without the flush.

**Pairing request**
- After an `OK` PIN login, the viewer may send `PairingRequest`; the host answers with `grant_pairing`.
- It only grants after a PIN login by a known device. Otherwise it returns an empty grant, meaning declined.

## SPAKE2

- **Construction:** SPAKE2 over Ed25519 as implemented by the RustCrypto `spake2` 0.4 crate (compatible with python-spake2 / magic-wormhole). The viewer is side A and the host is side B. *The plan said ristretto255. The audited crate only offers the Ed25519 group, so we use it, and the web viewer implements that same group.*
- **Identities:**
  - viewer: `"moonrd/v1/viewer/" || method || "/" || binding`
  - host: `"moonrd/v1/host/" || method || "/" || binding`

  This binds the run to the auth method and to this exact transport channel. A relay that terminates the transport twice cannot complete key confirmation, so the signalling server can't sit in the middle.
- **Password input:**
  - PIN and support code: `w = Argon2id(PIN, salt, m=19 MiB, t=2, p=1)`, 32 bytes. The host stores only `w` (DPAPI LocalMachine). Viewers refuse unreasonable Argon2 parameters (above 256 MiB, and so on).
  - Pairing: the 32-byte pairing key directly.
- **Key schedule from the SPAKE2 output K:**
  - `confirm_viewer = HMAC-SHA256(K, "moonrd/v1 confirm viewer")`
  - `confirm_host = HMAC-SHA256(K, "moonrd/v1 confirm host")`
  - `session_key = HMAC-SHA256(K, "moonrd/v1 session")`

  Tags are compared in constant time, and a side never accepts its own tag back. A wrong PIN is detected only at this step.
- **PIN rules:** 6–12 ASCII digits. Rejected: all one digit, and straight runs (123456, 654321).

## Pairing ("remember this controller")

- **Grant:** after a PIN success the host may grant `{pairing_id, pairing_key}`, sent only inside the authenticated session.
- **Later connections:** the viewer offers `pairing_id`. The host accepts it only from the **same viewer device id** it was granted to, and uses `pairing_key` as the SPAKE2 secret (`AUTH_METHOD_PAIRING`).
- **Storage:** at most 32 pairings per host; beyond that, the least recently used is dropped.
- **Labels:** stripped of control and bidi/zero-width characters before they're shown to the host user.
- **Removal:** the host user can revoke a pairing. Pairings of devices that leave the account are pruned.

## Test vectors

`core/crates/moonrd-session/testdata/pake-vectors.json` holds deterministic vectors: the Argon2id output, both binding constructions, and four handshakes (PIN ok, wrong PIN, support code over WebRTC binding, pairing). The TypeScript web viewer must reproduce them byte for byte.
- The test `vectors_are_stable` fails if the Rust output ever changes.
- Regenerate them only after an intentional protocol change, with `MOONRD_REGEN_VECTORS=1 cargo test -p moonrd-session --test vectors`.
