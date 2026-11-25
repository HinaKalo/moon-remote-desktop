//! SPAKE2 authentication of a session with a low-entropy secret (host PIN, support
//! code) or a pairing key.
//!
//! * Group: SPAKE2 over Ed25519 as implemented by the RustCrypto `spake2` crate (the
//!   magic-wormhole / python-spake2 construction). The viewer is side A, the host side B.
//!   Wire messages are the crate's 33 bytes: a side byte (`A`/`B`) plus a point.
//! * Both identities contain the auth method and the channel binding: a SHA-256 over
//!   the transport's exporter (QUIC TLS exporter, or both DTLS fingerprints for WebRTC).
//!   A relay that terminates the transport on each side sees two different channels,
//!   so the two runs derive different keys and key confirmation fails. The signalling
//!   server therefore cannot sit in the middle even though it relays the setup.
//! * Key schedule from the SPAKE2 output K:
//!   `confirm_viewer = HMAC-SHA256(K, "moonrd/v1 confirm viewer")`,
//!   `confirm_host   = HMAC-SHA256(K, "moonrd/v1 confirm host")`,
//!   `session_key    = HMAC-SHA256(K, "moonrd/v1 session")`.
//!   Each side sends its own confirmation tag and checks the peer's in constant time.
//!   A wrong secret is only detectable here; SPAKE2 itself always "succeeds".

use hmac::{Hmac, Mac};
use moonrd_proto::AuthMethod;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::pin::Secret;

type HmacSha256 = Hmac<Sha256>;

/// Which end of the session this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Host,
}

/// Errors during authentication.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("malformed SPAKE2 message")]
    BadMessage,
    #[error("key confirmation failed (wrong secret or tampered channel)")]
    Mismatch,
}

/// Hash of the transport channel that the authentication is tied to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChannelBinding([u8; 32]);

impl ChannelBinding {
    /// For QUIC: pass 32 bytes from the TLS exporter with label
    /// `"EXPORTER-moonrd-v1-binding"` and empty context (RFC 5705 / RFC 8446 §7.5).
    pub fn from_tls_exporter(ekm: &[u8]) -> Self {
        Self::hash(b"tls-exporter", &[ekm])
    }

    /// For WebRTC: the DTLS certificate fingerprints of both ends, as raw digest bytes.
    pub fn from_dtls_fingerprints(viewer: &[u8], host: &[u8]) -> Self {
        Self::hash(b"dtls-fingerprints", &[viewer, host])
    }

    /// Wraps an already computed binding (tests, test vectors).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn hash(kind: &[u8], parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update(b"moonrd/v1 binding ");
        h.update(kind);
        for p in parts {
            h.update((p.len() as u32).to_be_bytes());
            h.update(p);
        }
        Self(h.finalize().into())
    }
}

fn identity(role: Role, method: AuthMethod, binding: &ChannelBinding) -> Vec<u8> {
    let mut id = Vec::with_capacity(64);
    id.extend_from_slice(match role {
        Role::Viewer => b"moonrd/v1/viewer/".as_slice(),
        Role::Host => b"moonrd/v1/host/".as_slice(),
    });
    id.push(method as i32 as u8);
    id.push(b'/');
    id.extend_from_slice(binding.as_bytes());
    id
}

/// One side of a SPAKE2 run in progress.
pub struct Pake {
    role: Role,
    inner: Spake2<Ed25519Group>,
}

impl Pake {
    /// Starts a run and returns the first message to send to the peer.
    pub fn start(role: Role, method: AuthMethod, secret: &Secret, binding: &ChannelBinding) -> (Self, Vec<u8>) {
        Self::start_with_rng(role, method, secret, binding, OsRng)
    }

    /// Like [`Pake::start`] with a caller-supplied RNG. Only for deterministic test
    /// vectors; production code must use [`Pake::start`].
    #[doc(hidden)]
    pub fn start_with_rng(
        role: Role,
        method: AuthMethod,
        secret: &Secret,
        binding: &ChannelBinding,
        rng: impl RngCore + CryptoRng,
    ) -> (Self, Vec<u8>) {
        let pw = Password::new(secret.as_bytes());
        let id_a = Identity::new(&identity(Role::Viewer, method, binding));
        let id_b = Identity::new(&identity(Role::Host, method, binding));
        let (inner, msg) = match role {
            Role::Viewer => Spake2::<Ed25519Group>::start_a_with_rng(&pw, &id_a, &id_b, rng),
            Role::Host => Spake2::<Ed25519Group>::start_b_with_rng(&pw, &id_a, &id_b, rng),
        };
        (Self { role, inner }, msg)
    }

    /// Consumes the peer's message and derives the keys.
    pub fn finish(self, peer_msg: &[u8]) -> Result<Keys, AuthError> {
        let k = Zeroizing::new(self.inner.finish(peer_msg).map_err(|_| AuthError::BadMessage)?);
        let viewer = mac(&k, b"moonrd/v1 confirm viewer");
        let host = mac(&k, b"moonrd/v1 confirm host");
        let session = Zeroizing::new(mac(&k, b"moonrd/v1 session"));
        let (mine, peer) = match self.role {
            Role::Viewer => (viewer, host),
            Role::Host => (host, viewer),
        };
        Ok(Keys { mine, peer, session })
    }
}

fn mac(key: &[u8], label: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(label);
    m.finalize().into_bytes().into()
}

/// Keys derived from a finished run. The session is authenticated only after
/// [`Keys::verify_peer`] succeeds.
pub struct Keys {
    mine: [u8; 32],
    peer: [u8; 32],
    session: Zeroizing<[u8; 32]>,
}

impl Keys {
    /// Tag to send in `AuthMessage.key_confirmation`.
    pub fn confirmation(&self) -> [u8; 32] {
        self.mine
    }

    /// Checks the peer's tag in constant time.
    pub fn verify_peer(&self, tag: &[u8]) -> Result<(), AuthError> {
        if tag.len() == 32 && bool::from(tag.ct_eq(&self.peer)) { Ok(()) } else { Err(AuthError::Mismatch) }
    }

    /// Key shared by both ends, e.g. to derive the pairing grant or resume tokens.
    pub fn session_key(&self) -> &[u8; 32] {
        &self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(b: u8) -> Secret {
        Secret::from_key([b; 32])
    }

    fn binding(b: u8) -> ChannelBinding {
        ChannelBinding::from_bytes([b; 32])
    }

    /// Runs both sides; returns (viewer verifies host, host verifies viewer).
    fn run(
        vs: &Secret,
        hs: &Secret,
        vb: &ChannelBinding,
        hb: &ChannelBinding,
        vm: AuthMethod,
        hm: AuthMethod,
    ) -> (Result<(), AuthError>, Result<(), AuthError>) {
        let (v, v_msg) = Pake::start(Role::Viewer, vm, vs, vb);
        let (h, h_msg) = Pake::start(Role::Host, hm, hs, hb);
        let vk = v.finish(&h_msg).unwrap();
        let hk = h.finish(&v_msg).unwrap();
        (vk.verify_peer(&hk.confirmation()), hk.verify_peer(&vk.confirmation()))
    }

    #[test]
    fn same_secret_and_channel_authenticates() {
        let (a, b) = run(&secret(1), &secret(1), &binding(9), &binding(9), AuthMethod::Pin, AuthMethod::Pin);
        assert_eq!((a, b), (Ok(()), Ok(())));
    }

    #[test]
    fn session_keys_agree() {
        let (v, v_msg) = Pake::start(Role::Viewer, AuthMethod::Pin, &secret(1), &binding(9));
        let (h, h_msg) = Pake::start(Role::Host, AuthMethod::Pin, &secret(1), &binding(9));
        let (vk, hk) = (v.finish(&h_msg).unwrap(), h.finish(&v_msg).unwrap());
        assert_eq!(vk.session_key(), hk.session_key());
        assert_ne!(vk.confirmation(), hk.confirmation(), "tags are direction-specific");
        assert!(vk.verify_peer(&vk.confirmation()).is_err(), "own tag must not be accepted back (reflection)");
    }

    #[test]
    fn wrong_secret_fails_both_ways() {
        let (a, b) = run(&secret(1), &secret(2), &binding(9), &binding(9), AuthMethod::Pin, AuthMethod::Pin);
        assert_eq!((a, b), (Err(AuthError::Mismatch), Err(AuthError::Mismatch)));
    }

    #[test]
    fn relayed_across_two_channels_fails() {
        // A man in the middle that terminates the transport twice cannot make the
        // bindings match, even if it forwards the SPAKE2 messages untouched.
        let (a, b) = run(&secret(1), &secret(1), &binding(9), &binding(8), AuthMethod::Pin, AuthMethod::Pin);
        assert_eq!((a, b), (Err(AuthError::Mismatch), Err(AuthError::Mismatch)));
    }

    #[test]
    fn method_is_bound() {
        let (a, _) = run(&secret(1), &secret(1), &binding(9), &binding(9), AuthMethod::Pin, AuthMethod::Pairing);
        assert_eq!(a, Err(AuthError::Mismatch));
    }

    #[test]
    fn rejects_malformed_and_same_side_messages() {
        let (v, _) = Pake::start(Role::Viewer, AuthMethod::Pin, &secret(1), &binding(9));
        assert!(matches!(v.finish(&[1, 2, 3]), Err(AuthError::BadMessage)));
        // A viewer must not accept another viewer's (side A) message.
        let (v1, _) = Pake::start(Role::Viewer, AuthMethod::Pin, &secret(1), &binding(9));
        let (_, other_viewer_msg) = Pake::start(Role::Viewer, AuthMethod::Pin, &secret(1), &binding(9));
        assert!(matches!(v1.finish(&other_viewer_msg), Err(AuthError::BadMessage)));
    }

    #[test]
    fn short_or_long_tags_rejected() {
        let (v, v_msg) = Pake::start(Role::Viewer, AuthMethod::Pin, &secret(1), &binding(9));
        let (h, h_msg) = Pake::start(Role::Host, AuthMethod::Pin, &secret(1), &binding(9));
        let (vk, hk) = (v.finish(&h_msg).unwrap(), h.finish(&v_msg).unwrap());
        let tag = hk.confirmation();
        assert!(vk.verify_peer(&tag[..31]).is_err());
        let mut long = tag.to_vec();
        long.push(0);
        assert!(vk.verify_peer(&long).is_err());
    }

    #[test]
    fn binding_constructors_are_domain_separated() {
        let a = ChannelBinding::from_tls_exporter(&[1; 32]);
        let b = ChannelBinding::from_dtls_fingerprints(&[1; 16], &[1; 16]);
        let c = ChannelBinding::from_dtls_fingerprints(&[1; 16], &[2; 16]);
        let d = ChannelBinding::from_dtls_fingerprints(&[2; 16], &[1; 16]);
        assert!(a != b && b != c && c != d);
    }
}
