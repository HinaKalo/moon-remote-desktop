//! Device keys as TLS raw public keys (RFC 7250).
//!
//! Every installation has one Ed25519 key, registered with the server
//! (`POST /v1/devices`). The same key authenticates the QUIC connection: each side
//! presents only its SubjectPublicKeyInfo, no X.509 certificate, and the peer compares
//! it byte for byte with the key it expects. There is no certificate parsing to get
//! wrong and no CA involved.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the 32-byte key follows.
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// DER prefix of an Ed25519 PKCS#8 v1 private key (RFC 8410); the 32-byte seed follows.
const PKCS8_PREFIX: [u8; 16] =
    [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

/// An Ed25519 public key.
pub type PublicKey = [u8; 32];

/// SubjectPublicKeyInfo DER of an Ed25519 public key.
pub fn spki(public: &PublicKey) -> Vec<u8> {
    let mut v = SPKI_PREFIX.to_vec();
    v.extend_from_slice(public);
    v
}

/// Parses an Ed25519 SubjectPublicKeyInfo produced by [`spki`]. Anything else
/// (other algorithms, extra bytes, a real X.509 certificate) is rejected.
pub fn public_from_spki(der: &[u8]) -> Option<PublicKey> {
    if der.len() != SPKI_PREFIX.len() + 32 || der[..SPKI_PREFIX.len()] != SPKI_PREFIX {
        return None;
    }
    der[SPKI_PREFIX.len()..].try_into().ok()
}

/// The device's own key pair.
pub struct DeviceKey {
    seed: Zeroizing<[u8; 32]>,
    public: PublicKey,
}

impl DeviceKey {
    /// From the 32-byte Ed25519 seed (stored by the app/service under DPAPI) and its
    /// public key. The public key is checked against the seed when the TLS signer is
    /// built.
    pub fn new(seed: [u8; 32], public: PublicKey) -> Self {
        Self { seed: Zeroizing::new(seed), public }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The key as rustls needs it: a raw-public-key "certificate" plus a signer.
    pub(crate) fn certified(&self, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>, rustls::Error> {
        let mut pkcs8 = Zeroizing::new(Vec::with_capacity(48));
        pkcs8.extend_from_slice(&PKCS8_PREFIX);
        pkcs8.extend_from_slice(self.seed.as_ref());
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec()));
        let signer = provider.key_provider.load_private_key(der)?;
        // Make sure the configured public key really belongs to this seed.
        match signer.public_key() {
            Some(spki_der) if public_from_spki(spki_der.as_ref()) == Some(self.public) => {}
            _ => return Err(rustls::Error::General("device public key does not match its seed".into())),
        }
        Ok(Arc::new(CertifiedKey::new(vec![CertificateDer::from(spki(&self.public))], signer)))
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey").field("public", &self.public).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_round_trip_and_strictness() {
        let k = [9u8; 32];
        assert_eq!(public_from_spki(&spki(&k)), Some(k));
        let mut long = spki(&k);
        long.push(0);
        assert_eq!(public_from_spki(&long), None);
        let mut other_alg = spki(&k);
        other_alg[8] = 0x71; // Ed448 OID
        assert_eq!(public_from_spki(&other_alg), None);
        assert_eq!(public_from_spki(&[]), None);
    }
}
