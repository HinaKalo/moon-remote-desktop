//! rustls verifiers for raw-public-key peers: the viewer pins exactly one host key; the
//! host accepts any key on its allow list (the account's devices, from the server's
//! device list or, in LAN mode, the signed roster).

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, PeerIncompatible, SignatureScheme};

use crate::keys::{public_from_spki, PublicKey};

fn check_tls13(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    algs: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme != SignatureScheme::ED25519 {
        return Err(Error::PeerIncompatible(PeerIncompatible::NoSignatureSchemesInCommon));
    }
    verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(cert.as_ref()), dss, algs)
}

fn no_tls12() -> Result<HandshakeSignatureValid, Error> {
    Err(Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
}

/// Viewer side: the host must present exactly `expected`.
#[derive(Debug)]
pub struct PinnedHost {
    pub expected: PublicKey,
    pub algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedHost {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if intermediates.is_empty() && public_from_spki(end_entity) == Some(self.expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("host key does not match the expected device key".into()))
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        no_tls12()
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        check_tls13(m, c, d, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The set of viewer keys a host accepts. Shared with the host service, which replaces
/// it whenever the account's device list or roster changes; new handshakes see the
/// update immediately.
#[derive(Debug, Clone, Default)]
pub struct AllowList(Arc<RwLock<HashSet<PublicKey>>>);

impl AllowList {
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self(Arc::new(RwLock::new(keys.into_iter().collect())))
    }

    pub fn replace(&self, keys: impl IntoIterator<Item = PublicKey>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = keys.into_iter().collect();
    }

    pub fn contains(&self, key: &PublicKey) -> bool {
        self.0.read().unwrap_or_else(|e| e.into_inner()).contains(key)
    }
}

/// Host side: the viewer must present a key on the allow list.
#[derive(Debug)]
pub struct AllowedViewers {
    pub allow: AllowList,
    pub algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AllowedViewers {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], _now: UnixTime) -> Result<ClientCertVerified, Error> {
        match public_from_spki(end_entity) {
            Some(k) if intermediates.is_empty() && self.allow.contains(&k) => Ok(ClientCertVerified::assertion()),
            _ => Err(Error::General("viewer key is not a device of this account".into())),
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        no_tls12()
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        check_tls13(m, c, d, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
