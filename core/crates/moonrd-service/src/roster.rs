//! Offline signed device roster verification for LAN direct mode.
//!
//! Matches `server/internal/roster/roster.go`: verifies the Ed25519 signature over the
//! exact decoded `roster` JSON bytes against the pinned `roster_key`, then checks
//! version (`v == 1`), `userSub`, and expiry (`now < exp`, 14-day offline validity).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::server_api::DeviceView;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedRoster {
    pub roster: String,
    pub signature: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RosterEntry {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Roster {
    pub v: u32,
    pub user_sub: String,
    pub iat: i64,
    pub exp: i64,
    pub devices: Vec<RosterEntry>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterError {
    #[error("invalid pinned roster key")]
    BadPinnedKey,
    #[error("invalid base64 payload or signature")]
    BadEncoding,
    #[error("roster signature verification failed")]
    BadSignature,
    #[error("invalid roster json: {0}")]
    BadJson(String),
    #[error("unsupported roster version {0}")]
    BadVersion(u32),
    #[error("roster belongs to another account")]
    WrongAccount,
    #[error("roster expired")]
    Expired,
}

/// Verifies `signed` against the pinned base64 Ed25519 `pinned_key_b64`, checks account
/// binding (`expected_user_sub`), and checks expiry against `now_unix` (seconds).
pub fn verify_roster(
    pinned_key_b64: &str,
    expected_user_sub: &str,
    signed: &SignedRoster,
    now_unix: i64,
) -> Result<Roster, RosterError> {
    let key_bytes: [u8; 32] = B64
        .decode(pinned_key_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(RosterError::BadPinnedKey)?;
    let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|_| RosterError::BadPinnedKey)?;

    let body = B64.decode(&signed.roster).map_err(|_| RosterError::BadEncoding)?;
    let sig_bytes: [u8; 64] = B64
        .decode(&signed.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(RosterError::BadEncoding)?;
    let sig = Signature::from_bytes(&sig_bytes);

    vk.verify(&body, &sig).map_err(|_| RosterError::BadSignature)?;

    let roster: Roster = serde_json::from_slice(&body).map_err(|e| RosterError::BadJson(e.to_string()))?;
    if roster.v != 1 {
        return Err(RosterError::BadVersion(roster.v));
    }
    if roster.user_sub != expected_user_sub {
        return Err(RosterError::WrongAccount);
    }
    if now_unix >= roster.exp {
        return Err(RosterError::Expired);
    }
    Ok(roster)
}

impl Roster {
    /// Converts roster entries into `DeviceView`s for populating [`crate::quic_host::DeviceDirectory`].
    pub fn to_device_views(&self, self_device_id: &str) -> Vec<DeviceView> {
        self.devices
            .iter()
            .map(|e| DeviceView {
                id: e.id.clone(),
                name: e.name.clone(),
                kind: e.kind.clone(),
                public_key: e.public_key.clone(),
                online: false,
                is_self: e.id == self_device_id,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign(sk: &SigningKey, json: &str) -> SignedRoster {
        let sig = sk.sign(json.as_bytes());
        SignedRoster {
            roster: B64.encode(json.as_bytes()),
            signature: B64.encode(sig.to_bytes()),
            key_id: "k1".into(),
        }
    }

    #[test]
    fn verifies_valid_and_rejects_expired_tampered_or_wrong_account() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let pk_b64 = B64.encode(sk.verifying_key().to_bytes());
        let payload = r#"{"v":1,"userSub":"alice","iat":1000,"exp":2000,"devices":[{"id":"d1","name":"Laptop","kind":"viewer","publicKey":"AAAA"}]}"#;
        let sr = sign(&sk, payload);

        let r = verify_roster(&pk_b64, "alice", &sr, 1500).unwrap();
        assert_eq!(r.devices.len(), 1);
        assert_eq!(r.to_device_views("d-host").len(), 1);

        assert_eq!(verify_roster(&pk_b64, "alice", &sr, 2000), Err(RosterError::Expired));
        assert_eq!(verify_roster(&pk_b64, "bob", &sr, 1500), Err(RosterError::WrongAccount));

        let mut tampered = sr.clone();
        tampered.roster = B64.encode(payload.replace("Laptop", "Evil").as_bytes());
        assert_eq!(verify_roster(&pk_b64, "alice", &tampered, 1500), Err(RosterError::BadSignature));
    }
}
