//! Shared verification of immutable relhub release manifests.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Pinned Ed25519 release signing public key of `https://release.moonl.cloud`
/// (`relhub keys`, keyId `f5faa9f9858b789f`).
pub const RELHUB_TRUSTED_KEYS: &[&str] = &["k4thZR+OVYSGAT/9j5F39csgGqTL0t3X6GYdNCmuRI8="];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelhubManifest {
    pub app: String,
    pub platform: String,
    pub channel: String,
    pub version_code: i64,
    pub version_name: String,
    pub file: String,
    pub size: i64,
    pub sha256: String,
    #[serde(default)]
    min_version_code: i64,
    #[serde(default)]
    notes: String,
    published_at: String,
    signature: String,
}

fn relhub_signing_payload(m: &RelhubManifest) -> Vec<u8> {
    let notes_hash = Sha256::digest(m.notes.as_bytes());
    let mut notes_hex = String::with_capacity(64);
    for b in notes_hash {
        use std::fmt::Write;
        let _ = write!(&mut notes_hex, "{b:02x}");
    }
    format!(
        "relhub-release-v1\napp={}\nplatform={}\nchannel={}\nversionCode={}\nversionName={}\nfile={}\nsize={}\nsha256={}\nminVersionCode={}\npublishedAt={}\nnotesSha256={notes_hex}\n",
        m.app,
        m.platform,
        m.channel,
        m.version_code,
        m.version_name,
        m.file,
        m.size,
        m.sha256,
        m.min_version_code,
        m.published_at,
    )
    .into_bytes()
}

fn verify_relhub_manifest_with_keys(
    m: &RelhubManifest,
    trusted_b64: &[&str],
) -> Result<(), String> {
    if trusted_b64.is_empty() {
        return Err("no trusted release keys configured".into());
    }
    let sig_bytes: [u8; 64] = B64
        .decode(m.signature.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "malformed signature".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);
    let payload = relhub_signing_payload(m);
    for key_b64 in trusted_b64 {
        if let Ok(raw) = B64.decode(key_b64.trim())
            && let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice())
            && let Ok(vk) = VerifyingKey::from_bytes(&arr)
            && vk.verify(&payload, &sig).is_ok()
        {
            return Ok(());
        }
    }
    Err("signature is not from a trusted release key".into())
}

impl RelhubManifest {
    pub fn verify(&self) -> Result<(), String> {
        verify_relhub_manifest_with_keys(self, RELHUB_TRUSTED_KEYS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn relhub_manifest_signature_verifies_and_rejects_tampering() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk_b64 = B64.encode(sk.verifying_key().to_bytes());
        let mut m = RelhubManifest {
            app: "moon-remote".into(),
            platform: "windows-x64".into(),
            channel: "stable".into(),
            version_code: 10,
            version_name: "0.1.0".into(),
            file: "moon-remote-0.1.0-windows-x64.zip".into(),
            size: 12345,
            sha256: "a".repeat(64),
            min_version_code: 0,
            notes: "Initial release".into(),
            published_at: "2026-11-20T15:00:00Z".into(),
            signature: String::new(),
        };
        let payload = relhub_signing_payload(&m);
        m.signature = B64.encode(sk.sign(&payload).to_bytes());
        assert!(verify_relhub_manifest_with_keys(&m, &[pk_b64.as_str()]).is_ok());
        assert!(verify_relhub_manifest_with_keys(&m, &[]).is_err());

        m.size = 12346;
        assert!(verify_relhub_manifest_with_keys(&m, &[pk_b64.as_str()]).is_err());
    }
}
