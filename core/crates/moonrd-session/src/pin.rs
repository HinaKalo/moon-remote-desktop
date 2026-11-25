//! Host PIN rules and the stored PIN verifier.
//!
//! The host never stores the PIN. It stores `w = Argon2id(PIN, salt)`, the value both
//! sides feed into SPAKE2. `w` is still password-equivalent for this host, so the host
//! service keeps it under DPAPI (LocalMachine) with an ACL; the PIN itself cannot be
//! recovered from it without a brute-force search over the PIN space at Argon2 cost.

use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Shortest accepted PIN.
pub const MIN_PIN_LEN: usize = 6;
/// Longest accepted PIN.
pub const MAX_PIN_LEN: usize = 12;

/// Argon2id cost. The viewer pays it once per attempt, including in the browser (WASM),
/// so it follows the OWASP minimum (19 MiB, 2 passes) rather than something heavier;
/// online guessing is bounded by the host's lockout, not by this cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 }
    }
}

impl KdfParams {
    /// Bounds a viewer accepts from a host, so a malicious host cannot make the viewer
    /// burn gigabytes of memory.
    pub fn is_reasonable(&self) -> bool {
        (8 * 1024..=256 * 1024).contains(&self.memory_kib)
            && (1..=10).contains(&self.iterations)
            && (1..=4).contains(&self.parallelism)
    }

    pub fn to_proto(self) -> moonrd_proto::Argon2Params {
        moonrd_proto::Argon2Params { memory_kib: self.memory_kib, iterations: self.iterations, parallelism: self.parallelism }
    }

    pub fn from_proto(p: &moonrd_proto::Argon2Params) -> Self {
        Self { memory_kib: p.memory_kib, iterations: p.iterations, parallelism: p.parallelism }
    }
}

/// Why a PIN was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PinError {
    #[error("PIN must be {MIN_PIN_LEN}-{MAX_PIN_LEN} digits")]
    Length,
    #[error("PIN must contain only the digits 0-9")]
    NotDigits,
    #[error("PIN is too easy to guess")]
    Weak,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("unreasonable key-derivation parameters")]
    BadParams,
}

/// Checks a new PIN: digits only, 6-12 long, not all one digit and not a straight run.
pub fn validate_new_pin(pin: &str) -> Result<(), PinError> {
    validate_format(pin)?;
    let d: Vec<i32> = pin.bytes().map(|b| i32::from(b - b'0')).collect();
    let all_same = d.iter().all(|&x| x == d[0]);
    let step = d[1] - d[0];
    let run = (step == 1 || step == -1) && d.windows(2).all(|w| w[1] - w[0] == step);
    if all_same || run {
        return Err(PinError::Weak);
    }
    Ok(())
}

fn validate_format(pin: &str) -> Result<(), PinError> {
    if !(MIN_PIN_LEN..=MAX_PIN_LEN).contains(&pin.len()) {
        return Err(PinError::Length);
    }
    if !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PinError::NotDigits);
    }
    Ok(())
}

/// 32-byte secret fed into SPAKE2. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Secret(pub(crate) [u8; 32]);

impl Secret {
    /// Wraps a high-entropy key (a pairing key).
    pub fn from_key(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Derives the SPAKE2 input from a PIN or support code.
    pub fn derive(pin: &str, salt: &[u8], params: KdfParams) -> Result<Self, PinError> {
        validate_format(pin)?;
        if !params.is_reasonable() {
            return Err(PinError::BadParams);
        }
        let p = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
            .map_err(|e| PinError::Kdf(e.to_string()))?;
        let mut out = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
            .hash_password_into(pin.as_bytes(), salt, &mut out)
            .map_err(|e| PinError::Kdf(e.to_string()))?;
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// What the host stores for its PIN.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinVerifier {
    pub salt: [u8; 16],
    pub params: KdfParams,
    /// `w = Argon2id(PIN, salt)`.
    pub w: [u8; 32],
}

impl Drop for PinVerifier {
    fn drop(&mut self) {
        self.w.zeroize();
    }
}

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinVerifier").field("params", &self.params).finish_non_exhaustive()
    }
}

impl PinVerifier {
    /// Validates a new PIN and derives its verifier with a fresh salt.
    pub fn create(pin: &str) -> Result<Self, PinError> {
        validate_new_pin(pin)?;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let params = KdfParams::default();
        let s = Secret::derive(pin, &salt, params)?;
        Ok(Self { salt, params, w: s.0 })
    }

    /// Verifier for a one-time support code issued by the server. Codes are random, so
    /// only the format is checked, not guessability.
    pub fn for_support_code(code: &str) -> Result<Self, PinError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let params = KdfParams::default();
        let s = Secret::derive(code, &salt, params)?;
        Ok(Self { salt, params, w: s.0 })
    }

    pub fn secret(&self) -> Secret {
        Secret(self.w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_rules() {
        for ok in ["482916", "2025113", "000100", "135790", "123456789013"] {
            assert_eq!(validate_new_pin(ok), Ok(()), "{ok}");
        }
        assert_eq!(validate_new_pin("12345"), Err(PinError::Length));
        assert_eq!(validate_new_pin("1234567890123"), Err(PinError::Length));
        assert_eq!(validate_new_pin("12a456"), Err(PinError::NotDigits));
        assert_eq!(validate_new_pin("１２３４５６"), Err(PinError::Length), "full-width digits are multi-byte");
        for weak in ["000000", "999999", "123456", "654321", "3456789", "987654321"] {
            assert_eq!(validate_new_pin(weak), Err(PinError::Weak), "{weak}");
        }
    }

    #[test]
    fn verifier_matches_viewer_derivation() {
        let v = PinVerifier::create("482916").unwrap();
        let viewer = Secret::derive("482916", &v.salt, v.params).unwrap();
        assert_eq!(viewer, v.secret());
        let wrong = Secret::derive("482917", &v.salt, v.params).unwrap();
        assert_ne!(wrong, v.secret());
        let other_salt = PinVerifier::create("482916").unwrap();
        assert_ne!(other_salt.secret(), v.secret(), "salt must differ per host");
    }

    #[test]
    fn viewer_refuses_hostile_params() {
        let huge = KdfParams { memory_kib: 4 << 20, iterations: 2, parallelism: 1 };
        assert_eq!(Secret::derive("482916", b"saltsaltsaltsalt", huge), Err(PinError::BadParams));
        let zero = KdfParams { memory_kib: 19 * 1024, iterations: 0, parallelism: 1 };
        assert_eq!(Secret::derive("482916", b"saltsaltsaltsalt", zero), Err(PinError::BadParams));
    }

    #[test]
    fn debug_does_not_leak() {
        let v = PinVerifier::create("482916").unwrap();
        assert_eq!(format!("{:?}", v.secret()), "Secret(..)");
        let dbg = format!("{v:?}");
        assert!(dbg.starts_with("PinVerifier") && !dbg.contains("w:") && !dbg.contains("salt"), "{dbg}");
    }
}
