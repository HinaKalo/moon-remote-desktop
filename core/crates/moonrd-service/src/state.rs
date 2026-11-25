//! The host's persistent secrets and settings.
//!
//! Everything lives in one file, encrypted with a [`Protector`] (DPAPI with the machine
//! key on Windows) inside a directory only SYSTEM and Administrators can open. It holds:
//! the device's Ed25519 key (generated here, never leaves the service), the server
//! registration and device token, the PIN verifier, the lockout counter and the
//! pairings. Writes are atomic (temp file + rename), so a crash never leaves a torn file;
//! the lockout counter is persisted before each PIN attempt (see `moonrd-session`).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use moonrd_session::handshake::HostStore;
use moonrd_session::lockout::Lockout;
use moonrd_session::pairing::Pairings;
use moonrd_session::pin::{PinError, PinVerifier};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Encrypts the state file at rest.
pub trait Protector: Send + Sync {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>>;
    fn unprotect(&self, sealed: &[u8]) -> io::Result<Vec<u8>>;
}

/// The device's registration with moon-remote-server.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Registration {
    pub server_url: String,
    pub device_id: String,
    pub user_sub: String,
    pub name: String,
    /// `mrdd_…`; authenticates the host to the server while nobody is signed in.
    pub device_token: String,
    /// Server key that signs LAN rosters (base64), pinned at registration.
    pub roster_key: String,
    pub roster_key_id: String,
}

impl std::fmt::Debug for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("server_url", &self.server_url)
            .field("device_id", &self.device_id)
            .field("user_sub", &self.user_sub)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Everything persisted by the host service.
#[derive(Default, Serialize, Deserialize)]
pub struct HostState {
    pub version: u32,
    /// Ed25519 seed of the device key.
    pub device_seed: Option<[u8; 32]>,
    pub registration: Option<Registration>,
    pub pin: Option<PinVerifier>,
    pub lockout: Lockout,
    pub pairings: Pairings,
    /// "Allow LAN direct connection" (off by default).
    pub lan_direct: bool,
}

impl Drop for HostState {
    fn drop(&mut self) {
        if let Some(s) = self.device_seed.as_mut() {
            s.zeroize();
        }
        if let Some(r) = self.registration.as_mut() {
            r.device_token.zeroize();
        }
    }
}

const STATE_VERSION: u32 = 1;

/// Exact bytes a device signs to register (must match the server's
/// `devices.RegistrationMessage`).
pub fn registration_message(nonce: &str, user_sub: &str, kind: &str, public_key_b64: &str) -> Vec<u8> {
    format!("moonrd/device-register/v1\n{nonce}\n{user_sub}\n{kind}\n{public_key_b64}").into_bytes()
}

/// State file on disk.
pub struct StateFile {
    path: PathBuf,
    protector: Box<dyn Protector>,
}

impl StateFile {
    pub fn new(path: impl Into<PathBuf>, protector: Box<dyn Protector>) -> Self {
        Self { path: path.into(), protector }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads the state; a missing file is a fresh install.
    pub fn load(&self) -> io::Result<HostState> {
        let sealed = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut fresh = HostState::default();
                fresh.version = STATE_VERSION;
                return Ok(fresh);
            }
            Err(e) => return Err(e),
        };
        let mut plain = self.protector.unprotect(&sealed)?;
        let parsed = serde_json::from_slice::<HostState>(&plain);
        plain.zeroize();
        let state = parsed.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("host state: {e}")))?;
        if state.version != STATE_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported host state version {}", state.version)));
        }
        Ok(state)
    }

    /// Writes the state atomically.
    pub fn save(&self, state: &HostState) -> io::Result<()> {
        let mut plain = serde_json::to_vec(state).map_err(io::Error::other)?;
        let sealed = self.protector.protect(&plain);
        plain.zeroize();
        let sealed = sealed?;
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&sealed)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }
}

/// The loaded state plus its file: the object the rest of the service works with.
pub struct Host {
    pub state: HostState,
    file: StateFile,
    /// Unix seconds; injectable for tests.
    clock: fn() -> u64,
}

fn system_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Host {
    pub fn open(file: StateFile) -> io::Result<Self> {
        Ok(Self { state: file.load()?, file, clock: system_now })
    }

    #[doc(hidden)]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    pub fn save(&self) -> io::Result<()> {
        self.file.save(&self.state)
    }

    /// The device key, generated and persisted on first use.
    pub fn device_key(&mut self) -> io::Result<SigningKey> {
        if let Some(seed) = self.state.device_seed {
            return Ok(SigningKey::from_bytes(&seed));
        }
        let key = SigningKey::generate(&mut OsRng);
        self.state.device_seed = Some(key.to_bytes());
        self.save()?;
        Ok(key)
    }

    /// Signs a registration challenge for the signed-in user (the UI then calls the
    /// server). Returns `(public key, signature)` in base64.
    pub fn sign_registration(&mut self, nonce: &str, user_sub: &str, kind: &str) -> io::Result<(String, String)> {
        let key = self.device_key()?;
        let public = B64.encode(key.verifying_key().to_bytes());
        let sig = key.sign(&registration_message(nonce, user_sub, kind, &public));
        Ok((public, B64.encode(sig.to_bytes())))
    }

    /// Stores a completed registration. Changing the account invalidates PIN state
    /// and pairings, which belong to the previous owner.
    pub fn complete_registration(&mut self, reg: Registration) -> io::Result<()> {
        let account_changed = self.state.registration.as_ref().is_some_and(|r| r.user_sub != reg.user_sub);
        if account_changed {
            self.state.pin = None;
            self.state.pairings = Pairings::default();
            self.state.lockout = Lockout::default();
        }
        self.state.registration = Some(reg);
        self.save()
    }

    /// Forgets the registration, PIN and pairings, and rotates the device key so a
    /// leaked old token or key is useless.
    pub fn unregister(&mut self) -> io::Result<()> {
        self.state.registration = None;
        self.state.pin = None;
        self.state.pairings = Pairings::default();
        self.state.lockout = Lockout::default();
        self.state.device_seed = None;
        self.save()
    }

    /// Sets a new PIN (validated) and clears pairings made with the old one.
    pub fn set_pin(&mut self, pin: &str) -> Result<(), SetPinError> {
        let v = PinVerifier::create(pin).map_err(SetPinError::Pin)?;
        self.state.pin = Some(v);
        self.state.pairings = Pairings::default();
        self.state.lockout = Lockout::default();
        self.save().map_err(SetPinError::Io)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SetPinError {
    #[error(transparent)]
    Pin(PinError),
    #[error("saving host state: {0}")]
    Io(io::Error),
}

impl HostStore for Host {
    fn now(&self) -> u64 {
        (self.clock)()
    }
    fn lockout(&mut self) -> &mut Lockout {
        &mut self.state.lockout
    }
    fn pairings(&mut self) -> &mut Pairings {
        &mut self.state.pairings
    }
    fn persist(&mut self) -> Result<(), String> {
        self.save().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    /// XOR "encryption" so tests can check the file is not plain JSON.
    struct Xor;
    impl Protector for Xor {
        fn protect(&self, p: &[u8]) -> io::Result<Vec<u8>> {
            Ok(p.iter().map(|b| b ^ 0x5a).collect())
        }
        fn unprotect(&self, s: &[u8]) -> io::Result<Vec<u8>> {
            Ok(s.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    fn host(dir: &Path) -> Host {
        Host::open(StateFile::new(dir.join("host-state.bin"), Box::new(Xor))).unwrap()
    }

    fn reg(sub: &str) -> Registration {
        Registration {
            server_url: "https://remote.moonl.cloud".into(),
            device_id: "d1".into(),
            user_sub: sub.into(),
            name: "Office".into(),
            device_token: "mrdd_x".into(),
            roster_key: "AAAA".into(),
            roster_key_id: "k".into(),
        }
    }

    #[test]
    fn fresh_install_then_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = host(dir.path());
        assert!(h.state.registration.is_none() && h.state.device_seed.is_none());
        let key = h.device_key().unwrap();
        h.set_pin("482916").unwrap();
        h.complete_registration(reg("alice")).unwrap();

        let raw = fs::read(dir.path().join("host-state.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("mrdd_x"), "state must not be stored in clear");

        let mut again = host(dir.path());
        assert_eq!(again.device_key().unwrap().to_bytes(), key.to_bytes(), "device key is stable");
        assert_eq!(again.state.registration, Some(reg("alice")));
        assert!(again.state.pin.is_some());
    }

    #[test]
    fn registration_signature_matches_server_format() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = host(dir.path());
        let (public, sig) = h.sign_registration("n0nce", "sub-1", "host").unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&B64.decode(&public).unwrap().try_into().unwrap()).unwrap();
        let sig = Signature::from_slice(&B64.decode(sig).unwrap()).unwrap();
        let msg = format!("moonrd/device-register/v1\nn0nce\nsub-1\nhost\n{public}");
        assert!(vk.verify(msg.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn known_vector_matches_go_server() {
        // Same vector as server/internal/devices TestRegistrationVector (computed with Go's
        // devices.RegistrationMessage); change both together if the format changes.
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let public = B64.encode(key.verifying_key().to_bytes());
        let sig = B64.encode(key.sign(&registration_message("nonce-1", "sub-1", "host", &public)).to_bytes());
        assert_eq!(public, "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=");
        assert_eq!(sig, "f83P7B4J4MFyqlbkCwBPI5NlzTkv1LzDRgCP+nYS/iJAK93Fl0DTpiGf+1lkN+pSNcKWcEAbS1o4WasgjuzhCQ==");
    }

    #[test]
    fn account_change_drops_pin_and_pairings() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = host(dir.path());
        h.complete_registration(reg("alice")).unwrap();
        h.set_pin("482916").unwrap();
        h.state.pairings.grant("v1", "laptop", 0);
        h.complete_registration(reg("alice")).unwrap();
        assert!(h.state.pin.is_some() && h.state.pairings.list().len() == 1, "same account keeps them");
        h.complete_registration(reg("bob")).unwrap();
        assert!(h.state.pin.is_none() && h.state.pairings.list().is_empty());
    }

    #[test]
    fn unregister_rotates_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = host(dir.path());
        let k1 = h.device_key().unwrap();
        h.complete_registration(reg("alice")).unwrap();
        h.unregister().unwrap();
        assert!(h.state.registration.is_none());
        assert_ne!(h.device_key().unwrap().to_bytes(), k1.to_bytes());
    }

    #[test]
    fn new_pin_clears_pairings_and_lockout() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = host(dir.path());
        h.state.pairings.grant("v1", "laptop", 0);
        h.state.lockout.failures = 3;
        assert!(matches!(h.set_pin("123456"), Err(SetPinError::Pin(PinError::Weak))));
        h.set_pin("482916").unwrap();
        assert!(h.state.pairings.list().is_empty() && h.state.lockout.failures == 0);
    }

    #[test]
    fn host_store_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = host(dir.path()).with_clock(|| 1234);
        assert_eq!(h.now(), 1234);
        h.lockout().failures = 2;
        h.persist().unwrap();
        assert_eq!(host(dir.path()).state.lockout.failures, 2);
    }

    #[test]
    fn corrupt_or_foreign_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("host-state.bin"), b"garbage").unwrap();
        assert!(Host::open(StateFile::new(dir.path().join("host-state.bin"), Box::new(Xor))).is_err());
    }
}
