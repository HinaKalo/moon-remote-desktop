//! Cross-implementation test vectors for the PIN KDF and the SPAKE2 handshake.
//!
//! The TypeScript web viewer must reproduce `testdata/pake-vectors.json` byte for
//! byte. This test regenerates the vectors with a deterministic RNG and compares them
//! to the committed file; run with `MOONRD_REGEN_VECTORS=1` to rewrite it after an
//! intentional protocol change.

use moonrd_session::pake::{ChannelBinding, Pake, Role};
use moonrd_session::pin::{KdfParams, Secret};
use moonrd_session::proto::AuthMethod;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// Deterministic RNG: SHA-256(seed || counter) blocks. Test use only.
struct TestRng {
    seed: Vec<u8>,
    counter: u64,
    buf: Vec<u8>,
}

impl TestRng {
    fn new(seed: &str) -> Self {
        Self { seed: seed.as_bytes().to_vec(), counter: 0, buf: Vec::new() }
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest.iter_mut() {
            if self.buf.is_empty() {
                let mut h = Sha256::new();
                h.update(&self.seed);
                h.update(self.counter.to_be_bytes());
                self.counter += 1;
                self.buf = h.finalize().to_vec();
            }
            *d = self.buf.remove(0);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

fn vector(name: &str, method: AuthMethod, viewer_secret: &Secret, host_secret: &Secret, binding: ChannelBinding) -> serde_json::Value {
    let (v, v_msg) = Pake::start_with_rng(Role::Viewer, method, viewer_secret, &binding, TestRng::new(&format!("{name}/viewer")));
    let (h, h_msg) = Pake::start_with_rng(Role::Host, method, host_secret, &binding, TestRng::new(&format!("{name}/host")));
    let vk = v.finish(&h_msg).unwrap();
    let hk = h.finish(&v_msg).unwrap();
    serde_json::json!({
        "name": name,
        "method": method as i32,
        "viewerSecret": hex::encode(viewer_secret.as_bytes()),
        "hostSecret": hex::encode(host_secret.as_bytes()),
        "binding": hex::encode(binding.as_bytes()),
        "viewerRngSeed": format!("{name}/viewer"),
        "hostRngSeed": format!("{name}/host"),
        "viewerMessage": hex::encode(&v_msg),
        "hostMessage": hex::encode(&h_msg),
        "viewerConfirmation": hex::encode(vk.confirmation()),
        "hostConfirmation": hex::encode(hk.confirmation()),
        "viewerAccepts": vk.verify_peer(&hk.confirmation()).is_ok(),
        "hostAccepts": hk.verify_peer(&vk.confirmation()).is_ok(),
        "sessionKeyViewer": hex::encode(vk.session_key()),
        "sessionKeyHost": hex::encode(hk.session_key()),
    })
}

fn build() -> serde_json::Value {
    let params = KdfParams::default();
    let salt = *b"moonrd-test-salt";
    let pin = "482916";
    let w = Secret::derive(pin, &salt, params).unwrap();
    let wrong = Secret::derive("482917", &salt, params).unwrap();

    let ekm = [0x42u8; 32];
    let tls = ChannelBinding::from_tls_exporter(&ekm);
    let dtls = ChannelBinding::from_dtls_fingerprints(&[0x11; 32], &[0x22; 32]);

    serde_json::json!({
        "description": "Moon Remote session auth vectors; see crates/moonrd-session/src/pake.rs. RNG: SHA-256(seed || u64be counter) blocks; each side draws its SPAKE2 scalar as curve25519-dalek Scalar::random (64 RNG bytes reduced mod l). Group, M/N constants and transcript hash follow the RustCrypto spake2 0.4 crate (python-spake2 compatible).",
        "kdf": {
            "pin": pin, "salt": hex::encode(salt),
            "memoryKib": params.memory_kib, "iterations": params.iterations, "parallelism": params.parallelism,
            "w": hex::encode(w.as_bytes()),
        },
        "bindings": {
            "tlsExporter": { "ekm": hex::encode(ekm), "binding": hex::encode(tls.as_bytes()) },
            "dtlsFingerprints": { "viewer": hex::encode([0x11u8; 32]), "host": hex::encode([0x22u8; 32]), "binding": hex::encode(dtls.as_bytes()) },
        },
        "handshakes": [
            vector("pin-ok", AuthMethod::Pin, &w, &w, tls),
            vector("pin-wrong", AuthMethod::Pin, &wrong, &w, tls),
            vector("support-code-webrtc", AuthMethod::SupportCode, &w, &w, dtls),
            vector("pairing", AuthMethod::Pairing, &Secret::from_key([7; 32]), &Secret::from_key([7; 32]), tls),
        ],
    })
}

#[test]
fn vectors_are_stable() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/pake-vectors.json");
    let got = serde_json::to_string_pretty(&build()).unwrap() + "\n";
    if std::env::var_os("MOONRD_REGEN_VECTORS").is_some() {
        std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata")).unwrap();
        std::fs::write(path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path).expect("testdata/pake-vectors.json missing; run with MOONRD_REGEN_VECTORS=1");
    assert_eq!(got.replace("\r\n", "\n"), want.replace("\r\n", "\n"), "protocol output changed; regenerate only if intentional");
}

#[test]
fn vectors_have_expected_outcomes() {
    let v = build();
    for hs in v["handshakes"].as_array().unwrap() {
        let ok = hs["name"] != "pin-wrong";
        assert_eq!(hs["viewerAccepts"], ok, "{}", hs["name"]);
        assert_eq!(hs["hostAccepts"], ok, "{}", hs["name"]);
        assert_eq!(hs["sessionKeyViewer"] == hs["sessionKeyHost"], ok, "{}", hs["name"]);
    }
}
