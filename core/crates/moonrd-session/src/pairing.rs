//! "Remember this controller": after a successful PIN login the host may grant the
//! viewer a pairing key, which later replaces the PIN as the SPAKE2 secret
//! (`AUTH_METHOD_PAIRING`). The key is sent only inside the authenticated channel.
//! The host user can revoke pairings; removing a device from the account (and, in LAN
//! mode, its absence from the signed roster) also stops it from connecting.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::pin::Secret;

/// Most pairings a host keeps; the oldest is dropped beyond this.
pub const MAX_PAIRINGS: usize = 32;

/// One remembered controller.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pairing {
    pub id: [u8; 16],
    pub key: [u8; 32],
    /// Account device id of the controller.
    pub viewer_device_id: String,
    /// Label shown to the host user, e.g. "Alice's laptop".
    pub label: String,
    pub created: u64,
    pub last_used: u64,
}

impl Drop for Pairing {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairing")
            .field("viewer_device_id", &self.viewer_device_id)
            .field("label", &self.label)
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

/// The host's pairing list (persisted by the host service under DPAPI).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pairings {
    items: Vec<Pairing>,
}

impl Pairings {
    /// Creates a pairing for a viewer device, replacing any earlier one for that device.
    pub fn grant(&mut self, viewer_device_id: &str, label: &str, now: u64) -> Pairing {
        self.items.retain(|p| p.viewer_device_id != viewer_device_id);
        if self.items.len() >= MAX_PAIRINGS {
            let oldest = self.items.iter().enumerate().min_by_key(|(_, p)| p.last_used).map(|(i, _)| i);
            if let Some(i) = oldest {
                self.items.remove(i);
            }
        }
        let mut id = [0u8; 16];
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        OsRng.fill_bytes(&mut key);
        let label: String = label.chars().filter(|&c| !is_hidden_char(c)).take(64).collect();
        let p = Pairing { id, key, viewer_device_id: viewer_device_id.to_string(), label, created: now, last_used: now };
        self.items.push(p.clone());
        p
    }

    /// The SPAKE2 secret for a pairing presented by `viewer_device_id`. A pairing id
    /// presented by a different device is ignored, so a copied id alone is useless.
    pub fn secret_for(&self, id: &[u8], viewer_device_id: &str) -> Option<Secret> {
        self.items
            .iter()
            .find(|p| p.id.as_slice() == id && p.viewer_device_id == viewer_device_id)
            .map(|p| Secret::from_key(p.key))
    }

    /// Records a successful use.
    pub fn touch(&mut self, id: &[u8], now: u64) {
        if let Some(p) = self.items.iter_mut().find(|p| p.id.as_slice() == id) {
            p.last_used = now;
        }
    }

    /// Removes one pairing; returns whether it existed.
    pub fn revoke(&mut self, id: &[u8]) -> bool {
        let before = self.items.len();
        self.items.retain(|p| p.id.as_slice() != id);
        before != self.items.len()
    }

    /// Removes pairings of devices no longer in the account (from the device list or roster).
    pub fn retain_devices(&mut self, known_device_ids: &[&str]) {
        self.items.retain(|p| known_device_ids.contains(&p.viewer_device_id.as_str()));
    }

    pub fn list(&self) -> &[Pairing] {
        &self.items
    }
}

/// Control characters and bidi/zero-width formatting characters, which could make a
/// label shown in the host's consent and pairing lists display misleadingly.
fn is_hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_and_lookup_bound_to_device() {
        let mut ps = Pairings::default();
        let p = ps.grant("dev-a", "Laptop", 10);
        assert_eq!(ps.secret_for(&p.id, "dev-a"), Some(Secret::from_key(p.key)));
        assert_eq!(ps.secret_for(&p.id, "dev-b"), None, "id replayed from another device");
        assert_eq!(ps.secret_for(&[0; 16], "dev-a"), None);
    }

    #[test]
    fn regrant_replaces_and_revoke_removes() {
        let mut ps = Pairings::default();
        let first = ps.grant("dev-a", "Laptop", 10);
        let second = ps.grant("dev-a", "Laptop", 20);
        assert_eq!(ps.list().len(), 1);
        assert!(ps.secret_for(&first.id, "dev-a").is_none());
        assert!(ps.revoke(&second.id));
        assert!(!ps.revoke(&second.id));
        assert!(ps.list().is_empty());
    }

    #[test]
    fn evicts_least_recently_used() {
        let mut ps = Pairings::default();
        let mut ids = Vec::new();
        for i in 0..MAX_PAIRINGS {
            ids.push(ps.grant(&format!("dev-{i}"), "x", i as u64).id);
        }
        ps.touch(&ids[0], 1_000); // dev-0 used recently; dev-1 is now the oldest
        ps.grant("dev-new", "x", 2_000);
        assert_eq!(ps.list().len(), MAX_PAIRINGS);
        assert!(ps.secret_for(&ids[0], "dev-0").is_some());
        assert!(ps.secret_for(&ids[1], "dev-1").is_none());
    }

    #[test]
    fn retain_devices_drops_removed_ones() {
        let mut ps = Pairings::default();
        ps.grant("dev-a", "a", 0);
        ps.grant("dev-b", "b", 0);
        ps.retain_devices(&["dev-b"]);
        assert_eq!(ps.list().len(), 1);
        assert_eq!(ps.list()[0].viewer_device_id, "dev-b");
    }

    #[test]
    fn label_is_sanitised_and_debug_hides_key() {
        let mut ps = Pairings::default();
        let p = ps.grant("dev-a", "evil\u{202e}\nna\u{200b}me", 0);
        assert_eq!(p.label, "evilname");
        assert!(!format!("{p:?}").contains("key"));
    }
}
