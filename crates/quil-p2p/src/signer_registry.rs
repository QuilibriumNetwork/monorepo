//! In-memory signer registry populated from inbound KeyRegistry
//! broadcasts. Given an Ed448 identity key (peer identity), callers
//! can look up the associated BLS48-581 G2 prover public key — this
//! is required to verify BLS signatures on consensus messages from
//! peers whose identity↔prover binding was announced over the
//! `GLOBAL_PEER_INFO` bitmask.
//!
//! Mirrors the subset of `CachedSignerRegistry` in
//! `node/consensus/registration/cached_signer_registry.go` that the
//! runtime actually queries from consensus/materializer paths.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::peer_info::CanonicalKeyRegistry;

/// One entry per registered identity.
#[derive(Debug, Clone, Default)]
pub struct SignerEntry {
    pub ed448_pubkey: Vec<u8>,
    pub bls_pubkey: Vec<u8>,
    pub identity_to_prover_sig: Vec<u8>,
    pub prover_to_identity_sig: Vec<u8>,
    pub last_updated_ms: u64,
}

/// Thread-safe in-memory store. Backed by two maps: one keyed on the
/// 57-byte Ed448 pubkey, one keyed on the 585-byte BLS G2 pubkey.
/// `update` is last-write-wins scoped by `last_updated_ms`.
#[derive(Default)]
pub struct SignerRegistry {
    by_identity: RwLock<HashMap<Vec<u8>, SignerEntry>>,
    by_prover: RwLock<HashMap<Vec<u8>, SignerEntry>>,
}

impl SignerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a decoded KeyRegistry record. Older-timestamp updates
    /// for an already-known identity are ignored so malicious replays
    /// can't roll back a more recent binding.
    pub fn update(&self, reg: CanonicalKeyRegistry) {
        if reg.ed448_pubkey.is_empty() || reg.bls_pubkey.is_empty() {
            return;
        }
        let entry = SignerEntry {
            ed448_pubkey: reg.ed448_pubkey.clone(),
            bls_pubkey: reg.bls_pubkey.clone(),
            identity_to_prover_sig: reg.identity_to_prover_sig,
            prover_to_identity_sig: reg.prover_to_identity_sig,
            last_updated_ms: reg.last_updated_ms,
        };
        {
            let mut id_map = self.by_identity.write().unwrap();
            match id_map.get(&reg.ed448_pubkey) {
                Some(existing) if existing.last_updated_ms >= entry.last_updated_ms => {}
                _ => {
                    id_map.insert(reg.ed448_pubkey.clone(), entry.clone());
                }
            }
        }
        {
            let mut pk_map = self.by_prover.write().unwrap();
            match pk_map.get(&reg.bls_pubkey) {
                Some(existing) if existing.last_updated_ms >= entry.last_updated_ms => {}
                _ => {
                    pk_map.insert(reg.bls_pubkey.clone(), entry);
                }
            }
        }
    }

    /// Look up the BLS G2 pubkey associated with an Ed448 identity.
    pub fn bls_pubkey_for_identity(&self, ed448_pubkey: &[u8]) -> Option<Vec<u8>> {
        self.by_identity
            .read()
            .unwrap()
            .get(ed448_pubkey)
            .map(|e| e.bls_pubkey.clone())
    }

    /// Look up the Ed448 identity for a given BLS G2 prover pubkey.
    pub fn identity_for_prover(&self, bls_pubkey: &[u8]) -> Option<Vec<u8>> {
        self.by_prover
            .read()
            .unwrap()
            .get(bls_pubkey)
            .map(|e| e.ed448_pubkey.clone())
    }

    /// Full entry by identity.
    pub fn get_by_identity(&self, ed448_pubkey: &[u8]) -> Option<SignerEntry> {
        self.by_identity
            .read()
            .unwrap()
            .get(ed448_pubkey)
            .cloned()
    }

    /// Current entry count (identity-keyed).
    pub fn len(&self) -> usize {
        self.by_identity.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_and_lookup() {
        let reg = SignerRegistry::new();
        let entry = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0x22; 585],
            identity_to_prover_sig: vec![0x33; 114],
            prover_to_identity_sig: vec![0x44; 74],
            keys_by_purpose: Vec::new(),
            last_updated_ms: 1,
        };
        reg.update(entry);
        let pk = reg.bls_pubkey_for_identity(&[0x11; 57]).unwrap();
        assert_eq!(pk, vec![0x22; 585]);
        let id = reg.identity_for_prover(&[0x22; 585]).unwrap();
        assert_eq!(id, vec![0x11; 57]);
    }

    #[test]
    fn newer_timestamp_wins() {
        let reg = SignerRegistry::new();
        let old = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0xAA; 585],
            last_updated_ms: 10,
            ..Default::default()
        };
        let new = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0xBB; 585],
            last_updated_ms: 20,
            ..Default::default()
        };
        reg.update(old);
        reg.update(new);
        let pk = reg.bls_pubkey_for_identity(&[0x11; 57]).unwrap();
        assert_eq!(pk, vec![0xBB; 585], "newer ts should win");
    }

    #[test]
    fn older_timestamp_ignored() {
        let reg = SignerRegistry::new();
        let new = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0xBB; 585],
            last_updated_ms: 20,
            ..Default::default()
        };
        let old = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0xAA; 585],
            last_updated_ms: 10,
            ..Default::default()
        };
        reg.update(new);
        reg.update(old);
        let pk = reg.bls_pubkey_for_identity(&[0x11; 57]).unwrap();
        assert_eq!(pk, vec![0xBB; 585], "older ts replay should be ignored");
    }
}
