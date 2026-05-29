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

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

use crate::peer_info::CanonicalKeyRegistry;

/// Hard cap on the number of distinct identities the registry will
/// retain. Each entry is ~850 bytes (57-byte Ed448 + 585-byte BLS +
/// two signatures + metadata), so 65536 × 850 ≈ 56 MB worst case.
/// On real networks the live signer set is far smaller; this bound
/// only kicks in under sustained Sybil / replay pressure where a
/// malicious peer broadcasts KeyRegistry messages with fabricated
/// identities. Without it, `update` is strictly append-on-newer and
/// the maps grow linearly forever.
pub const MAX_SIGNER_ENTRIES: usize = 65_536;

/// One entry per registered identity.
#[derive(Debug, Clone, Default)]
pub struct SignerEntry {
    pub ed448_pubkey: Vec<u8>,
    pub bls_pubkey: Vec<u8>,
    pub identity_to_prover_sig: Vec<u8>,
    pub prover_to_identity_sig: Vec<u8>,
    pub last_updated_ms: u64,
}

/// Joint state behind a single `RwLock`. Held together so eviction
/// stays atomic across the two indexes; otherwise an evicted entry
/// could linger in one map after disappearing from the other.
#[derive(Default)]
struct Inner {
    by_identity: HashMap<Vec<u8>, SignerEntry>,
    /// Reverse index BLS pubkey → Ed448 identity. We store only the
    /// identity key (not the full entry) to halve the per-entry
    /// footprint; full entries are reachable via `by_identity`.
    by_prover: HashMap<Vec<u8>, Vec<u8>>,
    /// Insertion / update order of Ed448 identities. Used to evict
    /// the oldest-touched entry when `by_identity.len()` exceeds
    /// `MAX_SIGNER_ENTRIES`.
    order: VecDeque<Vec<u8>>,
}

/// Thread-safe in-memory store. Indexes by 57-byte Ed448 pubkey and
/// 585-byte BLS G2 pubkey. `update` is last-write-wins scoped by
/// `last_updated_ms` and capped at [`MAX_SIGNER_ENTRIES`] total
/// entries (FIFO eviction by most recent write).
#[derive(Default)]
pub struct SignerRegistry {
    inner: RwLock<Inner>,
}

impl SignerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a decoded KeyRegistry record. Older-timestamp updates
    /// for an already-known identity are ignored so malicious replays
    /// can't roll back a more recent binding. When the registry is at
    /// capacity, the least-recently-updated identity is evicted to
    /// make room.
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
        let mut inner = self.inner.write().unwrap();
        // Capture only the bits we need from the existing entry so
        // the immutable borrow ends before we mutate other fields.
        enum Slot {
            Skip,
            Replace { stale_bls: Option<Vec<u8>> },
            Insert,
        }
        let slot = match inner.by_identity.get(&reg.ed448_pubkey) {
            Some(existing) if existing.last_updated_ms >= entry.last_updated_ms => Slot::Skip,
            Some(existing) => {
                let stale_bls = if existing.bls_pubkey != entry.bls_pubkey {
                    Some(existing.bls_pubkey.clone())
                } else {
                    None
                };
                Slot::Replace { stale_bls }
            }
            None => Slot::Insert,
        };
        match slot {
            Slot::Skip => return,
            Slot::Replace { stale_bls } => {
                if let Some(b) = stale_bls {
                    inner.by_prover.remove(&b);
                }
                inner.order.retain(|id| id != &reg.ed448_pubkey);
                inner.order.push_back(reg.ed448_pubkey.clone());
            }
            Slot::Insert => {
                if inner.order.len() >= MAX_SIGNER_ENTRIES {
                    if let Some(victim_id) = inner.order.pop_front() {
                        if let Some(victim) = inner.by_identity.remove(&victim_id) {
                            inner.by_prover.remove(&victim.bls_pubkey);
                        }
                    }
                }
                inner.order.push_back(reg.ed448_pubkey.clone());
            }
        }
        let id_key = reg.ed448_pubkey.clone();
        inner.by_prover.insert(reg.bls_pubkey, id_key.clone());
        inner.by_identity.insert(id_key, entry);
    }

    /// Look up the BLS G2 pubkey associated with an Ed448 identity.
    pub fn bls_pubkey_for_identity(&self, ed448_pubkey: &[u8]) -> Option<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        inner.by_identity.get(ed448_pubkey).map(|e| e.bls_pubkey.clone())
    }

    /// Look up the Ed448 identity for a given BLS G2 prover pubkey.
    pub fn identity_for_prover(&self, bls_pubkey: &[u8]) -> Option<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        inner.by_prover.get(bls_pubkey).cloned()
    }

    /// Full entry by identity.
    pub fn get_by_identity(&self, ed448_pubkey: &[u8]) -> Option<SignerEntry> {
        let inner = self.inner.read().unwrap();
        inner.by_identity.get(ed448_pubkey).cloned()
    }

    /// Current entry count (identity-keyed).
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().by_identity.len()
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

    /// Build a unique 57-byte Ed448 pubkey for test purposes.
    fn ed448_key(i: u32) -> Vec<u8> {
        let mut v = vec![0u8; 57];
        v[..4].copy_from_slice(&i.to_be_bytes());
        v
    }

    /// Build a unique 585-byte BLS pubkey for test purposes.
    fn bls_key(i: u32) -> Vec<u8> {
        let mut v = vec![0u8; 585];
        v[..4].copy_from_slice(&i.to_be_bytes());
        v
    }

    #[test]
    fn lru_evicts_oldest_when_at_capacity() {
        // Sanity-cap the test by using a smaller MAX via direct
        // exercise: we push MAX + 5 distinct identities and assert
        // the first 5 are evicted.
        let reg = SignerRegistry::new();
        let total = MAX_SIGNER_ENTRIES + 5;
        for i in 0..total {
            reg.update(CanonicalKeyRegistry {
                ed448_pubkey: ed448_key(i as u32),
                bls_pubkey: bls_key(i as u32),
                last_updated_ms: 100 + i as u64,
                ..Default::default()
            });
        }
        assert_eq!(reg.len(), MAX_SIGNER_ENTRIES);
        // First 5 identities should be evicted from BOTH indexes.
        for i in 0..5 {
            assert!(
                reg.bls_pubkey_for_identity(&ed448_key(i)).is_none(),
                "expected identity {} evicted from by_identity", i,
            );
            assert!(
                reg.identity_for_prover(&bls_key(i)).is_none(),
                "expected bls key {} evicted from by_prover", i,
            );
        }
        // Tail entries retained.
        for i in 5..total {
            assert!(
                reg.bls_pubkey_for_identity(&ed448_key(i as u32)).is_some(),
                "expected identity {} retained", i,
            );
        }
    }

    #[test]
    fn update_refreshes_order_so_recent_entries_survive() {
        // Insert MAX entries, then update entry 0 (oldest by insertion).
        // It should move to the back of the eviction queue. Then push
        // one more new entry; entry 1 (now the oldest) should evict,
        // entry 0 should survive.
        let reg = SignerRegistry::new();
        for i in 0..MAX_SIGNER_ENTRIES {
            reg.update(CanonicalKeyRegistry {
                ed448_pubkey: ed448_key(i as u32),
                bls_pubkey: bls_key(i as u32),
                last_updated_ms: 100 + i as u64,
                ..Default::default()
            });
        }
        // Refresh entry 0 with a newer timestamp.
        reg.update(CanonicalKeyRegistry {
            ed448_pubkey: ed448_key(0),
            bls_pubkey: bls_key(0),
            last_updated_ms: 100 + MAX_SIGNER_ENTRIES as u64 + 1,
            ..Default::default()
        });
        // Add one more new entry to trigger eviction.
        let new_idx = MAX_SIGNER_ENTRIES as u32;
        reg.update(CanonicalKeyRegistry {
            ed448_pubkey: ed448_key(new_idx),
            bls_pubkey: bls_key(new_idx),
            last_updated_ms: 100 + MAX_SIGNER_ENTRIES as u64 + 2,
            ..Default::default()
        });
        assert!(
            reg.bls_pubkey_for_identity(&ed448_key(0)).is_some(),
            "refreshed entry 0 should survive eviction",
        );
        assert!(
            reg.bls_pubkey_for_identity(&ed448_key(1)).is_none(),
            "entry 1 (oldest after refresh) should be evicted",
        );
    }

    #[test]
    fn bls_pubkey_change_drops_stale_reverse_index() {
        // An identity rotating its BLS pubkey should NOT leave the
        // old BLS pubkey pointing at it in `by_prover` — otherwise
        // `identity_for_prover(old_bls)` would return a stale answer.
        let reg = SignerRegistry::new();
        reg.update(CanonicalKeyRegistry {
            ed448_pubkey: ed448_key(0),
            bls_pubkey: bls_key(0),
            last_updated_ms: 100,
            ..Default::default()
        });
        reg.update(CanonicalKeyRegistry {
            ed448_pubkey: ed448_key(0),
            bls_pubkey: bls_key(1),
            last_updated_ms: 200,
            ..Default::default()
        });
        assert_eq!(
            reg.identity_for_prover(&bls_key(1)),
            Some(ed448_key(0)),
            "new bls key should resolve to the identity",
        );
        assert_eq!(
            reg.identity_for_prover(&bls_key(0)),
            None,
            "old bls key should no longer resolve",
        );
    }
}
