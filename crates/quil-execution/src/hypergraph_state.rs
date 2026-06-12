//! HypergraphState — changeset accumulator bridging the execution
//! engine and the hypergraph CRDT. Port of
//! `node/execution/state/hypergraph/hypergraph_state.go`.
//!
//! The state object accumulates `StateChange` entries during message
//! processing, then commits them atomically to the CRDT when the
//! frame is finalized.

use std::sync::{Arc, Mutex};

use quil_crypto::poseidon::hash_bytes_to_32;
use quil_tries::get_full_path;
use quil_types::error::{QuilError, Result};
use quil_types::execution::{StateChange, StateChangeEvent};

use quil_hypergraph::HypergraphCrdt;
use quil_hypergraph::addressing::Location;

// =====================================================================
// Discriminator constants
// =====================================================================

/// `poseidon("vertex:adds")` — 32 bytes.
pub fn vertex_adds_discriminator() -> Result<[u8; 32]> {
    hash_bytes_to_32(b"vertex:adds")
}

/// `poseidon("vertex:removes")` — 32 bytes.
pub fn vertex_removes_discriminator() -> Result<[u8; 32]> {
    hash_bytes_to_32(b"vertex:removes")
}

/// `poseidon("hyperedge:adds")` — 32 bytes.
pub fn hyperedge_adds_discriminator() -> Result<[u8; 32]> {
    hash_bytes_to_32(b"hyperedge:adds")
}

/// `poseidon("hyperedge:removes")` — 32 bytes.
pub fn hyperedge_removes_discriminator() -> Result<[u8; 32]> {
    hash_bytes_to_32(b"hyperedge:removes")
}

/// The special metadata address within each hypergraph domain.
/// `bytes.Repeat([]byte{0xff}, 32)` in Go.
pub const HYPERGRAPH_METADATA_ADDRESS: [u8; 32] = [0xFF; 32];

/// Vertex data deletion interval (ms). ~600 frames after deletion.
pub const VERTEX_DATA_DELETION_INTERVAL_MS: i64 = 10 * 60 * 1000;

// =====================================================================
// HypergraphState
// =====================================================================

/// One entry in the undo log built during `commit()`. Each successfully-
/// Changeset accumulator. The execution engine creates one per frame,
/// appends state changes during `process_message`, and commits them
/// via `commit()` at the end of the frame.
///
/// (Earlier revisions kept an `undo_log` + `revert_changes` API
/// mirroring Go's `TrackChange`/`RevertChanges`. Nothing in the
/// workspace ever wired the revert path, and the per-node lazy tree
/// doesn't implement `delete` — so the undo machinery has been
/// dropped along with its sole consumer.)
pub struct HypergraphState {
    crdt: Arc<HypergraphCrdt>,
    changeset: Mutex<Vec<StateChange>>,
}

impl HypergraphState {
    pub fn new(crdt: Arc<HypergraphCrdt>) -> Self {
        Self {
            crdt,
            changeset: Mutex::new(Vec::new()),
        }
    }

    /// Borrow the underlying CRDT. Needed by executors that have to run
    /// their own reads against the committed state — e.g. the legacy
    /// pre-2.1 pending-transaction verifier loads the coin's underlying
    /// VerEnc-encoded vertex data.
    pub fn crdt(&self) -> &Arc<HypergraphCrdt> {
        &self.crdt
    }

    /// Get a value from the CRDT. Checks the pending changeset first
    /// (reverse order for most recent), then falls back to the CRDT.
    ///
    /// Returns the data payload for the matching change, or looks up
    /// the vertex/hyperedge data from the CRDT directly.
    pub fn get(
        &self,
        domain: &[u8],
        address: &[u8],
        discriminator: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // Check changeset (most recent first)
        let changeset = self.changeset.lock().unwrap();
        for change in changeset.iter().rev() {
            if change.domain == domain
                && change.address == address
                && change.discriminator == discriminator
            {
                return Ok(Some(change.value.clone()));
            }
        }
        drop(changeset);

        // Fall back to CRDT lookup — returns actual vertex/hyperedge data bytes.
        let va_disc = vertex_adds_discriminator()?;
        let ha_disc = hyperedge_adds_discriminator()?;

        if discriminator == va_disc.as_slice() {
            let loc = location_from_domain_address(domain, address)?;
            return Ok(self.crdt.get_vertex_data(&loc));
        }

        if discriminator == ha_disc.as_slice() {
            let loc = location_from_domain_address(domain, address)?;
            return Ok(self.crdt.get_hyperedge_data(&loc));
        }

        Err(QuilError::InvalidArgument(
            "HypergraphState::get: invalid discriminator".into(),
        ))
    }

    /// Set (create or update) a state entry. Appends to the changeset.
    pub fn set(
        &self,
        domain: &[u8],
        address: &[u8],
        discriminator: &[u8],
        _frame_number: u64,
        value: Vec<u8>,
    ) -> Result<()> {
        let loc = location_from_domain_address(domain, address)?;
        let va_disc = vertex_adds_discriminator()?;
        let ha_disc = hyperedge_adds_discriminator()?;

        let event = if discriminator == va_disc.as_slice() {
            if self.crdt.lookup_vertex(&loc) {
                StateChangeEvent::Update
            } else {
                StateChangeEvent::Create
            }
        } else if discriminator == ha_disc.as_slice() {
            if self.crdt.lookup_hyperedge(&loc) {
                StateChangeEvent::Update
            } else {
                StateChangeEvent::Create
            }
        } else {
            return Err(QuilError::InvalidArgument(
                "HypergraphState::set: invalid discriminator".into(),
            ));
        };

        self.changeset.lock().unwrap().push(StateChange {
            domain: domain.to_vec(),
            address: address.to_vec(),
            discriminator: discriminator.to_vec(),
            state_change: event,
            value,
        });

        Ok(())
    }

    /// Delete a state entry. Appends a delete event to the changeset.
    pub fn delete(
        &self,
        domain: &[u8],
        address: &[u8],
        discriminator: &[u8],
        _frame_number: u64,
    ) -> Result<()> {
        self.changeset.lock().unwrap().push(StateChange {
            domain: domain.to_vec(),
            address: address.to_vec(),
            discriminator: discriminator.to_vec(),
            state_change: StateChangeEvent::Delete,
            value: Vec::new(),
        });
        Ok(())
    }

    /// Commit the accumulated changeset to the CRDT. Walks each change
    /// and applies it:
    /// - Create/Update on vertex_adds → `crdt.add_vertex`
    /// - Delete on vertex_removes → `crdt.remove_vertex`
    /// - Create/Update on hyperedge_adds → `crdt.add_hyperedge`
    /// - Delete on hyperedge_removes → `crdt.remove_hyperedge`
    ///
    /// Each change is gated by the CRDT's `covered_prefix`: vertices
    /// or hyperedges whose 64-byte id (`app || data`) doesn't begin
    /// with the configured nibble prefix are silently skipped. This
    /// mirrors the Go `coveredPrefix` short-circuit at
    /// `node/execution/state/hypergraph/hypergraph_state.go:78-80`,
    /// `:173-175`, `:250-252`, `:319-322` — without it, a node would
    /// accept vertices for shards it shouldn't store and produce
    /// roots that diverge from any peer that correctly drops them.
    ///
    pub fn commit(&self) -> Result<()> {
        let va_disc = vertex_adds_discriminator()?;
        let vr_disc = vertex_removes_discriminator()?;
        let ha_disc = hyperedge_adds_discriminator()?;
        let hr_disc = hyperedge_removes_discriminator()?;

        let prefix = self.crdt.get_covered_prefix();

        let changeset = self.changeset.lock().unwrap().clone();
        for change in &changeset {
            let loc = location_from_domain_address(&change.domain, &change.address)?;

            // covered_prefix gate — drop changes whose nibble path
            // doesn't begin with our prefix. Empty prefix accepts all.
            if !prefix.is_empty() {
                let id = loc.to_id();
                let path = get_full_path(&id);
                if path.len() < prefix.len() || path[..prefix.len()] != prefix[..] {
                    continue;
                }
            }

            if change.discriminator == va_disc.as_slice() {
                match change.state_change {
                    StateChangeEvent::Create | StateChangeEvent::Update | StateChangeEvent::Initialize => {
                        self.crdt.add_vertex(&loc, &change.value)?;
                    }
                    StateChangeEvent::Delete => {}
                }
            } else if change.discriminator == vr_disc.as_slice() {
                self.crdt.remove_vertex(&loc)?;
            } else if change.discriminator == ha_disc.as_slice() {
                match change.state_change {
                    StateChangeEvent::Create | StateChangeEvent::Update | StateChangeEvent::Initialize => {
                        self.crdt.add_hyperedge(&loc, &change.value)?;
                    }
                    StateChangeEvent::Delete => {}
                }
            } else if change.discriminator == hr_disc.as_slice() {
                self.crdt.remove_hyperedge(&loc)?;
            }
        }

        Ok(())
    }

    /// Abort — discard all pending changes.
    pub fn abort(&self) {
        self.changeset.lock().unwrap().clear();
    }

    /// Number of pending changes.
    pub fn changeset_len(&self) -> usize {
        self.changeset.lock().unwrap().len()
    }
}

fn location_from_domain_address(domain: &[u8], address: &[u8]) -> Result<Location> {
    if domain.len() < 32 || address.len() < 32 {
        return Err(QuilError::InvalidArgument(
            "HypergraphState: domain and address must be at least 32 bytes".into(),
        ));
    }
    let mut app = [0u8; 32];
    let mut data = [0u8; 32];
    app.copy_from_slice(&domain[..32]);
    data.copy_from_slice(&address[..32]);
    Ok(Location {
        app_address: app,
        data_address: data,
    })
}

// =====================================================================
// In-memory HypergraphStore for use when RocksDB trait impl isn't ready
// =====================================================================

/// Minimal in-memory HypergraphStore. All writes are no-ops and all
/// reads return empty. Used as a placeholder until `RocksHypergraphStore`
/// implements the `HypergraphStore` trait.
pub struct InMemoryHypergraphStore {
    nodes: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    per_vertex: std::sync::Mutex<std::collections::HashMap<(String, Vec<u8>), Vec<u8>>>,
}

impl InMemoryHypergraphStore {
    pub fn new() -> Self {
        Self {
            nodes: std::sync::Mutex::new(std::collections::HashMap::new()),
            per_vertex: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
    fn key(s: &str, p: &str, sk: &quil_types::store::ShardKey, k: &[u8]) -> String {
        format!("{}/{}/{:?}/{:?}", s, p, sk.l1, k)
    }
    fn scope(s: &str, p: &str, sk: &quil_types::store::ShardKey) -> String {
        format!("{}/{}/{:?}", s, p, sk.l1)
    }
}

struct NoopTxn;
impl quil_types::store::Transaction for NoopTxn {
    fn get(&self, _: &[u8]) -> Result<Option<Vec<u8>>> { Ok(None) }
    fn set(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
    fn delete(&self, _: &[u8]) -> Result<()> { Ok(()) }
    fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
    fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn quil_types::store::Iterator>> { Err(QuilError::Internal("iterator not supported on in-memory state".into())) }
    fn delete_range(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

impl quil_types::store::HypergraphStore for InMemoryHypergraphStore {
    fn new_transaction(&self, _: bool) -> Result<Box<dyn quil_types::store::Transaction>> { Ok(Box::new(NoopTxn)) }
    fn get_node_by_key(&self, s: &str, p: &str, sk: &quil_types::store::ShardKey, k: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.nodes.lock().unwrap().get(&Self::key(s, p, sk, k)).cloned())
    }
    fn get_node_by_path(&self, _: &str, _: &str, _: &quil_types::store::ShardKey, _: &[i32]) -> Result<Option<Vec<u8>>> { Ok(None) }
    fn insert_node(&self, _: &dyn quil_types::store::Transaction, s: &str, p: &str, sk: &quil_types::store::ShardKey, k: &[u8], _: &[i32], d: &[u8]) -> Result<()> {
        self.nodes.lock().unwrap().insert(Self::key(s, p, sk, k), d.to_vec());
        if k != [0xFFu8; 32] {
            self.per_vertex.lock().unwrap().insert((Self::scope(s, p, sk), k.to_vec()), d.to_vec());
        }
        Ok(())
    }
    fn save_root(&self, _: &dyn quil_types::store::Transaction, _: &str, _: &str, _: &quil_types::store::ShardKey, _: &[u8]) -> Result<()> { Ok(()) }
    fn delete_node(&self, _: &dyn quil_types::store::Transaction, _: &str, _: &str, _: &quil_types::store::ShardKey, _: &[u8], _: &[i32]) -> Result<()> { Ok(()) }
    fn set_covered_prefix(&self, _: &[i32]) -> Result<()> { Ok(()) }
    fn set_shard_commit(&self, _: &dyn quil_types::store::Transaction, _: u64, _: &str, _: &str, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn get_shard_commit(&self, _: u64, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>> { Ok(vec![]) }
    fn get_root_commits(&self, _: u64) -> Result<std::collections::HashMap<quil_types::store::ShardKey, Vec<Vec<u8>>>> { Ok(std::collections::HashMap::new()) }
    fn load_vertex_underlying_raw(&self, s: &str, p: &str, sk: &quil_types::store::ShardKey, k: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.nodes.lock().unwrap().get(&Self::key(s, p, sk, k)).cloned())
    }
    fn save_vertex_underlying(&self, s: &str, p: &str, sk: &quil_types::store::ShardKey, k: &[u8], d: &[u8]) -> Result<()> {
        self.nodes.lock().unwrap().insert(Self::key(s, p, sk, k), d.to_vec());
        self.per_vertex.lock().unwrap().insert((Self::scope(s, p, sk), k.to_vec()), d.to_vec());
        Ok(())
    }
    fn for_each_vertex_underlying(&self, s: &str, p: &str, sk: &quil_types::store::ShardKey, callback: &mut dyn FnMut(Vec<u8>, Vec<u8>)) -> Result<usize> {
        let scope = Self::scope(s, p, sk);
        let mut count = 0usize;
        for ((sc, vk), v) in self.per_vertex.lock().unwrap().iter() {
            if sc == &scope {
                callback(vk.clone(), v.clone());
                count += 1;
            }
        }
        Ok(count)
    }
    fn apply_snapshot(&self, _: &str) -> Result<()> { Ok(()) }
    fn set_alt_shard_commit(&self, _: &dyn quil_types::store::Transaction, _: u64, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn get_latest_alt_shard_commit(&self, _: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> { Ok((vec![], vec![], vec![], vec![])) }
    fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> { Ok(vec![]) }
    fn reap_old_changesets(&self, _: &dyn quil_types::store::Transaction, _: u64) -> Result<()> { Ok(()) }
    fn track_change(&self, _: &dyn quil_types::store::Transaction, _: &[u8], _: Option<&[u8]>, _: u64, _: &str, _: &str, _: &quil_types::store::ShardKey) -> Result<()> { Ok(()) }
    fn get_changes(&self, _: u64, _: u64, _: &str, _: &str, _: &quil_types::store::ShardKey) -> Result<Vec<quil_types::store::ChangeRecord>> { Ok(vec![]) }
    fn untrack_change(&self, _: &dyn quil_types::store::Transaction, _: &[u8], _: u64, _: &str, _: &str, _: &quil_types::store::ShardKey) -> Result<()> { Ok(()) }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::NoopInclusionProver;
    use quil_hypergraph::testing::MemStore;

    fn stub_state() -> HypergraphState {
        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        HypergraphState::new(crdt)
    }

    fn domain() -> Vec<u8> { vec![0xAAu8; 32] }
    fn addr() -> Vec<u8> { vec![0xBBu8; 32] }

    // -----------------------------------------------------------------
    // Discriminators
    // -----------------------------------------------------------------

    #[test]
    fn discriminators_are_32_bytes_and_distinct() {
        let va = vertex_adds_discriminator().unwrap();
        let vr = vertex_removes_discriminator().unwrap();
        let ha = hyperedge_adds_discriminator().unwrap();
        let hr = hyperedge_removes_discriminator().unwrap();
        assert_eq!(va.len(), 32);
        assert_ne!(va, vr);
        assert_ne!(va, ha);
        assert_ne!(ha, hr);
    }

    #[test]
    fn discriminators_are_deterministic() {
        assert_eq!(
            vertex_adds_discriminator().unwrap(),
            vertex_adds_discriminator().unwrap()
        );
    }

    // -----------------------------------------------------------------
    // State operations
    // -----------------------------------------------------------------

    #[test]
    fn set_and_get_from_changeset() {
        let s = stub_state();
        let disc = vertex_adds_discriminator().unwrap();
        s.set(&domain(), &addr(), &disc, 1, b"data".to_vec()).unwrap();
        let val = s.get(&domain(), &addr(), &disc).unwrap();
        assert_eq!(val, Some(b"data".to_vec()));
    }

    #[test]
    fn get_returns_most_recent_change() {
        let s = stub_state();
        let disc = vertex_adds_discriminator().unwrap();
        s.set(&domain(), &addr(), &disc, 1, b"old".to_vec()).unwrap();
        s.set(&domain(), &addr(), &disc, 2, b"new".to_vec()).unwrap();
        assert_eq!(s.get(&domain(), &addr(), &disc).unwrap(), Some(b"new".to_vec()));
    }

    #[test]
    fn get_missing_returns_none() {
        let s = stub_state();
        let disc = vertex_adds_discriminator().unwrap();
        assert_eq!(s.get(&domain(), &addr(), &disc).unwrap(), None);
    }

    #[test]
    fn delete_appends_to_changeset() {
        let s = stub_state();
        let disc = vertex_removes_discriminator().unwrap();
        s.delete(&domain(), &addr(), &disc, 1).unwrap();
        assert_eq!(s.changeset_len(), 1);
    }

    #[test]
    fn abort_clears_changeset() {
        let s = stub_state();
        let disc = vertex_adds_discriminator().unwrap();
        s.set(&domain(), &addr(), &disc, 1, b"data".to_vec()).unwrap();
        assert_eq!(s.changeset_len(), 1);
        s.abort();
        assert_eq!(s.changeset_len(), 0);
    }

    #[test]
    fn commit_applies_vertex_add_to_crdt() {
        let s = stub_state();
        let disc = vertex_adds_discriminator().unwrap();
        s.set(&domain(), &addr(), &disc, 1, b"vertex-data".to_vec()).unwrap();
        s.commit().unwrap();
        let loc = Location { app_address: [0xAAu8; 32], data_address: [0xBBu8; 32] };
        assert!(s.crdt.lookup_vertex(&loc));
    }

    #[test]
    fn commit_applies_vertex_remove_to_crdt() {
        let s = stub_state();
        let va_disc = vertex_adds_discriminator().unwrap();
        let vr_disc = vertex_removes_discriminator().unwrap();
        // First add
        s.set(&domain(), &addr(), &va_disc, 1, b"data".to_vec()).unwrap();
        s.commit().unwrap();
        let loc = Location { app_address: [0xAAu8; 32], data_address: [0xBBu8; 32] };
        assert!(s.crdt.lookup_vertex(&loc));
        // Then remove
        s.delete(&domain(), &addr(), &vr_disc, 2).unwrap();
        s.commit().unwrap();
        assert!(!s.crdt.lookup_vertex(&loc));
    }

    #[test]
    fn commit_applies_hyperedge_add() {
        let s = stub_state();
        let disc = hyperedge_adds_discriminator().unwrap();
        s.set(&domain(), &addr(), &disc, 1, b"edge".to_vec()).unwrap();
        s.commit().unwrap();
        let loc = Location { app_address: [0xAAu8; 32], data_address: [0xBBu8; 32] };
        assert!(s.crdt.lookup_hyperedge(&loc));
    }

    #[test]
    fn metadata_address_is_all_ff() {
        assert_eq!(HYPERGRAPH_METADATA_ADDRESS, [0xFFu8; 32]);
    }

    // -----------------------------------------------------------------
    // covered_prefix gate
    // -----------------------------------------------------------------

    #[test]
    fn covered_prefix_drops_out_of_prefix_vertices_silently() {
        let s = stub_state();

        // Set a non-empty covered_prefix that won't match our test address.
        // address = 0xAA*32 || 0xBB*32. The full nibble path begins with the
        // first 6 bits of 0xAA = 10101010 => first nibble = 101010 = 42.
        // Use a prefix whose first nibble is 0 — the path won't match.
        s.crdt.set_covered_prefix(&[0, 0, 0, 0]).unwrap();

        let disc = vertex_adds_discriminator().unwrap();
        s.set(&domain(), &addr(), &disc, 1, b"data".to_vec()).unwrap();
        // commit must NOT error and must NOT add the vertex (out of prefix).
        s.commit().unwrap();

        let loc = Location { app_address: [0xAAu8; 32], data_address: [0xBBu8; 32] };
        assert!(!s.crdt.lookup_vertex(&loc), "out-of-prefix vertex was wrongly added");

        // Now switch to a matching prefix. First nibble of 0xAA is 42 (0b101010).
        s.crdt.set_covered_prefix(&[42]).unwrap();
        // Re-issue the change (commit consumed the changeset's intent but
        // doesn't drain it — set up a fresh state object to keep the test
        // explicit).
        let s2 = stub_state();
        s2.crdt.set_covered_prefix(&[42]).unwrap();
        s2.set(&domain(), &addr(), &disc, 1, b"data".to_vec()).unwrap();
        s2.commit().unwrap();
        assert!(s2.crdt.lookup_vertex(&loc), "in-prefix vertex should be added");
    }
}
