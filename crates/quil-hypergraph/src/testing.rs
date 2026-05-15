//! Shared test utilities for crates that depend on `quil-hypergraph`.
//!
//! Gated behind the `test-utils` feature. Downstream crates enable it via:
//!
//! ```toml
//! [dev-dependencies]
//! quil-hypergraph = { path = "../quil-hypergraph", features = ["test-utils"] }
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use quil_types::crypto::{InclusionProver, Multiproof};
use quil_types::error::{QuilError, Result};
use quil_types::store::{
    ChangeRecord, HypergraphStore, Iterator as KvIterator, ShardKey, Transaction,
};

/// A no-op transaction that accepts all writes and returns nothing.
pub struct NoopTxn;

impl Transaction for NoopTxn {
    fn get(&self, _: &[u8]) -> Result<Option<Vec<u8>>> { Ok(None) }
    fn set(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
    fn delete(&self, _: &[u8]) -> Result<()> { Ok(()) }
    fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
    fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn KvIterator>> {
        Err(QuilError::Internal("iterator not supported on in-memory state".into()))
    }
    fn delete_range(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

/// Minimal in-memory `HypergraphStore` for tests. Stores node and root
/// data in hash maps; all other operations are no-ops.
pub struct MemStore {
    nodes: Mutex<HashMap<String, Vec<u8>>>,
    roots: Mutex<HashMap<String, Vec<u8>>>,
    /// Per-vertex underlying-data keyed by `(scope_prefix, vk)` so
    /// `for_each_vertex_underlying` can hand back the exact original
    /// `vk` bytes without round-tripping them through the debug-format
    /// string keys used by `nodes`.
    per_vertex: Mutex<HashMap<(String, Vec<u8>), Vec<u8>>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::new(HashMap::new()),
            roots: Mutex::new(HashMap::new()),
            per_vertex: Mutex::new(HashMap::new()),
        }
    }

    fn node_key(set: &str, phase: &str, shard: &ShardKey, key: &[u8]) -> String {
        format!("{}/{}/{:?}{:?}/{:?}", set, phase, shard.l1, shard.l2, key)
    }

    fn root_key(set: &str, phase: &str, shard: &ShardKey) -> String {
        format!("root/{}/{}/{:?}{:?}", set, phase, shard.l1, shard.l2)
    }

    fn vertex_scope(set: &str, phase: &str, shard: &ShardKey) -> String {
        format!("{}/{}/{:?}{:?}", set, phase, shard.l1, shard.l2)
    }
}

impl HypergraphStore for MemStore {
    fn new_transaction(&self, _: bool) -> Result<Box<dyn Transaction>> {
        Ok(Box::new(NoopTxn))
    }
    fn get_node_by_key(&self, set: &str, phase: &str, shard: &ShardKey, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let k = Self::node_key(set, phase, shard, key);
        Ok(self.nodes.lock().unwrap().get(&k).cloned())
    }
    fn get_node_by_path(&self, _: &str, _: &str, _: &ShardKey, _: &[i32]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn insert_node(&self, _: &dyn Transaction, set: &str, phase: &str, shard: &ShardKey, key: &[u8], _: &[i32], data: &[u8]) -> Result<()> {
        let k = Self::node_key(set, phase, shard, key);
        self.nodes.lock().unwrap().insert(k, data.to_vec());
        // Non-root inserts also land in the per-vertex map so
        // iteration can recover the original vk bytes.
        if key != [0xFFu8; 32] {
            let scope = Self::vertex_scope(set, phase, shard);
            self.per_vertex.lock().unwrap().insert((scope, key.to_vec()), data.to_vec());
        }
        Ok(())
    }
    fn save_root(&self, _: &dyn Transaction, set: &str, phase: &str, shard: &ShardKey, data: &[u8]) -> Result<()> {
        let k = Self::root_key(set, phase, shard);
        self.roots.lock().unwrap().insert(k, data.to_vec());
        Ok(())
    }
    fn delete_node(&self, _: &dyn Transaction, _: &str, _: &str, _: &ShardKey, _: &[u8], _: &[i32]) -> Result<()> { Ok(()) }
    fn set_covered_prefix(&self, _: &[i32]) -> Result<()> { Ok(()) }
    fn set_shard_commit(&self, _: &dyn Transaction, _: u64, _: &str, _: &str, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn get_shard_commit(&self, _: u64, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>> { Ok(vec![]) }
    fn get_root_commits(&self, _: u64) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> { Ok(HashMap::new()) }
    fn load_vertex_underlying_raw(&self, set: &str, phase: &str, shard: &ShardKey, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let k = Self::node_key(set, phase, shard, key);
        Ok(self.nodes.lock().unwrap().get(&k).cloned())
    }
    fn save_vertex_underlying(&self, set: &str, phase: &str, shard: &ShardKey, key: &[u8], data: &[u8]) -> Result<()> {
        let k = Self::node_key(set, phase, shard, key);
        self.nodes.lock().unwrap().insert(k, data.to_vec());
        let scope = Self::vertex_scope(set, phase, shard);
        self.per_vertex.lock().unwrap().insert((scope, key.to_vec()), data.to_vec());
        Ok(())
    }
    fn for_each_vertex_underlying(&self, set: &str, phase: &str, shard: &ShardKey, callback: &mut dyn FnMut(Vec<u8>, Vec<u8>)) -> Result<usize> {
        let scope = Self::vertex_scope(set, phase, shard);
        let mut count = 0usize;
        for ((s, vk), v) in self.per_vertex.lock().unwrap().iter() {
            if s == &scope {
                callback(vk.clone(), v.clone());
                count += 1;
            }
        }
        Ok(count)
    }
    fn apply_snapshot(&self, _: &str) -> Result<()> { Ok(()) }
    fn set_alt_shard_commit(&self, _: &dyn Transaction, _: u64, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn get_latest_alt_shard_commit(&self, _: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> { Ok((vec![], vec![], vec![], vec![])) }
    fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> { Ok(vec![]) }
    fn reap_old_changesets(&self, _: &dyn Transaction, _: u64) -> Result<()> { Ok(()) }
    fn track_change(&self, _: &dyn Transaction, _: &[u8], _: Option<&[u8]>, _: u64, _: &str, _: &str, _: &ShardKey) -> Result<()> { Ok(()) }
    fn get_changes(&self, _: u64, _: u64, _: &str, _: &str, _: &ShardKey) -> Result<Vec<ChangeRecord>> { Ok(vec![]) }
    fn untrack_change(&self, _: &dyn Transaction, _: &[u8], _: u64, _: &str, _: &str, _: &ShardKey) -> Result<()> { Ok(()) }
}

/// Minimal `InclusionProver` for tests that need a deterministic
/// 64-byte commitment over arbitrary input bytes. Uses the standard
/// library's `DefaultHasher` so the result is stable within a process
/// run; the leading 8 bytes are the hash, the rest is zero-padded.
pub struct StubProver;

impl InclusionProver for StubProver {
    fn commit_raw(&self, data: &[u8], _: u64) -> Result<Vec<u8>> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        data.hash(&mut h);
        let hash = h.finish().to_be_bytes();
        let mut out = vec![0u8; 64];
        out[..8].copy_from_slice(&hash);
        Ok(out)
    }
    fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
    fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
    fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
        Err(QuilError::Internal("batch multiproof generation not supported".into()))
    }
    fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
}
