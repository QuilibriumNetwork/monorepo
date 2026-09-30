//! Shared test utilities for crates that depend on `quil-hypergraph`.
//!
//! Gated behind the `test-utils` feature. Downstream crates enable it via:
//!
//! ```toml
//! [dev-dependencies]
//! quil-hypergraph = { path = "../quil-hypergraph", features = ["test-utils"] }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

/// A write-THROUGH transaction over [`MemStore`]'s shared kv map — so plain
/// key/value writes (`set`/`get`/`delete`), e.g. the persisted size-bucket cache
/// (`SIZE_BUCKETS_KEY`), survive across CRDT instances built on the same store
/// (a simulated restart). Writes land immediately; `commit`/`abort` are no-ops.
pub struct MemTxn {
    kv: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl Transaction for MemTxn {
    fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.kv.lock().unwrap().get(k).cloned())
    }
    fn set(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.kv.lock().unwrap().insert(k.to_vec(), v.to_vec());
        Ok(())
    }
    fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
    fn delete(&self, k: &[u8]) -> Result<()> {
        self.kv.lock().unwrap().remove(k);
        Ok(())
    }
    fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
    fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn KvIterator>> {
        Err(QuilError::Internal("iterator not supported on in-memory state".into()))
    }
    fn delete_range(&self, lo: &[u8], hi: &[u8]) -> Result<()> {
        self.kv.lock().unwrap().retain(|k, _| k.as_slice() < lo || k.as_slice() >= hi);
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

/// Minimal in-memory `HypergraphStore` for tests. Stores node and root
/// data in hash maps; all other operations are no-ops.
pub struct MemStore {
    read_failure_phase: Mutex<Option<String>>,
    commit_setup_failures: Mutex<(bool, bool)>,
    nodes: Mutex<HashMap<String, Vec<u8>>>,
    roots: Mutex<HashMap<String, Vec<u8>>>,
    /// Per-vertex underlying-data keyed by `(scope_prefix, vk)` so
    /// `for_each_vertex_underlying` can hand back the exact original
    /// `vk` bytes without round-tripping them through the debug-format
    /// string keys used by `nodes`.
    per_vertex: Mutex<HashMap<(String, Vec<u8>), Vec<u8>>>,
    /// Plain kv keyspace (the `Transaction` get/set surface), shared so a
    /// transaction and successive CRDT instances on the same store see the same
    /// data — needed to exercise the persisted size-bucket cache.
    kv: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            read_failure_phase: Mutex::new(None),
            commit_setup_failures: Mutex::new((false, false)),
            nodes: Mutex::new(HashMap::new()),
            roots: Mutex::new(HashMap::new()),
            per_vertex: Mutex::new(HashMap::new()),
            kv: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Inject underlying-blob I/O failures for one phase; test utility only.
    pub fn fail_vertex_reads(&self, phase: Option<&str>) {
        *self.read_failure_phase.lock().unwrap() = phase.map(str::to_owned);
    }

    /// Inject transaction-creation or root-read failures before commit staging.
    pub fn fail_commit_setup(&self, transaction: bool, roots: bool) {
        *self.commit_setup_failures.lock().unwrap() = (transaction, roots);
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

    /// Number of tree nodes written to the store (test introspection).
    pub fn node_count(&self) -> usize {
        self.nodes.lock().unwrap().len()
    }

    /// Number of per-vertex underlying blobs written (test introspection).
    pub fn per_vertex_count(&self) -> usize {
        self.per_vertex.lock().unwrap().len()
    }
}

impl HypergraphStore for MemStore {
    fn new_transaction(&self, _: bool) -> Result<Box<dyn Transaction>> {
        if self.commit_setup_failures.lock().unwrap().0 {
            return Err(QuilError::Store("injected transaction creation failure".into()));
        }
        Ok(Box::new(MemTxn { kv: self.kv.clone() }))
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
    fn get_root_commits(&self, _: u64) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        if self.commit_setup_failures.lock().unwrap().1 {
            return Err(QuilError::Store("injected root read failure".into()));
        }
        Ok(HashMap::new())
    }
    fn load_vertex_underlying_raw(&self, set: &str, phase: &str, shard: &ShardKey, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.read_failure_phase.lock().unwrap().as_deref() == Some(phase) {
            return Err(QuilError::Store("injected underlying-blob read failure".into()));
        }
        let k = Self::node_key(set, phase, shard, key);
        Ok(self.nodes.lock().unwrap().get(&k).cloned())
    }
    fn save_vertex_underlying(&self, _txn: &dyn quil_types::store::Transaction, set: &str, phase: &str, shard: &ShardKey, key: &[u8], data: &[u8]) -> Result<()> {
        let k = Self::node_key(set, phase, shard, key);
        self.nodes.lock().unwrap().insert(k, data.to_vec());
        let scope = Self::vertex_scope(set, phase, shard);
        self.per_vertex.lock().unwrap().insert((scope, key.to_vec()), data.to_vec());
        Ok(())
    }
    fn page_vertex_underlying_fixed(
        &self, set: &str, phase: &str, shard: &ShardKey, domain: &[u8; 32],
        after: Option<&[u8; 32]>, limits: quil_types::store::VertexPageLimits,
    ) -> Result<quil_types::store::VertexDataPage> {
        let invalid = || quil_types::error::QuilError::InvalidArgument("invalid or oversized vertex page".into());
        if limits.max_entries == 0 || limits.max_bytes < 64 { return Err(invalid()); }
        let retained = limits.max_entries.checked_add(1).ok_or_else(invalid)?;
        let scope = Self::vertex_scope(set, phase, shard);
        let values = self.per_vertex.lock().unwrap();
        let mut selected = std::collections::BTreeMap::new();
        for ((s, key), value) in values.iter() {
            if s != &scope || key.len() != 64 || &key[..32] != domain { continue; }
            let address: [u8; 32] = key[32..].try_into().unwrap();
            if after.is_some_and(|after| address <= *after) { continue; }
            selected.insert(address, value);
            if selected.len() > retained { selected.pop_last(); }
        }
        let mut page = quil_types::store::VertexDataPage { entries: Vec::new(), has_more: false };
        let mut used: usize = 0;
        for (address, value) in selected {
            if page.entries.len() == limits.max_entries { page.has_more = true; break; }
            let next = value.len().checked_add(64).and_then(|n| used.checked_add(n));
            if next.is_none_or(|n| n > limits.max_bytes) {
                if page.entries.is_empty() { return Err(invalid()); }
                page.has_more = true; break;
            }
            used = next.unwrap();
            page.entries.push((address, value.clone()));
        }
        Ok(page)
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

#[cfg(test)]
mod fixed_vertex_page_tests {
    use super::*;
    #[test]
    fn crdt_fixed_vertex_page_forwarding_preserves_cursor_and_limits() {
        let store = std::sync::Arc::new(MemStore::new());
        let domain = [7; 32];
        let shard = crate::addressing::shard_key_for_location(&crate::addressing::Location { app_address: domain, data_address: [0; 32] });
        let txn = store.new_transaction(false).unwrap();
        for i in (0..3).rev() {
            let mut key = domain.to_vec(); key.extend_from_slice(&[i; 32]);
            store.save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, b"row").unwrap();
        }
        let crdt = crate::HypergraphCrdt::new(store, std::sync::Arc::new(quil_types::crypto::NoopInclusionProver));
        let limits = quil_types::store::VertexPageLimits { max_entries: 2, max_bytes: 134 };
        let first = crdt.page_committed_vertex_adds(&domain, None, limits).unwrap();
        assert_eq!(first.entries, vec![([0; 32], b"row".to_vec()), ([1; 32], b"row".to_vec())]);
        assert!(first.has_more);
        let last = crdt.page_committed_vertex_adds(&domain, Some(&[1; 32]), limits).unwrap();
        assert_eq!(last.entries, vec![([2; 32], b"row".to_vec())]);
        assert!(!last.has_more);
    }
}
