use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use num_traits::Zero;

use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};
use quil_types::store::{HypergraphStore, ShardKey, Transaction};

use crate::node::VectorCommitmentNode;
use crate::serialize::{deserialize_tree, serialize_tree};
use crate::tree::VectorCommitmentTree;

/// A lazy-loaded vector commitment tree backed by persistent storage.
///
/// On first access (insert, get, commit), the tree loads its root from
/// the `HypergraphStore`. All mutations happen in-memory. On `commit`,
/// the root is serialized and written back to the store.
///
/// This is a simplified "load-all / save-all" strategy that matches
/// the Go `LazyVectorCommitmentTree` in steady state — the full Go
/// implementation also supports per-node lazy loading for large trees,
/// which can be layered on later as an optimization.
pub struct LazyVectorCommitmentTree {
    /// In-memory tree. Initialized lazily from the store.
    inner: RwLock<Option<VectorCommitmentTree>>,
    /// Whether the tree has been loaded from the store.
    loaded: RwLock<bool>,
    /// Whether the tree has been modified since last commit/load.
    dirty: RwLock<bool>,
    /// The backing store.
    store: Arc<dyn HypergraphStore>,
    /// The CRDT set type this tree belongs to ("vertex" or "hyperedge").
    pub set_type: String,
    /// The CRDT phase type ("adds" or "removes").
    pub phase_type: String,
    /// The shard this tree belongs to.
    pub shard_key: ShardKey,
    /// Covered prefix for partial trees in sharded deployments.
    pub covered_prefix: Vec<i32>,
}

impl LazyVectorCommitmentTree {
    /// Lazy tree bound to a specific shard and phase.
    pub fn new(
        store: Arc<dyn HypergraphStore>,
        set_type: impl Into<String>,
        phase_type: impl Into<String>,
        shard_key: ShardKey,
        covered_prefix: Vec<i32>,
    ) -> Self {
        Self {
            inner: RwLock::new(None),
            loaded: RwLock::new(false),
            dirty: RwLock::new(false),
            store,
            set_type: set_type.into(),
            phase_type: phase_type.into(),
            shard_key,
            covered_prefix,
        }
    }

    /// Ensure the tree is loaded from the store. Idempotent.
    fn ensure_loaded(&self) -> Result<()> {
        let loaded = *self.loaded.read().unwrap();
        if loaded {
            return Ok(());
        }

        // Try to load root from the store's node-by-key path.
        // The root is stored at key [0xFF; 32] (the "root" sentinel).
        let root_key = [0xFFu8; 32];
        let root_data = self.store.get_node_by_key(
            &self.set_type,
            &self.phase_type,
            &self.shard_key,
            &root_key,
        )?;

        let tree = match root_data {
            Some(data) if !data.is_empty() => {
                let root_node = deserialize_tree(&data)?;
                VectorCommitmentTree { root: root_node }
            }
            _ => VectorCommitmentTree::new(),
        };

        *self.inner.write().unwrap() = Some(tree);
        *self.loaded.write().unwrap() = true;
        Ok(())
    }

    /// Insert a key-value pair. Loads from store if not already loaded.
    pub fn insert(
        &self,
        key: &[u8],
        value: &[u8],
        hash_target: &[u8],
        size: &BigInt,
    ) -> Result<()> {
        self.ensure_loaded()?;
        let mut inner = self.inner.write().unwrap();
        let tree = inner.as_mut().ok_or_else(|| {
            QuilError::Internal("lazy tree: inner tree missing after load".into())
        })?;
        tree.insert(key, value, hash_target, size)?;
        *self.dirty.write().unwrap() = true;
        Ok(())
    }

    /// Get a value by key. Loads from store if not already loaded.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.ensure_loaded()?;
        let inner = self.inner.read().unwrap();
        let tree = inner.as_ref().ok_or_else(|| {
            QuilError::Internal("lazy tree: inner tree missing after load".into())
        })?;
        Ok(tree.get(key).map(|v| v.to_vec()))
    }

    /// Commit the tree: compute all KZG commitments and write the
    /// serialized root back to the store via the provided transaction.
    /// Returns the root commitment bytes (64 bytes).
    pub fn commit(
        &self,
        txn: &dyn Transaction,
        prover: &(dyn InclusionProver + Sync),
    ) -> Result<Vec<u8>> {
        self.ensure_loaded()?;
        let mut inner = self.inner.write().unwrap();
        let tree = inner.as_mut().ok_or_else(|| {
            QuilError::Internal("lazy tree: inner tree missing after load".into())
        })?;

        // Compute commitments
        let root_commitment = tree.commit(prover);

        // Serialize the tree and save root to store
        let serialized = serialize_tree(tree.root.as_ref())?;
        let root_key = [0xFFu8; 32];
        self.store.save_root(
            txn,
            &self.set_type,
            &self.phase_type,
            &self.shard_key,
            &serialized,
        )?;

        // Also store the node data for lookup
        self.store.insert_node(
            txn,
            &self.set_type,
            &self.phase_type,
            &self.shard_key,
            &root_key,
            &[],
            &serialized,
        )?;

        *self.dirty.write().unwrap() = false;

        Ok(root_commitment)
    }

    /// Get the total size of the tree.
    pub fn get_size(&self) -> BigInt {
        let inner = self.inner.read().unwrap();
        match inner.as_ref() {
            Some(tree) => match &tree.root {
                Some(node) => node.size().clone(),
                None => BigInt::zero(),
            },
            None => BigInt::zero(),
        }
    }

    /// Get (leaf_count, longest_branch) metadata.
    pub fn get_metadata(&self) -> (usize, usize) {
        let inner = self.inner.read().unwrap();
        match inner.as_ref() {
            Some(tree) => match &tree.root {
                Some(VectorCommitmentNode::Branch(branch)) => {
                    (branch.leaf_count, branch.longest_branch)
                }
                Some(VectorCommitmentNode::Leaf(_)) => (1, 1),
                None => (0, 0),
            },
            None => (0, 0),
        }
    }

    /// Whether the tree has been modified since last load/commit.
    pub fn is_dirty(&self) -> bool {
        *self.dirty.read().unwrap()
    }

    /// Whether the tree has been loaded from the store.
    pub fn is_loaded(&self) -> bool {
        *self.loaded.read().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use quil_types::crypto::Multiproof;
    use quil_types::store::ChangeRecord;

    // =========================================================
    // In-memory HypergraphStore stub for tests
    // =========================================================

    struct MemStore {
        nodes: Mutex<HashMap<String, Vec<u8>>>,
        roots: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemStore {
        fn new() -> Self {
            Self {
                nodes: Mutex::new(HashMap::new()),
                roots: Mutex::new(HashMap::new()),
            }
        }

        fn node_key(set: &str, phase: &str, shard: &ShardKey, key: &[u8]) -> String {
            format!("{}/{}/{:?}/{:?}", set, phase, shard.l1, key)
        }
        fn root_key(set: &str, phase: &str, shard: &ShardKey) -> String {
            format!("root/{}/{}/{:?}", set, phase, shard.l1)
        }
    }

    struct NoopTxn;
    impl Transaction for NoopTxn {
        fn get(&self, _: &[u8]) -> Result<Option<Vec<u8>>> { Ok(None) }
        fn set(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
        fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
        fn delete(&self, _: &[u8]) -> Result<()> { Ok(()) }
        fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
        fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn quil_types::store::Iterator>> { Err(QuilError::Internal("iterator not supported on in-memory state".into())) }
        fn delete_range(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
        fn as_any(&self) -> &dyn std::any::Any { self }
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
        fn apply_snapshot(&self, _: &str) -> Result<()> { Ok(()) }
        fn set_alt_shard_commit(&self, _: &dyn Transaction, _: u64, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
        fn get_latest_alt_shard_commit(&self, _: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> { Ok((vec![], vec![], vec![], vec![])) }
        fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> { Ok(vec![]) }
        fn reap_old_changesets(&self, _: &dyn Transaction, _: u64) -> Result<()> { Ok(()) }
        fn track_change(&self, _: &dyn Transaction, _: &[u8], _: Option<&[u8]>, _: u64, _: &str, _: &str, _: &ShardKey) -> Result<()> { Ok(()) }
        fn get_changes(&self, _: u64, _: u64, _: &str, _: &str, _: &ShardKey) -> Result<Vec<ChangeRecord>> { Ok(vec![]) }
        fn untrack_change(&self, _: &dyn Transaction, _: &[u8], _: u64, _: &str, _: &str, _: &ShardKey) -> Result<()> { Ok(()) }
    }

    struct StubProver;
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
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> { Err(QuilError::Internal("batch multiproof generation not supported".into())) }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    fn test_shard() -> ShardKey {
        ShardKey { l1: [0xAA, 0xBB, 0xCC], l2: [0x01u8; 32] }
    }

    // =========================================================
    // Tests
    // =========================================================

    #[test]
    fn lazy_tree_starts_unloaded() {
        let store = Arc::new(MemStore::new());
        let tree = LazyVectorCommitmentTree::new(
            store, "vertex", "adds", test_shard(), vec![],
        );
        assert!(!tree.is_loaded());
        assert!(!tree.is_dirty());
    }

    #[test]
    fn lazy_tree_insert_loads_and_marks_dirty() {
        let store = Arc::new(MemStore::new());
        let tree = LazyVectorCommitmentTree::new(
            store, "vertex", "adds", test_shard(), vec![],
        );
        tree.insert(b"key-1", b"value-1", &[], &BigInt::from(7)).unwrap();
        assert!(tree.is_loaded());
        assert!(tree.is_dirty());
    }

    #[test]
    fn lazy_tree_get_after_insert() {
        let store = Arc::new(MemStore::new());
        let tree = LazyVectorCommitmentTree::new(
            store, "vertex", "adds", test_shard(), vec![],
        );
        tree.insert(b"key-1", b"value-1", &[], &BigInt::from(7)).unwrap();
        let val = tree.get(b"key-1").unwrap();
        assert_eq!(val, Some(b"value-1".to_vec()));
    }

    #[test]
    fn lazy_tree_get_missing_key_returns_none() {
        let store = Arc::new(MemStore::new());
        let tree = LazyVectorCommitmentTree::new(
            store, "vertex", "adds", test_shard(), vec![],
        );
        tree.insert(b"key-1", b"value-1", &[], &BigInt::from(7)).unwrap();
        let val = tree.get(b"key-2").unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn lazy_tree_commit_produces_nonzero_root() {
        let store = Arc::new(MemStore::new());
        let prover = StubProver;
        let tree = LazyVectorCommitmentTree::new(
            store, "vertex", "adds", test_shard(), vec![],
        );
        tree.insert(b"key-1", b"value-1", &[], &BigInt::from(7)).unwrap();
        let txn = NoopTxn;
        let root = tree.commit(&txn, &prover).unwrap();
        assert_eq!(root.len(), 64);
        assert_ne!(root, vec![0u8; 64]);
        assert!(!tree.is_dirty());
    }

    #[test]
    fn lazy_tree_commit_persists_to_store() {
        let store = Arc::new(MemStore::new());
        let prover = StubProver;
        let shard = test_shard();
        let tree = LazyVectorCommitmentTree::new(
            store.clone(), "vertex", "adds", shard.clone(), vec![],
        );
        tree.insert(b"key-1", b"value-1", &[], &BigInt::from(7)).unwrap();
        let txn = NoopTxn;
        tree.commit(&txn, &prover).unwrap();

        // Verify the root was saved
        let root_key = MemStore::root_key("vertex", "adds", &shard);
        let saved = store.roots.lock().unwrap().get(&root_key).cloned();
        assert!(saved.is_some());
        assert!(!saved.unwrap().is_empty());
    }

    #[test]
    fn lazy_tree_reload_from_store() {
        let store = Arc::new(MemStore::new());
        let prover = StubProver;
        let shard = test_shard();

        // First tree: insert and commit
        let tree1 = LazyVectorCommitmentTree::new(
            store.clone(), "vertex", "adds", shard.clone(), vec![],
        );
        tree1.insert(b"key-1", b"value-1", &[], &BigInt::from(7)).unwrap();
        let txn = NoopTxn;
        let root1 = tree1.commit(&txn, &prover).unwrap();

        // Second tree: load from same store
        let tree2 = LazyVectorCommitmentTree::new(
            store, "vertex", "adds", shard, vec![],
        );
        let val = tree2.get(b"key-1").unwrap();
        assert_eq!(val, Some(b"value-1".to_vec()));

        // Commit produces same root
        let txn2 = NoopTxn;
        let root2 = tree2.commit(&txn2, &prover).unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn lazy_tree_multiple_inserts_and_metadata() {
        let store = Arc::new(MemStore::new());
        let tree = LazyVectorCommitmentTree::new(
            store, "vertex", "adds", test_shard(), vec![],
        );
        tree.insert(b"key-1", b"val1", &[], &BigInt::from(4)).unwrap();
        tree.insert(b"key-2", b"val22", &[], &BigInt::from(5)).unwrap();
        tree.insert(b"key-3", b"val333", &[], &BigInt::from(6)).unwrap();
        let (leaf_count, _) = tree.get_metadata();
        assert_eq!(leaf_count, 3);
        // All three values retrievable
        assert_eq!(tree.get(b"key-1").unwrap(), Some(b"val1".to_vec()));
        assert_eq!(tree.get(b"key-2").unwrap(), Some(b"val22".to_vec()));
        assert_eq!(tree.get(b"key-3").unwrap(), Some(b"val333".to_vec()));
    }

    #[test]
    fn lazy_tree_empty_commit_returns_zero_root() {
        let store = Arc::new(MemStore::new());
        let prover = StubProver;
        let tree = LazyVectorCommitmentTree::new(
            store, "vertex", "adds", test_shard(), vec![],
        );
        let txn = NoopTxn;
        let root = tree.commit(&txn, &prover).unwrap();
        assert_eq!(root, vec![0u8; 64]);
    }
}
