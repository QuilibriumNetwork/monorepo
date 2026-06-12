use std::sync::Arc;

use quil_types::error::{QuilError, Result};
use quil_types::store::ShardKey;

use crate::encoding::{
    hypergraph_alt_shard_address_index_key, hypergraph_alt_shard_address_prefix,
    hypergraph_alt_shard_commit_key, hypergraph_alt_shard_commit_latest_key,
    hypergraph_shard_commit_frame_prefix, hypergraph_shard_commit_key,
    hypergraph_tree_blob_key, hypergraph_tree_node_by_key,
    hypergraph_tree_node_by_path, hypergraph_tree_node_by_path_prefix,
    hypergraph_vertex_data_key, hypergraph_vertex_data_prefix,
    HG_VERTEX_ADDS_SHARD_COMMIT,
};

/// RocksDB-backed hypergraph tree storage.
pub struct RocksHypergraphStore {
    db: Arc<rocksdb::DB>,
}

impl RocksHypergraphStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }

    /// Capture a point-in-time snapshot of all tree blobs. The returned
    /// handle reflects the store's state at the moment of capture and
    /// is immune to subsequent writes through this store.
    pub fn capture_snapshot(&self) -> Result<Arc<RocksHypergraphSnapshot>> {
        Ok(Arc::new(RocksHypergraphSnapshot::capture(&self.db)?))
    }

    /// Save a fully-serialized vector commitment tree as a single blob,
    /// keyed by `(set_type, phase_type, shard_key)`. The bytes should be
    /// the output of `quil_tries::serialize_tree`.
    pub fn save_tree_blob(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        bytes: &[u8],
    ) -> Result<()> {
        let key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        self.db
            .put(&key, bytes)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Load a previously stored tree blob, or `Ok(None)` if no blob exists
    /// for the given key.
    pub fn load_tree_blob(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
    ) -> Result<Option<Vec<u8>>> {
        let key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        self.db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Persist one vertex's `underlying_data` sub-tree blob. See
    /// `quil_tries::deserialize_go_tree` for parsing the wire format.
    pub fn save_vertex_underlying(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        let key = hypergraph_vertex_data_key(set_type, phase_type, shard_key, vertex_key);
        self.db
            .put(&key, bytes)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Load one vertex's `underlying_data`, or `Ok(None)` if absent.
    pub fn load_vertex_underlying(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let key = hypergraph_vertex_data_key(set_type, phase_type, shard_key, vertex_key);
        self.db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Iterate every `(vertex_key, underlying_data)` pair persisted for
    /// the given `(set, phase, shard)`. The callback receives owned
    /// bytes so it can move them into a caller-owned collection.
    pub fn for_each_vertex_underlying<F>(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        mut callback: F,
    ) -> Result<usize>
    where
        F: FnMut(Vec<u8>, Vec<u8>),
    {
        let prefix = hypergraph_vertex_data_prefix(set_type, phase_type, shard_key);
        // Seek to the first key ≥ prefix and walk forward until we leave
        // the prefix. Avoids the correctness pitfalls of
        // `set_iterate_upper_bound` when the shard or vertex keys have
        // high byte values — incrementing 0xFF bytes is error-prone, so
        // we just compare each yielded key against the prefix.
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &prefix,
            rocksdb::Direction::Forward,
        ));
        let prefix_len = prefix.len();
        let mut count = 0usize;
        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            if k.len() <= prefix_len {
                continue;
            }
            let vertex_key = k[prefix_len..].to_vec();
            callback(vertex_key, v.into_vec());
            count += 1;
        }
        Ok(count)
    }
}

use std::collections::HashMap;
use quil_types::store::{ChangeRecord, HypergraphStore, SnapshotReadable, Transaction};

use crate::encoding::HG_TREE_BLOB_PREFIX;

/// Frozen-bytes snapshot of all hypergraph tree blobs at capture time.
///
/// Lifetime / ownership choice: rocksdb 0.22's `Snapshot<'a>` borrows
/// the `DB`, and binding it to an `Arc<DB>` would require either a
/// self-referential struct or unsafe lifetime erasure. Rather than
/// reach for those, we copy every `(set, phase, shard) → tree_blob`
/// entry from the live store into a `HashMap` at publish time. This
/// mirrors the semantic Go gets from Pebble's MVCC snapshot — reads
/// against the snapshot reflect the publish-time state, immune to
/// later writes — at the cost of holding O(num_shards * num_phases)
/// blobs in memory per retained generation. With
/// `MAX_GENERATIONS = 10` and the typical handful of active shards
/// per node, this stays small. Per-vertex underlying-data blobs are
/// NOT captured because the sync server doesn't read them; the trait
/// only exposes `load_tree_blob`.
pub struct RocksHypergraphSnapshot {
    /// Key: full `hypergraph_tree_blob_key` bytes. Value: tree blob.
    blobs: HashMap<Vec<u8>, Vec<u8>>,
}

impl RocksHypergraphSnapshot {
    /// Walk the live DB and copy every tree-blob entry into memory.
    /// Iterates only the `HG_TREE_BLOB_PREFIX` range, so cost is
    /// proportional to the number of (set, phase, shard) tuples — not
    /// the entire DB.
    pub fn capture(db: &rocksdb::DB) -> Result<Self> {
        let prefix = [HG_TREE_BLOB_PREFIX];
        let iter = db.iterator(rocksdb::IteratorMode::From(
            &prefix,
            rocksdb::Direction::Forward,
        ));
        let mut blobs: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            blobs.insert(k.into_vec(), v.into_vec());
        }
        Ok(Self { blobs })
    }

    /// Number of tree blobs frozen in this snapshot. Test hook.
    #[doc(hidden)]
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }
}

impl SnapshotReadable for RocksHypergraphSnapshot {
    fn load_tree_blob(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &quil_types::store::ShardKey,
    ) -> Result<Option<Vec<u8>>> {
        let key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        Ok(self.blobs.get(&key).cloned())
    }
}

/// Live-store adapter — lets the sync server call the same
/// `SnapshotReadable` interface against the current DB when no
/// generation-bound snapshot is available. Reads always go to the
/// live store, so concurrent writes ARE visible (unlike a captured
/// snapshot). Use this only as the fallback path.
impl SnapshotReadable for RocksHypergraphStore {
    fn load_tree_blob(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &quil_types::store::ShardKey,
    ) -> Result<Option<Vec<u8>>> {
        RocksHypergraphStore::load_tree_blob(self, set_type, phase_type, shard_key)
    }
}

/// RocksDB Transaction — wraps a WriteBatch for atomicity.
pub(crate) struct RocksTxn {
    pub(crate) batch: std::sync::Mutex<rocksdb::WriteBatch>,
    db: Arc<rocksdb::DB>,
}

impl Transaction for RocksTxn {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(key).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().put(key, value);
        Ok(())
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let batch = self.batch.into_inner().unwrap();
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete(key);
        Ok(())
    }
    fn abort(self: Box<Self>) -> Result<()> {
        // Drop the batch without writing
        Ok(())
    }
    fn new_iter(&self, _lower: &[u8], _upper: &[u8]) -> Result<Box<dyn quil_types::store::Iterator>> {
        Err(QuilError::Internal("RocksTxn iterator not implemented".into()))
    }
    fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete_range(lower, upper);
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// If `txn` is a `RocksTxn`, stage `op` into its write batch and
/// return `true`; else return `false` so the caller can fall back
/// to direct DB writes.
#[inline]
fn with_rocks_batch<F>(txn: &dyn Transaction, op: F) -> bool
where
    F: FnOnce(&mut rocksdb::WriteBatch),
{
    if let Some(rt) = txn.as_any().downcast_ref::<RocksTxn>() {
        let mut guard = rt.batch.lock().unwrap();
        op(&mut *guard);
        true
    } else {
        false
    }
}

impl HypergraphStore for RocksHypergraphStore {
    fn new_transaction(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
        Ok(Box::new(RocksTxn {
            batch: std::sync::Mutex::new(rocksdb::WriteBatch::default()),
            db: self.db.clone(),
        }))
    }

    fn get_node_by_key(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // The `[0xFF; 32]` "root sentinel" key is the legacy whole-tree
        // backend's handshake — it expects `load_tree_blob` to return
        // the entire serialized tree under prefix 0x2F. The per-node
        // lazy backend doesn't use that sentinel: it walks via
        // `get_node_by_path` from the empty path. We keep the sentinel
        // route working so any caller still on the old API path picks
        // up the tree, but new callers should not rely on it.
        if key == [0xFFu8; 32] {
            return self.load_tree_blob(set_type, phase_type, shard_key);
        }
        // Per-node lookup at `[0x33, set, phase, l1, l2, key]`.
        let db_key = hypergraph_tree_node_by_key(set_type, phase_type, shard_key, key);
        self.db
            .get(&db_key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn get_node_by_path(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        path: &[i32],
    ) -> Result<Option<Vec<u8>>> {
        // SeekGE on the by-path index. Prefix-compressed branches mean
        // the deepest covering node may live at a path longer than
        // `path` itself — its by-path key starts with the requested
        // path bytes. So we seek to `requested_path_key` and check the
        // first entry that still has the `prefix` (per-shard) byte
        // sequence as its prefix.
        let prefix = hypergraph_tree_node_by_path_prefix(set_type, phase_type, shard_key);
        let requested = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
        let mut iter = self.db.raw_iterator();
        iter.seek(&requested);
        if !iter.valid() {
            return Ok(None);
        }
        let found_key = match iter.key() {
            Some(k) => k.to_vec(),
            None => return Ok(None),
        };
        if !found_key.starts_with(&prefix) {
            return Ok(None);
        }
        // The found key must also extend `requested` — otherwise we've
        // walked PAST the requested subtree to an unrelated path.
        if !found_key.starts_with(&requested) {
            return Ok(None);
        }
        // Value is the by-key key for that node — deref to fetch.
        let by_key = match iter.value() {
            Some(v) => v.to_vec(),
            None => return Ok(None),
        };
        self.db
            .get(&by_key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn insert_node(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        key: &[u8],
        path: &[i32],
        data: &[u8],
    ) -> Result<()> {
        // Root sentinel keeps its legacy blob route for backward compat.
        if key == [0xFFu8; 32] {
            let db_key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
            if with_rocks_batch(txn, |b| b.put(&db_key, data)) {
                return Ok(());
            }
            return self
                .db
                .put(&db_key, data)
                .map_err(|e| QuilError::Store(e.to_string()));
        }
        // Per-node: write the by-key entry and the by-path pointer
        // atomically. Pointer value is the by-key key — the lazy
        // walker SeekGEs the by-path index and then `Get`s the by-key
        // entry. This is exactly Go's dual-index scheme.
        let by_key = hypergraph_tree_node_by_key(set_type, phase_type, shard_key, key);
        let by_path = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
        let by_key_for_pointer = by_key.clone();
        if with_rocks_batch(txn, |b| {
            b.put(&by_key, data);
            b.put(&by_path, &by_key_for_pointer);
        }) {
            return Ok(());
        }
        self.db
            .put(&by_key, data)
            .map_err(|e| QuilError::Store(e.to_string()))?;
        self.db
            .put(&by_path, &by_key_for_pointer)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn save_root(&self, txn: &dyn Transaction, set_type: &str, phase_type: &str, shard_key: &ShardKey, data: &[u8]) -> Result<()> {
        let db_key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        if with_rocks_batch(txn, |b| b.put(&db_key, data)) {
            return Ok(());
        }
        self.db
            .put(&db_key, data)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn delete_node(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        key: &[u8],
        path: &[i32],
    ) -> Result<()> {
        if key == [0xFFu8; 32] {
            let db_key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
            if with_rocks_batch(txn, |b| b.delete(&db_key)) {
                return Ok(());
            }
            return self
                .db
                .delete(&db_key)
                .map_err(|e| QuilError::Store(e.to_string()));
        }
        let by_key = hypergraph_tree_node_by_key(set_type, phase_type, shard_key, key);
        let by_path = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
        if with_rocks_batch(txn, |b| {
            b.delete(&by_key);
            b.delete(&by_path);
        }) {
            return Ok(());
        }
        self.db
            .delete(&by_key)
            .map_err(|e| QuilError::Store(e.to_string()))?;
        self.db
            .delete(&by_path)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn set_covered_prefix(&self, prefix: &[i32]) -> Result<()> {
        // Go serializes `[]int` as a series of big-endian int64s via
        // `binary.Write(buf, BigEndian, []int64{...})` — mirror that
        // exactly so a future Rust-reads-Go-data path stays compatible.
        let mut buf = Vec::with_capacity(prefix.len() * 8);
        for &p in prefix {
            buf.extend_from_slice(&(p as i64).to_be_bytes());
        }
        let key = crate::encoding::hypergraph_covered_prefix_key();
        self.db.put(&key, &buf).map_err(|e| QuilError::Store(e.to_string()))
    }

    fn set_shard_commit(&self, txn: &dyn Transaction, frame_number: u64, phase_type: &str, set_type: &str, shard_address: &[u8], commitment: &[u8]) -> Result<()> {
        let key = hypergraph_shard_commit_key(frame_number, phase_type, set_type, shard_address);
        if with_rocks_batch(txn, |b| b.put(&key, commitment)) {
            return Ok(());
        }
        self.db.put(&key, commitment).map_err(|e| QuilError::Store(e.to_string()))
    }

    fn get_shard_commit(&self, frame_number: u64, phase_type: &str, set_type: &str, shard_address: &[u8]) -> Result<Vec<u8>> {
        let key = hypergraph_shard_commit_key(frame_number, phase_type, set_type, shard_address);
        self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("shard commit not found".into()))
    }

    fn get_root_commits(&self, frame_number: u64) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        let prefix = hypergraph_shard_commit_frame_prefix(frame_number);
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &prefix,
            rocksdb::Direction::Forward,
        ));
        let prefix_len = prefix.len();
        let mut result: HashMap<ShardKey, Vec<Vec<u8>>> = HashMap::new();
        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            // Key layout past the prefix: [commit_type(1), shard_address(32)]
            // Skip keys that don't have exactly commit_type + 32-byte address.
            if k.len() != prefix_len + 1 + 32 {
                continue;
            }
            let commit_type = k[prefix_len];
            let shard_address = &k[prefix_len + 1..];
            let commit_idx = (commit_type - HG_VERTEX_ADDS_SHARD_COMMIT) as usize;
            if commit_idx >= 4 {
                continue;
            }
            // Derive L1 bloom filter from L2 (shard_address) via
            // SHAKE256-based GetBloomFilterIndices(addr, 256, 3),
            // matching Go's `node/store/hypergraph.go:2083` and
            // `quil_hypergraph::addressing::get_bloom_filter_indices`.
            let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(
                shard_address,
                256,
                3,
            );
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(shard_address);
            let sk = ShardKey { l1, l2 };
            let commits = result.entry(sk).or_insert_with(|| vec![vec![]; 4]);
            commits[commit_idx] = v.to_vec();
        }
        Ok(result)
    }

    fn load_vertex_underlying_raw(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.load_vertex_underlying(set_type, phase_type, shard_key, vertex_key)
    }

    fn save_vertex_underlying(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        data: &[u8],
    ) -> Result<()> {
        RocksHypergraphStore::save_vertex_underlying(
            self, set_type, phase_type, shard_key, vertex_key, data,
        )
    }

    fn for_each_vertex_underlying(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        callback: &mut dyn FnMut(Vec<u8>, Vec<u8>),
    ) -> Result<usize> {
        RocksHypergraphStore::for_each_vertex_underlying(
            self, set_type, phase_type, shard_key, |vk, data| callback(vk, data),
        )
    }

    fn apply_snapshot(&self, db_path: &str) -> Result<()> {
        // Mirror of Go's `PebbleHypergraphStore.ApplySnapshot`
        // (`node/store/hypergraph.go:2110`). The peer's snapshot was
        // dropped at `<db_path>/snapshot` as a self-contained DB; bulk-
        // copy every key into the active store, then remove the temp
        // directory. Idempotent — if the snapshot dir is missing, just
        // clean up anything stale and return Ok.
        use std::path::Path;
        let snap_dir = Path::new(db_path).join("snapshot");
        let cleanup = |dir: &Path| {
            let _ = std::fs::remove_dir_all(dir);
        };
        match std::fs::metadata(&snap_dir) {
            Ok(md) if md.is_dir() => {}
            _ => {
                cleanup(&snap_dir);
                return Ok(());
            }
        }

        // Open the snapshot DB read-only so we don't trigger compactions
        // or stray writes against the staging area.
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        let src = rocksdb::DB::open_for_read_only(&opts, &snap_dir, true)
            .map_err(|e| {
                cleanup(&snap_dir);
                QuilError::Store(format!("apply snapshot: open src: {}", e))
            })?;

        let mut batch = rocksdb::WriteBatch::default();
        let mut count: usize = 0;
        const CHUNK: usize = 100;
        for entry in src.iterator(rocksdb::IteratorMode::Start) {
            let (k, v) = match entry {
                Ok(p) => p,
                Err(e) => {
                    cleanup(&snap_dir);
                    return Err(QuilError::Store(format!("apply snapshot: iter: {}", e)));
                }
            };
            batch.put(&k, &v);
            count += 1;
            if count % CHUNK == 0 {
                let to_commit = std::mem::take(&mut batch);
                if let Err(e) = self.db.write(to_commit) {
                    cleanup(&snap_dir);
                    return Err(QuilError::Store(format!("apply snapshot: write: {}", e)));
                }
            }
        }
        // Final commit for the remainder.
        if let Err(e) = self.db.write(batch) {
            cleanup(&snap_dir);
            return Err(QuilError::Store(format!("apply snapshot: final write: {}", e)));
        }
        cleanup(&snap_dir);
        tracing::info!(keys = count, "imported snapshot via raw key/value copy");
        Ok(())
    }

    fn set_alt_shard_commit(
        &self,
        txn: &dyn Transaction,
        frame_number: u64,
        shard_address: &[u8],
        va: &[u8],
        vr: &[u8],
        ha: &[u8],
        hr: &[u8],
    ) -> Result<()> {
        // Validate root sizes — Go accepts 64 (raw) or 74 (KZG-with-proof).
        for (name, root) in [("vertex_adds", va), ("vertex_removes", vr),
                              ("hyperedge_adds", ha), ("hyperedge_removes", hr)] {
            if root.len() != 64 && root.len() != 74 {
                return Err(QuilError::InvalidArgument(format!(
                    "alt shard commit {name} root must be 64 or 74 bytes, got {}",
                    root.len()
                )));
            }
        }

        // Serialize as length-prefixed values (1-byte len + data for each of
        // the four roots) — matches `SetAltShardCommit` at
        // node/store/hypergraph.go:2425.
        let mut value = Vec::with_capacity(4 + va.len() + vr.len() + ha.len() + hr.len());
        for root in [va, vr, ha, hr] {
            value.push(root.len() as u8);
            value.extend_from_slice(root);
        }

        let commit_key = hypergraph_alt_shard_commit_key(frame_number, shard_address);
        let latest_key = hypergraph_alt_shard_commit_latest_key(shard_address);
        let index_key = hypergraph_alt_shard_address_index_key(shard_address);

        // Consult existing latest-frame so we only overwrite with a newer one.
        let should_update_latest = match self.db.get(&latest_key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let existing = u64::from_be_bytes(bytes.as_slice().try_into().unwrap());
                frame_number > existing
            }
            _ => true,
        };

        if with_rocks_batch(txn, |b| {
            b.put(&commit_key, &value);
            if should_update_latest {
                b.put(&latest_key, frame_number.to_be_bytes());
            }
            b.put(&index_key, &[] as &[u8]);
        }) {
            return Ok(());
        }

        // Fallback path — no RocksTxn; use a local atomic batch.
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(&commit_key, &value);
        if should_update_latest {
            batch.put(&latest_key, frame_number.to_be_bytes());
        }
        batch.put(&index_key, &[] as &[u8]);
        self.db
            .write(batch)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn get_latest_alt_shard_commit(
        &self,
        shard_address: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let latest_key = hypergraph_alt_shard_commit_latest_key(shard_address);
        let latest = self
            .db
            .get(&latest_key)
            .map_err(|e| QuilError::Store(e.to_string()))?;
        let frame_number = match latest {
            Some(bytes) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes.as_slice().try_into().unwrap())
            }
            _ => return Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new())),
        };
        let commit_key = hypergraph_alt_shard_commit_key(frame_number, shard_address);
        let value = self
            .db
            .get(&commit_key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("alt shard commit not found".into()))?;

        // Decode four length-prefixed roots.
        let mut cursor = 0usize;
        let mut parts = Vec::with_capacity(4);
        for _ in 0..4 {
            if cursor >= value.len() {
                return Err(QuilError::Serialization(
                    "alt shard commit value truncated".into(),
                ));
            }
            let len = value[cursor] as usize;
            cursor += 1;
            if cursor + len > value.len() {
                return Err(QuilError::Serialization(
                    "alt shard commit length prefix overruns buffer".into(),
                ));
            }
            parts.push(value[cursor..cursor + len].to_vec());
            cursor += len;
        }
        Ok((
            parts.remove(0),
            parts.remove(0),
            parts.remove(0),
            parts.remove(0),
        ))
    }

    fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> {
        let prefix = hypergraph_alt_shard_address_prefix();
        let prefix_len = prefix.len();
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &prefix,
            rocksdb::Direction::Forward,
        ));
        let mut out = Vec::new();
        for entry in iter {
            let (k, _v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            if k.len() > prefix_len {
                out.push(k[prefix_len..].to_vec());
            }
        }
        Ok(out)
    }
    fn reap_old_changesets(&self, txn: &dyn Transaction, frame_number: u64) -> Result<()> {
        // Mirror Go's `ReapOldChangesets` (`node/store/hypergraph.go:1830`):
        // (1) enumerate every shard for which a `VERTEX_ADDS_TREE_ROOT`
        // exists, then (2) for each of the four change-record discriminators
        // delete all entries for that shard with `frame_number` < `frame_number`.
        if frame_number == 0 {
            return Ok(());
        }
        let (start, end) = crate::encoding::hypergraph_tree_roots_iter_bounds();
        let mut shard_keys: Vec<Vec<u8>> = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &start,
            rocksdb::Direction::Forward,
        ));
        for entry in iter {
            let (k, _v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if k.as_ref() >= end.as_slice() {
                break;
            }
            // Strip the [HYPERGRAPH_SHARD, change_type] prefix.
            if k.len() <= 2 {
                continue;
            }
            shard_keys.push(k[2..].to_vec());
        }

        let change_types = [
            crate::encoding::HG_VERTEX_ADDS_CHANGE_RECORD,
            crate::encoding::HG_VERTEX_REMOVES_CHANGE_RECORD,
            crate::encoding::HG_HYPEREDGE_ADDS_CHANGE_RECORD,
            crate::encoding::HG_HYPEREDGE_REMOVES_CHANGE_RECORD,
        ];
        for change_type in change_types {
            for sk in &shard_keys {
                let mut start_key = Vec::with_capacity(2 + sk.len() + 8);
                start_key.push(crate::encoding::HYPERGRAPH_SHARD);
                start_key.push(change_type);
                start_key.extend_from_slice(sk);
                start_key.extend_from_slice(&0u64.to_be_bytes());
                let mut end_key = Vec::with_capacity(2 + sk.len() + 8);
                end_key.push(crate::encoding::HYPERGRAPH_SHARD);
                end_key.push(change_type);
                end_key.extend_from_slice(sk);
                end_key.extend_from_slice(&frame_number.to_be_bytes());
                txn.delete_range(&start_key, &end_key)?;
            }
        }
        Ok(())
    }
    fn track_change(
        &self,
        txn: &dyn Transaction,
        key: &[u8],
        old_value: Option<&[u8]>,
        frame_number: u64,
        phase_type: &str,
        set_type: &str,
        shard_key: &ShardKey,
    ) -> Result<()> {
        // Mirror Go's `TrackChange` (`node/store/hypergraph.go:1714`):
        // write the serialized `oldValue` tree blob (empty if `nil`) under
        // a per-(set/phase/shard/frame/key) change-record key.
        let change_key = crate::encoding::hypergraph_change_record_key(
            set_type, phase_type, shard_key, frame_number, key,
        )
        .ok_or_else(|| QuilError::InvalidArgument(format!(
            "track_change: unknown set/phase pair ({}, {})", set_type, phase_type,
        )))?;
        let value: &[u8] = old_value.unwrap_or(&[]);
        if with_rocks_batch(txn, |b| b.put(&change_key, value)) {
            return Ok(());
        }
        self.db.put(&change_key, value).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_changes(
        &self,
        frame_start: u64,
        frame_end: u64,
        phase_type: &str,
        set_type: &str,
        shard_key: &ShardKey,
    ) -> Result<Vec<ChangeRecord>> {
        // Mirror Go's `GetChanges` (`node/store/hypergraph.go:1886`):
        // range-scan `[HYPERGRAPH_SHARD, change_type, l1, l2,
        // frame_start..=frame_end]`, parse the suffix into frame + key,
        // and return the records reversed for rollback-friendly order.
        let change_type = crate::encoding::change_record_type_byte(set_type, phase_type)
            .ok_or_else(|| QuilError::InvalidArgument(format!(
                "get_changes: unknown set/phase pair ({}, {})", set_type, phase_type,
            )))?;
        let mut start_key = Vec::with_capacity(2 + 3 + 32 + 8);
        start_key.push(crate::encoding::HYPERGRAPH_SHARD);
        start_key.push(change_type);
        start_key.extend_from_slice(&shard_key.l1);
        start_key.extend_from_slice(&shard_key.l2);
        start_key.extend_from_slice(&frame_start.to_be_bytes());

        let mut end_key = Vec::with_capacity(2 + 3 + 32 + 8);
        end_key.push(crate::encoding::HYPERGRAPH_SHARD);
        end_key.push(change_type);
        end_key.extend_from_slice(&shard_key.l1);
        end_key.extend_from_slice(&shard_key.l2);
        // Go's iterator is exclusive-end with `frameEnd + 1`. Saturate
        // on overflow rather than wrap to 0 — wrapping would produce a
        // key strictly less than `start_key` and immediately terminate
        // the scan, silently returning no changes.
        end_key.extend_from_slice(&frame_end.saturating_add(1).to_be_bytes());

        let header_len = 2 + 3 + 32;
        let mut changes: Vec<ChangeRecord> = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &start_key,
            rocksdb::Direction::Forward,
        ));
        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if k.as_ref() >= end_key.as_slice() {
                break;
            }
            if k.len() < header_len + 8 {
                continue;
            }
            let frame_number = u64::from_be_bytes(k[header_len..header_len + 8].try_into().unwrap());
            let original_key = k[header_len + 8..].to_vec();
            let old_value = if v.is_empty() { None } else { Some(v.to_vec()) };
            changes.push(ChangeRecord {
                key: original_key,
                old_value,
                frame: frame_number,
            });
        }
        changes.reverse();
        Ok(changes)
    }
    fn untrack_change(
        &self,
        txn: &dyn Transaction,
        key: &[u8],
        frame_number: u64,
        phase_type: &str,
        set_type: &str,
        shard_key: &ShardKey,
    ) -> Result<()> {
        // Mirror Go's `UntrackChange` (`node/store/hypergraph.go:1961`).
        let change_key = crate::encoding::hypergraph_change_record_key(
            set_type, phase_type, shard_key, frame_number, key,
        )
        .ok_or_else(|| QuilError::InvalidArgument(format!(
            "untrack_change: unknown set/phase pair ({}, {})", set_type, phase_type,
        )))?;
        if with_rocks_batch(txn, |b| b.delete(&change_key)) {
            return Ok(());
        }
        self.db.delete(&change_key).map_err(|e| QuilError::Store(e.to_string()))
    }

    fn capture_tree_snapshot(&self) -> Result<Option<Arc<dyn SnapshotReadable>>> {
        let snap = RocksHypergraphSnapshot::capture(&self.db)?;
        Ok(Some(Arc::new(snap) as Arc<dyn SnapshotReadable>))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rocksdb_store::RocksDb;
    use tempfile::TempDir;

    #[test]
    fn test_tree_blob_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = RocksHypergraphStore::new(Arc::new(db).inner());

        let shard = ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };

        // Absent key returns Ok(None).
        assert!(store.load_tree_blob("vertex", "adds", &shard).unwrap().is_none());

        // Save and read back.
        let blob = vec![1u8, 2, 3, 4, 5];
        store.save_tree_blob("vertex", "adds", &shard, &blob).unwrap();
        let loaded = store.load_tree_blob("vertex", "adds", &shard).unwrap();
        assert_eq!(loaded, Some(blob));

        // Different phase → different key → still absent.
        assert!(store.load_tree_blob("vertex", "removes", &shard).unwrap().is_none());
    }

    #[test]
    fn test_vertex_underlying_roundtrip_and_iter() {
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = RocksHypergraphStore::new(Arc::new(db).inner());

        let shard = ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };

        let keys = [
            vec![0xAA; 64],
            vec![0xBB; 64],
            vec![0xCC; 64],
        ];
        let data = [b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];

        // Empty-phase point lookup returns Ok(None).
        assert!(store
            .load_vertex_underlying("vertex", "adds", &shard, &keys[0])
            .unwrap()
            .is_none());

        // Save three entries under (vertex, adds, shard).
        for (k, v) in keys.iter().zip(data.iter()) {
            store
                .save_vertex_underlying("vertex", "adds", &shard, k, v)
                .unwrap();
        }

        // Point lookup.
        assert_eq!(
            store
                .load_vertex_underlying("vertex", "adds", &shard, &keys[1])
                .unwrap()
                .as_deref(),
            Some(&b"beta"[..])
        );

        // Different phase is isolated.
        for k in &keys {
            assert!(store
                .load_vertex_underlying("vertex", "removes", &shard, k)
                .unwrap()
                .is_none());
        }

        // Iterate all entries for the phase.
        let mut collected: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let count = store
            .for_each_vertex_underlying("vertex", "adds", &shard, |k, v| {
                collected.push((k, v));
            })
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(collected.len(), 3);
        // Iterator yields them in key order, which is our insertion order
        // by construction (0xAA < 0xBB < 0xCC).
        assert_eq!(collected[0].0, keys[0]);
        assert_eq!(collected[1].0, keys[1]);
        assert_eq!(collected[2].0, keys[2]);
    }

    /// End-to-end check that `capture_tree_snapshot` is point-in-time:
    /// reads through the captured snapshot reflect the bytes at capture
    /// time, regardless of subsequent live-store writes.
    #[test]
    fn test_capture_tree_snapshot_is_point_in_time() {
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = RocksHypergraphStore::new(Arc::new(db).inner());

        let shard = ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };

        // Stage some pre-capture data across multiple phases/shards.
        store.save_tree_blob("vertex", "adds", &shard, b"v-adds-pre").unwrap();
        store.save_tree_blob("vertex", "removes", &shard, b"v-removes-pre").unwrap();

        // Capture.
        let snap = store.capture_snapshot().unwrap();

        // Mutate the live store AFTER capture.
        store.save_tree_blob("vertex", "adds", &shard, b"v-adds-POST").unwrap();
        // Add a new shard entirely after capture; the snapshot must
        // not see it.
        let new_shard = ShardKey {
            l1: [1u8; 3],
            l2: [0u8; 32],
        };
        store
            .save_tree_blob("hyperedge", "adds", &new_shard, b"new-shard")
            .unwrap();

        // Snapshot must still see the pre-mutation bytes for the
        // shard that existed at capture time.
        let snap_dyn: &dyn SnapshotReadable = snap.as_ref();
        assert_eq!(
            snap_dyn
                .load_tree_blob("vertex", "adds", &shard)
                .unwrap()
                .as_deref(),
            Some(&b"v-adds-pre"[..]),
            "snapshot must reflect pre-mutation bytes"
        );
        assert_eq!(
            snap_dyn
                .load_tree_blob("vertex", "removes", &shard)
                .unwrap()
                .as_deref(),
            Some(&b"v-removes-pre"[..])
        );
        // The post-capture insert is invisible through the snapshot.
        assert!(snap_dyn
            .load_tree_blob("hyperedge", "adds", &new_shard)
            .unwrap()
            .is_none());

        // The live store DOES see the new state — confirming we
        // really did mutate the underlying DB after capture.
        assert_eq!(
            store.load_tree_blob("vertex", "adds", &shard).unwrap().as_deref(),
            Some(&b"v-adds-POST"[..])
        );

        // Sanity: the snapshot covers exactly the pre-capture blobs
        // (2 entries: v-adds-pre and v-removes-pre).
        assert_eq!(snap.blob_count(), 2);
    }
}
