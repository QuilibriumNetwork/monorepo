use std::sync::Arc;

use crate::overlay::{OverlayDb, OverlayDbSnapshot, OverlayTxn, PageCursor, PageSnapshot};

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
    db: quil_forest::CoordinatedDb,
    #[cfg(any(test, feature = "test-utils"))]
    fail_commit: std::sync::atomic::AtomicBool,
}

/// Hypergraph records in an isolated execution branch. Use `forest()` to
/// ensure the JMT and all ancillary records share the same overlay.
pub struct OverlayHypergraphStore {
    db: OverlayDb,
}

struct OverlayHypergraphSnapshot {
    snapshot: OverlayDbSnapshot,
}

impl OverlayHypergraphSnapshot {
    fn scan_point_backend(&self) -> Option<quil_types::store::ScanPoint> {
        self.snapshot.scan_point()
    }
}

impl OverlayHypergraphStore {
    fn backing_store_identity_backend(&self) -> quil_types::store::BackingStoreIdentity {
        quil_types::store::BackingStoreIdentity::of(&self.db.0)
    }

    pub fn new(overlay: Arc<quil_forest::ExecutionOverlay>) -> Self {
        Self { db: OverlayDb(overlay) }
    }

    pub fn forest(&self) -> quil_forest::Forest {
        quil_forest::Forest::on_overlay(self.db.0.clone(), FOREST_NAMESPACE)
    }

    fn new_transaction_backend(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
        if self.db.0.stats().closed {
            return Err(QuilError::Store("execution overlay closed".into()));
        }
        Ok(Box::new(OverlayTxn::new(self.db.clone())))
    }

    fn capture_tree_snapshot_backend(&self) -> Result<Option<Arc<dyn SnapshotReadable>>> {
        let snapshot = self.db.snapshot();
        snapshot.check()?;
        Ok(Some(Arc::new(OverlayHypergraphSnapshot { snapshot })))
    }

    fn apply_snapshot_backend(&self, _db_path: &str) -> Result<()> {
        Err(QuilError::Store("external database import is unavailable during tentative execution".into()))
    }
}

/// Reserved key namespace for the JMT forest when it shares this
/// store's RocksDB. Prefixes every forest key so the forest sub-range is
/// disjoint from all hypergraph keys (whose tags are `< 0xF7`). Both the
/// migration (which writes the forest into the migrated DB) and the runtime
/// (which commits to it) must use this exact prefix.
pub const FOREST_NAMESPACE: &[u8] = &[0xF7];

/// Reverse of `encoding::set_type_byte` — recover the set-type string a
/// versioned key encodes (0 ⇒ "vertex", 1 ⇒ "hyperedge"). `None` for an
/// unknown byte, so the pruner skips malformed keys rather than mis-classifying.
fn byte_set_str(b: u8) -> Option<&'static str> {
    match b {
        0 => Some("vertex"),
        1 => Some("hyperedge"),
        _ => None,
    }
}

/// Reverse of `encoding::phase_type_byte` (0 ⇒ "adds", 1 ⇒ "removes").
fn byte_phase_str(b: u8) -> Option<&'static str> {
    match b {
        0 => Some("adds"),
        1 => Some("removes"),
        _ => None,
    }
}

/// Exclusive upper bound for a `delete_range` that covers every key beginning
/// with `prefix`: increment the last byte that is `< 0xFF`, dropping any
/// trailing `0xFF` bytes. `None` if `prefix` is empty or all `0xFF` (no bound —
/// caller must skip the range delete rather than wipe to the end of the DB).
fn prefix_range_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut u = prefix.to_vec();
    while matches!(u.last(), Some(&0xff)) {
        u.pop();
    }
    match u.last_mut() {
        Some(b) => {
            *b += 1;
            Some(u)
        }
        None => None,
    }
}

impl RocksHypergraphStore {
    fn backing_store_identity_backend(&self) -> quil_types::store::BackingStoreIdentity {
        self.db.backing_store_identity()
    }

    pub fn new(db: quil_forest::CoordinatedDb) -> Self {
        Self { db, #[cfg(any(test, feature = "test-utils"))] fail_commit: std::sync::atomic::AtomicBool::new(false) }
    }

    /// Fail the final batch write without publishing any staged records.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fail_commit_for_test(&self, fail: bool) {
        self.fail_commit.store(fail, std::sync::atomic::Ordering::Relaxed);
    }

    /// The coordinated RocksDB handle backing this store. Exposed so startup can build
    /// the JMT forest (`quil_forest::Forest::with_namespace(store.raw_db(),
    /// FOREST_NAMESPACE)`) sharing this DB — the `HypergraphStore` trait
    /// deliberately doesn't surface it, so this is the concrete-store escape
    /// hatch the forest installation needs.
    pub fn raw_db(&self) -> quil_forest::CoordinatedDb {
        self.db.clone()
    }

    // (helper `prefix_range_upper_bound` is a free function below the impl)

    /// Whether this DB already contains JMT forest data (any key under
    /// [`FOREST_NAMESPACE`]). The runtime uses this to gate the forest
    /// commitment path: only a migrated DB — one the `--migrate-db` converter
    /// has populated — reads `true`, so non-migrated nodes keep the KZG path
    /// and never silently switch to empty forest roots.
    pub fn has_forest_data(&self) -> bool {
        let mut it = self.db.raw_iterator();
        it.seek(FOREST_NAMESPACE);
        it.valid() && it.key().map(|k| k.starts_with(FOREST_NAMESPACE)).unwrap_or(false)
    }

    /// Delete the entire JMT forest (every key under [`FOREST_NAMESPACE`]) so it
    /// can be rebuilt fresh. Used by the coin-rescale corrective pass, which
    /// changes coin content addresses and must recommit the forest from a clean
    /// slate rather than layering onto the stale (inflated) generation.
    pub fn clear_forest_data(&self) -> Result<()> {
        // FOREST_NAMESPACE is the single byte 0xF7; the exclusive upper bound is
        // 0xF8 (delete_range is [lower, upper)).
        let lower = FOREST_NAMESPACE.to_vec();
        let mut upper = FOREST_NAMESPACE.to_vec();
        *upper.last_mut().unwrap() += 1; // 0xF7 -> 0xF8
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range(&lower, &upper);
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Delete a single shard's UNDERLYING vertex-blob keyspace — both the V1
    /// (`0x30`) and V2/MVCC (`0x31`) ranges, across all four phases. The store
    /// half of the shard-scoped prover-tree reset: the forest trees are wiped
    /// separately (`Forest::reset_shard_phase_trees`), and this clears the flat
    /// blob cache the prover registry reads (`for_each_vertex_underlying`) so a
    /// rebuild can't resurrect the old records. Scoped to `shard` only; leaves
    /// every other shard untouched.
    pub fn clear_shard_underlying(&self, shard: &quil_types::store::ShardKey) -> Result<()> {
        <Self as HypergraphStore>::clear_shard_underlying(self, shard)
    }

    /// Whether any `root_version` (sync-by-hash) index entry exists — i.e. the DB
    /// was committed/migrated by a build that seeds the versioned-sync indexes. A
    /// DB migrated before index seeding returns `false`, signalling a backfill.
    pub fn has_sync_indexes(&self) -> bool {
        let prefix = [crate::encoding::HG_ROOT_VERSION];
        let mut it = self.db.raw_iterator();
        it.seek(&prefix);
        it.valid() && it.key().map(|k| k.first() == Some(&crate::encoding::HG_ROOT_VERSION)).unwrap_or(false)
    }

    /// Capture a point-in-time snapshot of all tree blobs. The returned
    /// handle reflects the store's state at the moment of capture and
    /// is immune to subsequent writes through this store.
    pub fn capture_snapshot(&self) -> Result<Arc<RocksHypergraphSnapshot>> {
        Ok(Arc::new(RocksHypergraphSnapshot::capture(self.db.clone())?))
    }

    /// Save a fully-serialized vector commitment tree as a single blob,
    /// keyed by `(set_type, phase_type, shard_key)`. The bytes should be
    /// the output of `quil_tries::serialize_tree`.
    ///
    /// Test-only: production persists tree blobs transactionally via
    /// [`save_tree_blob_txn`]. Kept for unit tests that don't need a
    /// transaction around the write.
    #[cfg(test)]
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

    /// Transaction-aware tree-blob write: stages the put into `txn`'s
    /// batch so the blob becomes durable atomically with the rest of the
    /// transaction.
    ///
    /// Like every other `RocksHypergraphStore` writer, this stages into the
    /// txn's batch and errors (rather than writing directly) if `txn` isn't a
    /// `RocksTxn` — see [`RocksTxn::from_dyn`]. A silent fallback would
    /// persist the blob outside the caller's transaction, defeating the
    /// atomicity this method exists to provide.
    pub fn save_tree_blob_txn(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        bytes: &[u8],
    ) -> Result<()> {
        let key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        RocksTxn::for_store(txn, &self.db)?.batch.lock().unwrap().put(&key, bytes);
        Ok(())
    }


    /// Persist one vertex's `underlying_data` sub-tree blob directly,
    /// outside any transaction. See `quil_tries::deserialize_go_tree` for
    /// parsing the wire format.
    ///
    /// Test-only: production persists vertex content transactionally via
    /// [`save_vertex_underlying_txn`] (or the `HypergraphStore` trait
    /// method, which delegates to it). Kept as a direct-write fixture for
    /// tests that seed the per-vertex keyspace without a transaction. Gated
    /// behind the `test-utils` feature so it can't be reached from
    /// production code; consuming crates enable it via `[dev-dependencies]`.
    #[cfg(any(test, feature = "test-utils"))]
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


    /// Like [`stream_migrate_vertex_adds`](Self::stream_migrate_vertex_adds) but
    /// scoped to the SUB-RANGE of a shard's vertex-adds keyspace whose key
    /// (after the shard prefix) starts with `sub_prefix` — e.g. `domain ‖ [top]`
    /// to select one top-address-byte slice. Takes its OWN point-in-time
    /// snapshot. This is the unit of PARALLELISM for the coin migration: the
    /// caller runs one call per disjoint range across a thread pool so all cores
    /// stay busy (a single serial iterator was the throughput ceiling). Ranges
    /// are disjoint by address, so each coin is processed exactly once; the
    /// transparent puts other ranges make are skipped by the caller's transform.
    /// `vertex_key` handed to `process_chunk` still strips only the SHARD prefix
    /// (so it is `domain ‖ address`, identical to the non-ranged scan). Returns
    /// `(scanned, migrated)`.
    pub fn migrate_vertex_adds_subrange<F>(
        &self,
        shard: &quil_types::store::ShardKey,
        sub_prefix: &[u8],
        chunk_size: usize,
        mut process_chunk: F,
    ) -> Result<(usize, usize)>
    where
        F: FnMut(&[(Vec<u8>, Vec<u8>)]) -> Result<(usize, Vec<VertexWrite>)>,
    {
        let shard_prefix = hypergraph_vertex_data_prefix("vertex", "adds", shard);
        let shard_prefix_len = shard_prefix.len();
        let mut full_prefix = shard_prefix.clone();
        full_prefix.extend_from_slice(sub_prefix);
        let chunk_size = chunk_size.max(1);
        let snapshot = self.db.snapshot();
        let iter = snapshot
            .iterator(rocksdb::IteratorMode::From(&full_prefix, rocksdb::Direction::Forward));
        let mut chunk: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(chunk_size);
        let mut scanned = 0usize;
        let mut migrated = 0usize;

        let mut flush = |chunk: &[(Vec<u8>, Vec<u8>)],
                         migrated: &mut usize,
                         process_chunk: &mut F|
         -> Result<()> {
            let (m, writes) = process_chunk(chunk)?;
            *migrated += m;
            if !writes.is_empty() {
                let mut batch = rocksdb::WriteBatch::default();
                for w in &writes {
                    match w {
                        VertexWrite::Put { set, phase, vertex_key, blob } => {
                            let key = hypergraph_vertex_data_key(set, phase, shard, vertex_key);
                            batch.put(&key, blob);
                        }
                        VertexWrite::Delete { set, phase, vertex_key } => {
                            let key = hypergraph_vertex_data_key(set, phase, shard, vertex_key);
                            batch.delete(&key);
                        }
                    }
                }
                self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))?;
            }
            Ok(())
        };

        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&full_prefix) {
                break;
            }
            if k.len() <= shard_prefix_len {
                continue;
            }
            chunk.push((k[shard_prefix_len..].to_vec(), v.to_vec()));
            if chunk.len() >= chunk_size {
                scanned += chunk.len();
                flush(&chunk, &mut migrated, &mut process_chunk)?;
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            scanned += chunk.len();
            flush(&chunk, &mut migrated, &mut process_chunk)?;
        }
        Ok((scanned, migrated))
    }

    /// Direct (non-transactional) write of one vertex's underlying blob into the
    /// unversioned keyspace — for the OFFLINE `--migrate-*` passes that write
    /// straight to the KV (the identical bytes a commit persists), bypassing the
    /// CRDT tree, since the forest is rebuilt afterward. Mirrors what
    /// [`stream_migrate_vertex_adds`](Self::stream_migrate_vertex_adds)'s
    /// `VertexWrite::Put` does, for the handful of reserved metadata vertices
    /// (shadow-accumulator root, conservation receipt). NOT for the live path —
    /// use [`save_vertex_underlying_txn`](Self::save_vertex_underlying_txn).
    pub fn migrate_put_vertex_underlying(
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


    /// Iterate every `(vertex_key, latest_underlying_data)` pair persisted for
    /// the given `(set, phase, shard)`. The callback receives owned bytes so it
    /// can move them into a caller-owned collection.
    ///
    /// Reads the versioned (v2) keyspace — keeping the LATEST version per vertex
    /// — UNION the legacy unversioned keyspace for vertices not yet re-written
    /// versioned. The commit path writes v2, so this MUST see v2 or provers
    /// vanish from the registry (this is the sole enumerator the registry
    /// refresh uses). Mirrors the trait impl of the same name.
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
        use std::collections::{HashMap, HashSet};
        // v2 (versioned): accumulate the max-version blob per vertex_key. Keys
        // interleave across variable-length vertex keys, so use a map rather
        // than assume per-key contiguity.
        let v2_prefix = crate::encoding::hypergraph_vertex_data_v2_shard_prefix(
            set_type, phase_type, shard_key,
        );
        let mut latest: HashMap<Vec<u8>, (u64, Vec<u8>)> = HashMap::new();
        for entry in self
            .db
            .iterator(rocksdb::IteratorMode::From(&v2_prefix, rocksdb::Direction::Forward))
        {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&v2_prefix) {
                break;
            }
            if k.len() < v2_prefix.len() + 8 {
                continue;
            }
            let vk = k[v2_prefix.len()..k.len() - 8].to_vec();
            let ver = u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap());
            match latest.get_mut(&vk) {
                Some((mv, mb)) if ver > *mv => {
                    *mv = ver;
                    *mb = v.into_vec();
                }
                Some(_) => {}
                None => {
                    latest.insert(vk, (ver, v.into_vec()));
                }
            }
        }
        let mut count = 0usize;
        let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(latest.len());
        for (vk, (_ver, blob)) in latest {
            seen.insert(vk.clone());
            callback(vk, blob);
            count += 1;
        }
        // Legacy (unversioned) fills any vertex not yet re-written v2.
        let prefix = hypergraph_vertex_data_prefix(set_type, phase_type, shard_key);
        let prefix_len = prefix.len();
        for entry in self
            .db
            .iterator(rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward))
        {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            if k.len() <= prefix_len {
                continue;
            }
            let vertex_key = k[prefix_len..].to_vec();
            if seen.contains(&vertex_key) {
                continue;
            }
            callback(vertex_key, v.into_vec());
            count += 1;
        }
        Ok(count)
    }

    /// Greatest MVCC version of any blob in the **v2** keyspace of one
    /// `(set, phase, shard)`, or `None` when it holds none. Reads are of the
    /// greatest version, so a tree committing below this would have its writes
    /// shadowed by older blobs.
    pub fn max_vertex_v2_version(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
    ) -> Result<Option<u64>> {
        let v2_prefix = crate::encoding::hypergraph_vertex_data_v2_shard_prefix(
            set_type, phase_type, shard_key,
        );
        let mut max = None;
        for entry in self
            .db
            .iterator(rocksdb::IteratorMode::From(&v2_prefix, rocksdb::Direction::Forward))
        {
            let (k, _) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&v2_prefix) {
                break;
            }
            if k.len() >= v2_prefix.len() + 8 {
                max = max.max(Some(u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap())));
            }
        }
        Ok(max)
    }


    /// Emit the max-version blob per vertex from the MVCC **v2** keyspace of one
    /// `(set, phase, shard)`, via a fallible callback. Peak memory is O(number of
    /// v2 vertices in this shard/phase) — a dedup `HashMap`, because variable-
    /// length vertex keys let versions of different keys interleave. For the
    /// `--migrate-db` forest build this is bounded in practice: a fresh Go→rocks
    /// DB has NO v2 state (the v2 keyspace is written only by the live Rust CRDT
    /// commit AFTER migration), and a re-run's v2 set is small. The companion
    /// [`for_each_vertex_unversioned_ordered`] streams the (large) legacy set.
    /// Emission order is unspecified (the caller buckets by sub-shard, so order
    /// is irrelevant). Returns the vertex count.
    pub fn for_each_vertex_v2_max_version<F>(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        mut callback: F,
    ) -> Result<usize>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>,
    {
        use std::collections::HashMap;
        let v2_prefix = crate::encoding::hypergraph_vertex_data_v2_shard_prefix(
            set_type, phase_type, shard_key,
        );
        let mut latest: HashMap<Vec<u8>, (u64, Vec<u8>)> = HashMap::new();
        for entry in self
            .db
            .iterator(rocksdb::IteratorMode::From(&v2_prefix, rocksdb::Direction::Forward))
        {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&v2_prefix) {
                break;
            }
            if k.len() < v2_prefix.len() + 8 {
                continue;
            }
            let vk = k[v2_prefix.len()..k.len() - 8].to_vec();
            let ver = u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap());
            match latest.get_mut(&vk) {
                Some((mv, mb)) if ver > *mv => {
                    *mv = ver;
                    *mb = v.into_vec();
                }
                Some(_) => {}
                None => {
                    latest.insert(vk, (ver, v.into_vec()));
                }
            }
        }
        let mut count = 0usize;
        for (vk, (_ver, blob)) in latest {
            callback(&vk, &blob)?;
            count += 1;
        }
        Ok(count)
    }

    /// Stream the UNVERSIONED (legacy, pre-forest) vertex blobs of one
    /// `(set, phase, shard)` keyspace in KEY (address) order, one row at a time,
    /// through a fallible callback. Peak store-side memory is O(1) — a raw
    /// snapshot iterator with NO dedup map (unlike
    /// [`for_each_vertex_underlying`], which accumulates the whole shard/phase in
    /// a `HashMap` to reconcile the MVCC v2 keyspace).
    ///
    /// Correct for the `--migrate-db` forest build specifically: the legacy state
    /// being converted lives entirely in the unversioned keyspace (the v2 keyspace
    /// is written only by the LIVE forest AFTER migration), and the keys sort by
    /// `vertex_key` — for the address-path forest, `domain(32) ‖ address(32)` — so
    /// within one app the rows arrive in address order, letting the caller flush
    /// one contiguous sub-shard at a time. `callback(vertex_key, blob)`. Returns
    /// the row count (0 ⇒ this phase's leaves live in a legacy whole-tree blob;
    /// the caller falls back to `load_tree_blob`).
    pub fn for_each_vertex_unversioned_ordered<F>(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        mut callback: F,
    ) -> Result<usize>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>,
    {
        let prefix = crate::encoding::hypergraph_vertex_data_prefix(set_type, phase_type, shard_key);
        let prefix_len = prefix.len();
        let snapshot = self.db.snapshot();
        let iter = snapshot
            .iterator(rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        let mut count = 0usize;
        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            if k.len() <= prefix_len {
                continue;
            }
            callback(&k[prefix_len..], &v)?;
            count += 1;
        }
        Ok(count)
    }


    /// Streaming, bounded-memory migration over a domain's committed
    /// `("vertex","adds", shard)` keyspace. Reads a point-in-time snapshot in
    /// `chunk_size`-row chunks — so the puts/deletes this makes into the same
    /// keyspace are never re-seen by the forward scan — and hands
    /// each chunk of `(vertex_key, blob)` pairs to `process_chunk`. The chunk
    /// handler returns `(migrated_in_chunk, writes)`; the [`VertexWrite`]s are
    /// applied as one `WriteBatch` per chunk. Peak memory is O(chunk_size)
    /// regardless of the coin count (essential at 100+ GB coin sets that cannot
    /// be collected into RAM). `progress(scanned, migrated)` fires after every
    /// chunk. Returns `(scanned, migrated)`.
    ///
    /// Chunking (rather than row-at-a-time) exists so the caller can fan the
    /// expensive per-coin transform out across a thread pool while this method
    /// keeps the snapshot scan and the RocksDB writes single-threaded. Writes go
    /// straight to the KV keyspace, bypassing the CRDT tree — for offline
    /// `--migrate-*` passes whose forest is rebuilt afterward — emitting the
    /// identical vertex-store bytes a normal `commit` would (same
    /// [`hypergraph_vertex_data_key`]), without any tree recompute.
    pub fn stream_migrate_vertex_adds<F, P>(
        &self,
        shard: &quil_types::store::ShardKey,
        chunk_size: usize,
        mut process_chunk: F,
        mut progress: P,
    ) -> Result<(usize, usize)>
    where
        F: FnMut(&[(Vec<u8>, Vec<u8>)]) -> Result<(usize, Vec<VertexWrite>)>,
        P: FnMut(usize, usize),
    {
        let prefix = hypergraph_vertex_data_prefix("vertex", "adds", shard);
        let prefix_len = prefix.len();
        let chunk_size = chunk_size.max(1);
        let snapshot = self.db.snapshot();
        let iter = snapshot.iterator(rocksdb::IteratorMode::From(
            &prefix,
            rocksdb::Direction::Forward,
        ));
        let mut chunk: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(chunk_size);
        let mut scanned = 0usize;
        let mut migrated = 0usize;

        // Apply one chunk: run the (possibly parallel) transform, then commit its
        // writes in a single batch. Kept as a closure so the tail chunk reuses it.
        let mut flush = |chunk: &[(Vec<u8>, Vec<u8>)],
                         migrated: &mut usize,
                         process_chunk: &mut F|
         -> Result<()> {
            let (m, writes) = process_chunk(chunk)?;
            *migrated += m;
            if !writes.is_empty() {
                let mut batch = rocksdb::WriteBatch::default();
                for w in &writes {
                    match w {
                        VertexWrite::Put { set, phase, vertex_key, blob } => {
                            let key = hypergraph_vertex_data_key(set, phase, shard, vertex_key);
                            batch.put(&key, blob);
                        }
                        VertexWrite::Delete { set, phase, vertex_key } => {
                            let key = hypergraph_vertex_data_key(set, phase, shard, vertex_key);
                            batch.delete(&key);
                        }
                    }
                }
                self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))?;
            }
            Ok(())
        };

        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            if k.len() <= prefix_len {
                continue;
            }
            chunk.push((k[prefix_len..].to_vec(), v.to_vec()));
            if chunk.len() >= chunk_size {
                scanned += chunk.len();
                flush(&chunk, &mut migrated, &mut process_chunk)?;
                chunk.clear();
                progress(scanned, migrated);
            }
        }
        if !chunk.is_empty() {
            scanned += chunk.len();
            flush(&chunk, &mut migrated, &mut process_chunk)?;
        }
        progress(scanned, migrated);
        Ok((scanned, migrated))
    }
}

/// A single vertex-store operation staged by
/// [`RocksHypergraphStore::stream_migrate_vertex_adds`]. `set`/`phase` name the
/// CRDT phase keyspace (`"vertex"`/`"adds"`, etc.) and `vertex_key` is the full
/// `app‖data` id.
pub enum VertexWrite {
    /// Write `blob` at `(set, phase, vertex_key)`.
    Put { set: &'static str, phase: &'static str, vertex_key: Vec<u8>, blob: Vec<u8> },
    /// Physically remove `(set, phase, vertex_key)` from the keyspace — used to
    /// erase migrated-away originals as though they never existed (no tombstone).
    Delete { set: &'static str, phase: &'static str, vertex_key: Vec<u8> },
}

use std::collections::HashMap;
use quil_types::store::{ChangeRecord, HypergraphStore, SnapshotReadable, Transaction};

/// A real RocksDB point-in-time snapshot bound to a published root.
///
/// Reads (`load_tree_blob`) are served at the DB sequence number captured
/// at `capture` time — immune to later writes through the live store,
/// matching Go's `tries.TreeBackingStore.NewDBSnapshot`. Capture is cheap
/// (pins the current sequence; no data copy), but holding the snapshot
/// pins every key version superseded after it until this struct is
/// dropped, which releases the snapshot. Release is therefore driven by
/// the snapshot manager dropping the generation handle (FIFO eviction or
/// `close()`), gated by any in-flight sync session still holding an `Arc`.
///
/// Lifetime: rocksdb 0.22's `SnapshotWithThreadMode<'a, DB>` borrows the
/// `DB`. To store it past a single scope we keep its `CoordinatedDb` owner in the same
/// struct and erase the borrow to `'static` (one contained `unsafe` in
/// `capture`), relying on field drop order — `snapshot` before `_db` — so
/// the snapshot is always released before its `DB` can go away.
pub struct RocksHypergraphSnapshot {
    /// Point-in-time snapshot. MUST be declared before `_db`: struct
    /// fields drop in declaration order, so this drops first (releasing
    /// the rocksdb snapshot) while the backing `DB` is still alive.
    snapshot: rocksdb::SnapshotWithThreadMode<'static, rocksdb::DB>,
    scan: quil_types::store::ScanPoint,
    /// Keeps the `DB` alive for as long as `snapshot` borrows it.
    _db: quil_forest::CoordinatedDb,
}

impl RocksHypergraphSnapshot {
    /// Capture a RocksDB point-in-time snapshot. Cheap — pins the current
    /// sequence number; copies no data.
    pub fn capture(db: quil_forest::CoordinatedDb) -> Result<Self> {
        Ok(Self::from_database(db))
    }

    /// Infallible read-view capture over a known coordinated database. The
    /// canonical publisher holds its write guard while binding the new state.
    pub fn from_database(db: quil_forest::CoordinatedDb) -> Self {
        let (snap, scan) = db.snapshot_with_scan_point();
        // SAFETY: `snap` borrows the DB inside the stable Arc allocation
        // owned by `CoordinatedDb`. Moving its clone into `_db` keeps that
        // allocation alive for the snapshot, and
        // field declaration order (`snapshot` then `_db`) guarantees the
        // snapshot is dropped — releasing the rocksdb snapshot — before
        // `_db` is dropped (which may close the DB). Erasing the borrow to
        // `'static` only launders the lifetime; layout is unchanged
        // (a `&DB` plus a raw snapshot pointer), so the transmute is sound.
        let snapshot: rocksdb::SnapshotWithThreadMode<'static, rocksdb::DB> =
            unsafe { std::mem::transmute(snap) };
        Self { snapshot, scan, _db: db }
    }

    fn scan_point_backend(&self) -> Option<quil_types::store::ScanPoint> {
        Some(self.scan)
    }
}

fn page_fixed_vertices_at_snapshot(
    snapshot: &impl PageSnapshot,
    set_type: &str,
    phase_type: &str,
    shard: &ShardKey,
    domain: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: quil_types::store::VertexPageLimits,
    skip: &dyn Fn(&[u8; 32]) -> bool,
) -> Result<quil_types::store::VertexDataPage> {
    use quil_types::store::VertexDataPage;
    if limits.max_entries == 0 || limits.max_bytes < 64 {
        return Err(QuilError::InvalidArgument(
            "invalid vertex page limits".into(),
        ));
    }
    let mut page = VertexDataPage {
        entries: Vec::new(),
        has_more: false,
    };
    let lower = match after {
        None => None,
        Some(address) => {
            let mut next = *address;
            let Some(index) = next.iter().rposition(|&b| b != 255) else {
                return Ok(page);
            };
            next[index] += 1;
            next[index + 1..].fill(0);
            Some(next)
        }
    };
    let mut legacy_prefix = hypergraph_vertex_data_prefix(set_type, phase_type, shard);
    legacy_prefix.extend_from_slice(domain);
    let mut versioned_prefix =
        crate::encoding::hypergraph_vertex_data_v2_shard_prefix(set_type, phase_type, shard);
    versioned_prefix.extend_from_slice(domain);
    let start = |prefix: &[u8]| {
        let mut key = prefix.to_vec();
        if let Some(address) = lower {
            key.extend_from_slice(&address);
        }
        key
    };
    let mut legacy = snapshot.raw_cursor();
    let mut versioned = snapshot.raw_cursor();
    legacy.seek(start(&legacy_prefix));
    versioned.seek(start(&versioned_prefix));
    // None for the blob records an oversized row without copying it. That
    // row only fails the page if selected before any smaller page result;
    // an oversized legacy row may be superseded by a small v2 value.
    type Row = ([u8; 32], Option<Vec<u8>>);
    let copy_blob = |bytes: &[u8]| (bytes.len() <= limits.max_bytes - 64).then(|| bytes.to_vec());
    let mut next_legacy = || -> Result<Option<Row>> {
        while legacy.valid() {
            let key = legacy.key().unwrap();
            if !key.starts_with(&legacy_prefix) {
                break;
            }
            if key.len() != legacy_prefix.len() + 32 {
                legacy.next();
                continue;
            }
            let address = key[legacy_prefix.len()..].try_into().unwrap();
            // A skipped row is passed over below; its value is never copied.
            let blob = if skip(&address) { Some(Vec::new()) } else { copy_blob(legacy.value().unwrap()) };
            legacy.next();
            legacy
                .status()
                .map_err(|e| QuilError::Store(e.to_string()))?;
            return Ok(Some((address, blob)));
        }
        legacy
            .status()
            .map_err(|e| QuilError::Store(e.to_string()))?;
        Ok(None)
    };
    let mut versioned_done = false;
    let mut next_versioned = || -> Result<Option<Row>> {
        if versioned_done {
            return Ok(None);
        }
        while versioned.valid() {
            let key = versioned.key().unwrap();
            if !key.starts_with(&versioned_prefix) {
                break;
            }
            if key.len() != versioned_prefix.len() + 32 + 8 {
                versioned.next();
                continue;
            }
            let address: [u8; 32] = key[versioned_prefix.len()..versioned_prefix.len() + 32]
                .try_into()
                .unwrap();
            let mut entry_prefix = versioned_prefix.clone();
            entry_prefix.extend_from_slice(&address);
            let mut upper = entry_prefix.clone();
            upper.extend_from_slice(&u64::MAX.to_be_bytes());
            versioned.seek_for_prev(&upper);
            let mut selected = None;
            // Other-length keys may interleave with versions. Walk past
            // those only; the first exact key is the latest fixed-key row.
            while versioned.valid() {
                let key = versioned.key().unwrap();
                if !key.starts_with(&entry_prefix) {
                    break;
                }
                if key.len() == entry_prefix.len() + 8 {
                    let blob = if skip(&address) { Some(Vec::new()) } else { copy_blob(versioned.value().unwrap()) };
                    selected = Some((address, blob));
                    break;
                }
                versioned.prev();
            }
            versioned
                .status()
                .map_err(|e| QuilError::Store(e.to_string()))?;
            let selected = selected.ok_or_else(|| {
                QuilError::Store("fixed MVCC vertex vanished within snapshot".into())
            })?;
            // Seek beyond every version of this address, not just the
            // chosen version, and handle the final all-ff address explicitly.
            let mut next = address;
            if let Some(index) = next.iter().rposition(|&b| b != 255) {
                next[index] += 1;
                next[index + 1..].fill(0);
                let mut lower = versioned_prefix.clone();
                lower.extend_from_slice(&next);
                versioned.seek(&lower);
            } else {
                versioned_done = true;
            }
            versioned
                .status()
                .map_err(|e| QuilError::Store(e.to_string()))?;
            return Ok(Some(selected));
        }
        versioned
            .status()
            .map_err(|e| QuilError::Store(e.to_string()))?;
        Ok(None)
    };
    let mut left = next_legacy()?;
    let mut right = next_versioned()?;
    let mut used: usize = 0;
    while left.is_some() || right.is_some() {
        if page.entries.len() == limits.max_entries {
            page.has_more = true;
            break;
        }
        let use_v2 = match (&left, &right) {
            (_, None) => false,
            (None, _) => true,
            (Some((a, _)), Some((b, _))) => b <= a,
        };
        let (address, blob) = if use_v2 {
            right.take().unwrap()
        } else {
            left.take().unwrap()
        };
        // Passed over exactly like a returned row, but neither returned nor
        // counted against the page, however large.
        if skip(&address) {
            if use_v2 {
                right = next_versioned()?;
                if left.as_ref().is_some_and(|(legacy_address, _)| *legacy_address == address) {
                    left = next_legacy()?;
                }
            } else {
                left = next_legacy()?;
            }
            continue;
        }
        let cost = blob.as_ref().and_then(|b| used.checked_add(64 + b.len()));
        if cost.is_none_or(|bytes| bytes > limits.max_bytes) {
            if page.entries.is_empty() {
                return Err(QuilError::InvalidArgument(
                    "vertex row exceeds page byte limit".into(),
                ));
            }
            page.has_more = true;
            break;
        }
        used = cost.unwrap();
        page.entries.push((address, blob.unwrap()));
        if use_v2 {
            right = next_versioned()?;
            if left
                .as_ref()
                .is_some_and(|(legacy_address, _)| *legacy_address == address)
            {
                left = next_legacy()?;
            }
        } else {
            left = next_legacy()?;
        }
    }
    Ok(page)
}

macro_rules! impl_hypergraph_snapshot {
    ($snapshot:ty) => {
impl SnapshotReadable for $snapshot {
    fn has_snapshot_vertex_reads(&self) -> bool {
        true
    }

    fn scan_point(&self) -> Option<quil_types::store::ScanPoint> {
        self.scan_point_backend()
    }

    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.snapshot.get(key).map_err(|e| QuilError::Store(e.to_string()))
    }

    fn page_vertex_underlying_fixed(
        &self, set_type: &str, phase_type: &str, shard: &ShardKey,
        domain: &[u8; 32], after: Option<&[u8; 32]>,
        limits: quil_types::store::VertexPageLimits,
    ) -> Result<quil_types::store::VertexDataPage> {
        page_fixed_vertices_at_snapshot(&self.snapshot, set_type, phase_type, shard, domain, after, limits, &|_| false)
    }

    fn page_vertex_underlying_fixed_skipping(
        &self, set_type: &str, phase_type: &str, shard: &ShardKey,
        domain: &[u8; 32], after: Option<&[u8; 32]>,
        limits: quil_types::store::VertexPageLimits, skip: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<quil_types::store::VertexDataPage> {
        page_fixed_vertices_at_snapshot(&self.snapshot, set_type, phase_type, shard, domain, after, limits, skip)
    }

    fn load_tree_blob(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &quil_types::store::ShardKey,
    ) -> Result<Option<Vec<u8>>> {
        let key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        // Reads at the captured sequence — point-in-time consistent.
        self.snapshot
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Per-node read at the captured sequence. MUST mirror
    /// `RocksHypergraphStore::get_node_by_path` (SeekGE + prefix
    /// compression) exactly, but bound to the snapshot so a whole-tree
    /// walk is isolated from concurrent commits.
    fn get_node_by_path(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &quil_types::store::ShardKey,
        path: &[i32],
    ) -> Result<Option<Vec<u8>>> {
        let prefix = hypergraph_tree_node_by_path_prefix(set_type, phase_type, shard_key);
        let requested = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
        let mut iter = self.snapshot.raw_iterator();
        iter.seek(&requested);
        iter.status().map_err(|e| QuilError::Store(e.to_string()))?;
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
        if !found_key.starts_with(&requested) {
            return Ok(None);
        }
        let by_key = match iter.value() {
            Some(v) => v.to_vec(),
            None => return Ok(None),
        };
        self.snapshot
            .get(&by_key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn load_vertex_underlying_raw(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &quil_types::store::ShardKey,
        vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // MVCC "latest at capture" within the pinned snapshot: seek_for_prev to
        // `vk_prefix ‖ u64::MAX`; the largest key still sharing `vk_prefix` (which
        // is exactly `vk_prefix.len() + 8` bytes) is this vertex's latest version
        // as-of the captured sequence. Mirrors the live `load_vertex_underlying_at`.
        let vk_prefix = crate::encoding::hypergraph_vertex_data_v2_vk_prefix(
            set_type, phase_type, shard_key, vertex_key,
        );
        let seek = crate::encoding::hypergraph_vertex_data_v2_key(
            set_type, phase_type, shard_key, vertex_key, u64::MAX,
        );
        let mut iter = self.snapshot.raw_iterator();
        iter.seek_for_prev(&seek);
        // An iterator read failure must not become authenticated absence via
        // the legacy fallback, particularly during history reconstruction.
        iter.status().map_err(|error| QuilError::Store(error.to_string()))?;
        if iter.valid() {
            if let Some(k) = iter.key() {
                if k.len() == vk_prefix.len() + 8 && k.starts_with(&vk_prefix) {
                    return Ok(iter.value().map(|v| v.to_vec()));
                }
            }
        }
        // Legacy fallback: an un-migrated (unversioned) blob captured before the
        // version dimension existed.
        let key = hypergraph_vertex_data_key(set_type, phase_type, shard_key, vertex_key);
        self.snapshot
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }
}

    };
}
impl_hypergraph_snapshot!(RocksHypergraphSnapshot);
impl_hypergraph_snapshot!(OverlayHypergraphSnapshot);

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

    fn get_node_by_path(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &quil_types::store::ShardKey,
        path: &[i32],
    ) -> Result<Option<Vec<u8>>> {
        // Live fallback (not isolated) — delegates to the HypergraphStore impl.
        <Self as HypergraphStore>::get_node_by_path(self, set_type, phase_type, shard_key, path)
    }

    fn load_vertex_underlying_raw(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &quil_types::store::ShardKey,
        vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // Live fallback (not isolated) — delegate to the HypergraphStore impl so
        // the versioned (v2) latest ∪ legacy keyspace is read, not legacy only.
        <Self as HypergraphStore>::load_vertex_underlying_raw(
            self, set_type, phase_type, shard_key, vertex_key,
        )
    }
}

/// RocksDB Transaction — wraps a WriteBatch for atomicity.
pub(crate) struct RocksTxn {
    pub(crate) batch: std::sync::Mutex<rocksdb::WriteBatch>,
    db: quil_forest::CoordinatedDb,
    #[cfg(any(test, feature = "test-utils"))]
    fail_commit: bool,
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
        #[cfg(any(test, feature = "test-utils"))]
        if self.fail_commit { return Err(QuilError::Store("injected final write failure".into())); }
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

impl RocksTxn {
    fn for_store<'a>(txn: &'a dyn Transaction, db: &quil_forest::CoordinatedDb) -> Result<&'a RocksTxn> {
        let txn = Self::from_dyn(txn)?;
        if !txn.db.same_database(db) {
            return Err(QuilError::Store("hypergraph transaction belongs to another database".into()));
        }
        Ok(txn)
    }

    /// Recover the concrete `RocksTxn` from the `&dyn Transaction` that the
    /// [`HypergraphStore`] trait hands every writer. The trait must stay
    /// `dyn`-typed (it has several store implementors and is used as
    /// `Arc<dyn HypergraphStore>`), but every txn reaching a
    /// `RocksHypergraphStore` write is obtained from [`new_transaction`],
    /// which always yields a `RocksTxn` — so this downcast always succeeds
    /// in practice.
    ///
    /// It deliberately errors (rather than letting the caller fall back to a
    /// direct `db.put`/`db.delete`) for an unrecognized txn: a silent direct
    /// write would persist outside the caller's transaction, breaking the
    /// atomicity these writers exist to provide (and masking bugs like a
    /// no-op txn leaking writes to disk — the defect that made
    /// `compute_shard_root` non-read-only). An unrecognized txn is a
    /// programming error and is surfaced loudly.
    ///
    /// [`HypergraphStore`]: quil_types::store::HypergraphStore
    /// [`new_transaction`]: quil_types::store::HypergraphStore::new_transaction
    fn from_dyn(txn: &dyn Transaction) -> Result<&RocksTxn> {
        txn.as_any().downcast_ref::<RocksTxn>().ok_or_else(|| {
            QuilError::Internal(
                "hypergraph store write requires a RocksTxn; refusing to write outside the transaction"
                    .into(),
            )
        })
    }
}

impl RocksHypergraphStore {
    fn new_transaction_backend(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
        Ok(Box::new(RocksTxn {
            batch: std::sync::Mutex::new(rocksdb::WriteBatch::default()),
            db: self.db.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            fail_commit: self.fail_commit.load(std::sync::atomic::Ordering::Relaxed),
        }))
    }

    fn apply_snapshot_backend(&self, db_path: &str) -> Result<()> {
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

    fn capture_tree_snapshot_backend(&self) -> Result<Option<Arc<dyn SnapshotReadable>>> {
        let snap = RocksHypergraphSnapshot::capture(self.db.clone())?;
        Ok(Some(Arc::new(snap) as Arc<dyn SnapshotReadable>))
    }

}

include!("hypergraph_core.rs");

#[cfg(test)]
#[path = "hypergraph_overlay_tests.rs"]
mod overlay_tests;

#[cfg(test)]
#[path = "hypergraph_capture_tests.rs"]
mod capture_tests;

#[cfg(test)]
#[path = "hypergraph_retention_tests.rs"]
mod retention_tests;

#[cfg(test)]
#[path = "hypergraph_orphaned_head_tests.rs"]
mod orphaned_head_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rocksdb_store::RocksDb;
    use tempfile::TempDir;

    #[test]
    fn committed_shard_checkpoint_excludes_staging_and_survives_failed_commit_and_reopen() {
        use quil_hypergraph::{HypergraphCrdt, Location};
        use std::sync::atomic::Ordering;
        for unified in [false, true] {
            let dir = TempDir::new().unwrap();
            let app = [7; 32];
            let filter = [app.as_slice(), &[0]].concat();
            let cursor = crate::encoding::consensus_materialized_cursor_key(&filter);
            let history = crate::encoding::clock_shard_frame_fee_total_key(&filter, 2);
            let first = Location { app_address: app, data_address: [1; 32] };
            let second = Location { app_address: app, data_address: [2; 32] };
            let committed_roots;
            {
                let db = RocksDb::open(dir.path()).unwrap();
                let store = Arc::new(RocksHypergraphStore::new(db.inner()));
                let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
                crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
                crdt.set_app_shard_prefixes(app, (0..64).map(|n| vec![n]).collect());
                crdt.set_unified_tree(unified);
                let empty = crdt.capture_committed_shard(&filter).unwrap();
                assert_eq!(empty.roots, [[0; 32]; 4]);
                assert!(empty.records.read_record(&cursor).unwrap().is_none());
                crdt.add_vertex(&first, b"first").unwrap();
                crdt.commit_with_frame_cursor(1, &cursor).unwrap();
                let before = crdt.capture_committed_shard(&filter).unwrap();
                assert_ne!(before.roots[0], [0; 32]);
                assert_eq!(before.records.read_record(&cursor).unwrap(), Some(1u64.to_be_bytes().to_vec()));
                crdt.add_vertex(&second, b"second").unwrap();
                assert_eq!(crdt.capture_committed_shard(&filter).unwrap().roots, before.roots);
                store.fail_commit.store(true, Ordering::Relaxed);
                let records = vec![(history.clone(), 123u128.to_be_bytes().to_vec())];
                assert!(crdt.commit_with_frame_cursor_and_records(2, &cursor, &records).is_err());
                let failed = crdt.capture_committed_shard(&filter).unwrap();
                assert_eq!(failed.roots, before.roots);
                assert_eq!(failed.records.read_record(&cursor).unwrap(), Some(1u64.to_be_bytes().to_vec()));
                assert!(failed.records.read_record(&history).unwrap().is_none());
                store.fail_commit.store(false, Ordering::Relaxed);
                crdt.commit_with_frame_cursor_and_records(2, &cursor, &records).unwrap();
                let after = crdt.capture_committed_shard(&filter).unwrap();
                committed_roots = after.roots;
                assert_ne!(after.roots, before.roots);
                assert_eq!(after.records.read_record(&cursor).unwrap(), Some(2u64.to_be_bytes().to_vec()));
                assert_eq!(after.records.read_record(&history).unwrap(), Some(123u128.to_be_bytes().to_vec()));
                assert_eq!(before.records.read_record(&cursor).unwrap(), Some(1u64.to_be_bytes().to_vec()));
                assert!(before.records.read_record(&history).unwrap().is_none());
                let sentinel = quil_forest::encode_shard_bit_path(&app, &[false; 6]);
                assert_eq!(crdt.capture_committed_shard(&sentinel).unwrap().roots, committed_roots);
            }
            let db = RocksDb::open(dir.path()).unwrap();
            let store = Arc::new(RocksHypergraphStore::new(db.inner()));
            let reopened = HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver));
            reopened.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
            reopened.set_app_shard_prefixes(app, (0..64).map(|n| vec![n]).collect());
            reopened.set_unified_tree(unified);
            let checkpoint = reopened.capture_committed_shard(&filter).unwrap();
            assert_eq!(checkpoint.roots, committed_roots);
            assert_eq!(checkpoint.records.read_record(&cursor).unwrap(), Some(2u64.to_be_bytes().to_vec()));
        }
    }

    #[test]
    fn history_checkpoint_is_atomic_rejects_stale_state_and_leaves_pending_mutations() {
        use quil_hypergraph::{HypergraphCrdt, Location};
        let dir = TempDir::new().unwrap();
        let app = [7; 32];
        let cursor = crate::encoding::consensus_materialized_cursor_key(&app);
        let history = crate::encoding::clock_shard_frame_fee_total_key(&app, 1);
        let marker = crate::encoding::app_history_recovery_key(&app, &[8; 32]);
        let first = Location { app_address: app, data_address: [1; 32] };
        let pending = Location { app_address: app, data_address: [2; 32] };
        let open = || {
            let db = RocksDb::open(dir.path()).unwrap();
            let store = Arc::new(RocksHypergraphStore::new(db.inner()));
            let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
            crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
            (db, store, crdt)
        };
        {
            let (_db, store, crdt) = open();
            crdt.add_vertex(&first, b"first").unwrap();
            crdt.commit_with_frame_cursor(1, &cursor).unwrap();
            let before = crdt.capture_committed_shard(&app).unwrap();
            crdt.add_vertex(&pending, b"pending").unwrap();
            let records = vec![(history.clone(), 17u128.to_be_bytes().to_vec()),
                (marker.clone(), b"through frame one".to_vec())];
            store.fail_commit_for_test(true);
            assert!(crdt.checkpoint_shard_records(&app, &before.roots, &cursor, 1, &records).is_err());
            let failed = crdt.capture_committed_shard(&app).unwrap();
            assert_eq!(failed.roots, before.roots);
            assert!(failed.records.read_record(&history).unwrap().is_none());
            assert!(failed.records.read_record(&marker).unwrap().is_none());
            store.fail_commit_for_test(false);
            assert!(crdt.checkpoint_shard_records(&app, &before.roots, &cursor, 2, &records).is_err());
            assert!(crdt.checkpoint_shard_records(&app, &[[0; 32]; 4], &cursor, 1, &records).is_err());
            crdt.checkpoint_shard_records(&app, &before.roots, &cursor, 1, &records).unwrap();
            let repaired = crdt.capture_committed_shard(&app).unwrap();
            assert_eq!(repaired.roots, before.roots);
            assert_eq!(repaired.records.read_record(&cursor).unwrap(), Some(1u64.to_be_bytes().to_vec()));
            for (key, value) in &records {
                assert!(before.records.read_record(key).unwrap().is_none());
                assert_eq!(repaired.records.read_record(key).unwrap().as_ref(), Some(value));
            }
            let shard = quil_hypergraph::shard_key_for_location(&pending);
            assert!(repaired.records.load_vertex_underlying_raw("vertex", "adds", &shard, &pending.to_id()).unwrap().is_none());
            assert_eq!(crdt.get_vertex_data_checked(&pending).unwrap(), Some(b"pending".to_vec()));
            // Recovery neither flushes nor discards staged execution.
            crdt.commit_with_frame_cursor(2, &cursor).unwrap();
            let advanced = crdt.capture_committed_shard(&app).unwrap();
            assert_ne!(advanced.roots, before.roots);
            let rejected = vec![(marker.clone(), b"stale".to_vec())];
            assert!(crdt.checkpoint_shard_records(&app, &before.roots, &cursor, 2, &rejected).is_err());
            assert!(crdt.checkpoint_shard_records(&app, &advanced.roots, &cursor, 1, &rejected).is_err());
        }
        let (_db, _store, reopened) = open();
        let recovered = reopened.capture_committed_shard(&app).unwrap();
        assert_eq!(recovered.records.read_record(&marker).unwrap(), Some(b"through frame one".to_vec()));
        assert_eq!(recovered.records.read_record(&history).unwrap(), Some(17u128.to_be_bytes().to_vec()));
        assert_eq!(recovered.records.read_record(&cursor).unwrap(), Some(2u64.to_be_bytes().to_vec()));
        assert_eq!(reopened.get_vertex_data_checked(&pending).unwrap(), Some(b"pending".to_vec()));
    }

    #[test]
    fn committed_shard_checkpoint_rejects_invalid_filters_and_missing_or_malformed_heads() {
        use quil_hypergraph::HypergraphCrdt;
        let dir = TempDir::new().unwrap();
        let db = RocksDb::open(dir.path()).unwrap();
        let store = Arc::new(RocksHypergraphStore::new(db.inner()));
        let crdt = HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver));
        assert!(crdt.capture_committed_shard(&[7; 32]).is_err(), "an unwired in-memory forest is not committed empty state");
        let forest = quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE);
        crdt.set_forest(forest.clone());
        let app = [7; 32];
        for invalid in [vec![], vec![7; 31], [app.as_slice(), &[64]].concat(),
            quil_forest::encode_shard_bit_path(&app, &[false; 257])] {
            assert!(crdt.capture_committed_shard(&invalid).is_err());
        }
        assert!(crdt.capture_committed_shard(&[app.as_slice(), &[0]].concat()).is_err(), "unregistered legacy child");
        for unified in [false, true] {
            crdt.set_unified_tree(unified);
            let (head, value) = forest.head_version_put(&app, quil_forest::Phase::VertexAdds, 9).unwrap();
            db.inner().put(&head, value).unwrap();
            assert!(crdt.capture_committed_shard(&app).is_err(), "known phase head without a root");
            db.inner().put(&head, [0]).unwrap();
            assert!(crdt.capture_committed_shard(&app).is_err(), "malformed phase head");
            db.inner().delete(head).unwrap();
        }
    }

    #[test]
    fn crdt_failed_transaction_retries_without_losing_writes_or_advancing_roots() {
        use quil_hypergraph::{HypergraphCrdt, Location};
        use std::sync::atomic::Ordering;
        let first = Location { app_address: [7; 32], data_address: [8; 32] };
        let second = Location { app_address: [7; 32], data_address: [9; 32] };
        let cursor = b"test/materialized-frame";
        for baseline in [false, true] {
            let dir = TempDir::new().unwrap();
            let db = Arc::new(RocksDb::open(dir.path()).unwrap());
            let store = Arc::new(RocksHypergraphStore::new(db.inner()));
            let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
            crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
            if baseline {
                crdt.add_vertex(&first, b"first").unwrap();
                crdt.commit_with_global_cursor(1, cursor).unwrap();
            }
            let old_roots = crdt.global_commitments();
            let shard = quil_hypergraph::shard_key_for_location(&second);
            let old_phase_root = crdt.compute_shard_root("vertex", "adds", &shard);
            let metadata = |c: &HypergraphCrdt| c.shard_metadata_for_address(&second.app_address)
                .map(|m| (m.commitment, m.leaf_count, m.size));
            let old_metadata = metadata(&crdt);
            let old_cursor = db.inner().get(cursor).unwrap();
            crdt.add_vertex(&second, b"second").unwrap();
            store.fail_commit.store(true, Ordering::Relaxed);
            for _ in 0..2 {
                assert!(crdt.commit_with_global_cursor(2, cursor).unwrap_err().is_execution_unavailable());
                assert_eq!(crdt.global_commitments(), old_roots);
                assert_eq!(crdt.compute_shard_root("vertex", "adds", &shard), old_phase_root);
                assert_eq!(metadata(&crdt), old_metadata);
                assert_eq!(db.inner().get(cursor).unwrap(), old_cursor);
                assert!(HypergraphStore::load_vertex_underlying_raw(store.as_ref(), "vertex", "adds", &shard, &second.to_id()).unwrap().is_none());
                assert_eq!(crdt.get_vertex_data_checked(&second).unwrap(), Some(b"second".to_vec()));
            }
            store.fail_commit.store(false, Ordering::Relaxed);
            // No re-staging: the failed commits must have retained both maps.
            crdt.commit_with_global_cursor(2, cursor).unwrap();
            let committed_roots = crdt.global_commitments();
            assert_ne!(committed_roots, old_roots);
            assert_eq!(db.inner().get(cursor).unwrap(), Some(2u64.to_be_bytes().to_vec()));
            drop(crdt); drop(store); drop(db);
            let db = Arc::new(RocksDb::open(dir.path()).unwrap());
            let store = Arc::new(RocksHypergraphStore::new(db.inner()));
            let reopened = HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver));
            reopened.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
            assert_eq!(reopened.global_commitments(), committed_roots);
            assert_eq!(reopened.get_vertex_data_checked(&second).unwrap(), Some(b"second".to_vec()));
            if baseline { assert_eq!(reopened.get_vertex_data_checked(&first).unwrap(), Some(b"first".to_vec())); }
        }
    }

    #[test]
    fn app_cursor_sync_checkpoint_retries_without_flushing_pending_state() {
        use quil_hypergraph::{HypergraphCrdt, Location};
        use std::sync::atomic::Ordering;
        let directory = TempDir::new().unwrap();
        let application = [17; 32];
        let cursor = crate::encoding::consensus_materialized_cursor_key(&application);
        let location = Location { app_address: application, data_address: [19; 32] };
        {
            let db = Arc::new(RocksDb::open(directory.path()).unwrap());
            let store = Arc::new(RocksHypergraphStore::new(db.inner()));
            let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
            crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
            crdt.checkpoint_frame_cursor(1, &cursor).unwrap();
            crdt.add_vertex(&location, b"pending after sync").unwrap();
            store.fail_commit.store(true, Ordering::Relaxed);
            assert!(crdt.checkpoint_frame_cursor(2, &cursor).is_err());
            assert_eq!(crdt.read_frame_cursor(&cursor).unwrap(), 1);
            store.fail_commit.store(false, Ordering::Relaxed);
            crdt.checkpoint_frame_cursor(2, &cursor).unwrap();
            assert_eq!(crdt.read_frame_cursor(&cursor).unwrap(), 2);
            let shard = quil_hypergraph::shard_key_for_location(&location);
            assert!(HypergraphStore::load_vertex_underlying_raw(store.as_ref(), "vertex", "adds",
                &shard, &location.to_id()).unwrap().is_none());
            // The cursor-only transaction neither published nor consumed the pending write.
            crdt.commit_with_frame_cursor(3, &cursor).unwrap();
        }
        let db = Arc::new(RocksDb::open(directory.path()).unwrap());
        let store = Arc::new(RocksHypergraphStore::new(db.inner()));
        let crdt = HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
        assert_eq!(crdt.read_frame_cursor(&cursor).unwrap(), 3);
        assert_eq!(crdt.get_vertex_data_checked(&location).unwrap(), Some(b"pending after sync".to_vec()));
    }

    #[test]
    fn app_cursor_and_history_are_atomic_with_state_and_reopen_from_the_state_store() {
        use quil_hypergraph::{HypergraphCrdt, Location};
        use std::sync::atomic::Ordering;
        let directory = TempDir::new().unwrap();
        let application = [7; 32];
        let cursor = crate::encoding::consensus_materialized_cursor_key(&application);
        let global_cursor = crate::encoding::global_materialized_cursor_key();
        let location = Location { app_address: application, data_address: [9; 32] };
        let history = vec![
            (crate::encoding::clock_shard_frame_fee_total_key(&application, 2), 123u128.to_be_bytes().to_vec()),
            (crate::encoding::clock_shard_frame_settlements_key(&application, 2), vec![4; 12]),
            (crate::encoding::clock_shard_frame_spends_key(&application, 2), vec![5; 12]),
            (crate::encoding::clock_shard_frame_accumulator_key(&application, 2), vec![6; 32]),
            (crate::encoding::clock_shard_accumulator_report_key(&application, &[6; 32]), vec![7; 128]),
        ];
        {
            let db = Arc::new(RocksDb::open(directory.path()).unwrap());
            let store = Arc::new(RocksHypergraphStore::new(db.inner()));
            let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
            crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
            assert_eq!(crdt.read_frame_cursor(&cursor).unwrap(), 0);
            db.inner().put(&global_cursor, 77u64.to_be_bytes()).unwrap();
            crdt.commit_with_frame_cursor(1, &cursor).unwrap();
            crdt.add_vertex(&location, b"committed with cursor").unwrap();
            store.fail_commit.store(true, Ordering::Relaxed);
            assert!(crdt.commit_with_frame_cursor_and_records(2, &cursor, &history).is_err());
            assert_eq!(crdt.read_frame_cursor(&cursor).unwrap(), 1);
            for (key, _) in &history { assert!(db.inner().get(key).unwrap().is_none()); }
            let shard = quil_hypergraph::shard_key_for_location(&location);
            assert!(HypergraphStore::load_vertex_underlying_raw(store.as_ref(), "vertex", "adds", &shard, &location.to_id()).unwrap().is_none());
            store.fail_commit.store(false, Ordering::Relaxed);
            crdt.commit_with_frame_cursor_and_records(2, &cursor, &history).unwrap();
            assert_eq!(crdt.read_frame_cursor(&cursor).unwrap(), 2);
            assert_eq!(db.inner().get(&global_cursor).unwrap(), Some(77u64.to_be_bytes().to_vec()));
        }
        let db = Arc::new(RocksDb::open(directory.path()).unwrap());
        let store = Arc::new(RocksHypergraphStore::new(db.inner()));
        let crdt = HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
        assert_eq!(crdt.read_frame_cursor(&cursor).unwrap(), 2);
        assert_eq!(crdt.get_vertex_data_checked(&location).unwrap(), Some(b"committed with cursor".to_vec()));
        for (key, value) in &history { assert_eq!(db.inner().get(key).unwrap().as_ref(), Some(value)); }
        for malformed in [vec![0; 7], vec![0; 9]] {
            db.inner().put(&cursor, malformed).unwrap();
            assert!(crdt.read_frame_cursor(&cursor).is_err());
        }
    }

    #[test]
    fn crdt_commit_rejects_corrupt_heads_and_retries_after_repair() {
        use quil_hypergraph::{HypergraphCrdt, Location};
        use quil_forest::{Forest, Phase};
        let location = Location { app_address: [7; 32], data_address: [8; 32] };
        for global in [false, true] {
            for bad in [vec![1], 99u64.to_be_bytes().to_vec()] {
                let dir = TempDir::new().unwrap();
                let db = Arc::new(RocksDb::open(dir.path()).unwrap());
                let store = Arc::new(RocksHypergraphStore::new(db.inner()));
                let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
                crdt.set_forest(Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
                crdt.add_vertex(&location, b"old").unwrap();
                crdt.commit(1).unwrap();
                drop(crdt);
                let forest = Forest::with_namespace(db.inner(), FOREST_NAMESPACE);
                let (head_key, _) = if global { forest.global_head_version_put(7, 0) }
                    else { forest.head_version_put(&location.app_address, Phase::VertexAdds, 0) }.unwrap();
                let valid = db.inner().get(&head_key).unwrap().unwrap();
                db.inner().put(&head_key, &bad).unwrap();
                let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
                crdt.set_forest(forest);
                crdt.add_vertex(&location, b"new").unwrap();
                let cursor = b"test/corrupt-head-cursor";
                assert!(crdt.commit_with_global_cursor(2, cursor).unwrap_err().is_execution_unavailable());
                assert!(db.inner().get(cursor).unwrap().is_none());
                let shard = quil_hypergraph::shard_key_for_location(&location);
                assert_eq!(HypergraphStore::load_vertex_underlying_raw(store.as_ref(), "vertex", "adds", &shard,
                    &location.to_id()).unwrap(), Some(b"old".to_vec()));
                db.inner().put(&head_key, valid).unwrap();
                // Failure retained the staged update; repair does not restage it.
                crdt.commit_with_global_cursor(2, cursor).unwrap();
                assert_eq!(HypergraphStore::load_vertex_underlying_raw(store.as_ref(), "vertex", "adds", &shard,
                    &location.to_id()).unwrap(), Some(b"new".to_vec()));
                assert_eq!(db.inner().get(cursor).unwrap(), Some(2u64.to_be_bytes().to_vec()));
            }
        }
    }

    #[test]
    fn crdt_append_preserves_unmarked_migration_trees_and_other_apps() {
        use quil_hypergraph::{HypergraphCrdt, Location};
        use quil_forest::{Forest, Phase};
        let app = [7; 32];
        let mut other_app = app; other_app[31] = 9; // same L1 bucket
        let first = Location { app_address: app, data_address: [1; 32] };
        let next = Location { app_address: app, data_address: [2; 32] };
        let other = Location { app_address: other_app, data_address: [3; 32] };
        let run = |unmarked: bool| {
            let dir = TempDir::new().unwrap();
            let db = Arc::new(RocksDb::open(dir.path()).unwrap());
            let store = Arc::new(RocksHypergraphStore::new(db.inner()));
            let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
            crdt.set_forest(Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
            crdt.add_vertex(&first, b"first").unwrap();
            crdt.add_vertex(&other, b"other-app").unwrap();
            crdt.commit(1).unwrap();
            drop(crdt);
            let forest = Forest::with_namespace(db.inner(), FOREST_NAMESPACE);
            if unmarked {
                // Simulate migration output retaining version-zero trees but
                // lacking the later head-marker convention.
                let (phase_key, _) = forest.head_version_put(&app, Phase::VertexAdds, 0).unwrap();
                let (global_key, _) = forest.global_head_version_put(7, 0).unwrap();
                db.inner().delete(phase_key).unwrap();
                db.inner().delete(global_key).unwrap();
            }
            let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
            crdt.set_forest(forest);
            crdt.add_vertex(&next, b"next").unwrap();
            crdt.commit(2).unwrap();
            let roots = crdt.global_commitments();
            let phase = crdt.compute_shard_root("vertex", "adds", &quil_hypergraph::shard_key_for_location(&first));
            drop(crdt); drop(store); drop(db);
            let db = Arc::new(RocksDb::open(dir.path()).unwrap());
            let forest = Forest::with_namespace(db.inner(), FOREST_NAMESPACE);
            assert_eq!(forest.read_head_version(&app, Phase::VertexAdds).unwrap(), Some(1));
            assert_eq!(forest.read_global_head_version(7).unwrap(), Some(1));
            let reopened = HypergraphCrdt::new(Arc::new(RocksHypergraphStore::new(db.inner())),
                Arc::new(quil_types::crypto::NoopInclusionProver));
            reopened.set_forest(forest);
            assert_eq!(reopened.global_commitments(), roots);
            assert_eq!(reopened.get_vertex_data_checked(&first).unwrap(), Some(b"first".to_vec()));
            assert_eq!(reopened.get_vertex_data_checked(&next).unwrap(), Some(b"next".to_vec()));
            assert_eq!(reopened.get_vertex_data_checked(&other).unwrap(), Some(b"other-app".to_vec()));
            (roots, phase)
        };
        // Equal commitments prove that the old leaf and untouched app are
        // retained in the forest, not merely in the underlying blob store.
        assert_eq!(run(true), run(false));
    }

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

    }

    // The registry-refresh path (`for_each_vertex_underlying`) must see blobs
    // written by the versioned commit path, or provers vanish from the registry.
    #[test]
    fn test_for_each_reads_versioned_and_legacy() {
        use quil_types::store::HypergraphStore as _;
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = RocksHypergraphStore::new(Arc::new(db).inner());
        let shard = ShardKey { l1: [1, 2, 3], l2: [0xffu8; 32] };

        // A v2 (versioned-commit) vertex and a legacy (pre-migration) vertex.
        let vk_v2 = vec![0xAAu8; 64];
        let vk_legacy = vec![0xBBu8; 64];
        let txn = store.new_transaction(false).unwrap();
        store.save_vertex_underlying_versioned(txn.as_ref(), "vertex", "adds", &shard, &vk_v2, b"newest", 2).unwrap();
        store.save_vertex_underlying_versioned(txn.as_ref(), "vertex", "adds", &shard, &vk_v2, b"OLD", 1).unwrap();
        txn.commit().unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &vk_legacy, b"legacy").unwrap();

        let mut seen: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();
        store.for_each_vertex_underlying("vertex", "adds", &shard, |vk: Vec<u8>, d: Vec<u8>| {
            seen.insert(vk, d);
        }).unwrap();
        assert_eq!(seen.get(&vk_v2).map(|v| v.as_slice()), Some(&b"newest"[..]), "v2 latest version");
        assert_eq!(seen.get(&vk_legacy).map(|v| v.as_slice()), Some(&b"legacy"[..]), "legacy fallback");
        assert_eq!(seen.len(), 2);
    }

    // A captured snapshot must read the versioned (v2) latest blob too, or a
    // generation-isolated read (sync full-load) would miss committed state.
    #[test]
    fn test_snapshot_reads_versioned_latest() {
        use quil_types::store::{HypergraphStore as _, SnapshotReadable as _};
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = RocksHypergraphStore::new(Arc::new(db).inner());
        let shard = ShardKey { l1: [9, 9, 9], l2: [0x77u8; 32] };
        let vk = vec![0xCDu8; 48];

        let txn = store.new_transaction(false).unwrap();
        store.save_vertex_underlying_versioned(txn.as_ref(), "vertex", "adds", &shard, &vk, b"gen-old", 1).unwrap();
        store.save_vertex_underlying_versioned(txn.as_ref(), "vertex", "adds", &shard, &vk, b"gen-new", 2).unwrap();
        txn.commit().unwrap();

        // Live adapter (SnapshotReadable for RocksHypergraphStore) → v2 latest.
        assert_eq!(
            SnapshotReadable::load_vertex_underlying_raw(&store, "vertex", "adds", &shard, &vk).unwrap().as_deref(),
            Some(&b"gen-new"[..])
        );
        // Captured snapshot → v2 latest at capture.
        let snap = store.capture_snapshot().unwrap();
        assert_eq!(
            snap.load_vertex_underlying_raw("vertex", "adds", &shard, &vk).unwrap().as_deref(),
            Some(&b"gen-new"[..])
        );
    }

    // Versioned-snapshot sync building blocks: MVCC blob reads, root→version
    // resolution, and the 2-epoch pruner. Exercises the store half of the
    // versionless-blob race fix.
    #[test]
    fn test_versioned_blob_mvcc_resolve_and_prune() {
        use quil_types::store::HypergraphStore as _;
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = RocksHypergraphStore::new(Arc::new(db).inner());

        let shard = ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
        let vk = vec![0x11u8; 32];

        // Three versioned writes of the same vertex at versions 1,2,3.
        let txn = store.new_transaction(false).unwrap();
        store.save_vertex_underlying_versioned(txn.as_ref(), "vertex", "adds", &shard, &vk, b"v1", 1).unwrap();
        store.save_vertex_underlying_versioned(txn.as_ref(), "vertex", "adds", &shard, &vk, b"v2", 2).unwrap();
        store.save_vertex_underlying_versioned(txn.as_ref(), "vertex", "adds", &shard, &vk, b"v3", 3).unwrap();
        // Root→(version,frame) index: rootA@(1,50), rootB@(2,100), rootC@(3,200).
        store.put_root_version(txn.as_ref(), "vertex", "adds", &shard.l2, &[0xA1u8; 32], 1, 50).unwrap();
        store.put_root_version(txn.as_ref(), "vertex", "adds", &shard.l2, &[0xB2u8; 32], 2, 100).unwrap();
        store.put_root_version(txn.as_ref(), "vertex", "adds", &shard.l2, &[0xC3u8; 32], 3, 200).unwrap();
        txn.commit().unwrap();

        // MVCC "latest write ≤ V".
        assert_eq!(store.load_vertex_underlying_at("vertex", "adds", &shard, &vk, 1).unwrap().as_deref(), Some(&b"v1"[..]));
        assert_eq!(store.load_vertex_underlying_at("vertex", "adds", &shard, &vk, 2).unwrap().as_deref(), Some(&b"v2"[..]));
        assert_eq!(store.load_vertex_underlying_at("vertex", "adds", &shard, &vk, 5).unwrap().as_deref(), Some(&b"v3"[..]));

        // Root resolution.
        assert_eq!(store.get_root_version("vertex", "adds", &shard.l2, &[0xB2u8; 32]).unwrap(), Some((2, 100)));

        // Prune at cull_frame=150 → tree watermark = max{ver : frame ≤ 150} = 2.
        let watermarks = store.prune_versioned(150).unwrap();
        assert_eq!(watermarks, vec![(shard.l2.to_vec(), 0usize, 2u64)]);

        // Blob version 1 (< watermark) is gone; 2 (the floor) and 3 remain.
        assert_eq!(store.load_vertex_underlying_at("vertex", "adds", &shard, &vk, 2).unwrap().as_deref(), Some(&b"v2"[..]));
        assert_eq!(store.load_vertex_underlying_at("vertex", "adds", &shard, &vk, 5).unwrap().as_deref(), Some(&b"v3"[..]));
        // rootA (ver 1 < watermark) is dropped from the index; rootB/rootC remain.
        assert_eq!(store.get_root_version("vertex", "adds", &shard.l2, &[0xA1u8; 32]).unwrap(), None);
        assert_eq!(store.get_root_version("vertex", "adds", &shard.l2, &[0xB2u8; 32]).unwrap(), Some((2, 100)));
        assert_eq!(store.get_root_version("vertex", "adds", &shard.l2, &[0xC3u8; 32]).unwrap(), Some((3, 200)));
    }

    #[test]
    fn forest_sync_chunks_keep_blobs_atomic_and_resume_after_reopen() {
        use quil_forest::{Forest, SubtreeSyncAnchor, PHASES};
        use quil_hypergraph::{HypergraphCrdt, Location};
        use std::sync::atomic::Ordering;

        let open = |path: &std::path::Path| {
            let db = Arc::new(RocksDb::open(path).unwrap());
            let store = Arc::new(RocksHypergraphStore::new(db.inner()));
            let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
            crdt.set_forest(Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
            (db, store, crdt)
        };
        let source_dir = TempDir::new().unwrap();
        let target_dir = TempDir::new().unwrap();
        let (source_db, _, source) = open(source_dir.path());
        let app = [0x21; 32];
        let location = |key| Location { app_address: app, data_address: [key; 32] };
        for key in 1..=3 { source.add_vertex(&location(key), &vec![key; 48]).unwrap(); }
        source.commit(1).unwrap();
        let (version, root) = source.serve_forest_head(&app, 0).unwrap();
        let source_forest = Forest::with_namespace(source_db.inner(), FOREST_NAMESPACE);
        let reader = source_forest.shard_phase_reader(&app, PHASES[0]);
        let blobs = |plan: &quil_hypergraph::crdt::ForestSyncPlan, count| {
            plan.remaining().iter().take(count).map(|(key, _)| vec![key[0]; 48]).collect::<Vec<_>>()
        };
        let first;
        {
            let (_db, store, target) = open(target_dir.path());
            let mut plan = target.prepare_phase_sync(&reader, version, &app, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
            assert_eq!(plan.remaining().len(), 3);
            // Preparing, or abandoning a failed download, publishes nothing.
            assert!(target.serve_forest_head(&app, 0).is_none());
            assert!(target.finish_phase_sync(&plan).is_err());
            first = plan.remaining()[0].0[0];
            assert!(target.apply_sync_chunk(&mut plan, &[b"wrong blob".to_vec()]).is_err());
            assert!(target.serve_forest_head(&app, 0).is_none());
            assert!(target.get_vertex_data_checked(&location(first)).unwrap().is_none());
            let first_blob = blobs(&plan, 1);
            target.apply_sync_chunk(&mut plan, &first_blob).unwrap();
            assert_eq!(target.get_vertex_data_checked(&location(first)).unwrap(), Some(vec![first; 48]));
            let committed = target.serve_forest_head(&app, 0).unwrap();
            assert_ne!(committed.1, root, "one chunk is not the complete sync");
            let next = plan.remaining()[0].0[0];
            let next_blob = blobs(&plan, 1);
            store.fail_commit.store(true, Ordering::Relaxed);
            assert!(target.apply_sync_chunk(&mut plan, &next_blob).is_err());
            assert_eq!(target.serve_forest_head(&app, 0), Some(committed));
            assert!(target.get_vertex_data_checked(&location(next)).unwrap().is_none());
            assert_eq!(plan.remaining().len(), 2, "failed commit must not consume the plan");
            // Drop the plan and process state while only the first chunk exists.
        }
        let (_target_db, _, target) = open(target_dir.path());
        let mut resumed = target.prepare_phase_sync(&reader, version, &app, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
        for key in (1..=3).filter(|key| *key != first) {
            assert!(resumed.remaining().iter().any(|(address, _)| address[0] == key),
                "a restarted diff must include every missing blob");
        }
        // A compressed singleton target can be returned again while the
        // source branches; replaying that already-complete leaf is harmless.
        let remaining = blobs(&resumed, resumed.remaining().len());
        target.apply_sync_chunk(&mut resumed, &remaining).unwrap();
        assert_eq!(target.finish_phase_sync(&resumed).unwrap(), root);
        for key in 1..=3 {
            assert_eq!(target.get_vertex_data_checked(&location(key)).unwrap(), Some(vec![key; 48]));
        }

        // Upgrade recovery: the old implementation could persist the complete
        // tree and then fail its very first blob fetch. Equal roots must not
        // hide this state, including after a partially completed repair.
        let broken_dir = TempDir::new().unwrap();
        {
            let (_db, _, broken) = open(broken_dir.path());
            broken.sync_shard_phase_from(&reader, version, &app, 0).unwrap();
            assert_eq!(broken.serve_forest_head(&app, 0).unwrap().1, root);
            assert!(broken.get_vertex_data_checked(&location(1)).unwrap().is_none());
            let mut repair = broken.prepare_phase_sync(&reader, version, &app, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
            assert_eq!(repair.remaining().len(), 3);
            let one = blobs(&repair, 1);
            broken.apply_sync_chunk(&mut repair, &one).unwrap();
            assert!(!broken.sync_data_ready(&app, 0, &[]).unwrap());
        }
        {
            let (_db, _, broken) = open(broken_dir.path());
            let mut repair = broken.prepare_phase_sync(&reader, version, &app, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
            assert_eq!(repair.remaining().len(), 3, "an unfinished legacy audit must resume");
            let all = blobs(&repair, 3);
            broken.apply_sync_chunk(&mut repair, &all).unwrap();
            assert_eq!(broken.finish_phase_sync(&repair).unwrap(), root);
            assert!(broken.sync_data_ready(&app, 0, &[]).unwrap());
            assert!(broken.prepare_phase_sync(&reader, version, &app, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root)))
                .unwrap().remaining().is_empty(), "verified data enables the cheap Merkle diff");
            for key in 1..=3 {
                assert_eq!(broken.get_vertex_data_checked(&location(key)).unwrap(), Some(vec![key; 48]));
            }
        }

        // Removal blobs are intentionally empty; their leaf retains the size
        // of the removed value. They must not be confused with a failed fetch.
        source.remove_vertex(&location(first)).unwrap();
        source.commit(2).unwrap();
        let (removed_version, removed_root) = source.serve_forest_head(&app, 1).unwrap();
        let removed_reader = source_forest.shard_phase_reader(&app, PHASES[1]);
        let mut removal = target.prepare_phase_sync(&removed_reader, removed_version, &app, 1, &[],
            Some(SubtreeSyncAnchor::AppRoot(removed_root))).unwrap();
        assert_eq!(removal.remaining().len(), 1);
        target.apply_sync_chunk(&mut removal, &[Vec::new()]).unwrap();
        assert_eq!(target.finish_phase_sync(&removal).unwrap(), removed_root);
        assert!(target.get_vertex_data_checked(&location(first)).unwrap().is_none());

        // A concurrent local commit invalidates a downloaded plan. It cannot
        // be overwritten or blended into an older certified source snapshot.
        source.add_vertex(&location(4), &[4; 48]).unwrap();
        source.commit(3).unwrap();
        let (version, root) = source.serve_forest_head(&app, 0).unwrap();
        let mut stale = target.prepare_phase_sync(&reader, version, &app, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
        let downloaded = blobs(&stale, 1);
        target.add_vertex(&location(5), &[5; 48]).unwrap();
        target.commit(4).unwrap();
        let before = target.serve_forest_head(&app, 0);
        assert!(target.apply_sync_chunk(&mut stale, &downloaded).is_err());
        assert_eq!(target.serve_forest_head(&app, 0), before);
        assert!(target.get_vertex_data_checked(&location(4)).unwrap().is_none());
        assert_eq!(target.get_vertex_data_checked(&location(5)).unwrap(), Some(vec![5; 48]));
        assert!(target.prepare_phase_sync(&reader, version, &app, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).is_err());
        assert_eq!(target.serve_forest_head(&app, 0), before, "failed reconstruction must publish no chunk");
    }

    #[test]
    fn global_sync_removal_is_atomic_resumable_and_preserves_history() {
        use quil_forest::{Forest, SubtreeSyncAnchor, PHASES};
        use quil_hypergraph::{HypergraphCrdt, Location};

        for phase in [0, 2] {
            let set = if phase == 0 { "vertex" } else { "hyperedge" };
            let add = if phase == 0 { HypergraphCrdt::add_vertex } else { HypergraphCrdt::add_hyperedge };
            let read = if phase == 0 { HypergraphCrdt::get_vertex_data_checked } else { HypergraphCrdt::get_hyperedge_data_checked };
            let open = |path: &std::path::Path| {
                let db = RocksDb::open(path).unwrap();
                let store = Arc::new(RocksHypergraphStore::new(db.inner()));
                let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
                crdt.set_forest(Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
                (db, store, crdt)
            };
            let source_dir = TempDir::new().unwrap();
            let target_dir = TempDir::new().unwrap();
            let app = [0xff; 32];
            let location = |key| Location { app_address: app, data_address: [key; 32] };
            let extra = location(1);
            let common = location(2);
            let new = location(3);
            let other = Location { app_address: [0x71; 32], data_address: [1; 32] };
            let shard = quil_hypergraph::shard_key_for_location(&extra);
            let (source_db, _, source) = open(source_dir.path());
            add(&source, &common, b"canonical").unwrap();
            add(&source, &new, b"new").unwrap();
            source.commit(1).unwrap();
            let (version, root) = source.serve_forest_head(&app, phase).unwrap();
            let reader = Forest::with_namespace(source_db.inner(), FOREST_NAMESPACE)
                .shard_phase_reader(&app, PHASES[phase]);
            let anchor = Some(SubtreeSyncAnchor::AppRoot(root));
            let old_version;
            {
                let (_db, store, target) = open(target_dir.path());
                add(&target, &extra, b"noncanonical join").unwrap();
                add(&target, &common, b"stale").unwrap();
                add(&target, &other, b"unrelated application").unwrap();
                target.commit(1).unwrap();
                let before = target.serve_forest_head(&app, phase).unwrap();
                old_version = before.0;
                let mut plan = target.prepare_phase_sync(&reader, version, &app, phase, &[], anchor).unwrap();
                assert_eq!(plan.remaining()[0], (extra.data_address, None));
                assert!(target.apply_sync_chunk(&mut plan, &[b"cannot write a deletion value".to_vec()]).is_err());
                store.fail_commit_for_test(true);
                assert!(target.apply_sync_chunk(&mut plan, &[Vec::new()]).is_err());
                assert_eq!(target.serve_forest_head(&app, phase), Some(before));
                assert_eq!(read(&target, &extra).unwrap(), Some(b"noncanonical join".to_vec()));
                assert_eq!(plan.remaining().len(), 3);
                store.fail_commit_for_test(false);
                target.apply_sync_chunk(&mut plan, &[Vec::new()]).unwrap();
                assert!(read(&target, &extra).unwrap().is_none());
                assert_eq!(store.load_vertex_underlying_at(set, "adds", &shard, &extra.to_id(), old_version).unwrap(), Some(b"noncanonical join".to_vec()));
                assert!(!target.sync_data_ready(&app, phase, &[]).unwrap());
                assert!(target.finish_phase_sync(&plan).is_err());
                // Reopen with the deletion committed but the two puts missing.
            }
            {
                let (_db, store, target) = open(target_dir.path());
                assert!(read(&target, &extra).unwrap().is_none());
                assert_eq!(read(&target, &common).unwrap(), Some(b"stale".to_vec()));
                let mut plan = target.prepare_phase_sync(&reader, version, &app, phase, &[], anchor).unwrap();
                assert_eq!(plan.remaining().len(), 2);
                let blobs = plan.remaining().iter().map(|(key, value)| {
                    assert!(value.is_some());
                    read(&source, &location(key[0])).unwrap().unwrap()
                }).collect::<Vec<_>>();
                target.apply_sync_chunk(&mut plan, &blobs).unwrap();
                assert_eq!(target.finish_phase_sync(&plan).unwrap(), root);
                assert!(target.sync_data_ready(&app, phase, &[]).unwrap());
                assert_eq!(store.load_vertex_underlying_at(set, "adds", &shard, &extra.to_id(), old_version).unwrap(), Some(b"noncanonical join".to_vec()));
            }
            let (_db, store, target) = open(target_dir.path());
            assert_eq!(target.serve_forest_head(&app, phase).unwrap().1, root);
            assert!(read(&target, &extra).unwrap().is_none());
            assert_eq!(read(&target, &common).unwrap(), Some(b"canonical".to_vec()));
            assert_eq!(read(&target, &new).unwrap(), Some(b"new".to_vec()));
            assert_eq!(read(&target, &other).unwrap(), Some(b"unrelated application".to_vec()));
            assert_eq!(store.load_vertex_underlying_at(set, "adds", &shard, &extra.to_id(), old_version).unwrap(), Some(b"noncanonical join".to_vec()));
            assert!(target.prepare_phase_sync(&reader, version, &app, phase, &[], anchor).unwrap().remaining().is_empty());
        }
    }

    #[test]
    fn new_wallet_scans_refresh_past_published_roots_while_continuations_stay_pinned() {
        use quil_hypergraph::{HypergraphCrdt, Location};
        let directory = TempDir::new().unwrap();
        let db = Arc::new(RocksDb::open(directory.path()).unwrap());
        let store = Arc::new(RocksHypergraphStore::new(db.inner()));
        let crdt = HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE));
        let location = Location { app_address: [21; 32], data_address: [7; 32] };
        let shard = quil_hypergraph::shard_key_for_location(&location);
        let read = |generation: &quil_hypergraph::snapshot::GenerationHandle| {
            generation.db_snapshot.as_ref().unwrap()
                .load_vertex_underlying_raw("vertex", "adds", &shard, &location.to_id()).unwrap()
        };

        // The root generation published at boot does not track later app writes.
        assert!(crdt.publish_snapshot_capturing(vec![1; 32], 0).unwrap());
        let historical = crdt.acquire_snapshot(&[1; 32]).unwrap();
        let before = crdt.acquire_or_capture_scan_snapshot(None).unwrap().unwrap();
        assert!(read(&before).is_none());
        crdt.add_vertex(&location, b"first committed value").unwrap();
        crdt.commit(1).unwrap();
        let first = crdt.acquire_or_capture_scan_snapshot(None).unwrap().unwrap();
        assert_eq!(read(&first), Some(b"first committed value".to_vec()));
        assert_ne!(before.scan_id, first.scan_id);
        assert!(read(&historical).is_none());
        assert!(read(&crdt.acquire_or_capture_scan_snapshot(before.scan_id.as_ref()).unwrap().unwrap()).is_none());

        crdt.add_vertex(&location, b"second committed value").unwrap();
        crdt.commit(2).unwrap();
        let second = crdt.acquire_or_capture_scan_snapshot(None).unwrap().unwrap();
        assert_eq!(read(&second), Some(b"second committed value".to_vec()));
        assert_eq!(read(&crdt.acquire_or_capture_scan_snapshot(first.scan_id.as_ref()).unwrap().unwrap()),
            Some(b"first committed value".to_vec()));
        assert!(crdt.acquire_or_capture_scan_snapshot(Some(&[0xff; 32])).unwrap().is_none());
        assert_eq!(crdt.known_snapshot_roots(), vec![vec![1; 32]], "wallet reads must not publish a new authenticated root");
    }

    #[test]
    fn test_serve_blob_pin_zero_survives_later_writes() {
        use quil_types::store::HypergraphStore as _;
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = Arc::new(RocksHypergraphStore::new(Arc::new(db).inner()));
        let shard = ShardKey { l1: [0; 3], l2: [0xff; 32] };
        let vertex = vec![0x11; 64];
        let txn = store.new_transaction(false).unwrap();
        for (version, blob) in [(0, b"first".as_slice()), (1, b"later".as_slice())] {
            store.save_vertex_underlying_versioned(
                txn.as_ref(), "vertex", "adds", &shard, &vertex, blob, version,
            ).unwrap();
        }
        txn.commit().unwrap();
        let crdt = quil_hypergraph::HypergraphCrdt::new(
            store, Arc::new(quil_types::crypto::NoopInclusionProver),
        );
        assert_eq!(crdt.serve_vertex_blob(&shard, 0, &vertex, Some(0)).as_deref(), Some(b"first".as_slice()));
        assert_eq!(crdt.serve_vertex_blob(&shard, 0, &vertex, Some(1)).as_deref(), Some(b"later".as_slice()));
        assert_eq!(crdt.serve_vertex_blob(&shard, 0, &vertex, None).as_deref(), Some(b"later".as_slice()));
    }
}

#[cfg(test)]
mod fixed_vertex_page_tests {
    use super::*;
    use quil_types::store::{HypergraphStore, VertexPageLimits};

    fn put(db: &quil_forest::CoordinatedDb, shard: &ShardKey, domain: &[u8; 32], address: u8, version: Option<u64>, value: &[u8]) {
        let mut key = domain.to_vec(); key.extend_from_slice(&[address; 32]);
        let key = match version {
            Some(version) => crate::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", shard, &key, version),
            None => hypergraph_vertex_data_key("vertex", "adds", shard, &key),
        };
        db.put(key, value).unwrap();
    }
    #[test]
    fn fixed_vertex_pages_retained_snapshot_excludes_between_page_commits() {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
        let store = RocksHypergraphStore::new(db.clone());
        let shard = ShardKey { l1: [1; 3], l2: [2; 32] };
        let domain = [4; 32];
        put(&db, &shard, &domain, 1, None, b"one");
        put(&db, &shard, &domain, 2, Some(1), b"two-before");
        put(&db, &shard, &domain, 3, None, b"three-before");
        let snapshot = store.capture_snapshot().unwrap();
        // Exercise the object-safe API used by retained snapshot managers.
        let reader: &dyn SnapshotReadable = snapshot.as_ref();
        let limits = VertexPageLimits { max_entries: 1, max_bytes: 1024 };
        let first = reader.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, None, limits).unwrap();
        assert_eq!(first.entries, vec![([1; 32], b"one".to_vec())]);
        assert!(first.has_more);
        put(&db, &shard, &domain, 2, Some(2), b"two-after");
        put(&db, &shard, &domain, 3, None, b"three-after");
        put(&db, &shard, &domain, 4, Some(1), b"four-after");
        let second = reader.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, Some(&[1; 32]), limits).unwrap();
        assert_eq!(second.entries, vec![([2; 32], b"two-before".to_vec())]);
        assert!(second.has_more);
        let third = reader.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, Some(&[2; 32]), limits).unwrap();
        assert_eq!(third.entries, vec![([3; 32], b"three-before".to_vec())]);
        assert!(!third.has_more);
        let live = store.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, Some(&[1; 32]), VertexPageLimits { max_entries: 4, ..limits }).unwrap();
        assert_eq!(live.entries, vec![([2; 32], b"two-after".to_vec()), ([3; 32], b"three-after".to_vec()), ([4; 32], b"four-after".to_vec())]);
        assert!(!live.has_more);
    }

    #[test]
    fn fixed_vertex_pages_merge_latest_versions_and_skip_other_key_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
        let store = RocksHypergraphStore::new(db.clone());
        let shard = ShardKey { l1: [1; 3], l2: [2; 32] }; let domain = [4; 32];
        put(&db, &shard, &domain, 1, None, b"legacy");
        put(&db, &shard, &domain, 1, Some(1), b"old");
        put(&db, &shard, &domain, 1, Some(u64::MAX), b"new");
        put(&db, &shard, &domain, 2, None, b"two");
        put(&db, &shard, &domain, 3, Some(2), b"three");
        put(&db, &shard, &[9; 32], 1, Some(7), b"other domain");
        for length in [31, 33] {
            let mut key = domain.to_vec(); key.extend_from_slice(&vec![1; length]);
            db.put(crate::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard, &key, 4), b"variable").unwrap();
            db.put(hypergraph_vertex_data_key("vertex", "adds", &shard, &key), b"variable").unwrap();
        }
        let provider: &dyn HypergraphStore = &store;
        let limits = VertexPageLimits { max_entries: 1, max_bytes: 1024 };
        let mut cursor = None; let mut result = Vec::new();
        loop {
            let page = provider.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, cursor.as_ref(), limits).unwrap();
            assert!(!page.entries.is_empty());
            assert_eq!(page.entries.len(), 1);
            cursor = Some(page.entries.last().unwrap().0);
            result.extend(page.entries);
            if !page.has_more { break; }
        }
        assert_eq!(result, vec![([1; 32], b"new".to_vec()), ([2; 32], b"two".to_vec()), ([3; 32], b"three".to_vec())]);
        put(&db, &shard, &domain, 255, Some(u64::MAX), b"last");
        let last = provider.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, Some(&[3; 32]), limits).unwrap();
        assert_eq!(last.entries, vec![([255; 32], b"last".to_vec())]);
        assert!(!last.has_more);
        let end = provider.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, Some(&[255; 32]), limits).unwrap();
        assert!(end.entries.is_empty() && !end.has_more);
    }
    #[test]
    fn fixed_vertex_page_byte_limits_preserve_progress_and_mvcc_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
        let store = RocksHypergraphStore::new(db.clone());
        let shard = ShardKey { l1: [1; 3], l2: [2; 32] }; let domain = [4; 32];
        put(&db, &shard, &domain, 1, None, &vec![9; 4096]);
        put(&db, &shard, &domain, 1, Some(0), &vec![9; 4096]);
        put(&db, &shard, &domain, 1, Some(1), b"new");
        put(&db, &shard, &domain, 2, None, b"two");
        put(&db, &shard, &domain, 3, Some(1), &vec![9; 4096]);
        let limits = VertexPageLimits { max_entries: 10, max_bytes: 67 };
        let first = store.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, None, limits).unwrap();
        assert_eq!(first.entries, vec![([1; 32], b"new".to_vec())]); assert!(first.has_more);
        let second = store.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, Some(&[1; 32]), limits).unwrap();
        assert_eq!(second.entries, vec![([2; 32], b"two".to_vec())]); assert!(second.has_more);
        assert!(store.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, Some(&[2; 32]), limits).is_err());
        for limits in [VertexPageLimits { max_entries: 0, ..limits }, VertexPageLimits { max_bytes: 63, ..limits }] {
            assert!(store.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, None, limits).is_err());
        }
    }

    /// Rows a caller passes over are neither returned nor counted, however
    /// large, in either keyspace; everything else pages as before. An MVCC
    /// row that is passed over also hides its superseded legacy value.
    #[test]
    fn skipped_rows_neither_return_nor_count_against_a_page() {
        use quil_types::store::SnapshotReadable as _;
        let dir = tempfile::tempdir().unwrap();
        let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
        let store = RocksHypergraphStore::new(db.clone());
        let shard = ShardKey { l1: [1; 3], l2: [2; 32] }; let domain = [4; 32];
        put(&db, &shard, &domain, 1, Some(1), b"one");
        put(&db, &shard, &domain, 2, None, &vec![9; 4096]);
        put(&db, &shard, &domain, 2, Some(1), &vec![9; 4096]);
        put(&db, &shard, &domain, 3, None, b"three");
        put(&db, &shard, &domain, 4, Some(2), &vec![9; 4096]);
        put(&db, &shard, &domain, 5, Some(1), b"five");
        let snapshot = store.capture_snapshot().unwrap();
        let limits = VertexPageLimits { max_entries: 2, max_bytes: 200 };
        let large = |address: &[u8; 32]| *address == [2; 32] || *address == [4; 32];
        assert!(snapshot.page_vertex_underlying_fixed("vertex", "adds", &shard, &domain, Some(&[1; 32]), limits).is_err(),
            "unskipped, the large row fails its page");
        let (mut cursor, mut rows, mut pages) = (None, Vec::new(), 0);
        loop {
            let page = snapshot.page_vertex_underlying_fixed_skipping("vertex", "adds", &shard, &domain, cursor.as_ref(), limits, &large).unwrap();
            pages += 1;
            cursor = page.entries.last().map(|(address, _)| *address);
            rows.extend(page.entries);
            if !page.has_more { break; }
        }
        assert_eq!(rows, vec![([1; 32], b"one".to_vec()), ([3; 32], b"three".to_vec()), ([5; 32], b"five".to_vec())]);
        assert_eq!(pages, 2);
        let none = snapshot.page_vertex_underlying_fixed_skipping("vertex", "adds", &shard, &domain, Some(&[1; 32]), limits, &|_| false);
        assert!(none.is_err(), "skipping nothing pages as before");
    }
}
