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

/// Reserved key namespace for the Phase-3 JMT forest when it shares this
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
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }

    /// The raw RocksDB handle backing this store. Exposed so startup can build
    /// the Phase-3 forest (`quil_forest::Forest::with_namespace(store.raw_db(),
    /// FOREST_NAMESPACE)`) sharing this DB — the `HypergraphStore` trait
    /// deliberately doesn't surface it, so this is the concrete-store escape
    /// hatch the forest installation needs.
    pub fn raw_db(&self) -> Arc<rocksdb::DB> {
        self.db.clone()
    }

    // (helper `prefix_range_upper_bound` is a free function below the impl)

    /// Whether this DB already contains Phase-3 forest data (any key under
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
        let combos = [
            ("vertex", "adds"),
            ("vertex", "removes"),
            ("hyperedge", "adds"),
            ("hyperedge", "removes"),
        ];
        let mut batch = rocksdb::WriteBatch::default();
        for (set, phase) in combos {
            for lower in [
                crate::encoding::hypergraph_vertex_data_prefix(set, phase, shard),
                crate::encoding::hypergraph_vertex_data_v2_shard_prefix(set, phase, shard),
            ] {
                if let Some(upper) = prefix_range_upper_bound(&lower) {
                    batch.delete_range(&lower, &upper);
                }
            }
        }
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
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
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&key, bytes);
        Ok(())
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

    /// Transaction-aware variant of [`save_vertex_underlying`]: stages the
    /// write into `txn`'s batch so vertex content becomes durable
    /// atomically with the tree nodes and shard commit of the surrounding
    /// transaction. Errors for an unrecognized txn type rather than writing
    /// outside the transaction (see [`RocksTxn::from_dyn`]).
    pub fn save_vertex_underlying_txn(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        let key = hypergraph_vertex_data_key(set_type, phase_type, shard_key, vertex_key);
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&key, bytes);
        Ok(())
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

    /// Prune superseded MVCC blob versions of one `(set, phase, shard)` keyspace
    /// to `watermark`: per vertex keep the greatest version ≤ `watermark` (the
    /// value readable AT the watermark) and every version above it, deleting the
    /// strictly-older ones. Staged into `txn`. Returns the number deleted.
    fn prune_blob_versions(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        watermark: u64,
    ) -> Result<usize> {
        use std::collections::HashMap;
        let sprefix =
            crate::encoding::hypergraph_vertex_data_v2_shard_prefix(set_type, phase_type, shard_key);
        // vertex_key -> [(version, full_key)]
        let mut by_vk: HashMap<Vec<u8>, Vec<(u64, Vec<u8>)>> = HashMap::new();
        for entry in self
            .db
            .iterator(rocksdb::IteratorMode::From(&sprefix, rocksdb::Direction::Forward))
        {
            let (k, _v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&sprefix) {
                break;
            }
            if k.len() < sprefix.len() + 8 {
                continue;
            }
            let vk = k[sprefix.len()..k.len() - 8].to_vec();
            let ver = u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap());
            by_vk.entry(vk).or_default().push((ver, k.to_vec()));
        }
        let mut deleted = 0usize;
        for (_vk, versions) in by_vk {
            // Floor = greatest version ≤ watermark (the value current at the
            // watermark). If none exists (all versions above), keep them all.
            let floor = versions
                .iter()
                .filter(|(v, _)| *v <= watermark)
                .map(|(v, _)| *v)
                .max();
            if let Some(floor) = floor {
                for (v, key) in &versions {
                    if *v < floor {
                        txn.delete(key)?;
                        deleted += 1;
                    }
                }
            }
        }
        Ok(deleted)
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
/// `DB`. To store it past a single scope we keep the `Arc<DB>` in the same
/// struct and erase the borrow to `'static` (one contained `unsafe` in
/// `capture`), relying on field drop order — `snapshot` before `_db` — so
/// the snapshot is always released before its `DB` can go away.
pub struct RocksHypergraphSnapshot {
    /// Point-in-time snapshot. MUST be declared before `_db`: struct
    /// fields drop in declaration order, so this drops first (releasing
    /// the rocksdb snapshot) while the backing `DB` is still alive.
    snapshot: rocksdb::SnapshotWithThreadMode<'static, rocksdb::DB>,
    /// Keeps the `DB` alive for as long as `snapshot` borrows it.
    _db: Arc<rocksdb::DB>,
}

impl RocksHypergraphSnapshot {
    /// Capture a RocksDB point-in-time snapshot. Cheap — pins the current
    /// sequence number; copies no data.
    pub fn capture(db: Arc<rocksdb::DB>) -> Result<Self> {
        let snap = db.snapshot();
        // SAFETY: `snap` borrows `*db`. We move the owning `Arc<DB>` into
        // `_db` in this same struct, so `*db` outlives the snapshot, and
        // field declaration order (`snapshot` then `_db`) guarantees the
        // snapshot is dropped — releasing the rocksdb snapshot — before
        // `_db` is dropped (which may close the DB). Erasing the borrow to
        // `'static` only launders the lifetime; layout is unchanged
        // (a `&DB` plus a raw snapshot pointer), so the transmute is sound.
        let snapshot: rocksdb::SnapshotWithThreadMode<'static, rocksdb::DB> =
            unsafe { std::mem::transmute(snap) };
        Ok(Self { snapshot, _db: db })
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

impl RocksTxn {
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
            RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&db_key, data);
            return Ok(());
        }
        // Per-node: write the by-key entry and the by-path pointer
        // atomically. Pointer value is the by-key key — the lazy
        // walker SeekGEs the by-path index and then `Get`s the by-key
        // entry. This is exactly Go's dual-index scheme.
        let by_key = hypergraph_tree_node_by_key(set_type, phase_type, shard_key, key);
        let by_path = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
        let mut batch = RocksTxn::from_dyn(txn)?.batch.lock().unwrap();
        batch.put(&by_key, data);
        batch.put(&by_path, &by_key);
        Ok(())
    }

    fn save_root(&self, txn: &dyn Transaction, set_type: &str, phase_type: &str, shard_key: &ShardKey, data: &[u8]) -> Result<()> {
        let db_key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&db_key, data);
        Ok(())
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
            RocksTxn::from_dyn(txn)?.batch.lock().unwrap().delete(&db_key);
            return Ok(());
        }
        let by_key = hypergraph_tree_node_by_key(set_type, phase_type, shard_key, key);
        let by_path = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
        let mut batch = RocksTxn::from_dyn(txn)?.batch.lock().unwrap();
        batch.delete(&by_key);
        batch.delete(&by_path);
        Ok(())
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
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&key, commitment);
        Ok(())
    }

    fn get_shard_commit(&self, frame_number: u64, phase_type: &str, set_type: &str, shard_address: &[u8]) -> Result<Vec<u8>> {
        let key = hypergraph_shard_commit_key(frame_number, phase_type, set_type, shard_address);
        self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("shard commit not found".into()))
    }

    fn delete_shard_commits(&self, frame_number: u64, shard_address: &[u8]) -> Result<()> {
        // All four (phase_type, set_type) pairs that `commit` caches per
        // shard — matches the PHASES table in `HypergraphCrdt::commit`.
        for (phase_type, set_type) in [
            ("adds", "vertex"),
            ("removes", "vertex"),
            ("adds", "hyperedge"),
            ("removes", "hyperedge"),
        ] {
            let key = hypergraph_shard_commit_key(frame_number, phase_type, set_type, shard_address);
            self.db.delete(&key).map_err(|e| QuilError::Store(e.to_string()))?;
        }
        Ok(())
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
        // Latest = MVCC read at u64::MAX (falls back to the legacy keyspace).
        self.load_vertex_underlying_at(set_type, phase_type, shard_key, vertex_key, u64::MAX)
    }

    fn save_vertex_underlying(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        data: &[u8],
    ) -> Result<()> {
        RocksHypergraphStore::save_vertex_underlying_txn(
            self, txn, set_type, phase_type, shard_key, vertex_key, data,
        )
    }

    fn save_vertex_underlying_versioned(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        data: &[u8],
        version: u64,
    ) -> Result<()> {
        let key = crate::encoding::hypergraph_vertex_data_v2_key(
            set_type, phase_type, shard_key, vertex_key, version,
        );
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&key, data);
        Ok(())
    }

    fn load_vertex_underlying_at(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        version: u64,
    ) -> Result<Option<Vec<u8>>> {
        // MVCC: reverse-seek to `vk_prefix ‖ V`; the first (largest ≤ V) key that
        // still shares `vk_prefix` is the latest write with version ≤ V. Version
        // is a fixed 8-byte non-inverted suffix, so a matching key has length
        // exactly `vk_prefix.len() + 8`.
        let vk_prefix = crate::encoding::hypergraph_vertex_data_v2_vk_prefix(
            set_type, phase_type, shard_key, vertex_key,
        );
        let seek = crate::encoding::hypergraph_vertex_data_v2_key(
            set_type, phase_type, shard_key, vertex_key, version,
        );
        let mut iter = self
            .db
            .iterator(rocksdb::IteratorMode::From(&seek, rocksdb::Direction::Reverse));
        if let Some(entry) = iter.next() {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if k.len() == vk_prefix.len() + 8 && k.starts_with(&vk_prefix) {
                return Ok(Some(v.into_vec()));
            }
        }
        // Legacy fallback: an un-migrated (unversioned) blob written before the
        // version dimension existed. The next commit re-writes it versioned.
        self.load_vertex_underlying(set_type, phase_type, shard_key, vertex_key)
    }

    fn for_each_vertex_underlying(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        callback: &mut dyn FnMut(Vec<u8>, Vec<u8>),
    ) -> Result<usize> {
        use std::collections::{HashMap, HashSet};
        // v2 (versioned) keyspace: keep the LATEST version per vertex_key. Keys
        // may interleave across variable-length vertex keys, so accumulate into a
        // map rather than assume per-key contiguity.
        let v2_prefix =
            crate::encoding::hypergraph_vertex_data_v2_shard_prefix(set_type, phase_type, shard_key);
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
        // Legacy (unversioned) keyspace fills any vertex not yet re-written v2.
        let old_prefix =
            crate::encoding::hypergraph_vertex_data_prefix(set_type, phase_type, shard_key);
        for entry in self
            .db
            .iterator(rocksdb::IteratorMode::From(&old_prefix, rocksdb::Direction::Forward))
        {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&old_prefix) {
                break;
            }
            if k.len() <= old_prefix.len() {
                continue;
            }
            let vk = k[old_prefix.len()..].to_vec();
            if seen.contains(&vk) {
                continue;
            }
            callback(vk, v.into_vec());
            count += 1;
        }
        Ok(count)
    }

    fn put_root_version(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_id: &[u8],
        root_hash: &[u8],
        version: u64,
        frame_number: u64,
    ) -> Result<()> {
        // Repeated roots collapse to the LATEST (version, frame): a `put` keyed by
        // root overwrites, and commits happen in version order, so the last write
        // for a recurring root wins.
        let key = crate::encoding::hypergraph_root_version_key(
            set_type, phase_type, shard_id, root_hash,
        );
        let mut val = Vec::with_capacity(16);
        val.extend_from_slice(&version.to_be_bytes());
        val.extend_from_slice(&frame_number.to_be_bytes());
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&key, &val);
        Ok(())
    }

    fn get_root_version(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_id: &[u8],
        root_hash: &[u8],
    ) -> Result<Option<(u64, u64)>> {
        let key = crate::encoding::hypergraph_root_version_key(
            set_type, phase_type, shard_id, root_hash,
        );
        match self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))? {
            Some(v) if v.len() == 16 => Ok(Some((
                u64::from_be_bytes(v[..8].try_into().unwrap()),
                u64::from_be_bytes(v[8..16].try_into().unwrap()),
            ))),
            _ => Ok(None),
        }
    }

    fn put_app_manifest(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        app_address: &[u8],
        app_root: &[u8],
        entries: &[(Vec<u8>, [u8; 32], u64)],
        frame_number: u64,
    ) -> Result<()> {
        // frame(u64) ‖ count(u32) then per entry: prefix_len(u16) ‖ prefix ‖
        // sub_root(32) ‖ ver(u64). The leading frame lets the pruner drop stale
        // manifests by age without re-deriving each aggregate root's version.
        let key = crate::encoding::hypergraph_app_manifest_key(
            set_type, phase_type, app_address, app_root,
        );
        let mut val = Vec::new();
        val.extend_from_slice(&frame_number.to_be_bytes());
        val.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (prefix, root, ver) in entries {
            val.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
            val.extend_from_slice(prefix);
            val.extend_from_slice(root);
            val.extend_from_slice(&ver.to_be_bytes());
        }
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&key, &val);
        Ok(())
    }

    fn get_app_manifest(
        &self,
        set_type: &str,
        phase_type: &str,
        app_address: &[u8],
        app_root: &[u8],
    ) -> Result<Option<Vec<(Vec<u8>, [u8; 32], u64)>>> {
        let key = crate::encoding::hypergraph_app_manifest_key(
            set_type, phase_type, app_address, app_root,
        );
        let raw = match self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))? {
            Some(v) => v,
            None => return Ok(None),
        };
        // Skip the leading frame(u64) — retained only for the pruner.
        let mut p = 8usize;
        if raw.len() < p {
            return Err(QuilError::Store("manifest: short frame".into()));
        }
        let rd_u32 = |b: &[u8], p: &mut usize| -> Option<u32> {
            if *p + 4 > b.len() { return None; }
            let v = u32::from_be_bytes(b[*p..*p + 4].try_into().unwrap());
            *p += 4;
            Some(v)
        };
        let n = rd_u32(&raw, &mut p).ok_or_else(|| QuilError::Store("manifest: short".into()))?;
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            if p + 2 > raw.len() { return Err(QuilError::Store("manifest: short prefix_len".into())); }
            let plen = u16::from_be_bytes(raw[p..p + 2].try_into().unwrap()) as usize;
            p += 2;
            if p + plen + 32 + 8 > raw.len() { return Err(QuilError::Store("manifest: short entry".into())); }
            let prefix = raw[p..p + plen].to_vec();
            p += plen;
            let mut root = [0u8; 32];
            root.copy_from_slice(&raw[p..p + 32]);
            p += 32;
            let ver = u64::from_be_bytes(raw[p..p + 8].try_into().unwrap());
            p += 8;
            out.push((prefix, root, ver));
        }
        Ok(Some(out))
    }

    fn prune_versioned(&self, cull_frame: u64) -> Result<Vec<(Vec<u8>, usize, u64)>> {
        use std::collections::HashMap;
        // ---- 1. Watermarks from the root→(version,frame) index -------------
        // Per tree `(set_byte, phase_byte, shard_id)` the retention watermark is
        // `min_readable_version = max{ version : frame ≤ cull_frame }` — the state
        // that was current as-of the cull frame. Everything strictly older is
        // superseded and prunable. Version and frame are jointly monotonic, so a
        // version below the watermark also has frame ≤ cull_frame.
        let rv_first = [crate::encoding::HG_ROOT_VERSION];
        // (set,phase,shard_id) -> (min_ver, [(root_key, version)])
        let mut trees: HashMap<(u8, u8, Vec<u8>), (u64, Vec<(Vec<u8>, u64)>)> = HashMap::new();
        for entry in self
            .db
            .iterator(rocksdb::IteratorMode::From(&rv_first, rocksdb::Direction::Forward))
        {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if k.first() != Some(&crate::encoding::HG_ROOT_VERSION) {
                break;
            }
            // key = [0x35][set][phase][shard_id(var)][root(32)]; value = ver(8)‖frame(8)
            if k.len() < 1 + 1 + 1 + 32 || v.len() != 16 {
                continue;
            }
            let set_b = k[1];
            let phase_b = k[2];
            let shard_id = k[3..k.len() - 32].to_vec();
            let version = u64::from_be_bytes(v[..8].try_into().unwrap());
            let frame = u64::from_be_bytes(v[8..16].try_into().unwrap());
            let e = trees.entry((set_b, phase_b, shard_id)).or_insert((0u64, Vec::new()));
            if frame <= cull_frame && version > e.0 {
                e.0 = version;
            }
            e.1.push((k.to_vec(), version));
        }

        let txn = self.new_transaction(false)?;
        let mut watermarks: Vec<(Vec<u8>, usize, u64)> = Vec::new();
        // Blob watermark per (set, phase, app_l2): a split app packs many
        // sub-shards under one app ShardKey, each with its own version counter,
        // so use the MIN sub-shard watermark — a safe (never-under-prune) floor,
        // since a vertex is only read at versions ≥ its own sub-shard watermark.
        let mut blob_wm: HashMap<(u8, u8, [u8; 32]), u64> = HashMap::new();
        for ((set_b, phase_b, shard_id), (min_ver, roots)) in &trees {
            if *min_ver == 0 {
                continue; // no commit ≤ cull_frame — too new to prune
            }
            // Drop root→version entries strictly below the watermark (their
            // forest generation is about to be pruned, so they'd be un-servable).
            for (rk, ver) in roots {
                if *ver < *min_ver {
                    txn.delete(rk)?;
                }
            }
            let phase_idx = (*set_b as usize) * 2 + (*phase_b as usize);
            if phase_idx < 4 {
                watermarks.push((shard_id.clone(), phase_idx, *min_ver));
            }
            if shard_id.len() >= 32 {
                let mut app = [0u8; 32];
                app.copy_from_slice(&shard_id[..32]); // addr_path_shard_id = app‖prefix
                let w = blob_wm.entry((*set_b, *phase_b, app)).or_insert(u64::MAX);
                if *min_ver < *w {
                    *w = *min_ver;
                }
            }
        }

        // ---- 2. Prune superseded blob versions per app ShardKey ------------
        for ((set_b, phase_b, app), wm) in &blob_wm {
            if *wm == u64::MAX || *wm == 0 {
                continue;
            }
            let (set_s, phase_s) = match (byte_set_str(*set_b), byte_phase_str(*phase_b)) {
                (Some(s), Some(p)) => (s, p),
                _ => continue,
            };
            let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3);
            let shard = ShardKey { l1, l2: *app };
            self.prune_blob_versions(txn.as_ref(), set_s, phase_s, &shard, *wm)?;
        }

        // ---- 3. Prune stale split-app manifests (frame < cull_frame) --------
        let mf_first = [crate::encoding::HG_APP_MANIFEST];
        for entry in self
            .db
            .iterator(rocksdb::IteratorMode::From(&mf_first, rocksdb::Direction::Forward))
        {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if k.first() != Some(&crate::encoding::HG_APP_MANIFEST) {
                break;
            }
            if v.len() < 8 {
                continue;
            }
            let frame = u64::from_be_bytes(v[..8].try_into().unwrap());
            if frame < cull_frame {
                txn.delete(&k)?;
            }
        }

        txn.commit()?;
        Ok(watermarks)
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

        let mut batch = RocksTxn::from_dyn(txn)?.batch.lock().unwrap();
        batch.put(&commit_key, &value);
        if should_update_latest {
            batch.put(&latest_key, frame_number.to_be_bytes());
        }
        batch.put(&index_key, &[] as &[u8]);
        Ok(())
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
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().put(&change_key, value);
        Ok(())
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
        RocksTxn::from_dyn(txn)?.batch.lock().unwrap().delete(&change_key);
        Ok(())
    }

    fn capture_tree_snapshot(&self) -> Result<Option<Arc<dyn SnapshotReadable>>> {
        let snap = RocksHypergraphSnapshot::capture(self.db.clone())?;
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
}
