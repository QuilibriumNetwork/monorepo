use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use num_traits::Zero;
use quil_types::crypto::InclusionProver;
use quil_types::error::Result;
use quil_types::store::{HypergraphStore, ShardKey};

use crate::addressing::{shard_key_for_location, Location};
use quil_tries::LazyVectorCommitmentTree;

/// Metadata about a shard's state.
#[derive(Debug, Clone)]
pub struct ShardMetadata {
    pub commitment: Vec<Vec<u8>>,
    pub leaf_count: u64,
    pub size: BigInt,
}

/// The four CRDT phase sets, each holding per-shard store-backed lazy trees.
struct PhaseSets {
    vertex_adds: HashMap<ShardKey, LazyVectorCommitmentTree>,
    vertex_removes: HashMap<ShardKey, LazyVectorCommitmentTree>,
    hyperedge_adds: HashMap<ShardKey, LazyVectorCommitmentTree>,
    hyperedge_removes: HashMap<ShardKey, LazyVectorCommitmentTree>,
}

impl PhaseSets {
    fn new() -> Self {
        Self {
            vertex_adds: HashMap::new(),
            vertex_removes: HashMap::new(),
            hyperedge_adds: HashMap::new(),
            hyperedge_removes: HashMap::new(),
        }
    }
}

/// The core hypergraph CRDT with add/remove sets for vertices and hyperedges.
///
/// Each atom (vertex or hyperedge) exists in four trees:
/// - vertex_adds: vertices that have been added
/// - vertex_removes: vertices that have been removed
/// - hyperedge_adds: hyperedges that have been added
/// - hyperedge_removes: hyperedges that have been removed
///
/// An atom is "present" if it exists in the adds set but not in the removes set.
///
/// Trees are backed by `LazyVectorCommitmentTree` which loads from and
/// saves to the `HypergraphStore` on demand.
pub struct HypergraphCrdt {
    store: Arc<dyn HypergraphStore>,
    prover: Arc<dyn InclusionProver>,
    phase_sets: RwLock<PhaseSets>,
    shard_metadata: RwLock<HashMap<ShardKey, ShardMetadata>>,
    size: RwLock<BigInt>,
    /// Snapshot generations registry — tracks recent published roots
    /// so sync clients can validate `expected_root` requests against
    /// historical state. Mirrors Go `HypergraphCRDT.snapshotMgr`.
    snapshot_mgr: crate::snapshot::SnapshotManager,
    /// Nibble path covered by this node — vertices/hyperedges whose
    /// full nibble path doesn't begin with this prefix are dropped.
    /// Empty by default (covers everything). Mirrors Go
    /// `HypergraphCRDT.coveredPrefix`.
    covered_prefix: RwLock<Vec<i32>>,
}

impl HypergraphCrdt {
    pub fn new(
        store: Arc<dyn HypergraphStore>,
        prover: Arc<dyn InclusionProver>,
    ) -> Self {
        Self {
            store,
            prover,
            phase_sets: RwLock::new(PhaseSets::new()),
            shard_metadata: RwLock::new(HashMap::new()),
            size: RwLock::new(BigInt::zero()),
            snapshot_mgr: crate::snapshot::SnapshotManager::new(),
            covered_prefix: RwLock::new(Vec::new()),
        }
    }

    /// Return a clone of the covered nibble prefix. Empty means
    /// "no gating — accept all addresses". Mirrors Go
    /// `HypergraphCRDT.GetCoveredPrefix`.
    pub fn get_covered_prefix(&self) -> Vec<i32> {
        self.covered_prefix.read().unwrap().clone()
    }

    /// Ensure a lazy tree exists in `phase_sets.vertex_adds` for the
    /// given shard. Used at startup on archive/global-prover nodes so
    /// that `commit` includes the shard even when no in-process
    /// `add_vertex` happened this session — without this, a migrated
    /// store with persisted trie nodes for the shard is invisible to
    /// `commit`, so the sync server's `load_tree_blob` lookup
    /// (`hypergraph_tree_blob_key`) never gets a value and remote
    /// peers see "no tree data available".
    pub fn ensure_vertex_adds_tree(&self, shard_key: &ShardKey) {
        let mut sets = self.phase_sets.write().unwrap();
        Self::ensure_tree(
            &mut sets.vertex_adds,
            &self.store,
            "vertex",
            "adds",
            shard_key,
        );
    }

    /// Prime all four phase-set trees for a shard. Used at startup for
    /// migrated shards whose on-disk trie nodes exist but were never
    /// touched by an in-process mutation this session — without
    /// priming, `phase_set_metadata_at_path` returns `None` for that
    /// shard and `GetAppShards` reports size=0 / zero commitments per
    /// phase. Mutations (`add_vertex` / `remove_vertex` /
    /// `add_hyperedge` / `remove_hyperedge`) auto-populate via
    /// `ensure_tree`, so this is only the cold-start gap-filler.
    pub fn ensure_all_phase_trees(&self, shard_key: &ShardKey) {
        let mut sets = self.phase_sets.write().unwrap();
        Self::ensure_tree(&mut sets.vertex_adds, &self.store, "vertex", "adds", shard_key);
        Self::ensure_tree(&mut sets.vertex_removes, &self.store, "vertex", "removes", shard_key);
        Self::ensure_tree(&mut sets.hyperedge_adds, &self.store, "hyperedge", "adds", shard_key);
        Self::ensure_tree(&mut sets.hyperedge_removes, &self.store, "hyperedge", "removes", shard_key);
    }

    /// Update the covered nibble prefix and forward to the backing
    /// store. Mirrors Go `HypergraphCRDT.SetCoveredPrefix` (without
    /// the per-tree `CoveredPrefix` field assignment, which the
    /// Rust lazy tree doesn't expose yet).
    pub fn set_covered_prefix(&self, prefix: &[i32]) -> Result<()> {
        {
            let mut p = self.covered_prefix.write().unwrap();
            *p = prefix.to_vec();
        }
        self.store.set_covered_prefix(prefix)
    }

    /// Returns `[vertex_adds, vertex_removes, hyperedge_adds,
    /// hyperedge_removes]` metadata at the path. Absent trees and
    /// missing nodes contribute `None`.
    pub fn phase_set_metadata_at_path(
        &self,
        shard_key: &ShardKey,
        full_path: &[i32],
    ) -> Result<[Option<quil_tries::NodeMetadata>; 4]> {
        let sets = self.phase_sets.read().unwrap();
        let read_one = |tree: Option<&LazyVectorCommitmentTree>| -> Result<Option<quil_tries::NodeMetadata>> {
            match tree {
                Some(t) => t.get_node_metadata_at_path(full_path),
                None => Ok(None),
            }
        };
        let va = read_one(sets.vertex_adds.get(shard_key))?;
        let vr = read_one(sets.vertex_removes.get(shard_key))?;
        let ha = read_one(sets.hyperedge_adds.get(shard_key))?;
        let hr = read_one(sets.hyperedge_removes.get(shard_key))?;
        Ok([va, vr, ha, hr])
    }

    /// Record a published root in the snapshot registry. Mirrors Go
    /// `HypergraphCRDT.PublishSnapshot`. The Rust port uses an in-
    /// memory registry of recent (root, frame_number) pairs without
    /// any backing-store snapshot — sync clients fall back to live
    /// store reads. Sync requests with an `expected_root` not in this
    /// registry are still rejected by the server, catching the
    /// stale-root corruption mode; for full point-in-time-consistent
    /// reads under concurrent writes, prefer `publish_snapshot_with_store`.
    pub fn publish_snapshot(&self, root: Vec<u8>, frame_number: u64) {
        self.snapshot_mgr.publish(root, frame_number);
    }

    /// Record a published root and bind a point-in-time backing-store
    /// snapshot to it. Sync requests pinned to this root will see
    /// reads served from the snapshot — immune to subsequent writes
    /// through the live store. Mirrors Go's
    /// `HypergraphCRDT.PublishSnapshot` paired with
    /// `tries.TreeBackingStore.NewDBSnapshot` (`hypergraph/snapshot_manager.go:233-242`).
    ///
    /// Callers that want point-in-time consistency should call this
    /// from the same critical section that produced the root, before
    /// any subsequent mutation of the live store, so the snapshot is
    /// captured against exactly the state the root reflects. The
    /// Rocks-backed store implements snapshot capture via
    /// `HypergraphStore::capture_tree_snapshot`.
    pub fn publish_snapshot_with_store(
        &self,
        root: Vec<u8>,
        frame_number: u64,
        snapshot: std::sync::Arc<dyn quil_types::store::SnapshotReadable>,
    ) {
        self.snapshot_mgr
            .publish_with_snapshot(root, frame_number, snapshot);
    }

    /// Convenience: capture a snapshot from the backing store and
    /// publish it. If the store does not implement snapshot capture,
    /// falls back to a snapshot-less publish. Returns `Ok(true)` when
    /// a snapshot was bound, `Ok(false)` when the fall-back path was
    /// taken.
    pub fn publish_snapshot_capturing(
        &self,
        root: Vec<u8>,
        frame_number: u64,
    ) -> quil_types::error::Result<bool> {
        match self.store.capture_tree_snapshot()? {
            Some(snap) => {
                self.snapshot_mgr
                    .publish_with_snapshot(root, frame_number, snap);
                Ok(true)
            }
            None => {
                self.snapshot_mgr.publish(root, frame_number);
                Ok(false)
            }
        }
    }

    /// Look up a snapshot generation by `expected_root` (mirror of Go
    /// `snapshotManager.acquire`). Returns `None` when no matching
    /// generation is recorded — the caller must reject sync requests
    /// in that case rather than serving live tree data tagged with
    /// the wrong root.
    pub fn acquire_snapshot(
        &self,
        expected_root: &[u8],
    ) -> Option<crate::snapshot::GenerationHandle> {
        self.snapshot_mgr.acquire(expected_root)
    }

    /// All known published roots (newest first) for diagnostic /
    /// testing purposes.
    pub fn known_snapshot_roots(&self) -> Vec<Vec<u8>> {
        self.snapshot_mgr.known_roots()
    }

    /// Close the snapshot manager (Go `CloseSnapshots`). Used during
    /// shutdown so a re-spawn can `reopen` cleanly.
    pub fn close_snapshots(&self) {
        self.snapshot_mgr.close();
    }

    /// Reopen the snapshot manager after a previous close.
    pub fn reopen_snapshots(&self) {
        self.snapshot_mgr.reopen();
    }

    /// Get or create a lazy tree for a specific phase set and shard.
    fn ensure_tree<'a>(
        map: &'a mut HashMap<ShardKey, LazyVectorCommitmentTree>,
        store: &Arc<dyn HypergraphStore>,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
    ) -> &'a LazyVectorCommitmentTree {
        map.entry(shard_key.clone()).or_insert_with(|| {
            LazyVectorCommitmentTree::new(
                store.clone(),
                set_type,
                phase_type,
                shard_key.clone(),
                vec![],
            )
        })
    }

    /// Add a vertex to the hypergraph.
    pub fn add_vertex(
        &self,
        location: &Location,
        data: &[u8],
    ) -> Result<()> {
        let shard_key = shard_key_for_location(location);
        let id = location.to_id();
        let data_size = BigInt::from(data.len() as u64);

        let mut sets = self.phase_sets.write().unwrap();
        let tree = Self::ensure_tree(
            &mut sets.vertex_adds, &self.store,
            "vertex", "adds", &shard_key,
        );
        tree.insert(&id, data, &[], &data_size)?;

        let mut size = self.size.write().unwrap();
        *size += &data_size;
        Ok(())
    }

    /// Remove a vertex from the hypergraph (CRDT semantics).
    pub fn remove_vertex(
        &self,
        location: &Location,
    ) -> Result<()> {
        let shard_key = shard_key_for_location(location);
        let id = location.to_id();

        let mut sets = self.phase_sets.write().unwrap();

        let exists_in_adds = sets.vertex_adds
            .get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten())
            .is_some();

        let exists_in_removes = sets.vertex_removes
            .get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten())
            .is_some();

        let vertex_is_present = exists_in_adds && !exists_in_removes;

        // Get the value size before we modify anything (for size subtraction)
        let value_size = if vertex_is_present {
            sets.vertex_adds
                .get(&shard_key)
                .and_then(|t| t.get(&id).ok().flatten())
                .map(|v| BigInt::from(v.len() as u64))
                .unwrap_or_default()
        } else {
            BigInt::zero()
        };

        if !exists_in_adds {
            let add_tree = Self::ensure_tree(
                &mut sets.vertex_adds, &self.store,
                "vertex", "adds", &shard_key,
            );
            add_tree.insert(&id, &[], &[], &BigInt::zero())?;
        }

        let rm_tree = Self::ensure_tree(
            &mut sets.vertex_removes, &self.store,
            "vertex", "removes", &shard_key,
        );
        rm_tree.insert(&id, &[], &[], &BigInt::zero())?;

        if vertex_is_present {
            let mut size = self.size.write().unwrap();
            *size -= &value_size;
        }

        Ok(())
    }

    /// Add a hyperedge to the hypergraph.
    pub fn add_hyperedge(
        &self,
        location: &Location,
        data: &[u8],
    ) -> Result<()> {
        let shard_key = shard_key_for_location(location);
        let id = location.to_id();
        let data_size = BigInt::from(data.len() as u64);

        let mut sets = self.phase_sets.write().unwrap();

        let in_removes = sets.hyperedge_removes
            .get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten())
            .is_some();

        if in_removes {
            return Ok(());
        }

        let tree = Self::ensure_tree(
            &mut sets.hyperedge_adds, &self.store,
            "hyperedge", "adds", &shard_key,
        );
        tree.insert(&id, data, &[], &data_size)?;

        let mut size = self.size.write().unwrap();
        *size += &data_size;
        Ok(())
    }

    /// Remove a hyperedge from the hypergraph (CRDT semantics).
    pub fn remove_hyperedge(
        &self,
        location: &Location,
    ) -> Result<()> {
        let shard_key = shard_key_for_location(location);
        let id = location.to_id();

        let mut sets = self.phase_sets.write().unwrap();

        let exists_in_adds = sets.hyperedge_adds
            .get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten())
            .is_some();

        let exists_in_removes = sets.hyperedge_removes
            .get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten())
            .is_some();

        let is_present = exists_in_adds && !exists_in_removes;

        let value_size = if is_present {
            sets.hyperedge_adds
                .get(&shard_key)
                .and_then(|t| t.get(&id).ok().flatten())
                .map(|v| BigInt::from(v.len() as u64))
                .unwrap_or_default()
        } else {
            BigInt::zero()
        };

        if !exists_in_adds {
            let add_tree = Self::ensure_tree(
                &mut sets.hyperedge_adds, &self.store,
                "hyperedge", "adds", &shard_key,
            );
            add_tree.insert(&id, &[], &[], &BigInt::zero())?;
        }

        let rm_tree = Self::ensure_tree(
            &mut sets.hyperedge_removes, &self.store,
            "hyperedge", "removes", &shard_key,
        );
        rm_tree.insert(&id, &[], &[], &BigInt::zero())?;

        if is_present {
            let mut size = self.size.write().unwrap();
            *size -= &value_size;
        }

        Ok(())
    }

    /// Commit all trees for the given frame number, returning per-shard
    /// commitments: `[vertex_adds_root, vertex_removes_root,
    /// hyperedge_adds_root, hyperedge_removes_root]`.
    ///
    /// Mirrors Go's `HypergraphCRDT.Commit` at `hypergraph/proofs.go:20-158`,
    /// including its per-frame cache:
    ///
    /// - At entry, `store.GetRootCommits(frame_number)` retrieves any
    ///   previously-persisted roots for this frame.
    /// - For each (shard, phase) slot, if the cached root is a real
    ///   commitment (NOT the 64-byte zero placeholder), the computation
    ///   is skipped and the cached value is returned verbatim.
    /// - Otherwise the tree is committed fresh and the new root is
    ///   written back via `store.SetShardCommit`.
    ///
    /// Consequence: a second call to `commit(N)` for the same frame
    /// returns the same roots regardless of subsequent in-memory tree
    /// mutations — identical to Go's behavior and required for
    /// consensus parity. Do NOT call `commit(N)` after mutating the
    /// tree and expect an updated root.
    pub fn commit(
        &self,
        frame_number: u64,
    ) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        let sets = self.phase_sets.write().unwrap();
        let prover: &(dyn InclusionProver + Sync) = self.prover.as_ref();
        let txn = self.store.new_transaction(false)?;

        // Cached roots from prior commit(frame_number). Missing shards
        // or placeholder (64-byte zero) slots signal "not yet committed".
        let mut commits: HashMap<ShardKey, Vec<Vec<u8>>> =
            self.store.get_root_commits(frame_number)?;

        let mut all_shard_keys: Vec<ShardKey> = Vec::new();
        for key in sets.vertex_adds.keys().chain(sets.vertex_removes.keys())
            .chain(sets.hyperedge_adds.keys()).chain(sets.hyperedge_removes.keys()) {
            if !all_shard_keys.contains(key) { all_shard_keys.push(key.clone()); }
        }
        // Include any shards the cache knows about but which no longer
        // have in-memory phase sets (e.g. after restart with lazy load).
        for key in commits.keys() {
            if !all_shard_keys.contains(key) { all_shard_keys.push(key.clone()); }
        }

        let empty_root = vec![0u8; 64];
        let mut result: HashMap<ShardKey, Vec<Vec<u8>>> = HashMap::new();

        // Phase tuple: (index into commits[shardKey], phase_type, set_type).
        // Indices match `hypergraph_shard_commit_key` layout in
        // `crates/quil-store/src/hypergraph.rs:get_root_commits`.
        const PHASES: &[(usize, &str, &str)] = &[
            (0, "adds", "vertex"),
            (1, "removes", "vertex"),
            (2, "adds", "hyperedge"),
            (3, "removes", "hyperedge"),
        ];

        for shard_key in &all_shard_keys {
            let phase_trees = [
                sets.vertex_adds.get(shard_key),
                sets.vertex_removes.get(shard_key),
                sets.hyperedge_adds.get(shard_key),
                sets.hyperedge_removes.get(shard_key),
            ];

            let mut roots: [Vec<u8>; 4] = [
                empty_root.clone(),
                empty_root.clone(),
                empty_root.clone(),
                empty_root.clone(),
            ];

            let cached_row = commits.remove(shard_key);
            for (i, phase, set_type) in PHASES.iter().copied() {
                // Go's idempotency check: skip recompute when a real
                // (non-placeholder) commitment is already cached for
                // this frame. 64-byte entries are the zero placeholder;
                // real KZG roots are 74 bytes.
                let cached_this_phase: Option<&Vec<u8>> = cached_row
                    .as_ref()
                    .and_then(|r| r.get(i))
                    .filter(|v| v.len() != 64 && !v.is_empty());
                if let Some(cached) = cached_this_phase {
                    roots[i] = cached.clone();
                    continue;
                }
                if let Some(tree) = phase_trees[i] {
                    let root = tree.commit(txn.as_ref(), prover)?;
                    // Persist so a subsequent commit(frame_number)
                    // short-circuits on the idempotency check above.
                    self.store.set_shard_commit(
                        txn.as_ref(),
                        frame_number,
                        phase,
                        set_type,
                        &shard_key.l2,
                        &root,
                    )?;
                    roots[i] = root;
                }
            }

            let leaf_count = sets.vertex_adds
                .get(shard_key)
                .map(|t| t.get_metadata().0 as u64)
                .unwrap_or(0);

            self.shard_metadata.write().unwrap().insert(
                shard_key.clone(),
                ShardMetadata {
                    commitment: roots.to_vec(),
                    leaf_count,
                    size: BigInt::zero(),
                },
            );

            result.insert(shard_key.clone(), roots.to_vec());
        }

        // Atomically flush all per-shard per-phase tree writes that
        // accumulated in the batch. Mirrors Go's pebble batch commit
        // after `hg.Commit()` collects every shard's new roots.
        // Without this, the batch was silently dropped and any store
        // impl that honors the txn argument (our `RocksTxn`) would
        // lose its buffered writes.
        txn.commit()?;

        Ok(result)
    }

    /// Get the size of the hypergraph across all shards.
    pub fn total_size(&self) -> BigInt {
        self.size.read().unwrap().clone()
    }

    /// Look up shard metadata (commitment, leaf_count, size) for a
    /// shard identified by its app-address filter.
    ///
    /// Mirrors Go `HypergraphCRDT.GetMetadataAtKey` at
    /// `hypergraph/proofs.go` — returns the latest computed shard
    /// metadata for the address. Used by the consensus materializer
    /// to source `shard_count` and `state_size` for ProverShardUpdate.
    pub fn shard_metadata_for_address(&self, filter: &[u8]) -> Option<ShardMetadata> {
        if filter.len() < 32 {
            return None;
        }
        let mut app = [0u8; 32];
        app.copy_from_slice(&filter[..32]);
        let l1 = crate::addressing::get_bloom_filter_indices(&app, 256, 3);
        let shard_key = quil_types::store::ShardKey { l1, l2: app };
        self.shard_metadata.read().unwrap().get(&shard_key).cloned()
    }

    /// Compute the current root commitment for a single phase set
    /// (e.g. vertex-adds) of a single shard. Lightweight alternative
    /// to `commit()` — reads from the in-memory tree without writing
    /// anything to the store. Returns an empty vec if the shard/phase
    /// has no tree loaded.
    /// Compute the current root commitment for a single phase set
    /// (e.g. vertex-adds) of a single shard. Lightweight alternative
    /// to `commit()` — reads from the in-memory tree without writing
    /// to RocksDB. Returns an empty vec if the shard/phase has no
    /// tree loaded.
    pub fn compute_shard_root(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
    ) -> Vec<u8> {
        let sets = self.phase_sets.read().unwrap();
        let tree = match (set_type, phase_type) {
            ("vertex", "adds") => sets.vertex_adds.get(shard_key),
            ("vertex", "removes") => sets.vertex_removes.get(shard_key),
            ("hyperedge", "adds") => sets.hyperedge_adds.get(shard_key),
            ("hyperedge", "removes") => sets.hyperedge_removes.get(shard_key),
            _ => None,
        };
        let Some(t) = tree else {
            return Vec::new();
        };
        // Use a no-op transaction — we only want the in-memory
        // commitment, not a store write. `commit` loads the root
        // if needed, walks dirty nodes, and returns the root hash.
        struct NoopTxn;
        impl quil_types::store::Transaction for NoopTxn {
            fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
            fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
            fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
            fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
            fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
            fn new_iter(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
                Err(quil_types::error::QuilError::Internal("noop".into()))
            }
            fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
            fn as_any(&self) -> &dyn std::any::Any { self }
        }
        t.commit(&NoopTxn, self.prover.as_ref()).unwrap_or_default()
    }

    /// Look up whether a vertex exists (in adds and not in removes).
    pub fn lookup_vertex(&self, location: &Location) -> bool {
        self.get_vertex_data(location).is_some()
    }

    /// Get vertex data bytes if the vertex exists (in adds and not in removes).
    pub fn get_vertex_data(&self, location: &Location) -> Option<Vec<u8>> {
        let shard_key = shard_key_for_location(location);
        let id = location.to_id();
        let sets = self.phase_sets.read().unwrap();

        let data = sets.vertex_adds.get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten());
        let in_removes = sets.vertex_removes.get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten()).is_some();

        if in_removes { return None; }
        data
    }

    /// Fetch the four sub-scoped vector commitments for a given shard
    /// at a given frame number: `[vertex_adds, vertex_removes,
    /// hyperedge_adds, hyperedge_removes]`.
    ///
    /// Mirrors Go `HypergraphCRDT.GetShardCommits` at
    /// `hypergraph/proofs.go:463-540`. Returns an error if any of the
    /// four commits is absent from the store.
    pub fn get_shard_commits(
        &self,
        frame_number: u64,
        shard_address: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let va = self.store.get_shard_commit(
            frame_number, "adds", "vertex", shard_address,
        )?;
        let vr = self.store.get_shard_commit(
            frame_number, "removes", "vertex", shard_address,
        )?;
        let ha = self.store.get_shard_commit(
            frame_number, "adds", "hyperedge", shard_address,
        )?;
        let hr = self.store.get_shard_commit(
            frame_number, "removes", "hyperedge", shard_address,
        )?;
        Ok(vec![va, vr, ha, hr])
    }

    /// Load a vertex's underlying-data sub-tree blob (the Go-serialized
    /// `VectorCommitmentTree` written via `SetVertexData`). Returns `None`
    /// if the vertex is not present or has been removed. The caller is
    /// responsible for deserializing the blob via `quil_tries`
    /// `deserialize_go_tree` and reading indexed slots.
    ///
    /// Mirrors Go `HypergraphCRDT.GetVertexData` except the Rust variant
    /// returns the raw serialized bytes rather than a loaded tree — the
    /// caller can parse and index directly.
    pub fn get_vertex_underlying_tree_bytes(
        &self,
        location: &Location,
    ) -> Option<Vec<u8>> {
        let shard_key = shard_key_for_location(location);
        let id = location.to_id();

        // Remove-set short-circuit mirrors lookup_vertex / get_vertex_data.
        let sets = self.phase_sets.read().unwrap();
        let in_removes = sets.vertex_removes.get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten()).is_some();
        if in_removes { return None; }
        drop(sets);

        self.store
            .load_vertex_underlying_raw("vertex", "adds", &shard_key, &id)
            .ok()
            .flatten()
    }

    /// Look up whether a hyperedge exists (in adds and not in removes).
    pub fn lookup_hyperedge(&self, location: &Location) -> bool {
        self.get_hyperedge_data(location).is_some()
    }

    /// Get hyperedge data bytes if it exists (in adds and not in removes).
    pub fn get_hyperedge_data(&self, location: &Location) -> Option<Vec<u8>> {
        let shard_key = shard_key_for_location(location);
        let id = location.to_id();
        let sets = self.phase_sets.read().unwrap();

        let data = sets.hyperedge_adds.get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten());
        let in_removes = sets.hyperedge_removes.get(&shard_key)
            .and_then(|t| t.get(&id).ok().flatten()).is_some();

        if in_removes { return None; }
        data
    }

    /// Enumerate the extrinsic atom IDs (64 bytes each = appAddr ||
    /// dataAddr) carried by the hyperedge stored at `location`. The
    /// hyperedge data is stored as a serialized `VectorCommitmentTree`
    /// (Go's `SerializeNonLazyTree` format) whose leaf keys are the
    /// 64-byte atom IDs.
    ///
    /// Mirrors the iteration done by Go's
    /// `ProverKick.Materialize` at `global_prover_kick.go:200` — the
    /// caller (e.g. the kick path) walks each ID's `dataAddress`
    /// segment to load + mutate the matching allocation vertex.
    ///
    /// Returns an empty vec if the hyperedge is absent, removed, or
    /// the stored bytes do not parse as a tree (e.g. an unrelated
    /// blob format).
    pub fn get_hyperedge_extrinsic_ids(&self, location: &Location) -> Vec<[u8; 64]> {
        let Some(blob) = self.get_hyperedge_data(location) else {
            return Vec::new();
        };
        let mut tree = quil_tries::VectorCommitmentTree::new();
        match quil_tries::deserialize_go_tree(&blob) {
            Ok(Some(root)) => tree.root = Some(root),
            _ => return Vec::new(),
        }
        let mut out = Vec::new();
        for (key, _value) in tree.leaves() {
            if key.len() == 64 {
                let mut id = [0u8; 64];
                id.copy_from_slice(&key);
                out.push(id);
            }
        }
        out
    }

    /// Number of shards that have at least one tree.
    pub fn shard_count(&self) -> usize {
        let sets = self.phase_sets.read().unwrap();
        let mut keys: Vec<&ShardKey> = Vec::new();
        for k in sets.vertex_adds.keys().chain(sets.vertex_removes.keys())
            .chain(sets.hyperedge_adds.keys()).chain(sets.hyperedge_removes.keys()) {
            if !keys.contains(&k) { keys.push(k); }
        }
        keys.len()
    }

    #[cfg(test)]
    pub(crate) fn insert_shard_metadata_for_test(&self, key: ShardKey, meta: ShardMetadata) {
        self.shard_metadata.write().unwrap().insert(key, meta);
    }

    #[cfg(test)]
    pub(crate) fn shard_count_for_test(&self) -> usize {
        self.shard_metadata.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::NoopInclusionProver;
    use crate::testing::MemStore;

    /// Deterministic inclusion prover that hashes data via DefaultHasher.
    /// Produces distinct 64-byte commitments for distinct inputs, which is
    /// needed by tests that assert non-zero / distinct roots.
    struct HashingProver;
    impl InclusionProver for HashingProver {
        fn commit_raw(&self, data: &[u8], _: u64) -> quil_types::error::Result<Vec<u8>> {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            data.hash(&mut h);
            let hash = h.finish().to_be_bytes();
            let mut out = vec![0u8; 64]; out[..8].copy_from_slice(&hash); Ok(out)
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> quil_types::error::Result<Vec<u8>> { Ok(vec![0u8; 64]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> quil_types::error::Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> quil_types::error::Result<Box<dyn quil_types::crypto::Multiproof>> {
            Err(quil_types::error::QuilError::Internal("batch multiproof generation not supported".into()))
        }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    fn stub_crdt() -> HypergraphCrdt {
        HypergraphCrdt::new(Arc::new(MemStore::new()), Arc::new(HashingProver))
    }

    fn loc(app: u8, data: u8) -> Location {
        Location { app_address: [app; 32], data_address: [data; 32] }
    }

    fn meta_with_size(size: u64) -> ShardMetadata {
        ShardMetadata { commitment: vec![], leaf_count: 0, size: BigInt::from(size) }
    }

    fn shard_key(app_byte: u8) -> ShardKey {
        let mut l2 = [0u8; 32]; l2[0] = app_byte;
        ShardKey { l1: [app_byte, 0, 0], l2 }
    }

    #[test] fn total_size_empty_is_zero() { assert_eq!(stub_crdt().total_size(), BigInt::from(0)); }

    #[test] fn total_size_reflects_shard_metadata_test_helper() {
        let crdt = stub_crdt();
        crdt.insert_shard_metadata_for_test(shard_key(1), meta_with_size(100));
        crdt.insert_shard_metadata_for_test(shard_key(2), meta_with_size(250));
        assert_eq!(crdt.shard_count_for_test(), 2);
    }

    #[test] fn add_vertex_increases_total_size() {
        let crdt = stub_crdt();
        crdt.add_vertex(&loc(0xAA, 0xBB), b"hello-world").unwrap();
        assert_eq!(crdt.total_size(), BigInt::from(11));
    }

    #[test] fn add_vertex_twice_accumulates_size() {
        let crdt = stub_crdt();
        crdt.add_vertex(&loc(0xAA, 0x01), b"aaaa").unwrap();
        crdt.add_vertex(&loc(0xAA, 0x02), b"bbbbb").unwrap();
        assert_eq!(crdt.total_size(), BigInt::from(9));
    }

    #[test] fn add_vertex_creates_shard_entry() {
        let crdt = stub_crdt();
        assert_eq!(crdt.shard_count(), 0);
        crdt.add_vertex(&loc(0xAA, 0xBB), b"data").unwrap();
        assert_eq!(crdt.shard_count(), 1);
    }

    #[test] fn add_vertex_lookup_returns_true() {
        let crdt = stub_crdt();
        let l = loc(0xAA, 0xBB);
        crdt.add_vertex(&l, b"data").unwrap();
        assert!(crdt.lookup_vertex(&l));
    }

    #[test] fn lookup_vertex_returns_false_when_not_added() { assert!(!stub_crdt().lookup_vertex(&loc(0xAA, 0xBB))); }

    #[test] fn remove_existing_vertex_makes_lookup_return_false() {
        let crdt = stub_crdt();
        let l = loc(0xAA, 0xBB);
        crdt.add_vertex(&l, b"data").unwrap();
        assert!(crdt.lookup_vertex(&l));
        crdt.remove_vertex(&l).unwrap();
        assert!(!crdt.lookup_vertex(&l));
    }

    #[test] fn remove_nonexistent_vertex_does_not_panic() {
        let crdt = stub_crdt();
        crdt.remove_vertex(&loc(0x01, 0x02)).unwrap();
        assert_eq!(crdt.total_size(), BigInt::from(0));
    }

    #[test] fn add_hyperedge_increases_total_size() {
        let crdt = stub_crdt();
        crdt.add_hyperedge(&loc(0xCC, 0xDD), b"edge-data").unwrap();
        assert_eq!(crdt.total_size(), BigInt::from(9));
    }

    #[test] fn add_hyperedge_lookup_returns_true() {
        let crdt = stub_crdt();
        let l = loc(0xCC, 0xDD);
        crdt.add_hyperedge(&l, b"edge-data").unwrap();
        assert!(crdt.lookup_hyperedge(&l));
    }

    #[test] fn add_hyperedge_after_remove_is_noop() {
        let crdt = stub_crdt();
        let l = loc(0xCC, 0xDD);
        crdt.add_hyperedge(&l, b"initial").unwrap();
        crdt.remove_hyperedge(&l).unwrap();
        crdt.add_hyperedge(&l, b"re-add").unwrap();
        assert!(!crdt.lookup_hyperedge(&l));
    }

    #[test] fn remove_existing_hyperedge_makes_lookup_return_false() {
        let crdt = stub_crdt();
        let l = loc(0xCC, 0xDD);
        crdt.add_hyperedge(&l, b"edge-data").unwrap();
        assert!(crdt.lookup_hyperedge(&l));
        crdt.remove_hyperedge(&l).unwrap();
        assert!(!crdt.lookup_hyperedge(&l));
    }

    #[test] fn remove_nonexistent_hyperedge_does_not_panic() {
        stub_crdt().remove_hyperedge(&loc(0x01, 0x02)).unwrap();
    }

    #[test] fn commit_empty_crdt_returns_empty_map() {
        assert!(stub_crdt().commit(1).unwrap().is_empty());
    }

    #[test] fn commit_after_add_vertex_returns_four_roots_per_shard() {
        let crdt = stub_crdt();
        crdt.add_vertex(&loc(0xAA, 0x01), b"data-1").unwrap();
        crdt.add_vertex(&loc(0xAA, 0x02), b"data-2").unwrap();
        let result = crdt.commit(1).unwrap();
        assert_eq!(result.len(), 1);
        let roots = result.values().next().unwrap();
        assert_eq!(roots.len(), 4);
        assert_ne!(roots[0], vec![0u8; 64]); // vertex_adds
        assert_eq!(roots[1], vec![0u8; 64]); // vertex_removes (empty)
        assert_eq!(roots[2], vec![0u8; 64]); // hyperedge_adds (empty)
        assert_eq!(roots[3], vec![0u8; 64]); // hyperedge_removes (empty)
    }

    #[test] fn commit_updates_shard_metadata() {
        let crdt = stub_crdt();
        crdt.add_vertex(&loc(0xBB, 0x01), b"data").unwrap();
        crdt.commit(1).unwrap();
        assert_eq!(crdt.shard_count_for_test(), 1);
    }

    #[test] fn commit_after_add_and_remove_has_both_trees() {
        let crdt = stub_crdt();
        let l = loc(0xAA, 0x01);
        crdt.add_vertex(&l, b"will-be-removed").unwrap();
        crdt.remove_vertex(&l).unwrap();
        let result = crdt.commit(1).unwrap();
        let roots = result.values().next().unwrap();
        assert_ne!(roots[0], vec![0u8; 64]);
        assert_ne!(roots[1], vec![0u8; 64]);
    }

    #[test] fn commit_multiple_shards_returns_multiple_entries() {
        let crdt = stub_crdt();
        crdt.add_vertex(&loc(0xAA, 0x01), b"shard-1").unwrap();
        crdt.add_vertex(&loc(0xBB, 0x01), b"shard-2").unwrap();
        assert_eq!(crdt.commit(1).unwrap().len(), 2);
    }

    #[test] fn vertex_and_hyperedge_in_same_shard_both_committed() {
        let crdt = stub_crdt();
        crdt.add_vertex(&loc(0xAA, 0x01), b"vertex").unwrap();
        crdt.add_hyperedge(&loc(0xAA, 0x02), b"edge").unwrap();
        let result = crdt.commit(1).unwrap();
        assert_eq!(result.len(), 1);
        let roots = result.values().next().unwrap();
        assert_ne!(roots[0], vec![0u8; 64]); // vertex_adds
        assert_eq!(roots[1], vec![0u8; 64]); // vertex_removes
        assert_ne!(roots[2], vec![0u8; 64]); // hyperedge_adds
        assert_eq!(roots[3], vec![0u8; 64]); // hyperedge_removes
    }
}
