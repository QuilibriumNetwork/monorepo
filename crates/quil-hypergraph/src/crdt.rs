//! Forest-native hypergraph CRDT.
//!
//! The state-commitment authority is the [`quil_forest::Forest`] (a hash-Merkle
//! JMT), NOT a KZG vector-commitment trie. Each shard has four independent JMT
//! phase trees (the OR-set: vertex/hyperedge × adds/removes); their four
//! 32-byte roots are the header `state_roots`.
//!
//! Two stores work together, and neither is a KZG trie:
//! - **The forest** holds the *commitment* — each vertex's fields flattened
//! into Level-3 leaves (`l3_leaf_key(id, field_key)`), so a branch commit is
//! a hash, not a G1 multiexp. An empty value is a tombstone leaf keyed by the
//! id (OR-set `removes` / add-side placeholder) so the phase root reflects
//! removals.
//! - **The `HypergraphStore` KV keyspace** holds the per-vertex *blobs*
//! (`save_vertex_underlying`/`load_vertex_underlying_raw`), keyed by id and
//! RocksDB-prefix-scannable. Reads (`get_vertex_data`) and the PoRep /
//! shard-info path navigation read from here — plain key-value, no trie.
//!
//! Mutations stage leaf deltas + blobs in memory; `commit` applies the deltas
//! to the forest (JMT `put_value_set` is natively incremental) and persists the
//! blobs, staging forest writes + the durable materialization cursor into one
//! atomic `Transaction` so they can never diverge.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use num_traits::Zero;

use quil_forest::{
    app_membership_path_dynamic, app_root_from_shard_paths, canonical_shard_bit_paths, l3_leaf_key,
    rollup_phase_roots, Forest, PHASES,
};
use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};
use quil_types::store::{HypergraphStore, ShardKey};

use crate::addressing::{shard_key_for_location, Location};

pub use crate::snapshot::{GenerationHandle, SnapshotManager};

/// `(set_type, phase_type)` string pair for each phase index (0..4), matching
/// the store's keying and `quil_forest::PHASES` order.
const PHASE_STR: [(&str, &str); 4] = [
    ("vertex", "adds"),
    ("vertex", "removes"),
    ("hyperedge", "adds"),
    ("hyperedge", "removes"),
];

/// Expand a UNIFORM 64-way split `depth` into its complete prefix set: depth 0 ⇒
/// `[[]]` (single shard); depth 1 ⇒ `{[0]..[63]}` (QUIL); etc. Used by the
/// convenience [`HypergraphCrdt::set_shard_partition`].
fn expand_uniform_prefixes(depth: u32) -> Vec<Vec<u32>> {
    let mut prefixes = vec![Vec::new()];
    for _ in 0..depth {
        let mut next = Vec::with_capacity(prefixes.len() * 64);
        for p in &prefixes {
            for i in 0..64u32 {
                let mut q = p.clone();
                q.push(i);
                next.push(q);
            }
        }
        prefixes = next;
    }
    prefixes
}


/// Per-shard committed metadata surfaced to the consensus materializer
/// (`ProverShardUpdate` reads `shard_count`/`state_size`).
#[derive(Debug, Clone)]
pub struct ShardMetadata {
    /// The four 32-byte phase roots (`state_roots`).
    pub commitment: Vec<Vec<u8>>,
    pub leaf_count: u64,
    pub size: BigInt,
}

/// Staged, not-yet-committed leaf changes for one (shard, phase): the L3 leaf
/// puts (key → value). All forest deltas are puts — the OR-set never deletes a
/// leaf; it writes tombstones instead.
type PhaseDeltas = BTreeMap<Vec<u8>, Vec<u8>>;
/// Staged per-vertex blobs for one (shard, phase): id → blob (persisted to the
/// store KV at commit; also read before commit).
type PhaseBlobs = BTreeMap<Vec<u8>, Vec<u8>>;

/// The forest-native hypergraph CRDT.
pub struct HypergraphCrdt {
    /// Key-value store: per-vertex blobs, the shard-commit cache, the cursor.
    store: Arc<dyn HypergraphStore>,
    /// Legacy KZG inclusion prover — retained only for the [`prover`](Self::prover)
    /// accessor that a few callers still use to commit ancillary KZG sub-trees.
    /// The CRDT's own state commitment never uses it.
    prover: Arc<dyn InclusionProver>,
    /// The state-commitment forest (JMT). `in_memory` by default so
    /// `MemStore`-backed tests work; production installs the namespaced RocksDB
    /// forest via [`set_forest`](Self::set_forest).
    forest: RwLock<Forest>,
    /// Monotonic JMT commit version (roots are content-addressed, so only
    /// monotonicity matters).
    forest_version: AtomicU64,
    /// Coarse serialization for FOREST WRITES. Global-frame materialization
    /// (a whole verify + apply + commit) and prover-tree SYNC both mutate the
    /// forest; they must never interleave. Without this a sync — fired by a
    /// prover-root mismatch — can advance the forest out from under a
    /// materialize's pre-apply prover-root verify (which then reads state AHEAD
    /// of N-1 and forks the root, firing another sync: a self-amplifying loop).
    /// Both the materializer and the syncer hold this for their WHOLE operation,
    /// enforcing the single-writer, monotonic forest invariant.
    forest_write_lock: std::sync::Mutex<()>,
    /// Deterministic per-frame global-prover-shard root: `frame N → the prover
    /// vertex-adds root AFTER materializing frame N`. Written by the frame
    /// materializer the instant it finishes frame N; read by BOTH the leader
    /// (which binds `prover_root_at(N-1)` — the PARENT root — into frame N's
    /// header) and the follower's pre-apply cross-check (which compares its own
    /// `prover_root_at(N-1)`). This replaces reading the LIVE forest at proposal
    /// time, which is RACY: the async materializer may or may not have advanced
    /// the forest to frame N by the moment the leader proposes N, so a live read
    /// lands on N-1 or N unpredictably and forks the commitment. All nodes
    /// materialize a frame to the identical root, so this map is identical
    /// network-wide. Bounded to the most recent frames.
    prover_root_by_frame: RwLock<std::collections::BTreeMap<u64, Vec<u8>>>,
    /// The exact JMT version each `(shard, phase)` tree was last committed at.
    /// `get_with_proof`/`get_root_hash_option` need the precise version a tree
    /// was written at (they do not walk back to the latest ≤ v), and each
    /// phase commits at its own `next_forest_version()`, so a global
    /// `forest_version` snapshot does not identify a specific tree's head.
    /// The producer ([`build_membership_proof`](Self::build_membership_proof))
    /// reads this to prove against the tree's current root.
    /// Keyed by `(shard_id, phase)` where `shard_id` is the forest tree id:
    /// `addr_path_shard_id(app, prefix)`. For a single-shard app that is just
    /// the app address (`shard.l2`); for a split app (QUIL) it is the app
    /// address ‖ the sub-shard prefix, so each of the 64 sub-shard trees tracks
    /// its own version.
    phase_versions: RwLock<HashMap<(Vec<u8>, usize), u64>>,
    /// The exact JMT version each Level-1 global bucket tree (keyed by first
    /// address byte `0..=255`) was last committed at — the L1 analogue of
    /// [`phase_versions`](Self::phase_versions). Seeded from the persisted
    /// head marker (`forest.read_global_head_version`, written by the
    /// migration and every live commit) so version-exact reads
    /// ([`global_commitments`](Self::global_commitments)) address the current
    /// bucket root across restarts and on the mem backend.
    global_versions: RwLock<HashMap<u8, u64>>,
    /// Apps that split into address-path sub-shards, mapped to their COMPLETE
    /// shard-prefix set (each prefix a `ShardInfo.prefix`: QUIL 6-bit indices or
    /// split-marker bytes — see [`canonical_shard_bit_paths`]). Absent ⇒ the app
    /// is a single shard (the default — every unsplit app). The node populates
    /// this from the shards store so `commit_inner` splits + aggregates exactly
    /// the apps' real, possibly non-uniform, shard sets (matching the converter).
    #[allow(clippy::type_complexity)]
    app_shard_prefixes: RwLock<HashMap<[u8; 32], Vec<Vec<u32>>>>,
    /// DEEP-BIFURCATION (Phase 2): each app's shard address BIT-PATHS, stored
    /// DIRECTLY (not derived from `app_shard_prefixes` via
    /// `canonical_shard_bit_paths`, which can't carry a bit-path that skips
    /// uniform bits). When present for an app, [`Self::shard_bit_paths`] returns
    /// these; absent ⇒ it falls back to canonical of `app_shard_prefixes`. MUST
    /// be index-aligned with `app_shard_prefixes` (same order/count) — the routing
    /// indexes both. Empty by default (canonical source); populated at the
    /// deep-bifurcation flag day. See `DEEP_BIFURCATION_ENCODING_SCOPE.md`.
    #[allow(clippy::type_complexity)]
    app_shard_bit_paths: RwLock<HashMap<[u8; 32], Vec<Vec<bool>>>>,
    /// Staged L3 leaf deltas per (shard, phase index).
    pending: RwLock<HashMap<(ShardKey, usize), PhaseDeltas>>,
    /// Staged per-vertex blobs per (shard, phase index).
    pending_blobs: RwLock<HashMap<(ShardKey, usize), PhaseBlobs>>,
    /// Latest committed per-shard metadata.
    shard_metadata: RwLock<HashMap<ShardKey, ShardMetadata>>,
    /// Per-sub-shard live state metadata: `forest shard_id -> (raw_count, size)`.
    /// `size` is the LIVE byte size accounting for ALL four phases — Σ present
    /// vertices' blob size (adds MINUS removes) + Σ present hyperedges' blob size
    /// (adds MINUS removes) — bucketed by the real forest partition. `raw_count`
    /// is the vertex-adds leaf count (monotonic, tombstone-inclusive), the reward
    /// `shard_count`. `total_size()` is Σ of all sizes (the prover shard 0xff is
    /// excluded — its registry/reward vertices aren't reward-bearing state).
    /// Maintained live in the mutation methods; the migrated baseline is seeded
    /// once by [`warm_sizes`](Self::warm_sizes) at startup.
    sub_meta: RwLock<HashMap<Vec<u8>, (u64, i128)>>,
    /// Set once `warm_sizes` has seeded the committed baseline.
    sizes_warmed: AtomicBool,
    /// Snapshot-generation registry for sync `expected_root` gating.
    snapshot_mgr: SnapshotManager,
    /// Covered nibble prefix (address gating). Empty = accept all.
    covered_prefix: RwLock<Vec<i32>>,
    /// Serializes commits against each other.
    commit_lock: std::sync::Mutex<()>,
    /// UNIFIED-APP-TREE mode (Phase 2, `UNIFIED_APP_TREE_DESIGN.md`). When set,
    /// every app commits ALL its vertices into ONE L3 tree per phase keyed by the
    /// app address (leaves raw-key positioned), so a shard is the in-place subtree
    /// at its prefix and the app-phase root is the JMT root over all shards — no
    /// separate per-sub-shard trees, no `app_root_from_shard_paths` rollup, no
    /// per-frame manifest. Per-shard commitments are read on demand via
    /// [`Forest::app_subtree_root`]. DEFAULT off (legacy separate-tree path);
    /// flipped at the flag-day frame AFTER the one-time consolidation (§9), since
    /// a split app's existing data lives in the per-prefix trees until then.
    unified_tree: AtomicBool,
}

impl HypergraphCrdt {
    pub fn new(store: Arc<dyn HypergraphStore>, prover: Arc<dyn InclusionProver>) -> Self {
        Self {
            store,
            prover,
            forest: RwLock::new(Forest::in_memory()),
            forest_version: AtomicU64::new(0),
            forest_write_lock: std::sync::Mutex::new(()),
            prover_root_by_frame: RwLock::new(std::collections::BTreeMap::new()),
            phase_versions: RwLock::new(HashMap::new()),
            global_versions: RwLock::new(HashMap::new()),
            app_shard_prefixes: RwLock::new(HashMap::new()),
            app_shard_bit_paths: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            pending_blobs: RwLock::new(HashMap::new()),
            shard_metadata: RwLock::new(HashMap::new()),
            sub_meta: RwLock::new(HashMap::new()),
            sizes_warmed: AtomicBool::new(false),
            snapshot_mgr: SnapshotManager::new(),
            covered_prefix: RwLock::new(Vec::new()),
            commit_lock: std::sync::Mutex::new(()),
            unified_tree: AtomicBool::new(false),
        }
    }

    /// Enable/disable [`unified_tree`](Self::unified_tree) mode. Flag-day gated in
    /// production (set only after the one-time consolidation); tests flip it
    /// directly on a fresh CRDT.
    pub fn set_unified_tree(&self, on: bool) {
        self.unified_tree.store(on, Ordering::SeqCst);
    }

    /// Whether unified-app-tree mode is active.
    pub fn unified_tree(&self) -> bool {
        self.unified_tree.load(Ordering::Relaxed)
    }

    /// Install the state-commitment forest (production: the namespaced RocksDB
    /// forest sharing the store's DB). Replaces the default in-memory forest.
    pub fn set_forest(&self, forest: Forest) {
        *self.forest.write().unwrap() = forest;
    }

    /// Acquire the coarse forest-write serialization guard. Held for the WHOLE
    /// duration by the global-frame materializer (verify + apply + commit) and
    /// by the prover-tree syncer (its forest apply), so the two never write the
    /// forest concurrently. Poisoning is recovered (a panic mid-write is already
    /// a stop-the-materializer condition upstream). See `forest_write_lock`.
    pub fn lock_forest_writes(&self) -> std::sync::MutexGuard<'_, ()> {
        self.forest_write_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Always true now — the CRDT is forest-native. Retained for callers that
    /// gate on it during the transition.
    pub fn has_forest(&self) -> bool {
        true
    }

    /// Whether the installed forest is the persistent (RocksDB-backed) one, as
    /// opposed to the default ephemeral in-memory forest. A node that boots on a
    /// non-migrated store starts in-memory; onboarding via sync must swap in the
    /// persistent forest (see `install_forest_for_sync`) so synced + produced
    /// state actually lands on disk.
    pub fn forest_is_persistent(&self) -> bool {
        self.forest.read().unwrap().db().is_some()
    }

    /// Declare that `app` splits UNIFORMLY into `64^depth` sub-shards (QUIL =
    /// depth 1 ⇒ 64). Convenience over [`set_app_shard_prefixes`] for the uniform
    /// case; expands to the full prefix set `{[i]}` / `{[i,j]}` / … The set MUST
    /// match the converter's `quil_shards_for_app` and every other node's, since
    /// it changes the committed state root.
    pub fn set_shard_partition(&self, app: [u8; 32], depth: u32) {
        self.set_app_shard_prefixes(app, expand_uniform_prefixes(depth));
    }

    /// Declare `app`'s COMPLETE shard-prefix set explicitly — the general form
    /// that supports dynamic, NON-UNIFORM splits (binary/quaternary/octal at
    /// mixed depths). Each prefix is a `ShardInfo.prefix` exactly as the shards
    /// store holds it. The node populates this from the shards store; the set
    /// must be complete + prefix-free (every split writes all its children).
    /// Returns `true` iff this TRANSITIONED an already-registered app to a
    /// different prefix set (a split or merge just landed) — the caller uses that
    /// to trigger [`rebucket_app`], re-partitioning the size buckets so
    /// freshly-created leaves don't read 0. First-sight population (init /
    /// post-restart priming) returns `false`: the buckets there come from
    /// `warm_sizes` (persisted fast-path or cold scan), which must not be clobbered.
    pub fn set_app_shard_prefixes(&self, app: [u8; 32], prefixes: Vec<Vec<u32>>) -> bool {
        let set = if prefixes.is_empty() { vec![Vec::new()] } else { prefixes };
        let mut w = self.app_shard_prefixes.write().unwrap();
        match w.get(&app) {
            Some(existing) if *existing == set => false, // unchanged
            Some(_) => {
                w.insert(app, set);
                true // genuine split/merge transition
            }
            None => {
                w.insert(app, set);
                false // first sight — warm_sizes owns the initial buckets
            }
        }
    }

    /// The complete address-path shard prefix set for `app`: a single empty
    /// prefix (the whole app is one shard — the default) unless a split set was
    /// declared via [`set_app_shard_prefixes`] / [`set_shard_partition`]. The set
    /// is COMPLETE + prefix-free so the app-root aggregation is deterministic
    /// across nodes.
    fn app_prefixes(&self, app: &[u8; 32]) -> Vec<Vec<u32>> {
        self.app_shard_prefixes
            .read()
            .unwrap()
            .get(app)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new()])
    }

    /// Declare `app`'s shard address BIT-PATHS directly (deep-bifurcation Phase 2).
    /// MUST be index-aligned with the prefix set from [`set_app_shard_prefixes`]
    /// (same order/count) — routing indexes both. Empty ⇒ clears the override
    /// (back to canonical derivation).
    pub fn set_app_shard_bit_paths(&self, app: [u8; 32], bit_paths: Vec<Vec<bool>>) {
        let mut w = self.app_shard_bit_paths.write().unwrap();
        if bit_paths.is_empty() {
            w.remove(&app);
        } else {
            w.insert(app, bit_paths);
        }
    }

    /// The canonical address bit-path of every shard of `app`, IN PREFIX ORDER —
    /// the single source the routing (`address_shard_index`) and aggregation
    /// (`app_root_from_shard_paths`) consume. Directly-stored bit-paths
    /// ([`Self::set_app_shard_bit_paths`], the deep-bifurcation path) when present;
    /// otherwise derived from the `Vec<u32>` prefixes via
    /// [`canonical_shard_bit_paths`] (the default — lossless for every current
    /// uniform/marker split, so swapping the source is a no-op until a deep split
    /// stores a bit-path the `Vec<u32>` form can't express).
    fn shard_bit_paths(&self, app: &[u8; 32]) -> Vec<Vec<bool>> {
        if let Some(bp) = self.app_shard_bit_paths.read().unwrap().get(app) {
            return bp.clone();
        }
        let prefixes = self.app_prefixes(app);
        // Deep-bifurcation: a post-cutover app's shards are persisted as
        // SENTINEL-tagged bit-path prefixes (`bit_path_to_prefix`, riding the
        // existing `ShardInfo.prefix`). The migration converts an app's whole set
        // ATOMICALLY, so it's all-sentinel or all-legacy — never mixed (canonical
        // can't resolve a mixed set). All-sentinel ⇒ decode directly; otherwise
        // resolve the legacy set via canonical.
        if !prefixes.is_empty()
            && prefixes
                .iter()
                .all(|p| quil_forest::shard_bit_path_from_prefix(p).is_some())
        {
            return prefixes
                .iter()
                .map(|p| quil_forest::shard_bit_path_from_prefix(p).unwrap())
                .collect();
        }
        canonical_shard_bit_paths(&prefixes)
    }

    /// Commit one shard/phase tree's flattened L3 leaves, staging the forest node
    /// writes + the DB head-version into `txn`, and record the version (in-memory
    /// + DB) so version-exact reads address it. Returns the new 32-byte root.
    /// `forest` is the caller's held read guard.
    ///
    /// The commit version is this TREE's own last version + 1 (0 for a first
    /// commit) — JMT builds an incremental commit on the root at `version - 1`,
    /// so per-tree versions MUST be contiguous. A single global counter (which
    /// other trees also bump) would leave gaps, and JMT would then build on a
    /// missing base and silently drop the tree's prior leaves.
    fn commit_one_shard_phase(
        &self,
        forest: &Forest,
        txn: &dyn quil_types::store::Transaction,
        shard_id: &[u8],
        phase_idx: usize,
        leaves: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<([u8; 32], u64)> {
        let ver = self
            .resolve_phase_version_with(forest, shard_id, phase_idx)
            .map(|v| v + 1)
            .unwrap_or(0);
        let (root, puts) = forest
            .commit_shard_phase_raw_staged(shard_id, PHASES[phase_idx], ver, leaves)
            .map_err(|e| QuilError::Internal(format!("forest commit: {e}")))?;
        self.phase_versions
            .write()
            .unwrap()
            .insert((shard_id.to_vec(), phase_idx), ver);
        for (k, v) in puts {
            txn.set(&k, &v)?;
        }
        if let Some((hk, hv)) = forest.head_version_put(shard_id, PHASES[phase_idx], ver) {
            txn.set(&hk, &hv)?;
        }
        Ok((root, ver))
    }

    /// [`resolve_phase_version`] but reading `read_head_version` off the caller's
    /// already-held forest guard, so it is safe to call while `self.forest` is
    /// read-locked (which [`resolve_phase_version`] is not — it re-locks).
    fn resolve_phase_version_with(
        &self,
        forest: &Forest,
        shard_id: &[u8],
        phase_idx: usize,
    ) -> Option<u64> {
        self.phase_versions
            .read()
            .unwrap()
            .get(&(shard_id.to_vec(), phase_idx))
            .copied()
            .or_else(|| forest.read_head_version(shard_id, PHASES[phase_idx]).ok().flatten())
    }

    /// The last-committed version of Level-1 global bucket `index`: the
    /// in-memory cache (covers the mem backend / same-process commits) falling
    /// back to the persisted head marker. `None` before the bucket has ever
    /// been committed. L1 analogue of [`resolve_phase_version_with`].
    fn resolve_global_version(&self, forest: &Forest, index: u8) -> Option<u64> {
        self.global_versions
            .read()
            .unwrap()
            .get(&index)
            .copied()
            .or_else(|| forest.read_global_head_version(index).ok().flatten())
    }

    /// The current 32-byte root of one shard/phase tree at its last committed
    /// version (`[0; 32]` if there is no such tree). `forest` is the held guard.
    ///
    /// When neither the in-memory map nor a persisted head version identifies the
    /// tree — which is the case for state written by the MIGRATION converter,
    /// committed at version 0 without a head-version marker — fall back to the
    /// global forest version (0 on a freshly-migrated node), matching the legacy
    /// `commit_inner` read. Without this, migrated-but-untouched shards would read
    /// as empty and corrupt the app root.
    fn read_shard_phase_root(&self, forest: &Forest, shard_id: &[u8], phase_idx: usize) -> [u8; 32] {
        let ver = self
            .resolve_phase_version_with(forest, shard_id, phase_idx)
            .unwrap_or_else(|| self.forest_version.load(Ordering::SeqCst));
        forest
            .shard_phase_root(shard_id, PHASES[phase_idx], ver)
            .ok()
            .flatten()
            .unwrap_or([0u8; 32])
    }

    /// The app's current phase root: a single-shard app is one tree keyed by the
    /// app address; a split app aggregates its sub-shard roots (positioned by
    /// prefix) via [`app_root_from_shard_paths`]. Used when a phase has nothing
    /// staged this frame yet has no cached root to reuse.
    fn current_app_phase_root(
        &self,
        forest: &Forest,
        app: &[u8; 32],
        prefixes: &[Vec<u32>],
        phase_idx: usize,
    ) -> Vec<u8> {
        // Unified mode: the app is one tree keyed by the app address, so the
        // app-phase root is that tree's root directly (no sub-shard aggregation).
        if self.unified_tree() || (prefixes.len() == 1 && prefixes[0].is_empty()) {
            return self.read_shard_phase_root(forest, app, phase_idx).to_vec();
        }
        let bit_paths = self.shard_bit_paths(app);
        let shard_roots: Vec<(Vec<bool>, [u8; 32])> = prefixes
            .iter()
            .zip(bit_paths)
            .map(|(prefix, bits)| {
                let shard_id = Forest::addr_path_shard_id(app, prefix);
                (bits, self.read_shard_phase_root(forest, &shard_id, phase_idx))
            })
            .collect();
        app_root_from_shard_paths(&shard_roots).to_vec()
    }

    /// Borrow the legacy inclusion prover (ancillary KZG sub-tree callers).
    pub fn prover(&self) -> &Arc<dyn InclusionProver> {
        &self.prover
    }

    /// Record the deterministic global-prover-shard root produced by
    /// materializing `frame` (post-state root). Called by the frame materializer
    /// the instant frame `frame` finishes. Bounded to the most recent 256 frames.
    /// See [`prover_root_by_frame`](Self::prover_root_by_frame).
    pub fn record_prover_root(&self, frame: u64, root: Vec<u8>) {
        if root.is_empty() {
            return;
        }
        let mut map = self.prover_root_by_frame.write().unwrap();
        map.insert(frame, root);
        while map.len() > 256 {
            let oldest = *map.keys().next().unwrap();
            map.remove(&oldest);
        }
    }

    /// The deterministic global-prover-shard root as of the END of `frame`
    /// (post-materialization). `None` if that frame hasn't been recorded yet
    /// (fresh node / pruned). The leader binds `prover_root_at(N-1)` into frame
    /// N's header; the follower verifies against the same. See
    /// [`prover_root_by_frame`](Self::prover_root_by_frame).
    pub fn prover_root_at(&self, frame: u64) -> Option<Vec<u8>> {
        self.prover_root_by_frame
            .read()
            .unwrap()
            .get(&frame)
            .cloned()
    }

    // ---- covered prefix -------------------------------------------------

    pub fn get_covered_prefix(&self) -> Vec<i32> {
        self.covered_prefix.read().unwrap().clone()
    }

    pub fn set_covered_prefix(&self, prefix: &[i32]) -> Result<()> {
        *self.covered_prefix.write().unwrap() = prefix.to_vec();
        self.store.set_covered_prefix(prefix)
    }

    // ---- per-vertex leaf helper -----------------------------------------

    /// One `(id, blob)` → its SINGLE per-vertex shard leaf: the vertex's own
    /// hash-Merkle commitment `‖ size`, keyed by the vertex's 32-byte DATA
    /// address (`id = app(32) ‖ data(32)` ⇒ `data = id[32..64]`). This is the
    /// per-vertex-subtree model — each vertex is one raw-key leaf in the shard
    /// tree whose value is `vertex_leaf_value(blob)` = `commitment(32) ‖
    /// size(u64 BE)`. Empty/non-tree blobs are handled tolerantly by
    /// [`quil_tries::vertex_leaf_value`]. Mirrors
    /// `quil_forest_migrate::per_vertex_phase_leaves` (kept in sync — migration
    /// and live commit MUST produce identical roots).
    fn per_vertex_leaf(id: &[u8], blob: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let data_address = if id.len() >= 64 { id[32..64].to_vec() } else { id.to_vec() };
        let value = quil_tries::vertex_leaf_value(blob)?;
        Ok(vec![(data_address, value)])
    }

    /// Stage a `(id, blob)` into (shard, phase): record the blob and its single
    /// per-vertex leaf.
    fn stage(&self, shard: &ShardKey, phase_idx: usize, id: &[u8], blob: &[u8]) -> Result<()> {
        let deltas = Self::per_vertex_leaf(id, blob)?;
        {
            let mut p = self.pending.write().unwrap();
            let entry = p.entry((shard.clone(), phase_idx)).or_default();
            for (k, v) in deltas {
                entry.insert(k, v);
            }
        }
        {
            let mut b = self.pending_blobs.write().unwrap();
            b.entry((shard.clone(), phase_idx))
                .or_default()
                .insert(id.to_vec(), blob.to_vec());
        }
        Ok(())
    }

    // ---- read helpers (KV blobs + tombstone check) ----------------------

    /// The staged-or-committed blob for `(shard, phase, id)`, or `None`.
    fn read_blob(&self, shard: &ShardKey, phase_idx: usize, id: &[u8]) -> Option<Vec<u8>> {
        if let Some(m) = self.pending_blobs.read().unwrap().get(&(shard.clone(), phase_idx)) {
            if let Some(b) = m.get(id) {
                return Some(b.clone());
            }
        }
        let (set, phase) = PHASE_STR[phase_idx];
        self.store
            .load_vertex_underlying_raw(set, phase, shard, id)
            .ok()
            .flatten()
    }

    /// Whether `(shard, phase, id)` has any entry (staged or committed).
    fn has_entry(&self, shard: &ShardKey, phase_idx: usize, id: &[u8]) -> bool {
        self.read_blob(shard, phase_idx, id).is_some()
    }

    // ---- per-sub-shard live metadata (size + raw count) -----------------

    /// The forest sub-shard id (`addr_path_shard_id(app, prefix)`) a vertex's
    /// DATA address routes to — the same top-6-bit partition the state trees
    /// commit under. Single-shard app ⇒ the app id itself.
    fn sub_shard_id_for(&self, app: &[u8; 32], data_addr: &[u8]) -> Vec<u8> {
        let prefixes = self.app_prefixes(app);
        if prefixes.len() == 1 && prefixes[0].is_empty() {
            Forest::addr_path_shard_id(app, &[])
        } else {
            let bit_paths = self.shard_bit_paths(app);
            let pi = quil_forest::address_shard_index(data_addr, &bit_paths);
            Forest::addr_path_shard_id(app, &prefixes[pi])
        }
    }

    /// Apply `(Δcount, Δsize)` to a vertex's sub-shard bucket. The global prover
    /// shard (`l2 == 0xff`) is EXCLUDED from world size: its prover registry /
    /// per-epoch leaf-root registry / reward vertices are not proven or stored by
    /// regular workers, so they must never count toward the issuance denominator.
    fn bump_meta(&self, shard: &ShardKey, data_addr: &[u8], d_count: i64, d_size: i128) {
        if shard.l2 == [0xFFu8; 32] {
            return;
        }
        let shard_id = self.sub_shard_id_for(&shard.l2, data_addr);
        let mut m = self.sub_meta.write().unwrap();
        let e = m.entry(shard_id).or_insert((0, 0));
        e.0 = (e.0 as i64 + d_count).max(0) as u64;
        e.1 += d_size;
    }

    // ---- mutations ------------------------------------------------------

    pub fn add_vertex(&self, location: &Location, data: &[u8]) -> Result<()> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        let is_new = !self.has_entry(&shard, 0, &id);
        self.stage(&shard, 0, &id, data)?;
        // Live size (present vertex) + raw vertex-adds count (a NEW leaf only),
        // bucketed by the forest sub-shard.
        self.bump_meta(&shard, &location.data_address, i64::from(is_new), data.len() as i128);
        Ok(())
    }

    pub fn remove_vertex(&self, location: &Location) -> Result<()> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();

        let existing = self.read_blob(&shard, 0, &id);
        let in_removes = self.has_entry(&shard, 1, &id);
        let present = existing.as_ref().map(|b| !b.is_empty()).unwrap_or(false) && !in_removes;
        let value_size = if present {
            existing.as_ref().map(|b| b.len()).unwrap_or(0)
        } else {
            0
        };
        // A removed-but-never-added id gets an empty add-side placeholder — a NEW
        // phase-0 leaf (raw count +1), matching the scan's leaf enumeration.
        let new_placeholder = existing.is_none();
        if new_placeholder {
            self.stage(&shard, 0, &id, &[])?;
        }
        // Tombstone in the removes phase.
        self.stage(&shard, 1, &id, &[])?;

        // Removing a present vertex frees its live size (adds MINUS removes).
        let d_size = if present { -(value_size as i128) } else { 0 };
        let d_count = i64::from(new_placeholder);
        if present || new_placeholder {
            self.bump_meta(&shard, &location.data_address, d_count, d_size);
        }
        Ok(())
    }

    pub fn add_hyperedge(&self, location: &Location, data: &[u8]) -> Result<()> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        if self.has_entry(&shard, 3, &id) {
            return Ok(()); // in hyperedge_removes → no-op
        }
        self.stage(&shard, 2, &id, data)?;
        // Hyperedges contribute to LIVE size but not the vertex-adds count.
        self.bump_meta(&shard, &location.data_address, 0, data.len() as i128);
        Ok(())
    }

    pub fn remove_hyperedge(&self, location: &Location) -> Result<()> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        let existing = self.read_blob(&shard, 2, &id);
        let in_removes = self.has_entry(&shard, 3, &id);
        let present = existing.as_ref().map(|b| !b.is_empty()).unwrap_or(false) && !in_removes;
        let value_size = if present {
            existing.as_ref().map(|b| b.len()).unwrap_or(0)
        } else {
            0
        };
        if existing.is_none() {
            self.stage(&shard, 2, &id, &[])?;
        }
        self.stage(&shard, 3, &id, &[])?;
        // FIX: a removed hyperedge frees its live size — previously this was never
        // subtracted (hyperedges have only existed on the excluded prover shard,
        // so it was a latent no-op until now).
        if present {
            self.bump_meta(&shard, &location.data_address, 0, -(value_size as i128));
        }
        Ok(())
    }

    // ---- ensure (forest loads lazily; these are compatibility no-ops) ---

    pub fn ensure_vertex_adds_tree(&self, _shard_key: &ShardKey) {}
    pub fn ensure_all_phase_trees(&self, _shard_key: &ShardKey) {}

    /// Scan every committed vertex-adds blob of a token `domain` — one shard per
    /// domain, since `ShardKey` derives from `app_address = domain` only. Invokes
    /// `cb(vertex_key, blob)` where `vertex_key = domain ‖ address` (64 bytes).
    /// Used to (re)build the per-token SIS coin accumulator (the shadow tree).
    pub fn for_each_vertex_adds_blob(
        &self,
        domain: &[u8],
        cb: &mut dyn FnMut(Vec<u8>, Vec<u8>),
    ) -> Result<usize> {
        let mut app = [0u8; 32];
        let n = domain.len().min(32);
        app[..n].copy_from_slice(&domain[..n]);
        let location = Location { app_address: app, data_address: [0u8; 32] };
        let shard = shard_key_for_location(&location);
        self.store.for_each_vertex_underlying("vertex", "adds", &shard, cb)
    }

    /// Enumerate committed `(vertex_key, blob)` for an EXPLICIT shard/phase —
    /// used to read the global prover shard ({l1:[0;3], l2:[0xff;32]}) whose
    /// L1 is not derivable from a domain. Reads the committed underlying store
    /// (identical across nodes at a given committed height), so callers get a
    /// deterministic snapshot for consensus-critical enumeration.
    pub fn for_each_vertex_underlying_shard(
        &self,
        set_type: &str,
        phase_type: &str,
        shard: &ShardKey,
        cb: &mut dyn FnMut(Vec<u8>, Vec<u8>),
    ) -> Result<usize> {
        self.store.for_each_vertex_underlying(set_type, phase_type, shard, cb)
    }

    // ---- commit ---------------------------------------------------------

    pub fn commit(&self, frame_number: u64) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        self.commit_inner(frame_number, None)
    }

    pub fn commit_with_global_cursor(
        &self,
        frame_number: u64,
        cursor_key: &[u8],
    ) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        self.commit_inner(frame_number, Some(cursor_key))
    }

    fn commit_inner(
        &self,
        frame_number: u64,
        cursor_key: Option<&[u8]>,
    ) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        let _guard = self.commit_lock.lock().unwrap();

        // Drain the pending deltas + blobs for this commit.
        let pending: HashMap<(ShardKey, usize), PhaseDeltas> =
            std::mem::take(&mut *self.pending.write().unwrap());
        let pending_blobs: HashMap<(ShardKey, usize), PhaseBlobs> =
            std::mem::take(&mut *self.pending_blobs.write().unwrap());

        let txn = self.store.new_transaction(false)?;
        let forest = self.forest.read().unwrap();

        // Union of shards touched this commit + shards with cached commits.
        let mut shard_keys: Vec<ShardKey> = Vec::new();
        for (sk, _) in pending.keys() {
            if !shard_keys.contains(sk) {
                shard_keys.push(sk.clone());
            }
        }
        let cached = self.store.get_root_commits(frame_number)?;
        for sk in cached.keys() {
            if !shard_keys.contains(sk) {
                shard_keys.push(sk.clone());
            }
        }

        let empty_root = vec![0u8; 32];
        let mut result: HashMap<ShardKey, Vec<Vec<u8>>> = HashMap::new();
        // Level-1 global buckets touched this frame: first address byte →
        // apps' `(app_address, AppEntry)` leaves. Committed after the shard
        // loop into the same txn so `global_commitments` can retrieve the
        // per-bucket roots. The global prover shard (`0xff..ff`) is excluded —
        // its root is carried separately as `prover_tree_commitment`.
        let mut l1_buckets: HashMap<u8, Vec<(Vec<u8>, quil_forest::AppEntry)>> = HashMap::new();

        for shard in &shard_keys {
            let cached_row = cached.get(shard);
            let prefixes = self.app_prefixes(&shard.l2);
            // UNIFIED mode commits every app as a SINGLE tree keyed by the app
            // address (all vertices raw-key positioned) — the existing
            // single-shard path IS the unified commit (one tree, root = app
            // root, one version). Per-shard commitments are read separately via
            // `Forest::app_subtree_root`. Legacy split apps keep the per-prefix
            // trees + `app_root_from_shard_paths` rollup until the flag-day
            // consolidation flips `unified_tree`.
            let single_shard =
                self.unified_tree() || (prefixes.len() == 1 && prefixes[0].is_empty());
            let mut roots: [Vec<u8>; 4] =
                [empty_root.clone(), empty_root.clone(), empty_root.clone(), empty_root.clone()];
            let mut va_leaf_count: u64 = 0;
            let mut va_size = BigInt::zero();

            for phase_idx in 0..4 {
                let (set, phase) = PHASE_STR[phase_idx];
                let deltas = pending.get(&(shard.clone(), phase_idx));
                let blobs = pending_blobs.get(&(shard.clone(), phase_idx));

                if deltas.is_none() {
                    // Nothing staged this frame — reuse the cached root if any.
                    if let Some(row) = cached_row.and_then(|r| r.get(phase_idx)) {
                        if row.len() == 32 {
                            roots[phase_idx] = row.clone();
                            continue;
                        }
                    }
                    // Otherwise read the current root (unchanged phase): a single
                    // tree, or the aggregate of the app's sub-shard roots.
                    roots[phase_idx] =
                        self.current_app_phase_root(&forest, &shard.l2, &prefixes, phase_idx);
                    continue;
                }
                let deltas = deltas.unwrap();

                // Commit the phase's per-vertex deltas FIRST (staging forest writes
                // into the same txn), because the versioned blob writes below need
                // each vertex's committed `version`. A single-shard app is one tree
                // keyed by the app address; a split app (QUIL) routes each delta to
                // its sub-shard by data address, commits the touched sub-shards,
                // reads the untouched ones, aggregates the sub-shard roots into the
                // app phase root, and records a manifest so the aggregate root is
                // syncable by hash. Each committed root is indexed
                // `root → (version, frame)` (`put_root_version`) so a peer can
                // resolve OUR local version from the content-addressed root the
                // syncing node already trusts.
                let app_root: [u8; 32];
                let bit_paths = if single_shard {
                    Vec::new()
                } else {
                    self.shard_bit_paths(&shard.l2)
                };
                // `sub_vers` maps a blob's routing → the version of the tree it
                // belongs to (identity for single-shard; per-sub-shard for split),
                // so each blob is written at the exact version its forest leaf was
                // committed at (the load-bearing pairing invariant).
                let sub_vers: Vec<u64>;
                if single_shard {
                    let leaves: Vec<(Vec<u8>, Vec<u8>)> =
                        deltas.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    let (root, ver) = self.commit_one_shard_phase(
                        &forest,
                        txn.as_ref(),
                        &shard.l2,
                        phase_idx,
                        leaves,
                    )?;
                    app_root = root;
                    sub_vers = vec![ver];
                    self.store.put_root_version(
                        txn.as_ref(),
                        set,
                        phase,
                        &shard.l2,
                        &root,
                        ver,
                        frame_number,
                    )?;
                } else {
                    // Under the per-vertex model the delta key IS the vertex's
                    // 32-byte data address, so route on the whole key.
                    let mut by_shard: HashMap<usize, Vec<(Vec<u8>, Vec<u8>)>> = HashMap::new();
                    for (k, v) in deltas {
                        let pi = quil_forest::address_shard_index(&k, &bit_paths);
                        by_shard.entry(pi).or_default().push((k.clone(), v.clone()));
                    }
                    let mut shard_roots: Vec<(Vec<bool>, [u8; 32])> =
                        Vec::with_capacity(prefixes.len());
                    let mut vers: Vec<u64> = vec![0; prefixes.len()];
                    let mut manifest: Vec<(Vec<u8>, [u8; 32], u64)> =
                        Vec::with_capacity(prefixes.len());
                    for (i, prefix) in prefixes.iter().enumerate() {
                        let shard_id = Forest::addr_path_shard_id(&shard.l2, prefix);
                        let (root, ver) = match by_shard.remove(&i) {
                            Some(leaves) => self.commit_one_shard_phase(
                                &forest,
                                txn.as_ref(),
                                &shard_id,
                                phase_idx,
                                leaves,
                            )?,
                            None => (
                                self.read_shard_phase_root(&forest, &shard_id, phase_idx),
                                self.resolve_phase_version_with(&forest, &shard_id, phase_idx)
                                    .unwrap_or(0),
                            ),
                        };
                        vers[i] = ver;
                        shard_roots.push((bit_paths[i].clone(), root));
                        self.store.put_root_version(
                            txn.as_ref(),
                            set,
                            phase,
                            &shard_id,
                            &root,
                            ver,
                            frame_number,
                        )?;
                        // Manifest prefix = each u32 level as 4 BE bytes.
                        let prefix_bytes: Vec<u8> =
                            prefix.iter().flat_map(|n| n.to_be_bytes()).collect();
                        manifest.push((prefix_bytes, root, ver));
                    }
                    app_root = app_root_from_shard_paths(&shard_roots);
                    sub_vers = vers;
                    self.store.put_app_manifest(
                        txn.as_ref(),
                        set,
                        phase,
                        &shard.l2,
                        &app_root,
                        &manifest,
                        frame_number,
                    )?;
                }

                // Persist the per-vertex blobs into the txn at their tree's
                // version. Blobs stay keyed by the app ShardKey (reads use it); for
                // a split app each blob routes to its sub-shard's version.
                if let Some(blobs) = blobs {
                    for (id, blob) in blobs {
                        let ver = if single_shard {
                            sub_vers[0]
                        } else {
                            let routing_key: &[u8] =
                                if id.len() >= 64 { &id[32..64] } else { &id[..] };
                            let pi = quil_forest::address_shard_index(routing_key, &bit_paths);
                            sub_vers[pi]
                        };
                        self.store.save_vertex_underlying_versioned(
                            txn.as_ref(),
                            set,
                            phase,
                            shard,
                            id,
                            blob,
                            ver,
                        )?;
                    }
                }

                self.store.set_shard_commit(
                    txn.as_ref(),
                    frame_number,
                    phase,
                    set,
                    &shard.l2,
                    &app_root,
                )?;
                roots[phase_idx] = app_root.to_vec();

                if phase_idx == 0 {
                    if let Some(blobs) = blobs {
                        va_leaf_count = blobs.len() as u64;
                        va_size = blobs.values().map(|b| BigInt::from(b.len() as u64)).sum();
                    }
                }
            }

            self.shard_metadata.write().unwrap().insert(
                shard.clone(),
                ShardMetadata { commitment: roots.to_vec(), leaf_count: va_leaf_count, size: va_size },
            );

            // Accumulate this app's Level-1 leaf: value = AppEntry(app_root ‖
            // num_leaves ‖ total_size ‖ metadata). `app_root` rolls the four
            // committed phase roots up (same as the migration's `convert_app`);
            // num_leaves/total_size are the app's maintained LIVE totals
            // (`sub_meta`, all four phases, tombstone-accounted — consistent
            // with `total_size()`). The global prover shard is excluded.
            if shard.l2 != [0xffu8; 32] {
                let mut phase_roots = [[0u8; 32]; 4];
                for (p, slot) in phase_roots.iter_mut().enumerate() {
                    if roots[p].len() == 32 {
                        slot.copy_from_slice(&roots[p]);
                    }
                }
                let app_root = quil_forest::rollup_phase_roots(&phase_roots);
                let (num_leaves, live_size) = self.sub_meta_for(&shard.l2, &[]);
                l1_buckets
                    .entry(shard.l2[0])
                    .or_default()
                    .push((
                        shard.l2.to_vec(),
                        quil_forest::AppEntry {
                            app_root,
                            num_leaves,
                            total_size: live_size.max(0) as u128,
                            metadata: Vec::new(),
                        },
                    ));
            }
            result.insert(shard.clone(), roots.to_vec());
        }

        // Commit the touched Level-1 global buckets into the SAME txn (atomic
        // with the L2/L3 shard commits). Each call upserts only this frame's
        // touched apps; untouched apps in the bucket persist because
        // `put_value_set` builds on the bucket tree's prior version. The head
        // version is staged + cached so version-exact reads
        // (`global_commitments`) address the new root.
        for (bucket, apps) in l1_buckets {
            let ver = self
                .resolve_global_version(&forest, bucket)
                .map(|v| v + 1)
                .unwrap_or(0);
            match forest.commit_global_staged(bucket, ver, apps) {
                Ok((_root, puts)) => {
                    for (k, v) in puts {
                        txn.set(&k, &v)?;
                    }
                    if let Some((hk, hv)) = forest.global_head_version_put(bucket, ver) {
                        txn.set(&hk, &hv)?;
                    }
                    self.global_versions.write().unwrap().insert(bucket, ver);
                }
                Err(e) => {
                    tracing::warn!(bucket, error = %e, "L1 global bucket commit failed");
                }
            }
        }

        if let Some(cursor_key) = cursor_key {
            txn.set(cursor_key, &frame_number.to_be_bytes())?;
        }
        // Persist the live-size buckets ATOMICALLY with the tree commit, so a
        // restart loads the small per-sub-shard baseline (O(#sub-shards)) instead
        // of re-streaming the whole state. The buckets already reflect this
        // frame's committed mutations (they are bumped at stage time).
        txn.set(SIZE_BUCKETS_KEY, &serialize_buckets(&self.sub_meta.read().unwrap()))?;
        txn.commit()?;
        Ok(result)
    }

    // ---- roots / metadata ----------------------------------------------

    /// World-state size for reward/fee issuance = Σ of every sub-shard's LIVE
    /// size (all four phases, tombstone-accounted). EXCLUDES the global prover
    /// shard (`0xff`) — its registry / reward vertices are not reward-bearing
    /// state (enforced in [`bump_meta`](Self::bump_meta), so no `0xff` bucket
    /// ever exists). Held MID-frame as shards grow (live mutation counters), not
    /// just at commit boundaries. Requires [`warm_sizes`](Self::warm_sizes) to
    /// have seeded the migrated baseline.
    /// The 256 Level-1 global bucket roots. `global_commitments[i]` is the
    /// root of the tree whose leaves are the `AppEntry`s (`app_root ‖
    /// num_leaves ‖ total_size ‖ metadata`) of every app whose FIRST address
    /// byte is `i` — empty (`vec![]`) for a bucket with no apps. Retrieved
    /// live from the forest (maintained per-frame by `commit_inner`), read at
    /// each bucket's exact committed version. The leader binds these into the
    /// global frame header's `global_commitments`. Always length 256.
    pub fn global_commitments(&self) -> Vec<Vec<u8>> {
        let forest = self.forest.read().unwrap();
        (0u8..=255)
            .map(|i| match self.resolve_global_version(&forest, i) {
                Some(ver) => forest
                    .global_root(i, ver)
                    .ok()
                    .flatten()
                    .map(|r| r.to_vec())
                    .unwrap_or_default(),
                None => Vec::new(),
            })
            .collect()
    }

    pub fn total_size(&self) -> BigInt {
        let sum: i128 = self.sub_meta.read().unwrap().values().map(|(_, s)| *s).sum();
        BigInt::from(sum.max(0))
    }

    /// Summed `(raw_count, live_size)` of every declared sub-shard at/under a
    /// query `(app, prefix)` — an O(#sub-shards) read of the maintained buckets,
    /// no tree scan. `prefix` empty ⇒ whole app.
    fn sub_meta_for(&self, app: &[u8; 32], prefix: &[u32]) -> (u64, i128) {
        let m = self.sub_meta.read().unwrap();
        self.app_prefixes(app)
            .into_iter()
            .filter(|p| p.starts_with(prefix))
            .filter_map(|p| m.get(&Forest::addr_path_shard_id(app, &p)).copied())
            .fold((0u64, 0i128), |(c, s), (pc, ps)| (c + pc, s + ps))
    }

    /// Load (or, on first upgrade, compute) the per-sub-shard live-size buckets.
    /// MUST be called ONCE at startup, BEFORE any frame is processed (mutation
    /// counters accumulate on top). Idempotent (`sizes_warmed`).
    ///
    /// FAST PATH: the buckets are persisted atomically with every commit (see
    /// `commit_inner`), keyed `SIZE_BUCKETS_KEY`, so a restart just deserializes
    /// the SMALL per-sub-shard map — O(#sub-shards), never O(state).
    ///
    /// COLD PATH (no persisted baseline — a freshly upgraded / migrated store):
    /// stream each committed app's vertex-adds (raw count for every leaf, live
    /// size only for present not-tombstoned leaves) + present hyperedge-adds,
    /// bucket by the forest partition, then persist. `apps` is the COMPLETE set
    /// of committed app addresses (the node passes it from
    /// `shards_store.range_app_shards()`). Runs at most once ever.
    pub fn warm_sizes(&self, apps: &[[u8; 32]]) -> Result<()> {
        if self.sizes_warmed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Fast path: restore the persisted buckets.
        let read_txn = self.store.new_transaction(false)?;
        if let Some(blob) = read_txn.get(SIZE_BUCKETS_KEY)? {
            *self.sub_meta.write().unwrap() = deserialize_buckets(&blob);
            return Ok(());
        }
        drop(read_txn);
        let mut buckets: HashMap<Vec<u8>, (u64, i128)> = HashMap::new();
        for &app in apps {
            self.scan_app_buckets(&app, &mut buckets)?;
        }
        // Persist the freshly-computed baseline so subsequent restarts take the
        // fast path.
        let txn = self.store.new_transaction(false)?;
        txn.set(SIZE_BUCKETS_KEY, &serialize_buckets(&buckets))?;
        txn.commit()?;
        *self.sub_meta.write().unwrap() = buckets;
        Ok(())
    }

    /// Stream `app`'s committed vertex/hyperedge adds+removes and accumulate the
    /// per-sub-shard `(raw_count, live_size)` buckets into `buckets`, routing each
    /// leaf by the CURRENT prefix set (`app_prefixes` / `shard_bit_paths`). The
    /// single scan pass mirrors the incremental [`bump_meta`] accounting so a fresh
    /// scan reproduces the running totals. The global prover shard (`l2 == 0xff`)
    /// is excluded from world size. Shared by [`warm_sizes`] (cold path) and
    /// [`rebucket_app`] (post-split/-merge re-partition).
    fn scan_app_buckets(
        &self,
        app: &[u8; 32],
        buckets: &mut HashMap<Vec<u8>, (u64, i128)>,
    ) -> Result<()> {
        if *app == [0xFFu8; 32] {
            return Ok(()); // prover shard excluded from world size
        }
        let l1 = crate::addressing::get_bloom_filter_indices(app, 256, 3);
        let shard_key = ShardKey { l1, l2: *app };
        let prefixes = self.app_prefixes(app);
        let single = prefixes.len() == 1 && prefixes[0].is_empty();
        let bit_paths = if single {
            Vec::new()
        } else {
            self.shard_bit_paths(app)
        };
        let route = |vk: &[u8]| -> Vec<u8> {
            let data: &[u8] = if vk.len() >= 64 { &vk[32..64] } else { vk };
            let pi = if single {
                0
            } else {
                quil_forest::address_shard_index(data, &bit_paths)
            };
            Forest::addr_path_shard_id(app, &prefixes[pi])
        };
        // Load the tombstone sets ONCE (a streaming pass), so "present" is an
        // O(1) membership test — NOT a per-leaf versioned store lookup, which
        // on a large migrated shard is millions of reads and appears to hang.
        let mut v_removed: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
        self.store.for_each_vertex_underlying("vertex", "removes", &shard_key, &mut |vk, _| {
            v_removed.insert(vk);
        })?;
        let mut he_removed: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
        self.store.for_each_vertex_underlying("hyperedge", "removes", &shard_key, &mut |vk, _| {
            he_removed.insert(vk);
        })?;
        // Vertex adds: raw count for every leaf; live size only if present.
        self.store.for_each_vertex_underlying("vertex", "adds", &shard_key, &mut |vk, blob| {
            let e = buckets.entry(route(&vk)).or_insert((0, 0));
            e.0 += 1;
            if !blob.is_empty() && !v_removed.contains(&vk) {
                e.1 += blob.len() as i128;
            }
        })?;
        // Hyperedge adds: live size only (no vertex-count contribution).
        self.store.for_each_vertex_underlying("hyperedge", "adds", &shard_key, &mut |vk, blob| {
            if !blob.is_empty() && !he_removed.contains(&vk) {
                buckets.entry(route(&vk)).or_insert((0, 0)).1 += blob.len() as i128;
            }
        })?;
        Ok(())
    }

    /// Re-partition `app`'s per-sub-shard size buckets against the CURRENT prefix
    /// set. Called when a shard split/merge changes an app's registered shards:
    /// the incremental [`bump_meta`] only routes NEW writes, so data written before
    /// the split stays stranded in the now-removed parent bucket (a deep-split leaf
    /// reads size 0 → provers churn, proposing to "leave" the data-bearing child).
    /// This drops the app's existing buckets and rebuilds them from committed state
    /// by the new routing — zero-copy (Option A leaves data in place, only the
    /// shard boundaries move), so the app's TOTAL size is preserved and only the
    /// per-sub-shard attribution changes. Deterministic across nodes: every node
    /// runs it at the same frame the split's new prefixes become visible (the
    /// per-frame `refresh_crdt_shard_prefixes` change-detection), over identical
    /// committed state. Idempotent for an unchanged prefix set.
    pub fn rebucket_app(&self, app: &[u8; 32]) -> Result<()> {
        // Rebuild the app's buckets from committed state under a lock held across
        // the swap so a concurrent commit can't interleave a stale partition.
        let mut fresh: HashMap<Vec<u8>, (u64, i128)> = HashMap::new();
        self.scan_app_buckets(app, &mut fresh)?;
        let mut m = self.sub_meta.write().unwrap();
        // Drop every bucket belonging to this app (keys are `app(32) ‖ prefix`),
        // clearing the orphaned parent/ancestor buckets, then install the fresh set.
        m.retain(|k, _| !k.starts_with(&app[..]));
        for (k, v) in fresh {
            m.insert(k, v);
        }
        Ok(())
    }

    pub fn shard_metadata_for_address(&self, filter: &[u8]) -> Option<ShardMetadata> {
        if filter.len() < 32 {
            return None;
        }
        let mut app = [0u8; 32];
        app.copy_from_slice(&filter[..32]);
        let l1 = crate::addressing::get_bloom_filter_indices(&app, 256, 3);
        let shard_key = ShardKey { l1, l2: app };
        self.shard_metadata.read().unwrap().get(&shard_key).cloned()
    }

    /// Per-SUB-SHARD vertex-adds metadata (size + leaf_count) for a
    /// (possibly split-app) coverage `filter` = `app(32) ‖ prefix-byte-per-level`
    /// (`coverage.rs` appends `prefix as u8` per level). Unlike
    /// [`shard_metadata_for_address`](Self::shard_metadata_for_address), which
    /// truncates to the 32-byte app and returns WHOLE-APP metadata, this resolves
    /// the specific sub-shard subtree the filter addresses — the storage a single
    /// covering worker actually holds. This is the correct reward basis: a worker
    /// covering `QUIL‖[d]` is paid for that sub-shard's leaves, not the whole app
    /// (otherwise every one of an app's N sub-shards would be credited the full
    /// app size = N× over-reward). An unsplit app (bare 32-byte filter, empty
    /// prefix) yields whole-app metadata, matching `shard_metadata_for_address`.
    /// Reads the maintained per-sub-shard bucket (live size + raw count) — O(1),
    /// no tree scan, deterministic across nodes given the same committed state +
    /// warm. `size` is the LIVE all-phase size; `leaf_count` the raw vertex-adds
    /// count. `None` if malformed or the sub-shard is empty.
    pub fn sub_shard_metadata_for_filter(&self, filter: &[u8]) -> Option<quil_tries::NodeMetadata> {
        if filter.len() < 32 {
            return None;
        }
        let mut app = [0u8; 32];
        app.copy_from_slice(&filter[..32]);
        let prefix: Vec<u32> = filter[32..].iter().map(|&b| b as u32).collect();
        let (count, size) = self.sub_meta_for(&app, &prefix);
        if count == 0 && size == 0 {
            return None;
        }
        Some(quil_tries::NodeMetadata {
            commitment: Vec::new(),
            leaf_count: count,
            size: BigInt::from(size.max(0)),
        })
    }

    /// The current 32-byte forest root for one shard/phase (read-only).
    pub fn compute_shard_root(&self, set_type: &str, phase_type: &str, shard_key: &ShardKey) -> Vec<u8> {
        let phase_idx = match (set_type, phase_type) {
            ("vertex", "adds") => 0,
            ("vertex", "removes") => 1,
            ("hyperedge", "adds") => 2,
            ("hyperedge", "removes") => 3,
            _ => return Vec::new(),
        };
        // Read at each tree's EXACT committed version (JMT is version-exact). A
        // single-shard app is one tree; a split app (QUIL) aggregates its
        // sub-shard roots — the same value `commit_inner` puts in the header.
        let forest = self.forest.read().unwrap();
        let prefixes = self.app_prefixes(&shard_key.l2);
        self.current_app_phase_root(&forest, &shard_key.l2, &prefixes, phase_idx)
    }

    /// A SPECIFIC sub-shard's phase commitment (vs [`compute_shard_root`], which
    /// is the app aggregate). UNIFIED mode: the in-place subtree root via
    /// [`Forest::app_subtree_root`] at the shard's canonical bit-path — a READ,
    /// no separate tree. LEGACY: the shard's own per-prefix tree root. Both
    /// compose to `compute_shard_root` (the app-phase root the header carries) —
    /// natively via `subtree_hash` under unified, via `app_root_from_shard_paths`
    /// under legacy. `prefix` is a `ShardInfo.prefix` (e.g. `[i]` for a QUIL
    /// 64-way shard). Used by attestation / coverage / sync to read one shard's
    /// commitment without materializing the whole app aggregate. Returns `vec![]`
    /// for an unknown phase.
    pub fn sub_shard_commitment(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        prefix: &[u32],
    ) -> Vec<u8> {
        let phase_idx = match (set_type, phase_type) {
            ("vertex", "adds") => 0,
            ("vertex", "removes") => 1,
            ("hyperedge", "adds") => 2,
            ("hyperedge", "removes") => 3,
            _ => return Vec::new(),
        };
        let forest = self.forest.read().unwrap();
        let app = &shard_key.l2;
        if self.unified_tree() {
            // The shard's canonical bit-path within the app's COMPLETE prefix set
            // (handles non-uniform splits; the isolated `prefix_to_bits` is only a
            // fallback for a prefix not in the declared set).
            let prefixes = self.app_prefixes(app);
            let bit_paths = self.shard_bit_paths(app);
            let bits = prefixes
                .iter()
                .position(|p| p == prefix)
                .map(|i| bit_paths[i].clone())
                .unwrap_or_else(|| quil_forest::prefix_to_bits(prefix, 6));
            let ver = self
                .resolve_phase_version_with(&forest, app, phase_idx)
                .unwrap_or(0);
            forest
                .app_subtree_root(app, PHASES[phase_idx], ver, &bits)
                .map(|r| r.to_vec())
                .unwrap_or_default()
        } else {
            let sid = Forest::addr_path_shard_id(app, prefix);
            self.read_shard_phase_root(&forest, &sid, phase_idx).to_vec()
        }
    }

    /// The covered shard's subtree commitment addressed by its WIRE FILTER
    /// (`app(32) ‖ encoded prefix`), i.e. the per-shard `state_root` under the
    /// sharded unified model — computable from partial (subtree-only) storage,
    /// unlike [`compute_shard_root`] (the whole-app aggregate a subtree-only
    /// worker cannot reproduce). Resolves the filter to a registered
    /// `ShardInfo.prefix` by matching against `app_prefixes` (handling BOTH
    /// sentinel bit-path and byte-suffix encodings), then defers to
    /// [`sub_shard_commitment`] (unified → `app_subtree_root` at the canonical
    /// bit-path; legacy → the per-prefix tree root). A bare-app filter (unsplit)
    /// resolves to the empty prefix, whose subtree root IS the app root — so an
    /// unsplit app is a no-op vs `compute_shard_root`. `vec![]` on a malformed
    /// filter / unknown phase.
    pub fn sub_shard_commitment_for_filter(
        &self,
        set_type: &str,
        phase_type: &str,
        filter: &[u8],
    ) -> Vec<u8> {
        if filter.len() < 32 {
            return Vec::new();
        }
        let mut app = [0u8; 32];
        app.copy_from_slice(&filter[..32]);
        let shard_key = ShardKey {
            l1: crate::addressing::get_bloom_filter_indices(&app, 256, 3),
            l2: app,
        };
        // The registered prefix whose canonical wire filter equals `filter`.
        // Falls back to the empty prefix (whole app / unsplit) when unmatched.
        let prefix = self
            .app_prefixes(&app)
            .into_iter()
            .find(|p| quil_forest::shard_prefix_to_filter(&app, p).as_slice() == filter)
            .unwrap_or_default();
        self.sub_shard_commitment(set_type, phase_type, &shard_key, &prefix)
    }

    /// Build a forest membership proof for one or more vertices in a
    /// shard/phase — the PRODUCER side of the token/prover-spend traversal
    /// proof. Each `(vertex_address, field_keys)` becomes a
    /// [`quil_forest::VertexMembershipProof`] binding those flat L3 fields
    /// under the current shard/phase root; a wallet verifies the result with
    /// [`quil_forest::verify_vertex_membership`]. The proof reads at the same
    /// forest version [`compute_shard_root`](Self::compute_shard_root) exposes,
    /// so it verifies against the root the header advertises. Only meaningful
    /// on a forest-active (migrated) node; on the KZG path callers use the
    /// legacy `prove_multiple` generator instead.
    pub fn build_membership_proof(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertices: &[(Vec<u8>, Vec<Vec<u8>>)],
    ) -> Result<quil_forest::MembershipProof> {
        let phase_idx = match (set_type, phase_type) {
            ("vertex", "adds") => 0,
            ("vertex", "removes") => 1,
            ("hyperedge", "adds") => 2,
            ("hyperedge", "removes") => 3,
            _ => {
                return Err(QuilError::InvalidArgument(format!(
                    "build_membership_proof: bad phase ({set_type}, {phase_type})"
                )))
            }
        };
        let forest = self.forest.read().unwrap();
        let prefixes = self.app_prefixes(&shard_key.l2);
        // Unified mode: one app tree, so a vertex leaf proves DIRECTLY against
        // the app-phase root the header advertises — no per-sub-shard tree, no
        // co-path aggregation (a shard-scoped verifier folds the co-path itself,
        // spike #3). Same direct path as a genuinely single-shard app.
        let single_shard =
            self.unified_tree() || (prefixes.len() == 1 && prefixes[0].is_empty());
        let never_committed = || {
            QuilError::InvalidArgument(format!(
                "build_membership_proof: shard/phase ({set_type}, {phase_type}) never committed"
            ))
        };
        let mut inputs = Vec::with_capacity(vertices.len());
        for (vertex_address, _field_keys) in vertices {
            // Per-vertex-subtree proofs carry the WHOLE vertex blob (the small
            // blob IS the field opening); the verifier recomputes
            // `vertex_leaf_value(blob)` and reads the queried fields from it, so
            // the builder needs the blob rather than a field-key list.
            let vertex_blob = self.read_blob(shard_key, phase_idx, vertex_address).unwrap_or_default();
            if single_shard {
                // One tree keyed by the app address; the vertex leaf proves
                // directly against the header root (no aggregation).
                let v = self
                    .resolve_phase_version_with(&forest, &shard_key.l2, phase_idx)
                    .ok_or_else(never_committed)?;
                let vp = forest
                    .build_vertex_membership_proof(
                        &shard_key.l2,
                        PHASES[phase_idx],
                        v,
                        vertex_address,
                        &vertex_blob,
                    )
                    .map_err(|e| QuilError::Internal(format!("build_membership_proof: {e}")))?;
                inputs.push(vp);
            } else {
                // Split app: the vertex lives in the sub-shard whose canonical
                // bit-path matches its data-address bits (generalizes QUIL
                // top-6-bits to non-uniform splits). Prove the fields against that
                // sub-shard tree, then attach the co-path binding the sub-shard
                // root up to the app phase root the header advertises.
                let bit_paths = self.shard_bit_paths(&shard_key.l2);
                let data = if vertex_address.len() > 32 { &vertex_address[32..] } else { &[][..] };
                let pi = quil_forest::address_shard_index(data, &bit_paths);
                let prefix = &prefixes[pi];
                let shard_id = Forest::addr_path_shard_id(&shard_key.l2, prefix);
                let v = self
                    .resolve_phase_version_with(&forest, &shard_id, phase_idx)
                    .ok_or_else(never_committed)?;
                let mut vp = forest
                    .build_vertex_membership_proof(
                        &shard_id,
                        PHASES[phase_idx],
                        v,
                        vertex_address,
                        &vertex_blob,
                    )
                    .map_err(|e| QuilError::Internal(format!("build_membership_proof: {e}")))?;
                let shard_phase_root = self.read_shard_phase_root(&forest, &shard_id, phase_idx);
                let all_roots: Vec<(Vec<bool>, [u8; 32])> = prefixes
                    .iter()
                    .zip(&bit_paths)
                    .map(|(p, bits)| {
                        let sid = Forest::addr_path_shard_id(&shard_key.l2, p);
                        (bits.clone(), self.read_shard_phase_root(&forest, &sid, phase_idx))
                    })
                    .collect();
                let prefix_bits = bit_paths[pi].clone();
                let copath = app_membership_path_dynamic(&all_roots, &prefix_bits);
                vp.shard_aggregation = Some(quil_forest::ShardAggregation {
                    shard_phase_root,
                    prefix_bits,
                    copath,
                });
                inputs.push(vp);
            }
        }
        Ok(quil_forest::MembershipProof { inputs })
    }

    /// Forest-sync SERVER: serve one JMT node (`borsh(NodeKey)` → `borsh(Node)`)
    /// of a shard/phase tree, for a peer running the Merkle diff. Read-only
    /// proxy; the diff client authenticates against the trusted header root.
    pub fn serve_forest_node(
        &self,
        shard_id: &[u8],
        phase_idx: usize,
        node_key: &[u8],
    ) -> Option<Vec<u8>> {
        if phase_idx >= 4 {
            return None;
        }
        self.forest
            .read()
            .unwrap()
            .serve_node(shard_id, PHASES[phase_idx], node_key)
            .ok()
            .flatten()
    }

    /// Forest-sync SERVER: the head `(version, root)` of a shard/phase tree, for
    /// a client's version-discovery step before it diffs.
    pub fn serve_forest_head(&self, shard_id: &[u8], phase_idx: usize) -> Option<(u64, [u8; 32])> {
        if phase_idx >= 4 {
            return None;
        }
        let forest = self.forest.read().unwrap();
        let v = self.resolve_phase_version_with(&forest, shard_id, phase_idx)?;
        let root = forest.shard_phase_root(shard_id, PHASES[phase_idx], v).ok().flatten()?;
        Some((v, root))
    }

    /// Forest-sync CLIENT: pull one shard/phase tree from a remote `source` (at
    /// `source_version`) via the efficient Merkle diff and apply the differing
    /// leaves into this CRDT's forest at a fresh, COORDINATED version (so it
    /// doesn't collide with live `commit_inner` versions). Returns the new root
    /// for the caller to verify against the trusted target.
    ///
    /// The diff walk (remote reads) runs LOCK-FREE — it takes neither
    /// `forest_write_lock` nor `commit_lock`. JMT reads are version-exact, so the
    /// diff stays consistent even if the materializer advances the tree mid-walk;
    /// only the apply takes the locks (forest_write_lock THEN commit_lock, the
    /// same order the materializer uses). Because the diff is lock-free, the
    /// version it read (`v_t`) is revalidated under the write lock before the
    /// apply: if a commit advanced this phase in between, the diff's leaves are
    /// stale and the apply is aborted for the caller to retry — so an expensive
    /// full-tree diff can never block the global-frame materializer.
    pub fn sync_shard_phase_from<S: quil_forest::TreeReader>(
        &self,
        source: &S,
        source_version: u64,
        shard_id: &[u8],
        phase_idx: usize,
    ) -> Result<([u8; 32], u64, Vec<([u8; 32], Vec<u8>)>)> {
        if phase_idx >= 4 {
            return Err(QuilError::InvalidArgument("phase_idx >= 4".into()));
        }
        // Lock-free diff (no forest_write_lock, no commit_lock). Capture the
        // version it read (`v_t_opt`) so we can revalidate it under the write lock
        // before applying.
        let (v_t_opt, leaves) = {
            let forest = self.forest.read().unwrap();
            let v_t_opt = self.resolve_phase_version_with(&forest, shard_id, phase_idx);
            let target = forest.shard_phase_reader(shard_id, PHASES[phase_idx]);
            let leaves =
                quil_forest::diff_leaves(source, source_version, &target, v_t_opt.unwrap_or(0))
                    .map_err(|e| QuilError::Internal(format!("diff_leaves: {e}")))?;
            (v_t_opt, leaves)
        };
        // The changed leaves as `(key_hash, leaf_value)` pairs. Under the
        // per-vertex-subtree model the raw-key `key_hash` IS the vertex's 32-byte
        // DATA address (no hashing, no preimage), and `leaf_value` is its
        // committed `commitment ‖ size` — the caller derives `vertex_id =
        // app ‖ key_hash` directly and verifies each fetched blob against
        // `leaf_value` (a peer cannot serve data not matching the commitment).
        let changed: Vec<([u8; 32], Vec<u8>)> =
            leaves.iter().map(|(k, v)| (k.0, v.clone())).collect();
        // Take the forest-write lock ONLY around the apply — the diff above ran
        // lock-free, so an O(tree) diff no longer starves the global-frame
        // materializer (which holds `forest_write_lock` across its whole
        // verify+apply). Lock order matches the materializer: forest_write_lock
        // BEFORE commit_lock.
        let _forest_guard = self.forest_write_lock.lock().unwrap();
        let _guard = self.commit_lock.lock().unwrap();
        let forest = self.forest.read().unwrap();
        // Revalidate the version the lock-free diff read against. If a commit
        // advanced this phase between the diff and here, `leaves` is stale
        // (computed against `v_t_opt`) and applying it would build a divergent
        // version — abort so the caller re-diffs against the new head. (Under the
        // old whole-sync forest lock this couldn't happen; the diff is now
        // lock-free, so the guard moves here.)
        let cur_opt = self.resolve_phase_version_with(&forest, shard_id, phase_idx);
        if cur_opt != v_t_opt {
            return Err(QuilError::Internal(format!(
                "sync phase {phase_idx} advanced {v_t_opt:?}→{cur_opt:?} during diff — retry"
            )));
        }
        // Per-tree contiguous version (JMT builds on `version - 1`), same as
        // `commit_one_shard_phase`.
        let ver = cur_opt.map(|v| v + 1).unwrap_or(0);
        let (root, puts) = forest
            .apply_synced_shard_phase(shard_id, PHASES[phase_idx], ver, leaves)
            .map_err(|e| QuilError::Internal(format!("apply synced shard: {e}")))?;
        let txn = self.store.new_transaction(false)?;
        for (k, v) in puts {
            txn.set(&k, &v)?;
        }
        if let Some((hk, hv)) = forest.head_version_put(shard_id, PHASES[phase_idx], ver) {
            txn.set(&hk, &hv)?;
        }
        txn.commit()?;
        self.phase_versions.write().unwrap().insert((shard_id.to_vec(), phase_idx), ver);
        // Return `ver` so the caller can persist the fetched vertex blobs at the
        // SAME version the tree was applied at (see `save_synced_blob`), keeping
        // the blob keyspace consistent with the forest it was synced against.
        Ok((root, ver, changed))
    }

    /// UNIFIED shard-prover subtree-range sync: pull ONLY the leaves under
    /// `bit_path` (this prover's shard prefix) from `source`'s app tree and apply
    /// them to the LOCAL app tree (keyed by `app`), returning the local SUBTREE
    /// root — the shard commitment. `pinned_app_root` is the trusted header app
    /// root for the phase; the descent to the prefix is authenticated against it
    /// (so a peer can't serve a fake subtree), and the applied local subtree root
    /// is verified to equal the authenticated source subtree root. A shard prover
    /// thus stores only its subtree yet holds a commitment that composes to the
    /// global app root — never pulling the whole app. Empty `bit_path` ==
    /// [`sync_shard_phase_from`] over the whole app tree.
    pub fn sync_shard_subtree_phase_from<S: quil_forest::TreeReader>(
        &self,
        source: &S,
        source_version: u64,
        app: &[u8],
        phase_idx: usize,
        bit_path: &[bool],
        pinned_app_root: Option<[u8; 32]>,
    ) -> Result<([u8; 32], u64, Vec<([u8; 32], Vec<u8>)>)> {
        if phase_idx >= 4 {
            return Err(QuilError::InvalidArgument("phase_idx >= 4".into()));
        }
        // Lock-free subtree diff + authenticated source subtree root.
        let (v_t_opt, leaves, src_subtree_root) = {
            let forest = self.forest.read().unwrap();
            let v_t_opt = self.resolve_phase_version_with(&forest, app, phase_idx);
            let target = forest.shard_phase_reader(app, PHASES[phase_idx]);
            let (leaves, src_root) = quil_forest::diff_leaves_under_prefix(
                source,
                source_version,
                &target,
                v_t_opt.unwrap_or(0),
                bit_path,
                pinned_app_root,
            )
            .map_err(|e| QuilError::Internal(format!("diff_leaves_under_prefix: {e}")))?;
            (v_t_opt, leaves, src_root)
        };
        let changed: Vec<([u8; 32], Vec<u8>)> =
            leaves.iter().map(|(k, v)| (k.0, v.clone())).collect();

        // Nothing to pull — already synced. Return the current local subtree root
        // without bumping the tree version.
        if changed.is_empty() {
            let forest = self.forest.read().unwrap();
            let ver = v_t_opt.unwrap_or(0);
            let local = forest
                .app_subtree_root(app, PHASES[phase_idx], ver, bit_path)
                .map_err(|e| QuilError::Internal(format!("app_subtree_root: {e}")))?;
            if pinned_app_root.is_some() && local != src_subtree_root {
                return Err(QuilError::Internal(
                    "local subtree root != authenticated source subtree root (no-op path)".into(),
                ));
            }
            return Ok((local, ver, changed));
        }

        let _forest_guard = self.forest_write_lock.lock().unwrap();
        let _guard = self.commit_lock.lock().unwrap();
        let forest = self.forest.read().unwrap();
        let cur_opt = self.resolve_phase_version_with(&forest, app, phase_idx);
        if cur_opt != v_t_opt {
            return Err(QuilError::Internal(format!(
                "sync subtree phase {phase_idx} advanced {v_t_opt:?}→{cur_opt:?} during diff — retry"
            )));
        }
        let ver = cur_opt.map(|v| v + 1).unwrap_or(0);
        let (_full_root, puts) = forest
            .apply_synced_shard_phase(app, PHASES[phase_idx], ver, leaves)
            .map_err(|e| QuilError::Internal(format!("apply synced subtree: {e}")))?;
        let txn = self.store.new_transaction(false)?;
        for (k, v) in puts {
            txn.set(&k, &v)?;
        }
        if let Some((hk, hv)) = forest.head_version_put(app, PHASES[phase_idx], ver) {
            txn.set(&hk, &hv)?;
        }
        txn.commit()?;
        self.phase_versions.write().unwrap().insert((app.to_vec(), phase_idx), ver);

        // The freshly-applied local subtree root MUST equal the authenticated
        // source subtree root — this is what binds the pulled leaves to the
        // trusted header (the pin authenticated the source subtree; this ties our
        // reconstruction to it).
        let local = forest
            .app_subtree_root(app, PHASES[phase_idx], ver, bit_path)
            .map_err(|e| QuilError::Internal(format!("app_subtree_root: {e}")))?;
        if pinned_app_root.is_some() && local != src_subtree_root {
            return Err(QuilError::Internal(
                "post-sync local subtree root != authenticated source subtree root".into(),
            ));
        }
        Ok((local, ver, changed))
    }

    /// The canonical bit-path of one shard `prefix` within an app's COMPLETE
    /// prefix set — the input to unified subtree-range sync
    /// ([`sync_shard_subtree_phase_from`](Self::sync_shard_subtree_phase_from))
    /// and [`Forest::app_subtree_root`]. Falls back to an isolated
    /// [`quil_forest::prefix_to_bits`] (6-bit levels) for a prefix not in the
    /// declared set.
    pub fn canonical_bits_for_prefix(&self, app: &[u8; 32], prefix: &[u32]) -> Vec<bool> {
        let prefixes = self.app_prefixes(app);
        let bit_paths = self.shard_bit_paths(app);
        prefixes
            .iter()
            .position(|p| p == prefix)
            .map(|i| bit_paths[i].clone())
            .unwrap_or_else(|| quil_forest::prefix_to_bits(prefix, 6))
    }

    /// Leaf count under a `bit_path` in the unified app tree — the §6.1
    /// empty-split guard's data-bearing test (see
    /// [`quil_forest::Forest::app_subtree_leaf_count`]). Returns 0 when NOT in
    /// unified mode (the app tree isn't the source of truth then), so callers
    /// must treat "not unified" as "no opinion" and not block on it.
    pub fn unified_subtree_leaf_count(
        &self,
        set_type: &str,
        phase_type: &str,
        app: &[u8],
        bit_path: &[bool],
    ) -> u64 {
        if !self.unified_tree() {
            return 0;
        }
        let phase_idx = match (set_type, phase_type) {
            ("vertex", "adds") => 0,
            ("vertex", "removes") => 1,
            ("hyperedge", "adds") => 2,
            ("hyperedge", "removes") => 3,
            _ => return 0,
        };
        let forest = self.forest.read().unwrap();
        let ver = self
            .resolve_phase_version_with(&forest, app, phase_idx)
            .unwrap_or(0);
        forest
            .app_subtree_leaf_count(app, PHASES[phase_idx], ver, bit_path)
            .unwrap_or(0)
    }

    /// DEEP-BIFURCATION split PROPOSAL (Phase 3): compute a shard's MEANINGFUL
    /// split children as bit-path shard filters. Runs
    /// [`Forest::first_split_bifurcation`] on the app tree from the shard's
    /// `shard_bits` — descending past any uniform run to the shallowest bit where
    /// the data divides — and encodes each child bit-path via
    /// [`quil_forest::encode_shard_bit_path`]. `None` when the shard is
    /// unsplittable (<2 leaves, or no branch within `max_extra_bits`) — the
    /// caller then proposes nothing (the §6.1 empty-split guard, done right: not
    /// a one-sided cut but a real bifurcation). Only meaningful under unified (the
    /// app tree is the data source); returns `None` otherwise.
    pub fn propose_split_children(
        &self,
        set_type: &str,
        phase_type: &str,
        app: &[u8],
        shard_bits: &[bool],
        max_extra_bits: usize,
    ) -> Option<Vec<Vec<u8>>> {
        if !self.unified_tree() {
            return None;
        }
        let phase_idx = match (set_type, phase_type) {
            ("vertex", "adds") => 0,
            ("vertex", "removes") => 1,
            ("hyperedge", "adds") => 2,
            ("hyperedge", "removes") => 3,
            _ => return None,
        };
        let forest = self.forest.read().unwrap();
        let ver = self
            .resolve_phase_version_with(&forest, app, phase_idx)
            .unwrap_or(0);
        let children_bits = forest
            .first_split_bifurcation(app, PHASES[phase_idx], ver, shard_bits, max_extra_bits)
            .ok()
            .flatten()?;
        Some(
            children_bits
                .iter()
                .map(|b| quil_forest::encode_shard_bit_path(app, b))
                .collect(),
        )
    }

    /// The address-path sub-shards of an app: `(shard_id, prefix_bits)` for each
    /// (a single `(app, [])` for a single-shard app; 64 for QUIL). A sync client
    /// enumerates these to fetch each sub-shard's head and verify the set.
    pub fn app_sub_shards(&self, app: &[u8; 32]) -> Vec<(Vec<u8>, Vec<bool>)> {
        let prefixes = self.app_prefixes(app);
        let bit_paths = self.shard_bit_paths(app);
        prefixes
            .into_iter()
            .zip(bit_paths)
            .map(|(p, bits)| (Forest::addr_path_shard_id(app, &p), bits))
            .collect()
    }

    /// Whether a split app's sub-shard roots aggregate to `expected_app_root`
    /// (the model-B binding, [`app_root_from_shard_paths`]). The sync client
    /// calls this over the COMPLETE sub-shard set (absent sub-shards contribute
    /// the empty root `[0; 32]`, matching `commit_inner`) to authenticate every
    /// sub-shard root against the trusted app root in one shot.
    pub fn app_root_matches(
        &self,
        sub_roots: &[(Vec<bool>, [u8; 32])],
        expected_app_root: &[u8],
    ) -> bool {
        app_root_from_shard_paths(sub_roots).as_slice() == expected_app_root
    }

    /// Forest-sync SERVER: the raw l3 key a `key_hash` was committed from
    /// (`vertex_id ‖ field_key`) — lets the client map a diff's changed leaves
    /// to the vertices whose blobs it must fetch.
    pub fn serve_forest_preimage(
        &self,
        shard_id: &[u8],
        phase_idx: usize,
        key_hash: [u8; 32],
    ) -> Option<Vec<u8>> {
        if phase_idx >= 4 {
            return None;
        }
        self.forest
            .read()
            .unwrap()
            .get_preimage(shard_id, PHASES[phase_idx], key_hash)
            .ok()
            .flatten()
    }

    /// Forest-sync SERVER: the committed blob of a vertex (the readable data the
    /// client stores). `shard` is the app ShardKey the blob is keyed under.
    pub fn serve_vertex_blob(
        &self,
        shard: &ShardKey,
        phase_idx: usize,
        id: &[u8],
        version: u64,
    ) -> Option<Vec<u8>> {
        if phase_idx >= 4 {
            return None;
        }
        if version == 0 {
            return self.read_blob(shard, phase_idx, id).filter(|b| !b.is_empty());
        }
        let (set, phase) = PHASE_STR[phase_idx];
        self.store
            .load_vertex_underlying_at(set, phase, shard, id, version)
            .ok()
            .flatten()
            .filter(|b| !b.is_empty())
    }

    /// Sync CLIENT read: the staged-or-committed blob for `(shard, phase, id)`,
    /// so `forest_sync::fetch_changed_blobs` can skip re-fetching a vertex it
    /// already holds (and verify a fetched blob against what it committed).
    pub fn peek_synced_blob(&self, shard: &ShardKey, phase_idx: usize, id: &[u8]) -> Option<Vec<u8>> {
        if phase_idx >= 4 {
            return None;
        }
        self.read_blob(shard, phase_idx, id)
    }

    /// Sync-by-hash SERVER: translate an authenticated tree `root` to THIS
    /// node's local `(version, global_frame)` for a `(shard_id, phase)` tree.
    /// `None` ⇒ never committed here (behind) or pruned past it.
    pub fn resolve_root(
        &self,
        shard_id: &[u8],
        phase_idx: usize,
        root: [u8; 32],
    ) -> Option<(u64, u64)> {
        if phase_idx >= 4 {
            return None;
        }
        let (set, phase) = PHASE_STR[phase_idx];
        self.store.get_root_version(set, phase, shard_id, &root).ok().flatten()
    }

    /// Sync-by-hash SERVER (split apps): the sub-shard manifest that folds into
    /// an aggregate `app_root` — `[(prefix_words, sub_root, sub_version)]`.
    /// `app` is the 32-byte app address (ShardKey.l2). `None` ⇒ not a known
    /// aggregate root here (single-shard, behind, or pruned).
    #[allow(clippy::type_complexity)]
    pub fn serve_app_manifest(
        &self,
        app: &[u8],
        phase_idx: usize,
        app_root: [u8; 32],
    ) -> Option<Vec<(Vec<u8>, [u8; 32], u64)>> {
        if phase_idx >= 4 {
            return None;
        }
        let (set, phase) = PHASE_STR[phase_idx];
        self.store.get_app_manifest(set, phase, app, &app_root).ok().flatten()
    }

    /// Wipe ALL FOUR forest phase trees of a single shard back to empty and
    /// forget its in-memory phase versions, so the NEXT commit rebuilds the
    /// shard from version 0. The forest half of the shard-scoped prover-tree
    /// reset (the engine clears the underlying blob keyspace via
    /// `RocksHypergraphStore::clear_shard_underlying`, then re-seeds genesis and
    /// commits). `shard_l2` is the shard's 32-byte l2 — the same id the CRDT
    /// commits the shard under (`&shard.l2`); for the global prover shard it is
    /// `[0xff; 32]`. Serialized against commits via the forest write + commit
    /// locks. Idempotent.
    pub fn reset_shard_forest_trees(&self, shard_l2: &[u8]) -> Result<()> {
        let _forest_guard = self.forest_write_lock.lock().unwrap();
        let _commit_guard = self.commit_lock.lock().unwrap();
        {
            let forest = self.forest.read().unwrap();
            forest
                .reset_shard_phase_trees(shard_l2)
                .map_err(|e| QuilError::Internal(format!("reset_shard_forest_trees: {e}")))?;
        }
        self.phase_versions
            .write()
            .unwrap()
            .retain(|(sid, _), _| sid.as_slice() != shard_l2);
        Ok(())
    }

    /// Versioned-snapshot pruner: cull blob versions + forest nodes older than
    /// `cull_frame`, returning `(tree_watermarks, forest_nodes_reclaimed)`.
    pub fn prune_to_frame(&self, cull_frame: u64) -> Result<(usize, usize)> {
        let _guard = self.commit_lock.lock().unwrap();
        let watermarks = self.store.prune_versioned(cull_frame)?;
        let forest = self.forest.read().unwrap();
        let mut nodes = 0usize;
        for (shard_id, phase_idx, min_ver) in &watermarks {
            if *phase_idx >= 4 {
                continue;
            }
            match forest.prune_shard_phase(shard_id, PHASES[*phase_idx], *min_ver) {
                Ok(n) => nodes += n,
                Err(e) => tracing::warn!(
                    shard = %hex::encode(shard_id),
                    phase = *phase_idx,
                    error = %e,
                    "forest prune of a shard/phase tree failed (will retry next cycle)",
                ),
            }
        }
        Ok((watermarks.len(), nodes))
    }

    /// Forest-sync CLIENT: store a blob pulled during sync (the readable data),
    /// keyed under the app ShardKey — so `get_vertex_data` / the prover registry
    /// (which read the blob keyspace, not the forest) see the synced state.
    /// (Re-recording forest key preimages so a synced node can itself SERVE this
    /// vertex is a later refinement — a synced node reads fine without it.)
    pub fn save_synced_blob(
        &self,
        shard: &ShardKey,
        phase_idx: usize,
        id: &[u8],
        blob: &[u8],
        version: u64,
    ) -> Result<()> {
        if phase_idx >= 4 {
            return Err(QuilError::InvalidArgument("phase_idx >= 4".into()));
        }
        let (set, phase) = PHASE_STR[phase_idx];
        let txn = self.store.new_transaction(false)?;
        // VERSIONED write at the applied tree version — MUST mirror
        // `commit_inner` (which uses `save_vertex_underlying_versioned`), NOT the
        // legacy unversioned `save_vertex_underlying`. The read path prefers the
        // V2 MVCC keyspace (`load_vertex_underlying_at`); a V1 write is only found
        // via a fragile legacy fallback and, for a MUTABLE vertex (e.g. a prover
        // reward balance that grows every frame), the stale V1 blob shadows the
        // real one → the vertex reads empty/old forever. Writing at `version` (the
        // version the synced tree was applied at) makes the versioned read resolve
        // it and lets this node re-serve the correct blob.
        self.store
            .save_vertex_underlying_versioned(txn.as_ref(), set, phase, shard, id, blob, version)?;
        txn.commit()?;
        Ok(())
    }

    /// Forest-sync CLIENT: record a raw-key preimage received during sync (from
    /// the peer's `get_forest_preimage`) into this node's forest, so a node that
    /// later syncs FROM us can recover the same mapping. Without it a synced node
    /// reads fine but cannot re-serve preimages downstream.
    pub fn save_synced_preimage(&self, shard_id: &[u8], phase_idx: usize, raw_key: &[u8]) -> Result<()> {
        if phase_idx >= 4 {
            return Err(QuilError::InvalidArgument("phase_idx >= 4".into()));
        }
        self.forest
            .read()
            .unwrap()
            .write_preimage(shard_id, PHASES[phase_idx], raw_key)
            .map_err(|e| QuilError::Internal(format!("write_preimage: {e}")))
    }

    /// Forest-sync SERVER: serve a leaf value by `KeyHash` at `version`.
    pub fn serve_forest_value(
        &self,
        shard_id: &[u8],
        phase_idx: usize,
        version: u64,
        key_hash: [u8; 32],
    ) -> Option<Vec<u8>> {
        if phase_idx >= 4 {
            return None;
        }
        self.forest
            .read()
            .unwrap()
            .serve_value(shard_id, PHASES[phase_idx], version, key_hash)
            .ok()
            .flatten()
    }

    pub fn invalidate_domain_shard_commit(&self, frame_number: u64, app_address: &[u8]) -> Result<()> {
        self.store.delete_shard_commits(frame_number, app_address)
    }

    pub fn get_shard_commits(&self, frame_number: u64, shard_address: &[u8]) -> Result<Vec<Vec<u8>>> {
        let va = self.store.get_shard_commit(frame_number, "adds", "vertex", shard_address)?;
        let vr = self.store.get_shard_commit(frame_number, "removes", "vertex", shard_address)?;
        let ha = self.store.get_shard_commit(frame_number, "adds", "hyperedge", shard_address)?;
        let hr = self.store.get_shard_commit(frame_number, "removes", "hyperedge", shard_address)?;
        Ok(vec![va, vr, ha, hr])
    }

    pub fn shard_count(&self) -> usize {
        let mut keys: Vec<ShardKey> = Vec::new();
        for (sk, _) in self.pending.read().unwrap().keys() {
            if !keys.contains(sk) {
                keys.push(sk.clone());
            }
        }
        for sk in self.shard_metadata.read().unwrap().keys() {
            if !keys.contains(sk) {
                keys.push(sk.clone());
            }
        }
        keys.len()
    }

    // ---- reads ----------------------------------------------------------

    pub fn lookup_vertex(&self, location: &Location) -> bool {
        self.get_vertex_data(location).is_some()
    }

    pub fn get_vertex_data(&self, location: &Location) -> Option<Vec<u8>> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        if self.has_entry(&shard, 1, &id) {
            return None; // removed
        }
        self.read_blob(&shard, 0, &id).filter(|b| !b.is_empty())
    }

    pub fn get_vertex_underlying_tree_bytes(&self, location: &Location) -> Option<Vec<u8>> {
        self.get_vertex_data(location)
    }

    pub fn lookup_hyperedge(&self, location: &Location) -> bool {
        self.get_hyperedge_data(location).is_some()
    }

    pub fn get_hyperedge_data(&self, location: &Location) -> Option<Vec<u8>> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        if self.has_entry(&shard, 3, &id) {
            return None;
        }
        self.read_blob(&shard, 2, &id).filter(|b| !b.is_empty())
    }

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
        for (key, _v) in tree.leaves() {
            if key.len() == 64 {
                let mut id = [0u8; 64];
                id.copy_from_slice(&key);
                out.push(id);
            }
        }
        out
    }

    // ---- PoRep / shard-info (KV prefix scan, no trie) -------------------

    /// Collect a phase's committed `(id, blob)` leaves whose id matches the
    /// nibble `path` prefix, from the store KV. `path` is a 6-bit-nibble path
    /// (the KZG tree's branching); an empty path matches all. Ascending by id.
    fn collect_phase_leaves(
        &self,
        shard: &ShardKey,
        phase_idx: usize,
        path: &[i32],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let (set, phase) = PHASE_STR[phase_idx];
        // Committed store leaves, then staged (uncommitted) blobs overlaid on
        // top — so metadata reflects mutations made this frame before commit
        // (the old in-memory KZG tree held them; the forest-native path merges).
        let mut map: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        self.store.for_each_vertex_underlying(set, phase, shard, &mut |k, v| {
            if path.is_empty() || id_matches_path(&k, path) {
                map.insert(k, v);
            }
        })?;
        if let Some(pb) = self.pending_blobs.read().unwrap().get(&(shard.clone(), phase_idx)) {
            for (k, v) in pb {
                if path.is_empty() || id_matches_path(k, path) {
                    map.insert(k.clone(), v.clone());
                }
            }
        }
        Ok(map.into_iter().collect())
    }

    /// `[vertex_adds, vertex_removes, hyperedge_adds, hyperedge_removes]`
    /// metadata at `full_path`. Slot 0 (the only one consumed by
    /// `get_app_shard_metadata`) carries the maintained per-sub-shard LIVE size +
    /// raw vertex-adds count — an O(1) bucket read, no tree scan. Slots 1–3 are
    /// `None` (their commitments already decode as zero downstream).
    pub fn phase_set_metadata_at_path(
        &self,
        shard_key: &ShardKey,
        full_path: &[i32],
    ) -> Result<[Option<quil_tries::NodeMetadata>; 4]> {
        let app = shard_key.l2;
        let app_path_len = quil_tries::get_full_path(&app).len();
        let prefix: Vec<u32> = if full_path.len() > app_path_len {
            full_path[app_path_len..].iter().map(|&n| n as u32).collect()
        } else {
            Vec::new()
        };
        let (count, size) = self.sub_meta_for(&app, &prefix);
        let phase0 = if count == 0 && size == 0 {
            None
        } else {
            Some(quil_tries::NodeMetadata {
                commitment: Vec::new(),
                leaf_count: count,
                size: BigInt::from(size.max(0)),
            })
        };
        Ok([phase0, None, None, None])
    }

    /// Canonical PoRep leaf-data body: per phase (fixed order)
    /// `set_tag(1B) || entry_count(u32 BE) || (key_len||key||val_len||val)*`,
    /// entries ascending by id, read from committed KV state at `full_path`.
    pub fn serialize_phase_subtrees(&self, shard_key: &ShardKey, full_path: &[i32]) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        for phase_idx in 0..4 {
            out.push(phase_idx as u8);
            let entries = self.collect_phase_leaves(shard_key, phase_idx, full_path)?;
            out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
            for (key, val) in &entries {
                out.extend_from_slice(&(key.len() as u32).to_be_bytes());
                out.extend_from_slice(key);
                out.extend_from_slice(&(val.len() as u32).to_be_bytes());
                out.extend_from_slice(val);
            }
        }
        Ok(out)
    }

    // ---- snapshots (unchanged, width-agnostic) --------------------------

    pub fn publish_snapshot(&self, root: Vec<u8>, frame_number: u64) {
        self.snapshot_mgr.publish(root, frame_number);
    }

    pub fn publish_snapshot_with_store(
        &self,
        root: Vec<u8>,
        frame_number: u64,
        snapshot: Arc<dyn quil_types::store::SnapshotReadable>,
    ) {
        self.snapshot_mgr.publish_with_snapshot(root, frame_number, snapshot);
    }

    pub fn publish_snapshot_capturing(&self, root: Vec<u8>, frame_number: u64) -> Result<bool> {
        match self.store.capture_tree_snapshot()? {
            Some(snap) => {
                self.snapshot_mgr.publish_with_snapshot(root, frame_number, snap);
                Ok(true)
            }
            None => {
                self.snapshot_mgr.publish(root, frame_number);
                Ok(false)
            }
        }
    }

    pub fn acquire_snapshot(&self, expected_root: &[u8]) -> Option<GenerationHandle> {
        self.snapshot_mgr.acquire(expected_root)
    }

    pub fn known_snapshot_roots(&self) -> Vec<Vec<u8>> {
        self.snapshot_mgr.known_roots()
    }

    pub fn close_snapshots(&self) {
        self.snapshot_mgr.close();
    }

    pub fn reopen_snapshots(&self) {
        self.snapshot_mgr.reopen();
    }

    /// Commit the current per-shard contents into the forest, returning each
    /// shard's four phase roots + rollup. Thin wrapper over [`commit`] kept for
    /// callers that want the rollup form.
    pub fn commit_to_forest(
        &self,
        frame_number: u64,
    ) -> Result<HashMap<ShardKey, quil_forest::ShardRoots>> {
        let commits = self.commit(frame_number)?;
        let mut out = HashMap::new();
        for (sk, roots) in commits {
            let mut phase_roots = [[0u8; 32]; 4];
            for (i, r) in roots.iter().enumerate().take(4) {
                if r.len() == 32 {
                    phase_roots[i].copy_from_slice(r);
                }
            }
            out.insert(
                sk,
                quil_forest::ShardRoots { commitment: rollup_phase_roots(&phase_roots), phase_roots },
            );
        }
        Ok(out)
    }
}

/// Whether an id's 6-bit-nibble representation begins with `path`. The KZG
/// vector trie branched 64-ary (6 bits per level); the PoRep path is such a
/// nibble sequence. Bytes are big-endian bit order.
/// KV key for the persisted per-sub-shard live-size buckets (one small blob).
const SIZE_BUCKETS_KEY: &[u8] = b"hgsz:buckets";

/// `[count u32][ (klen u32)(shard_id)(count u64)(size i128) ]*` — the persisted
/// per-sub-shard `(raw_count, live_size)` map. Small (one entry per sub-shard).
fn serialize_buckets(m: &HashMap<Vec<u8>, (u64, i128)>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + m.len() * 40);
    out.extend_from_slice(&(m.len() as u32).to_be_bytes());
    for (k, (c, s)) in m {
        out.extend_from_slice(&(k.len() as u32).to_be_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(&c.to_be_bytes());
        out.extend_from_slice(&s.to_be_bytes());
    }
    out
}

fn deserialize_buckets(b: &[u8]) -> HashMap<Vec<u8>, (u64, i128)> {
    let mut m = HashMap::new();
    if b.len() < 4 {
        return m;
    }
    let n = u32::from_be_bytes(b[0..4].try_into().unwrap());
    let mut i = 4usize;
    for _ in 0..n {
        if i + 4 > b.len() {
            break;
        }
        let kl = u32::from_be_bytes(b[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + kl + 8 + 16 > b.len() {
            break;
        }
        let k = b[i..i + kl].to_vec();
        i += kl;
        let c = u64::from_be_bytes(b[i..i + 8].try_into().unwrap());
        i += 8;
        let s = i128::from_be_bytes(b[i..i + 16].try_into().unwrap());
        i += 16;
        m.insert(k, (c, s));
    }
    m
}

fn id_matches_path(id: &[u8], path: &[i32]) -> bool {
    for (level, &nib) in path.iter().enumerate() {
        let bit = level * 6;
        let byte = bit / 8;
        if byte >= id.len() {
            return false;
        }
        // Extract 6 bits starting at absolute bit offset `bit`.
        let mut acc: u32 = 0;
        for j in 0..6 {
            let b = bit + j;
            let by = b / 8;
            if by >= id.len() {
                return false;
            }
            let bitval = (id[by] >> (7 - (b % 8))) & 1;
            acc = (acc << 1) | bitval as u32;
        }
        if acc as i32 != nib {
            return false;
        }
    }
    true
}
