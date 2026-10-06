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
use quil_types::store::{HypergraphStore, RecordMutation, ShardKey};

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

/// Bound the readable data held by one sync write batch. A large bootstrap
/// commits several batches, each with its leaves and blobs in one transaction.
pub const MAX_SYNC_CHUNK_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SYNC_CHUNK_LEAVES: usize = 256;

/// Committed phase roots and a database snapshot captured under the same commit
/// lock. Metadata (cursor, outgoing history) must be read from this handle, not
/// from the live store. The caller still establishes authenticated data readiness
/// and excludes concurrent layout changes/external synchronization.
pub struct CommittedShardSnapshot {
    pub roots: [[u8; 32]; 4],
    pub records: Arc<dyn quil_types::store::SnapshotReadable>,
}

/// An authenticated diff whose complete reconstruction was checked before
/// the first write. Only `apply_sync_chunk` advances it, after durable commit.
pub struct ForestSyncPlan {
    store: Arc<dyn HypergraphStore>,
    shard_id: Vec<u8>,
    phase_idx: usize,
    bit_path: Vec<bool>,
    base_version: Option<u64>,
    target_root: [u8; 32],
    repair_existing: bool,
    // None removes a noncanonical GLOBAL add leaf. Its historical blob
    // versions remain available; the new version stores an absent/empty blob.
    leaves: Vec<([u8; 32], Option<Vec<u8>>)>,
    next: usize,
    /// A pinned GLOBAL add phase: leaves absent from the source are removed.
    removals: bool,
}

impl ForestSyncPlan {
    pub fn remaining(&self) -> &[([u8; 32], Option<Vec<u8>>)] { &self.leaves[self.next..] }
    pub fn target_root(&self) -> [u8; 32] { self.target_root }
}

/// The local tree moved under a sync in progress (see
/// [`HypergraphCrdt::rebase_phase_sync`]).
pub const SYNC_PHASE_ADVANCED: &str = "sync phase advanced";
/// Local writes were staged but not yet committed when a chunk was installed.
pub const SYNC_STAGED_WRITES: &str = "sync phase has staged local writes";

/// Whether `error` reports that the local tree moved under a sync.
pub fn sync_phase_advanced(error: &QuilError) -> bool {
    matches!(error, QuilError::ExecutionUnavailable(m) if m.starts_with(SYNC_PHASE_ADVANCED))
}

/// Whether `error` reports staged, uncommitted local writes in the way.
pub fn sync_staged_writes(error: &QuilError) -> bool {
    matches!(error, QuilError::ExecutionUnavailable(m) if m.starts_with(SYNC_STAGED_WRITES))
}

/// Tombstones carry the removed blob's size, but store an empty blob. The
/// authenticated leaf itself supplies everything needed to reconstruct them.
pub fn sync_blob_matches(phase_idx: usize, leaf: &[u8], blob: &[u8]) -> Result<bool> {
    if phase_idx >= 4 || leaf.len() != 40 { return Ok(false); }
    if blob.is_empty() {
        return Ok(leaf[..32] == [0; 32]
            && (phase_idx % 2 == 1 || leaf[32..] == [0; 8]));
    }
    Ok(quil_tries::vertex_leaf_value(blob)? == leaf)
}

fn sync_data_key(shard_id: &[u8], phase_idx: usize, bit_path: &[bool]) -> Result<Vec<u8>> {
    if shard_id.len() < 32 || shard_id.len() > u16::MAX as usize || phase_idx >= 4 || bit_path.len() > 256 {
        return Err(QuilError::InvalidArgument("invalid sync data scope".into()));
    }
    let mut key = b"quil/forest-sync/verified-blobs/v1/".to_vec();
    key.extend_from_slice(&(shard_id.len() as u16).to_be_bytes());
    key.extend_from_slice(shard_id);
    key.push(phase_idx as u8);
    key.extend_from_slice(&(bit_path.len() as u16).to_be_bytes());
    for chunk in bit_path.chunks(8) {
        key.push(chunk.iter().enumerate().fold(0, |byte, (i, bit)| byte | (u8::from(*bit) << (7 - i))));
    }
    Ok(key)
}

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

/// One mutation in an ordered, atomically staged batch. Data is borrowed until
/// preparation completes; the batch owns only its changed blobs and leaves.
pub enum Mutation<'a> {
    AddVertex(Location, &'a [u8]),
    RemoveVertex(Location),
    AddHyperedge(Location, &'a [u8]),
    RemoveHyperedge(Location),
    Record(&'a RecordMutation),
}

#[derive(Default)]
struct PreparedMutations {
    deltas: HashMap<(ShardKey, usize), PhaseDeltas>,
    blobs: HashMap<(ShardKey, usize), PhaseBlobs>,
    metadata: Vec<(Vec<u8>, i64, i128)>,
    records: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}
impl PreparedMutations {
    fn read(&self, crdt: &HypergraphCrdt, shard: &ShardKey, phase: usize, id: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(blob) = self.blobs.get(&(shard.clone(), phase)).and_then(|m| m.get(id)) {
            return Ok(Some(blob.clone()));
        }
        crdt.read_blob_checked(shard, phase, id)
    }

    fn stage(&mut self, shard: &ShardKey, phase: usize, id: &[u8], blob: &[u8], tombstone_size: Option<u64>) -> Result<()> {
        let leaves = match tombstone_size {
            Some(size) => vec![(id[32..64].to_vec(), quil_tries::sized_tombstone_leaf_value(size)?)],
            None => HypergraphCrdt::per_vertex_leaf(id, blob)?,
        };
        self.deltas.entry((shard.clone(), phase)).or_default().extend(leaves);
        self.blobs.entry((shard.clone(), phase)).or_default().insert(id.to_vec(), blob.to_vec());
        Ok(())
    }

    fn bump(&mut self, crdt: &HypergraphCrdt, shard: &ShardKey, location: &Location, count: i64, size: i128) {
        if shard.l2 != [0xff; 32] {
            self.metadata.push((crdt.sub_shard_id_for(&shard.l2, &location.data_address), count, size));
        }
    }
}

/// Own drained work until durable commit succeeds. On failure, restore older
/// entries without overwriting newer writes staged while the commit ran.
struct PendingCommit<'a> {
    crdt: &'a HypergraphCrdt,
    deltas: HashMap<(ShardKey, usize), PhaseDeltas>,
    blobs: HashMap<(ShardKey, usize), PhaseBlobs>,
    records: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    committed: bool,
}
impl Drop for PendingCommit<'_> {
    fn drop(&mut self) {
        if self.committed { return; }
        let mut pending = self.crdt.pending.write().unwrap();
        let mut blobs = self.crdt.pending_blobs.write().unwrap();
        for (phase, entries) in std::mem::take(&mut self.deltas) {
            let target = pending.entry(phase).or_default();
            for (key, value) in entries { target.entry(key).or_insert(value); }
        }
        for (phase, entries) in std::mem::take(&mut self.blobs) {
            let target = blobs.entry(phase).or_default();
            for (key, value) in entries { target.entry(key).or_insert(value); }
        }
        let mut records = self.crdt.pending_records.write().unwrap();
        for (key, value) in std::mem::take(&mut self.records) {
            records.entry(key).or_insert(value);
        }
    }
}


#[path = "execution_capture.rs"]
mod execution_capture;
pub use execution_capture::{ExecutionCapture, ExecutionFork, ExecutionForkLimits, ExecutionMetadataUsage, PreparedCrdtAdoption};

/// Identifies the CRDT whose coarse forest-write barrier is held. Maintenance
/// routines may use it without reacquiring the same non-reentrant lock.
pub struct ForestWriteGuard<'a> {
    source: &'a HypergraphCrdt,
    _guard: std::sync::MutexGuard<'a, ()>,
}

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
    /// Network world-state size (`total_size`) at the END of each materialized
    /// global frame, recorded with the prover root. The leader stamps
    /// `world_size_at(N-1)` on global frame N and voters check it, so the size
    /// every venue prices from is certified by global consensus.
    world_size_by_frame: RwLock<std::collections::BTreeMap<u64, u64>>,
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
    /// DEEP-BIFURCATION: each app's shard address BIT-PATHS, stored
    /// DIRECTLY (not derived from `app_shard_prefixes` via
    /// `canonical_shard_bit_paths`, which can't carry a bit-path that skips
    /// uniform bits). When present for an app, [`Self::shard_bit_paths`] returns
    /// these; absent ⇒ it falls back to canonical of `app_shard_prefixes`. MUST
    /// be index-aligned with `app_shard_prefixes` (same order/count) — the routing
    /// indexes both. Empty by default (canonical source); populated at the
    /// deep-bifurcation flag day.
    #[allow(clippy::type_complexity)]
    app_shard_bit_paths: RwLock<HashMap<[u8; 32], Vec<Vec<bool>>>>,
    /// Layout changes whose size buckets have not yet been rebuilt. Capturing
    /// such an intermediate configuration for execution is forbidden.
    layout_rebuilds: RwLock<std::collections::HashSet<[u8; 32]>>,
    /// Staged L3 leaf deltas per (shard, phase index).
    pending: RwLock<HashMap<(ShardKey, usize), PhaseDeltas>>,
    /// Staged per-vertex blobs per (shard, phase index).
    pending_blobs: RwLock<HashMap<(ShardKey, usize), PhaseBlobs>>,
    /// Ancillary execution records, co-committed with forest state and cursor.
    pending_records: RwLock<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
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
    size_warm_lock: std::sync::Mutex<()>,
    /// Snapshot-generation registry for sync `expected_root` gating.
    snapshot_mgr: SnapshotManager,
    local_vertex_observer: RwLock<Option<Arc<dyn quil_types::store::LocalVertexCommitObserver>>>,
    /// Covered nibble prefix (address gating). Empty = accept all.
    covered_prefix: RwLock<Vec<i32>>,
    /// Serializes mutation batches, commits and coordinated forest updates.
    commit_lock: std::sync::Mutex<()>,
    /// UNIFIED-APP-TREE mode. When set,
    /// every app commits ALL its vertices into ONE L3 tree per phase keyed by the
    /// app address (leaves raw-key positioned), so a shard is the in-place subtree
    /// at its prefix and the app-phase root is the JMT root over all shards — no
    /// separate per-sub-shard trees, no `app_root_from_shard_paths` rollup, no
    /// per-frame manifest. Per-shard commitments are read on demand via
    /// [`Forest::app_subtree_root`]. DEFAULT off (legacy separate-tree path);
    /// flipped at the flag-day frame AFTER the one-time consolidation, since
    /// a split app's existing data lives in the per-prefix trees until then.
    unified_tree: AtomicBool,
}

/// READ-ONLY snapshot of where an app's forest leaves actually live — the
/// UNIFIED app tree (keyed by the bare app address, post-699500 home of state)
/// vs the LEGACY per-prefix byte-suffix sub-shard trees (`addr_path_shard_id(app,
/// [i])`, where pre-cutover / freshly-migrated QUIL state was written). Lets an
/// operator tell "unified tree populated" (healthy) apart from "data stranded in
/// legacy trees, consolidation never drained it". Produced by
/// [`HypergraphCrdt::dump_app_forest_stats`]; not on any consensus path.
#[derive(Clone, Debug)]
pub struct AppForestStats {
    /// Unified app tree, per phase (0=VertexAdds .. 3=HyperedgeRemoves):
    /// `(leaf_count, root, version_read_at)`.
    pub unified: [(u64, [u8; 32], u64); 4],
    /// Legacy byte-suffix trees `[i]` (i in 0..64) with ANY VertexAdds leaves —
    /// `(i, vertex_adds_leaf_count)`. Empty once fully drained into the unified tree.
    pub legacy_nonempty: Vec<(u32, u64)>,
    /// Sum of VertexAdds leaves across ALL 64 legacy per-prefix trees.
    pub legacy_total_vertex_adds: u64,
}

impl HypergraphCrdt {
    /// READ-ONLY diagnostic: the PERSISTED per-sub-shard size buckets
    /// (`SIZE_BUCKETS_KEY`) that `warm_sizes` restores and `sub_meta_for` /
    /// GetAppShards / the reward basis read — returned for `app` as
    /// `(bucket_key_len, raw_count, live_size)`. The key is
    /// `addr_path_shard_id(app, prefix) = app(32) ‖ prefix_bytes`, so the LENGTH
    /// reveals the ENCODING: 36 (`app ‖ [i]`, one u32) = byte-suffix, 60
    /// (`app ‖ [SENTINEL, b×6]`, seven u32) = sentinel. If the buckets are
    /// byte-suffix while the live CRDT prefixes (post-refresh) are sentinel, every
    /// `sub_meta_for` fold misses → GetAppShards reports size 0 → the proposer sees
    /// no join candidates and the reward basis is 0. Does NOT run `warm_sizes`
    /// (no scan) — reads the cache verbatim.
    pub fn dump_persisted_size_buckets(&self, app: &[u8; 32]) -> Vec<(usize, u64, i128)> {
        let read_txn = match self.store.new_transaction(false) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let blob = match read_txn.get(SIZE_BUCKETS_KEY) {
            Ok(Some(b)) => b,
            _ => return Vec::new(),
        };
        let mut out: Vec<(usize, u64, i128)> = deserialize_buckets(&blob)
            .into_iter()
            .filter(|(k, _)| k.starts_with(&app[..]))
            .map(|(k, (c, s))| (k.len(), c, s))
            .collect();
        out.sort();
        out
    }

    /// READ-ONLY diagnostic: the persisted `(raw_count, live_size)` bucket of
    /// one sub-shard, keyed `addr_path_shard_id(app, prefix)`, as the last
    /// commit wrote it. Does not run `warm_sizes`.
    pub fn persisted_size_bucket(&self, key: &[u8]) -> Option<(u64, i128)> {
        let read_txn = self.store.new_transaction(false).ok()?;
        let blob = read_txn.get(SIZE_BUCKETS_KEY).ok()??;
        deserialize_buckets(&blob).get(key).copied()
    }

    /// READ-ONLY diagnostic (see [`AppForestStats`]): resolve each tree's exact
    /// committed version the same way the live reader does
    /// ([`Self::read_shard_phase_root`]), then read the UNIFIED app tree (keyed by
    /// the bare app address) and the 64 LEGACY per-prefix byte-suffix trees. If
    /// the unified VertexAdds count is ~total and legacy is ~0, state is where the
    /// live path reads it; if unified is ~0 while legacy holds the leaves, the
    /// one-time consolidation never drained them.
    pub fn dump_app_forest_stats(&self, app: &[u8; 32]) -> AppForestStats {
        let forest = self.forest.read().unwrap();
        let resolve = |sid: &[u8], pi: usize| -> u64 {
            self.resolve_phase_version_with(&forest, sid, pi)
                .unwrap_or_else(|| self.forest_version.load(Ordering::SeqCst))
        };
        let mut unified = [(0u64, [0u8; 32], 0u64); 4];
        for (pi, slot) in unified.iter_mut().enumerate() {
            let ver = resolve(app, pi);
            let count = forest.shard_phase_leaf_count(app, PHASES[pi], ver).unwrap_or(0);
            let root =
                forest.shard_phase_root(app, PHASES[pi], ver).ok().flatten().unwrap_or([0u8; 32]);
            *slot = (count, root, ver);
        }
        let mut legacy_nonempty = Vec::new();
        let mut legacy_total_vertex_adds = 0u64;
        for i in 0..64u32 {
            let sid = Forest::addr_path_shard_id(app, &[i]);
            let ver = resolve(&sid, 0); // phase 0 = VertexAdds = the state
            let count = forest.shard_phase_leaf_count(&sid, PHASES[0], ver).unwrap_or(0);
            if count > 0 {
                legacy_nonempty.push((i, count));
                legacy_total_vertex_adds += count;
            }
        }
        AppForestStats { unified, legacy_nonempty, legacy_total_vertex_adds }
    }

    pub fn new(store: Arc<dyn HypergraphStore>, prover: Arc<dyn InclusionProver>) -> Self {
        Self {
            store,
            prover,
            forest: RwLock::new(Forest::in_memory()),
            forest_version: AtomicU64::new(0),
            forest_write_lock: std::sync::Mutex::new(()),
            prover_root_by_frame: RwLock::new(std::collections::BTreeMap::new()),
            world_size_by_frame: RwLock::new(std::collections::BTreeMap::new()),
            phase_versions: RwLock::new(HashMap::new()),
            global_versions: RwLock::new(HashMap::new()),
            app_shard_prefixes: RwLock::new(HashMap::new()),
            app_shard_bit_paths: RwLock::new(HashMap::new()),
            layout_rebuilds: RwLock::new(std::collections::HashSet::new()),
            pending: RwLock::new(HashMap::new()),
            pending_blobs: RwLock::new(HashMap::new()),
            pending_records: RwLock::new(BTreeMap::new()),
            shard_metadata: RwLock::new(HashMap::new()),
            sub_meta: RwLock::new(HashMap::new()),
            sizes_warmed: AtomicBool::new(false),
            size_warm_lock: std::sync::Mutex::new(()),
            snapshot_mgr: SnapshotManager::new(),
            local_vertex_observer: RwLock::new(None),
            covered_prefix: RwLock::new(Vec::new()),
            commit_lock: std::sync::Mutex::new(()),
            unified_tree: AtomicBool::new(false),
        }
    }

    /// Install a best-effort local cache observer. Canonical commits do not
    /// depend on delivery, and the callback must not reenter the CRDT.
    pub fn set_local_vertex_observer(&self, observer: Arc<dyn quil_types::store::LocalVertexCommitObserver>) {
        *self.local_vertex_observer.write().unwrap() = Some(observer);
    }

    /// Enable/disable [`unified_tree`](Self::unified_tree) mode. Flag-day gated in
    /// production (set only after the one-time consolidation); tests flip it
    /// directly on a fresh CRDT.
    pub fn set_unified_tree(&self, on: bool) {
        let _guard = self.commit_lock.lock().unwrap();
        self.unified_tree.store(on, Ordering::SeqCst);
    }

    /// Whether unified-app-tree mode is active.
    pub fn unified_tree(&self) -> bool {
        self.unified_tree.load(Ordering::Relaxed)
    }

    /// Install the state-commitment forest (production: the namespaced RocksDB
    /// forest sharing the store's DB). Replaces the default in-memory forest.
    pub fn set_forest(&self, forest: Forest) {
        let _guard = self.commit_lock.lock().unwrap();
        *self.forest.write().unwrap() = forest;
    }

    /// Acquire the coarse forest-write serialization guard. Held for the WHOLE
    /// duration by the global-frame materializer (verify + apply + commit) and
    /// by the prover-tree syncer (its forest apply), so the two never write the
    /// forest concurrently. Poisoning is recovered (a panic mid-write is already
    /// a stop-the-materializer condition upstream). See `forest_write_lock`.
    pub fn lock_forest_writes(&self) -> ForestWriteGuard<'_> {
        ForestWriteGuard {
            source: self,
            _guard: self.forest_write_lock.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }

    /// Refuse a maintenance token belonging to another CRDT before any reads
    /// or writes. The guard itself cannot be constructed outside this module.
    pub fn check_forest_guard(&self, guard: &ForestWriteGuard<'_>) -> Result<()> {
        if !std::ptr::eq(self, guard.source) {
            return Err(QuilError::ExecutionUnavailable("foreign CRDT forest guard".into()));
        }
        Ok(())
    }

    /// Execute storage maintenance under this CRDT's forest and commit
    /// barriers. The operation must not reenter CRDT methods. Clear cached head
    /// versions even on failure: a partially completed operation may have
    /// changed them. A tentative owner must discard the branch on failure.
    pub fn maintain_forest<T>(
        &self,
        guard: &ForestWriteGuard<'_>,
        operation: impl FnOnce(&Forest) -> Result<T>,
    ) -> Result<T> {
        self.check_forest_guard(guard)?;
        let poisoned = |name| QuilError::ExecutionUnavailable(format!("maintenance {name} lock poisoned"));
        let _commit = self.commit_lock.lock().map_err(|_| poisoned("commit"))?;
        if !self.pending.read().map_err(|_| poisoned("pending"))?.is_empty()
            || !self.pending_blobs.read().map_err(|_| poisoned("blobs"))?.is_empty()
            || !self.pending_records.read().map_err(|_| poisoned("records"))?.is_empty()
        {
            return Err(QuilError::ExecutionUnavailable("maintenance has unfinished CRDT mutations".into()));
        }
        let forest = self.forest.read().map_err(|_| poisoned("forest"))?;
        let identity = self.store.backing_store_identity().ok_or_else(|| QuilError::ExecutionUnavailable("maintenance requires identifiable storage".into()))?;
        if forest.backing_store_identity().as_ref() != Some(&identity) {
            return Err(QuilError::ExecutionUnavailable("maintenance forest/record store mismatch".into()));
        }
        let mut phases = self.phase_versions.write().map_err(|_| poisoned("phase versions"))?;
        let mut globals = self.global_versions.write().map_err(|_| poisoned("global versions"))?;
        let result = operation(&forest);
        phases.clear();
        globals.clear();
        result
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
        let _guard = self.commit_lock.lock().unwrap();
        self.set_app_shard_prefixes_locked(app, prefixes)
    }

    fn set_app_shard_prefixes_locked(&self, app: [u8; 32], prefixes: Vec<Vec<u32>>) -> bool {
        let set = if prefixes.is_empty() { vec![Vec::new()] } else { prefixes };
        // Change-detection is ORDER-INDEPENDENT: a shard set is semantically a
        // SET, and routing is value-matched (an address finds its matching prefix
        // regardless of position), so a mere re-ordering must NOT read as a
        // transition. Comparing the raw `Vec` order once made a boot where the
        // shards-store range order differed from the seeded order (e.g. the forest
        // default vs the reset grid) look like a split EVERY boot, triggering a
        // full `rebucket_app` re-scan of all committed coins (the 30m-2hr hang).
        // Storage keeps the caller's order (routing derives bit-paths from it).
        let sorted = |v: &[Vec<u32>]| {
            let mut s = v.to_vec();
            s.sort();
            s
        };
        let mut w = self.app_shard_prefixes.write().unwrap();
        let changed = match w.get(&app) {
            Some(existing) if sorted(existing) == sorted(&set) => return false, // unchanged set
            Some(_) => {
                w.insert(app, set);
                true // genuine split/merge transition
            }
            None => {
                w.insert(app, set);
                false // first sight — warm_sizes owns the initial buckets
            }
        };
        drop(w);
        if changed || !self.buckets_match_current_prefixes(&[app], &self.sub_meta.read().unwrap()) {
            self.layout_rebuilds.write().unwrap().insert(app);
        }
        changed
    }

    /// Coordinate a shard-layout change and its size buckets with commits and
    /// execution captures. On a rebuild error, restore the previous layout so
    /// a retry still sees the transition. This does not supply a snapshot for
    /// callers reading these maps independently; use execution capture for
    /// that. Explicit bit-path overrides use the low-level setters followed by
    /// `rebucket_app` under an outer forest barrier.
    pub fn refresh_app_shard_prefixes(&self, app: [u8; 32], prefixes: Vec<Vec<u32>>) -> Result<bool> {
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "layout commit lock poisoned".into()))?;
        let previous = self.app_shard_prefixes.read().unwrap().get(&app).cloned();
        let previously_dirty = self.layout_rebuilds.read().unwrap().contains(&app);
        let changed = self.set_app_shard_prefixes_locked(app, prefixes);
        let result = if self.layout_rebuilds.read().unwrap().contains(&app) {
            if self.app_shard_bit_paths.read().unwrap().contains_key(&app) {
                Err(QuilError::ExecutionUnavailable("layout refresh requires coordinated explicit bit paths".into()))
            } else {
                tracing::info!(app = %hex::encode(app), unified = self.unified_tree(),
                    "shard layout refresh: rebuilding size buckets before publication");
                self.rebucket_app_locked(&app)
            }
        } else { Ok(()) };
        if let Err(error) = result {
            let mut layouts = self.app_shard_prefixes.write().unwrap();
            match previous { Some(prefixes) => { layouts.insert(app, prefixes); }, None => { layouts.remove(&app); } }
            if !previously_dirty { self.layout_rebuilds.write().unwrap().remove(&app); }
            return Err(error);
        }
        Ok(changed)
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

    /// Declare `app`'s shard address BIT-PATHS directly (deep-bifurcation).
    /// MUST be index-aligned with the prefix set from [`set_app_shard_prefixes`]
    /// (same order/count) — routing indexes both. Empty ⇒ clears the override
    /// (back to canonical derivation).
    pub fn set_app_shard_bit_paths(&self, app: [u8; 32], bit_paths: Vec<Vec<bool>>) {
        let _guard = self.commit_lock.lock().unwrap();
        let mut w = self.app_shard_bit_paths.write().unwrap();
        let changed = w.get(&app).map_or(!bit_paths.is_empty(), |old| *old != bit_paths);
        if bit_paths.is_empty() {
            w.remove(&app);
        } else {
            w.insert(app, bit_paths);
        }
        if changed { self.layout_rebuilds.write().unwrap().insert(app); }
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
        versions: &mut HashMap<(Vec<u8>, usize), u64>,
    ) -> Result<([u8; 32], u64)> {
        let mut head = self.resolve_phase_version_checked(forest, shard_id, phase_idx)?;
        if head.is_some() {
            self.read_shard_phase_root_checked(forest, shard_id, phase_idx)?;
        } else {
            // Older migration output can contain a tree at the fallback
            // version without a head marker. Append to it, never overwrite it
            // as a fresh version-zero tree.
            let fallback = self.forest_version.load(Ordering::SeqCst);
            if forest.shard_phase_root(shard_id, PHASES[phase_idx], fallback)
                .map_err(|e| QuilError::ExecutionUnavailable(format!("read unmarked phase root: {e}")))?.is_some() {
                head = Some(fallback);
            }
        }
        let ver = head
            .map(|v| v.checked_add(1).ok_or_else(|| QuilError::ExecutionUnavailable("phase version exhausted".into())))
            .transpose()?.unwrap_or(0);
        let (root, puts) = forest
            .commit_shard_phase_raw_staged(shard_id, PHASES[phase_idx], ver, leaves)
            .map_err(|e| QuilError::ExecutionUnavailable(format!("forest commit: {e}")))?;
        versions.insert((shard_id.to_vec(), phase_idx), ver);
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
        &self, forest: &Forest, shard_id: &[u8], phase_idx: usize,
    ) -> Option<u64> {
        self.resolve_phase_version_checked(forest, shard_id, phase_idx).ok().flatten()
    }

    /// Commit callers must distinguish a missing head from unreadable state.
    fn resolve_phase_version_checked(
        &self, forest: &Forest, shard_id: &[u8], phase_idx: usize,
    ) -> Result<Option<u64>> {
        if let Some(version) = self.phase_versions.read().unwrap()
            .get(&(shard_id.to_vec(), phase_idx)).copied() { return Ok(Some(version)); }
        forest.read_head_version(shard_id, PHASES[phase_idx])
            .map_err(|e| QuilError::ExecutionUnavailable(format!("read phase head: {e}")))
    }

    fn resolve_global_version(&self, forest: &Forest, index: u8) -> Option<u64> {
        self.resolve_global_version_checked(forest, index).ok().flatten()
    }

    fn resolve_global_version_checked(&self, forest: &Forest, index: u8) -> Result<Option<u64>> {
        if let Some(version) = self.global_versions.read().unwrap().get(&index).copied() {
            return Ok(Some(version));
        }
        forest.read_global_head_version(index)
            .map_err(|e| QuilError::ExecutionUnavailable(format!("read global head: {e}")))
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
        self.read_shard_phase_root_checked(forest, shard_id, phase_idx).unwrap_or([0; 32])
    }

    fn read_shard_phase_root_checked(&self, forest: &Forest, shard_id: &[u8], phase_idx: usize) -> Result<[u8; 32]> {
        let head = self.resolve_phase_version_checked(forest, shard_id, phase_idx)?;
        let version = head.unwrap_or_else(|| self.forest_version.load(Ordering::SeqCst));
        match forest.shard_phase_root(shard_id, PHASES[phase_idx], version)
            .map_err(|e| QuilError::ExecutionUnavailable(format!("read phase root: {e}")))? {
            Some(root) => Ok(root),
            None if head.is_none() => Ok([0; 32]),
            None => Err(QuilError::ExecutionUnavailable("persisted phase head has no root".into())),
        }
    }

    fn current_app_phase_root(
        &self, forest: &Forest, app: &[u8; 32], prefixes: &[Vec<u32>], phase_idx: usize,
    ) -> Vec<u8> {
        self.current_app_phase_root_checked(forest, app, prefixes, phase_idx).unwrap_or_else(|_| vec![0; 32])
    }

    fn current_app_phase_root_checked(
        &self, forest: &Forest, app: &[u8; 32], prefixes: &[Vec<u32>], phase_idx: usize,
    ) -> Result<Vec<u8>> {
        if self.unified_tree() || (prefixes.len() == 1 && prefixes[0].is_empty()) {
            return Ok(self.read_shard_phase_root_checked(forest, app, phase_idx)?.to_vec());
        }
        let shard_roots: Vec<(Vec<bool>, [u8; 32])> = prefixes.iter().zip(self.shard_bit_paths(app))
            .map(|(prefix, bits)| {
                let shard_id = Forest::addr_path_shard_id(app, prefix);
                Ok((bits, self.read_shard_phase_root_checked(forest, &shard_id, phase_idx)?))
            }).collect::<Result<_>>()?;
        Ok(app_root_from_shard_paths(&shard_roots).to_vec())
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
        let _guard = self.commit_lock.lock().unwrap();
        // The world size is captured at the same instant: the materializer
        // records the root the moment frame `frame` finishes.
        {
            use num_traits::ToPrimitive;
            let size = self.total_size().to_u64().unwrap_or(u64::MAX);
            let mut sizes = self.world_size_by_frame.write().unwrap();
            sizes.insert(frame, size);
            while sizes.len() > 256 {
                let oldest = *sizes.keys().next().unwrap();
                sizes.remove(&oldest);
            }
        }
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

    /// Network world-state size at the END of global frame `frame`, if this
    /// node recorded that frame's materialization. See `world_size_by_frame`.
    pub fn world_size_at(&self, frame: u64) -> Option<u64> {
        self.world_size_by_frame.read().unwrap().get(&frame).copied()
    }

    // ---- covered prefix -------------------------------------------------

    pub fn get_covered_prefix(&self) -> Vec<i32> {
        self.covered_prefix.read().unwrap().clone()
    }

    pub fn set_covered_prefix(&self, prefix: &[i32]) -> Result<()> {
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "coverage commit lock poisoned".into()))?;
        self.store.set_covered_prefix(prefix)?;
        *self.covered_prefix.write().unwrap() = prefix.to_vec();
        Ok(())
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

    // ---- read helpers (KV blobs + tombstone check) ----------------------

    /// The staged-or-committed blob for `(shard, phase, id)`, or `None`.
    fn read_blob(&self, shard: &ShardKey, phase_idx: usize, id: &[u8]) -> Option<Vec<u8>> {
        self.read_blob_checked(shard, phase_idx, id).ok().flatten()
    }

    fn read_blob_checked(&self, shard: &ShardKey, phase_idx: usize, id: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(m) = self.pending_blobs.read().unwrap().get(&(shard.clone(), phase_idx)) {
            if let Some(b) = m.get(id) {
                return Ok(Some(b.clone()));
            }
        }
        let (set, phase) = PHASE_STR[phase_idx];
        self.store
            .load_vertex_underlying_raw(set, phase, shard, id)
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

    // ---- mutations ------------------------------------------------------

    pub fn add_vertex(&self, location: &Location, data: &[u8]) -> Result<()> {
        self.apply_mutations(&[Mutation::AddVertex(location.clone(), data)])
    }

    pub fn remove_vertex(&self, location: &Location) -> Result<()> {
        self.apply_mutations(&[Mutation::RemoveVertex(location.clone())])
    }

    pub fn add_hyperedge(&self, location: &Location, data: &[u8]) -> Result<()> {
        self.apply_mutations(&[Mutation::AddHyperedge(location.clone(), data)])
    }

    pub fn remove_hyperedge(&self, location: &Location) -> Result<()> {
        self.apply_mutations(&[Mutation::RemoveHyperedge(location.clone())])
    }

    /// Prepare the entire ordered batch before publishing any staged state.
    /// Reads see earlier operations in this batch and previously staged work.
    /// Serializes with other mutations, commit and coordinated forest sync.
    /// Success stages work; it does not durably commit a frame.
    pub fn apply_mutations(&self, mutations: &[Mutation<'_>]) -> Result<()> {
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "CRDT mutation/commit lock poisoned".into()))?;
        let mut prepared = PreparedMutations::default();
        for mutation in mutations {
            let (location, data, adds_phase) = match mutation {
                Mutation::AddVertex(location, data) => (location, Some(*data), 0),
                Mutation::RemoveVertex(location) => (location, None, 0),
                Mutation::AddHyperedge(location, data) => (location, Some(*data), 2),
                Mutation::RemoveHyperedge(location) => (location, None, 2),
                Mutation::Record(record) => {
                    prepared.records.insert(record.key.clone(), record.value.clone());
                    continue;
                }
            };
            let shard = shard_key_for_location(location);
            let id = location.to_id();
            if let Some(data) = data {
                let new_vertex = if adds_phase == 0 {
                    prepared.read(self, &shard, 0, &id)?.is_none()
                } else {
                    if prepared.read(self, &shard, 3, &id)?.is_some() { continue; }
                    false
                };
                prepared.stage(&shard, adds_phase, &id, data, None)?;
                prepared.bump(self, &shard, location, i64::from(new_vertex), data.len() as i128);
            } else {
                let existing = prepared.read(self, &shard, adds_phase, &id)?;
                let removed = prepared.read(self, &shard, adds_phase + 1, &id)?.is_some();
                let size = existing.as_ref().map_or(0, |blob| blob.len());
                let present = size != 0 && !removed;
                let placeholder = existing.is_none();
                if placeholder { prepared.stage(&shard, adds_phase, &id, &[], None)?; }
                prepared.stage(&shard, adds_phase + 1, &id, &[], Some(size as u64))?;
                // Vertex placeholders enter the raw adds count. Hyperedges
                // contribute only live size. Repeated removes keep original size.
                if present || (adds_phase == 0 && placeholder) {
                    prepared.bump(self, &shard, location,
                        i64::from(adds_phase == 0 && placeholder),
                        if present { -(size as i128) } else { 0 });
                }
            }
        }

        // Acquire every publication lock before changing any map. Preparation
        // above cannot leak partial blobs, leaves or metadata on a read error.
        let mut pending = self.pending.write().unwrap();
        let mut blobs = self.pending_blobs.write().unwrap();
        let mut metadata = self.sub_meta.write().unwrap();
        let mut records = self.pending_records.write().unwrap();
        let mut next_metadata = HashMap::new();
        for (key, count, size) in prepared.metadata {
            let entry = next_metadata.entry(key.clone())
                .or_insert_with(|| metadata.get(&key).copied().unwrap_or((0u64, 0i128)));
            entry.0 = if count >= 0 {
                entry.0.checked_add(count as u64).ok_or_else(||
                    QuilError::ExecutionUnavailable("CRDT metadata count overflow".into()))?
            } else { entry.0.saturating_sub(count.unsigned_abs()) };
            entry.1 = entry.1.checked_add(size).ok_or_else(||
                QuilError::ExecutionUnavailable("CRDT metadata size overflow".into()))?;
        }
        for (phase, entries) in prepared.deltas {
            pending.entry(phase).or_default().extend(entries);
        }
        for (phase, entries) in prepared.blobs {
            blobs.entry(phase).or_default().extend(entries);
        }
        metadata.extend(next_metadata);
        records.extend(prepared.records);
        Ok(())
    }

    /// Whether mutations are staged in memory but not committed. A failed
    /// in-place execution can leave them, and any later commit publishes them.
    pub fn has_staged_mutations(&self) -> bool {
        let _guard = self.commit_lock.lock().unwrap();
        !self.pending.read().unwrap().is_empty()
            || !self.pending_blobs.read().unwrap().is_empty()
            || !self.pending_records.read().unwrap().is_empty()
    }

    /// Execution-only overlay. Callers serialize execution while deriving state.
    /// External readers continue to use the committed store.
    pub fn staged_records(&self) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
        let _guard = self.commit_lock.lock().unwrap();
        self.pending_records.read().unwrap().clone()
    }

    pub fn read_execution_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let _guard = self.commit_lock.lock().unwrap();
        if let Some(value) = self.pending_records.read().unwrap().get(key) {
            return Ok(value.clone());
        }
        self.store.new_transaction(false)?.get(key)
    }

    // ---- ensure (forest loads lazily; these are compatibility no-ops) ---

    pub fn ensure_vertex_adds_tree(&self, _shard_key: &ShardKey) {}
    pub fn ensure_all_phase_trees(&self, _shard_key: &ShardKey) {}

    /// Read one committed fixed-address page. Each store call has its own
    /// snapshot; callers needing a multi-page snapshot must also pin/check a
    /// committed root/version. This does not include staged forest writes.
    pub fn page_committed_vertex_adds(
        &self, domain: &[u8; 32], after: Option<&[u8; 32]>,
        limits: quil_types::store::VertexPageLimits,
    ) -> Result<quil_types::store::VertexDataPage> {
        let shard = shard_key_for_location(&Location { app_address: *domain, data_address: [0; 32] });
        self.store.page_vertex_underlying_fixed("vertex", "adds", &shard, domain, after, limits)
    }

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

    /// Collect vertex-adds blobs including writes staged since the last forest
    /// commit. Execution uses this to derive state from earlier messages in the
    /// same frame. Callers must serialize mutations while deriving that state;
    /// this is not a committed snapshot for external readers.
    pub fn collect_live_vertex_adds(&self, domain: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let app_address: [u8; 32] = domain.try_into().map_err(|_| {
            QuilError::InvalidArgument("vertex-adds domain must be 32 bytes".into())
        })?;
        let shard = shard_key_for_location(&Location { app_address, data_address: [0; 32] });
        self.collect_phase_leaves(&shard, 0, &[])
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
        self.commit_inner(frame_number, None, &[])
    }

    /// Commit frame state and its execution cursor in one store transaction.
    pub fn commit_with_frame_cursor(
        &self, frame_number: u64, cursor_key: &[u8],
    ) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        self.commit_with_frame_cursor_and_records(frame_number, cursor_key, &[])
    }

    /// Publish frame history in the same transaction as its state and cursor.
    /// The records must use the namespaces of stores sharing this state DB.
    pub fn commit_with_frame_cursor_and_records(
        &self,
        frame_number: u64,
        cursor_key: &[u8],
        records: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        self.commit_inner(frame_number, Some(cursor_key), records)
    }

    /// Checkpoint an already completed external state import. This writes only
    /// the cursor; it neither flushes pending mutations nor makes the import
    /// atomic with this transaction.
    pub fn checkpoint_frame_cursor(&self, frame_number: u64, cursor_key: &[u8]) -> Result<()> {
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "frame checkpoint commit lock poisoned".into()))?;
        let txn = self.store.new_transaction(false)?;
        if let Err(error) = txn.set(cursor_key, &frame_number.to_be_bytes()) {
            let _ = txn.abort();
            return Err(error);
        }
        txn.commit()
    }

    /// Read the cursor from the same store that publishes the state. Absence
    /// means genesis; malformed bytes and read failures must not become zero.
    pub fn read_frame_cursor(&self, cursor_key: &[u8]) -> Result<u64> {
        let txn = self.store.new_transaction(true)?;
        let value = txn.get(cursor_key);
        let aborted = txn.abort();
        let value = value?;
        aborted?;
        match value {
            None => Ok(0),
            Some(bytes) => Ok(u64::from_be_bytes(bytes.as_slice().try_into().map_err(|_|
                QuilError::ExecutionUnavailable("malformed materialized frame cursor".into()))?)),
        }
    }

    pub fn commit_with_global_cursor(
        &self,
        frame_number: u64,
        cursor_key: &[u8],
    ) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        self.commit_with_frame_cursor(frame_number, cursor_key)
    }

    fn commit_inner(
        &self,
        frame_number: u64,
        cursor_key: Option<&[u8]>,
        records: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        let _guard = self.commit_lock.lock().unwrap();

        // Complete fallible store setup before taking ownership of staged
        // writes. An unavailable transaction or root read must leave them
        // intact for retry; the drained work below has its own recovery guard.
        let txn = self.store.new_transaction(false)?;
        let cached = self.store.get_root_commits(frame_number)?;

        // Drain the pending deltas + blobs for this commit.
        let mut staged = PendingCommit {
            crdt: self,
            deltas: std::mem::take(&mut *self.pending.write().unwrap()),
            blobs: std::mem::take(&mut *self.pending_blobs.write().unwrap()),
            records: std::mem::take(&mut *self.pending_records.write().unwrap()),
            committed: false,
        };
        let pending = &staged.deltas;
        let pending_blobs = &staged.blobs;
        let mut phase_versions = HashMap::new();
        let mut global_versions = HashMap::new();
        let mut shard_metadata = HashMap::new();

        let forest = self.forest.read().unwrap();

        // Union of shards touched this commit + shards with cached commits.
        let mut shard_keys: Vec<ShardKey> = Vec::new();
        for (sk, _) in pending.keys() {
            if !shard_keys.contains(sk) {
                shard_keys.push(sk.clone());
            }
        }
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
                        self.current_app_phase_root_checked(&forest, &shard.l2, &prefixes, phase_idx)?;
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
                        &mut phase_versions,
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
                                &mut phase_versions,
                            )?,
                            None => (
                                self.read_shard_phase_root_checked(&forest, &shard_id, phase_idx)?,
                                self.resolve_phase_version_checked(&forest, &shard_id, phase_idx)?
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

            shard_metadata.insert(
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
            let mut head = self.resolve_global_version_checked(&forest, bucket)?;
            let version = head.unwrap_or_else(|| self.forest_version.load(Ordering::SeqCst));
            let root = forest.global_root(bucket, version)
                .map_err(|e| QuilError::ExecutionUnavailable(format!("read global root: {e}")))?;
            if root.is_none() && head.is_some() {
                return Err(QuilError::ExecutionUnavailable("persisted global head has no root".into()));
            }
            if root.is_some() { head = Some(version); }
            let ver = head
                .map(|v| v.checked_add(1).ok_or_else(|| QuilError::ExecutionUnavailable("global version exhausted".into())))
                .transpose()?.unwrap_or(0);
            match forest.commit_global_staged(bucket, ver, apps) {
                Ok((_root, puts)) => {
                    for (k, v) in puts {
                        txn.set(&k, &v)?;
                    }
                    if let Some((hk, hv)) = forest.global_head_version_put(bucket, ver) {
                        txn.set(&hk, &hv)?;
                    }
                    global_versions.insert(bucket, ver);
                }
                Err(e) => {
                    return Err(QuilError::ExecutionUnavailable(format!("L1 global bucket {bucket} commit failed: {e}")));
                }
            }
        }

        for (key, value) in &staged.records {
            match value {
                Some(value) => txn.set(key, value)?,
                None => txn.delete(key)?,
            }
        }
        for (key, value) in records {
            // Content-addressed reports recur across frames. Retain one copy
            // without rewriting it into the WAL at every materialization.
            if txn.get(key)?.as_deref() != Some(value.as_slice()) {
                txn.set(key, value)?;
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
        staged.committed = true;
        // Publish only heads whose nodes and blobs are now durable. A failed
        // transaction must retry from the previous head, not a missing version.
        self.phase_versions.write().unwrap().extend(phase_versions);
        self.global_versions.write().unwrap().extend(global_versions);
        self.shard_metadata.write().unwrap().extend(shard_metadata);
        let observer = self.local_vertex_observer.read().ok().and_then(|observer| observer.clone());
        if let Some(observer) = observer {
            let mut vertices = pending_blobs.iter().filter(|((_, phase), _)| *phase == 0)
                .flat_map(|(_, blobs)| blobs.iter().map(|(key, value)| (key.as_slice(), value.as_slice())))
                .chain(staged.records.iter().filter_map(|(key, value)| value.as_ref().map(|value| (key.as_slice(), value.as_slice()))));
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| observer.committed(&mut vertices))).is_err() {
                tracing::warn!("local vertex commit observer panicked after durable commit");
            }
        }

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

    /// Read all current global bucket roots without treating an unavailable
    /// version or root as an empty bucket. Execution checkpointing must retain
    /// that distinction; a head without its root is incomplete state.
    pub fn global_commitments_checked(&self) -> Result<Vec<Vec<u8>>> {
        let forest = self.forest.read().map_err(|_| QuilError::ExecutionUnavailable(
            "global commitment forest lock poisoned".into()))?;
        (0u8..=255).map(|index| {
            let Some(version) = self.resolve_global_version_checked(&forest, index)? else {
                return Ok(Vec::new());
            };
            forest.global_root(index, version)
                .map_err(|error| QuilError::ExecutionUnavailable(format!("global commitment read: {error}")))?
                .map(|root| root.to_vec())
                .ok_or_else(|| QuilError::ExecutionUnavailable("global commitment head has no root".into()))
        }).collect()
    }

    pub fn total_size(&self) -> BigInt {
        let sum: i128 = self.sub_meta.read().unwrap().values().map(|(_, s)| *s).sum();
        BigInt::from(sum.max(0))
    }

    /// Summed `(raw_count, live_size)` of every declared sub-shard at/under a
    /// query `(app, prefix)` — an O(#sub-shards) read of the maintained buckets,
    /// no tree scan. `prefix` empty ⇒ whole app.
    fn sub_meta_for(&self, app: &[u8; 32], prefix: &[u32]) -> (u64, i128) {
        // Match by CANONICAL bit-path, not raw `starts_with`: the lookup prefix
        // and the CRDT's stored prefixes can be in DIFFERENT encodings (a byte-
        // suffix `[i]` vs a sentinel `[SENTINEL, bits]` after a reset). A raw
        // compare misses — a sentinel prefix never `starts_with([i])` — so every
        // sentinel-shard lookup returned size 0, zeroing rewards and making
        // GetAppShards report empty (post-v5 "no rewards / no join candidates").
        // `shard_bit_paths` is the SPLIT-AWARE canonical decode (aligned with
        // `app_prefixes`), so this handles non-uniform / non-6-bit splits too.
        // `prefix` empty ⇒ whole app.
        let prefixes = self.app_prefixes(app);
        let bit_paths = self.shard_bit_paths(app);
        // The lookup prefix's canonical bits: its entry in the set if it IS a
        // current shard, else a best-effort decode (a parent prefix not itself a
        // current shard — sentinel-tagged if present, else the 6-bit QUIL split).
        let lookup_bits = prefixes
            .iter()
            .position(|p| p == prefix)
            .and_then(|i| bit_paths.get(i).cloned())
            .unwrap_or_else(|| {
                if prefix.is_empty() {
                    Vec::new()
                } else {
                    quil_forest::shard_bit_path_from_prefix(prefix)
                        .unwrap_or_else(|| quil_forest::prefix_to_bits(prefix, 6))
                }
            });
        let m = self.sub_meta.read().unwrap();
        prefixes
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                bit_paths
                    .get(*i)
                    .map(|b| b.starts_with(&lookup_bits))
                    .unwrap_or(false)
            })
            .filter_map(|(_, p)| m.get(&Forest::addr_path_shard_id(app, p)).copied())
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
    /// Whether a size-bucket map is keyed consistently with each app's CURRENT
    /// `app_prefixes` — every bucket key for an app must be one of that app's
    /// current-prefix shard ids (`addr_path_shard_id(app, prefix)`). A cache
    /// written under a since-replaced encoding (byte-suffix vs sentinel) or under
    /// a pre-split parent prefix carries keys absent from the current set and
    /// fails this, so [`warm_sizes`] rebuilds instead of restoring stale keys.
    /// Missing expected keys are fine (a shard with no data has no bucket); only
    /// UNEXPECTED keys (belonging to a prior encoding/partition) reject the cache.
    fn buckets_match_current_prefixes(
        &self,
        apps: &[[u8; 32]],
        m: &HashMap<Vec<u8>, (u64, i128)>,
    ) -> bool {
        for &app in apps {
            if app == [0xFFu8; 32] {
                continue; // prover shard excluded from world size (never bucketed)
            }
            let expected: std::collections::HashSet<Vec<u8>> = self
                .app_prefixes(&app)
                .iter()
                .map(|p| Forest::addr_path_shard_id(&app, p))
                .collect();
            for k in m.keys() {
                if k.starts_with(&app[..]) && !expected.contains(k) {
                    return false;
                }
            }
        }
        true
    }

    /// Re-key a stale-encoded bucket map to the CURRENT prefixes by canonical
    /// bit-path, WITHOUT rescanning committed state. A byte-suffix `[i]` bucket and
    /// the sentinel `binary(i)` bucket describe the SAME shard and carry the same
    /// `(raw_count, live_size)`, so an encoding flip is a pure key remap. Returns
    /// `None` — signalling the caller to do a full rescan — if any app-owned bucket
    /// maps to zero or more-than-one current prefix (a genuine partition change,
    /// e.g. a split, needs real re-attribution, not a remap). Keys not owned by any
    /// `apps` entry pass through unchanged.
    fn transcode_buckets_to_current(
        &self,
        apps: &[[u8; 32]],
        stale: &HashMap<Vec<u8>, (u64, i128)>,
    ) -> Option<HashMap<Vec<u8>, (u64, i128)>> {
        let per_app: HashMap<[u8; 32], (Vec<Vec<u32>>, Vec<Vec<bool>>)> = apps
            .iter()
            .map(|&app| (app, (self.app_prefixes(&app), self.shard_bit_paths(&app))))
            .collect();
        let mut out: HashMap<Vec<u8>, (u64, i128)> = HashMap::new();
        for (k, v) in stale {
            let Some(&app) = apps.iter().find(|a| k.starts_with(&a[..])) else {
                out.insert(k.clone(), *v); // foreign key — keep verbatim
                continue;
            };
            let (prefixes, bit_paths) = per_app.get(&app).unwrap();
            // Already a current-prefix key ⇒ keep as-is.
            if prefixes.iter().any(|p| Forest::addr_path_shard_id(&app, p) == *k) {
                let e = out.entry(k.clone()).or_insert((0, 0));
                e.0 += v.0;
                e.1 += v.1;
                continue;
            }
            // Decode the stale key's prefix (`app(32) ‖ u32-BE levels`) → bit-path,
            // then find the single current prefix sharing those canonical bits.
            let prefix_bytes = &k[app.len().min(k.len())..];
            if prefix_bytes.len() % 4 != 0 {
                return None;
            }
            let stale_prefix: Vec<u32> = prefix_bytes
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            let stale_bits = quil_forest::shard_bit_path_from_prefix(&stale_prefix)
                .unwrap_or_else(|| quil_forest::prefix_to_bits(&stale_prefix, 6));
            let mut matched: Option<&Vec<u32>> = None;
            for (i, b) in bit_paths.iter().enumerate() {
                if *b == stale_bits {
                    if matched.is_some() {
                        return None; // ambiguous — needs a real scan
                    }
                    matched = prefixes.get(i);
                }
            }
            let cur_prefix = matched?; // no current shard with these bits ⇒ rescan
            let e = out
                .entry(Forest::addr_path_shard_id(&app, cur_prefix))
                .or_insert((0, 0));
            e.0 += v.0;
            e.1 += v.1;
        }
        Some(out)
    }

    pub fn warm_sizes(&self, apps: &[[u8; 32]]) -> Result<()> {
        let _commit_guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "size warm commit lock poisoned".into()))?;
        if self.sizes_warmed.load(Ordering::Acquire) {
            return Ok(());
        }
        if !self.pending.read().unwrap().is_empty() || !self.pending_blobs.read().unwrap().is_empty() {
            return Err(QuilError::ExecutionUnavailable("cannot initialize size accounting with staged mutations".into()));
        }
        let _guard = self.size_warm_lock.lock().unwrap();
        if self.sizes_warmed.load(Ordering::Acquire) { return Ok(()); }
        // Fast path: restore the persisted buckets — but ONLY if their key
        // encoding still matches the CURRENT prefixes. The cache is keyed
        // `addr_path_shard_id(app, prefix)` for the prefixes in force when it was
        // written; if the shard set has since been re-encoded (a byte-suffix →
        // sentinel grid reset), a blind restore reinstates STALE keys that
        // `sub_meta_for` — which folds by the current sentinel prefixes — can never
        // match, zeroing GetAppShards sizes and the reward basis (post-reset
        // "no join candidates / no rewards"). On mismatch: keep the current
        // in-memory buckets if a `rebucket_app` this boot already re-keyed them to
        // the current prefixes (the `refresh_crdt_shard_prefixes` path), re-persist,
        // and skip the rescan; otherwise fall through to a fresh scan that re-keys.
        let blob = {
            let read_txn = self.store.new_transaction(false)?;
            read_txn.get(SIZE_BUCKETS_KEY)?
        };
        if let Some(blob) = blob {
            let restored = deserialize_buckets(&blob);
            if self.buckets_match_current_prefixes(apps, &restored) {
                *self.sub_meta.write().unwrap() = restored;
                self.sizes_warmed.store(true, Ordering::Release);
                self.layout_rebuilds.write().unwrap().retain(|app| !apps.contains(app));
                return Ok(());
            }
            // Stale encoding (a byte-suffix→sentinel grid flip since the cache was
            // written). Prefer, in order: the already-rebuilt in-memory buckets (a
            // `rebucket_app` this boot); a no-rescan TRANSCODE that re-keys the
            // stale buckets to the current prefixes by canonical bit-path (a
            // byte-suffix `[i]` bucket and the sentinel `binary(i)` bucket carry the
            // same `(count,size)`); else fall through to a full cold scan.
            let current = self.sub_meta.read().unwrap().clone();
            let replacement = if !current.is_empty()
                && self.buckets_match_current_prefixes(apps, &current)
            {
                Some(current)
            } else {
                self.transcode_buckets_to_current(apps, &restored)
            };
            if let Some(buckets) = replacement {
                let txn = self.store.new_transaction(false)?;
                txn.set(SIZE_BUCKETS_KEY, &serialize_buckets(&buckets))?;
                txn.commit()?;
                *self.sub_meta.write().unwrap() = buckets;
                self.sizes_warmed.store(true, Ordering::Release);
                self.layout_rebuilds.write().unwrap().retain(|app| !apps.contains(app));
                return Ok(());
            }
        }
        let mut buckets: HashMap<Vec<u8>, (u64, i128)> = HashMap::new();
        for &app in apps {
            self.forest_app_buckets(&app, &mut buckets)?;
        }
        // Persist the freshly-computed baseline so subsequent restarts take the
        // fast path.
        let txn = self.store.new_transaction(false)?;
        txn.set(SIZE_BUCKETS_KEY, &serialize_buckets(&buckets))?;
        txn.commit()?;
        *self.sub_meta.write().unwrap() = buckets;
        self.sizes_warmed.store(true, Ordering::Release);
        self.layout_rebuilds.write().unwrap().retain(|app| !apps.contains(app));
        Ok(())
    }

    /// One-time backfill of the forest Merkle-sum size index (the per-node
    /// `TAG_SIZE` side column) over a pre-existing tree, so the write-time
    /// maintenance ([`quil_forest::batch_size_sums`]) keeps it warm from a
    /// complete baseline. Returns `true` iff it actually seeded (so the caller
    /// can log), `false` if it was skipped (marker already set, or non-unified).
    ///
    /// Marker-gated (`SIZE_INDEX_SEEDED_KEY`): walks each phase tree at most once
    /// per DB. MUST run at boot BEFORE the materializer replays or produces and
    /// BEFORE the first `rebucket_app`, so the size walk lands on a quiescent DB
    /// (~the "30m–2h archive boot") rather than cold-walking on the consensus
    /// hot path at an epoch-boundary split (the network-wide halt this fixes).
    /// Idempotent: a crash mid-seed leaves the marker unset and re-seeds next
    /// boot — already-memoized nodes are cheap hits, so the re-walk resumes.
    pub fn warm_size_index(&self, apps: &[[u8; 32]]) -> Result<bool> {
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "size index commit lock poisoned".into()))?;
        // NOTE: NOT gated on `unified_tree()` — this must run at boot BEFORE the
        // unified flag is set (which happens in `boot_consolidate_and_gate`,
        // after the first `rebucket_app` in `refresh_crdt_shard_prefixes`). It
        // seeds the on-disk tree regardless of the in-memory routing mode;
        // seeding a non-unified node's trees is harmless (its `rebucket_app`
        // uses the legacy scan and never reads the index). The marker gate keeps
        // it a once-per-DB operation.
        {
            let read_txn = self.store.new_transaction(false)?;
            if read_txn.get(SIZE_INDEX_SEEDED_KEY)?.is_some() {
                return Ok(false);
            }
        }
        {
            let forest = self.forest.read().unwrap();
            let fallback_ver = self.forest_version.load(Ordering::SeqCst);
            for &app in apps {
                if app == [0xFFu8; 32] {
                    continue; // prover shard excluded from world size
                }
                tracing::info!(
                    app = %hex::encode(&app[..4]),
                    "size-index backfill: seeding app — ONE-TIME sequential full-tree sweep (node \
                     will not produce until done; restarts cleanly if interrupted; progress logged \
                     periodically)"
                );
                let start = std::time::Instant::now();
                let mut total: u128 = 0;
                for ph in 0..4 {
                    let ver = self
                        .resolve_phase_version_with(&forest, &app, ph)
                        .unwrap_or(fallback_ver);
                    // Throttled progress heartbeat (~every 30s). `nodes` is the cumulative
                    // count of size-index entries written for this phase tree (leaves as they
                    // stream in, then internals summed bottom-up), so the rate reflects the
                    // sequential sweep's throughput.
                    let ph_start = std::time::Instant::now();
                    let last_log_s = std::sync::atomic::AtomicU64::new(0);
                    let on_flush = |nodes: u64| {
                        let el = ph_start.elapsed().as_secs();
                        let prev = last_log_s.load(Ordering::Relaxed);
                        if el >= prev.saturating_add(30)
                            && last_log_s
                                .compare_exchange(prev, el, Ordering::Relaxed, Ordering::Relaxed)
                                .is_ok()
                        {
                            tracing::info!(
                                app = %hex::encode(&app[..4]),
                                phase = ph,
                                nodes_seeded = nodes,
                                elapsed_s = el,
                                nodes_per_s = nodes / el.max(1),
                                "size-index backfill: progress"
                            );
                        }
                    };
                    total = total.saturating_add(
                        forest
                            .seed_size_index(&app, PHASES[ph], ver, &on_flush)
                            .unwrap_or(0),
                    );
                }
                tracing::info!(
                    app = %hex::encode(&app[..4]),
                    size = total as u64,
                    ms = start.elapsed().as_millis() as u64,
                    "size-index backfill: seeded app phase trees (one-time)"
                );
            }
        }
        let txn = self.store.new_transaction(false)?;
        txn.set(SIZE_INDEX_SEEDED_KEY, b"1")?;
        txn.commit()?;
        Ok(true)
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

    /// The live committed size of the unified app tree under `bits`, from the
    /// forest's Merkle-sum index (the same `(VA − VR) + (HA − HR)` as
    /// [`Self::forest_app_buckets`]), or `None` off the unified tree. For a
    /// subtree this node received by sync or inherited at a split or merge,
    /// the CRDT's size metadata was never written; the forest still knows.
    pub fn unified_live_size_at_bits(&self, app: &[u8; 32], bits: &[bool]) -> Option<u64> {
        if !self.unified_tree() {
            return None;
        }
        let forest = self.forest.read().ok()?;
        let fallback_ver = self.forest_version.load(Ordering::SeqCst);
        let ver = |ph: usize| self.resolve_phase_version_with(&forest, app, ph).unwrap_or(fallback_ver);
        let size = |ph: usize| forest.app_subtree_size(app, PHASES[ph], ver(ph), bits).unwrap_or(0) as i128;
        let live = ((size(0) - size(1)) + (size(2) - size(3))).max(0);
        Some(u64::try_from(live).unwrap_or(u64::MAX))
    }

    /// Forest-aggregate equivalent of [`scan_app_buckets`]: build `app`'s
    /// per-sub-shard `(raw_count, live_size)` buckets from the unified app tree's
    /// Merkle-sum aggregates — [`Forest::app_subtree_leaf_count`] (count) +
    /// [`Forest::app_subtree_size`] (size) at each current shard's bit-path —
    /// instead of a full O(all-leaves) leaf iteration. **O(shards × depth)**: the
    /// epoch-boundary [`rebucket_app`] no longer rescans the whole tree (the ~2h
    /// QUIL stall that stalled FrameHeader flow → froze rewards). `size` is the
    /// LIVE size `(VertexAdds − VertexRemoves) + (HyperedgeAdds − HyperedgeRemoves)`
    /// (the removes tombstones carry the removed sizes — see
    /// [`Self::stage_sized_tombstone`]); `count` is the VertexAdds subtree leaf
    /// count (incl. removed leaves, matching the scan's raw count). Produces
    /// byte-identical buckets to `scan_app_buckets` — unit-validated for adds,
    /// removes, and hyperedges. Falls back to the scan only when the app isn't on
    /// the unified tree.
    fn forest_app_buckets(
        &self,
        app: &[u8; 32],
        buckets: &mut HashMap<Vec<u8>, (u64, i128)>,
    ) -> Result<()> {
        if *app == [0xFFu8; 32] {
            return Ok(()); // prover shard excluded from world size
        }
        if !self.unified_tree() {
            return self.scan_app_buckets(app, buckets);
        }
        let prefixes = self.app_prefixes(app);
        let single = prefixes.len() == 1 && prefixes[0].is_empty();
        let bit_paths = if single { Vec::new() } else { self.shard_bit_paths(app) };
        let forest = self.forest.read().unwrap();
        // Same version resolution as `unified_subtree_leaf_count` /
        // `propose_split_children`: the per-phase head, else the global forest
        // version (NOT 0, which reads an empty tree). Each phase tree resolves
        // independently.
        let fallback_ver = self.forest_version.load(Ordering::SeqCst);
        let ver = |ph: usize| self.resolve_phase_version_checked(&forest, app, ph).map(|v| v.unwrap_or(fallback_ver));
        let (ver_va, ver_vr, ver_ha, ver_hr) = (ver(0)?, ver(1)?, ver(2)?, ver(3)?);
        if !single && bit_paths.len() != prefixes.len() {
            return Err(QuilError::ExecutionUnavailable("size accounting has misaligned shard paths".into()));
        }
        let read_error = |e| QuilError::ExecutionUnavailable(format!("size accounting forest read: {e}"));
        let empty_bits: Vec<bool> = Vec::new();
        for (i, prefix) in prefixes.iter().enumerate() {
            let bits: &[bool] = if single { &empty_bits } else { &bit_paths[i] };
            // COUNT: raw VertexAdds leaf count — INCLUDING removed leaves (whose add
            // leaf, or an empty placeholder, is retained), matching
            // `scan_app_buckets` (`e.0 += 1` for every add, no `v_removed` check).
            let count = forest
                .app_subtree_leaf_count(app, PHASES[0], ver_va, bits)
                .map_err(read_error)?;
            // SIZE: LIVE size = adds − removes across both vertex and hyperedge
            // phases. The forest add-trees RETAIN removed leaves (removes are a
            // SEPARATE phase tree, not deletions), and each removes-phase tombstone
            // now carries the removed leaf's original size (`stage_sized_tombstone`
            // / `sized_tombstone_leaf_value`), so the removes subtree-size sums the
            // removed sizes exactly. Thus `scan_app_buckets`'s present-only
            // `blob.len()` sum == (VertexAdds − VertexRemoves) + (HyperedgeAdds −
            // HyperedgeRemoves) — a pure O(depth) subtree subtraction, no leaf scan.
            // Clamp at 0 (a shard can't have negative live size).
            let size_at = |phase, version| -> Result<i128> {
                i128::try_from(forest.app_subtree_size(app, phase, version, bits).map_err(read_error)?)
                    .map_err(|_| QuilError::ExecutionUnavailable("size accounting overflow".into()))
            };
            let va = size_at(PHASES[0], ver_va)?;
            let vr = size_at(PHASES[1], ver_vr)?;
            let ha = size_at(PHASES[2], ver_ha)?;
            let hr = size_at(PHASES[3], ver_hr)?;
            let size = va.checked_sub(vr).and_then(|v| v.checked_add(ha)).and_then(|v| v.checked_sub(hr))
                .ok_or_else(|| QuilError::ExecutionUnavailable("size accounting overflow".into()))?.max(0);
            // Match `scan_app_buckets`, which only creates a bucket for a shard a
            // leaf actually routes to — never an empty `(0, 0)` placeholder.
            if count == 0 && size == 0 {
                continue;
            }
            let e = buckets.entry(Forest::addr_path_shard_id(app, prefix)).or_insert((0, 0));
            e.0 += count;
            e.1 += size;
        }
        Ok(())
    }

    /// Re-partition `app`'s per-sub-shard size buckets against the CURRENT prefix
    /// set. Called when a shard split/merge changes an app's registered shards:
    /// the incremental [`bump_meta`] only routes NEW writes, so data written before
    /// the split stays stranded in the now-removed parent bucket (a deep-split leaf
    /// reads size 0 → provers churn, proposing to "leave" the data-bearing child).
    /// This drops the app's existing buckets and rebuilds them from committed state
    /// by the new routing — zero-copy (data stays in place, only the
    /// shard boundaries move), so the app's TOTAL size is preserved and only the
    /// per-sub-shard attribution changes. Deterministic across nodes: every node
    /// runs it at the same frame the split's new prefixes become visible (the
    /// per-frame `refresh_crdt_shard_prefixes` change-detection), over identical
    /// committed state. Idempotent for an unchanged prefix set.
    pub fn rebucket_app(&self, app: &[u8; 32]) -> Result<()> {
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "rebucket commit lock poisoned".into()))?;
        self.rebucket_app_locked(app)
    }

    fn rebucket_app_locked(&self, app: &[u8; 32]) -> Result<()> {
        if self.pending.read().unwrap().iter().any(|((shard, _), values)| shard.l2 == *app && !values.is_empty())
            || self.pending_blobs.read().unwrap().iter().any(|((shard, _), values)| shard.l2 == *app && !values.is_empty())
        {
            return Err(QuilError::ExecutionUnavailable("cannot rebuild size buckets with staged application mutations".into()));
        }
        // Rebuild the app's buckets from committed state under a lock held across
        // the swap so a concurrent commit can't interleave a stale partition.
        let mut fresh: HashMap<Vec<u8>, (u64, i128)> = HashMap::new();
        self.forest_app_buckets(app, &mut fresh)?;
        // Validation shadow (`QUIL_REBUCKET_SHADOW=1`): recompute the buckets via
        // the legacy full-leaf `scan_app_buckets` and log any divergence. The
        // forest Merkle-sum MUST be byte-identical to the scan — the per-shard
        // `(count, size)` is the consensus-relevant reward/join basis, so a
        // mismatch would be a soft-fork. OFF in production: the scan is exactly
        // the O(all-leaves) cost the forest aggregate replaces (the ~2h QUIL
        // epoch-boundary stall). Used to validate value-preservation on localnet
        // across real splits + vertex removes + hyperedges before relying on it.
        if std::env::var("QUIL_REBUCKET_SHADOW").as_deref() == Ok("1") {
            let mut scan: HashMap<Vec<u8>, (u64, i128)> = HashMap::new();
            match self.scan_app_buckets(app, &mut scan) {
                Err(e) => tracing::warn!(error = %e, "rebucket shadow: scan_app_buckets failed"),
                Ok(()) if scan == fresh => tracing::info!(
                    app = %hex::encode(&app[..4]),
                    shards = fresh.len(),
                    "rebucket shadow: forest == scan OK"
                ),
                Ok(()) => {
                    let mut keys: std::collections::BTreeSet<&Vec<u8>> =
                        scan.keys().collect();
                    keys.extend(fresh.keys());
                    for k in keys {
                        let sv = scan.get(k).copied().unwrap_or((0, 0));
                        let fv = fresh.get(k).copied().unwrap_or((0, 0));
                        if sv != fv {
                            tracing::error!(
                                app = %hex::encode(&app[..4]),
                                shard = %hex::encode(k),
                                scan_count = sv.0, scan_size = sv.1,
                                forest_count = fv.0, forest_size = fv.1,
                                "REBUCKET SHADOW MISMATCH — forest aggregate != leaf scan"
                            );
                        }
                    }
                }
            }
        }
        let mut m = self.sub_meta.write().unwrap();
        // Drop every bucket belonging to this app (keys are `app(32) ‖ prefix`),
        // clearing the orphaned parent/ancestor buckets, then install the fresh set.
        m.retain(|k, _| !k.starts_with(&app[..]));
        for (k, v) in fresh {
            m.insert(k, v);
        }
        self.layout_rebuilds.write().unwrap().remove(app);
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
        // Decode the filter suffix into a prefix `sub_meta_for` can canonicalize.
        // A SENTINEL filter (`app ‖ bit_len ‖ packed`, ≥2 suffix bytes) must be
        // decoded to its bit-path — NOT read byte-for-byte, which yields garbage
        // like `[0,6,0]` that matches no shard. A legacy 1-byte byte-suffix and
        // the bare-app root are passed through (canonicalized downstream).
        let suffix = &filter[32..];
        let prefix: Vec<u32> = if suffix.is_empty() {
            Vec::new()
        } else if suffix.len() == 1 {
            vec![suffix[0] as u32]
        } else if let Some((_, bits)) = quil_forest::decode_shard_filter_or_root(filter, 32) {
            quil_forest::bit_path_to_prefix(&bits)
        } else {
            suffix.iter().map(|&b| b as u32).collect()
        };
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
                .unwrap_or_else(|| quil_forest::shard_bit_path_from_prefix(prefix)
                    .unwrap_or_else(|| quil_forest::prefix_to_bits(prefix, 6)));
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
        // The registered prefix for this filter's shard, matched by CANONICAL
        // bit-path (NOT a byte-exact wire compare, which misses when the filter
        // and the stored prefix are in different encodings — a byte-suffix
        // filter vs a sentinel prefix post-reset — silently falling back to the
        // whole-app root). Decode the filter suffix to its bit-path and find the
        // registered shard with the same canonical bits. Empty ⇒ whole app.
        let suffix = &filter[32..];
        let lookup_prefix: Vec<u32> = if suffix.is_empty() {
            Vec::new()
        } else if suffix.len() == 1 {
            vec![suffix[0] as u32]
        } else if let Some((_, bits)) = quil_forest::decode_shard_filter_or_root(filter, 32) {
            quil_forest::bit_path_to_prefix(&bits)
        } else {
            suffix.iter().map(|&b| b as u32).collect()
        };
        let prefixes = self.app_prefixes(&app);
        let bit_paths = self.shard_bit_paths(&app);
        let lookup_bits = prefixes
            .iter()
            .position(|p| p == &lookup_prefix)
            .and_then(|i| bit_paths.get(i).cloned())
            .unwrap_or_else(|| {
                if lookup_prefix.is_empty() {
                    Vec::new()
                } else {
                    quil_forest::shard_bit_path_from_prefix(&lookup_prefix)
                        .unwrap_or_else(|| quil_forest::prefix_to_bits(&lookup_prefix, 6))
                }
            });
        let prefix = prefixes
            .iter()
            .enumerate()
            .find(|(i, _)| bit_paths.get(*i).map(|b| *b == lookup_bits).unwrap_or(false))
            .map(|(_, p)| p.clone())
            .unwrap_or(lookup_prefix);
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
        // co-path aggregation (a shard-scoped verifier folds the co-path itself).
        // Same direct path as a genuinely single-shard app.
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

    /// Read one physical tree's current root without treating unreadable state
    /// as an empty tree. Sync uses this when the authenticated source is empty.
    /// The phases of `shard_id` whose head marker an old reset left on an
    /// emptied tree (see [`Forest::orphaned_phase_head`]): `(phase, version)`.
    pub fn orphaned_phase_heads(&self, shard_id: &[u8]) -> Result<Vec<(usize, u64)>> {
        let forest = self.forest.read()
            .map_err(|_| QuilError::ExecutionUnavailable("forest lock poisoned".into()))?;
        let mut orphaned = Vec::new();
        for (phase_idx, phase) in PHASES.iter().enumerate() {
            if let Some(version) = forest.orphaned_phase_head(shard_id, *phase)
                .map_err(|e| QuilError::ExecutionUnavailable(format!("read phase head: {e}")))? {
                orphaned.push((phase_idx, version));
            }
        }
        Ok(orphaned)
    }

    /// Drop the orphaned head markers of `shard_id`, so each such phase reads
    /// as the empty tree it is and its next commit rebuilds from version 0.
    /// Holds the forest write guard, so no commit or sync interleaves.
    pub fn drop_orphaned_phase_heads(&self, shard_id: &[u8]) -> Result<Vec<(usize, u64)>> {
        let poisoned = |name| QuilError::ExecutionUnavailable(format!("{name} lock poisoned"));
        let forest = self.forest.write().map_err(|_| poisoned("forest"))?;
        let mut dropped = Vec::new();
        for (phase_idx, phase) in PHASES.iter().enumerate() {
            if let Some(version) = forest.drop_orphaned_phase_head(shard_id, *phase)
                .map_err(|e| QuilError::ExecutionUnavailable(format!("drop phase head: {e}")))? {
                self.phase_versions.write().map_err(|_| poisoned("phase versions"))?
                    .remove(&(shard_id.to_vec(), phase_idx));
                dropped.push((phase_idx, version));
            }
        }
        Ok(dropped)
    }

    pub fn current_forest_phase_root(&self, shard_id: &[u8], phase_idx: usize) -> Result<[u8; 32]> {
        if shard_id.len() < 32 || phase_idx >= PHASES.len() {
            return Err(QuilError::InvalidArgument("invalid forest phase scope".into()));
        }
        self.read_shard_phase_root_checked(&self.forest.read().unwrap(), shard_id, phase_idx)
    }

    /// Whether this scope has been checked or built by atomic blob/tree sync.
    /// A legacy tree may have reached its root before its blob downloads failed;
    /// it needs one complete leaf/data check before root equality is sufficient.
    pub fn sync_data_ready(&self, shard_id: &[u8], phase_idx: usize, bit_path: &[bool]) -> Result<bool> {
        let key = sync_data_key(shard_id, phase_idx, bit_path)?;
        let txn = self.store.new_transaction(false)?;
        let ready = txn.get(&key)?.as_deref() == Some(&[1]);
        txn.abort()?;
        Ok(ready)
    }

    /// Authenticate and preview a sync before downloading its readable blobs.
    /// Remote reads and reconstruction do not hold the materializer's write
    /// lock. Each later chunk rechecks the local version under that lock.
    pub fn prepare_phase_sync<S: quil_forest::BatchTreeReader>(
        &self,
        source: &S,
        source_version: u64,
        shard_id: &[u8],
        phase_idx: usize,
        bit_path: &[bool],
        anchor: Option<quil_forest::SubtreeSyncAnchor>,
    ) -> Result<ForestSyncPlan> {
        if phase_idx >= 4 || shard_id.len() < 32 {
            return Err(QuilError::InvalidArgument("invalid sync shard or phase".into()));
        }
        let forest = self.forest.read().unwrap();
        let base_version = self.resolve_phase_version_with(&forest, shard_id, phase_idx);
        let local_root = forest.app_subtree_root(shard_id, PHASES[phase_idx], base_version.unwrap_or(0), bit_path)
            .map_err(|e| QuilError::Internal(format!("local sync root: {e}")))?;
        let repair_existing = local_root != [0; 32] && local_root != *b"SPARSE_MERKLE_PLACEHOLDER_HASH__"
            && !self.sync_data_ready(shard_id, phase_idx, bit_path)?;
        let target = if repair_existing {
            // A one-time audit also repairs previously torn installations. Its
            // existing correct blobs can be reused without network downloads.
            Forest::in_memory().shard_phase_reader(shard_id, PHASES[phase_idx])
        } else {
            forest.shard_phase_reader(shard_id, PHASES[phase_idx])
        };
        let (leaves, target_root) = quil_forest::diff_leaves_under_prefix(
            source, source_version, &target, base_version.unwrap_or(0), bit_path, anchor,
        ).map_err(|e| QuilError::Internal(format!("sync diff: {e}")))?;
        let mut updates: std::collections::BTreeMap<_, _> = leaves.into_iter()
            .map(|(key, value)| (key.0, Some(value))).collect();
        // Regular masters used to replay GLOBAL operations against local shard
        // metadata that could miss an archive's split/merge freeze. A rejected
        // join then created local-only prover records and a membership edge,
        // and a put-only diff could never recover. Under a pinned GLOBAL root,
        // reconcile those extra adds too. Scope this to GLOBAL add phases: application data and remove
        // phases retain their existing monotonic-sync contract.
        if phase_idx % 2 == 0 && shard_id == [0xff; 32] && bit_path.is_empty() && anchor.is_some() {
            let local = forest.shard_phase_reader(shard_id, PHASES[phase_idx]);
            let (local_changes, _) = quil_forest::diff_leaves_under_prefix(
                &local, base_version.unwrap_or(0), source, source_version, bit_path, None,
            ).map_err(|e| QuilError::Internal(format!("reverse GLOBAL sync diff: {e}")))?;
            for (key, _) in local_changes {
                // A changed common key occurs in both diffs; keep its source
                // value. A key occurring only in the reverse diff is absent
                // from the source. Full root reconstruction verifies the set.
                updates.entry(key.0).or_insert(None);
            }
        }
        let leaves: Vec<_> = updates.into_iter().collect();
        if leaves.is_empty() {
            let local = forest.app_subtree_root(shard_id, PHASES[phase_idx], base_version.unwrap_or(0), bit_path)
                .map_err(|e| QuilError::Internal(format!("sync root: {e}")))?;
            if local != target_root
                && !(base_version.is_none() && bit_path.is_empty()
                    && target_root == *b"SPARSE_MERKLE_PLACEHOLDER_HASH__")
            {
                return Err(QuilError::Internal("sync would retain leaves absent from its source".into()));
            }
        } else {
            let version = base_version.map_or(Some(0), |v| v.checked_add(1))
                .ok_or_else(|| QuilError::Internal("sync version overflow".into()))?;
            // Drop the prepared batch without publishing it. The complete
            // result, including any GLOBAL removals, must match before writes.
            forest.stage_synced_phase(shard_id, PHASES[phase_idx], version,
                leaves.iter().map(|(key, value)| (quil_forest::KeyHash(*key), value.clone())),
                bit_path, Some(target_root))
                .map_err(|e| QuilError::Internal(format!("sync phase {phase_idx} reconstruction: {e}")))?;
        }
        Ok(ForestSyncPlan {
            store: self.store.clone(), shard_id: shard_id.to_vec(), phase_idx,
            bit_path: bit_path.to_vec(), base_version, target_root, repair_existing,
            leaves, next: 0,
            removals: phase_idx % 2 == 0 && shard_id == [0xff; 32] && bit_path.is_empty() && anchor.is_some(),
        })
    }

    /// Bring a sync up to date after the local tree moved under it, without
    /// reading the source again. A regular node commits GLOBAL frame messages
    /// itself every few minutes, and a cold prover-tree download takes longer
    /// than that, so the download used to be thrown away each time.
    ///
    /// The source tree is fixed, and every key outside the plan held the
    /// source's value at the plan's base version (only planned keys are ever
    /// written by the sync). So a key the local commits changed is put back to
    /// its base value unless the plan targets it, and every planned key not
    /// already at its target (including one a local commit overwrote) is
    /// installed again. A key the local commits created that the source lacks
    /// can be removed only where the plan removes keys; elsewhere the sync
    /// fails as before. The final root check still decides. Returns the
    /// leaves left to install.
    pub fn rebase_phase_sync(&self, plan: &mut ForestSyncPlan) -> Result<usize> {
        use quil_forest::TreeReader as _;
        if !Arc::ptr_eq(&self.store, &plan.store) {
            return Err(QuilError::InvalidArgument("sync plan belongs to another store".into()));
        }
        let forest = self.forest.read().unwrap();
        let current = self.resolve_phase_version_with(&forest, &plan.shard_id, plan.phase_idx);
        let (Some(base), Some(now)) = (plan.base_version, current) else {
            return Err(QuilError::ExecutionUnavailable(format!(
                "{SYNC_PHASE_ADVANCED} from an empty tree; retry"
            )));
        };
        if now == base {
            return Ok(plan.remaining().len());
        }
        let reader = forest.shard_phase_reader(&plan.shard_id, PHASES[plan.phase_idx]);
        let (changed, _) = quil_forest::diff_leaves_under_prefix(&reader, now, &reader, base, &plan.bit_path, None)
            .map_err(|e| QuilError::Internal(format!("local sync rebase diff: {e}")))?;
        let mut target: std::collections::BTreeMap<[u8; 32], Option<Vec<u8>>> =
            std::mem::take(&mut plan.leaves).into_iter().collect();
        for (key, _) in changed {
            if target.contains_key(&key.0) {
                continue;
            }
            let at_base = reader.get_value_option(base, key)
                .map_err(|e| QuilError::Internal(format!("local sync rebase read: {e}")))?;
            if at_base.is_none() && !plan.removals {
                return Err(QuilError::ExecutionUnavailable(format!(
                    "{SYNC_PHASE_ADVANCED} with a key the source lacks; retry"
                )));
            }
            target.insert(key.0, at_base);
        }
        let mut remaining = Vec::new();
        for (key, want) in target {
            let have = reader.get_value_option(now, quil_forest::KeyHash(key))
                .map_err(|e| QuilError::Internal(format!("local sync rebase read: {e}")))?;
            if have != want {
                remaining.push((key, want));
            }
        }
        plan.leaves = remaining;
        plan.next = 0;
        plan.base_version = Some(now);
        Ok(plan.leaves.len())
    }

    /// Install the next leaves and their verified blobs in one transaction.
    /// A fetch failure before this call changes nothing. A failed transaction
    /// leaves both the durable head and the plan at the preceding chunk, so a
    /// retry or restart includes all data that still needs installation.
    pub fn apply_sync_chunk(&self, plan: &mut ForestSyncPlan, blobs: &[Vec<u8>]) -> Result<()> {
        let bytes = blobs.iter().try_fold(0usize, |n, blob| n.checked_add(blob.len()));
        if !Arc::ptr_eq(&self.store, &plan.store) || blobs.is_empty()
            || blobs.len() > plan.remaining().len() || blobs.len() > MAX_SYNC_CHUNK_LEAVES
            || bytes.is_none_or(|bytes| bytes > MAX_SYNC_CHUNK_BYTES)
        {
            return Err(QuilError::InvalidArgument("invalid or oversized sync chunk".into()));
        }
        let leaves = &plan.remaining()[..blobs.len()];
        for ((_, leaf), blob) in leaves.iter().zip(blobs) {
            let matches = match leaf {
                Some(leaf) => sync_blob_matches(plan.phase_idx, leaf, blob)?,
                None => blob.is_empty(),
            };
            if !matches {
                return Err(QuilError::InvalidArgument("synced blob does not match its authenticated leaf".into()));
            }
        }
        let _forest_guard = self.forest_write_lock.lock().unwrap();
        let _guard = self.commit_lock.lock().unwrap();
        let forest = self.forest.read().unwrap();
        let current = self.resolve_phase_version_with(&forest, &plan.shard_id, plan.phase_idx);
        if current != plan.base_version {
            return Err(QuilError::ExecutionUnavailable(format!("{SYNC_PHASE_ADVANCED} during download; retry")));
        }
        let app: [u8; 32] = plan.shard_id[..32].try_into().unwrap();
        let shard = ShardKey { l1: crate::addressing::get_bloom_filter_indices(&app, 256, 3), l2: app };
        if self.pending.read().unwrap().get(&(shard.clone(), plan.phase_idx)).is_some_and(|m| !m.is_empty()) {
            return Err(QuilError::ExecutionUnavailable(format!("{SYNC_STAGED_WRITES}; retry")));
        }
        let version = current.map_or(Some(0), |v| v.checked_add(1))
            .ok_or_else(|| QuilError::Internal("sync version overflow".into()))?;
        let final_chunk = blobs.len() == plan.remaining().len();
        let staged = forest.stage_synced_phase(
            &plan.shard_id, PHASES[plan.phase_idx], version,
            leaves.iter().map(|(key, value)| (quil_forest::KeyHash(*key), value.clone())),
            &plan.bit_path, final_chunk.then_some(plan.target_root),
        ).map_err(|e| QuilError::Internal(format!("stage sync chunk: {e}")))?;
        let txn = self.store.new_transaction(false)?;
        for (key, value) in staged.puts() { txn.set(key, value)?; }
        if let Some((key, value)) = forest.head_version_put(&plan.shard_id, PHASES[plan.phase_idx], version) {
            txn.set(&key, &value)?;
        }
        let (set, phase) = PHASE_STR[plan.phase_idx];
        for ((key, _), blob) in leaves.iter().zip(blobs) {
            let mut id = app.to_vec();
            id.extend_from_slice(key);
            // An empty add blob hides an absent GLOBAL record from live reads
            // and registry decoding without erasing its historical versions.
            self.store.save_vertex_underlying_versioned(txn.as_ref(), set, phase, &shard, &id, blob, version)?;
        }
        // A scope that began empty is complete after every chunk. Repair of
        // legacy state becomes complete only after checking every source leaf.
        if !plan.repair_existing || final_chunk {
            txn.set(&sync_data_key(&plan.shard_id, plan.phase_idx, &plan.bit_path)?, &[1])?;
        }
        txn.commit()?;
        staged.publish_memory().map_err(|e| QuilError::Internal(format!("publish synced memory tree: {e}")))?;
        self.phase_versions.write().unwrap().insert((plan.shard_id.clone(), plan.phase_idx), version);
        plan.base_version = Some(version);
        plan.next += blobs.len();
        Ok(())
    }

    /// Completion is a current local root check, including a no-op diff.
    pub fn finish_phase_sync(&self, plan: &ForestSyncPlan) -> Result<[u8; 32]> {
        if !Arc::ptr_eq(&self.store, &plan.store) || !plan.remaining().is_empty() {
            return Err(QuilError::InvalidArgument("unfinished sync plan".into()));
        }
        let _forest_guard = self.forest_write_lock.lock().unwrap();
        let _guard = self.commit_lock.lock().unwrap();
        let forest = self.forest.read().unwrap();
        let current = self.resolve_phase_version_with(&forest, &plan.shard_id, plan.phase_idx);
        if current != plan.base_version {
            return Err(QuilError::ExecutionUnavailable(format!("{SYNC_PHASE_ADVANCED} before completion; retry")));
        }
        let root = forest.app_subtree_root(&plan.shard_id, PHASES[plan.phase_idx], current.unwrap_or(0), &plan.bit_path)
            .map_err(|e| QuilError::Internal(format!("synced root: {e}")))?;
        if root != plan.target_root
            && !(current.is_none() && plan.bit_path.is_empty()
                && plan.target_root == *b"SPARSE_MERKLE_PLACEHOLDER_HASH__")
        {
            return Err(QuilError::ExecutionUnavailable("sync root changed before completion; retry".into()));
        }
        Ok(plan.target_root)
    }

    /// Roll one application shard's committed state back to the retained
    /// state whose per-phase subtree roots are `roots`, as a fresh commit at
    /// each changed phase's next version. Versions stay monotonic, so no stale
    /// tree record or newer blob version can shadow the restored state: a leaf
    /// changed since is restored from its blob at the old version, an add made
    /// since is hidden by an empty blob, and a removal made since has its blob
    /// versions above the old version deleted (any removes-phase blob hides
    /// its vertex). Every phase is checked against its root before anything is
    /// written. A member whose session GLOBAL fenced below its head rewinds to
    /// the fence this way.
    pub fn rewind_app_shard(&self, filter: &[u8], roots: &[[u8; 32]; 4]) -> Result<()> {
        if !self.unified_tree() || filter.len() < 32 {
            return Err(QuilError::InvalidArgument("a rewind needs an application shard of a unified tree".into()));
        }
        let bits = self.canonical_bits_for_filter(filter)
            .ok_or_else(|| QuilError::InvalidArgument("rewind filter is not a shard of its application".into()))?;
        let app: [u8; 32] = filter[..32].try_into().unwrap();
        let shard = ShardKey { l1: crate::addressing::get_bloom_filter_indices(&app, 256, 3), l2: app };
        // An empty target (a phase first written after it) has no version.
        let empty = |root: &[u8; 32]| *root == [0; 32] || *root == *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";
        let targets = (0..4).map(|phase_idx| {
            match self.resolve_root(filter, phase_idx, roots[phase_idx]) {
                Some((version, _)) => Ok(Some(version)),
                None if empty(&roots[phase_idx]) => Ok(None),
                None => Err(QuilError::ExecutionUnavailable(format!("rewind target of phase {phase_idx} is not retained here"))),
            }
        }).collect::<Result<Vec<Option<u64>>>>()?;
        let _forest_guard = self.forest_write_lock.lock().unwrap();
        let _guard = self.commit_lock.lock().unwrap();
        if self.pending.read().unwrap().iter().any(|((key, _), values)| key.l2 == app && !values.is_empty())
            || self.pending_blobs.read().unwrap().iter().any(|((key, _), values)| key.l2 == app && !values.is_empty())
        {
            return Err(QuilError::ExecutionUnavailable("cannot rewind with staged application mutations".into()));
        }
        let forest = self.forest.read().unwrap();
        let txn = self.store.new_transaction(false)?;
        let mut staged = Vec::new();
        let mut wiped = Vec::new();
        for (phase_idx, target) in targets.into_iter().enumerate() {
            let Some(head) = self.resolve_phase_version_with(&forest, &app, phase_idx) else { continue };
            let current = forest.app_subtree_root(&app, PHASES[phase_idx], head, &bits)
                .map_err(|e| QuilError::Internal(format!("rewind root: {e}")))?;
            if current == roots[phase_idx] {
                continue;
            }
            let reader = forest.shard_phase_reader(&app, PHASES[phase_idx]);
            let nothing = Forest::in_memory().shard_phase_reader(&app, PHASES[phase_idx]);
            let (set, kind) = PHASE_STR[phase_idx];
            if target.is_none() && roots[phase_idx] == [0; 32] {
                // The whole phase tree postdates the target, which reads it as
                // never committed: remove it rather than leave an empty tree,
                // whose root reads differently.
                let (all, _) = quil_forest::diff_leaves_under_prefix(&reader, head, &nothing, 0, &[], None)
                    .map_err(|e| QuilError::Internal(format!("rewind phase listing: {e}")))?;
                for (key, _) in all {
                    let mut id = app.to_vec();
                    id.extend_from_slice(&key.0);
                    self.store.delete_vertex_underlying_versions_from(txn.as_ref(), set, kind, &shard, &id, 0)?;
                }
                wiped.push(phase_idx);
                continue;
            }
            let (restore, since) = match target {
                Some(target) => {
                    let (restore, source_root) = quil_forest::diff_leaves_under_prefix(&reader, target, &reader, head, &bits, None)
                        .map_err(|e| QuilError::Internal(format!("rewind diff: {e}")))?;
                    if source_root != roots[phase_idx] {
                        return Err(QuilError::Internal("rewind target version differs from its root".into()));
                    }
                    let (since, _) = quil_forest::diff_leaves_under_prefix(&reader, head, &reader, target, &bits, None)
                        .map_err(|e| QuilError::Internal(format!("rewind reverse diff: {e}")))?;
                    (restore, since)
                }
                None => {
                    let (since, _) = quil_forest::diff_leaves_under_prefix(&reader, head, &nothing, 0, &bits, None)
                        .map_err(|e| QuilError::Internal(format!("rewind reverse diff: {e}")))?;
                    (Vec::new(), since)
                }
            };
            let mut updates: BTreeMap<[u8; 32], Option<Vec<u8>>> =
                restore.into_iter().map(|(key, value)| (key.0, Some(value))).collect();
            for (key, _) in since {
                updates.entry(key.0).or_insert(None);
            }
            let version = head.checked_add(1).ok_or_else(|| QuilError::Internal("rewind version overflow".into()))?;
            let phase = forest.stage_synced_phase(&app, PHASES[phase_idx], version,
                updates.iter().map(|(key, value)| (quil_forest::KeyHash(*key), value.clone())),
                &bits, target.map(|_| roots[phase_idx]))
                .map_err(|e| QuilError::Internal(format!("rewind phase {phase_idx}: {e}")))?;
            if target.is_none() && !empty(&phase.root()) {
                return Err(QuilError::Internal(format!("rewind phase {phase_idx} did not empty the shard")));
            }
            for (key, value) in phase.puts() { txn.set(key, value)?; }
            if let Some((key, value)) = forest.head_version_put(&app, PHASES[phase_idx], version) {
                txn.set(&key, &value)?;
            }
            for (key, value) in &updates {
                let mut id = app.to_vec();
                id.extend_from_slice(key);
                match value {
                    Some(_) => {
                        let target = target.expect("restored leaves come from a retained target");
                        let blob = self.store.load_vertex_underlying_at(set, kind, &shard, &id, target)?
                            .ok_or_else(|| QuilError::ExecutionUnavailable("rewind blob is not retained here".into()))?;
                        self.store.save_vertex_underlying_versioned(txn.as_ref(), set, kind, &shard, &id, &blob, version)?;
                    }
                    None if phase_idx % 2 == 0 => {
                        self.store.save_vertex_underlying_versioned(txn.as_ref(), set, kind, &shard, &id, &[], version)?;
                    }
                    None => self.store.delete_vertex_underlying_versions_from(
                        txn.as_ref(), set, kind, &shard, &id, target.map_or(0, |target| target + 1))?,
                }
            }
            staged.push((phase_idx, version, phase));
        }
        if staged.is_empty() && wiped.is_empty() {
            txn.abort()?;
            return Ok(());
        }
        txn.commit()?;
        for (phase_idx, version, phase) in staged {
            phase.publish_memory().map_err(|e| QuilError::Internal(format!("publish rewound memory tree: {e}")))?;
            self.phase_versions.write().unwrap().insert((app.to_vec(), phase_idx), version);
        }
        for phase_idx in wiped {
            forest.reset_shard_phase_tree(&app, PHASES[phase_idx])
                .map_err(|e| QuilError::Internal(format!("rewind phase reset: {e}")))?;
            let (set, kind) = PHASE_STR[phase_idx];
            self.store.clear_phase_root_versions(set, kind, &app)?;
            self.phase_versions.write().unwrap().remove(&(app.to_vec(), phase_idx));
        }
        drop(forest);
        self.rebucket_app_locked(&app)
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
    pub fn sync_shard_phase_from<S: quil_forest::BatchTreeReader>(
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
    /// root — the shard commitment. `anchor` names either the whole app root or
    /// the covered subtree root; the source is authenticated against it
    /// (so a peer can't serve a fake subtree), and the applied local subtree root
    /// is verified to equal the authenticated source subtree root. A shard prover
    /// thus stores only its subtree yet holds a commitment that composes to the
    /// global app root — never pulling the whole app. Empty `bit_path` ==
    /// [`sync_shard_phase_from`] over the whole app tree.
    pub fn sync_shard_subtree_phase_from<S: quil_forest::BatchTreeReader>(
        &self,
        source: &S,
        source_version: u64,
        app: &[u8],
        phase_idx: usize,
        bit_path: &[bool],
        anchor: Option<quil_forest::SubtreeSyncAnchor>,
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
                anchor,
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
            if anchor.is_some() && local != src_subtree_root {
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
        let (local, puts) = forest
            .apply_synced_subtree_phase(app, PHASES[phase_idx], ver, leaves, bit_path, src_subtree_root)
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

        // The staged tree was checked against the source BEFORE the write.
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
            .unwrap_or_else(|| quil_forest::shard_bit_path_from_prefix(prefix)
                .unwrap_or_else(|| quil_forest::prefix_to_bits(prefix, 6)))
    }

    /// Decode the wire filter before interpreting its prefix. A deep filter's
    /// length and packed path bytes are not legacy six-bit shard indices.
    pub fn canonical_bits_for_filter(&self, filter: &[u8]) -> Option<Vec<bool>> {
        let (app, bits) = quil_forest::decode_shard_filter_or_root(filter, 32)?;
        if filter.len() == 33 {
            let app: [u8; 32] = app.try_into().ok()?;
            Some(self.canonical_bits_for_prefix(&app, &[filter[32] as u32]))
        } else {
            Some(bits)
        }
    }

    /// Leaf count under a `bit_path` in the unified app tree — the
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

    /// DEEP-BIFURCATION split PROPOSAL: compute a shard's MEANINGFUL
    /// split children as bit-path shard filters. Runs
    /// [`Forest::first_split_bifurcation`] on the app tree from the shard's
    /// `shard_bits` — descending past any uniform run to the shallowest bit where
    /// the data divides — and encodes each child bit-path via
    /// [`quil_forest::encode_shard_bit_path`]. `None` when the shard is
    /// unsplittable (<2 leaves, or no branch within `max_extra_bits`) — the
    /// caller then proposes nothing (the empty-split guard: not
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
        let resolved = self.resolve_phase_version_with(&forest, app, phase_idx);
        // Fall back to the global forest version — NOT 0 — exactly like
        // `read_shard_phase_root`. The unified app tree's version is often not
        // tracked under the app-address key (no phase_versions entry / head
        // marker), so `resolve` returns None; reading at version 0 sees an EMPTY
        // tree (leaf_count 0 → empty-split guard → NO split ever proposed), while
        // the forest version reads the real committed state.
        let ver = resolved.unwrap_or_else(|| self.forest_version.load(Ordering::SeqCst));
        let parent_leaves = forest
            .app_subtree_leaf_count(app, PHASES[phase_idx], ver, shard_bits)
            .unwrap_or(0);
        // DIAGNOSTIC: whole-tree leaf count at `ver` (empty bit-path) distinguishes
        // a VERSION problem (whole_tree==0 ⇒ the app tree is empty at `ver`, data
        // lives at a different version) from a BIT-PATH problem (whole_tree>0 but
        // parent_leaves==0 ⇒ data present but not under `shard_bits`). Plus the
        // persisted head version for the app-address key and the raw forest_version.
        let whole_tree_leaves = forest
            .app_subtree_leaf_count(app, PHASES[phase_idx], ver, &[])
            .unwrap_or(u64::MAX);
        let head_ver_app = forest
            .read_head_version(app, PHASES[phase_idx])
            .ok()
            .flatten();
        let forest_ver = self.forest_version.load(Ordering::SeqCst);
        let bifurcation = forest
            .first_split_bifurcation(app, PHASES[phase_idx], ver, shard_bits, max_extra_bits)
            .ok()
            .flatten();
        // Split-proposer diagnostic: pins WHY an over-crowded shard does / doesn't
        // produce children. `resolved_version=None` ⇒ version fell back to 0 (an
        // empty read → leaf_count 0 → no split; the read_shard_phase_root path
        // instead falls back to forest_version); `parent_leaves<2` ⇒ empty-split
        // guard fired; `children=0` with parent_leaves≥2 ⇒ data too clustered to
        // bifurcate within the bit budget.
        tracing::info!(
            app = hex::encode(app),
            shard_bits_len = shard_bits.len(),
            phase_idx,
            resolved_version = ?resolved,
            used_version = ver,
            forest_version = forest_ver,
            head_ver_app = ?head_ver_app,
            parent_leaves,
            whole_tree_leaves,
            children = bifurcation.as_ref().map(|c| c.len()).unwrap_or(0),
            "split-proposer: bifurcation probe"
        );
        let children_bits = bifurcation?;
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
        version: Option<u64>,
    ) -> Option<Vec<u8>> {
        if phase_idx >= 4 {
            return None;
        }
        let Some(version) = version else {
            return self.read_blob(shard, phase_idx, id).filter(|b| !b.is_empty());
        };
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
        if let Some(indexed) = self.indexed_root_version(shard_id, phase_idx, &root) {
            return Some(indexed);
        }
        if !self.unified_tree() || shard_id.len() <= 32 {
            return None;
        }
        // Unified shard headers name a SUBTREE of the app tree. The app's
        // root->version index cannot resolve that commitment. Search retained
        // versions of the app, newest first, comparing only the covered subtree.
        // This also works for databases written before subtree sync was wired.
        // Bound unknown-root requests; no unauthenticated tree is returned when
        // a peer is behind or the required history has been pruned.
        const SUBTREE_ROOT_LOOKBACK: u64 = 720;
        let bits = self.canonical_bits_for_filter(shard_id)?;
        let app = &shard_id[..32];
        let forest = self.forest.read().ok()?;
        let head = self.resolve_phase_version_with(&forest, app, phase_idx)?;
        for version in (head.saturating_sub(SUBTREE_ROOT_LOOKBACK - 1)..=head).rev() {
            if forest.app_subtree_root(app, PHASES[phase_idx], version, &bits).ok() == Some(root) {
                // Version is exact; a subtree lookup has no recorded global
                // frame. Its sync caller uses the certified shard header's
                // frame, never this zero, to advance its materialized cursor.
                return Some((version, 0));
            }
        }
        None
    }

    /// Whether this node retains the GLOBAL prover-shard (vertex-adds) tree at
    /// `root` — committed here or indexed after a verified sync — so a proof
    /// against it can be served.
    pub fn global_root_available(&self, root: &[u8; 32]) -> Result<bool> {
        Ok(self.indexed_root_version(&[0xff; 32], 0, root).is_some())
    }

    /// The indexed `(version, global_frame)` of `root`, only while the tree at
    /// that version still has that root. An index entry outlives its tree when
    /// a reset clears the tree without clearing the index (mainnet's prover-tree
    /// resets at 747,000, 754,000 and 759,000 ran on builds that kept it), and
    /// a rebuilt tree may reuse the version for a different root. Answering
    /// with such an entry named a version no sync could read ("missing source
    /// for the pinned header root"); the caller is told the root is
    /// unavailable instead.
    fn indexed_root_version(&self, shard_id: &[u8], phase_idx: usize, root: &[u8; 32]) -> Option<(u64, u64)> {
        let (set, phase) = PHASE_STR.get(phase_idx)?;
        let (version, frame) = self.store.get_root_version(set, phase, shard_id, root).ok().flatten()?;
        let forest = self.forest.read().ok()?;
        match forest.shard_phase_root(shard_id, PHASES[phase_idx], version) {
            Ok(Some(found)) if found == *root => Some((version, frame)),
            _ => {
                tracing::debug!(
                    shard = %hex::encode(&shard_id[..shard_id.len().min(8)]),
                    phase = phase_idx,
                    version,
                    root = %hex::encode(root),
                    "root index names a version whose tree no longer has that root; unavailable",
                );
                None
            }
        }
    }

    /// Prove one GLOBAL vertex against a retained root, using the blob from
    /// that root's exact version. Global headers bind parent state, so live
    /// blobs and live proofs cannot serve reward claims once the head advances.
    /// Serializes with commit/pruning so the blob and JMT path survive the read.
    pub fn global_vertex_membership_at_root(
        &self,
        root: &[u8; 32],
        data_address: &[u8; 32],
    ) -> Result<Option<quil_forest::VertexMembershipProof>> {
        let _guard = self.commit_lock.lock().map_err(|_| {
            QuilError::ExecutionUnavailable("historical proof commit lock poisoned".into())
        })?;
        let app = [0xff; 32];
        let (version, _) = self.store.get_root_version("vertex", "adds", &app, root)?
            .ok_or_else(|| QuilError::ExecutionUnavailable("historical global reward root unavailable".into()))?;
        let shard = ShardKey { l1: [0; 3], l2: app };
        let mut vertex = app.to_vec();
        vertex.extend_from_slice(data_address);
        let blob = match self.store.load_vertex_underlying_at("vertex", "adds", &shard, &vertex, version)? {
            Some(blob) => blob,
            None => return Ok(None),
        };
        let forest = self.forest.read().unwrap();
        let proof = forest.build_vertex_membership_proof(&app, PHASES[0], version, &vertex, &blob)
            .map_err(|e| QuilError::ExecutionUnavailable(format!("historical global reward proof: {e}")))?;
        // Also detects alternate backends that only implement latest-blob reads.
        quil_forest::verify_vertex_membership(root, &proof, &[])
            .map_err(|_| QuilError::ExecutionUnavailable("historical global reward blob/root mismatch".into()))?;
        Ok(Some(proof))
    }

    /// Index the current head root of (`shard_id`, `phase_idx`) into the
    /// sync-by-hash `root → (version, frame)` map at `frame` — but ONLY if that
    /// head root still equals `expect_root` (the just-verified sync anchor).
    ///
    /// This is what lets a node that obtained a tree via SYNC/reconcile
    /// ([`crate::forest_sync`]) rather than via its own [`commit_inner`] later
    /// SERVE [`resolve_root`] for that root. `commit_inner` maintains the
    /// root→version index via [`put_root_version`], but the sync install path
    /// (`sync_shard_phase_from`) writes the tree at its coordinated version WITHOUT
    /// touching that index — so an archive that reconciled its prover tree (instead
    /// of materializing it frame-by-frame) answers `resolve_root` with a MISS for
    /// its CURRENT roots and can't be a bootstrap source, even though it holds the
    /// exact tree. Calling this after a verified phase sync closes that gap.
    ///
    /// The head-root equality guard makes it race-safe against a concurrent commit
    /// that moved the head to a different root: we index the version at which the
    /// synced root actually lives, or skip if the head no longer matches.
    pub fn index_synced_root(
        &self,
        shard_id: &[u8],
        phase_idx: usize,
        expect_root: &[u8],
        frame: u64,
    ) -> Result<()> {
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "sync root index commit lock poisoned".into()))?;
        if phase_idx >= 4 || expect_root.len() != 32 || frame == 0 {
            return Ok(());
        }
        let (set, phase) = PHASE_STR[phase_idx];
        let (head_root, ver) = {
            let forest = self.forest.read().unwrap();
            (
                self.read_shard_phase_root(&forest, shard_id, phase_idx),
                self.resolve_phase_version_with(&forest, shard_id, phase_idx),
            )
        };
        if head_root.as_slice() != expect_root {
            return Ok(()); // head moved under us (concurrent commit) — don't mis-map
        }
        let Some(ver) = ver else { return Ok(()) };
        let txn = self.store.new_transaction(false)?;
        self.store
            .put_root_version(txn.as_ref(), set, phase, shard_id, expect_root, ver, frame)?;
        txn.commit()?;
        Ok(())
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
        let guard = self.lock_forest_writes();
        self.reset_shard_forest_trees_with_guard(&guard, shard_l2)
    }

    pub fn reset_shard_forest_trees_with_guard(&self, guard: &ForestWriteGuard<'_>, shard_l2: &[u8]) -> Result<()> {
        self.maintain_forest(guard, |forest| {
            forest
                .reset_shard_phase_trees(shard_l2)
                .map_err(|e| QuilError::ExecutionUnavailable(format!("reset_shard_forest_trees: {e}")))?;
            // The index maps roots to versions of the tree just wiped. Left behind
            // it resolves old roots to the rebuilt tree's reused versions, and the
            // retention pruner reads the restart as a history it must not touch.
            self.store.clear_root_versions(shard_l2)?;
            Ok(())
        })
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

    /// Retention pruner: each tree keeps the last `retain_frames` of its own
    /// frames (see `quil_store`'s retention plan), at most `max_blob_deletes`
    /// blob versions go per call, and a forest watermark above the tree's head
    /// (a store whose versions ran backwards) is refused. Returns
    /// `(trees pruned, forest nodes reclaimed)`.
    pub fn prune_retaining(&self, retain_frames: u64, max_blob_deletes: usize) -> Result<(usize, usize)> {
        self.prune_retaining_with(retain_frames, max_blob_deletes, None)
            .map(|pass| (pass.trees, pass.nodes))
    }

    /// [`Self::prune_retaining`], also deleting superseded JMT leaf values
    /// below each pruned tree's watermark, at most `max_value_deletes` per call
    /// (`None`: values are kept).
    pub fn prune_retaining_with(
        &self,
        retain_frames: u64,
        max_blob_deletes: usize,
        max_value_deletes: Option<usize>,
    ) -> Result<crate::retention::RetentionPass> {
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "retention prune commit lock poisoned".into()))?;
        let forest = self.forest.read().unwrap();
        let watermarks = self.store.prune_versioned_retaining(retain_frames, max_blob_deletes,
            &|shard_id, phase_idx| (phase_idx < 4).then(|| self.resolve_phase_version_with(&forest, shard_id, phase_idx)).flatten())?;
        let (mut trees, mut nodes, mut values) = (0usize, 0usize, 0usize);
        let mut value_budget = max_value_deletes.unwrap_or(0);
        for (shard_id, phase_idx, min_ver) in &watermarks {
            if *phase_idx >= 4 {
                continue;
            }
            match self.resolve_phase_version_checked(&forest, shard_id, *phase_idx) {
                Ok(Some(head)) if head >= *min_ver => {}
                head => {
                    tracing::warn!(shard = %hex::encode(shard_id), phase = *phase_idx, min_ver, ?head,
                        "retention watermark is above the tree head; not pruning its nodes");
                    continue;
                }
            }
            match forest.prune_shard_phase(shard_id, PHASES[*phase_idx], *min_ver) {
                Ok(n) => {
                    trees += 1;
                    nodes += n;
                }
                Err(e) => tracing::warn!(
                    shard = %hex::encode(shard_id),
                    phase = *phase_idx,
                    error = %e,
                    "forest prune of a shard/phase tree failed (will retry next cycle)",
                ),
            }
            if max_value_deletes.is_some() && value_budget > 0 {
                match forest.prune_shard_phase_values(shard_id, PHASES[*phase_idx], *min_ver, &mut value_budget) {
                    Ok(n) => values += n,
                    Err(e) => tracing::warn!(
                        shard = %hex::encode(shard_id),
                        phase = *phase_idx,
                        error = %e,
                        "forest value prune of a shard/phase tree failed (will retry next cycle)",
                    ),
                }
            }
        }
        Ok(crate::retention::RetentionPass { trees, nodes, values })
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
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "sync blob commit lock poisoned".into()))?;
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
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "sync preimage commit lock poisoned".into()))?;
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
        let _guard = self.commit_lock.lock().map_err(|_| QuilError::ExecutionUnavailable(
            "shard commit invalidation lock poisoned".into()))?;
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
        self.get_vertex_data_checked(location).ok().flatten()
    }

    /// Execution must distinguish absent state from an unavailable database.
    pub fn get_vertex_data_checked(&self, location: &Location) -> Result<Option<Vec<u8>>> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        if self.read_blob_checked(&shard, 1, &id)?.is_some() {
            return Ok(None); // removed
        }
        Ok(self.read_blob_checked(&shard, 0, &id)?.filter(|b| !b.is_empty()))
    }

    pub fn get_vertex_underlying_tree_bytes(&self, location: &Location) -> Option<Vec<u8>> {
        self.get_vertex_data(location)
    }

    pub fn lookup_hyperedge(&self, location: &Location) -> bool {
        self.get_hyperedge_data(location).is_some()
    }

    pub fn get_hyperedge_data(&self, location: &Location) -> Option<Vec<u8>> {
        self.get_hyperedge_data_checked(location).ok().flatten()
    }

    pub fn get_hyperedge_data_checked(&self, location: &Location) -> Result<Option<Vec<u8>>> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        if self.read_blob_checked(&shard, 3, &id)?.is_some() {
            return Ok(None);
        }
        Ok(self.read_blob_checked(&shard, 2, &id)?.filter(|b| !b.is_empty()))
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

    pub fn prepare_snapshot_publication(
        &self,
        root: Vec<u8>,
        frame_number: u64,
    ) -> Result<crate::snapshot::PreparedSnapshotPublication<'_>> {
        self.snapshot_mgr.prepare_publication(root, frame_number)
    }

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

    /// Capture committed state and metadata together, excluding execution's
    /// staged blobs and records. The caller owns the handle and must release it
    /// promptly; this does not add a retained snapshot to the serving cache.
    pub fn capture_committed_snapshot(&self) -> Result<Arc<dyn quil_types::store::SnapshotReadable>> {
        let _guard = self.commit_lock.lock().map_err(|_| {
            QuilError::ExecutionUnavailable("snapshot commit lock poisoned".into())
        })?;
        self.store.capture_tree_snapshot()?.ok_or_else(|| {
            QuilError::ExecutionUnavailable("committed snapshots unsupported by this store".into())
        })
    }

    /// Capture a full-filter checkpoint without interpreting read failures as
    /// empty state. The forest must use the same persistent database as the
    /// hypergraph store. Persisted phase heads are authoritative here; pending
    /// deltas, blobs and metadata never contribute to the returned checkpoint.
    pub fn capture_committed_shard(&self, filter: &[u8]) -> Result<CommittedShardSnapshot> {
        let _guard = self.commit_lock.lock().map_err(|_| {
            QuilError::ExecutionUnavailable("checkpoint commit lock poisoned".into())
        })?;
        self.capture_committed_shard_locked(filter)
    }

    /// Commit recovered metadata only if its input checkpoint still holds.
    /// Application state, its cursor, and pending mutations are untouched.
    /// The recovery progress marker belongs in `records`, so it shares the
    /// same atomic batch as the records it certifies.
    pub fn checkpoint_shard_records(
        &self,
        filter: &[u8],
        expected_roots: &[[u8; 32]; 4],
        cursor_key: &[u8],
        expected_cursor: u64,
        records: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<()> {
        let _guard = self.commit_lock.lock().map_err(|_| {
            QuilError::ExecutionUnavailable("history recovery commit lock poisoned".into())
        })?;
        let current = self.capture_committed_shard_locked(filter)?;
        if current.roots != *expected_roots
            || current.records.read_record(cursor_key)?.as_deref() != Some(expected_cursor.to_be_bytes().as_slice())
        {
            return Err(QuilError::ExecutionUnavailable("history recovery checkpoint changed".into()));
        }
        let txn = self.store.new_transaction(false)?;
        for (key, value) in records {
            if let Err(error) = txn.set(key, value) {
                let _ = txn.abort();
                return Err(error);
            }
        }
        txn.commit()
    }

    fn capture_committed_shard_locked(&self, filter: &[u8]) -> Result<CommittedShardSnapshot> {
        let (app, bits) = quil_forest::decode_shard_filter_or_root(filter, 32)
            .filter(|(_, bits)| bits.len() <= 256)
            .ok_or_else(|| QuilError::InvalidArgument("invalid checkpoint shard filter".into()))?;
        if filter.len() == 33 && filter[32] >= 64 {
            return Err(QuilError::InvalidArgument("aliased legacy checkpoint filter".into()));
        }
        let app: [u8; 32] = app.try_into().map_err(|_| {
            QuilError::InvalidArgument("invalid checkpoint application address".into())
        })?;
        let forest = self.forest.read().map_err(|_| {
            QuilError::ExecutionUnavailable("checkpoint forest lock poisoned".into())
        })?;
        if !forest.supports_checkpoint_reads() {
            return Err(QuilError::ExecutionUnavailable("checkpoint requires versioned forest storage".into()));
        }
        let unified = self.unified_tree();
        let shard_id = if unified {
            app.to_vec()
        } else {
            let prefixes = self.app_prefixes(&app);
            let paths = self.shard_bit_paths(&app);
            let matches: Vec<_> = paths.iter().enumerate().filter(|(_, p)| **p == bits).collect();
            if paths.len() != prefixes.len() || matches.len() != 1 {
                return Err(QuilError::ExecutionUnavailable("checkpoint shard layout is unknown or ambiguous".into()));
            }
            Forest::addr_path_shard_id(&app, &prefixes[matches[0].0])
        };
        let records = self.store.capture_tree_snapshot()?.ok_or_else(|| {
            QuilError::ExecutionUnavailable("committed snapshots unsupported by this store".into())
        })?;
        let read_error = |error| QuilError::ExecutionUnavailable(format!("checkpoint forest read: {error}"));
        let mut roots = [[0; 32]; 4];
        for (i, phase) in PHASES.iter().copied().enumerate() {
            let head = forest.read_head_version(&shard_id, phase).map_err(read_error)?;
            // The migration importer may have a real version-zero tree without
            // a marker. Never substitute a different app's global forest version.
            let version = head.unwrap_or(0);
            let root = forest.shard_phase_root(&shard_id, phase, version).map_err(read_error)?;
            if root.is_none() && head.is_some() {
                return Err(QuilError::ExecutionUnavailable("checkpoint phase head has no root".into()));
            }
            roots[i] = if unified && !bits.is_empty() {
                forest.app_subtree_root(&app, phase, version, &bits).map_err(read_error)?
            } else {
                root.unwrap_or([0; 32])
            };
        }
        Ok(CommittedShardSnapshot { roots, records })
    }

    pub fn acquire_scan_snapshot(&self, id: Option<&[u8; 32]>) -> Option<GenerationHandle> {
        self.snapshot_mgr.acquire_scan(id)
    }

    /// Start a new wallet scan at the current committed store, independently of
    /// historical root publication. A boot-time prover snapshot may remain the
    /// latest published generation while application coins keep changing.
    /// Continuations still use their exact retained identity, never a new view.
    pub fn acquire_or_capture_scan_snapshot(&self, id: Option<&[u8; 32]>) -> Result<Option<GenerationHandle>> {
        if id.is_some() {
            return Ok(self.snapshot_mgr.acquire_scan(id));
        }
        let _guard = self.commit_lock.lock().map_err(|_| {
            QuilError::ExecutionUnavailable("scan snapshot commit lock poisoned".into())
        })?;
        Ok(match self.store.capture_tree_snapshot()? {
            Some(snapshot) => self.snapshot_mgr.publish_scan_only(
                self.forest_version.load(Ordering::SeqCst), snapshot,
            ),
            None => None,
        })
    }

    pub fn known_snapshot_roots(&self) -> Vec<Vec<u8>> {
        self.snapshot_mgr.known_roots()
    }

    /// Keep store snapshots only on the newest `limit` published generations
    /// (see [`SnapshotManager::set_pinned_limit`]).
    pub fn set_snapshot_pinned_limit(&self, limit: usize) {
        self.snapshot_mgr.set_pinned_limit(limit);
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
/// Marker: the forest Merkle-sum size index has been backfilled over this DB's
/// pre-existing tree ([`HypergraphCrdt::warm_size_index`]). Present ⇒ the index
/// is warm and kept so by write-time maintenance; absent ⇒ backfill on boot.
const SIZE_INDEX_SEEDED_KEY: &[u8] = b"hgsz:seeded";

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

#[cfg(test)]
mod size_index_tests {
    use super::*;
    use crate::testing::{MemStore, StubProver};
    use std::sync::Arc;

    fn crdt() -> HypergraphCrdt {
        HypergraphCrdt::new(Arc::new(MemStore::new()), Arc::new(StubProver))
    }

    /// The world size is recorded per materialized frame with the prover root
    /// (even when the root is degenerate) and pruned with the same bound.
    #[test]
    fn world_size_recorded_with_each_frame() {
        let hg = crdt();
        assert_eq!(hg.world_size_at(7), None);
        hg.record_prover_root(7, vec![1; 32]);
        assert_eq!(hg.world_size_at(7), Some(0));
        hg.add_vertex(&at([0x42; 32], 0, 1, 2), &vec![9u8; 512]).unwrap();
        hg.record_prover_root(8, Vec::new());
        let grown = hg.world_size_at(8).unwrap();
        assert!(grown > 0, "recorded size reflects state at that frame");
        assert_eq!(hg.world_size_at(7), Some(0), "earlier frames keep their size");
        for frame in 9..300 {
            hg.record_prover_root(frame, vec![1; 32]);
        }
        assert_eq!(hg.world_size_at(7), None);
        assert!(hg.world_size_at(299).is_some());
    }

    /// A coin-shaped vertex whose data-address top bits route it to a shard: byte0
    /// selects the top-of-tree bit-path (so `< 0x04` → shard `[0]`, `0x04` → `[1]`
    /// in the binary grid the tests below use), the rest disambiguates the leaf.
    fn at(app: [u8; 32], b0: u8, b1: u8, b2: u8) -> Location {
        Location {
            app_address: app,
            data_address: {
                let mut a = [0u8; 32];
                a[0] = b0;
                a[1] = b1;
                a[2] = b2;
                a
            },
        }
    }

    /// The forest Merkle-sum aggregate (`forest_app_buckets`) MUST produce
    /// byte-identical per-shard `(count, size)` to the legacy full-leaf scan
    /// (`scan_app_buckets`). The per-shard basis is consensus-relevant (reward +
    /// join gate), so the O(depth) fast path can't change any value. This is the
    /// pure-adds case across a 2-way split grid — the split/rebucket path the
    /// localnet genesis shard is too small to exercise.
    #[test]
    fn forest_buckets_match_scan_adds_split() {
        let app = [7u8; 32];
        let c = crdt();
        c.set_unified_tree(true);
        // Binary split grid: shard `[0]` (top-6-bits 000000) and `[1]` (000001).
        c.set_app_shard_prefixes(app, vec![vec![0u32], vec![1u32]]);
        // Three leaves under `[0]` (byte0 == 0x00) + one under `[1]` (byte0 0x04).
        c.add_vertex(&at(app, 0x00, 0xFF, 0x11), b"coin-a").unwrap();
        c.add_vertex(&at(app, 0x00, 0xFE, 0x22), b"coin-bb").unwrap();
        c.add_vertex(&at(app, 0x00, 0xF0, 0x33), b"coin-ccc").unwrap();
        c.add_vertex(&at(app, 0x04, 0xAB, 0x44), b"coin-dddd").unwrap();
        c.commit(1).unwrap();

        let mut scan = HashMap::new();
        c.scan_app_buckets(&app, &mut scan).unwrap();
        let mut forest = HashMap::new();
        c.forest_app_buckets(&app, &mut forest).unwrap();

        assert!(
            scan.values().any(|(cnt, _)| *cnt > 0),
            "precondition: scan found leaves (grid/version wired)"
        );
        assert_eq!(
            forest, scan,
            "forest Merkle-sum buckets must equal the leaf-scan buckets\n\
             forest={forest:?}\nscan={scan:?}"
        );
    }

    /// Same equality invariant, now stressing the removes paths that most diverge
    /// between the two code sides: `scan_app_buckets` excludes a removed leaf from
    /// `live_size` (but still counts it in `raw_count`), while the forest retains
    /// the add leaf and nets it out via the sized removes tombstone. Covers a spent
    /// coin, a DOUBLE remove (tombstone must re-stamp the same size, not zero it), a
    /// removed-but-never-added placeholder, and a removed hyperedge.
    #[test]
    fn forest_buckets_match_scan_with_removes() {
        let app = [8u8; 32];
        let c = crdt();
        c.set_unified_tree(true);
        c.set_app_shard_prefixes(app, vec![vec![0u32], vec![1u32]]);
        c.add_vertex(&at(app, 0x00, 0xFF, 0x11), b"coin-a").unwrap();
        c.add_vertex(&at(app, 0x04, 0xAB, 0x44), b"coin-dddd").unwrap();
        // Add then remove a leaf under `[0]` — a spent coin, removed TWICE (the
        // second remove must not zero the tombstone's recorded size).
        let spent = at(app, 0x00, 0x12, 0x99);
        c.add_vertex(&spent, b"spent-coin-xyz").unwrap();
        c.remove_vertex(&spent).unwrap();
        c.remove_vertex(&spent).unwrap();
        // Remove an id that was never added — an empty add placeholder + tombstone.
        c.remove_vertex(&at(app, 0x00, 0x77, 0x77)).unwrap();
        // A live hyperedge and a removed one under `[1]`.
        c.add_hyperedge(&at(app, 0x04, 0x01, 0x02), b"edge-live").unwrap();
        let dead_edge = at(app, 0x04, 0x03, 0x04);
        c.add_hyperedge(&dead_edge, b"edge-dead-longer").unwrap();
        c.remove_hyperedge(&dead_edge).unwrap();
        c.commit(1).unwrap();

        let mut scan = HashMap::new();
        c.scan_app_buckets(&app, &mut scan).unwrap();
        let mut forest = HashMap::new();
        c.forest_app_buckets(&app, &mut forest).unwrap();

        assert_eq!(
            forest, scan,
            "forest vs scan must agree under removes (spent, double-remove, \
             never-added, removed hyperedge)\nforest={forest:?}\nscan={scan:?}"
        );
    }
}
