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
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Apps that split into address-path sub-shards, mapped to their COMPLETE
    /// shard-prefix set (each prefix a `ShardInfo.prefix`: QUIL 6-bit indices or
    /// split-marker bytes — see [`canonical_shard_bit_paths`]). Absent ⇒ the app
    /// is a single shard (the default — every unsplit app). The node populates
    /// this from the shards store so `commit_inner` splits + aggregates exactly
    /// the apps' real, possibly non-uniform, shard sets (matching the converter).
    #[allow(clippy::type_complexity)]
    app_shard_prefixes: RwLock<HashMap<[u8; 32], Vec<Vec<u32>>>>,
    /// Staged L3 leaf deltas per (shard, phase index).
    pending: RwLock<HashMap<(ShardKey, usize), PhaseDeltas>>,
    /// Staged per-vertex blobs per (shard, phase index).
    pending_blobs: RwLock<HashMap<(ShardKey, usize), PhaseBlobs>>,
    /// Latest committed per-shard metadata.
    shard_metadata: RwLock<HashMap<ShardKey, ShardMetadata>>,
    /// Running total live byte size.
    size: RwLock<BigInt>,
    /// Snapshot-generation registry for sync `expected_root` gating.
    snapshot_mgr: SnapshotManager,
    /// Covered nibble prefix (address gating). Empty = accept all.
    covered_prefix: RwLock<Vec<i32>>,
    /// Serializes commits against each other.
    commit_lock: std::sync::Mutex<()>,
}

impl HypergraphCrdt {
    pub fn new(store: Arc<dyn HypergraphStore>, prover: Arc<dyn InclusionProver>) -> Self {
        Self {
            store,
            prover,
            forest: RwLock::new(Forest::in_memory()),
            forest_version: AtomicU64::new(0),
            phase_versions: RwLock::new(HashMap::new()),
            app_shard_prefixes: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            pending_blobs: RwLock::new(HashMap::new()),
            shard_metadata: RwLock::new(HashMap::new()),
            size: RwLock::new(BigInt::zero()),
            snapshot_mgr: SnapshotManager::new(),
            covered_prefix: RwLock::new(Vec::new()),
            commit_lock: std::sync::Mutex::new(()),
        }
    }

    /// Install the state-commitment forest (production: the namespaced RocksDB
    /// forest sharing the store's DB). Replaces the default in-memory forest.
    pub fn set_forest(&self, forest: Forest) {
        *self.forest.write().unwrap() = forest;
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
    pub fn set_app_shard_prefixes(&self, app: [u8; 32], prefixes: Vec<Vec<u32>>) {
        let set = if prefixes.is_empty() { vec![Vec::new()] } else { prefixes };
        self.app_shard_prefixes.write().unwrap().insert(app, set);
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
        if prefixes.len() == 1 && prefixes[0].is_empty() {
            return self.read_shard_phase_root(forest, app, phase_idx).to_vec();
        }
        let bit_paths = canonical_shard_bit_paths(prefixes);
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

    // ---- mutations ------------------------------------------------------

    pub fn add_vertex(&self, location: &Location, data: &[u8]) -> Result<()> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        self.stage(&shard, 0, &id, data)?;
        // World size EXCLUDES the global prover shard (0xff): its prover
        // registry + per-epoch leaf-root registry + reward vertices are not
        // proven/stored by regular workers, so they must never count toward the
        // reward/fee issuance denominator. Excluding here (at the live counter)
        // rather than subtracting a committed snapshot is what makes the
        // exclusion correct MID-frame, as the registry grows within a frame.
        if shard.l2 != [0xFFu8; 32] {
            *self.size.write().unwrap() += BigInt::from(data.len() as u64);
        }
        Ok(())
    }

    pub fn remove_vertex(&self, location: &Location) -> Result<()> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();

        let existing = self.read_blob(&shard, 0, &id);
        let in_removes = self.has_entry(&shard, 1, &id);
        let present = existing.as_ref().map(|b| !b.is_empty()).unwrap_or(false) && !in_removes;
        let value_size = if present {
            existing.as_ref().map(|b| BigInt::from(b.len() as u64)).unwrap_or_default()
        } else {
            BigInt::zero()
        };

        // Add-side placeholder for a removed-but-never-added id.
        if existing.is_none() {
            self.stage(&shard, 0, &id, &[])?;
        }
        // Tombstone in the removes phase.
        self.stage(&shard, 1, &id, &[])?;

        if present && shard.l2 != [0xFFu8; 32] {
            *self.size.write().unwrap() -= &value_size;
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
        if shard.l2 != [0xFFu8; 32] {
            *self.size.write().unwrap() += BigInt::from(data.len() as u64);
        }
        Ok(())
    }

    pub fn remove_hyperedge(&self, location: &Location) -> Result<()> {
        let shard = shard_key_for_location(location);
        let id = location.to_id();
        let existing = self.read_blob(&shard, 2, &id);
        if existing.is_none() {
            self.stage(&shard, 2, &id, &[])?;
        }
        self.stage(&shard, 3, &id, &[])?;
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

        for shard in &shard_keys {
            let cached_row = cached.get(shard);
            let prefixes = self.app_prefixes(&shard.l2);
            let single_shard = prefixes.len() == 1 && prefixes[0].is_empty();
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
                    canonical_shard_bit_paths(&prefixes)
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
            result.insert(shard.clone(), roots.to_vec());
        }

        if let Some(cursor_key) = cursor_key {
            txn.set(cursor_key, &frame_number.to_be_bytes())?;
        }
        txn.commit()?;
        Ok(result)
    }

    // ---- roots / metadata ----------------------------------------------

    /// World-state size for reward/fee issuance. EXCLUDES the global prover shard
    /// (`GLOBAL_INTRINSIC_ADDRESS` = `[0xff; 32]`) — its prover registry, per-epoch
    /// leaf-root registry, and reward vertices are not proven/stored by regular
    /// workers, so they must never count toward the issuance denominator. The
    /// exclusion is enforced at the live `self.size` counter (see `add_vertex` /
    /// `add_hyperedge` / `remove_vertex`), so it holds MID-frame as the prover
    /// shard grows, not just at commit boundaries.
    pub fn total_size(&self) -> BigInt {
        self.size.read().unwrap().clone()
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
    /// Reads committed state via `collect_phase_leaves`, so it is deterministic
    /// across nodes given the same committed forest. `None` if malformed or empty.
    pub fn sub_shard_metadata_for_filter(&self, filter: &[u8]) -> Option<quil_tries::NodeMetadata> {
        if filter.len() < 32 {
            return None;
        }
        let mut app = [0u8; 32];
        app.copy_from_slice(&filter[..32]);
        let l1 = crate::addressing::get_bloom_filter_indices(&app, 256, 3);
        let shard_key = ShardKey { l1, l2: app };
        let mut full_path = quil_tries::get_full_path(&app);
        for &b in &filter[32..] {
            full_path.push(b as i32);
        }
        self.phase_set_metadata_at_path(&shard_key, &full_path)
            .ok()
            .and_then(|metas| metas[0].clone())
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
        let single_shard = prefixes.len() == 1 && prefixes[0].is_empty();
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
                let bit_paths = canonical_shard_bit_paths(&prefixes);
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
    /// The diff walk (remote reads) runs WITHOUT the commit lock — JMT reads are
    /// version-exact, so it stays consistent even if a live commit advances the
    /// tree; only the apply takes the lock. For a catch-up node a concurrent
    /// local commit to the same shard is caught by the caller's root check.
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
        let leaves = {
            let forest = self.forest.read().unwrap();
            let v_t = self.resolve_phase_version_with(&forest, shard_id, phase_idx).unwrap_or(0);
            let target = forest.shard_phase_reader(shard_id, PHASES[phase_idx]);
            quil_forest::diff_leaves(source, source_version, &target, v_t)
                .map_err(|e| QuilError::Internal(format!("diff_leaves: {e}")))?
        };
        // The changed leaves as `(key_hash, leaf_value)` pairs. Under the
        // per-vertex-subtree model the raw-key `key_hash` IS the vertex's 32-byte
        // DATA address (no hashing, no preimage), and `leaf_value` is its
        // committed `commitment ‖ size` — the caller derives `vertex_id =
        // app ‖ key_hash` directly and verifies each fetched blob against
        // `leaf_value` (a peer cannot serve data not matching the commitment).
        let changed: Vec<([u8; 32], Vec<u8>)> =
            leaves.iter().map(|(k, v)| (k.0, v.clone())).collect();
        let _guard = self.commit_lock.lock().unwrap();
        let forest = self.forest.read().unwrap();
        // Per-tree contiguous version (JMT builds on `version - 1`), same as
        // `commit_one_shard_phase`.
        let ver = self
            .resolve_phase_version_with(&forest, shard_id, phase_idx)
            .map(|v| v + 1)
            .unwrap_or(0);
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

    /// The address-path sub-shards of an app: `(shard_id, prefix_bits)` for each
    /// (a single `(app, [])` for a single-shard app; 64 for QUIL). A sync client
    /// enumerates these to fetch each sub-shard's head and verify the set.
    pub fn app_sub_shards(&self, app: &[u8; 32]) -> Vec<(Vec<u8>, Vec<bool>)> {
        let prefixes = self.app_prefixes(app);
        let bit_paths = canonical_shard_bit_paths(&prefixes);
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
    /// leaf-count/size metadata at `full_path`, from the KV. `longest_branch`
    /// is not meaningful for a JMT and is left zero.
    pub fn phase_set_metadata_at_path(
        &self,
        shard_key: &ShardKey,
        full_path: &[i32],
    ) -> Result<[Option<quil_tries::NodeMetadata>; 4]> {
        let mut out: [Option<quil_tries::NodeMetadata>; 4] = [None, None, None, None];
        for phase_idx in 0..4 {
            let leaves = self.collect_phase_leaves(shard_key, phase_idx, full_path)?;
            if leaves.is_empty() {
                continue;
            }
            let size: u64 = leaves.iter().map(|(_, v)| v.len() as u64).sum();
            out[phase_idx] = Some(quil_tries::NodeMetadata {
                commitment: Vec::new(),
                leaf_count: leaves.len() as u64,
                size: BigInt::from(size),
            });
        }
        Ok(out)
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
