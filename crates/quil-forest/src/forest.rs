//! The forest driver: the 3-tier commit orchestration over the shared
//! RocksDB, plus the CRDT phase model for Level 3.
//!
//! Level 3 keeps four *phase* trees per shard (the CRDT's OR-set
//! adds/removes for vertices and hyperedges). Their four roots are exactly
//! the header `state_roots`, and they roll up — [`rollup_phase_roots`] — into
//! the single 32-byte commitment a shard contributes to its app's Level-2
//! [`ShardEntry`](crate::ShardEntry). Level 2 rolls into Level 1 the same way
//! (an app's L2 root is its [`AppEntry`](crate::AppEntry) leaf).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use jmt::storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeUpdateBatch, TreeWriter};
use jmt::{KeyHash, OwnedValue, Sha256Jmt, Version};
use sha2::{Digest, Sha256};

use crate::{commit_pruning, ForestStore, MemTreeStore, RocksTreeStore, TreeId};

/// A per-tree store the forest opens on demand, over either RocksDB or an
/// in-memory backing. A concrete enum (not a trait object) so JMT's generic
/// `TreeReader`/`TreeWriter` bounds accept it directly.
pub enum TreeStore {
    Rocks(RocksTreeStore),
    Mem(Arc<MemTreeStore>),
}

impl TreeReader for TreeStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        match self {
            TreeStore::Rocks(s) => s.get_node_option(node_key),
            TreeStore::Mem(s) => s.get_node_option(node_key),
        }
    }
    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        match self {
            TreeStore::Rocks(s) => s.get_value_option(max_version, key_hash),
            TreeStore::Mem(s) => s.get_value_option(max_version, key_hash),
        }
    }
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        match self {
            TreeStore::Rocks(s) => s.get_rightmost_leaf(),
            TreeStore::Mem(s) => s.get_rightmost_leaf(),
        }
    }
}

impl TreeWriter for TreeStore {
    fn write_node_batch(&self, batch: &NodeBatch) -> Result<()> {
        match self {
            TreeStore::Rocks(s) => s.write_node_batch(batch),
            TreeStore::Mem(s) => s.write_node_batch(batch),
        }
    }
}

impl ForestStore for TreeStore {
    fn apply_update(&self, batch: &TreeUpdateBatch) -> Result<()> {
        match self {
            TreeStore::Rocks(s) => s.apply_update(batch),
            TreeStore::Mem(s) => s.apply_update(batch),
        }
    }
    fn prune(&self, min_readable_version: Version) -> Result<usize> {
        match self {
            TreeStore::Rocks(s) => s.prune(min_readable_version),
            TreeStore::Mem(s) => s.prune(min_readable_version),
        }
    }
}

/// The forest's storage backend.
#[derive(Clone)]
enum Backend {
    Rocks { db: Arc<rocksdb::DB>, namespace: Vec<u8> },
    /// In-memory: one [`MemTreeStore`] per tree-id prefix (tests/benches).
    Mem(Arc<Mutex<HashMap<Vec<u8>, Arc<MemTreeStore>>>>),
}

/// A CRDT phase. The four phases are independent Level-3 JMT trees per shard;
/// the discriminant is the on-disk tree-id tag (see
/// [`TreeId::shard_phase`](crate::TreeId::shard_phase)) and the index into a
/// shard's four roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    VertexAdds = 0,
    VertexRemoves = 1,
    HyperedgeAdds = 2,
    HyperedgeRemoves = 3,
}

/// The four phases in canonical order — the order of a shard's `state_roots`
/// and the order [`rollup_phase_roots`] folds them.
pub const PHASES: [Phase; 4] = [
    Phase::VertexAdds,
    Phase::VertexRemoves,
    Phase::HyperedgeAdds,
    Phase::HyperedgeRemoves,
];

/// Domain separator for the shard rollup so a shard commitment can never
/// collide with a raw JMT root or another protocol's hash.
const SHARD_ROLLUP_DOMAIN: &[u8] = b"quil-forest:shard-rollup:v1";

/// Fold a shard's four phase roots into its single 32-byte commitment:
/// `SHA-256(domain || vertex_adds || vertex_removes || hyperedge_adds ||
/// hyperedge_removes)`. Deterministic and order-fixed by [`PHASES`].
pub fn rollup_phase_roots(phase_roots: &[[u8; 32]; 4]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SHARD_ROLLUP_DOMAIN);
    for r in phase_roots {
        h.update(r);
    }
    h.finalize().into()
}

/// A shard's committed state after one frame: the four phase roots (the
/// header `state_roots`) and their rollup (the app-level commitment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRoots {
    pub phase_roots: [[u8; 32]; 4],
    pub commitment: [u8; 32],
}

/// An app's committed state after aggregating its shards ([`Forest::commit_app_shards`]):
/// the app roots plus the branch metadata (the verkle-style per-branch aggregates).
/// `num_leaves` is JMT's native cumulative subtree leaf count; `total_size` is the
/// accumulated VertexAdds value byte-count (JMT does not track size).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppCommit {
    pub roots: ShardRoots,
    pub num_leaves: u64,
    pub total_size: u128,
}

/// The forest over one shared RocksDB. Cheap to clone (an `Arc` handle);
/// every method opens the relevant per-tree store on demand, so a party can
/// touch exactly the trees its role needs. An optional `namespace` prefixes
/// every key so the forest can live in the node's main DB alongside its
/// clock/shard/registry data (see [`RocksTreeStore::with_namespace`]).
#[derive(Clone)]
pub struct Forest {
    backend: Backend,
}

impl Forest {
    /// A standalone forest DB (no namespace) — e.g. the converter's fresh
    /// destination DB.
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Forest { backend: Backend::Rocks { db, namespace: Vec::new() } }
    }

    /// A forest embedded in a shared DB under `namespace` (a reserved prefix
    /// the surrounding schema never emits).
    pub fn with_namespace(db: Arc<rocksdb::DB>, namespace: impl Into<Vec<u8>>) -> Self {
        Forest { backend: Backend::Rocks { db, namespace: namespace.into() } }
    }

    /// An in-memory forest — for unit tests / benches that construct a
    /// forest-backed CRDT without a RocksDB. Each tree gets its own
    /// [`MemTreeStore`], keyed by tree-id prefix so they never collide.
    pub fn in_memory() -> Self {
        Forest { backend: Backend::Mem(Arc::new(Mutex::new(HashMap::new()))) }
    }

    /// The RocksDB handle, if this forest is RocksDB-backed (`None` for
    /// [`in_memory`](Self::in_memory)).
    pub fn db(&self) -> Option<&Arc<rocksdb::DB>> {
        match &self.backend {
            Backend::Rocks { db, .. } => Some(db),
            Backend::Mem(_) => None,
        }
    }

    fn store(&self, tree: &TreeId) -> TreeStore {
        match &self.backend {
            Backend::Rocks { db, namespace } => {
                TreeStore::Rocks(RocksTreeStore::with_namespace(db.clone(), namespace, tree))
            }
            Backend::Mem(stores) => {
                let prefix = tree.prefix();
                let mut g = stores.lock().unwrap();
                let s = g
                    .entry(prefix)
                    .or_insert_with(|| Arc::new(MemTreeStore::default()))
                    .clone();
                TreeStore::Mem(s)
            }
        }
    }

    // ---- Level 3: per-shard phase trees ----------------------------------

    /// Commit one shard/phase tree at `version`, returning its 32-byte root.
    /// Overwritten nodes are indexed for pruning.
    pub fn commit_shard_phase(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<[u8; 32]> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let leaves: Vec<(Vec<u8>, Vec<u8>)> = leaves.into_iter().collect();
        let raw_keys: Vec<Vec<u8>> = leaves.iter().map(|(k, _)| k.clone()).collect();
        let root = commit_pruning(&store, version, leaves)?.0;
        // Record raw-key preimages (see the staged variant) so the migration's
        // trees are sync-recoverable too.
        if let TreeStore::Rocks(s) = &store {
            for k in &raw_keys {
                s.put_preimage(k)?;
            }
        }
        Ok(root)
    }

    /// Record a raw l3 key's preimage in a shard/phase tree directly — the CLIENT
    /// side of sync uses this so a synced node can later re-SERVE preimages to
    /// nodes syncing from it (the diff apply only carries KeyHashes, not raw
    /// keys). No-op for a mem forest.
    pub fn write_preimage(&self, shard_id: &[u8], phase: Phase, raw_key: &[u8]) -> Result<()> {
        if let TreeStore::Rocks(s) = self.store(&TreeId::shard_phase(shard_id, phase)) {
            s.put_preimage(raw_key)?;
        }
        Ok(())
    }

    /// Read the raw l3 leaf key (`vertex_id ‖ field_key`) a shard/phase tree's
    /// `key_hash` was committed from — the SERVER side of blob sync. `None` if
    /// not recorded (e.g. a mem forest, or pre-preimage data).
    pub fn get_preimage(
        &self,
        shard_id: &[u8],
        phase: Phase,
        key_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        match self.store(&TreeId::shard_phase(shard_id, phase)) {
            TreeStore::Rocks(s) => s.get_preimage(&KeyHash(key_hash)),
            TreeStore::Mem(_) => Ok(None),
        }
    }

    /// Commit one shard/phase tree, **staging** the writes into `wb` instead
    /// of writing them immediately, and return its 32-byte root. The caller
    /// flushes `wb` — use this when the forest write must land atomically with
    /// other writes in the same batch (the hypergraph CRDT stages its phase
    /// commits alongside its durable materialization cursor so the two can
    /// never diverge across a crash). Stale-node records are staged too, so
    /// pruning still works.
    pub fn stage_shard_phase(
        &self,
        wb: &mut rocksdb::WriteBatch,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<[u8; 32]> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let (root, batch) = crate::commit_update(&store, version, leaves)?;
        match &store {
            TreeStore::Rocks(s) => s.stage_update(wb, &batch)?,
            // No external batch for an in-memory forest — apply directly.
            TreeStore::Mem(_) => store.apply_update(&batch)?,
        }
        Ok(root.0)
    }

    /// Commit one shard/phase tree and return its 32-byte root **plus** the
    /// raw `(key, value)` puts to persist it, WITHOUT writing anything. The
    /// caller stages the puts into its own key-value transaction (e.g. the
    /// hypergraph CRDT's `Transaction::set`) so the forest write commits
    /// atomically with the caller's other writes. All forest writes are puts,
    /// so no delete handling is needed.
    pub fn commit_shard_phase_staged(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<([u8; 32], Vec<(Vec<u8>, Vec<u8>)>)> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let leaves: Vec<(Vec<u8>, Vec<u8>)> = leaves.into_iter().collect();
        let raw_keys: Vec<Vec<u8>> = leaves.iter().map(|(k, _)| k.clone()).collect();
        let (root, batch) = crate::commit_update(&store, version, leaves)?;
        match &store {
            TreeStore::Rocks(s) => {
                let mut puts = s.update_puts(&batch)?;
                // Record each leaf's raw-key preimage so the sync can map a
                // diff's changed KeyHash back to its (vertex, field).
                for k in &raw_keys {
                    puts.push(s.preimage_put(k));
                }
                Ok((root.0, puts))
            }
            // Mem forest: no external key-value txn to stage into — apply
            // directly and return no puts (nothing for the caller to stage).
            TreeStore::Mem(_) => {
                store.apply_update(&batch)?;
                Ok((root.0, Vec::new()))
            }
        }
    }

    /// Commit all four phase trees of a shard at `version` and roll their
    /// roots into the shard commitment. `phase_leaves` is indexed by
    /// [`Phase`] discriminant (0..4). Returns the four roots (= header
    /// `state_roots`) and their rollup.
    pub fn commit_shard(
        &self,
        shard_id: &[u8],
        version: u64,
        phase_leaves: [Vec<(Vec<u8>, Vec<u8>)>; 4],
    ) -> Result<ShardRoots> {
        let mut phase_roots = [[0u8; 32]; 4];
        // `into_iter` on a `[T; 4]` yields owned elements in order.
        for (leaves, phase) in phase_leaves.into_iter().zip(PHASES) {
            phase_roots[phase as usize] =
                self.commit_shard_phase(shard_id, phase, version, leaves)?;
        }
        Ok(ShardRoots { commitment: rollup_phase_roots(&phase_roots), phase_roots })
    }

    /// Like [`commit_shard`] but positions every phase's leaves by RAW address
    /// ([`commit_shard_phase_raw`]) — the per-vertex-subtree model, where each
    /// leaf is keyed by its 32-byte vertex data address so the shard stays a
    /// prefix-navigable subtree. Matches the running node's `commit_inner`
    /// (which commits each phase via `commit_shard_phase_raw_staged`).
    pub fn commit_shard_raw(
        &self,
        shard_id: &[u8],
        version: u64,
        phase_leaves: [Vec<(Vec<u8>, Vec<u8>)>; 4],
    ) -> Result<ShardRoots> {
        let mut phase_roots = [[0u8; 32]; 4];
        for (leaves, phase) in phase_leaves.into_iter().zip(PHASES) {
            phase_roots[phase as usize] =
                self.commit_shard_phase_raw(shard_id, phase, version, leaves)?;
        }
        Ok(ShardRoots { commitment: rollup_phase_roots(&phase_roots), phase_roots })
    }

    // ---- Address-path forest (D-4): raw-key shards + app aggregation ------

    /// The shard-tree id for `(app_address, prefix)` in the address-path model:
    /// `app_address ‖ prefix (each 64-way level as a big-endian u32)`. The
    /// `prefix` is the `ShardInfo.prefix` — empty for an unsplit single-shard app,
    /// `[i]` for a QUIL 64-way shard, deeper as the app splits. A shard's leaves
    /// live in this tree positioned by their RAW address (see
    /// [`commit_shard_phase_raw`]).
    pub fn addr_path_shard_id(app_address: &[u8], prefix: &[u32]) -> Vec<u8> {
        let mut id = Vec::with_capacity(app_address.len() + 4 * prefix.len());
        id.extend_from_slice(app_address);
        for &lvl in prefix {
            id.extend_from_slice(&lvl.to_be_bytes());
        }
        id
    }

    /// Commit one shard/phase tree with RAW-KEY (address-path) positioning —
    /// leaves cluster by address, so the shard is the address-prefix subtree of
    /// the app. (vs [`commit_shard_phase`], which positions by `SHA-256(key)`.)
    pub fn commit_shard_phase_raw(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<[u8; 32]> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let (root, batch) = crate::commit_update_raw(&store, version, leaves)?;
        store.apply_update(&batch)?;
        Ok(root.0)
    }

    /// Like [`commit_shard_phase_raw`] but returns the raw `(key, value)` puts to
    /// persist the tree WITHOUT writing them — the caller stages them into its own
    /// key-value transaction (the CRDT stages forest writes alongside its durable
    /// cursor so they land atomically). All forest writes are puts.
    pub fn commit_shard_phase_raw_staged(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<([u8; 32], Vec<(Vec<u8>, Vec<u8>)>)> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let (root, batch) = crate::commit_update_raw(&store, version, leaves)?;
        match &store {
            TreeStore::Rocks(s) => Ok((root.0, s.update_puts(&batch)?)),
            TreeStore::Mem(_) => {
                store.apply_update(&batch)?;
                Ok((root.0, Vec::new()))
            }
        }
    }

    /// Apply a sync diff — `(key_hash, value)` leaves received from a peer (see
    /// [`crate::diff_leaves`]) — into a shard/phase tree at `version`, returning
    /// the new root + the staged puts (empty for a mem forest). The caller MUST
    /// verify the returned root equals the pinned target (and, for a split app,
    /// that it aggregates to the trusted app root via
    /// [`crate::app_root_from_shard_path`]) before trusting the state.
    pub fn apply_synced_shard_phase(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        leaves: impl IntoIterator<Item = (crate::KeyHash, Vec<u8>)>,
    ) -> Result<([u8; 32], Vec<(Vec<u8>, Vec<u8>)>)> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let (root, batch) = crate::commit_update_keyhash(&store, version, leaves)?;
        match &store {
            TreeStore::Rocks(s) => Ok((root.0, s.update_puts(&batch)?)),
            TreeStore::Mem(_) => {
                store.apply_update(&batch)?;
                Ok((root.0, Vec::new()))
            }
        }
    }

    /// A [`TreeReader`] view of one shard/phase tree — the target side of a sync
    /// diff (the peer/source is a remote reader). Lets [`crate::diff_leaves`] walk
    /// this forest's tree without exposing the store internals.
    pub fn shard_phase_reader(&self, shard_id: &[u8], phase: Phase) -> TreeStore {
        self.store(&TreeId::shard_phase(shard_id, phase))
    }

    /// SERVER side of forest sync: serve one JMT node of a shard/phase tree.
    /// `node_key` is `borsh(NodeKey)` (as the diff client requests it); returns
    /// `borsh(Node)`, or `None` if the node is absent. Pure proxy over the store —
    /// authentication is the client's (the diff walk is rooted at the trusted
    /// header root), so the server holds no secrets here.
    pub fn serve_node(&self, shard_id: &[u8], phase: Phase, node_key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key: NodeKey = borsh::from_slice(node_key)
            .map_err(|e| anyhow::anyhow!("decode NodeKey: {e}"))?;
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        match store.get_node_option(&key)? {
            Some(node) => Ok(Some(
                borsh::to_vec(&node).map_err(|e| anyhow::anyhow!("encode Node: {e}"))?,
            )),
            None => Ok(None),
        }
    }

    /// SERVER side of forest sync: serve a leaf value of a shard/phase tree by its
    /// 32-byte `KeyHash` at `version` (newest ≤ `version`), or `None` if absent.
    pub fn serve_value(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        key_hash: [u8; 32],
    ) -> Result<Option<OwnedValue>> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        store.get_value_option(version, KeyHash(key_hash))
    }

    /// Staged form of [`commit_app_shards`]: returns the [`AppCommit`] plus all
    /// the raw `(key, value)` puts across the app's shard trees, for the caller to
    /// stage into its own atomic transaction. Aggregation is identical.
    pub fn commit_app_shards_staged(
        &self,
        app_address: &[u8],
        version: u64,
        bits_per_level: u32,
        shards: std::collections::BTreeMap<Vec<u32>, [Vec<(Vec<u8>, Vec<u8>)>; 4]>,
    ) -> Result<(AppCommit, Vec<(Vec<u8>, Vec<u8>)>)> {
        let mut phase_shards: [Vec<(Vec<bool>, [u8; 32])>; 4] = Default::default();
        let mut num_leaves: u64 = 0;
        let mut total_size: u128 = 0;
        let mut puts: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (prefix, phase_leaves) in shards {
            let shard_id = Self::addr_path_shard_id(app_address, &prefix);
            let bits = crate::prefix_to_bits(&prefix, bits_per_level);
            total_size += phase_leaves[Phase::VertexAdds as usize]
                .iter()
                .map(|(_, v)| crate::vertex_leaf_size(v))
                .sum::<u128>();
            for (leaves, phase) in phase_leaves.into_iter().zip(PHASES) {
                let (root, p) =
                    self.commit_shard_phase_raw_staged(&shard_id, phase, version, leaves)?;
                puts.extend(p);
                phase_shards[phase as usize].push((bits.clone(), root));
            }
            num_leaves += self.shard_phase_leaf_count(&shard_id, Phase::VertexAdds, version)?;
        }
        let mut phase_roots = [[0u8; 32]; 4];
        for (p, shards_p) in phase_shards.iter().enumerate() {
            phase_roots[p] = crate::app_root_from_shard_paths(shards_p);
        }
        Ok((
            AppCommit {
                roots: ShardRoots { commitment: rollup_phase_roots(&phase_roots), phase_roots },
                num_leaves,
                total_size,
            },
            puts,
        ))
    }

    /// The number of leaves in a shard/phase tree at `version` — read NATIVELY
    /// from JMT (`get_leaf_count`), which aggregates the subtree leaf count at
    /// every internal node (the "count of leaves under this branch" the verkle
    /// carried). This is the cumulative total, not a per-commit delta.
    pub fn shard_phase_leaf_count(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
    ) -> Result<u64> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let tree = Sha256Jmt::new(&store);
        Ok(tree.get_leaf_count(version)? as u64)
    }

    /// Commit an app's shards (address-path model, DYNAMIC depth) and roll them
    /// into the app commitment. `shards` maps each shard's `prefix` (the
    /// `ShardInfo.prefix`: empty = unsplit single-shard app; `[i]` = QUIL 64-way
    /// shard; deeper as split) → its four phase-leaf sets. `bits_per_level` is 6
    /// (64-way). Each shard's phase tree is raw-key committed; per phase the
    /// shards' roots aggregate via [`crate::app_root_from_shard_paths`] (a sparse
    /// binary Merkle at each shard's prefix bit-path — handles mixed depths) into
    /// an app-phase root; the four roll up to the app commitment.
    ///
    /// The [`AppCommit`] carries the branch metadata your verkle held per node:
    /// `num_leaves` comes for free from JMT's native subtree count
    /// (`get_leaf_count`), summed over the app's shards; `total_size` (which JMT
    /// does NOT track) is accumulated from the VertexAdds leaf-value byte lengths.
    pub fn commit_app_shards(
        &self,
        app_address: &[u8],
        version: u64,
        bits_per_level: u32,
        shards: std::collections::BTreeMap<Vec<u32>, [Vec<(Vec<u8>, Vec<u8>)>; 4]>,
    ) -> Result<AppCommit> {
        let mut phase_shards: [Vec<(Vec<bool>, [u8; 32])>; 4] = Default::default();
        let mut num_leaves: u64 = 0;
        let mut total_size: u128 = 0;
        for (prefix, phase_leaves) in shards {
            let shard_id = Self::addr_path_shard_id(app_address, &prefix);
            let bits = crate::prefix_to_bits(&prefix, bits_per_level);
            // VertexAdds (phase 0) is the state; accumulate its value bytes for
            // `total_size` before the leaves are consumed by the commit.
            total_size += phase_leaves[Phase::VertexAdds as usize]
                .iter()
                .map(|(_, v)| crate::vertex_leaf_size(v))
                .sum::<u128>();
            for (leaves, phase) in phase_leaves.into_iter().zip(PHASES) {
                let root = self.commit_shard_phase_raw(&shard_id, phase, version, leaves)?;
                phase_shards[phase as usize].push((bits.clone(), root));
            }
            // num_leaves: JMT's native cumulative count of the shard's VertexAdds.
            num_leaves += self.shard_phase_leaf_count(&shard_id, Phase::VertexAdds, version)?;
        }
        let mut phase_roots = [[0u8; 32]; 4];
        for (p, shards_p) in phase_shards.iter().enumerate() {
            phase_roots[p] = crate::app_root_from_shard_paths(shards_p);
        }
        Ok(AppCommit {
            roots: ShardRoots { commitment: rollup_phase_roots(&phase_roots), phase_roots },
            num_leaves,
            total_size,
        })
    }

    /// Read the current committed root of a shard/phase tree at `version`
    /// WITHOUT committing — the read side of sync. A syncing node computes its
    /// local root this way to compare against the header's `expected_root`
    /// before deciding whether it needs to pull leaves. `None` if the tree has
    /// no state at or below `version`.
    pub fn shard_phase_root(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
    ) -> Result<Option<[u8; 32]>> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let tree = Sha256Jmt::new(&store);
        Ok(tree.get_root_hash_option(version)?.map(|r| r.0))
    }

    /// Authenticated read of one leaf in a shard/phase tree at `version`:
    /// returns the value (if present) alongside a proof that verifies against
    /// that phase's root.
    pub fn shard_phase_get_with_proof(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, jmt::proof::SparseMerkleProof<Sha256>)> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let tree = Sha256Jmt::new(&store);
        Ok(tree.get_with_proof(KeyHash::with::<Sha256>(key), version)?)
    }

    /// Authenticated read of one leaf in a RAW-KEY (address-path) shard/phase
    /// tree — the proof verifies against the shard's raw-key root via the raw
    /// [`crate::shard_path_key_hash`]. Pairs with [`commit_shard_phase_raw`] /
    /// [`commit_app_shards`] and the app-membership combiner.
    pub fn shard_phase_get_with_proof_raw(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, jmt::proof::SparseMerkleProof<Sha256>)> {
        let store = self.store(&TreeId::shard_phase(shard_id, phase));
        let tree = Sha256Jmt::new(&store);
        Ok(tree.get_with_proof(crate::shard_path_key_hash(key), version)?)
    }

    // ---- Per-tree head version (for version-exact reads) ------------------

    /// The persisted-head-version key for a shard/phase tree: `namespace ‖
    /// 0xFE ‖ shard_phase_prefix`. The `0xFE` marker sits where a tree-id's
    /// level byte (1/2/3) would, so it can never collide with a JMT node/value
    /// key of any forest tree.
    fn head_version_key(namespace: &[u8], shard_id: &[u8], phase: Phase) -> Vec<u8> {
        let tp = TreeId::shard_phase(shard_id, phase).prefix();
        let mut k = Vec::with_capacity(namespace.len() + 1 + tp.len());
        k.extend_from_slice(namespace);
        k.push(0xFE);
        k.extend_from_slice(&tp);
        k
    }

    /// The `(key, value)` a caller should stage (into its own atomic write
    /// batch, alongside the commit's node puts) to persist a shard/phase
    /// tree's head version. `None` for an in-memory forest — there is no DB to
    /// persist into, and the caller's ephemeral map covers that case.
    ///
    /// JMT reads are version-exact (they do not walk back to the latest
    /// version ≤ v), and each phase commits at its own version, so a reader
    /// that only knows a global counter cannot address a specific tree's head.
    /// Persisting the head version lets [`read_head_version`](Self::read_head_version)
    /// answer that after a restart, when any in-process version map is empty.
    pub fn head_version_put(
        &self,
        shard_id: &[u8],
        phase: Phase,
        version: u64,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        match &self.backend {
            Backend::Rocks { namespace, .. } => Some((
                Self::head_version_key(namespace, shard_id, phase),
                version.to_be_bytes().to_vec(),
            )),
            Backend::Mem(_) => None,
        }
    }

    /// Persist a shard/phase tree's head version DIRECTLY (not via a staged
    /// txn) — for the migration converter, which commits trees outside the CRDT.
    /// Without it, migrated state has no head marker and reads as empty once the
    /// live forest version advances past the migration version. No-op for mem.
    pub fn write_head_version(&self, shard_id: &[u8], phase: Phase, version: u64) -> Result<()> {
        if let (Some((k, v)), Backend::Rocks { db, .. }) =
            (self.head_version_put(shard_id, phase, version), &self.backend)
        {
            db.put(&k, &v)?;
        }
        Ok(())
    }

    /// Read a shard/phase tree's persisted head version. `None` for an
    /// in-memory forest, or if the tree has never been committed.
    pub fn read_head_version(&self, shard_id: &[u8], phase: Phase) -> Result<Option<u64>> {
        match &self.backend {
            Backend::Rocks { db, namespace } => {
                let key = Self::head_version_key(namespace, shard_id, phase);
                match db.get(&key)? {
                    Some(v) if v.len() == 8 => {
                        Ok(Some(u64::from_be_bytes(v[..8].try_into().unwrap())))
                    }
                    _ => Ok(None),
                }
            }
            Backend::Mem(_) => Ok(None),
        }
    }

    // ---- Level 1: global bucket head-version tracking --------------------

    /// Synthetic shard id under which a Level-1 global bucket tree's head
    /// version is persisted. The global buckets have no shard/phase of their
    /// own, but reusing the shard/phase head-version keyspace lets both the
    /// migration and the live commit path address them uniformly. The fixed
    /// marker prefix keeps it disjoint from any real 32-byte shard address.
    fn global_head_shard_id(index: u8) -> Vec<u8> {
        let mut s = b"__l1_global_head__".to_vec();
        s.push(index);
        s
    }

    /// Staged `(key, value)` to persist global bucket `index`'s head version
    /// (fold into the commit txn). `None` for a mem forest. Live-path analogue
    /// of [`head_version_put`](Self::head_version_put).
    pub fn global_head_version_put(&self, index: u8, version: u64) -> Option<(Vec<u8>, Vec<u8>)> {
        self.head_version_put(&Self::global_head_shard_id(index), Phase::VertexAdds, version)
    }

    /// Persist global bucket `index`'s head version DIRECTLY — for the
    /// migration converter (mirrors [`write_head_version`](Self::write_head_version)).
    pub fn write_global_head_version(&self, index: u8, version: u64) -> Result<()> {
        self.write_head_version(&Self::global_head_shard_id(index), Phase::VertexAdds, version)
    }

    /// Read global bucket `index`'s persisted head version. `None` if the
    /// bucket has never been committed (or a mem forest).
    pub fn read_global_head_version(&self, index: u8) -> Result<Option<u64>> {
        self.read_head_version(&Self::global_head_shard_id(index), Phase::VertexAdds)
    }

    // ---- Level 2: per-app shard-commitment tree --------------------------

    /// Commit the app's Level-2 shard-commitment tree at `version`. Each
    /// entry is `(shard_id, ShardEntry)`; the leaf key is the shard id, the
    /// value its [`ShardEntry`](crate::ShardEntry) encoding. Returns the app
    /// root (the app's Level-1 [`AppEntry`](crate::AppEntry) commitment).
    pub fn commit_app(
        &self,
        app_address: &[u8],
        version: u64,
        entries: impl IntoIterator<Item = (Vec<u8>, crate::ShardEntry)>,
    ) -> Result<[u8; 32]> {
        let store = self.store(&TreeId::app(app_address));
        let leaves = entries.into_iter().map(|(shard_id, e)| (shard_id, e.to_bytes()));
        Ok(commit_pruning(&store, version, leaves)?.0)
    }

    // ---- Level 1: the 256 global trees -----------------------------------

    /// Commit one of the 256 Level-1 global trees at `version`. Each entry is
    /// `(app_address, AppEntry)`; the leaf key is the app address. Returns the
    /// global tree root. The tree index is the app address's first byte — see
    /// [`global_tree_index`](crate::global_tree_index).
    pub fn commit_global(
        &self,
        index: u8,
        version: u64,
        entries: impl IntoIterator<Item = (Vec<u8>, crate::AppEntry)>,
    ) -> Result<[u8; 32]> {
        let store = self.store(&TreeId::global(index));
        let leaves = entries.into_iter().map(|(addr, e)| (addr, e.to_bytes()));
        Ok(commit_pruning(&store, version, leaves)?.0)
    }

    /// Staged variant of [`commit_global`] for the live commit path: commits
    /// the Level-1 global bucket `index` (leaves = `app_address → AppEntry`,
    /// hashed keys, matching `commit_global`/the migration) at `version` and
    /// returns the root plus the raw KV puts to fold into the caller's commit
    /// transaction (so the L1 update is atomic with the L2/L3 shard commits).
    /// Mirrors [`commit_shard_phase_raw_staged`](Self::commit_shard_phase_raw_staged).
    /// `put_value_set` builds on the tree's prior version, so passing only the
    /// apps TOUCHED this frame upserts them while untouched apps in the bucket
    /// persist.
    pub fn commit_global_staged(
        &self,
        index: u8,
        version: u64,
        entries: impl IntoIterator<Item = (Vec<u8>, crate::AppEntry)>,
    ) -> Result<([u8; 32], Vec<(Vec<u8>, Vec<u8>)>)> {
        let store = self.store(&TreeId::global(index));
        let leaves = entries.into_iter().map(|(addr, e)| (addr, e.to_bytes()));
        let (root, batch) = crate::commit_update(&store, version, leaves)?;
        match &store {
            TreeStore::Rocks(s) => Ok((root.0, s.update_puts(&batch)?)),
            TreeStore::Mem(_) => {
                store.apply_update(&batch)?;
                Ok((root.0, Vec::new()))
            }
        }
    }

    /// The current 32-byte root of the Level-1 global bucket `index` at
    /// `version` (the version it was last committed at — track it via a head
    /// marker, as the shard-phase trees do). `None` when the bucket has never
    /// been committed (no app has that first address byte).
    pub fn global_root(&self, index: u8, version: u64) -> Result<Option<[u8; 32]>> {
        let store = self.store(&TreeId::global(index));
        let tree = Sha256Jmt::new(&store);
        Ok(tree.get_root_hash_option(version)?.map(|r| r.0))
    }

    // ---- Pruning ---------------------------------------------------------

    /// Prune superseded nodes of one tree at or below `min_readable_version`,
    /// returning the node count reclaimed.
    pub fn prune_tree(&self, tree: &TreeId, min_readable_version: u64) -> Result<usize> {
        self.store(tree).prune(min_readable_version)
    }

    /// Prune superseded nodes of one `(shard, phase)` tree at or below
    /// `min_readable_version`, returning the node count reclaimed.
    pub fn prune_shard_phase(
        &self,
        shard_id: &[u8],
        phase: Phase,
        min_readable_version: u64,
    ) -> Result<usize> {
        self.store(&TreeId::shard_phase(shard_id, phase))
            .prune(min_readable_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_path_app_shards_commit_and_leaf_proves_against_app_root() {
        use jmt::RootHash;
        use std::collections::BTreeMap;

        let forest = Forest::in_memory();
        let app = b"quil-app-address-0123456789abcd!".to_vec(); // 32B app address
        let bpl = 6u32; // 64-way levels (QUIL)

        // Two vertices, in QUIL shards prefix [0] and [63] (addr top-6-bits).
        let addr_a = [0x00u8; 32]; // top-6 = 0
        let addr_b = [0xFCu8; 32]; // 0xFC top-6 = 63
        assert_eq!(crate::shard_index(&addr_a, bpl), 0);
        assert_eq!(crate::shard_index(&addr_b, bpl), 63);

        // Per-vertex shard leaf = `commitment(32) ‖ size(u64 BE)` (40B); the
        // aggregated `total_size` reads the `size` field via `vertex_leaf_size`,
        // NOT the leaf-value byte length (which is a constant 40).
        let pv = |commit_byte: u8, size: u64| -> Vec<u8> {
            let mut v = vec![commit_byte; 32];
            v.extend_from_slice(&size.to_be_bytes());
            v
        };
        let val_a = pv(0xAA, 6);
        let val_b = pv(0xBB, 6);
        let empty = || -> [Vec<(Vec<u8>, Vec<u8>)>; 4] { Default::default() };
        let build = |a: &[u8; 32], v: &[u8]| {
            let mut s = empty();
            s[Phase::VertexAdds as usize] = vec![(a.to_vec(), v.to_vec())];
            s
        };
        let shards = || -> BTreeMap<Vec<u32>, [Vec<(Vec<u8>, Vec<u8>)>; 4]> {
            [(vec![0u32], build(&addr_a, &val_a)), (vec![63u32], build(&addr_b, &val_b))]
                .into_iter()
                .collect()
        };

        let app_commit = forest.commit_app_shards(&app, 0, bpl, shards()).unwrap();
        let roots = &app_commit.roots;
        // Branch metadata: 2 leaves (native JMT count), size = 6+6 (the `size`
        // fields of the two per-vertex leaves, via `vertex_leaf_size`).
        assert_eq!(app_commit.num_leaves, 2, "num_leaves from JMT get_leaf_count");
        assert_eq!(app_commit.total_size, 6 + 6);
        // Deterministic re-commit into a fresh forest gives the same app root.
        let app2 = Forest::in_memory().commit_app_shards(&app, 0, bpl, shards()).unwrap();
        assert_eq!(roots.commitment, app2.roots.commitment, "app commitment is deterministic");

        // Read shard roots for the VertexAdds phase (shards keyed by prefix).
        let sid0 = Forest::addr_path_shard_id(&app, &[0]);
        let sid63 = Forest::addr_path_shard_id(&app, &[63]);
        let r0 = forest.shard_phase_root(&sid0, Phase::VertexAdds, 0).unwrap().unwrap();
        let r63 = forest.shard_phase_root(&sid63, Phase::VertexAdds, 0).unwrap().unwrap();

        // (1) coin-A is in shard [0]'s raw-key JMT (leaf → shard root).
        let (val, proof) = forest
            .shard_phase_get_with_proof_raw(&sid0, Phase::VertexAdds, 0, &addr_a)
            .unwrap();
        assert_eq!(val.as_deref(), Some(&val_a[..]));
        proof
            .verify_existence(RootHash(r0), crate::shard_path_key_hash(&addr_a), &val_a)
            .expect("leaf proves against its shard root");

        // (2) the two shard roots aggregate (at their prefix bit-paths) to the
        // app VertexAdds phase root — the same variable-depth aggregation the
        // commit used.
        let aggregated = crate::app_root_from_shard_paths(&[
            (crate::prefix_to_bits(&[0], bpl), r0),
            (crate::prefix_to_bits(&[63], bpl), r63),
        ]);
        assert_eq!(
            aggregated,
            roots.phase_roots[Phase::VertexAdds as usize],
            "shard roots aggregate to the app phase root"
        );
        // A wrong shard root must not reconstruct the app phase root (binding).
        let tampered = crate::app_root_from_shard_paths(&[
            (crate::prefix_to_bits(&[0], bpl), [0xEE; 32]),
            (crate::prefix_to_bits(&[63], bpl), r63),
        ]);
        assert_ne!(tampered, roots.phase_roots[Phase::VertexAdds as usize]);
    }
    use crate::{AppEntry, ShardEntry};

    fn open_db(path: &std::path::Path) -> Arc<rocksdb::DB> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        Arc::new(rocksdb::DB::open(&opts, path).unwrap())
    }

    fn leaves(n: u32, tag: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
        (0..n).map(|i| (i.to_be_bytes().to_vec(), vec![tag ^ i as u8; 40])).collect()
    }

    /// The option-B sync loop end to end at the forest level: a behind target
    /// diffs a source tree (transferring only changed leaves), recovers the
    /// changed vertices via preimages, and applying the diff reaches the source
    /// root. This is the whole commitment + change-detection path in miniature.
    #[test]
    fn sync_diff_preimage_apply_reaches_source_root() {
        let sdir = tempfile::tempdir().unwrap();
        let tdir = tempfile::tempdir().unwrap();
        let source = Forest::new(open_db(sdir.path()));
        let target = Forest::new(open_db(tdir.path()));
        let shard = b"shard-A".to_vec();

        let mk = |v: u8, f: u8| crate::l3_leaf_key(&[v; 64], &[f]);
        let apply_puts = |f: &Forest, puts: Vec<(Vec<u8>, Vec<u8>)>| {
            let db = f.db().unwrap().clone();
            for (k, v) in puts {
                db.put(&k, &v).unwrap();
            }
        };

        // Base state (v0): three vertices, committed to BOTH forests.
        let base: Vec<(Vec<u8>, Vec<u8>)> = (0..3u8).map(|i| (mk(i, 0x04), vec![i; 8])).collect();
        for f in [&source, &target] {
            let (_r, puts) = f
                .commit_shard_phase_staged(&shard, Phase::VertexAdds, 0, base.clone())
                .unwrap();
            apply_puts(f, puts);
        }

        // Source advances (v1): a new vertex 9 + an updated vertex 1.
        let delta: Vec<(Vec<u8>, Vec<u8>)> =
            vec![(mk(9, 0x04), vec![9; 8]), (mk(1, 0x04), vec![0xFF; 8])];
        let (src_root, puts) = source
            .commit_shard_phase_staged(&shard, Phase::VertexAdds, 1, delta)
            .unwrap();
        apply_puts(&source, puts);

        // Diff transfers ONLY the two changed leaves.
        let changed = crate::diff_leaves(
            &source.shard_phase_reader(&shard, Phase::VertexAdds),
            1,
            &target.shard_phase_reader(&shard, Phase::VertexAdds),
            0,
        )
        .unwrap();
        assert_eq!(changed.len(), 2, "only the changed leaves diff");

        // Preimages recover the changed vertices (9 and 1).
        let mut ids = std::collections::HashSet::new();
        for (kh, _) in &changed {
            let raw = source
                .get_preimage(&shard, Phase::VertexAdds, kh.0)
                .unwrap()
                .expect("preimage recorded");
            ids.insert(raw[..64].to_vec());
        }
        assert!(ids.contains(&vec![9u8; 64]));
        assert!(ids.contains(&vec![1u8; 64]));

        // Applying the diff brings the target to the source root. JMT requires
        // a CONTIGUOUS version (base at version-1), so the target's next version
        // is its current (0) + 1.
        let (tgt_root, _) = target
            .apply_synced_shard_phase(&shard, Phase::VertexAdds, 1, changed)
            .unwrap();
        assert_eq!(tgt_root, src_root, "synced target reaches the source root");
    }

    #[test]
    fn preimages_recover_raw_keys_after_commit() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let shard = b"shard-A".to_vec();

        // Two flat leaves keyed by raw l3 keys (vertex_id ‖ field_key style).
        let k1 = crate::l3_leaf_key(&[0x11u8; 64], &[0x04u8]);
        let k2 = crate::l3_leaf_key(&[0x22u8; 64], &[0xFFu8; 32]);
        let leaves = vec![(k1.clone(), b"v1".to_vec()), (k2.clone(), b"v2".to_vec())];

        // Staged commit returns the preimage puts; apply them to the DB.
        let (_root, puts) = forest
            .commit_shard_phase_staged(&shard, Phase::VertexAdds, 0, leaves)
            .unwrap();
        let db = forest.db().unwrap().clone();
        for (k, v) in puts {
            db.put(&k, &v).unwrap();
        }

        // The sync server recovers each raw key from its committed KeyHash.
        use sha2::Sha256;
        for k in [&k1, &k2] {
            let kh = KeyHash::with::<Sha256>(k).0;
            assert_eq!(
                forest.get_preimage(&shard, Phase::VertexAdds, kh).unwrap().as_deref(),
                Some(&k[..]),
                "preimage recovers the raw l3 key"
            );
        }
        // A KeyHash never committed has no preimage.
        assert!(forest
            .get_preimage(&shard, Phase::VertexAdds, [0xEE; 32])
            .unwrap()
            .is_none());

        // Client-side re-record (write_preimage) round-trips too — this is what a
        // synced node does so it can re-serve preimages downstream.
        let synced_key = crate::l3_leaf_key(&[0x55u8; 64], &[0x0c]);
        forest.write_preimage(&shard, Phase::VertexAdds, &synced_key).unwrap();
        let kh = KeyHash::with::<Sha256>(&synced_key).0;
        assert_eq!(
            forest.get_preimage(&shard, Phase::VertexAdds, kh).unwrap().as_deref(),
            Some(&synced_key[..]),
            "write_preimage is recoverable by get_preimage"
        );
    }

    #[test]
    fn rollup_is_deterministic_and_order_sensitive() {
        let a = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let b = [[2u8; 32], [1u8; 32], [3u8; 32], [4u8; 32]];
        assert_eq!(rollup_phase_roots(&a), rollup_phase_roots(&a));
        assert_ne!(rollup_phase_roots(&a), rollup_phase_roots(&b), "order matters");
    }

    #[test]
    fn three_tier_commit_via_driver() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));

        let app_address = vec![0x2a, 0x01, 0x02, 0x03];
        let shard = vec![0xaa, 0x00];

        // Level 3: four phase trees → shard commitment.
        let sr = forest
            .commit_shard(
                &shard,
                0,
                [leaves(30, 0x10), leaves(5, 0x20), leaves(12, 0x30), leaves(2, 0x40)],
            )
            .unwrap();
        assert_eq!(sr.commitment, rollup_phase_roots(&sr.phase_roots));
        // The four phase roots are distinct (different leaf sets).
        assert_ne!(sr.phase_roots[0], sr.phase_roots[1]);

        // Level 2: the shard's commitment becomes an L2 leaf.
        let app_root = forest
            .commit_app(
                &app_address,
                0,
                vec![(
                    shard.clone(),
                    ShardEntry { shard_commitment: sr.commitment, num_leaves: 49, total_size: 1960 },
                )],
            )
            .unwrap();

        // Level 1: the app root becomes a global-tree leaf.
        let g = crate::global_tree_index(&app_address);
        assert_eq!(g, 0x2a);
        let global_root = forest
            .commit_global(
                g,
                0,
                vec![(
                    app_address.clone(),
                    AppEntry { app_root, num_leaves: 49, total_size: 1960, metadata: b"QUIL".to_vec() },
                )],
            )
            .unwrap();
        assert_ne!(global_root, app_root);
        assert_ne!(app_root, sr.commitment);

        // Authenticated read against a phase root verifies.
        let (val, proof) = forest
            .shard_phase_get_with_proof(&shard, Phase::VertexAdds, 0, &3u32.to_be_bytes())
            .unwrap();
        assert!(val.is_some());
        proof
            .verify_existence(
                jmt::RootHash(sr.phase_roots[0]),
                KeyHash::with::<Sha256>(3u32.to_be_bytes()),
                val.as_ref().unwrap(),
            )
            .expect("phase inclusion proof verifies against its state root");
    }

    #[test]
    fn namespaced_forest_coexists_with_colliding_foreign_keys() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(dir.path());
        // Foreign data whose key starts with the bare app-tree level byte
        // (0x02) — exactly what would collide with an un-namespaced forest.
        db.put([0x02u8, 0xAB, 0xCD], b"foreign").unwrap();

        let forest = Forest::with_namespace(db.clone(), vec![0xF7u8]);
        let shard = b"S".to_vec();
        let sr = forest
            .commit_shard(&shard, 0, [leaves(10, 1), vec![], vec![], vec![]])
            .unwrap();

        // The foreign key is untouched by forest writes.
        assert_eq!(
            db.get([0x02u8, 0xAB, 0xCD]).unwrap().as_deref(),
            Some(&b"foreign"[..])
        );
        // A namespaced read still resolves + the commitment is well-formed.
        let (val, _) = forest
            .shard_phase_get_with_proof(&shard, Phase::VertexAdds, 0, &3u32.to_be_bytes())
            .unwrap();
        assert!(val.is_some());
        assert_eq!(sr.commitment, rollup_phase_roots(&sr.phase_roots));

        // A second forest under a DIFFERENT namespace, same shard id, is a
        // disjoint keyspace — its write doesn't clobber the first.
        let forest2 = Forest::with_namespace(db.clone(), vec![0xF8u8]);
        forest2
            .commit_shard(&shard, 0, [leaves(5, 2), vec![], vec![], vec![]])
            .unwrap();
        let (val_after, _) = forest
            .shard_phase_get_with_proof(&shard, Phase::VertexAdds, 0, &7u32.to_be_bytes())
            .unwrap();
        assert_eq!(val_after, Some(vec![1u8 ^ 7u8; 40]), "first forest intact");
    }

    #[test]
    fn shard_phase_root_reads_committed_root_without_committing() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let shard = b"S".to_vec();
        // No state yet → None.
        assert_eq!(
            forest.shard_phase_root(&shard, Phase::VertexAdds, 0).unwrap(),
            None
        );
        // Commit, then the read-side root matches the commit's returned root.
        let committed = forest
            .commit_shard_phase(&shard, Phase::VertexAdds, 0, leaves(15, 0x9))
            .unwrap();
        assert_eq!(
            forest.shard_phase_root(&shard, Phase::VertexAdds, 0).unwrap(),
            Some(committed),
            "read side sees the committed root"
        );
    }

    #[test]
    fn stage_shard_phase_is_atomic_and_matches_direct_commit() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let shard = b"S".to_vec();
        let ls = leaves(20, 0x55);

        // Staged into an external batch: nothing is durable until flushed.
        let mut wb = rocksdb::WriteBatch::default();
        let staged_root = forest
            .stage_shard_phase(&mut wb, &shard, Phase::VertexAdds, 0, ls.clone())
            .unwrap();
        // Before flush, the tree is unreadable (no root committed).
        let store = RocksTreeStore::new(forest.db().unwrap().clone(), &TreeId::shard_phase(&shard, Phase::VertexAdds));
        assert!(
            Sha256Jmt::new(&store)
                .get(KeyHash::with::<Sha256>(3u32.to_be_bytes()), 0)
                .unwrap()
                .is_none(),
            "staged writes are not visible until the batch is flushed"
        );
        // Flush → durable, and the leaf reads back.
        forest.db().unwrap().write(wb).unwrap();
        assert_eq!(
            Sha256Jmt::new(&store).get(KeyHash::with::<Sha256>(3u32.to_be_bytes()), 0).unwrap(),
            Some(vec![0x55u8 ^ 3u8; 40])
        );

        // The staged root equals a direct commit of the same leaves.
        let dir2 = tempfile::tempdir().unwrap();
        let forest2 = Forest::new(open_db(dir2.path()));
        let direct_root = forest2
            .commit_shard_phase(&shard, Phase::VertexAdds, 0, ls)
            .unwrap();
        assert_eq!(staged_root, direct_root, "staging must not change the root");
    }

    #[test]
    fn head_version_persists_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let shard = b"S".to_vec();
        // Commit vertex-adds at version 7, then persist its head version.
        forest.commit_shard_phase(&shard, Phase::VertexAdds, 7, leaves(5, 1)).unwrap();
        let (k, v) = forest.head_version_put(&shard, Phase::VertexAdds, 7).unwrap();
        forest.db().unwrap().put(&k, &v).unwrap();

        assert_eq!(forest.read_head_version(&shard, Phase::VertexAdds).unwrap(), Some(7));
        // Distinct phase / shard have no head version recorded.
        assert_eq!(forest.read_head_version(&shard, Phase::VertexRemoves).unwrap(), None);
        assert_eq!(forest.read_head_version(b"other", Phase::VertexAdds).unwrap(), None);

        // The head-version key never collides with a JMT node/value key: the
        // committed leaf still reads back after the head-version put.
        let store = RocksTreeStore::new(
            forest.db().unwrap().clone(),
            &TreeId::shard_phase(&shard, Phase::VertexAdds),
        );
        assert!(Sha256Jmt::new(&store)
            .get(KeyHash::with::<Sha256>(3u32.to_be_bytes()), 7)
            .unwrap()
            .is_some());
    }

    #[test]
    fn head_version_mem_forest_is_none() {
        let forest = Forest::in_memory();
        assert!(forest.head_version_put(b"S", Phase::VertexAdds, 3).is_none());
        assert_eq!(forest.read_head_version(b"S", Phase::VertexAdds).unwrap(), None);
    }

    #[test]
    fn prune_reclaims_superseded_nodes_below_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let shard = b"S".to_vec();

        // Version 0, then overwrite the same keys at versions 1 and 2.
        for v in 0..=2u64 {
            forest
                .commit_shard_phase(&shard, Phase::VertexAdds, v, leaves(20, v as u8))
                .unwrap();
        }

        // Pruning below version 2 must reclaim nodes superseded at v1/v2, and
        // reads at the retained head must still resolve.
        let tree = TreeId::shard_phase(&shard, Phase::VertexAdds);
        let reclaimed = forest.prune_tree(&tree, 2).unwrap();
        assert!(reclaimed > 0, "expected superseded nodes to be reclaimed");

        let store = RocksTreeStore::new(forest.db().unwrap().clone(), &tree);
        let jmt_tree = Sha256Jmt::new(&store);
        let got = jmt_tree.get(KeyHash::with::<Sha256>(3u32.to_be_bytes()), 2).unwrap();
        assert_eq!(got, Some(vec![2u8 ^ 3u8; 40]), "head read survives pruning");

        // A second prune at the same watermark reclaims nothing new.
        assert_eq!(forest.prune_tree(&tree, 2).unwrap(), 0);
    }

    #[test]
    fn prune_keeps_nodes_still_readable_above_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let shard = b"S".to_vec();
        for v in 0..=3u64 {
            forest
                .commit_shard_phase(&shard, Phase::VertexAdds, v, leaves(10, v as u8))
                .unwrap();
        }
        let tree = TreeId::shard_phase(&shard, Phase::VertexAdds);
        // Watermark at version 1: nodes stale since 2 or 3 must survive.
        forest.prune_tree(&tree, 1).unwrap();
        let store = RocksTreeStore::new(forest.db().unwrap().clone(), &tree);
        let jmt_tree = Sha256Jmt::new(&store);
        // A read pinned at version 1 still resolves (its nodes were retained).
        let got = jmt_tree.get(KeyHash::with::<Sha256>(3u32.to_be_bytes()), 1).unwrap();
        assert_eq!(got, Some(vec![1u8 ^ 3u8; 40]));
    }
}
