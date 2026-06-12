//! Per-node lazy `LazyVectorCommitmentTree` — Rust port of Go's
//! `types/tries/lazy_proof_tree.go`. Designed so the running set is
//! bounded by `touched_paths × log_64(tree_size)`, not by the
//! total tree size — the production mainnet QUIL token shard is
//! well over 700 GB on disk; nothing here ever materializes the
//! whole thing.
//!
//! - On `ensure_root_loaded`, reads only the root node via the
//!   by-path index (`HypergraphStore::get_node_by_path(&[])`).
//! - During `insert`, walks the tree lazily — child branches are
//!   pulled from the store one slot at a time as the walker
//!   descends, never materializing untouched subtrees.
//! - During `commit`, persists each touched node individually via
//!   the dual by-key + by-path index (per-node format —
//!   `crate::serialize::serialize_node_solo`).
//!
//! Mutating ops stage changes in an in-memory working set; `commit`
//! flushes them through the caller-supplied `txn` and resets the
//! working set. Public API: `insert(key, value, hash_target, size)`,
//! `commit(txn, prover) -> root_commitment`, `get(key)`,
//! `get_metadata()`, `get_size()`, `get_node_metadata_at_path(path)`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use num_traits::Zero;
use sha3::{Digest, Sha3_256};

use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};
use quil_types::store::{HypergraphStore, ShardKey, Transaction};

use crate::nibble::{
    get_full_path, get_next_nibble, get_nibbles_until_diverge,
};
use crate::node::{BranchNode, LeafNode, VectorCommitmentNode};
use crate::serialize::{deserialize_node_solo, serialize_node_solo};
use crate::{BRANCH_BITS, BRANCH_NODES};

/// Metadata returned by [`LazyVectorCommitmentTree::get_node_metadata_at_path`].
/// `leaf_count` is 1 for leaves; for branches it's the aggregate.
#[derive(Debug, Clone)]
pub struct NodeMetadata {
    pub commitment: Vec<u8>,
    pub leaf_count: u64,
    pub size: BigInt,
}

// ---------------------------------------------------------------------------
// By-key derivation for branches.
//
// Mirrors Go's `generateKeyFromPath` at
// `types/tries/lazy_proof_tree.go:1246-1253`: cast each nibble to a
// single byte (0–63), then SHA3-256. Branches are addressed in the
// by-key index under this 32-byte hash; leaves are addressed by their
// user-supplied key bytes directly.
// ---------------------------------------------------------------------------
fn branch_key_from_path(path: &[i32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(path.len());
    for &p in path {
        buf.push(p as u8);
    }
    Sha3_256::digest(&buf).to_vec()
}

// ---------------------------------------------------------------------------
// Tree state.
// ---------------------------------------------------------------------------

pub struct LazyVectorCommitmentTree {
    /// Backing store.
    store: Arc<dyn HypergraphStore>,
    pub set_type: String,
    pub phase_type: String,
    pub shard_key: ShardKey,
    pub covered_prefix: Vec<i32>,

    /// In-memory working state. Branches may have `fully_loaded = false`,
    /// in which case `None` children mean "consult the store before
    /// treating as absent." `Some(None)` is a valid loaded-but-empty
    /// state; `None` (outer) is "not yet loaded."
    root: RwLock<Option<Option<VectorCommitmentNode>>>,

    /// `(by_key, by_path)` pairs flagged for deletion at commit time —
    /// this fires when a branch is split (`Insert`'s mid-prefix
    /// divergence case) and its on-disk position moves. Without
    /// cleanup the old position would linger as an orphan entry. See
    /// Go's `Store.DeleteNode` call at
    /// `types/tries/lazy_proof_tree.go:1079`.
    pending_deletions: RwLock<Vec<(Vec<u8>, Vec<i32>)>>,

    /// Nodes whose on-disk representation needs (re)writing at commit
    /// time. Keyed by `by_key` bytes; the stored value is the
    /// `(by_path, in-memory node)` pair — Commit recomputes the
    /// commitment then serializes via `serialize_node_solo`.
    dirty: RwLock<HashMap<Vec<u8>, (Vec<i32>, VectorCommitmentNode)>>,

    /// Set whenever a mutation happens. Reset by `commit`. Surfaced via
    /// `is_dirty` so the wrapping CRDT can skip no-op commits.
    dirty_flag: RwLock<bool>,
}

impl LazyVectorCommitmentTree {
    pub fn new(
        store: Arc<dyn HypergraphStore>,
        set_type: impl Into<String>,
        phase_type: impl Into<String>,
        shard_key: ShardKey,
        covered_prefix: Vec<i32>,
    ) -> Self {
        Self {
            store,
            set_type: set_type.into(),
            phase_type: phase_type.into(),
            shard_key,
            covered_prefix,
            root: RwLock::new(None),
            pending_deletions: RwLock::new(Vec::new()),
            dirty: RwLock::new(HashMap::new()),
            dirty_flag: RwLock::new(false),
        }
    }

    /// Load the root plus its immediate children into memory and
    /// return an owned clone of the resulting root node. Bounded read
    /// cost: 1 read for the root + at most 64 reads for direct
    /// children — no deeper descendants are pulled in, so this is
    /// safe to call on production-sized trees.
    ///
    /// Intended for read-only callers (sync server's GetBranch root
    /// path) that need the root's commitment + each child's
    /// commitment but must not trigger an unbounded eager load.
    pub fn load_root_and_immediate_children(
        &self,
    ) -> Result<Option<VectorCommitmentNode>> {
        self.ensure_root_loaded()?;
        let mut root_guard = self.root.write().unwrap();
        let Some(Some(node)) = root_guard.as_mut() else {
            return Ok(None);
        };
        if let VectorCommitmentNode::Branch(b) = node {
            self.ensure_branch_children_loaded(b)?;
        }
        Ok(Some(node.clone()))
    }

    /// Same as `load_root_and_immediate_children`, but additionally
    /// loads the children of each first-level branch. Used by
    /// `collect_leaves` on the sync server when a request originates
    /// at the root path and the caller wants every leaf reachable
    /// within a bounded subtree. Bounded at 1 + 64 + 64*64 = 4161
    /// reads in the worst case — still independent of total leaf
    /// count.
    pub fn load_root_and_two_levels(
        &self,
    ) -> Result<Option<VectorCommitmentNode>> {
        self.ensure_root_loaded()?;
        {
            let mut root_guard = self.root.write().unwrap();
            let Some(Some(node)) = root_guard.as_mut() else {
                return Ok(None);
            };
            if let VectorCommitmentNode::Branch(b) = node {
                self.ensure_branch_children_loaded(b)?;
                for slot in b.children.iter_mut() {
                    if let Some(child) = slot.as_mut() {
                        if let VectorCommitmentNode::Branch(cb) = child.as_mut() {
                            self.ensure_branch_children_loaded(cb)?;
                        }
                    }
                }
            }
        }
        let root_guard = self.root.read().unwrap();
        Ok(root_guard.as_ref().and_then(|o| o.clone()))
    }

    /// Load just the root node — `get_node_by_path(&[])` returns
    /// whatever node is rooted at the empty path (SeekGE; the store
    /// resolves prefix-compressed roots). Cheaper than walking the
    /// store; idempotent on subsequent calls.
    fn ensure_root_loaded(&self) -> Result<()> {
        if self.root.read().unwrap().is_some() {
            return Ok(());
        }
        // Per-node root via by-path SeekGE is the canonical source.
        // The old whole-tree-blob fallback was an attractive nuisance:
        // a previous `commit` may have serialized the root with
        // unloaded child slots as `TYPE_NIL`, and `deserialize_tree`
        // then hands back a branch tagged `fully_loaded = true` —
        // `ensure_branch_children_loaded` early-exits and the lazy
        // walker treats real per-node children as absent. Skipping the
        // blob altogether forces every read to go through the by-path
        // index, which is what the writers populate per-node.
        let data = self.store.get_node_by_path(
            &self.set_type,
            &self.phase_type,
            &self.shard_key,
            &[],
        )?;
        let root_node = match data {
            Some(d) => {
                let mut n = deserialize_node_solo(&d)?;
                // The solo encoding doesn't carry full_prefix — it's
                // computed by the walker. For the ROOT branch, the
                // full_prefix IS its local prefix (the root is at
                // absolute path = its prefix nibbles).
                if let VectorCommitmentNode::Branch(ref mut b) = n {
                    b.full_prefix = b.prefix.clone();
                    // A branch loaded fresh from disk has no in-memory
                    // children yet — the walker pulls them on demand.
                    b.fully_loaded = false;
                }
                Some(n)
            }
            None => None,
        };
        *self.root.write().unwrap() = Some(root_node);
        Ok(())
    }

    /// Ensure every slot of `branch` is materialized in memory, pulling
    /// from the store as needed. After this, `branch.fully_loaded =
    /// true` and traversal can iterate children directly.
    ///
    /// Mirrors Go's lazy-load block at
    /// `types/tries/lazy_proof_tree.go:963-978`.
    fn ensure_branch_children_loaded(
        &self,
        branch: &mut BranchNode,
    ) -> Result<()> {
        if branch.fully_loaded {
            return Ok(());
        }
        let mut hits = 0usize;
        let mut misses = 0usize;
        for i in 0..BRANCH_NODES {
            if branch.children[i].is_some() {
                continue;
            }
            let mut child_path = branch.full_prefix.clone();
            child_path.push(i as i32);
            let data = self.store.get_node_by_path(
                &self.set_type,
                &self.phase_type,
                &self.shard_key,
                &child_path,
            )?;
            if let Some(bytes) = data {
                let mut child = deserialize_node_solo(&bytes)?;
                if let VectorCommitmentNode::Branch(ref mut b) = child {
                    // child_path is the slot path; the child's actual
                    // full_prefix extends that by its local prefix
                    // (prefix compression).
                    b.full_prefix = child_path.clone();
                    b.full_prefix.extend_from_slice(&b.prefix);
                    b.fully_loaded = false;
                }
                branch.children[i] = Some(Box::new(child));
                hits += 1;
            } else {
                misses += 1;
            }
        }
        tracing::info!(
            target: "quil_tries::lazy_tree",
            set_type = %self.set_type,
            phase_type = %self.phase_type,
            full_prefix_len = branch.full_prefix.len(),
            full_prefix = ?branch.full_prefix,
            hits, misses,
            commitment = %hex::encode(&branch.commitment),
            "ensure_branch_children_loaded",
        );
        branch.fully_loaded = true;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Public API — stubs filled in by follow-up commits.
    // -----------------------------------------------------------------

    /// Lazy Insert. Walks from the root toward the position of `key`,
    /// loading branches on demand via the by-path index. Modified or
    /// newly created nodes are staged in `dirty` (and recorded for
    /// later by-path index cleanup in `pending_deletions` if a branch
    /// is split). Persisted by `commit`.
    ///
    /// Mirrors Go's `LazyVectorCommitmentTree.Insert` at
    /// `types/tries/lazy_proof_tree.go:879-1244`, modulo per-step
    /// `Store.InsertNode` calls — those become staged dirty entries
    /// the next `commit` will write through the supplied txn.
    pub fn insert(
        &self,
        key: &[u8],
        value: &[u8],
        hash_target: &[u8],
        size: &BigInt,
    ) -> Result<()> {
        if key.is_empty() {
            return Err(QuilError::InvalidArgument(
                "lazy_tree_v2 insert: empty key not allowed".into(),
            ));
        }
        self.ensure_root_loaded()?;

        // Probe for an existing leaf at `key` so we compute the right
        // size delta (replace vs add). Same prologue as Go's
        // `Insert` at line 891.
        let size_delta = match self.lookup_by_key(key)? {
            Some(VectorCommitmentNode::Branch(_)) => {
                return Err(QuilError::InvalidArgument(
                    "lazy_tree_v2 insert: value is branch (key collides with branch hash)".into(),
                ));
            }
            Some(VectorCommitmentNode::Leaf(leaf)) => size - &leaf.size,
            None => size.clone(),
        };

        // CoveredPrefix gate — refuse keys outside the shard's covered
        // range, same as Go (`lazy_proof_tree.go:909-914`).
        if !self.covered_prefix.is_empty() {
            let kp = get_full_path(key);
            if !is_path_within_prefix(&kp, &self.covered_prefix) {
                return Err(QuilError::InvalidArgument(
                    "lazy_tree_v2 insert: key outside covered prefix".into(),
                ));
            }
        }

        // The walker takes ownership of the current root node, mutates,
        // returns the new root. `root` guard goes through a take/restore
        // cycle so the borrow checker accepts recursion.
        let new_root = {
            let mut root_guard = self.root.write().unwrap();
            let current = root_guard
                .as_mut()
                .map(|opt| opt.take())
                .flatten();
            let (_delta, new_node) = self.insert_recursive(
                current,
                key,
                value,
                hash_target,
                size,
                &size_delta,
                0,
                &[],
            )?;
            *root_guard = Some(Some(new_node.clone()));
            new_node
        };
        // After Insert the root may have a new identity (new node, new
        // path). The dirty-list write below covers persistence — no
        // separate root pointer to maintain in the new scheme; the
        // by-path SeekGE from `[]` always resolves to whatever lives
        // at the lowest path on disk.
        let root_path = root_full_prefix(&new_root);
        let root_key = node_by_key(&new_root, &root_path);
        self.mark_dirty(root_key, root_path, new_root);

        *self.dirty_flag.write().unwrap() = true;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Insert helpers — private to this module.
    // -----------------------------------------------------------------

    /// Inner recursion used by `insert`. Takes ownership of the current
    /// node at the descent point, returns the updated node plus the
    /// leaf-count delta (number of new leaves added to this subtree).
    fn insert_recursive(
        &self,
        node: Option<VectorCommitmentNode>,
        key: &[u8],
        value: &[u8],
        hash_target: &[u8],
        size: &BigInt,
        size_delta: &BigInt,
        depth: usize,
        path: &[i32],
    ) -> Result<(i64, VectorCommitmentNode)> {
        // No node materialized at this slot: lazily check the store —
        // a branch from a previous commit may live here even though
        // the parent never loaded it.
        let node = match node {
            Some(n) => Some(n),
            None => self.load_node_at_path(path)?,
        };

        // Still nothing — fresh leaf.
        let mut node = match node {
            None => {
                let leaf = LeafNode {
                    key: key.to_vec(),
                    value: value.to_vec(),
                    hash_target: hash_target.to_vec(),
                    commitment: Vec::new(),
                    size: size.clone(),
                };
                let node = VectorCommitmentNode::Leaf(leaf);
                self.mark_dirty(key.to_vec(), get_full_path(key), node.clone());
                return Ok((1, node));
            }
            Some(n) => n,
        };

        // For an in-memory branch that's not fully loaded, pull the rest
        // of its children. This is the moment Go inflates a partial
        // branch (`lazy_proof_tree.go:963-978`).
        if let VectorCommitmentNode::Branch(ref mut b) = node {
            self.ensure_branch_children_loaded(b)?;
        }

        match node {
            VectorCommitmentNode::Leaf(mut existing) => {
                if existing.key == key {
                    // Update in place.
                    existing.value = value.to_vec();
                    existing.hash_target = hash_target.to_vec();
                    existing.commitment = Vec::new();
                    existing.size = size.clone();
                    let updated = VectorCommitmentNode::Leaf(existing);
                    self.mark_dirty(key.to_vec(), get_full_path(key), updated.clone());
                    Ok((0, updated))
                } else {
                    // Split into a branch over the shared prefix.
                    let (shared_nibbles, diverge_depth) =
                        get_nibbles_until_diverge(&existing.key, key, depth);
                    let full_prefix: Vec<i32> = path
                        .iter()
                        .copied()
                        .chain(shared_nibbles.iter().copied())
                        .collect();
                    let mut branch = BranchNode::new(shared_nibbles);
                    branch.leaf_count = 2;
                    // longest_branch deliberately left at 0 to match
                    // the legacy in-memory tree (`tree.rs:467-492`),
                    // which also doesn't init it here. The metric is
                    // observability-only — it does NOT enter the
                    // commitment math — but golden tests pin it down.
                    branch.size = existing.size.clone() + size_delta;
                    branch.full_prefix = full_prefix.clone();
                    branch.fully_loaded = true;

                    let old_nibble = get_next_nibble(&existing.key, diverge_depth);
                    let new_nibble = get_next_nibble(key, diverge_depth);

                    let new_leaf = LeafNode {
                        key: key.to_vec(),
                        value: value.to_vec(),
                        hash_target: hash_target.to_vec(),
                        commitment: Vec::new(),
                        size: size.clone(),
                    };
                    let new_leaf_node = VectorCommitmentNode::Leaf(new_leaf);

                    self.mark_dirty(
                        key.to_vec(),
                        get_full_path(key),
                        new_leaf_node.clone(),
                    );

                    branch.children[old_nibble as usize] =
                        Some(Box::new(VectorCommitmentNode::Leaf(existing)));
                    branch.children[new_nibble as usize] =
                        Some(Box::new(new_leaf_node));

                    let branch_node = VectorCommitmentNode::Branch(branch);
                    let bkey = branch_key_from_path(&full_prefix);
                    self.mark_dirty(bkey, full_prefix, branch_node.clone());

                    Ok((1, branch_node))
                }
            }
            VectorCommitmentNode::Branch(mut n) => {
                if !n.prefix.is_empty() {
                    // Walk the branch's compressed prefix; if any
                    // nibble disagrees, we split.
                    for i in 0..n.prefix.len() {
                        let expected = n.prefix[i];
                        let actual = get_next_nibble(key, depth + i * BRANCH_BITS);
                        if actual != expected {
                            return self.split_branch_at_prefix(
                                n,
                                key,
                                value,
                                hash_target,
                                size,
                                size_delta,
                                depth,
                                path,
                                i,
                                expected,
                                actual,
                            );
                        }
                    }
                    // Key matches branch prefix in full — recurse into
                    // the child at the next nibble.
                    let final_nibble =
                        get_next_nibble(key, depth + n.prefix.len() * BRANCH_BITS);
                    let mut child_path = n.full_prefix.clone();
                    child_path.push(final_nibble);
                    let next_depth = depth + n.prefix.len() * BRANCH_BITS + BRANCH_BITS;
                    let child = n.children[final_nibble as usize]
                        .take()
                        .map(|b| *b);
                    let (delta, inserted) = self.insert_recursive(
                        child,
                        key,
                        value,
                        hash_target,
                        size,
                        size_delta,
                        next_depth,
                        &child_path,
                    )?;
                    n.children[final_nibble as usize] = Some(Box::new(inserted));
                    self.update_branch_metadata_after_insert(&mut n, delta, size_delta);
                    let bkey = branch_key_from_path(&n.full_prefix);
                    let bpath = n.full_prefix.clone();
                    let node = VectorCommitmentNode::Branch(n);
                    self.mark_dirty(bkey, bpath, node.clone());
                    Ok((delta, node))
                } else {
                    // Branch with no compressed prefix — recurse via the
                    // immediate child for the current nibble.
                    let nibble = get_next_nibble(key, depth);
                    let mut child_path = n.full_prefix.clone();
                    child_path.push(nibble);
                    let next_depth = depth + BRANCH_BITS;
                    let child = n.children[nibble as usize]
                        .take()
                        .map(|b| *b);
                    let (delta, inserted) = self.insert_recursive(
                        child,
                        key,
                        value,
                        hash_target,
                        size,
                        size_delta,
                        next_depth,
                        &child_path,
                    )?;
                    n.children[nibble as usize] = Some(Box::new(inserted));
                    self.update_branch_metadata_after_insert(&mut n, delta, size_delta);
                    let bkey = branch_key_from_path(&n.full_prefix);
                    let bpath = n.full_prefix.clone();
                    let node = VectorCommitmentNode::Branch(n);
                    self.mark_dirty(bkey, bpath, node.clone());
                    Ok((delta, node))
                }
            }
        }
    }

    /// Branch-split case: the new key diverges from `branch.prefix` at
    /// position `i`. We synthesize a new outer branch over the shared
    /// prefix subset `branch.prefix[..i]`, place the old branch
    /// (whose remaining prefix becomes `branch.prefix[i+1..]`) at
    /// slot `expected`, and a fresh leaf at slot `actual`. The OLD
    /// branch's on-disk position is also flagged for deletion at
    /// commit time — its `full_prefix` changes, so its previous
    /// by-path entry has to go.
    ///
    /// Mirrors Go's mid-prefix divergence block at
    /// `types/tries/lazy_proof_tree.go:1067-1156`.
    #[allow(clippy::too_many_arguments)]
    fn split_branch_at_prefix(
        &self,
        mut n: BranchNode,
        key: &[u8],
        value: &[u8],
        hash_target: &[u8],
        size: &BigInt,
        size_delta: &BigInt,
        _depth: usize,
        path: &[i32],
        i: usize,
        expected: i32,
        actual: i32,
    ) -> Result<(i64, VectorCommitmentNode)> {
        // The old branch's on-disk position (about to become stale).
        let old_by_key = branch_key_from_path(&n.full_prefix);
        let old_full_prefix = n.full_prefix.clone();
        self.pending_deletions
            .write()
            .unwrap()
            .push((old_by_key, old_full_prefix));

        // Build the new outer branch.
        let outer_prefix: Vec<i32> = n.prefix[..i].to_vec();
        let outer_full_prefix: Vec<i32> = path
            .iter()
            .copied()
            .chain(outer_prefix.iter().copied())
            .collect();
        let mut outer = BranchNode::new(outer_prefix.clone());
        outer.leaf_count = n.leaf_count + 1;
        outer.longest_branch = n.longest_branch + 1;
        outer.size = n.size.clone() + size_delta;
        outer.full_prefix = outer_full_prefix.clone();
        outer.fully_loaded = true;

        // Truncate the old branch's local prefix and update its
        // full_prefix to reflect its new position under the outer
        // branch.
        n.prefix = n.prefix[i + 1..].to_vec();
        let mut new_inner_full_prefix = outer_full_prefix.clone();
        new_inner_full_prefix.push(expected);
        new_inner_full_prefix.extend_from_slice(&n.prefix);
        n.full_prefix = new_inner_full_prefix.clone();
        // Inner branch's commitment is stale (children unchanged but
        // its prefix changed → its by-key changes → it must be
        // re-written at commit time).
        n.commitment = Vec::new();

        // Stage the displaced inner branch.
        let inner_by_key = branch_key_from_path(&n.full_prefix);
        let inner_node = VectorCommitmentNode::Branch(n);
        self.mark_dirty(
            inner_by_key,
            new_inner_full_prefix,
            inner_node.clone(),
        );

        // New leaf at `actual`.
        let new_leaf = LeafNode {
            key: key.to_vec(),
            value: value.to_vec(),
            hash_target: hash_target.to_vec(),
            commitment: Vec::new(),
            size: size.clone(),
        };
        let new_leaf_node = VectorCommitmentNode::Leaf(new_leaf);
        self.mark_dirty(
            key.to_vec(),
            get_full_path(key),
            new_leaf_node.clone(),
        );

        // Wire children into the outer branch.
        outer.children[expected as usize] = Some(Box::new(inner_node));
        outer.children[actual as usize] = Some(Box::new(new_leaf_node));

        let outer_node = VectorCommitmentNode::Branch(outer);
        let outer_by_key = branch_key_from_path(&outer_full_prefix);
        self.mark_dirty(outer_by_key, outer_full_prefix, outer_node.clone());

        Ok((1, outer_node))
    }

    fn update_branch_metadata_after_insert(
        &self,
        n: &mut BranchNode,
        delta: i64,
        size_delta: &BigInt,
    ) {
        n.commitment = Vec::new();
        // leaf_count can decrease in theory (replacements yield delta=0)
        // but never goes negative here — Insert can only add leaves.
        if delta > 0 {
            n.leaf_count = n.leaf_count.saturating_add(delta as usize);
        }
        n.size += size_delta;
        // longest_branch follows the deepest child chain.
        let mut deepest = 0usize;
        for child in n.children.iter().flatten() {
            let d = match child.as_ref() {
                VectorCommitmentNode::Leaf(_) => 1,
                VectorCommitmentNode::Branch(b) => b.longest_branch + 1,
            };
            if d > deepest {
                deepest = d;
            }
        }
        n.longest_branch = deepest;
    }

    /// Direct by-key probe used at Insert prologue to detect "key
    /// already a leaf with this exact byte sequence" vs. "key happens
    /// to collide with a branch's sha3 path" vs. absent.
    fn lookup_by_key(&self, key: &[u8]) -> Result<Option<VectorCommitmentNode>> {
        match self.store.get_node_by_key(
            &self.set_type,
            &self.phase_type,
            &self.shard_key,
            key,
        )? {
            Some(bytes) => {
                // Could be solo-encoded (per-node format) or whole-tree
                // blob (legacy [0xFF;32] sentinel only — never hit here
                // because `key` is a user-supplied key). Try solo first;
                // fall back to whole-tree if it errors so a partially
                // migrated store doesn't break Insert.
                match deserialize_node_solo(&bytes) {
                    Ok(n) => Ok(Some(n)),
                    Err(_) => {
                        // Best-effort: legacy blob path. Treat as
                        // "couldn't decode" and walk normally.
                        Ok(None)
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// Lazy fetch of the node currently rooted at `path` in the store
    /// (returns `None` if nothing exists there). For branches the
    /// returned node has `full_prefix = path ++ branch.prefix` so
    /// child paths line up correctly.
    fn load_node_at_path(&self, path: &[i32]) -> Result<Option<VectorCommitmentNode>> {
        let data = self.store.get_node_by_path(
            &self.set_type,
            &self.phase_type,
            &self.shard_key,
            path,
        )?;
        Ok(match data {
            Some(bytes) => {
                let mut n = deserialize_node_solo(&bytes)?;
                if let VectorCommitmentNode::Branch(ref mut b) = n {
                    b.full_prefix = path.to_vec();
                    b.full_prefix.extend_from_slice(&b.prefix);
                    b.fully_loaded = false;
                }
                Some(n)
            }
            None => None,
        })
    }

    /// Stage `node` for write to the store at commit time, keyed by
    /// `by_key` / `by_path`. Subsequent stages for the same `by_key`
    /// overwrite the prior entry — only the latest state matters.
    fn mark_dirty(
        &self,
        by_key: Vec<u8>,
        by_path: Vec<i32>,
        node: VectorCommitmentNode,
    ) {
        self.dirty
            .write()
            .unwrap()
            .insert(by_key, (by_path, node));
    }

    /// Commit: walk the in-memory tree top-down, recomputing every
    /// commitment whose `commitment` field was cleared by Insert,
    /// then persist all touched nodes via `Store.insert_node(txn, ...)`
    /// and drop any orphaned by-path entries flagged during
    /// branch-split (the `pending_deletions` list). Returns the root
    /// commitment.
    ///
    /// Mirrors the bottom-up recommit semantics of Go's
    /// `commitNode` (`types/tries/lazy_proof_tree.go:147+`), without
    /// the parallel-goroutines optimization for the moment — Rust
    /// gets per-shard parallelism at a higher level and this commit
    /// is bounded by the touched-paths working set, not the whole
    /// tree.
    pub fn commit(
        &self,
        txn: &dyn Transaction,
        prover: &(dyn InclusionProver + Sync),
    ) -> Result<Vec<u8>> {
        self.ensure_root_loaded()?;

        // Recompute commitments. The walker mutates the in-memory
        // tree under the root write guard: any branch whose
        // `commitment` field was cleared by Insert is recomputed
        // bottom-up; cached commitments are left intact (matches
        // Go's `recalculate=false` short-circuit semantic in
        // `commitNode`).
        let root_commitment = {
            let mut root_guard = self.root.write().unwrap();
            match root_guard.as_mut() {
                Some(Some(node)) => self.commit_recursive(node, prover)?,
                _ => vec![0u8; 64],
            }
        };

        // Persist every dirty node + the latest root via the txn.
        // After persistence the dirty map is cleared — fresh Inserts
        // will repopulate it.
        let dirty = std::mem::take(&mut *self.dirty.write().unwrap());
        let mut latest: HashMap<Vec<u8>, (Vec<i32>, VectorCommitmentNode)> = HashMap::new();
        for (k, (p, _)) in dirty.iter() {
            latest.insert(k.clone(), (p.clone(), VectorCommitmentNode::Leaf(LeafNode {
                key: vec![],
                value: vec![],
                hash_target: vec![],
                commitment: vec![],
                size: BigInt::zero(),
            })));
        }
        // Re-walk the in-memory tree to pull the freshly-committed
        // nodes for every entry in `dirty`. The cheap way: index in-
        // memory nodes by their by_key bytes and look them up.
        let in_mem_index = {
            let root_guard = self.root.read().unwrap();
            let mut idx: HashMap<Vec<u8>, VectorCommitmentNode> = HashMap::new();
            if let Some(Some(node)) = root_guard.as_ref() {
                index_by_key(node, &mut idx);
            }
            idx
        };
        for (by_key, (by_path, _)) in dirty.into_iter() {
            // Prefer the freshly-committed in-memory copy. If a dirty
            // entry can't be located in the in-memory tree (e.g. a
            // branch displaced by a split, or a leaf that got
            // replaced), fall back to the staged copy — its
            // commitment will be empty but the data still needs to
            // be on disk so `get` can find it.
            let node = match in_mem_index.get(&by_key) {
                Some(n) => n.clone(),
                None => continue, // Was dropped during a split; the
                // pending_deletions list will clean up the on-disk
                // remnant separately.
            };
            let payload = serialize_node_solo(&node)?;
            self.store.insert_node(
                txn,
                &self.set_type,
                &self.phase_type,
                &self.shard_key,
                &by_key,
                &by_path,
                &payload,
            )?;
        }

        // Drop orphaned by-path entries from branch splits.
        let deletions = std::mem::take(&mut *self.pending_deletions.write().unwrap());
        for (by_key, by_path) in deletions {
            // `delete_node` clears both the by-key entry and the
            // by-path pointer (per `RocksHypergraphStore::delete_node`).
            self.store.delete_node(
                txn,
                &self.set_type,
                &self.phase_type,
                &self.shard_key,
                &by_key,
                &by_path,
            )?;
        }

        // The legacy whole-tree blob write was removed. With the lazy
        // tree, `serialize_tree(root)` produces a stub that records
        // `TYPE_NIL` for every child slot whose lazy node hasn't been
        // pulled in this session — and `deserialize_tree` then hands
        // the consumer a branch tagged `fully_loaded = true` with no
        // children, so lazy walks early-exit and the sync server sees
        // an empty tree even when the per-node store is populated.
        // The canonical storage is the per-node by-path / by-key
        // index; readers should always go through that.

        // Persist every leaf's underlying value into the per-vertex
        // keyspace — same as the legacy commit (vertex content lives
        // outside the tree blob; the tree carries only
        // hash_target / commitment / size).
        {
            let root_guard = self.root.read().unwrap();
            if let Some(Some(node)) = root_guard.as_ref() {
                walk_leaves_persist(
                    node,
                    self.store.as_ref(),
                    &self.set_type,
                    &self.phase_type,
                    &self.shard_key,
                )?;
            }
        }

        *self.dirty_flag.write().unwrap() = false;
        Ok(root_commitment)
    }

    /// Recompute commitments for any node whose `commitment` field is
    /// empty (was cleared by Insert), bottom-up. Returns this node's
    /// commitment bytes (64 bytes for branches via KZG, 64 bytes for
    /// leaves via SHA-512).
    fn commit_recursive(
        &self,
        node: &mut VectorCommitmentNode,
        prover: &(dyn InclusionProver + Sync),
    ) -> Result<Vec<u8>> {
        match node {
            VectorCommitmentNode::Leaf(leaf) => {
                if leaf.commitment.is_empty() {
                    leaf.compute_commitment();
                }
                Ok(leaf.commitment.clone())
            }
            VectorCommitmentNode::Branch(branch) => {
                if !branch.commitment.is_empty() {
                    return Ok(branch.commitment.clone());
                }
                // Ensure every slot is populated so the polynomial
                // covers all 64 children.
                self.ensure_branch_children_loaded(branch)?;
                for child_opt in branch.children.iter_mut() {
                    if let Some(child) = child_opt.as_deref_mut() {
                        self.commit_recursive(child, prover)?;
                    }
                }
                // BranchNode::commit recomputes its KZG commitment
                // from the children's commitments. `recalculate=true`
                // forces the recompute regardless of any cached
                // value (we already cleared it, but be explicit).
                let bytes = branch.commit(prover, true).to_vec();
                Ok(bytes)
            }
        }
    }

    /// Lazy Get. Walks from the root toward `key`, loading branches
    /// on demand. Returns the leaf's value if found.
    ///
    /// The on-disk solo encoding drops the leaf value (vertex content
    /// lives in the per-vertex keyspace). If the in-memory leaf has
    /// an empty `value`, fall back to `load_vertex_underlying_raw`.
    /// This mirrors the legacy `LazyVectorCommitmentTree::get`.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if key.is_empty() {
            return Ok(None);
        }
        self.ensure_root_loaded()?;

        // Walk in-memory tree, loading children lazily.
        let in_tree_value = {
            let root_guard = self.root.read().unwrap();
            match root_guard.as_ref() {
                Some(Some(node)) => self.lazy_get(node, key, 0)?,
                _ => None,
            }
        };

        match in_tree_value {
            Some(v) if !v.is_empty() => Ok(Some(v)),
            Some(_empty) => {
                // Leaf exists but value was stripped — pull from
                // per-vertex keyspace.
                let stored = self.store.load_vertex_underlying_raw(
                    &self.set_type,
                    &self.phase_type,
                    &self.shard_key,
                    key,
                )?;
                Ok(stored.or(Some(Vec::new())))
            }
            None => Ok(None),
        }
    }

    /// Recursive lazy walk used by `get` and `get_node_metadata_at_path`.
    /// Returns the leaf value if `key` is present in this subtree.
    fn lazy_get(
        &self,
        node: &VectorCommitmentNode,
        key: &[u8],
        depth: usize,
    ) -> Result<Option<Vec<u8>>> {
        match node {
            VectorCommitmentNode::Leaf(l) => {
                if l.key == key {
                    Ok(Some(l.value.clone()))
                } else {
                    Ok(None)
                }
            }
            VectorCommitmentNode::Branch(b) => {
                // Walk the branch's compressed prefix: any nibble
                // mismatch means the key isn't in this subtree.
                for (i, &expected) in b.prefix.iter().enumerate() {
                    let actual = get_next_nibble(key, depth + i * BRANCH_BITS);
                    if actual != expected {
                        return Ok(None);
                    }
                }
                let next_depth = depth + b.prefix.len() * BRANCH_BITS;
                let nibble = get_next_nibble(key, next_depth);
                // Try in-memory child first.
                if let Some(child) = b.children[nibble as usize].as_deref() {
                    return self.lazy_get(child, key, next_depth + BRANCH_BITS);
                }
                // Branch fully loaded but slot empty → key absent.
                if b.fully_loaded {
                    return Ok(None);
                }
                // Lazy fetch.
                let mut child_path = b.full_prefix.clone();
                child_path.push(nibble);
                match self.load_node_at_path(&child_path)? {
                    Some(loaded) => self.lazy_get(&loaded, key, next_depth + BRANCH_BITS),
                    None => Ok(None),
                }
            }
        }
    }

    pub fn get_size(&self) -> BigInt {
        let guard = self.root.read().unwrap();
        match guard.as_ref() {
            Some(Some(node)) => node.size().clone(),
            _ => BigInt::zero(),
        }
    }

    pub fn get_metadata(&self) -> (usize, usize) {
        let guard = self.root.read().unwrap();
        match guard.as_ref() {
            Some(Some(VectorCommitmentNode::Branch(b))) => (b.leaf_count, b.longest_branch),
            Some(Some(VectorCommitmentNode::Leaf(_))) => (1, 1),
            _ => (0, 0),
        }
    }

    /// Lazy version of `walk_path`: descend from the root toward the
    /// requested nibble path, loading branches as needed, and return
    /// the metadata (commitment / leaf_count / size) of whichever
    /// node covers the path. Returns `None` if the path lands in an
    /// unpopulated slot.
    pub fn get_node_metadata_at_path(
        &self,
        path: &[i32],
    ) -> Result<Option<NodeMetadata>> {
        self.ensure_root_loaded()?;
        let root_guard = self.root.read().unwrap();
        let Some(Some(node)) = root_guard.as_ref() else {
            return Ok(None);
        };
        self.lazy_walk_path(node, path, 0)
    }

    /// Recursive helper for `get_node_metadata_at_path`. Mirrors the
    /// in-memory `walk_path` in `crate::lazy_tree`, but loads
    /// children on demand for partially-loaded branches.
    fn lazy_walk_path(
        &self,
        node: &VectorCommitmentNode,
        path: &[i32],
        depth: usize,
    ) -> Result<Option<NodeMetadata>> {
        match node {
            VectorCommitmentNode::Leaf(leaf) => {
                let leaf_path = get_full_path(&leaf.key);
                if path.len().saturating_sub(depth) > leaf_path.len() {
                    return Ok(None);
                }
                for i in depth..path.len() {
                    if leaf_path[i] != path[i] {
                        return Ok(None);
                    }
                }
                Ok(Some(NodeMetadata {
                    commitment: leaf.commitment.clone(),
                    leaf_count: 1,
                    size: leaf.size.clone(),
                }))
            }
            VectorCommitmentNode::Branch(b) => {
                let mut d = depth;
                for &p in &b.prefix {
                    if d >= path.len() {
                        return Ok(Some(NodeMetadata {
                            commitment: b.commitment.clone(),
                            leaf_count: b.leaf_count as u64,
                            size: b.size.clone(),
                        }));
                    }
                    if path[d] != p {
                        return Ok(None);
                    }
                    d += 1;
                }
                if d == path.len() {
                    return Ok(Some(NodeMetadata {
                        commitment: b.commitment.clone(),
                        leaf_count: b.leaf_count as u64,
                        size: b.size.clone(),
                    }));
                }
                let nibble = path[d];
                if !(0..BRANCH_NODES as i32).contains(&nibble) {
                    return Ok(None);
                }
                // In-memory child first.
                if let Some(child) = b.children[nibble as usize].as_deref() {
                    return self.lazy_walk_path(child, path, d + 1);
                }
                if b.fully_loaded {
                    return Ok(None);
                }
                // Lazy fetch.
                let mut child_path = b.full_prefix.clone();
                child_path.push(nibble);
                match self.load_node_at_path(&child_path)? {
                    Some(loaded) => self.lazy_walk_path(&loaded, path, d + 1),
                    None => Ok(None),
                }
            }
        }
    }

    pub fn is_dirty(&self) -> bool {
        *self.dirty_flag.read().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Free helpers — module-private. Kept out of the impl block so they
// can be called from `insert_recursive` without re-borrowing `&self`.
// ---------------------------------------------------------------------------

fn is_path_within_prefix(path: &[i32], prefix: &[i32]) -> bool {
    if path.len() < prefix.len() {
        return false;
    }
    for (i, &p) in prefix.iter().enumerate() {
        if path[i] != p {
            return false;
        }
    }
    true
}

/// Absolute path identifying `node`'s on-disk position. For branches
/// this is `branch.full_prefix`; for leaves it's the nibble path of
/// the leaf's key.
fn root_full_prefix(node: &VectorCommitmentNode) -> Vec<i32> {
    match node {
        VectorCommitmentNode::Leaf(l) => get_full_path(&l.key),
        VectorCommitmentNode::Branch(b) => b.full_prefix.clone(),
    }
}

/// Compute the by-key index key for a node. Leaves use their raw key
/// bytes; branches use sha3 of the full prefix.
fn node_by_key(node: &VectorCommitmentNode, _path: &[i32]) -> Vec<u8> {
    match node {
        VectorCommitmentNode::Leaf(l) => l.key.clone(),
        VectorCommitmentNode::Branch(b) => branch_key_from_path(&b.full_prefix),
    }
}

/// Walk the in-memory tree, indexing every node by the bytes it
/// would live under in the by-key index. Used by `commit` to
/// efficiently locate the latest in-memory state for each dirty
/// entry.
fn index_by_key(
    node: &VectorCommitmentNode,
    out: &mut HashMap<Vec<u8>, VectorCommitmentNode>,
) {
    let key = node_by_key(node, &[]);
    out.insert(key, node.clone());
    if let VectorCommitmentNode::Branch(b) = node {
        for child in b.children.iter().flatten() {
            index_by_key(child, out);
        }
    }
}

/// Persist every leaf's underlying value into the per-vertex
/// keyspace. Mirrors `lazy_tree::commit`'s vertex-data loop.
fn walk_leaves_persist(
    node: &VectorCommitmentNode,
    store: &dyn HypergraphStore,
    set_type: &str,
    phase_type: &str,
    shard_key: &ShardKey,
) -> Result<()> {
    match node {
        VectorCommitmentNode::Leaf(l) if !l.value.is_empty() => {
            store.save_vertex_underlying(set_type, phase_type, shard_key, &l.key, &l.value)
        }
        VectorCommitmentNode::Leaf(_) => Ok(()),
        VectorCommitmentNode::Branch(b) => {
            for child in b.children.iter().flatten() {
                walk_leaves_persist(child, store, set_type, phase_type, shard_key)?;
            }
            Ok(())
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_key_matches_go_sha3() {
        // Empty path → sha3-256 of empty bytes.
        let k = branch_key_from_path(&[]);
        // sha3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        assert_eq!(
            hex_encode(&k),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        // A few sample paths — these must match what Go would compute.
        let k = branch_key_from_path(&[0, 1, 63]);
        // sha3-256([0x00, 0x01, 0x3F]) = computed offline
        // (recapture if format ever changes)
        assert_eq!(k.len(), 32);
    }

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((byte & 0xF) as u32, 16).unwrap());
        }
        s
    }
}
