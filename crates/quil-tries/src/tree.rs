use num_bigint::BigInt;
use rayon::prelude::*;
use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};

use crate::nibble::{get_next_nibble, get_nibbles_until_diverge};
use crate::node::{BranchNode, LeafNode, VectorCommitmentNode};
use crate::BRANCH_BITS;

/// In-memory vector commitment tree (non-lazy, no backing store).
pub struct VectorCommitmentTree {
    pub root: Option<VectorCommitmentNode>,
}

impl VectorCommitmentTree {
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Insert a key-value pair into the tree.
    pub fn insert(
        &mut self,
        key: &[u8],
        value: &[u8],
        hash_target: &[u8],
        size: &BigInt,
    ) -> Result<()> {
        let root = self.root.take();
        self.root = Some(insert_recursive(root, key, value, hash_target, size, 0)?);
        Ok(())
    }

    /// Commit the entire tree, computing all commitments. Branches are
    /// processed in parallel via rayon.
    pub fn commit(&mut self, prover: &(dyn InclusionProver + Sync)) -> Vec<u8> {
        match &mut self.root {
            None => vec![0u8; 64],
            Some(node) => commit_node(node, prover, true).to_vec(),
        }
    }

    /// Get a value by key.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        get_recursive(self.root.as_ref(), key, 0)
    }

    /// Delete a key from the tree.
    ///
    /// Returns `Err(QuilError::NotFound)` if the key isn't present so callers
    /// (eviction-prune, RevertChanges, sync remove-paths, CRDT remove-set
    /// updates) can distinguish a missing entry from a successful removal —
    /// matching Go's `LazyVectorCommitmentTree.Delete` contract at
    /// `types/tries/lazy_proof_tree.go:2038`.
    ///
    /// When a parent branch is left with exactly one remaining child it is
    /// collapsed and merged with that child (`merge_branch_with_child`),
    /// reversing Insert's branch-split. The post-Delete tree therefore has
    /// the same shape — and the same root commitment — as a freshly-built
    /// tree without the deleted key.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if key.is_empty() {
            return Err(QuilError::InvalidArgument(
                "delete: empty key not allowed".into(),
            ));
        }
        let root = self.root.take();
        let (found, new_root) = delete_recursive(root, key, 0);
        self.root = new_root;
        if found {
            Ok(())
        } else {
            Err(QuilError::NotFound(format!(
                "key {} not found in tree",
                hex_short(key)
            )))
        }
    }

    /// Collect every leaf in this tree. Returns owned `(key, value)`
    /// pairs. Mirrors Go's `tries.GetAllPreloadedLeaves` — convenient
    /// for hyperedge enumeration where the caller needs the keys
    /// (atom IDs) and not just the values.
    pub fn leaves(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut leaves: Vec<&crate::node::LeafNode> = Vec::new();
        if let Some(root) = self.root.as_ref() {
            root.collect_leaves(&mut leaves);
        }
        leaves.into_iter()
            .map(|l| (l.key.clone(), l.value.clone()))
            .collect()
    }

    /// Generate a traversal proof for a key. Returns the polynomials,
    /// commitments, evaluation points (ys), and paths needed for
    /// verification via `InclusionProver::prove_multiple`.
    ///
    /// Matches Go's `VectorCommitmentTree.Prove()`.
    pub fn prove(
        &self,
        prover: &(dyn InclusionProver + Sync),
        key: &[u8],
    ) -> Option<TraversalProof> {
        if key.is_empty() {
            return None;
        }
        let (polys, commits, ys, paths) = prove_recursive(self.root.as_ref()?, key, 0, prover)?;
        if commits.is_empty() {
            return None;
        }

        // Build path indices
        let path_indices: Vec<Vec<u64>> = paths.iter()
            .map(|p| p.iter().map(|&i| i as u64).collect())
            .collect();
        let indices: Vec<u64> = paths.iter()
            .map(|p| *p.last().unwrap_or(&0) as u64)
            .collect();

        // Generate multiproof via KZG
        let commit_refs: Vec<&[u8]> = commits[..commits.len() - 1].iter().map(|c| c.as_slice()).collect();
        let poly_refs: Vec<&[u8]> = polys.iter().map(|p| p.as_slice()).collect();
        let multiproof = prover.prove_multiple(&commit_refs, &poly_refs, &indices, 64).ok()?;

        Some(TraversalProof {
            multiproof,
            ys,
            commits,
            paths: path_indices,
        })
    }
}

/// Proof data for tree traversal verification.
pub struct TraversalProof {
    pub multiproof: Box<dyn quil_types::crypto::Multiproof>,
    pub ys: Vec<Vec<u8>>,
    pub commits: Vec<Vec<u8>>,
    pub paths: Vec<Vec<u64>>,
}

/// Per-key sub-proof emitted by [`VectorCommitmentTree::prove_multiple`].
/// Each one carries the tree-walk commits / ys / paths for a single key;
/// the KZG multiproof that ties them all together is aggregated at the
/// outer [`MultiKeyTraversalProof`] level.
#[derive(Debug, Clone)]
pub struct TraversalSubProof {
    pub commits: Vec<Vec<u8>>,
    pub ys: Vec<Vec<u8>>,
    pub paths: Vec<Vec<u64>>,
}

/// Multi-key traversal proof. Mirrors Go's `tries.TraversalProof`
/// returned by `VectorCommitmentTree.ProveMultiple` —
/// N sub-proofs + one aggregated KZG multiproof.
pub struct MultiKeyTraversalProof {
    pub multiproof: Box<dyn quil_types::crypto::Multiproof>,
    pub sub_proofs: Vec<TraversalSubProof>,
}

impl MultiKeyTraversalProof {
    /// Serialize to Go's `TraversalProof.ToBytes()` wire format:
    /// `[u32 mp_len] [mp_bytes] [u32 n_sub] (per sub: [u32 c_n] [u32 l] [c]* [u32 y_n] [u32 l] [y]* [u32 p_n] [u32 l] [u64]*)`.
    ///
    /// The multiproof byte layout is
    /// `[u32 commit_len] [commitment] [u32 proof_len] [proof] [u32 eval_n] ([u32 len] [eval])*`,
    /// matching the Go-side KZG multiproof serialization.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mp_bytes = serialize_multiproof(self.multiproof.as_ref());
        let mut out = Vec::with_capacity(mp_bytes.len() + 256);
        put_u32(&mut out, mp_bytes.len() as u32);
        out.extend_from_slice(&mp_bytes);
        put_u32(&mut out, self.sub_proofs.len() as u32);
        for sp in &self.sub_proofs {
            put_u32(&mut out, sp.commits.len() as u32);
            for c in &sp.commits {
                put_u32(&mut out, c.len() as u32);
                out.extend_from_slice(c);
            }
            put_u32(&mut out, sp.ys.len() as u32);
            for y in &sp.ys {
                put_u32(&mut out, y.len() as u32);
                out.extend_from_slice(y);
            }
            put_u32(&mut out, sp.paths.len() as u32);
            for path in &sp.paths {
                put_u32(&mut out, path.len() as u32);
                for &p in path {
                    out.extend_from_slice(&p.to_be_bytes());
                }
            }
        }
        out
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn serialize_multiproof(mp: &dyn quil_types::crypto::Multiproof) -> Vec<u8> {
    let commitment = mp.commitment();
    let proof = mp.proof();
    let evaluations = mp.evaluations();
    let mut out = Vec::with_capacity(commitment.len() + proof.len() + 128);
    put_u32(&mut out, commitment.len() as u32);
    out.extend_from_slice(commitment);
    put_u32(&mut out, proof.len() as u32);
    out.extend_from_slice(proof);
    put_u32(&mut out, evaluations.len() as u32);
    for e in &evaluations {
        put_u32(&mut out, e.len() as u32);
        out.extend_from_slice(e);
    }
    out
}

impl VectorCommitmentTree {
    /// Generate a multi-key traversal proof. One KZG multiproof is
    /// aggregated across all keys so the verifier makes a single
    /// `verify_multiple` call. Keys that don't exist in the tree are
    /// silently skipped — the returned `sub_proofs` only covers the
    /// keys that were found.
    ///
    /// Port of Go's `VectorCommitmentTree.ProveMultiple` at
    /// `types/tries/lazy_proof_tree.go`.
    pub fn prove_multiple(
        &self,
        prover: &(dyn InclusionProver + Sync),
        keys: &[&[u8]],
    ) -> Option<MultiKeyTraversalProof> {
        let root = self.root.as_ref()?;

        // Collect per-key tree walks.
        let mut sub_proofs: Vec<TraversalSubProof> = Vec::new();
        let mut agg_polys: Vec<Vec<u8>> = Vec::new();
        let mut agg_commits: Vec<Vec<u8>> = Vec::new();
        let mut agg_ys: Vec<Vec<u8>> = Vec::new();
        let mut agg_indices: Vec<u64> = Vec::new();

        for key in keys {
            if key.is_empty() {
                continue;
            }
            let Some((polys, commits, ys, paths)) = prove_recursive(root, key, 0, prover) else {
                continue;
            };
            if commits.is_empty() {
                continue;
            }

            let path_indices: Vec<Vec<u64>> = paths
                .iter()
                .map(|p| p.iter().map(|&i| i as u64).collect())
                .collect();
            let indices: Vec<u64> = paths
                .iter()
                .map(|p| *p.last().unwrap_or(&0) as u64)
                .collect();

            // Exclude the leaf commit — the last commit is the leaf value, not a
            // branch polynomial commitment, matching the single-key
            // `prove` method above.
            agg_commits.extend_from_slice(&commits[..commits.len() - 1]);
            agg_polys.extend(polys.iter().cloned());
            agg_ys.extend(ys[..ys.len() - 1].iter().cloned());
            agg_indices.extend(indices);

            sub_proofs.push(TraversalSubProof {
                commits,
                ys,
                paths: path_indices,
            });
        }

        if agg_commits.is_empty() {
            return None;
        }

        let commit_refs: Vec<&[u8]> = agg_commits.iter().map(|c| c.as_slice()).collect();
        let poly_refs: Vec<&[u8]> = agg_polys.iter().map(|p| p.as_slice()).collect();
        let multiproof = prover
            .prove_multiple(&commit_refs, &poly_refs, &agg_indices, 64)
            .ok()?;

        Some(MultiKeyTraversalProof {
            multiproof,
            sub_proofs,
        })
    }
}

impl Default for VectorCommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

fn commit_node<'a>(
    node: &'a mut VectorCommitmentNode,
    prover: &(dyn InclusionProver + Sync),
    recalculate: bool,
) -> &'a [u8] {
    match node {
        VectorCommitmentNode::Leaf(leaf) => leaf.commit(recalculate),
        VectorCommitmentNode::Branch(branch) => {
            // Walk all 64 child slots in parallel. Each child commit is
            // independent: leaves do SHA-512, branches recurse.
            // KZG branch commit happens once all children are settled.
            branch
                .children
                .par_iter_mut()
                .for_each(|child_opt| {
                    if let Some(child) = child_opt {
                        commit_node(child, prover, recalculate);
                    }
                });

            // Aggregate `size` from children. `leaf_count` and
            // `longest_branch` are maintained at insert/delete time.
            let mut aggregate = num_bigint::BigInt::from(0u64);
            for child in branch.children.iter().flatten() {
                aggregate += child.size();
            }
            branch.size = aggregate;

            branch.commit(prover, recalculate)
        }
    }
}

/// Recursively collect proof data (polynomials, commits, ys, paths)
/// matching Go's `VectorCommitmentTree.Prove` inner function.
fn prove_recursive(
    node: &VectorCommitmentNode,
    key: &[u8],
    depth: usize,
    prover: &(dyn InclusionProver + Sync),
) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<i32>>)> {
    match node {
        VectorCommitmentNode::Leaf(leaf) => {
            if leaf.key == key {
                let commitment = leaf.commitment.clone();
                let y = if !leaf.hash_target.is_empty() {
                    leaf.hash_target.clone()
                } else {
                    leaf.value.clone()
                };
                Some((vec![], vec![commitment], vec![y], vec![]))
            } else {
                None
            }
        }
        VectorCommitmentNode::Branch(branch) => {
            // Check prefix match
            let mut d = depth;
            for &expected in &branch.prefix {
                let n = get_next_nibble(key, d);
                if n != expected {
                    return None;
                }
                d += BRANCH_BITS;
            }

            let final_nibble = get_next_nibble(key, d);
            if final_nibble < 0 {
                return None;
            }
            let idx = final_nibble as usize;

            let commit = branch.commitment.clone();
            let poly = branch.get_polynomial();

            let y = if idx * 64 + 64 <= poly.len() {
                poly[idx * 64..(idx + 1) * 64].to_vec()
            } else {
                vec![0u8; 64]
            };

            let child = branch.children[idx].as_deref()?;
            let (mut pl, mut co, mut ys, mut pa) =
                prove_recursive(child, key, d + BRANCH_BITS, prover)?;

            let mut path: Vec<i32> = branch.prefix.clone();
            path.push(final_nibble);

            // Prepend this level
            pl.insert(0, poly);
            co.insert(0, commit);
            ys.insert(0, y);
            pa.insert(0, path);

            Some((pl, co, ys, pa))
        }
    }
}

fn get_recursive<'a>(node: Option<&'a VectorCommitmentNode>, key: &[u8], depth: usize) -> Option<&'a [u8]> {
    match node? {
        VectorCommitmentNode::Leaf(leaf) => {
            if leaf.key == key {
                Some(&leaf.value)
            } else {
                None
            }
        }
        VectorCommitmentNode::Branch(branch) => {
            // Skip prefix nibbles
            let mut d = depth;
            for &p in &branch.prefix {
                let n = get_next_nibble(key, d);
                if n != p {
                    return None;
                }
                d += BRANCH_BITS;
            }
            let nibble = get_next_nibble(key, d);
            if nibble < 0 {
                return None;
            }
            get_recursive(
                branch.children[nibble as usize].as_deref(),
                key,
                d + BRANCH_BITS,
            )
        }
    }
}

fn insert_recursive(
    node: Option<VectorCommitmentNode>,
    key: &[u8],
    value: &[u8],
    hash_target: &[u8],
    size: &BigInt,
    depth: usize,
) -> Result<VectorCommitmentNode> {
    match node {
        None => {
            // Create new leaf
            let mut leaf = LeafNode {
                key: key.to_vec(),
                value: value.to_vec(),
                hash_target: hash_target.to_vec(),
                commitment: Vec::new(),
                size: size.clone(),
            };
            leaf.compute_commitment();
            Ok(VectorCommitmentNode::Leaf(leaf))
        }
        Some(VectorCommitmentNode::Leaf(existing)) => {
            if existing.key == key {
                // Update existing leaf
                let mut leaf = LeafNode {
                    key: key.to_vec(),
                    value: value.to_vec(),
                    hash_target: hash_target.to_vec(),
                    commitment: Vec::new(),
                    size: size.clone(),
                };
                leaf.compute_commitment();
                Ok(VectorCommitmentNode::Leaf(leaf))
            } else {
                // Split: create branch with both leaves
                let (common, diverge_depth) =
                    get_nibbles_until_diverge(&existing.key, key, depth);

                let mut branch = BranchNode::new(common);

                let n1 = get_next_nibble(&existing.key, diverge_depth);
                let n2 = get_next_nibble(key, diverge_depth);

                if n1 >= 0 {
                    branch.children[n1 as usize] =
                        Some(Box::new(VectorCommitmentNode::Leaf(existing)));
                }
                if n2 >= 0 {
                    let mut new_leaf = LeafNode {
                        key: key.to_vec(),
                        value: value.to_vec(),
                        hash_target: hash_target.to_vec(),
                        commitment: Vec::new(),
                        size: size.clone(),
                    };
                    new_leaf.compute_commitment();
                    branch.children[n2 as usize] =
                        Some(Box::new(VectorCommitmentNode::Leaf(new_leaf)));
                }

                branch.leaf_count = 2;
                branch.commitment = Vec::new(); // invalidate

                Ok(VectorCommitmentNode::Branch(branch))
            }
        }
        Some(VectorCommitmentNode::Branch(mut branch)) => {
            // Check prefix match
            let mut d = depth;
            for (i, &p) in branch.prefix.iter().enumerate() {
                let n = get_next_nibble(key, d);
                if n != p {
                    // Prefix diverges — split the branch. Go's
                    // `insertRecursive` at `lazy_proof_tree.go:1069-1077`
                    // sets the new parent's counters to the OLD branch's
                    // values bumped by one: `LeafCount = n.LeafCount + 1`,
                    // `LongestBranch = n.LongestBranch + 1`. Leaving
                    // them at zero would silently diverge the computed
                    // root hash from Go's.
                    let common_prefix = branch.prefix[..i].to_vec();
                    let remaining_prefix = branch.prefix[i + 1..].to_vec();
                    let old_leaf_count = branch.leaf_count;
                    let old_longest = branch.longest_branch;

                    let mut new_parent = BranchNode::new(common_prefix);

                    // Old branch becomes child at its divergence nibble
                    branch.prefix = remaining_prefix;
                    branch.commitment = Vec::new();
                    new_parent.children[p as usize] =
                        Some(Box::new(VectorCommitmentNode::Branch(branch)));

                    // New leaf becomes child at key's divergence nibble
                    if n >= 0 {
                        let mut new_leaf = LeafNode {
                            key: key.to_vec(),
                            value: value.to_vec(),
                            hash_target: hash_target.to_vec(),
                            commitment: Vec::new(),
                            size: size.clone(),
                        };
                        new_leaf.compute_commitment();
                        new_parent.children[n as usize] =
                            Some(Box::new(VectorCommitmentNode::Leaf(new_leaf)));
                    }

                    new_parent.leaf_count = old_leaf_count.saturating_add(1);
                    new_parent.longest_branch = old_longest.saturating_add(1);

                    return Ok(VectorCommitmentNode::Branch(new_parent));
                }
                d += BRANCH_BITS;
            }

            // Prefix matches, descend to child
            let nibble = get_next_nibble(key, d);
            if nibble < 0 {
                return Err(QuilError::InvalidArgument(
                    "key too short for tree depth".into(),
                ));
            }

            let child = branch.children[nibble as usize].take().map(|c| *c);
            let new_child =
                insert_recursive(child, key, value, hash_target, size, d + BRANCH_BITS)?;
            branch.children[nibble as usize] = Some(Box::new(new_child));

            // Invalidate commitment and update metadata.
            // `leaf_count` is the sum of child leaf counts; `longest_branch`
            // is `1 + max(child.longest_branch)` with leaves counted as
            // depth 0 — matches Go's post-insert update at
            // `lazy_proof_tree.go:1170-1177`.
            branch.commitment = Vec::new();
            branch.leaf_count = branch
                .children
                .iter()
                .map(|c| match c {
                    Some(c) => match c.as_ref() {
                        VectorCommitmentNode::Leaf(_) => 1,
                        VectorCommitmentNode::Branch(b) => b.leaf_count,
                    },
                    None => 0,
                })
                .sum();
            branch.longest_branch = 1 + branch
                .children
                .iter()
                .map(|c| match c {
                    Some(c) => match c.as_ref() {
                        VectorCommitmentNode::Leaf(_) => 0,
                        VectorCommitmentNode::Branch(b) => b.longest_branch,
                    },
                    None => 0,
                })
                .max()
                .unwrap_or(0);

            Ok(VectorCommitmentNode::Branch(branch))
        }
    }
}

/// Recursive Delete walker. Returns `(found, replacement_node)`.
///
/// `found` is true iff a leaf with the exact key was removed somewhere in
/// the sub-tree. `replacement_node` is what the caller should put in place
/// of `node`:
///   - `None` if the sub-tree is now empty
///   - `Some(leaf)` if a branch collapsed down to its single remaining leaf
///   - `Some(branch)` with refreshed metadata otherwise
///
/// Mirrors Go's `Delete` recursion at `types/tries/lazy_proof_tree.go:2056`
/// and `mergeBranchWithChild` at line 2242, minus the
/// `FullPrefix`/`FullyLoaded` store bookkeeping the lazy Go variant
/// performs. The Rust in-memory tree keeps the entire structure resident,
/// so per-node store deletes are unnecessary here — they belong in the
/// lazy wrapper's commit step.
fn delete_recursive(
    node: Option<VectorCommitmentNode>,
    key: &[u8],
    depth: usize,
) -> (bool, Option<VectorCommitmentNode>) {
    let Some(node) = node else {
        return (false, None);
    };

    match node {
        VectorCommitmentNode::Leaf(leaf) => {
            if leaf.key == key {
                (true, None)
            } else {
                (false, Some(VectorCommitmentNode::Leaf(leaf)))
            }
        }
        VectorCommitmentNode::Branch(mut branch) => {
            // Verify the prefix matches the key — if not, the key isn't here.
            let mut d = depth;
            for &expected in &branch.prefix {
                let n = get_next_nibble(key, d);
                if n != expected {
                    return (false, Some(VectorCommitmentNode::Branch(branch)));
                }
                d += BRANCH_BITS;
            }

            let nibble = get_next_nibble(key, d);
            if nibble < 0 {
                // Key is shorter than required to reach a leaf below this
                // branch — no possible match.
                return (false, Some(VectorCommitmentNode::Branch(branch)));
            }
            let idx = nibble as usize;

            let child = branch.children[idx].take().map(|c| *c);
            let (found, new_child) = delete_recursive(child, key, d + BRANCH_BITS);

            if !found {
                // Restore the slot if we took it but didn't actually delete.
                branch.children[idx] = new_child.map(Box::new);
                return (false, Some(VectorCommitmentNode::Branch(branch)));
            }

            branch.children[idx] = new_child.map(Box::new);
            // Commitment is now stale.
            branch.commitment = Vec::new();

            // Collapse if exactly one child remains. Go's reference at
            // `lazy_proof_tree.go:2191-2194` calls `mergeBranchWithChild`
            // here; the Rust in-memory equivalent inlines it below.
            let remaining: Vec<usize> = branch
                .children
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.as_ref().map(|_| i))
                .collect();

            match remaining.len() {
                0 => (true, None),
                1 => {
                    let only_idx = remaining[0];
                    let only = branch.children[only_idx].take().map(|c| *c).unwrap();
                    let merged = merge_branch_with_child(branch, only_idx, only);
                    (true, Some(merged))
                }
                _ => {
                    // Recompute metadata to match a freshly-built tree.
                    // `leaf_count` = sum of children's leaf counts (a leaf
                    // child counts as 1). `longest_branch` = 1 + max child
                    // depth, with leaves at depth 0. Mirrors Insert's
                    // post-update at `tree.rs` lines 521-543.
                    branch.leaf_count = branch
                        .children
                        .iter()
                        .map(|c| match c {
                            Some(c) => match c.as_ref() {
                                VectorCommitmentNode::Leaf(_) => 1,
                                VectorCommitmentNode::Branch(b) => b.leaf_count,
                            },
                            None => 0,
                        })
                        .sum();
                    branch.longest_branch = 1 + branch
                        .children
                        .iter()
                        .map(|c| match c {
                            Some(c) => match c.as_ref() {
                                VectorCommitmentNode::Leaf(_) => 0,
                                VectorCommitmentNode::Branch(b) => b.longest_branch,
                            },
                            None => 0,
                        })
                        .max()
                        .unwrap_or(0);
                    (true, Some(VectorCommitmentNode::Branch(branch)))
                }
            }
        }
    }
}

/// Merge a branch with its sole remaining child — the reverse of Insert's
/// branch-split.
///
/// - If the child is a leaf, the branch disappears entirely; the leaf
///   takes its place. Insert would never have created the parent branch
///   in the first place if only one leaf existed under it.
/// - If the child is a branch, fold the parent's prefix + the child-slot
///   nibble + the child's prefix into a single new prefix, and let the
///   merged branch take the parent's place. Counters carry over from the
///   child unchanged: it's the same set of leaves at the same depths.
fn merge_branch_with_child(
    branch: BranchNode,
    child_index: usize,
    child: VectorCommitmentNode,
) -> VectorCommitmentNode {
    match child {
        VectorCommitmentNode::Leaf(leaf) => VectorCommitmentNode::Leaf(leaf),
        VectorCommitmentNode::Branch(mut child_branch) => {
            // New prefix = parent.prefix + [child_index] + child.prefix
            let mut merged_prefix =
                Vec::with_capacity(branch.prefix.len() + 1 + child_branch.prefix.len());
            merged_prefix.extend_from_slice(&branch.prefix);
            merged_prefix.push(child_index as i32);
            merged_prefix.extend_from_slice(&child_branch.prefix);
            child_branch.prefix = merged_prefix;
            child_branch.commitment = Vec::new();
            VectorCommitmentNode::Branch(child_branch)
        }
    }
}

/// Hex-encode the first 8 bytes of a key for diagnostic use in error
/// messages — keeps `NotFound` output readable without pulling in a hex
/// dependency.
fn hex_short(key: &[u8]) -> String {
    use std::fmt::Write;
    let take = key.len().min(8);
    let mut s = String::with_capacity(take * 2 + 4);
    for &b in &key[..take] {
        let _ = write!(&mut s, "{:02x}", b);
    }
    if key.len() > take {
        s.push_str("..");
    }
    s
}

#[cfg(test)]
mod delete_tests {
    //! Regression tests for `VectorCommitmentTree::delete`.
    //!
    //! The `*_yields_same_commit_as_fresh_insert` cases are the
    //! property-style invariants: a tree built by inserting a set then
    //! deleting one key must root-match a tree built by inserting only
    //! the surviving keys. If they don't, branch-merge is wrong.
    use super::*;
    use num_bigint::BigInt;
    use quil_types::crypto::{InclusionProver, Multiproof};
    use quil_types::error::{QuilError, Result};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    /// Deterministic stub commitment scheme. KZG isn't required to verify
    /// branch-merge correctness — we only need a commit that's a pure
    /// function of input bytes so the same tree shape produces the same
    /// root.
    struct StubProver;
    impl InclusionProver for StubProver {
        fn commit_raw(&self, data: &[u8], _: u64) -> Result<Vec<u8>> {
            let mut h = DefaultHasher::new();
            data.hash(&mut h);
            let hash = h.finish().to_be_bytes();
            let mut out = vec![0u8; 64];
            out[..8].copy_from_slice(&hash);
            Ok(out)
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> {
            Ok(vec![0u8; 64])
        }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> {
            Ok(true)
        }
        fn prove_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
        ) -> Result<Box<dyn Multiproof>> {
            Err(QuilError::Internal("not used in delete tests".into()))
        }
        fn verify_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
            _: &[u8],
            _: &[u8],
        ) -> bool {
            true
        }
    }

    fn ins(tree: &mut VectorCommitmentTree, k: &[u8], v: &[u8]) {
        tree.insert(k, v, &[], &BigInt::from(v.len() as u64)).unwrap();
    }

    #[test]
    fn delete_existing_leaf_removes_it() {
        let mut tree = VectorCommitmentTree::new();
        ins(&mut tree, b"key-1", b"v1");
        ins(&mut tree, b"key-2", b"v2");
        assert!(tree.delete(b"key-1").is_ok());
        assert_eq!(tree.get(b"key-1"), None);
        assert_eq!(tree.get(b"key-2"), Some(&b"v2"[..]));
    }

    #[test]
    fn delete_returns_notfound_for_missing_key() {
        let mut tree = VectorCommitmentTree::new();
        ins(&mut tree, b"key-1", b"v1");
        let err = tree.delete(b"missing").unwrap_err();
        assert!(
            matches!(err, QuilError::NotFound(_)),
            "expected NotFound, got {:?}",
            err
        );
        // Original key still there.
        assert_eq!(tree.get(b"key-1"), Some(&b"v1"[..]));
    }

    #[test]
    fn delete_empty_key_is_invalid_argument() {
        let mut tree = VectorCommitmentTree::new();
        ins(&mut tree, b"key-1", b"v1");
        let err = tree.delete(b"").unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn delete_from_empty_tree_returns_notfound() {
        let mut tree = VectorCommitmentTree::new();
        let err = tree.delete(b"k").unwrap_err();
        assert!(matches!(err, QuilError::NotFound(_)));
    }

    #[test]
    fn delete_only_leaf_empties_tree() {
        let mut tree = VectorCommitmentTree::new();
        ins(&mut tree, b"key-1", b"v1");
        assert!(tree.delete(b"key-1").is_ok());
        assert!(tree.root.is_none());
    }

    #[test]
    fn delete_collapses_branch_with_single_remaining_child() {
        // Two keys → branch with two leaf children. After deleting one,
        // the branch should collapse to the surviving leaf.
        let mut tree = VectorCommitmentTree::new();
        ins(&mut tree, b"alpha", b"a");
        ins(&mut tree, b"bravo", b"b");
        // Sanity check: root is a branch.
        assert!(matches!(tree.root, Some(VectorCommitmentNode::Branch(_))));

        tree.delete(b"alpha").unwrap();

        // Root is now a leaf — branch collapsed.
        match &tree.root {
            Some(VectorCommitmentNode::Leaf(leaf)) => {
                assert_eq!(leaf.key, b"bravo");
                assert_eq!(leaf.value, b"b");
            }
            other => panic!("expected leaf root after collapse, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn delete_collapses_branch_branch_into_merged_branch() {
        // Three keys carefully chosen to produce a nested branch
        // structure, then delete one leaf so the resulting parent has
        // only its remaining branch child — exercising the
        // branch-into-branch merge path of `merge_branch_with_child`.
        let mut tree = VectorCommitmentTree::new();
        // Use byte patterns that share a prefix nibble at the top level
        // (so the root is a branch) but diverge below.
        let k1: &[u8] = b"\x10\x00key-1";
        let k2: &[u8] = b"\x10\x01key-2";
        let k3: &[u8] = b"\xF0\x00key-3";
        ins(&mut tree, k1, b"v1");
        ins(&mut tree, k2, b"v2");
        ins(&mut tree, k3, b"v3");

        tree.delete(k3).unwrap();

        // After deleting k3, the surviving subtree (k1 + k2) must be
        // accessible via the original keys.
        assert_eq!(tree.get(k1), Some(&b"v1"[..]));
        assert_eq!(tree.get(k2), Some(&b"v2"[..]));
        assert_eq!(tree.get(k3), None);
    }

    #[test]
    fn delete_then_reinsert_yields_same_commit_as_fresh_insert() {
        // Property-style: build tree A with k1+k2+k3 then delete k2.
        // Build tree B with just k1+k3. Their commitments must match —
        // any divergence means the delete left stale metadata or a
        // dangling internal branch.
        let prover = StubProver;
        let mut tree_a = VectorCommitmentTree::new();
        ins(&mut tree_a, b"key-aa", b"v-aa");
        ins(&mut tree_a, b"key-bb", b"v-bb");
        ins(&mut tree_a, b"key-cc", b"v-cc");
        tree_a.delete(b"key-bb").unwrap();
        let root_a = tree_a.commit(&prover);

        let mut tree_b = VectorCommitmentTree::new();
        ins(&mut tree_b, b"key-aa", b"v-aa");
        ins(&mut tree_b, b"key-cc", b"v-cc");
        let root_b = tree_b.commit(&prover);

        assert_eq!(
            root_a, root_b,
            "delete-then-commit must equal fresh-insert commit"
        );
    }

    #[test]
    fn delete_many_then_commit_equals_fresh_tree() {
        // Larger property check: insert 16 keys into A, delete 8;
        // insert the surviving 8 into B fresh. Same commit expected.
        let prover = StubProver;
        let keys: Vec<Vec<u8>> = (0..16u8).map(|i| vec![i, 0xAB, i ^ 0x55]).collect();
        let to_delete: Vec<usize> = vec![1, 3, 5, 7, 9, 11, 13, 15];

        let mut tree_a = VectorCommitmentTree::new();
        for (i, k) in keys.iter().enumerate() {
            ins(&mut tree_a, k, &[i as u8]);
        }
        for &i in &to_delete {
            tree_a.delete(&keys[i]).unwrap();
        }
        let root_a = tree_a.commit(&prover);

        let mut tree_b = VectorCommitmentTree::new();
        for (i, k) in keys.iter().enumerate() {
            if !to_delete.contains(&i) {
                ins(&mut tree_b, k, &[i as u8]);
            }
        }
        let root_b = tree_b.commit(&prover);

        assert_eq!(root_a, root_b);
    }

    #[test]
    fn delete_then_reinsert_same_key_round_trips() {
        let prover = StubProver;
        let mut tree = VectorCommitmentTree::new();
        ins(&mut tree, b"k1", b"v1");
        ins(&mut tree, b"k2", b"v2");
        ins(&mut tree, b"k3", b"v3");
        let root_before = tree.commit(&prover);
        tree.delete(b"k2").unwrap();
        ins(&mut tree, b"k2", b"v2");
        let root_after = tree.commit(&prover);
        assert_eq!(root_before, root_after);
    }
}
