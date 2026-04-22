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
                    // Prefix diverges: need to split the branch
                    let common_prefix = branch.prefix[..i].to_vec();
                    let remaining_prefix = branch.prefix[i + 1..].to_vec();

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

            // Invalidate commitment and update metadata
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

            Ok(VectorCommitmentNode::Branch(branch))
        }
    }
}
