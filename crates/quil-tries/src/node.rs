use num_bigint::BigInt;
use num_traits::Zero;
use sha2::{Digest, Sha512};

use crate::BRANCH_NODES;
use quil_types::crypto::InclusionProver;

/// A node in the vector commitment tree: either a leaf or a 64-way branch.
#[derive(Clone)]
pub enum VectorCommitmentNode {
    Leaf(LeafNode),
    Branch(BranchNode),
}

/// A leaf node storing a key-value pair with its commitment.
#[derive(Clone)]
pub struct LeafNode {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub hash_target: Vec<u8>,
    pub commitment: Vec<u8>,
    pub size: BigInt,
}

/// A 64-way branch node with prefix compression.
#[derive(Clone)]
pub struct BranchNode {
    /// Compressed prefix nibbles (relative to parent).
    pub prefix: Vec<i32>,
    /// 64 children. Semantics depend on [`Self::fully_loaded`]:
    /// - `fully_loaded = true`: `None` means the slot is genuinely empty.
    /// - `fully_loaded = false`: `None` means "not yet loaded from store"
    ///   — the lazy walker calls `get_node_by_path(full_prefix + [i])`
    ///   to fetch on demand. `Some(...)` always means resident.
    pub children: [Option<Box<VectorCommitmentNode>>; BRANCH_NODES],
    /// KZG or SHA-512 commitment.
    pub commitment: Vec<u8>,
    /// Total size of all leaves under this branch.
    pub size: BigInt,
    /// Number of leaves under this branch.
    pub leaf_count: usize,
    /// Depth of the longest chain of children.
    pub longest_branch: usize,
    /// Absolute nibble path from the tree root through this branch's
    /// prefix. Needed for lazy walks that must compute child paths
    /// (`full_prefix + [i]`) without re-traversing from the root.
    /// In-memory branches built via `BranchNode::new` start with an
    /// empty `full_prefix`; the lazy tree fills it in as it walks.
    pub full_prefix: Vec<i32>,
    /// True when every child slot reflects the on-disk state (no
    /// further `get_node_by_path` calls needed to enumerate). In-memory
    /// trees that don't have a backing store are always fully loaded.
    /// Lazy walks set this to `false` after a load-by-path returns
    /// just the branch metadata.
    pub fully_loaded: bool,
}

impl LeafNode {
    /// Compute the SHA-512 commitment for this leaf.
    /// Format: SHA-512(0x00 || key || hash_target_or_value)
    pub fn compute_commitment(&mut self) {
        let mut h = Sha512::new();
        h.update([0u8]); // type marker: leaf
        h.update(&self.key);
        if !self.hash_target.is_empty() {
            h.update(&self.hash_target);
        } else {
            h.update(&self.value);
        }
        self.commitment = h.finalize().to_vec();
    }

    /// Commit this leaf, recomputing if needed.
    pub fn commit(&mut self, recalculate: bool) -> &[u8] {
        if recalculate || self.commitment.is_empty() {
            self.compute_commitment();
        }
        &self.commitment
    }
}

impl BranchNode {
    /// Empty branch with the given prefix. In-memory trees that have no
    /// backing store use this constructor; `fully_loaded` defaults to
    /// `true` so callers don't trigger phantom loads.
    pub fn new(prefix: Vec<i32>) -> Self {
        Self {
            prefix,
            children: std::array::from_fn(|_| None),
            commitment: Vec::new(),
            size: BigInt::zero(),
            leaf_count: 0,
            longest_branch: 0,
            full_prefix: Vec::new(),
            fully_loaded: true,
        }
    }

    /// Compute the KZG commitment for this branch.
    ///
    /// For each of the 64 children:
    /// - nil child => 64 zero bytes
    /// - leaf child => child.commitment (64 bytes)
    /// - branch child => SHA-512(0x01 || prefix_as_u32_be... || child.commitment)
    ///
    /// All 64 commitments concatenated (4096 bytes) are committed via KZG.
    /// Get the 4096-byte polynomial vector (64 child commitments, each 64 bytes).
    /// Matches Go's `GetPolynomial()`.
    pub fn get_polynomial(&self) -> Vec<u8> {
        let mut data = vec![0u8; 64 * 64];
        for (i, child_opt) in self.children.iter().enumerate() {
            let c = match child_opt {
                None => vec![0u8; 64],
                Some(child) => match child.as_ref() {
                    VectorCommitmentNode::Leaf(leaf) => {
                        let mut c = leaf.commitment.clone();
                        c.resize(64, 0);
                        c
                    }
                    VectorCommitmentNode::Branch(branch) => {
                        let mut h = Sha512::new();
                        h.update([1u8]);
                        for &p in &branch.prefix {
                            h.update((p as u32).to_be_bytes());
                        }
                        h.update(&branch.commitment);
                        h.finalize().to_vec()
                    }
                },
            };
            data[i * 64..(i + 1) * 64].copy_from_slice(&c[..64.min(c.len())]);
        }
        data
    }

    pub fn commit(
        &mut self,
        prover: &dyn InclusionProver,
        recalculate: bool,
    ) -> &[u8] {
        if !recalculate && !self.commitment.is_empty() {
            return &self.commitment;
        }

        let mut data = vec![0u8; 64 * 64]; // 4096 bytes

        for (i, child_opt) in self.children.iter().enumerate() {
            let child_commitment = match child_opt {
                None => {
                    vec![0u8; 64]
                }
                Some(child) => match child.as_ref() {
                    VectorCommitmentNode::Leaf(leaf) => {
                        let mut c = leaf.commitment.clone();
                        c.resize(64, 0);
                        c
                    }
                    VectorCommitmentNode::Branch(branch) => {
                        // Wrap with prefix: SHA-512(0x01 || prefix || commitment)
                        let mut h = Sha512::new();
                        h.update([1u8]); // type marker: branch prefix
                        for &p in &branch.prefix {
                            h.update((p as u32).to_be_bytes());
                        }
                        h.update(&branch.commitment);
                        h.finalize().to_vec()
                    }
                },
            };

            let offset = i * 64;
            let len = child_commitment.len().min(64);
            data[offset..offset + len].copy_from_slice(&child_commitment[..len]);
        }

        // KZG commit over the 4096-byte vector
        self.commitment = prover
            .commit_raw(&data, 64)
            .unwrap_or_else(|_| vec![0u8; 64]);

        &self.commitment
    }

    /// Count non-nil children.
    pub fn child_count(&self) -> usize {
        self.children.iter().filter(|c| c.is_some()).count()
    }
}

impl VectorCommitmentNode {
    pub fn is_leaf(&self) -> bool {
        matches!(self, VectorCommitmentNode::Leaf(_))
    }

    pub fn is_branch(&self) -> bool {
        matches!(self, VectorCommitmentNode::Branch(_))
    }

    pub fn commitment(&self) -> &[u8] {
        match self {
            VectorCommitmentNode::Leaf(leaf) => &leaf.commitment,
            VectorCommitmentNode::Branch(branch) => &branch.commitment,
        }
    }

    pub fn size(&self) -> &BigInt {
        match self {
            VectorCommitmentNode::Leaf(leaf) => &leaf.size,
            VectorCommitmentNode::Branch(branch) => &branch.size,
        }
    }

    /// Recursively search this sub-tree for a leaf whose key exactly matches
    /// `target`. Returns the leaf's value bytes if found. Suitable for small
    /// trees (e.g. prover vertex sub-trees with <= ~20 leaves).
    pub fn find_leaf_value(&self, target: &[u8]) -> Option<Vec<u8>> {
        match self {
            VectorCommitmentNode::Leaf(leaf) => {
                if leaf.key == target {
                    Some(leaf.value.clone())
                } else {
                    None
                }
            }
            VectorCommitmentNode::Branch(branch) => {
                for child in branch.children.iter().flatten() {
                    if let Some(v) = child.find_leaf_value(target) {
                        return Some(v);
                    }
                }
                None
            }
        }
    }

    /// Collect every leaf in this sub-tree into `out`. Mirrors Go's
    /// `tries.GetAllPreloadedLeaves` — used by hyperedge iteration to
    /// enumerate the extrinsic atoms (prover allocations, etc).
    pub fn collect_leaves<'a>(&'a self, out: &mut Vec<&'a LeafNode>) {
        match self {
            VectorCommitmentNode::Leaf(leaf) => out.push(leaf),
            VectorCommitmentNode::Branch(branch) => {
                for child in branch.children.iter().flatten() {
                    child.collect_leaves(out);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_leaf() -> LeafNode {
        LeafNode {
            key: vec![],
            value: vec![],
            hash_target: vec![],
            commitment: vec![],
            size: BigInt::zero(),
        }
    }

    fn leaf_with(key: &[u8], value: &[u8]) -> LeafNode {
        LeafNode {
            key: key.to_vec(),
            value: value.to_vec(),
            hash_target: vec![],
            commitment: vec![],
            size: BigInt::from(value.len() as u64),
        }
    }

    // =================================================================
    // LeafNode::compute_commitment
    // =================================================================

    #[test]
    fn leaf_compute_commitment_produces_64_bytes() {
        let mut leaf = leaf_with(b"key-bytes", b"value-bytes");
        leaf.compute_commitment();
        // SHA-512 digest is 64 bytes.
        assert_eq!(leaf.commitment.len(), 64);
    }

    #[test]
    fn leaf_compute_commitment_is_deterministic() {
        let mut a = leaf_with(b"k", b"v");
        let mut b = leaf_with(b"k", b"v");
        a.compute_commitment();
        b.compute_commitment();
        assert_eq!(a.commitment, b.commitment);
    }

    #[test]
    fn leaf_compute_commitment_differs_by_key() {
        let mut a = leaf_with(b"key-1", b"same-value");
        let mut b = leaf_with(b"key-2", b"same-value");
        a.compute_commitment();
        b.compute_commitment();
        assert_ne!(a.commitment, b.commitment);
    }

    #[test]
    fn leaf_compute_commitment_differs_by_value() {
        let mut a = leaf_with(b"same-key", b"value-a");
        let mut b = leaf_with(b"same-key", b"value-b");
        a.compute_commitment();
        b.compute_commitment();
        assert_ne!(a.commitment, b.commitment);
    }

    #[test]
    fn leaf_compute_commitment_uses_hash_target_when_set() {
        // When `hash_target` is set, it's used instead of `value` in
        // the commitment hash. Two leaves with different values but
        // the same hash_target should produce equal commitments.
        let mut a = LeafNode {
            key: b"k".to_vec(),
            value: b"value-a".to_vec(),
            hash_target: b"precomputed-hash".to_vec(),
            commitment: vec![],
            size: BigInt::zero(),
        };
        let mut b = LeafNode {
            key: b"k".to_vec(),
            value: b"value-b".to_vec(),
            hash_target: b"precomputed-hash".to_vec(),
            commitment: vec![],
            size: BigInt::zero(),
        };
        a.compute_commitment();
        b.compute_commitment();
        // Both leaves have the same key + hash_target → same commitment,
        // even though their `value` fields differ.
        assert_eq!(a.commitment, b.commitment);
    }

    #[test]
    fn leaf_compute_commitment_empty_key_and_value() {
        let mut leaf = empty_leaf();
        leaf.compute_commitment();
        // Still produces a 64-byte digest.
        assert_eq!(leaf.commitment.len(), 64);
        // Commitment is non-zero (SHA-512 of even the empty string
        // produces a fixed, non-zero output).
        assert!(leaf.commitment.iter().any(|&b| b != 0));
    }

    // =================================================================
    // LeafNode::commit (recalculate semantics)
    // =================================================================

    #[test]
    fn leaf_commit_returns_existing_commitment_when_not_recalculating() {
        let mut leaf = leaf_with(b"k", b"v");
        leaf.commitment = vec![0xAAu8; 64]; // pre-set
        let result = leaf.commit(false);
        assert_eq!(result, &[0xAAu8; 64][..]);
    }

    #[test]
    fn leaf_commit_recomputes_when_empty() {
        let mut leaf = leaf_with(b"k", b"v");
        assert!(leaf.commitment.is_empty());
        leaf.commit(false);
        // commit(false) with an empty commitment still triggers a
        // recompute (the code checks `recalculate || commitment.is_empty()`).
        assert_eq!(leaf.commitment.len(), 64);
    }

    #[test]
    fn leaf_commit_force_recalculate_overwrites_existing() {
        let mut leaf = leaf_with(b"k", b"v");
        leaf.commitment = vec![0xBBu8; 64]; // stale
        leaf.commit(true);
        // Should be replaced by a real SHA-512 of the leaf contents.
        assert_ne!(leaf.commitment, vec![0xBBu8; 64]);
        assert_eq!(leaf.commitment.len(), 64);
    }

    // =================================================================
    // BranchNode::new
    // =================================================================

    #[test]
    fn branch_new_empty_children() {
        let branch = BranchNode::new(vec![]);
        assert_eq!(branch.prefix, Vec::<i32>::new());
        assert!(branch.commitment.is_empty());
        assert_eq!(branch.size, BigInt::zero());
        assert_eq!(branch.leaf_count, 0);
        assert_eq!(branch.longest_branch, 0);
        // All 64 child slots are None.
        assert!(branch.children.iter().all(|c| c.is_none()));
    }

    #[test]
    fn branch_new_with_prefix() {
        let branch = BranchNode::new(vec![1, 2, 3]);
        assert_eq!(branch.prefix, vec![1, 2, 3]);
        assert!(branch.commitment.is_empty());
    }

    // =================================================================
    // BranchNode::child_count
    // =================================================================

    #[test]
    fn branch_child_count_empty_is_zero() {
        let branch = BranchNode::new(vec![]);
        assert_eq!(branch.child_count(), 0);
    }

    #[test]
    fn branch_child_count_reflects_set_children() {
        let mut branch = BranchNode::new(vec![]);
        let leaf = leaf_with(b"k", b"v");
        branch.children[0] = Some(Box::new(VectorCommitmentNode::Leaf(leaf.clone())));
        branch.children[5] = Some(Box::new(VectorCommitmentNode::Leaf(leaf.clone())));
        branch.children[63] = Some(Box::new(VectorCommitmentNode::Leaf(leaf)));
        assert_eq!(branch.child_count(), 3);
    }

    #[test]
    fn branch_child_count_all_64_children() {
        let mut branch = BranchNode::new(vec![]);
        let leaf = leaf_with(b"k", b"v");
        for i in 0..BRANCH_NODES {
            branch.children[i] = Some(Box::new(VectorCommitmentNode::Leaf(leaf.clone())));
        }
        assert_eq!(branch.child_count(), BRANCH_NODES);
    }

    // =================================================================
    // VectorCommitmentNode accessors
    // =================================================================

    #[test]
    fn node_is_leaf_vs_is_branch() {
        let leaf = VectorCommitmentNode::Leaf(leaf_with(b"k", b"v"));
        let branch = VectorCommitmentNode::Branch(BranchNode::new(vec![]));
        assert!(leaf.is_leaf());
        assert!(!leaf.is_branch());
        assert!(!branch.is_leaf());
        assert!(branch.is_branch());
    }

    #[test]
    fn node_commitment_returns_leaf_commitment() {
        let mut leaf = leaf_with(b"k", b"v");
        leaf.commitment = vec![0xAA; 64];
        let node = VectorCommitmentNode::Leaf(leaf);
        assert_eq!(node.commitment(), &[0xAA; 64][..]);
    }

    #[test]
    fn node_commitment_returns_branch_commitment() {
        let mut branch = BranchNode::new(vec![]);
        branch.commitment = vec![0xBB; 64];
        let node = VectorCommitmentNode::Branch(branch);
        assert_eq!(node.commitment(), &[0xBB; 64][..]);
    }

    #[test]
    fn node_size_returns_underlying_size() {
        let leaf_size = BigInt::from(42u64);
        let leaf = LeafNode {
            key: vec![],
            value: vec![],
            hash_target: vec![],
            commitment: vec![],
            size: leaf_size.clone(),
        };
        let node = VectorCommitmentNode::Leaf(leaf);
        assert_eq!(node.size(), &leaf_size);

        let mut branch = BranchNode::new(vec![]);
        branch.size = BigInt::from(1000u64);
        let node = VectorCommitmentNode::Branch(branch);
        assert_eq!(node.size(), &BigInt::from(1000u64));
    }

    // =================================================================
    // Clone independence
    // =================================================================

    #[test]
    fn leaf_clone_is_independent() {
        let mut original = leaf_with(b"k", b"v");
        original.compute_commitment();
        let cloned = original.clone();
        assert_eq!(cloned.commitment, original.commitment);
        assert_eq!(cloned.key, original.key);
        assert_eq!(cloned.value, original.value);

        // Mutate the original; clone stays the same.
        original.value = b"mutated".to_vec();
        assert_ne!(original.value, cloned.value);
    }

    #[test]
    fn branch_clone_preserves_children_count() {
        let mut original = BranchNode::new(vec![1, 2]);
        let leaf = leaf_with(b"k", b"v");
        original.children[10] =
            Some(Box::new(VectorCommitmentNode::Leaf(leaf.clone())));
        original.children[20] =
            Some(Box::new(VectorCommitmentNode::Leaf(leaf)));

        let cloned = original.clone();
        assert_eq!(cloned.prefix, original.prefix);
        assert_eq!(cloned.child_count(), 2);
        assert_eq!(cloned.child_count(), original.child_count());
    }
}
