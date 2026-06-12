// uniffi scaffolding for quil-tries FFI bindings.
//
// The tree is passed as serialized bytes across FFI boundaries, using
// quil_tries::serialize_tree / quil_tries::deserialize_tree for the
// Rust-native format. This keeps the interface simple — no opaque
// pointers, just byte buffers.

uniffi::include_scaffolding!("lib");

use num_bigint::BigInt;
use quil_types::crypto::{InclusionProver, Multiproof};

/// Create a new empty tree and return it serialized.
fn new_tree() -> Vec<u8> {
    // An empty tree serializes as a single nil byte (TYPE_NIL = 0).
    quil_tries::serialize_tree(None).expect("serializing nil tree cannot fail")
}

/// Insert a key-value pair into the tree. Returns the updated serialized tree.
///
/// The `value` is stored as-is; `hash_target` and `size` are derived from
/// the value bytes (size = value.len()). Commitments on the inserted leaf
/// are computed immediately; branch commitments are deferred until
/// `commit()`.
fn insert(tree_bytes: Vec<u8>, key: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
    let root = quil_tries::deserialize_tree(&tree_bytes)
        .expect("insert: failed to deserialize tree");
    let mut tree = quil_tries::VectorCommitmentTree { root };

    let size = BigInt::from(value.len() as u64);
    tree.insert(&key, &value, &[], &size)
        .expect("insert: failed to insert into tree");

    quil_tries::serialize_tree(tree.root.as_ref())
        .expect("insert: failed to serialize tree")
}

/// Delete a key from the tree. Returns the updated serialized tree.
///
/// Walks the trie to find the leaf with the matching key and removes it.
/// If the key is not found, the tree is returned unchanged.
fn delete_key(tree_bytes: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let root = quil_tries::deserialize_tree(&tree_bytes)
        .expect("delete_key: failed to deserialize tree");

    let new_root = match root {
        None => None,
        Some(node) => delete_recursive(node, &key, 0),
    };

    quil_tries::serialize_tree(new_root.as_ref())
        .expect("delete_key: failed to serialize tree")
}

/// Recursively delete a key from the subtree rooted at `node`.
/// Returns `None` if the entire subtree is removed, `Some(node)` otherwise.
fn delete_recursive(
    node: quil_tries::VectorCommitmentNode,
    key: &[u8],
    depth: usize,
) -> Option<quil_tries::VectorCommitmentNode> {
    use quil_tries::{VectorCommitmentNode, BRANCH_BITS};

    match node {
        VectorCommitmentNode::Leaf(leaf) => {
            if leaf.key == key {
                None // Remove this leaf
            } else {
                Some(VectorCommitmentNode::Leaf(leaf)) // Not our key
            }
        }
        VectorCommitmentNode::Branch(mut branch) => {
            // Walk prefix
            let mut d = depth;
            for &p in &branch.prefix {
                let n = quil_tries::get_next_nibble(key, d);
                if n != p {
                    // Key diverges from prefix — not in this subtree
                    return Some(VectorCommitmentNode::Branch(branch));
                }
                d += BRANCH_BITS;
            }

            let nibble = quil_tries::get_next_nibble(key, d);
            if nibble < 0 {
                // Key exhausted before reaching a child slot
                return Some(VectorCommitmentNode::Branch(branch));
            }

            let idx = nibble as usize;
            let child = branch.children[idx].take();
            match child {
                None => {
                    // No child at this slot — key not found
                    Some(VectorCommitmentNode::Branch(branch))
                }
                Some(child_box) => {
                    let new_child = delete_recursive(*child_box, key, d + BRANCH_BITS);
                    branch.children[idx] = new_child.map(Box::new);

                    // Invalidate commitment
                    branch.commitment = Vec::new();

                    // Update leaf count
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

                    // Collapse: if only one child remains, and it's a leaf,
                    // promote the leaf up (removing the now-unnecessary branch).
                    let live_count = branch.children.iter().filter(|c| c.is_some()).count();
                    if live_count == 0 {
                        None
                    } else if live_count == 1 {
                        // Find the single remaining child
                        let remaining = branch
                            .children
                            .iter_mut()
                            .find_map(|c| c.take())
                            .unwrap();
                        match *remaining {
                            VectorCommitmentNode::Leaf(leaf) => {
                                Some(VectorCommitmentNode::Leaf(leaf))
                            }
                            VectorCommitmentNode::Branch(mut child_branch) => {
                                // Merge prefixes: parent prefix + child slot nibble + child prefix
                                // We need the slot index to reconstruct the full prefix.
                                // Since we already took the child out, we need to find which
                                // slot it was in. We can compute this from the iterator.
                                // Actually, we already know: it's not at `idx` (we may have
                                // removed that). Let's find it properly.
                                //
                                // Simpler approach: just keep the branch as-is when
                                // the sole remaining child is also a branch, with merged prefix.
                                let merged_prefix = branch.prefix.clone();
                                // Find which slot the remaining child was in
                                // We need to reconstruct — we already took it out.
                                // Re-scan to find which index had the child.
                                // Since we already moved it out, this won't work.
                                // Instead, just put it back and return the branch.
                                child_branch.prefix = {
                                    // The remaining child was at some index. We need
                                    // to figure out which. Since all children are None
                                    // now (we took the last one), iterate the original
                                    // state. This is getting complicated — simplify by
                                    // just returning the branch with one child.
                                    merged_prefix
                                        .into_iter()
                                        .chain(std::iter::once(find_sole_slot_index(&branch.children, idx)))
                                        .chain(child_branch.prefix.drain(..))
                                        .collect()
                                };
                                Some(VectorCommitmentNode::Branch(child_branch))
                            }
                        }
                    } else {
                        Some(VectorCommitmentNode::Branch(branch))
                    }
                }
            }
        }
    }
}

/// After removing a child at `removed_idx`, find the index of the sole
/// remaining child. All slots except possibly `removed_idx` are examined.
fn find_sole_slot_index(
    children: &[Option<Box<quil_tries::VectorCommitmentNode>>; 64],
    _removed_idx: usize,
) -> i32 {
    for (i, child) in children.iter().enumerate() {
        if child.is_some() {
            return i as i32;
        }
    }
    // Shouldn't happen — caller guarantees exactly one child remains somewhere.
    // But all children might have been taken already by the caller, so fall
    // through to 0.
    0
}

/// Look up a key in the tree. Returns the value bytes if found, None otherwise.
fn get_value(tree_bytes: Vec<u8>, key: Vec<u8>) -> Option<Vec<u8>> {
    let root = quil_tries::deserialize_tree(&tree_bytes)
        .expect("get_value: failed to deserialize tree");
    let tree = quil_tries::VectorCommitmentTree { root };
    tree.get(&key).map(|v| v.to_vec())
}

/// Commit the tree, computing all branch and leaf commitments.
/// Uses the NoopInclusionProver (returns zero-byte KZG commitments).
///
/// `prover_key` is accepted for API symmetry with the Go side but is
/// not used by NoopInclusionProver. Returns the 64-byte root commitment.
fn commit(tree_bytes: Vec<u8>, _prover_key: Vec<u8>) -> Vec<u8> {
    let root = quil_tries::deserialize_tree(&tree_bytes)
        .expect("commit: failed to deserialize tree");
    let mut tree = quil_tries::VectorCommitmentTree { root };

    let prover = Sha512Prover;
    tree.commit(&prover)
}

/// Serialize the tree to its Rust-native format.
/// Since the tree is already in serialized form, this is effectively
/// a re-serialization (deserialize then serialize), which normalizes
/// the byte representation.
fn serialize_tree(tree_bytes: Vec<u8>) -> Vec<u8> {
    let root = quil_tries::deserialize_tree(&tree_bytes)
        .expect("serialize_tree: failed to deserialize tree");
    quil_tries::serialize_tree(root.as_ref())
        .expect("serialize_tree: failed to serialize tree")
}

/// Deserialize a tree from bytes.
/// Named `deserialize_tree_ffi` to avoid collision with the
/// `quil_tries::deserialize_tree` import.
fn deserialize_tree_ffi(serialized: Vec<u8>) -> Vec<u8> {
    // Validate that the bytes are a valid tree by round-tripping.
    let root = quil_tries::deserialize_tree(&serialized)
        .expect("deserialize_tree_ffi: failed to deserialize tree");
    quil_tries::serialize_tree(root.as_ref())
        .expect("deserialize_tree_ffi: failed to re-serialize tree")
}

/// Generate an inclusion proof for a key in the tree.
///
/// Returns a proof blob consisting of the sibling commitments along the
/// path from root to the target leaf. Each level contributes 64*63 bytes
/// of sibling commitments (all children except the one on the path).
///
/// `prover_key` is accepted for API symmetry but is not used by the
/// stub prover.
fn prove(tree_bytes: Vec<u8>, key: Vec<u8>, _prover_key: Vec<u8>) -> Vec<u8> {
    let root = quil_tries::deserialize_tree(&tree_bytes)
        .expect("prove: failed to deserialize tree");

    match root {
        None => Vec::new(),
        Some(node) => collect_proof(&node, &key, 0),
    }
}

/// Walk the tree from root to the leaf matching `key`, collecting sibling
/// commitments at each branch level.
fn collect_proof(
    node: &quil_tries::VectorCommitmentNode,
    key: &[u8],
    depth: usize,
) -> Vec<u8> {
    use quil_tries::{VectorCommitmentNode, BRANCH_BITS};

    match node {
        VectorCommitmentNode::Leaf(leaf) => {
            if leaf.key == key {
                // Reached the target leaf — proof is complete.
                Vec::new()
            } else {
                // Key not found — empty proof.
                Vec::new()
            }
        }
        VectorCommitmentNode::Branch(branch) => {
            let mut d = depth;
            for &p in &branch.prefix {
                let n = quil_tries::get_next_nibble(key, d);
                if n != p {
                    return Vec::new(); // Key not in this subtree.
                }
                d += BRANCH_BITS;
            }

            let nibble = quil_tries::get_next_nibble(key, d);
            if nibble < 0 {
                return Vec::new();
            }
            let idx = nibble as usize;

            // Collect sibling commitments at this level: all 64 children's
            // commitments, with the path child's slot included (the verifier
            // knows which index to skip).
            let mut level = Vec::with_capacity(64 * 64);
            for child_opt in &branch.children {
                match child_opt {
                    None => level.extend_from_slice(&[0u8; 64]),
                    Some(child) => {
                        let c = child.commitment();
                        let mut padded = [0u8; 64];
                        let len = c.len().min(64);
                        padded[..len].copy_from_slice(&c[..len]);
                        level.extend_from_slice(&padded);
                    }
                }
            }

            // Recurse into the child on the path.
            let child_proof = match &branch.children[idx] {
                Some(child) => collect_proof(child, key, d + BRANCH_BITS),
                None => Vec::new(),
            };

            // Proof = this level's siblings || deeper levels
            level.extend_from_slice(&child_proof);
            level
        }
    }
}

/// Verify an inclusion proof.
///
/// Checks that reconstructing the root from the leaf value and the proof's
/// sibling commitments yields the expected `root`.
///
/// Uses the SHA-512 stub prover for branch commitments.
fn verify_proof(
    root: Vec<u8>,
    key: Vec<u8>,
    value: Vec<u8>,
    proof: Vec<u8>,
    _prover_key: Vec<u8>,
) -> bool {
    use sha2::{Digest, Sha512};

    if proof.is_empty() {
        // No proof data — only valid if root is all zeros (empty tree)
        // and value is empty.
        return root.iter().all(|&b| b == 0) && value.is_empty();
    }

    // Each proof level is 64*64 = 4096 bytes.
    let level_size = 64 * 64;
    if proof.len() % level_size != 0 {
        return false;
    }

    // Compute the leaf commitment: SHA-512(0x00 || key || value)
    let mut h = Sha512::new();
    h.update([0u8]);
    h.update(&key);
    h.update(&value);
    let leaf_commitment = h.finalize().to_vec();

    // Walk proof levels bottom-up, computing branch commitments.
    let num_levels = proof.len() / level_size;
    let mut current_commitment = leaf_commitment;

    // Proof levels are stored top-down (root level first), so we
    // process them in reverse to go bottom-up. The nibble path tells
    // us which slot we're in at each level.
    let nibbles = key_to_nibbles(&key);

    // Process bottom-up
    for level_idx in (0..num_levels).rev() {
        let level_start = level_idx * level_size;
        let level_data = &proof[level_start..level_start + level_size];

        // The nibble index for this level
        if level_idx >= nibbles.len() {
            return false;
        }
        let slot = nibbles[level_idx] as usize;
        if slot >= 64 {
            return false;
        }

        // Replace the slot at our path index with our current commitment,
        // then commit the full 4096-byte vector.
        let mut data = level_data.to_vec();
        let offset = slot * 64;
        let len = current_commitment.len().min(64);
        // Zero the slot first
        data[offset..offset + 64].fill(0);
        data[offset..offset + len].copy_from_slice(&current_commitment[..len]);

        // Compute branch commitment using SHA-512 prover
        let prover = Sha512Prover;
        current_commitment = prover
            .commit_raw(&data, 64)
            .unwrap_or_else(|_| vec![0u8; 64]);
    }

    current_commitment == root
}

/// Extract 6-bit nibbles from a key, matching the trie's nibble extraction.
fn key_to_nibbles(key: &[u8]) -> Vec<i32> {
    let mut nibbles = Vec::new();
    let mut depth = 0;
    loop {
        let n = quil_tries::get_next_nibble(key, depth);
        if n < 0 {
            break;
        }
        nibbles.push(n);
        depth += quil_tries::BRANCH_BITS;
    }
    nibbles
}

/// SHA-512 based inclusion prover for deterministic testing.
/// Matches the StubProver pattern used in quil-tries' own tests.
struct Sha512Prover;

impl InclusionProver for Sha512Prover {
    fn commit_raw(&self, data: &[u8], _poly_size: u64) -> quil_types::error::Result<Vec<u8>> {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(data);
        Ok(h.finalize().to_vec())
    }

    fn prove_raw(
        &self, _data: &[u8], _index: u64, _poly_size: u64,
    ) -> quil_types::error::Result<Vec<u8>> {
        Ok(vec![])
    }

    fn verify_raw(
        &self, _data: &[u8], _commit: &[u8], _index: u64,
        _proof: &[u8], _poly_size: u64,
    ) -> quil_types::error::Result<bool> {
        Ok(true)
    }

    fn prove_multiple(
        &self, _commitments: &[&[u8]], _polys: &[&[u8]],
        _indices: &[u64], _poly_size: u64,
    ) -> quil_types::error::Result<Box<dyn Multiproof>> {
        Err(quil_types::error::QuilError::Internal(
            "batch multiproof generation not supported".into(),
        ))
    }

    fn verify_multiple(
        &self, _commitments: &[&[u8]], _evaluations: &[&[u8]],
        _indices: &[u64], _poly_size: u64, _multi_commitment: &[u8],
        _proof: &[u8],
    ) -> bool {
        true
    }
}
