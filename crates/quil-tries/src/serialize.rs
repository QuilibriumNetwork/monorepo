use std::io::{self, Read};

use num_bigint::BigInt;
use num_traits::Zero;

use quil_types::error::{QuilError, Result};

use crate::node::{BranchNode, LeafNode, VectorCommitmentNode};
use crate::{TYPE_BRANCH, TYPE_LEAF, TYPE_NIL};

/// Maximum legitimate prefix length for a tree node. A vector
/// commitment tree path is at most 64 nibbles (32-byte addresses,
/// 4 bits/nibble × 64 = 256 bits). 256 gives generous headroom over
/// the legitimate max while rejecting deserialization bombs that
/// would otherwise cause `Vec::with_capacity(u32::MAX)` to attempt a
/// 16GB allocation.
const MAX_TREE_PREFIX_LEN: usize = 256;

/// Maximum legitimate length for a length-prefixed field in a node
/// (leaf value, commitment, size_bytes). 16MB is well over any
/// realistic field size while still preventing OOM via a crafted
/// u64 length prefix on untrusted input.
const MAX_LENGTH_PREFIXED_FIELD: usize = 16 * 1024 * 1024;

/// Maximum recursion depth for nested branches. Tree paths are at
/// most 64 nibbles, so even pathologically-unbalanced trees can't
/// exceed 64 in depth via legitimate construction. 128 provides
/// headroom; deeper inputs are rejected to prevent stack overflow.
const MAX_DESERIALIZE_DEPTH: usize = 128;

/// Serialize a tree to bytes.
pub fn serialize_tree(root: Option<&VectorCommitmentNode>) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    serialize_node(&mut buf, root)?;
    Ok(buf)
}

/// Deserialize a tree from bytes.
pub fn deserialize_tree(data: &[u8]) -> Result<Option<VectorCommitmentNode>> {
    let mut cursor = io::Cursor::new(data);
    deserialize_node_at_depth(&mut cursor, 0)
}

/// Per-node lazy storage encoding: branch children are NOT included —
/// they live at their own keys and are fetched on demand via the by-path
/// index. Leaf value is also stripped (the per-vertex keyspace owns it).
pub fn serialize_node_solo(node: &VectorCommitmentNode) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(128);
    match node {
        VectorCommitmentNode::Leaf(leaf) => {
            buf.push(TYPE_LEAF);
            write_length_prefixed(&mut buf, &leaf.key)?;
            write_length_prefixed(&mut buf, &[])?;
            write_length_prefixed(&mut buf, &leaf.hash_target)?;
            write_length_prefixed(&mut buf, &leaf.commitment)?;
            let size_bytes = leaf.size.to_signed_bytes_be();
            write_length_prefixed(&mut buf, &size_bytes)?;
        }
        VectorCommitmentNode::Branch(branch) => {
            buf.push(TYPE_BRANCH);
            buf.extend_from_slice(&(branch.prefix.len() as u32).to_be_bytes());
            for &p in &branch.prefix {
                buf.extend_from_slice(&(p as i32).to_be_bytes());
            }
            write_length_prefixed(&mut buf, &branch.commitment)?;
            let size_bytes = branch.size.to_signed_bytes_be();
            write_length_prefixed(&mut buf, &size_bytes)?;
            buf.extend_from_slice(&(branch.leaf_count as i64).to_be_bytes());
            buf.extend_from_slice(&(branch.longest_branch as i32).to_be_bytes());
        }
    }
    Ok(buf)
}

/// Inverse of [`serialize_node_solo`]. Branch children come back empty;
/// the lazy walker loads them individually.
pub fn deserialize_node_solo(data: &[u8]) -> Result<VectorCommitmentNode> {
    let mut r = io::Cursor::new(data);
    let mut type_byte = [0u8; 1];
    r.read_exact(&mut type_byte)
        .map_err(|e| QuilError::Serialization(e.to_string()))?;
    match type_byte[0] {
        TYPE_LEAF => {
            let key = read_length_prefixed(&mut r)?;
            let value = read_length_prefixed(&mut r)?;
            let hash_target = read_length_prefixed(&mut r)?;
            let commitment = read_length_prefixed(&mut r)?;
            let size_bytes = read_length_prefixed(&mut r)?;
            let size = if size_bytes.is_empty() {
                BigInt::zero()
            } else {
                BigInt::from_signed_bytes_be(&size_bytes)
            };
            Ok(VectorCommitmentNode::Leaf(LeafNode {
                key,
                value,
                hash_target,
                commitment,
                size,
            }))
        }
        TYPE_BRANCH => {
            let prefix_len = read_u32(&mut r)? as usize;
            if prefix_len > MAX_TREE_PREFIX_LEN {
                return Err(QuilError::Serialization(format!(
                    "tree deserialize: prefix length {} exceeds max {}",
                    prefix_len, MAX_TREE_PREFIX_LEN,
                )));
            }
            let mut prefix = Vec::with_capacity(prefix_len);
            for _ in 0..prefix_len {
                prefix.push(read_i32(&mut r)?);
            }
            let commitment = read_length_prefixed(&mut r)?;
            let size_bytes = read_length_prefixed(&mut r)?;
            let size = if size_bytes.is_empty() {
                BigInt::zero()
            } else {
                BigInt::from_signed_bytes_be(&size_bytes)
            };
            let leaf_count = read_i64(&mut r)? as usize;
            let longest_branch = read_i32(&mut r)? as usize;
            let children: [Option<Box<VectorCommitmentNode>>; 64] =
                std::array::from_fn(|_| None);
            // `full_prefix` is filled in by the walker from its descent path.
            Ok(VectorCommitmentNode::Branch(BranchNode {
                prefix,
                children,
                commitment,
                size,
                leaf_count,
                longest_branch,
                full_prefix: Vec::new(),
                fully_loaded: false,
            }))
        }
        // TYPE_NIL is invalid in solo format — a non-existent node is
        // represented by absence from the by-key index, not by a nil
        // record.
        other => Err(QuilError::Serialization(format!(
            "deserialize_node_solo: unexpected node type byte {}",
            other
        ))),
    }
}

/// Serialize a node to a writer.
fn serialize_node(w: &mut Vec<u8>, node: Option<&VectorCommitmentNode>) -> Result<()> {
    match node {
        None => {
            w.push(TYPE_NIL);
            Ok(())
        }
        Some(VectorCommitmentNode::Leaf(leaf)) => {
            w.push(TYPE_LEAF);
            write_length_prefixed(w, &leaf.key)?;
            // Include the full leaf value. `add_vertex` writes leaves
            // with `hash_target = []`, so the leaf commitment is
            // `SHA512(0x00 || key || value)`. Stripping `value` here
            // (the previous behaviour, mirrored from per-node solo
            // encoding where the per-vertex keyspace holds the bytes)
            // breaks every subsequent `tree.commit(prover)` reload —
            // the recompute hashes `SHA512(key || empty)` and the
            // root diverges from what we just wrote. The whole-tree
            // blob is a local cache, so duplicating the value here
            // is cheap compared with the cost of saving a broken
            // commitment on every sync.
            write_length_prefixed(w, &leaf.value)?;
            write_length_prefixed(w, &leaf.hash_target)?;
            write_length_prefixed(w, &leaf.commitment)?;
            let size_bytes = leaf.size.to_signed_bytes_be();
            write_length_prefixed(w, &size_bytes)?;
            Ok(())
        }
        Some(VectorCommitmentNode::Branch(branch)) => {
            w.push(TYPE_BRANCH);

            // Prefix
            w.extend_from_slice(&(branch.prefix.len() as u32).to_be_bytes());
            for &p in &branch.prefix {
                w.extend_from_slice(&(p as i32).to_be_bytes());
            }

            // Children (recursive)
            for child in &branch.children {
                serialize_node(w, child.as_deref())?;
            }

            // Commitment
            write_length_prefixed(w, &branch.commitment)?;

            // Size
            let size_bytes = branch.size.to_signed_bytes_be();
            write_length_prefixed(w, &size_bytes)?;

            // Leaf count and longest branch
            w.extend_from_slice(&(branch.leaf_count as i64).to_be_bytes());
            w.extend_from_slice(&(branch.longest_branch as i32).to_be_bytes());

            Ok(())
        }
    }
}

/// Deserialize a node from a reader. The depth counter caps nesting
/// to prevent stack overflow on a crafted serialized tree (see
/// `MAX_DESERIALIZE_DEPTH`). External entrypoint `deserialize_tree`
/// invokes this with depth=0.
fn deserialize_node_at_depth<R: Read>(
    r: &mut R,
    depth: usize,
) -> Result<Option<VectorCommitmentNode>> {
    if depth > MAX_DESERIALIZE_DEPTH {
        return Err(QuilError::Serialization(format!(
            "tree deserialize: nesting depth exceeded {}",
            MAX_DESERIALIZE_DEPTH,
        )));
    }
    let mut type_byte = [0u8; 1];
    r.read_exact(&mut type_byte)
        .map_err(|e| QuilError::Serialization(e.to_string()))?;

    match type_byte[0] {
        TYPE_NIL => Ok(None),
        TYPE_LEAF => {
            let key = read_length_prefixed(r)?;
            let value = read_length_prefixed(r)?;
            let hash_target = read_length_prefixed(r)?;
            let commitment = read_length_prefixed(r)?;
            let size_bytes = read_length_prefixed(r)?;
            let size = if size_bytes.is_empty() {
                BigInt::zero()
            } else {
                BigInt::from_signed_bytes_be(&size_bytes)
            };

            Ok(Some(VectorCommitmentNode::Leaf(LeafNode {
                key,
                value,
                hash_target,
                commitment,
                size,
            })))
        }
        TYPE_BRANCH => {
            // Prefix
            let prefix_len = read_u32(r)? as usize;
            if prefix_len > MAX_TREE_PREFIX_LEN {
                return Err(QuilError::Serialization(format!(
                    "tree deserialize: prefix length {} exceeds max {}",
                    prefix_len, MAX_TREE_PREFIX_LEN,
                )));
            }
            let mut prefix = Vec::with_capacity(prefix_len);
            for _ in 0..prefix_len {
                prefix.push(read_i32(r)?);
            }

            // Children
            let mut children: [Option<Box<VectorCommitmentNode>>; 64] =
                std::array::from_fn(|_| None);
            for slot in children.iter_mut() {
                if let Some(child) = deserialize_node_at_depth(r, depth + 1)? {
                    *slot = Some(Box::new(child));
                }
            }

            // Commitment
            let commitment = read_length_prefixed(r)?;

            // Size
            let size_bytes = read_length_prefixed(r)?;
            let size = if size_bytes.is_empty() {
                BigInt::zero()
            } else {
                BigInt::from_signed_bytes_be(&size_bytes)
            };

            // Leaf count and longest branch
            let leaf_count = read_i64(r)? as usize;
            let longest_branch = read_i32(r)? as usize;

            // Whole-tree deserialization always returns a fully-loaded
            // tree (every child has been read inline). The walker can
            // skip lazy fetches for these branches.
            Ok(Some(VectorCommitmentNode::Branch(BranchNode {
                prefix,
                children,
                commitment,
                size,
                leaf_count,
                longest_branch,
                full_prefix: Vec::new(),
                fully_loaded: true,
            })))
        }
        other => Err(QuilError::Serialization(format!(
            "unknown node type byte: {}",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_length_prefixed(w: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    w.extend_from_slice(&(data.len() as u64).to_be_bytes());
    w.extend_from_slice(data);
    Ok(())
}

fn read_length_prefixed<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let len = read_u64(r)? as usize;
    if len > MAX_LENGTH_PREFIXED_FIELD {
        return Err(QuilError::Serialization(format!(
            "tree deserialize: length-prefixed field {} exceeds max {}",
            len, MAX_LENGTH_PREFIXED_FIELD,
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|e| QuilError::Serialization(e.to_string()))?;
    Ok(buf)
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)
        .map_err(|e| QuilError::Serialization(e.to_string()))?;
    Ok(u32::from_be_bytes(buf))
}

fn read_i32<R: Read>(r: &mut R) -> Result<i32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)
        .map_err(|e| QuilError::Serialization(e.to_string()))?;
    Ok(i32::from_be_bytes(buf))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)
        .map_err(|e| QuilError::Serialization(e.to_string()))?;
    Ok(u64::from_be_bytes(buf))
}

fn read_i64<R: Read>(r: &mut R) -> Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)
        .map_err(|e| QuilError::Serialization(e.to_string()))?;
    Ok(i64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    #[test]
    fn test_roundtrip_nil() {
        let data = serialize_tree(None).unwrap();
        let result = deserialize_tree(&data).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn solo_leaf_round_trip() {
        let mut leaf = LeafNode {
            key: vec![0xAA, 0xBB, 0xCC, 0xDD],
            value: vec![0xDE, 0xAD, 0xBE, 0xEF],
            hash_target: vec![0x01; 32],
            commitment: vec![0x02; 64],
            size: BigInt::from(0x1234_5678i64),
        };
        leaf.compute_commitment();
        let node = VectorCommitmentNode::Leaf(leaf.clone());
        let bytes = serialize_node_solo(&node).unwrap();
        let back = deserialize_node_solo(&bytes).unwrap();
        match back {
            VectorCommitmentNode::Leaf(l) => {
                assert_eq!(l.key, leaf.key);
                // Solo format drops the value (matches whole-tree blob).
                assert!(l.value.is_empty());
                assert_eq!(l.hash_target, leaf.hash_target);
                assert_eq!(l.commitment, leaf.commitment);
                assert_eq!(l.size, leaf.size);
            }
            _ => panic!("expected leaf"),
        }
    }

    #[test]
    fn solo_branch_round_trip_drops_children() {
        // Build a branch with two non-empty children and verify that
        // serialize_node_solo writes a fixed-size record that does NOT
        // include child data. On deserialize, all children come back
        // as None — the lazy walker will load them via the path index.
        let child_leaf = LeafNode {
            key: vec![0x01, 0x02],
            value: vec![],
            hash_target: vec![0x33; 32],
            commitment: vec![0x44; 64],
            size: BigInt::from(5),
        };
        let mut children: [Option<Box<VectorCommitmentNode>>; 64] =
            std::array::from_fn(|_| None);
        children[7] = Some(Box::new(VectorCommitmentNode::Leaf(child_leaf.clone())));
        children[42] = Some(Box::new(VectorCommitmentNode::Leaf(child_leaf)));
        let branch = BranchNode {
            prefix: vec![3, 5, 7],
            children,
            commitment: vec![0xFF; 64],
            size: BigInt::from(0x9999_8888_7777_i64),
            leaf_count: 12,
            longest_branch: 9,
            full_prefix: Vec::new(),
            fully_loaded: true,
        };
        let node = VectorCommitmentNode::Branch(branch.clone());
        let bytes = serialize_node_solo(&node).unwrap();
        let back = deserialize_node_solo(&bytes).unwrap();
        match back {
            VectorCommitmentNode::Branch(b) => {
                assert_eq!(b.prefix, branch.prefix);
                assert_eq!(b.commitment, branch.commitment);
                assert_eq!(b.size, branch.size);
                assert_eq!(b.leaf_count, branch.leaf_count);
                assert_eq!(b.longest_branch, branch.longest_branch);
                // Children are NOT in the on-disk solo record.
                assert!(b.children.iter().all(|c| c.is_none()));
            }
            _ => panic!("expected branch"),
        }

        // Sanity: the solo format is *much* smaller than the whole-tree
        // format for the same branch with two children.
        let whole_tree_bytes = serialize_tree(Some(&node)).unwrap();
        assert!(
            bytes.len() < whole_tree_bytes.len(),
            "solo {} should be smaller than whole-tree {}",
            bytes.len(),
            whole_tree_bytes.len()
        );
    }

    /// Hand-build the byte sequence the Go migrator
    /// (`translateGoNodeToRustSolo` at
    /// `node/store/migrate_to_rocksdb.go`) emits for a leaf, then
    /// verify `deserialize_node_solo` parses it correctly. Guards
    /// against drift between the migrator's emission and Rust's
    /// reader.
    #[test]
    fn migrator_leaf_output_round_trips() {
        // Sample leaf: key=[0xAA,0xBB], hash_target=[0x11;32],
        // commitment=[0x22;64], size=0xDEAD (big-endian: 0xDE, 0xAD).
        // Value field is empty (migrator strips it).
        let key = vec![0xAA, 0xBB];
        let hash_target = vec![0x11u8; 32];
        let commitment = vec![0x22u8; 64];
        // 0xDEAD = 57005. Go's `big.Int.Bytes()` would emit
        // [0xDE, 0xAD] (high bit set), and the Go migrator's
        // `goUnsignedToRustSignedBigInt` prepends 0x00 so Rust's
        // `BigInt::from_signed_bytes_be` reads it as positive.
        let size_bytes = vec![0x00, 0xDE, 0xAD];

        let mut emitted = Vec::<u8>::new();
        emitted.push(TYPE_LEAF);
        // key
        emitted.extend_from_slice(&(key.len() as u64).to_be_bytes());
        emitted.extend_from_slice(&key);
        // empty value (migrator: writeLenPrefixedU64(out, nil))
        emitted.extend_from_slice(&0u64.to_be_bytes());
        // hash_target
        emitted.extend_from_slice(&(hash_target.len() as u64).to_be_bytes());
        emitted.extend_from_slice(&hash_target);
        // commitment
        emitted.extend_from_slice(&(commitment.len() as u64).to_be_bytes());
        emitted.extend_from_slice(&commitment);
        // size (forwarded as raw bytes — for non-negative sizes < 2^63
        // the bytes are identical to BigInt::from_signed_bytes_be).
        emitted.extend_from_slice(&(size_bytes.len() as u64).to_be_bytes());
        emitted.extend_from_slice(&size_bytes);

        let parsed = deserialize_node_solo(&emitted).expect("parse leaf");
        match parsed {
            VectorCommitmentNode::Leaf(l) => {
                assert_eq!(l.key, key);
                assert!(l.value.is_empty(), "value must be empty after migration");
                assert_eq!(l.hash_target, hash_target);
                assert_eq!(l.commitment, commitment);
                assert_eq!(l.size, BigInt::from(0xDEADi32));
            }
            _ => panic!("expected leaf"),
        }
    }

    /// Same idea for branches. The migrator's emission MUST NOT
    /// include the pathLength + fullPrefix prefix that Go's on-disk
    /// format has — the walker computes full_prefix from descent.
    #[test]
    fn migrator_branch_output_round_trips() {
        // Branch with local prefix=[1, 2, 3], commitment, size, etc.
        let prefix: Vec<i32> = vec![1, 2, 3];
        let commitment = vec![0x33u8; 64];
        let size_bytes = vec![0x01, 0x02]; // 258
        let leaf_count: i64 = 7;
        let longest_branch: i32 = 3;

        let mut emitted = Vec::<u8>::new();
        emitted.push(TYPE_BRANCH);
        emitted.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
        for &p in &prefix {
            emitted.extend_from_slice(&p.to_be_bytes());
        }
        emitted.extend_from_slice(&(commitment.len() as u64).to_be_bytes());
        emitted.extend_from_slice(&commitment);
        emitted.extend_from_slice(&(size_bytes.len() as u64).to_be_bytes());
        emitted.extend_from_slice(&size_bytes);
        emitted.extend_from_slice(&leaf_count.to_be_bytes());
        emitted.extend_from_slice(&longest_branch.to_be_bytes());

        let parsed = deserialize_node_solo(&emitted).expect("parse branch");
        match parsed {
            VectorCommitmentNode::Branch(b) => {
                assert_eq!(b.prefix, prefix);
                assert!(
                    b.children.iter().all(|c| c.is_none()),
                    "children must be empty after migration",
                );
                assert_eq!(b.commitment, commitment);
                assert_eq!(b.size, BigInt::from(258i32));
                assert_eq!(b.leaf_count, leaf_count as usize);
                assert_eq!(b.longest_branch, longest_branch as usize);
                assert!(
                    !b.fully_loaded,
                    "migrated branches must report fully_loaded=false so the walker fetches children",
                );
            }
            _ => panic!("expected branch"),
        }
    }

    #[test]
    fn solo_rejects_nil_type_byte() {
        match deserialize_node_solo(&[TYPE_NIL]) {
            Ok(_) => panic!("expected error for TYPE_NIL in solo format"),
            Err(e) => {
                let msg = format!("{}", e);
                assert!(
                    msg.contains("unexpected node type byte"),
                    "got {}",
                    msg
                );
            }
        }
    }

    #[test]
    fn test_roundtrip_leaf_preserves_value_when_hash_target_empty() {
        // `add_vertex` (and friends) insert leaves with empty
        // `hash_target`, so the leaf commitment depends on `value`.
        // The whole-tree blob must preserve `value` byte-for-byte
        // so the post-reload `tree.commit(prover)` recomputes the
        // same `SHA512(0x00 || key || value)`. Stripping it broke
        // every sync persistence round-trip.
        let mut leaf = LeafNode {
            key: vec![1, 2, 3],
            value: vec![4, 5, 6],
            hash_target: vec![],
            commitment: vec![0u8; 64],
            size: BigInt::from(100),
        };
        leaf.compute_commitment();
        let original_commitment = leaf.commitment.clone();
        let original_value = leaf.value.clone();

        let node = VectorCommitmentNode::Leaf(leaf);
        let data = serialize_tree(Some(&node)).unwrap();
        let result = deserialize_tree(&data).unwrap().unwrap();

        match result {
            VectorCommitmentNode::Leaf(l) => {
                assert_eq!(l.key, vec![1, 2, 3]);
                assert_eq!(l.value, original_value, "blob must round-trip the leaf value");
                assert_eq!(l.commitment, original_commitment);
                assert_eq!(l.size, BigInt::from(100));
            }
            _ => panic!("expected leaf"),
        }
    }

    /// Build a small multi-leaf tree, commit it, serialize, deserialize,
    /// and check that the root commitment survives the round trip
    /// byte-for-byte. Covers the path used by `save_tree_blob` /
    /// `load_tree_blob` for prover-tree persistence.
    #[test]
    fn test_roundtrip_committed_tree_preserves_root() {
        use crate::VectorCommitmentTree;
        use quil_types::crypto::InclusionProver;
        use quil_types::error::Result as QResult;

        // Stub prover that returns a deterministic "commitment" without
        // needing the real bls48581 crate initialized. Real verification
        // against Go happens end-to-end in `hypergraph_sync_probe`.
        struct StubProver;
        impl InclusionProver for StubProver {
            fn commit_raw(&self, data: &[u8], _poly_size: u64) -> QResult<Vec<u8>> {
                use sha2::{Digest, Sha512};
                let mut h = Sha512::new();
                h.update(data);
                Ok(h.finalize().to_vec())
            }
            fn prove_raw(
                &self, _data: &[u8], _index: u64, _poly_size: u64,
            ) -> QResult<Vec<u8>> { Ok(vec![]) }
            fn verify_raw(
                &self, _data: &[u8], _commit: &[u8], _index: u64,
                _proof: &[u8], _poly_size: u64,
            ) -> QResult<bool> { Ok(true) }
            fn prove_multiple(
                &self, _commitments: &[&[u8]], _polys: &[&[u8]],
                _indices: &[u64], _poly_size: u64,
            ) -> QResult<Box<dyn quil_types::crypto::Multiproof>> {
                Err(quil_types::error::QuilError::Internal("batch multiproof generation not supported".into()))
            }
            fn verify_multiple(
                &self, _commitments: &[&[u8]], _evaluations: &[&[u8]],
                _indices: &[u64], _poly_size: u64, _multi_commitment: &[u8],
                _proof: &[u8],
            ) -> bool { true }
        }

        // Outer-tree leaves carry a non-empty `hash_target` so the
        // commitment depends on hash_target rather than `value` — the
        // production invariant that lets us strip values from the
        // serialized blob without disturbing root commitments.
        let mut tree = VectorCommitmentTree::new();
        for i in 0u8..16 {
            let key = vec![i, i.wrapping_add(1), i.wrapping_add(2), 0xAB];
            let hash_target = vec![i; 64];
            tree.insert(&key, &[i, i, i], &hash_target, &BigInt::from(i as i64 + 1)).unwrap();
        }
        let prover = StubProver;
        let original_root = tree.commit(&prover);
        assert_eq!(original_root.len(), 64);

        let blob = serialize_tree(tree.root.as_ref()).unwrap();
        let deserialized = deserialize_tree(&blob).unwrap().unwrap();
        assert_eq!(deserialized.commitment(), &original_root[..]);

        // Re-committing on the deserialized tree should also yield the
        // same root, since all commitments are already cached in the
        // deserialized nodes.
        let mut reloaded_tree = VectorCommitmentTree { root: Some(deserialized) };
        let reloaded_root = reloaded_tree.commit(&prover);
        assert_eq!(reloaded_root, original_root);
    }
}
