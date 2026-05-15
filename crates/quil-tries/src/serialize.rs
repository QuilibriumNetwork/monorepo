use std::io::{self, Read};

use num_bigint::BigInt;
use num_traits::Zero;

use quil_types::error::{QuilError, Result};

use crate::node::{BranchNode, LeafNode, VectorCommitmentNode};
use crate::{TYPE_BRANCH, TYPE_LEAF, TYPE_NIL};

/// Serialize a tree to bytes.
pub fn serialize_tree(root: Option<&VectorCommitmentNode>) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    serialize_node(&mut buf, root)?;
    Ok(buf)
}

/// Deserialize a tree from bytes.
pub fn deserialize_tree(data: &[u8]) -> Result<Option<VectorCommitmentNode>> {
    let mut cursor = io::Cursor::new(data);
    deserialize_node(&mut cursor)
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
            // Vertex content lives in the per-vertex keyspace; the
            // commitment tree blob carries only topology + per-node
            // commitments + leaf metadata. Emit a zero-length value
            // so the on-disk shape stays stable and deserialize sees
            // an empty value (callers needing the data look it up
            // via `load_vertex_underlying_raw`).
            write_length_prefixed(w, &[])?;
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

/// Deserialize a node from a reader.
fn deserialize_node<R: Read>(r: &mut R) -> Result<Option<VectorCommitmentNode>> {
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
            let mut prefix = Vec::with_capacity(prefix_len);
            for _ in 0..prefix_len {
                prefix.push(read_i32(r)?);
            }

            // Children
            let mut children: [Option<Box<VectorCommitmentNode>>; 64] =
                std::array::from_fn(|_| None);
            for slot in children.iter_mut() {
                if let Some(child) = deserialize_node(r)? {
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

            Ok(Some(VectorCommitmentNode::Branch(BranchNode {
                prefix,
                children,
                commitment,
                size,
                leaf_count,
                longest_branch,
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
    fn test_roundtrip_leaf_metadata_only() {
        // Leaf serialization deliberately drops `value` — vertex
        // content lives in the per-vertex keyspace. The tree blob
        // round-trips key, hash_target, commitment, and size; on
        // deserialize, value is empty and callers fetch from the
        // per-vertex store.
        let mut leaf = LeafNode {
            key: vec![1, 2, 3],
            value: vec![4, 5, 6],
            hash_target: vec![],
            commitment: vec![0u8; 64],
            size: BigInt::from(100),
        };
        leaf.compute_commitment();
        let original_commitment = leaf.commitment.clone();

        let node = VectorCommitmentNode::Leaf(leaf);
        let data = serialize_tree(Some(&node)).unwrap();
        let result = deserialize_tree(&data).unwrap().unwrap();

        match result {
            VectorCommitmentNode::Leaf(l) => {
                assert_eq!(l.key, vec![1, 2, 3]);
                assert!(l.value.is_empty(), "leaf value must be stripped on disk");
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
