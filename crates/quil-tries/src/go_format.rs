//! Go wire-compatible serialization for `VectorCommitmentTree`.
//!
//! This parses the format produced by Go's `SerializeNonLazyTree` in
//! `types/tries/proof_tree.go`. It's the format Quilibrium uses for
//! `LeafData.underlying_data` on the wire (the per-vertex sub-tree blob
//! attached to each global-prover-tree leaf) and for tree-level blobs
//! passed around during hypersync.
//!
//! The format is distinct from the in-memory Rust-native format in
//! `serialize.rs`, which we use for RocksDB blob caching. Keep them
//! separate so the blob cache can evolve without breaking wire parsing.
//!
//! Node formats (all big-endian):
//!
//! ```text
//! Nil node:
//!   [u8 = 0]
//!
//! Leaf node:
//!   [u8 = 1]
//!   [u64 len][key bytes]
//!   [u64 len][value bytes]
//!   [u64 len][hash_target bytes]
//!   [u64 len][commitment bytes]
//!   [u64 len][size bytes]        // BigInt absolute-value, unsigned BE
//!
//! Branch node:
//!   [u8 = 2]
//!   [u32 len][i32 * len]         // prefix (compressed nibbles)
//!   [64 child nodes]             // recursive, nil for empty slot
//!   [u64 len][commitment bytes]
//!   [u64 len][size bytes]
//!   [i64 leaf_count]
//!   [i32 longest_branch]
//! ```

use num_bigint::BigInt;
use num_bigint::Sign;
use quil_types::error::{QuilError, Result};

use crate::node::{BranchNode, LeafNode, VectorCommitmentNode};
use crate::{TYPE_BRANCH, TYPE_LEAF, TYPE_NIL};

/// Deserialize a `VectorCommitmentTree` root node from Go's
/// `SerializeNonLazyTree` wire format.
pub fn deserialize_go_tree(data: &[u8]) -> Result<Option<VectorCommitmentNode>> {
    let mut cursor = GoCursor::new(data);
    cursor.read_node()
}

/// Serialize a `VectorCommitmentTree` root node in Go's
/// `SerializeNonLazyTree` wire format. The round trip is lossy in one
/// specific way: `BigInt` values are written using Go's
/// `big.Int.Bytes()` (unsigned absolute-value), so negative sizes are
/// rejected. Sizes in Quilibrium are always non-negative.
pub fn serialize_go_tree(root: Option<&VectorCommitmentNode>) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    write_node(&mut out, root)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

struct GoCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> GoCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(QuilError::Serialization(format!(
                "go_format: short read at {} (need {}, have {})",
                self.pos,
                n,
                self.buf.len() - self.pos
            )));
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u32_be(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_i32_be(&mut self) -> Result<i32> {
        Ok(self.read_u32_be()? as i32)
    }

    fn read_u64_be(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_i64_be(&mut self) -> Result<i64> {
        Ok(self.read_u64_be()? as i64)
    }

    /// Go's `serializeBytes`: `[u64 BE len][bytes]`.
    fn read_len_prefixed(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u64_be()? as usize;
        // Match Go's 1 GiB sanity cap.
        if len > 1024 * 1024 * 1024 {
            return Err(QuilError::Serialization(format!(
                "go_format: length {} exceeds 1 GiB cap",
                len
            )));
        }
        Ok(self.take(len)?.to_vec())
    }

    /// Go's `serializeBigInt`: length-prefixed unsigned absolute-value bytes.
    fn read_bigint(&mut self) -> Result<BigInt> {
        let bytes = self.read_len_prefixed()?;
        if bytes.is_empty() {
            Ok(BigInt::from(0))
        } else {
            Ok(BigInt::from_bytes_be(Sign::Plus, &bytes))
        }
    }

    fn read_int_slice(&mut self) -> Result<Vec<i32>> {
        let len = self.read_u32_be()? as usize;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_i32_be()?);
        }
        Ok(out)
    }

    fn read_node(&mut self) -> Result<Option<VectorCommitmentNode>> {
        let tag = self.read_u8()?;
        match tag {
            TYPE_NIL => Ok(None),
            TYPE_LEAF => Ok(Some(VectorCommitmentNode::Leaf(self.read_leaf()?))),
            TYPE_BRANCH => Ok(Some(VectorCommitmentNode::Branch(self.read_branch()?))),
            other => Err(QuilError::Serialization(format!(
                "go_format: unknown node tag {}",
                other
            ))),
        }
    }

    fn read_leaf(&mut self) -> Result<LeafNode> {
        let key = self.read_len_prefixed()?;
        let value = self.read_len_prefixed()?;
        let hash_target = self.read_len_prefixed()?;
        let commitment = self.read_len_prefixed()?;
        let size = self.read_bigint()?;
        Ok(LeafNode {
            key,
            value,
            hash_target,
            commitment,
            size,
        })
    }

    fn read_branch(&mut self) -> Result<BranchNode> {
        let prefix = self.read_int_slice()?;
        let mut children: [Option<Box<VectorCommitmentNode>>; 64] =
            std::array::from_fn(|_| None);
        for slot in children.iter_mut() {
            if let Some(child) = self.read_node()? {
                *slot = Some(Box::new(child));
            }
        }
        let commitment = self.read_len_prefixed()?;
        let size = self.read_bigint()?;
        let leaf_count = self.read_i64_be()? as usize;
        let longest_branch = self.read_i32_be()? as usize;
        Ok(BranchNode {
            prefix,
            children,
            commitment,
            size,
            leaf_count,
            longest_branch,
            full_prefix: Vec::new(),
            fully_loaded: true,
        })
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

fn write_node(out: &mut Vec<u8>, node: Option<&VectorCommitmentNode>) -> Result<()> {
    match node {
        None => {
            out.push(TYPE_NIL);
            Ok(())
        }
        Some(VectorCommitmentNode::Leaf(leaf)) => {
            out.push(TYPE_LEAF);
            write_len_prefixed(out, &leaf.key);
            write_len_prefixed(out, &leaf.value);
            write_len_prefixed(out, &leaf.hash_target);
            write_len_prefixed(out, &leaf.commitment);
            write_bigint(out, &leaf.size)?;
            Ok(())
        }
        Some(VectorCommitmentNode::Branch(branch)) => {
            out.push(TYPE_BRANCH);
            write_int_slice(out, &branch.prefix);
            for child in &branch.children {
                write_node(out, child.as_deref())?;
            }
            write_len_prefixed(out, &branch.commitment);
            write_bigint(out, &branch.size)?;
            out.extend_from_slice(&(branch.leaf_count as i64).to_be_bytes());
            out.extend_from_slice(&(branch.longest_branch as i32).to_be_bytes());
            Ok(())
        }
    }
}

fn write_len_prefixed(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
}

fn write_int_slice(out: &mut Vec<u8>, ints: &[i32]) {
    out.extend_from_slice(&(ints.len() as u32).to_be_bytes());
    for &v in ints {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

fn write_bigint(out: &mut Vec<u8>, n: &BigInt) -> Result<()> {
    // Go's big.Int.Bytes() returns the absolute-value magnitude in BE
    // form, with the zero integer mapping to an empty slice.
    let (sign, bytes) = n.to_bytes_be();
    if sign == Sign::Minus {
        return Err(QuilError::Serialization(
            "go_format: negative BigInt not representable".into(),
        ));
    }
    let canonical: &[u8] = if sign == Sign::NoSign {
        &[]
    } else {
        &bytes
    };
    write_len_prefixed(out, canonical);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_nil() {
        let data = serialize_go_tree(None).unwrap();
        assert_eq!(data, vec![TYPE_NIL]);
        let back = deserialize_go_tree(&data).unwrap();
        assert!(back.is_none());
    }

    #[test]
    fn test_roundtrip_leaf() {
        let leaf = LeafNode {
            key: vec![1, 2, 3, 4],
            value: vec![0xAA, 0xBB],
            hash_target: vec![0xFF; 32],
            commitment: vec![0xCC; 64],
            size: BigInt::from(42u64),
        };
        let node = VectorCommitmentNode::Leaf(leaf);
        let data = serialize_go_tree(Some(&node)).unwrap();
        let back = deserialize_go_tree(&data).unwrap().unwrap();
        match back {
            VectorCommitmentNode::Leaf(l) => {
                assert_eq!(l.key, vec![1, 2, 3, 4]);
                assert_eq!(l.value, vec![0xAA, 0xBB]);
                assert_eq!(l.hash_target, vec![0xFF; 32]);
                assert_eq!(l.commitment, vec![0xCC; 64]);
                assert_eq!(l.size, BigInt::from(42u64));
            }
            _ => panic!("expected leaf"),
        }
    }

    #[test]
    fn test_roundtrip_branch_with_children() {
        let mut branch = BranchNode::new(vec![5, 6, 7]);
        branch.children[0] = Some(Box::new(VectorCommitmentNode::Leaf(LeafNode {
            key: vec![0x00],
            value: vec![0x10],
            hash_target: vec![],
            commitment: vec![0xAA; 64],
            size: BigInt::from(1u64),
        })));
        branch.children[63] = Some(Box::new(VectorCommitmentNode::Leaf(LeafNode {
            key: vec![0xFF],
            value: vec![0x20],
            hash_target: vec![],
            commitment: vec![0xBB; 64],
            size: BigInt::from(2u64),
        })));
        branch.commitment = vec![0xCC; 64];
        branch.size = BigInt::from(3u64);
        branch.leaf_count = 2;
        branch.longest_branch = 1;

        let node = VectorCommitmentNode::Branch(branch);
        let data = serialize_go_tree(Some(&node)).unwrap();
        let back = deserialize_go_tree(&data).unwrap().unwrap();
        match back {
            VectorCommitmentNode::Branch(b) => {
                assert_eq!(b.prefix, vec![5, 6, 7]);
                assert_eq!(b.leaf_count, 2);
                assert_eq!(b.longest_branch, 1);
                assert_eq!(b.size, BigInt::from(3u64));
                // Check children
                assert!(b.children[0].is_some());
                assert!(b.children[1].is_none());
                assert!(b.children[63].is_some());
            }
            _ => panic!("expected branch"),
        }
    }

    #[test]
    fn test_bigint_zero_is_empty_slice() {
        // Go's big.NewInt(0).Bytes() is []byte{}. Verify we match.
        let mut buf = Vec::new();
        write_bigint(&mut buf, &BigInt::from(0u64)).unwrap();
        // u64 BE length = 0
        assert_eq!(buf, vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
