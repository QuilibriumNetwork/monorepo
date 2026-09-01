//! Per-vertex commitment: reduce one vertex's serialized field subtree to a
//! canonical 32-byte commitment, plus the shard-leaf encoding `commitment ‖
//! size`.
//!
//! Each vertex/hyperedge add is stored (in the KV) as a serialized
//! `VectorCommitmentTree` of its `(field_key → value)` fields. Under the
//! per-vertex-subtree state model, that tree is committed with a **hash** prover
//! (SHA-256 via `ShaInclusionProver`, not KZG) to a 32-byte root — the vertex
//! commitment — which becomes the *value* of the vertex's leaf in the raw-key
//! (address-keyed) shard JMT. The vertex's byte size rides alongside so the
//! shard/app size aggregates are readable straight from the tree.

use sha2::{Digest, Sha256};

use quil_types::crypto::{InclusionProver, Multiproof};
use quil_types::error::{QuilError, Result};

use crate::go_format::deserialize_go_tree;
use crate::tree::VectorCommitmentTree;

/// Fixed width of the shard-leaf encoding: `commitment(32) ‖ size(u64 BE)`.
pub const VERTEX_LEAF_LEN: usize = 32 + 8;

/// SHA-256 hash-based inclusion prover — the post-quantum replacement for KZG in
/// the per-vertex commitment trees. `commit_raw` is a plain SHA-256 of a node's
/// 4096-byte child-commitment vector (cheap — no BLS multiexp), so a
/// [`VectorCommitmentTree`] committed with this prover is a hash-Merkle tree
/// whose 32-byte root is the vertex commitment.
///
/// The proof methods are Merkle sibling-revelation shaped, not KZG-opening
/// shaped, and are not yet wired (state-root commitment is the current
/// deliverable). They error rather than return a wrong/forgeable result.
pub struct ShaInclusionProver;

impl InclusionProver for ShaInclusionProver {
    fn commit_raw(&self, data: &[u8], _poly_size: u64) -> Result<Vec<u8>> {
        Ok(Sha256::digest(data).to_vec())
    }

    fn prove_raw(&self, _data: &[u8], _index: u64, _poly_size: u64) -> Result<Vec<u8>> {
        Err(QuilError::Internal(
            "ShaInclusionProver: prove_raw (Merkle opening) not yet implemented".into(),
        ))
    }

    fn verify_raw(
        &self,
        _data: &[u8],
        _commit: &[u8],
        _index: u64,
        _proof: &[u8],
        _poly_size: u64,
    ) -> Result<bool> {
        Err(QuilError::Internal(
            "ShaInclusionProver: verify_raw (Merkle opening) not yet implemented".into(),
        ))
    }

    fn prove_multiple(
        &self,
        _commitments: &[&[u8]],
        _polys: &[&[u8]],
        _indices: &[u64],
        _poly_size: u64,
    ) -> Result<Box<dyn Multiproof>> {
        Err(QuilError::Internal(
            "ShaInclusionProver: prove_multiple not yet implemented".into(),
        ))
    }

    fn verify_multiple(
        &self,
        _commitments: &[&[u8]],
        _evaluations: &[&[u8]],
        _indices: &[u64],
        _poly_size: u64,
        _multi_commitment: &[u8],
        _proof: &[u8],
    ) -> bool {
        false
    }
}

/// Canonical 32-byte commitment of a vertex's serialized field subtree.
///
/// An empty blob (an OR-set removes tombstone, or an add-side placeholder for a
/// removed-but-never-added id) commits to all-zeros — a present-but-empty leaf,
/// distinct from any real vertex, so removals still move the shard root.
///
/// The tree's root commitment is a branch (SHA-256, 32 B) for a multi-field
/// vertex but a leaf (SHA-512, 64 B) for a single-field one, so we fold the raw
/// root through one more SHA-256 to get a fixed 32-byte commitment regardless of
/// shape.
pub fn vertex_commitment(blob: &[u8]) -> Result<[u8; 32]> {
    if blob.is_empty() {
        return Ok([0u8; 32]);
    }
    match deserialize_go_tree(blob) {
        Ok(Some(root)) => {
            let mut tree = VectorCommitmentTree { root: Some(root) };
            let root_commit = tree.commit(&ShaInclusionProver);
            Ok(Sha256::digest(&root_commit).into())
        }
        // Not a decodable go-tree (a raw non-tree value, or an empty tree) →
        // commit the raw bytes directly. Production vertex blobs are always
        // go-trees; this mirrors the old flatten's raw-leaf fallback so odd
        // values (or test blobs) don't fail the commit.
        _ => Ok(Sha256::digest(blob).into()),
    }
}

/// The shard-leaf value for a vertex: `commitment(32) ‖ size(u64 BE)`, where
/// `size` is the serialized blob's byte length — matching the legacy
/// `Σ blob.len()` size accounting, now committed into the state root.
/// A removes-phase tombstone leaf that carries the removed vertex's `size` (its
/// original add-blob byte length) in the size field, while keeping the empty
/// commitment of the historical tombstone (`vertex_leaf_value(&[])`). This lets
/// the forest removes-tree subtree-size aggregate equal the sum of removed
/// sizes, so a shard's LIVE size is the O(depth) subtree subtraction
/// `adds − removes` (see `HypergraphCrdt::forest_app_buckets`). The commitment
/// is unchanged from the old size-0 tombstone, so ONLY the 8 size bytes differ;
/// this changes the removes-tree root only for shards that actually record a
/// remove (none on mainnet QUIL today) — a forward, non-retroactive encoding
/// that every node must adopt before removes begin.
pub fn sized_tombstone_leaf_value(size: u64) -> Result<Vec<u8>> {
    let mut v = vertex_leaf_value(&[])?;
    v[32..VERTEX_LEAF_LEN].copy_from_slice(&size.to_be_bytes());
    Ok(v)
}

pub fn vertex_leaf_value(blob: &[u8]) -> Result<Vec<u8>> {
    let commitment = vertex_commitment(blob)?;
    let mut v = Vec::with_capacity(VERTEX_LEAF_LEN);
    v.extend_from_slice(&commitment);
    v.extend_from_slice(&(blob.len() as u64).to_be_bytes());
    Ok(v)
}

/// Split a shard-leaf value back into `(commitment, size)`. Tolerates a bare
/// 32-byte commitment (size defaults to 0) for forward/backward flexibility.
pub fn split_vertex_leaf(value: &[u8]) -> Option<([u8; 32], u64)> {
    if value.len() < 32 {
        return None;
    }
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&value[..32]);
    let size = if value.len() >= VERTEX_LEAF_LEN {
        u64::from_be_bytes(value[32..VERTEX_LEAF_LEN].try_into().unwrap())
    } else {
        0
    };
    Some((commitment, size))
}
