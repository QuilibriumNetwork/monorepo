//! Forest-native membership proofs — **two-level**, matching the per-vertex
//! subtree state model.
//!
//! # Two levels, again
//!
//! State nests once more: a raw-key shard-phase JMT whose leaves are per-vertex
//! subtree commitments, over per-vertex hash-Merkle trees (`VectorCommitmentTree`
//! committed with [`quil_tries::ShaInclusionProver`]) whose leaves are the
//! vertex's fields. Proving "a vertex with fields F exists" is therefore:
//!
//! 1. **Level 1 (vertex → shard):** a JMT [`SparseMerkleProof`] that the vertex's
//!    32-byte DATA address maps to `commitment ‖ size` under the shard-phase
//!    root — raw-key positioned (the leaf's tree path IS its address).
//! 2. **Level 2 (field → vertex):** the vertex's serialized subtree is carried
//!    verbatim; the verifier recomputes its commitment ([`quil_tries::
//!    vertex_commitment`]) — which MUST equal the Level-1 leaf's commitment —
//!    and reads each bound field straight out of it. The small subtree *is* the
//!    opening, so no per-field Merkle path is needed.
//!
//! The shared 64-byte `vertex_address` (`app ‖ data`) is what the token engine
//! matches against the input; the fields' binding to one vertex comes for free
//! because they all live in the one committed subtree.
//!
//! This module is generic — it knows nothing about coins or field-key
//! conventions. The engine builds the expected `(field_key, value)` layout and
//! calls [`verify_vertex_membership`]; this crate does the JMT + subtree
//! plumbing.

use borsh::{BorshDeserialize, BorshSerialize};
use jmt::proof::SparseMerkleProof;
use jmt::{KeyHash, RootHash};
use sha2::Sha256;

use quil_tries::{deserialize_go_tree, vertex_leaf_value, VectorCommitmentTree};

/// Binds a split app's (QUIL) sub-shard phase root — the root the Level-1
/// `shard_proof` proves against — up to the app phase root the header
/// advertises. Present ONLY for vertices in a multi-shard app; a single-shard
/// app's vertex proves directly against the header root and carries no
/// aggregation.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct ShardAggregation {
    /// The sub-shard's phase root. UNTRUSTED on its own — the verifier accepts
    /// it only because `copath` binds it to the trusted app phase root.
    pub shard_phase_root: [u8; 32],
    /// The sub-shard's position: its `ShardInfo.prefix` as MSB-first bits (see
    /// [`crate::prefix_to_bits`]).
    pub prefix_bits: Vec<bool>,
    /// The sibling-subtree roots along the path from the app root down to this
    /// sub-shard ([`crate::app_membership_path_dynamic`]).
    pub copath: Vec<[u8; 32]>,
}

/// Two-level forest membership proof for ONE vertex (a coin / prover /
/// pending-transaction input).
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct VertexMembershipProof {
    /// The vertex's full `app(32) ‖ data(32)` id — the identity the engine
    /// matches. The Level-1 shard-tree key is its 32-byte DATA half.
    pub vertex_address: Vec<u8>,
    /// The vertex's serialized field subtree — the Level-2 opening. The verifier
    /// recomputes its commitment (must equal the Level-1 leaf) and reads bound
    /// fields from it.
    pub vertex_blob: Vec<u8>,
    /// Level-1 JMT existence proof: `data_address → commitment ‖ size` under the
    /// shard-phase root (raw-key positioned).
    pub shard_proof: SparseMerkleProof<Sha256>,
    /// `Some` iff the vertex lives in a split app (QUIL) — binds the sub-shard
    /// root `shard_proof` proves against up to the header's app phase root.
    pub shard_aggregation: Option<ShardAggregation>,
}

/// A whole transaction's forest membership proof: one
/// [`VertexMembershipProof`] per input, in input order. The wire object carried
/// in a token transaction's `traversal_proof` on the forest path.
#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct MembershipProof {
    pub inputs: Vec<VertexMembershipProof>,
}

impl MembershipProof {
    /// Canonical wire encoding (borsh).
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization of MembershipProof is infallible")
    }

    /// Decode from [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        borsh::from_slice(bytes).map_err(|e| anyhow::anyhow!("decode MembershipProof: {e}"))
    }
}

/// The 32-byte DATA address (raw-key shard leaf key) of a vertex id
/// `app(32) ‖ data(32)`. Tolerates a bare 32-byte address.
fn data_address_of(vertex_address: &[u8]) -> &[u8] {
    if vertex_address.len() >= 64 {
        &vertex_address[32..64]
    } else {
        vertex_address
    }
}

/// Verify one vertex's membership against `phase_root` (the shard's phase JMT
/// root at the cited frame). `expected` is the ordered `(field_key, value)`
/// layout the caller requires this vertex to bind to.
///
/// Checks, in order:
/// 1. the vertex actually has content (a fabricated input has no on-chain blob);
/// 2. **Level 1** — `shard_proof` proves `data_address → commitment ‖ size`
///    (recomputed from `vertex_blob`) under the shard-phase root, so the blob is
///    the genuinely-committed vertex — this is the identity binding;
/// 3. **Level 2** — each expected `(field_key, value)` is present, with that
///    exact value, in `vertex_blob`'s subtree;
/// 4. for a split app, `shard_aggregation` binds the (untrusted) sub-shard root
///    up to the trusted app phase root.
pub fn verify_vertex_membership(
    phase_root: &[u8; 32],
    vertex: &VertexMembershipProof,
    expected: &[(Vec<u8>, Vec<u8>)],
) -> anyhow::Result<()> {
    // (1) An empty blob is a tombstone / absent vertex — never a valid existence
    // proof, and it has no fields to bind.
    if vertex.vertex_blob.is_empty() {
        anyhow::bail!("forest membership: absent vertex (empty blob)");
    }

    // The Level-1 proof is against the sub-shard phase root (split app) or the
    // header root directly (single-shard app).
    let shard_root = match &vertex.shard_aggregation {
        Some(a) => RootHash(a.shard_phase_root),
        None => RootHash(*phase_root),
    };

    // (2) Level 1: recompute the committed leaf value from the carried blob and
    // prove the data address maps to it. `vertex_leaf_value` = commitment ‖ size,
    // so a tampered blob (different commitment/size) fails the JMT check.
    let leaf_value = vertex_leaf_value(&vertex.vertex_blob)
        .map_err(|e| anyhow::anyhow!("forest membership: vertex commitment: {e}"))?;
    let key = data_address_of(&vertex.vertex_address);
    vertex
        .shard_proof
        .verify_existence(shard_root, KeyHash(crate::shard_path_key_hash(key).0), &leaf_value)
        .map_err(|e| {
            anyhow::anyhow!("forest membership: Level-1 shard inclusion proof failed: {e}")
        })?;

    // (3) Level 2: every expected field is present in the committed subtree with
    // exactly the caller's value (the input-to-on-chain-vertex binding).
    let tree = VectorCommitmentTree {
        root: deserialize_go_tree(&vertex.vertex_blob)
            .map_err(|e| anyhow::anyhow!("forest membership: decode vertex blob: {e}"))?,
    };
    for (exp_key, exp_val) in expected {
        match tree.get(exp_key) {
            Some(v) if v == exp_val.as_slice() => {}
            Some(_) => anyhow::bail!(
                "forest membership: field value does not match this input's data \
                 (input not bound to the on-chain vertex)"
            ),
            None => anyhow::bail!("forest membership: expected field absent from vertex"),
        }
    }

    // (4) Split-app aggregation: bind the sub-shard root up to the app phase root.
    if let Some(a) = &vertex.shard_aggregation {
        // DEFENSE: `prefix_bits`/`copath` are attacker-controlled wire data;
        // `app_root_from_shard_path` indexes `copath` by `prefix_bits` length, so
        // a short copath would panic (a remote consensus halt). Require equality.
        if a.copath.len() != a.prefix_bits.len() {
            anyhow::bail!("forest membership: shard-aggregation copath/prefix length mismatch");
        }
        let recomputed =
            crate::app_root_from_shard_path(&a.prefix_bits, a.shard_phase_root, &a.copath);
        if recomputed != *phase_root {
            anyhow::bail!(
                "forest membership: sub-shard root does not aggregate to the app phase root"
            );
        }
    }
    Ok(())
}

impl crate::Forest {
    /// Build a [`VertexMembershipProof`] for `vertex_address` (`app ‖ data`, or a
    /// bare 32-byte data address), reading the Level-1 raw-key JMT proof from the
    /// shard-phase tree at `version`. `vertex_blob` is the vertex's serialized
    /// subtree (the caller reads it from the vertex-KV) and rides along as the
    /// Level-2 opening. A split app's `shard_aggregation` is filled by the caller
    /// (`crdt.rs`) afterward; a single-shard proof leaves it `None`.
    pub fn build_vertex_membership_proof(
        &self,
        shard_id: &[u8],
        phase: crate::Phase,
        version: u64,
        vertex_address: &[u8],
        vertex_blob: &[u8],
    ) -> anyhow::Result<VertexMembershipProof> {
        let key = data_address_of(vertex_address);
        let (_leaf_value, shard_proof) =
            self.shard_phase_get_with_proof_raw(shard_id, phase, version, key)?;
        Ok(VertexMembershipProof {
            vertex_address: vertex_address.to_vec(),
            vertex_blob: vertex_blob.to_vec(),
            shard_proof,
            shard_aggregation: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Forest, Phase};
    use num_bigint::BigInt;

    fn open_db(path: &std::path::Path) -> std::sync::Arc<rocksdb::DB> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        std::sync::Arc::new(rocksdb::DB::open(&opts, path).unwrap())
    }

    /// Build a vertex subtree blob from `(field_key, value)` fields.
    fn vertex_blob(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut t = VectorCommitmentTree::new();
        for (k, v) in fields {
            t.insert(k, v, &[], &BigInt::from(v.len() as u64)).unwrap();
        }
        quil_tries::serialize_go_tree(t.root.as_ref()).unwrap()
    }

    /// End-to-end: commit a vertex as one raw-key per-vertex leaf, build the
    /// two-level proof, verify it. The coin-existence + identity-binding path.
    #[test]
    fn build_and_verify_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let shard = b"shard-A".to_vec();
        // vertex id = app(32) ‖ data(32); the shard leaf is keyed by data.
        let mut addr = vec![0x2au8; 32];
        addr.extend_from_slice(&[0x07u8; 32]);
        let data = &addr[32..64];

        let commitment_key = vec![0x04u8];
        let type_key = vec![0xFFu8; 32];
        let commitment_val = vec![0xAAu8; 56];
        let type_val = vec![0xBBu8; 32];
        let blob = vertex_blob(&[(&commitment_key, &commitment_val), (&type_key, &type_val)]);

        // ONE per-vertex leaf keyed by the data address, value = commitment‖size.
        let leaf = quil_tries::vertex_leaf_value(&blob).unwrap();
        let root = forest
            .commit_shard_phase_raw(&shard, Phase::VertexAdds, 0, vec![(data.to_vec(), leaf)])
            .unwrap();

        let vertex = forest
            .build_vertex_membership_proof(&shard, Phase::VertexAdds, 0, &addr, &blob)
            .unwrap();
        let expected =
            vec![(commitment_key.clone(), commitment_val.clone()), (type_key.clone(), type_val.clone())];
        verify_vertex_membership(&root, &vertex, &expected).expect("membership verifies");

        // Wire round-trip preserves verification.
        let mp = MembershipProof { inputs: vec![vertex.clone()] };
        let decoded = MembershipProof::from_bytes(&mp.to_bytes()).unwrap();
        verify_vertex_membership(&root, &decoded.inputs[0], &expected)
            .expect("membership verifies after wire round-trip");
    }

    fn seed_and_prove(
        forest: &Forest,
        shard: &[u8],
        addr: &[u8],
        blob: &[u8],
    ) -> ([u8; 32], VertexMembershipProof) {
        let data = &addr[32..64];
        let leaf = quil_tries::vertex_leaf_value(blob).unwrap();
        let root = forest
            .commit_shard_phase_raw(shard, Phase::VertexAdds, 0, vec![(data.to_vec(), leaf)])
            .unwrap();
        let vp = forest
            .build_vertex_membership_proof(shard, Phase::VertexAdds, 0, addr, blob)
            .unwrap();
        (root, vp)
    }

    #[test]
    fn rejects_wrong_value() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let mut addr = vec![0x2au8; 32];
        addr.extend_from_slice(&[0x07u8; 32]);
        let key = vec![0x04u8];
        let blob = vertex_blob(&[(&key, &vec![0xAAu8; 56])]);
        let (root, vertex) = seed_and_prove(&forest, b"S", &addr, &blob);
        // Verifier expects a DIFFERENT value (a fabricated input's commitment).
        let expected = vec![(key.clone(), vec![0xCCu8; 56])];
        assert!(
            verify_vertex_membership(&root, &vertex, &expected).is_err(),
            "a value that doesn't match on-chain state must be rejected"
        );
    }

    #[test]
    fn rejects_absent_field() {
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let mut addr = vec![0x2au8; 32];
        addr.extend_from_slice(&[0x07u8; 32]);
        // Commit a vertex WITHOUT the field the verifier will expect.
        let blob = vertex_blob(&[(&[0x08u8], &vec![1u8; 8])]);
        let (root, vertex) = seed_and_prove(&forest, b"S", &addr, &blob);
        let expected = vec![(vec![0x04u8], vec![0xAAu8; 56])];
        assert!(verify_vertex_membership(&root, &vertex, &expected).is_err());
    }

    #[test]
    fn rejects_tampered_blob() {
        // A blob whose commitment differs from the committed leaf must fail the
        // Level-1 JMT check even if it locally contains the expected fields.
        let dir = tempfile::tempdir().unwrap();
        let forest = Forest::new(open_db(dir.path()));
        let mut addr = vec![0x2au8; 32];
        addr.extend_from_slice(&[0x07u8; 32]);
        let key = vec![0x04u8];
        let real = vertex_blob(&[(&key, &vec![0xAAu8; 56])]);
        let (root, mut vertex) = seed_and_prove(&forest, b"S", &addr, &real);
        // Swap in a different blob (adds an extra field → different commitment).
        vertex.vertex_blob = vertex_blob(&[(&key, &vec![0xAAu8; 56]), (&[0x09u8], &vec![9u8; 4])]);
        let expected = vec![(key.clone(), vec![0xAAu8; 56])];
        assert!(
            verify_vertex_membership(&root, &vertex, &expected).is_err(),
            "a blob not matching the committed commitment must be rejected"
        );
    }
}
