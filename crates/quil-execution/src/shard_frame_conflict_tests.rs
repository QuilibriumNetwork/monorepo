//! Historical traversal-root regression for retained helpers.
//! These do not exercise current QCT3 admission or a live consensus transition.
//! Current token authorization and replay tests reside in the QCT3 adapters.

#![cfg(test)]

use std::sync::Arc;

use quil_types::crypto::NoopInclusionProver;

// ---------------------------------------------------------------------------
// Condition 3(a) — cross-shard: a coin's proof is bound to its shard's root
// ---------------------------------------------------------------------------

#[test]
fn cond3a_cross_shard_transfer_proof_bound_to_cited_shard_root() {
    use crate::traversal_proof::{verify_traversal_proof, TraversalProof, TraversalSubProof};

    // Two shards with distinct committed roots. `root_a` is the shard that
    // actually holds the coin; `root_b` is a different shard where the coin
    // does NOT exist.
    let root_a = vec![0xAAu8; 64];
    let root_b = vec![0xBBu8; 64];

    // A coin's traversal proof chains from the holding shard's root
    // (`commits[0] == root_a`). This is exactly what the engine builds at
    // engines.rs:889: it fetches the CITED shard's commit root via
    // `get_shard_commits(cited_frame, tx.domain)` and verifies the proof
    // against `roots[0]`.
    let proof = TraversalProof {
        multicommitment: vec![0u8; 64],
        proof: vec![0u8; 64],
        sub_proofs: vec![TraversalSubProof {
            commits: vec![root_a.clone()],
            ys: vec![vec![0u8; 32]],
            paths: vec![],
        }],
    };

    // Cited correctly (the coin's own shard) → accepted.
    assert!(
        verify_traversal_proof(&NoopInclusionProver, &root_a, &proof).unwrap(),
        "proof must verify against the shard root that holds the coin"
    );

    // A cross-shard transfer citing a shard that does NOT hold the coin
    // presents the same proof against that shard's root → rejected. This is
    // the "exists on one shard but not the other" case: the proof cannot
    // chain to a root under which the coin was never committed.
    let res = verify_traversal_proof(&NoopInclusionProver, &root_b, &proof);
    assert!(
        res.is_err() || !res.unwrap(),
        "proof must be rejected against a shard root that does not hold the coin"
    );
}

// ---------------------------------------------------------------------------
// Condition 3(b) — cross-shard: changing the recipient breaks the signature
// ---------------------------------------------------------------------------
