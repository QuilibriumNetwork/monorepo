//! Conditions 2 & 3 — conflicting shard-frame proposals are rejected at the
//! global level by the real state-mutation / cross-shard gates.
//!
//! A shard frame carries token transactions in its `requests` bundle. When an
//! archive ingests a shard frame during global materialization, each carried
//! transaction is run through the token engine's verify+apply path
//! (`engines.rs::process_message`). These tests drive the EXACT gates that
//! path invokes, modelling the conflict scenarios a malicious prover set would
//! attempt:
//!
//! - **Condition 2** — two shard-frame proposals on one shard double-spend the
//!   same coin. The first frame's materialize writes a spent marker; the
//!   second is rejected by `check_input_not_double_spent` (engines.rs:708).
//! - **Condition 3(a)** — a cross-shard transfer cites a shard that does not
//!   hold the coin. The traversal proof is bound (commits[0]) to the CITED
//!   shard's commit root (engines.rs:889 → `verify_traversal_proof`); against
//!   a different shard's root it is rejected.
//! - **Condition 3(b)** — a tampered cross-shard copy keeps the coin but
//!   changes the recipient. The recipient is folded into the transaction
//!   transcript → the Schnorr challenge, so a signature authorizing recipient
//!   A cannot authorize recipient B.
//!
//! FIDELITY BOUNDARY: these exercise the real STATE-MUTATION / CONFLICT and
//! ROOT/RECIPIENT-BINDING gates with the real functions the materializer
//! calls. They deliberately use `NoopInclusionProver` and hand-built fixtures
//! — the ZK SOUNDNESS of bulletproofs / KZG multiproofs is a separate concern
//! covered by the crypto crates' own tests. Here we isolate the consensus-level
//! "is this conflicting/invalid state mutation rejected" logic.

#![cfg(test)]

use std::sync::Arc;

use quil_hypergraph::testing::MemStore;
use quil_hypergraph::HypergraphCrdt;
use quil_types::crypto::NoopInclusionProver;

use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};

fn empty_state() -> HypergraphState {
    let crdt = Arc::new(HypergraphCrdt::new(
        Arc::new(MemStore::new()),
        Arc::new(NoopInclusionProver),
    ));
    HypergraphState::new(crdt)
}

/// A 336-byte token input signature whose verification-key window
/// (`sig[56*4..56*5]`) is filled with `vk_byte`. Both the spent-marker writer
/// (`materialize_transaction`) and the double-spend reader
/// (`check_input_not_double_spent`) key off this exact window, so two inputs
/// with the same `vk_byte` are the SAME coin.
fn input_signature(vk_byte: u8) -> Vec<u8> {
    let mut sig = vec![0u8; 336];
    for b in sig.iter_mut().take(56 * 5).skip(56 * 4) {
        *b = vk_byte;
    }
    sig
}

// ---------------------------------------------------------------------------
// Condition 2 — intra-shard double-spend rejected at the global level
// ---------------------------------------------------------------------------

#[test]
fn cond2_intra_shard_double_spend_rejected_by_spent_marker() {
    use crate::prover_registry::vertex_tree_to_blob;
    use crate::token_intrinsic::materialize::materialize_transaction;
    use crate::token_intrinsic::spent_check::check_input_not_double_spent;

    let state = empty_state();
    let domain = vec![0x11u8; 32]; // the shard the coin lives on
    let sig = input_signature(0xC0); // coin C

    // Before any frame consumes it, coin C is spendable.
    assert!(
        check_input_not_double_spent(&state, &domain, &sig).unwrap(),
        "coin must be spendable before it is consumed"
    );

    // Frame A (the first, honest shard-frame proposal) materializes a spend of
    // coin C. This uses the REAL materialize path: it produces a spent marker
    // keyed at poseidon(vk), written into the shard's vertex-add tree exactly
    // as `engines.rs:1297` does.
    let out = materialize_transaction(&domain, &[], &[sig.clone()], &NoopInclusionProver)
        .expect("materialize frame A spend");
    assert_eq!(out.spent_markers.len(), 1, "one input → one spent marker");
    let va_disc = vertex_adds_discriminator().unwrap();
    for (addr, tree) in &out.spent_markers {
        let blob = vertex_tree_to_blob(tree);
        state.set(&domain, addr, &va_disc, 1, blob).unwrap();
    }

    // Frame B (a conflicting proposal from a malicious prover set) tries to
    // spend coin C again. The global level's per-input gate rejects it:
    // invalid state mutation, not accepted.
    assert!(
        !check_input_not_double_spent(&state, &domain, &sig).unwrap(),
        "second spend of an already-consumed coin must be rejected (double-spend)"
    );

    // A DIFFERENT coin on the same shard is unaffected — the rejection is
    // coin-scoped, not a blanket shard rejection.
    let other = input_signature(0xD1);
    assert!(
        check_input_not_double_spent(&state, &domain, &other).unwrap(),
        "an unrelated coin on the same shard stays spendable"
    );
}

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

#[test]
fn cond3b_cross_shard_different_recipient_changes_transcript_binding() {
    use crate::token_intrinsic::transaction::{
        RecipientBundle, Transaction, TransactionOutput,
    };
    use crate::token_intrinsic::verify::build_transaction_transcript;

    // Build a transfer output paying `recipient` (its one-time + verification
    // keys identify the payee). The recipient bundle is folded byte-for-byte
    // into the transaction transcript by `build_transaction_transcript`.
    let mk_output = |otk: u8, vk: u8| -> Vec<u8> {
        let rb = RecipientBundle {
            one_time_key: vec![otk; 56],
            verification_key: vec![vk; 56],
            coin_balance: vec![0x33u8; 16],
            mask: vec![0x44u8; 56],
            additional_reference: vec![],
            additional_reference_key: vec![],
        };
        let out = TransactionOutput {
            frame_number: 42u64.to_be_bytes().to_vec(),
            commitment: vec![0x55u8; 56],
            recipient_output: rb.to_canonical_bytes().unwrap(),
        };
        out.to_canonical_bytes().unwrap()
    };

    let tx_a = Transaction {
        domain: vec![0x11u8; 32],
        inputs: vec![],
        outputs: vec![mk_output(0x11, 0x22)], // recipient A
        fees: vec![],
        range_proof: vec![],
        traversal_proof: vec![],
    };
    // A tampered cross-shard copy: identical EXCEPT the recipient keys.
    let tx_b = Transaction {
        outputs: vec![mk_output(0x66, 0x77)], // recipient B
        ..tx_a.clone()
    };

    let t_a = build_transaction_transcript(&tx_a).expect("transcript A");
    let t_b = build_transaction_transcript(&tx_b).expect("transcript B");

    assert_ne!(
        t_a, t_b,
        "recipient keys must be bound into the transcript — a swapped recipient \
         changes the challenge, so a signature authorizing recipient A cannot \
         authorize recipient B"
    );
}
