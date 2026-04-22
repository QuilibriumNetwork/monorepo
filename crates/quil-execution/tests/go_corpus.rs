//! Golden-corpus round-trip test: loads hex-encoded Go-produced
//! canonical bytes from `tools/canonical-corpus/corpus/` and asserts
//! that Rust's decode-then-re-encode produces byte-identical output.
//!
//! Run the Go generator first:
//!     cd tools/canonical-corpus && go run main.go
//!
//! Then run this test:
//!     cargo test --test go_corpus
//!
//! If the corpus directory doesn't exist the test is skipped with a
//! clear message rather than failing — useful for CI environments
//! without Go available.

use std::path::PathBuf;

use quil_execution::global_intrinsic::{
    consensus_types::{AltShardUpdate, AppShardProposal as ConsensusAppShardProposal},
    prover_filter_ops::{ProverLeave, ProverPause, ProverResume},
    prover_join::ProverJoin,
    prover_ops::{
        ProverConfirm, ProverKick, ProverReject, ProverSeniorityMerge, ProverUpdate, ShardMerge,
        ShardSplit,
    },
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_execution::token_intrinsic::transaction::{
    RecipientBundle, Transaction, TransactionInput, TransactionOutput,
};
use quil_engine::consensus_wire::{
    GlobalProposal, ProposalVote, QuorumCertificate, TimeoutCertificate, TimeoutState,
};

fn corpus_dir() -> Option<PathBuf> {
    // Walk up from the crate dir to find the workspace root, then
    // into tools/canonical-corpus/corpus.
    let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..5 {
        let candidate = here.join("tools").join("canonical-corpus").join("corpus");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !here.pop() {
            break;
        }
    }
    None
}

fn load_corpus(name: &str) -> Option<Vec<Vec<u8>>> {
    let dir = corpus_dir()?;
    let path = dir.join(format!("{}.txt", name));
    let content = std::fs::read_to_string(&path).ok()?;
    let entries: Vec<Vec<u8>> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| hex::decode(l.trim()).expect("hex line"))
        .collect();
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Round-trip assertion helper: decode Go bytes, re-encode, compare.
fn assert_round_trip<T, D, E>(name: &str, decoder: D, encoder: E)
where
    T: std::fmt::Debug,
    D: Fn(&[u8]) -> Result<T, Box<dyn std::error::Error>>,
    E: Fn(&T) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
{
    let Some(entries) = load_corpus(name) else {
        eprintln!("corpus {} not present — skipping", name);
        return;
    };
    for (i, go_bytes) in entries.iter().enumerate() {
        let decoded = decoder(go_bytes)
            .unwrap_or_else(|e| panic!("{}[{}] decode failed: {}", name, i, e));
        let rust_bytes = encoder(&decoded)
            .unwrap_or_else(|e| panic!("{}[{}] re-encode failed: {}", name, i, e));
        if &rust_bytes != go_bytes {
            panic!(
                "{}[{}] byte mismatch:\n  go:   {}\n  rust: {}",
                name,
                i,
                hex::encode(go_bytes),
                hex::encode(&rust_bytes),
            );
        }
    }
    eprintln!("  ✓ {} — {} entries round-tripped", name, entries.len());
}

#[test]
fn prover_join_round_trip() {
    assert_round_trip(
        "ProverJoin",
        |b| ProverJoin::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn prover_leave_round_trip() {
    assert_round_trip(
        "ProverLeave",
        |b| ProverLeave::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn prover_confirm_round_trip() {
    assert_round_trip(
        "ProverConfirm",
        |b| ProverConfirm::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn prover_reject_round_trip() {
    assert_round_trip(
        "ProverReject",
        |b| ProverReject::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn prover_pause_round_trip() {
    assert_round_trip(
        "ProverPause",
        |b| ProverPause::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn prover_resume_round_trip() {
    assert_round_trip(
        "ProverResume",
        |b| ProverResume::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn shard_split_round_trip() {
    assert_round_trip(
        "ShardSplit",
        |b| ShardSplit::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn shard_merge_round_trip() {
    assert_round_trip(
        "ShardMerge",
        |b| ShardMerge::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn proposal_vote_round_trip() {
    assert_round_trip(
        "ProposalVote",
        |b| ProposalVote::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn quorum_certificate_round_trip() {
    assert_round_trip(
        "QuorumCertificate",
        |b| QuorumCertificate::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn timeout_certificate_round_trip() {
    assert_round_trip(
        "TimeoutCertificate",
        |b| TimeoutCertificate::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn prover_kick_round_trip() {
    assert_round_trip(
        "ProverKick",
        |b| ProverKick::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn prover_update_round_trip() {
    assert_round_trip(
        "ProverUpdate",
        |b| ProverUpdate::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn prover_seniority_merge_round_trip() {
    assert_round_trip(
        "ProverSeniorityMerge",
        |b| ProverSeniorityMerge::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn transaction_input_round_trip() {
    assert_round_trip(
        "TransactionInput",
        |b| TransactionInput::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn transaction_output_round_trip() {
    assert_round_trip(
        "TransactionOutput",
        |b| TransactionOutput::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn recipient_bundle_round_trip() {
    assert_round_trip(
        "RecipientBundle",
        |b| RecipientBundle::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn transaction_round_trip() {
    assert_round_trip(
        "Transaction",
        |b| Transaction::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn timeout_state_round_trip() {
    assert_round_trip(
        "TimeoutState",
        |b| TimeoutState::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn global_proposal_round_trip() {
    assert_round_trip(
        "GlobalProposal",
        |b| GlobalProposal::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn app_shard_proposal_round_trip() {
    assert_round_trip(
        "AppShardProposal",
        |b| ConsensusAppShardProposal::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn alt_shard_update_round_trip() {
    assert_round_trip(
        "AltShardUpdate",
        |b| AltShardUpdate::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn message_request_round_trip() {
    assert_round_trip(
        "MessageRequest",
        |b| CanonicalMessageRequest::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn message_bundle_round_trip() {
    assert_round_trip(
        "MessageBundle",
        |b| CanonicalMessageBundle::from_canonical_bytes(b).map_err(|e| e.into()),
        |t| t.to_canonical_bytes().map_err(|e| e.into()),
    );
}

#[test]
fn peer_info_round_trip() {
    // PeerInfo's Rust encoder takes public_key and signature as separate
    // args rather than reading them from the struct, so we wrap the
    // decode/encode pair to pass them through.
    let Some(entries) = load_corpus("PeerInfo") else {
        eprintln!("corpus PeerInfo not present — skipping");
        return;
    };
    for (i, go_bytes) in entries.iter().enumerate() {
        let info = quil_p2p::decode_canonical_peer_info(go_bytes)
            .unwrap_or_else(|e| panic!("PeerInfo[{}] decode failed: {}", i, e));
        let rust_bytes = quil_p2p::encode_canonical_peer_info(
            &info,
            &info.public_key,
            &info.signature,
        );
        if &rust_bytes != go_bytes {
            panic!(
                "PeerInfo[{}] byte mismatch:\n  go:   {}\n  rust: {}",
                i,
                hex::encode(go_bytes),
                hex::encode(&rust_bytes),
            );
        }
    }
    eprintln!("  ✓ PeerInfo — {} entries round-tripped", entries.len());
}
