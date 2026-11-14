//! Bounds of the verdict cache and of what reaches the proof worker. These
//! tests use only interfaces of the release base, so they show its outcome
//! there; the canonical owner tests also set that gate's frame.
use super::*;

/// A cache full of rejected verdicts keeps the accepted ones: a verdict a
/// proposal or frame still needs took minutes to compute.
#[test]
fn rejected_verdicts_never_evict_an_accepted_one() {
    let accepted = [0xa5; 32];
    record_verdict(accepted, true);
    for n in 0..VERDICT_CACHE_ENTRIES as u32 {
        let mut key = [0x5a; 32];
        key[..4].copy_from_slice(&n.to_le_bytes());
        record_verdict(key, false);
    }
    assert_eq!(
        cached_verdict(&accepted),
        Some(true),
        "an accepted verdict was evicted by {VERDICT_CACHE_ENTRIES} rejected ones"
    );
    // A full side keeps its newest entries and drops only its oldest.
    let mut newest = [0x5a; 32];
    newest[..4].copy_from_slice(&(VERDICT_CACHE_ENTRIES as u32 - 1).to_le_bytes());
    let mut extra = [0x5b; 32];
    extra[..4].copy_from_slice(&7u32.to_le_bytes());
    record_verdict(extra, false);
    assert_eq!(
        cached_verdict(&newest),
        Some(false),
        "a full cache forgot its newest verdicts"
    );
    assert_eq!(cached_verdict(&extra), Some(false));
}

/// An operation dispatch refuses before native work (here: it does not
/// decode) is never sent to the proof worker by a pre-verification.
#[test]
fn an_undecodable_operation_never_reaches_the_proof_worker() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("spawned");
    let script = directory.path().join("worker.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > /dev/null\ntouch {}\nexit 81\n",
            marker.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let worker = WorkerVerifier::new(script, 5, std::time::Duration::from_secs(30)).unwrap();
    let policy = TokenPolicy::for_network(1);
    let mut junk = TYPE_LATTICE_TRANSACTION.to_be_bytes().to_vec();
    junk.extend_from_slice(&[0x33; 4096]);
    let outcome = policy.preverify(
        &worker,
        &domains::QUIL_TOKEN,
        &junk,
        TYPE_LATTICE_TRANSACTION,
    );
    assert!(
        !marker.exists(),
        "an undecodable operation was sent to the proof worker (pre-verification: {outcome:?})"
    );
    assert_eq!(outcome, Preverified::NotApplicable);
}

/// From the canonical owner frame the executing shard refuses an
/// operation naming an owner that is not a canonical identity, before any
/// proof work; before that frame the same operation goes on to its proof.
#[test]
fn the_executing_shard_refuses_a_noncanonical_owner_from_its_frame() {
    use quil_lattice_ct::confidential::{
        relation::membership::{Node, NODE_BYTES},
        transfer::{parameter_context, Output, Transfer, TransferStatement, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("spawned");
    let script = directory.path().join("worker.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > /dev/null\ntouch {}\nexit 81\n",
            marker.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let worker = WorkerVerifier::new(script, 5, std::time::Duration::from_secs(30)).unwrap();
    let policy = TokenPolicy::for_network(1);
    let application = domains::QUIL_TOKEN;
    let context = parameter_context(&policy.network, &application);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let bytes = Transfer {
        statement: TransferStatement {
            network: policy.network,
            application,
            depth: 1,
            root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(),
            images: vec![[5; IDENTITY_BYTES]],
            fee: 2,
            outputs: vec![Output {
                owner: [0xff; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context)
                    .commit(4, &AmountOpening::from_seed(&context, &[5; 32])),
                memo: [3; MEMO_BYTES],
            }],
        },
        proof,
    }
    .encode()
    .unwrap();
    let state = crate::hypergraph_state::HypergraphState::new(std::sync::Arc::new(
        quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        ),
    ));
    let stubs = crate::testing::NoopExecutionCrypto::new();
    let dispatch = || {
        policy.dispatch_for_commit(
            &state,
            quil_types::execution::FrameExecutionContext {
                frame_number: 1_001,
                finalized_global_frame: Some(1_000),
                shard: quil_types::execution::ShardPath::WHOLE,
                venue: None,
            },
            stubs.clock_store.as_ref(),
            &application,
            &bytes,
            TYPE_LATTICE_TRANSACTION,
            Some(&worker),
            None,
        )
    };
    super::super::global_commit::set_canonical_owner_frame_for_thread(Some(1_000));
    let refused = dispatch().unwrap_err();
    assert!(
        refused.to_string().contains("not a canonical identity"),
        "{refused}"
    );
    assert!(
        !marker.exists(),
        "the refused operation reached the proof worker"
    );
    super::super::global_commit::set_canonical_owner_frame_for_thread(Some(1_001));
    let before = dispatch().unwrap_err();
    assert!(
        !before.to_string().contains("not a canonical identity"),
        "refused before its frame: {before}"
    );
    super::super::global_commit::set_canonical_owner_frame_for_thread(None);
}

/// From the canonical owner frame GLOBAL refuses a QUIL reward mint
/// authorizing an output whose owner is not a canonical identity, before
/// it reads the cited reward root; before that frame it goes on to that read.
#[test]
fn the_global_reward_mint_refuses_a_noncanonical_output_from_its_frame() {
    use quil_lattice_ct::confidential::{
        mint::{MintStatement, RewardClaim, FALCON_PUBLIC_BYTES, FALCON_SIGNATURE_BYTES},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    let policy = TokenPolicy::for_network(1);
    let application = domains::QUIL_TOKEN;
    let context = parameter_context(&policy.network, &application);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let bytes = Mint {
        statement: MintStatement {
            network: policy.network,
            application,
            cited_frame: 1,
            reward_root: [8; 32],
            fee: 2,
            claims: vec![RewardClaim {
                owner: [8; 32],
                value: 18,
                public_key: [0; FALCON_PUBLIC_BYTES],
                forest_proof: vec![1],
            }],
            outputs: vec![Output {
                owner: [0xff; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context)
                    .commit(16, &AmountOpening::from_seed(&context, &[5; 32])),
                memo: [3; MEMO_BYTES],
            }],
        },
        signatures: vec![[0; FALCON_SIGNATURE_BYTES]],
        proof,
    }
    .encode()
    .unwrap();
    let state = crate::hypergraph_state::HypergraphState::new(std::sync::Arc::new(
        quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        ),
    ));
    let stubs = crate::testing::NoopExecutionCrypto::new();
    let mint = |frame: u64| {
        policy.dispatch_global_mint(
            &state,
            frame,
            stubs.clock_store.as_ref(),
            &application,
            &bytes,
            None,
        )
    };
    super::super::global_commit::set_canonical_owner_frame_for_thread(Some(1_000));
    let refused = mint(1_001).unwrap_err();
    assert!(
        refused.to_string().contains("not a canonical identity"),
        "{refused}"
    );
    let before = mint(1_000).unwrap_err();
    assert!(
        !before.to_string().contains("not a canonical identity"),
        "refused before its frame: {before}"
    );
    super::super::global_commit::set_canonical_owner_frame_for_thread(None);
}
