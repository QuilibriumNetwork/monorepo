//! A/B reproducer: an archive verifies the confidential proofs of the
//! application frames a GLOBAL frame carries while it holds its ingest.
//!
//! The GLOBAL hook (`archive_sync::sequenced_ingest_hook`) materializes those
//! frames under the archive ingest, which gossip ingest, its retry pass and
//! the gap fetch's admission also take, so for as long as a proof verifies
//! they all wait. Live, archives verified a backlog of batch shields (about
//! two minutes each) this way from GLOBAL frame 945,000 (2026-10-28). Only
//! APIs of the release base are used: a frame admitted before GLOBAL
//! sequences it must be materialized, under the ingest, without verifying a
//! proof there. The worker is a stub that sleeps before its verdict.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quil_engine::archive_ingest::ArchiveAppShardIngest;
use quil_types::proto::global::{
    message_request::Request, AppShardFrame, FrameHeader, MessageBundle, MessageRequest,
};

/// How long the stub worker takes per proof.
const VERIFY: Duration = Duration::from_secs(2);

/// A worker that reads its request, sleeps [`VERIFY`] and rejects the proof
/// (a cached verdict either way).
fn stub_worker(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("slow-amount-worker");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\ncat >/dev/null\nsleep {}\nexit 81\n",
            VERIFY.as_secs()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// A well-formed batch shield of the QUIL token as a wallet submits it: this
/// network's and the token's context, one legacy coin, one output and a fee
/// the coin covers, so it decodes and fits the token's dimensions like a real
/// one. Its signature and proof are placeholders: the stub judges the proof.
fn shield(application: &[u8]) -> Vec<u8> {
    use quil_lattice_ct::confidential::{
        relation::membership::IDENTITY_BYTES,
        shield::{AnyShield, BatchShield, BatchShieldStatement, ShieldSource},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    let policy = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(1);
    let network = policy.network;
    let application: [u8; 32] = application.try_into().unwrap();
    let context = parameter_context(&network, &application);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let bytes = BatchShield {
        statement: BatchShieldStatement {
            network,
            application,
            owner_public_key: [4; 57],
            sources: vec![ShieldSource {
                address: [3; 32],
                amount: 12,
            }],
            fee: 2,
            outputs: vec![Output {
                commitment: CommitmentKey::derive(&context).commit(10, &opening),
                owner: [5; IDENTITY_BYTES],
                memo: [6; MEMO_BYTES],
            }],
        },
        signature: [0; 114],
        proof,
    }
    .encode()
    .unwrap();
    let decoded = AnyShield::decode(&bytes, &network, &application).unwrap();
    assert!(decoded.is_batch() && decoded.outputs().len() <= policy.limits.max_outputs);
    bytes
}

fn frame_with_shield(application: &[u8], number: u64) -> AppShardFrame {
    AppShardFrame {
        header: Some(FrameHeader {
            address: application.to_vec(),
            frame_number: number,
            ..Default::default()
        }),
        requests: vec![MessageBundle {
            requests: vec![MessageRequest {
                request: Some(Request::TokenOperation(
                    quil_types::proto::token::TokenOperation {
                        canonical_bytes: shield(application),
                    },
                )),
                timestamp: 0,
            }],
            timestamp: 1,
        }],
        storage_attestation: None,
    }
}

fn archive_ingest(worker: std::path::PathBuf) -> ArchiveAppShardIngest {
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let inclusion = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        store,
        inclusion.clone(),
    ));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let worker =
        quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier::new(
            worker,
            30,
            Duration::from_secs(30),
        )
        .unwrap();
    let manager = quil_execution::ExecutionEngineManager::new(
        inclusion.clone(),
        crypto.key_manager,
        crdt.clone(),
        crypto.circuit_compiler,
        crypto.clock_store.clone(),
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
        false,
    )
    .with_token_worker(
        quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(1),
        worker,
    )
    .unwrap();
    ArchiveAppShardIngest::new(
        Arc::new(quil_engine::test_support::TestProverRegistry::new()),
        Arc::new(quil_crypto::FalconKeyConstructor),
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        Arc::new(manager),
        inclusion,
        crdt,
        crypto.clock_store,
    )
    .sequenced()
}

/// A frame admitted ahead of the GLOBAL frame that sequences it is later
/// materialized under the ingest without a proof verifying there: the
/// verdict is computed outside the ingest by then. Vulnerable outcome: the
/// ingest is held for the whole verification.
#[test]
fn materializing_an_admitted_frame_does_not_verify_proofs_under_the_ingest() {
    let directory = tempfile::tempdir().unwrap();
    let application = quil_execution::domains::QUIL_TOKEN.to_vec();
    let mut ingest = archive_ingest(stub_worker(directory.path()));
    // Admitted (as the gap fetch and gossip admit a verified frame), not
    // yet sequenced by GLOBAL.
    ingest.admit_verified(frame_with_shield(&application, 1), true);
    let ingest = Mutex::new(ingest);
    // GLOBAL carries its header a while later.
    std::thread::sleep(VERIFY * 3);
    let start = Instant::now();
    let held = {
        let mut guard = ingest.lock().unwrap();
        let _ = guard.materialize_through(&application, 1);
        start.elapsed()
    };
    assert!(
        held < VERIFY / 2,
        "the archive ingest was held {held:?} while GLOBAL materialization verified a \
         confidential proof ({VERIFY:?} per proof): gossip ingest and the gap fetch wait \
         behind it"
    );
}

/// A GLOBAL proposal holds back the header of a shard whose admitted frame
/// carries a batch shield this archive has not verified yet (its size class
/// was never measured here, so it is not known to fit the per-frame budget),
/// and carries it once the shield verified here and the margin for slower
/// archives passed: GLOBAL then finds its verdict cached instead of waiting
/// for it. Vulnerable outcome: the header rides at once.
#[test]
fn a_global_proposal_holds_a_shard_until_its_shield_verified_on_this_archive() {
    let directory = tempfile::tempdir().unwrap();
    let application = quil_execution::domains::QUIL_TOKEN.to_vec();
    let mut ingest = archive_ingest(stub_worker(directory.path()));
    let start = Instant::now();
    ingest.admit_verified(frame_with_shield(&application, 1), true);
    let settlement = ingest.proof_prewarm().unwrap().settlement();
    assert!(
        settlement.check(&application, 0, 1).holds(),
        "a GLOBAL proposal would carry the header of a frame whose shield no archive \
         verified yet, and GLOBAL execution would wait for it"
    );
    let released = loop {
        let decision = settlement.check(&application, 0, 1);
        if !decision.holds() {
            assert_eq!(
                decision,
                quil_engine::archive_preverify::Settlement::Settled
            );
            break start.elapsed();
        }
        assert!(start.elapsed() < VERIFY * 10, "never released");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        released >= VERIFY,
        "released after {released:?}, before it verified"
    );
    assert!(
        !settlement.check(&application, 0, 0).holds(),
        "a header below the frame was never held"
    );
}
