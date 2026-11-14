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

/// The Ed448 key whose legacy coins the shields here spend, and another.
const OWNER: [u8; 57] = [23; 57];
const OTHER: [u8; 57] = [24; 57];

/// A legacy coin of 12 owned by the Ed448 key `owner`, told apart by
/// `salt`, written into `store` (an archive's, holding every shard): its
/// address.
fn legacy_coin(
    store: &Arc<quil_hypergraph::HypergraphCrdt>,
    owner: [u8; 57],
    salt: u8,
) -> [u8; 32] {
    use quil_execution::{
        hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        token_intrinsic::{legacy_migration, materialize},
    };
    let application = quil_execution::domains::QUIL_TOKEN;
    let public = quil_crypto::Ed448Signer::derive_public(&owner).unwrap();
    let tree = legacy_migration::create_transparent_coin_tree(
        &legacy_migration::TransparentCoin {
            owner_address: quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap(),
            amount: 12,
        },
        &legacy_migration::transparent_type_hash(&application).unwrap(),
        &[salt; 32],
    )
    .unwrap();
    let address = materialize::coin_content_address(&tree).unwrap();
    let state = HypergraphState::new(store.clone());
    state
        .set(
            &application,
            &address,
            &vertex_adds_discriminator().unwrap(),
            1,
            quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    state.commit().unwrap();
    state.abort();
    address
}

/// A well-formed batch shield of the QUIL token as a wallet submits it: this
/// network's and the token's context, one legacy coin `source` of 12, one
/// output and a fee the coin covers, by the Ed448 key `signer`, signed by it
/// when `signed`, so it decodes and fits the token's dimensions like a real
/// one. Its proof is a placeholder: the stub judges the proof.
fn shield(application: &[u8], signer: [u8; 57], source: [u8; 32], signed: bool) -> Vec<u8> {
    use quil_lattice_ct::confidential::{
        relation::membership::IDENTITY_BYTES,
        shield::{AnyShield, BatchShield, BatchShieldStatement, ShieldSource},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    use quil_types::crypto::Signer as _;
    let policy = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(1);
    let network = policy.network;
    let application: [u8; 32] = application.try_into().unwrap();
    let context = parameter_context(&network, &application);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    let public = quil_crypto::Ed448Signer::derive_public(&signer).unwrap();
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let statement = BatchShieldStatement {
        network,
        application,
        owner_public_key: public.clone().try_into().unwrap(),
        sources: vec![ShieldSource {
            address: source,
            amount: 12,
        }],
        fee: 2,
        outputs: vec![Output {
            commitment: CommitmentKey::derive(&context).commit(10, &opening),
            owner: [5; IDENTITY_BYTES],
            memo: [6; MEMO_BYTES],
        }],
    };
    let signature = if signed {
        quil_crypto::Ed448Signer::from_bytes(&signer, &public)
            .unwrap()
            .sign(&statement.context_bytes().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    } else {
        [0; 114]
    };
    let bytes = BatchShield {
        statement,
        signature,
        proof,
    }
    .encode()
    .unwrap();
    let decoded = AnyShield::decode(&bytes, &network, &application).unwrap();
    assert!(decoded.is_batch() && decoded.outputs().len() <= policy.limits.max_outputs);
    bytes
}

/// A transfer of the QUIL token proving membership against a root of the
/// submitter's own making (GLOBAL never held it), spending image `image`:
/// well-formed, with a fee, no valid proof. It needs no coin.
fn coinless_transfer(image: u8) -> Vec<u8> {
    use quil_lattice_ct::confidential::{
        relation::membership::{Node, IDENTITY_BYTES, NODE_BYTES},
        transfer::{parameter_context, Output, Transfer, TransferStatement, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(1).network;
    let application = quil_execution::domains::QUIL_TOKEN;
    let context = parameter_context(&network, &application);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    Transfer {
        statement: TransferStatement {
            network,
            application,
            depth: 1,
            root: Node::from_bytes(&[9; NODE_BYTES]).unwrap(),
            images: vec![[image; IDENTITY_BYTES]],
            outputs: vec![Output {
                commitment: CommitmentKey::derive(&context)
                    .commit(10, &AmountOpening::from_seed(&context, &[image; 32])),
                owner: [5; IDENTITY_BYTES],
                memo: [6; MEMO_BYTES],
            }],
            fee: 2,
        },
        proof,
    }
    .encode()
    .unwrap()
}

/// App frame `number` of `application` carrying each operation in its own
/// bundle.
fn frame_with(application: &[u8], number: u64, operations: &[Vec<u8>]) -> AppShardFrame {
    AppShardFrame {
        header: Some(FrameHeader {
            address: application.to_vec(),
            frame_number: number,
            ..Default::default()
        }),
        requests: operations
            .iter()
            .map(|operation| MessageBundle {
                requests: vec![MessageRequest {
                    request: Some(Request::TokenOperation(
                        quil_types::proto::token::TokenOperation {
                            canonical_bytes: operation.clone(),
                        },
                    )),
                    timestamp: 0,
                }],
                timestamp: 1,
            })
            .collect(),
        storage_attestation: None,
    }
}

/// A frame carrying one shield this archive's execution accepts before its
/// proof: of a coin of its key in the archive's store `store`, signed.
fn frame_with_shield(
    store: &Arc<quil_hypergraph::HypergraphCrdt>,
    application: &[u8],
    number: u64,
) -> AppShardFrame {
    let source = legacy_coin(store, OWNER, number as u8);
    frame_with(
        application,
        number,
        &[shield(application, OWNER, source, true)],
    )
}

/// An archive's ingest verifying with `worker`, and its store.
fn archive_ingest(
    worker: std::path::PathBuf,
) -> (ArchiveAppShardIngest, Arc<quil_hypergraph::HypergraphCrdt>) {
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
    let ingest = ArchiveAppShardIngest::new(
        Arc::new(quil_engine::test_support::TestProverRegistry::new()),
        Arc::new(quil_crypto::FalconKeyConstructor),
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        Arc::new(manager),
        inclusion,
        crdt.clone(),
        crypto.clock_store,
    )
    .sequenced();
    (ingest, crdt)
}

/// A worker that counts its runs in `directory/runs` (one line each) and
/// rejects every proof at once, and that file.
fn counting_worker(directory: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let runs = directory.join("runs");
    let path = directory.join("counting-worker");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\ncat >/dev/null\necho run >> {}\nexit 81\n",
            runs.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (path, runs)
}

/// How many times the [`counting_worker`] writing `runs` ran.
fn worker_runs(runs: &std::path::Path) -> usize {
    std::fs::read_to_string(runs).map_or(0, |text| text.lines().count())
}

/// A frame admitted ahead of the GLOBAL frame that sequences it is later
/// materialized under the ingest without a proof verifying there: the
/// verdict is computed outside the ingest by then. Vulnerable outcome: the
/// ingest is held for the whole verification.
#[test]
fn materializing_an_admitted_frame_does_not_verify_proofs_under_the_ingest() {
    let directory = tempfile::tempdir().unwrap();
    let application = quil_execution::domains::QUIL_TOKEN.to_vec();
    let (mut ingest, store) = archive_ingest(stub_worker(directory.path()));
    // Admitted (as the gap fetch and gossip admit a verified frame), not
    // yet sequenced by GLOBAL.
    ingest.admit_verified(frame_with_shield(&store, &application, 1), true);
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
    let (mut ingest, store) = archive_ingest(stub_worker(directory.path()));
    let start = Instant::now();
    ingest.admit_verified(frame_with_shield(&store, &application, 1), true);
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

/// A shield execution refuses before its proof (of a coin its key does not
/// own, one its key did not sign, one of a coin no shard holds) needs no
/// coin of the submitter's own. On the base an archive verifies its proof
/// all the same, in the background and in the pre-pass a GLOBAL frame waits
/// on, whichever leader proposed it; here it verifies none, and executing
/// the frame refuses them before any proof, as before.
#[test]
fn an_archive_never_verifies_a_shield_its_execution_refuses_before_the_proof() {
    let directory = tempfile::tempdir().unwrap();
    let application = quil_execution::domains::QUIL_TOKEN.to_vec();
    let (worker, runs) = counting_worker(directory.path());
    let (mut ingest, store) = archive_ingest(worker);
    let theirs = legacy_coin(&store, OWNER, 1);
    let refused = [
        shield(&application, OTHER, theirs, true),
        shield(&application, OWNER, theirs, false),
        shield(&application, OWNER, [0x2a; 32], true),
    ];
    ingest.admit_verified(frame_with(&application, 1, &refused), true);
    let ingest = Mutex::new(ingest);
    let report =
        quil_engine::archive_preverify::preverify_through(&ingest, 2, &[(application.clone(), 1)]);
    let _ = ingest.lock().unwrap().materialize_through(&application, 1);
    let verified = worker_runs(&runs);
    assert_eq!(
        verified, 0,
        "VULNERABLE: this archive verified {verified} proofs of shields its execution refuses \
         before their proof (another key's coin, unsigned, a coin no shard holds); the GLOBAL \
         frame carrying them waited on that ({report:?})"
    );
}

/// The archive leg of the coinless operations. A transfer citing a root
/// GLOBAL never held needs no coin and passes every check shard execution
/// makes before its proof (its funding shape), so every archive verifies its
/// proof before the GLOBAL frame carrying it executes, whatever leader
/// proposed it, and only then does the commit refuse it, for no fee; an
/// archive cannot leave it out, as its own execution of the frame verifies
/// it too. A shield of a coin its key does not own, which execution refuses
/// before its proof, the base's pre-pass verified as well; here it does not.
#[test]
fn the_archive_prepass_verifies_a_transfer_only_the_global_commit_refuses() {
    let directory = tempfile::tempdir().unwrap();
    let application = quil_execution::domains::QUIL_TOKEN.to_vec();
    let (worker, runs) = counting_worker(directory.path());
    let (mut ingest, store) = archive_ingest(worker);
    let theirs = legacy_coin(&store, OWNER, 1);
    let carried = [
        coinless_transfer(7),
        shield(&application, OTHER, theirs, true),
    ];
    ingest.admit_verified(frame_with(&application, 1, &carried), true);
    let ingest = Mutex::new(ingest);
    let report =
        quil_engine::archive_preverify::preverify_through(&ingest, 2, &[(application.clone(), 1)]);
    let _ = ingest.lock().unwrap().materialize_through(&application, 1);
    let verified = worker_runs(&runs);
    assert!(
        verified >= 1,
        "the archive verified nothing: the transfer's proof was not verified ({report:?})"
    );
    assert_eq!(
        verified, 1,
        "VULNERABLE: the archive verified {verified} proofs: the transfer's, which only the \
         GLOBAL commit refuses, and the shield's, which its own execution refuses before the \
         proof ({report:?})"
    );
}
