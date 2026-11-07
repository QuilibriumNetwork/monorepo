//! Base reproducer at the GLOBAL materializer: a frame carrying a QUIL reward
//! mint whose cited frame no store holds fails as a whole (the op's
//! `ExecutionUnavailable` is returned at `frame_materializer.rs` ~1109), so
//! the cursor never passes it. Here the mint (on mainnet, network 0) cites
//! frame 0, which no mainnet node holds: on mainnet no frame before the first
//! 2.1.0 frame (669,976) resolves, as none exists below the 2.1 genesis and
//! the legacy frames from it commit 74-byte prover roots.
//! The control shows a deterministically refused mint is skipped instead.
use super::*;
use quil_lattice_ct::confidential::{
    mint::{Mint, MintStatement, RewardClaim, FALCON_PUBLIC_BYTES, FALCON_SIGNATURE_BYTES},
    relation::membership::IDENTITY_BYTES,
    transfer::{parameter_context, Output, MEMO_BYTES},
    AmountOpening, CommitmentKey,
};

/// Past the first citable frame (669,976), so the mint meets the bound on the
/// anchor and not the one on the first citable frame.
const FUTURE: u64 = 669_976 + 5;

fn policy() -> quil_execution::token_intrinsic::dispatch::TokenPolicy {
    quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0)
}

/// [`Fixture::seeded`] with the token suite configured as a node configures
/// it (`with_token_worker`). The worker is never reached: the cited-frame
/// read comes before any proof work.
fn token_source() -> (FrameMaterializer, [u8; 32], std::path::PathBuf) {
    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let prover = Arc::new(quil_tries::ShaInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        store.clone(),
        prover.clone(),
    ));
    crdt.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
    crdt.set_unified_tree(true);
    crdt.warm_sizes(&[]).unwrap();
    let key = quil_crypto::FalconSigner::generate().public_key().to_vec();
    crate::genesis::seed_active_prover_on_filter(&crdt, &key, 1000, 0, &[]).unwrap();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let dir = std::env::temp_dir().join(format!("quil-uncitable-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let worker =
        quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier::new(
            dir.join("absent-worker"),
            1,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
    let stubs = quil_execution::testing::NoopExecutionCrypto::new();
    let manager = Arc::new(
        quil_execution::ExecutionEngineManager::new_with_shards(
            prover,
            stubs.key_manager,
            crdt.clone(),
            stubs.circuit_compiler,
            clock.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            true,
            Some(Arc::new(quil_store::RocksShardsStore::new(db.inner()))),
            Some(db.clone()),
        )
        .with_pricing_network(1)
        .with_token_worker(policy(), worker)
        .unwrap(),
    );
    crdt.commit_with_global_cursor(0, &quil_store::encoding::global_materialized_cursor_key())
        .unwrap();
    let root = crdt.current_forest_phase_root(&[0xff; 32], 0).unwrap();
    crdt.record_prover_root(0, root.to_vec());
    let registry = Arc::new(quil_execution::prover_registry::SharedProverRegistry::new());
    registry.refresh_from_store(store.as_ref()).unwrap();
    let source = crate::frame_materializer::FrameMaterializer::new(
        manager,
        registry.clone(),
        clock,
        crdt,
        store,
        Arc::new(crate::rewards::OptRewardIssuance),
        vec![8; 32],
        true,
    )
    .with_eviction_registry(registry);
    (source, root, dir)
}

/// A QUIL reward mint any submitter can build: only its encoding is valid.
fn junk_mint_bundle(cited_frame: u64) -> quil_types::proto::global::MessageBundle {
    let network = policy().network;
    let application = quil_execution::domains::QUIL_TOKEN;
    let context = parameter_context(&network, &application);
    let key = CommitmentKey::derive(&context);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    let value = u128::MAX / 2;
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let mint = Mint {
        statement: MintStatement {
            network,
            application,
            cited_frame,
            reward_root: [9; 32],
            fee: value,
            claims: vec![RewardClaim {
                owner: [5; 32],
                value,
                public_key: [6; FALCON_PUBLIC_BYTES],
                forest_proof: vec![7; 40],
            }],
            outputs: vec![Output {
                commitment: key.commit(7, &opening),
                owner: [3; IDENTITY_BYTES],
                memo: [4; MEMO_BYTES],
            }],
        },
        signatures: vec![[8; FALCON_SIGNATURE_BYTES]],
        proof,
    }
    .encode()
    .unwrap();
    quil_types::proto::global::MessageBundle {
        requests: vec![quil_types::proto::global::MessageRequest {
            request: Some(
                quil_types::proto::global::message_request::Request::TokenOperation(
                    quil_types::proto::token::TokenOperation {
                        canonical_bytes: mint,
                    },
                ),
            ),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The steps before execution must let the mint through, or the reproducer
/// would pass for another reason.
fn check_setup(source: &FrameMaterializer, bundle: &quil_types::proto::global::MessageBundle) {
    let bytes = crate::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle).unwrap();
    let route = bundle_global_route(bundle, false, |_| false);
    assert_eq!(
        route,
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        "EARLY SETUP: the mint must take the global reward route"
    );
    let manager = &source.execution_manager;
    if let Err(error) = manager.get_cost(&bytes) {
        panic!("EARLY SETUP: pricing refused the mint before execution: {error}");
    }
    if let Err(error) = manager.validate_message(1, &route, &bytes) {
        panic!("EARLY SETUP: the materializer's validate step refused the mint: {error}");
    }
}

#[test]
fn global_materializer_must_finish_a_frame_whose_mint_cites_an_unheld_frame() {
    let (source, root, dir) = token_source();
    let mut input = frame(1, root);
    input.requests = vec![junk_mint_bundle(0)];
    check_setup(&source, &input.requests[0]);
    let first = source.materialize(&input);
    let retry = source.materialize(&input);
    let outcomes = source.clock_store.get_global_clock_frame_outcomes(1);
    let _ = std::fs::remove_dir_all(&dir);
    match first {
        Ok(result) => {
            assert_eq!(
                (result.processed, source.last_materialized_frame()),
                (0, 1),
                "the refused mint is skipped and the frame completes"
            );
            let outcomes = outcomes.unwrap();
            assert!(
                outcomes.iter().any(|o| o
                    .error
                    .contains("precedes the network's first citable frame")),
                "EARLY WRONG REFUSAL: the mint was skipped, but not by the first citable frame: \
                 {outcomes:?}"
            );
        }
        Err(error) => panic!(
            "EARLY HALT: the GLOBAL materializer failed frame 1 as a whole on a junk reward mint \
             citing a frame this store never held (unavailable class: {}); cursor stays at {}, \
             retry: {:?}; error: {error}",
            error.is_execution_unavailable(),
            source.last_materialized_frame(),
            retry.err().map(|e| e.to_string()),
        ),
    }
}

#[test]
fn control_global_materializer_skips_a_refused_mint_and_finishes_the_frame() {
    let (source, root, dir) = token_source();
    let mut input = frame(1, root);
    // A future citation is refused with InvalidArgument before the clock read.
    input.requests = vec![junk_mint_bundle(FUTURE)];
    check_setup(&source, &input.requests[0]);
    let result = source.materialize(&input);
    let outcomes = source.clock_store.get_global_clock_frame_outcomes(1);
    let _ = std::fs::remove_dir_all(&dir);
    let result = result.unwrap_or_else(|error| {
        panic!("control: a deterministically refused mint must not fail the frame: {error}")
    });
    assert_eq!(
        (
            result.processed,
            result.skipped,
            source.last_materialized_frame()
        ),
        (0, 1, 1),
        "control: the refused mint is skipped and the cursor passes frame 1"
    );
    let outcomes = outcomes.unwrap();
    assert!(
        outcomes
            .iter()
            .any(|o| o.error.contains("future global reward frame")),
        "control: the mint must be refused as a future citation: {outcomes:?}"
    );
    eprintln!("EARLY CONTROL: a refused mint is skipped and the GLOBAL frame completes");
}

#[test]
fn global_proposal_validation_keeps_a_junk_reward_mint() {
    // `leader_provider.rs` ~1341 validates collected messages against the
    // GLOBAL engine (0xff..), which skips token ops: the leader proposes the
    // junk mint, and voters execute only the parent ancestry
    // (`cw_global_seams.rs` ~1006), so nothing drops it before certification.
    let (source, _, dir) = token_source();
    let bundle = junk_mint_bundle(0);
    let bytes = crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundle).unwrap();
    let manager = &source.execution_manager;
    let kept = manager.validate_message(1, &[0xff; 32], &bytes);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        kept.is_ok(),
        "fact changed: GLOBAL proposal validation now refuses the junk mint: {:?}",
        kept.err()
    );
    eprintln!("EARLY FACT: GLOBAL proposal validation keeps the junk reward mint (no drop)");
}
