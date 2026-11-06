//! A QUIL-shard frame carrying a reward citation of a GLOBAL frame
//! this worker does not hold. A regular node holds GLOBAL frames only from
//! its start and gap-fills 2,880 frames below its head, so a mint claim
//! citing an older 2.1.0 frame finds nothing here, though archives and older
//! replicas hold that frame. The failed read is an execution failure: the
//! frame is held for retry. The reproducer fails with "UNHELD HALT" while no
//! retry can succeed; the control shows a worker holding the frame finishes
//! it. These use only interfaces of the base.
use super::*;
use quil_lattice_ct::confidential::{
    mint_claim::MintClaim,
    relation::membership::IDENTITY_BYTES,
    transfer::{parameter_context, Output, MEMO_BYTES},
    AmountOpening, CommitmentKey,
};
use quil_store::testing::InMemoryClockStore;
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader, MessageBundle};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The first mainnet frame a reward may cite (the first 2.1.0 frame).
const FIRST_CITABLE: u64 = 669_976;
/// The executing frame's GLOBAL anchor, past the 2,880 frames a regular
/// node's gap fill keeps below its head.
const ANCHOR: u64 = FIRST_CITABLE + 3_000;
/// The cited frame: 2.1.0 history this worker does not hold.
const CITED: u64 = FIRST_CITABLE;

type Fetch = std::pin::Pin<Box<dyn std::future::Future<Output = Result<GlobalFrame>> + Send>>;

fn global_frame(number: u64) -> GlobalFrame {
    GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: number,
            prover_tree_commitment: vec![0x5a; 32],
            world_state_size: 1234,
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A GLOBAL frame store holding `numbers`.
fn holding(numbers: &[u64]) -> Arc<InMemoryClockStore> {
    let store = Arc::new(InMemoryClockStore::new());
    for &number in numbers {
        store.seed_frame(global_frame(number));
    }
    store
}

/// The worker's own master, answering from `master` (its store and archive
/// fallback in one), counting the requests.
fn master_source(
    master: &Arc<InMemoryClockStore>,
    calls: &Arc<AtomicUsize>,
) -> crate::global_anchor::GlobalAnchorSource {
    let master = master.clone();
    let calls = calls.clone();
    Arc::new(move |number: u64| -> Fetch {
        calls.fetch_add(1, Ordering::SeqCst);
        let master = master.clone();
        Box::pin(async move { master.get_global_clock_frame(number) })
    })
}

/// A mint claim any submitter can build: no authorization behind it, a root
/// matching no frame. Only its encoding is valid.
fn mint_claim_bundle(cited_global_frame: u64) -> MessageBundle {
    let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).network;
    let application = quil_execution::domains::QUIL_TOKEN;
    let context = parameter_context(&network, &application);
    let key = CommitmentKey::derive(&context);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    let claim = MintClaim {
        network,
        application,
        cited_global_frame,
        global_root: [9; 32],
        receipt: [10; 32],
        fee: 1,
        outputs: vec![Output {
            commitment: key.commit(7, &opening),
            owner: [3; IDENTITY_BYTES],
            memo: [4; MEMO_BYTES],
        }],
        forest_proof: vec![11; 40],
    }
    .encode()
    .unwrap();
    MessageBundle {
        requests: vec![quil_types::proto::global::MessageRequest {
            request: Some(
                quil_types::proto::global::message_request::Request::TokenOperation(
                    quil_types::proto::token::TokenOperation {
                        canonical_bytes: claim,
                    },
                ),
            ),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// A QUIL-shard worker of a mainnet node, built as a thread worker is: the
/// token suite installed (never reached: the citation is read first), GLOBAL
/// frames in `anchors`, historical ones from its master through `source`.
struct Worker {
    engine: AppConsensusEngine,
    anchors: Arc<InMemoryClockStore>,
    _events: mpsc::UnboundedReceiver<AppEngineEvent>,
    dir: std::path::PathBuf,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn worker(
    anchors: Arc<InMemoryClockStore>,
    source: Option<crate::global_anchor::GlobalAnchorSource>,
) -> Worker {
    let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        prover.clone(),
    ));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let dir = std::env::temp_dir().join(format!("quil-cited-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let verifier =
        quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier::new(
            dir.join("absent-worker"),
            1,
            Duration::from_secs(2),
        )
        .unwrap();
    let manager = Arc::new(
        quil_execution::ExecutionEngineManager::new(
            prover.clone(),
            crypto.key_manager.clone(),
            crdt.clone(),
            crypto.circuit_compiler.clone(),
            crypto.clock_store.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            false,
        )
        .with_pricing_network(0)
        .with_application_venue()
        .unwrap()
        .with_global_clock_store(anchors.clone())
        .unwrap()
        .with_token_worker(
            quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0),
            verifier,
        )
        .unwrap(),
    );
    let (events, received) = mpsc::unbounded_channel();
    let private = [7; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
    let deps = AppEngineDeps {
        delivery_frame_source: None,
        clock_store: crypto.clock_store,
        global_anchor_store: Some(anchors.clone() as Arc<dyn ClockStore>),
        global_hypergraph: None,
        prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
        frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        message_collector: Arc::new(MessageCollector::new()),
        fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
        local_prover_address: vec![1; 32],
        local_bls_pubkey: vec![],
        bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
        reward_greedy: false,
        min_active_provers_for_propose: 1,
        coverage_publish: None,
        hypergraph: Some(crdt),
        storage_source_hypergraph: None,
        topology: None,
        execution_engine: Some(manager),
        inclusion_prover: Some(prover),
        kv_db: None,
        db_config: Default::default(),
        unified_cutover_hook: None,
    };
    let application = quil_execution::domains::QUIL_TOKEN;
    let (engine, _handle) = AppConsensusEngine::new(1, application.to_vec(), deps, events);
    Worker {
        engine: engine.with_global_anchor_source(source),
        anchors,
        _events: received,
        dir,
    }
}

/// Materialize QUIL-shard frame 1 (anchored at [`ANCHOR`]) carrying `requests`.
async fn materialize(node: &Worker, requests: Vec<MessageBundle>) -> Result<(usize, usize)> {
    node.engine
        .materialize_offloaded(requests, 1, 50_000, 7, ANCHOR, &[])
        .await
}

fn setup_error(error: &QuilError) -> bool {
    quil_execution::token_intrinsic::is_proof_verification_pending(error)
        || quil_execution::token_intrinsic::is_proof_worker_busy(error)
}

#[tokio::test]
async fn reproduces_a_mint_claim_citing_an_unheld_frame_halts_the_quil_shard() {
    let calls = Arc::new(AtomicUsize::new(0));
    let master = holding(&[CITED]);
    let node = worker(holding(&[ANCHOR]), Some(master_source(&master, &calls)));
    let requests = vec![mint_claim_bundle(CITED)];
    let mut failures = Vec::new();
    for attempt in 1..=MAX_MATERIALIZE_RETRIES {
        match materialize(&node, requests.clone()).await {
            Ok(counts) => {
                assert!(
                    node.anchors.get_global_clock_frame(CITED).is_ok(),
                    "UNHELD SETUP: attempt {attempt} finished the frame ({counts:?}) without the \
                     cited frame: the claim never reached its citation"
                );
                assert_eq!(
                    counts,
                    (0, 1),
                    "the junk claim must be skipped once its cited frame is read"
                );
                assert_eq!(node.engine.load_materialized_cursor().unwrap(), 1);
                return;
            }
            Err(error) if setup_error(&error) => {
                panic!("UNHELD SETUP: the frame waits on proof verification instead: {error}")
            }
            Err(error) if error.is_execution_unavailable() => failures.push(error.to_string()),
            Err(error) => panic!("UNHELD UNEXPECTED: the frame failed with {error}"),
        }
    }
    panic!(
        "UNHELD HALT: a mint claim citing GLOBAL frame {CITED}, which this worker lacks and its \
         master serves (asked {} times), failed the QUIL-shard frame on all \
         {MAX_MATERIALIZE_RETRIES} attempts, so the frame is dropped and every replica lacking \
         the frame stalls alike: {}",
        calls.load(Ordering::SeqCst),
        failures.last().map_or("", String::as_str)
    );
}

#[tokio::test]
async fn control_a_worker_holding_the_cited_frame_finishes_the_frame() {
    let calls = Arc::new(AtomicUsize::new(0));
    let master = holding(&[CITED]);
    let node = worker(
        holding(&[CITED, ANCHOR]),
        Some(master_source(&master, &calls)),
    );
    let finished = materialize(&node, vec![mint_claim_bundle(CITED)]).await;
    assert!(
        matches!(finished, Ok((0, 1))),
        "control: a worker holding the cited frame must skip the junk claim and finish: \
         {finished:?}"
    );
    assert_eq!(node.engine.load_materialized_cursor().unwrap(), 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "control: a worker holding the cited frame must not ask its master"
    );
    eprintln!("UNHELD CONTROL: a worker holding the cited frame finishes the frame");
}
