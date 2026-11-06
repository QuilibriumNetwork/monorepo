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
pub(super) const FIRST_CITABLE: u64 = 669_976;
/// The executing frame's GLOBAL anchor, past the 2,880 frames a regular
/// node's gap fill keeps below its head.
pub(super) const ANCHOR: u64 = FIRST_CITABLE + 3_000;
/// The cited frame: 2.1.0 history this worker does not hold.
pub(super) const CITED: u64 = FIRST_CITABLE;

pub(super) type Fetch =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<GlobalFrame>> + Send>>;

pub(super) fn global_frame(number: u64) -> GlobalFrame {
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
pub(super) fn holding(numbers: &[u64]) -> Arc<InMemoryClockStore> {
    let store = Arc::new(InMemoryClockStore::new());
    for &number in numbers {
        store.seed_frame(global_frame(number));
    }
    store
}

/// The worker's own master, answering from `master` (its store and archive
/// fallback in one), counting the requests.
pub(super) fn master_source(
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
pub(super) fn mint_claim_bundle(cited_global_frame: u64) -> MessageBundle {
    let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).network;
    let claim = MintClaim {
        network,
        application: quil_execution::domains::QUIL_TOKEN,
        cited_global_frame,
        global_root: [9; 32],
        receipt: [10; 32],
        fee: 1,
        outputs: vec![junk_output(&network)],
        forest_proof: vec![11; 40],
    }
    .encode()
    .unwrap();
    token_bundle(claim)
}

/// A QUIL output any submitter can build: a commitment to 7 with a seeded
/// opening.
fn junk_output(network: &[u8; 32]) -> Output {
    let context = parameter_context(network, &quil_execution::domains::QUIL_TOKEN);
    let key = CommitmentKey::derive(&context);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    Output {
        commitment: key.commit(7, &opening),
        owner: [3; IDENTITY_BYTES],
        memo: [4; MEMO_BYTES],
    }
}

/// A bundle of one confidential token operation.
fn token_bundle(operation: Vec<u8>) -> MessageBundle {
    MessageBundle {
        requests: vec![quil_types::proto::global::MessageRequest {
            request: Some(
                quil_types::proto::global::message_request::Request::TokenOperation(
                    quil_types::proto::token::TokenOperation {
                        canonical_bytes: operation,
                    },
                ),
            ),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// A settlement claim for `application` any submitter can build: no record
/// behind it, a root matching no frame. Only a non-QUIL application decodes
/// one (`SettlementClaim::decode`).
fn settlement_claim(application: [u8; 32], cited_global_frame: u64) -> Vec<u8> {
    quil_execution::token_intrinsic::settlement_claim::SettlementClaim {
        network: [1; 32],
        application,
        cited_global_frame,
        global_root: [3; 32],
        receipt: [4; 32],
        settlement: 1_000,
        context: [5; 32],
        payment_address: [0; 32],
        payment: 0,
        claimant_key_type: 0,
        claimant_public_key: Vec::new(),
        claimant_signature: Vec::new(),
        forest_proof: vec![6; 40],
    }
    .encode()
    .unwrap()
}

/// A delivery of `delivered` any byzantine shard leader can include: no
/// record behind it, a root matching no frame.
fn delivery(
    cited_global_frame: u64,
    delivered: quil_execution::token_intrinsic::delivery::Delivered,
) -> Vec<u8> {
    quil_execution::token_intrinsic::delivery::CoinDelivery {
        network: quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).network,
        application: quil_execution::domains::QUIL_TOKEN,
        cited_global_frame,
        global_root: [9; 32],
        block: 0,
        seq: 0,
        source_frame: 1,
        tx_id: [12; 32],
        source_shard: quil_types::execution::ShardPath::WHOLE,
        delivered,
        forest_proof: vec![11; 40],
    }
    .encode()
    .unwrap()
}

/// `manager` as a mainnet worker builds it: the token suite installed (its
/// proof worker is absent under `dir`; junk claims never reach it), the
/// application venue, and GLOBAL frames read from `anchors`.
pub(super) fn with_token_suite(
    manager: quil_execution::ExecutionEngineManager,
    anchors: Arc<dyn ClockStore>,
    dir: &std::path::Path,
) -> quil_execution::ExecutionEngineManager {
    let verifier =
        quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier::new(
            dir.join("absent-worker"),
            1,
            Duration::from_secs(2),
        )
        .unwrap();
    manager
        .with_pricing_network(0)
        .with_application_venue()
        .unwrap()
        .with_global_clock_store(anchors)
        .unwrap()
        .with_token_worker(
            quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0),
            verifier,
        )
        .unwrap()
}

/// A fresh directory under the system's temporary one.
pub(super) fn scratch_dir() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let dir = std::env::temp_dir().join(format!("quil-cited-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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
    worker_at(quil_execution::domains::QUIL_TOKEN, anchors, source)
}

/// [`worker`] of a shard of `application`.
fn worker_at(
    application: [u8; 32],
    anchors: Arc<InMemoryClockStore>,
    source: Option<crate::global_anchor::GlobalAnchorSource>,
) -> Worker {
    let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        prover.clone(),
    ));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let dir = scratch_dir();
    let manager = Arc::new(with_token_suite(
        quil_execution::ExecutionEngineManager::new(
            prover.clone(),
            crypto.key_manager.clone(),
            crdt.clone(),
            crypto.circuit_compiler.clone(),
            crypto.clock_store.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            false,
        ),
        anchors.clone(),
        &dir,
    ));
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

/// The master cannot serve the cited frame (no archive answers): the frame is
/// held for retry, never finished by refusing the claim, since a replica
/// holding the frame decides it. Once the master has the frame, the same
/// frame finishes as on a holder.
#[tokio::test]
async fn an_unfetchable_cited_frame_keeps_the_frame_for_retry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let master = holding(&[]);
    let node = worker(holding(&[ANCHOR]), Some(master_source(&master, &calls)));
    let requests = vec![mint_claim_bundle(CITED)];
    let held = materialize(&node, requests.clone()).await;
    assert!(
        held.as_ref()
            .is_err_and(|error| error.is_execution_unavailable() && !setup_error(error)),
        "a cited frame no source serves must hold the frame for retry: {held:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the worker must ask its master for the cited frame"
    );
    assert_eq!(node.engine.load_materialized_cursor().unwrap(), 0);
    master.seed_frame(global_frame(CITED));
    let finished = materialize(&node, requests).await;
    assert!(
        matches!(finished, Ok((0, 1))),
        "once the master serves the cited frame, the frame must finish: {finished:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(node.engine.load_materialized_cursor().unwrap(), 1);
}

/// A frame whose citation of a GLOBAL frame cannot be fetched executes none
/// of its bundles, not even those before it whose cited frames are here, and
/// stages nothing: the bundles a partial execution ran would stay staged and
/// commit with the retry, which skips them as already applied. The frame
/// waits for retry and, once every cited frame is held, executes whole.
#[tokio::test]
async fn a_frame_with_an_unfetched_citation_executes_no_bundle() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (served, unserved) = (CITED + 1, CITED + 2);
    let master = holding(&[served]);
    let node = worker(holding(&[ANCHOR]), Some(master_source(&master, &calls)));
    let requests = vec![mint_claim_bundle(served), mint_claim_bundle(unserved)];
    let canonical: Vec<Vec<u8>> = requests
        .iter()
        .map(|bundle| crate::consensus_wire::app_bundle_to_canonical_bytes(bundle).unwrap())
        .collect();
    let held = materialize(&node, requests.clone()).await;
    assert!(
        held.as_ref()
            .is_err_and(|error| error.is_execution_unavailable()
                && error.to_string().contains(CITED_FRAMES_UNFETCHED)),
        "a frame citing a GLOBAL frame no source serves must wait before executing: {held:?}"
    );
    assert!(
        !canonical.iter().any(|bundle| bundle_executed(bundle)),
        "no bundle of a frame waiting for a cited frame may execute"
    );
    let exec = node.engine.execution_engine.as_ref().unwrap();
    assert!(!exec.crdt().has_staged_mutations());
    assert_eq!(node.engine.load_materialized_cursor().unwrap(), 0);
    assert!(
        node.anchors.get_global_clock_frame(served).is_ok(),
        "the cited frame the master serves is fetched and kept"
    );
    master.seed_frame(global_frame(unserved));
    let finished = materialize(&node, requests).await;
    assert!(
        matches!(finished, Ok((0, 2))),
        "once every cited frame is held the frame executes whole: {finished:?}"
    );
    assert!(canonical.iter().all(|bundle| bundle_executed(bundle)));
    assert_eq!(node.engine.load_materialized_cursor().unwrap(), 1);
}

/// Settlement claims and coin and escrow deliveries cite GLOBAL frames as
/// mint claims do: a worker lacking the cited frame fetches it from its
/// master before executing the frame, which then finishes as on a holder.
#[tokio::test]
async fn settlement_claim_and_delivery_citations_are_fetched_before_execution() {
    use quil_execution::token_intrinsic::delivery::Delivered;
    let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).network;
    let quil = quil_execution::domains::QUIL_TOKEN;
    // A settlement claim funds a custom token's bundle on that token's shard;
    // the token base domain routes to the token engine like a deployed token.
    let paid = quil_execution::token_intrinsic::constants::token_base_domain();
    let operations = [
        ("settlement claim", paid, settlement_claim(paid, CITED + 10)),
        (
            "coin delivery",
            quil,
            delivery(CITED + 11, Delivered::Coin(junk_output(&network))),
        ),
        (
            "escrow delivery",
            quil,
            delivery(CITED + 12, Delivered::Escrow(vec![13; 64])),
        ),
    ];
    for (offset, (name, application, operation)) in (10..).zip(operations) {
        let cited = CITED + offset;
        let calls = Arc::new(AtomicUsize::new(0));
        let master = holding(&[cited]);
        let node = worker_at(
            application,
            holding(&[ANCHOR]),
            Some(master_source(&master, &calls)),
        );
        let finished = materialize(&node, vec![token_bundle(operation)]).await;
        // The frame finishes; how the junk operation counts is beside the point.
        assert!(
            matches!(finished, Ok((processed, skipped)) if processed + skipped == 1),
            "a frame whose {name} cites a frame the master serves must finish: {finished:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the worker must ask its master for the frame a {name} cites"
        );
        assert!(
            node.anchors.get_global_clock_frame(cited).is_ok(),
            "the frame a {name} cites must be stored"
        );
        assert_eq!(node.engine.load_materialized_cursor().unwrap(), 1);
    }
}

/// The wait for cited GLOBAL frames logs its start, then once per repeat
/// interval with the time waited, then its end, whatever the retry rate.
#[test]
fn a_cited_frame_wait_logs_its_start_bounded_repeats_and_end() {
    let mut waits = CitedFrameWaits::default();
    let start = std::time::Instant::now();
    let at = |secs: u64| start + Duration::from_secs(secs);
    let filter = [7u8; 32];
    assert_eq!(waits.missing(&filter, 5, at(0)), CitedWaitNote::Start);
    // Canonical retries come every 10 s; they stay quiet until the interval.
    for secs in (10..600).step_by(10) {
        assert_eq!(
            waits.missing(&filter, 5, at(secs)),
            CitedWaitNote::Quiet,
            "check at {secs} s"
        );
    }
    assert_eq!(
        waits.missing(&filter, 5, at(600)),
        CitedWaitNote::Repeat {
            waited: Duration::from_secs(600),
            checks: 61
        }
    );
    assert_eq!(waits.missing(&filter, 5, at(610)), CitedWaitNote::Quiet);
    // Another frame, or another shard's, waits on its own.
    assert_eq!(waits.missing(&filter, 6, at(610)), CitedWaitNote::Start);
    assert_eq!(waits.missing(&[8u8; 32], 5, at(610)), CitedWaitNote::Start);
    assert!(waits.known(&filter, 5));
    assert_eq!(
        waits.over(&filter, 5, at(700)),
        Some((Duration::from_secs(700), 62))
    );
    assert!(!waits.known(&filter, 5));
    assert_eq!(waits.over(&filter, 5, at(700)), None, "a wait ends once");
    // A wait no check found for a repeat interval is forgotten: the next
    // check starts a new one.
    assert_eq!(waits.missing(&filter, 6, at(1_210)), CitedWaitNote::Start);
}
