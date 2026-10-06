//! The committee-handoff flag day (`LegacyHistory::Discard`, mainnet's
//! policy) with production app engines: a legacy registry committee certifies
//! frames; the policy activates; every member discards its legacy frame chain
//! but keeps the application state; GLOBAL authorizes the shard's first
//! session at frame 0, and its members certify frames from 1 over that state.
//!
//! One test per binary: the committee-handoff policy is process-global.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{AppShardHarness, TestProver};
use prost::Message as _;
use quil_engine::test_support::TestProverRegistry;
use quil_execution::{
    global_intrinsic::handoff::{self, frames, CommittedView},
    hypergraph_state::HypergraphState,
};
use quil_types::{
    consensus::{CommitteeHandoffPolicy, LegacyHistory, ProverRegistry},
    proto::global::AppShardFrame,
    store::ClockStore as _,
};

const APP: [u8; 32] = [0x55; 32];

fn commit(state: &HypergraphState, number: u64) {
    state.commit().unwrap();
    state.abort();
    state
        .crdt()
        .commit_with_global_cursor(number, &quil_store::encoding::global_materialized_cursor_key())
        .unwrap();
}

fn seed(crdt: &quil_hypergraph::HypergraphCrdt) {
    for d in 0u8..4 {
        crdt.add_vertex(&location(d), &value(d)).unwrap();
    }
    crdt.commit(0).unwrap();
}

fn location(d: u8) -> quil_hypergraph::Location {
    quil_hypergraph::Location { app_address: APP, data_address: [d; 32] }
}

fn value(d: u8) -> Vec<u8> {
    vec![d.wrapping_add(1); 256]
}

fn all_frames(harness: &AppShardHarness) -> Vec<AppShardFrame> {
    harness
        .workers
        .iter()
        .flat_map(|w| w.full_frames.lock().clone())
        .filter_map(|bytes| AppShardFrame::decode(bytes.as_slice()).ok())
        .collect()
}

fn number(frame: &AppShardFrame) -> u64 {
    frame.header.as_ref().unwrap().frame_number
}

fn certificate(frame: &AppShardFrame) -> Vec<u8> {
    let header = frame.header.as_ref().unwrap();
    let signature = header.public_key_signature_bls48581.as_ref().expect("finalized frames carry a certificate");
    quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature).unwrap().to_vec()
}

/// The session a frame's certificate is authorized by, if any.
fn session_of(view: &CommittedView, frame: &AppShardFrame) -> Option<quil_cw_consensus::handoff::Session> {
    let header = frame.header.as_ref().unwrap();
    let claim = frames::FrameClaim {
        filter: &header.address,
        frame: header.frame_number,
        view: header.rank,
        parent: &header.parent_selector,
        digest: quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap(),
    };
    frames::verify(view, &claim, &certificate(frame)).ok().flatten().map(|v| v.session)
}

async fn until<T>(timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(value) = probe() {
            return Some(value);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn legacy_history_is_discarded_and_the_first_session_certifies_from_frame_one() {
    common::init_tracing();
    quil_types::consensus::set_committee_handoff_policy(None);
    let filter = APP.to_vec();
    let provers: Vec<TestProver> = (0..4).map(|_| TestProver::generate()).collect();
    let mut committee: Vec<_> = provers.iter().map(|p| p.bls_pubkey.clone()).collect();
    committee.sort();
    let registry = Arc::new(TestProverRegistry::with_provers(
        provers.iter().map(|p| p.to_prover_info(1)).collect(),
    )) as Arc<dyn ProverRegistry>;

    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
        Arc::new(quil_hypergraph::testing::StubProver),
    ));
    global.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
    let state = HypergraphState::new(global.clone());
    commit(&state, 1);

    // 1. Legacy: the registry committee certifies frames.
    let harness = AppShardHarness::build_cw_sessions_seeded(provers.clone(), registry, global.clone(), seed);
    let legacy = until(Duration::from_secs(90), || {
        let frames = all_frames(&harness);
        (frames.iter().filter(|f| number(f) >= 3).count() > 0).then_some(frames)
    })
    .await
    .expect("the legacy committee certifies frames");
    let legacy_head = legacy.iter().map(number).max().unwrap();

    // 2. Activation: every member discards its legacy chain; none produces.
    quil_types::consensus::set_committee_handoff_policy(Some(CommitteeHandoffPolicy {
        activation_frame: 0,
        chain_id: [0x51; 32],
        legacy_history: LegacyHistory::Discard, membership_boundary_frame: u64::MAX, first_session_boundary_frame: u64::MAX
    }));
    let discarded = until(Duration::from_secs(60), || {
        harness.workers.iter().all(|w| {
            w.clock.as_ref().is_some_and(|clock| clock.app_frame_history_discarded().unwrap().is_some())
        }).then_some(())
    })
    .await;
    assert!(discarded.is_some(), "every member discards its legacy history at activation");
    for worker in &harness.workers {
        let clock = worker.clock.as_ref().unwrap();
        assert!(clock.get_latest_shard_clock_frame(&filter).is_err(), "no legacy frame remains");
        let cursor = worker.shard.as_ref().unwrap()
            .read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(&filter)).unwrap();
        assert_eq!(cursor, 0, "the materialized cursor restarts with the chain");
    }

    // 3. GLOBAL authorizes the first session at frame 0, over the state the
    // members kept.
    let first = quil_cw_consensus::handoff::Session {
        chain_id: [0x51; 32],
        filter: filter.clone(),
        generation: 1,
        genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
        base_frame: 0,
        authorization: [0; 32],
        members: committee.clone(),
    };
    handoff::initialize(&state, 2, &first).unwrap();
    commit(&state, 2);

    let sessions = until(Duration::from_secs(150), || {
        let view = CommittedView::capture(&global).unwrap();
        let mut certified: Vec<AppShardFrame> = all_frames(&harness)
            .into_iter()
            .filter(|f| session_of(&view, f).as_ref() == Some(&first))
            .collect();
        certified.sort_by_key(number);
        certified.dedup_by_key(|f| number(f));
        (certified.len() >= 3).then_some(certified)
    })
    .await
    .expect("the first session certifies frames from 1");
    assert_eq!(number(&sessions[0]), 1, "frames number from the session's base");
    assert_eq!(sessions[0].header.as_ref().unwrap().parent_selector, first.genesis.to_vec());
    for pair in sessions.windows(2) {
        assert_eq!(number(&pair[1]), number(&pair[0]) + 1);
        assert_eq!(
            pair[1].header.as_ref().unwrap().parent_selector,
            quil_crypto::poseidon::hash_bytes_to_32(&pair[0].header.as_ref().unwrap().output).unwrap().to_vec(),
        );
    }
    assert!(legacy_head >= 3);

    // The application state crossed the flag day unchanged.
    for worker in &harness.workers {
        let shard = worker.shard.as_ref().unwrap();
        for d in 0u8..4 {
            assert_eq!(shard.get_vertex_data(&location(d)), Some(value(d)));
        }
        let clock = worker.clock.as_ref().unwrap();
        let head = clock.get_latest_shard_clock_frame(&filter).unwrap();
        let view = CommittedView::capture(&global).unwrap();
        assert_eq!(session_of(&view, &head).as_ref(), Some(&first), "the stored chain is the session's");
    }
    quil_types::consensus::set_committee_handoff_policy(None);
}
