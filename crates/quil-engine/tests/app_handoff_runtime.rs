//! Production app engines under globally authorized committee sessions: real
//! Falcon/Simplex hosts, RocksDB shard state and authorization records. The
//! global chain is driven by the test (it commits authorization frames itself);
//! app frames are empty and use test inclusion/execution dependencies.
//!
//! One test per binary: the committee-handoff policy is process-global.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{AppShardHarness, TestProver};
use prost::Message as _;
use quil_engine::test_support::TestProverRegistry;
use quil_execution::{
    global_intrinsic::handoff::{
        self, frames, schedule, CertificateSubmission, CommittedView, DesiredCommittee, Status,
        TYPE_COMMITTEE_HANDOFF,
    },
    hypergraph_state::HypergraphState,
};
use quil_types::{consensus::ProverRegistry, proto::global::AppShardFrame};

fn commit(state: &HypergraphState, number: u64) {
    state.commit().unwrap();
    state.abort();
    state
        .crdt()
        .commit_with_global_cursor(number, &quil_store::encoding::global_materialized_cursor_key())
        .unwrap();
}

fn members(provers: &[TestProver]) -> Vec<Vec<u8>> {
    let mut members: Vec<_> = provers.iter().map(|p| p.bls_pubkey.clone()).collect();
    members.sort();
    members
}

fn finalized(harness: &AppShardHarness) -> Vec<AppShardFrame> {
    let mut frames: Vec<AppShardFrame> = harness
        .workers
        .iter()
        .flat_map(|w| w.full_frames.lock().clone())
        .filter_map(|bytes| AppShardFrame::decode(bytes.as_slice()).ok())
        .collect();
    frames.sort_by_key(|f| f.header.as_ref().map_or(0, |h| h.frame_number));
    frames.dedup_by_key(|f| f.header.as_ref().map_or(0, |h| h.frame_number));
    frames
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

/// Every finalized frame must verify against the session its certificate names.
fn verify(view: &CommittedView, frame: &AppShardFrame) -> quil_cw_consensus::handoff::Session {
    let header = frame.header.as_ref().unwrap();
    let signature = header.public_key_signature_bls48581.as_ref().expect("finalized frames carry a certificate");
    let certificate = quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature).unwrap();
    frames::verify(
        view,
        &frames::FrameClaim {
            filter: &header.address,
            frame: header.frame_number,
            view: header.rank,
            parent: &header.parent_selector,
            digest: quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap(),
        },
        certificate,
    )
    .unwrap()
    .expect("a managed application never falls back to the legacy verifier")
    .session
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn session_seals_on_a_scheduled_change_and_resumes_under_its_successor() {
    common::init_tracing();
    quil_types::consensus::set_committee_handoff_policy(Some(
        quil_types::consensus::CommitteeHandoffPolicy { activation_frame: 0, chain_id: [0x51; 32], legacy_history: quil_types::consensus::LegacyHistory::Migrate },
    ));
    let filter = vec![0x55u8; 32];
    let provers: Vec<TestProver> = (0..4).map(|_| TestProver::generate()).collect();
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
    let first = quil_cw_consensus::handoff::Session {
        chain_id: [0x51; 32],
        filter: filter.clone(),
        generation: 1,
        genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
        base_frame: 0,
        authorization: [0; 32],
        members: members(&provers),
    };
    handoff::initialize(&state, 2, &first).unwrap();
    commit(&state, 2);

    let harness = AppShardHarness::build_cw_sessions(provers.clone(), registry, global.clone());
    let early = until(Duration::from_secs(90), || {
        let frames = finalized(&harness);
        (frames.len() >= 3).then_some(frames)
    })
    .await
    .expect("the authorized session finalizes data frames");
    {
        let view = CommittedView::capture(&global).unwrap();
        for frame in &early {
            assert_eq!(verify(&view, frame), first);
        }
        assert_eq!(early[0].header.as_ref().unwrap().parent_selector, first.genesis);
    }

    // The global scheduler replaces the committee with three of its members.
    let successors = members(&provers[..3]);
    let request = handoff::schedule(
        &state,
        3,
        vec![filter.clone()],
        vec![DesiredCommittee { filter: filter.clone(), members: successors.clone() }],
    )
    .unwrap();
    commit(&state, 3);

    // Any member that observes the terminal finalization submits it through the
    // same prover-message path as coverage headers.
    let prefix = TYPE_COMMITTEE_HANDOFF.to_be_bytes();
    let submission = until(Duration::from_secs(120), || {
        harness.workers.iter().find_map(|w| {
            w.coverage_published.lock().iter().find(|b| b.starts_with(&prefix)).cloned()
        })
    })
    .await
    .expect("the closing committee finalizes and submits its terminal seal");
    let submission = CertificateSubmission::from_canonical_bytes(&submission).unwrap();
    assert_eq!(submission.seal.request, request.id().unwrap());
    let sealed_at = submission.seal.checkpoint.frame;
    assert!(sealed_at >= 3, "the seal follows the data frames it checkpoints");
    // GLOBAL executed the source's data frames through the sealed checkpoint.
    handoff::record_session_tip(&state, 4, &submission.seal.session, &submission.seal.checkpoint).unwrap();
    assert!(handoff::apply_submission(&state, 4, &submission).unwrap(), "a single source activates its successor");
    commit(&state, 4);
    assert!(matches!(handoff::status(&state, &first.id().unwrap()).unwrap(), Status::Closed(_)));
    let second = handoff::head(&state, &filter).unwrap().unwrap();
    assert_eq!((second.generation, second.base_frame, &second.members), (2, sealed_at, &successors));
    assert!(schedule::seal_submitted(&CommittedView::capture(&global).unwrap(), &first).unwrap());

    // The three authorized members restart in the successor's namespace and
    // extend its authorized genesis; the fourth has no session to run.
    let resumed = until(Duration::from_secs(120), || {
        let frames = finalized(&harness);
        let after: Vec<_> = frames.into_iter()
            .filter(|f| f.header.as_ref().unwrap().frame_number > sealed_at).collect();
        (after.len() >= 2).then_some(after)
    })
    .await
    .expect("the successor committee finalizes frames past the sealed checkpoint");
    let view = CommittedView::capture(&global).unwrap();
    for frame in finalized(&harness) {
        let number = frame.header.as_ref().unwrap().frame_number;
        let expected = if number > sealed_at { &second } else { &first };
        assert_eq!(&verify(&view, &frame), expected, "frame {number}");
    }
    let next = resumed[0].header.as_ref().unwrap();
    assert_eq!(next.frame_number, sealed_at + 1);
    assert_eq!(next.parent_selector, second.genesis, "the successor extends its authorized genesis");
    assert!(finalized(&harness).iter().all(|f| f.header.as_ref().unwrap().frame_number != 0));
    quil_types::consensus::set_committee_handoff_policy(None);
}
