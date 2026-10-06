//! The in-place generation-zero migration with
//! production app engines: real Falcon/Simplex hosts, RocksDB shard state and
//! GLOBAL records. The shard first runs its legacy registry committee with no
//! policy, as mainnet does today. Then the policy activates, GLOBAL records the
//! shard's legacy tip and registers it as generation 0, the legacy committee
//! drains and seals, and generation 1 produces from the sealed checkpoint over
//! the same application state. The GLOBAL chain is driven by the test.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::common::{self, AppShardHarness, TestProver};
use prost::Message as _;
use quil_cw_consensus::handoff::Checkpoint;
use quil_engine::app_handoff::SessionChoice;
use quil_engine::test_support::TestProverRegistry;
use quil_execution::{
    global_intrinsic::handoff::{
        self, frames, legacy, schedule, CertificateSubmission, CommittedView, Status, TYPE_COMMITTEE_HANDOFF,
    },
    hypergraph_state::HypergraphState,
    prover_registry::CommittedProverScan,
};
use quil_types::{
    consensus::{CommitteeHandoffPolicy, ProverAllocationInfo, ProverRegistry, ProverStatus},
    proto::global::AppShardFrame,
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

fn members(provers: &[TestProver]) -> Vec<Vec<u8>> {
    let mut members: Vec<_> = provers.iter().map(|p| p.bls_pubkey.clone()).collect();
    members.sort();
    members
}

/// The GLOBAL registry's committed view of the provers, as the maintenance
/// pass scans it.
fn scan(filter: &[u8], provers: &[TestProver]) -> CommittedProverScan {
    let mut pubkeys = std::collections::HashMap::new();
    let mut allocations = Vec::new();
    for prover in provers {
        pubkeys.insert(prover.address.clone(), prover.bls_pubkey.clone());
        allocations.push((prover.address.clone(), ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: filter.to_vec(),
            rejection_filter: vec![],
            join_frame_number: 0, leave_frame_number: 0, pause_frame_number: 0,
            resume_frame_number: 0, kick_frame_number: 0, join_confirm_frame_number: 0,
            join_reject_frame_number: 0, leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0, last_active_frame_number: 0,
            epoch: u64::MAX, ring: 0, vertex_address: vec![],
        }));
    }
    CommittedProverScan::from_parts(pubkeys, allocations)
}

/// Wallet-visible application state: vertices every member holds before the
/// migration, as a coin or account would be.
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

fn number(frame: &AppShardFrame) -> u64 {
    frame.header.as_ref().unwrap().frame_number
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

fn certificate(frame: &AppShardFrame) -> &[u8] {
    let header = frame.header.as_ref().unwrap();
    let signature = header.public_key_signature_bls48581.as_ref().expect("finalized frames carry a certificate");
    quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature).unwrap()
}

fn claim(frame: &AppShardFrame) -> frames::FrameClaim<'_> {
    let header = frame.header.as_ref().unwrap();
    frames::FrameClaim {
        filter: &header.address,
        frame: header.frame_number,
        view: header.rank,
        parent: &header.parent_selector,
        digest: quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap(),
    }
}

/// The session a frame's certificate is authorized by; `None` for legacy
/// history, which must then verify as a legacy certificate: epoch 0, the
/// `appshard‖filter` namespace and the registry committee.
fn verify(view: &CommittedView, frame: &AppShardFrame, registry: &[Vec<u8>]) -> Option<quil_cw_consensus::handoff::Session> {
    let authorized = frames::verify(view, &claim(frame), certificate(frame)).unwrap().map(|v| v.session);
    if authorized.is_none() {
        let header = frame.header.as_ref().unwrap();
        let mut namespace = b"appshard".to_vec();
        namespace.extend_from_slice(&header.address);
        let verified = quil_cw_consensus::app_cert::verify_finalization_details(
            certificate(frame), registry, &namespace, claim(frame).digest,
        )
        .expect("legacy history verifies under the legacy committee");
        assert_eq!(verified.finalization.proposal.round.epoch().get(), 0);
        assert_eq!(verified.finalization.proposal.round.view().get(), header.rank);
    }
    authorized
}

/// The tip GLOBAL records when it executes a legacy-verified header
/// (`GlobalIntrinsic::invoke_frame_header`).
fn tip_of(frame: &AppShardFrame) -> legacy::LegacyTip {
    let header = frame.header.as_ref().unwrap();
    let state_roots: Vec<[u8; 32]> =
        header.state_roots.iter().map(|root| <[u8; 32]>::try_from(root.as_slice()).unwrap()).collect();
    legacy::LegacyTip {
        checkpoint: Checkpoint {
            frame: header.frame_number,
            view: header.rank,
            digest: claim(frame).digest,
            state_roots: state_roots.try_into().expect("a legacy header carries four state roots"),
            history_root: [0; 32],
        },
        anchor: header.global_frame_number,
    }
}


/// Every worker's durably materialized cursor.
fn cursors(harness: &AppShardHarness) -> Vec<u64> {
    let key = quil_store::encoding::consensus_materialized_cursor_key(&APP);
    harness.workers.iter().map(|w| w.shard.as_ref().unwrap().read_frame_cursor(&key).unwrap()).collect()
}

/// Where GLOBAL's recorded tip stands relative to the members' heads when
/// generation 0 is registered.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tip {
    /// Every member's head: the members stop producing (a coverage halt) until
    /// generation 0 is registered, so generation 0's own hosts extend the
    /// tip, drain and seal.
    AtEveryHead,
    /// Behind the heads, as headers lag frames in production: the legacy
    /// instance keeps finalizing past the tip until each member switches, and
    /// those frames become generation-0 frames.
    Lagging,
}

pub async fn migrate_in_place(tip_kind: Tip) {
    common::init_tracing();
    // Mainnet today: no committee-handoff policy.
    quil_types::consensus::set_committee_handoff_policy(None);
    let policy = CommitteeHandoffPolicy { activation_frame: 0, chain_id: [0x51; 32], legacy_history: quil_types::consensus::LegacyHistory::Migrate };
    let filter = APP.to_vec();
    let provers: Vec<TestProver> = (0..4).map(|_| TestProver::generate()).collect();
    let committee = members(&provers);
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

    // 1. Legacy: the registry committee certifies frames in epoch 0.
    let harness = AppShardHarness::build_cw_sessions_seeded(provers.clone(), registry, global.clone(), seed);
    let legacy_frames = until(Duration::from_secs(90), || {
        let frames = finalized(&harness);
        (frames.len() >= 3).then_some(frames)
    })
    .await
    .expect("the legacy committee finalizes frames");
    {
        let view = CommittedView::capture(&global).unwrap();
        for frame in &legacy_frames {
            assert!(verify(&view, frame, &committee).is_none(), "an unmanaged shard is legacy");
        }
    }

    // 2. Activation. GLOBAL executes the shard's legacy headers in the lead
    // window and records its tip; the shard is pending.
    quil_types::consensus::set_committee_handoff_policy(Some(policy));
    let first_tip = tip_of(legacy_frames.last().unwrap());
    legacy::record_tip(&state, 2, &filter, &first_tip).unwrap();
    commit(&state, 2);
    {
        let view = CommittedView::capture(&global).unwrap();
        assert!(legacy::pending(&view, &filter).unwrap());
        // Every (re)start of a pending shard's consensus resolves to the
        // legacy instance, even after activation; a shard without legacy
        // history waits for its first authorized session instead.
        assert!(matches!(quil_engine::app_handoff::resolve(&global, &filter, 2).unwrap(), SessionChoice::Legacy));
        assert!(matches!(quil_engine::app_handoff::resolve(&global, &[0x66; 32], 2).unwrap(), SessionChoice::Pending(_)));
    }
    // It keeps producing legacy frames, still verified as legacy history.
    let after_activation = until(Duration::from_secs(90), || {
        let frames = finalized(&harness);
        frames.iter().any(|f| number(f) > first_tip.checkpoint.frame + 1).then_some(frames)
    })
    .await
    .expect("a pending legacy shard keeps producing after activation");
    {
        let view = CommittedView::capture(&global).unwrap();
        for frame in &after_activation {
            assert!(verify(&view, frame, &committee).is_none(), "frame {} is legacy history", number(frame));
        }
    }

    // 3. Registration: the tip has advanced; the maintenance pass registers
    // generation 0 at it and schedules generation 1 with the same members.
    let tip = match tip_kind {
        Tip::Lagging => tip_of(after_activation.last().unwrap()),
        Tip::AtEveryHead => {
            for worker in &harness.workers {
                worker.handle.set_halted(true);
            }
            let mut last = (Vec::new(), Instant::now());
            let head = until(Duration::from_secs(60), || {
                let now = cursors(&harness);
                if now != last.0 {
                    last = (now, Instant::now());
                    return None;
                }
                (now.iter().all(|c| *c == now[0]) && last.1.elapsed() > Duration::from_secs(3)).then_some(now[0])
            })
            .await
            .expect("a halted committee stops at one head");
            let frame = finalized(&harness).into_iter().find(|f| number(f) == head).unwrap();
            tip_of(&frame)
        }
    };
    legacy::record_tip(&state, 3, &filter, &tip).unwrap();
    commit(&state, 3);
    assert_eq!(legacy::migrate(&state, 4, &policy, &[filter.clone()], &scan(&filter, &provers)).unwrap(), 1);
    commit(&state, 4);
    let zero = handoff::head(&state, &filter).unwrap().expect("generation 0 registered");
    assert_eq!((zero.generation, zero.base_frame, zero.genesis), (0, tip.checkpoint.frame, tip.checkpoint.digest));
    assert_eq!(zero.members, committee);
    let request = {
        let view = CommittedView::capture(&global).unwrap();
        schedule::closing_request(&view, &zero).unwrap().expect("generation 0 is scheduled into its successor")
    };

    // 4. Each member restarts its legacy instance under generation 0,
    // drains and seals; any member submits the terminal certificate.
    let prefix = TYPE_COMMITTEE_HANDOFF.to_be_bytes();
    let submitted = || {
        harness.workers.iter().find_map(|w| {
            w.coverage_published.lock().iter().find(|b| b.starts_with(&prefix)).cloned()
        })
    };
    if tip_kind == Tip::AtEveryHead {
        // Every member's maintenance tick (10 s) restarts it under generation 0
        // at the tip. Nothing can be sealed there: a generation-0 seal must
        // checkpoint a frame its own committee finalized after the tip.
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert!(submitted().is_none(), "no generation-0 seal of the registered tip itself");
        assert_eq!(cursors(&harness), vec![zero.base_frame; 4]);
        for worker in &harness.workers {
            worker.handle.set_halted(false);
        }
    }
    let submission = until(Duration::from_secs(150), submitted)
        .await
        .expect("the legacy committee seals generation 0");
    let submission = CertificateSubmission::from_canonical_bytes(&submission).unwrap();
    assert_eq!(submission.seal.session, zero.id().unwrap());
    assert_eq!(submission.seal.request, request);
    let sealed = submission.seal.checkpoint.clone();
    assert!(sealed.frame > zero.base_frame, "a generation-0 seal follows its registered tip");

    // 5. GLOBAL executed the shard through the sealed checkpoint and
    // accepts the seal; generation 1 starts there.
    handoff::record_session_tip(&state, 5, &submission.seal.session, &sealed).unwrap();
    assert!(handoff::apply_submission(&state, 5, &submission).unwrap());
    commit(&state, 5);
    assert!(matches!(handoff::status(&state, &zero.id().unwrap()).unwrap(), Status::Closed(_)));
    let one = handoff::head(&state, &filter).unwrap().unwrap();
    assert_eq!((one.generation, one.base_frame, &one.members), (1, sealed.frame, &committee));

    let resumed = until(Duration::from_secs(150), || {
        let after: Vec<_> = finalized(&harness).into_iter().filter(|f| number(f) > sealed.frame).collect();
        (after.len() >= 2).then_some(after)
    })
    .await
    .expect("generation 1 finalizes frames past the sealed checkpoint");
    assert_eq!(number(&resumed[0]), sealed.frame + 1);
    assert_eq!(resumed[0].header.as_ref().unwrap().parent_selector, one.genesis);

    // Every frame verifies against exactly one authority: the legacy committee
    // through the tip, generation 0 up to its seal, generation 1 after.
    let view = CommittedView::capture(&global).unwrap();
    let all = finalized(&harness);
    for frame in &all {
        let n = number(frame);
        let expected = if n <= zero.base_frame {
            None
        } else if n <= sealed.frame {
            Some(&zero)
        } else {
            Some(&one)
        };
        assert_eq!(verify(&view, frame, &committee).as_ref(), expected, "frame {n}");
    }
    let generation_zero_frames = all.iter().filter(|f| (zero.base_frame + 1..=sealed.frame).contains(&number(f))).count();
    assert!(generation_zero_frames > 0);
    if tip_kind == Tip::AtEveryHead {
        // Generation 0's own hosts extended the tip before sealing.
        let first = all.iter().find(|f| number(f) == zero.base_frame + 1).unwrap();
        assert_eq!(first.header.as_ref().unwrap().parent_selector, tip.checkpoint.digest.to_vec());
    }

    // The application state crossed both boundaries unchanged: generation 1
    // started from the sealed roots, and every member still serves the seeded
    // state from its committed shard.
    for worker in &harness.workers {
        let shard = worker.shard.as_ref().unwrap();
        for d in 0u8..4 {
            assert_eq!(shard.get_vertex_data(&location(d)), Some(value(d)));
        }
        assert_eq!(shard.capture_committed_shard(&filter).unwrap().roots, sealed.state_roots);
    }
    quil_types::consensus::set_committee_handoff_policy(None);
}
