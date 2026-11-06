//! Sequenced ingest vouches for exactly the headers execution can act on, and
//! every wait it imposes ends: a body that arrives, or an anchor this archive
//! was missing inside the frame's window. Built on the reproducers' rig.

use quil_engine::{global_finalization::FinalizationStep, message_collector::anchor_in_lockstep};
use quil_execution::hypergraph_state::HypergraphState;
use quil_types::{
    proto::global::{FrameHeader, GlobalFrame},
    store::ClockStore,
};

use super::{
    fh_r1_tests::{frame_carrying, single, Rig, StubFrameProver},
    vouched_shard_headers, VouchedHeaders,
};

/// A GLOBAL frame whose window is `[7, 19]`.
const FRAME: u64 = 20;

fn vouched(rig: &Rig, frame: &GlobalFrame) -> VouchedHeaders {
    vouched_shard_headers(
        frame,
        frame.header.as_ref().unwrap().frame_number,
        rig.clock.as_ref(),
        &HypergraphState::new(rig.crdt.clone()),
        &StubFrameProver,
        rig.registry.as_ref(),
    )
}

/// A copy with a rewritten field, in either order, never takes the genuine
/// header's place, so the empty-frame rebuild reads the header the committee
/// certified (the map keeps the last copy of a number).
#[test]
fn fh_fix_a_tampered_copy_never_replaces_the_genuine_header() {
    let rig = Rig::new();
    rig.hold(FRAME - 1);
    let genuine = rig.certified(1, FRAME - 1);
    let tampered = FrameHeader {
        timestamp: genuine.timestamp + 1,
        ..genuine.clone()
    };
    let renumbered = Rig::rewritten(&rig.certified(2, FRAME - 1), 1);
    for headers in [
        vec![genuine.clone(), tampered.clone(), renumbered.clone()],
        vec![renumbered, tampered, genuine.clone()],
    ] {
        let found = vouched(&rig, &frame_carrying(FRAME, headers));
        assert!(found.unheld_anchors.is_empty());
        let shard = found.shards.get(&rig.session.filter).unwrap();
        assert_eq!(shard.len(), 1, "FH FIX: only the genuine header counts");
        assert_eq!(shard.get(&1), Some(&genuine));
    }
    eprintln!("FH FIX: a tampered copy never replaces the genuine header");
}

/// Honest leaders are never refused: the hook vouches for every anchor they
/// pack, at both edges of the window, by the predicate they pack by, and waits
/// for its body. It vouches for no other, certified or not.
#[test]
fn fh_liveness_hook_vouches_exactly_the_anchors_an_honest_leader_packs() {
    for anchor in [6, 7, 19, 20, 21, 1_000_000] {
        let rig = Rig::new();
        rig.hold(anchor);
        let genuine = rig.certified(1, anchor);
        let input = frame_carrying(FRAME, vec![genuine.clone()]);
        if anchor_in_lockstep(anchor, FRAME) {
            assert!(
                matches!((rig.hook)(&input), Ok(false)),
                "FH LIVENESS: anchor {anchor} is in the window: the frame waits for the body"
            );
            assert_eq!(rig.height(), 0);
            rig.admit_body(&genuine);
            let ready = (rig.hook)(&input);
            assert!(
                matches!(ready, Ok(true)),
                "FH LIVENESS: anchor {anchor}: the body arrived and the wait must end: {ready:?}"
            );
            assert_eq!(rig.height(), 1, "materialized through the honest header");
        } else {
            rig.admit_body(&genuine);
            let ready = (rig.hook)(&input);
            assert!(
                matches!(ready, Ok(true)),
                "FH FIX: anchor {anchor} is outside the window: execution skips the header, so \
                 nothing waits for it: {ready:?}"
            );
            assert_eq!(
                rig.height(),
                0,
                "FH FIX: anchor {anchor} is outside the window: the header sequences nothing"
            );
        }
    }
    eprintln!("FH LIVENESS: the hook vouches for exactly what an honest leader packs");
}

/// An anchor inside the window that this archive lacks is a wait, as in
/// execution, which cannot judge the header either: nothing moves until the
/// record arrives, whatever the header claims, and then the header is judged.
/// Refused instead, an archive with a hole would split from those without.
#[test]
fn fh_liveness_hook_waits_for_an_in_window_anchor_it_lacks_and_recovers() {
    let anchor = FRAME - 5;
    let rig = Rig::new();
    let genuine = rig.certified(1, anchor);
    rig.admit_body(&genuine);
    let forged = Rig::rewritten(&rig.certified(2, anchor), 1 << 60);
    let input = frame_carrying(FRAME, vec![genuine, forged]);
    for _ in 0..3 {
        assert!(
            matches!((rig.hook)(&input), Ok(false)),
            "FH LIVENESS: the anchor is in the window and this archive lacks it: a wait"
        );
        assert_eq!(rig.height(), 0, "nothing moves while the anchor is missing");
    }
    let found = vouched(&rig, &input);
    assert_eq!(
        found.unheld_anchors.into_iter().collect::<Vec<_>>(),
        [anchor]
    );
    rig.hold(anchor);
    let ready = (rig.hook)(&input);
    assert!(
        matches!(ready, Ok(true)),
        "FH LIVENESS: the anchor arrived and the wait must end: {ready:?}"
    );
    assert_eq!(rig.height(), 1, "and the genuine header alone decided");
    eprintln!("FH LIVENESS: an in-window anchor gap waits and recovers");
}

/// The same wait on the whole path: finalization retries while the record is
/// missing, never handing a frame it cannot judge to the legacy materializer,
/// and publishes once the record is back.
#[test]
fn fh_liveness_finalization_recovers_when_an_in_window_anchor_returns() {
    let rig = Rig::new();
    let pipeline = rig.pipeline();
    let parent = rig.publish_through(&pipeline, 3);
    let genuine = rig.certified(1, 2);
    rig.admit_body(&genuine);
    let record = rig.clock.get_global_clock_frame(2).unwrap();
    rig.db
        .inner()
        .delete(quil_store::encoding::clock_global_frame_key(2))
        .unwrap();
    assert!(
        rig.clock.get_global_clock_frame_header(2).is_err(),
        "FH SETUP: the record must be gone"
    );
    assert!(pipeline.offer(rig.next_frame(&parent, vec![single(genuine)])));
    for _ in 0..8 {
        assert!(
            matches!(pipeline.step(4), FinalizationStep::Retry(_)),
            "FH LIVENESS: finalization waits for the anchor, past its atomic attempts"
        );
    }
    assert_eq!(rig.source.last_materialized_frame(), 3);
    assert_eq!(rig.height(), 0);
    let txn = rig.clock.new_transaction(false).unwrap();
    rig.clock
        .put_global_clock_frame(&record, txn.as_ref())
        .unwrap();
    txn.commit().unwrap();
    assert!(
        matches!(pipeline.step(4), FinalizationStep::Published { .. }),
        "FH LIVENESS: the record is back: GLOBAL frame 4 must publish"
    );
    assert_eq!(rig.source.last_materialized_frame(), 4);
    assert_eq!(rig.height(), 1);
    eprintln!("FH LIVENESS: finalization waits for an in-window anchor and recovers");
}
