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
    body_availability_holding,
    fh_r1_tests::{frame_carrying, single, Rig, StubFrameProver},
    live_header_judge, shard_body_availability, shard_body_fetch, vouched_shard_headers,
    HeaderVouch, VoteVerdicts, VouchedHeaders,
};
use quil_engine::leader_provider::{ShardBodyAsk, ShardBodyNeed};

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

/// A GLOBAL voter asks for the bodies of exactly the shard headers GLOBAL
/// execution would vouch for. A refused header (its frame number rewritten,
/// or certified by keys its session does not name) is never asked for:
/// asking publishes the shard it names, so the ingest would track any shard
/// a leader writes. A header anchored to a GLOBAL frame this archive lacks is
/// not judged yet, never refused for good: it is asked for once the anchor
/// arrives. The ask never waits for a held ingest. A verdict is remembered,
/// so asking again about a judged header verifies nothing again.
#[test]
fn a_voter_asks_only_for_the_bodies_of_headers_execution_vouches_for() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let rig = Rig::new();
    let judged = std::sync::Arc::new(AtomicUsize::new(0));
    let fetch = {
        let judge = live_header_judge(
            rig.crdt.clone(),
            std::sync::Arc::new(StubFrameProver),
            rig.registry.clone(),
            rig.clock.clone(),
        );
        let judged = judged.clone();
        shard_body_fetch(rig.ingest.clone(), move |header, frame_number| {
            judged.fetch_add(1, Ordering::SeqCst);
            judge(header, frame_number)
        })
    };
    let ingest = rig.ingest.get().unwrap();
    let held = quil_engine::archive_ingest::lock_ingest(ingest).held_bodies();
    let filter = rig.session.filter.clone();
    assert_eq!(held.cursor(&filter), None, "setup: no shard published yet");

    let refused_anchor = FRAME - 5;
    rig.hold(refused_anchor);
    let renumbered = Rig::rewritten(&rig.certified(2, refused_anchor), 1 << 40);
    rig.check_forged_setup(&renumbered, FRAME);
    let foreign = Rig::new().certified(1, refused_anchor);
    let set_executed = |frame: u64| {
        rig.crdt
            .commit_with_global_cursor(
                frame,
                &quil_store::encoding::global_materialized_cursor_key(),
            )
            .unwrap();
    };
    set_executed(FRAME - 1);
    let asks: Vec<(ShardBodyAsk, ShardBodyAsk)> = [&renumbered, &foreign]
        .into_iter()
        .map(|header| (fetch(header, FRAME), fetch(header, FRAME)))
        .collect();
    assert!(
        asks.iter()
            .all(|(first, _)| *first == ShardBodyAsk::Refused),
        "vote_fetch_unvouched: the voter says it refused the header: {asks:?}"
    );
    assert_eq!(
        judged.load(Ordering::SeqCst),
        2,
        "vote_verdict_uncached: a second ask about a refused header is answered from the cache"
    );
    assert!(
        asks.iter()
            .all(|(_, again)| *again == ShardBodyAsk::RefusedBefore),
        "vote_refused_counted: a remembered refusal says so, and costs no ask: {asks:?}"
    );
    {
        let off_parent = shard_body_fetch(
            rig.ingest.clone(),
            live_header_judge(
                rig.crdt.clone(),
                std::sync::Arc::new(StubFrameProver),
                rig.registry.clone(),
                rig.clock.clone(),
            ),
        );
        set_executed(FRAME - 2);
        assert_eq!(
            off_parent(&renumbered, FRAME),
            ShardBodyAsk::Unavailable,
            "vote_refusal_off_parent: a refusal against another state than the proposal's \
             parent's is not judged yet, so it holds the vote"
        );
        set_executed(FRAME - 1);
    }
    assert_eq!(
        held.cursor(&filter),
        None,
        "vote_fetch_unvouched: a header execution refuses must not be asked for"
    );

    let anchor = FRAME - 6;
    let genuine = rig.certified(1, anchor);
    assert_eq!(
        fetch(&genuine, FRAME),
        ShardBodyAsk::UnheldAnchor { anchor },
        "vote_fetch_unjudged: a header whose anchor is missing is not judged yet"
    );
    assert_eq!(
        held.cursor(&filter),
        None,
        "an unjudged header (its anchor missing) is not asked for yet"
    );
    rig.hold(anchor);
    let guard = quil_engine::archive_ingest::lock_ingest(ingest);
    assert_eq!(
        fetch(&genuine, FRAME),
        ShardBodyAsk::IngestUnavailable,
        "vote_fetch_unjudged: the held ingest is named, not a refusal"
    );
    drop(guard);
    assert_eq!(
        held.cursor(&filter),
        None,
        "the ingest was held: the voter skipped the ask instead of waiting"
    );
    let before = judged.load(Ordering::SeqCst);
    assert_eq!(fetch(&genuine, FRAME), ShardBodyAsk::Asked);
    assert_eq!(
        judged.load(Ordering::SeqCst),
        before,
        "vote_verdict_uncached: the header vouched for on the last ask is not verified again"
    );
    assert_eq!(
        held.cursor(&filter),
        Some(0),
        "vote_fetch_unjudged: once its anchor arrived the header is judged again and its \
         bodies asked for"
    );
    eprintln!("VOTE FETCH: only headers execution vouches for are asked for");
}

/// A GLOBAL voter's body check records nothing for the ingest: a
/// proposal's headers are not verified when it checks them, so a forged
/// header naming any shard must not reach the wanted list, whose retry pass
/// would publish that shard and make the ingest take its frames. The
/// leader's check of the same need does record it, as its headers were
/// verified: the observable works.
#[test]
fn a_voters_body_availability_check_wants_no_shard() {
    let rig = Rig::new();
    let available = shard_body_availability(rig.ingest.clone(), 0);
    let ingest = rig.ingest.get().unwrap();
    let held = quil_engine::archive_ingest::lock_ingest(ingest).held_bodies();
    let forged = vec![0xab; 32];
    let need = |vote| ShardBodyNeed {
        address: forged.clone(),
        frame_number: 5,
        empty: false,
        anchor: FRAME - 6,
        vote,
        ..Default::default()
    };

    assert_eq!(available(&[need(true)]), vec![None]);
    quil_engine::archive_ingest::lock_ingest(ingest).look_into_wanted();
    assert_eq!(
        held.cursor(&forged),
        None,
        "vote_avail_records: a voter's check must not want the shard a proposal's header names"
    );

    assert_eq!(available(&[need(false)]), vec![None]);
    quil_engine::archive_ingest::lock_ingest(ingest).look_into_wanted();
    assert_eq!(
        held.cursor(&forged),
        Some(0),
        "setup: a leader's check wants the shard, and the retry pass publishes it"
    );
    eprintln!("VOTE AVAILABILITY: a voter's body check wants no shard");
}

/// A GLOBAL voter remembers its last [`VoteVerdicts::KEPT`] definite
/// verdicts, oldest out first, so a proposal crammed with headers cannot
/// grow it without a bound, and a recheck of a remembered header verifies
/// nothing again.
#[test]
fn a_voter_remembers_its_last_verdicts_only() {
    use std::cell::Cell;
    let verdicts = VoteVerdicts::default();
    let now = std::time::Instant::now();
    let judged = Cell::new(0);
    let ask = |n: u64| {
        verdicts.vouched(([0; 32], n), now, |_| {
            judged.set(judged.get() + 1);
            HeaderVouch::Vouched
        })
    };
    let kept = VoteVerdicts::KEPT as u64;
    for n in 0..kept {
        assert_eq!(ask(n), Ok(true));
    }
    assert_eq!(judged.get(), VoteVerdicts::KEPT);
    assert_eq!(ask(0), Ok(true));
    assert_eq!(
        judged.get(),
        VoteVerdicts::KEPT,
        "vote_verdict_uncached: a remembered header is not judged again"
    );
    assert_eq!(ask(kept), Ok(true));
    assert_eq!(ask(1), Ok(true));
    assert_eq!(
        judged.get(),
        VoteVerdicts::KEPT + 1,
        "only the oldest verdict made room for the newest"
    );
    assert_eq!(ask(0), Ok(true));
    assert_eq!(
        judged.get(),
        VoteVerdicts::KEPT + 2,
        "vote_verdicts_unbounded: past {} verdicts the oldest is forgotten and judged again",
        VoteVerdicts::KEPT
    );
}

/// A header whose certificate could not be checked yet is answered as such
/// without being judged again for [`VoteVerdicts::UNJUDGED_RETRY`], then
/// judged again; one whose anchor this archive lacks is judged on every
/// check, as its clock lookup is cheap and the anchor may arrive at any
/// time. Only the first judgment of a header is told it is the first, so
/// its line is logged once.
#[test]
fn a_voter_judges_an_unchecked_header_again_after_the_retry() {
    use quil_engine::leader_provider::ShardBodyAsk;
    use std::cell::{Cell, RefCell};
    use std::time::Duration;
    let verdicts = VoteVerdicts::default();
    let start = std::time::Instant::now();
    let retry = VoteVerdicts::UNJUDGED_RETRY;
    let firsts = RefCell::new(Vec::new());
    let answer = Cell::new(Some(HeaderVouch::Unavailable("registry".into())));
    let ask = |key: u64, at: std::time::Duration| {
        verdicts.vouched(([1; 32], key), start + at, |first| {
            firsts.borrow_mut().push(first);
            answer
                .take()
                .unwrap_or_else(|| HeaderVouch::Unavailable("still".into()))
        })
    };

    assert_eq!(ask(1, Duration::ZERO), Err(ShardBodyAsk::Unavailable));
    assert_eq!(
        ask(1, retry - Duration::from_millis(1)),
        Err(ShardBodyAsk::Unavailable),
        "vote_unjudged_eager: not judged again before the retry"
    );
    assert_eq!(
        *firsts.borrow(),
        vec![true],
        "vote_unjudged_eager: judged once before the retry"
    );
    answer.set(Some(HeaderVouch::Vouched));
    assert_eq!(
        ask(1, retry),
        Ok(true),
        "vote_unjudged_stuck: judged again once the retry passed"
    );
    assert_eq!(*firsts.borrow(), vec![true, false]);
    assert_eq!(ask(1, retry * 10), Ok(true), "then remembered");

    for at in [Duration::ZERO, Duration::from_millis(1)] {
        answer.set(Some(HeaderVouch::UnheldAnchor(7)));
        assert_eq!(
            ask(2, at),
            Err(ShardBodyAsk::UnheldAnchor { anchor: 7 }),
            "an unheld anchor is judged on every check"
        );
    }
    assert_eq!(*firsts.borrow(), vec![true, false, true, true]);
}

/// A devnet holding shard headers back with
/// `QUIL_DEVNET_HOLD_SHARD_HEADERS_FILE` holds them back from this archive's
/// proposals only: a voter's check is answered as without the file. Held
/// there too, an archive holding headers declined every proposal carrying
/// one, so a devnet holding on some archives stalled GLOBAL.
#[test]
fn a_devnet_hold_keeps_headers_from_proposals_not_from_votes() {
    let rig = Rig::new();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("hold");
    let available = body_availability_holding(rig.ingest.clone(), Some(file.clone()), None);
    let need = held_next_frame(&rig);

    std::fs::write(&file, b"").unwrap();
    assert_eq!(
        available(&[need(false)]),
        vec![None],
        "the hold keeps the header from this archive's proposals"
    );
    assert_eq!(
        available(&[need(true)]),
        vec![Some(1)],
        "vote_hold_answers_vote: the hold must not answer a voter's check"
    );
    std::fs::remove_file(&file).unwrap();
    assert_eq!(available(&[need(false)]), vec![Some(1)], "released");
}

/// A devnet making voters lack bodies with
/// `QUIL_DEVNET_HOLD_VOTE_BODIES_FILE` answers this archive's voter that it
/// holds no shard body, and leaves its proposals alone: devnets check how
/// GLOBAL fares when some voters lack the bodies a proposal's headers need.
#[test]
fn a_devnet_vote_hold_answers_votes_not_proposals() {
    let rig = Rig::new();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("hold-votes");
    let available = body_availability_holding(rig.ingest.clone(), None, Some(file.clone()));
    let need = held_next_frame(&rig);

    std::fs::write(&file, b"").unwrap();
    assert_eq!(
        available(&[need(true)]),
        vec![None],
        "vote_hold_ignored: the vote hold must answer a voter's check"
    );
    assert_eq!(
        available(&[need(false)]),
        vec![Some(1)],
        "the vote hold leaves this archive's proposals alone"
    );
    std::fs::remove_file(&file).unwrap();
    assert_eq!(available(&[need(true)]), vec![Some(1)], "released");
}

/// The rig's next shard frame, provably empty and so held, as a leader's
/// (`false`) or a voter's (`true`) body need.
fn held_next_frame(rig: &Rig) -> impl Fn(bool) -> ShardBodyNeed {
    let ingest = rig.ingest.get().unwrap();
    let filter = rig.session.filter.clone();
    {
        let mut ingest = quil_engine::archive_ingest::lock_ingest(ingest);
        let cursor = ingest.materialized_height(&filter).unwrap();
        assert!(
            ingest
                .holds_bodies_through(&filter, cursor + 1, true)
                .unwrap(),
            "setup: a provably empty next frame is held"
        );
    }
    let held = quil_engine::archive_ingest::lock_ingest(ingest).held_bodies();
    let cursor = held.cursor(&filter).unwrap();
    move |vote| ShardBodyNeed {
        address: filter.clone(),
        frame_number: cursor + 1,
        empty: true,
        anchor: FRAME - 6,
        vote,
        ..Default::default()
    }
}
