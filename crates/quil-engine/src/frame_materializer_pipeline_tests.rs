//! The runtime finalization worker's decisions over real Falcon finalizations
//! and fixture VDF/execution crypto: atomic publication, restart recovery,
//! legacy fallback, busy leases and authentication failures.
use super::*;
use crate::global_finalization::{
    FinalizationStep, FinalizedFrameAnnouncer, GlobalFinalizationLimits,
    GlobalFinalizationPipeline,
};
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct Announcements {
    heads: Arc<AtomicUsize>,
    gossip: Arc<AtomicUsize>,
}

fn pipeline(rig: &Rig, prover: Vec<u8>, max_queued: usize) -> (GlobalFinalizationPipeline, Announcements) {
    let heads = Arc::new(AtomicUsize::new(0));
    let gossip = Arc::new(AtomicUsize::new(0));
    let announcer = FinalizedFrameAnnouncer::new(
        {
            let heads = heads.clone();
            Arc::new(move |_, _| {
                heads.fetch_add(1, Ordering::SeqCst);
            })
        },
        Some({
            let gossip = gossip.clone();
            Arc::new(move |_| {
                gossip.fetch_add(1, Ordering::SeqCst);
            })
        }),
        prover,
    );
    let pipeline = GlobalFinalizationPipeline::new(
        rig.executor.clone(),
        rig.verifier.clone(),
        rig.clock.clone(),
        announcer,
        GlobalFinalizationLimits {
            max_queued,
            max_attempts: 3,
            retry: Duration::from_millis(1),
            max_ahead: 32,
        },
    );
    (pipeline, Announcements { heads, gossip })
}

fn certified_deploy(rig: &Rig) -> GlobalFrame {
    let mut frame = rig.deploy();
    frame.header.as_mut().unwrap().prover = vec![0x42; 32];
    certify(&mut frame, &rig.signer, 0);
    frame
}

fn prover(frame: &GlobalFrame) -> Vec<u8> {
    frame.header.as_ref().unwrap().prover.clone()
}

/// An archive executes a GLOBAL frame only once the application frames it
/// rewards are ingested: until then the step retries and publishes nothing,
/// and the ingest sees exactly the frame being executed.
#[test]
fn a_frame_waits_for_its_sequenced_ingest_before_executing() {
    let rig = Rig::new();
    let input = certified_deploy(&rig);
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen_frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (pipeline, _) = pipeline(&rig, prover(&input), 8);
    let pipeline = pipeline.with_sequenced_ingest({
        let (ready, seen_frames) = (ready.clone(), seen_frames.clone());
        Arc::new(move |frame: &GlobalFrame| {
            seen_frames.lock().unwrap().push(frame.header.as_ref().unwrap().frame_number);
            Ok(ready.load(Ordering::SeqCst))
        })
    });
    assert!(pipeline.offer(input.clone()));
    assert!(matches!(pipeline.step(1), FinalizationStep::Retry(_)));
    assert!(matches!(pipeline.step(1), FinalizationStep::Retry(_)));
    assert_eq!(rig.source.last_materialized_frame(), 0, "nothing executes before its ingest");
    assert_ne!(rig.clock.get_latest_global_clock_frame().ok(), Some(input.clone()), "nor becomes canonical");

    ready.store(true, Ordering::SeqCst);
    let FinalizationStep::Published { frame, .. } = pipeline.step(1) else {
        panic!("expected publication once ingested");
    };
    assert_eq!(frame, input);
    assert_eq!(rig.source.last_materialized_frame(), 1);
    assert_eq!(*seen_frames.lock().unwrap(), vec![1, 1, 1]);
}

#[test]
fn queued_finalization_publishes_atomically_before_any_announcement() {
    let rig = Rig::new();
    let input = certified_deploy(&rig);
    let (pipeline, seen) = pipeline(&rig, prover(&input), 8);
    assert!(pipeline.offer(input.clone()));
    let FinalizationStep::Published { frame, result } = pipeline.step(1) else {
        panic!("expected publication");
    };
    assert_eq!(frame, input);
    assert_eq!((result.processed, result.skipped), (1, 0));
    assert_eq!(rig.source.last_materialized_frame(), 1);
    assert_eq!(rig.clock.get_latest_global_clock_frame().unwrap(), input);
    assert_eq!(pipeline.queued(), 0);
    // The worker announces only after its mempool/topology follow-ups.
    assert_eq!(seen.heads.load(Ordering::SeqCst), 0);
    pipeline.announce(&frame);
    assert_eq!(seen.heads.load(Ordering::SeqCst), 1);
    assert_eq!(seen.gossip.load(Ordering::SeqCst), 1);
    assert!(matches!(pipeline.step(2), FinalizationStep::Idle));
    // Another node's proposal is announced without gossip.
    let (other, seen) = pipeline_for_other_prover(&rig);
    other.announce(&frame);
    assert_eq!(seen.heads.load(Ordering::SeqCst), 1);
    assert_eq!(seen.gossip.load(Ordering::SeqCst), 0);
}

fn pipeline_for_other_prover(rig: &Rig) -> (GlobalFinalizationPipeline, Announcements) {
    pipeline(rig, vec![0xee; 32], 8)
}

#[test]
fn restart_recovers_only_a_certified_durable_candidate() {
    let rig = Rig::new();
    let mut uncertified = rig.deploy();
    uncertified.header.as_mut().unwrap().public_key_signature_bls48581 = None;
    let noop = crate::cw_global_seams::NoopTxn;
    rig.clock
        .put_global_clock_frame_candidate(&uncertified, &noop)
        .unwrap();
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    let sequence = rig.db.inner().latest_sequence_number();
    assert!(matches!(pipeline.step(1), FinalizationStep::Idle));
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    assert_eq!(rig.source.last_materialized_frame(), 0);

    // The finalizer overwrites the same candidate key with the certified header.
    let input = certified_deploy(&rig);
    rig.clock.put_global_clock_frame_candidate(&input, &noop).unwrap();
    // A later proposal or vote persisting it as an ancestor carries no
    // certificate; the stored certificate survives for restart recovery.
    let mut ancestor = input.clone();
    ancestor.header.as_mut().unwrap().public_key_signature_bls48581 = None;
    rig.clock.put_global_clock_frame_candidate(&ancestor, &noop).unwrap();
    let (fresh, _) = pipeline_for_other_prover(&rig);
    let FinalizationStep::Published { frame, .. } = fresh.step(1) else {
        panic!("expected recovery from the durable candidate");
    };
    assert_eq!(frame, input);
    assert_eq!(rig.source.last_materialized_frame(), 1);
    assert_eq!(rig.clock.get_latest_global_clock_frame().unwrap(), input);
}

#[test]
fn a_held_proposal_lease_defers_publication_without_counting_a_failure() {
    let rig = Rig::new();
    let input = certified_deploy(&rig);
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    pipeline.offer(input.clone());
    let genesis = rig.clock.get_global_clock_frame(0).unwrap();
    let lease = rig
        .executor
        .prepare(rig.context(&genesis), 0, &rig.blocks, &rig.verifier, false)
        .unwrap();
    let sequence = rig.db.inner().latest_sequence_number();
    for _ in 0..5 {
        assert!(matches!(pipeline.step(1), FinalizationStep::Retry(_)));
    }
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    assert!(rig.clock.get_global_clock_frame(1).is_err());
    drop(lease);
    assert!(matches!(pipeline.step(1), FinalizationStep::Published { .. }));
}

#[test]
fn a_store_without_an_execution_receipt_publishes_on_its_certified_head() {
    let rig = Rig::new();
    let old = certified_deploy(&rig);
    rig.source.materialize(&old).unwrap();
    save(rig.clock.as_ref(), &old);
    rig.db
        .inner()
        .delete(quil_store::encoding::global_execution_checkpoint_key())
        .unwrap();
    let mut next = state_frame(&rig.source, 2, 73, id(&old));
    certify_parent(&mut next, &rig.signer, 0, old.header.as_ref().unwrap().rank);
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    pipeline.offer(next.clone());
    assert!(matches!(pipeline.step(2), FinalizationStep::Published { .. }));
    assert_eq!(rig.source.last_materialized_frame(), 2);
    assert!(rig
        .db
        .inner()
        .get(quil_store::encoding::global_execution_checkpoint_key())
        .unwrap()
        .is_some());
}

#[test]
fn an_uncertified_canonical_base_falls_back_to_legacy_after_retries() {
    let rig = Rig::new();
    let old = certified_deploy(&rig);
    rig.source.materialize(&old).unwrap();
    // A legacy writer stored the head without its certificate, so it is not
    // an authenticated base for atomic publication.
    let mut stored = old.clone();
    stored.header.as_mut().unwrap().public_key_signature_bls48581 = None;
    save(rig.clock.as_ref(), &stored);
    let mut next = state_frame(&rig.source, 2, 73, id(&old));
    certify_parent(&mut next, &rig.signer, 0, old.header.as_ref().unwrap().rank);
    let (pipeline, seen) = pipeline(&rig, prover(&next), 8);
    pipeline.offer(next.clone());
    let sequence = rig.db.inner().latest_sequence_number();
    for _ in 0..2 {
        assert!(matches!(pipeline.step(2), FinalizationStep::Retry(_)));
        assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    }
    assert!(matches!(pipeline.step(2), FinalizationStep::Legacy));
    assert_eq!(rig.clock.get_global_clock_frame(2).unwrap(), next);
    assert_eq!(rig.source.last_materialized_frame(), 1);
    assert_eq!(seen.heads.load(Ordering::SeqCst), 0);
    // The worker's legacy branch materializes it, then announces it.
    rig.source.materialize(&next).unwrap();
    assert!(pipeline.finish_legacy(&next));
    assert_eq!(pipeline.queued(), 0);
    assert!(!pipeline.finish_legacy(&next));
    assert_eq!(rig.source.last_materialized_frame(), 2);
}

#[test]
fn a_canonical_clock_written_ahead_by_sync_uses_the_legacy_order() {
    let rig = Rig::new();
    let input = certified_deploy(&rig);
    let mut ahead = input.clone();
    ahead.header.as_mut().unwrap().frame_number = 2;
    save(rig.clock.as_ref(), &ahead);
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    pipeline.offer(input.clone());
    assert!(matches!(pipeline.step(1), FinalizationStep::Legacy));
    assert_eq!(rig.clock.get_global_clock_frame(1).unwrap(), input);
    assert_eq!(rig.source.last_materialized_frame(), 0);
}

#[test]
fn unauthenticated_finalizations_are_never_published_or_reloaded() {
    let rig = Rig::new();
    let (pipeline, seen) = pipeline(&rig, vec![], 8);
    let sequence = rig.db.inner().latest_sequence_number();
    // A certificate from another epoch is refused before execution.
    let mut wrong_epoch = rig.deploy();
    certify(&mut wrong_epoch, &rig.signer, 1);
    pipeline.offer(wrong_epoch);
    assert!(matches!(pipeline.step(1), FinalizationStep::Idle));
    assert_eq!(pipeline.queued(), 0);
    // A valid certificate over a substituted body is refused and remembered,
    // so the same durable candidate is not retried.
    let mut substituted = certified_deploy(&rig);
    substituted
        .requests
        .push(quil_types::proto::global::MessageBundle::default());
    pipeline.offer(substituted.clone());
    assert!(matches!(pipeline.step(1), FinalizationStep::Idle));
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    rig.clock
        .put_global_clock_frame_candidate(&substituted, &crate::cw_global_seams::NoopTxn)
        .unwrap();
    let sequence = rig.db.inner().latest_sequence_number();
    assert!(matches!(pipeline.step(1), FinalizationStep::Idle));
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    assert!(rig.clock.get_global_clock_frame(1).is_err());
    assert_eq!(rig.source.last_materialized_frame(), 0);
    assert_eq!(seen.heads.load(Ordering::SeqCst), 0);
}

#[test]
fn the_queue_keeps_the_lowest_heights_and_prunes_executed_ones() {
    let rig = Rig::new();
    let (pipeline, _) = pipeline(&rig, vec![], 2);
    let at = |number: u64| {
        let mut frame = rig.deploy();
        frame.header.as_mut().unwrap().frame_number = number;
        frame
    };
    assert!(pipeline.offer(at(3)));
    assert!(pipeline.offer(at(4)));
    // Full: a lower height evicts the highest; a higher one is refused.
    assert!(pipeline.offer(at(2)));
    assert!(!pipeline.offer(at(5)));
    assert_eq!(pipeline.queued(), 2);
    assert!(pipeline.offer(at(3)));
    pipeline.prune_through(2);
    assert_eq!(pipeline.queued(), 1);
    pipeline.prune_through(u64::MAX);
    assert_eq!(pipeline.queued(), 0);
}

#[test]
fn atomic_finalizer_defers_clock_head_and_gossip_to_the_worker() {
    use quil_cw_consensus::adapters::FrameFinalizer as _;
    let rig = Rig::new();
    let input = certified_deploy(&rig);
    let (pipeline, published) = pipeline(&rig, prover(&input), 8);
    let pipeline = Arc::new(pipeline);
    let (tx, mut jobs) = tokio::sync::mpsc::unbounded_channel();
    let direct = Arc::new(AtomicUsize::new(0));
    let finalizer = crate::cw_global_seams::GlobalSeamFinalizer::new(
        rig.clock.clone(),
        tx,
        {
            let direct = direct.clone();
            Arc::new(move |_, _| {
                direct.fetch_add(1, Ordering::SeqCst);
            })
        },
        Some({
            let direct = direct.clone();
            Arc::new(move |_| {
                direct.fetch_add(1, Ordering::SeqCst);
            })
        }),
        prover(&input),
    )
    .with_pipeline(Some(pipeline.clone()));
    let view = input.header.as_ref().unwrap().rank;
    let bytes = crate::consensus_wire::encode_global_frame(&input).unwrap();
    // The finalizer persists the body as consensus delivered it.
    let input = crate::consensus_wire::decode_global_frame(&bytes).unwrap();
    finalizer.on_finalized(view, id(&input), Some(bytes), None, true);
    assert!(rig.clock.get_global_clock_frame(1).is_err());
    assert_eq!(
        rig.clock
            .get_global_clock_frame_candidate(1, id(&input).as_ref())
            .unwrap(),
        input
    );
    assert_eq!(jobs.try_recv().unwrap().1, 1);
    assert_eq!(pipeline.queued(), 1);
    assert_eq!(direct.load(Ordering::SeqCst), 0);
    let FinalizationStep::Published { frame, .. } = pipeline.step(1) else {
        panic!("expected publication");
    };
    pipeline.announce(&frame);
    assert_eq!(rig.clock.get_global_clock_frame(1).unwrap(), input);
    assert_eq!(published.heads.load(Ordering::SeqCst), 1);
    assert_eq!(published.gossip.load(Ordering::SeqCst), 1);
    assert_eq!(direct.load(Ordering::SeqCst), 0);
}

#[test]
fn synced_frames_wait_as_certified_candidates_only_inside_the_admission_window() {
    let rig = Rig::new();
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    let input = certified_deploy(&rig);
    let candidate = |number: u64, frame: &GlobalFrame| {
        rig.clock
            .get_global_clock_frame_candidate(number, id(frame).as_ref())
            .ok()
    };
    // Without this epoch's certificate the poller stores it canonically.
    let mut plain = input.clone();
    plain.header.as_mut().unwrap().public_key_signature_bls48581 = None;
    assert!(!pipeline.offer_synced(&plain));
    let mut other_epoch = rig.deploy();
    certify(&mut other_epoch, &rig.signer, 1);
    assert!(!pipeline.offer_synced(&other_epoch));
    assert_eq!(candidate(1, &plain), None);
    assert_eq!(pipeline.queued(), 0);
    // A certified frame above the head waits durably and publishes atomically.
    assert!(pipeline.offer_synced(&input));
    assert_eq!(candidate(1, &input), Some(input.clone()));
    assert_eq!(pipeline.queued(), 1);
    assert!(rig.clock.get_global_clock_frame(1).is_err());
    assert!(matches!(pipeline.step(1), FinalizationStep::Published { .. }));
    // At or below the head, and beyond the window, it keeps the legacy order.
    assert!(!pipeline.offer_synced(&input));
    let at = |number: u64| {
        let mut frame = input.clone();
        frame.header.as_mut().unwrap().frame_number = number;
        frame
    };
    assert!(!pipeline.admits(1) && pipeline.admits(2) && pipeline.admits(33) && !pipeline.admits(34));
    assert!(!pipeline.offer_synced(&at(34)));
    assert!(pipeline.offer_synced(&at(33)));
    assert_eq!(pipeline.queued(), 1);
}

/// A synced frame the clock already holds as a certified candidate (the
/// finalizer stored it first) is queued without rewriting it, so the plan
/// executing it is not invalidated; a different body is still written.
#[test]
fn a_synced_frame_already_held_as_a_certified_candidate_is_not_rewritten() {
    let rig = Rig::new();
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    let input = certified_deploy(&rig);
    assert!(pipeline.offer_synced(&input));
    let sequence = rig.db.inner().latest_sequence_number();
    assert!(pipeline.offer_synced(&input));
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence, "not rewritten");
    assert_eq!(pipeline.queued(), 1);

    let mut other_body = input.clone();
    other_body.requests.push(Default::default());
    assert!(pipeline.offer_synced(&other_body));
    assert_ne!(rig.db.inner().latest_sequence_number(), sequence);
    assert_eq!(
        rig.clock.get_global_clock_frame_candidate(1, id(&input).as_ref()).unwrap().requests,
        other_body.requests,
    );
}

#[test]
fn atomic_finalizer_keeps_the_legacy_order_beyond_the_admission_window() {
    use quil_cw_consensus::adapters::FrameFinalizer as _;
    let rig = Rig::new();
    let mut far = certified_deploy(&rig);
    far.header.as_mut().unwrap().frame_number = 40;
    let (pipeline, _) = pipeline(&rig, prover(&far), 8);
    let pipeline = Arc::new(pipeline);
    let (tx, mut jobs) = tokio::sync::mpsc::unbounded_channel();
    let heads = Arc::new(AtomicUsize::new(0));
    let finalizer = crate::cw_global_seams::GlobalSeamFinalizer::new(
        rig.clock.clone(),
        tx,
        {
            let heads = heads.clone();
            Arc::new(move |_, _| {
                heads.fetch_add(1, Ordering::SeqCst);
            })
        },
        None,
        prover(&far),
    )
    .with_pipeline(Some(pipeline.clone()));
    let bytes = crate::consensus_wire::encode_global_frame(&far).unwrap();
    let delivered = crate::consensus_wire::decode_global_frame(&bytes).unwrap();
    finalizer.on_finalized(
        far.header.as_ref().unwrap().rank,
        id(&far),
        Some(bytes),
        None,
        true,
    );
    assert_eq!(rig.clock.get_global_clock_frame(40).unwrap(), delivered);
    assert_eq!(heads.load(Ordering::SeqCst), 1);
    assert_eq!(jobs.try_recv().unwrap().1, 40);
    assert_eq!(pipeline.queued(), 0);
}

// Simplex finalizes every ancestor of a finalized block, but only that block
// carries a certificate. After a restart, views can be notarized without
// being finalized until a later one is; a worker waiting at the first
// uncertified ancestor stops GLOBAL publishing.
#[test]
fn a_certified_descendant_publishes_its_notarized_ancestor() {
    let rig = Rig::new();
    let ancestor = rig.deploy();
    let noop = crate::cw_global_seams::NoopTxn;
    rig.clock.put_global_clock_frame_candidate(&ancestor, &noop).unwrap();
    let rank = ancestor.header.as_ref().unwrap().rank;
    let mut descendant = state_frame(&rig.source, 2, rank + 5, id(&ancestor));
    certify_parent(&mut descendant, &rig.signer, 0, rank);
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    assert!(pipeline.offer(descendant));
    let FinalizationStep::Published { frame, result } = pipeline.step(1) else {
        panic!("expected the implied ancestor to publish");
    };
    assert_eq!(frame, ancestor);
    assert_eq!((result.processed, result.skipped), (1, 0));
    assert_eq!(rig.source.last_materialized_frame(), 1);
    assert_eq!(rig.clock.get_latest_global_clock_frame().unwrap(), ancestor);
}

#[test]
fn a_certified_frame_that_does_not_link_implies_nothing() {
    let rig = Rig::new();
    let ancestor = rig.deploy();
    let noop = crate::cw_global_seams::NoopTxn;
    rig.clock.put_global_clock_frame_candidate(&ancestor, &noop).unwrap();
    let rank = ancestor.header.as_ref().unwrap().rank;
    let unrelated = quil_cw_consensus::adapters::digest_from_identity([9; 32]);
    let mut descendant = state_frame(&rig.source, 2, rank + 5, unrelated);
    certify_parent(&mut descendant, &rig.signer, 0, rank);
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    assert!(pipeline.offer(descendant));
    let sequence = rig.db.inner().latest_sequence_number();
    assert!(matches!(pipeline.step(1), FinalizationStep::Idle));
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    assert_eq!(rig.source.last_materialized_frame(), 0);
}

/// A peer serves an ancestor Simplex finalized through a descendant, without a
/// certificate of its own, followed by that descendant. Offered as a chain, the
/// ancestor waits as a candidate (the canonical clock is untouched) and is
/// published atomically through the descendant, not by the legacy path.
#[test]
fn a_synced_chain_publishes_its_uncertified_ancestor_atomically() {
    let rig = Rig::new();
    let ancestor = rig.deploy();
    let rank = ancestor.header.as_ref().unwrap().rank;
    let mut descendant = state_frame(&rig.source, 2, rank + 5, id(&ancestor));
    certify_parent(&mut descendant, &rig.signer, 0, rank);
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    let before = rig.clock.get_latest_global_clock_frame().ok();

    assert!(!pipeline.offer_synced(&ancestor), "alone, the ancestor has no certificate");
    assert!(pipeline.offer_synced_chain(&[ancestor.clone(), descendant.clone()]));
    assert_eq!(rig.clock.get_latest_global_clock_frame().ok(), before, "nothing canonical before publication");
    let FinalizationStep::Published { frame, .. } = pipeline.step(1) else {
        panic!("expected the synced ancestor to publish atomically");
    };
    assert_eq!(frame, ancestor);
    assert_eq!(rig.source.last_materialized_frame(), 1);
}

/// A chain whose frames do not link, or whose top is not certified, is
/// refused whole, so the caller keeps its previous behavior.
#[test]
fn a_synced_chain_that_does_not_link_or_certify_is_refused() {
    let rig = Rig::new();
    let ancestor = rig.deploy();
    let rank = ancestor.header.as_ref().unwrap().rank;
    let unrelated = quil_cw_consensus::adapters::digest_from_identity([9; 32]);
    let mut stranger = state_frame(&rig.source, 2, rank + 5, unrelated);
    certify_parent(&mut stranger, &rig.signer, 0, rank);
    let uncertified = state_frame(&rig.source, 2, rank + 5, id(&ancestor));
    let (pipeline, _) = pipeline(&rig, vec![], 8);
    assert!(!pipeline.offer_synced_chain(&[ancestor.clone(), stranger]));
    assert!(!pipeline.offer_synced_chain(&[ancestor.clone(), uncertified]));
    assert!(!pipeline.offer_synced_chain(&[]));
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&ancestor.header.as_ref().unwrap().output).unwrap();
    assert!(rig.clock.get_global_clock_frame_candidate(1, &selector).is_err(),
        "a refused chain leaves no ancestor candidate");
}
