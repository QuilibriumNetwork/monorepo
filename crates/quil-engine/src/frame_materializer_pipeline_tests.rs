//! The runtime finalization worker's decisions over real Falcon finalizations
//! and fixture VDF/execution crypto: atomic publication, restart recovery,
//! legacy fallback, busy leases and authentication failures.
use super::*;
use crate::global_finalization::{
    FinalizationStep, FinalizedFrameAnnouncer, GlobalFinalizationLimits, GlobalFinalizationPipeline,
};
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct Announcements {
    heads: Arc<AtomicUsize>,
    gossip: Arc<AtomicUsize>,
}

fn pipeline(
    rig: &Rig,
    prover: Vec<u8>,
    max_queued: usize,
) -> (GlobalFinalizationPipeline, Announcements) {
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
            seen_frames
                .lock()
                .unwrap()
                .push(frame.header.as_ref().unwrap().frame_number);
            Ok(ready.load(Ordering::SeqCst))
        })
    });
    assert!(pipeline.offer(input.clone()));
    assert!(matches!(pipeline.step(1), FinalizationStep::Retry(_)));
    assert!(matches!(pipeline.step(1), FinalizationStep::Retry(_)));
    assert_eq!(
        rig.source.last_materialized_frame(),
        0,
        "nothing executes before its ingest"
    );
    assert_ne!(
        rig.clock.get_latest_global_clock_frame().ok(),
        Some(input.clone()),
        "nor becomes canonical"
    );

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
    uncertified
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
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
    rig.clock
        .put_global_clock_frame_candidate(&input, &noop)
        .unwrap();
    // A later proposal or vote persisting it as an ancestor carries no
    // certificate; the stored certificate survives for restart recovery.
    let mut ancestor = input.clone();
    ancestor
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
    rig.clock
        .put_global_clock_frame_candidate(&ancestor, &noop)
        .unwrap();
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
    assert!(matches!(
        pipeline.step(1),
        FinalizationStep::Published { .. }
    ));
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
    assert!(matches!(
        pipeline.step(2),
        FinalizationStep::Published { .. }
    ));
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
    stored
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
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
    assert!(matches!(
        pipeline.step(1),
        FinalizationStep::Published { .. }
    ));
    // At or below the head, and beyond the window, it keeps the legacy order.
    assert!(!pipeline.offer_synced(&input));
    let at = |number: u64| {
        let mut frame = input.clone();
        frame.header.as_mut().unwrap().frame_number = number;
        frame
    };
    assert!(
        !pipeline.admits(1) && pipeline.admits(2) && pipeline.admits(33) && !pipeline.admits(34)
    );
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
    assert_eq!(
        rig.db.inner().latest_sequence_number(),
        sequence,
        "not rewritten"
    );
    assert_eq!(pipeline.queued(), 1);

    let mut other_body = input.clone();
    other_body.requests.push(Default::default());
    assert!(pipeline.offer_synced(&other_body));
    assert_ne!(rig.db.inner().latest_sequence_number(), sequence);
    assert_eq!(
        rig.clock
            .get_global_clock_frame_candidate(1, id(&input).as_ref())
            .unwrap()
            .requests,
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
    rig.clock
        .put_global_clock_frame_candidate(&ancestor, &noop)
        .unwrap();
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
    rig.clock
        .put_global_clock_frame_candidate(&ancestor, &noop)
        .unwrap();
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

    assert!(
        !pipeline.offer_synced(&ancestor),
        "alone, the ancestor has no certificate"
    );
    assert!(pipeline.offer_synced_chain(&[ancestor.clone(), descendant.clone()]));
    assert_eq!(
        rig.clock.get_latest_global_clock_frame().ok(),
        before,
        "nothing canonical before publication"
    );
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
    let selector =
        quil_crypto::poseidon::hash_bytes_to_32(&ancestor.header.as_ref().unwrap().output).unwrap();
    assert!(
        rig.clock
            .get_global_clock_frame_candidate(1, &selector)
            .is_err(),
        "a refused chain leaves no ancestor candidate"
    );
}

/// While execution trails the head beyond the voting window, an authentic
/// finalization goes to the legacy materializer without an atomic attempt
/// when none is allowed, and after one failed attempt when one is. An
/// unauthentic one is still refused.
#[test]
fn a_catching_up_worker_hands_finalizations_to_the_legacy_path_without_retrying() {
    let rig = Rig::new();
    let input = certified_deploy(&rig);
    let (pipeline, seen) = pipeline(&rig, prover(&input), 8);
    let mut substituted = input.clone();
    substituted
        .requests
        .push(quil_types::proto::global::MessageBundle::default());
    pipeline.offer(substituted);
    assert!(matches!(pipeline.step_within(1, 0), FinalizationStep::Idle));
    assert!(rig.clock.get_global_clock_frame(1).is_err());

    pipeline.offer(input.clone());
    let before = rig.source.execution_counts();
    assert!(matches!(
        pipeline.step_within(1, 0),
        FinalizationStep::Legacy
    ));
    assert_eq!(rig.source.execution_counts(), before, "no atomic attempt");
    assert_eq!(
        rig.source.last_materialized_frame(),
        0,
        "nothing executed yet"
    );
    assert_eq!(rig.clock.get_global_clock_frame(1).unwrap(), input);
    assert_eq!(seen.heads.load(Ordering::SeqCst), 0);
    rig.source.materialize(&input).unwrap();
    assert!(pipeline.finish_legacy(&input));

    // One attempt allowed: its failure hands the frame over at once.
    let mut stored = input.clone();
    stored
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
    save(rig.clock.as_ref(), &stored);
    let mut next = state_frame(&rig.source, 2, 73, id(&input));
    certify_parent(
        &mut next,
        &rig.signer,
        0,
        input.header.as_ref().unwrap().rank,
    );
    pipeline.offer(next.clone());
    assert!(matches!(
        pipeline.step_within(2, 1),
        FinalizationStep::Legacy
    ));
    let counts = rig.source.execution_counts();
    assert_eq!((counts.atomic_published, counts.atomic_failed), (0, 1));
    assert_eq!(rig.clock.get_global_clock_frame(2).unwrap(), next);
}

/// Near the head, a finalization whose atomic attempts fail goes to the
/// legacy path after three, and its canonical record then executes in place
/// at once: no frame executes more than three times plus once in place.
/// The canonical clock written ahead by sync is not an attempt.
#[test]
fn a_finalization_handed_over_after_failed_attempts_is_not_attempted_again() {
    let rig = Rig::new();
    let old = certified_deploy(&rig);
    rig.source.materialize(&old).unwrap();
    let mut stored = old.clone();
    stored
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
    save(rig.clock.as_ref(), &stored);
    let mut next = state_frame(&rig.source, 2, 73, id(&old));
    certify_parent(&mut next, &rig.signer, 0, old.header.as_ref().unwrap().rank);
    let (worker, _) = pipeline(&rig, prover(&next), 8);
    worker.offer(next.clone());
    for _ in 0..2 {
        assert!(matches!(worker.step(2), FinalizationStep::Retry(_)));
    }
    assert!(matches!(worker.step(2), FinalizationStep::Legacy));
    assert!(worker.attempted(2));
    let failed = rig.source.execution_counts();
    assert_eq!((failed.atomic_published, failed.atomic_failed), (0, 3));

    // The worker's canonical path.
    let attempts = if worker.attempted(2) {
        0
    } else {
        crate::global_catch_up::AT_HEAD_ATOMIC_ATTEMPTS
    };
    let outcome = crate::global_catch_up::attempt_atomically(attempts, || {
        rig.source.materialize_canonical_atomically(&next, limits())
    });
    assert!(outcome.is_none());
    rig.source.materialize(&next).unwrap();
    assert_eq!(rig.source.last_materialized_frame(), 2);
    let counts = rig.source.execution_counts();
    assert_eq!(
        (counts.atomic_published, counts.atomic_failed),
        (0, 3),
        "three attempts, then in place"
    );
    assert!(worker.finish_legacy(&next));
    assert!(!worker.attempted(2));

    // Written ahead by sync: handed over without an attempt.
    let rig = Rig::new();
    let input = certified_deploy(&rig);
    let mut ahead = input.clone();
    ahead.header.as_mut().unwrap().frame_number = 2;
    save(rig.clock.as_ref(), &ahead);
    let (synced, _) = pipeline(&rig, vec![], 8);
    synced.offer(input);
    assert!(matches!(synced.step(1), FinalizationStep::Legacy));
    assert!(!synced.attempted(1));
}

/// A pipeline whose sequenced ingest reports the frame's application frames
/// ingested once `ready` is set.
fn sequenced_pipeline(
    rig: &Rig,
    input: &GlobalFrame,
    ready: &Arc<std::sync::atomic::AtomicBool>,
) -> GlobalFinalizationPipeline {
    let (pipeline, _) = pipeline(rig, prover(input), 8);
    let ready = ready.clone();
    pipeline.with_sequenced_ingest(Arc::new(move |_: &GlobalFrame| {
        Ok(ready.load(Ordering::SeqCst))
    }))
}

/// An archive materializes the application frames a GLOBAL frame sequences
/// only when finalization publishes the frame, and shard-header rewards read
/// the shard and world sizes they change. A leader or voter that executed the
/// finalized parent privately before then, past the publication priority,
/// declared or accepted a prover root the finalized execution did not
/// reproduce: every archive logged a prover root mismatch and GLOBAL stalled
/// for 70-160 s (devnet, 2026-10-30). The archive waits until the parent
/// publishes, then votes and proposes on the published state.
#[test]
fn an_archive_never_executes_a_finalized_parent_before_its_sequenced_ingest() {
    use crate::outage::test_logs::CapturedLogs;
    let logs = CapturedLogs::default();
    let _logs = logs.install();
    let rig = Rig::new();
    let parent = certified_deploy(&rig);
    rig.put(&parent);
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pipeline = sequenced_pipeline(&rig, &parent, &ready);
    assert!(pipeline.offer(parent.clone()));
    assert!(
        matches!(pipeline.step(1), FinalizationStep::Retry(_)),
        "the parent's application frames are not ingested yet"
    );
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();
    // Without the wait, a node past its publication priority executes the
    // parent privately (a_voter_lets_its_finalized_parent_publish_before_executing_it_privately).
    let seam = rig.seam(&parent).with_publication_priority(Duration::ZERO);
    for attempt in 0..3 {
        assert!(
            seam.verify_or_defer(context, id(&child), Some(encoded.clone()))
                .is_err(),
            "attempt {attempt}: the vote executed the finalized parent privately before its sequenced ingest"
        );
        assert!(
            seam.propose_with_context(context).is_none(),
            "attempt {attempt}: the proposal executed the finalized parent privately before its sequenced ingest"
        );
    }
    assert!(!rig.executor.busy(), "waiting takes no lease");
    assert_eq!(rig.source.last_materialized_frame(), 0);
    seam.verify_patience_ran_out(context, Duration::from_secs(20));

    ready.store(true, Ordering::SeqCst);
    assert!(matches!(
        pipeline.step(1),
        FinalizationStep::Published { .. }
    ));
    assert_eq!(
        seam.verify_or_defer(context, id(&child), Some(encoded)),
        Ok(true),
        "then it votes on the published state"
    );
    assert!(
        seam.propose_with_context(context).is_some(),
        "and proposes on it"
    );

    let began = logs.lines_with("wait for this archive's finalized frames to publish");
    assert_eq!(began.len(), 1, "one line for the wait: {began:?}");
    assert!(
        began[0].contains("INFO")
            && began[0].contains("parent=1")
            && began[0].contains("published=0")
            && began[0].contains("finalized=1"),
        "{}",
        began[0]
    );
    let declined = logs.lines_with("GLOBAL vote declined");
    assert_eq!(declined.len(), 1, "{declined:?}");
    assert!(
        declined[0].contains("INFO")
            && declined[0].contains("action=\"wait\"")
            && declined[0].contains("finalized frames through 1 wait to publish"),
        "an expected wait, with the event ending it: {}",
        declined[0]
    );
    let ended = logs.lines_with("no longer wait");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert!(
        ended[0].contains("INFO") && ended[0].contains("through=1"),
        "{}",
        ended[0]
    );
}

/// The wait holds only while finalized frames wait to publish here. A parent
/// that is not finalized may finalize only through its child, so an archive
/// executes it privately at once, as before: waiting for it would halt
/// GLOBAL.
#[test]
fn an_archive_executes_a_parent_not_finalized_here_at_once() {
    let rig = Rig::new();
    let parent = certified_deploy(&rig);
    rig.put(&parent);
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _pipeline = sequenced_pipeline(&rig, &parent, &ready);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();
    let seam = rig.seam(&parent);
    assert_eq!(
        seam.verify_or_defer(context, id(&child), Some(encoded)),
        Ok(true),
        "a notarized parent is voted on at once"
    );
    assert!(seam.propose_with_context(context).is_some(), "and built on");
}

/// The bounds of the wait, through the consensus adapter: a vote still
/// waiting when its verify patience (20 s) runs out is declined, and the views
/// after it wait the same way; a vote whose parent publishes within the
/// patience is cast on the published state.
#[test]
fn an_archive_vote_waiting_for_publication_declines_at_its_patience_and_votes_once_published() {
    use quil_cw_consensus::_consensus::simplex::types::Context;
    use quil_cw_consensus::_consensus::types::{Epoch, Round, View};
    use quil_cw_consensus::_consensus::Automaton as _;
    use quil_cw_consensus::_runtime::{deterministic, Clock as _, Runner as _, Supervisor as _};
    let rig = Rig::new();
    let parent = certified_deploy(&rig);
    rig.put(&parent);
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pipeline = sequenced_pipeline(&rig, &parent, &ready);
    assert!(pipeline.offer(parent.clone()));
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let mut context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let store = BlockStore::new();
    // Past its publication priority only the wait keeps the vote from
    // executing the parent.
    let seam = Arc::new(rig.seam(&parent).with_publication_priority(Duration::ZERO));
    let leader =
        quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(rig.signer.public_key())
            .unwrap();
    // Checks `child` for `context.view`; publishes the parent after
    // `published_after`, if given. Returns the answer and when it came.
    let verify = |context: ProposalContext,
                  child: &GlobalFrame,
                  published_after: Option<Duration>| {
        let digest = id(child);
        store.put(
            digest,
            crate::consensus_wire::encode_global_frame(child).unwrap(),
        );
        let (seam, store, leader, pipeline, ready) = (&seam, &store, &leader, &pipeline, &ready);
        deterministic::Runner::timed(Duration::from_secs(120)).start(|runtime| async move {
            let mut automaton = quil_cw_consensus::adapters::FalconAutomaton::new(
                runtime.child("automaton"),
                seam.clone(),
                store.clone(),
            );
            let started = runtime.current();
            let pending = automaton
                .verify(
                    Context {
                        round: Round::new(Epoch::new(context.epoch), View::new(context.view)),
                        leader: leader.clone(),
                        parent: (View::new(context.parent_view), context.parent),
                    },
                    digest,
                )
                .await;
            if let Some(after) = published_after {
                runtime.sleep(after).await;
                ready.store(true, Ordering::SeqCst);
                assert!(matches!(
                    pipeline.step(1),
                    FinalizationStep::Published { .. }
                ));
            }
            let verdict = pending.await.ok();
            (verdict, runtime.current().duration_since(started).unwrap())
        })
    };

    for view in [73, 74] {
        context.view = view;
        let mut child = child.clone();
        child.header.as_mut().unwrap().rank = view;
        body_root(&mut child);
        let (verdict, answered) = verify(context, &child, None);
        assert_eq!(verdict, Some(false), "view {view}: unpublished, no vote");
        assert!(
            answered >= Duration::from_secs(20) && answered < Duration::from_secs(21),
            "view {view}: declined when its patience ran out: {answered:?}"
        );
        assert!(!rig.executor.busy());
    }
    assert_eq!(rig.source.last_materialized_frame(), 0);

    context.view = 75;
    let mut child = child.clone();
    child.header.as_mut().unwrap().rank = 75;
    body_root(&mut child);
    let (verdict, answered) = verify(context, &child, Some(Duration::from_secs(5)));
    assert_eq!(verdict, Some(true), "published within the patience: a vote");
    assert!(
        answered >= Duration::from_secs(5) && answered < Duration::from_secs(6),
        "{answered:?}"
    );
    assert_eq!(rig.source.last_materialized_frame(), 1);
}

/// The application whose committee the shard-reward tests certify a header of.
const REWARDED_APP: [u8; 32] = [0x55; 32];

fn app_data(data: u8) -> (quil_hypergraph::Location, Vec<u8>) {
    (
        quil_hypergraph::Location {
            app_address: REWARDED_APP,
            data_address: [data; 32],
        },
        vec![data; 4096],
    )
}

/// A fixture whose registry holds `shard` as [`REWARDED_APP`]'s committee,
/// whose application holds some data, and which executes shard headers and
/// issues their rewards as an archive does. `extra` more application vertices
/// stand for frames an ingest already materialized.
fn rewarding_fixture(
    global: &quil_crypto::FalconSigner,
    shard: &quil_crypto::FalconSigner,
    extra: bool,
) -> Fixture {
    let fixture = Fixture::seeded(Some(global.public_key()), |crdt| {
        crate::genesis::seed_active_prover_on_filter(
            crdt,
            shard.public_key(),
            1000,
            0,
            &REWARDED_APP,
        )
        .unwrap();
        let (location, value) = app_data(1);
        crdt.add_vertex(&location, &value).unwrap();
        crdt.commit(0).unwrap();
    });
    fixture
        .source
        .execution_manager
        .install_global_frame_header_deps(
            fixture.source.prover_registry.clone(),
            Arc::new(crate::rewards::OptRewardIssuance),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_tries::ShaInclusionProver),
            Arc::new(TestFrameProver),
        )
        .unwrap();
    if extra {
        let (location, value) = app_data(2);
        fixture
            .source
            .hypergraph
            .add_vertex(&location, &value)
            .unwrap();
        fixture.source.hypergraph.commit(0).unwrap();
    }
    fixture
}

/// `parent` with a shard header of [`REWARDED_APP`] that `shard` certified.
fn with_shard_header(mut parent: GlobalFrame, shard: &quil_crypto::FalconSigner) -> GlobalFrame {
    let mut header = quil_types::proto::global::FrameHeader {
        address: REWARDED_APP.to_vec(),
        frame_number: 1,
        rank: 5,
        timestamp: 1,
        difficulty: 200_000,
        parent_selector: vec![0; 32],
        requests_root: vec![0; 32],
        state_roots: vec![vec![0; 32]; 4],
        prover: quil_crypto::poseidon::hash_bytes_to_32(shard.public_key())
            .unwrap()
            .to_vec(),
        ..Default::default()
    };
    header.output = quil_crypto::porep::deterministic_app_frame_output(
        &header.parent_selector,
        &header.requests_root,
        &header.state_roots,
        &quil_crypto::porep::derive_storage_beacon(0, &[]),
        header.frame_number,
        header.rank,
        &header.prover,
        header.difficulty,
        0,
        header.timestamp,
        &[],
        0,
        &[],
        &[],
        &[],
    );
    let mut namespace = b"appshard".to_vec();
    namespace.extend_from_slice(&REWARDED_APP);
    header.public_key_signature_bls48581 =
        Some(quil_types::proto::keys::Bls48581AggregateSignature {
            signature: finalization_certificate(&namespace, shard, 0, 5, 0, &header.output),
            ..Default::default()
        });
    parent.requests = vec![quil_types::proto::global::MessageBundle {
        requests: vec![quil_types::proto::global::MessageRequest {
            request: Some(quil_types::proto::global::message_request::Request::Shard(
                header,
            )),
            ..Default::default()
        }],
        ..Default::default()
    }];
    body_root(&mut parent);
    parent
}

/// The defect itself, through the real reward path: the parent carries a
/// certified shard header, and the ingest finalization runs first adds data
/// to that shard, which moves the reward the header credits into the prover
/// tree. A private execution before the ingest therefore yields another root
/// than the finalized execution, and a voter that accepts it votes for a chain
/// no member can execute: every archive logged a prover root mismatch and
/// GLOBAL stalled (devnet, 2026-10-30). The archive waits instead, then accepts
/// only the root finalization published.
#[test]
fn an_archive_never_accepts_a_root_its_finalized_execution_does_not_reproduce() {
    let global = Arc::new(quil_crypto::FalconSigner::generate());
    let shard = quil_crypto::FalconSigner::generate();
    let rig = Rig::over(global.clone(), rewarding_fixture(&global, &shard, false));
    let mut parent = with_shard_header(state_frame(&rig.source, 1, 41, rig.genesis), &shard);
    parent.header.as_mut().unwrap().prover = vec![0x42; 32];
    certify(&mut parent, &rig.signer, 0);
    rig.put(&parent);
    let context = rig.context(&parent);

    // What executing the parent yields without and with the ingest.
    let child_of = |extra: bool| {
        let twin = rewarding_fixture(&global, &shard, extra);
        twin.source.materialize(&parent).unwrap();
        state_frame(&twin.source, 2, context.view, context.parent)
    };
    let private_child = child_of(false);
    let finalized_child = child_of(true);
    let root = |child: &GlobalFrame| {
        child
            .header
            .as_ref()
            .unwrap()
            .prover_tree_commitment
            .clone()
    };
    assert_ne!(
        root(&private_child),
        root(&finalized_child),
        "the ingest moves the reward basis, so the two executions declare different prover roots"
    );

    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (pipeline, _) = pipeline(&rig, prover(&parent), 8);
    let pipeline = pipeline.with_sequenced_ingest({
        let (ready, crdt) = (ready.clone(), rig.source.hypergraph.clone());
        let done = std::sync::atomic::AtomicBool::new(false);
        Arc::new(move |_: &GlobalFrame| -> quil_types::error::Result<bool> {
            if !ready.load(Ordering::SeqCst) {
                return Ok(false);
            }
            if !done.swap(true, Ordering::SeqCst) {
                let (location, value) = app_data(2);
                crdt.add_vertex(&location, &value)?;
                crdt.commit(0)?;
            }
            Ok(true)
        })
    });
    assert!(pipeline.offer(parent.clone()));
    assert!(matches!(pipeline.step(1), FinalizationStep::Retry(_)));

    let check = |seam: &GlobalSeamProposer, child: &GlobalFrame| {
        seam.verify_or_defer(
            context,
            id(child),
            Some(crate::consensus_wire::encode_global_frame(child).unwrap()),
        )
    };
    let seam = rig.seam(&parent).with_publication_priority(Duration::ZERO);
    for _ in 0..3 {
        assert!(
            check(&seam, &private_child).is_err(),
            "the vote accepted prover root {} of a private execution before the sequenced \
             ingest; the finalized execution yields {}",
            hex::encode(root(&private_child)),
            hex::encode(root(&finalized_child)),
        );
    }

    ready.store(true, Ordering::SeqCst);
    assert!(matches!(
        pipeline.step(1),
        FinalizationStep::Published { .. }
    ));
    assert_eq!(
        check(&seam, &private_child),
        Ok(false),
        "published: the root of the private execution is refused"
    );
    assert_eq!(
        check(&seam, &finalized_child),
        Ok(true),
        "and the finalized root accepted"
    );
}

/// A finalizer over `pipeline`, as an archive's consensus host builds it.
fn finalizer_over(
    rig: &Rig,
    pipeline: &Arc<GlobalFinalizationPipeline>,
) -> Arc<crate::cw_global_seams::GlobalSeamFinalizer> {
    let (jobs, _) = tokio::sync::mpsc::unbounded_channel();
    Arc::new(
        crate::cw_global_seams::GlobalSeamFinalizer::new(
            rig.clock.clone(),
            jobs,
            Arc::new(|_, _| {}),
            None,
            vec![],
        )
        .with_pipeline(Some(pipeline.clone())),
    )
}

/// Consensus finalizes `frame` on this node from its certificate alone.
fn finalize_without_body(
    finalizer: &crate::cw_global_seams::GlobalSeamFinalizer,
    frame: &GlobalFrame,
) {
    use quil_cw_consensus::adapters::FrameFinalizer as _;
    finalizer.on_finalized(
        frame.header.as_ref().unwrap().rank,
        id(frame),
        None,
        None,
        false,
    );
}

/// The residual of the wait for publication, through the real reward path:
/// consensus finalized the parent here from its certificate alone, so the
/// finalizer queued nothing and nothing said the parent was finalized. Once
/// the body arrived, the leader executed the parent privately, without the
/// application frames its publication ingests, and proposed a prover root
/// the published execution did not reproduce; the other archives refused it
/// until the next view (about 1.5 an hour on one archive, 2026-10-31). The
/// leader now hands the arrived body to publication and proposes on the
/// published state.
#[test]
fn a_leader_holding_only_its_finalized_parents_certificate_proposes_on_the_published_state() {
    use crate::outage::test_logs::CapturedLogs;
    let logs = CapturedLogs::default();
    let _logs = logs.install();
    let global = Arc::new(quil_crypto::FalconSigner::generate());
    let shard = quil_crypto::FalconSigner::generate();
    let rig = Rig::over(global.clone(), rewarding_fixture(&global, &shard, false));
    let mut parent = with_shard_header(state_frame(&rig.source, 1, 41, rig.genesis), &shard);
    parent.header.as_mut().unwrap().prover = vec![0x42; 32];
    certify(&mut parent, &rig.signer, 0);
    let context = rig.context(&parent);
    let child_of = |extra: bool| {
        let twin = rewarding_fixture(&global, &shard, extra);
        twin.source.materialize(&parent).unwrap();
        state_frame(&twin.source, 2, context.view, context.parent)
    };
    let root = |child: &GlobalFrame| {
        child
            .header
            .as_ref()
            .unwrap()
            .prover_tree_commitment
            .clone()
    };
    let (private_root, finalized_root) = (root(&child_of(false)), root(&child_of(true)));
    assert_ne!(
        private_root, finalized_root,
        "the ingest moves the reward basis"
    );

    let (pipeline, _) = pipeline(&rig, prover(&parent), 8);
    let pipeline = Arc::new(pipeline.with_sequenced_ingest({
        let crdt = rig.source.hypergraph.clone();
        let done = std::sync::atomic::AtomicBool::new(false);
        Arc::new(move |_: &GlobalFrame| -> quil_types::error::Result<bool> {
            if !done.swap(true, Ordering::SeqCst) {
                let (location, value) = app_data(2);
                crdt.add_vertex(&location, &value)?;
                crdt.commit(0)?;
            }
            Ok(true)
        })
    }));
    let finalizer = finalizer_over(&rig, &pipeline);
    let seam = rig.seam(&parent).with_finalizer(finalizer.clone());
    let finalized_child = child_of(true);
    let vote = |seam: &GlobalSeamProposer| {
        seam.verify_or_defer(
            context,
            id(&finalized_child),
            Some(crate::consensus_wire::encode_global_frame(&finalized_child).unwrap()),
        )
    };

    finalize_without_body(&finalizer, &parent);
    assert_eq!(pipeline.queued(), 0, "nothing to queue without the body");
    assert!(seam.propose_with_context(context).is_none(), "no body yet");
    assert!(vote(&seam).is_err(), "the vote waits for the body too");

    // The body arrives over the block channel.
    rig.put(&parent);
    for attempt in 0..3 {
        assert!(
            seam.propose_with_context(context).is_none(),
            "attempt {attempt}: the leader executed its finalized parent privately before publishing it"
        );
        assert!(vote(&seam).is_err(), "attempt {attempt}: the vote waits");
    }
    assert_eq!(
        pipeline.queued(),
        1,
        "the arrived body is queued to publish"
    );
    assert_eq!(rig.source.last_materialized_frame(), 0);
    assert!(!rig.executor.busy(), "waiting takes no lease");

    assert!(matches!(
        pipeline.step(1),
        FinalizationStep::Published { .. }
    ));
    assert_eq!(
        vote(&seam),
        Ok(true),
        "then it votes on the published state"
    );
    let (_, bytes) = seam
        .propose_with_context(context)
        .expect("and proposes on it");
    let proposed = crate::consensus_wire::decode_global_frame(&bytes).unwrap();
    assert_eq!(
        hex::encode(root(&proposed)),
        hex::encode(&finalized_root),
        "the proposal declares the published root, not the private one {}",
        hex::encode(&private_root)
    );

    let began = logs.lines_with("holds only the certificate of: executing above it first");
    assert_eq!(began.len(), 1, "one line for the wait: {began:?}");
    assert!(
        began[0].contains("INFO") && began[0].contains("finalized_view=41"),
        "{}",
        began[0]
    );
    let ended = logs.lines_with("its body arrived and was queued to publish");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert!(
        ended[0].contains("INFO")
            && ended[0].contains("finalized_view=41")
            && ended[0].contains("waited_ms=")
            && ended[0].contains("past_patience=false"),
        "{}",
        ended[0]
    );
    assert!(logs
        .lines_with("stop waiting for a finalized frame")
        .is_empty());
}

/// The bound: a finalized body that never arrives holds proposals and votes
/// at most the patience after its finalization, with one warning when it
/// runs out; then they proceed as before, so GLOBAL never waits on a body no
/// peer delivers. Its publication by the archive poller later ends it.
#[test]
fn a_finalized_body_that_never_arrives_holds_proposals_and_votes_only_until_the_patience() {
    use crate::outage::test_logs::CapturedLogs;
    let logs = CapturedLogs::default();
    let _logs = logs.install();
    let rig = Rig::new();
    let parent = certified_deploy(&rig);
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let pipeline = Arc::new(sequenced_pipeline(&rig, &parent, &ready));
    let finalizer = finalizer_over(&rig, &pipeline);
    let patience = Duration::from_millis(300);
    let seam = rig
        .seam(&parent)
        .with_finalizer(finalizer.clone())
        .with_unheld_patience(patience);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();

    finalize_without_body(&finalizer, &parent);
    let started = std::time::Instant::now();
    assert!(seam.propose_with_context(context).is_none());
    let waiting = seam.verify_or_defer(context, id(&child), Some(encoded.clone()));
    if started.elapsed() < patience {
        assert!(waiting.is_err(), "within the patience the vote waits");
    }
    std::thread::sleep(patience + Duration::from_millis(50));
    assert_eq!(
        seam.verify_or_defer(context, id(&child), Some(encoded.clone())),
        Ok(false),
        "past the patience the vote no longer waits: without the body it cannot check the proposal"
    );
    assert!(
        seam.propose_with_context(context).is_none(),
        "nor build one"
    );
    let stopped = logs.lines_with("stop waiting for a finalized frame");
    assert_eq!(
        stopped.len(),
        1,
        "one warning when the patience runs out: {stopped:?}"
    );
    assert!(
        stopped[0].contains("WARN")
            && stopped[0].contains("finalized_view=41")
            && stopped[0].contains("action=\"check\""),
        "{}",
        stopped[0]
    );

    // A copy that later turns up (here the parent as a durable candidate,
    // which the unheld check does not read) is executed as before.
    rig.clock
        .put_global_clock_frame_candidate(&parent, &crate::cw_global_seams::NoopTxn)
        .unwrap();
    assert_eq!(
        seam.verify_or_defer(context, id(&child), Some(encoded)),
        Ok(true),
        "past the patience a vote executes the parent as before"
    );
    assert_eq!(rig.source.last_materialized_frame(), 0);

    // The archive poller publishes it.
    assert!(pipeline.offer_synced(&parent));
    assert!(matches!(
        pipeline.step(1),
        FinalizationStep::Published { .. }
    ));
    assert!(seam.propose_with_context(context).is_some());
    let ended = logs.lines_with("held only the certificate of: it published");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert!(ended[0].contains("past_patience=true"), "{}", ended[0]);
    assert_eq!(
        logs.lines_with("stop waiting for a finalized frame").len(),
        1,
        "warned once"
    );
}

/// The archive poller publishing the frame ends the wait at once, and a
/// node whose publication ingests nothing never waits: there a private
/// execution reproduces the published one.
#[test]
fn publication_ends_the_wait_for_a_finalized_body_and_only_ingesting_archives_wait() {
    let rig = Rig::new();
    let parent = certified_deploy(&rig);
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let queue = Arc::new(sequenced_pipeline(&rig, &parent, &ready));
    let finalizer = finalizer_over(&rig, &queue);
    let seam = rig.seam(&parent).with_finalizer(finalizer.clone());
    let context = rig.context(&parent);
    finalize_without_body(&finalizer, &parent);
    assert!(seam.propose_with_context(context).is_none());
    assert!(queue.offer_synced(&parent));
    assert!(matches!(queue.step(1), FinalizationStep::Published { .. }));
    assert!(
        seam.propose_with_context(context).is_some(),
        "published: the proposal no longer waits, well within the patience"
    );

    let rig = Rig::new();
    let parent = certified_deploy(&rig);
    rig.clock
        .put_global_clock_frame_candidate(&parent, &crate::cw_global_seams::NoopTxn)
        .unwrap();
    let (plain, _) = pipeline(&rig, prover(&parent), 8);
    let finalizer = finalizer_over(&rig, &Arc::new(plain));
    let seam = rig.seam(&parent).with_finalizer(finalizer.clone());
    finalize_without_body(&finalizer, &parent);
    assert!(
        seam.propose_with_context(rig.context(&parent)).is_some(),
        "without sequenced ingest the parent is executed at once"
    );
}
