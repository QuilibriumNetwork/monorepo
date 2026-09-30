//! Real Falcon finalizations over fixture VDF/execution crypto. These exercise
//! the live owners and retained caches, without reopening the database.
use super::*;

#[test]
fn busy_publication_readers_refuse_the_batch_without_advancing_public_state() {
    for busy in ["snapshot", "clock", "registry"] {
        let rig = Rig::new();
        let mut frame = rig.deploy();
        certify(&mut frame, &rig.signer, 0);
        let before = rig.db.inner().latest_sequence_number();
        let run = || rig.executor.finalize_frame(&frame, &rig.verifier);
        let result = match busy {
            "snapshot" => {
                let _held = rig
                    .source
                    .hypergraph
                    .prepare_snapshot_publication(vec![7; 32], 0)
                    .unwrap();
                run()
            }
            "clock" => {
                let _held = rig.clock.prepare_execution_publication().unwrap();
                run()
            }
            "registry" => rig
                .source
                .eviction_registry
                .as_ref()
                .unwrap()
                .read(|_| run()),
            _ => unreachable!(),
        };
        assert!(result.is_err(), "accepted while {busy} was busy");
        assert_eq!(rig.db.inner().latest_sequence_number(), before);
        assert_eq!(rig.source.last_materialized_frame(), 0);
        assert_eq!(rig.source.current_frame.as_ref().unwrap().materialized(), 0);
        assert!(rig
            .source
            .execution_manager
            .global_venue_fee_snapshot(1)
            .unwrap()
            .is_none());
        assert!(run().unwrap().is_some());
    }
}

#[test]
fn finalized_deployment_adopts_live_state_and_supports_the_next_frame_and_replay() {
    let rig = Rig::new();
    let expected = Fixture::new(Some(rig.signer.public_key()));
    rig.clock.warm_global_frame_cache().unwrap();
    let genesis = rig.clock.get_latest_global_clock_frame().unwrap();
    rig.source
        .hypergraph
        .publish_snapshot_capturing(vec![99; 32], 0)
        .unwrap();
    let old_view = rig
        .source
        .hypergraph
        .acquire_snapshot(&[99; 32])
        .unwrap()
        .db_snapshot
        .unwrap();
    let mut input = rig.deploy();
    certify(&mut input, &rig.signer, 0);
    expected.source.materialize(&input).unwrap();
    let current = rig.source.current_frame.as_ref().unwrap().clone();
    let registry = rig.source.eviction_registry.as_ref().unwrap().clone();
    let fee_manager = rig.source.execution_manager.clone();
    rig.source.flag_prover_root_mismatch(vec![77; 32]);
    let result = rig
        .executor
        .finalize_frame(&input, &rig.verifier)
        .unwrap()
        .unwrap();
    assert_eq!((result.processed, result.skipped), (1, 0));
    assert_eq!(
        result.prover_root,
        expected
            .source
            .hypergraph
            .current_forest_phase_root(&[0xff; 32], 0)
            .unwrap()
    );
    assert_eq!(rig.source.last_materialized_frame(), 1);
    assert_eq!(current.materialized(), 1);
    assert_eq!(rig.clock.get_latest_global_clock_frame().unwrap(), input);
    assert_eq!(rig.clock.get_global_clock_frame(0).unwrap(), genesis);
    assert_eq!(
        rig.source.hypergraph.total_size(),
        expected.source.hypergraph.total_size()
    );
    assert_eq!(
        rig.source.hypergraph.global_commitments_checked().unwrap(),
        expected
            .source
            .hypergraph
            .global_commitments_checked()
            .unwrap()
    );
    assert!(fee_manager.global_venue_fee_snapshot(1).unwrap().is_some());
    assert!(!rig.source.prover_root_mismatch_detected());
    assert_eq!(rig.source.fork_target_root(), None);
    let addresses = |registry: &dyn ProverRegistry| {
        registry
            .get_active_provers(&[], 1)
            .unwrap()
            .into_iter()
            .map(|p| p.address)
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(
        addresses(registry.as_ref()),
        addresses(expected.source.prover_registry.as_ref())
    );
    let new_view = rig
        .source
        .hypergraph
        .acquire_snapshot(&result.prover_root)
        .unwrap()
        .db_snapshot
        .unwrap();
    let cursor_key = quil_store::encoding::global_materialized_cursor_key();
    assert_eq!(
        old_view.read_record(&cursor_key).unwrap(),
        Some(0u64.to_be_bytes().to_vec())
    );
    assert_eq!(
        new_view.read_record(&cursor_key).unwrap(),
        Some(1u64.to_be_bytes().to_vec())
    );
    let after_commit = rig.db.inner().latest_sequence_number();
    assert!(rig
        .executor
        .finalize_frame(&input, &rig.verifier)
        .unwrap()
        .is_none());
    assert_eq!(rig.db.inner().latest_sequence_number(), after_commit);
    assert_eq!(
        rig.source.hypergraph.total_size(),
        expected.source.hypergraph.total_size()
    );
    // Fresh proposal preparation must see the new providers and local receipt.
    assert!(rig
        .executor
        .prepare(rig.context(&input), 1, &rig.blocks, &rig.verifier, true)
        .is_ok());
    let mut next = state_frame(&rig.source, 2, 73, id(&input));
    certify_parent(
        &mut next,
        &rig.signer,
        0,
        input.header.as_ref().unwrap().rank,
    );
    assert!(rig
        .executor
        .finalize_frame(&next, &rig.verifier)
        .unwrap()
        .is_some());
    assert_eq!(current.materialized(), 2);
    assert_eq!(rig.clock.get_latest_global_clock_frame().unwrap(), next);
    assert_eq!(
        fee_manager
            .global_venue_fee_snapshot(2)
            .unwrap()
            .unwrap()
            .frame_number,
        2
    );
    assert!(rig
        .source
        .capture_execution_branch(limits())
        .unwrap()
        .completed_checkpoint()
        .unwrap()
        .unwrap()
        .matches_frame(&next)
        .unwrap());
}

#[test]
fn finalization_rejects_certificates_parent_coordinates_and_substituted_state() {
    for invalid in [
        "no-cert",
        "epoch",
        "view",
        "parent-view",
        "parent-digest",
        "pre-state",
        "body",
        "height",
        "vdf",
    ] {
        let rig = Rig::new();
        let mut frame = rig.deploy();
        match invalid {
            "epoch" => certify(&mut frame, &rig.signer, 1),
            "parent-view" => certify_parent(&mut frame, &rig.signer, 0, 1),
            "no-cert" => {}
            _ => certify(&mut frame, &rig.signer, 0),
        }
        match invalid {
            "view" => frame.header.as_mut().unwrap().rank += 1,
            "parent-digest" => frame.header.as_mut().unwrap().parent_selector = vec![7; 32],
            "pre-state" => frame.header.as_mut().unwrap().prover_tree_commitment[0] ^= 1,
            "body" => frame.requests.clear(),
            "height" => frame.header.as_mut().unwrap().frame_number += 1,
            "vdf" => {
                frame.header.as_mut().unwrap().output[0] = 0xfe;
                certify(&mut frame, &rig.signer, 0);
            }
            _ => {}
        }
        let before = rig.db.inner().latest_sequence_number();
        assert!(
            rig.executor.finalize_frame(&frame, &rig.verifier).is_err(),
            "accepted {invalid}"
        );
        assert_eq!(
            rig.db.inner().latest_sequence_number(),
            before,
            "wrote for {invalid}"
        );
        assert_eq!(rig.source.last_materialized_frame(), 0);
        assert_eq!(rig.source.current_frame.as_ref().unwrap().materialized(), 0);
        assert_eq!(
            rig.clock
                .get_latest_global_clock_frame()
                .unwrap()
                .header
                .unwrap()
                .frame_number,
            0
        );
    }
}

#[test]
fn repeated_finalization_cannot_substitute_another_body_at_the_completed_height() {
    let rig = Rig::new();
    let mut frame = rig.deploy();
    certify(&mut frame, &rig.signer, 0);
    rig.executor.finalize_frame(&frame, &rig.verifier).unwrap();
    frame.requests.clear();
    body_root(&mut frame);
    certify(&mut frame, &rig.signer, 0);
    // The fixture VDF does not bind fields, so this reaches the execution receipt
    // check rather than being rejected merely by cryptography or body hashing.
    let before = rig.db.inner().latest_sequence_number();
    assert!(rig.executor.finalize_frame(&frame, &rig.verifier).is_err());
    assert_eq!(rig.db.inner().latest_sequence_number(), before);
}

#[test]
fn receipt_less_certified_head_is_authenticated_by_its_certified_child() {
    let rig = Rig::new();
    let mut old = rig.deploy();
    certify(&mut old, &rig.signer, 0);
    rig.source.materialize(&old).unwrap();
    save(rig.clock.as_ref(), &old);
    rig.db
        .inner()
        .delete(quil_store::encoding::global_execution_checkpoint_key())
        .unwrap();
    let mut next = state_frame(&rig.source, 2, 73, id(&old));
    certify_parent(&mut next, &rig.signer, 0, old.header.as_ref().unwrap().rank);
    let before = rig.db.inner().latest_sequence_number();
    // No receipt to replay against, and a child declaring another parent
    // state is refused without publishing anything.
    assert!(rig.executor.finalize_frame(&old, &rig.verifier).is_err());
    let mut substituted = next.clone();
    substituted.header.as_mut().unwrap().prover_tree_commitment[0] ^= 1;
    certify_parent(&mut substituted, &rig.signer, 0, old.header.as_ref().unwrap().rank);
    assert!(rig.executor.finalize_frame(&substituted, &rig.verifier).is_err());
    assert_eq!(rig.db.inner().latest_sequence_number(), before);
    assert_eq!(rig.source.last_materialized_frame(), 1);
    // The certified child whose parent roots equal the local state publishes
    // and leaves a receipt.
    assert!(rig.executor.finalize_frame(&next, &rig.verifier).unwrap().is_some());
    assert_eq!(rig.source.last_materialized_frame(), 2);
    assert!(rig
        .db
        .inner()
        .get(quil_store::encoding::global_execution_checkpoint_key())
        .unwrap()
        .is_some());
    assert!(rig.executor.finalize_frame(&next, &rig.verifier).unwrap().is_none());
}

#[test]
fn intervening_write_abandons_publication_and_a_fresh_attempt_can_succeed() {
    let fixture = Fixture::new(None);
    let input = frame(
        1,
        fixture
            .source
            .hypergraph
            .current_forest_phase_root(&[0xff; 32], 0)
            .unwrap(),
    );
    let root = fixture
        .source
        .hypergraph
        .global_commitments_checked()
        .unwrap();
    let notifications = fixture.notifications.load(Ordering::SeqCst);
    let result = fixture
        .source
        .materialize_atomically(&input, limits(), |_| {
            fixture
                .db
                .inner()
                .put(b"external-maintenance", b"changed")
                .unwrap();
            Ok(true)
        });
    assert!(result.is_err());
    assert_eq!(fixture.source.last_materialized_frame(), 0);
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 0);
    assert_eq!(fixture.current.materialized(), 0);
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), notifications);
    assert_eq!(
        fixture
            .source
            .hypergraph
            .global_commitments_checked()
            .unwrap(),
        root
    );
    assert!(fixture
        .source
        .execution_manager
        .global_venue_fee_snapshot(1)
        .unwrap()
        .is_none());
    assert!(fixture.clock.get_global_clock_frame(1).is_err());
    assert!(fixture.source.hypergraph.acquire_snapshot(&[]).is_none());
    assert!(fixture
        .source
        .materialize_atomically(&input, limits(), |_| Ok(true))
        .unwrap()
        .is_some());
    assert_eq!(fixture.current.materialized(), 1);
    assert_eq!(
        fixture.notifications.load(Ordering::SeqCst),
        notifications + 1
    );
}

#[test]
fn consensus_candidate_writes_during_execution_do_not_abandon_publication() {
    let rig = Rig::new();
    let mut input = rig.deploy();
    certify(&mut input, &rig.signer, 0);
    let mut next = input.clone();
    let header = next.header.as_mut().unwrap();
    header.frame_number = 2;
    header.rank = 9;
    header.output = vec![5; 516];
    let result = rig
        .source
        .materialize_atomically(&input, limits(), |_| {
            // The next view's candidate lands after capture, as it would while
            // this frame executes.
            rig.clock
                .put_global_clock_frame_candidate(&next, &crate::cw_global_seams::NoopTxn)?;
            Ok(true)
        })
        .unwrap()
        .unwrap();
    assert_eq!((result.processed, result.skipped), (1, 0));
    assert_eq!(rig.source.last_materialized_frame(), 1);
    assert_eq!(rig.clock.get_latest_global_clock_frame().unwrap(), input);
    assert_eq!(
        rig.clock
            .get_global_clock_frame_candidate(2, id(&next).as_ref())
            .unwrap(),
        next
    );
    // A general write in the same window still abandons the attempt.
    let mut later = state_frame(&rig.source, 2, 73, id(&input));
    certify_parent(&mut later, &rig.signer, 0, input.header.as_ref().unwrap().rank);
    let before = rig.db.inner().latest_sequence_number();
    assert!(rig
        .source
        .materialize_atomically(&later, limits(), |_| {
            rig.db.inner().put(b"external-maintenance", b"changed").unwrap();
            Ok(true)
        })
        .is_err());
    assert_eq!(rig.db.inner().latest_sequence_number(), before + 1);
    assert_eq!(rig.source.last_materialized_frame(), 1);
}

#[test]
fn application_data_ingested_between_global_frames_keeps_the_executed_base() {
    // Archives ingest application frames between GLOBAL frames. That moves
    // bucket roots and world size, not the GLOBAL-owned prover tree. Binding
    // them in the receipt halted GLOBAL on the first state-changing ingest.
    let rig = Rig::new();
    let mut input = rig.deploy();
    certify(&mut input, &rig.signer, 0);
    assert!(rig.executor.finalize_frame(&input, &rig.verifier).unwrap().is_some());
    // The next leader declared its state before the ingest reached it.
    let mut next = state_frame(&rig.source, 2, 73, id(&input));
    certify_parent(&mut next, &rig.signer, 0, input.header.as_ref().unwrap().rank);
    let buckets = rig.source.hypergraph.global_commitments_checked().unwrap();
    let size = rig.source.hypergraph.total_size();
    let location = quil_hypergraph::addressing::Location {
        app_address: [0x11; 32],
        data_address: [0x22; 32],
    };
    rig.source
        .hypergraph
        .add_vertex(&location, b"ingested application data")
        .unwrap();
    rig.source.hypergraph.commit(1).unwrap();
    assert!(
        rig.source.hypergraph.global_commitments_checked().unwrap() != buckets
            || rig.source.hypergraph.total_size() != size,
        "the ingest must move non-GLOBAL-owned state"
    );
    assert!(rig
        .executor
        .prepare(rig.context(&input), 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
    assert!(rig.executor.finalize_frame(&next, &rig.verifier).unwrap().is_some());
    assert_eq!(rig.source.last_materialized_frame(), 2);
}

#[test]
fn a_prover_tree_reconciled_after_divergence_keeps_the_certified_base_usable() {
    // A diverged archive re-syncs its prover tree from peers, outside
    // execution, leaving a stale receipt. Refusing on it halted GLOBAL live
    // once two of four archives had reconciled.
    let rig = Rig::new();
    let mut input = rig.deploy();
    certify(&mut input, &rig.signer, 0);
    assert!(rig.executor.finalize_frame(&input, &rig.verifier).unwrap().is_some());
    let key = quil_crypto::FalconSigner::generate().public_key().to_vec();
    crate::genesis::seed_active_prover_on_filter(&rig.source.hypergraph, &key, 1000, 2, &[]).unwrap();
    // As the reconcile does once converged.
    rig.source.record_current_prover_root();
    // The network's next frame declares the reconciled prover tree.
    let mut next = state_frame(&rig.source, 2, 73, id(&input));
    certify_parent(&mut next, &rig.signer, 0, input.header.as_ref().unwrap().rank);
    assert!(rig
        .executor
        .prepare(rig.context(&input), 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
    assert!(rig.executor.finalize_frame(&next, &rig.verifier).unwrap().is_some());
    assert_eq!(rig.source.last_materialized_frame(), 2);
}

fn store_canonical(fixture: &Fixture, frame: &GlobalFrame) {
    let txn = fixture.clock.new_transaction(false).unwrap();
    fixture.clock.put_global_clock_frame(frame, txn.as_ref()).unwrap();
    txn.commit().unwrap();
}

fn execution_record(fixture: &Fixture, key: Vec<u8>) -> Option<Vec<u8>> {
    fixture.db.inner().get(key).unwrap()
}

// A frame stored canonically before execution (sync ahead of the cursor, or
// the finalization fallback) executes in a branch and publishes state,
// receipt and cursor together, instead of writing its effects in place.
#[test]
fn a_canonical_frame_executes_atomically_and_then_replays() {
    use crate::frame_materializer::CanonicalAttempt;
    let fixture = Fixture::new(None);
    let root = fixture
        .source
        .hypergraph
        .current_forest_phase_root(&[0xff; 32], 0)
        .unwrap();
    let input = frame(1, root);
    assert!(matches!(
        fixture.source.materialize_canonical_atomically(&input, limits()),
        CanonicalAttempt::Unavailable(_)
    ), "a frame that is not canonical is not executed");
    store_canonical(&fixture, &input);
    // The canonical clock is ahead of execution, as after a sync.
    store_canonical(&fixture, &frame(2, [7; 32]));
    let mut other = input.clone();
    other.header.as_mut().unwrap().output = vec![9; 516];
    assert!(matches!(
        fixture.source.materialize_canonical_atomically(&other, limits()),
        CanonicalAttempt::Unavailable(_)
    ), "another body at the canonical height is refused");
    assert!(matches!(
        fixture.source.materialize_canonical_atomically(&frame(2, [7; 32]), limits()),
        CanonicalAttempt::Unavailable(_)
    ), "only the next height executes");
    match fixture.source.materialize_canonical_atomically(&input, limits()) {
        CanonicalAttempt::Published(result) => assert_eq!(result.skipped, 0),
        other => panic!("expected publication, got {other:?}"),
    }
    assert_eq!(fixture.source.last_materialized_frame(), 1);
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 1);
    assert_eq!(fixture.current.materialized(), 1);
    assert!(execution_record(&fixture, quil_store::encoding::global_execution_checkpoint_key()).is_some());
    assert!(execution_record(&fixture, quil_store::encoding::global_execution_pending_key()).is_none());
    assert_eq!(fixture.clock.get_global_clock_frame(1).unwrap(), input);
    assert_eq!(
        fixture.clock.get_latest_global_clock_frame().unwrap().header.unwrap().frame_number,
        2,
        "the canonical clock is not rewritten"
    );
    assert!(matches!(
        fixture.source.materialize_canonical_atomically(&input, limits()),
        CanonicalAttempt::Replayed
    ));
}

// The in-place path's unfinished-execution marker refuses every retry. A
// canonical attempt that fails at publication leaves no marker, no cursor
// change and no receipt, and a later attempt succeeds.
#[test]
fn a_failed_canonical_attempt_leaves_nothing_to_recover() {
    use crate::frame_materializer::CanonicalAttempt;
    let fixture = Fixture::new(None);
    let root = fixture
        .source
        .hypergraph
        .current_forest_phase_root(&[0xff; 32], 0)
        .unwrap();
    let input = frame(1, root);
    store_canonical(&fixture, &input);
    {
        let _held = fixture.clock.prepare_execution_publication().unwrap();
        assert!(matches!(
            fixture.source.materialize_canonical_atomically(&input, limits()),
            CanonicalAttempt::Unavailable(_)
        ));
    }
    assert_eq!(fixture.source.last_materialized_frame(), 0);
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 0);
    assert!(execution_record(&fixture, quil_store::encoding::global_execution_pending_key()).is_none());
    assert!(execution_record(&fixture, quil_store::encoding::global_execution_checkpoint_key()).is_none());
    assert!(matches!(
        fixture.source.materialize_canonical_atomically(&input, limits()),
        CanonicalAttempt::Published(_)
    ));
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 1);
}
