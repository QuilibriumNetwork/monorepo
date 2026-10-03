use super::*;
use crate::{OverlayHypergraphStore, RocksClockStore};
use quil_types::store::{HypergraphStore, RequestOutcome, RequestStatus};

fn limits() -> quil_forest::OverlayLimits {
    quil_forest::OverlayLimits {
        max_delta_bytes: 2 << 20,
        max_delta_entries: 10_000,
        max_record_bytes: 64 << 10,
        max_read_bytes: 8 << 20,
        max_read_operations: 10_000,
        max_cursors: 16,
    }
}
fn database() -> (tempfile::TempDir, quil_forest::CoordinatedDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
    (dir, db)
}
fn branch(db: quil_forest::CoordinatedDb) -> (Arc<ExecutionOverlay>, OverlayClockStore) {
    let overlay = Arc::new(ExecutionOverlay::capture(db, limits()).unwrap());
    let store = OverlayClockStore::new(overlay.clone());
    (overlay, store)
}
fn frame(n: u64) -> g::GlobalFrame {
    g::GlobalFrame {
        header: Some(g::GlobalFrameHeader {
            frame_number: n,
            rank: n,
            prover: vec![9],
            output: vec![n as u8; 32],
            ..Default::default()
        }),
        requests: vec![
            g::MessageBundle {
                timestamp: n as _,
                ..Default::default()
            },
            g::MessageBundle::default(),
        ],
    }
}
fn identity(f: &g::GlobalFrame) -> [u8; 32] {
    quil_crypto::poseidon::hash_bytes_to_32(&f.header.as_ref().unwrap().output).unwrap()
}
fn app(filter: &[u8], n: u64) -> g::AppShardFrame {
    g::AppShardFrame {
        header: Some(g::FrameHeader {
            address: filter.to_vec(),
            frame_number: n,
            rank: n,
            output: vec![n as u8; 32],
            ..Default::default()
        }),
        ..Default::default()
    }
}
fn outcomes() -> Vec<RequestOutcome> {
    vec![RequestOutcome {
        status: RequestStatus::Failed,
        error: "rejected operation".into(),
    }]
}
fn put(store: &dyn ClockStore, f: &g::GlobalFrame) {
    let t = store.new_transaction(false).unwrap();
    store.put_global_clock_frame(f, t.as_ref()).unwrap();
    t.commit().unwrap();
}
fn proposal(n: u64) -> g::GlobalProposal {
    g::GlobalProposal {
        state: Some(frame(n)),
        parent_quorum_certificate: Some(g::QuorumCertificate {
            rank: n - 1,
            ..Default::default()
        }),
        prior_rank_timeout_certificate: Some(g::TimeoutCertificate {
            rank: n - 2,
            ..Default::default()
        }),
        vote: Some(g::ProposalVote {
            rank: n,
            selector: vec![9],
            ..Default::default()
        }),
    }
}

#[test]
fn outcomes_do_not_overwrite_certification_and_legacy_decoding_is_bounded() {
    let (dir, db) = database();
    let store = RocksClockStore::new(db.clone());
    let expected = proposal(5);
    let t = store.new_transaction(false).unwrap();
    store
        .put_certified_global_state(&expected, t.as_ref())
        .unwrap();
    t.commit().unwrap();
    let certified = db
        .get(e::clock_global_certified_state_key(5))
        .unwrap()
        .unwrap();
    assert_eq!(certified.len(), 24);
    store
        .put_global_clock_frame_outcomes(5, &outcomes())
        .unwrap();
    assert_eq!(store.get_certified_global_state(5).unwrap(), expected);
    assert_eq!(
        db.get(e::clock_global_certified_state_key(5))
            .unwrap()
            .unwrap(),
        certified
    );
    assert_eq!(
        store.get_global_clock_frame_outcomes(5).unwrap(),
        outcomes()
    );
    let legacy = crate::clock_codec::encode_outcomes(&outcomes(), 1024).unwrap();
    db.put(e::clock_global_certified_state_key(6), &legacy)
        .unwrap();
    assert_eq!(
        store.get_global_clock_frame_outcomes(6).unwrap(),
        outcomes()
    );
    store.put_global_clock_frame_outcomes(6, &[]).unwrap();
    assert!(store.get_global_clock_frame_outcomes(6).unwrap().is_empty());
    db.put(e::clock_global_certified_state_key(7), certified)
        .unwrap();
    assert!(store.get_global_clock_frame_outcomes(7).unwrap().is_empty());
    // A legacy 24-byte outcome is indistinguishable from a certified-state row.
    let ambiguous = vec![RequestOutcome {
        status: RequestStatus::Failed,
        error: "x".repeat(15),
    }];
    let ambiguous = crate::clock_codec::encode_outcomes(&ambiguous, 1024).unwrap();
    assert_eq!(ambiguous.len(), 24);
    db.put(e::clock_global_certified_state_key(8), ambiguous)
        .unwrap();
    assert!(store.get_global_clock_frame_outcomes(8).unwrap().is_empty());
    let mut invalid_status = legacy.clone();
    invalid_status[4] = 255;
    let mut trailing = legacy.clone();
    trailing.push(0);
    for invalid in [
        u32::MAX.to_be_bytes().to_vec(),
        legacy[..legacy.len() - 1].to_vec(),
        invalid_status,
        trailing,
    ] {
        db.put(e::clock_global_frame_outcomes_key(9), invalid)
            .unwrap();
        assert!(store.get_global_clock_frame_outcomes(9).is_err());
    }
    drop(store);
    drop(db);
    let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
    let store = RocksClockStore::new(db);
    assert_eq!(store.get_certified_global_state(5).unwrap(), expected);
    assert_eq!(
        store.get_global_clock_frame_outcomes(5).unwrap(),
        outcomes()
    );
}

fn fill(store: &dyn ClockStore) {
    put(store, &frame(3));
    let t = store.new_transaction(false).unwrap();
    store
        .put_global_clock_frame_candidate(&frame(4), t.as_ref())
        .unwrap();
    store
        .put_certified_global_state(&proposal(5), t.as_ref())
        .unwrap();
    store
        .put_peer_seniority_map(t.as_ref(), &[3; 32], &HashMap::from([("peer".into(), 12)]))
        .unwrap();
    let timeout = g::TimeoutState {
        timeout_tick: 8,
        vote: Some(g::ProposalVote {
            selector: vec![9],
            ..Default::default()
        }),
        latest_quorum_certificate: Some(g::QuorumCertificate {
            filter: vec![3; 32],
            ..Default::default()
        }),
        ..Default::default()
    };
    store.put_timeout_vote(t.as_ref(), &timeout).unwrap();
    store
        .stage_shard_clock_frame(&[6; 32], &app(&[3; 32], 6), t.as_ref())
        .unwrap();
    t.commit().unwrap();
    let t = store.new_transaction(false).unwrap();
    store
        .commit_shard_clock_frame(&[3; 32], 6, &[6; 32], t.as_ref(), false)
        .unwrap();
    store
        .put_certified_app_shard_state(
            &g::AppShardProposal {
                state: Some(app(&[3; 32], 6)),
                ..Default::default()
            },
            t.as_ref(),
        )
        .unwrap();
    t.commit().unwrap();
    store
        .put_global_clock_frame_outcomes(5, &outcomes())
        .unwrap();
    store.put_shard_frame_fee_total(&[3; 32], 6, 123).unwrap();
    store
        .put_shard_frame_settlements(&[3; 32], 6, b"settled")
        .unwrap();
    store.put_shard_frame_spends(&[3; 32], 6, b"spent").unwrap();
    store
        .put_shard_frame_accumulator(&[3; 32], 6, &[7; 32], b"report")
        .unwrap();
    store
        .set_total_distance(&[3; 32], 6, &[6; 32], &BigInt::from(987))
        .unwrap();
}
fn inspect(store: &dyn ClockStore) {
    assert_eq!(store.get_global_clock_frame(3).unwrap(), frame(3));
    assert_eq!(store.get_earliest_global_clock_frame().unwrap(), frame(3));
    assert_eq!(store.get_latest_global_clock_frame().unwrap(), frame(5));
    assert_eq!(
        store
            .get_global_clock_frame_candidate(4, &identity(&frame(4)))
            .unwrap(),
        frame(4)
    );
    assert_eq!(
        store.range_global_clock_frame_candidates(4, 4, 5).unwrap(),
        vec![frame(4)]
    );
    assert_eq!(
        store.get_latest_certified_global_state().unwrap(),
        proposal(5)
    );
    assert_eq!(
        store.get_earliest_certified_global_state().unwrap(),
        proposal(5)
    );
    assert_eq!(store.get_latest_quorum_certificate(&[]).unwrap().rank, 4);
    assert_eq!(store.get_quorum_certificate(&[], 4).unwrap().rank, 4);
    assert_eq!(store.get_latest_timeout_certificate(&[]).unwrap().rank, 3);
    assert_eq!(store.get_timeout_certificate(&[], 3).unwrap().rank, 3);
    assert_eq!(store.get_proposal_votes(&[], 5).unwrap().len(), 1);
    assert_eq!(
        store.get_proposal_vote(&[], 5, &[9]).unwrap().selector,
        vec![9]
    );
    assert_eq!(store.get_timeout_votes(&[3; 32], 8).unwrap().len(), 1);
    assert_eq!(
        store
            .get_timeout_vote(&[3; 32], 8, &[9])
            .unwrap()
            .timeout_tick,
        8
    );
    assert_eq!(
        store.get_global_clock_frame_outcomes(5).unwrap(),
        outcomes()
    );
    assert_eq!(
        store.get_latest_shard_clock_frame(&[3; 32]).unwrap(),
        app(&[3; 32], 6)
    );
    assert_eq!(
        store.get_shard_clock_frame(&[3; 32], 6, false).unwrap(),
        app(&[3; 32], 6)
    );
    assert!(
        store
            .get_staged_shard_clock_frame(&[3; 32], 6, &[6; 32], false)
            .is_err(),
        "a committed frame keeps only its canonical copy"
    );
    assert_eq!(
        store
            .get_latest_certified_app_shard_state(&[3; 32])
            .unwrap()
            .state,
        Some(app(&[3; 32], 6))
    );
    assert_eq!(
        store.get_shard_frame_fee_total(&[3; 32], 6).unwrap(),
        Some(123)
    );
    assert_eq!(
        store.get_shard_frame_settlements(&[3; 32], 6).unwrap(),
        Some(b"settled".to_vec())
    );
    assert_eq!(
        store.get_shard_frame_spends(&[3; 32], 6).unwrap(),
        Some(b"spent".to_vec())
    );
    assert_eq!(
        store.get_shard_frame_accumulator(&[3; 32], 6).unwrap(),
        Some(vec![7; 32])
    );
    assert_eq!(
        store
            .get_shard_accumulator_report(&[3; 32], &[7; 32])
            .unwrap(),
        Some(b"report".to_vec())
    );
    assert_eq!(
        store.get_total_distance(&[3; 32], 6, &[6; 32]).unwrap(),
        BigInt::from(987)
    );
    assert_eq!(
        store.get_peer_seniority_map(&[3; 32]).unwrap().get("peer"),
        Some(&12)
    );
}

#[test]
fn clock_overlay_matches_durable_records_and_isolates_parent_and_siblings() {
    let (_dir, db) = database();
    let (_expected_dir, expected_db) = database();
    let primary = RocksClockStore::new(db.clone());
    let expected = RocksClockStore::new(expected_db.clone());
    let (overlay, store) = branch(db.clone());
    let (sibling, sibling_store) = branch(db.clone());
    let sequence = db.latest_sequence_number();
    fill(&store);
    fill(&expected);
    inspect(&store);
    inspect(&expected);
    let mut actual = overlay.cursor(&[0], &[1]).unwrap();
    actual.seek(&[0]).unwrap();
    let mut rows = Vec::new();
    while let Some(key) = actual.key() {
        rows.push((key.to_vec(), actual.value().unwrap().to_vec()));
        actual.next().unwrap();
    }
    let expected_rows: Vec<_> = expected_db
        .iterator(rocksdb::IteratorMode::Start)
        .map(|r| {
            let (k, v) = r.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect();
    assert_eq!(rows, expected_rows);
    assert_eq!(db.latest_sequence_number(), sequence);
    assert!(primary.get_global_clock_frame(5).is_err());
    assert!(sibling_store.get_global_clock_frame(5).is_err());
    let child = Arc::new(overlay.fork(limits()).unwrap());
    let child_store = OverlayClockStore::new(child.clone());
    let retained = store.read().unwrap();
    let mut revised = frame(5);
    revised.requests.clear();
    put(&store, &revised);
    assert_eq!(store.get_global_clock_frame(5).unwrap(), revised);
    assert_eq!(retained.global(5).unwrap(), frame(5));
    drop(actual);
    overlay.close();
    assert!(retained.global(5).is_err());
    inspect(&child_store);
    assert_eq!(db.latest_sequence_number(), sequence);
    child.close();
    sibling.close();
}

#[test]
fn clock_capture_ignores_later_primary_changes_and_shares_hypergraph_transactions() {
    let (_dir, db) = database();
    let primary = RocksClockStore::new(db.clone());
    fill(&primary);
    let (overlay, store) = branch(db.clone());
    primary.reset_global_clock_frames().unwrap();
    primary.put_global_clock_frame_outcomes(5, &[]).unwrap();
    inspect(&store);
    let hg = OverlayHypergraphStore::new(overlay.clone());
    assert!(hg.backing_store_identity() == store.backing_store_identity());
    let sequence = db.latest_sequence_number();
    let txn = hg.new_transaction(false).unwrap();
    store
        .put_global_clock_frame(&frame(10), txn.as_ref())
        .unwrap();
    txn.set(b"state/commit", b"same batch").unwrap();
    assert!(store.get_global_clock_frame(10).is_err());
    assert!(overlay.get(b"state/commit").unwrap().is_none());
    txn.commit().unwrap();
    assert_eq!(store.get_global_clock_frame(10).unwrap(), frame(10));
    assert_eq!(
        overlay.get(b"state/commit").unwrap(),
        Some(b"same batch".to_vec())
    );
    assert_eq!(db.latest_sequence_number(), sequence);
    overlay.close();
}

#[test]
fn clock_transactions_reject_foreign_stores_and_poison_all_partial_writes() {
    let (_dir, db) = database();
    let primary = RocksClockStore::new(db.clone());
    let overlay = Arc::new(ExecutionOverlay::capture(
        db.clone(),
        quil_forest::OverlayLimits {
            max_record_bytes: 256,
            ..limits()
        },
    ).unwrap());
    let store = OverlayClockStore::new(overlay.clone());
    let (other, sibling) = branch(db.clone());
    for foreign in [
        primary.new_transaction(false).unwrap(),
        sibling.new_transaction(false).unwrap(),
    ] {
        assert!(store
            .put_global_clock_frame(&frame(1), foreign.as_ref())
            .is_err());
        foreign.commit().unwrap();
    }
    let sequence = db.latest_sequence_number();
    let txn = store.new_transaction(false).unwrap();
    txn.set(b"earlier", b"must abort").unwrap();
    let mut large = frame(1);
    large.header.as_mut().unwrap().output = vec![1; 300];
    assert!(store.put_global_clock_frame(&large, txn.as_ref()).is_err());
    assert!(txn.commit().is_err());
    assert!(overlay.get(b"earlier").unwrap().is_none());
    let txn = store.new_transaction(false).unwrap();
    store
        .put_global_clock_frame(&frame(1), txn.as_ref())
        .unwrap();
    assert!(store
        .put_peer_seniority_map(txn.as_ref(), &[], &HashMap::from([("x".repeat(500), 1)]))
        .is_err());
    assert!(txn.commit().is_err());
    assert!(store.get_global_clock_frame(1).is_err());
    assert_eq!(db.latest_sequence_number(), sequence);
    assert!(store.compact_data(&[]).is_err());
    overlay.close();
    other.close();
}

#[test]
fn clock_transactions_read_staged_frames_and_keep_indices_monotonic() {
    let (_dir, db) = database();
    let (overlay, store) = branch(db);
    let txn = store.new_transaction(false).unwrap();
    for n in [10, 2, 7] {
        store
            .put_global_clock_frame(&frame(n), txn.as_ref())
            .unwrap();
    }
    store
        .stage_shard_clock_frame(&[4; 32], &app(&[3; 32], 4), txn.as_ref())
        .unwrap();
    store
        .commit_shard_clock_frame(&[3; 32], 4, &[4; 32], txn.as_ref(), false)
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(store.get_latest_global_clock_frame().unwrap(), frame(10));
    assert_eq!(store.get_earliest_global_clock_frame().unwrap(), frame(2));
    assert_eq!(
        store.get_latest_shard_clock_frame(&[3; 32]).unwrap(),
        app(&[3; 32], 4)
    );
    let txn = store.new_transaction(false).unwrap();
    store
        .commit_shard_clock_frame(&[3; 32], u64::MAX, &[5; 32], txn.as_ref(), false)
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        store.get_latest_shard_clock_frame(&[3; 32]).unwrap(),
        app(&[3; 32], 4)
    );
    assert_eq!(
        store
            .get_global_clock_frame_candidate(10, &identity(&frame(10)))
            .unwrap(),
        frame(10)
    );
    assert!(store
        .get_global_clock_frame_candidate(10, &identity(&frame(2)))
        .is_err());
    let txn = store.new_transaction(false).unwrap();
    store
        .stage_shard_clock_frame(&[5; 32], &app(&[3; 32], 5), txn.as_ref())
        .unwrap();
    assert!(store
        .commit_shard_clock_frame(&[2; 32], 5, &[5; 32], txn.as_ref(), false)
        .is_err());
    assert!(txn.commit().is_err());
    assert!(store
        .get_staged_shard_clock_frame(&[3; 32], 5, &[5; 32], false)
        .is_err());
    overlay.close();
}

#[test]
fn clock_range_deletion_preserves_neighbor_filters_and_bounds_empty_work() {
    let (_dir, db) = database();
    let overlay = Arc::new(ExecutionOverlay::capture(
        db.clone(),
        quil_forest::OverlayLimits {
            max_delta_entries: 64,
            ..limits()
        },
    ).unwrap());
    let store = OverlayClockStore::new(overlay.clone());
    let txn = store.new_transaction(false).unwrap();
    for filter in [&[1][..], &[1, 0][..]] {
        for n in [0, 1, u64::MAX] {
            txn.set(
                &e::clock_shard_frame_key(filter, n),
                &app(filter, n).encode_to_vec(),
            )
            .unwrap();
            txn.set(
                &e::clock_shard_parent_index_key(filter, n, &[255; 32]),
                b"parent",
            )
            .unwrap();
            txn.set(
                &e::clock_data_total_distance_key(filter, n, &[255; 32]),
                b"distance",
            )
            .unwrap();
        }
    }
    txn.commit().unwrap();
    assert!(store
        .delete_shard_clock_frame_range(&[1], 0, u64::MAX)
        .is_err());
    assert_eq!(
        store.get_shard_clock_frame(&[1], 0, false).unwrap(),
        app(&[1], 0)
    );
    store.delete_shard_clock_frame_range(&[1], 0, 2).unwrap();
    for n in [0, 1] {
        assert!(store.get_shard_clock_frame(&[1], n, false).is_err());
        assert!(overlay
            .get(&e::clock_shard_parent_index_key(&[1], n, &[255; 32]))
            .unwrap()
            .is_none());
        assert!(overlay
            .get(&e::clock_data_total_distance_key(&[1], n, &[255; 32]))
            .unwrap()
            .is_none());
        assert!(overlay
            .get(&e::clock_shard_parent_index_key(&[1, 0], n, &[255; 32]))
            .unwrap()
            .is_some());
    }
    store.reset_shard_clock_frames(&[1]).unwrap();
    assert!(store.get_shard_clock_frame(&[1], u64::MAX, false).is_err());
    for n in [0, 1, u64::MAX] {
        assert_eq!(
            store.get_shard_clock_frame(&[1, 0], n, false).unwrap(),
            app(&[1, 0], n)
        );
    }
    assert_eq!(db.latest_sequence_number(), 0);
    overlay.close();
}

#[test]
fn clock_reads_propagate_budget_and_corruption_errors_without_empty_fallbacks() {
    let (_dir, db) = database();
    let primary = RocksClockStore::new(db.clone());
    fill(&primary);
    let (overlay, store) = branch(db.clone());
    let t = store.new_transaction(false).unwrap();
    t.set(&e::clock_global_latest_index(), b"broken").unwrap();
    t.commit().unwrap();
    assert!(store.get_latest_global_clock_frame().is_err());
    let t = store.new_transaction(false).unwrap();
    t.delete(&e::clock_global_frame_request_key(3, 0)).unwrap();
    t.commit().unwrap();
    assert!(store.get_global_clock_frame(3).is_err());
    while overlay.get(b"exhaust budget").is_ok() {}
    assert!(matches!(
        store.get_global_clock_frame(5),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    assert!(matches!(
        store.get_proposal_votes(&[], 5),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    let t = store.new_transaction(false).unwrap();
    assert!(store
        .put_global_clock_frame(&frame(20), t.as_ref())
        .is_err());
    assert!(t.commit().is_err());
    overlay.close();
    assert!(store.new_transaction(false).is_err());
    let limited = Arc::new(ExecutionOverlay::capture(
        db,
        quil_forest::OverlayLimits {
            max_cursors: 0,
            ..limits()
        },
    ).unwrap());
    assert!(OverlayClockStore::new(limited.clone())
        .get_global_clock_frame(5)
        .is_err());
    limited.close();
}

#[test]
fn clock_accumulator_and_candidate_replacements_are_atomic() {
    let (_dir, db) = database();
    let (overlay, store) = branch(db.clone());
    store
        .put_shard_frame_accumulator(&[3; 32], 1, &[4; 32], b"original")
        .unwrap();
    assert!(store
        .put_shard_frame_accumulator(&[3; 32], 2, &[4; 32], b"conflict")
        .is_err());
    assert!(store
        .get_shard_frame_accumulator(&[3; 32], 2)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .get_shard_accumulator_report(&[3; 32], &[4; 32])
            .unwrap(),
        Some(b"original".to_vec())
    );
    for requests in [2, 0, 1] {
        let mut f = frame(3);
        f.requests.truncate(requests);
        let t = store.new_transaction(false).unwrap();
        store
            .put_global_clock_frame_candidate(&f, t.as_ref())
            .unwrap();
        t.commit().unwrap();
        assert_eq!(
            store
                .get_global_clock_frame_candidate(3, &identity(&f))
                .unwrap(),
            f
        );
    }
    let t = store.new_transaction(false).unwrap();
    store
        .put_global_clock_frame_candidate(&frame(u64::MAX), t.as_ref())
        .unwrap();
    t.commit().unwrap();
    assert_eq!(
        store
            .range_global_clock_frame_candidates(u64::MAX, u64::MAX, 1)
            .unwrap(),
        vec![frame(u64::MAX)]
    );
    assert_eq!(db.latest_sequence_number(), 0);
    overlay.close();

    let tiny = Arc::new(ExecutionOverlay::capture(
        db.clone(),
        quil_forest::OverlayLimits {
            max_delta_bytes: 90,
            ..limits()
        },
    ).unwrap());
    let tiny_store = OverlayClockStore::new(tiny.clone());
    // The report fits by itself, but the report plus frame digest does not.
    assert!(tiny_store
        .put_shard_frame_accumulator(&[3; 32], 1, &[4; 32], &[5; 20])
        .is_err());
    assert!(tiny_store
        .get_shard_accumulator_report(&[3; 32], &[4; 32])
        .unwrap()
        .is_none());
    assert!(tiny_store
        .get_shard_frame_accumulator(&[3; 32], 1)
        .unwrap()
        .is_none());
    assert_eq!(db.latest_sequence_number(), 0);
    tiny.close();
}

#[test]
fn clock_candidates_support_legacy_records_and_vote_scans_keep_filters_separate() {
    let (_dir, db) = database();
    let legacy = frame(7);
    db.put(
        e::clock_global_frame_candidate_key(7, &identity(&legacy)),
        legacy.encode_to_vec(),
    )
    .unwrap();
    let (overlay, store) = branch(db);
    assert_eq!(
        store
            .get_global_clock_frame_candidate(7, &identity(&legacy))
            .unwrap(),
        legacy
    );
    let t = store.new_transaction(false).unwrap();
    for filter in [vec![], vec![0]] {
        let vote = g::ProposalVote {
            filter: filter.clone(),
            rank: 3,
            selector: vec![9],
            ..Default::default()
        };
        store.put_proposal_vote(t.as_ref(), &vote).unwrap();
        store
            .put_timeout_vote(
                t.as_ref(),
                &g::TimeoutState {
                    vote: Some(vote),
                    timeout_tick: 3,
                    latest_quorum_certificate: Some(g::QuorumCertificate {
                        filter,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    t.commit().unwrap();
    for filter in [&[][..], &[0][..]] {
        let votes = store.get_proposal_votes(filter, 3).unwrap();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].filter, filter);
        let timeouts = store.get_timeout_votes(filter, 3).unwrap();
        assert_eq!(timeouts.len(), 1);
        assert_eq!(
            timeouts[0]
                .latest_quorum_certificate
                .as_ref()
                .unwrap()
                .filter,
            filter
        );
    }
    let t = store.new_transaction(false).unwrap();
    t.set(&e::clock_proposal_vote_key(&[], 3, &[8]), &[255])
        .unwrap();
    t.set(
        &e::clock_global_frame_candidate_key(7, &identity(&legacy)),
        &frame(8).header.unwrap().encode_to_vec(),
    )
    .unwrap();
    t.commit().unwrap();
    assert!(store.get_proposal_votes(&[], 3).is_err());
    assert!(store
        .get_global_clock_frame_candidate(7, &identity(&legacy))
        .is_err());
    overlay.close();
}
