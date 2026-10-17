//! Storage publication of real private execution, followed by a fresh reopen.
//! Live metadata/cache adoption and consensus finalization are separate gates.
use super::*;
use quil_types::store::{ClockStore, KvDb};

#[test]
fn publication_recovers_complete_deployment_frame_and_execution_receipt() {
    let fixture = Fixture::new(None);
    let path = fixture.db.inner().path().to_path_buf();
    let sequence = fixture.db.inner().latest_sequence_number();
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let config = quil_execution::token_intrinsic::config::TokenConfiguration {
        behavior: quil_execution::token_intrinsic::constants::DIVISIBLE as u32,
        name: b"atomic publication token".to_vec(),
        owner_public_key: vec![1; 32],
        ..Default::default()
    };
    let app = quil_execution::token_intrinsic::materialize::token_deploy_domain(&config).unwrap();
    let deploy = quil_execution::token_intrinsic::TokenDeploy {
        config: config.to_canonical_bytes().unwrap(),
        rdf_schema: vec![],
    };
    let mut input = frame(1, branch.prover_root().unwrap());
    input.requests[0]
        .requests
        .push(quil_types::proto::global::MessageRequest {
            timestamp: 0,
            request: Some(
                quil_types::proto::global::message_request::Request::TokenDeploy(
                    quil_execution::token_intrinsic::conversions::token_deploy_to_proto(&deploy)
                        .unwrap(),
                ),
            ),
        });
    let result = branch.materialize(&input).unwrap();
    assert_eq!(result.processed, 1);
    assert_eq!(result.skipped, 0);
    let root = branch
        .materializer
        .hypergraph
        .current_forest_phase_root(&app, 0)
        .unwrap();
    let size = branch.materializer.hypergraph.total_size();
    let outcomes = branch
        .execution
        .clock_store()
        .get_global_clock_frame_outcomes(1)
        .unwrap();
    let location = quil_hypergraph::addressing::Location {
        app_address: app,
        data_address: [0xff; 32],
    };
    let deployed = branch
        .materializer
        .hypergraph
        .get_vertex_data_checked(&location)
        .unwrap()
        .unwrap();
    // The canonical clock body is also part of this single private delta.
    let txn = branch
        .execution
        .clock_store()
        .new_transaction(false)
        .unwrap();
    branch
        .execution
        .clock_store()
        .put_global_clock_frame(&input, txn.as_ref())
        .unwrap();
    txn.commit().unwrap();
    let complete = branch.completed_checkpoint().unwrap().unwrap();
    assert_eq!(complete, result.checkpoint);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 0);
    assert!(fixture.clock.get_global_clock_frame(1).is_err());
    let notifications = fixture.notifications.load(Ordering::SeqCst);
    let plan = branch.execution.overlay().prepare_commit().unwrap();
    drop(branch);
    plan.commit(&fixture.db.inner()).unwrap();
    // This storage primitive deliberately has no public runtime callbacks.
    assert_eq!(fixture.current.materialized(), 0);
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), notifications);
    // Do not use the old CRDT's caches after a storage-only publication.
    drop(fixture);

    let db = quil_store::RocksDb::open_for_read_only(&path).unwrap();
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let clock = quil_store::RocksClockStore::new(db.inner());
    let crdt = quil_hypergraph::HypergraphCrdt::new(
        store.clone(),
        Arc::new(quil_tries::ShaInclusionProver),
    );
    crdt.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
    crdt.set_unified_tree(true);
    crdt.warm_sizes(&[]).unwrap();
    assert_eq!(read_cursor(store.as_ref()).unwrap(), 1);
    assert_eq!(clock.get_global_clock_frame(1).unwrap(), input);
    assert_eq!(clock.get_global_clock_frame_outcomes(1).unwrap(), outcomes);
    assert_eq!(crdt.current_forest_phase_root(&app, 0).unwrap(), root);
    assert_eq!(crdt.total_size(), size);
    assert_eq!(
        crdt.get_vertex_data_checked(&location).unwrap(),
        Some(deployed)
    );
    assert_eq!(
        execution_checkpoint::read_completed(store.as_ref(), &crdt, 1).unwrap(),
        Some(complete)
    );
    assert!(db
        .inner()
        .get(quil_store::encoding::global_execution_pending_key())
        .unwrap()
        .is_none());
}

#[test]
fn publication_rejects_real_store_writers_without_advancing_execution() {
    for writer in [
        "kv",
        "kv-transaction",
        "hypergraph",
        "clock",
        "candidate-in-transaction",
        "forest",
    ] {
        let fixture = Fixture::new(None);
        let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
        let input = frame(1, branch.prover_root().unwrap());
        branch.materialize(&input).unwrap();
        match writer {
            "kv" => fixture
                .db
                .set(b"publication-test-marker", b"changed")
                .unwrap(),
            "kv-transaction" => {
                let txn = fixture.db.new_batch(false).unwrap();
                txn.set(b"publication-test-marker", b"changed").unwrap();
                txn.commit().unwrap();
            }
            "hypergraph" => {
                let txn = fixture.store.new_transaction(false).unwrap();
                txn.set(b"publication-test-marker", b"changed").unwrap();
                txn.commit().unwrap();
            }
            "clock" => {
                let txn = fixture.clock.new_transaction(false).unwrap();
                fixture
                    .clock
                    .put_global_clock_frame(&frame(50, [0; 32]), txn.as_ref())
                    .unwrap();
                txn.commit().unwrap();
            }
            "candidate-in-transaction" => {
                // A candidate inside a clock transaction commits as a general
                // write. The direct consensus writer is covered below.
                let txn = fixture.clock.new_transaction(false).unwrap();
                fixture
                    .clock
                    .put_global_clock_frame_candidate(&frame(50, [0; 32]), txn.as_ref())
                    .unwrap();
                txn.commit().unwrap();
            }
            "forest" => {
                let tree = quil_forest::RocksTreeStore::with_namespace(
                    fixture.db.inner(),
                    quil_store::FOREST_NAMESPACE,
                    &quil_forest::TreeId::shard_phase(&[9; 32], quil_forest::Phase::VertexAdds),
                );
                tree.put_preimage(b"publication-test-marker").unwrap();
            }
            _ => unreachable!(),
        }
        let sequence = fixture.db.inner().latest_sequence_number();
        assert!(
            matches!(
                branch
                    .execution
                    .overlay()
                    .prepare_commit()
                    .unwrap()
                    .commit(&fixture.db.inner()),
                Err(quil_forest::DatabaseCommitError::Stale { .. })
            ),
            "{writer}"
        );
        assert_eq!(
            fixture.db.inner().latest_sequence_number(),
            sequence,
            "{writer}"
        );
        assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 0, "{writer}");
        assert!(
            fixture
                .clock
                .get_global_clock_frame_outcomes(1)
                .unwrap()
                .is_empty(),
            "{writer}"
        );
        assert!(
            fixture
                .db
                .inner()
                .get(quil_store::encoding::global_execution_checkpoint_key())
                .unwrap()
                .is_none(),
            "{writer}"
        );
        assert_eq!(fixture.current.materialized(), 0, "{writer}");
    }
}

#[test]
fn direct_candidate_writes_leave_an_untouching_publication_valid() {
    let fixture = Fixture::new(None);
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let input = frame(1, branch.prover_root().unwrap());
    branch.materialize(&input).unwrap();
    // A non-clock transaction selects the same direct, synced candidate
    // writer used by the consensus seam's NoopTxn.
    let txn = fixture.db.new_batch(false).unwrap();
    fixture
        .clock
        .put_global_clock_frame_candidate(&frame(50, [0; 32]), txn.as_ref())
        .unwrap();
    txn.abort().unwrap();
    branch
        .execution
        .overlay()
        .prepare_commit()
        .unwrap()
        .commit(&fixture.db.inner())
        .unwrap();
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 1);
    let candidate = frame(50, [0; 32]);
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&candidate.header.as_ref().unwrap().output).unwrap();
    assert_eq!(
        fixture.clock.get_global_clock_frame_candidate(50, &selector).unwrap(),
        candidate
    );
}
