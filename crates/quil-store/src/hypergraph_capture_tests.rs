use super::*;
use quil_hypergraph::{ExecutionFork, ExecutionForkLimits, HypergraphCrdt, Location, Mutation};
use quil_types::store::{HypergraphStore, RecordMutation};
use std::sync::atomic::{AtomicUsize, Ordering};

const APP: [u8; 32] = [7; 32];

fn limits() -> ExecutionForkLimits {
    ExecutionForkLimits {
        overlay: quil_forest::OverlayLimits {
            max_delta_bytes: 16 << 20,
            max_delta_entries: 100_000,
            max_record_bytes: 2 << 20,
            max_read_bytes: 128 << 20,
            max_read_operations: 100_000,
            max_cursors: 32,
        },
        max_metadata_entries: 10_000,
        max_metadata_bytes: 4 << 20,
    }
}

fn record_store(overlay: Arc<quil_forest::ExecutionOverlay>) -> Result<Arc<dyn HypergraphStore>> {
    Ok(Arc::new(OverlayHypergraphStore::new(overlay)))
}

fn capture(crdt: &HypergraphCrdt) -> ExecutionFork {
    crdt.lock_execution_capture()
        .unwrap()
        .fork(limits(), record_store)
        .unwrap()
}

fn location(n: u8) -> Location {
    Location {
        app_address: APP,
        data_address: [n; 32],
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    db: quil_forest::CoordinatedDb,
    store: Arc<RocksHypergraphStore>,
    crdt: Arc<HypergraphCrdt>,
}

impl Fixture {
    fn new(unified: bool, initialize: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
        let store = Arc::new(RocksHypergraphStore::new(db.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.clone(),
            FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(unified);
        crdt.set_app_shard_prefixes(APP, vec![vec![]]);
        if initialize {
            crdt.warm_sizes(&[APP]).unwrap();
        }
        Self {
            _dir: dir,
            db,
            store,
            crdt,
        }
    }

    fn seed(&self) {
        self.crdt.add_vertex(&location(1), b"one").unwrap();
        self.crdt.add_vertex(&location(128), b"other").unwrap();
        self.crdt.add_hyperedge(&location(3), b"edge").unwrap();
        self.crdt
            .add_vertex(
                &Location {
                    app_address: [255; 32],
                    data_address: [4; 32],
                },
                b"registry",
            )
            .unwrap();
        self.crdt
            .commit_with_global_cursor(1, &crate::encoding::global_materialized_cursor_key())
            .unwrap();
        let root = self
            .crdt
            .current_forest_phase_root(&[255; 32], 0)
            .unwrap()
            .to_vec();
        self.crdt.record_prover_root(1, root.clone());
        self.crdt.publish_snapshot_capturing(root, 1).unwrap();
        self.crdt
            .set_covered_prefix(&quil_tries::get_full_path(&APP))
            .unwrap();
    }
}

struct Observer(AtomicUsize);
impl quil_types::store::LocalVertexCommitObserver for Observer {
    fn committed<'a>(&self, _: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn execution_capture_preserves_metadata_and_forks_selected_parent_state() {
    for unified in [false, true] {
        let fixture = Fixture::new(unified, true);
        fixture.seed();
        let source = &fixture.crdt;
        let observer = Arc::new(Observer(AtomicUsize::new(0)));
        source.set_local_vertex_observer(observer.clone());
        let sequence = fixture.db.latest_sequence_number();
        let (branch, sibling) = {
            let barrier = source.lock_execution_capture().unwrap();
            (
                barrier.fork(limits(), record_store).unwrap(),
                barrier.fork(limits(), record_store).unwrap(),
            )
        };
        assert_eq!(fixture.db.latest_sequence_number(), sequence);
        assert_eq!(branch.crdt.unified_tree(), unified);
        assert!(
            !branch.crdt.forest_is_persistent(),
            "a fork must not expose a writable primary database"
        );
        assert_eq!(
            branch.crdt.get_covered_prefix(),
            source.get_covered_prefix()
        );
        assert_eq!(
            branch.crdt.app_sub_shards(&APP),
            source.app_sub_shards(&APP)
        );
        assert_eq!(branch.crdt.total_size(), source.total_size());
        assert_eq!(
            branch.crdt.global_commitments(),
            source.global_commitments()
        );
        assert_eq!(branch.crdt.prover_root_at(1), source.prover_root_at(1));
        assert_eq!(branch.crdt.world_size_at(1), source.world_size_at(1));
        assert!(branch.crdt.known_snapshot_roots().is_empty());
        assert!(!source.known_snapshot_roots().is_empty());
        assert_eq!(
            branch.crdt.capture_committed_shard(&APP).unwrap().roots,
            source.capture_committed_shard(&APP).unwrap().roots
        );
        let before_size = branch.crdt.total_size();

        source
            .add_vertex(&location(1), b"new primary value")
            .unwrap();
        source
            .commit_with_global_cursor(2, &crate::encoding::global_materialized_cursor_key())
            .unwrap();
        source.record_prover_root(2, source.prover_root_at(1).unwrap());
        source.close_snapshots();
        source.prune_to_frame(2).unwrap();
        assert_eq!(observer.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            branch.crdt.get_vertex_data_checked(&location(1)).unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(branch.crdt.total_size(), before_size);
        assert_eq!(branch.crdt.world_size_at(2), None);
        assert_ne!(source.total_size(), before_size);
        let sequence = fixture.db.latest_sequence_number();
        branch
            .crdt
            .add_vertex(&location(2), b"parent branch")
            .unwrap();
        branch
            .crdt
            .commit_with_global_cursor(2, &crate::encoding::global_materialized_cursor_key())
            .unwrap();
        let child = capture(&branch.crdt);
        let expected = child.crdt.capture_committed_shard(&APP).unwrap().roots;
        branch
            .crdt
            .add_vertex(&location(2), b"later parent")
            .unwrap();
        branch
            .crdt
            .commit_with_global_cursor(3, &crate::encoding::global_materialized_cursor_key())
            .unwrap();
        branch.overlay.close();
        assert_eq!(
            child.crdt.capture_committed_shard(&APP).unwrap().roots,
            expected
        );
        assert_eq!(
            child.crdt.get_vertex_data_checked(&location(2)).unwrap(),
            Some(b"parent branch".to_vec())
        );
        assert!(sibling
            .crdt
            .get_vertex_data_checked(&location(2))
            .unwrap()
            .is_none());
        child.crdt.add_vertex(&location(5), b"child only").unwrap();
        child
            .crdt
            .commit_with_global_cursor(3, &crate::encoding::global_materialized_cursor_key())
            .unwrap();
        assert!(source
            .get_vertex_data_checked(&location(5))
            .unwrap()
            .is_none());
        assert_eq!(
            observer.0.load(Ordering::SeqCst),
            1,
            "tentative commits must not notify a primary cache"
        );
        assert_eq!(fixture.db.latest_sequence_number(), sequence);
        child.overlay.close();
        sibling.overlay.close();
    }
}

#[test]
fn execution_capture_rejects_uninitialized_pending_and_partial_layout_state() {
    let fixture = Fixture::new(true, false);
    let source = &fixture.crdt;
    assert!(source
        .lock_execution_capture()
        .unwrap()
        .fork(limits(), record_store)
        .is_err());
    source.warm_sizes(&[APP]).unwrap();
    fixture.seed();
    source.add_vertex(&location(2), b"pending").unwrap();
    assert!(source
        .lock_execution_capture()
        .unwrap()
        .fork(limits(), record_store)
        .is_err());
    assert!(
        source.rebucket_app(&APP).is_err(),
        "pending size deltas must survive a rejected rebuild"
    );
    source
        .commit_with_global_cursor(2, &crate::encoding::global_materialized_cursor_key())
        .unwrap();
    let record = RecordMutation {
        key: b"capture/test".to_vec(),
        value: Some(vec![3]),
    };
    source
        .apply_mutations(&[Mutation::Record(&record)])
        .unwrap();
    assert!(source
        .lock_execution_capture()
        .unwrap()
        .fork(limits(), record_store)
        .is_err());
    source
        .commit_with_global_cursor(3, &crate::encoding::global_materialized_cursor_key())
        .unwrap();
    let before = source.total_size();
    assert!(source.set_app_shard_prefixes(APP, vec![vec![0], vec![128]]));
    assert!(source
        .lock_execution_capture()
        .unwrap()
        .fork(limits(), record_store)
        .is_err());
    source.rebucket_app(&APP).unwrap();
    assert_eq!(source.total_size(), before);
    let branch = capture(source);
    assert_eq!(
        branch.crdt.app_sub_shards(&APP),
        source.app_sub_shards(&APP)
    );
    assert_eq!(branch.crdt.total_size(), before);
    assert_eq!(
        branch.crdt.read_execution_record(b"capture/test").unwrap(),
        Some(vec![3])
    );
    branch.overlay.close();
}

#[test]
fn execution_capture_checks_store_identity_budgets_and_failed_factory_cleanup() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let source = &fixture.crdt;
    let branch = capture(source);
    let mut exact = limits();
    exact.max_metadata_entries = branch.metadata.entries;
    exact.max_metadata_bytes = branch.metadata.bytes;
    branch.overlay.close();
    source
        .lock_execution_capture()
        .unwrap()
        .fork(exact, record_store)
        .unwrap()
        .overlay
        .close();
    for limited in [
        ExecutionForkLimits {
            max_metadata_bytes: exact.max_metadata_bytes - 1,
            ..exact
        },
        ExecutionForkLimits {
            max_metadata_entries: exact.max_metadata_entries - 1,
            ..exact
        },
    ] {
        assert!(source
            .lock_execution_capture()
            .unwrap()
            .fork(limited, |_| panic!("must check before cloning/factory"))
            .is_err());
    }
    let mut failed_overlay = None;
    let result = source
        .lock_execution_capture()
        .unwrap()
        .fork(limits(), |overlay| {
            failed_overlay = Some(overlay);
            Ok(fixture.store.clone())
        });
    assert!(result.is_err());
    assert!(failed_overlay.unwrap().stats().closed);
    let other = Fixture::new(true, true);
    source.set_forest(quil_forest::Forest::with_namespace(
        other.db,
        FOREST_NAMESPACE,
    ));
    assert!(source
        .lock_execution_capture()
        .unwrap()
        .fork(limits(), |_| panic!(
            "mismatched primary forest must reject first"
        ))
        .is_err());
}

#[test]
fn execution_capture_rejects_stale_heads_and_roots_after_external_resets() {
    for global in [false, true] {
        let fixture = Fixture::new(true, true);
        fixture.seed();
        let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
        let version = if global {
            forest.read_global_head_version(APP[0]).unwrap().unwrap()
        } else {
            forest
                .read_head_version(&APP, quil_forest::Phase::VertexAdds)
                .unwrap()
                .unwrap()
        };
        let write_head = |version| {
            if global {
                forest.write_global_head_version(APP[0], version).unwrap();
            } else {
                forest
                    .write_head_version(&APP, quil_forest::Phase::VertexAdds, version)
                    .unwrap();
            }
        };
        let reject = |expected: &str| {
            let error = fixture
                .crdt
                .lock_execution_capture()
                .unwrap()
                .fork(limits(), |_| {
                    panic!("reject inconsistent state before constructing providers")
                })
                .err()
                .expect("external reset must invalidate capture");
            assert!(error.to_string().contains(expected), "{error}");
        };
        write_head(version + 1);
        reject("version mismatch");
        write_head(version);
        let retained = capture(&fixture.crdt);
        let tree = if global {
            quil_forest::TreeId::global(APP[0])
        } else {
            quil_forest::TreeId::shard_phase(&APP, quil_forest::Phase::VertexAdds)
        };
        // A reset may leave the old head marker but remove its actual root.
        quil_forest::RocksTreeStore::with_namespace(fixture.db.clone(), FOREST_NAMESPACE, &tree)
            .clear()
            .unwrap();
        reject("head has no root");
        assert_eq!(
            retained.crdt.get_vertex_data_checked(&location(1)).unwrap(),
            Some(b"one".to_vec())
        );
        retained.overlay.close();
    }
}

#[test]
fn execution_capture_blocks_metadata_writers_until_dependent_construction_finishes() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let source = fixture.crdt.clone();
    let barrier = source.lock_execution_capture().unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let writer_source = source.clone();
    let writer = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        writer_source.set_covered_prefix(&[]).unwrap();
        done_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    assert!(done_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    let branch = barrier.fork(limits(), record_store).unwrap();
    assert_eq!(
        branch.crdt.get_covered_prefix(),
        quil_tries::get_full_path(&APP)
    );
    drop(barrier);
    done_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    writer.join().unwrap();
    assert!(source.get_covered_prefix().is_empty());
    assert!(!branch.crdt.get_covered_prefix().is_empty());
    branch.overlay.close();
}

#[test]
fn execution_capture_layout_failure_preserves_sizes_and_allows_a_fresh_attempt() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let branch = capture(&fixture.crdt);
    let size = branch.crdt.total_size();
    let layout = branch.crdt.app_sub_shards(&APP);
    // Exhaust only the branch's read budget. Rebuild must propagate the read
    // failure, rather than interpreting unavailable subtrees as zero bytes.
    while branch.overlay.get(b"budget probe").is_ok() {}
    assert!(branch
        .crdt
        .refresh_app_shard_prefixes(APP, vec![vec![0], vec![128]])
        .is_err());
    assert_eq!(branch.crdt.total_size(), size);
    assert_eq!(branch.crdt.app_sub_shards(&APP), layout);
    let retry = capture(&branch.crdt);
    assert!(retry
        .crdt
        .refresh_app_shard_prefixes(APP, vec![vec![0], vec![128]])
        .unwrap());
    assert_eq!(retry.crdt.total_size(), size);
    assert_eq!(retry.crdt.app_sub_shards(&APP).len(), 2);
    assert!(!retry
        .crdt
        .refresh_app_shard_prefixes(APP, vec![vec![128], vec![0]])
        .unwrap());
    branch.overlay.close();
    retry.overlay.close();
}

#[derive(Default)]
struct AdoptionObserver {
    keys: std::sync::Mutex<Vec<[u8; 64]>>,
    invalidations: AtomicUsize,
    legacy: AtomicUsize,
}
impl quil_types::store::LocalVertexCommitObserver for AdoptionObserver {
    fn execution_key_domains(&self) -> &'static [[u8; 32]] {
        &[APP]
    }
    fn committed<'a>(&self, _: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>) {
        self.legacy.fetch_add(1, Ordering::SeqCst);
    }
    fn committed_keys(&self, keys: Vec<[u8; 64]>) {
        self.keys.lock().unwrap().extend(keys);
    }
    fn watches_sync(&self, app: &[u8]) -> bool {
        app == APP
    }
    fn invalidated(&self) {
        self.invalidations.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn canonical_adoption_notifies_live_cache_only_after_publication() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let witness = Arc::new(Observer(AtomicUsize::new(0)));
    fixture.crdt.set_local_vertex_observer(witness.clone());
    let cache = Arc::new(AdoptionObserver::default());
    fixture.crdt.add_local_vertex_observer(cache.clone());
    let old = fixture.crdt.capture_fresh_committed_snapshot().unwrap();
    let branch = capture(&fixture.crdt);
    branch
        .crdt
        .add_vertex(&location(1), b"replacement")
        .unwrap();
    branch.crdt.remove_vertex(&location(128)).unwrap();
    branch
        .crdt
        .commit_with_global_cursor(2, &crate::encoding::global_materialized_cursor_key())
        .unwrap();
    let child = capture(&branch.crdt);
    child.crdt.add_vertex(&location(2), b"child").unwrap();
    child
        .crdt
        .commit_with_global_cursor(3, &crate::encoding::global_materialized_cursor_key())
        .unwrap();
    assert!(cache.keys.lock().unwrap().is_empty());
    {
        let capture = fixture.crdt.lock_execution_capture().unwrap();
        let mut adoption = capture
            .prepare_adoption(&child.crdt, &child.overlay, limits(), record_store)
            .unwrap();
        assert!(cache.keys.lock().unwrap().is_empty());
        let plan = child.overlay.prepare_commit().unwrap();
        let mut write = fixture.db.lock_writes().unwrap();
        plan.commit_locked(&mut write).unwrap();
        adoption.adopt();
        adoption.adopt();
    }
    let mut expected = vec![
        location(1).to_id(),
        location(2).to_id(),
        location(128).to_id(),
    ];
    expected.sort();
    assert_eq!(*cache.keys.lock().unwrap(), expected);
    assert_eq!(cache.invalidations.load(Ordering::SeqCst), 0);
    assert_eq!(cache.legacy.load(Ordering::SeqCst), 0);
    assert_eq!(witness.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.crdt.get_vertex_data_checked(&location(1)).unwrap(),
        Some(b"replacement".to_vec())
    );
    let shard = quil_hypergraph::shard_key_for_location(&location(1));
    assert_eq!(
        old.load_vertex_underlying_raw("vertex", "adds", &shard, &location(1).to_id())
            .unwrap(),
        Some(b"one".to_vec())
    );
    branch.overlay.close();
    child.overlay.close();
}

#[test]
fn discarded_and_failed_adoptions_do_not_notify_local_cache() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let cache = Arc::new(AdoptionObserver::default());
    fixture.crdt.set_local_vertex_observer(cache.clone());
    let branch = capture(&fixture.crdt);
    branch.crdt.add_vertex(&location(2), b"discarded").unwrap();
    branch.crdt.commit(2).unwrap();
    let capture = fixture.crdt.lock_execution_capture().unwrap();
    let adoption = capture
        .prepare_adoption(&branch.crdt, &branch.overlay, limits(), record_store)
        .unwrap();
    let plan = branch.overlay.prepare_commit().unwrap();
    fixture.db.put(b"canonical conflict", b"changed").unwrap();
    assert!(plan.commit(&fixture.db).is_err());
    drop(adoption);
    drop(capture);
    branch.overlay.close();
    assert!(cache.keys.lock().unwrap().is_empty());
    assert_eq!(cache.invalidations.load(Ordering::SeqCst), 0);
}

#[test]
fn private_reset_invalidation_waits_for_canonical_adoption() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let cache = Arc::new(AdoptionObserver::default());
    fixture.crdt.set_local_vertex_observer(cache.clone());
    let branch = capture(&fixture.crdt);
    branch
        .crdt
        .invalidate_local_vertex_observer_for_app(&[8; 32]);
    branch.crdt.invalidate_local_vertex_observer_for_app(&APP);
    assert_eq!(cache.invalidations.load(Ordering::SeqCst), 0);
    {
        let capture = fixture.crdt.lock_execution_capture().unwrap();
        let mut adoption = capture
            .prepare_adoption(&branch.crdt, &branch.overlay, limits(), record_store)
            .unwrap();
        let plan = branch.overlay.prepare_commit().unwrap();
        let mut write = fixture.db.lock_writes().unwrap();
        plan.commit_locked(&mut write).unwrap();
        adoption.adopt();
        adoption.adopt();
    }
    assert_eq!(cache.invalidations.load(Ordering::SeqCst), 1);
    assert!(cache.keys.lock().unwrap().is_empty());
    branch.overlay.close();
}

#[test]
fn fresh_index_snapshot_waits_for_reset_forest_barrier() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let cache = Arc::new(AdoptionObserver::default());
    fixture.crdt.set_local_vertex_observer(cache.clone());
    let guard = fixture.crdt.lock_forest_writes();
    let source = fixture.crdt.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        snapshot_tx
            .send(source.capture_fresh_committed_snapshot().unwrap())
            .unwrap();
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();
    assert!(snapshot_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    let shard = quil_hypergraph::shard_key_for_location(&location(1));
    fixture.store.clear_shard_underlying(&shard).unwrap();
    fixture.crdt.invalidate_local_vertex_observer_for_app(&APP);
    assert!(snapshot_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    drop(guard);
    let snapshot = snapshot_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();
    assert_eq!(
        snapshot
            .load_vertex_underlying_raw("vertex", "adds", &shard, &location(1).to_id())
            .unwrap(),
        None
    );
    assert_eq!(cache.invalidations.load(Ordering::SeqCst), 1);
    reader.join().unwrap();
}

#[test]
fn observer_registered_after_capture_invalidates_once_then_receives_keys() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let branch = capture(&fixture.crdt);
    branch
        .crdt
        .add_vertex(&location(2), b"captured before registration")
        .unwrap();
    branch.crdt.commit(2).unwrap();
    let cache = Arc::new(AdoptionObserver::default());
    fixture.crdt.add_local_vertex_observer(cache.clone());
    {
        let capture = fixture.crdt.lock_execution_capture().unwrap();
        let mut adoption = capture
            .prepare_adoption(&branch.crdt, &branch.overlay, limits(), record_store)
            .unwrap();
        let plan = branch.overlay.prepare_commit().unwrap();
        let mut write = fixture.db.lock_writes().unwrap();
        plan.commit_locked(&mut write).unwrap();
        adoption.adopt();
    }
    assert_eq!(cache.invalidations.load(Ordering::SeqCst), 1);
    assert!(cache.keys.lock().unwrap().is_empty());
    branch.overlay.close();
    let branch = capture(&fixture.crdt);
    branch
        .crdt
        .add_vertex(&location(2), b"captured after registration")
        .unwrap();
    branch.crdt.commit(3).unwrap();
    {
        let capture = fixture.crdt.lock_execution_capture().unwrap();
        let mut adoption = capture
            .prepare_adoption(&branch.crdt, &branch.overlay, limits(), record_store)
            .unwrap();
        let plan = branch.overlay.prepare_commit().unwrap();
        let mut write = fixture.db.lock_writes().unwrap();
        plan.commit_locked(&mut write).unwrap();
        adoption.adopt();
    }
    assert_eq!(cache.invalidations.load(Ordering::SeqCst), 1);
    assert_eq!(*cache.keys.lock().unwrap(), vec![location(2).to_id()]);
    branch.overlay.close();
}

#[test]
fn prepared_adoption_serializes_observer_registration() {
    let fixture = Fixture::new(true, true);
    fixture.seed();
    let branch = capture(&fixture.crdt);
    branch
        .crdt
        .add_vertex(&location(2), b"before registration")
        .unwrap();
    branch.crdt.commit(2).unwrap();
    let capture = fixture.crdt.lock_execution_capture().unwrap();
    let mut adoption = capture
        .prepare_adoption(&branch.crdt, &branch.overlay, limits(), record_store)
        .unwrap();
    let cache = Arc::new(AdoptionObserver::default());
    let registered_cache = cache.clone();
    let source = fixture.crdt.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let registration = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        source.add_local_vertex_observer(registered_cache);
        done_tx.send(()).unwrap();
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();
    assert!(done_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    let plan = branch.overlay.prepare_commit().unwrap();
    {
        let mut write = fixture.db.lock_writes().unwrap();
        plan.commit_locked(&mut write).unwrap();
        adoption.adopt();
    }
    assert!(done_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    drop(adoption);
    done_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();
    drop(capture);
    registration.join().unwrap();
    let snapshot = fixture.crdt.capture_fresh_committed_snapshot().unwrap();
    let shard = quil_hypergraph::shard_key_for_location(&location(2));
    assert_eq!(
        snapshot
            .load_vertex_underlying_raw("vertex", "adds", &shard, &location(2).to_id())
            .unwrap(),
        Some(b"before registration".to_vec())
    );
    assert_eq!(cache.invalidations.load(Ordering::SeqCst), 0);
    assert!(cache.keys.lock().unwrap().is_empty());
    branch.overlay.close();
}
