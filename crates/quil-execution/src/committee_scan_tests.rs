use super::*;
use crate::global_intrinsic::{
    handoff::schedule::desired_members, prover_release::Release, storage_seat::Seat,
};
use quil_forest::{ExecutionOverlay, OverlayMutation};
use quil_hypergraph::HypergraphCrdt;
use quil_types::crypto::NoopInclusionProver;

const FILTER: &[u8] = &[0x31, 0x42, 0x53];

fn physical(phase: &str, id: u8, version: Option<u64>) -> Vec<u8> {
    let shard = quil_store::encoding::prover_registry_shard();
    let vk = make_vertex_key(id);
    match version {
        None => quil_store::encoding::hypergraph_vertex_data_key("vertex", phase, &shard, &vk),
        Some(v) => {
            quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", phase, &shard, &vk, v)
        }
    }
}

fn key_for(id: u8) -> Vec<u8> {
    vec![id; quil_crypto::FALCON_PUBLIC_KEY_LEN]
}

fn prover(id: u8, status: u8) -> Vec<u8> {
    let cls = "prover:Prover";
    build_sub_tree(vec![
        type_hash_leaf(cls),
        field_leaf(cls, "Status", vec![status]),
        field_leaf(cls, "PublicKey", key_for(id)),
        field_leaf(cls, "Seniority", u64::from(id).to_be_bytes().to_vec()),
    ])
}

fn allocation(owner: u8, filter: &[u8]) -> Vec<u8> {
    let cls = "allocation:ProverAllocation";
    build_sub_tree(vec![
        type_hash_leaf(cls),
        field_leaf(cls, "Status", vec![1]),
        field_leaf(cls, "Prover", vec![owner; 32]),
        field_leaf(cls, "ConfirmationFilter", filter.to_vec()),
        field_leaf(cls, "JoinConfirmFrameNumber", 1u64.to_be_bytes().to_vec()),
        field_leaf(cls, "RingEpoch", 3u64.to_be_bytes().to_vec()),
        field_leaf(cls, "RingSeniority", 42u64.to_be_bytes().to_vec()),
        field_leaf(cls, "Release", Release::current().to_bytes().to_vec()),
    ])
}

struct Fixture {
    _dir: tempfile::TempDir,
    db: quil_forest::CoordinatedDb,
    store: Arc<RocksHypergraphStore>,
    crdt: HypergraphCrdt,
    registry: SharedProverRegistry,
    seat: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap().inner();
        let store = Arc::new(RocksHypergraphStore::new(db.clone()));
        let crdt = HypergraphCrdt::new(store.clone(), Arc::new(NoopInclusionProver));
        crdt.set_forest(quil_forest::Forest::new(db.clone()));
        let mut seat = Seat::new([1; 32], FILTER.to_vec());
        seat.register(2, &[vec![1]], 10);
        assert!(seat.seal(2, 11));
        let seat = vertex_tree_to_blob(&seat.to_tree().unwrap());
        let txn = store.new_transaction(false).unwrap();
        for (id, version, data) in [
            (1, None, prover(1, 1)),
            (2, None, prover(2, 1)),
            (8, None, allocation(1, FILTER)),
            (9, None, allocation(2, &[0])),
            (9, Some(2), allocation(2, FILTER)),
            (20, None, seat.clone()),
        ] {
            txn.set(&physical("adds", id, version), &data).unwrap();
        }
        for n in 32..=200 {
            txn.set(&physical("adds", n, None), b"unrelated row")
                .unwrap();
        }
        txn.commit().unwrap();
        let registry = SharedProverRegistry::new();
        let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
        registry
            .inner
            .write()
            .unwrap()
            .refresh_rows(snapshot.as_ref(), RegistryLimits::UNBOUNDED, true, None)
            .unwrap();
        Self {
            _dir: dir,
            db,
            store,
            crdt,
            registry,
            seat,
        }
    }

    fn branch(
        &self,
        parent: Option<&ExecutionOverlay>,
    ) -> (Arc<ExecutionOverlay>, SharedProverRegistry, HypergraphCrdt) {
        let limits = registry_overlay_limits();
        let overlay = Arc::new(match parent {
            Some(parent) => parent.fork(limits).unwrap(),
            None => ExecutionOverlay::capture(self.db.clone(), limits).unwrap(),
        });
        let store = Arc::new(quil_store::OverlayHypergraphStore::new(overlay.clone()));
        let registry = SharedProverRegistry::for_materialization_overlay(
            store.as_ref(),
            RegistryLimits::UNBOUNDED,
            Some(&self.registry),
            &overlay,
            true,
        )
        .unwrap();
        (
            overlay,
            registry,
            HypergraphCrdt::new(store, Arc::new(NoopInclusionProver)),
        )
    }
}

// Compare all six inputs, including allocation order, and the actual sorted
// public keys the committee scheduler would persist.
fn compare(registry: &SharedProverRegistry, crdt: &HypergraphCrdt, members: &[u8]) {
    let (indexed, source) = CommittedProverScan::for_committee(crdt, Some(registry), true).unwrap();
    assert_eq!(source, Some("indexed"));
    let (full, source) = CommittedProverScan::for_committee(crdt, Some(registry), false).unwrap();
    assert_eq!(source, None);
    assert_eq!(indexed.addr_to_pubkey, full.addr_to_pubkey);
    assert_eq!(indexed.seniority, full.seniority);
    assert_eq!(indexed.ring_keys, full.ring_keys);
    assert_eq!(indexed.releases, full.releases);
    assert_eq!(indexed.seats, full.seats);
    assert_eq!(
        format!("{:?}", indexed.allocations),
        format!("{:?}", full.allocations)
    );
    let selected = desired_members(&indexed, FILTER, 100);
    assert_eq!(selected, desired_members(&full, FILTER, 100));
    assert_eq!(
        selected,
        members.iter().copied().map(key_for).collect::<Vec<_>>()
    );
}

#[test]
fn archive_committee_matches_full_scan_across_writes_forks_and_rollback() {
    let f = Fixture::new();
    compare(&f.registry, &f.crdt, &[1, 2]);
    let initial = f.registry.committee_scan(&f.crdt).unwrap().unwrap();
    assert_eq!(initial.seats[&(vec![1; 32], FILTER.to_vec())], vec![2]);
    assert_eq!(initial.releases, vec![Some(Release::current()); 2]);
    assert!(initial.ring_keys.iter().all(Option::is_some));
    let (overlay, registry, crdt) = f.branch(None);
    let before = overlay.stats().read_operations;
    registry.committee_scan(&crdt).unwrap().unwrap();
    let indexed = overlay.stats().read_operations - before;
    let before = overlay.stats().read_operations;
    CommittedProverScan::try_scan(&crdt).unwrap();
    let full = overlay.stats().read_operations - before;
    assert!(
        indexed * 8 < full,
        "indexed {indexed}, full {full} read operations"
    );
    eprintln!("committee fixture: {indexed} indexed vs {full} full-scan overlay reads");
    // Removing a version reveals the legacy allocation on a different filter.
    // A fork inherits the point edits, a later parent write stays private.
    overlay
        .apply(&[
            OverlayMutation::Delete(physical("adds", 9, Some(2))),
            OverlayMutation::Put(physical("adds", 3, Some(1)), prover(3, 1)),
            OverlayMutation::Put(physical("adds", 7, Some(1)), allocation(3, FILTER)),
            OverlayMutation::Put(physical("removes", 20, Some(1)), vec![]),
        ])
        .unwrap();
    compare(&registry, &crdt, &[1, 3]);
    let (child, child_registry, child_crdt) = f.branch(Some(&overlay));
    compare(&child_registry, &child_crdt, &[1, 3]);
    overlay
        .apply(&[OverlayMutation::Put(
            physical("adds", 1, Some(1)),
            prover(1, 4),
        )])
        .unwrap();
    compare(&registry, &crdt, &[3]);
    compare(&child_registry, &child_crdt, &[1, 3]);
    child
        .apply(&[
            OverlayMutation::Put(physical("removes", 7, None), vec![]),
            OverlayMutation::Delete(physical("removes", 20, Some(1))),
        ])
        .unwrap();
    compare(&child_registry, &child_crdt, &[1]);
    assert!(registry.committee_scan(&child_crdt).unwrap().is_none());
    child.close();
    assert!(child_registry.committee_scan(&child_crdt).is_err());
    overlay.close();
    compare(&f.registry, &f.crdt, &[1, 2]);
}

#[test]
fn archive_committee_rejects_stale_ranges_foreign_domains_and_ambiguous_seats() {
    let f = Fixture::new();
    let (overlay, registry, crdt) = f.branch(None);
    overlay
        .apply(&[OverlayMutation::Put(
            physical("adds", 21, Some(1)),
            f.seat.clone(),
        )])
        .unwrap();
    assert!(registry.committee_scan(&crdt).unwrap().is_none());
    overlay
        .apply(&[OverlayMutation::Delete(physical("adds", 21, Some(1)))])
        .unwrap();
    compare(&registry, &crdt, &[1, 2]);
    let shard = quil_store::encoding::prover_registry_shard();
    let vk = [0x77; 64];
    for foreign in [
        quil_store::encoding::hypergraph_vertex_data_key("vertex", "adds", &shard, &vk),
        quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "removes", &shard, &vk, 1),
    ] {
        overlay
            .apply(&[OverlayMutation::Put(foreign.clone(), prover(7, 1))])
            .unwrap();
        assert!(registry.committee_scan(&crdt).unwrap().is_none());
        f.db.put(&foreign, prover(7, 1)).unwrap();
        assert!(f.registry.committee_scan(&f.crdt).unwrap().is_none());
        overlay
            .apply(&[OverlayMutation::Delete(foreign.clone())])
            .unwrap();
        f.db.delete(foreign).unwrap();
    }
    overlay
        .apply(&[OverlayMutation::DeleteRange(
            physical("adds", 1, None),
            physical("adds", 4, None),
        )])
        .unwrap();
    assert!(registry.committee_scan(&crdt).unwrap().is_none());
    let (fallback, source) =
        CommittedProverScan::for_committee(&crdt, Some(&registry), true).unwrap();
    assert_eq!(source, Some("full"));
    assert!(desired_members(&fallback, FILTER, 100).is_empty());
    f.db.enable_watched_journal().unwrap();
    f.db.put(physical("removes", 8, None), b"deleted").unwrap();
    assert!(f.registry.committee_scan(&f.crdt).unwrap().is_none());
    let caught = f
        .registry
        .catch_up(f.store.as_ref(), |_, sequence| {
            f.db.watched_writes_since(sequence).unwrap()
        })
        .unwrap();
    assert_eq!(caught, RegistryCatchUp::Updated { rows: 1 });
    compare(&f.registry, &f.crdt, &[2]);
}

#[test]
fn archive_publication_distinguishes_incremental_copy_and_full_refresh() {
    let f = Fixture::new();
    let (overlay, registry, _) = f.branch(None);
    let store = quil_store::OverlayHypergraphStore::new(overlay.clone());
    let mut t = RegistryUpdateTiming::default();
    registry
        .update_written_rows_timed(&store, Some(&mut t))
        .unwrap();
    assert_eq!(
        (t.mode, t.changed_rows, t.copied),
        ("incremental", Some(0), None)
    );
    overlay
        .apply(&[OverlayMutation::Put(
            physical("adds", 2, None),
            prover(2, 2),
        )])
        .unwrap();
    let mut t = RegistryUpdateTiming::default();
    registry
        .update_written_rows_timed(&store, Some(&mut t))
        .unwrap();
    assert_eq!(
        (t.mode, t.changed_rows, t.copied),
        ("incremental", Some(1), Some(true))
    );
    for elapsed in [&t.read, &t.decode, &t.copy, &t.rebuild] {
        assert!(!elapsed.get().is_zero());
    }
    overlay
        .apply(&[OverlayMutation::DeleteRange(
            physical("adds", 5, None),
            physical("adds", 6, None),
        )])
        .unwrap();
    let mut t = RegistryUpdateTiming::default();
    registry
        .update_written_rows_timed(&store, Some(&mut t))
        .unwrap();
    assert_eq!((t.mode, t.changed_rows, t.copied), ("full", None, None));
    for elapsed in [&t.read, &t.decode, &t.rebuild] {
        assert!(!elapsed.get().is_zero());
    }
}

#[test]
fn archive_publication_batches_sparse_phases_across_multiple_pages() {
    let f = Fixture::new();
    let (overlay, registry, crdt) = f.branch(None);
    let store = quil_store::OverlayHypergraphStore::new(overlay.clone());
    let mut updates = Vec::new();
    for id in 32..160 {
        if id % 3 != 1 {
            updates.push(OverlayMutation::Put(
                physical("adds", id, Some(8)),
                prover(id, 1),
            ));
        }
        if id % 3 != 0 {
            updates.push(OverlayMutation::Put(
                physical("removes", id, Some(9)),
                vec![],
            ));
        }
    }
    overlay.apply(&updates).unwrap();
    let mut t = RegistryUpdateTiming::default();
    registry
        .update_written_rows_timed(&store, Some(&mut t))
        .unwrap();
    assert_eq!((t.mode, t.changed_rows), ("incremental", Some(128)));
    compare(&registry, &crdt, &[1, 2]);
}

#[test]
fn archive_committee_keeps_publication_conflict_checks_for_cached_rows() {
    let f = Fixture::new();
    let (overlay, registry, crdt) = f.branch(None);
    assert!(registry.committee_scan(&crdt).unwrap().is_some());
    f.db.put(physical("adds", 17, Some(1)), allocation(1, FILTER))
        .unwrap();
    assert!(
        overlay.check_commit_base(&f.db).is_err(),
        "a concurrent committee-row insertion must conflict with the indexed scan"
    );
    assert!(f.registry.committee_scan(&f.crdt).unwrap().is_none());
}

#[test]
fn archive_epoch_census_matches_a_full_registry_after_branch_edits() {
    let f = Fixture::new();
    let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 2000;
    let members: Vec<_> = (0x10..0x16)
        .map(|p| (p, if p < 0x12 { frame - 1000 } else { frame - 10 }, 0))
        .collect();
    seed_signers(
        &f.store,
        &quil_store::encoding::prover_registry_shard(),
        FILTER,
        &members,
        frame,
    );
    let base = f.store.capture_tree_snapshot().unwrap().unwrap();
    f.registry
        .inner
        .write()
        .unwrap()
        .refresh_rows(base.as_ref(), RegistryLimits::UNBOUNDED, true, None)
        .unwrap();
    let (overlay, registry, _) = f.branch(None);
    let store = quil_store::OverlayHypergraphStore::new(overlay.clone());
    let refresh = || {
        registry
            .refresh_archive_epoch(&store, |_, _| {
                panic!("private branch consulted canonical journal")
            })
            .unwrap()
    };
    let compare_full = || {
        let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
        let mut full = InMemoryProverRegistry::new();
        full.refresh_rows(snapshot.as_ref(), RegistryLimits::UNBOUNDED, true, None)
            .unwrap();
        assert_eq!(
            registry.read(InMemoryProverRegistry::content),
            full.content()
        );
        let scan = registry.scan_eviction_candidates(frame, 500, &HashMap::new());
        assert_eq!(
            scan,
            full.scan_eviction_candidates(frame, 500, &HashMap::new())
        );
        scan.candidates
    };
    assert_eq!(refresh(), RegistryCatchUp::Current);
    assert_eq!(compare_full().len(), 2);
    let before_edits = store.capture_tree_snapshot().unwrap().unwrap();
    let removed = physical("removes", 0x90, Some(3));
    overlay
        .apply(&[OverlayMutation::Put(removed.clone(), vec![])])
        .unwrap();
    let after_removal = store.capture_tree_snapshot().unwrap().unwrap();
    overlay
        .apply(&[OverlayMutation::Put(
            physical("adds", 2, Some(4)),
            prover(2, 2),
        )])
        .unwrap();
    assert_eq!(before_edits.written_registry_keys().unwrap(), Some(vec![]));
    assert_eq!(
        after_removal.written_registry_keys().unwrap(),
        Some(vec![removed])
    );
    let before = overlay.stats().read_operations;
    assert_eq!(refresh(), RegistryCatchUp::Updated { rows: 2 });
    let incremental = overlay.stats().read_operations - before;
    let before = overlay.stats().read_operations;
    let candidates = compare_full();
    let full = overlay.stats().read_operations - before;
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].prover_address, vec![0x11; 32]);
    assert!(
        incremental * 8 < full,
        "{incremental} incremental vs {full} full reads"
    );
    eprintln!("archive epoch fixture: {incremental} incremental vs {full} full overlay reads");

    // A logical activity edit is outside the two written rows. An incremental
    // refresh would incorrectly spare this candidate from the committed census.
    assert_eq!(
        registry
            .inner
            .write()
            .unwrap()
            .update_prover_activity(&[0x11; 32], FILTER, frame),
        1
    );
    assert!(registry
        .scan_eviction_candidates(frame, 500, &HashMap::new())
        .candidates
        .is_empty());
    assert_eq!(refresh(), RegistryCatchUp::Refreshed);
    assert_eq!(compare_full(), candidates);

    // Removing an unknown range cannot be resolved by enumerating point writes.
    overlay
        .apply(&[OverlayMutation::DeleteRange(
            physical("adds", 0x91, None),
            physical("adds", 0x92, None),
        )])
        .unwrap();
    assert_eq!(refresh(), RegistryCatchUp::Refreshed);
    assert!(compare_full().is_empty());
    assert_eq!(
        f.registry
            .scan_eviction_candidates(frame, 500, &HashMap::new())
            .candidates
            .len(),
        2
    );
}

#[test]
fn archive_epoch_reuses_unchanged_rows_with_one_read_handle_and_tracks_conflicts() {
    let f = Fixture::new();
    let mut limits = registry_overlay_limits();
    limits.max_cursors = 1;
    let overlay = Arc::new(ExecutionOverlay::capture(f.db.clone(), limits).unwrap());
    let store = quil_store::OverlayHypergraphStore::new(overlay.clone());
    let registry = SharedProverRegistry::for_materialization_overlay(
        &store,
        RegistryLimits::UNBOUNDED,
        Some(&f.registry),
        &overlay,
        true,
    )
    .unwrap();
    assert_eq!(
        registry
            .refresh_archive_epoch(&store, |_, _| unreachable!())
            .unwrap(),
        RegistryCatchUp::Current
    );
    f.db.put(physical("adds", 17, Some(1)), allocation(1, FILTER))
        .unwrap();
    assert!(overlay.check_commit_base(&f.db).is_err());
}

#[test]
fn archive_epoch_canonical_refresh_requires_a_covered_journal() {
    let f = Fixture::new();
    f.db.enable_watched_journal().unwrap();
    let refresh = || {
        f.registry
            .refresh_archive_epoch(f.store.as_ref(), |database, sequence| {
                f.crdt.watched_writes_since_for(
                    database,
                    sequence,
                    &quil_store::encoding::prover_registry_key_prefixes(),
                )
            })
            .unwrap()
    };
    assert_eq!(refresh(), RegistryCatchUp::Current);
    f.db.put(physical("removes", 8, None), b"deleted").unwrap();
    assert_eq!(refresh(), RegistryCatchUp::Updated { rows: 1 });
    compare(&f.registry, &f.crdt, &[2]);
    f.db.delete(physical("removes", 8, None)).unwrap();
    assert_eq!(
        f.registry
            .refresh_archive_epoch(f.store.as_ref(), |database, sequence| f
                .crdt
                .watched_writes_since_for(database, sequence, &[b"unwatched prefix".to_vec()]))
            .unwrap(),
        RegistryCatchUp::Refreshed
    );
    let fresh = SharedProverRegistry::new();
    assert_eq!(
        fresh
            .refresh_archive_epoch(f.store.as_ref(), |_, _| panic!(
                "uninitialized cache consulted journal"
            ))
            .unwrap(),
        RegistryCatchUp::Refreshed
    );
    assert_eq!(
        f.registry.read(InMemoryProverRegistry::content),
        fresh.read(InMemoryProverRegistry::content)
    );
    assert_eq!(
        f.registry
            .read(|r| r.get_prover_info(&[1; 32]).unwrap().allocations.len()),
        1
    );
}
