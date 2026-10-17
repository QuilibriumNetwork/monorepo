use super::*;
use quil_hypergraph::{HypergraphCrdt, Location};

const GLOBAL: [u8; 32] = [0xff; 32];

/// An older build's reset of the GLOBAL prover tree emptied a phase but kept
/// its head marker. Commits read every untouched phase's root strictly, so the
/// first GLOBAL frame after an upgrade fails ("persisted phase head has no
/// root"), and the prover-root repair's sync stops on the same read. Dropping
/// the orphaned marker (the master does so at boot) leaves the empty tree the
/// current reset leaves.
#[test]
fn an_orphaned_head_marker_blocks_global_commits_until_it_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
    let store = Arc::new(RocksHypergraphStore::new(db.clone()));
    let crdt = || {
        let crdt = Arc::new(HypergraphCrdt::new(store.clone(), Arc::new(quil_tries::ShaInclusionProver)));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.clone(), FOREST_NAMESPACE));
        crdt
    };
    let prover = |n: u8| Location { app_address: GLOBAL, data_address: [n; 32] };

    let node = crdt();
    node.add_vertex(&prover(1), b"prover one").unwrap();
    node.commit(1).unwrap();

    // What the old reset left on vertex removes: a marker naming a version
    // that has no tree.
    quil_forest::Forest::with_namespace(db.clone(), FOREST_NAMESPACE)
        .write_head_version(&GLOBAL, quil_forest::Phase::VertexRemoves, 5)
        .unwrap();
    let node = crdt();
    assert!(node.current_forest_phase_root(&GLOBAL, 1).is_err(), "the strict read refuses the marker");
    node.add_vertex(&prover(2), b"prover two").unwrap();
    assert!(node.commit(2).is_err(), "a GLOBAL commit reads the untouched phase strictly");

    let node = crdt();
    assert_eq!(node.orphaned_phase_heads(&GLOBAL).unwrap(), vec![(1, 5)]);
    assert_eq!(node.drop_orphaned_phase_heads(&GLOBAL).unwrap(), vec![(1, 5)]);
    assert!(node.orphaned_phase_heads(&GLOBAL).unwrap().is_empty());
    assert_eq!(node.current_forest_phase_root(&GLOBAL, 1).unwrap(), [0u8; 32], "an empty tree");
    node.add_vertex(&prover(2), b"prover two").unwrap();
    node.commit(2).unwrap();
    assert!(node.drop_orphaned_phase_heads(&GLOBAL).unwrap().is_empty(), "nothing left to drop");
    assert!(crdt().orphaned_phase_heads(&GLOBAL).unwrap().is_empty(), "a live tree is never orphaned");
}

/// Localnet check of the repair tool: plant the marker an older build's
/// reset leaves (GLOBAL vertex removes, a version with no tree) on a COPY of
/// a stopped node's store. `QUIL_PLANT_ORPHANED_HEAD=<store>`.
#[test]
#[ignore]
fn plant_an_orphaned_head_marker() {
    let Ok(path) = std::env::var("QUIL_PLANT_ORPHANED_HEAD") else { return };
    let db = crate::rocksdb_store::RocksDb::open(std::path::Path::new(&path)).unwrap();
    let forest = quil_forest::Forest::with_namespace(db.inner(), FOREST_NAMESPACE);
    assert!(forest.read_head_version(&GLOBAL, quil_forest::Phase::VertexRemoves).unwrap().is_none());
    forest.write_head_version(&GLOBAL, quil_forest::Phase::VertexRemoves, 5).unwrap();
    assert_eq!(forest.orphaned_phase_head(&GLOBAL, quil_forest::Phase::VertexRemoves).unwrap(), Some(5));
}
