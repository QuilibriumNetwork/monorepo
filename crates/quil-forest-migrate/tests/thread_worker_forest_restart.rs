//! Regression for #590: a fresh thread-mode worker must put its JMT forest in
//! the same per-worker RocksDB as its hypergraph blobs.  Reconstructing the
//! worker on the same path must therefore recover the advertised state root
//! and extend that tree, rather than starting again from an empty forest.

use std::sync::Arc;

use num_bigint::BigInt;
use quil_hypergraph::{shard_key_for_location, HypergraphCrdt, Location};
use quil_store::RocksHypergraphStore;
use quil_types::store::HypergraphStore;

fn open_db(path: &std::path::Path) -> Arc<quil_store::RocksDb> {
    Arc::new(quil_store::RocksDb::open(path).unwrap())
}

fn vertex_blob(field_key: &[u8], field_value: &[u8]) -> Vec<u8> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(
        field_key,
        field_value,
        &[],
        &BigInt::from(field_value.len() as u64),
    )
    .unwrap();
    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()
}

#[test]
fn fresh_thread_worker_forest_root_survives_restart_and_next_commit() {
    let dir = tempfile::tempdir().unwrap();
    let app = [0x2a; 32];
    let field_key = vec![0xff; 32];
    let first_value = b"state-before-restart".to_vec();
    let first = Location {
        app_address: app,
        data_address: [0x01; 32],
    };
    let shard = shard_key_for_location(&first);

    // First process lifetime: this is a brand-new per-worker DB.  The boot
    // installer must select a RocksDB-backed forest even though there is no
    // migrated forest data yet (the old thread-worker path did not).
    let root_before_restart = {
        let db = open_db(dir.path());
        let hg = Arc::new(RocksHypergraphStore::new(db.inner()));
        assert!(
            !hg.has_forest_data(),
            "brand-new worker DB has no forest data"
        );

        let crdt = HypergraphCrdt::new(
            hg.clone() as Arc<dyn HypergraphStore>,
            Arc::new(quil_tries::ShaInclusionProver),
        );
        assert!(
            quil_forest_migrate::install_forest_boot(&crdt, hg.as_ref(), true, false),
            "fresh worker must install the persistent forest"
        );
        assert!(crdt.forest_is_persistent());

        crdt.add_vertex(&first, &vertex_blob(&field_key, &first_value))
            .unwrap();
        let commits = crdt.commit(1).unwrap();
        let root = commits.get(&shard).expect("worker shard committed")[0].clone();
        assert_eq!(root.len(), 32);
        assert!(root.iter().any(|byte| *byte != 0));
        assert_eq!(
            crdt.compute_shard_root("vertex", "adds", &shard),
            root,
            "the advertised state root is the committed forest root"
        );
        assert!(
            hg.has_forest_data(),
            "worker forest was persisted to its DB"
        );
        root
    };

    // Second process lifetime: model a restored, non-genesis worker cursor by
    // passing `store_is_fresh = false`.  Existing forest data alone must recover
    // the exact root.  Extending it must retain the pre-restart vertex too.
    let db = open_db(dir.path());
    let hg = Arc::new(RocksHypergraphStore::new(db.inner()));
    assert!(
        hg.has_forest_data(),
        "reopened worker DB contains its forest"
    );
    let crdt = HypergraphCrdt::new(
        hg.clone() as Arc<dyn HypergraphStore>,
        Arc::new(quil_tries::ShaInclusionProver),
    );
    assert!(
        quil_forest_migrate::install_forest_boot(&crdt, hg.as_ref(), false, false),
        "restarted worker must reinstall the persistent forest"
    );
    assert_eq!(
        crdt.compute_shard_root("vertex", "adds", &shard),
        root_before_restart,
        "restart must recover the prior frame's state root"
    );

    let second_value = b"state-after-restart".to_vec();
    let second = Location {
        app_address: app,
        data_address: [0x02; 32],
    };
    crdt.add_vertex(&second, &vertex_blob(&field_key, &second_value))
        .unwrap();
    let commits = crdt.commit(2).unwrap();
    let root_after_restart = commits.get(&shard).expect("next worker shard committed")[0].clone();
    assert_ne!(root_after_restart, root_before_restart);
    assert_eq!(
        crdt.compute_shard_root("vertex", "adds", &shard),
        root_after_restart
    );

    let proof = crdt
        .build_membership_proof(
            "vertex",
            "adds",
            &shard,
            &[
                (first.to_id().to_vec(), vec![field_key.clone()]),
                (second.to_id().to_vec(), vec![field_key.clone()]),
            ],
        )
        .expect("restarted worker proves both old and new state");
    let root: [u8; 32] = root_after_restart.try_into().unwrap();
    quil_forest::verify_vertex_membership(
        &root,
        &proof.inputs[0],
        &[(field_key.clone(), first_value)],
    )
    .expect("pre-restart state remains in the extended tree");
    quil_forest::verify_vertex_membership(&root, &proof.inputs[1], &[(field_key, second_value)])
        .expect("post-restart state is committed alongside it");
}
