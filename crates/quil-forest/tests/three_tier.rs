//! End-to-end model of the three-tier forest over a single shared RocksDB:
//! Level-3 shard state trees roll up into a Level-2 app shard-commitment
//! tree, which rolls up into one of the 256 Level-1 global trees. Proves the
//! wiring, determinism, per-tree-id isolation, and on-disk round-trip.

use std::sync::Arc;

use jmt::{KeyHash, RootHash, Sha256Jmt};
use quil_forest::{
    commit, global_tree_index, AppEntry, RocksTreeStore, ShardEntry, TreeId,
};
use sha2::Sha256;

fn open_db(path: &std::path::Path) -> Arc<rocksdb::DB> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    Arc::new(rocksdb::DB::open(&opts, path).unwrap())
}

/// Build a Level-3 shard tree of `n` state leaves; return (root, count, size).
fn build_shard(
    db: &Arc<rocksdb::DB>,
    shard_id: &[u8],
    n: u32,
) -> (RootHash, u64, u128) {
    let store = RocksTreeStore::new(db.clone(), &TreeId::shard(shard_id));
    let mut total_size: u128 = 0;
    let leaves: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
        .map(|i| {
            let key = format!("{}/{}", hex::encode(shard_id), i).into_bytes();
            let val = vec![(i % 251) as u8; 32 + (i as usize % 16)];
            total_size += val.len() as u128;
            (key, val)
        })
        .collect();
    let root = commit(&store, 0, leaves).unwrap();
    (root, n as u64, total_size)
}

#[test]
fn three_tier_rollup_over_shared_rocksdb() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path());

    // ---- Level 3: two shards of one app -------------------------------
    let app_address = vec![0x2a, 0x01, 0x02, 0x03]; // → global tree 0x2a
    let shard_a = vec![0xaa, 0x00];
    let shard_b = vec![0xbb, 0x00];
    let (root_a, n_a, sz_a) = build_shard(&db, &shard_a, 300);
    let (root_b, n_b, sz_b) = build_shard(&db, &shard_b, 120);

    // ---- Level 2: the app's shard-commitment tree ---------------------
    let app_store = RocksTreeStore::new(db.clone(), &TreeId::app(&app_address));
    let l2_leaves = vec![
        (
            shard_a.clone(),
            ShardEntry { shard_commitment: root_a.0, num_leaves: n_a, total_size: sz_a }
                .to_bytes(),
        ),
        (
            shard_b.clone(),
            ShardEntry { shard_commitment: root_b.0, num_leaves: n_b, total_size: sz_b }
                .to_bytes(),
        ),
    ];
    let app_root = commit(&app_store, 0, l2_leaves).unwrap();

    // ---- Level 1: the global tree selected by the app address ---------
    let g_index = global_tree_index(&app_address);
    assert_eq!(g_index, 0x2a);
    let global_store = RocksTreeStore::new(db.clone(), &TreeId::global(g_index));
    let l1_leaves = vec![(
        app_address.clone(),
        AppEntry {
            app_root: app_root.0,
            num_leaves: n_a + n_b,
            total_size: sz_a + sz_b,
            metadata: b"QUIL:token".to_vec(),
        }
        .to_bytes(),
    )];
    let global_root = commit(&global_store, 0, l1_leaves).unwrap();

    // ---- Assertions ---------------------------------------------------
    // Roots are real 32-byte hashes, all distinct across the three levels.
    assert_ne!(global_root.0, app_root.0);
    assert_ne!(app_root.0, root_a.0);
    assert_ne!(root_a.0, root_b.0);

    // A Level-3 state leaf round-trips through its own tree on disk.
    let shard_store = RocksTreeStore::new(db.clone(), &TreeId::shard(&shard_a));
    let tree = Sha256Jmt::new(&shard_store);
    let key = format!("{}/{}", hex::encode(&shard_a), 7u32).into_bytes();
    let got = tree.get(KeyHash::with::<Sha256>(&key), 0).unwrap();
    assert_eq!(got, Some(vec![7u8; 32 + 7]));

    // The Level-2 leaf really carries shard A's root as its commitment.
    let app_tree = Sha256Jmt::new(&app_store);
    let l2_val = app_tree
        .get(KeyHash::with::<Sha256>(&shard_a), 0)
        .unwrap()
        .expect("shard A present in Level-2 tree");
    assert_eq!(&l2_val[..32], &root_a.0[..], "L2 commitment == L3 root");

    // A get-with-proof against the Level-3 root verifies (authenticated read).
    let (val, proof) = tree
        .get_with_proof(KeyHash::with::<Sha256>(&key), 0)
        .unwrap();
    proof
        .verify_existence(root_a, KeyHash::with::<Sha256>(&key), val.as_ref().unwrap())
        .expect("inclusion proof verifies against the shard root");
}

#[test]
fn split_produces_two_independent_shard_trees() {
    // A Level-2 leaf subdividing: shard S becomes S0 + S1, each an
    // independent Level-3 tree with its own root. Demonstrates that split
    // is a forest op (new tree ids), not a tree-internal rewrite.
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path());

    let (root_s0, _, _) = build_shard(&db, b"S0", 64);
    let (root_s1, _, _) = build_shard(&db, b"S1", 64);
    assert_ne!(root_s0.0, root_s1.0);

    // Both live in the same DB, isolated by tree-id prefix: reading S0's
    // tree never sees S1's leaves.
    let s0 = RocksTreeStore::new(db.clone(), &TreeId::shard(b"S0"));
    let tree0 = Sha256Jmt::new(&s0);
    let s1_only_key = format!("{}/{}", hex::encode(b"S1"), 0u32).into_bytes();
    assert_eq!(
        tree0.get(KeyHash::with::<Sha256>(&s1_only_key), 0).unwrap(),
        None,
        "tree-id namespacing keeps sibling shards isolated"
    );
}
