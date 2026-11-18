//! A frame's commitment over leaves an earlier build stored whole: they are
//! converted to the chunked layout off the proposal path, and the root is the
//! one the whole replicas give, byte for byte.
use std::sync::Arc;
use std::time::{Duration, Instant};

use quil_crypto::storage_proof::{
    opening_index, openings_root, MerkleTree, Node, Tree, CAP_HEIGHT, NODE_BYTES,
};
use quil_execution::global_intrinsic::leaf_id_bytes;
use quil_store::replica_store::{wait_for_background_work, ReplicaStore};
use quil_types::consensus::{StorageSeatSlot, STORAGE_QUERIES_PER_LEAF};
use quil_types::error::QuilError;
use quil_types::store::KvDb;

const MEMBER: [u8; 32] = [0x5A; 32];
const FILTER: [u8; 35] = [0x3C; 35];

fn replica(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9) | 1;
    (0..n * NODE_BYTES / 4)
        .flat_map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 2).to_le_bytes()
        })
        .collect()
}

/// The value builds before the chunked layout stored a hash leaf as, under
/// `[STORAGE_REPLICA][epoch BE][leaf_id]`.
fn put_legacy(db: &dyn KvDb, epoch: u64, leaf_id: &[u8], nodes: &[u8], tree: &MerkleTree) {
    let cap = tree.cap(CAP_HEIGHT).to_bytes();
    let mut root = vec![0u8; 2 * NODE_BYTES];
    root.extend_from_slice(&tree.commitment(Tree::Replica));
    let mut key = vec![quil_store::encoding::STORAGE_REPLICA];
    key.extend_from_slice(&epoch.to_be_bytes());
    key.extend_from_slice(leaf_id);
    let mut value = vec![0xA5];
    value.extend_from_slice(&(cap.len() as u32).to_be_bytes());
    value.extend_from_slice(&cap);
    value.extend_from_slice(&(root.len() as u32).to_be_bytes());
    value.extend_from_slice(&root);
    value.extend_from_slice(nodes);
    db.set(&key, &value).unwrap();
}

/// A commitment once the leaves it opens are readable.
fn commit(replicas: &ReplicaStore, slot: &StorageSeatSlot, frame: u64, rho_n: &[u8]) -> [u8; 32] {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match quil_engine::storage_snapshot::commitment(
            replicas, &MEMBER, &FILTER, slot, frame, rho_n,
        ) {
            Ok(root) => return root,
            Err(QuilError::ExecutionUnavailable(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(error) => panic!("commitment: {error}"),
        }
    }
}

#[test]
fn a_commitment_over_leaves_stored_whole_equals_the_whole_replica_root() {
    let epoch = 1400;
    let db: Arc<dyn KvDb> = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let replicas = ReplicaStore::new(db.clone());
    let mut leaves = Vec::new();
    let mut prefixes = Vec::new();
    for (i, n) in [3 * (1usize << CAP_HEIGHT) + 77, 5, 1 << CAP_HEIGHT]
        .into_iter()
        .enumerate()
    {
        let prefix = vec![i as u32 * 7, 3];
        let leaf_id = leaf_id_bytes(&FILTER, &prefix);
        let nodes = replica(n, i as u32 + 1);
        let tree = MerkleTree::from_nodes(&nodes).unwrap();
        put_legacy(db.as_ref(), epoch, &leaf_id, &nodes, &tree);
        leaves.push((leaf_id, nodes, tree));
        prefixes.push(prefix);
    }
    let slot = StorageSeatSlot {
        epoch,
        leaves: prefixes,
        registered_at: 900,
        sealed_at: Some(901),
        frames: 0,
        accumulator: [0; 32],
        chained: vec![],
        open: true,
    };
    for (frame, rho_n) in [(77u64, [0x11u8; 32]), (78, [0x12; 32])] {
        let mut values: Vec<Node> = Vec::new();
        for (leaf_id, nodes, tree) in &leaves {
            for query in 0..STORAGE_QUERIES_PER_LEAF {
                let index = opening_index(&rho_n, leaf_id, epoch, &MEMBER, query, tree.n());
                let at = index as usize * NODE_BYTES;
                values.push(nodes[at..at + NODE_BYTES].try_into().unwrap());
            }
        }
        let expected = openings_root(frame, &values).unwrap();
        assert_eq!(
            commit(&replicas, &slot, frame, &rho_n),
            expected,
            "frame {frame}"
        );
    }
    for (leaf_id, _, _) in &leaves {
        assert_eq!(
            replicas.get(epoch, leaf_id).unwrap(),
            None,
            "converted, not kept whole"
        );
    }
    // A leaf the member does not hold commits nothing.
    let mut missing = slot.clone();
    missing.leaves.push(vec![99]);
    assert!(quil_engine::storage_snapshot::commitment(
        &replicas,
        &MEMBER,
        &FILTER,
        &missing,
        80,
        &[0x14; 32]
    )
    .is_err());
    assert_eq!(wait_for_background_work(Duration::from_secs(60)), 0);
}
