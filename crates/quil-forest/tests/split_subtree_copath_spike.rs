//! SPIKE #3: the co-path / sync mechanic for the unified-app-tree shard model.
//!
//! A shard prover holds only its prefix-range subtree. Can it verify a leaf
//! against the SINGLE app root without the whole tree, via
//!     leaf → shard_root  (intra-shard)   composed with
//!     shard_root → app_root  (co-path)?
//!
//! We prove it by replaying jmt's own authentication fold for a leaf (using only
//! the leaf + proof siblings — NO tree) and showing the running hash passes
//! through the independently-computed shard commitment `subtree_hash` — i.e. the
//! shard root is a WAYPOINT on the leaf's path. The siblings past the waypoint
//! are the co-path; folding shard_root up them reproduces the app root.

use jmt::mock::MockTreeStore;
use jmt::proof::SparseMerkleProof;
use jmt::storage::{NibblePath, Node, NodeKey, TreeReader};
use jmt::{KeyHash, RootHash, Sha256Jmt};
use sha2::Sha256;

fn key(byte0: u8, tag: u8) -> KeyHash {
    let mut k = [0u8; 32];
    k[0] = byte0;
    k[31] = tag;
    KeyHash(k)
}

/// bit at tree-depth `d` (MSB-first), matching jmt's `iter_bits`.
fn bit_at(k: &[u8; 32], d: usize) -> bool {
    (k[d / 8] >> (7 - (d % 8))) & 1 == 1
}

#[test]
fn shard_scoped_proof_composes_leaf_to_shard_to_app_root() {
    let store = MockTreeStore::default();
    let tree = Sha256Jmt::new(&store);

    // Same 6-bit-shard layout as spike #2: shard X = top-6-bits 000000
    // (byte0 0x00..0x03), shard Y = 000001 (0x04..0x07), + shard Z at nibble 8.
    let mut kvs: Vec<(KeyHash, Option<Vec<u8>>)> = Vec::new();
    for b in 0u8..8 {
        kvs.push((key(b, b), Some(vec![0xCC, b])));
    }
    kvs.push((key(0x80, 0x80), Some(vec![0xDD, 0])));
    let (app_root, batch) = tree.put_value_set(kvs.clone(), 0).unwrap();
    store.write_tree_update_batch(batch).unwrap();
    let app_root = app_root.0;

    // Independently compute shard X's commitment = width-4 sub-range [0,4) of the
    // 2nd-nibble node (the SAME value spike #2 validated composes to the node).
    let root_key = NodeKey::new(0, NibblePath::new(vec![]));
    let root_internal = match store.get_node_option(&root_key).unwrap().unwrap() {
        Node::Internal(n) => n,
        o => panic!("root not internal: {o:?}"),
    };
    let (nib0, ver0, _) = root_internal
        .children_sorted()
        .map(|(nib, c)| (nib, c.version, c.hash))
        .next()
        .unwrap();
    let n2 = match store
        .get_node_option(&root_key.gen_child_node_key(ver0, nib0))
        .unwrap()
        .unwrap()
    {
        Node::Internal(n) => n,
        o => panic!("2nd-nibble node not internal: {o:?}"),
    };
    let shard_x_root = n2.subtree_hash::<Sha256>(0, 4);

    // A leaf inside shard X. Get its proof and (baseline) verify vs the app root
    // using ONLY (leaf, value, proof) — the light-client property, no tree.
    let probe = key(0x01, 1);
    let value = vec![0xCC, 1u8];
    let (val, proof): (_, SparseMerkleProof<Sha256>) = tree.get_with_proof(probe, 0).unwrap();
    assert_eq!(val.as_deref(), Some(value.as_slice()));
    proof
        .verify_existence(RootHash(app_root), probe, &value)
        .expect("baseline: leaf verifies against app root with no tree");

    // Replay jmt's fold ourselves (leaf + siblings only) and watch for shard_x_root.
    let leaf_h = proof.leaf_node_hash().expect("inclusion proof has a leaf");
    let sibs = proof.sibling_hashes();
    let n = sibs.len();
    println!("proof has {n} siblings (O(depth), tree-size-independent)");

    let mut h = leaf_h;
    let mut waypoint: Option<usize> = None;
    for (i, sib) in sibs.iter().enumerate() {
        // sibling[i] pairs with the key bit at tree-depth (n-1-i); mirrors
        // `iter_bits().rev().skip(256 - n)`.
        let bit = bit_at(&probe.0, n - 1 - i);
        h = if bit {
            SparseMerkleProof::<Sha256>::combine(*sib, h)
        } else {
            SparseMerkleProof::<Sha256>::combine(h, *sib)
        };
        if h == shard_x_root {
            waypoint = Some(i);
        }
    }
    // (1) our replay reaches the app root → the fold is faithful.
    assert_eq!(h, app_root, "(1) replayed fold reaches the app root");
    // (2) the shard commitment IS a waypoint on the leaf's authentication path.
    let split = waypoint.expect("(2) shard_x_root must appear as a fold waypoint");
    println!("(2) shard_x_root is a waypoint after {} intra-shard siblings", split + 1);

    // (3) co-path: fold shard_x_root up the REMAINING siblings → app root, with no
    //     tree and no intra-shard leaves. This is what a syncing shard prover does
    //     ONCE to authenticate its whole subtree's placement.
    let mut hc = shard_x_root;
    for (i, sib) in sibs.iter().enumerate().skip(split + 1) {
        let bit = bit_at(&probe.0, n - 1 - i);
        hc = if bit {
            SparseMerkleProof::<Sha256>::combine(*sib, hc)
        } else {
            SparseMerkleProof::<Sha256>::combine(hc, *sib)
        };
    }
    assert_eq!(hc, app_root, "(3) shard_root + co-path folds to the app root");
    let copath_len = n - (split + 1);
    println!("(3) co-path has {copath_len} siblings: shard_root → app_root — SPIKE #3 PASSES");
}
