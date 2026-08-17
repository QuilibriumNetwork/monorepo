//! SPIKE: is "a shard = an in-place subtree of ONE per-app raw-key JMT" sound,
//! and is a split zero-copy? Validates the load-bearing claims:
//!   (1) app root = jmt internal hash over its children → the children AT the
//!       shard-prefix nibbles ARE the shard commitments (native composition, no
//!       separate hash_pair rollup);
//!   (2) reading a shard's subtree gives its own children = the sub-shard roots
//!       after a split — already present, zero new commit / zero data movement;
//!   (3) a leaf membership proof verifies to the single app root;
//!   (4) the app root is INVARIANT under a split (only the boundary re-interprets).

use jmt::mock::MockTreeStore;
use jmt::storage::{NibblePath, Node, NodeKey, TreeReader};
use jmt::{KeyHash, RootHash, Sha256Jmt};
use sha2::Sha256;

fn key(first: u8, second: u8, tag: u8) -> KeyHash {
    // first nibble = shard, second nibble = sub-shard (for the split demo).
    let mut k = [0u8; 32];
    k[0] = (first << 4) | second;
    k[31] = tag;
    KeyHash(k)
}

#[test]
fn shard_is_an_in_place_subtree_and_split_is_zero_copy() {
    let store = MockTreeStore::default();
    let tree = Sha256Jmt::new(&store);

    // Shard A = top nibble 0x0 (4 leaves at sub-nibbles 0..4 → 4 future sub-shards).
    // Shard B = top nibble 0x8 (4 leaves).
    let mut kvs: Vec<(KeyHash, Option<Vec<u8>>)> = Vec::new();
    for s in 0u8..4 {
        kvs.push((key(0x0, s, s), Some(vec![0xAA, s])));
        kvs.push((key(0x8, s, s), Some(vec![0xBB, s])));
    }
    let (app_root, batch) = tree.put_value_set(kvs.clone(), 0).unwrap();
    store.write_tree_update_batch(batch).unwrap();
    let app_root = app_root.0;

    // ---- (1) app root = internal hash over children; children at nibble 0 / 8
    //          ARE the shard roots.
    let root_key = NodeKey::new(0, NibblePath::new(vec![]));
    let root_internal = match store.get_node_option(&root_key).unwrap().unwrap() {
        Node::Internal(n) => n,
        other => panic!("root is not internal: {other:?}"),
    };
    assert_eq!(
        root_internal.hash::<Sha256>(),
        app_root,
        "(1) app root must equal the jmt internal hash over its children",
    );
    // children_sorted yields the nibbles, so we never have to name/construct Nibble.
    let shards: Vec<_> = root_internal
        .children_sorted()
        .map(|(nib, c)| (nib, c.version, c.hash))
        .collect();
    assert_eq!(shards.len(), 2, "two shards: top nibble 0 and 8");
    let (nib_a, ver_a, shard_a_root) = shards[0];
    let shard_b_root = shards[1].2;
    println!("(1) app_root     = {}", hex::encode(app_root));
    println!("    shard_A root = {}", hex::encode(shard_a_root));
    println!("    shard_B root = {}", hex::encode(shard_b_root));
    assert_ne!(shard_a_root, shard_b_root);

    // ---- (2) SPLIT shard A by the 2nd nibble → read its subtree's children as
    //          the sub-shard roots. No new commit; they already exist.
    let shard_a_key = root_key.gen_child_node_key(ver_a, nib_a);
    let shard_a_internal = match store.get_node_option(&shard_a_key).unwrap().unwrap() {
        Node::Internal(n) => n,
        other => panic!("shard A subtree not internal: {other:?}"),
    };
    assert_eq!(
        shard_a_internal.hash::<Sha256>(),
        shard_a_root,
        "(2) shard A subtree root must equal the child hash the parent commits to",
    );
    let subshards: Vec<_> = shard_a_internal
        .children_sorted()
        .map(|(_n, c)| c.hash)
        .collect();
    for (i, r) in subshards.iter().enumerate() {
        println!("(2) sub-shard A.{i} root = {}", hex::encode(r));
    }
    assert_eq!(subshards.len(), 4, "4 sub-shards, read with ZERO new commit");

    // ---- (3) a leaf proof verifies to the SINGLE app root.
    let probe = key(0x0, 1, 1);
    let (val, proof) = tree.get_with_proof(probe, 0).unwrap();
    assert_eq!(val.as_deref(), Some([0xAA, 1u8].as_slice()));
    proof
        .verify_existence(RootHash(app_root), probe, &[0xAA, 1u8])
        .expect("(3) leaf must verify against the single app root");
    println!("(3) leaf {} verified against app root", hex::encode(probe.0));

    // ---- (4) the app root is INVARIANT: splitting shard A (re-reading deeper
    //          subtree roots) touched nothing.
    let root_again = match store.get_node_option(&root_key).unwrap().unwrap() {
        Node::Internal(n) => n.hash::<Sha256>(),
        _ => unreachable!(),
    };
    assert_eq!(root_again, app_root, "(4) app root invariant under split");
    println!("(4) app root invariant under split — SPIKE PASSES");
}
