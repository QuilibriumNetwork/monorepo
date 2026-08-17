//! SPIKE #2: does a NON-nibble-aligned shard boundary (the real 64-way / top-6-bit
//! QUIL split) still yield a well-defined shard commitment that composes to the
//! single app root, and does a leaf round-trip against that app root?
//!
//! A 6-bit prefix = full 1st nibble (bits 0-3) + top 2 bits of the 2nd nibble
//! (bits 4-5). So a shard is a width-4 sub-range of the 2nd-nibble internal
//! node's 16-way sub-merkle, reachable via the (newly exposed) `subtree_hash`.

use jmt::mock::MockTreeStore;
use jmt::storage::{NibblePath, Node, NodeKey, TreeReader};
use jmt::{KeyHash, RootHash, Sha256Jmt};
use sha2::Sha256;

fn key(byte0: u8, tag: u8) -> KeyHash {
    let mut k = [0u8; 32];
    k[0] = byte0;
    k[31] = tag;
    KeyHash(k)
}

#[test]
fn six_bit_shard_boundary_composes_and_round_trips() {
    let store = MockTreeStore::default();
    let tree = Sha256Jmt::new(&store);

    // Under 1st-nibble 0x0, put 8 leaves at 2nd-nibbles 0..8.
    //   shard X = top-6-bits 0b0000_00 → 2nd-nibbles [0,4)  (byte0 0x00..0x03)
    //   shard Y = top-6-bits 0b0000_01 → 2nd-nibbles [4,8)  (byte0 0x04..0x07)
    // Plus a shard Z at 1st-nibble 0x8 so the ROOT is a real internal node.
    let mut kvs: Vec<(KeyHash, Option<Vec<u8>>)> = Vec::new();
    for b in 0u8..8 {
        kvs.push((key(b, b), Some(vec![0xCC, b]))); // 0x00..0x07 under nibble 0
    }
    kvs.push((key(0x80, 0x80), Some(vec![0xDD, 0]))); // shard Z under nibble 8
    let (app_root, batch) = tree.put_value_set(kvs.clone(), 0).unwrap();
    store.write_tree_update_batch(batch).unwrap();
    let app_root = app_root.0;

    // Descend root → child at 1st nibble 0 (the 2nd-nibble internal node holding X+Y).
    let root_key = NodeKey::new(0, NibblePath::new(vec![]));
    let root_internal = match store.get_node_option(&root_key).unwrap().unwrap() {
        Node::Internal(n) => n,
        o => panic!("root not internal: {o:?}"),
    };
    let (nib0, ver0, nib0_child_hash) = root_internal
        .children_sorted()
        .map(|(nib, c)| (nib, c.version, c.hash))
        .next()
        .expect("first child = nibble 0 subtree");

    let n2_key = root_key.gen_child_node_key(ver0, nib0);
    let n2 = match store.get_node_option(&n2_key).unwrap().unwrap() {
        Node::Internal(n) => n,
        o => panic!("2nd-nibble node not internal: {o:?}"),
    };

    // (A) the helper reproduces the real node hash → any sub-range it returns is
    //     a genuine sub-merkle root that composes UP to this node.
    assert_eq!(
        n2.subtree_hash::<Sha256>(0, 16),
        n2.hash::<Sha256>(),
        "(A) subtree_hash(0,16) must equal the node hash",
    );
    assert_eq!(
        n2.hash::<Sha256>(),
        nib0_child_hash,
        "(A) 2nd-nibble node hash == the child hash the root commits to",
    );

    // (B) the two 6-bit shards are width-4 sub-ranges — well-defined, distinct.
    let shard_x = n2.subtree_hash::<Sha256>(0, 4); // 2nd-nibbles [0,4)
    let shard_y = n2.subtree_hash::<Sha256>(4, 4); // 2nd-nibbles [4,8)
    println!("(B) app_root  = {}", hex::encode(app_root));
    println!("    shard_X   = {}  (top-6-bits 000000)", hex::encode(shard_x));
    println!("    shard_Y   = {}  (top-6-bits 000001)", hex::encode(shard_y));
    assert_ne!(shard_x, shard_y);

    // (C) sub-ranges nest: [0,4)=X and [4,8)=Y both live under [0,8); [0,8) and
    //     [8,16) fold into the node hash. All from the same recursion that (A)
    //     showed reproduces node.hash() — so X and Y are genuine sub-roots that
    //     roll UP to the app-committed child hash.
    let half_lo = n2.subtree_hash::<Sha256>(0, 8); // parent of X and Y
    let half_hi = n2.subtree_hash::<Sha256>(8, 8); // [8,16) (empty here)
    assert_ne!(half_lo, shard_x);
    assert_ne!(half_lo, shard_y);
    println!("(C) nested: X,Y ⊂ [0,8)={}  ; [0,8),[8,16) ⊂ node", hex::encode(half_lo));
    let _ = half_hi;

    // (D) a leaf inside shard X round-trips against the SINGLE app root.
    let probe = key(0x01, 1);
    let (val, proof) = tree.get_with_proof(probe, 0).unwrap();
    assert_eq!(val.as_deref(), Some([0xCC, 1u8].as_slice()));
    proof
        .verify_existence(RootHash(app_root), probe, &[0xCC, 1u8])
        .expect("(D) leaf in a 6-bit shard verifies against the app root");
    println!("(D) leaf in 6-bit shard X verified against app root — SPIKE #2 PASSES");
}
