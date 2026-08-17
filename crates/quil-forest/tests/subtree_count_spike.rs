//! SPIKE #4: per-shard leaf COUNT via `InternalNode::subtree_leaf_count` — the
//! count half of the unified-app-tree Merkle-sum, and the data signal the split
//! decision needs (UNIFIED_APP_TREE_DESIGN §5/§6.1).
//!
//! Validates that, for the real 64-way / top-6-bit shard layout, a prospective
//! shard's data-bearing leaf count is a width-N sub-range of a JMT internal node
//! (no tree walk, uses jmt's own per-Child leaf_count metadata), the sub-ranges
//! partition the node's total, and — the point — the ≥2-non-empty-children guard
//! is decidable from these counts: a split is meaningful iff ≥2 candidate child
//! ranges are non-empty.

use jmt::mock::MockTreeStore;
use jmt::storage::{Node, NodeKey, NibblePath, TreeReader};
use jmt::{KeyHash, Sha256Jmt};

fn key(byte0: u8, tag: u8) -> KeyHash {
    let mut k = [0u8; 32];
    k[0] = byte0;
    k[31] = tag;
    KeyHash(k)
}

#[test]
fn subtree_leaf_count_partitions_and_decides_the_split_guard() {
    let store = MockTreeStore::default();
    let tree = Sha256Jmt::new(&store);

    // Same layout as spikes #2/#3: shard X = top-6-bits 000000 (byte0 0x00..0x03
    // → 2nd-nibble range [0,4)), shard Y = 000001 (0x04..0x07 → [4,8)). Put an
    // UNEVEN amount of data: 5 leaves in X's range, 2 in Y's, 0 elsewhere.
    let mut kvs: Vec<(KeyHash, Option<Vec<u8>>)> = Vec::new();
    for b in [0x00u8, 0x01, 0x02, 0x03, 0x03] {
        // distinct tags so 0x03 contributes two DISTINCT leaves
        kvs.push((key(b, b.wrapping_add(if b == 0x03 { kvs.len() as u8 } else { 0 })), Some(vec![0xCC, b])));
    }
    for b in [0x04u8, 0x05] {
        kvs.push((key(b, b), Some(vec![0xDD, b])));
    }
    let (_root, batch) = tree.put_value_set(kvs, 0).unwrap();
    store.write_tree_update_batch(batch).unwrap();

    // Fetch the 2nd-nibble internal node (spike #2's node) WITHOUT naming the
    // private `InternalNode` type — let inference bind it.
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

    // Whole-node count == total leaves placed (7), and == subtree_leaf_count over
    // the full width — the [0,16) range reproduces leaf_count().
    let total = n2.leaf_count();
    assert_eq!(total, 7, "7 leaves placed under the 2nd-nibble node");
    assert_eq!(n2.subtree_leaf_count(0, 16), total);

    // Per-shard counts: shard X = range [0,4), shard Y = range [4,8).
    let x = n2.subtree_leaf_count(0, 4);
    let y = n2.subtree_leaf_count(4, 4);
    let z = n2.subtree_leaf_count(8, 4);
    let w = n2.subtree_leaf_count(12, 4);
    println!("shard leaf counts — X:{x} Y:{y} Z:{z} W:{w} (total {total})");
    assert_eq!(x, 5, "shard X holds 5 leaves");
    assert_eq!(y, 2, "shard Y holds 2 leaves");
    assert_eq!(z, 0);
    assert_eq!(w, 0);
    // Sub-ranges PARTITION the parent — merkle-sum composition for counts.
    assert_eq!(x + y + z + w, total);

    // THE SPLIT GUARD, decided purely from these counts. Splitting shard X∪Y at
    // this node (the [0,8) → [0,4)/[4,8) boundary) is MEANINGFUL: both sides are
    // non-empty. Splitting shard X alone deeper toward [0,4) vs its emptier
    // siblings would NOT be (only one non-empty side) — descend instead.
    let candidates = [x, y];
    let non_empty = candidates.iter().filter(|&&c| c > 0).count();
    assert!(
        non_empty >= 2,
        "≥2 data-bearing children ⇒ split is meaningful (guard passes)"
    );

    // Contrast: a hypothetical cut whose data all lands on one side (X range vs
    // the empty Z/W ranges) fails the guard — exactly the empty-split we must
    // suppress and, under the unified tree, descend past.
    let degenerate = [x, z];
    assert!(
        degenerate.iter().filter(|&&c| c > 0).count() < 2,
        "one-sided cut ⇒ guard REJECTS (would produce an empty child)"
    );
    println!("split guard: X|Y cut has {non_empty} non-empty sides ⇒ meaningful; X|Z cut is one-sided ⇒ rejected — SPIKE #4 PASSES");
}
