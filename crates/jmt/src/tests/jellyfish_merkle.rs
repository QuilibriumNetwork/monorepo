// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::SimpleHasher;
use crate::{
    mock::MockTreeStore,
    node_type::{Child, Children, Node, NodeKey, NodeType},
    storage::{TreeReader, TreeUpdateBatch},
    tests::helper::{
        arb_existent_kvs_and_deletions_and_nonexistent_keys, arb_existent_kvs_and_nonexistent_keys,
        arb_interleaved_insertions_and_deletions, arb_kv_pair_with_distinct_last_nibble,
        arb_partitions, arb_tree_with_index,
        test_clairvoyant_construction_matches_interleaved_construction, test_get_leaf_count,
        test_get_range_proof, test_get_with_proof, test_get_with_proof_with_deletions,
        test_get_with_proof_with_distinct_last_nibble,
    },
    types::{
        nibble::{nibble_path::NibblePath, Nibble},
        Version,
    },
    JellyfishMerkleTree, KeyHash, MissingRootError, SPARSE_MERKLE_PLACEHOLDER_HASH,
};

fn update_nibble(original_key: &KeyHash, n: usize, nibble: u8) -> KeyHash {
    assert!(nibble < 16);
    let mut key = original_key.0;
    key[n / 2] = if n % 2 == 0 {
        key[n / 2] & 0x0f | nibble << 4
    } else {
        key[n / 2] & 0xf0 | nibble
    };
    KeyHash(key)
}

macro_rules! impl_jellyfish_tests_for_hasher {
    ($name:ident, $hasher:ty) => {
        mod $name {
            use proptest::collection::btree_set;
            use proptest::prelude::*;
            use super::KeyHash;

            instantiate_test_for_hasher!(test_insert_to_empty_tree, $hasher);
            instantiate_test_for_hasher!(test_insert_at_leaf_with_internal_created, $hasher);
            instantiate_test_for_hasher!(test_insert_at_leaf_with_multiple_internals_created, $hasher);
            instantiate_test_for_hasher!(test_batch_insertion, $hasher);
            instantiate_test_for_hasher!(test_non_existence, $hasher);
            instantiate_test_for_hasher!(test_missing_root, $hasher);
            instantiate_test_for_hasher!(test_non_batch_empty_write_set, $hasher);
            instantiate_test_for_hasher!(test_put_value_sets, $hasher);
            instantiate_test_for_hasher!(test_1000_keys, $hasher);
            instantiate_test_for_hasher!(test_1000_versions, $hasher);
            instantiate_test_for_hasher!(test_delete_then_get_in_one, $hasher);
            instantiate_test_for_hasher!(test_two_gets_then_delete, $hasher);


            proptest! {
                #[test]
                fn proptest_get_with_proof((existent_kvs, nonexistent_keys) in super::arb_existent_kvs_and_nonexistent_keys(1000, 100)) {
                    super::test_get_with_proof::<$hasher>((existent_kvs, nonexistent_keys))
                }

                #[test]
                fn proptest_get_with_proof_with_deletions((existent_kvs, deletions, nonexistent_keys) in super::arb_existent_kvs_and_deletions_and_nonexistent_keys(1000, 100)) {
                    super::test_get_with_proof_with_deletions::<$hasher>((existent_kvs, deletions, nonexistent_keys))
                }

                // This is a replica of the test below, with the values tuned to the smallest values that were
                // useful when isolating bugs. Set `PROPTEST_MAX_SHRINK_ITERS=5000000` to shrink enough to
                // isolate bugs down to minimal examples when hunting using this test. Good hunting.
                #[test]
                fn proptest_clairvoyant_construction_matches_interleaved_construction_small(
                    operations_by_version in
                        (1usize..4) // possible numbers of versions
                            .prop_flat_map(|versions| {
                                super::arb_interleaved_insertions_and_deletions::<$hasher>(2, 1, 5, 15) // (distinct keys, distinct values, insertions, deletions)
                                    .prop_flat_map(move |ops| super::arb_partitions(versions, ops))
                        })
                ) {
                    super::test_clairvoyant_construction_matches_interleaved_construction::<$hasher>(operations_by_version)
                }

                // This is a replica of the test above, but with much larger parameters for more exhaustive
                // testing. It won't feasibly shrink to a useful counterexample because the generators for these
                // tests are not very efficient for shrinking. For some exhaustive fuzzing, try setting
                // `PROPTEST_CASES=10000`, which takes about 30 seconds on a fast machine.
                #[test]
                fn proptest_clairvoyant_construction_matches_interleaved_construction(
                    operations_by_version in
                        (1usize..500) // possible numbers of versions
                            .prop_flat_map(|versions| {
                                super::arb_interleaved_insertions_and_deletions::<$hasher>(100, 100, 1000, 1000) // (distinct keys, distinct values, insertions, deletions)
                                    .prop_flat_map(move |ops| super::arb_partitions(versions, ops))
                        })
                ) {
                    super::test_clairvoyant_construction_matches_interleaved_construction::<$hasher>(operations_by_version)
                }

                #[test]
                fn proptest_get_with_proof_with_distinct_last_nibble((kv1, kv2) in super::arb_kv_pair_with_distinct_last_nibble()) {
                    super::test_get_with_proof_with_distinct_last_nibble::<$hasher>((kv1, kv2))
                }

                #[test]
                fn proptest_get_range_proof((btree, n) in super::arb_tree_with_index(1000)) {
                    super::test_get_range_proof::<$hasher>((btree, n))
                }

                #[test]
                fn proptest_get_leaf_count(keys in btree_set(any::<KeyHash>(), 1..1000).prop_map(|m| m.into_iter().collect())) {
                    super::test_get_leaf_count::<$hasher>(keys)
                }
            }

        }
    };
}

macro_rules! instantiate_test_for_hasher {
    ($test_name:ident, $hasher:ty) => {
        #[test]
        fn $test_name() {
            super::$test_name::<$hasher>();
        }
    };
}

fn test_insert_to_empty_tree<H: SimpleHasher>() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    // Tree is initially empty. Root is a null node. We'll insert a key-value pair which creates a
    // leaf node.
    let key = b"testkey";
    let value = vec![1u8, 2u8, 3u8, 4u8];

    // batch version
    let (_new_root_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(KeyHash::with::<H>(key), value.clone())]],
            None,
            0, /* version */
        )
        .unwrap();
    assert!(batch.stale_node_index_batch.is_empty());

    db.write_tree_update_batch(batch).unwrap();

    assert_eq!(
        tree.get(KeyHash::with::<H>(key), 0).unwrap().unwrap(),
        value
    );
}

fn test_insert_at_leaf_with_internal_created<H: SimpleHasher>() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8, 2u8];

    let (_root0_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key1, value1.clone())]],
            None,
            0, /* version */
        )
        .unwrap();

    assert!(batch.stale_node_index_batch.is_empty());
    db.write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.get(key1, 0).unwrap().unwrap(), value1);

    // Insert at the previous leaf node. Should generate an internal node at the root.
    // Change the 1st nibble to 15.
    let key2 = update_nibble(&key1, 0, 15);
    let value2 = vec![3u8, 4u8];

    let (_root1_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key2, value2.clone())]],
            None,
            1, /* version */
        )
        .unwrap();
    assert_eq!(batch.stale_node_index_batch.len(), 1);
    db.write_tree_update_batch(batch).unwrap();

    assert_eq!(tree.get(key1, 0).unwrap().unwrap(), value1);
    assert!(tree.get(key2, 0).unwrap().is_none());
    assert_eq!(tree.get(key2, 1).unwrap().unwrap(), value2);

    // get # of nodes
    assert_eq!(db.num_nodes(), 4 /* 1 + 3 */);

    let internal_node_key = NodeKey::new_empty_path(1);

    let leaf1 = Node::leaf_from_value::<H>(key1, &value1);
    let leaf2 = Node::leaf_from_value::<H>(key2, &value2);
    let mut children = Children::new();
    children.insert(
        Nibble::from(0),
        Child::new(leaf1.hash::<H>(), 1 /* version */, NodeType::Leaf),
    );
    children.insert(
        Nibble::from(15),
        Child::new(leaf2.hash::<H>(), 1 /* version */, NodeType::Leaf),
    );
    let internal = Node::new_internal(children);
    assert_eq!(db.get_node(&NodeKey::new_empty_path(0)).unwrap(), leaf1);
    assert_eq!(
        db.get_node(&internal_node_key.gen_child_node_key(1 /* version */, Nibble::from(0)))
            .unwrap(),
        leaf1
    );
    assert_eq!(
        db.get_node(&internal_node_key.gen_child_node_key(1 /* version */, Nibble::from(15)))
            .unwrap(),
        leaf2
    );
    assert_eq!(db.get_node(&internal_node_key).unwrap(), internal);
}

fn test_insert_at_leaf_with_multiple_internals_created<H: SimpleHasher>() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    // 1. Insert the first leaf into empty tree
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8, 2u8];

    let (_root0_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key1, value1.clone())]],
            None,
            0, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.get(key1, 0).unwrap().unwrap(), value1);

    // 2. Insert at the previous leaf node. Should generate a branch node at root.
    // Change the 2nd nibble to 1.
    let key2 = update_nibble(&key1, 1 /* nibble_index */, 1 /* nibble */);
    let value2 = vec![3u8, 4u8];

    let (_root1_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key2, value2.clone())]],
            None,
            1, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.get(key1, 0).unwrap().unwrap(), value1);
    assert!(tree.get(key2, 0).unwrap().is_none());
    assert_eq!(tree.get(key2, 1).unwrap().unwrap(), value2);

    assert_eq!(db.num_nodes(), 5);

    let internal_node_key = NodeKey::new(1, NibblePath::new_odd(vec![0x00]));

    let leaf1 = Node::leaf_from_value::<H>(key1, value1.as_slice());
    let leaf2 = Node::leaf_from_value::<H>(key2, value2.as_slice());
    let internal = {
        let mut children = Children::new();
        children.insert(
            Nibble::from(0),
            Child::new(leaf1.hash::<H>(), 1 /* version */, NodeType::Leaf),
        );
        children.insert(
            Nibble::from(1),
            Child::new(leaf2.hash::<H>(), 1 /* version */, NodeType::Leaf),
        );
        Node::new_internal(children)
    };

    let root_internal = {
        let mut children = Children::new();
        children.insert(
            Nibble::from(0),
            Child::new(
                internal.hash::<H>(),
                1, /* version */
                NodeType::Internal { leaf_count: 2 },
            ),
        );
        Node::new_internal(children)
    };

    assert_eq!(db.get_node(&NodeKey::new_empty_path(0)).unwrap(), leaf1);
    assert_eq!(
        db.get_node(&internal_node_key.gen_child_node_key(1 /* version */, Nibble::from(0)))
            .unwrap(),
        leaf1,
    );
    assert_eq!(
        db.get_node(&internal_node_key.gen_child_node_key(1 /* version */, Nibble::from(1)))
            .unwrap(),
        leaf2,
    );
    assert_eq!(db.get_node(&internal_node_key).unwrap(), internal);
    assert_eq!(
        db.get_node(&NodeKey::new_empty_path(1)).unwrap(),
        root_internal,
    );

    // 3. Update leaf2 with new value
    let value2_update = vec![5u8, 6u8];
    let (_root2_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key2, value2_update.clone())]],
            None,
            2, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();
    assert!(tree.get(key2, 0).unwrap().is_none());
    assert_eq!(tree.get(key2, 1).unwrap().unwrap(), value2);
    assert_eq!(tree.get(key2, 2).unwrap().unwrap(), value2_update);

    // Get # of nodes.
    assert_eq!(db.num_nodes(), 8);

    // Purge retired nodes.
    db.purge_stale_nodes(1).unwrap();
    assert_eq!(db.num_nodes(), 7);
    db.purge_stale_nodes(2).unwrap();
    assert_eq!(db.num_nodes(), 4);
    assert_eq!(tree.get(key1, 2).unwrap().unwrap(), value1);
    assert_eq!(tree.get(key2, 2).unwrap().unwrap(), value2_update);
}

fn test_batch_insertion<H: SimpleHasher>() {
    // ```text
    //                             internal(root)
    //                            /        \
    //                       internal       2        <- nibble 0
    //                      /   |   \
    //              internal    3    4               <- nibble 1
    //                 |
    //              internal                         <- nibble 2
    //              /      \
    //        internal      6                        <- nibble 3
    //           |
    //        internal                               <- nibble 4
    //        /      \
    //       1        5                              <- nibble 5
    //
    // Total: 12 nodes
    // ```
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8];

    let key2 = update_nibble(&key1, 0, 2);
    let value2 = vec![2u8];
    let value2_update = vec![22u8];

    let key3 = update_nibble(&key1, 1, 3);
    let value3 = vec![3u8];

    let key4 = update_nibble(&key1, 1, 4);
    let value4 = vec![4u8];

    let key5 = update_nibble(&key1, 5, 5);
    let value5 = vec![5u8];

    let key6 = update_nibble(&key1, 3, 6);
    let value6 = vec![6u8];

    let batches = vec![
        vec![(key1, Some(value1))],
        vec![(key2, Some(value2))],
        vec![(key3, Some(value3))],
        vec![(key4, Some(value4))],
        vec![(key5, Some(value5))],
        vec![(key6, Some(value6))],
        vec![(key2, Some(value2_update))],
    ];
    let one_batch = batches.iter().flatten().cloned().collect::<Vec<_>>();

    let mut to_verify = one_batch.clone();
    // key2 was updated so we remove it.
    to_verify.remove(1);
    let verify_fn = |tree: &JellyfishMerkleTree<MockTreeStore, H>, version: Version| {
        to_verify
            .iter()
            .for_each(|(k, v)| assert_eq!(Some(tree.get(*k, version).unwrap().unwrap()), *v))
    };

    // Insert as one batch and update one by one.
    {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let (_root, batch) = tree.put_value_set(one_batch, 0 /* version */).unwrap();
        db.write_tree_update_batch(batch).unwrap();
        verify_fn(&tree, 0);

        // get # of nodes
        assert_eq!(db.num_nodes(), 12);
    }

    // Insert in multiple batches.
    {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let (_roots, batch) = tree.put_value_sets(batches, 0 /* first_version */).unwrap();
        db.write_tree_update_batch(batch).unwrap();
        verify_fn(&tree, 6);

        // get # of nodes
        assert_eq!(db.num_nodes(), 26 /* 1 + 3 + 4 + 3 + 8 + 5 + 2 */);

        // Purge retired nodes('p' means purged and 'a' means added).
        // The initial state of the tree at version 0
        // ```test
        //   1(root)
        // ```
        db.purge_stale_nodes(1).unwrap();
        // ```text
        //   1 (p)           internal(a)
        //           ->     /        \
        //                 1(a)       2(a)
        // add 3, prune 1
        // ```
        assert_eq!(db.num_nodes(), 25);
        db.purge_stale_nodes(2).unwrap();
        // ```text
        //     internal(p)             internal(a)
        //    /        \              /        \
        //   1(p)       2   ->   internal(a)    2
        //                       /       \
        //                      1(a)      3(a)
        // add 4, prune 2
        // ```
        assert_eq!(db.num_nodes(), 23);
        db.purge_stale_nodes(3).unwrap();
        // ```text
        //         internal(p)                internal(a)
        //        /        \                 /        \
        //   internal(p)    2   ->     internal(a)     2
        //   /       \                /   |   \
        //  1         3              1    3    4(a)
        // add 3, prune 2
        // ```
        assert_eq!(db.num_nodes(), 21);
        db.purge_stale_nodes(4).unwrap();
        // ```text
        //            internal(p)                         internal(a)
        //           /        \                          /        \
        //     internal(p)     2                    internal(a)    2
        //    /   |   \                            /   |   \
        //   1(p) 3    4           ->      internal(a) 3    4
        //                                     |
        //                                 internal(a)
        //                                     |
        //                                 internal(a)
        //                                     |
        //                                 internal(a)
        //                                 /      \
        //                                1(a)     5(a)
        // add 8, prune 3
        // ```
        assert_eq!(db.num_nodes(), 18);
        db.purge_stale_nodes(5).unwrap();
        // ```text
        //                  internal(p)                             internal(a)
        //                 /        \                              /        \
        //            internal(p)    2                        internal(a)    2
        //           /   |   \                               /   |   \
        //   internal(p) 3    4                      internal(a) 3    4
        //       |                                      |
        //   internal(p)                 ->          internal(a)
        //       |                                   /      \
        //   internal                          internal      6(a)
        //       |                                |
        //   internal                          internal
        //   /      \                          /      \
        //  1        5                        1        5
        // add 5, prune 4
        // ```
        assert_eq!(db.num_nodes(), 14);
        db.purge_stale_nodes(6).unwrap();
        // ```text
        //                         internal(p)                               internal(a)
        //                        /        \                                /        \
        //                   internal       2(p)                       internal       2(a)
        //                  /   |   \                                 /   |   \
        //          internal    3    4                        internal    3    4
        //             |                                         |
        //          internal                      ->          internal
        //          /      \                                  /      \
        //    internal      6                           internal      6
        //       |                                         |
        //    internal                                  internal
        //    /      \                                  /      \
        //   1        5                                1        5
        // add 2, prune 2
        // ```
        assert_eq!(db.num_nodes(), 12);
        verify_fn(&tree, 6);
    }
}

fn test_non_existence<H: SimpleHasher>() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);
    // ```text
    //                     internal(root)
    //                    /        \
    //                internal      2
    //                   |
    //                internal
    //                /      \
    //               1        3
    // Total: 7 nodes
    // ```
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8];

    let key2 = update_nibble(&key1, 0, 15);
    let value2 = vec![2u8];

    let key3 = update_nibble(&key1, 2, 3);
    let value3 = vec![3u8];

    let (roots, batch) = tree
        .batch_put_value_sets(
            vec![vec![
                (key1, value1.clone()),
                (key2, value2.clone()),
                (key3, value3.clone()),
            ]],
            None,
            0, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.get(key1, 0).unwrap().unwrap(), value1);
    assert_eq!(tree.get(key2, 0).unwrap().unwrap(), value2);
    assert_eq!(tree.get(key3, 0).unwrap().unwrap(), value3);
    // get # of nodes
    assert_eq!(db.num_nodes(), 6);

    // test non-existing nodes.
    // 1. Non-existing node at root node
    {
        let non_existing_key = update_nibble(&key1, 0, 1);
        let (value, proof) = tree.get_with_proof(non_existing_key, 0).unwrap();
        assert_eq!(value, None);
        assert!(proof
            .verify_nonexistence(roots[0], non_existing_key)
            .is_ok());
    }
    // 2. Non-existing node at non-root internal node
    {
        let non_existing_key = update_nibble(&key1, 1, 15);
        let (value, proof) = tree.get_with_proof(non_existing_key, 0).unwrap();
        assert_eq!(value, None);
        assert!(proof
            .verify_nonexistence(roots[0], non_existing_key)
            .is_ok());
    }
    // 3. Non-existing node at leaf node
    {
        let non_existing_key = update_nibble(&key1, 2, 4);
        let (value, proof) = tree.get_with_proof(non_existing_key, 0).unwrap();
        assert_eq!(value, None);
        assert!(proof
            .verify_nonexistence(roots[0], non_existing_key)
            .is_ok());
    }
}

fn test_missing_root<H: SimpleHasher>() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);
    let err = tree
        .get_with_proof(KeyHash::with::<H>(b"testkey"), 0)
        .err()
        .unwrap()
        .downcast::<MissingRootError>()
        .unwrap();
    assert_eq!(err.version, 0);
}

fn test_non_batch_empty_write_set<H: SimpleHasher>() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);
    let (_, batch) = tree.put_value_set(vec![], 0 /* version */).unwrap();
    db.write_tree_update_batch(batch).unwrap();
    let root = tree.get_root_hash(0).unwrap();
    assert_eq!(root.0, SPARSE_MERKLE_PLACEHOLDER_HASH);
}

fn test_put_value_sets<H: SimpleHasher>() {
    let mut keys = vec![];
    let mut values = vec![];
    let total_updates = 20;
    for i in 0..total_updates {
        keys.push(KeyHash::with::<H>(format!("key{}", i)));
        values.push(format!("value{}", i).into_bytes());
    }

    let mut root_hashes_one_by_one = vec![];
    let mut batch_one_by_one = TreeUpdateBatch::default();
    {
        let mut iter = keys
            .clone()
            .into_iter()
            .zip(values.clone().into_iter().map(Some));
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::<_, H>::new(&db);
        for version in 0..10 {
            let mut keyed_value_set = vec![];
            for _ in 0..total_updates / 10 {
                keyed_value_set.push(iter.next().unwrap());
            }
            let (root, batch) = tree
                .put_value_set(keyed_value_set, version as Version)
                .unwrap();
            db.write_tree_update_batch(batch.clone()).unwrap();
            root_hashes_one_by_one.push(root);
            batch_one_by_one.node_batch.merge(batch.node_batch);
            batch_one_by_one
                .stale_node_index_batch
                .extend(batch.stale_node_index_batch);
            batch_one_by_one.node_stats.extend(batch.node_stats);
        }
    }
    {
        let mut iter = keys.into_iter().zip(values.into_iter());
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::<_, H>::new(&db);
        let mut value_sets = vec![];
        for _ in 0..10 {
            let mut keyed_value_set = vec![];
            for _ in 0..total_updates / 10 {
                keyed_value_set.push(iter.next().unwrap());
            }
            value_sets.push(keyed_value_set);
        }
        let (root_hashes, batch) = tree
            .batch_put_value_sets(value_sets, None, 0 /* version */)
            .unwrap();
        assert_eq!(root_hashes, root_hashes_one_by_one);
        assert_eq!(batch, batch_one_by_one);
    }
}

fn many_keys_get_proof_and_verify_tree_root<H: SimpleHasher>(seed: &[u8], num_keys: usize) {
    assert!(seed.len() < 32);
    let mut actual_seed = [0u8; 32];
    actual_seed[..seed.len()].copy_from_slice(seed);
    let _rng: StdRng = StdRng::from_seed(actual_seed);

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    let mut kvs = vec![];
    for i in 0..num_keys {
        let key = KeyHash::with::<H>(format!("key{}", i));
        let value = format!("value{}", i).into_bytes();
        kvs.push((key, value));
    }

    let (roots, batch) = tree
        .batch_put_value_sets(vec![kvs.clone()], None, 0 /* version */)
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();

    for (k, v) in kvs {
        let (value, proof) = tree.get_with_proof(k, 0).unwrap();
        assert_eq!(value.unwrap(), *v);
        assert!(proof.verify(roots[0], k, Some(v)).is_ok());
    }
}

fn test_1000_keys<H: SimpleHasher>() {
    let seed: &[_] = &[1, 2, 3, 4];
    many_keys_get_proof_and_verify_tree_root::<H>(seed, 1000);
}

fn many_versions_get_proof_and_verify_tree_root<H: SimpleHasher>(seed: &[u8], num_versions: usize) {
    assert!(seed.len() < 32);
    let mut actual_seed = [0u8; 32];
    actual_seed[..seed.len()].copy_from_slice(seed);
    let mut rng: StdRng = StdRng::from_seed(actual_seed);

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    let mut kvs = vec![];
    let mut roots = vec![];

    for i in 0..num_versions {
        let key = KeyHash::with::<H>(format!("key{}", i));
        let value = format!("value{}", i).into_bytes();
        let new_value = format!("new_value{}", i).into_bytes();
        kvs.push((key, value.clone(), new_value.clone()));
    }

    for (idx, (k, v_old, _v_new)) in kvs.iter().enumerate() {
        let (root, batch) = tree
            .batch_put_value_sets(vec![vec![(*k, v_old.clone())]], None, idx as Version)
            .unwrap();
        roots.push(root[0]);
        db.write_tree_update_batch(batch).unwrap();
    }

    // Update value of all keys
    for (idx, (k, _v_old, v_new)) in kvs.iter().enumerate() {
        let version = (num_versions + idx) as Version;
        let (root, batch) = tree
            .batch_put_value_sets(vec![vec![(*k, v_new.clone())]], None, version)
            .unwrap();
        roots.push(root[0]);
        db.write_tree_update_batch(batch).unwrap();
    }

    for (i, (k, v, _)) in kvs.iter().enumerate() {
        let random_version = rng.gen_range(i..i + num_versions);
        let (value, proof) = tree.get_with_proof(*k, random_version as Version).unwrap();
        assert_eq!(value.unwrap(), *v);
        assert!(proof.verify(roots[random_version], *k, Some(v)).is_ok());
    }

    for (i, (k, _, v)) in kvs.iter().enumerate() {
        let random_version = rng.gen_range(i + num_versions..2 * num_versions);
        let (value, proof) = tree.get_with_proof(*k, random_version as Version).unwrap();
        assert_eq!(value.unwrap(), *v);
        assert!(proof.verify(roots[random_version], *k, Some(v)).is_ok());
    }
}

fn test_1000_versions<H: SimpleHasher>() {
    let seed: &[_] = &[1, 2, 3, 4];
    many_versions_get_proof_and_verify_tree_root::<H>(seed, 1000);
}

fn test_delete_then_get_in_one<H: SimpleHasher>() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    let key1: KeyHash = KeyHash([1; 32]);
    let key2: KeyHash = KeyHash([2; 32]);

    let value = "".to_string().into_bytes();

    let (_root, batch) = tree
        .put_value_set(
            vec![(key1, None), (key2, Some(value))],
            0, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();
}

fn test_two_gets_then_delete<H: SimpleHasher>() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    let key1: KeyHash = KeyHash([1; 32]);

    let value = "".to_string().into_bytes();

    let (_root, batch) = tree
        .put_value_set(
            vec![(key1, Some(value.clone())), (key1, Some(value))],
            0, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();

    let (_root, batch) = tree
        .put_value_set(vec![(key1, None)], 0 /* version */)
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();
}

// Implement the test suite for sha256
impl_jellyfish_tests_for_hasher!(sha256_tests, sha2::Sha256);

// Optionally implement the test suite for blake3
#[cfg(feature = "blake3_tests")]
impl_jellyfish_tests_for_hasher!(blake3_tests, blake3::Hasher);
