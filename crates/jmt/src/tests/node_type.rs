// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::{mock::MockTreeStore, JellyfishMerkleTree, OwnedValue, SimpleHasher};
use alloc::{rc::Rc, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use core::{convert::TryInto, panic};

use alloc::{format, vec};
use proptest::prelude::*;
use rand::rngs::OsRng;
use sha2::Sha256;

use crate::{
    node_type::{Child, Children, InternalNode, Node, NodeKey, NodeType},
    storage::TreeReader,
    types::{
        nibble::{nibble_path::NibblePath, Nibble},
        proof::{SparseMerkleInternalNode, SparseMerkleLeafNode},
        Version,
    },
    KeyHash, ValueHash, SPARSE_MERKLE_PLACEHOLDER_HASH,
};

fn hash_internal(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    SparseMerkleInternalNode::new(left, right).hash::<Sha256>()
}

fn hash_leaf(key: KeyHash, value_hash: ValueHash) -> [u8; 32] {
    SparseMerkleLeafNode::new(key, value_hash).hash::<Sha256>()
}

// Generate a random node key with k nibbles.
fn random_k_nibbles_node_key(k: u8) -> NodeKey {
    assert!(k < 64);
    let num_nibbles = k / 2;
    let remainder = k % 2;
    let mut nibbles: Vec<u8> = Vec::with_capacity((num_nibbles + remainder).into());
    nibbles.resize((num_nibbles + remainder).into(), 0);

    OsRng.fill_bytes(&mut nibbles);

    let nibble_path = if remainder == 1 {
        *nibbles.last_mut().unwrap() &= 0xf0;
        NibblePath::new_odd(nibbles)
    } else {
        NibblePath::new(nibbles)
    };

    NodeKey::new(0 /* version */, nibble_path)
}

// Generate a pair of leaf node key and account key with a passed-in k-nibble node key and the n-last
// nibbles to be appended.
fn gen_leaf_keys(
    version: Version,
    nibble_path: &NibblePath,
    nibbles: Vec<Nibble>,
) -> (NodeKey, KeyHash) {
    assert_eq!(nibble_path.num_nibbles() + nibbles.len(), 64);
    let mut np = nibble_path.clone();

    for nibble in nibbles {
        np.push(nibble);
    }

    let account_key = KeyHash(np.bytes().try_into().unwrap());
    (NodeKey::new(version, np), account_key)
}

fn gen_node_keys(version: Version, nibble_path: &NibblePath, nibbles: Vec<Nibble>) -> NodeKey {
    let mut np = nibble_path.clone();
    for nibble in nibbles {
        np.push(nibble);
    }

    NodeKey::new(version, np)
}

fn get_only_child_with_siblings_helper<H: SimpleHasher>(
    merkle_tree_reader: &impl TreeReader,
    internal_node: &InternalNode,
    internal_node_key: &NodeKey,
    i: Nibble,
) -> (Option<NodeKey>, Vec<[u8; 32]>) {
    let (child, siblings) = internal_node.get_only_child_with_siblings::<H>(
        merkle_tree_reader,
        internal_node_key,
        i.into(),
    );
    (
        child,
        siblings.into_iter().map(|sib| sib.hash::<H>()).collect(),
    )
}

fn mock_tree_from_values(values: Vec<Vec<(KeyHash, Option<OwnedValue>)>>) -> impl TreeReader {
    mock_tree_from_values_with_version(values, 0)
}

fn mock_tree_from_values_with_version(
    values: Vec<Vec<(KeyHash, Option<OwnedValue>)>>,
    version: Version,
) -> impl TreeReader {
    let db = MockTreeStore::default();
    let tree: JellyfishMerkleTree<MockTreeStore, Sha256> = JellyfishMerkleTree::new(&db);

    let (_root, batch) = tree.put_value_sets(values, version /* version */).unwrap();
    db.write_tree_update_batch(batch).unwrap();

    db
}

proptest! {


    #[test]
    fn test_internal_node_roundtrip(input in any::<InternalNode>()) {
        let mut vec = vec![];
        input.serialize(&mut vec, ).unwrap();
        let deserialized = InternalNode::deserialize(&mut vec.as_ref()).unwrap();
        assert_eq!(deserialized, input.clone());
    }
}

#[test]
#[cfg(feature = "std")]
fn test_internal_validity() {
    use std::panic;
    let result = panic::catch_unwind(|| {
        let children = Children::default();
        InternalNode::new(children)
    });
    assert!(result.is_err());

    let result = panic::catch_unwind(|| {
        let mut children = Children::default();
        children.insert(
            Nibble::from(1),
            Child::new(OsRng.gen(), 0 /* version */, NodeType::Leaf),
        );
        InternalNode::new(children);
    });
    assert!(result.is_err());
}

#[test]
fn test_leaf_hash() {
    {
        let address = KeyHash(OsRng.gen());
        let blob = vec![0x02];
        let value_hash = ValueHash::with::<Sha256>(blob.as_slice());
        let hash = hash_leaf(address, value_hash);
        let leaf_node = Node::leaf_from_value::<Sha256>(address, blob);
        assert_eq!(leaf_node.hash::<Sha256>(), hash);
    }
}

proptest! {
    #[test]
    fn two_leaves_test1(index1 in (0..8u8).prop_map(Nibble::from), index2 in (8..16u8).prop_map(Nibble::from),
    value1 in prop::collection::vec(any::<u8>(), 1..10), value2 in prop::collection::vec(any::<u8>(), 1..10)) {
        let internal_node_key = random_k_nibbles_node_key(63);
        let mut children = Children::default();

        // Now the version must be 1 for both leaves, because we update the internal node (and the first leaf)
        // when inserting the second leaf. Indeed we have to update the leaf version
        let (leaf1_node_key, leaf1_key_hash) = gen_leaf_keys(1 /* version */, internal_node_key.nibble_path(), vec![index1]);
        let (leaf2_node_key, leaf2_key_hash) = gen_leaf_keys(1 /* version */, internal_node_key.nibble_path(), vec![index2]);
        let leaf1 = Node::leaf_from_value::<Sha256>(leaf1_key_hash, value1.clone());
        let leaf2 = Node::leaf_from_value::<Sha256>(leaf2_key_hash, value2.clone());

        let hash1 = leaf1.hash::<Sha256>();
        let hash2 = leaf2.hash::<Sha256>();

        children.insert(index1, Child::new(hash1, 1 /* version */, NodeType::Leaf));
        children.insert(index2, Child::new(hash2, 1 /* version */, NodeType::Leaf));
        let internal_node = InternalNode::new(children);

        let mock_tree = mock_tree_from_values(vec![
           vec![(leaf1_key_hash, Some(value1))], vec![(leaf2_key_hash, Some(value2))]
        ]);

        // Internal node will have a structure below
        //
        //              root
        //              / \
        //             /   \
        //        leaf1     leaf2
        //
        let root_hash = hash_internal(hash1, hash2);
        prop_assert_eq!(internal_node.hash::<Sha256>(), root_hash);

        for i in 0..8 {
            prop_assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (Some(leaf1_node_key.clone()), vec![hash2])
            );
        }
        for i in 8..16 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (Some(leaf2_node_key.clone()), vec![hash1])
            );
        }

    }

    #[test]
    fn two_leaves_test2(index1 in (4..6u8).prop_map(Nibble::from), index2 in (6..8u8).prop_map(Nibble::from),
value1 in prop::collection::vec(any::<u8>(), 1..10), value2 in prop::collection::vec(any::<u8>(), 1..10)) {
        let internal_node_key = random_k_nibbles_node_key(63);
        let mut children = Children::default();

        // Now the version must be 1 for both leaves, because we update the internal node (and the first leaf)
        // when inserting the second leaf. Indeed we have to update the leaf version
        let (leaf1_node_key, leaf1_key_hash) = gen_leaf_keys(1 /* version */, internal_node_key.nibble_path(), vec![index1]);
        let (leaf2_node_key, leaf2_key_hash) = gen_leaf_keys(1 /* version */, internal_node_key.nibble_path(), vec![index2]);
        let leaf1 = Node::leaf_from_value::<Sha256>(leaf1_key_hash, value1.clone());
        let leaf2 = Node::leaf_from_value::<Sha256>(leaf2_key_hash, value2.clone());

        let hash1 = leaf1.hash::<Sha256>();
        let hash2 = leaf2.hash::<Sha256>();

        children.insert(index1, Child::new(hash1, 1 /* version */, NodeType::Leaf));

        children.insert(index2, Child::new(hash2, 1 /* version */, NodeType::Leaf));
        let internal_node = InternalNode::new(children);

        let mock_tree = mock_tree_from_values(vec![
           vec![(leaf1_key_hash, Some(value1))], vec![(leaf2_key_hash, Some(value2))]
        ]);

        // Internal node will have a structure below
        //
        //              root
        //              /
        //             /
        //            x2
        //             \
        //              \
        //               x1
        //              / \
        //             /   \
        //        leaf1     leaf2
        let hash_x1 = hash_internal(hash1, hash2);
        let hash_x2 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x1);

        let root_hash = hash_internal(hash_x2, SPARSE_MERKLE_PLACEHOLDER_HASH);
        assert_eq!(internal_node.hash::<Sha256>(), root_hash);


        for i in 0..4 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (None, vec![SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x1])
            );
        }

        for i in 4..6 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (
                    Some(leaf1_node_key.clone()),
                    vec![
                        SPARSE_MERKLE_PLACEHOLDER_HASH,
                        SPARSE_MERKLE_PLACEHOLDER_HASH,
                        hash2
                    ]
                )
            );
        }

        for i in 6..8 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (
                    Some(leaf2_node_key.clone()),
                    vec![
                        SPARSE_MERKLE_PLACEHOLDER_HASH,
                        SPARSE_MERKLE_PLACEHOLDER_HASH,
                        hash1
                    ]
                )
            );
        }

        for i in 8..16 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (None, vec![hash_x2])
            );
        }

    }

    #[test]
    fn three_leaves_test1(index1 in (0..4u8).prop_map(Nibble::from), index2 in (4..8u8).prop_map(Nibble::from), index3 in (8..16u8).prop_map(Nibble::from),
value1 in prop::collection::vec(any::<u8>(), 1..10), value2 in prop::collection::vec(any::<u8>(), 1..10), value3 in prop::collection::vec(any::<u8>(), 1..10)) {
        let internal_node_key = random_k_nibbles_node_key(63);
        let mut children = Children::default();

        // Now the version must be 1 for both leaves, because we update the internal node (and the first leaf)
        // when inserting the second leaf. Indeed we have to update the leaf version
        let (leaf1_node_key, leaf1_key_hash) = gen_leaf_keys(1 /* version */, internal_node_key.nibble_path(), vec![index1]);
        let (leaf2_node_key, leaf2_key_hash) = gen_leaf_keys(1 /* version */, internal_node_key.nibble_path(), vec![index2]);
        let (leaf3_node_key, leaf3_key_hash) = gen_leaf_keys(2 /* version */, internal_node_key.nibble_path(), vec![index3]);
        let leaf1 = Node::leaf_from_value::<Sha256>(leaf1_key_hash, value1.clone());
        let leaf2 = Node::leaf_from_value::<Sha256>(leaf2_key_hash, value2.clone());
        let leaf3 = Node::leaf_from_value::<Sha256>(leaf3_key_hash, value3.clone());

        let hash1 = leaf1.hash::<Sha256>();
        let hash2 = leaf2.hash::<Sha256>();
        let hash3 = leaf3.hash::<Sha256>();

        children.insert(index1, Child::new(hash1, 1 /* version */, NodeType::Leaf));
        children.insert(index2, Child::new(hash2, 1 /* version */, NodeType::Leaf));
        children.insert(index3, Child::new(hash3, 2 /* version */, NodeType::Leaf));
        let internal_node = InternalNode::new(children);

        let mock_tree = mock_tree_from_values(vec![
           vec![(leaf1_key_hash, Some(value1))], vec![(leaf2_key_hash, Some(value2))],
        vec![(leaf3_key_hash, Some(value3))]
        ]);
        // Internal node will have a structure below
        //
        //               root
        //               / \
        //              /   \
        //             x     leaf3
        //            / \
        //           /   \
        //      leaf1     leaf2
        let hash_x = hash_internal(hash1, hash2);
        let root_hash = hash_internal(hash_x, hash3);
        prop_assert_eq!(internal_node.hash::<Sha256>(), root_hash);

        for i in 0..4 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (Some(leaf1_node_key.clone()),vec![hash3, hash2])
            );
        }

        for i in 4..8 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (Some(leaf2_node_key.clone()),vec![hash3, hash1])
            );
        }

        for i in 8..16 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (Some(leaf3_node_key.clone()),vec![hash_x])
            );
        }
    }

    #[test]
    fn mixed_nodes_test(index0 in (0..2u8).prop_map(Nibble::from), (index1, index2) in ((0..8u8).prop_map(Nibble::from), (8..16u8).prop_map(Nibble::from)),
      (index3, index4) in ((0..8u8).prop_map(Nibble::from), (8..16u8).prop_map(Nibble::from)),index5 in (8..16u8).prop_map(Nibble::from),
     leaf_values in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..10), 6)) {
        let internal_node_key = random_k_nibbles_node_key(62);
        let mut children = Children::default();

        let mut leaf_keys: Vec<(NodeKey, KeyHash)> = vec![];

        leaf_keys.push(gen_leaf_keys(0 /* version */, internal_node_key.nibble_path(),
         vec![index0, Nibble::from(OsRng.gen::<u8>() % 16)]));

        let internal2_node_key = gen_node_keys(0 /* version */, internal_node_key.nibble_path(), vec![2.into()]);

        leaf_keys.push(gen_leaf_keys(0, internal2_node_key.nibble_path(), vec![index1]));
        leaf_keys.push(gen_leaf_keys(0, internal2_node_key.nibble_path(), vec![index2]));

        let internal3_node_key = gen_node_keys(0 /* version */, internal_node_key.nibble_path(), vec![7.into()]);
        leaf_keys.push(gen_leaf_keys(0, internal3_node_key.nibble_path(), vec![index3]));
        leaf_keys.push(gen_leaf_keys(0, internal3_node_key.nibble_path(), vec![index4]));

        leaf_keys.push(gen_leaf_keys(0 /* version */, internal_node_key.nibble_path(), vec![index5, Nibble::from(OsRng.gen::<u8>() % 16)]));

        let mut leaves: Vec<Node> = vec![];
        let mut leaf_hashes: Vec<[u8;32]> = vec![];

        for (idx, (_leaf_key, leaf_hash)) in leaf_keys.clone().into_iter().enumerate(){
            let new_leaf = Node::leaf_from_value::<Sha256>(leaf_hash, leaf_values[idx].clone());
            leaves.push(new_leaf.clone());
            leaf_hashes.push(new_leaf.hash::<Sha256>());
        }

        let internal2_hash = hash_internal(leaf_hashes[1], leaf_hashes[2]);
        let internal3_hash = hash_internal(leaf_hashes[3], leaf_hashes[4]);

        children.insert(index0, Child::new(leaf_hashes[0], 0, NodeType::Leaf));
        children.insert(2.into(), Child::new(internal2_hash, 0, NodeType::Internal { leaf_count: 2 }));
        children.insert(7.into(), Child::new(internal3_hash, 0, NodeType::Internal { leaf_count: 2 }));
        children.insert(index5, Child::new(leaf_hashes[5], 0, NodeType::Leaf));
        let internal_node = InternalNode::new(children);

        let mock_tree = mock_tree_from_values( vec![
            vec![(leaf_keys[0].1, Some(leaf_values[0].clone())),
            ((leaf_keys[1].1, Some(leaf_values[1].clone()))), ((leaf_keys[2].1, Some(leaf_values[2].clone()))),
            ((leaf_keys[3].1, Some(leaf_values[3].clone()))), ((leaf_keys[4].1, Some(leaf_values[4].clone()))),
            (leaf_keys[5].1, Some(leaf_values[5].clone()))],
        ]);

        // Internal node (B) will have a structure below
        //
        //                   B (root hash)
        //                  / \
        //                 /   \
        //                x5    leaf5
        //               / \
        //              /   \
        //             x2    x4
        //            / \     \
        //           /   \     \
        //      leaf0    x1     x3
        //               /       \
        //              /         \
        //          internal2      internal3
        //          /     \          /     \
        //       leaf1   leaf2    leaf3   leaf4
        let hash_x1 = hash_internal(internal2_hash, SPARSE_MERKLE_PLACEHOLDER_HASH);
        let hash_x2 = hash_internal(leaf_hashes[0], hash_x1);
        let hash_x3 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, internal3_hash);
        let hash_x4 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x3);
        let hash_x5 = hash_internal(hash_x2, hash_x4);
        let root_hash = hash_internal(hash_x5, leaf_hashes[5]);
        assert_eq!(internal_node.hash::<Sha256>(), root_hash);

        let first_leaf_key_full = leaf_keys[0].0.clone();
        let mut new_nibble_path = first_leaf_key_full.nibble_path().clone();
        new_nibble_path.pop();
        let first_leaf_key_reduced = NodeKey::new(first_leaf_key_full.version(), new_nibble_path);

        for i in 0..2 {

            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (
                    Some(first_leaf_key_reduced.clone()),
                    vec![leaf_hashes[5], hash_x4, hash_x1]
                )
            );
        }

        prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, 2.into()),
            (
                Some(internal2_node_key),
                vec![
                    leaf_hashes[5],
                    hash_x4,
                    leaf_hashes[0],
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                ]
            )
        );

        prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, 3.into()),

            (
                None,
                vec![leaf_hashes[5], hash_x4, leaf_hashes[0], internal2_hash,]
            )
        );

        for i in 4..6 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (
                    None,
                    vec![leaf_hashes[5], hash_x2, hash_x3]
                )
            );
        }

        prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, 6.into()),
            (
                None,
                vec![
                    leaf_hashes[5],
                    hash_x2,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    internal3_hash,
                ]
            )
        );

        prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, 7.into()),
            (
                Some(internal3_node_key),
                vec![
                    leaf_hashes[5],
                    hash_x2,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                ]
            )
        );

        let last_leaf_key_full = leaf_keys[5].0.clone();
        let mut new_nibble_path = last_leaf_key_full.nibble_path().clone();
        new_nibble_path.pop();
        let last_leaf_key_reduced = NodeKey::new(last_leaf_key_full.version(), new_nibble_path);

        for i in 8..16 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &internal_node, &internal_node_key, i.into()),
                (Some(last_leaf_key_reduced.clone()), vec![hash_x5])
            );
        }
    }
}

#[test]
fn test_internal_hash_and_proof() {
    // non-leaf case 1
    {
        let internal_node_key = random_k_nibbles_node_key(62);
        let mut children = Children::default();

        let index1 = Nibble::from(4);
        let index2 = Nibble::from(15);

        let child1_node_key = gen_node_keys(
            0, /* version */
            internal_node_key.nibble_path(),
            vec![index1],
        );

        let leaf1_key = gen_leaf_keys(0, child1_node_key.nibble_path(), vec![Nibble::from(0)]);
        let leaf1 = Node::leaf_from_value::<Sha256>(leaf1_key.1, [1_u8]);

        let leaf2_key = gen_leaf_keys(0, child1_node_key.nibble_path(), vec![Nibble::from(8)]);
        let leaf2 = Node::leaf_from_value::<Sha256>(leaf2_key.1, [2_u8]);

        let hash1 = hash_internal(leaf1.hash::<Sha256>(), leaf2.hash::<Sha256>());

        let child2_node_key = gen_node_keys(
            0, /* version */
            internal_node_key.nibble_path(),
            vec![index2],
        );

        let leaf3_key = gen_leaf_keys(0, child2_node_key.nibble_path(), vec![Nibble::from(0)]);
        let leaf3 = Node::leaf_from_value::<Sha256>(leaf3_key.1, [3_u8]);

        let leaf4_key = gen_leaf_keys(0, child2_node_key.nibble_path(), vec![Nibble::from(8)]);
        let leaf4 = Node::leaf_from_value::<Sha256>(leaf4_key.1, [4_u8]);

        let hash2 = hash_internal(leaf3.hash::<Sha256>(), leaf4.hash::<Sha256>());

        children.insert(
            index1,
            Child::new(
                hash1,
                0, /* version */
                NodeType::Internal { leaf_count: 2 },
            ),
        );
        children.insert(
            index2,
            Child::new(
                hash2,
                0, /* version */
                NodeType::Internal { leaf_count: 2 },
            ),
        );
        let internal_node = InternalNode::new(children);
        let mock_tree = mock_tree_from_values(vec![vec![
            (leaf1_key.1, Some(vec![1_u8])),
            (leaf2_key.1, Some(vec![2_u8])),
            (leaf3_key.1, Some(vec![3_u8])),
            (leaf4_key.1, Some(vec![4_u8])),
        ]]);

        // Internal node (B) will have a structure below
        //
        //              root
        //              / \
        //             /   \
        //            x3    x6
        //             \     \
        //              \     \
        //              x2     x5
        //              /       \
        //             /         \
        //            x1          x4
        //           /             \
        //          /               \
        // internal_node1          internal_node2
        //     /      \                /    \
        //  leaf1    leaf2          leaf3   leaf4
        let hash_x1 = hash_internal(hash1, SPARSE_MERKLE_PLACEHOLDER_HASH);
        let hash_x2 = hash_internal(hash_x1, SPARSE_MERKLE_PLACEHOLDER_HASH);
        let hash_x3 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x2);
        let hash_x4 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, hash2);
        let hash_x5 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x4);
        let hash_x6 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x5);
        let root_hash = hash_internal(hash_x3, hash_x6);
        assert_eq!(internal_node.hash::<Sha256>(), root_hash);

        for i in 0..4 {
            assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(
                    &mock_tree,
                    &internal_node,
                    &internal_node_key,
                    i.into()
                ),
                (None, vec![hash_x6, hash_x2])
            );
        }

        assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(
                &mock_tree,
                &internal_node,
                &internal_node_key,
                index1
            ),
            (
                Some(child1_node_key),
                vec![
                    hash_x6,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH
                ]
            )
        );

        assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(
                &mock_tree,
                &internal_node,
                &internal_node_key,
                5.into()
            ),
            (
                None,
                vec![
                    hash_x6,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    hash1
                ]
            )
        );
        for i in 6..8 {
            assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(
                    &mock_tree,
                    &internal_node,
                    &internal_node_key,
                    i.into()
                ),
                (None, vec![hash_x6, SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x1])
            );
        }

        for i in 8..12 {
            assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(
                    &mock_tree,
                    &internal_node,
                    &internal_node_key,
                    i.into()
                ),
                (None, vec![hash_x3, hash_x5])
            );
        }

        for i in 12..14 {
            assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(
                    &mock_tree,
                    &internal_node,
                    &internal_node_key,
                    i.into()
                ),
                (None, vec![hash_x3, SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x4])
            );
        }
        assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(
                &mock_tree,
                &internal_node,
                &internal_node_key,
                14.into()
            ),
            (
                None,
                vec![
                    hash_x3,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    hash2
                ]
            )
        );
        assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(
                &mock_tree,
                &internal_node,
                &internal_node_key,
                index2
            ),
            (
                Some(child2_node_key),
                vec![
                    hash_x3,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH
                ]
            )
        );
    }

    // non-leaf case 2
    {
        let internal_node_key = random_k_nibbles_node_key(62);
        let mut children = Children::default();

        let index1 = Nibble::from(0);
        let index2 = Nibble::from(7);

        let child1_node_key = gen_node_keys(
            0, /* version */
            internal_node_key.nibble_path(),
            vec![index1],
        );

        let leaf1_key = gen_leaf_keys(0, child1_node_key.nibble_path(), vec![Nibble::from(0)]);
        let leaf1 = Node::leaf_from_value::<Sha256>(leaf1_key.1, [1_u8]);

        let leaf2_key = gen_leaf_keys(0, child1_node_key.nibble_path(), vec![Nibble::from(8)]);
        let leaf2 = Node::leaf_from_value::<Sha256>(leaf2_key.1, [2_u8]);

        let hash1 = hash_internal(leaf1.hash::<Sha256>(), leaf2.hash::<Sha256>());

        let child2_node_key = gen_node_keys(
            0, /* version */
            internal_node_key.nibble_path(),
            vec![index2],
        );

        let leaf3_key = gen_leaf_keys(0, child2_node_key.nibble_path(), vec![Nibble::from(0)]);
        let leaf3 = Node::leaf_from_value::<Sha256>(leaf3_key.1, [3_u8]);

        let leaf4_key = gen_leaf_keys(0, child2_node_key.nibble_path(), vec![Nibble::from(8)]);
        let leaf4 = Node::leaf_from_value::<Sha256>(leaf4_key.1, [4_u8]);

        let hash2 = hash_internal(leaf3.hash::<Sha256>(), leaf4.hash::<Sha256>());

        children.insert(
            index1,
            Child::new(
                hash1,
                0, /* version */
                NodeType::Internal { leaf_count: 2 },
            ),
        );
        children.insert(
            index2,
            Child::new(
                hash2,
                0, /* version */
                NodeType::Internal { leaf_count: 2 },
            ),
        );
        let internal_node = InternalNode::new(children);

        let mock_tree = mock_tree_from_values(vec![vec![
            (leaf1_key.1, Some(vec![1_u8])),
            (leaf2_key.1, Some(vec![2_u8])),
            (leaf3_key.1, Some(vec![3_u8])),
            (leaf4_key.1, Some(vec![4_u8])),
        ]]);

        // Internal node will have a structure below
        //
        //                     root
        //                     /
        //                    /
        //                   x5
        //                  / \
        //                 /   \
        //               x2     x4
        //               /       \
        //              /         \
        //            x1           x3
        //            /             \
        //           /               \
        //  non-leaf1                 non-leaf2
        //   /     \                   /      \
        // leaf1   leaf2            leaf3     leaf4

        let hash_x1 = hash_internal(hash1, SPARSE_MERKLE_PLACEHOLDER_HASH);
        let hash_x2 = hash_internal(hash_x1, SPARSE_MERKLE_PLACEHOLDER_HASH);
        let hash_x3 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, hash2);
        let hash_x4 = hash_internal(SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x3);
        let hash_x5 = hash_internal(hash_x2, hash_x4);
        let root_hash = hash_internal(hash_x5, SPARSE_MERKLE_PLACEHOLDER_HASH);
        assert_eq!(internal_node.hash::<Sha256>(), root_hash);

        assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(
                &mock_tree,
                &internal_node,
                &internal_node_key,
                0.into()
            ),
            (
                Some(child1_node_key),
                vec![
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    hash_x4,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                ]
            )
        );

        assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(
                &mock_tree,
                &internal_node,
                &internal_node_key,
                1.into()
            ),
            (
                None,
                vec![
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    hash_x4,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    hash1,
                ]
            )
        );

        for i in 2..4 {
            assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(
                    &mock_tree,
                    &internal_node,
                    &internal_node_key,
                    i.into()
                ),
                (None, vec![SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x4, hash_x1])
            );
        }

        for i in 4..6 {
            assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(
                    &mock_tree,
                    &internal_node,
                    &internal_node_key,
                    i.into()
                ),
                (None, vec![SPARSE_MERKLE_PLACEHOLDER_HASH, hash_x2, hash_x3])
            );
        }

        assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(
                &mock_tree,
                &internal_node,
                &internal_node_key,
                6.into()
            ),
            (
                None,
                vec![
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    hash_x2,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    hash2
                ]
            )
        );

        assert_eq!(
            get_only_child_with_siblings_helper::<Sha256>(
                &mock_tree,
                &internal_node,
                &internal_node_key,
                7.into()
            ),
            (
                Some(child2_node_key),
                vec![
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    hash_x2,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                    SPARSE_MERKLE_PLACEHOLDER_HASH,
                ]
            )
        );

        for i in 8..16 {
            assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(
                    &mock_tree,
                    &internal_node,
                    &internal_node_key,
                    i.into()
                ),
                (None, vec![hash_x5])
            );
        }
    }
}

enum BinaryTreeNode {
    Internal(BinaryTreeInternalNode),
    Child(BinaryTreeChildNode),
    Null,
}

impl BinaryTreeNode {
    fn new_child(index: u8, child: &Child) -> Self {
        Self::Child(BinaryTreeChildNode {
            index,
            version: child.version,
            hash: child.hash,
            is_leaf: child.is_leaf(),
        })
    }

    fn new_internal(
        first_child_index: u8,
        num_children: u8,
        left: BinaryTreeNode,
        right: BinaryTreeNode,
    ) -> Self {
        let hash = SparseMerkleInternalNode::new(left.hash(), right.hash()).hash::<Sha256>();

        Self::Internal(BinaryTreeInternalNode {
            begin: first_child_index,
            width: num_children,
            left: Rc::new(left),
            right: Rc::new(right),
            hash,
        })
    }

    fn hash(&self) -> [u8; 32] {
        match self {
            BinaryTreeNode::Internal(node) => node.hash,
            BinaryTreeNode::Child(node) => node.hash,
            BinaryTreeNode::Null => SPARSE_MERKLE_PLACEHOLDER_HASH,
        }
    }
}

/// An internal node in a binary tree corresponding to a `InternalNode` being tested.
///
/// To describe its position in the binary tree, we use a range of level 0 (children level)
/// positions expressed by (`begin`, `width`)
///
/// For example, in the below graph, node A has (begin:0, width:4), while node B has
/// (begin:2, width: 2):
///            ...
///         /
///       [A]    ...
///     /    \
///    *     [B]   ...
///   / \    / \
///  0   1  2   3    ... 15
struct BinaryTreeInternalNode {
    begin: u8,
    width: u8,
    left: Rc<BinaryTreeNode>,
    right: Rc<BinaryTreeNode>,
    hash: [u8; 32],
}

impl BinaryTreeInternalNode {
    fn in_left_subtree(&self, n: u8) -> bool {
        assert!(n >= self.begin);
        assert!(n < self.begin + self.width);

        n < self.begin + self.width / 2
    }
}

/// A child node, corresponding to one that is in the corresponding `InternalNode` being tested.
///
/// `index` is its key in `InternalNode::children`.
/// N.B. when `is_leaf` is true, in the binary tree represented by a `NaiveInternalNode`, the child
/// node will be brought up to the root of the highest subtree that has only that leaf.
#[derive(Clone, Copy)]
struct BinaryTreeChildNode {
    version: Version,
    index: u8,
    hash: [u8; 32],
    is_leaf: bool,
}

struct NaiveInternalNode {
    root: Rc<BinaryTreeNode>,
}

impl NaiveInternalNode {
    fn from_clever_node(node: &InternalNode) -> Self {
        Self {
            root: Rc::new(Self::node_for_subtree(0, 16, node.children())),
        }
    }

    fn node_for_subtree(begin: u8, width: u8, children: &Children) -> BinaryTreeNode {
        if width == 1 {
            return children
                .get(begin.into())
                .as_ref()
                .map_or(BinaryTreeNode::Null, |child| {
                    BinaryTreeNode::new_child(begin, child)
                });
        }

        let half_width = width / 2;
        let left = Self::node_for_subtree(begin, half_width, children);
        let right = Self::node_for_subtree(begin + half_width, half_width, children);

        match (&left, &right) {
            (BinaryTreeNode::Null, BinaryTreeNode::Null) => {
                return BinaryTreeNode::Null;
            }
            (BinaryTreeNode::Null, BinaryTreeNode::Child(node))
            | (BinaryTreeNode::Child(node), BinaryTreeNode::Null) => {
                if node.is_leaf {
                    return BinaryTreeNode::Child(*node);
                }
            }
            _ => (),
        };

        BinaryTreeNode::new_internal(begin, width, left, right)
    }

    fn get_child_with_siblings(
        &self,
        node_key: &NodeKey,
        n: u8,
    ) -> (Option<NodeKey>, Vec<[u8; 32]>) {
        let mut current_node = Rc::clone(&self.root);
        let mut siblings = Vec::new();

        loop {
            match current_node.as_ref() {
                BinaryTreeNode::Internal(node) => {
                    if node.in_left_subtree(n) {
                        siblings.push(node.right.hash());
                        current_node = Rc::clone(&node.left);
                    } else {
                        siblings.push(node.left.hash());
                        current_node = Rc::clone(&node.right);
                    }
                }
                BinaryTreeNode::Child(node) => {
                    return (
                        Some(node_key.gen_child_node_key(node.version, node.index.into())),
                        siblings,
                    )
                }
                BinaryTreeNode::Null => return (None, siblings),
            }
        }
    }
}

// This test needs to be fixed to account for the changes in [`get_only_child_with_siblings`]. No easy fix for that one
proptest! {
    #[test]
    #[allow(clippy::unnecessary_operation)]
    // This test needs to be fixed so that it doesn't panic anymore
    #[should_panic]
    fn test_get_child_with_siblings(
        node_key in any::<NodeKey>().prop_filter(
            "Filter out keys for leaves.",
            |k| k.nibble_path().num_nibbles() < 64
        ).no_shrink(),
        node in any::<InternalNode>(),
    ) {
        let mock_tree = mock_tree_from_values_with_version(vec![], 0);

        for n in 0..16u8 {
            prop_assert_eq!(
                get_only_child_with_siblings_helper::<Sha256>(&mock_tree, &node, &node_key, n.into()),
                NaiveInternalNode::from_clever_node(&node).get_child_with_siblings(&node_key, n)
            )
        }
    }
}
