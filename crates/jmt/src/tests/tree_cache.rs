// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use rand::{rngs::OsRng, Rng};
use sha2::Sha256;

use crate::{
    mock::MockTreeStore,
    node_type::{Node, NodeKey},
    storage::LeafNode,
    tree_cache::TreeCache,
    types::{nibble::nibble_path::NibblePath, Version, PRE_GENESIS_VERSION},
    KeyHash, OwnedValue, ValueHash,
};

fn random_leaf_with_key(next_version: Version) -> (LeafNode, OwnedValue, NodeKey) {
    let key: [u8; 32] = OsRng.gen();
    let value: [u8; 32] = OsRng.gen();
    let key_hash: KeyHash = KeyHash::with::<Sha256>(key);
    let node = LeafNode::new(key_hash, ValueHash::with::<Sha256>(value));
    let node_key = NodeKey::new(next_version, NibblePath::new(key_hash.0.to_vec()));
    (node, value.to_vec(), node_key)
}

#[test]
fn test_get_node() {
    let next_version = 0;
    let db = MockTreeStore::default();
    let cache = TreeCache::new(&db, next_version).unwrap();

    let (node, value, node_key) = random_leaf_with_key(next_version);
    db.put_leaf(node_key.clone(), node.clone(), value).unwrap();

    assert_eq!(cache.get_node(&node_key).unwrap(), node.into());
}

#[test]
fn test_root_node() {
    let next_version = 0;
    let db = MockTreeStore::default();
    let mut cache = TreeCache::new(&db, next_version).unwrap();
    assert_eq!(*cache.get_root_node_key(), NodeKey::new_empty_path(0));

    let (node, value, node_key) = random_leaf_with_key(next_version);
    db.put_leaf(node_key.clone(), node, value).unwrap();
    cache.set_root_node_key(node_key.clone());

    assert_eq!(*cache.get_root_node_key(), node_key);
}

#[test]
fn test_pre_genesis() {
    let next_version = 0;
    let db = MockTreeStore::default();
    let pre_genesis_root_key = NodeKey::new_empty_path(PRE_GENESIS_VERSION);
    let (pre_genesis_only_node, pre_genesis_only_value, _) =
        random_leaf_with_key(PRE_GENESIS_VERSION);
    db.put_leaf(
        pre_genesis_root_key.clone(),
        pre_genesis_only_node,
        pre_genesis_only_value,
    )
    .unwrap();

    let cache = TreeCache::new(&db, next_version).unwrap();
    assert_eq!(*cache.get_root_node_key(), pre_genesis_root_key);
}

#[test]
fn test_freeze_with_delete() {
    let next_version = 0;
    let db = MockTreeStore::default();
    let mut cache = TreeCache::new(&db, next_version).unwrap();

    assert_eq!(*cache.get_root_node_key(), NodeKey::new_empty_path(0));

    let (node1, _, node1_key) = random_leaf_with_key(next_version);
    let node1: Node = node1.into();
    cache.put_node(node1_key.clone(), node1.clone()).unwrap();
    let (node2, _, node2_key) = random_leaf_with_key(next_version);
    let node2: Node = node2.into();
    cache
        .put_node(node2_key.clone(), node2.clone().into())
        .unwrap();
    assert_eq!(cache.get_node(&node1_key).unwrap(), node1);
    assert_eq!(cache.get_node(&node2_key).unwrap(), node2);
    cache.freeze::<Sha256>().unwrap();
    assert_eq!(cache.get_node(&node1_key).unwrap(), node1);
    assert_eq!(cache.get_node(&node2_key).unwrap(), node2);

    cache.delete_node(&node1_key, true /* is_leaf */);
    cache.freeze::<Sha256>().unwrap();
    let (_, update_batch) = cache.into();
    assert_eq!(update_batch.node_batch.nodes().len(), 3);
    assert_eq!(update_batch.stale_node_index_batch.len(), 1);
}
