// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "std"))]
use hashbrown::{HashMap, HashSet};
use sha2::Sha256;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use alloc::vec;
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{fmt::Debug, ops::Bound};

use proptest::{
    collection::{btree_map, vec},
    prelude::*,
    sample,
};

use crate::proof::definition::UpdateMerkleProof;
use crate::SimpleHasher;
use crate::{
    mock::MockTreeStore,
    node_type::LeafNode,
    storage::Node,
    types::{
        proof::{SparseMerkleInternalNode, SparseMerkleRangeProof},
        Version, PRE_GENESIS_VERSION,
    },
    Bytes32Ext, JellyfishMerkleIterator, JellyfishMerkleTree, KeyHash, OwnedValue, RootHash,
    ValueHash, SPARSE_MERKLE_PLACEHOLDER_HASH,
};

/// Computes the key immediately after `key`.
pub fn plus_one(key: KeyHash) -> KeyHash {
    assert_ne!(key, KeyHash([0xff; 32]));

    let mut buf = key.0;
    for i in (0..32).rev() {
        if buf[i] == 255 {
            buf[i] = 0;
        } else {
            buf[i] += 1;
            break;
        }
    }
    KeyHash(buf)
}

/// Initializes a DB with a set of key-value pairs by inserting one key at each version.
pub fn init_mock_db<H: SimpleHasher>(
    kvs: &HashMap<KeyHash, OwnedValue>,
) -> (MockTreeStore, Version) {
    assert!(!kvs.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    for (i, (key, value)) in kvs.clone().into_iter().enumerate() {
        let (_root_hash, write_batch) = tree
            .put_value_set(vec![(key, Some(value))], i as Version)
            .unwrap();
        db.write_tree_update_batch(write_batch).unwrap();
    }

    (db, (kvs.len() - 1) as Version)
}

/// Initializes a DB with a set of key-value pairs by inserting one key at each version, then
/// deleting the specified keys afterwards.
pub fn init_mock_db_with_deletions_afterwards<H: SimpleHasher>(
    kvs: &HashMap<KeyHash, OwnedValue>,
    deletions: Vec<KeyHash>,
) -> (MockTreeStore, Version) {
    assert!(!kvs.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    for (i, (key, value)) in kvs.clone().into_iter().enumerate() {
        let (_root_hash, write_batch) = tree
            .put_value_set(vec![(key, Some(value))], i as Version)
            .unwrap();
        db.write_tree_update_batch(write_batch).unwrap();
    }

    let after_insertions_version = kvs.len();

    for (i, key) in deletions.iter().enumerate() {
        let (_root_hash, write_batch) = tree
            .put_value_set(
                vec![(*key, None)],
                (after_insertions_version + i) as Version,
            )
            .unwrap();
        db.write_tree_update_batch(write_batch).unwrap();
    }
    (db, (kvs.len() + deletions.len() - 1) as Version)
}

fn init_mock_db_versioned<H: SimpleHasher>(
    operations_by_version: Vec<Vec<(KeyHash, Vec<u8>)>>,
    with_proof: bool,
) -> (
    MockTreeStore,
    Version,
    Option<
        Vec<(
            RootHash,
            UpdateMerkleProof<H>,
            Vec<(KeyHash, Option<Vec<u8>>)>,
        )>,
    >,
) {
    assert!(!operations_by_version.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);
    let mut roots_proofs: Option<
        Vec<(
            RootHash,
            UpdateMerkleProof<H>,
            Vec<(KeyHash, Option<Vec<u8>>)>,
        )>,
    > = if with_proof { Some(Vec::new()) } else { None };

    if operations_by_version
        .iter()
        .any(|operations| !operations.is_empty())
    {
        let mut next_version = 0;

        for operations in operations_by_version.into_iter() {
            let operations = operations
                .into_iter()
                .map(|(key, value)| (key, Some(value)));
            let (root_hash, proof_opt, write_batch) = if with_proof {
                let (root, proof, batch) = tree
                    .put_value_set_with_proof(
                        // Convert un-option-wrapped values to option-wrapped values to be compatible with
                        // deletion-enabled put_value_set:
                        operations.clone(),
                        next_version as Version,
                    )
                    .unwrap();
                (root, Some(proof), batch)
            } else {
                let (root, batch) = tree
                    .put_value_set(
                        // Convert un-option-wrapped values to option-wrapped values to be compatible with
                        // deletion-enabled put_value_set:
                        operations.clone(),
                        next_version as Version,
                    )
                    .unwrap();
                (root, None, batch)
            };

            db.write_tree_update_batch(write_batch).unwrap();

            roots_proofs
                .as_mut()
                .map(|proofs| proofs.push((root_hash, proof_opt.unwrap(), operations.collect())));

            next_version += 1;
        }

        (db, next_version - 1 as Version, roots_proofs)
    } else {
        (db, PRE_GENESIS_VERSION, roots_proofs)
    }
}

fn init_mock_db_versioned_with_deletions<H: SimpleHasher>(
    operations_by_version: Vec<Vec<(KeyHash, Option<Vec<u8>>)>>,
    with_proof: bool,
) -> (
    MockTreeStore,
    Version,
    Option<
        Vec<(
            RootHash,
            UpdateMerkleProof<H>,
            Vec<(KeyHash, Option<Vec<u8>>)>,
        )>,
    >,
) {
    assert!(!operations_by_version.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, H>::new(&db);
    let mut roots_proofs = if with_proof { Some(Vec::new()) } else { None };

    if operations_by_version
        .iter()
        .any(|operations| !operations.is_empty())
    {
        let mut next_version = 0;

        for operations in operations_by_version.into_iter() {
            let (root_hash, proof_opt, write_batch) = if with_proof {
                let (root_hash, proof, write_batch) = tree
                    .put_value_set_with_proof(operations.clone(), next_version as Version)
                    .unwrap();
                (root_hash, Some(proof), write_batch)
            } else {
                let (root_hash, write_batch) = tree
                    .put_value_set(operations.clone(), next_version as Version)
                    .unwrap();
                (root_hash, None, write_batch)
            };

            db.write_tree_update_batch(write_batch).unwrap();

            roots_proofs
                .as_mut()
                .map(|proofs| proofs.push((root_hash, proof_opt.unwrap(), operations)));

            next_version += 1;
        }

        (db, next_version - 1 as Version, roots_proofs)
    } else {
        (db, PRE_GENESIS_VERSION, roots_proofs)
    }
}

pub fn arb_existent_kvs_and_nonexistent_keys(
    num_kvs: usize,
    num_non_existing_keys: usize,
) -> impl Strategy<Value = (HashMap<KeyHash, OwnedValue>, Vec<KeyHash>)> {
    btree_map(any::<KeyHash>(), any::<OwnedValue>(), 1..num_kvs)
        .prop_flat_map(move |kvs| {
            let kvs_clone = kvs.clone();
            (
                Just(kvs),
                vec(
                    any::<KeyHash>().prop_filter(
                        "Make sure these keys do not exist in the tree.",
                        move |key| !kvs_clone.contains_key(key),
                    ),
                    num_non_existing_keys,
                ),
            )
        })
        .prop_map(|(map, v)| (map.into_iter().collect(), v))
}

pub fn arb_existent_kvs_and_deletions_and_nonexistent_keys(
    num_kvs: usize,
    num_non_existing_keys: usize,
) -> impl Strategy<Value = (HashMap<KeyHash, OwnedValue>, Vec<KeyHash>, Vec<KeyHash>)> {
    btree_map(any::<KeyHash>(), any::<OwnedValue>(), 1..num_kvs)
        .prop_flat_map(move |kvs| {
            let kvs_clone = kvs.clone();
            let keys: Vec<_> = kvs.keys().cloned().collect();
            let keys_count = keys.len();
            (
                Just(kvs),
                sample::subsequence(keys, 0..keys_count),
                vec(
                    any::<KeyHash>().prop_filter(
                        "Make sure these keys do not exist in the tree.",
                        move |key| !kvs_clone.contains_key(key),
                    ),
                    num_non_existing_keys,
                ),
            )
        })
        .prop_map(|(map, v1, v2)| (map.into_iter().collect(), v1, v2))
}

pub fn arb_interleaved_insertions_and_deletions<H: SimpleHasher>(
    num_keys: usize,
    num_values: usize,
    num_insertions: usize,
    num_deletions: usize,
) -> impl Strategy<Value = Vec<(KeyHash, Option<OwnedValue>)>> {
    // Make a hash set of all the keys and a vector of all the values we'll use in this test
    (
        // Key hashes are the sequential set of keys up to num_keys, but shuffled so that we don't
        // use them in order
        Just(
            (0..num_keys)
                .map(|n| KeyHash::with::<H>(n.to_le_bytes()))
                .collect::<Vec<_>>(),
        )
        .prop_shuffle(),
        // Values are sequential little-endian byte sequences starting from 0, with trailing zeroes
        // trimmed -- it doesn't really matter what they are for these tests, so we just use the
        // smallest distinct sequences we can
        (1..=num_values).prop_map(|end| {
            (0..end)
                .map(|i| {
                    let mut value = i.to_le_bytes().to_vec();
                    while let Some(byte) = value.last() {
                        if *byte != 0 {
                            break;
                        }
                        value.pop();
                    }
                    value
                })
                .collect::<Vec<_>>()
        }),
    )
        .prop_flat_map(move |(keys, values)| {
            // Create a random sequence of insertions using only the keys and values in the sets
            // (this permits keys to be inserted more than once, and with different values)
            vec(
                (sample::select(keys), sample::select(values).prop_map(Some)),
                1..num_insertions,
            )
            .prop_flat_map(move |insertions| {
                // Create a random sequence of deletions using only the keys that were actually inserted
                // (this permits keys to be deleted more than once, but not more times than they will
                // ever be inserted, though they may be deleted before they are inserted, in the end)
                let deletions = sample::subsequence(
                    insertions
                        .iter()
                        .map(|(key, _)| (*key, None))
                        .collect::<Vec<_>>(),
                    0..num_deletions.min(insertions.len()),
                );
                (Just(insertions), deletions)
            })
            .prop_flat_map(move |(insertions, deletions)| {
                // Shuffle together the insertions and the deletions into a single sequence
                let mut insertions_and_deletions = insertions;
                insertions_and_deletions.extend(deletions);
                Just(insertions_and_deletions).prop_shuffle()
            })
        })
}

/// Divide a vector into arbitrary partitions of size >= 1. If the number of partitions exceeds the
/// length of the vector, it is divided into size 1 partitions.
pub fn arb_partitions<T>(
    num_partitions: usize,
    values: Vec<T>,
) -> impl Strategy<Value = Vec<Vec<T>>>
where
    T: Debug + Clone,
{
    assert_ne!(
        num_partitions, 0,
        "cannot partition a vector into 0 partitions"
    );

    let indices = sample::subsequence(
        (0..=values.len()).collect::<Vec<_>>(),
        num_partitions.min(values.len()) - 1,
    );

    indices.prop_map(move |indices| {
        let mut partitions = Vec::with_capacity(num_partitions);
        let mut start = 0;
        for end in indices {
            if end - start > 0 {
                partitions.push(values[start..end].to_vec());
            } else {
                partitions.push(vec![]);
            }
            start = end;
        }

        // Anything that hasn't yet been put into the partitions, put it in the last chunk
        let remainder = values[start..].to_vec();
        partitions.push(remainder);

        partitions
    })
}

pub fn test_get_with_proof<H: SimpleHasher>(
    (existent_kvs, nonexistent_keys): (HashMap<KeyHash, OwnedValue>, Vec<KeyHash>),
) {
    let (db, version) = init_mock_db::<H>(&existent_kvs);
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    test_existent_keys_impl(&tree, version, &existent_kvs);
    test_nonexistent_keys_impl(&tree, version, &nonexistent_keys);
}

pub fn test_get_with_proof_with_deletions<H: SimpleHasher>(
    (mut existent_kvs, deletions, mut nonexistent_keys): (
        HashMap<KeyHash, OwnedValue>,
        Vec<KeyHash>,
        Vec<KeyHash>,
    ),
) {
    let (db, version) =
        init_mock_db_with_deletions_afterwards::<H>(&existent_kvs, deletions.clone());
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    for key in deletions {
        // We shouldn't test deleted keys as existent; they should be tested as nonexistent:
        existent_kvs.remove(&key);
        nonexistent_keys.push(key);
    }

    test_existent_keys_impl(&tree, version, &existent_kvs);
    test_nonexistent_keys_impl(&tree, version, &nonexistent_keys);
}

/// A very general test that demonstrates that given a sequence of insertions and deletions, batched
/// by version, the end result of having performed those operations is identical to having *already
/// known* what the end result would be, and only performing the insertions necessary to get there,
/// with no insertions that would have been overwritten, and no deletions at all.
pub fn test_clairvoyant_construction_matches_interleaved_construction<H: SimpleHasher>(
    operations_by_version: Vec<Vec<(KeyHash, Option<OwnedValue>)>>,
) {
    // Create the expected list of key-value pairs as a hashmap by following the list of operations
    // in order, keeping track of only the latest value
    let mut expected_final = HashMap::new();
    for (version, operations) in operations_by_version.iter().enumerate() {
        for (key, value) in operations {
            if let Some(value) = value {
                expected_final.insert(*key, (version, value.clone()));
            } else {
                expected_final.remove(key);
            }
        }
    }

    // Reconstruct the list of operations "as if updates and deletions didn't happen", by filtering
    // for updates that don't match the final state we computed above
    let mut clairvoyant_operations_by_version = Vec::new();
    for (version, operations) in operations_by_version.iter().enumerate() {
        let mut clairvoyant_operations = Vec::new();
        for (key, value) in operations {
            // This operation must correspond to some existing key-value pair in the final state
            if let Some((expected_version, _)) = expected_final.get(key) {
                // This operation must not be a deletion
                if let Some(value) = value {
                    // The version must be the final version that will end up in the result
                    if version == *expected_version {
                        clairvoyant_operations.push((*key, value.clone()));
                    }
                }
            }
        }
        clairvoyant_operations_by_version.push(clairvoyant_operations);
    }

    // Compute the root hash of the version without deletions (note that the computed root hash is a
    // `Result` which we haven't unwrapped yet)
    let (db_without_deletions, version_without_deletions, _) =
        init_mock_db_versioned::<H>(clairvoyant_operations_by_version, false);
    let tree_without_deletions = JellyfishMerkleTree::<_, H>::new(&db_without_deletions);

    let root_hash_without_deletions =
        tree_without_deletions.get_root_hash(version_without_deletions);

    // Compute the root hash of the version with deletions (note that the computed root hash is a
    // `Result` which we haven't unwrapped yet)
    let (db_with_deletions, version_with_deletions, _) =
        init_mock_db_versioned_with_deletions::<H>(operations_by_version, false);
    let tree_with_deletions = JellyfishMerkleTree::<_, H>::new(&db_with_deletions);

    let root_hash_with_deletions = tree_with_deletions.get_root_hash(version_with_deletions);

    // If either of the resultant trees are in a pre-genesis state (because no operations were
    // performed), then we can't compare their root hashes, because they won't have any root
    match (
        version_without_deletions == PRE_GENESIS_VERSION,
        version_with_deletions == PRE_GENESIS_VERSION,
    ) {
        (false, false) => {
            // If neither was uninitialized by the sequence of operations, their root hashes should
            // match each other, and should both exist
            assert_eq!(
                root_hash_without_deletions.unwrap(),
                root_hash_with_deletions.unwrap(),
                "root hashes mismatch"
            );
        }
        (true, true) => {
            // If both were uninitialized by the sequence of operations, both attempts to get their
            // root hashes should be met with failure, because they have no root node, so ensure
            // that both actually are errors
            assert!(root_hash_without_deletions.is_err());
            assert!(root_hash_with_deletions.is_err());
        }
        (true, false) => {
            // If only the one without deletions was uninitialized by the sequence of operations,
            // then the attempt to get its root hash should be met with failure, because it has no
            // root node
            assert!(root_hash_without_deletions.is_err());
            // And the one that was initialized should have a root hash equivalent to the hash of
            // the null node, since it should contain nothing
            assert_eq!(
                root_hash_with_deletions.unwrap(),
                RootHash(Node::Null.hash::<H>())
            );
        }
        (false, true) => {
            // If only the one with deletions was uninitialized by the sequence of operations,
            // then the attempt to get its root hash should be met with failure, because it has no
            // root node
            assert!(root_hash_with_deletions.is_err());
            // And the one that was initialized should have a root hash equivalent to the hash of
            // the null node, since it should contain nothing
            assert_eq!(
                root_hash_without_deletions.unwrap(),
                RootHash(Node::Null.hash::<H>())
            );
        }
    }

    // After having checked that the root hashes match, it's time to check that the actual values
    // contained in the trees match. We use the JellyfishMerkleIterator to extract a sorted list of
    // key-value pairs from each, and compare to the expected mapping:

    // Get all the key-value pairs in the version without deletions
    let iter_without_deletions = if version_without_deletions != PRE_GENESIS_VERSION {
        JellyfishMerkleIterator::new(
            Arc::new(db_without_deletions),
            version_without_deletions,
            KeyHash([0u8; 32]),
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    } else {
        vec![]
    };

    // Get all the key-value pairs in the version with deletions
    let iter_with_deletions = if version_with_deletions != PRE_GENESIS_VERSION {
        JellyfishMerkleIterator::new(
            Arc::new(db_with_deletions),
            version_with_deletions,
            KeyHash([0u8; 32]),
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    } else {
        vec![]
    };

    // Get the expected key-value pairs
    let mut iter_expected = expected_final
        .into_iter()
        .map(|(k, (_, v))| (k, v))
        .collect::<Vec<_>>();
    iter_expected.sort();

    // Assert that both with and without deletions, both are equal to the expected final contents
    assert_eq!(
        iter_expected, iter_without_deletions,
        "clairvoyant construction mismatches expectation"
    );
    assert_eq!(
        iter_expected, iter_with_deletions,
        "construction interleaved with deletions mismatches expectation"
    );
}

/// A very general test that demonstrates that given a sequence of insertions and deletions, batched
/// by version, the end result of having performed those operations is identical to having *already
/// known* what the end result would be, and only performing the insertions necessary to get there,
/// with no insertions that would have been overwritten, and no deletions at all.
/// This test differs from [`test_clairvoyant_construction_matches_interleaved_construction`] by
/// constructing (and verifying) update proofs.
pub fn test_clairvoyant_construction_matches_interleaved_construction_proved(
    operations_by_version: Vec<Vec<(KeyHash, Option<OwnedValue>)>>,
) {
    // Create the expected list of key-value pairs as a hashmap by following the list of operations
    // in order, keeping track of only the latest value
    let mut expected_final = HashMap::new();
    for (version, operations) in operations_by_version.iter().enumerate() {
        for (key, value) in operations {
            if let Some(value) = value {
                expected_final.insert(*key, (version, value.clone()));
            } else {
                expected_final.remove(key);
            }
        }
    }

    // Reconstruct the list of operations "as if updates and deletions didn't happen", by filtering
    // for updates that don't match the final state we computed above
    let mut clairvoyant_operations_by_version = Vec::new();
    for (version, operations) in operations_by_version.iter().enumerate() {
        let mut clairvoyant_operations = Vec::new();
        for (key, value) in operations {
            // This operation must correspond to some existing key-value pair in the final state
            if let Some((expected_version, _)) = expected_final.get(key) {
                // This operation must not be a deletion
                if let Some(value) = value {
                    // The version must be the final version that will end up in the result
                    if version == *expected_version {
                        clairvoyant_operations.push((*key, value.clone()));
                    }
                }
            }
        }
        clairvoyant_operations_by_version.push(clairvoyant_operations);
    }

    // Compute the root hash of the version without deletions (note that the computed root hash is a
    // `Result` which we haven't unwrapped yet)
    let (_db_without_deletions, version_without_deletions, roots_proofs_without_deletions) =
        init_mock_db_versioned::<Sha256>(clairvoyant_operations_by_version, true);

    // Compute the root hash of the version with deletions (note that the computed root hash is a
    // `Result` which we haven't unwrapped yet)
    let (_db_with_deletions, version_with_deletions, roots_proofs_with_deletions) =
        init_mock_db_versioned_with_deletions::<Sha256>(operations_by_version, true);

    // We know need to check that the updates from the tree have been performed correctly.
    // We need to loop over the vectors of proofs and verify each one
    if version_without_deletions != PRE_GENESIS_VERSION {
        let mut old_root = RootHash(Node::new_null().hash::<Sha256>());
        for (new_root, proof, ops) in roots_proofs_without_deletions.unwrap() {
            assert!(proof.verify_update(old_root, new_root, ops).is_ok());
            old_root = new_root;
        }
    }

    // We know need to check that the updates from the tree have been performed correctly.
    // We need to loop over the vectors of proofs and verify each one
    if version_with_deletions != PRE_GENESIS_VERSION {
        let mut old_root = RootHash(Node::new_null().hash::<Sha256>());
        for (new_root, proof, ops) in roots_proofs_with_deletions.unwrap() {
            assert!(proof.verify_update(old_root, new_root, ops).is_ok());
            old_root = new_root;
        }
    }
}

pub fn arb_kv_pair_with_distinct_last_nibble(
) -> impl Strategy<Value = ((KeyHash, OwnedValue), (KeyHash, OwnedValue))> {
    (
        any::<KeyHash>().prop_filter("Can't be 0xffffff...", |key| *key != KeyHash([0xff; 32])),
        vec(any::<OwnedValue>(), 2),
    )
        .prop_map(|(key1, accounts)| {
            let key2 = plus_one(key1);
            ((key1, accounts[0].clone()), (key2, accounts[1].clone()))
        })
}

pub fn test_get_with_proof_with_distinct_last_nibble<H: SimpleHasher>(
    (kv1, kv2): ((KeyHash, OwnedValue), (KeyHash, OwnedValue)),
) {
    let mut kvs = HashMap::new();
    kvs.insert(kv1.0, kv1.1);
    kvs.insert(kv2.0, kv2.1);

    let (db, version) = init_mock_db::<H>(&kvs);
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    test_existent_keys_impl(&tree, version, &kvs);
}

pub fn arb_tree_with_index(
    tree_size: usize,
) -> impl Strategy<Value = (BTreeMap<KeyHash, OwnedValue>, usize)> {
    btree_map(any::<KeyHash>(), any::<OwnedValue>(), 1..tree_size).prop_flat_map(|btree| {
        let len = btree.len();
        (Just(btree), 0..len)
    })
}

pub fn test_get_range_proof<H: SimpleHasher>((btree, n): (BTreeMap<KeyHash, OwnedValue>, usize)) {
    let (db, version) = init_mock_db::<H>(&btree.clone().into_iter().collect());
    let tree = JellyfishMerkleTree::<_, H>::new(&db);

    let nth_key = btree.keys().nth(n).unwrap();

    let proof = tree.get_range_proof(*nth_key, version).unwrap();
    verify_range_proof(
        tree.get_root_hash(version).unwrap(),
        btree.into_iter().take(n + 1).collect(),
        proof,
    );
}

fn test_existent_keys_impl<'a, H: SimpleHasher>(
    tree: &JellyfishMerkleTree<'a, MockTreeStore, H>,
    version: Version,
    existent_kvs: &HashMap<KeyHash, OwnedValue>,
) {
    let root_hash = tree.get_root_hash(version).unwrap();

    for (key, value) in existent_kvs {
        let (account, proof) = tree.get_with_proof(*key, version).unwrap();
        assert!(proof.verify(root_hash, *key, account.as_ref()).is_ok());
        assert_eq!(account.unwrap(), *value);
    }
}

fn test_nonexistent_keys_impl<'a, H: SimpleHasher>(
    tree: &JellyfishMerkleTree<'a, MockTreeStore, H>,
    version: Version,
    nonexistent_keys: &[KeyHash],
) {
    let root_hash = tree.get_root_hash(version).unwrap();

    for key in nonexistent_keys {
        let (account, proof) = tree.get_with_proof(*key, version).unwrap();
        assert!(proof.verify(root_hash, *key, account.as_ref()).is_ok());
        assert_eq!(account, None);
    }
}

/// Checks if we can construct the expected root hash using the entries in the btree and the proof.
fn verify_range_proof<H: SimpleHasher>(
    expected_root_hash: RootHash,
    btree: BTreeMap<KeyHash, OwnedValue>,
    proof: SparseMerkleRangeProof<H>,
) {
    // For example, given the following sparse Merkle tree:
    //
    //                   root
    //                  /     \
    //                 /       \
    //                /         \
    //               o           o
    //              / \         / \
    //             a   o       o   h
    //                / \     / \
    //               o   d   e   X
    //              / \         / \
    //             b   c       f   g
    //
    // we transform the keys as follows:
    //   a => 00,
    //   b => 0100,
    //   c => 0101,
    //   d => 011,
    //   e => 100,
    //   X => 101
    //   h => 11
    //
    // Basically, the suffixes that doesn't affect the common prefix of adjacent leaves are
    // discarded. In this example, we assume `btree` has the keys `a` to `e` and the proof has `X`
    // and `h` in the siblings.

    // Now we want to construct a set of key-value pairs that covers the entire set of leaves. For
    // `a` to `e` this is simple -- we just insert them directly into this set. For the rest of the
    // leaves, they are represented by the siblings, so we just make up some keys that make sense.
    // For example, for `X` we just use 101000... (more zeros omitted), because that is one key
    // that would cause `X` to end up in the above position.
    let mut btree1 = BTreeMap::new();
    for (key, value) in &btree {
        let leaf = LeafNode::new(*key, ValueHash::with::<H>(value.as_slice()));
        btree1.insert(*key, leaf.hash::<H>());
    }
    // Using the above example, `last_proven_key` is `e`. We look at the path from root to `e`.
    // For each 0-bit, there should be a sibling in the proof. And we use the path from root to
    // this position, plus a `1` as the key.
    let last_proven_key = *btree
        .keys()
        .last()
        .expect("We are proving at least one key.");
    for (i, sibling) in last_proven_key
        .0
        .iter_bits()
        .enumerate()
        .filter_map(|(i, bit)| if !bit { Some(i) } else { None })
        .zip(proof.right_siblings().iter().rev())
    {
        // This means the `i`-th bit is zero. We take `i` bits from `last_proven_key` and append a
        // one to make up the key for this sibling.
        let mut buf: Vec<_> = last_proven_key.0.iter_bits().take(i).collect();
        buf.push(true);
        // The rest doesn't matter, because they don't affect the position of the node. We just
        // add zeros.
        buf.resize(256, false);
        let key = KeyHash(<[u8; 32]>::from_bit_iter(buf.into_iter()).unwrap());
        btree1.insert(key, sibling.hash::<H>());
    }

    // Now we do the transformation (removing the suffixes) described above.
    let mut kvs = vec![];
    for (key, value) in &btree1 {
        // The length of the common prefix of the previous key and the current key.
        let prev_common_prefix_len =
            prev_key(&btree1, key).map(|pkey| pkey.0.common_prefix_bits_len(&key.0));
        // The length of the common prefix of the next key and the current key.
        let next_common_prefix_len =
            next_key(&btree1, key).map(|nkey| nkey.0.common_prefix_bits_len(&key.0));

        // We take the longest common prefix of the current key and its neighbors. That's how much
        // we need to keep.
        let len = match (prev_common_prefix_len, next_common_prefix_len) {
            (Some(plen), Some(nlen)) => core::cmp::max(plen, nlen),
            (Some(plen), None) => plen,
            (None, Some(nlen)) => nlen,
            (None, None) => 0,
        };
        let transformed_key: Vec<_> = key.0.iter_bits().take(len + 1).collect();
        kvs.push((transformed_key, *value));
    }

    assert_eq!(compute_root_hash::<H>(kvs), expected_root_hash);
}

/// Reduces the problem by removing the first bit of every key.
fn reduce<'a>(kvs: &'a [(&[bool], [u8; 32])]) -> Vec<(&'a [bool], [u8; 32])> {
    kvs.iter().map(|(key, value)| (&key[1..], *value)).collect()
}

/// Returns the key immediately before `key` in `btree`.
fn prev_key<K, V>(btree: &BTreeMap<K, V>, key: &K) -> Option<K>
where
    K: Clone + Ord,
{
    btree
        .range((Bound::Unbounded, Bound::Excluded(key)))
        .next_back()
        .map(|(k, _v)| k.clone())
}

fn next_key<K, V>(btree: &BTreeMap<K, V>, key: &K) -> Option<K>
where
    K: Clone + Ord,
{
    btree
        .range((Bound::Excluded(key), Bound::Unbounded))
        .next()
        .map(|(k, _v)| k.clone())
}

/// Computes the root hash of a sparse Merkle tree. `kvs` consists of the entire set of key-value
/// pairs stored in the tree.
fn compute_root_hash<H: SimpleHasher>(kvs: Vec<(Vec<bool>, [u8; 32])>) -> RootHash {
    let mut kv_ref = vec![];
    for (key, value) in &kvs {
        kv_ref.push((&key[..], *value));
    }
    RootHash(compute_root_hash_impl::<H>(kv_ref))
}

fn compute_root_hash_impl<H: SimpleHasher>(kvs: Vec<(&[bool], [u8; 32])>) -> [u8; 32] {
    assert!(!kvs.is_empty());

    // If there is only one entry, it is the root.
    if kvs.len() == 1 {
        return kvs[0].1;
    }

    // Otherwise the tree has more than one leaves, which means we can find which ones are in the
    // left subtree and which ones are in the right subtree. So we find the first key that starts
    // with a 1-bit.
    let left_hash;
    let right_hash;
    match kvs.iter().position(|(key, _value)| key[0]) {
        Some(0) => {
            // Every key starts with a 1-bit, i.e., they are all in the right subtree.
            left_hash = SPARSE_MERKLE_PLACEHOLDER_HASH;
            right_hash = compute_root_hash_impl::<H>(reduce(&kvs));
        }
        Some(index) => {
            // Both left subtree and right subtree have some keys.
            left_hash = compute_root_hash_impl::<H>(reduce(&kvs[..index]));
            right_hash = compute_root_hash_impl::<H>(reduce(&kvs[index..]));
        }
        None => {
            // Every key starts with a 0-bit, i.e., they are all in the left subtree.
            left_hash = compute_root_hash_impl::<H>(reduce(&kvs));
            right_hash = SPARSE_MERKLE_PLACEHOLDER_HASH;
        }
    }

    SparseMerkleInternalNode::new(left_hash, right_hash).hash::<H>()
}

pub fn test_get_leaf_count<H: SimpleHasher>(keys: HashSet<KeyHash>) {
    let kvs = keys.into_iter().map(|k| (k, vec![])).collect();
    let (db, version) = init_mock_db::<H>(&kvs);
    let tree = JellyfishMerkleTree::<_, H>::new(&db);
    assert_eq!(tree.get_leaf_count(version).unwrap(), kvs.len())
}
