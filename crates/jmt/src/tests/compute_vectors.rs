#![cfg(feature = "std")]
#![allow(unused)]
use sha2::Sha256;

use crate::{
    proof::{INTERNAL_DOMAIN_SEPARATOR, LEAF_DOMAIN_SEPARATOR},
    KeyHash, SimpleHasher, ValueHash, SPARSE_MERKLE_PLACEHOLDER_HASH,
};

const DESCRIPTION: &'static str =  "Manually computed test vectors for a JMT instantiated with the sha2-256 hash function. Keys and values are hex-encoded byte strings. Neither keys nor values have been pre-hashed.";

use super::vectors::{KeyValuePair, TestVector};

fn internal_hash(left_child_hash: [u8; 32], right_child_hash: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INTERNAL_DOMAIN_SEPARATOR);
    hasher.update(left_child_hash.as_ref());
    hasher.update(right_child_hash.as_ref());
    hasher.finalize()
}

fn leaf_hash(key_hash: KeyHash, value_hash: ValueHash) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN_SEPARATOR);
    hasher.update(key_hash.0.as_ref());
    hasher.update(value_hash.0.as_ref());
    hasher.finalize()
}

fn create_vector_for_empty_trie() -> TestVector {
    TestVector {
        expected_root: SPARSE_MERKLE_PLACEHOLDER_HASH,
        data: vec![],
    }
}

fn compute_vector_with_one_leaf() -> TestVector {
    let key = b"hello";
    let key_hash = KeyHash::with::<Sha256>(key);

    let value = b"world";
    let value_hash = ValueHash::with::<Sha256>(value);

    let leaf_hash = leaf_hash(key_hash, value_hash);

    let expected_root = leaf_hash;

    TestVector {
        expected_root: expected_root.into(),
        data: vec![KeyValuePair {
            key: key.to_vec(),
            value: value.to_vec(),
        }],
    }
}

fn compute_vector_with_two_leaves() -> TestVector {
    let left_key = b"hello";
    let left_key_hash = KeyHash::with::<Sha256>(left_key);

    let right_key = b"goodbye";
    let right_key_hash = KeyHash::with::<Sha256>(right_key);

    let value = b"world";
    let value_hash = ValueHash::with::<Sha256>(value);

    let left_leaf_hash = leaf_hash(left_key_hash, value_hash);
    let right_leaf_hash = leaf_hash(right_key_hash, value_hash);

    let expected_root = internal_hash(left_leaf_hash, right_leaf_hash);

    TestVector {
        expected_root: expected_root.into(),
        data: vec![
            KeyValuePair {
                key: left_key.to_vec(),
                value: value.to_vec(),
            },
            KeyValuePair {
                key: right_key.to_vec(),
                value: value.to_vec(),
            },
        ],
    }
}

fn generate_vectors() {
    use super::vectors::TestVectorWrapper;

    let vectors = vec![
        create_vector_for_empty_trie(),
        compute_vector_with_one_leaf(),
        compute_vector_with_two_leaves(),
    ];

    let test_vectors = TestVectorWrapper {
        description: DESCRIPTION.to_string(),
        hash_function: "sha2_256".to_string(),
        vectors,
    };
    let file = std::fs::File::create("sha2_256_vectors.json").unwrap();
    let writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &test_vectors).unwrap();
}
