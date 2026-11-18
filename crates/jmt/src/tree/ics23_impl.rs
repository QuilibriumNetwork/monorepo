use alloc::vec;
use alloc::vec::Vec;
use anyhow::Result;

use crate::{
    proof::{SparseMerkleProof, INTERNAL_DOMAIN_SEPARATOR, LEAF_DOMAIN_SEPARATOR},
    storage::HasPreimage,
    storage::TreeReader,
    tree::ExclusionProof,
    JellyfishMerkleTree, KeyHash, OwnedValue, SimpleHasher, Version,
    SPARSE_MERKLE_PLACEHOLDER_HASH,
};

fn sparse_merkle_proof_to_ics23_existence_proof<H: SimpleHasher>(
    key: Vec<u8>,
    value: Vec<u8>,
    proof: &SparseMerkleProof<H>,
) -> ics23::ExistenceProof {
    let key_hash: KeyHash = KeyHash::with::<H>(key.as_slice());
    let mut path = Vec::new();
    let mut skip = 256 - proof.siblings().len();
    let mut sibling_idx = 0;

    for byte_idx in (0..32).rev() {
        // The JMT proofs iterate over the bits in MSB order
        for bit_idx in 0..8 {
            if skip > 0 {
                skip -= 1;
                continue;
            } else {
                let bit = (key_hash.0[byte_idx] >> bit_idx) & 0x1;
                // ICS23 InnerOp computes
                //    hash( prefix || current || suffix )
                // so we want to construct (prefix, suffix) so that this is
                // the correct hash-of-internal-node
                let (prefix, suffix) = if bit == 1 {
                    // We want hash( domsep || sibling || current )
                    // so prefix = domsep || sibling
                    //    suffix = (empty)
                    let mut prefix = Vec::with_capacity(16 + 32);
                    prefix.extend_from_slice(INTERNAL_DOMAIN_SEPARATOR);
                    prefix.extend_from_slice(&proof.siblings()[sibling_idx].hash::<H>());
                    (prefix, Vec::new())
                } else {
                    // We want hash( domsep || current || sibling )
                    // so prefix = domsep
                    //    suffix = sibling
                    let prefix = INTERNAL_DOMAIN_SEPARATOR.to_vec();
                    let suffix = proof.siblings()[sibling_idx].hash::<H>().to_vec();
                    (prefix, suffix)
                };
                path.push(ics23::InnerOp {
                    hash: ics23::HashOp::Sha256.into(),
                    prefix,
                    suffix,
                });
                sibling_idx += 1;
            }
        }
    }

    ics23::ExistenceProof {
        key,
        value,
        path,
        leaf: Some(ics23::LeafOp {
            hash: ics23::HashOp::Sha256.into(),
            prehash_key: ics23::HashOp::Sha256.into(),
            prehash_value: ics23::HashOp::Sha256.into(),
            length: ics23::LengthOp::NoPrefix.into(),
            prefix: LEAF_DOMAIN_SEPARATOR.to_vec(),
        }),
    }
}

impl<'a, R, H> JellyfishMerkleTree<'a, R, H>
where
    R: 'a + TreeReader + HasPreimage,
    H: SimpleHasher,
{
    fn exclusion_proof_to_ics23_nonexistence_proof(
        &self,
        key: Vec<u8>,
        version: Version,
        proof: &ExclusionProof<H>,
    ) -> Result<ics23::NonExistenceProof> {
        match proof {
            ExclusionProof::Leftmost {
                leftmost_right_proof,
            } => {
                let key_hash = leftmost_right_proof
                    .leaf()
                    .expect("must have leaf")
                    .key_hash();
                let key_left_proof = self
                    .reader
                    .preimage(key_hash)?
                    .ok_or(anyhow::anyhow!("missing preimage for key hash"))?;

                let value = self
                    .get(key_hash, version)?
                    .ok_or(anyhow::anyhow!("missing value for key hash"))?;

                let leftmost_right_proof = sparse_merkle_proof_to_ics23_existence_proof(
                    key_left_proof.clone(),
                    value.clone(),
                    leftmost_right_proof,
                );

                Ok(ics23::NonExistenceProof {
                    key,
                    right: Some(leftmost_right_proof),
                    left: None,
                })
            }
            ExclusionProof::Middle {
                leftmost_right_proof,
                rightmost_left_proof,
            } => {
                let leftmost_key_hash = leftmost_right_proof
                    .leaf()
                    .expect("must have leaf")
                    .key_hash();
                let value_leftmost = self
                    .get(leftmost_key_hash, version)?
                    .ok_or(anyhow::anyhow!("missing value for key hash"))?;
                let key_leftmost = self
                    .reader
                    .preimage(leftmost_key_hash)?
                    .ok_or(anyhow::anyhow!("missing preimage for key hash"))?;
                let leftmost_right_proof = sparse_merkle_proof_to_ics23_existence_proof(
                    key_leftmost.clone(),
                    value_leftmost.clone(),
                    leftmost_right_proof,
                );

                let rightmost_key_hash = rightmost_left_proof
                    .leaf()
                    .expect("must have leaf")
                    .key_hash();
                let value_rightmost = self
                    .get(rightmost_key_hash, version)?
                    .ok_or(anyhow::anyhow!("missing value for key hash"))?;
                let key_rightmost = self
                    .reader
                    .preimage(rightmost_key_hash)?
                    .ok_or(anyhow::anyhow!("missing preimage for key hash"))?;
                let rightmost_left_proof = sparse_merkle_proof_to_ics23_existence_proof(
                    key_rightmost.clone(),
                    value_rightmost.clone(),
                    rightmost_left_proof,
                );

                Ok(ics23::NonExistenceProof {
                    key,
                    right: Some(leftmost_right_proof),
                    left: Some(rightmost_left_proof),
                })
            }
            ExclusionProof::Rightmost {
                rightmost_left_proof,
            } => {
                let rightmost_key_hash = rightmost_left_proof
                    .leaf()
                    .expect("must have leaf")
                    .key_hash();
                let value_rightmost = self
                    .get(rightmost_key_hash, version)?
                    .ok_or(anyhow::anyhow!("missing value for key hash"))?;
                let key_rightmost = self
                    .reader
                    .preimage(rightmost_key_hash)?
                    .ok_or(anyhow::anyhow!("missing preimage for key hash"))?;
                let rightmost_left_proof = sparse_merkle_proof_to_ics23_existence_proof(
                    key_rightmost.clone(),
                    value_rightmost.clone(),
                    rightmost_left_proof,
                );

                Ok(ics23::NonExistenceProof {
                    key,
                    right: None,
                    left: Some(rightmost_left_proof),
                })
            }
        }
    }

    /// Returns the value corresponding to the specified key (if there is a value associated with it)
    /// along with an [ics23::CommitmentProof] proving either the presence of the value at that key,
    /// or the absence of any value at that key, depending on which is the case.
    pub fn get_with_ics23_proof(
        &self,
        key: Vec<u8>,
        version: Version,
    ) -> Result<(Option<OwnedValue>, ics23::CommitmentProof)> {
        let key_hash: KeyHash = KeyHash::with::<H>(key.as_slice());
        let proof_or_exclusion = self.get_with_exclusion_proof(key_hash, version)?;

        match proof_or_exclusion {
            Ok((value, proof)) => {
                let ics23_exist =
                    sparse_merkle_proof_to_ics23_existence_proof(key, value.clone(), &proof);

                Ok((
                    Some(value),
                    ics23::CommitmentProof {
                        proof: Some(ics23::commitment_proof::Proof::Exist(ics23_exist)),
                    },
                ))
            }
            Err(exclusion_proof) => {
                let ics23_nonexist = self.exclusion_proof_to_ics23_nonexistence_proof(
                    key,
                    version,
                    &exclusion_proof,
                )?;

                Ok((
                    None,
                    ics23::CommitmentProof {
                        proof: Some(ics23::commitment_proof::Proof::Nonexist(ics23_nonexist)),
                    },
                ))
            }
        }
    }
}

pub fn ics23_spec() -> ics23::ProofSpec {
    ics23::ProofSpec {
        leaf_spec: Some(ics23::LeafOp {
            hash: ics23::HashOp::Sha256.into(),
            prehash_key: ics23::HashOp::Sha256.into(),
            prehash_value: ics23::HashOp::Sha256.into(),
            length: ics23::LengthOp::NoPrefix.into(),
            prefix: LEAF_DOMAIN_SEPARATOR.to_vec(),
        }),
        inner_spec: Some(ics23::InnerSpec {
            hash: ics23::HashOp::Sha256.into(),
            child_order: vec![0, 1],
            min_prefix_length: INTERNAL_DOMAIN_SEPARATOR.len() as i32,
            max_prefix_length: INTERNAL_DOMAIN_SEPARATOR.len() as i32,
            child_size: 32,
            empty_child: SPARSE_MERKLE_PLACEHOLDER_HASH.to_vec(),
        }),
        min_depth: 0,
        max_depth: 64,
        prehash_key_before_comparison: true,
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use ics23::{commitment_proof::Proof, HostFunctionsManager, NonExistenceProof};
    use proptest::prelude::*;
    use proptest::strategy::Strategy;
    use sha2::Sha256;

    use super::*;
    use crate::{mock::MockTreeStore, KeyHash, TransparentHasher, SPARSE_MERKLE_PLACEHOLDER_HASH};

    proptest! {
         #![proptest_config(ProptestConfig {
             cases: 1000, .. ProptestConfig::default()
         })]

        #[test]
        /// Assert that the Ics23 bonding path calculations are correct.
        /// To achieve this, the uses a strategy that consists in:
        /// 1. generating a sorted vector of key preimages
        /// 2. instantiating a JMT over a `TransparentHasher`
        ///
        /// The last point allow us to easily test that for a given key
        /// that is *in* the JMT, we can generate two non-existent keys
        /// that are "neighbor" to `k`: (k-1, k+1).
        ///
        /// To recap, we generate a vector of sorted key <k_1, ... k_n>;
        /// then, we iterate over each existing key `k_i` and compute a
        ///     tuple of neighbors (`k_i - 1`, `k_i + 1`) which are *not*
        ///     in the tree.
        /// Equipped with those nonexisting neighbors, we check for exclusion
        /// in the tree, and specifically assert that the generated proof contains:
        /// 1. the initial key we requested (i.e. `k_i + 1` or `k_i - 1`)
        /// 2. the correct left neighbor (i.e. `k_{i-1}`, or `k_{i+1}`, or none`)
        /// 2. the correct right neighbor (i.e. `k_{i-1}`, or `k_{i+1}`, or none`)
        /// across configurations e.g. bounding path for a leftmost or rightmost subtree.
        /// More context available in #104.
         fn test_ics23_bounding_path_simple(key_seeds in key_strategy()) {
             let mut preimages: Vec<String> = key_seeds.into_iter().filter(|k| *k!=0).map(|k| format!("{k:032x}")).collect();
             preimages.sort();
             preimages.dedup();

           assert!(preimages.len() > 0);

           let store = MockTreeStore::default();
           let tree = JellyfishMerkleTree::<_, TransparentHasher>::new(&store);

           // Our key preimages and key hashes are identical, but we still need to populate
           // the mock store so that ics23 internal queries can resolve.
           for preimage in preimages.iter() {
             store.put_key_preimage(KeyHash::with::<TransparentHasher>(preimage.clone()), preimage.clone().as_bytes().to_vec().as_ref());
           }

           let (_, write_batch) = tree.put_value_set(
               preimages.iter().enumerate().map(|(i,k)| (KeyHash::with::<TransparentHasher>(k.as_bytes()), Some(i.to_be_bytes().to_vec()))),
               1
           ).unwrap();

           store.write_tree_update_batch(write_batch).expect("can write to mock storage");

           let len_preimages = preimages.len();

           for (idx, existing_key) in preimages.iter().enumerate() {
            // For each existing key, we generate two alternative keys that are not
            // in the tree. One that is one bit "ahead" and one that is one bit after.
            // e.g.  0x5 -> 0x4 and 0x6
            let (smaller_key, bigger_key) = generate_adjacent_keys(existing_key);

            let (v, proof) = tree.get_with_ics23_proof(smaller_key.as_bytes().to_vec(), 1).expect("can query tree");
            assert!(v.is_none(), "the key should not exist!");
            let proof = proof.proof.expect("a proof is present");
            if let Proof::Nonexist(NonExistenceProof { key, left, right }) = proof {
              // Basic check that we are getting back the key that we queried.
              assert_eq!(key, smaller_key.as_bytes().to_vec());

             // The expected predecessor to the nonexistent key `k_i - 1` is `k_{i-1}`, unless `i=0`.
             let expected_left_neighbor = if idx == 0 { None } else { preimages.get(idx-1) };
             // The expected successor to the nonexistent key `k_i - 1` is `k_{i+1}`.
             let expected_right_neighbor = Some(existing_key);

             let reported_left_neighbor = left.clone().map(|existence_proof| String::from_utf8_lossy(&existence_proof.key).into_owned());
             let reported_right_neighbor = right.clone().map(|existence_proof| String::from_utf8_lossy(&existence_proof.key).into_owned());

             assert_eq!(expected_left_neighbor.cloned(), reported_left_neighbor);
             assert_eq!(expected_right_neighbor.cloned(), reported_right_neighbor);
           } else {
                unreachable!("we have assessed that the value is `None`")
            }

            let (v, proof) = tree.get_with_ics23_proof(bigger_key.as_bytes().to_vec(), 1).expect("can query tree");
            assert!(v.is_none(), "the key should not exist!");
            let proof = proof.proof.expect("a proof is present");
            if let Proof::Nonexist(NonExistenceProof { key, left, right }) = proof {
                    // Basic check that we are getting back the key that we queried.
                    assert_eq!(key, bigger_key.as_bytes().to_vec());
                    let reported_left_neighbor = left.clone().map(|existence_proof| String::from_utf8_lossy(&existence_proof.key).into_owned());
                    let reported_right_neighbor = right.clone().map(|existence_proof| String::from_utf8_lossy(&existence_proof.key).into_owned());

                    // The expected predecessor to the nonexistent key `k_i + 1` is `k_{i}`.
                    let expected_left_neighbor = Some(existing_key);
                    // The expected successor to the nonexistent key `k_i + 1` is `k_{i+1}`.
                    let expected_right_neighbor = if idx == len_preimages - 1 { None }  else { preimages.get(idx+1) };

                   assert_eq!(expected_left_neighbor.cloned(), reported_left_neighbor);
                   assert_eq!(expected_right_neighbor.cloned(), reported_right_neighbor);
             } else {
                 unreachable!("we have assessed that the value is `None`")
             }
         }
     }

     #[test]
    fn test_jmt_ics23_nonexistence(keys: Vec<Vec<u8>>) {
     test_jmt_ics23_nonexistence_with_keys(keys.into_iter().filter(|k| k.len() != 0));
     }
     }

    fn key_strategy() -> impl Strategy<Value = Vec<u128>> {
        proptest::collection::btree_set(u64::MAX as u128..=u128::MAX, 200)
            .prop_map(|set| set.into_iter().collect())
    }
    fn generate_adjacent_keys(hex: &String) -> (String, String) {
        let value = u128::from_str_radix(hex.as_str(), 16).expect("valid hexstring");
        let prev = value - 1;
        let next = value + 1;
        let p = format!("{prev:032x}");
        let n = format!("{next:032x}");
        (p, n)
    }

    fn test_jmt_ics23_nonexistence_with_keys(keys: impl Iterator<Item = Vec<u8>>) {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::<_, Sha256>::new(&db);

        let mut kvs = Vec::new();

        // Ensure that the tree contains at least one key-value pair
        kvs.push((KeyHash::with::<Sha256>(b"key"), Some(b"value1".to_vec())));
        db.put_key_preimage(KeyHash::with::<Sha256>(b"key"), &b"key".to_vec());

        for key_preimage in keys {
            // Since we hardcode the check for key, ensure that it's not inserted randomly by proptest
            if key_preimage == b"notexist" {
                continue;
            }
            let key_hash = KeyHash::with::<Sha256>(key_preimage.as_slice());
            let value = vec![0u8; 32];
            kvs.push((key_hash, Some(value)));
            db.put_key_preimage(key_hash, &key_preimage.to_vec());
        }

        let (new_root_hash, batch) = tree.put_value_set(kvs, 0).unwrap();
        db.write_tree_update_batch(batch).unwrap();

        let (value_retrieved, commitment_proof) =
            tree.get_with_ics23_proof(b"notexist".to_vec(), 0).unwrap();

        let key_hash = KeyHash::with::<Sha256>(b"notexist".as_slice());
        let proof_or_exclusion = tree.get_with_exclusion_proof(key_hash, 0).unwrap();

        use crate::tree::ExclusionProof::{Leftmost, Middle, Rightmost};
        match proof_or_exclusion {
            Ok(_) => panic!("expected nonexistence proof"),
            Err(exclusion_proof) => match exclusion_proof {
                Leftmost {
                    leftmost_right_proof,
                } => {
                    if leftmost_right_proof.root_hash() != new_root_hash {
                        panic!(
                            "root hash mismatch. siblings: {:?}, smph: {:?}",
                            leftmost_right_proof.siblings(),
                            SPARSE_MERKLE_PLACEHOLDER_HASH
                        );
                    }

                    assert!(ics23::verify_non_membership::<HostFunctionsManager>(
                        &commitment_proof,
                        &ics23_spec(),
                        &new_root_hash.0.to_vec(),
                        b"notexist"
                    ));

                    assert_eq!(value_retrieved, None)
                }
                Rightmost {
                    rightmost_left_proof,
                } => {
                    if rightmost_left_proof.root_hash() != new_root_hash {
                        panic!(
                            "root hash mismatch. siblings: {:?}, smph: {:?}",
                            rightmost_left_proof.siblings(),
                            SPARSE_MERKLE_PLACEHOLDER_HASH
                        );
                    }

                    assert!(ics23::verify_non_membership::<HostFunctionsManager>(
                        &commitment_proof,
                        &ics23_spec(),
                        &new_root_hash.0.to_vec(),
                        b"notexist"
                    ));

                    assert_eq!(value_retrieved, None)
                }
                Middle {
                    leftmost_right_proof,
                    rightmost_left_proof,
                } => {
                    if leftmost_right_proof.root_hash() != new_root_hash {
                        let good_proof = tree
                            .get_with_proof(leftmost_right_proof.leaf().unwrap().key_hash(), 0)
                            .unwrap();
                        panic!(
                            "root hash mismatch. bad proof: {:?}, good proof: {:?}",
                            leftmost_right_proof, good_proof
                        );
                    }
                    if rightmost_left_proof.root_hash() != new_root_hash {
                        panic!(
                            "root hash mismatch. siblings: {:?}",
                            rightmost_left_proof.siblings()
                        );
                    }

                    assert!(ics23::verify_non_membership::<HostFunctionsManager>(
                        &commitment_proof,
                        &ics23_spec(),
                        &new_root_hash.0.to_vec(),
                        b"notexist"
                    ));

                    assert_eq!(value_retrieved, None)
                }
            },
        }

        assert!(!ics23::verify_non_membership::<HostFunctionsManager>(
            &commitment_proof,
            &ics23_spec(),
            &new_root_hash.0.to_vec(),
            b"key",
        ));
    }

    #[test]
    #[should_panic]
    fn test_jmt_ics23_nonexistence_single_empty_key() {
        test_jmt_ics23_nonexistence_with_keys(vec![vec![]].into_iter());
    }

    #[test]
    fn test_jmt_ics23_existence() {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::<_, Sha256>::new(&db);

        let key = b"key";
        let key_hash = KeyHash::with::<Sha256>(&key);

        // For testing, insert multiple values into the tree
        let mut kvs = Vec::new();
        kvs.push((key_hash, Some(b"value".to_vec())));
        // make sure we have some sibling nodes, through carefully constructed k/v entries that will have overlapping paths
        for i in 1..4 {
            let mut overlap_key = KeyHash([0; 32]);
            overlap_key.0[0..i].copy_from_slice(&key_hash.0[0..i]);
            kvs.push((overlap_key, Some(b"bogus value".to_vec())));
        }

        let (new_root_hash, batch) = tree.put_value_set(kvs, 0).unwrap();
        db.write_tree_update_batch(batch).unwrap();

        let (value_retrieved, commitment_proof) =
            tree.get_with_ics23_proof(b"key".to_vec(), 0).unwrap();

        assert!(ics23::verify_membership::<HostFunctionsManager>(
            &commitment_proof,
            &ics23_spec(),
            &new_root_hash.0.to_vec(),
            b"key",
            b"value",
        ));

        assert_eq!(value_retrieved.unwrap(), b"value");
    }

    #[test]
    fn test_jmt_ics23_existence_random_keys() {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::<_, Sha256>::new(&db);

        const MAX_VERSION: u64 = 1 << 14;

        for version in 0..=MAX_VERSION {
            let key = format!("key{}", version).into_bytes();
            let value = format!("value{}", version).into_bytes();
            let (_root, batch) = tree
                .put_value_set(vec![(KeyHash::with::<Sha256>(key), Some(value))], version)
                .unwrap();
            db.write_tree_update_batch(batch).unwrap();
        }

        let value_maxversion = format!("value{}", MAX_VERSION).into_bytes();

        let (value_retrieved, commitment_proof) = tree
            .get_with_ics23_proof(format!("key{}", MAX_VERSION).into_bytes(), MAX_VERSION)
            .unwrap();

        let root_hash = tree.get_root_hash(MAX_VERSION).unwrap().0.to_vec();

        assert!(ics23::verify_membership::<HostFunctionsManager>(
            &commitment_proof,
            &ics23_spec(),
            &root_hash,
            format!("key{}", MAX_VERSION).as_bytes(),
            format!("value{}", MAX_VERSION).as_bytes(),
        ));

        assert_eq!(value_retrieved.unwrap(), value_maxversion);
    }

    #[test]
    /// Write four keys into the JMT, and query an ICS23 proof for a nonexistent
    /// key. This reproduces a bug that was fixed in release `0.8.0`
    fn test_jmt_ics23_nonexistence_simple() {
        use crate::Sha256Jmt;
        let db = MockTreeStore::default();
        let tree = Sha256Jmt::new(&db);

        const MAX_VERSION: u64 = 3;

        for version in 0..=MAX_VERSION {
            let key_str = format!("key-{}", version);
            let key = key_str.clone().into_bytes();
            let value_str = format!("value-{}", version);
            let value = value_str.clone().into_bytes();
            let keys = vec![key.clone()];
            let values = vec![value];
            let value_set = keys
                .into_iter()
                .zip(values.into_iter())
                .map(|(k, v)| (KeyHash::with::<Sha256>(&k), Some(v)))
                .collect::<Vec<_>>();
            let key_hash = KeyHash::with::<Sha256>(&key);

            db.put_key_preimage(key_hash, &key);
            let (_root, batch) = tree.put_value_set(value_set, version).unwrap();
            db.write_tree_update_batch(batch)
                .expect("can insert node batch");
        }
        let (_value_retrieved, _commitment_proof) = tree
            .get_with_ics23_proof(format!("does_not_exist").into_bytes(), MAX_VERSION)
            .unwrap();
    }

    #[test]
    /// Write four keys into the JMT, and query an ICS23 proof for a nonexistent
    /// key. This reproduces a bug that was fixed in release `0.8.0`
    fn test_jmt_ics23_nonexistence_simple_large() {
        use crate::Sha256Jmt;
        let db = MockTreeStore::default();
        let tree = Sha256Jmt::new(&db);

        const MAX_VERSION: u64 = 100;

        for version in 0..=MAX_VERSION {
            let key_str = format!("key-{}", version);
            let key = key_str.clone().into_bytes();
            let value_str = format!("value-{}", version);
            let value = value_str.clone().into_bytes();
            let keys = vec![key.clone()];
            let values = vec![value];
            let value_set = keys
                .into_iter()
                .zip(values.into_iter())
                .map(|(k, v)| (KeyHash::with::<Sha256>(&k), Some(v)))
                .collect::<Vec<_>>();
            let key_hash = KeyHash::with::<Sha256>(&key);

            db.put_key_preimage(key_hash, &key);
            let (_root, batch) = tree.put_value_set(value_set, version).unwrap();
            db.write_tree_update_batch(batch)
                .expect("can insert node batch");
        }

        for version in 0..=MAX_VERSION {
            let (_value_retrieved, _commitment_proof) = tree
                .get_with_ics23_proof(format!("does_not_exist").into_bytes(), version)
                .unwrap();
        }
    }

    #[test]
    /// Write four keys into the JMT, and query an ICS23 proof for a nonexistent
    /// key. This reproduces a bug that was fixed in release `0.8.0`. This test uses
    /// the `TransparentJmt` type, which uses a mock hash function that does not hash.
    fn test_jmt_ics23_nonexistence_simple_transparent() {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::<_, TransparentHasher>::new(&db);

        const MAX_VERSION: u64 = 4;

        let mock_keys_str = vec![
            prefix_pad("a0"),
            prefix_pad("b1"),
            prefix_pad("c2"),
            prefix_pad("d3"),
            prefix_pad("e4"),
        ];

        for version in 0..=MAX_VERSION {
            let key = mock_keys_str[version as usize].clone();
            let key_hash = KeyHash::with::<TransparentHasher>(&key);
            let value_str = format!("value-{}", version);
            let value = value_str.clone().into_bytes();
            let keys = vec![key.clone()];
            let values = vec![value];
            let value_set = keys
                .into_iter()
                .zip(values.into_iter())
                .map(|(k, v)| (KeyHash::with::<TransparentHasher>(&k), Some(v)))
                .collect::<Vec<_>>();
            db.put_key_preimage(key_hash, &key.to_vec());
            let (_root, batch) = tree.put_value_set(value_set, version).unwrap();
            db.write_tree_update_batch(batch)
                .expect("can insert node batch");
        }

        let nonexisting_key = prefix_pad("c3");
        let (_value_retrieved, _commitment_proof) = tree
            .get_with_ics23_proof(nonexisting_key.to_vec(), MAX_VERSION)
            .unwrap();
    }

    /// Takes an hexadecimal prefix string (e.g "deadbeef") and returns a padded byte string
    /// that encodes to the padded hexadecimal string (e.g. "deadbeef0....0")
    /// This is useful to create keys with specific hexadecimal representations.
    fn prefix_pad(hex_str: &str) -> [u8; 32] {
        if hex_str.len() > 64 {
            panic!("hexadecimal string is longer than 32 bytes when decoded");
        }

        let mut bytes = Vec::with_capacity(hex_str.len() / 2);
        for i in (0..hex_str.len()).step_by(2) {
            let byte_str = &hex_str[i..i + 2];
            let byte = u8::from_str_radix(byte_str, 16).expect("Invalid hex character");
            bytes.push(byte);
        }

        let mut padded_bytes = [0u8; 32];
        padded_bytes[..bytes.len()].copy_from_slice(&bytes);

        padded_bytes
    }
}
