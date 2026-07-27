// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module has definition of various proofs.
use core::marker::PhantomData;

use super::{SparseMerkleInternalNode, SparseMerkleLeafNode, SparseMerkleNode};
use crate::{
    storage::Node,
    types::nibble::nibble_path::{skip_common_prefix, NibblePath},
    Bytes32Ext, KeyHash, RootHash, SimpleHasher, ValueHash, SPARSE_MERKLE_PLACEHOLDER_HASH,
};
use alloc::vec::Vec;
use anyhow::{bail, ensure, format_err, Result};
use serde::{Deserialize, Serialize};

/// A proof that can be used to authenticate an element in a Sparse Merkle Tree given trusted root
/// hash. For example, `TransactionInfoToAccountProof` can be constructed on top of this structure.
#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SparseMerkleProof<H: SimpleHasher> {
    /// This proof can be used to authenticate whether a given leaf exists in the tree or not.
    ///     - If this is `Some(leaf_node)`
    ///         - If `leaf_node.key` equals requested key, this is an inclusion proof and
    ///           `leaf_node.value_hash` equals the hash of the corresponding account blob.
    ///         - Otherwise this is a non-inclusion proof. `leaf_node.key` is the only key
    ///           that exists in the subtree and `leaf_node.value_hash` equals the hash of the
    ///           corresponding account blob.
    ///     - If this is `None`, this is also a non-inclusion proof which indicates the subtree is
    ///       empty.
    // Prevent serde from adding a spurious Serialize/Deserialize bound on H
    #[serde(bound(serialize = "", deserialize = ""))]
    leaf: Option<SparseMerkleLeafNode>,

    /// All siblings in this proof, including the default ones. Siblings are ordered from the bottom
    /// level to the root level. The siblings contain the node type information to be able to efficiently
    /// coalesce on deletes.
    siblings: Vec<SparseMerkleNode>,

    /// A marker type showing which hash function is used in this proof.
    #[borsh(bound(serialize = "", deserialize = ""))]
    phantom_hasher: PhantomData<H>,
}

// Deriving Debug fails since H is not Debug though phantom_hasher implements it
// generically. Implement Debug manually as a workaround to enable Proptest
impl<H: SimpleHasher> core::fmt::Debug for SparseMerkleProof<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SparseMerkleProof")
            .field("leaf", &self.leaf)
            .field("siblings", &self.siblings)
            .field("phantom_hasher", &self.phantom_hasher)
            .finish()
    }
}

// Manually implement PartialEq to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> PartialEq for SparseMerkleProof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.leaf == other.leaf && self.siblings == other.siblings
    }
}

// Manually implement Clone to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> Clone for SparseMerkleProof<H> {
    fn clone(&self) -> Self {
        Self {
            leaf: self.leaf.clone(),
            siblings: self.siblings.clone(),
            phantom_hasher: Default::default(),
        }
    }
}

impl<H: SimpleHasher> SparseMerkleProof<H> {
    /// Constructs a new `SparseMerkleProof` using leaf and a list of siblings.
    pub(crate) fn new(leaf: Option<SparseMerkleLeafNode>, siblings: Vec<SparseMerkleNode>) -> Self {
        SparseMerkleProof {
            leaf,
            siblings,
            phantom_hasher: Default::default(),
        }
    }

    /// Returns the leaf node in this proof.
    pub fn leaf(&self) -> Option<SparseMerkleLeafNode> {
        self.leaf.clone()
    }

    /// Returns the list of siblings in this proof.
    pub(crate) fn siblings(&self) -> &[SparseMerkleNode] {
        &self.siblings
    }

    pub(crate) fn take_siblings(self) -> Vec<SparseMerkleNode> {
        self.siblings
    }

    /// Verifies an element whose key is `element_key` and value is
    /// `element_value` exists in the Sparse Merkle Tree using the provided proof.
    pub fn verify_existence<V: AsRef<[u8]>>(
        &self,
        expected_root_hash: RootHash,
        element_key: KeyHash,
        element_value: V,
    ) -> Result<()> {
        self.verify(expected_root_hash, element_key, Some(element_value))
    }

    /// Verifies the proof is a valid non-inclusion proof that shows this key doesn't exist in the
    /// tree.
    pub fn verify_nonexistence(
        &self,
        expected_root_hash: RootHash,
        element_key: KeyHash,
    ) -> Result<()> {
        self.verify(expected_root_hash, element_key, None::<&[u8]>)
    }

    /// If `element_value` is present, verifies an element whose key is `element_key` and value is
    /// `element_value` exists in the Sparse Merkle Tree using the provided proof. Otherwise
    /// verifies the proof is a valid non-inclusion proof that shows this key doesn't exist in the
    /// tree.
    pub fn verify<V: AsRef<[u8]>>(
        &self,
        expected_root_hash: RootHash,
        element_key: KeyHash,
        element_value: Option<V>,
    ) -> Result<()> {
        ensure!(
            self.siblings.len() <= 256,
            "Sparse Merkle Tree proof has more than {} ({}) siblings.",
            256,
            self.siblings.len(),
        );

        match (element_value, self.leaf.clone()) {
            (Some(value), Some(leaf)) => {
                // This is an inclusion proof, so the key and value hash provided in the proof
                // should match element_key and element_value_hash. `siblings` should prove the
                // route from the leaf node to the root.
                ensure!(
                    element_key == leaf.key_hash,
                    "Keys do not match. Key in proof: {:?}. Expected key: {:?}.",
                    leaf.key_hash,
                    element_key
                );
                let hash: ValueHash = ValueHash::with::<H>(value);
                ensure!(
                    hash == leaf.value_hash,
                    "Value hashes do not match. Value hash in proof: {:?}. \
                     Expected value hash: {:?}",
                    leaf.value_hash,
                    hash,
                );
            }
            (Some(_value), None) => bail!("Expected inclusion proof. Found non-inclusion proof."),
            (None, Some(leaf)) => {
                // This is a non-inclusion proof. The proof intends to show that if a leaf node
                // representing `element_key` is inserted, it will break a currently existing leaf
                // node represented by `proof_key` into a branch. `siblings` should prove the
                // route from that leaf node to the root.
                ensure!(
                    element_key != leaf.key_hash,
                    "Expected non-inclusion proof, but key exists in proof.",
                );
                ensure!(
                    element_key.0.common_prefix_bits_len(&leaf.key_hash.0) >= self.siblings.len(),
                    "Key would not have ended up in the subtree where the provided key in proof \
                     is the only existing key, if it existed. So this is not a valid \
                     non-inclusion proof.",
                );
            }
            (None, None) => {
                // This is a non-inclusion proof. The proof intends to show that if a leaf node
                // representing `element_key` is inserted, it will show up at a currently empty
                // position. `sibling` should prove the route from this empty position to the root.
            }
        }

        let current_hash = self
            .leaf
            .clone()
            .map_or(SPARSE_MERKLE_PLACEHOLDER_HASH, |leaf| leaf.hash::<H>());
        let actual_root_hash = self
            .siblings
            .iter()
            .zip(
                element_key
                    .0
                    .iter_bits()
                    .rev()
                    .skip(256 - self.siblings.len()),
            )
            .fold(current_hash, |hash, (sibling_node, bit)| {
                if bit {
                    SparseMerkleInternalNode::new(sibling_node.hash::<H>(), hash).hash::<H>()
                } else {
                    SparseMerkleInternalNode::new(hash, sibling_node.hash::<H>()).hash::<H>()
                }
            });

        ensure!(
            actual_root_hash == expected_root_hash.0,
            "Root hashes do not match. Actual root hash: {:?}. Expected root hash: {:?}.",
            actual_root_hash,
            expected_root_hash.0,
        );

        Ok(())
    }

    /// This function computes a new merkle path on split insertion (ie when inserting a new value creates
    /// a key split).
    ///
    /// Add the correct siblings of the new merkle path by finding the splitting nibble and
    /// adding the default leaves to the path
    ///
    /// To compute the number of default leaves we need to add, we need to:
    /// - Compute the number of default leaves to separate the old leaf from the new leaf in the last nibble
    /// - Compute the number of default leaves to traverse the common prefix
    /// - Compute the number of default leaves remaining to select the former old leaf in the former last nibble
    /// (this leaf becomes an internal node, hence the path needs to be fully specified)
    fn compute_new_merkle_path_on_split<V: AsRef<[u8]>>(
        mut self,
        leaf_node: SparseMerkleLeafNode,
        new_element_key: KeyHash,
        new_element_value: V,
    ) -> SparseMerkleProof<H> {
        let new_key_path = NibblePath::new(new_element_key.0.to_vec());
        let old_key_path = NibblePath::new(leaf_node.key_hash.0.to_vec());

        // The verify_nonexistence check from before ensure that the common prefix nibbles_len is greater than the
        // siblings len
        let mut new_key_nibbles = new_key_path.nibbles();
        let mut old_key_nibbles = old_key_path.nibbles();

        let common_prefix_len = skip_common_prefix(&mut new_key_nibbles, &mut old_key_nibbles);

        let num_siblings = self.siblings().len();

        // The number of default leaves we need to add to the path.
        let default_leaves_to_add_to_the_path =
            ((4 * (common_prefix_len + 1) - num_siblings) / 4) * 4;

        // This variable contains the number of default siblings that are inserted within the last nibble subtree to distinguish
        // between the former and the new key. Since we are splitting the former key, we are creating a new level of the jmt
        // that only contains the new and the former key. When converted into a binary tree, we need to add default leaves to
        // reach the binary tree level that can distinguish the two keys. This amounts adding as many default leaves as there
        // are bits in common in the last nibble of both keys.
        let mut default_siblings_leaf_nibble = 0;

        // We can safely unwrap these values as the check have been already performed in verify_nonexistence
        let mut new_key_bits = new_key_nibbles.bits();
        let mut old_key_bits = old_key_nibbles.bits();

        // Hence, we have to add the number of bits in common in both keys.
        while new_key_bits.next() == old_key_bits.next() {
            default_siblings_leaf_nibble += 1;
        }

        // The number of default leaves we need to add to the previous root. When splitting a leaf node, we create a new internal node
        // in place of the former leaf that has two leaf children. Hence we need to add some default siblings because the leaf node may
        // not be at the last level of the subtree of the last nibble.
        // To get this number, we need to take the number of siblings modulo 4 (this yields the hight of the splitted leaf in the last binary subtree,
        // or the number of bits in the last nibble of the splitted leaf), substract it to 4 (to get the number of bits needed to complete the last nibble)
        // and then take the result modulo 4 (in case num_siblings % 4 is zero, which happens when the leaf is at the lowest height of the last binary subtree).
        let default_siblings_prev_root = (4 - (num_siblings % 4)) % 4;

        let num_default_siblings = default_siblings_prev_root
            + default_leaves_to_add_to_the_path
            + default_siblings_leaf_nibble
            - 4;

        let mut new_siblings: Vec<SparseMerkleNode> = Vec::with_capacity(
            num_default_siblings + 1 + self.siblings.len(), /* The default siblings, the current leaf that becomes a sibling and the former siblings */
        );

        // Add the previous leaf node
        new_siblings.push(SparseMerkleNode::Leaf(SparseMerkleLeafNode {
            key_hash: leaf_node.key_hash,
            value_hash: leaf_node.value_hash,
        }));

        // Fill the siblings with the former default siblings
        new_siblings.resize(num_default_siblings + 1, SparseMerkleNode::Null);

        // Finally add the other siblings
        new_siblings.append(&mut self.siblings);

        // Step 2: we compute the new Merkle path (we build a new [`SparseMerkleProof`] object)
        // In this case the siblings are left unchanged, only the leaf value is updated
        SparseMerkleProof::new(
            Some(SparseMerkleLeafNode::new(
                new_element_key,
                ValueHash::with::<H>(new_element_value),
            )),
            new_siblings,
        )
    }

    /// Checks the old value against the root hash and computes the new root hash based on
    /// the new key value pair
    fn check_compute_new_root<V: AsRef<[u8]>>(
        self,
        old_root_hash: RootHash,
        new_element_key: KeyHash,
        new_element_value: Option<V>,
    ) -> Result<RootHash> {
        if let Some(new_element_value) = new_element_value {
            // A value have been supplied, we need to prove that we inserted a given value at the new key

            match self.leaf {
                // In the case there is a leaf in the Merkle path, we check that this leaf exists in the tree
                // The inserted key is going to update an existing leaf
                Some(leaf_node) => {
                    // First verify that the old merkle path is valid
                    ensure!(self.root_hash() == old_root_hash);
                    if new_element_key == leaf_node.key_hash {
                        // Step 2: we compute the new Merkle path (we build a new [`SparseMerkleProof`] object)
                        // In this case the siblings are left unchanged, only the leaf value is updated
                        let new_merkle_path: SparseMerkleProof<H> = SparseMerkleProof::new(
                            Some(SparseMerkleLeafNode::new(
                                new_element_key,
                                ValueHash::with::<H>(new_element_value),
                            )),
                            self.siblings,
                        );

                        // Step 3: we compute the new Merkle root
                        Ok(new_merkle_path.root_hash())
                    } else {
                        let new_merkle_path = self.compute_new_merkle_path_on_split(
                            leaf_node,
                            new_element_key,
                            new_element_value,
                        );

                        // Step 3: we compute the new Merkle root
                        Ok(new_merkle_path.root_hash())
                    }
                }

                // There is no leaf in the Merkle path, which means the key we are going to insert does not update an existing leaf
                None => {
                    ensure!(self
                        .verify_nonexistence(old_root_hash, new_element_key)
                        .is_ok());

                    // Step 2: we compute the new Merkle path (we build a new [`SparseMerkleProof`] object)
                    // In that case, the leaf is none so we don't need to change the siblings
                    let new_merkle_path: SparseMerkleProof<H> = SparseMerkleProof::new(
                        Some(SparseMerkleLeafNode::new(
                            new_element_key,
                            ValueHash::with::<H>(new_element_value),
                        )),
                        self.siblings,
                    );

                    // Step 3: we compute the new Merkle root
                    Ok(new_merkle_path.root_hash())
                }
            }
        } else {
            // No value supplied, we need to prove that the previous value was deleted
            if let Some(leaf_node) = self.leaf {
                ensure!(self.root_hash() == old_root_hash);
                ensure!(
                    new_element_key == leaf_node.key_hash,
                    "Key {:?} to remove doesn't match the leaf key {:?} supplied with the proof",
                    new_element_key,
                    leaf_node.key_hash
                );

                // Step 2: we compute the new Merkle tree path.
                // In case of deletion, we need to rewind the nibble until we reach the first non-default hash
                // to simulate node coalescing.
                // Then, when we reach the first non-default hash, we have to compute the new merkle path
                // We have two different cases:
                // - the first non-default sibling is an internal node: we don't apply coalescing.
                // - the first non-default sibling is a leaf node: we apply coalescing
                let mut siblings_it = self.siblings.into_iter().peekable();
                let mut next_non_default_sib = SparseMerkleNode::Null;
                while let Some(next_sibling) = siblings_it.peek() {
                    if *next_sibling != SparseMerkleNode::Null {
                        next_non_default_sib = *next_sibling;
                        break;
                    }
                    siblings_it.next();
                }

                let new_merkle_hash = match next_non_default_sib {
                    SparseMerkleNode::Internal(_) => {
                        // We need to keep the internal node in the iterator and simply compute the merkle path using the
                        // default leave as the root
                        let remaining_siblings_len = siblings_it.len();

                        // If the sibling is an internal node, it doesn't get coalesced after deletion.
                        RootHash(
                            siblings_it
                                .zip(
                                    new_element_key
                                        .0
                                        .iter_bits()
                                        .rev()
                                        .skip(256 - remaining_siblings_len),
                                )
                                .fold(Node::new_null().hash::<H>(), |hash, (sibling_node, bit)| {
                                    if bit {
                                        SparseMerkleInternalNode::new(
                                            sibling_node.hash::<H>(),
                                            hash,
                                        )
                                        .hash::<H>()
                                    } else {
                                        SparseMerkleInternalNode::new(
                                            hash,
                                            sibling_node.hash::<H>(),
                                        )
                                        .hash::<H>()
                                    }
                                }),
                        )
                    }
                    SparseMerkleNode::Leaf(_) => {
                        // We need to remove the leaf from the iterator
                        siblings_it.next();

                        // We have to remove the default leaves left in the siblings before the next root: coalescing
                        while let Some(next_sibling) = siblings_it.peek() {
                            if *next_sibling != SparseMerkleNode::Null {
                                break;
                            }
                            siblings_it.next();
                        }

                        let remaining_siblings_len = siblings_it.len();

                        // If the sibling is a leaf, we need to start computing the merkle hash from the leaf value
                        // because the node gets coalesced
                        RootHash(
                            siblings_it
                                .zip(
                                    new_element_key
                                        .0
                                        .iter_bits()
                                        .rev()
                                        .skip(256 - remaining_siblings_len),
                                )
                                .fold(
                                    next_non_default_sib.hash::<H>(),
                                    |hash, (sibling_node, bit)| {
                                        if bit {
                                            SparseMerkleInternalNode::new(
                                                sibling_node.hash::<H>(),
                                                hash,
                                            )
                                            .hash::<H>()
                                        } else {
                                            SparseMerkleInternalNode::new(
                                                hash,
                                                sibling_node.hash::<H>(),
                                            )
                                            .hash::<H>()
                                        }
                                    },
                                ),
                        )

                        // Step 3: we compute the new Merkle root
                    }
                    SparseMerkleNode::Null => RootHash(SPARSE_MERKLE_PLACEHOLDER_HASH),
                };

                Ok(new_merkle_hash)
            } else {
                // We just return the old root hash if we try to remove the empty node
                // because there isn't any changes to the merkle tree
                Ok(old_root_hash)
            }
        }
    }

    pub fn root_hash(&self) -> RootHash {
        let current_hash = self
            .leaf
            .clone()
            .map_or(SPARSE_MERKLE_PLACEHOLDER_HASH, |leaf| leaf.hash::<H>());
        let actual_root_hash = self
            .siblings
            .iter()
            .zip(
                self.leaf()
                    .expect("need leaf hash for root_hash")
                    .key_hash
                    .0
                    .iter_bits()
                    .rev()
                    .skip(256 - self.siblings.len()),
            )
            .fold(current_hash, |hash, (sibling_node, bit)| {
                if bit {
                    SparseMerkleInternalNode::new(sibling_node.hash::<H>(), hash).hash::<H>()
                } else {
                    SparseMerkleInternalNode::new(hash, sibling_node.hash::<H>()).hash::<H>()
                }
            });

        RootHash(actual_root_hash)
    }
}

#[derive(Debug, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct UpdateMerkleProof<H: SimpleHasher>(
    #[borsh(bound(serialize = "", deserialize = ""))] Vec<SparseMerkleProof<H>>,
);

impl<H: SimpleHasher> UpdateMerkleProof<H> {
    pub fn new(merkle_proofs: Vec<SparseMerkleProof<H>>) -> Self {
        UpdateMerkleProof(merkle_proofs)
    }

    /// Verifies an update of the [`JellyfishMerkleTree`], proving the transition from an `old_root_hash` to a `new_root_hash` ([`RootHash`])
    /// Multiple cases to handle:
    ///    - Insert a tuple `new_element_key`, `new_element_value`
    ///    - Update a tuple `new_element_key`, `new_element_value`
    ///    - Delete the `new_element_key`
    /// This function does the following high level operations:
    ///    1. Verify the Merkle path provided against the `old_root_hash`
    ///    2. Use the provided Merkle path and the tuple (`new_element_key`, `new_element_value`) to compute the new Merkle path.
    ///    3. Compare the new Merkle path against the new_root_hash
    /// If these steps are verified then the [`JellyfishMerkleTree`] has been soundly updated
    ///
    /// This function consumes the Merkle proof to avoid uneccessary copying.
    pub fn verify_update<V: AsRef<[u8]>>(
        self,
        old_root_hash: RootHash,
        new_root_hash: RootHash,
        updates: impl AsRef<[(KeyHash, Option<V>)]>,
    ) -> Result<()> {
        let updates = updates.as_ref();
        ensure!(
            updates.len() == self.0.len(),
            "Mismatched number of updates and proofs. Received {} proofs for {} updates",
            self.0.len(),
            updates.len()
        );
        let mut curr_root_hash = old_root_hash;

        for (merkle_proof, (new_element_key, new_element_value)) in
            self.0.into_iter().zip(updates.iter())
        {
            // Checks the old root hash and computes the new root
            curr_root_hash = merkle_proof.check_compute_new_root(
                curr_root_hash,
                *new_element_key,
                new_element_value.as_ref(),
            )?;
        }

        ensure!(
            curr_root_hash == new_root_hash,
            "Root hashes do not match. Actual root hash: {:?}. Expected root hash: {:?}.",
            curr_root_hash,
            new_root_hash,
        );

        Ok(())
    }
}

/// Note: this is not a range proof in the sense that a range of nodes is verified!
/// Instead, it verifies the entire left part of the tree up to a known rightmost node.
/// See the description below.
///
/// A proof that can be used to authenticate a range of consecutive leaves, from the leftmost leaf to
/// the rightmost known one, in a sparse Merkle tree. For example, given the following sparse Merkle tree:
///
/// ```text
///                   root
///                  /     \
///                 /       \
///                /         \
///               o           o
///              / \         / \
///             a   o       o   h
///                / \     / \
///               o   d   e   X
///              / \         / \
///             b   c       f   g
/// ```
///
/// if the proof wants show that `[a, b, c, d, e]` exists in the tree, it would need the siblings
/// `X` and `h` on the right.
#[derive(Eq, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SparseMerkleRangeProof<H: SimpleHasher> {
    /// The vector of siblings on the right of the path from root to last leaf. The ones near the
    /// bottom are at the beginning of the vector. In the above example, it's `[X, h]`.
    right_siblings: Vec<SparseMerkleNode>,
    _phantom: PhantomData<H>,
}

// Manually implement PartialEq to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> PartialEq for SparseMerkleRangeProof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.right_siblings == other.right_siblings
    }
}

// Manually implement Clone to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> Clone for SparseMerkleRangeProof<H> {
    fn clone(&self) -> Self {
        Self {
            right_siblings: self.right_siblings.clone(),
            _phantom: self._phantom.clone(),
        }
    }
}

// Manually implement Debug to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> core::fmt::Debug for SparseMerkleRangeProof<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SparseMerkleRangeProof")
            .field("right_siblings", &self.right_siblings)
            .field("_phantom", &self._phantom)
            .finish()
    }
}

impl<H: SimpleHasher> SparseMerkleRangeProof<H> {
    /// Constructs a new `SparseMerkleRangeProof`.
    pub(crate) fn new(right_siblings: Vec<SparseMerkleNode>) -> Self {
        Self {
            right_siblings,
            _phantom: Default::default(),
        }
    }

    /// Returns the right siblings.
    pub(crate) fn right_siblings(&self) -> &[SparseMerkleNode] {
        &self.right_siblings
    }

    /// Verifies that the rightmost known leaf exists in the tree and that the resulting
    /// root hash matches the expected root hash.
    pub fn verify(
        &self,
        expected_root_hash: RootHash,
        rightmost_known_leaf: SparseMerkleLeafNode,
        left_siblings: Vec<[u8; 32]>,
    ) -> Result<()> {
        let num_siblings = left_siblings.len() + self.right_siblings.len();
        let mut left_sibling_iter = left_siblings.iter();
        let mut right_sibling_iter = self.right_siblings().iter();

        let mut current_hash = rightmost_known_leaf.hash::<H>();
        for bit in rightmost_known_leaf
            .key_hash()
            .0
            .iter_bits()
            .rev()
            .skip(256 - num_siblings)
        {
            let (left_hash, right_hash) = if bit {
                (
                    *left_sibling_iter
                        .next()
                        .ok_or_else(|| format_err!("Missing left sibling."))?,
                    current_hash,
                )
            } else {
                (
                    current_hash,
                    right_sibling_iter
                        .next()
                        .ok_or_else(|| format_err!("Missing right sibling."))?
                        .hash::<H>(),
                )
            };
            current_hash = SparseMerkleInternalNode::new(left_hash, right_hash).hash::<H>();
        }

        ensure!(
            current_hash == expected_root_hash.0,
            "Root hashes do not match. Actual root hash: {:?}. Expected root hash: {:?}.",
            current_hash,
            expected_root_hash,
        );

        Ok(())
    }
}

#[cfg(test)]
mod serialization_tests {
    //! These tests ensure that the various proofs supported by the JMT can actually be serialized and deserialized
    //! when instantiated with a specific hasher. This is done as a sanity check to ensure the trait bounds inferred by Rustc
    //! are not too restrictive.

    use sha2::Sha256;

    use crate::{
        proof::{SparseMerkleInternalNode, SparseMerkleLeafNode, SparseMerkleNode},
        KeyHash, ValueHash,
    };

    use super::{SparseMerkleProof, SparseMerkleRangeProof};

    fn get_test_proof() -> SparseMerkleProof<Sha256> {
        SparseMerkleProof {
            leaf: Some(SparseMerkleLeafNode::new(
                KeyHash([1u8; 32]),
                ValueHash([2u8; 32]),
            )),
            siblings: alloc::vec![SparseMerkleNode::Internal(SparseMerkleInternalNode::new(
                [3u8; 32], [4u8; 32]
            ))],
            phantom_hasher: Default::default(),
        }
    }

    fn get_test_range_proof() -> SparseMerkleRangeProof<Sha256> {
        SparseMerkleRangeProof {
            right_siblings: alloc::vec![SparseMerkleNode::Internal(SparseMerkleInternalNode::new(
                [3u8; 32], [4u8; 32]
            ))],
            _phantom: Default::default(),
        }
    }

    #[test]
    fn test_sparse_merkle_proof_roundtrip_serde() {
        let proof = get_test_proof();
        let serialized_proof = serde_json::to_string(&proof).expect("serialization is infallible");
        let deserialized =
            serde_json::from_str(&serialized_proof).expect("serialized proof is valid");

        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_sparse_merkle_proof_roundtrip_borsh() {
        use borsh::BorshDeserialize;
        let proof = get_test_proof();
        let serialized_proof = borsh::to_vec(&proof).expect("serialization is infallible");
        let deserialized =
            SparseMerkleProof::<Sha256>::deserialize(&mut serialized_proof.as_slice())
                .expect("serialized proof is valid");

        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_sparse_merkle_range_proof_roundtrip_serde() {
        let proof = get_test_range_proof();
        let serialized_proof = serde_json::to_string(&proof).expect("serialization is infallible");
        let deserialized =
            serde_json::from_str(&serialized_proof).expect("serialized proof is valid");

        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_sparse_merkle_range_proof_roundtrip_borsh() {
        use borsh::BorshDeserialize;
        let proof = get_test_range_proof();
        let serialized_proof = borsh::to_vec(&proof).expect("serialization is infallible");
        let deserialized =
            SparseMerkleRangeProof::<Sha256>::deserialize(&mut serialized_proof.as_slice())
                .expect("serialized proof is valid");

        assert_eq!(proof, deserialized);
    }
}
