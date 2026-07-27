// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Merkle proof types.

pub(crate) mod definition;
#[cfg(all(test, feature = "std"))]
pub(crate) mod proptest_proof;

use crate::{
    proof::SparseMerkleNode::{Internal, Leaf},
    SimpleHasher,
};

#[cfg(all(test, feature = "std"))]
use proptest_derive::Arbitrary;

pub use self::definition::{SparseMerkleProof, SparseMerkleRangeProof, UpdateMerkleProof};
use crate::{KeyHash, ValueHash, SPARSE_MERKLE_PLACEHOLDER_HASH};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub const LEAF_DOMAIN_SEPARATOR: &[u8] = b"JMT::LeafNode";
pub const INTERNAL_DOMAIN_SEPARATOR: &[u8] = b"JMT::IntrnalNode";

#[cfg_attr(all(test, feature = "std"), derive(Arbitrary))]
#[derive(
    Serialize, Deserialize, Clone, Copy, Eq, PartialEq, BorshSerialize, BorshDeserialize, Debug,
)]
/// A [`SparseMerkleNode`] is either a null node, an internal sparse node or a leaf node.
/// This is useful in the delete case to know if we need to coalesce the leaves on deletion.
/// The [`SparseMerkleNode`] needs to store either a [`SparseMerkleInternalNode`] or a [`SparseMerkleLeafNode`]
/// to be able to safely assert that the node is either a leaf or an internal node. Indeed,
/// if one stores the node/leaf hash directly into the structure, any malicious prover would
/// be able to forge the node/leaf type, as this assertion wouldn't be checked.
/// Providing a [`SparseMerkleInternalNode`] or a [`SparseMerkleLeafNode`] structure is sufficient to
/// prove the node type as one would need to reverse the hash function to forge them.
pub(crate) enum SparseMerkleNode {
    // The default sparse node
    Null,
    // The internal sparse merkle tree node
    Internal(SparseMerkleInternalNode),
    // The leaf sparse merkle tree node
    Leaf(SparseMerkleLeafNode),
}

impl SparseMerkleNode {
    pub(crate) fn hash<H: SimpleHasher>(&self) -> [u8; 32] {
        match self {
            SparseMerkleNode::Null => SPARSE_MERKLE_PLACEHOLDER_HASH,
            Internal(node) => node.hash::<H>(),
            Leaf(node) => node.hash::<H>(),
        }
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Eq, PartialEq, BorshSerialize, BorshDeserialize, Debug,
)]
#[cfg_attr(all(test, feature = "std"), derive(Arbitrary))]
pub(crate) struct SparseMerkleInternalNode {
    left_child: [u8; 32],
    right_child: [u8; 32],
}

impl SparseMerkleInternalNode {
    pub fn new(left_child: [u8; 32], right_child: [u8; 32]) -> Self {
        Self {
            left_child,
            right_child,
        }
    }

    pub fn hash<H: SimpleHasher>(&self) -> [u8; 32] {
        let mut hasher = H::new();
        // chop a vowel to fit in 16 bytes
        hasher.update(INTERNAL_DOMAIN_SEPARATOR);
        hasher.update(&self.left_child);
        hasher.update(&self.right_child);
        hasher.finalize()
    }
}

#[derive(Eq, Copy, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SparseMerkleLeafNode {
    key_hash: KeyHash,
    value_hash: ValueHash,
}

// Manually implement Arbitrary to get the correct bounds. The derived Arbitrary impl adds a spurious
// H: Debug bound even with the proptest(no_bound) annotation
#[cfg(any(test))]
impl proptest::arbitrary::Arbitrary for SparseMerkleLeafNode {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, strategy::Strategy};
        (any::<KeyHash>(), any::<ValueHash>())
            .prop_map(|(key_hash, value_hash)| Self {
                key_hash,
                value_hash,
            })
            .boxed()
    }
}

// Manually implement Clone to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl Clone for SparseMerkleLeafNode {
    fn clone(&self) -> Self {
        Self {
            key_hash: self.key_hash.clone(),
            value_hash: self.value_hash.clone(),
        }
    }
}

// Manually implement Debug to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl core::fmt::Debug for SparseMerkleLeafNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SparseMerkleLeafNode")
            .field("key_hash", &self.key_hash)
            .field("value_hash", &self.value_hash)
            .finish()
    }
}

// Manually implement PartialEq to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl PartialEq for SparseMerkleLeafNode {
    fn eq(&self, other: &Self) -> bool {
        self.key_hash == other.key_hash && self.value_hash == other.value_hash
    }
}

impl SparseMerkleLeafNode {
    pub(crate) fn new(key_hash: KeyHash, value_hash: ValueHash) -> Self {
        SparseMerkleLeafNode {
            key_hash,
            value_hash,
        }
    }

    pub(crate) fn key_hash(&self) -> KeyHash {
        self.key_hash
    }

    pub(crate) fn hash<H: SimpleHasher>(&self) -> [u8; 32] {
        let mut hasher = H::new();
        hasher.update(LEAF_DOMAIN_SEPARATOR);
        hasher.update(&self.key_hash.0);
        hasher.update(&self.value_hash.0);
        hasher.finalize()
    }
}
