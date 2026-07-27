// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Node types of [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
//!
//! This module defines two types of Jellyfish Merkle tree nodes: [`InternalNode`]
//! and [`LeafNode`] as building blocks of a 256-bit
//! [`JellyfishMerkleTree`](crate::JellyfishMerkleTree). [`InternalNode`] represents a 4-level
//! binary tree to optimize for IOPS: it compresses a tree with 31 nodes into one node with 16
//! chidren at the lowest level. [`LeafNode`] stores the full key and the value associated.
use crate::storage::TreeReader;

use crate::SimpleHasher;
use alloc::format;
use alloc::vec::Vec;
use alloc::{boxed::Box, vec};
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use num_derive::{FromPrimitive, ToPrimitive};
#[cfg(any(test))]
use proptest::prelude::*;
#[cfg(any(test))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

use crate::proof::SparseMerkleNode;
use crate::{
    types::{
        nibble::{nibble_path::NibblePath, Nibble},
        proof::{SparseMerkleInternalNode, SparseMerkleLeafNode},
        Version,
    },
    KeyHash, ValueHash, SPARSE_MERKLE_PLACEHOLDER_HASH,
};

/// The unique key of each node.
#[derive(
    Clone,
    Debug,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[cfg_attr(any(test), derive(Arbitrary))]
pub struct NodeKey {
    // The version at which the node is created.
    version: Version,
    // The nibble path this node represents in the tree.
    nibble_path: NibblePath,
}

impl NodeKey {
    /// Creates a new `NodeKey`.
    pub fn new(version: Version, nibble_path: NibblePath) -> Self {
        Self {
            version,
            nibble_path,
        }
    }

    /// A shortcut to generate a node key consisting of a version and an empty nibble path.
    pub(crate) fn new_empty_path(version: Version) -> Self {
        Self::new(version, NibblePath::new(vec![]))
    }

    /// Gets the version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Gets the nibble path.
    pub fn nibble_path(&self) -> &NibblePath {
        &self.nibble_path
    }

    /// Generates a child node key based on this node key.
    // Quilibrium: exposed for the forest's efficient Merkle-diff sync
    // (quil-forest/src/sync.rs), which builds child node keys to walk two trees
    // top-down and transfer only differing subtrees. Upstream keeps this
    // pub(crate); we only widen visibility, no behavior change.
    pub fn gen_child_node_key(&self, version: Version, n: Nibble) -> Self {
        let mut node_nibble_path = self.nibble_path().clone();
        node_nibble_path.push(n);
        Self::new(version, node_nibble_path)
    }

    /// Generates parent node key at the same version based on this node key.
    pub(crate) fn gen_parent_node_key(&self) -> Self {
        let mut node_nibble_path = self.nibble_path().clone();
        assert!(
            node_nibble_path.pop().is_some(),
            "Current node key is root.",
        );
        Self::new(self.version, node_nibble_path)
    }

    /// Sets the version to the given version.
    pub(crate) fn set_version(&mut self, version: Version) {
        self.version = version;
    }
}

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum NodeType {
    Leaf,
    Internal { leaf_count: usize },
}

#[cfg(any(test))]
impl Arbitrary for NodeType {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        prop_oneof![
            Just(NodeType::Leaf),
            (2..100usize).prop_map(|leaf_count| NodeType::Internal { leaf_count })
        ]
        .boxed()
    }
}

/// Each child of [`InternalNode`] encapsulates a nibble forking at this node.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[cfg_attr(any(test), derive(Arbitrary))]
pub struct Child {
    /// The hash value of this child node.
    pub hash: [u8; 32],
    /// `version`, the `nibble_path` of the ['NodeKey`] of this [`InternalNode`] the child belongs
    /// to and the child's index constitute the [`NodeKey`] to uniquely identify this child node
    /// from the storage. Used by `[`NodeKey::gen_child_node_key`].
    pub version: Version,
    /// Indicates if the child is a leaf, or if it's an internal node, the total number of leaves
    /// under it.
    pub node_type: NodeType,
}

impl Child {
    pub fn new(hash: [u8; 32], version: Version, node_type: NodeType) -> Self {
        Self {
            hash,
            version,
            node_type,
        }
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self.node_type, NodeType::Leaf)
    }

    pub fn leaf_count(&self) -> usize {
        match self.node_type {
            NodeType::Leaf => 1,
            NodeType::Internal { leaf_count } => leaf_count,
        }
    }
}

/// [`Children`] is just a collection of children belonging to a [`InternalNode`], indexed from 0 to
/// 15, inclusive.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Children {
    /// The actual children. We box this array to avoid stack overflows, since the space consumed
    /// is somewhat large
    children: Box<[Option<Child>; 16]>,
    num_children: usize,
}

#[cfg(any(test))]
impl Arbitrary for Children {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<Box<[Option<Child>; 16]>>().prop_map(|children| {
            let num_children = children.iter().filter(|child| child.is_some()).count();
            Self {
                children,
                num_children,
            }
        }))
        .boxed()
    }
}

impl Children {
    /// Create an empty set of children.
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert a new child. Insert is guaranteed not to allocate.
    pub fn insert(&mut self, nibble: Nibble, child: Child) {
        let idx = nibble.as_usize();
        if self.children[idx].is_none() {
            self.num_children += 1;
        }
        self.children[idx] = Some(child);
    }

    /// Get the child at the provided nibble.
    pub fn get(&self, nibble: Nibble) -> &Option<Child> {
        &self.children[nibble.as_usize()]
    }

    /// Check if the struct contains any children.
    pub fn is_empty(&self) -> bool {
        self.num_children == 0
    }

    /// Remove the child at the provided nibble.
    pub fn remove(&mut self, nibble: Nibble) {
        let idx = nibble.as_usize();
        if self.children[idx].is_some() {
            self.num_children -= 1;
        }
        self.children[idx] = None;
    }

    /// Returns a (possibly unsorted) iterator over the children.
    pub fn values(&self) -> impl Iterator<Item = &Child> {
        self.children.iter().filter_map(|child| child.as_ref())
    }

    /// Returns a (possibly unsorted) iterator over the children and their respective Nibbles.
    pub fn iter(&self) -> impl Iterator<Item = (Nibble, &Child)> {
        self.iter_sorted()
    }

    /// Returns a (possibly unsorted) mutable iterator over the children, also yielding their respective nibbles.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Nibble, &mut Child)> {
        self.children
            .iter_mut()
            .enumerate()
            .filter_map(|(nibble, child)| {
                if let Some(child) = child {
                    Some((Nibble::from(nibble as u8), child))
                } else {
                    None
                }
            })
    }

    /// Returns the number of children.
    pub fn num_children(&self) -> usize {
        self.num_children
    }

    /// Returns an iterator that yields the children and their respective Nibbles in sorted order.
    pub fn iter_sorted(&self) -> impl Iterator<Item = (Nibble, &Child)> {
        self.children
            .iter()
            .enumerate()
            .filter_map(|(nibble, child)| {
                if let Some(child) = child {
                    Some((Nibble::from(nibble as u8), child))
                } else {
                    None
                }
            })
    }
}

/// Represents a 4-level subtree with 16 children at the bottom level. Theoretically, this reduces
/// IOPS to query a tree by 4x since we compress 4 levels in a standard Merkle tree into 1 node.
/// Though we choose the same internal node structure as that of Patricia Merkle tree, the root hash
/// computation logic is similar to a 4-level sparse Merkle tree except for some customizations. See
/// the `CryptoHash` trait implementation below for details.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct InternalNode {
    /// Up to 16 children.
    children: Children,
    /// Total number of leaves under this internal node
    leaf_count: usize,
}

impl SparseMerkleInternalNode {
    fn from<H: SimpleHasher>(internal_node: InternalNode) -> Self {
        let bitmaps = internal_node.generate_bitmaps();
        SparseMerkleInternalNode::new(
            internal_node.merkle_hash::<H>(0, 8, bitmaps),
            internal_node.merkle_hash::<H>(8, 8, bitmaps),
        )
    }
}

/// Computes the hash of internal node according to [`JellyfishTree`](crate::JellyfishTree)
/// data structure in the logical view. `start` and `nibble_height` determine a subtree whose
/// root hash we want to get. For an internal node with 16 children at the bottom level, we compute
/// the root hash of it as if a full binary Merkle tree with 16 leaves as below:
///
/// ```text
///   4 ->              +------ root hash ------+
///                     |                       |
///   3 ->        +---- # ----+           +---- # ----+
///               |           |           |           |
///   2 ->        #           #           #           #
///             /   \       /   \       /   \       /   \
///   1 ->     #     #     #     #     #     #     #     #
///           / \   / \   / \   / \   / \   / \   / \   / \
///   0 ->   0   1 2   3 4   5 6   7 8   9 A   B C   D E   F
///   ^
/// height
/// ```
///
/// As illustrated above, at nibble height 0, `0..F` in hex denote 16 chidren hashes.  Each `#`
/// means the hash of its two direct children, which will be used to generate the hash of its
/// parent with the hash of its sibling. Finally, we can get the hash of this internal node.
///
/// However, if an internal node doesn't have all 16 chidren exist at height 0 but just a few of
/// them, we have a modified hashing rule on top of what is stated above:
/// 1. From top to bottom, a node will be replaced by a leaf child if the subtree rooted at this
/// node has only one child at height 0 and it is a leaf child.
/// 2. From top to bottom, a node will be replaced by the placeholder node if the subtree rooted at
/// this node doesn't have any child at height 0. For example, if an internal node has 3 leaf
/// children at index 0, 3, 8, respectively, and 1 internal node at index C, then the computation
/// graph will be like:
///
/// ```text
///   4 ->              +------ root hash ------+
///                     |                       |
///   3 ->        +---- # ----+           +---- # ----+
///               |           |           |           |
///   2 ->        #           @           8           #
///             /   \                               /   \
///   1 ->     0     3                             #     @
///                                               / \
///   0 ->                                       C   @
///   ^
/// height
/// Note: @ denotes placeholder hash.
/// ```
#[cfg(any(test))]
impl Arbitrary for InternalNode {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        (any::<Children>().prop_filter(
            "InternalNode constructor panics when its only child is a leaf.",
            |children| {
                !(children.num_children() == 1
                    && children.values().next().expect("Must exist.").is_leaf())
            },
        ))
        .prop_map(InternalNode::new)
        .boxed()
    }
}

/// Helper for `InternalNode` implementations. Test if the leaf exaclty has one child within the width range specified
fn has_only_child(width: u8, range_existence_bitmap: u16, range_leaf_bitmap: u16) -> bool {
    width == 1 || (range_existence_bitmap.count_ones() == 1 && range_leaf_bitmap != 0)
}

/// Helper for `InternalNode` implementations. Test if the leaf exactly has one child *at the position n*
///  within the width range specified
fn has_child(
    width: u8,
    range_existence_bitmap: u16,
    n_bitmap: u16,
    range_leaf_bitmap: u16,
) -> bool {
    width == 1 || (range_existence_bitmap == n_bitmap && range_leaf_bitmap != 0)
}

impl InternalNode {
    /// Creates a new Internal node.
    pub fn new(children: Children) -> Self {
        // Assert the internal node must have >= 1 children. If it only has one child, it cannot be
        // a leaf node. Otherwise, the leaf node should be a child of this internal node's parent.
        assert!(!children.is_empty(), "Children must not be empty");
        if children.num_children() == 1 {
            assert!(
                !children
                    .values()
                    .next()
                    .expect("Must have 1 element")
                    .is_leaf(),
                "If there's only one child, it must not be a leaf."
            );
        }

        let leaf_count = Self::sum_leaf_count(&children);
        Self {
            children,
            leaf_count,
        }
    }

    fn sum_leaf_count(children: &Children) -> usize {
        let mut leaf_count = 0;
        for child in children.values() {
            let n = child.leaf_count();
            leaf_count += n;
        }
        leaf_count
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn node_type(&self) -> NodeType {
        NodeType::Internal {
            leaf_count: self.leaf_count,
        }
    }

    pub fn hash<H: SimpleHasher>(&self) -> [u8; 32] {
        self.merkle_hash::<H>(
            0,  /* start index */
            16, /* the number of leaves in the subtree of which we want the hash of root */
            self.generate_bitmaps(),
        )
    }

    pub fn children_sorted(&self) -> impl Iterator<Item = (Nibble, &Child)> {
        // Previously this used `.sorted_by_key()` directly on the iterator but this does not appear
        // to be available in itertools (it does not seem to ever have existed???) for unknown
        // reasons. This satisfies the same behavior. ¯\_(ツ)_/¯
        self.children.iter_sorted()
    }

    pub fn children_unsorted(&self) -> impl Iterator<Item = (Nibble, &Child)> {
        self.children.iter()
    }

    /// Gets the `n`-th child.
    pub fn child(&self, n: Nibble) -> Option<&Child> {
        self.children.get(n).as_ref()
    }

    /// Generates `existence_bitmap` and `leaf_bitmap` as a pair of `u16`s: child at index `i`
    /// exists if `existence_bitmap[i]` is set; child at index `i` is leaf node if
    /// `leaf_bitmap[i]` is set.
    pub fn generate_bitmaps(&self) -> (u16, u16) {
        let mut existence_bitmap = 0;
        let mut leaf_bitmap = 0;
        for (nibble, child) in self.children.iter() {
            let i = u8::from(nibble);
            existence_bitmap |= 1u16 << i;
            if child.is_leaf() {
                leaf_bitmap |= 1u16 << i;
            }
        }
        // `leaf_bitmap` must be a subset of `existence_bitmap`.
        assert_eq!(existence_bitmap | leaf_bitmap, existence_bitmap);
        (existence_bitmap, leaf_bitmap)
    }

    /// Given a range [start, start + width), returns the sub-bitmap of that range.
    fn range_bitmaps(start: u8, width: u8, bitmaps: (u16, u16)) -> (u16, u16) {
        assert!(start < 16 && width.count_ones() == 1 && start % width == 0);
        assert!(width <= 16 && (start + width) <= 16);
        // A range with `start == 8` and `width == 4` will generate a mask 0b0000111100000000.
        // use as converting to smaller integer types when 'width == 16'
        let mask = (((1u32 << width) - 1) << start) as u16;
        (bitmaps.0 & mask, bitmaps.1 & mask)
    }

    /// [`build_sibling`] builds the sibling contained in the merkle tree between
    /// [start; start+width) under the internal node (`self`) using the `TreeReader` as
    /// a node reader to get the leaves/internal nodes at the bottom level of this internal node
    fn build_sibling<H: SimpleHasher>(
        &self,
        tree_reader: &impl TreeReader,
        node_key: &NodeKey,
        start: u8,
        width: u8,
        (existence_bitmap, leaf_bitmap): (u16, u16),
    ) -> SparseMerkleNode {
        // Given a bit [start, 1 << nibble_height], return the value of that range.
        let (range_existence_bitmap, range_leaf_bitmap) =
            Self::range_bitmaps(start, width, (existence_bitmap, leaf_bitmap));
        if range_existence_bitmap == 0 {
            // No child under this subtree
            SparseMerkleNode::Null
        } else if has_only_child(width, range_existence_bitmap, range_leaf_bitmap) {
            // Only 1 leaf child under this subtree or reach the lowest level
            let only_child_index = Nibble::from(range_existence_bitmap.trailing_zeros() as u8);

            let child = self
                .child(only_child_index)
                .with_context(|| {
                    format!(
                        "Corrupted internal node: existence_bitmap indicates \
                         the existence of a non-exist child at index {:x}",
                        only_child_index
                    )
                })
                .unwrap();

            let child_node = tree_reader
                .get_node(&node_key.gen_child_node_key(child.version, only_child_index))
                .with_context(|| {
                    format!(
                        "Corruption error: the merkle tree reader supplied cannot find \
                         the child of version {:?} at index {:x}.",
                        child.version, only_child_index
                    )
                })
                .unwrap();

            match child_node {
                Node::Internal(node) => {
                    SparseMerkleNode::Internal(SparseMerkleInternalNode::from::<H>(node))
                }
                Node::Leaf(node) => SparseMerkleNode::Leaf(SparseMerkleLeafNode::from(node)),
                Node::Null => unreachable!("Impossible to get a null node at this location"),
            }
        } else {
            let left_child = self.merkle_hash::<H>(
                start,
                width / 2,
                (range_existence_bitmap, range_leaf_bitmap),
            );
            let right_child = self.merkle_hash::<H>(
                start + width / 2,
                width / 2,
                (range_existence_bitmap, range_leaf_bitmap),
            );
            SparseMerkleNode::Internal(SparseMerkleInternalNode::new(left_child, right_child))
        }
    }

    fn merkle_hash<H: SimpleHasher>(
        &self,
        start: u8,
        width: u8,
        (existence_bitmap, leaf_bitmap): (u16, u16),
    ) -> [u8; 32] {
        // Given a bit [start, 1 << nibble_height], return the value of that range.
        let (range_existence_bitmap, range_leaf_bitmap) =
            Self::range_bitmaps(start, width, (existence_bitmap, leaf_bitmap));
        if range_existence_bitmap == 0 {
            // No child under this subtree
            SPARSE_MERKLE_PLACEHOLDER_HASH
        } else if has_only_child(width, range_existence_bitmap, range_leaf_bitmap) {
            // Only 1 leaf child under this subtree or reach the lowest level
            let only_child_index = Nibble::from(range_existence_bitmap.trailing_zeros() as u8);
            self.child(only_child_index)
                .with_context(|| {
                    format!(
                        "Corrupted internal node: existence_bitmap indicates \
                         the existence of a non-exist child at index {:x}",
                        only_child_index
                    )
                })
                .unwrap()
                .hash
        } else {
            let left_child = self.merkle_hash::<H>(
                start,
                width / 2,
                (range_existence_bitmap, range_leaf_bitmap),
            );
            let right_child = self.merkle_hash::<H>(
                start + width / 2,
                width / 2,
                (range_existence_bitmap, range_leaf_bitmap),
            );
            SparseMerkleInternalNode::new(left_child, right_child).hash::<H>()
        }
    }

    /// Gets the child without its corresponding siblings (like using
    /// [`get_only_child_with_siblings`](InternalNode::get_only_child_with_siblings) and dropping the
    /// siblings, but more efficient).
    pub fn get_only_child_without_siblings(
        &self,
        node_key: &NodeKey,
        n: Nibble,
    ) -> Option<NodeKey> {
        let (existence_bitmap, leaf_bitmap) = self.generate_bitmaps();

        // Nibble height from 3 to 0.
        for h in (0..4).rev() {
            // Get the number of children of the internal node that each subtree at this height
            // covers.
            let width = 1 << h;
            let child_half_start = get_child_half_start(n, h);

            let (range_existence_bitmap, range_leaf_bitmap) =
                Self::range_bitmaps(child_half_start, width, (existence_bitmap, leaf_bitmap));

            if range_existence_bitmap == 0 {
                // No child in this range.
                return None;
            } else if has_only_child(width, range_existence_bitmap, range_leaf_bitmap) {
                // Return the only 1 leaf child under this subtree or reach the lowest level
                // Even this leaf child is not the n-th child, it should be returned instead of
                // `None` because it's existence indirectly proves the n-th child doesn't exist.
                // Please read proof format for details.
                let only_child_index = Nibble::from(range_existence_bitmap.trailing_zeros() as u8);

                let only_child_version = self
                    .child(only_child_index)
                    // Should be guaranteed by the self invariants, but these are not easy to express at the moment
                    .with_context(|| {
                        format!(
                            "Corrupted internal node: child_bitmap indicates \
                                     the existence of a non-exist child at index {:x}",
                            only_child_index
                        )
                    })
                    .unwrap()
                    .version;

                return Some(node_key.gen_child_node_key(only_child_version, only_child_index));
            }
        }
        unreachable!("Impossible to get here without returning even at the lowest level.")
    }

    /// Gets the child and its corresponding siblings that are necessary to generate the proof for
    /// the `n`-th child. This function will **either** return the child that matches the nibble n or the only
    /// child in the largest width range pointed by n. If it is an existence proof, the returned child must be the `n`-th
    /// child; otherwise, the returned child may be another child in the same nibble pointed by n.
    /// See inline explanation for details. When calling this function with n = 11
    ///  (node `b` in the following graph), the range at each level is illustrated as a pair of square brackets:
    ///
    /// ```text
    ///     4      [f   e   d   c   b   a   9   8   7   6   5   4   3   2   1   0] -> root level
    ///            ---------------------------------------------------------------
    ///     3      [f   e   d   c   b   a   9   8] [7   6   5   4   3   2   1   0] width = 8
    ///                                  chs <--┘                        shs <--┘
    ///     2      [f   e   d   c] [b   a   9   8] [7   6   5   4] [3   2   1   0] width = 4
    ///                  shs <--┘               └--> chs
    ///     1      [f   e] [d   c] [b   a] [9   8] [7   6] [5   4] [3   2] [1   0] width = 2
    ///                          chs <--┘       └--> shs
    ///     0      [f] [e] [d] [c] [b] [a] [9] [8] [7] [6] [5] [4] [3] [2] [1] [0] width = 1
    ///     ^                chs <--┘   └--> shs
    ///     |   MSB|<---------------------- uint 16 ---------------------------->|LSB
    ///  height    chs: `child_half_start`         shs: `sibling_half_start`
    /// ```
    fn get_child_with_siblings_helper<H: SimpleHasher>(
        &self,
        tree_reader: &impl TreeReader,
        node_key: &NodeKey,
        n: Nibble,
        get_only_child: bool,
    ) -> (Option<NodeKey>, Vec<SparseMerkleNode>) {
        let mut siblings: Vec<SparseMerkleNode> = vec![];
        let (existence_bitmap, leaf_bitmap) = self.generate_bitmaps();

        let n_bitmap = 1 << n.as_usize();

        // Nibble height from 3 to 0.
        for h in (0..4).rev() {
            // Get the number of children of the internal node that each subtree at this height
            // covers.
            let width = 1 << h;
            let (child_half_start, sibling_half_start) = get_child_and_sibling_half_start(n, h);
            // Compute the root hash of the subtree rooted at the sibling of `r`.
            siblings.push(self.build_sibling::<H>(
                tree_reader,
                node_key,
                sibling_half_start,
                width,
                (existence_bitmap, leaf_bitmap),
            ));

            let (range_existence_bitmap, range_leaf_bitmap) =
                Self::range_bitmaps(child_half_start, width, (existence_bitmap, leaf_bitmap));

            if range_existence_bitmap == 0 {
                // No child in this range.
                return (None, siblings);
            } else if get_only_child
                && (has_only_child(width, range_existence_bitmap, range_leaf_bitmap))
            {
                // Return the only 1 leaf child under this subtree or reach the lowest level
                // Even this leaf child is not the n-th child, it should be returned instead of
                // `None` because it's existence indirectly proves the n-th child doesn't exist.
                // Please read proof format for details.
                let only_child_index = Nibble::from(range_existence_bitmap.trailing_zeros() as u8);
                return (
                    {
                        let only_child_version = self
                            .child(only_child_index)
                            // Should be guaranteed by the self invariants, but these are not easy to express at the moment
                            .with_context(|| {
                                format!(
                                    "Corrupted internal node: child_bitmap indicates \
                                         the existence of a non-exist child at index {:x}",
                                    only_child_index
                                )
                            })
                            .unwrap()
                            .version;
                        Some(node_key.gen_child_node_key(only_child_version, only_child_index))
                    },
                    siblings,
                );
            } else if !get_only_child
                && (has_child(width, range_existence_bitmap, n_bitmap, range_leaf_bitmap))
            {
                // Early return the child in that subtree iff it is the only child and the nibble points
                // to it
                return (
                    {
                        let only_child_version = self
                            .child(n)
                            // Should be guaranteed by the self invariants, but these are not easy to express at the moment
                            .with_context(|| {
                                format!(
                                    "Corrupted internal node: child_bitmap indicates \
                                         the existence of a non-exist child at index {:x}",
                                    n
                                )
                            })
                            .unwrap()
                            .version;
                        Some(node_key.gen_child_node_key(only_child_version, n))
                    },
                    siblings,
                );
            }
        }
        unreachable!("Impossible to get here without returning even at the lowest level.")
    }

    /// [`get_child_with_siblings`] will return the child from this subtree that matches the nibble n in addition
    /// to building the list of its sibblings. This function has the same behavior as [`child`].
    pub(crate) fn get_child_with_siblings<H: SimpleHasher>(
        &self,
        tree_cache: &impl TreeReader,
        node_key: &NodeKey,
        n: Nibble,
    ) -> (Option<NodeKey>, Vec<SparseMerkleNode>) {
        self.get_child_with_siblings_helper::<H>(tree_cache, node_key, n, false)
    }

    /// [`get_only_child_with_siblings`] will **either** return the child that matches the nibble n or the only
    /// child in the largest width range pointed by n (see the helper function [`get_child_with_siblings_helper`] for more information).
    ///
    /// Even this leaf child is not the n-th child, it should be returned instead of
    /// `None` because it's existence indirectly proves the n-th child doesn't exist.
    /// Please read proof format for details.
    pub(crate) fn get_only_child_with_siblings<H: SimpleHasher>(
        &self,
        tree_reader: &impl TreeReader,
        node_key: &NodeKey,
        n: Nibble,
    ) -> (Option<NodeKey>, Vec<SparseMerkleNode>) {
        self.get_child_with_siblings_helper::<H>(tree_reader, node_key, n, true)
    }

    #[cfg(test)]
    pub(crate) fn children(&self) -> &Children {
        &self.children
    }
}

/// Given a nibble, computes the start position of its `child_half_start` and `sibling_half_start`
/// at `height` level.
pub(crate) fn get_child_and_sibling_half_start(n: Nibble, height: u8) -> (u8, u8) {
    // Get the index of the first child belonging to the same subtree whose root, let's say `r` is
    // at `height` that the n-th child belongs to.
    // Note: `child_half_start` will be always equal to `n` at height 0.
    let child_half_start = (0xff << height) & u8::from(n);

    // Get the index of the first child belonging to the subtree whose root is the sibling of `r`
    // at `height`.
    let sibling_half_start = child_half_start ^ (1 << height);

    (child_half_start, sibling_half_start)
}

/// Given a nibble, computes the start position of its `child_half_start` at `height` level.
pub(crate) fn get_child_half_start(n: Nibble, height: u8) -> u8 {
    // Get the index of the first child belonging to the same subtree whose root, let's say `r` is
    // at `height` that the n-th child belongs to.
    // Note: `child_half_start` will be always equal to `n` at height 0.
    (0xff << height) & u8::from(n)
}

/// Represents a key-value pair in the map.
///
/// Note: this does not store the key itself.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct LeafNode {
    /// The hash of the key for this entry.
    key_hash: KeyHash,
    /// The hash of the value for this entry.
    value_hash: ValueHash,
}

impl LeafNode {
    /// Creates a new leaf node.
    pub fn new(key_hash: KeyHash, value_hash: ValueHash) -> Self {
        Self {
            key_hash,
            value_hash,
        }
    }

    /// Gets the key hash.
    pub fn key_hash(&self) -> KeyHash {
        self.key_hash
    }

    /// Gets the associated value hash.
    pub(crate) fn value_hash(&self) -> ValueHash {
        self.value_hash
    }

    pub fn hash<H: SimpleHasher>(&self) -> [u8; 32] {
        SparseMerkleLeafNode::new(self.key_hash, self.value_hash).hash::<H>()
    }
}

impl From<LeafNode> for SparseMerkleLeafNode {
    fn from(leaf_node: LeafNode) -> Self {
        Self::new(leaf_node.key_hash, leaf_node.value_hash)
    }
}

#[repr(u8)]
#[derive(FromPrimitive, ToPrimitive, BorshDeserialize, BorshSerialize)]
#[borsh(use_discriminant = false)]
enum NodeTag {
    Null = 0,
    Leaf = 1,
    Internal = 2,
}

/// The concrete node type of [`JellyfishMerkleTree`](crate::JellyfishMerkleTree).
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum Node {
    /// Represents `null`.
    Null,
    /// A wrapper of [`InternalNode`].
    Internal(InternalNode),
    /// A wrapper of [`LeafNode`].
    Leaf(LeafNode),
}

impl From<InternalNode> for Node {
    fn from(node: InternalNode) -> Self {
        Node::Internal(node)
    }
}

impl From<InternalNode> for Children {
    fn from(node: InternalNode) -> Self {
        node.children
    }
}

impl From<LeafNode> for Node {
    fn from(node: LeafNode) -> Self {
        Node::Leaf(node)
    }
}

impl Node {
    /// Creates the [`Null`](Node::Null) variant.
    pub(crate) fn new_null() -> Self {
        Node::Null
    }

    /// Creates the [`Internal`](Node::Internal) variant.
    #[cfg(any(test))]
    pub(crate) fn new_internal(children: Children) -> Self {
        Node::Internal(InternalNode::new(children))
    }

    /// Creates the [`Leaf`](Node::Leaf) variant.
    pub(crate) fn new_leaf(key_hash: KeyHash, value_hash: ValueHash) -> Self {
        Node::Leaf(LeafNode::new(key_hash, value_hash))
    }

    /// Creates the [`Leaf`](Node::Leaf) variant by hashing a raw value.
    #[cfg(any(test))]
    pub(crate) fn leaf_from_value<H: SimpleHasher>(
        key_hash: KeyHash,
        value: impl AsRef<[u8]>,
    ) -> Self {
        Node::Leaf(LeafNode::new(key_hash, ValueHash::with::<H>(value)))
    }

    /// Returns `true` if the node is a leaf node.
    pub(crate) fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf(_))
    }

    /// Returns `NodeType`
    pub(crate) fn node_type(&self) -> NodeType {
        match self {
            // The returning value will be used to construct a `Child` of a internal node, while an
            // internal node will never have a child of Node::Null.
            Self::Null => unreachable!(),
            Self::Leaf(_) => NodeType::Leaf,
            Self::Internal(n) => n.node_type(),
        }
    }

    /// Returns leaf count if known
    pub(crate) fn leaf_count(&self) -> usize {
        match self {
            Node::Null => 0,
            Node::Leaf(_) => 1,
            Node::Internal(internal_node) => internal_node.leaf_count,
        }
    }

    /// Computes the hash of nodes.
    pub(crate) fn hash<H: SimpleHasher>(&self) -> [u8; 32] {
        match self {
            Node::Null => SPARSE_MERKLE_PLACEHOLDER_HASH,
            Node::Internal(internal_node) => internal_node.hash::<H>(),
            Node::Leaf(leaf_node) => leaf_node.hash::<H>(),
        }
    }
}
