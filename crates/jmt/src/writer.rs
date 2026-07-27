use alloc::collections::{BTreeMap, BTreeSet};

use alloc::vec::Vec;
use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(any(test))]
use proptest_derive::Arbitrary;

use crate::{
    node_type::{Node, NodeKey},
    types::Version,
    KeyHash, OwnedValue,
};

/// Defines the interface used to write a batch of updates from a
/// [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
/// to the underlying storage holding nodes.
pub trait TreeWriter {
    /// Writes a node batch into storage.
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()>;
}

/// Node batch that will be written into db atomically with other batches.
#[derive(Debug, Clone, PartialEq, Default, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct NodeBatch {
    nodes: BTreeMap<NodeKey, Node>,
    values: BTreeMap<(Version, KeyHash), Option<OwnedValue>>,
}

impl NodeBatch {
    /// Creates a new node batch
    pub fn new(
        nodes: BTreeMap<NodeKey, Node>,
        values: BTreeMap<(Version, KeyHash), Option<OwnedValue>>,
    ) -> Self {
        NodeBatch { nodes, values }
    }

    /// Reset a NodeBatch to its empty state.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.values.clear()
    }

    /// Get a node by key.
    pub fn get_node(&self, node_key: &NodeKey) -> Option<&Node> {
        self.nodes.get(node_key)
    }

    /// Returns a reference to the current set of nodes.
    pub fn nodes(&self) -> &BTreeMap<NodeKey, Node> {
        &self.nodes
    }

    /// Insert a node into the batch.
    pub fn insert_node(&mut self, node_key: NodeKey, node: Node) -> Option<Node> {
        self.nodes.insert(node_key, node)
    }

    /// Insert a node into the batch.
    pub fn insert_value(&mut self, version: Version, key_hash: KeyHash, value: OwnedValue) {
        self.values.insert((version, key_hash), Some(value));
    }

    /// Returns a reference to the current set of nodes.
    pub fn values(&self) -> &BTreeMap<(Version, KeyHash), core::option::Option<Vec<u8>>> {
        &self.values
    }

    /// Extend a node batch.
    pub fn extend(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeKey, Node)>,
        values: impl IntoIterator<Item = ((Version, KeyHash), Option<OwnedValue>)>,
    ) {
        self.nodes.extend(nodes);
        self.values.extend(values);
    }

    /// Merge two NodeBatches into a single one.
    pub fn merge(&mut self, rhs: Self) {
        self.extend(rhs.nodes, rhs.values)
    }

    /// Check if the node batch contains any items.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.values.is_empty()
    }
}
/// [`StaleNodeIndex`](struct.StaleNodeIndex.html) batch that will be written into db atomically
/// with other batches.
pub type StaleNodeIndexBatch = BTreeSet<StaleNodeIndex>;

#[derive(Clone, Debug, Default, Eq, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct NodeStats {
    pub new_nodes: usize,
    pub new_leaves: usize,
    pub stale_nodes: usize,
    pub stale_leaves: usize,
}

/// Indicates a node becomes stale since `stale_since_version`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, BorshDeserialize, BorshSerialize)]
#[cfg_attr(any(test), derive(Arbitrary))]
pub struct StaleNodeIndex {
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The [`NodeKey`](node_type/struct.NodeKey.html) identifying the node associated with this
    /// record.
    pub node_key: NodeKey,
}

/// This is a wrapper of [`NodeBatch`](type.NodeBatch.html),
/// [`StaleNodeIndexBatch`](type.StaleNodeIndexBatch.html) and some stats of nodes that represents
/// the incremental updates of a tree and pruning indices after applying a write set,
/// which is a vector of `hashed_account_address` and `new_value` pairs.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct TreeUpdateBatch {
    pub node_batch: NodeBatch,
    pub stale_node_index_batch: StaleNodeIndexBatch,
    pub node_stats: Vec<NodeStats>,
}
