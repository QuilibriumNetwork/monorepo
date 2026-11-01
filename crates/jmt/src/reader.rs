use alloc::vec::Vec;
use anyhow::{format_err, Result};

use crate::node_type::{LeafNode, Node, NodeKey};
use crate::{KeyHash, OwnedValue, Version};

/// Defines the interface between a
/// [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
/// and underlying storage holding nodes.
pub trait TreeReader {
    /// Gets node given a node key. Returns error if the node does not exist.
    fn get_node(&self, node_key: &NodeKey) -> Result<Node> {
        self.get_node_option(node_key)?
            .ok_or_else(|| format_err!("Missing node at {:?}.", node_key))
    }

    /// Gets node given a node key. Returns `None` if the node does not exist.
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>>;

    /// Gets a value by identifier, returning the newest value whose version is *less than or
    /// equal to* the specified version. Returns an error if the value does not exist.
    fn get_value(&self, max_version: Version, key_hash: KeyHash) -> Result<OwnedValue> {
        self.get_value_option(max_version, key_hash)?
            .ok_or_else(|| {
                format_err!(
                    "Missing value with max_version {max_version:} and key hash {key_hash:?}."
                )
            })
    }

    /// Gets a value by identifier, returning the newest value whose version is *less than or
    /// equal to* the specified version.  Returns None if the value does not exist.
    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>>;

    /// Gets the rightmost leaf. Note that this assumes we are in the process of restoring the tree
    /// and all nodes are at the same version.
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>>;
}

/// Defines the ability for a tree to look up the preimage of its key hashes.
pub trait HasPreimage {
    /// Gets the preimage of a key hash, if it is present in the tree.
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>>;
}
