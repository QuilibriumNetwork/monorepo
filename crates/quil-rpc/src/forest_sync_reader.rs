//! `RemoteTreeReader` — a [`jmt::storage::TreeReader`] backed by a peer's
//! `GetForestNode`/`GetForestValue` gRPC, so [`quil_forest::diff_leaves`] can
//! walk a remote shard/phase tree and pull only the nodes whose hash differs
//! from the local one.
//!
//! # Sync-over-async
//!
//! jmt's `TreeReader` is synchronous; the gRPC client is async. Each read
//! blocks the calling thread on the gRPC via a [`tokio::runtime::Handle`], so
//! `RemoteTreeReader` MUST be used from a blocking context (run the diff inside
//! `tokio::task::spawn_blocking`) — never on a runtime worker thread, where
//! `block_on` would panic.

use anyhow::Result;
use jmt::storage::{LeafNode, Node, NodeKey, TreeReader};
use jmt::{KeyHash, OwnedValue, Version};

use crate::archive_client::ArchiveClient;

/// A remote view of ONE shard/phase tree on a peer archive, addressed by
/// `(shard_id, phase)`. Clone-cheap (the client shares one h2 channel).
pub struct RemoteTreeReader {
    client: ArchiveClient,
    handle: tokio::runtime::Handle,
    shard_id: Vec<u8>,
    phase: u32,
}

impl RemoteTreeReader {
    /// `handle` is the runtime to drive gRPC on; the reader must be *called*
    /// from a blocking thread (`spawn_blocking`), not a worker of `handle`.
    pub fn new(
        client: ArchiveClient,
        handle: tokio::runtime::Handle,
        shard_id: Vec<u8>,
        phase: u32,
    ) -> Self {
        Self { client, handle, shard_id, phase }
    }
}

impl TreeReader for RemoteTreeReader {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key_bytes = borsh::to_vec(node_key)?;
        let mut client = self.client.clone();
        let shard_id = self.shard_id.clone();
        let phase = self.phase;
        let bytes = self
            .handle
            .block_on(async move { client.get_forest_node(shard_id, phase, key_bytes).await })
            .map_err(|e| anyhow::anyhow!("remote get_forest_node: {e}"))?;
        match bytes {
            Some(b) => Ok(Some(borsh::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let mut client = self.client.clone();
        let shard_id = self.shard_id.clone();
        let phase = self.phase;
        let kh = key_hash.0.to_vec();
        self.handle
            .block_on(async move { client.get_forest_value(shard_id, phase, max_version, kh).await })
            .map_err(|e| anyhow::anyhow!("remote get_forest_value: {e}"))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        // Used only by jmt's restore path, which the Merkle-diff sync never
        // exercises — the diff walk addresses nodes explicitly.
        Ok(None)
    }
}
