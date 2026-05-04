use crate::error::Result;

/// Validation result for incoming pubsub messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    Accept,
    Reject,
    Ignore,
}

/// A received pubsub message.
#[derive(Debug, Clone)]
pub struct PubSubMessage {
    pub from: Vec<u8>,
    pub data: Vec<u8>,
    pub bitmask: Vec<u8>,
    pub seqno: Vec<u8>,
    pub signature: Vec<u8>,
    pub key: Vec<u8>,
}

/// Message handler callback type.
pub type MessageHandler = Box<dyn Fn(&PubSubMessage) -> ValidationResult + Send + Sync>;

/// Publish-subscribe networking interface (BlossomSub in Go, needs port to Rust).
#[async_trait::async_trait]
pub trait PubSub: Send + Sync {
    /// Publish data to a bitmask topic.
    async fn publish_to_bitmask(&self, bitmask: &[u8], data: &[u8]) -> Result<()>;

    /// Subscribe to a bitmask topic with a message handler.
    async fn subscribe(
        &self,
        bitmask: &[u8],
        handler: MessageHandler,
    ) -> Result<()>;

    /// Subscribe with a sync validator.
    async fn subscribe_with_sync_validator(
        &self,
        bitmask: &[u8],
        handler: MessageHandler,
    ) -> Result<()>;

    /// Unsubscribe from a bitmask topic.
    fn unsubscribe(&self, bitmask: &[u8], raw: bool);

    /// Get the local peer ID.
    fn get_peer_id(&self) -> Vec<u8>;

    /// Get the count of peers in the peerstore.
    fn get_peerstore_count(&self) -> usize;

    /// Get the count of connected network peers.
    fn get_network_peers_count(&self) -> usize;

    /// Get a random peer subscribed to the given bitmask.
    fn get_random_peer(&self, bitmask: &[u8]) -> Result<Vec<u8>>;

    /// Get the multiaddr of a specific peer.
    fn get_multiaddr_of_peer(&self, peer_id: &[u8]) -> Result<String>;

    /// Get own listen multiaddrs.
    fn get_own_multiaddrs(&self) -> Vec<String>;

    /// Get peer score.
    fn get_peer_score(&self, peer_id: &[u8]) -> i64;

    /// Set peer score.
    fn set_peer_score(&self, peer_id: &[u8], score: i64);

    /// Add to peer score.
    fn add_peer_score(&self, peer_id: &[u8], delta: i64);

    /// Reconnect to a peer.
    async fn reconnect(&self, peer_id: &[u8]) -> Result<()>;

    /// Bootstrap peer connections.
    async fn bootstrap(&self) -> Result<()>;

    /// Discover new peers.
    async fn discover_peers(&self) -> Result<()>;

    /// Check if a peer is connected.
    fn is_peer_connected(&self, peer_id: &[u8]) -> bool;

    /// Get the network identifier.
    fn get_network(&self) -> u32;

    /// Check if the node is publicly reachable.
    fn is_reachable(&self) -> Option<bool>;

    /// Sign a message with the node's identity key.
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Get the node's public key.
    fn get_public_key(&self) -> Vec<u8>;
}

/// Peer information manager.
pub trait PeerInfoManager: Send + Sync {
    /// Get known peer info for broadcasting.
    fn get_peer_info(&self) -> Vec<crate::proto::node::PeerInfo>;

    /// Process received peer info.
    fn handle_peer_info(&self, info: &crate::proto::node::PeerInfo) -> Result<()>;

    /// Default implementation scans the broadcast snapshot; override
    /// for O(1) when a per-peer index is available.
    fn get_peer_info_for(&self, peer_id: &[u8]) -> Option<crate::proto::node::PeerInfo> {
        self.get_peer_info()
            .into_iter()
            .find(|p| p.peer_id == peer_id)
    }
}
