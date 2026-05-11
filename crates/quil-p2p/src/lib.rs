pub mod behaviour;
pub mod blossomsub;
pub mod bitmask;
pub mod ed448_identity;
pub mod ed448_noise;
pub mod ed448_noise_transport;
pub mod ed448_peer;
pub mod handler;
pub mod node;
pub mod onion;
pub mod peer_authenticator;
pub mod peer_info;
pub mod protocol;
mod scoring;
pub mod signer_registry;
pub mod tls_debug;

pub use behaviour::ValidationResult;
pub use bitmask::slice_bitmask;
pub use libp2p::PeerId;
pub use ed448_identity::Ed448Identity;
pub use peer_authenticator::{AllowedPeerPolicy, AuthState, PeerAuthenticator};
pub use peer_info::{
    build_worker_reachability, classify_peer_info_message, decode_canonical_key_registry,
    decode_canonical_peer_info, encode_canonical_peer_info, encode_key_registry,
    CanonicalCapability, CanonicalKeyRegistry, CanonicalPeerInfo, CanonicalReachability,
    InMemoryPeerInfoManager, PeerInfoMessage, ARCHIVE_SERVICE_CAPABILITY_ID, KEY_REGISTRY_TYPE,
    PEER_INFO_TYPE,
};
pub use signer_registry::{SignerEntry, SignerRegistry};

/// BlossomSub protocol identifiers.
pub const BLOSSOMSUB_PROTOCOL_V2_0: &str = "/blossomsub/2.0.0";
pub const BLOSSOMSUB_PROTOCOL_V2_1: &str = "/blossomsub/2.1.0";

/// Default BlossomSub parameters (matching Go implementation).
pub mod params {
    use std::time::Duration;

    pub const D: usize = 8;
    pub const D_LO: usize = 6;
    pub const D_HI: usize = 12;
    pub const D_SCORE: usize = 4;
    pub const D_OUT: usize = 2;
    pub const D_SAME: usize = 3;
    pub const D_SAME_LO: usize = 2;
    pub const D_LAZY: usize = 6;
    pub const HISTORY_LENGTH: usize = 9;
    pub const HISTORY_GOSSIP: usize = 6;
    pub const GOSSIP_FACTOR: f64 = 0.25;
    pub const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(700);
    pub const HEARTBEAT_INITIAL_DELAY: Duration = Duration::from_millis(100);
    pub const FANOUT_TTL: Duration = Duration::from_secs(60);
    pub const PRUNE_BACKOFF: Duration = Duration::from_secs(60);
    pub const UNSUBSCRIBE_BACKOFF: Duration = Duration::from_secs(10);
    pub const IDONT_WANT_MESSAGE_THRESHOLD: usize = 1024;
}
