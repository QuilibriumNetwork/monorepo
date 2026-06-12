pub mod behaviour;
pub mod blossomsub;
#[cfg(test)]
pub mod test_harness;
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
pub use node::{P2PHandle, P2PNode, ReceivedMessage};
pub use peer_authenticator::{AllowedPeerPolicy, AuthState, PeerAuthenticator};
pub use peer_info::{
    build_worker_reachability, classify_peer_info_message, decode_canonical_key_registry,
    decode_canonical_peer_info, encode_canonical_peer_info, encode_key_registry,
    peek_key_registry_timestamp, peek_peer_info_timestamp,
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
    // Bumped from 9/6 for WAN testnets: a peer that briefly drops
    // (NAT mapping churn, jitter, packet loss) needs the gossip
    // window long enough to discover missing messages via IHAVE
    // before they age out. The prior 4.2s gossip window (6
    // heartbeats × 700ms) was tight enough that any WAN blip past a
    // few hundred ms left consensus votes unrecoverable.
    pub const HISTORY_LENGTH: usize = 24;
    pub const HISTORY_GOSSIP: usize = 16;
    pub const GOSSIP_FACTOR: f64 = 0.25;
    pub const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(700);
    pub const HEARTBEAT_INITIAL_DELAY: Duration = Duration::from_millis(100);
    pub const FANOUT_TTL: Duration = Duration::from_secs(60);
    // Bumped from 60s. WAN-driven score dips (transient drops,
    // brief disconnects) trigger PRUNE; with a 60s backoff the
    // peer is locked out of the mesh for a full minute and the
    // consensus rounds in that window depend on fanout-only
    // gossip. 15s gives transient drops time to recover without
    // becoming sticky.
    pub const PRUNE_BACKOFF: Duration = Duration::from_secs(15);
    pub const UNSUBSCRIBE_BACKOFF: Duration = Duration::from_secs(10);
    pub const IDONT_WANT_MESSAGE_THRESHOLD: usize = 1024;
    /// How long to wait for an IWANT response before considering
    /// the gossip ad lost and (optionally) re-IWANTing from a
    /// different advertiser. Matches Go gossipsub's default.
    pub const IWANT_FOLLOWUP_TIME: Duration = Duration::from_secs(3);
    /// Per-subnet (IPv4 /24 or IPv6 /48) cap on mesh peers per
    /// bitmask. Eclipse-resistance: a Sybil attacker who controls a
    /// single /24 cannot fill more than this many mesh slots,
    /// limiting how much of the victim's view they can dominate.
    /// `0` disables the check (legacy / test setups). 2 lets normal
    /// clustering (a couple of legitimate co-located peers) through
    /// without bias; 1 is the strictest setting.
    pub const MESH_PEERS_PER_SUBNET: usize = 2;
}

/// Runtime-configurable BlossomSub parameters. Behaviour holds an
/// instance and reads from `self.params.*` instead of from the
/// `params::*` constants directly, so operators can tune for
/// WAN/LAN by setting non-zero values in `P2PConfig` without a
/// rebuild. `Default::default()` produces the WAN-friendly defaults
/// from the `params::*` constants.
#[derive(Debug, Clone)]
pub struct BlossomsubParams {
    pub d: usize,
    pub d_lo: usize,
    pub d_hi: usize,
    pub d_score: usize,
    pub d_out: usize,
    pub d_lazy: usize,
    pub history_length: usize,
    pub history_gossip: usize,
    pub gossip_factor: f64,
    pub heartbeat_interval: std::time::Duration,
    pub heartbeat_initial_delay: std::time::Duration,
    pub fanout_ttl: std::time::Duration,
    pub prune_backoff: std::time::Duration,
    pub unsubscribe_backoff: std::time::Duration,
    pub iwant_followup_time: std::time::Duration,
    pub idont_want_message_threshold: usize,
    /// Per-peer cap on cached IDONTWANT message IDs. Used to bound
    /// the per-peer LRU that tracks which messages a remote peer has
    /// asked us not to send. A malicious peer could otherwise
    /// enumerate IDs and balloon our memory.
    pub max_idont_want_messages: usize,
    /// Cap on mesh peers per IPv4 /24 (or IPv6 /48) per bitmask.
    /// Eclipse-resistance: see [`params::MESH_PEERS_PER_SUBNET`].
    /// `0` disables the check.
    pub mesh_peers_per_subnet: usize,
}

impl Default for BlossomsubParams {
    fn default() -> Self {
        Self {
            d: params::D,
            d_lo: params::D_LO,
            d_hi: params::D_HI,
            d_score: params::D_SCORE,
            d_out: params::D_OUT,
            d_lazy: params::D_LAZY,
            history_length: params::HISTORY_LENGTH,
            history_gossip: params::HISTORY_GOSSIP,
            gossip_factor: params::GOSSIP_FACTOR,
            heartbeat_interval: params::HEARTBEAT_INTERVAL,
            heartbeat_initial_delay: params::HEARTBEAT_INITIAL_DELAY,
            fanout_ttl: params::FANOUT_TTL,
            prune_backoff: params::PRUNE_BACKOFF,
            unsubscribe_backoff: params::UNSUBSCRIBE_BACKOFF,
            iwant_followup_time: params::IWANT_FOLLOWUP_TIME,
            idont_want_message_threshold: params::IDONT_WANT_MESSAGE_THRESHOLD,
            max_idont_want_messages: 5000,
            mesh_peers_per_subnet: params::MESH_PEERS_PER_SUBNET,
        }
    }
}

impl BlossomsubParams {
    /// Build a `BlossomsubParams` from operator-supplied
    /// `P2PConfig` values, falling back to defaults for any zero /
    /// unset fields. Treats `0` as "use default" because
    /// `serde(default)` produces zero-valued ints and durations
    /// from missing YAML keys, which we don't want to silently
    /// override sensible defaults with.
    pub fn from_p2p_config(cfg: &quil_config::P2PConfig) -> Self {
        let d = Self::default();
        let pos = |v: i32, fallback: usize| if v > 0 { v as usize } else { fallback };
        let dur_ms = |ms: u64, fallback: std::time::Duration| {
            if ms > 0 {
                std::time::Duration::from_millis(ms)
            } else {
                fallback
            }
        };
        Self {
            d: pos(cfg.d, d.d),
            d_lo: pos(cfg.d_lo, d.d_lo),
            d_hi: pos(cfg.d_hi, d.d_hi),
            d_score: pos(cfg.d_score, d.d_score),
            d_out: pos(cfg.d_out, d.d_out),
            d_lazy: pos(cfg.d_lazy, d.d_lazy),
            history_length: pos(cfg.history_length, d.history_length),
            history_gossip: pos(cfg.history_gossip, d.history_gossip),
            gossip_factor: if cfg.gossip_factor > 0.0 {
                cfg.gossip_factor
            } else {
                d.gossip_factor
            },
            heartbeat_interval: dur_ms(cfg.heartbeat_interval_ms, d.heartbeat_interval),
            heartbeat_initial_delay: dur_ms(
                cfg.heartbeat_initial_delay_ms,
                d.heartbeat_initial_delay,
            ),
            fanout_ttl: dur_ms(cfg.fanout_ttl_ms, d.fanout_ttl),
            prune_backoff: dur_ms(cfg.prune_backoff_ms, d.prune_backoff),
            unsubscribe_backoff: dur_ms(cfg.unsubscribe_backoff_ms, d.unsubscribe_backoff),
            iwant_followup_time: dur_ms(cfg.iwant_followup_time_ms, d.iwant_followup_time),
            idont_want_message_threshold: if cfg.idont_want_message_threshold > 0 {
                cfg.idont_want_message_threshold as usize
            } else {
                d.idont_want_message_threshold
            },
            max_idont_want_messages: if cfg.max_idont_want_messages > 0 {
                cfg.max_idont_want_messages as usize
            } else {
                d.max_idont_want_messages
            },
            // No P2PConfig field yet — operators tune via `set_params`
            // post-build if they need to. Default protects against
            // single-/24 eclipse on every node.
            mesh_peers_per_subnet: d.mesh_peers_per_subnet,
        }
    }
}
