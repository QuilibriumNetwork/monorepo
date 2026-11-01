use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineConfig {
    #[serde(default)]
    pub proving_key_id: String,
    #[serde(default)]
    pub genesis_seed: String,
    #[serde(default = "default_worker_base_listen")]
    pub data_worker_base_listen_multiaddr: String,
    #[serde(
        default = "default_worker_base_p2p_port",
        alias = "dataWorkerBaseP2PPort"
    )]
    pub data_worker_base_p2p_port: u16,
    #[serde(default = "default_worker_base_stream_port")]
    pub data_worker_base_stream_port: u16,
    #[serde(default, alias = "dataWorkerP2PMultiaddrs")]
    pub data_worker_p2p_multiaddrs: Vec<String>,
    #[serde(default)]
    pub data_worker_stream_multiaddrs: Vec<String>,
    #[serde(default, alias = "dataWorkerAnnounceP2PMultiaddrs")]
    pub data_worker_announce_p2p_multiaddrs: Vec<String>,
    #[serde(default)]
    pub data_worker_announce_stream_multiaddrs: Vec<String>,
    #[serde(default)]
    pub data_worker_count: i32,
    #[serde(default)]
    pub data_worker_filters: Vec<String>,
    #[serde(default)]
    pub multisig_prover_enrollment_paths: Vec<String>,
    #[serde(default)]
    pub enable_master_proxy: bool,
    #[serde(default = "default_reward_strategy")]
    pub reward_strategy: String,
    #[serde(default)]
    pub archive_mode: bool,
    #[serde(default)]
    pub delegate_address: String,
    /// Libp2p multiaddrs of archive nodes to seed the archive endpoint
    /// pool with at startup. Accepted shapes: `/ip4/.../tcp/PORT`,
    /// `/ip6/.../tcp/PORT`, `/dns4/host/tcp/PORT`, `/dns6/host/tcp/PORT`,
    /// `/dns/host/tcp/PORT`. The archive mTLS port convention is 8340.
    /// Plain `host:port` is NOT accepted — this matches the Go node
    /// (`node/main.go:736-795`) so configs round-trip between Go and Rust.
    #[serde(default)]
    pub archive_endpoints: Vec<String>,
    #[serde(default)]
    pub blacklist: Vec<String>,
    /// How long (seconds) the archive endpoint pool bans a failing archive
    /// before retrying it. `-1` disables banning entirely (a failed endpoint
    /// is retried on the next poll tick) — devnet sets this so recovery from
    /// a network partition is instantaneous. `0`/absent falls back to the
    /// default below. See `quil_rpc::ArchiveEndpointPool`.
    #[serde(
        default = "default_archive_blacklist_ttl_secs",
        alias = "archiveBlacklistTtl"
    )]
    pub archive_blacklist_ttl_secs: i64,
    #[serde(default = "default_alert_key")]
    pub alert_key: String,
    /// Hex-encoded Falcon-512 public keys of the global consensus committee
    /// (commonware simplex). Each member's committee identity is its
    /// **proving key** (`q-prover-key`) — the prover and consensus roles share
    /// one Falcon-512 key, so these are the same values as the members'
    /// `BLS_PUBKEY`/prover pubkeys. Every member (including this node) is
    /// listed; the committee `Set<FalconPublicKey>` is assembled from these
    /// (order-independent — the Set sorts). Empty until the simplex cutover is
    /// enabled. Populated from `--print-identity`'s `CONSENSUS_PUBKEY` lines at
    /// genesis (see `scripts/localnet.sh`).
    #[serde(default)]
    pub consensus_committee: Vec<String>,
    /// Parallel to [`consensus_committee`]: each member's libp2p peer id
    /// (base58), in the SAME order, so an inbound `:8340` simplex message
    /// resolves from its authenticated mTLS peer id to the sender's committee
    /// Falcon key. Populated from `--print-identity`'s `PEER_ID` lines at
    /// genesis alongside the `CONSENSUS_PUBKEY` lines.
    #[serde(default)]
    pub consensus_committee_peer_ids: Vec<String>,
    /// commonware-simplex leader timeout (seconds): how long a replica waits for
    /// the leader's proposal before nullifying the view. MUST exceed the leader's
    /// in-`propose` VDF prove time under real contention, or every view nullifies
    /// before the proposal lands. Certification timeout is derived as this + 5s.
    /// Default 30; raise for higher difficulty / slower CPUs.
    #[serde(default = "default_consensus_leader_timeout_secs")]
    pub consensus_leader_timeout_secs: u64,
    /// Drive APP-SHARD consensus with commonware-simplex + Falcon (EQUAL
    /// VOTES) instead of the legacy quil-consensus HotStuff loop. Off by default;
    /// the legacy per-shard path is unchanged until this is set. Independent of
    /// [`consensus_committee`] (which gates GLOBAL consensus).
    #[serde(default)]
    pub app_consensus_cw: bool,
}

fn default_consensus_leader_timeout_secs() -> u64 {
    30
}

// Defaults
fn default_worker_base_listen() -> String {
    "/ip4/0.0.0.0/tcp/%d".into()
}
fn default_worker_base_p2p_port() -> u16 {
    25000
}
fn default_worker_base_stream_port() -> u16 {
    32500
}
// Short enough that transient network blips don't permanently drain the
// archive pool, long enough that we don't hammer a struggling endpoint into
// the ground. `-1` disables banning (see `archive_blacklist_ttl_secs`).
fn default_archive_blacklist_ttl_secs() -> i64 {
    60
}
fn default_reward_strategy() -> String {
    "reward-greedy".into()
}
fn default_alert_key() -> String {
    "3ade80f96515e34caaf0c346b842d1f82d2841840f27e12826f4c14326a6bd15d13796c0421f8c440809fceb66c0a5c3c88f93deae16ee3100".into()
}

impl Default for EngineConfig {
    fn default() -> Self {
        serde_yaml::from_str("{}").unwrap()
    }
}

impl EngineConfig {
    pub fn apply_defaults(&mut self) {
        // `0`/absent → default; `-1` (disabled) and positive values preserved.
        if self.archive_blacklist_ttl_secs == 0 {
            self.archive_blacklist_ttl_secs = default_archive_blacklist_ttl_secs();
        }
        if self.reward_strategy.is_empty() {
            self.reward_strategy = default_reward_strategy();
        }
    }
}
