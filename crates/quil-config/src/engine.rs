use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineConfig {
    #[serde(default)]
    pub proving_key_id: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default)]
    pub genesis_seed: String,
    #[serde(default)]
    pub pending_commit_workers: i64,
    #[serde(default = "default_min_peers")]
    pub minimum_peers_required: i32,
    #[serde(default)]
    pub stats_multiaddr: String,
    #[serde(default = "default_worker_base_listen")]
    pub data_worker_base_listen_multiaddr: String,
    #[serde(default = "default_worker_base_p2p_port", alias = "dataWorkerBaseP2PPort")]
    pub data_worker_base_p2p_port: u16,
    #[serde(default = "default_worker_base_stream_port")]
    pub data_worker_base_stream_port: u16,
    #[serde(default = "default_worker_memory_limit")]
    pub data_worker_memory_limit: i64,
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
    #[serde(default = "default_sync_timeout_ms", alias = "syncTimeout", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub sync_timeout_ms: u64,
    #[serde(default = "default_sync_candidates")]
    pub sync_candidates: i32,
    #[serde(default)]
    pub sync_message_limits: GrpcMessageLimitsConfig,
    #[serde(default)]
    pub enable_master_proxy: bool,
    #[serde(default = "default_reward_strategy")]
    pub reward_strategy: String,
    #[serde(default)]
    pub archive_mode: bool,
    #[serde(default)]
    pub delegate_address: String,
    #[serde(default)]
    pub rewards_address: String,
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
    #[serde(default = "default_alert_key")]
    pub alert_key: String,
    #[serde(default)]
    pub frame_publish: FramePublishConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrpcMessageLimitsConfig {
    #[serde(default = "default_sync_msg_limit")]
    pub max_recv_msg_size: i32,
    #[serde(default = "default_sync_msg_limit")]
    pub max_send_msg_size: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FramePublishConfig {
    #[serde(default = "default_publish_mode")]
    pub mode: String,
    #[serde(default = "default_publish_threshold")]
    pub threshold: i32,
    #[serde(default)]
    pub fragmentation: FramePublishFragmentationConfig,
    #[serde(default)]
    pub ballast_size: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FramePublishFragmentationConfig {
    #[serde(default = "default_frag_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub reed_solomon: ReedSolomonConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReedSolomonConfig {
    #[serde(default = "default_data_shards")]
    pub data_shards: i32,
    #[serde(default = "default_parity_shards")]
    pub parity_shards: i32,
}

// Defaults
fn default_min_peers() -> i32 { 3 }
fn default_worker_base_listen() -> String { "/ip4/0.0.0.0/tcp/%d".into() }
fn default_worker_base_p2p_port() -> u16 { 25000 }
fn default_worker_base_stream_port() -> u16 { 32500 }
fn default_worker_memory_limit() -> i64 { 1792 * 1024 * 1024 }
fn default_sync_timeout_ms() -> u64 { 4000 }
fn default_sync_candidates() -> i32 { 8 }
// 64 MiB — matches the de-facto cap hardcoded in
// `quil-rpc/src/hypergraph_sync_probe.rs`. Was 600 MiB before, which
// is far larger than any legitimate sync message and would have been
// a DoS amplifier (a malicious peer could send a single ~half-gig
// payload and force us to allocate before failing). The `sync_message_limits`
// field isn't wired into any tonic client yet, but anyone who wires
// it up later will inherit this sane default.
fn default_sync_msg_limit() -> i32 { 64 * 1024 * 1024 }
fn default_reward_strategy() -> String { "reward-greedy".into() }
fn default_alert_key() -> String {
    "3ade80f96515e34caaf0c346b842d1f82d2841840f27e12826f4c14326a6bd15d13796c0421f8c440809fceb66c0a5c3c88f93deae16ee3100".into()
}
fn default_publish_mode() -> String { "full".into() }
fn default_publish_threshold() -> i32 { 1024 * 1024 }
fn default_frag_algorithm() -> String { "reed-solomon".into() }
fn default_data_shards() -> i32 { 224 }
fn default_parity_shards() -> i32 { 32 }

impl Default for EngineConfig {
    fn default() -> Self {
        serde_yaml::from_str("{}").unwrap()
    }
}

impl Default for GrpcMessageLimitsConfig {
    fn default() -> Self {
        Self {
            max_recv_msg_size: default_sync_msg_limit(),
            max_send_msg_size: default_sync_msg_limit(),
        }
    }
}

impl Default for FramePublishConfig {
    fn default() -> Self {
        serde_yaml::from_str("{}").unwrap()
    }
}

impl Default for FramePublishFragmentationConfig {
    fn default() -> Self {
        serde_yaml::from_str("{}").unwrap()
    }
}

impl Default for ReedSolomonConfig {
    fn default() -> Self {
        Self {
            data_shards: default_data_shards(),
            parity_shards: default_parity_shards(),
        }
    }
}

impl EngineConfig {
    pub fn apply_defaults(&mut self) {
        if self.minimum_peers_required == 0 {
            self.minimum_peers_required = default_min_peers();
        }
        if self.sync_timeout_ms == 0 {
            self.sync_timeout_ms = default_sync_timeout_ms();
        }
        if self.sync_candidates == 0 {
            self.sync_candidates = default_sync_candidates();
        }
        if self.reward_strategy.is_empty() {
            self.reward_strategy = default_reward_strategy();
        }
        if self.frame_publish.mode.is_empty() {
            self.frame_publish.mode = default_publish_mode();
        }
    }
}
