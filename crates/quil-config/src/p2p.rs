use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct P2PConfig {
    #[serde(default)]
    pub d: i32,
    #[serde(default)]
    pub d_lo: i32,
    #[serde(default)]
    pub d_hi: i32,
    #[serde(default)]
    pub d_score: i32,
    #[serde(default)]
    pub d_out: i32,
    #[serde(default)]
    pub history_length: i32,
    #[serde(default)]
    pub history_gossip: i32,
    #[serde(default)]
    pub d_lazy: i32,
    #[serde(default)]
    pub gossip_factor: f64,
    #[serde(default)]
    pub gossip_retransmission: i32,
    #[serde(default, alias = "heartbeatInitialDelay", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub heartbeat_initial_delay_ms: u64,
    #[serde(default, alias = "heartbeatInterval", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub heartbeat_interval_ms: u64,
    #[serde(default, alias = "fanoutTTL", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub fanout_ttl_ms: u64,
    #[serde(default)]
    pub prune_peers: i32,
    #[serde(default, alias = "pruneBackoff", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub prune_backoff_ms: u64,
    #[serde(default, alias = "unsubscribeBackoff", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub unsubscribe_backoff_ms: u64,
    #[serde(default)]
    pub connectors: i32,
    #[serde(default)]
    pub max_pending_connections: i32,
    #[serde(default, alias = "connectionTimeout", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub connection_timeout_ms: u64,
    #[serde(default)]
    pub direct_connect_ticks: u64,
    #[serde(default, alias = "directConnectInitialDelay", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub direct_connect_initial_delay_ms: u64,
    #[serde(default)]
    pub opportunistic_graft_ticks: u64,
    #[serde(default)]
    pub opportunistic_graft_peers: i32,
    #[serde(default, alias = "graftFloodThreshold", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub graft_flood_threshold_ms: u64,
    #[serde(default)]
    pub max_ihave_length: i32,
    #[serde(default)]
    pub max_ihave_messages: i32,
    #[serde(default, alias = "maxIDontWantMessages")]
    pub max_idont_want_messages: i32,
    #[serde(default, alias = "iWantFollowupTime", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub iwant_followup_time_ms: u64,
    #[serde(default, alias = "iDontWantMessageThreshold")]
    pub idont_want_message_threshold: i32,
    #[serde(default, alias = "iDontWantMessageTTL")]
    pub idont_want_message_ttl: i32,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    #[serde(default)]
    pub listen_multiaddr: String,
    #[serde(default = "default_stream_listen")]
    pub stream_listen_multiaddr: String,
    #[serde(default)]
    pub announce_listen_multiaddr: String,
    #[serde(default)]
    pub announce_stream_listen_multiaddr: String,
    #[serde(default)]
    pub peer_priv_key: String,
    #[serde(default)]
    pub trace_log_file: String,
    #[serde(default)]
    pub trace_log_stdout: bool,
    #[serde(default)]
    pub network: u8,
    #[serde(default = "default_low_watermark")]
    pub low_watermark_connections: i32,
    #[serde(default = "default_high_watermark")]
    pub high_watermark_connections: i32,
    #[serde(default)]
    pub direct_peers: Vec<String>,
    #[serde(default = "default_grpc_rate_limit")]
    pub grpc_server_rate_limit: i32,
    #[serde(default = "default_min_bootstrap")]
    pub min_bootstrap_peers: i32,
    #[serde(default = "default_bootstrap_parallelism")]
    pub bootstrap_parallelism: i32,
    #[serde(default = "default_discovery_parallelism")]
    pub discovery_parallelism: i32,
    #[serde(default = "default_discovery_peer_limit")]
    pub discovery_peer_lookup_limit: i32,
    #[serde(default = "default_ping_timeout_ms", alias = "pingTimeout", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub ping_timeout_ms: u64,
    #[serde(default = "default_ping_period_ms", alias = "pingPeriod", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub ping_period_ms: u64,
    #[serde(default = "default_ping_attempts")]
    pub ping_attempts: i32,
    #[serde(default)]
    pub validate_queue_size: i32,
    #[serde(default)]
    pub validate_workers: i32,
    #[serde(default)]
    pub subscription_queue_size: i32,
    #[serde(default)]
    pub peer_outbound_queue_size: i32,
    #[serde(default = "default_reconnect_interval_ms", alias = "peerReconnectCheckInterval", deserialize_with = "crate::deserialize_go_duration_ms")]
    pub peer_reconnect_check_interval_ms: u64,
}

fn default_stream_listen() -> String { "/ip4/0.0.0.0/tcp/8340".into() }
fn default_low_watermark() -> i32 { 160 }
fn default_high_watermark() -> i32 { 192 }
fn default_grpc_rate_limit() -> i32 { 10 }
fn default_min_bootstrap() -> i32 { 3 }
fn default_bootstrap_parallelism() -> i32 { 10 }
fn default_discovery_parallelism() -> i32 { 50 }
fn default_discovery_peer_limit() -> i32 { 1000 }
fn default_ping_timeout_ms() -> u64 { 5000 }
fn default_ping_period_ms() -> u64 { 30000 }
fn default_ping_attempts() -> i32 { 3 }
fn default_reconnect_interval_ms() -> u64 { 60000 }

impl Default for P2PConfig {
    fn default() -> Self {
        serde_yaml::from_str("{}").unwrap()
    }
}

/// Current mainnet bootstrap peers (mirrors config/config.go BootstrapPeers).
pub const MAINNET_BOOTSTRAP_PEERS: &[&str] = &[
    "/dns4/quinoa.quilibrium.com/udp/8336/quic-v1/p2p/QmP9NNzAzRjCL8gdQBkKHwyBCWJGVb3jPrQzTveYdU24kH",
    "/dns4/qualia.quilibrium.com/udp/8336/quic-v1/p2p/QmRP1UPiDg1enHgN6wEL1Y4uUh1XKg7V3QExdBKV9BUUQf",
    "/dns4/quetzalcoatl.quilibrium.com/udp/8336/quic-v1/p2p/QmNq4xSqrxTKKtK7J6UFEa4unjsoULP2G4qWwwH5EKmoJj",
    "/ip4/65.109.17.13/udp/8336/quic-v1/p2p/Qmc35n99eojSvW3PkbfBczJoSX92WmnnKh3Fg114ok3oo4",
    "/ip4/65.108.194.84/udp/8336/quic-v1/p2p/QmP8C7g9ZRiWzhqN2AgFu5onS6HwHzR6Vv1TCHxAhnCSnq",
    "/ip4/15.204.100.222/udp/8336/quic-v1/p2p/Qmef3Z3RvGg49ZpDPcf2shWtJNgPJNpXrowjUcfz23YQ3V",
];

impl P2PConfig {
    /// Apply defaults for all P2P and BlossomSub parameters.
    pub fn apply_defaults(&mut self) {
        // BlossomSub mesh parameters
        if self.d == 0 { self.d = 8; }
        if self.d_lo == 0 { self.d_lo = 6; }
        if self.d_hi == 0 { self.d_hi = 12; }
        if self.d_score == 0 { self.d_score = 4; }
        if self.d_out == 0 { self.d_out = 2; }

        // Gossip/history
        if self.history_length == 0 { self.history_length = 9; }
        if self.history_gossip == 0 { self.history_gossip = 6; }
        if self.d_lazy == 0 { self.d_lazy = 6; }
        if self.gossip_factor == 0.0 { self.gossip_factor = 0.25; }
        if self.gossip_retransmission == 0 { self.gossip_retransmission = 3; }

        // Heartbeat (Go: 100ms initial, 700ms interval)
        if self.heartbeat_initial_delay_ms == 0 { self.heartbeat_initial_delay_ms = 100; }
        if self.heartbeat_interval_ms == 0 { self.heartbeat_interval_ms = 700; }

        // Fanout TTL (Go: 60s)
        if self.fanout_ttl_ms == 0 { self.fanout_ttl_ms = 60_000; }

        // Prune/backoff (Go: 16 peers, 60s backoff, 10s unsub backoff)
        if self.prune_peers == 0 { self.prune_peers = 16; }
        if self.prune_backoff_ms == 0 { self.prune_backoff_ms = 60_000; }
        if self.unsubscribe_backoff_ms == 0 { self.unsubscribe_backoff_ms = 10_000; }

        // Connection (Go: 8 connectors, 128 max pending, 30s timeout)
        if self.connectors == 0 { self.connectors = 8; }
        if self.max_pending_connections == 0 { self.max_pending_connections = 128; }
        if self.connection_timeout_ms == 0 { self.connection_timeout_ms = 30_000; }

        // Direct connect (Go: 300 ticks, 1s initial delay)
        if self.direct_connect_ticks == 0 { self.direct_connect_ticks = 300; }
        if self.direct_connect_initial_delay_ms == 0 { self.direct_connect_initial_delay_ms = 1_000; }

        // Opportunistic graft (Go: 60 ticks, 2 peers)
        if self.opportunistic_graft_ticks == 0 { self.opportunistic_graft_ticks = 60; }
        if self.opportunistic_graft_peers == 0 { self.opportunistic_graft_peers = 2; }

        // Graft flood threshold (Go: 10s)
        if self.graft_flood_threshold_ms == 0 { self.graft_flood_threshold_ms = 10_000; }

        // IHAVE/IWANT (Go: 5000 max length, 10 max messages, 3s followup)
        if self.max_ihave_length == 0 { self.max_ihave_length = 5000; }
        if self.max_ihave_messages == 0 { self.max_ihave_messages = 10; }
        if self.iwant_followup_time_ms == 0 { self.iwant_followup_time_ms = 3_000; }

        // IDONTWANT (Go: 5000 max messages, 1024 byte threshold, 60 TTL in ticks)
        if self.max_idont_want_messages == 0 { self.max_idont_want_messages = 5000; }
        if self.idont_want_message_threshold == 0 { self.idont_want_message_threshold = 1024; }
        if self.idont_want_message_ttl == 0 { self.idont_want_message_ttl = 60; }

        // Queue sizes (Go: 16384 validate, runtime.NumCPU workers, 16384 subscription, 128 outbound)
        if self.validate_queue_size == 0 { self.validate_queue_size = 16384; }
        if self.validate_workers == 0 {
            self.validate_workers = std::thread::available_parallelism()
                .map(|n| n.get() as i32)
                .unwrap_or(4);
        }
        if self.subscription_queue_size == 0 { self.subscription_queue_size = 16384; }
        if self.peer_outbound_queue_size == 0 { self.peer_outbound_queue_size = 128; }

        // Connection watermarks (Go: 160 low, 192 high)
        if self.low_watermark_connections == 0 {
            self.low_watermark_connections = default_low_watermark();
        }
        if self.high_watermark_connections == 0 {
            self.high_watermark_connections = default_high_watermark();
        }

        // gRPC rate limit (Go: 10)
        if self.grpc_server_rate_limit == 0 {
            self.grpc_server_rate_limit = default_grpc_rate_limit();
        }

        // Bootstrap/discovery (Go: 3 min peers, 10 parallelism, 50 discovery, 1000 lookup)
        if self.min_bootstrap_peers == 0 {
            self.min_bootstrap_peers = default_min_bootstrap();
        }
        if self.bootstrap_parallelism == 0 { self.bootstrap_parallelism = 10; }
        if self.discovery_parallelism == 0 { self.discovery_parallelism = 50; }
        if self.discovery_peer_lookup_limit == 0 { self.discovery_peer_lookup_limit = 1000; }

        // Ping (Go: 5s timeout, 30s period, 3 attempts)
        if self.ping_timeout_ms == 0 { self.ping_timeout_ms = 5_000; }
        if self.ping_period_ms == 0 { self.ping_period_ms = 30_000; }
        if self.ping_attempts == 0 { self.ping_attempts = 3; }

        // Peer reconnect (Go: 60s)
        if self.peer_reconnect_check_interval_ms == 0 { self.peer_reconnect_check_interval_ms = 60_000; }

        // Stream listen (Go: /ip4/0.0.0.0/tcp/8340)
        if self.stream_listen_multiaddr.is_empty() {
            self.stream_listen_multiaddr = default_stream_listen();
        }

        // Migrate stale bootstrap peers to current list
        let stale = self.bootstrap_peers.is_empty()
            || self.bootstrap_peers.iter().any(|p| p.contains("bootstrap.quilibrium.com"));
        if stale {
            self.bootstrap_peers = MAINNET_BOOTSTRAP_PEERS.iter().map(|s| s.to_string()).collect();
        }
    }
}
