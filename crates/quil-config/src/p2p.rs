use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct P2PConfig {
    #[serde(default)]
    pub d_lo: i32,
    #[serde(default)]
    pub history_length: i32,
    #[serde(default)]
    pub history_gossip: i32,
    #[serde(default)]
    pub gossip_factor: f64,
    #[serde(
        default,
        alias = "heartbeatInitialDelay",
        deserialize_with = "crate::deserialize_go_duration_ms"
    )]
    pub heartbeat_initial_delay_ms: u64,
    #[serde(
        default,
        alias = "heartbeatInterval",
        deserialize_with = "crate::deserialize_go_duration_ms"
    )]
    pub heartbeat_interval_ms: u64,
    #[serde(
        default,
        alias = "fanoutTTL",
        deserialize_with = "crate::deserialize_go_duration_ms"
    )]
    pub fanout_ttl_ms: u64,
    #[serde(
        default,
        alias = "pruneBackoff",
        deserialize_with = "crate::deserialize_go_duration_ms"
    )]
    pub prune_backoff_ms: u64,
    #[serde(
        default,
        alias = "unsubscribeBackoff",
        deserialize_with = "crate::deserialize_go_duration_ms"
    )]
    pub unsubscribe_backoff_ms: u64,
    #[serde(
        default,
        alias = "iWantFollowupTime",
        deserialize_with = "crate::deserialize_go_duration_ms"
    )]
    pub iwant_followup_time_ms: u64,
    #[serde(default, alias = "iDontWantMessageThreshold")]
    pub idont_want_message_threshold: i32,
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
    pub network: u8,
    #[serde(default)]
    pub direct_peers: Vec<String>,
    /// Disable the live onion-routing relay (default: false, i.e. onion routing
    /// is ON). When true, the node neither runs the onion dispatcher nor
    /// advertises the routing capability, so no circuits traverse it. The
    /// `OnionService` transport is still served either way.
    #[serde(default, alias = "disableOnionRouting")]
    pub disable_onion_routing: bool,
}

fn default_stream_listen() -> String {
    "/ip4/0.0.0.0/tcp/8340".into()
}

impl Default for P2PConfig {
    fn default() -> Self {
        serde_yaml::from_str("{}").unwrap()
    }
}

/// Current mainnet bootstrap peers = the five genesis ARCHIVE servers (which
/// double as the DHT bootstrap nodes). Their `/p2p/<peer_id>` MUST be the
/// Falcon-derived peer IDs the archives actually present post-migration —
/// these are `peer_id_from_falcon_pubkey(archive_pubkey)` for each genesis
/// `archive_peers` entry (kept identical to
/// `quil_engine::genesis::genesis_archive_static_multiaddrs`, the sole other
/// copy, which reuses this list). The prior quinoa/qualia/quetzalcoatl hosts
/// with pre-Falcon `Qm…` peer IDs are GONE: dialing them yields a peer-ID
/// mismatch, the node never joins the gossip mesh, no PeerInfo is learned, and
/// archive `:8340` discovery (and thus prover submits) silently dies.
/// Update when an operator rotates IPs.
///
/// A decommissioned archive leaves this list but stays in the genesis
/// `archive_peers` (see [`DECOMMISSIONED_GENESIS_ARCHIVES`]).
pub const MAINNET_BOOTSTRAP_PEERS: &[&str] = &[
    "/ip4/165.140.86.86/udp/8336/quic-v1/p2p/QmRECrGL6yDoMgSydFDN5bhnnpJLAByKVuieAbwmmAiodC",
    "/ip4/147.124.202.2/udp/8336/quic-v1/p2p/QmdjbsbkDmsuxgawTkZmUihCoqJ5dVmciExQ2wKr11Nwjz",
    "/ip4/23.239.107.34/udp/8336/quic-v1/p2p/QmYajrEX6uk1xzobw1vvUUd2a69vJYKnmGwq1KFciuHzaF",
    "/ip4/146.71.104.122/udp/8336/quic-v1/p2p/QmQr15mPeMExsrymb9Q6episZbzPJduJRCKwpyLierXRHA",
];

/// Genesis archives no longer dialed, bootstrapped from or asked for frames.
/// They stay in the genesis `archive_peers`, which verify every frame before
/// the GLOBAL committee succession; from it on they are not in the committee
/// (`quil_types::consensus::MAINNET_GLOBAL_COMMITTEE_SUCCESSION_FRAME`).
///
/// QmQfp3 (109.94.96.183) was decommissioned 2026-10-20.
pub const DECOMMISSIONED_GENESIS_ARCHIVES: &[&str] =
    &["QmQfp3dpBdX48o1P2HxDLQNtoEJaXvSKejSDBUyxewsHRr"];

/// How many configured bootstrap peers [`P2PConfig::apply_defaults`]
/// replaces with [`MAINNET_BOOTSTRAP_PEERS`]: the number of distinct
/// configured entries on mainnet when they differ from the built-in list,
/// otherwise `None` (another network, an empty list or the same peers).
pub fn replaced_mainnet_bootstrap_peers(network: u8, configured: &[String]) -> Option<usize> {
    if network != 0 || configured.is_empty() {
        return None;
    }
    let configured: std::collections::BTreeSet<&str> =
        configured.iter().map(|peer| peer.trim()).collect();
    let built_in: std::collections::BTreeSet<&str> =
        MAINNET_BOOTSTRAP_PEERS.iter().copied().collect();
    (configured != built_in).then_some(configured.len())
}

impl P2PConfig {
    /// Apply defaults for all P2P and BlossomSub parameters.
    pub fn apply_defaults(&mut self) {
        // BlossomSub mesh parameters
        if self.d_lo == 0 {
            self.d_lo = 6;
        }

        // Gossip/history
        if self.history_length == 0 {
            self.history_length = 9;
        }
        if self.history_gossip == 0 {
            self.history_gossip = 6;
        }
        if self.gossip_factor == 0.0 {
            self.gossip_factor = 0.25;
        }

        // Heartbeat (Go: 100ms initial, 700ms interval)
        if self.heartbeat_initial_delay_ms == 0 {
            self.heartbeat_initial_delay_ms = 100;
        }
        if self.heartbeat_interval_ms == 0 {
            self.heartbeat_interval_ms = 700;
        }

        // Fanout TTL (Go: 60s)
        if self.fanout_ttl_ms == 0 {
            self.fanout_ttl_ms = 60_000;
        }

        // Prune/unsubscribe backoff (Go: 60s, 10s)
        if self.prune_backoff_ms == 0 {
            self.prune_backoff_ms = 60_000;
        }
        if self.unsubscribe_backoff_ms == 0 {
            self.unsubscribe_backoff_ms = 10_000;
        }

        // IWANT followup (Go: 3s)
        if self.iwant_followup_time_ms == 0 {
            self.iwant_followup_time_ms = 3_000;
        }

        // IDONTWANT (Go: 1024 byte threshold)
        if self.idont_want_message_threshold == 0 {
            self.idont_want_message_threshold = 1024;
        }

        // Stream listen (Go: /ip4/0.0.0.0/tcp/8340)
        if self.stream_listen_multiaddr.is_empty() {
            self.stream_listen_multiaddr = default_stream_listen();
        }

        // On MAINNET (network 0) the bootstrap peers are hardcoded and
        // UNCONDITIONALLY supersede whatever is in the config. The archive
        // servers are the DHT bootstraps, their peer IDs are the Falcon
        // identities they present, and a config carrying stale peers (old
        // quinoa/qualia hosts, or pre-Falcon `Qm…` IDs) must not be honored —
        // dialing a mismatched peer ID drops the connection and the node never
        // joins the mesh. Non-mainnet networks keep their own configured
        // bootstrap list (never inject mainnet archives onto a testnet/devnet).
        if self.network == 0 {
            self.bootstrap_peers = MAINNET_BOOTSTRAP_PEERS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }
    }
}
