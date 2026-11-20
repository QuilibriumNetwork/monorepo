use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
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
    /// Bootstrap peers added to the network's list, on mainnet to the
    /// built-in one, which `bootstrapPeers` cannot change there; e.g. an
    /// operator's own archive or an IPv6 or DNS address of a peer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_bootstrap_peers: Vec<String>,
    #[serde(default)]
    pub listen_multiaddr: String,
    #[serde(default = "default_stream_listen")]
    pub stream_listen_multiaddr: String,
    /// More addresses the p2p swarm of the master listens on, in the address
    /// family `listenMultiaddr` does not name, each bound as written, e.g.
    /// `/ip6/::/udp/8336/quic-v1` beside `/ip4/0.0.0.0/udp/8336/quic-v1`. The
    /// swarm's IPv6 sockets take IPv6 only, so a dual-stack host names both
    /// families. PeerInfo and AutoNAT stay on the family of `listenMultiaddr`;
    /// peers learn these addresses from identify.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_listen_multiaddrs: Vec<String>,
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
    /// Most connections the peer gRPC listener (`streamListenMultiaddr`)
    /// holds at once; 0 (the default) derives it from the process's open
    /// file limit, leaving room for the stores.
    #[serde(default)]
    pub stream_max_connections: usize,
    /// Most connections the peer gRPC listener holds from one public source
    /// address (an IPv6 /64); 0 (the default) is 512. Loopback and private
    /// sources are not capped per address.
    #[serde(default)]
    pub stream_max_connections_per_source: usize,
}

fn default_stream_listen() -> String {
    "/ip4/0.0.0.0/tcp/8340".into()
}

/// The p2p listen address of a config that names none.
pub const DEFAULT_LISTEN_MULTIADDR: &str = "/ip4/0.0.0.0/udp/8336/quic-v1";

/// The IPv6 counterpart of [`DEFAULT_LISTEN_MULTIADDR`], which a config
/// naming no listen address also listens on.
pub const DEFAULT_IPV6_LISTEN_MULTIADDR: &str = "/ip6/::/udp/8336/quic-v1";

/// Every setting but the peer key, which is the node's network identity
/// and shows only whether it is set: a config printed with `{:?}` (a log
/// line, a panic, an error chain) must not carry it.
impl std::fmt::Debug for P2PConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, so a new field fails to compile until it is listed.
        let Self {
            d_lo,
            history_length,
            history_gossip,
            gossip_factor,
            heartbeat_initial_delay_ms,
            heartbeat_interval_ms,
            fanout_ttl_ms,
            prune_backoff_ms,
            unsubscribe_backoff_ms,
            iwant_followup_time_ms,
            idont_want_message_threshold,
            bootstrap_peers,
            extra_bootstrap_peers,
            listen_multiaddr,
            stream_listen_multiaddr,
            additional_listen_multiaddrs,
            announce_listen_multiaddr,
            announce_stream_listen_multiaddr,
            peer_priv_key,
            network,
            direct_peers,
            disable_onion_routing,
            stream_max_connections,
            stream_max_connections_per_source,
        } = self;
        let peer_priv_key = if peer_priv_key.is_empty() {
            "unset"
        } else {
            "redacted"
        };
        f.debug_struct("P2PConfig")
            .field("d_lo", d_lo)
            .field("history_length", history_length)
            .field("history_gossip", history_gossip)
            .field("gossip_factor", gossip_factor)
            .field("heartbeat_initial_delay_ms", heartbeat_initial_delay_ms)
            .field("heartbeat_interval_ms", heartbeat_interval_ms)
            .field("fanout_ttl_ms", fanout_ttl_ms)
            .field("prune_backoff_ms", prune_backoff_ms)
            .field("unsubscribe_backoff_ms", unsubscribe_backoff_ms)
            .field("iwant_followup_time_ms", iwant_followup_time_ms)
            .field("idont_want_message_threshold", idont_want_message_threshold)
            .field("bootstrap_peers", bootstrap_peers)
            .field("extra_bootstrap_peers", extra_bootstrap_peers)
            .field("listen_multiaddr", listen_multiaddr)
            .field("stream_listen_multiaddr", stream_listen_multiaddr)
            .field("additional_listen_multiaddrs", additional_listen_multiaddrs)
            .field("announce_listen_multiaddr", announce_listen_multiaddr)
            .field(
                "announce_stream_listen_multiaddr",
                announce_stream_listen_multiaddr,
            )
            .field("peer_priv_key", &peer_priv_key)
            .field("network", network)
            .field("direct_peers", direct_peers)
            .field("disable_onion_routing", disable_onion_routing)
            .field("stream_max_connections", stream_max_connections)
            .field(
                "stream_max_connections_per_source",
                stream_max_connections_per_source,
            )
            .finish()
    }
}

impl Default for P2PConfig {
    fn default() -> Self {
        serde_yaml::from_str("{}").unwrap()
    }
}

/// Current mainnet bootstrap peers = the four genesis ARCHIVE servers (which
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
/// Each archive is listed at its IPv4 address, then at its IPv6 one, so an
/// IPv6-only node bootstraps too. A node dials a peer's entries over the
/// listened family first; the other family only after that dial fails
/// (a 5 s handshake wait), and a configured peer listed twice stays one
/// AutoNAT server and one archive.
///
/// A decommissioned archive leaves this list but stays in the genesis
/// `archive_peers` (see [`DECOMMISSIONED_GENESIS_ARCHIVES`]).
pub const MAINNET_BOOTSTRAP_PEERS: &[&str] = &[
    "/ip4/165.140.86.86/udp/8336/quic-v1/p2p/QmRECrGL6yDoMgSydFDN5bhnnpJLAByKVuieAbwmmAiodC",
    "/ip4/147.124.202.2/udp/8336/quic-v1/p2p/QmdjbsbkDmsuxgawTkZmUihCoqJ5dVmciExQ2wKr11Nwjz",
    "/ip4/23.239.107.34/udp/8336/quic-v1/p2p/QmYajrEX6uk1xzobw1vvUUd2a69vJYKnmGwq1KFciuHzaF",
    "/ip4/146.71.104.122/udp/8336/quic-v1/p2p/QmQr15mPeMExsrymb9Q6episZbzPJduJRCKwpyLierXRHA",
    "/ip6/2604:f440:4:29::2/udp/8336/quic-v1/p2p/QmRECrGL6yDoMgSydFDN5bhnnpJLAByKVuieAbwmmAiodC",
    "/ip6/2604:f440:1:c::2/udp/8336/quic-v1/p2p/QmdjbsbkDmsuxgawTkZmUihCoqJ5dVmciExQ2wKr11Nwjz",
    "/ip6/2606:c700:4020:ba:9e6b:ff:fec3:765e/udp/8336/quic-v1/p2p/QmYajrEX6uk1xzobw1vvUUd2a69vJYKnmGwq1KFciuHzaF",
    "/ip6/2606:c700:8410:62:a236:9fff:fee8:88cc/udp/8336/quic-v1/p2p/QmQr15mPeMExsrymb9Q6episZbzPJduJRCKwpyLierXRHA",
];

/// How many peers the multiaddr `entries` name: their distinct
/// `/p2p/<peer-id>` segments (the last of each entry), plus their distinct
/// entries without one, each naming a peer of unknown ID. A peer listed at
/// several addresses, such as an archive at both address families, is one
/// peer.
pub fn distinct_peer_count<S: AsRef<str>>(entries: impl IntoIterator<Item = S>) -> usize {
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    enum Named {
        Peer(String),
        Entry(String),
    }
    entries
        .into_iter()
        .filter_map(|entry| {
            let entry = entry.as_ref().trim();
            let peer = entry
                .rsplit_once("/p2p/")
                .and_then(|(_, peer)| peer.split('/').next())
                .filter(|peer| !peer.is_empty());
            match peer {
                Some(peer) => Some(Named::Peer(peer.to_owned())),
                None => (!entry.is_empty()).then(|| Named::Entry(entry.to_owned())),
            }
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// How many archives [`MAINNET_BOOTSTRAP_PEERS`] names: its distinct peers
/// ([`distinct_peer_count`]), as it lists each archive once per address
/// family.
pub(crate) fn mainnet_bootstrap_archive_count() -> usize {
    distinct_peer_count(MAINNET_BOOTSTRAP_PEERS)
}

/// The mainnet bootstrap list releases before the IPv6 entries built in.
/// A config saved by one of them holds it; it names no peer the node does
/// not dial, so it is not reported as replaced.
const EARLIER_MAINNET_BOOTSTRAP_PEERS: &[&str] = &[
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
/// configured peers ([`distinct_peer_count`]) on mainnet when the entries
/// differ from the built-in list and from
/// [`EARLIER_MAINNET_BOOTSTRAP_PEERS`], otherwise `None` (another network,
/// an empty list or the same entries).
pub fn replaced_mainnet_bootstrap_peers(network: u8, configured: &[String]) -> Option<usize> {
    if network != 0 || configured.is_empty() {
        return None;
    }
    use std::collections::BTreeSet;
    let configured: BTreeSet<&str> = configured.iter().map(|peer| peer.trim()).collect();
    let same = |list: &[&str]| configured == list.iter().copied().collect::<BTreeSet<_>>();
    let differs = !same(MAINNET_BOOTSTRAP_PEERS) && !same(EARLIER_MAINNET_BOOTSTRAP_PEERS);
    differs.then(|| distinct_peer_count(&configured))
}

impl P2PConfig {
    /// Whether the config names no p2p listen address, so the node listens
    /// on [`DEFAULT_LISTEN_MULTIADDR`] and, unless the config names
    /// additional listen addresses, on [`DEFAULT_IPV6_LISTEN_MULTIADDR`] and
    /// the peer gRPC port of both families.
    pub fn listens_by_default(&self) -> bool {
        self.listen_multiaddr.is_empty() && self.additional_listen_multiaddrs.is_empty()
    }

    /// The p2p listen address and the additional ones the node binds: the
    /// configured ones, or for a config naming none, the default IPv4
    /// address and its IPv6 counterpart.
    pub fn listen_multiaddrs(&self) -> (String, Vec<String>) {
        if !self.listen_multiaddr.is_empty() {
            return (
                self.listen_multiaddr.clone(),
                self.additional_listen_multiaddrs.clone(),
            );
        }
        let additional = if self.listens_by_default() {
            vec![DEFAULT_IPV6_LISTEN_MULTIADDR.to_string()]
        } else {
            self.additional_listen_multiaddrs.clone()
        };
        (DEFAULT_LISTEN_MULTIADDR.to_string(), additional)
    }

    /// Whether the peer gRPC listener takes both address families: a config
    /// that [`listens_by_default`](Self::listens_by_default) on the default
    /// stream address.
    pub fn stream_listens_on_both_families(&self) -> bool {
        self.listens_by_default() && self.stream_listen_multiaddr == default_stream_listen()
    }

    /// Whether onion links and the exit may dial a peer's loopback, private
    /// or otherwise non-public address: only off mainnet, where devnets run
    /// on one host or network. On mainnet a peer's advertised address could
    /// otherwise point a relay at services on its own host or network.
    pub fn onion_dials_private_addresses(&self) -> bool {
        self.network != 0
    }

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
        // `extraBootstrapPeers` adds to that list where the node builds its
        // dial list (`quil_p2p::node`), never here: a config saved after
        // loading would carry the merged list. A new key rather than honoring
        // `bootstrapPeers` on mainnet: configs written by earlier releases
        // carry their built-in lists, including hosts since retired, which
        // every such node would dial again.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config printed with `{:?}` (a log line, a panic, an error chain)
    /// never shows the p2p peer key, which is the node's network identity.
    #[test]
    fn the_peer_key_never_reaches_debug_output() {
        let config = P2PConfig {
            peer_priv_key: "5eed".repeat(16),
            ..P2PConfig::default()
        };
        let shown = format!("{config:?}");
        if shown.contains(&config.peer_priv_key) {
            panic!("VULNERABLE: the p2p peer key is printed by Debug");
        }
        assert!(
            shown.contains("stream_listen_multiaddr"),
            "Debug no longer shows the other settings: {shown}"
        );
    }

    /// Onion links and the exit dial private addresses only off mainnet.
    #[test]
    fn onion_dials_take_private_addresses_only_off_mainnet() {
        let on = |network: u8| {
            P2PConfig {
                network,
                ..P2PConfig::default()
            }
            .onion_dials_private_addresses()
        };
        assert!(!on(0), "mainnet onion dials take private addresses");
        assert!(
            on(1) && on(99),
            "devnet onion dials refuse private addresses"
        );
    }

    /// The IPv4 entries of the built-in list.
    fn ipv4_entries() -> Vec<String> {
        MAINNET_BOOTSTRAP_PEERS
            .iter()
            .filter(|entry| entry.starts_with("/ip4/"))
            .map(|entry| entry.to_string())
            .collect()
    }

    /// Every mainnet archive bootstraps over both families: the built-in
    /// list holds one IPv6 entry per IPv4 entry, under the same peer ID,
    /// each address in the form log redaction keeps.
    #[test]
    fn each_mainnet_archive_bootstraps_over_both_families() {
        let peer = |entry: &str| entry.rsplit("/p2p/").next().unwrap().to_string();
        let mut ipv4: Vec<String> = ipv4_entries().iter().map(|e| peer(e)).collect();
        let mut ipv6 = Vec::new();
        for entry in MAINNET_BOOTSTRAP_PEERS {
            let Some(rest) = entry.strip_prefix("/ip6/") else {
                continue;
            };
            let address = rest.split('/').next().unwrap();
            let parsed: std::net::Ipv6Addr = address.parse().unwrap();
            assert_eq!(parsed.to_string(), address, "IPv6 entry not canonical");
            assert!(
                entry.ends_with(&format!("/udp/8336/quic-v1/p2p/{}", peer(entry))),
                "IPv6 entry not on the archives' QUIC port: {entry}"
            );
            ipv6.push(peer(entry));
        }
        ipv4.sort();
        ipv6.sort();
        eprintln!("REACH v6-bootstrap checked");
        assert_eq!(ipv4.len(), 4, "IPv4 archive entries");
        assert_eq!(ipv6, ipv4, "an archive without its IPv6 entry");
        assert_eq!(MAINNET_BOOTSTRAP_PEERS.len(), ipv4.len() + ipv6.len());
    }

    /// A replaced list is counted in peers, not entries: an archive listed
    /// at both address families is one peer, and each distinct entry
    /// without a peer ID one more, so a list naming no peer ID is not
    /// reported as 0 peers.
    #[test]
    fn a_replaced_bootstrap_list_counts_peers_not_entries() {
        let peerless: Vec<String> = [
            "/ip4/192.0.2.1/udp/8336/quic-v1",
            "/ip4/192.0.2.2/udp/8336/quic-v1",
            " /ip4/192.0.2.1/udp/8336/quic-v1 ",
        ]
        .iter()
        .map(|entry| entry.to_string())
        .collect();
        assert_eq!(
            replaced_mainnet_bootstrap_peers(0, &peerless),
            Some(2),
            "a list naming no peer ID counted as fewer peers than its entries"
        );
        let built_in: Vec<String> = MAINNET_BOOTSTRAP_PEERS
            .iter()
            .map(|entry| entry.to_string())
            .collect();
        let archives = ipv4_entries().len();
        let mut entries = built_in[..built_in.len() - 1].to_vec();
        entries.push("/ip4/192.0.2.1/udp/8336/quic-v1".into());
        assert!(
            entries.len() > archives + 2,
            "premise: archives listed twice"
        );
        assert_eq!(
            replaced_mainnet_bootstrap_peers(0, &entries),
            Some(archives + 1),
            "a replaced list counted in entries, not peers"
        );
        assert_eq!(
            distinct_peer_count(["/p2p/QmA/p2p-circuit/p2p/QmB", " /p2p/QmB "]),
            1
        );
    }

    /// A config saved by a release whose built-in list held the IPv4
    /// entries only names no peer the node does not dial: it is not
    /// reported as replaced. One differing entry still is.
    #[test]
    fn a_config_saved_with_the_ipv4_bootstrap_list_is_not_reported() {
        let saved = ipv4_entries();
        eprintln!("REACH v6-bootstrap checked");
        for list in [saved.clone(), saved.iter().rev().cloned().collect()] {
            assert_eq!(
                replaced_mainnet_bootstrap_peers(0, &list),
                None,
                "the IPv4-only list reported as replaced"
            );
        }
        assert_eq!(
            replaced_mainnet_bootstrap_peers(0, &saved[1..]),
            Some(saved.len() - 1)
        );
    }
}
