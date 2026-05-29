use std::time::Duration;

use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{Multiaddr, PeerId, SwarmBuilder};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use quil_config::P2PConfig;
use quil_types::error::QuilError;

use crate::behaviour::{BlossomSubBehaviour, BlossomSubEvent};

/// A received message from the network.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub bitmask: Vec<u8>,
    pub data: Vec<u8>,
    pub from: Vec<u8>,
}

/// The P2P node.
pub struct P2PNode {
    pub peer_id: PeerId,
    keypair: Keypair,
    bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    network: u8,
    /// If a new Ed448 key was generated, the hex-encoded config key (228 chars).
    /// The caller should persist this in the config file.
    pub generated_key_hex: Option<String>,
    /// BlossomSub runtime params resolved from operator config at
    /// construction time. Plumbed into `BlossomSubBehaviour` in
    /// `start()` so operators can tune heartbeat / prune backoff /
    /// history length / IWANT follow-up timeout from `P2PConfig`
    /// without a rebuild.
    blossomsub_params: crate::BlossomsubParams,
    /// Optional pubsub signing identity, distinct from the libp2p
    /// host `keypair`. When set, pubsub messages are signed with this
    /// keypair and `msg.from` carries its derived peer ID; the host
    /// itself still uses `keypair` for connection-level identity.
    ///
    /// Standalone worker processes set this to the real prover key
    /// while using a deterministic synthetic key for `keypair` (see
    /// [`Self::new_for_worker`]). When `None`, pubsub signs with the
    /// host's own keypair (the master / single-node default).
    pubsub_signing_keypair: Option<Keypair>,
    /// Pubsub `from` peer ID. Mirrors `pubsub_signing_keypair`: when
    /// that field is set, this is the peer ID derived from the
    /// signing keypair's public key. `None` falls back to the host's
    /// own peer ID.
    pubsub_from_peer_id: Option<PeerId>,
}

impl P2PNode {
    pub fn new(config: &P2PConfig) -> quil_types::error::Result<Self> {
        Self::new_with_options(config, false)
    }

    pub fn new_with_options(config: &P2PConfig, force_ed25519: bool) -> quil_types::error::Result<Self> {
        let (keypair, generated_key_hex) = if force_ed25519 {
            debug!("using Ed25519 identity (--ed25519 flag)");
            (Keypair::generate_ed25519(), None)
        } else if config.peer_priv_key.is_empty() {
            // Generate Ed448 key
            let id = crate::ed448_identity::Ed448Identity::generate()?;
            let config_hex = id.to_config_hex();
            let kp = Keypair::ed448_from_config_bytes(
                &hex::decode(&config_hex).unwrap(),
            )
            .map_err(|e| QuilError::P2p(format!("ed448 key error: {}", e)))?;
            (kp, Some(config_hex))
        } else {
            let key_bytes = hex::decode(&config.peer_priv_key)
                .map_err(|e| QuilError::P2p(format!("invalid hex key: {}", e)))?;
            let kp = match key_bytes.len() {
                114 => Keypair::ed448_from_config_bytes(&key_bytes),
                57 => Keypair::ed448_from_bytes(&key_bytes),
                32 => Keypair::ed25519_from_bytes(key_bytes),
                n => return Err(QuilError::P2p(format!(
                    "unexpected key length: {} (expected 114/57/32)", n
                ))),
            }
            .map_err(|e| QuilError::P2p(format!("invalid key: {}", e)))?;
            (kp, None)
        };

        let peer_id = PeerId::from_public_key(&keypair.public());
        debug!(%peer_id, "initialized P2P identity");

        // Rewrite `/dnsaddr/<host>/...` → `/dns/<host>/...` at parse
        // time. The `/dnsaddr/` protocol is libp2p's TXT-record peer
        // discovery scheme (`_dnsaddr.<host>`), which is not deployed
        // for the Quilibrium bootstrap hosts and consistently returns
        // "No matching records found." Go dropped `/dnsaddr/` and
        // expects a plain A/AAAA lookup — `/dns/` does exactly that.
        //
        // Additionally, the Quilibrium `/dnsaddr/` bootstrap entries
        // were authored with the transport segment omitted (just
        // `.../udp/8339/p2p/<peer>`) on the assumption that the TXT
        // records would supply `/quic-v1/`. Once we rewrite to
        // `/dns/`, libp2p resolves to a bare `/ip4/.../udp/8339/p2p/...`
        // which it can't dial ("Unsupported resolved address"). Inject
        // `/quic-v1/` between `/udp/<port>` and `/p2p/<id>` for any
        // address that came in as `/dnsaddr/`.
        let bootstrap_peers = config
            .bootstrap_peers
            .iter()
            .filter_map(|addr_str| {
                let raw: Multiaddr = addr_str.parse().ok()?;
                let was_dnsaddr = raw
                    .iter()
                    .any(|p| matches!(p, Protocol::Dnsaddr(_)));
                let mut rewritten = Multiaddr::empty();
                let mut last_was_udp = false;
                let mut quic_inserted = false;
                for proto in raw.iter() {
                    match proto {
                        Protocol::Dnsaddr(host) => {
                            rewritten.push(Protocol::Dns(host));
                            last_was_udp = false;
                        }
                        Protocol::Udp(_) => {
                            rewritten.push(proto);
                            last_was_udp = true;
                        }
                        other => {
                            // Quilibrium `/dnsaddr/` entries omit the
                            // QUIC marker that TXT records would have
                            // supplied — synthesize it.
                            if was_dnsaddr
                                && last_was_udp
                                && !quic_inserted
                                && !matches!(other, Protocol::QuicV1 | Protocol::Quic)
                            {
                                rewritten.push(Protocol::QuicV1);
                                quic_inserted = true;
                            }
                            rewritten.push(other);
                            last_was_udp = false;
                        }
                    }
                }
                let peer_id = rewritten.iter().find_map(|p| match p {
                    Protocol::P2p(id) => Some(id),
                    _ => None,
                })?;
                Some((peer_id, rewritten))
            })
            .collect();

        Ok(Self {
            peer_id,
            keypair,
            bootstrap_peers,
            network: config.network,
            generated_key_hex,
            blossomsub_params: crate::BlossomsubParams::from_p2p_config(config),
            pubsub_signing_keypair: None,
            pubsub_from_peer_id: None,
        })
    }

    /// Construct a P2P node for a standalone worker process.
    ///
    /// The libp2p host identity (used for connections + peer store)
    /// is a deterministic synthetic Ed448 key derived from the real
    /// prover key and `core_id` (mirrors `node/p2p/blossomsub.go:477-496`).
    /// This avoids peer-id collisions between the master and its
    /// workers all running off the same prover key.
    ///
    /// Pubsub messages are signed with the REAL prover key and carry
    /// the real prover's peer ID in `msg.from`, so peers attribute
    /// messages to the node regardless of which worker emitted them.
    pub fn new_for_worker(
        p2p: &P2PConfig,
        core_id: u32,
    ) -> quil_types::error::Result<Self> {
        if p2p.peer_priv_key.is_empty() {
            return Err(QuilError::P2p(
                "worker p2p requires p2p.peerPrivKey to be set".into(),
            ));
        }
        // Real prover key: parse the same hex blob the master uses.
        let real_bytes = hex::decode(&p2p.peer_priv_key)
            .map_err(|e| QuilError::P2p(format!("invalid peer_priv_key hex: {}", e)))?;
        let real_seed: [u8; 57] = match real_bytes.len() {
            114 => {
                let mut s = [0u8; 57];
                s.copy_from_slice(&real_bytes[..57]);
                s
            }
            57 => {
                let mut s = [0u8; 57];
                s.copy_from_slice(&real_bytes);
                s
            }
            n => {
                return Err(QuilError::P2p(format!(
                    "worker p2p: peer_priv_key must be 57 or 114 bytes, got {}",
                    n
                )));
            }
        };
        let real_keypair = Keypair::ed448_from_bytes(&real_seed)
            .map_err(|e| QuilError::P2p(format!("real ed448 key: {}", e)))?;
        let real_peer_id = real_keypair.public().to_peer_id();

        // Synthetic worker key for host identity.
        let worker_identity =
            crate::ed448_identity::derive_worker_identity(&real_seed, core_id)?;
        let mut worker_seed = [0u8; 57];
        worker_seed.copy_from_slice(&worker_identity.private_key);
        let worker_keypair = Keypair::ed448_from_bytes(&worker_seed)
            .map_err(|e| QuilError::P2p(format!("worker ed448 key: {}", e)))?;
        let worker_peer_id = worker_keypair.public().to_peer_id();

        tracing::info!(
            core_id,
            worker_peer_id = %worker_peer_id,
            real_peer_id = %real_peer_id,
            "derived worker p2p identity (synthetic host, real signing)"
        );

        // Reuse the master's bootstrap-peer parsing logic by calling
        // `new_with_options` first, then swap in the worker-specific
        // identity + signing config.
        let mut base = Self::new_with_options(p2p, false)?;
        base.keypair = worker_keypair;
        base.peer_id = worker_peer_id;
        base.pubsub_signing_keypair = Some(real_keypair);
        base.pubsub_from_peer_id = Some(real_peer_id);
        Ok(base)
    }

    /// Compute a standalone worker's libp2p listen address. Prefers an
    /// explicit per-worker entry from `data_worker_p2p_multiaddrs`,
    /// falls back to formatting `data_worker_base_listen_multiaddr`
    /// with `data_worker_base_p2p_port + core_id - 1`.
    pub fn worker_listen_multiaddr(
        engine: &quil_config::EngineConfig,
        core_id: u32,
    ) -> quil_types::error::Result<String> {
        let idx = core_id.saturating_sub(1) as usize;
        if idx < engine.data_worker_p2p_multiaddrs.len() {
            let m = &engine.data_worker_p2p_multiaddrs[idx];
            if !m.is_empty() {
                return Ok(m.clone());
            }
        }
        if engine.data_worker_base_p2p_port > 0 {
            let port = engine
                .data_worker_base_p2p_port
                .saturating_add(core_id.saturating_sub(1) as u16);
            if engine.data_worker_base_listen_multiaddr.contains("%d") {
                return Ok(engine
                    .data_worker_base_listen_multiaddr
                    .replace("%d", &port.to_string()));
            }
        }
        Err(QuilError::P2p(format!(
            "worker p2p listen address unresolvable for core_id {}: \
             neither data_worker_p2p_multiaddrs[{}] nor \
             data_worker_base_p2p_port is configured",
            core_id, idx,
        )))
    }

    /// Start the P2P swarm.
    ///
    /// The swarm event loop is registered on the supplied supervisor as
    /// `"p2p-swarm"` (or `name` if customized by the caller via a future
    /// extension), so a panic inside the libp2p event loop propagates
    /// through `Supervisor::run` and terminates the process — rather
    /// than being silently swallowed by a detached `tokio::spawn`.
    pub async fn start(
        self,
        sup: &mut quil_lifecycle::Supervisor<anyhow::Error>,
        listen_addr: &str,
    ) -> quil_types::error::Result<(P2PHandle, mpsc::Receiver<ReceivedMessage>)> {
        let listen_multiaddr: Multiaddr = listen_addr
            .parse()
            .map_err(|e| QuilError::P2p(format!("invalid listen address: {}", e)))?;

        let network = self.network;
        let blossomsub_params = self.blossomsub_params.clone();
        let pubsub_signing_keypair = self.pubsub_signing_keypair.clone();
        let pubsub_from_peer_id = self.pubsub_from_peer_id;

        // yamux multiplexer configured with a higher per-connection
        // stream cap and a 30-second window timeout. Default
        // `max_num_streams` is 8192; we've seen production
        // accumulate that many on a single connection during
        // chronic-mesh-shortage events that flood
        // `BlossomSubEvent::NeedPeers` and (previously unthrottled)
        // trigger one Kademlia `get_providers` per event. The query
        // throttle below caps the new-stream rate; raising the
        // yamux cap is the second half — a defense for any future
        // path that opens streams faster than they're acked.
        // Surfaces as yamux's
        // `ConnectionError::TooManyStreams ("maximum number of
        // streams reached")` in logs.
        let yamux_config_fn = || {
            let mut cfg = libp2p::yamux::Config::default();
            cfg.set_max_num_streams(65536);
            cfg
        };
        let mut swarm = SwarmBuilder::with_existing_identity(self.keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                yamux_config_fn,
            )
            .map_err(|e| QuilError::P2p(format!("tcp: {}", e)))?
            .with_quic()
            .with_dns()
            .map_err(|e| QuilError::P2p(format!("dns: {}", e)))?
            .with_behaviour(|key| {
                let local_peer_id = PeerId::from_public_key(&key.public());

                // Kademlia DHT for peer discovery
                // Go mainnet uses default IPFS DHT protocol (/ipfs/kad/1.0.0)
                // Testnet uses /testnet prefix
                let mut kad_config = if network == 0 {
                    libp2p::kad::Config::default()
                } else {
                    let proto = format!("/testnet/kad/1.0.0");
                    libp2p::kad::Config::new(
                        libp2p::StreamProtocol::try_from_owned(proto)
                            .expect("valid protocol"),
                    )
                };
                kad_config.set_record_ttl(Some(std::time::Duration::from_secs(3600)));
                // Go bootstrap nodes have huge routing tables (~500KB responses).
                // Default libp2p-kad limit is 16KB — must increase to accept them.
                kad_config.set_max_packet_size(1024 * 1024);
                let kad_store = libp2p::kad::store::MemoryStore::new(local_peer_id);
                let kademlia = libp2p::kad::Behaviour::with_config(
                    local_peer_id,
                    kad_store,
                    kad_config,
                );

                let ping = libp2p::ping::Behaviour::default();
                let identify = libp2p::identify::Behaviour::new(
                    libp2p::identify::Config::new(
                        format!("/quilibrium/2.0.2/{}", network),
                        key.public(),
                    )
                    .with_push_listen_addr_updates(true),
                );
                let mut blossomsub =
                    BlossomSubBehaviour::with_params(network, blossomsub_params.clone());
                // Set signing identity so published messages pass Go's
                // StrictSign verification (WithStrictSignatureVerification(true)).
                // Pubsub signing identity. Workers use the REAL
                // prover key here so `msg.from` carries the prover's
                // peer ID; the libp2p host (`key`) is the synthetic
                // worker key for connection-level identity.
                let (sign_peer_id, sign_key) = match (
                    pubsub_from_peer_id,
                    pubsub_signing_keypair.clone(),
                ) {
                    (Some(pid), Some(kp)) => (pid, kp),
                    _ => (key.public().to_peer_id(), key.clone()),
                };
                blossomsub.set_signing_identity(sign_peer_id, sign_key);
                // Do NOT pre-subscribe to global bitmasks here. The
                // caller (`main.rs` or `run_worker_node`) selects
                // subscriptions based on node role:
                //   - Archive: all global + [0xFF;32] bulk shard
                //   - Non-archive master: GLOBAL_PEER_INFO only
                //   - Worker: GLOBAL_PEER_INFO only (per-shard added
                //     dynamically on Respawn)
                //
                // Pre-subscribing here bypasses those gates and causes
                // every node to receive and relay ALL global traffic
                // regardless of role — the root cause of bandwidth
                // explosion on non-archive clusters.
                let autonat = libp2p::autonat::Behaviour::new(
                    local_peer_id,
                    libp2p::autonat::Config::default(),
                );

                // Hard cap on swarm connections. Without these limits
                // the swarm accepts unbounded inbound connections and
                // pays the per-connection memory tax (QUIC/TCP buffers,
                // multiplexer state, BlossomSub mesh tracking) for
                // every one. Observed in prod: 4596 peers consuming
                // ~13 GB RSS with negligible application-level cache
                // growth. The cap shape mirrors typical libp2p
                // application defaults — keep dial outbound headroom
                // for kademlia and bootstrap, hard-cap inbound so a
                // chatty network can't fill us up.
                let conn_limits = libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(512))
                    .with_max_established_incoming(Some(384))
                    .with_max_established_outgoing(Some(256))
                    .with_max_established_per_peer(Some(2))
                    .with_max_pending_incoming(Some(64))
                    .with_max_pending_outgoing(Some(64));
                let connection_limits =
                    libp2p::connection_limits::Behaviour::new(conn_limits);

                Ok(NodeBehaviour {
                    connection_limits,
                    kademlia,
                    ping,
                    identify,
                    blossomsub,
                    autonat,
                })
            })
            .map_err(|e| QuilError::P2p(format!("behaviour: {}", e)))?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(120))
                    .with_max_negotiating_inbound_streams(32)
            })
            .build();

        // Respect the configured transport: a user who set
        // `listen_multiaddr = "/ip4/0.0.0.0/tcp/8336"` doesn't want a
        // QUIC listener silently bound on UDP/8336 too. Walk the
        // configured multiaddr's protocol stack and only start the
        // listeners it actually names; if neither TCP nor QUIC is
        // present (e.g. malformed config), fall back to the historic
        // "listen on both" default so we don't leave the node
        // unreachable.
        use libp2p::multiaddr::Protocol;
        let mut want_tcp: Option<u16> = None;
        let mut want_quic: Option<u16> = None;
        let mut last_udp_port: Option<u16> = None;
        for proto in listen_multiaddr.iter() {
            match proto {
                Protocol::Tcp(port) => want_tcp = Some(port),
                Protocol::Udp(port) => last_udp_port = Some(port),
                Protocol::QuicV1 | Protocol::Quic => {
                    if let Some(p) = last_udp_port {
                        want_quic = Some(p);
                    }
                }
                _ => {}
            }
        }
        if want_tcp.is_none() && want_quic.is_none() {
            let port = listen_multiaddr
                .to_string()
                .split('/')
                .filter_map(|s| s.parse::<u16>().ok())
                .last()
                .unwrap_or(8336);
            warn!(
                listen = %listen_multiaddr,
                fallback_port = port,
                "listen multiaddr names no transport — defaulting to TCP+QUIC for backward compat"
            );
            want_tcp = Some(port);
            want_quic = Some(port);
        }

        if let Some(port) = want_quic {
            let quic_addr: Multiaddr =
                format!("/ip4/0.0.0.0/udp/{}/quic-v1", port).parse().unwrap();
            match swarm.listen_on(quic_addr.clone()) {
                Ok(_) => debug!(%quic_addr, "QUIC listener starting"),
                Err(e) => debug!(error = format!("{:?}", e), "failed to start QUIC listener"),
            }
        }
        if let Some(port) = want_tcp {
            let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse().unwrap();
            match swarm.listen_on(tcp_addr.clone()) {
                Ok(_) => debug!(%tcp_addr, "TCP listener starting"),
                Err(e) => debug!(error = format!("{:?}", e), "failed to start TCP listener"),
            }
        }

        let peer_id = self.peer_id;
        let bootstrap_peers = self.bootstrap_peers.clone();
        let (msg_tx, msg_rx) = mpsc::channel::<ReceivedMessage>(4096);
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<P2PCommand>(256);
        let peer_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pc_writer = peer_count.clone();
        let observed_addrs: std::sync::Arc<std::sync::RwLock<Vec<String>>> =
            std::sync::Arc::new(std::sync::RwLock::new(Vec::new()));
        let observed_addrs_writer = observed_addrs.clone();

        sup.spawn("p2p-swarm", move |cancel_token| async move {
            debug!("P2P swarm event loop started");
            let mut bootstrapped = false;
            let mut discovery_timer = tokio::time::interval(Duration::from_secs(30));
            discovery_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut discovery_count = 0u32;
            // Throttle NeedPeers-driven Kademlia discovery. BlossomSub
            // can fire `NeedPeers` repeatedly when the mesh is short
            // of peers (bootstrap, partition, sustained churn); each
            // event used to fire `kademlia.get_providers` with no
            // rate-limit, opening DHT substreams to many peers. Burst
            // floods pushed per-connection stream counts past yamux's
            // 8192 cap, breaking connections with "maximum number of
            // streams reached". The periodic `discovery_timer` below
            // already runs the same query every 30 s, so this
            // throttle suppresses redundant NeedPeers re-issues
            // inside the window. 30 s matches the timer cadence —
            // any tighter is wasteful, any looser delays recovery
            // from a real partition.
            let need_peers_throttle = Duration::from_secs(30);
            let mut last_need_peers_query: Option<std::time::Instant> = None;
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!("P2P swarm shutting down — supervisor cancelled");
                        break;
                    }
                    _ = discovery_timer.tick() => {
                        if bootstrapped && discovery_count < 30 {
                            discovery_count += 1;
                            let connected = swarm.connected_peers().count();
                            let mesh_total: usize = swarm.behaviour().blossomsub.mesh_peer_counts();
                            debug!(
                                peers = connected,
                                mesh = mesh_total,
                                round = discovery_count,
                                "peer discovery"
                            );

                            // Re-dial bootstraps if connectivity drops.
                            if connected < 3 {
                                debug!(connected, "low connectivity, re-dialing bootstrap peers");
                                for (bp_peer, bp_addr) in &bootstrap_peers {
                                    if !swarm.is_connected(bp_peer) {
                                        swarm.behaviour_mut().kademlia.add_address(bp_peer, bp_addr.clone());
                                        let opts = DialOpts::unknown_peer_id()
                                            .address(bp_addr.clone())
                                            .allocate_new_port()
                                            .build();
                                        let _ = swarm.dial(opts);
                                    }
                                }
                            }

                            if discovery_count <= 5 {
                                // Use GetProviders with the same key derivation as Go:
                                // CIDv1(codec=Raw, hash=SHA2-256(namespace))
                                // The RecordKey is the multihash part of the CID
                                let namespace = "quilibrium-2.0.2-dusk-mainnet";
                                let hash = Sha256::digest(namespace.as_bytes());
                                // Multihash: 0x12 (SHA2-256) + 0x20 (32 bytes) + hash
                                let mut mh = vec![0x12u8, 0x20];
                                mh.extend_from_slice(&hash);
                                let key = libp2p::kad::RecordKey::new(&mh);
                                swarm.behaviour_mut().kademlia.get_providers(key);
                                debug!(
                                    connected,
                                    discovery_round = discovery_count,
                                    "DHT discovery: GetProviders for namespace"
                                );
                            } else {
                                // Later: random walk to fill routing table
                                let random_peer = PeerId::random();
                                swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
                                debug!(
                                    connected,
                                    discovery_round = discovery_count,
                                    "DHT discovery: random walk"
                                );
                            }
                        }
                    }
                    event = swarm.select_next_some() => {
                        match event {
                            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                                debug!(%address, "listening");
                                // Dial bootstrap peers and start DHT bootstrap
                                if !bootstrapped {
                                    bootstrapped = true;
                                    for (bp_peer, bp_addr) in &bootstrap_peers {
                                        debug!(%bp_peer, %bp_addr, "dialing bootstrap peer");
                                        swarm.behaviour_mut().kademlia.add_address(bp_peer, bp_addr.clone());
                                        let opts = DialOpts::unknown_peer_id()
                                            .address(bp_addr.clone())
                                            .allocate_new_port()
                                            .build();
                                        if let Err(e) = swarm.dial(opts) {
                                            debug!(%e, %bp_peer, "dial failed");
                                        }
                                    }
                                    // Start Kademlia bootstrap
                                    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                                        debug!(%e, "kad bootstrap failed");
                                    } else {
                                        debug!("Kademlia bootstrap started");
                                    }

                                    // Advertise ourselves on the network namespace
                                    let ns = "quilibrium-2.0.2-dusk-mainnet";
                                    let ns_hash = Sha256::digest(ns.as_bytes());
                                    let mut mh = vec![0x12u8, 0x20];
                                    mh.extend_from_slice(&ns_hash);
                                    let provider_key = libp2p::kad::RecordKey::new(&mh);
                                    if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(provider_key) {
                                        debug!(%e, "kad start_providing failed");
                                    } else {
                                        debug!("Kademlia: advertising as Quilibrium peer");
                                    }
                                }
                            }
                            libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                                let count = swarm.connected_peers().count();
                                pc_writer.store(count, std::sync::atomic::Ordering::Relaxed);
                                debug!(%peer_id, peers = count, "peer connected");
                            }
                            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                let count = swarm.connected_peers().count();
                                pc_writer.store(count, std::sync::atomic::Ordering::Relaxed);
                                debug!(%peer_id, cause = ?cause, peers = count, "peer disconnected");
                            }
                            libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                debug!(peer = ?peer_id, error = %error, "outgoing connection failed");
                            }
                            libp2p::swarm::SwarmEvent::IncomingConnectionError { error, .. } => {
                                debug!(error = %error, "incoming connection failed");
                            }
                            libp2p::swarm::SwarmEvent::ExternalAddrConfirmed { address } => {
                                let addr_str = address.to_string();
                                debug!(%addr_str, "external address confirmed (NAT-observed)");
                                let mut addrs = observed_addrs_writer.write().unwrap();
                                if !addrs.contains(&addr_str) {
                                    addrs.push(addr_str);
                                }
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(event) => match event {
                                NodeBehaviourEvent::Identify(
                                    libp2p::identify::Event::Received { peer_id, info, .. }
                                ) => {
                                    let proto_list: Vec<String> = info.protocols.iter()
                                        .map(|p| p.to_string()).collect();
                                    let routable: Vec<&Multiaddr> = info.listen_addrs.iter()
                                        .filter(|a| is_routable(a))
                                        .collect();
                                    debug!(
                                        %peer_id,
                                        agent = %info.agent_version,
                                        protos = proto_list.len(),
                                        routable = routable.len(),
                                        protocols = ?proto_list,
                                        "identified peer"
                                    );
                                    // Only feed publicly routable addresses into Kademlia.
                                    // Identify includes loopback/private addrs which would
                                    // otherwise cause thousands of failed local dials.
                                    for addr in routable {
                                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                                    }
                                    // If peer supports BlossomSub, send subscriptions
                                    let has_blossomsub = info.protocols.iter()
                                        .any(|p| p.as_ref().contains("blossomsub"));
                                    if has_blossomsub {
                                        swarm.behaviour_mut().blossomsub
                                            .send_subscriptions_to_peer(peer_id);
                                    }
                                }
                                NodeBehaviourEvent::Kademlia(event) => {
                                    match &event {
                                        libp2p::kad::Event::RoutingUpdated { peer, addresses, .. } => {
                                            let addr_count = addresses.len();
                                            let connected_count = swarm.connected_peers().count();
                                            // Only dial publicly-routable addresses.
                                            // Kademlia's routing table accumulates
                                            // peer records from FIND_NODE responses,
                                            // which often include 127.0.0.1 / RFC1918
                                            // listeners that are unreachable from us
                                            // and just generate EINVAL/ECONNREFUSED
                                            // dial spam.
                                            let routable: Vec<libp2p::Multiaddr> = addresses
                                                .iter()
                                                .filter(|a| is_routable(a))
                                                .cloned()
                                                .collect();
                                            if !routable.is_empty()
                                                && !swarm.is_connected(&peer)
                                                && connected_count < 50
                                            {
                                                debug!(
                                                    %peer,
                                                    addrs = addr_count,
                                                    routable_addrs = routable.len(),
                                                    connected = connected_count,
                                                    "kad: new peer with addresses, dialing"
                                                );
                                                // `.addresses(...)` defaults
                                                // `extend_addresses_through_behaviour=false`
                                                // — exactly what we want here so the
                                                // dial sticks to the filtered set.
                                                let opts = DialOpts::peer_id(*peer)
                                                    .addresses(routable)
                                                    .allocate_new_port()
                                                    .build();
                                                let _ = swarm.dial(opts);
                                            }
                                        }
                                        libp2p::kad::Event::OutboundQueryProgressed { result, .. } => {
                                            match result {
                                                libp2p::kad::QueryResult::Bootstrap(Ok(r)) => {
                                                    debug!(
                                                        peer = %r.peer,
                                                        remaining = r.num_remaining,
                                                        "kad: bootstrap progress"
                                                    );
                                                }
                                                libp2p::kad::QueryResult::GetClosestPeers(Ok(r)) => {
                                                    let connected_count = swarm.connected_peers().count();
                                                    let with_addrs: Vec<_> = r.peers.iter()
                                                        .filter(|p| !p.addrs.is_empty() && !swarm.is_connected(&p.peer_id))
                                                        .take(2.max(10usize.saturating_sub(connected_count)))
                                                        .collect();
                                                    for peer_info in with_addrs {
                                                        let routable: Vec<libp2p::Multiaddr> = peer_info.addrs
                                                            .iter()
                                                            .filter(|a| is_routable(a))
                                                            .cloned()
                                                            .collect();
                                                        if routable.is_empty() {
                                                            continue;
                                                        }
                                                        for addr in &routable {
                                                            swarm.behaviour_mut().kademlia
                                                                .add_address(&peer_info.peer_id, addr.clone());
                                                        }
                                                        let opts = DialOpts::peer_id(peer_info.peer_id)
                                                            .addresses(routable)
                                                            .allocate_new_port()
                                                            .build();
                                                        let _ = swarm.dial(opts);
                                                    }
                                                }
                                                libp2p::kad::QueryResult::GetProviders(Ok(
                                                    libp2p::kad::GetProvidersOk::FoundProviders { providers, .. }
                                                )) => {
                                                    debug!(
                                                        count = providers.len(),
                                                        "kad: found providers (Quilibrium peers)"
                                                    );
                                                    // Note: we don't dial provider
                                                    // peers directly here — the
                                                    // FoundProviders event doesn't
                                                    // include addresses, and
                                                    // `DialOpts::peer_id` alone would
                                                    // pull unfiltered records from
                                                    // kademlia (loopback / RFC1918)
                                                    // and spam EINVAL/ECONNREFUSED.
                                                    // We rely on the subsequent
                                                    // `RoutingUpdated` event (which
                                                    // does carry addresses) to do a
                                                    // routable-filtered dial.
                                                    let _ = providers;
                                                }
                                                libp2p::kad::QueryResult::GetProviders(Ok(
                                                    libp2p::kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. }
                                                )) => {
                                                    debug!("kad: provider search finished");
                                                }
                                                _ => {
                                                    debug!("kad: other query result");
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                NodeBehaviourEvent::Blossomsub(bss_event) => match bss_event {
                                    BlossomSubEvent::Message {
                                        message, ..
                                    } => {
                                        let _ = msg_tx.try_send(ReceivedMessage {
                                            bitmask: message.bitmask.clone(),
                                            data: message.data.clone(),
                                            from: message.from.clone(),
                                        });
                                    }
                                    BlossomSubEvent::Subscribed { peer_id, bitmask } => {
                                        debug!(%peer_id, bitmask = hex::encode(&bitmask), "peer subscribed");
                                    }
                                    BlossomSubEvent::Unsubscribed { peer_id, bitmask } => {
                                        debug!(%peer_id, bitmask = hex::encode(&bitmask), "peer unsubscribed");
                                    }
                                    BlossomSubEvent::NeedPeers { connected, .. } => {
                                        // BlossomSub needs more mesh peers — trigger DHT
                                        // discovery, but throttled. Unthrottled,
                                        // sustained NeedPeers floods opened enough
                                        // kademlia substreams per connection to hit
                                        // yamux's 8192-stream cap.
                                        let now = std::time::Instant::now();
                                        let throttled = match last_need_peers_query {
                                            Some(prev) => now.duration_since(prev) < need_peers_throttle,
                                            None => false,
                                        };
                                        if throttled {
                                            debug!(
                                                connected,
                                                "BlossomSub needs peers — DHT query throttled (recent query in flight)"
                                            );
                                        } else {
                                            debug!(connected, "BlossomSub needs peers, triggering DHT discovery");
                                            let ns = "quilibrium-2.0.2-dusk-mainnet";
                                            let ns_hash = Sha256::digest(ns.as_bytes());
                                            let mut mh = vec![0x12u8, 0x20];
                                            mh.extend_from_slice(&ns_hash);
                                            let key = libp2p::kad::RecordKey::new(&mh);
                                            swarm.behaviour_mut().kademlia.get_providers(key);
                                            last_need_peers_query = Some(now);
                                        }
                                    }
                                },
                                _ => {}
                            },
                            _ => {}
                        }
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(P2PCommand::Subscribe(bitmask)) => {
                                swarm.behaviour_mut().blossomsub.subscribe(bitmask);
                            }
                            Some(P2PCommand::Unsubscribe(bitmask)) => {
                                swarm.behaviour_mut().blossomsub.unsubscribe(&bitmask);
                            }
                            Some(P2PCommand::Publish { bitmask, data, ack }) => {
                                let result = swarm.behaviour_mut().blossomsub.publish(bitmask, data);
                                if let Err(ref e) = result {
                                    tracing::debug!(error = %e, "BlossomSub publish failed");
                                }
                                if let Some(ack) = ack {
                                    // Receiver may have dropped (caller didn't await);
                                    // treat that as best-effort fire-and-forget.
                                    let _ = ack.send(result);
                                }
                            }
                            Some(P2PCommand::BlacklistPeer(peer_id)) => {
                                debug!(%peer_id, "blacklisting peer");
                                swarm.behaviour_mut().blossomsub.blacklist_peer(peer_id);
                            }
                            Some(P2PCommand::GetPeerScore { peer, ack }) => {
                                let s = swarm.behaviour().blossomsub.scorer.score(&peer);
                                let _ = ack.send(s);
                            }
                            Some(P2PCommand::SetPeerScore { peer, score }) => {
                                swarm.behaviour_mut()
                                    .blossomsub.scorer
                                    .set_application_score(peer, score);
                            }
                            Some(P2PCommand::AddPeerScore { peer, delta }) => {
                                swarm.behaviour_mut()
                                    .blossomsub.scorer
                                    .add_application_score(peer, delta);
                            }
                            Some(P2PCommand::Reconnect { peer, ack }) => {
                                let _ = swarm.disconnect_peer_id(peer);
                                let res = match swarm.dial(peer) {
                                    Ok(()) => Ok(()),
                                    Err(e) => Err(format!("dial: {}", e)),
                                };
                                let _ = ack.send(res);
                            }
                            Some(P2PCommand::Bootstrap { ack }) => {
                                let res = swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .bootstrap()
                                    .map(|_| ())
                                    .map_err(|e| format!("kad bootstrap: {}", e));
                                let _ = ack.send(res);
                            }
                            Some(P2PCommand::DiscoverPeers { ack }) => {
                                // Trigger a Kademlia random-walk-style query
                                // by asking for closest peers to a fresh
                                // random key. `get_closest_peers` accepts
                                // any `Into<Vec<u8>>` key — we pass the
                                // 32 random bytes directly.
                                let mut key_bytes = [0u8; 32];
                                rand::Rng::fill(&mut rand::thread_rng(), &mut key_bytes);
                                swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .get_closest_peers(key_bytes.to_vec());
                                let _ = ack.send(Ok(()));
                            }
                            Some(P2PCommand::Shutdown) | None => {
                                debug!("P2P swarm shutting down");
                                break;
                            }
                        }
                    }
                }
            }
            Ok(())
        });

        Ok((
            P2PHandle { peer_id, cmd_tx, observed_addrs, peer_count },
            msg_rx,
        ))
    }
}

#[derive(Clone)]
pub struct P2PHandle {
    pub peer_id: PeerId,
    cmd_tx: mpsc::Sender<P2PCommand>,
    /// External addresses observed by the identify protocol (NAT-resolved).
    observed_addrs: std::sync::Arc<std::sync::RwLock<Vec<String>>>,
    /// Connected peer count, updated by the swarm event loop.
    peer_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl P2PHandle {
    pub async fn subscribe(&self, bitmask: Vec<u8>) {
        let _ = self.cmd_tx.send(P2PCommand::Subscribe(bitmask)).await;
    }

    pub async fn unsubscribe(&self, bitmask: Vec<u8>) {
        let _ = self.cmd_tx.send(P2PCommand::Unsubscribe(bitmask)).await;
    }

    /// Publish data to a bitmask topic. This is the send path —
    /// broadcasts the data to all peers subscribed to the bitmask.
    ///
    /// Returns `Ok(())` for empty-mesh / no-peer scenarios (BlossomSub
    /// silently buffers) and on every successful dispatch. Returns
    /// `Err` only on _true_ failures: the swarm
    /// command channel is closed (e.g. shutdown), the swarm loop has
    /// exited without acknowledging the publish, or the underlying
    /// BlossomSub behaviour rejected the message (e.g. local node not
    /// subscribed to the bitmask).
    pub async fn publish(
        &self,
        bitmask: Vec<u8>,
        data: Vec<u8>,
    ) -> quil_types::error::Result<()> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.cmd_tx
            .send(P2PCommand::Publish {
                bitmask,
                data,
                ack: Some(ack_tx),
            })
            .await
            .map_err(|_| QuilError::P2p(
                "p2p command channel closed (swarm shutting down?)".into(),
            ))?;
        match ack_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(reason)) => Err(QuilError::P2p(format!(
                "blossomsub publish failed: {}",
                reason
            ))),
            Err(_) => Err(QuilError::P2p(
                "p2p swarm dropped publish ack (event loop exited)".into(),
            )),
        }
    }

    /// Blacklist a peer — future connections will be denied.
    pub async fn blacklist_peer(&self, peer_id: PeerId) {
        let _ = self.cmd_tx.send(P2PCommand::BlacklistPeer(peer_id)).await;
    }

    /// Read the current score for a peer (computed weighted score plus
    /// any operator-applied application score). Returns `0.0` if the
    /// command channel has shut down.
    pub async fn get_peer_score(&self, peer: PeerId) -> f64 {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(P2PCommand::GetPeerScore { peer, ack: tx })
            .await
            .is_err()
        {
            return 0.0;
        }
        rx.await.unwrap_or(0.0)
    }

    /// Replace a peer's application score.
    pub async fn set_peer_score(&self, peer: PeerId, score: f64) {
        let _ = self
            .cmd_tx
            .send(P2PCommand::SetPeerScore { peer, score })
            .await;
    }

    /// Add `delta` to a peer's application score.
    pub async fn add_peer_score(&self, peer: PeerId, delta: f64) {
        let _ = self
            .cmd_tx
            .send(P2PCommand::AddPeerScore { peer, delta })
            .await;
    }

    /// Disconnect and immediately redial a peer.
    pub async fn reconnect_peer(&self, peer: PeerId) -> quil_types::error::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(P2PCommand::Reconnect { peer, ack: tx })
            .await
            .map_err(|_| QuilError::P2p("p2p command channel closed".into()))?;
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(QuilError::P2p(format!("reconnect failed: {}", e))),
            Err(_) => Err(QuilError::P2p("reconnect ack dropped".into())),
        }
    }

    /// Re-trigger Kademlia bootstrap.
    pub async fn bootstrap(&self) -> quil_types::error::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(P2PCommand::Bootstrap { ack: tx })
            .await
            .map_err(|_| QuilError::P2p("p2p command channel closed".into()))?;
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(QuilError::P2p(format!("bootstrap failed: {}", e))),
            Err(_) => Err(QuilError::P2p("bootstrap ack dropped".into())),
        }
    }

    /// Re-trigger Kademlia peer discovery via a random-walk closest-peers
    /// query.
    pub async fn discover_peers(&self) -> quil_types::error::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(P2PCommand::DiscoverPeers { ack: tx })
            .await
            .map_err(|_| QuilError::P2p("p2p command channel closed".into()))?;
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(QuilError::P2p(format!("discover_peers failed: {}", e))),
            Err(_) => Err(QuilError::P2p("discover_peers ack dropped".into())),
        }
    }

    /// Number of currently connected peers.
    pub fn peer_count(&self) -> usize {
        self.peer_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(P2PCommand::Shutdown).await;
    }

    /// Externally observed addresses (NAT-resolved) as reported by
    /// connected peers via the identify protocol.
    pub fn observed_addresses(&self) -> Vec<String> {
        self.observed_addrs.read().unwrap().clone()
    }

    /// Construct a stub `P2PHandle` for tests that exercise callers of
    /// `publish` without booting a real libp2p swarm. The handle's
    /// command-receiver task simply acks every publish with a fixed
    /// outcome (`Ok` if `fail_on_publish` is `false`, `Err` otherwise).
    /// The peer ID is a random placeholder — sufficient for code
    /// that only uses publish/peer_count.
    #[doc(hidden)]
    pub fn for_test(fail_on_publish: bool) -> Self {
        let peer_id = PeerId::random();
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<P2PCommand>(16);
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                if let P2PCommand::Publish { ack, .. } = cmd {
                    if let Some(ack) = ack {
                        let _ = ack.send(if fail_on_publish {
                            Err("test stub: simulated publish failure".to_string())
                        } else {
                            Ok(())
                        });
                    }
                }
                // other commands are silently consumed
            }
        });
        Self {
            peer_id,
            cmd_tx,
            observed_addrs: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
            peer_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

enum P2PCommand {
    Subscribe(Vec<u8>),
    Unsubscribe(Vec<u8>),
    Publish {
        bitmask: Vec<u8>,
        data: Vec<u8>,
        /// Optional oneshot used by `P2PHandle::publish` so callers can
        /// observe true publish failures (channel closed, behaviour
        /// rejected the message, etc.). Empty-mesh / no-peers scenarios
        /// remain `Ok` — the swarm event loop just buffers nothing.
        ack: Option<oneshot::Sender<std::result::Result<(), String>>>,
    },
    BlacklistPeer(PeerId),
    /// Read a peer's current score (computed + application override).
    GetPeerScore {
        peer: PeerId,
        ack: oneshot::Sender<f64>,
    },
    /// Replace a peer's application score override.
    SetPeerScore { peer: PeerId, score: f64 },
    /// Add `delta` to a peer's application score override.
    AddPeerScore { peer: PeerId, delta: f64 },
    /// Disconnect + redial a peer.
    Reconnect {
        peer: PeerId,
        ack: oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Re-trigger Kademlia bootstrap.
    Bootstrap {
        ack: oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Re-trigger Kademlia peer discovery via random walk.
    DiscoverPeers {
        ack: oneshot::Sender<std::result::Result<(), String>>,
    },
    Shutdown,
}

type KademliaBehaviour = libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>;

#[derive(NetworkBehaviour)]
struct NodeBehaviour {
    /// Connection-count cap. With no cap, observed deployments
    /// accumulated 4k+ peers on a 4 GB box — each connection brings
    /// QUIC/TCP buffers (~256-512 KB) plus libp2p multiplexer and
    /// BlossomSub mesh state. 4596 peers × ~700 KB ≈ 3.2 GB of
    /// swarm-only overhead, with continued growth as additional
    /// peers connect. Cap mirrors libp2p sample defaults.
    connection_limits: libp2p::connection_limits::Behaviour,
    kademlia: KademliaBehaviour,
    ping: libp2p::ping::Behaviour,
    identify: libp2p::identify::Behaviour,
    blossomsub: BlossomSubBehaviour,
    autonat: libp2p::autonat::Behaviour,
}

/// Compute the BlossomSub message ID: `[0x01, SHA256(data)...]` —
/// 33 bytes, leading byte 0x01. Other implementations that emit the
/// 32-byte digest alone would compute non-matching dedup IDs for the
/// same payload, corrupting IHAVE/IWANT gossip.
pub fn message_id(data: &[u8]) -> Vec<u8> {
    let mut id = Vec::with_capacity(33);
    id.push(0x01);
    id.extend_from_slice(&Sha256::digest(data));
    id
}

/// Returns `true` if the multiaddr's IP component is publicly routable
/// (not loopback, link-local, or private). Identify shares all listen
/// addresses including localhost/private — we must drop those before adding
/// them to Kademlia/dial, otherwise we generate thousands of useless dials
/// against our own machine and rate-limit ourselves out of the network.
fn is_routable(addr: &Multiaddr) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_loopback() || ip.is_link_local() || ip.is_private()
                    || ip == Ipv4Addr::UNSPECIFIED || ip.is_broadcast()
                    || ip.is_documentation() || ip.is_multicast()
                {
                    return false;
                }
                return true;
            }
            Protocol::Ip6(ip) => {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
                    || ip == Ipv6Addr::UNSPECIFIED
                    // unique-local fc00::/7
                    || (ip.segments()[0] & 0xfe00) == 0xfc00
                    // link-local fe80::/10
                    || (ip.segments()[0] & 0xffc0) == 0xfe80
                {
                    return false;
                }
                return true;
            }
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                return true;
            }
            _ => continue,
        }
    }
    false
}
