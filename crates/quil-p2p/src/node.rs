use std::time::Duration;

use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{Multiaddr, PeerId, SwarmBuilder};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::debug;

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

        let bootstrap_peers = config
            .bootstrap_peers
            .iter()
            .filter_map(|addr_str| {
                let addr: Multiaddr = addr_str.parse().ok()?;
                let peer_id = addr.iter().find_map(|p| match p {
                    Protocol::P2p(id) => Some(id),
                    _ => None,
                })?;
                Some((peer_id, addr))
            })
            .collect();

        Ok(Self {
            peer_id,
            keypair,
            bootstrap_peers,
            network: config.network,
            generated_key_hex,
        })
    }

    /// Start the P2P swarm.
    pub async fn start(
        self,
        listen_addr: &str,
    ) -> quil_types::error::Result<(P2PHandle, mpsc::Receiver<ReceivedMessage>)> {
        let listen_multiaddr: Multiaddr = listen_addr
            .parse()
            .map_err(|e| QuilError::P2p(format!("invalid listen address: {}", e)))?;

        let network = self.network;

        let mut swarm = SwarmBuilder::with_existing_identity(self.keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
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
                let mut blossomsub = BlossomSubBehaviour::new();
                // Set signing identity so published messages pass Go's
                // StrictSign verification (WithStrictSignatureVerification(true)).
                let local_peer_id = key.public().to_peer_id();
                blossomsub.set_signing_identity(local_peer_id, key.clone());
                // Pre-subscribe to global bitmasks so subscription RPCs
                // are sent as soon as peers connect (before command channel)
                blossomsub.subscribe(vec![0x00]);                   // GLOBAL_CONSENSUS
                blossomsub.subscribe(vec![0x00, 0x00]);             // GLOBAL_FRAME
                blossomsub.subscribe(vec![0x00, 0x00, 0x00]);       // GLOBAL_PROVER
                blossomsub.subscribe(vec![0x00, 0x00, 0x00, 0x00]); // GLOBAL_PEER_INFO
                blossomsub.subscribe(vec![0u8; 16]);                // GLOBAL_ALERT
                let autonat = libp2p::autonat::Behaviour::new(
                    local_peer_id,
                    libp2p::autonat::Config::default(),
                );
                Ok(NodeBehaviour { kademlia, ping, identify, blossomsub, autonat })
            })
            .map_err(|e| QuilError::P2p(format!("behaviour: {}", e)))?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(120))
                    .with_max_negotiating_inbound_streams(32)
            })
            .build();

        // Listen on QUIC and TCP (use configured or default port)
        let port = listen_multiaddr.to_string()
            .split('/')
            .filter_map(|s| s.parse::<u16>().ok())
            .last()
            .unwrap_or(8336);

        let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", port)
            .parse()
            .unwrap();
        match swarm.listen_on(quic_addr.clone()) {
            Ok(_) => debug!(%quic_addr, "QUIC listener starting"),
            Err(e) => debug!(error = format!("{:?}", e), "failed to start QUIC listener"),
        }

        let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port)
            .parse()
            .unwrap();
        match swarm.listen_on(tcp_addr.clone()) {
            Ok(_) => debug!(%tcp_addr, "TCP listener starting"),
            Err(e) => debug!(error = format!("{:?}", e), "failed to start TCP listener"),
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

        tokio::spawn(async move {
            debug!("P2P swarm event loop started");
            let mut bootstrapped = false;
            let mut discovery_timer = tokio::time::interval(Duration::from_secs(30));
            discovery_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut discovery_count = 0u32;
            loop {
                tokio::select! {
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
                                        let _ = swarm.dial(bp_addr.clone());
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
                                        if let Err(e) = swarm.dial(bp_addr.clone()) {
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
                                    // (mirrors Go's util.Advertise)
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
                                            if addr_count > 0
                                                && !swarm.is_connected(&peer)
                                                && connected_count < 50
                                            {
                                                debug!(
                                                    %peer,
                                                    addrs = addr_count,
                                                    connected = connected_count,
                                                    "kad: new peer with addresses, dialing"
                                                );
                                                let _ = swarm.dial(*peer);
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
                                                        for addr in peer_info.addrs.iter().filter(|a| is_routable(a)) {
                                                            swarm.behaviour_mut().kademlia
                                                                .add_address(&peer_info.peer_id, addr.clone());
                                                        }
                                                        let _ = swarm.dial(peer_info.peer_id);
                                                    }
                                                }
                                                libp2p::kad::QueryResult::GetProviders(Ok(
                                                    libp2p::kad::GetProvidersOk::FoundProviders { providers, .. }
                                                )) => {
                                                    debug!(
                                                        count = providers.len(),
                                                        "kad: found providers (Quilibrium peers)"
                                                    );
                                                    let local = *swarm.local_peer_id();
                                                    for provider_peer in providers.iter() {
                                                        if *provider_peer != local && !swarm.is_connected(provider_peer) {
                                                            let _ = swarm.dial(*provider_peer);
                                                        }
                                                    }
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
                                        // BlossomSub needs more mesh peers — trigger DHT discovery
                                        debug!(connected, "BlossomSub needs peers, triggering DHT discovery");
                                        let ns = "quilibrium-2.0.2-dusk-mainnet";
                                        let ns_hash = Sha256::digest(ns.as_bytes());
                                        let mut mh = vec![0x12u8, 0x20];
                                        mh.extend_from_slice(&ns_hash);
                                        let key = libp2p::kad::RecordKey::new(&mh);
                                        swarm.behaviour_mut().kademlia.get_providers(key);
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
                            Some(P2PCommand::Publish { bitmask, data }) => {
                                if let Err(e) = swarm.behaviour_mut().blossomsub.publish(bitmask, data) {
                                    tracing::debug!(error = %e, "BlossomSub publish failed");
                                }
                            }
                            Some(P2PCommand::BlacklistPeer(peer_id)) => {
                                debug!(%peer_id, "blacklisting peer");
                                swarm.behaviour_mut().blossomsub.blacklist_peer(peer_id);
                            }
                            Some(P2PCommand::Shutdown) | None => {
                                debug!("P2P swarm shutting down");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok((P2PHandle { peer_id, cmd_tx, observed_addrs, peer_count }, msg_rx))
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
    pub async fn publish(&self, bitmask: Vec<u8>, data: Vec<u8>) {
        let _ = self.cmd_tx.send(P2PCommand::Publish { bitmask, data }).await;
    }

    /// Blacklist a peer — future connections will be denied.
    pub async fn blacklist_peer(&self, peer_id: PeerId) {
        let _ = self.cmd_tx.send(P2PCommand::BlacklistPeer(peer_id)).await;
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
}

enum P2PCommand {
    Subscribe(Vec<u8>),
    Unsubscribe(Vec<u8>),
    Publish { bitmask: Vec<u8>, data: Vec<u8> },
    BlacklistPeer(PeerId),
    Shutdown,
}

type KademliaBehaviour = libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>;

#[derive(NetworkBehaviour)]
struct NodeBehaviour {
    kademlia: KademliaBehaviour,
    ping: libp2p::ping::Behaviour,
    identify: libp2p::identify::Behaviour,
    blossomsub: BlossomSubBehaviour,
    autonat: libp2p::autonat::Behaviour,
}

/// Compute message ID as SHA-256 of data (matching Go implementation).
pub fn message_id(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
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
