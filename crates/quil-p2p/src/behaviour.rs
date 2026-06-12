//! BlossomSub `NetworkBehaviour` implementation.
//!
//! Uses a custom `BlossomSubHandler` for each connection to exchange
//! protobuf RPCs over bidirectional libp2p streams.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::task::{Context, Poll};
use std::time::Instant;

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use tracing::{debug, info, trace, warn};

use crate::blossomsub::CompositeMeshEntry;
use crate::handler::{BlossomSubHandler, HandlerIn, HandlerOut};
use crate::protocol::{self, pb};

/// Result of a message validation callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// Message is valid — accept and forward.
    Accept,
    /// Message is invalid — reject and penalise the sender.
    Reject,
    /// Message should be silently ignored (neither forwarded nor penalised).
    Ignore,
}

/// Events emitted by the BlossomSub behaviour to the swarm.
#[derive(Debug)]
pub enum BlossomSubEvent {
    /// A message was received from the network.
    Message {
        propagation_source: PeerId,
        message_id: Vec<u8>,
        message: pb::Message,
    },
    /// A peer subscribed to a bitmask.
    Subscribed {
        peer_id: PeerId,
        bitmask: Vec<u8>,
    },
    /// A peer unsubscribed from a bitmask.
    Unsubscribed {
        peer_id: PeerId,
        bitmask: Vec<u8>,
    },
    /// We need more peers for our subscriptions — trigger DHT discovery.
    NeedPeers {
        subscriptions: Vec<Vec<u8>>,
        connected: usize,
    },
}

/// Classification of a composite-mesh peer. "Same" peers are subscribed to
/// every slice of the composite; "Broker" peers are subscribed to at least
/// one but not all — they intentionally bridge non-subscribed slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerClass {
    Same,
    Broker,
}

/// The BlossomSub `NetworkBehaviour`.
pub struct BlossomSubBehaviour {
    /// Our subscriptions.
    subscriptions: HashSet<Vec<u8>>,
    /// Known peer subscriptions.
    peer_subscriptions: HashMap<PeerId, HashSet<Vec<u8>>>,
    /// Connected peers → connection IDs.
    connected_peers: HashMap<PeerId, Vec<ConnectionId>>,
    /// Per-bitmask mesh.
    mesh: HashMap<Vec<u8>, HashSet<PeerId>>,
    /// Pending events to emit.
    events: VecDeque<ToSwarm<BlossomSubEvent, HandlerIn>>,
    /// Seen message IDs (dedup). LRU so the OLDEST entry evicts on
    /// insert when full, instead of clearing the whole set. The
    /// previous `HashSet::clear()` on overflow re-admitted any
    /// message still propagating in the mesh, causing each receiver
    /// to re-forward to its D mesh peers and burning bandwidth.
    seen_messages: lru::LruCache<Vec<u8>, ()>,
    /// Per-peer record of which message IDs that peer has announced
    /// `IDONTWANT` for. We skip forwarding those messages to them.
    /// Bounded per-peer LRU to cap memory under adversarial input.
    peer_idontwant: HashMap<PeerId, lru::LruCache<Vec<u8>, ()>>,
    /// Message cache for IHAVE/IWANT.
    mcache: crate::blossomsub::MessageCache,
    /// Last heartbeat.
    last_heartbeat: Instant,
    /// Pending subscription RPCs to send on new connections.
    pending_subscribe_rpc: Option<Vec<u8>>,
    /// Local peer ID for message signing.
    local_peer_id: Option<PeerId>,
    /// Libp2p signing keypair for message signing.
    signing_keypair: Option<libp2p::identity::Keypair>,
    /// Sequence number counter for published messages.
    seqno_counter: std::sync::atomic::AtomicU64,
    /// Peer blacklist — connections from/to these peers are denied.
    blacklisted_peers: HashSet<PeerId>,
    /// Peer scores for mesh management decisions.
    pub scorer: crate::scoring::PeerScorer,
    /// Fanout: bitmasks we publish to but aren't subscribed to.
    fanout: HashMap<Vec<u8>, HashSet<PeerId>>,
    /// Last fanout publish time per bitmask.
    fanout_last_pub: HashMap<Vec<u8>, Instant>,
    /// Backoff tracking: (peer, bitmask) → backoff expiry.
    backoffs: HashMap<(PeerId, Vec<u8>), Instant>,
    /// Outbound peers per bitmask (for D_OUT enforcement).
    outbound_peers: HashMap<Vec<u8>, HashSet<PeerId>>,
    /// Heartbeat tick counter (for opportunistic grafting).
    heartbeat_ticks: u64,
    /// Direct (always-connected) peers — kept in mesh unconditionally.
    direct_peers: HashSet<PeerId>,
    /// Per-bitmask message validators. Called before accepting inbound messages.
    validators: HashMap<Vec<u8>, Box<dyn Fn(&PeerId, &[u8]) -> ValidationResult + Send + Sync>>,
    /// Composite meshes for multi-bit bitmasks. Key = full (unspliced) bitmask.
    composites: HashMap<Vec<u8>, CompositeMeshEntry>,
    /// Reverse index: slice bitmask -> list of composite bitmask keys managing it.
    slice_to_composite: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    /// Negotiated protocol ID. Mainnet uses `/blossomsub/2.1.0`;
    /// other networks suffix `-network-N` (e.g. testnet → `-network-1`).
    protocol: libp2p::StreamProtocol,
    /// Runtime-tunable mesh/gossip parameters. Replaces direct
    /// reads from `crate::params::*` so operators can override
    /// timings via `P2PConfig` (heartbeat interval, prune backoff,
    /// history length, etc.) without a rebuild.
    pub(crate) params: crate::BlossomsubParams,
    /// Pending IWANT requests: msg_id → (peer asked, sent_at,
    /// other peers that also advertised this message). On
    /// heartbeat, if an entry has been pending past
    /// `params.iwant_followup_time`, retry from another advertiser
    /// if one exists, otherwise drop the entry and let the message
    /// be considered unrecoverable through gossip (consensus-layer
    /// rebroadcast remains the second-line recovery).
    pending_iwants: HashMap<Vec<u8>, PendingIwant>,
}

/// Per-message IWANT tracking entry.
pub(crate) struct PendingIwant {
    /// Peer we sent the IWANT to.
    pub asked: PeerId,
    /// When the IWANT was sent.
    pub sent_at: Instant,
    /// Other peers that also advertised this message (from IHAVE).
    /// On follow-up timeout we pop from here for the retry.
    pub other_advertisers: Vec<PeerId>,
    /// Bitmask for the message — needed to source from
    /// `peer_subscriptions` if `other_advertisers` is exhausted.
    pub bitmask: Vec<u8>,
}

impl BlossomSubBehaviour {
    pub fn new(network: u8) -> Self {
        Self::with_params(network, crate::BlossomsubParams::default())
    }

    /// Construct with custom mesh/gossip parameters. Use this
    /// (typically with `BlossomsubParams::from_p2p_config(...)`) when
    /// runtime overrides from operator config should apply.
    pub fn with_params(network: u8, params: crate::BlossomsubParams) -> Self {
        let mcache_len = params.history_length;
        let mcache_gossip = params.history_gossip;
        Self {
            subscriptions: HashSet::new(),
            peer_subscriptions: HashMap::new(),
            connected_peers: HashMap::new(),
            mesh: HashMap::new(),
            events: VecDeque::new(),
            // Capacity sized to comfortably cover a full mcache window
            // worth of distinct messages at peak rate without forcing
            // eviction. Go's pubsub uses time-based eviction; the LRU
            // size here is the rough equivalent for a steady-state
            // dedup horizon. 10k entries ≈ a few minutes of traffic at
            // typical message rates and keeps memory bounded.
            seen_messages: lru::LruCache::new(
                std::num::NonZeroUsize::new(10_000).unwrap(),
            ),
            peer_idontwant: HashMap::new(),
            mcache: crate::blossomsub::MessageCache::new(
                mcache_len,
                mcache_gossip,
            ),
            last_heartbeat: Instant::now(),
            pending_subscribe_rpc: None,
            local_peer_id: None,
            signing_keypair: None,
            seqno_counter: std::sync::atomic::AtomicU64::new(
                rand::random::<u64>(),
            ),
            blacklisted_peers: HashSet::new(),
            scorer: crate::scoring::PeerScorer::default(),
            fanout: HashMap::new(),
            fanout_last_pub: HashMap::new(),
            backoffs: HashMap::new(),
            outbound_peers: HashMap::new(),
            heartbeat_ticks: 0,
            direct_peers: HashSet::new(),
            validators: HashMap::new(),
            composites: HashMap::new(),
            slice_to_composite: HashMap::new(),
            protocol: crate::protocol::stream_protocol_for_network(network),
            params,
            pending_iwants: HashMap::new(),
        }
    }

    /// Add a peer to the blacklist. Existing connections are not closed,
    /// but new connections will be denied.
    pub fn blacklist_peer(&mut self, peer: PeerId) {
        self.blacklisted_peers.insert(peer);
    }

    /// Add a direct peer. Direct peers are always grafted into every mesh
    /// and reconnected if disconnected.
    pub fn add_direct_peer(&mut self, peer: PeerId) {
        self.direct_peers.insert(peer);
    }

    /// Register a message validator for a bitmask. The validator is called
    /// for every inbound message on that bitmask before it is accepted or
    /// forwarded. Only one validator per bitmask; a second call replaces the
    /// previous one.
    pub fn register_validator(
        &mut self,
        bitmask: Vec<u8>,
        validator: impl Fn(&PeerId, &[u8]) -> ValidationResult + Send + Sync + 'static,
    ) {
        self.validators.insert(bitmask, Box::new(validator));
    }

    /// Subscribe to a bitmask.
    pub fn subscribe(&mut self, bitmask: Vec<u8>) {
        if self.subscriptions.insert(bitmask.clone()) {
            info!(bitmask = hex::encode(&bitmask), "subscribed to bitmask");
            self.rebuild_subscribe_rpc();

            // Establish composite mesh state for multi-slice bitmasks.
            // Single-slice bitmasks fall through to the simple per-slice
            // mesh maintenance in `heartbeat`.
            let slices = crate::bitmask::slice_bitmask(&bitmask);
            if slices.len() > 1 {
                self.join_composite(bitmask.clone(), slices);
            }

            // Send to all connected peers
            if let Some(rpc_data) = &self.pending_subscribe_rpc {
                let peers: Vec<(PeerId, ConnectionId)> = self
                    .connected_peers
                    .iter()
                    .filter_map(|(p, conns)| conns.first().map(|c| (*p, *c)))
                    .collect();
                for (peer, conn) in peers {
                    let _ = conn;
                    self.events.push_back(ToSwarm::NotifyHandler {
                        peer_id: peer,
                        handler: NotifyHandler::Any,
                        event: HandlerIn {
                            rpc_data: rpc_data.clone(),
                        },
                    });
                }
            }
        }
    }

    /// Set the signing identity for message publishing. Must be called
    /// before publish() for messages to be accepted by Go nodes with
    /// strict signature verification.
    pub fn set_signing_identity(&mut self, peer_id: PeerId, keypair: libp2p::identity::Keypair) {
        self.local_peer_id = Some(peer_id);
        self.signing_keypair = Some(keypair);
    }

    /// Publish data to a bitmask topic. Sends the message to all mesh
    /// peers for this bitmask, adds to message cache, and marks as seen.
    /// Messages are signed with the libp2p identity key for Go compatibility.
    pub fn publish(&mut self, bitmask: Vec<u8>, data: Vec<u8>) -> std::result::Result<(), String> {
        if !self.subscriptions.contains(&bitmask) {
            return Err(format!(
                "not subscribed to bitmask {}",
                hex::encode(&bitmask)
            ));
        }

        let msg_id = crate::node::message_id(&data);

        // `LruCache::put` returns `Some(old_value)` when overwriting
        // an existing key — for dedup we treat "already present" as
        // "skip". `peek` is a non-promoting read; `put` promotes on
        // insert.
        if self.seen_messages.contains(&msg_id) {
            return Ok(());
        }
        self.seen_messages.put(msg_id.clone(), ());

        // Build the protobuf message with signing fields.
        // BlossomSub StrictSign requires: from, seqno, signature, key.
        let seqno = self.seqno_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_be_bytes()
            .to_vec();

        let from = self.local_peer_id
            .as_ref()
            .map(|p| p.to_bytes())
            .unwrap_or_default();

        let mut msg = pb::Message {
            from: from.clone(),
            data: data.clone(),
            bitmask: bitmask.clone(),
            seqno: seqno.clone(),
            signature: Vec::new(),
            key: Vec::new(),
        };

        // Sign the message if we have a keypair.
        // Format: sign("libp2p-pubsub:" + protobuf_marshal(msg_without_sig_and_key))
        if let Some(ref keypair) = self.signing_keypair {
            // Marshal message without signature and key for signing
            let mut sign_msg = msg.clone();
            sign_msg.signature = Vec::new();
            sign_msg.key = Vec::new();
            let marshalled = {
                use prost::Message;
                let mut buf = Vec::new();
                sign_msg.encode(&mut buf).ok();
                buf
            };

            let mut to_sign = Vec::with_capacity(14 + marshalled.len());
            to_sign.extend_from_slice(b"libp2p-pubsub:");
            to_sign.extend_from_slice(&marshalled);

            match keypair.sign(&to_sign) {
                Ok(sig) => {
                    msg.signature = sig.clone();
                    let encoded_key = keypair.public().encode_protobuf();
                    msg.key = encoded_key.clone();
                    tracing::debug!(
                        sig_len = sig.len(),
                        key_len = encoded_key.len(),
                        from_len = msg.from.len(),
                        seqno_len = msg.seqno.len(),
                        marshal_len = marshalled.len(),
                        "signed pubsub message"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to sign pubsub message");
                }
            }
        }

        // Add to message cache for IHAVE/IWANT
        self.mcache.put(msg_id, bitmask.clone(), data, libp2p::PeerId::random());

        // Send to all mesh peers for this bitmask
        let rpc = crate::protocol::publish_rpc(vec![msg]);
        let encoded = crate::protocol::encode_rpc(&rpc);

        if let Some(peers) = self.mesh.get(&bitmask) {
            for &peer in peers {
                self.events.push_back(ToSwarm::NotifyHandler {
                    peer_id: peer,
                    handler: NotifyHandler::Any,
                    event: HandlerIn { rpc_data: encoded.clone() },
                });
            }
            tracing::debug!(
                bitmask = hex::encode(&bitmask),
                mesh_peers = peers.len(),
                "published to mesh"
            );
        }

        Ok(())
    }

    pub fn unsubscribe(&mut self, bitmask: &[u8]) {
        if self.subscriptions.remove(bitmask) {
            self.mesh.remove(bitmask);
            // Tear down composite state (if any) for multi-slice bitmasks.
            self.leave_composite(bitmask);
            self.rebuild_subscribe_rpc();
        }
    }

    fn rebuild_subscribe_rpc(&mut self) {
        if self.subscriptions.is_empty() {
            self.pending_subscribe_rpc = None;
        } else {
            let bitmasks: Vec<Vec<u8>> = self.subscriptions.iter().cloned().collect();
            let rpc = protocol::subscribe_rpc(&bitmasks);
            self.pending_subscribe_rpc = Some(protocol::encode_rpc(&rpc));
        }
    }

    /// Handle an RPC received from a peer's handler.
    pub(crate) fn handle_rpc(&mut self, peer: PeerId, rpc: pb::Rpc) {
        // Subscriptions
        for sub in &rpc.subscriptions {
            let subs = self.peer_subscriptions.entry(peer).or_default();
            if sub.subscribe {
                // Per-peer subscription cap. Without this a peer can
                // spam SUBSCRIBE for thousands of fake bitmasks and
                // balloon `peer_subscriptions`. 256 is well above any
                // reasonable composite-mesh slice fan-out (typical
                // node subscribes to ~1-64 bitmasks).
                const MAX_SUBSCRIPTIONS_PER_PEER: usize = 256;
                if !subs.contains(&sub.bitmask)
                    && subs.len() >= MAX_SUBSCRIPTIONS_PER_PEER
                {
                    debug!(
                        %peer,
                        bitmask = hex::encode(&sub.bitmask),
                        existing = subs.len(),
                        cap = MAX_SUBSCRIPTIONS_PER_PEER,
                        "rejecting subscription: per-peer cap reached"
                    );
                    self.scorer.add_penalty(&peer, 1.0);
                    continue;
                }
                if subs.insert(sub.bitmask.clone()) {
                    // INFO-level log if peer subscribes to a bitmask we also
                    // subscribe to (likely a master/validator).
                    if self.subscriptions.contains(&sub.bitmask) {
                        debug!(
                            %peer,
                            bitmask = hex::encode(&sub.bitmask),
                            "MATCH: peer subscribed to one of our bitmasks (likely master)"
                        );
                    } else {
                        debug!(
                            %peer,
                            bitmask = hex::encode(&sub.bitmask),
                            "peer subscribed"
                        );
                    }
                    self.events.push_back(ToSwarm::GenerateEvent(
                        BlossomSubEvent::Subscribed {
                            peer_id: peer,
                            bitmask: sub.bitmask.clone(),
                        },
                    ));
                }
            } else if subs.remove(&sub.bitmask) {
                self.events.push_back(ToSwarm::GenerateEvent(
                    BlossomSubEvent::Unsubscribed {
                        peer_id: peer,
                        bitmask: sub.bitmask.clone(),
                    },
                ));
            }
        }

        // Published messages
        for msg in rpc.publish {
            let msg_id = crate::node::message_id(&msg.data);
            let is_subbed = self.subscriptions.contains(&msg.bitmask);
            debug!(
                %peer,
                bitmask = hex::encode(&msg.bitmask),
                bytes = msg.data.len(),
                subbed = is_subbed,
                "received published message"
            );
            if self.seen_messages.contains(&msg_id) {
                continue; // Dedup
            }
            self.seen_messages.put(msg_id.clone(), ());
            // Message arrived — clear any pending IWANT for it so
            // the heartbeat doesn't retry uselessly.
            self.pending_iwants.remove(&msg_id);

            // Run per-bitmask validator if registered.
            if let Some(validator) = self.validators.get(&msg.bitmask) {
                match validator(&peer, &msg.data) {
                    ValidationResult::Reject => {
                        debug!(
                            %peer,
                            bitmask = hex::encode(&msg.bitmask),
                            "message rejected by validator"
                        );
                        self.scorer.add_invalid(&peer, &msg.bitmask);
                        continue;
                    }
                    ValidationResult::Ignore => {
                        trace!(
                            %peer,
                            bitmask = hex::encode(&msg.bitmask),
                            "message ignored by validator"
                        );
                        continue;
                    }
                    ValidationResult::Accept => {} // fall through
                }
            }

            if self.subscriptions.contains(&msg.bitmask) {
                self.mcache.put(
                    msg_id.clone(),
                    msg.bitmask.clone(),
                    msg.data.clone(),
                    peer,
                );
                self.events.push_back(ToSwarm::GenerateEvent(
                    BlossomSubEvent::Message {
                        propagation_source: peer,
                        message_id: msg_id.clone(),
                        message: msg.clone(),
                    },
                ));
            }

            // Forward to mesh peers (excluding source and peers that
            // have announced IDONTWANT for this message id).
            let msg_size = msg.data.len();
            let msg_bitmask = msg.bitmask.clone();
            if let Some(mesh_peers) = self.mesh.get(&msg_bitmask) {
                let forward_rpc = protocol::publish_rpc(vec![msg]);
                let encoded = protocol::encode_rpc(&forward_rpc);
                let idontwant_peers: Vec<PeerId> = mesh_peers
                    .iter()
                    .filter(|p| **p != peer)
                    .filter(|p| {
                        self.peer_idontwant
                            .get(p)
                            .map(|c| c.contains(&msg_id))
                            .unwrap_or(false)
                    })
                    .copied()
                    .collect();
                let targets: Vec<(PeerId, ConnectionId)> = mesh_peers
                    .iter()
                    .filter(|p| **p != peer)
                    .filter(|p| !idontwant_peers.contains(p))
                    .filter_map(|p| {
                        self.connected_peers
                            .get(p)
                            .and_then(|c| c.first())
                            .map(|c| (*p, *c))
                    })
                    .collect();
                if !idontwant_peers.is_empty() {
                    tracing::trace!(
                        bitmask = hex::encode(&msg_bitmask),
                        skipped = idontwant_peers.len(),
                        "suppressed forward to IDONTWANT peers",
                    );
                }
                for (target, conn) in targets {
                    self.events.push_back(ToSwarm::NotifyHandler {
                        peer_id: target,
                        handler: NotifyHandler::Any,
                        event: HandlerIn {
                            rpc_data: encoded.clone(),
                        },
                    });
                }

                // Announce IDONTWANT to remaining mesh peers (other
                // than the source we just received from) for large
                // messages, so future copies on the gossip / IHAVE
                // path don't get re-pushed to us. Per BlossomSub
                // 2.0+: only emit when payload size exceeds the
                // configured threshold — small messages don't
                // benefit from the round-trip avoidance.
                if msg_size >= self.params.idont_want_message_threshold {
                    let idontwant_targets: Vec<(PeerId, ConnectionId)> = mesh_peers
                        .iter()
                        .filter(|p| **p != peer)
                        .filter_map(|p| {
                            self.connected_peers
                                .get(p)
                                .and_then(|c| c.first())
                                .map(|c| (*p, *c))
                        })
                        .collect();
                    if !idontwant_targets.is_empty() {
                        let idontwant_rpc = pb::Rpc {
                            subscriptions: Vec::new(),
                            publish: Vec::new(),
                            control: Some(pb::ControlMessage {
                                ihave: Vec::new(),
                                iwant: Vec::new(),
                                graft: Vec::new(),
                                prune: Vec::new(),
                                idontwant: vec![pb::ControlIDontWant {
                                    message_i_ds: vec![msg_id.clone()],
                                }],
                            }),
                        };
                        let encoded_idontwant = protocol::encode_rpc(&idontwant_rpc);
                        for (target, conn) in idontwant_targets {
                            self.events.push_back(ToSwarm::NotifyHandler {
                                peer_id: target,
                                handler: NotifyHandler::Any,
                                event: HandlerIn {
                                    rpc_data: encoded_idontwant.clone(),
                                },
                            });
                        }
                    }
                }
            }
        }

        // Control messages
        if let Some(control) = rpc.control {
            let mut composite_touched = false;
            // Cache the score once per peer per handle_rpc call — Go's
            // handleGraft does the same (line 984). The score doesn't
            // change mid-iteration over a single peer's GRAFT batch.
            let peer_score = self.scorer.score(&peer);
            let now = Instant::now();
            for graft in &control.graft {
                // A GRAFT is addressed to a slice bitmask. Accept it if
                // either (a) we are subscribed to that exact bitmask
                // (single-slice case) or (b) the slice is composite-managed
                // (multi-slice case — slice mesh exists because
                // rebuild_slice_meshes populated it).
                let is_subscribed = self.subscriptions.contains(&graft.bitmask);
                let is_composite_slice =
                    self.slice_to_composite.contains_key(&graft.bitmask);
                if !is_subscribed && !is_composite_slice {
                    // Spam hardening: ignore GRAFTs for unknown bitmasks.
                    // Mirrors Go's `handleGraft` early continue at
                    // blossomsub.go:995-1000.
                    continue;
                }

                // We don't GRAFT to/from direct peers — they're always
                // pinned in the mesh by config. A GRAFT from a direct
                // peer is a misconfiguration; warn and ignore (Go:
                // blossomsub.go:1008-1017).
                if self.direct_peers.contains(&peer) {
                    warn!(%peer, bitmask = hex::encode(&graft.bitmask),
                        "GRAFT: ignoring request from direct peer");
                    continue;
                }

                // Backoff enforcement: a previously-PRUNE'd peer must
                // wait `prune_backoff` before re-GRAFTing. Re-GRAFT
                // attempts add a behavioural penalty so repeat
                // offenders get scored down. Mirrors Go's
                // blossomsub.go:1020-1037.
                if let Some(&expire) = self.backoffs.get(&(peer, graft.bitmask.clone())) {
                    if now < expire {
                        debug!(%peer, bitmask = hex::encode(&graft.bitmask),
                            "GRAFT: ignoring backed-off peer");
                        self.scorer.add_penalty(&peer, 1.0);
                        // Refresh the backoff so the offender doesn't
                        // get a free retry window.
                        self.backoffs.insert(
                            (peer, graft.bitmask.clone()),
                            now + self.params.prune_backoff,
                        );
                        continue;
                    }
                }

                // Score gate: never GRAFT a peer with negative score.
                // Mirrors Go's blossomsub.go:1040-1050.
                if peer_score < 0.0 {
                    debug!(%peer, score = peer_score,
                        bitmask = hex::encode(&graft.bitmask),
                        "GRAFT: ignoring negative-score peer");
                    self.backoffs.insert(
                        (peer, graft.bitmask.clone()),
                        now + self.params.prune_backoff,
                    );
                    continue;
                }

                // Dhi cap: refuse new mesh entries once the slice is
                // saturated, unless the peer is one we dialed out to
                // (defense against love-bombing / sybil takeover).
                // Mirrors Go's blossomsub.go:1086-1093.
                let mesh_len = self.mesh.get(&graft.bitmask).map(|m| m.len()).unwrap_or(0);
                let is_outbound = self
                    .outbound_peers
                    .get(&graft.bitmask)
                    .map_or(false, |s| s.contains(&peer));
                if mesh_len >= self.params.d_hi && !is_outbound {
                    debug!(%peer, mesh_len, d_hi = self.params.d_hi,
                        bitmask = hex::encode(&graft.bitmask),
                        "GRAFT: at Dhi for inbound peer");
                    self.backoffs.insert(
                        (peer, graft.bitmask.clone()),
                        now + self.params.prune_backoff,
                    );
                    continue;
                }

                // Subnet-diversity gate. Cap inbound GRAFTs per
                // /24 (v4) or /48 (v6). A Sybil attacker with many
                // PeerIds across one provider subnet can love-bomb
                // a victim with simultaneous GRAFTs; the Dhi gate
                // above only catches them once the slice is at the
                // upper bound. The per-subnet cap fires earlier,
                // before mesh saturation. Inbound only — outbound
                // peers were dialed by us, so they're not Sybil
                // proxies regardless of subnet.
                if !is_outbound {
                    let mesh_set: HashSet<PeerId> = self
                        .mesh
                        .get(&graft.bitmask)
                        .cloned()
                        .unwrap_or_default();
                    if self.graft_would_violate_subnet_cap(&mesh_set, &peer) {
                        debug!(
                            %peer,
                            bitmask = hex::encode(&graft.bitmask),
                            "GRAFT: rejected — subnet cap reached"
                        );
                        self.backoffs.insert(
                            (peer, graft.bitmask.clone()),
                            now + self.params.prune_backoff,
                        );
                        continue;
                    }
                }

                // All gates passed — add to the simple slice mesh.
                // The per-slice mesh map is used for forwarding on
                // the wire.
                self.mesh
                    .entry(graft.bitmask.clone())
                    .or_default()
                    .insert(peer);
                debug!(%peer, bitmask = hex::encode(&graft.bitmask), "grafted");

                // If this slice is managed by one or more composites,
                // classify the peer as same/broker based on its
                // subscription set.
                if let Some(comp_keys) =
                    self.slice_to_composite.get(&graft.bitmask).cloned()
                {
                    for ck in &comp_keys {
                        let cls = self.classify_peer(&peer, ck);
                        if let Some(comp) = self.composites.get_mut(ck) {
                            match cls {
                                PeerClass::Same => {
                                    comp.broker.remove(&peer);
                                    comp.same.insert(peer);
                                }
                                PeerClass::Broker => {
                                    if !comp.same.contains(&peer) {
                                        comp.broker.insert(peer);
                                    }
                                }
                            }
                        }
                    }
                    composite_touched = true;
                }
            }
            for prune in &control.prune {
                // Is this PRUNE for a composite-managed slice? Slice
                // PRUNEs are legitimate composite-rebalancing
                // signals (same → broker demotion); they aren't
                // flap-graft attacks. Skip the backoff install for
                // those so subsequent slice GRAFTs (which legitimately
                // promote broker back to same when the peer is fully
                // subscribed) aren't penalty-blocked.
                let composite_managed =
                    self.slice_to_composite.contains_key(&prune.bitmask);

                if !composite_managed {
                    // Honor the remote peer's `backoff` hint: install
                    // a backoff entry so we don't try to re-GRAFT
                    // them until the suggested window expires.
                    // Without this, an attacker can prune us and
                    // immediately re-GRAFT to refresh their slot,
                    // defeating the purpose of the prune. A peer
                    // that omits the field (`0`) falls back to our
                    // local `prune_backoff` parameter so a missing
                    // or malicious-zero value can't disable the
                    // backoff entirely. Cap the upper bound at one
                    // hour to prevent a malicious peer from
                    // advertising a multi-day backoff that locks us
                    // out of grafting forever.
                    let suggested = if prune.backoff == 0 {
                        self.params.prune_backoff
                    } else {
                        let secs = std::cmp::min(prune.backoff, 3600);
                        std::time::Duration::from_secs(secs)
                    };
                    let expire = std::time::Instant::now() + suggested;
                    // Only extend an existing backoff (don't shorten
                    // it) so repeated PRUNEs from the same peer
                    // don't reset the clock to a more lenient value.
                    self.backoffs
                        .entry((peer, prune.bitmask.clone()))
                        .and_modify(|e| {
                            if expire > *e {
                                *e = expire;
                            }
                        })
                        .or_insert(expire);
                }

                // If this slice is managed by a composite, demote the peer
                // from `same` to `broker` rather than removing it from the
                // mesh — brokers remain in every slice mesh so traffic can
                // still bridge.  Only actually remove from the slice mesh
                // when the peer is not managed by any composite (or has
                // fully dropped out of them).
                if composite_managed {
                    if let Some(comp_keys) =
                        self.slice_to_composite.get(&prune.bitmask).cloned()
                    {
                        for ck in &comp_keys {
                            if let Some(comp) = self.composites.get_mut(ck) {
                                if comp.same.remove(&peer) {
                                    debug!(
                                        %peer,
                                        bitmask = hex::encode(&prune.bitmask),
                                        "PRUNE: demote composite peer same -> broker"
                                    );
                                    comp.broker.insert(peer);
                                }
                                // If peer is in broker already, leave it —
                                // it still bridges remaining slices.
                            }
                        }
                    }
                    composite_touched = true;
                } else if let Some(mesh) = self.mesh.get_mut(&prune.bitmask) {
                    mesh.remove(&peer);
                }
            }

            if composite_touched {
                // Collect the set of bitmasks we need to refresh, then
                // rebuild their slice meshes from composite membership.
                let touched: Vec<Vec<u8>> = control
                    .graft
                    .iter()
                    .map(|g| g.bitmask.clone())
                    .chain(control.prune.iter().map(|p| p.bitmask.clone()))
                    .collect();
                let mut seen: HashSet<Vec<u8>> = HashSet::new();
                for slice in touched {
                    if let Some(keys) = self.slice_to_composite.get(&slice).cloned() {
                        for k in keys {
                            if seen.insert(k.clone()) {
                                self.rebuild_slice_meshes(&k);
                            }
                        }
                    }
                }
            }

            // Respond to IHAVE with IWANT for messages we haven't
            // seen. Records each new IWANT in `pending_iwants` so
            // the heartbeat can detect drops and retry from another
            // advertiser. If a message_id is already pending
            // (different peer also advertised it), add this peer to
            // the candidates list instead of issuing a duplicate
            // IWANT — when the current IWANT times out we'll switch
            // to one of these.
            // IHAVE / IWANT score gating. Mirrors Go's `handleIHave`
            // (blossomsub.go:858-864) and `handleIWant`
            // (blossomsub.go:930-936): below-`gossip_threshold` peers
            // are ignored for both directions so a low-scoring peer
            // can't burn our bandwidth on gossip rounds. `peer_score`
            // was already captured above for the GRAFT path.
            let gossip_allowed =
                peer_score >= self.scorer.thresholds.gossip_threshold;
            if !gossip_allowed {
                debug!(%peer, score = peer_score,
                    "IHAVE/IWANT: ignoring below-threshold peer");
            }
            let mut wanted: Vec<Vec<u8>> = Vec::new();
            for ihave in &control.ihave {
                if !gossip_allowed {
                    break;
                }
                for msg_id in &ihave.message_i_ds {
                    if self.seen_messages.contains(msg_id) {
                        continue;
                    }
                    match self.pending_iwants.get_mut(msg_id) {
                        Some(entry) => {
                            if entry.asked != peer
                                && !entry.other_advertisers.contains(&peer)
                                && entry.other_advertisers.len() < 8
                            {
                                entry.other_advertisers.push(peer);
                            }
                        }
                        None => {
                            // Cap pending IWANT count to bound
                            // memory under IHAVE-flood. Standard
                            // gossipsub uses 5000.
                            if self.pending_iwants.len() >= 5000 {
                                continue;
                            }
                            self.pending_iwants.insert(
                                msg_id.clone(),
                                PendingIwant {
                                    asked: peer,
                                    sent_at: now,
                                    other_advertisers: Vec::new(),
                                    bitmask: ihave.bitmask.clone(),
                                },
                            );
                            wanted.push(msg_id.clone());
                        }
                    }
                }
            }
            if !wanted.is_empty() {
                let iwant_rpc = pb::Rpc {
                    subscriptions: Vec::new(),
                    publish: Vec::new(),
                    control: Some(pb::ControlMessage {
                        ihave: Vec::new(),
                        iwant: vec![pb::ControlIWant { message_i_ds: wanted }],
                        graft: Vec::new(),
                        prune: Vec::new(),
                        idontwant: Vec::new(),
                    }),
                };
                let encoded = protocol::encode_rpc(&iwant_rpc);
                if self.connected_peers.contains_key(&peer) {
                    self.events.push_back(ToSwarm::NotifyHandler {
                        peer_id: peer,
                        handler: NotifyHandler::Any,
                        event: HandlerIn { rpc_data: encoded },
                    });
                }
            }

            // Serve IWANT requests from message cache (only if peer is
            // at/above the gossip threshold — see IHAVE/IWANT gate
            // comment above).
            for iwant in &control.iwant {
                if !gossip_allowed {
                    break;
                }
                let mut msgs = Vec::new();
                for msg_id in &iwant.message_i_ds {
                    if let Some((bitmask, data)) = self.mcache.get(msg_id) {
                        msgs.push(pb::Message {
                            from: Vec::new(),
                            data: data.to_vec(),
                            seqno: Vec::new(),
                            bitmask: bitmask.to_vec(),
                            signature: Vec::new(),
                            key: Vec::new(),
                        });
                    }
                }
                if !msgs.is_empty() {
                    let rpc = protocol::publish_rpc(msgs);
                    let encoded = protocol::encode_rpc(&rpc);
                    if self.connected_peers.contains_key(&peer) {
                        self.events.push_back(ToSwarm::NotifyHandler {
                            peer_id: peer,
                            handler: NotifyHandler::Any,
                            event: HandlerIn { rpc_data: encoded },
                        });
                    }
                }
            }

            // Track inbound IDONTWANTs so we skip forwarding the
            // listed message IDs to this peer on subsequent receive
            // paths. Per-peer LRU bounded to the configured max
            // IDONTWANT message count so a malicious peer can't blow
            // out memory by enumerating message IDs.
            if !control.idontwant.is_empty() {
                let cap = self
                    .params
                    .max_idont_want_messages
                    .max(1);
                let cache = self
                    .peer_idontwant
                    .entry(peer)
                    .or_insert_with(|| {
                        lru::LruCache::new(
                            std::num::NonZeroUsize::new(cap).unwrap(),
                        )
                    });
                for idw in &control.idontwant {
                    for msg_id in &idw.message_i_ds {
                        cache.put(msg_id.clone(), ());
                    }
                }
            }
        }
    }

    /// Send subscriptions to a peer that supports BlossomSub.
    /// Called after Identify confirms the peer's protocol support.
    pub fn send_subscriptions_to_peer(&mut self, peer: PeerId) {
        if let Some(rpc_data) = &self.pending_subscribe_rpc {
            if self.connected_peers.contains_key(&peer) {
                debug!(%peer, "sending subscription RPC (Identify confirmed BlossomSub)");
                self.events.push_back(ToSwarm::NotifyHandler {
                    peer_id: peer,
                    handler: NotifyHandler::Any,
                    event: HandlerIn {
                        rpc_data: rpc_data.clone(),
                    },
                });
            }
        }
    }

    /// Get mesh peer count for a bitmask.
    pub fn mesh_peers(&self, bitmask: &[u8]) -> usize {
        self.mesh.get(bitmask).map(|m| m.len()).unwrap_or(0)
    }

    /// Read-only access to our own subscription set.
    pub fn subscriptions(&self) -> &HashSet<Vec<u8>> {
        &self.subscriptions
    }

    /// True iff `peer` is in our connected set.
    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.connected_peers.contains_key(peer)
    }

    /// True iff we know `peer` to be subscribed to `bitmask`.
    pub fn peer_subscribed_to(&self, peer: &PeerId, bitmask: &[u8]) -> bool {
        self.peer_subscriptions
            .get(peer)
            .map_or(false, |s| s.contains(bitmask))
    }

    /// Number of distinct peers currently connected.
    pub fn connected_count(&self) -> usize {
        self.connected_peers.len()
    }

    /// Set the local peer ID for outgoing message authoring. The
    /// production code path sets this through `set_signing_identity`
    /// (which also installs the signing keypair); the test harness
    /// uses this lighter setter when signing is irrelevant.
    pub fn set_local_peer_id(&mut self, peer_id: PeerId) {
        self.local_peer_id = Some(peer_id);
    }

    // ---- test-harness helpers (cfg(test) gated to avoid bloating
    // the production surface area). These let the in-memory
    // multi-node harness in `crate::test_harness` poke at the
    // behaviour's private state without exposing every field to the
    // wider crate. ----

    #[cfg(test)]
    pub(crate) fn test_record_connection(&mut self, peer: PeerId) {
        self.connected_peers.entry(peer).or_default();
        self.peer_subscriptions.entry(peer).or_default();
    }

    #[cfg(test)]
    pub(crate) fn test_record_subscription(
        &mut self,
        peer: PeerId,
        bitmask: Vec<u8>,
    ) {
        self.peer_subscriptions
            .entry(peer)
            .or_default()
            .insert(bitmask);
    }

    /// Force a heartbeat tick regardless of `last_heartbeat`. Mirrors
    /// what the libp2p swarm's poll loop would do, but lets tests
    /// drive timing deterministically.
    #[cfg(test)]
    pub(crate) fn test_force_heartbeat(&mut self) {
        self.heartbeat();
    }

    /// Drain pending outbound `NotifyHandler` events, invoking the
    /// callback with `(target_peer, rpc_bytes)` for each one. Used
    /// by the test harness to forward RPCs to recipient behaviours
    /// without going through a real swarm.
    #[cfg(test)]
    pub(crate) fn test_drain_events<F>(&mut self, mut on_send: F)
    where
        F: FnMut(PeerId, Vec<u8>),
    {
        let queued: Vec<_> = self.events.drain(..).collect();
        for ev in queued {
            match ev {
                libp2p::swarm::ToSwarm::NotifyHandler { peer_id, event, .. } => {
                    on_send(peer_id, event.rpc_data);
                }
                libp2p::swarm::ToSwarm::GenerateEvent(other) => {
                    // Push back; the caller drains GenerateEvent
                    // separately via `test_drain_generated`.
                    self.events.push_back(libp2p::swarm::ToSwarm::GenerateEvent(other));
                }
                other => {
                    // Other ToSwarm variants (Dial, etc.) aren't
                    // relevant to the in-memory harness; push back
                    // for future drains.
                    self.events.push_back(other);
                }
            }
        }
    }

    /// Drain pending `GenerateEvent` (application-facing)
    /// `BlossomSubEvent`s, invoking the callback with each.
    #[cfg(test)]
    pub(crate) fn test_drain_generated<F>(&mut self, mut on_ev: F)
    where
        F: FnMut(BlossomSubEvent),
    {
        let queued: Vec<_> = self.events.drain(..).collect();
        for ev in queued {
            match ev {
                libp2p::swarm::ToSwarm::GenerateEvent(inner) => on_ev(inner),
                other => self.events.push_back(other),
            }
        }
    }

    /// Sum of mesh peer counts across every subscribed bitmask —
    /// used by the discovery loop to gauge overall mesh health.
    pub fn mesh_peer_counts(&self) -> usize {
        self.mesh.values().map(|m| m.len()).sum()
    }

    /// Get total connected peers.
    pub fn num_connected(&self) -> usize {
        self.connected_peers.len()
    }

    /// Establish composite mesh state for a multi-slice bitmask. Selects up
    /// to D peers, preferring peers subscribed to ALL slices (same), and
    /// filling any remainder with peers subscribed to SOME slices (broker).
    pub(crate) fn join_composite(
        &mut self,
        bitmask: Vec<u8>,
        slices: Vec<Vec<u8>>,
    ) {
        if self.composites.contains_key(&bitmask) {
            return;
        }

        let mut entry = CompositeMeshEntry::new(bitmask.clone());
        entry.slices = slices.clone();

        // Pick "same" peers (subscribed to every slice) up to D.
        for (peer, subs) in &self.peer_subscriptions {
            if entry.total_peers() >= crate::params::D {
                break;
            }
            if self.backoffs.contains_key(&(*peer, bitmask.clone())) {
                continue;
            }
            if slices.iter().all(|s| subs.contains(s)) {
                entry.same.insert(*peer);
            }
        }
        // If we didn't fill up, promote peers subscribed to ANY slice to
        // broker status.
        if entry.total_peers() < crate::params::D {
            let candidates: Vec<PeerId> = self
                .peer_subscriptions
                .iter()
                .filter_map(|(p, subs)| {
                    if entry.same.contains(p) {
                        return None;
                    }
                    if self.backoffs.contains_key(&(*p, bitmask.clone())) {
                        return None;
                    }
                    if slices.iter().any(|s| subs.contains(s)) {
                        Some(*p)
                    } else {
                        None
                    }
                })
                .collect();
            for p in candidates {
                if entry.total_peers() >= crate::params::D {
                    break;
                }
                entry.broker.insert(p);
            }
        }

        // Register reverse index.
        for slice in &entry.slices {
            self.slice_to_composite
                .entry(slice.clone())
                .or_default()
                .push(bitmask.clone());
        }

        self.composites.insert(bitmask.clone(), entry);
        self.rebuild_slice_meshes(&bitmask);
    }

    /// Tear down a composite mesh — remove state, clean up reverse index,
    /// and drop per-slice meshes that are no longer composite-managed.
    pub(crate) fn leave_composite(&mut self, bitmask: &[u8]) {
        let comp = match self.composites.remove(bitmask) {
            Some(c) => c,
            None => return,
        };
        // Clean up the reverse index.
        for slice in &comp.slices {
            if let Some(keys) = self.slice_to_composite.get_mut(slice) {
                keys.retain(|k| k.as_slice() != bitmask);
                if keys.is_empty() {
                    self.slice_to_composite.remove(slice);
                }
            }
        }
        // Clear per-slice mesh entries for slices that are no longer
        // composite-managed, so a future Subscribe can re-join cleanly.
        for slice in &comp.slices {
            if !self.slice_to_composite.contains_key(slice) {
                self.mesh.remove(slice);
            } else {
                // Still managed by another composite — rebuild it.
                // (Use the first remaining composite as the rebuild target.)
                let keys = self.slice_to_composite.get(slice).cloned().unwrap_or_default();
                if let Some(k) = keys.first() {
                    self.rebuild_slice_meshes(k);
                }
            }
        }
    }

    /// Classify a peer as `Same` (subscribed to every slice of the composite)
    /// or `Broker` (subscribed to at least one but not all). On missing data
    /// we fall back to Broker.
    fn classify_peer(&self, peer: &PeerId, composite_key: &[u8]) -> PeerClass {
        let comp = match self.composites.get(composite_key) {
            Some(c) => c,
            None => return PeerClass::Broker,
        };
        let subs = match self.peer_subscriptions.get(peer) {
            Some(s) => s,
            None => return PeerClass::Broker,
        };
        if comp.slices.iter().all(|s| subs.contains(s)) {
            PeerClass::Same
        } else {
            PeerClass::Broker
        }
    }

    /// Rebuild per-slice mesh sets from composite.{same, broker} membership.
    /// Every composite peer (same + broker) is present in every slice mesh,
    /// because brokers intentionally bridge non-subscribed slices — messages
    /// carry the full bitmask and overlap the broker's actual subscription.
    fn rebuild_slice_meshes(&mut self, composite_key: &[u8]) {
        let comp = match self.composites.get(composite_key) {
            Some(c) => c,
            None => return,
        };
        // Clear composite-managed slice meshes then re-populate.
        let slices: Vec<Vec<u8>> = comp.slices.clone();
        let members: HashSet<PeerId> =
            comp.same.iter().chain(comp.broker.iter()).copied().collect();
        for slice in slices {
            let entry = self.mesh.entry(slice.clone()).or_default();
            entry.clear();
            for p in &members {
                entry.insert(*p);
            }
        }
    }

    /// Walk `pending_iwants` and, for every entry whose IWANT
    /// has been outstanding longer than
    /// `params.iwant_followup_time`, either retry from another
    /// advertiser (popping it from `other_advertisers`) or drop the
    /// entry entirely. Records a behaviour penalty on the
    /// original responder so the scoring path can PRUNE chronic
    /// missers. Without this, an IWANT lost on the wire is
    /// silently abandoned and the requesting node never recovers
    /// the message via gossip — relying instead on the slower
    /// consensus-layer rebroadcast (28s) which is too late for
    /// vote-aggregation deadlines on WAN.
    fn process_iwant_followups(&mut self) {
        let now = Instant::now();
        let timeout = self.params.iwant_followup_time;
        let mut retries: Vec<(PeerId, Vec<u8>)> = Vec::new();
        let mut expired_msg_ids: Vec<Vec<u8>> = Vec::new();
        let mut penalize_peers: Vec<PeerId> = Vec::new();

        // First pass: collect work without mutating the map (avoid
        // double-borrow issues with retries borrowing peer IDs that
        // also live in the same map).
        for (msg_id, entry) in self.pending_iwants.iter() {
            if now.duration_since(entry.sent_at) < timeout {
                continue;
            }
            // Penalize the peer that didn't deliver; their gossip
            // ad was effectively a lie. One penalty per missed IWANT.
            penalize_peers.push(entry.asked);
            // Pick a different advertiser, preferring connected
            // peers we're not already locked-out of.
            let next = entry
                .other_advertisers
                .iter()
                .copied()
                .find(|p| self.connected_peers.contains_key(p) && *p != entry.asked);
            match next {
                Some(p) => retries.push((p, msg_id.clone())),
                None => expired_msg_ids.push(msg_id.clone()),
            }
        }

        for peer in &penalize_peers {
            self.scorer.add_invalid(peer, &[]);
        }

        // Drop expired entries with no remaining advertiser.
        for id in &expired_msg_ids {
            self.pending_iwants.remove(id);
        }

        // Re-issue IWANTs to the new advertisers. Group by peer so
        // we send one RPC per target. Also rotate the pending entry
        // to the new peer with a fresh `sent_at`.
        let mut by_peer: HashMap<PeerId, Vec<Vec<u8>>> = HashMap::new();
        for (peer, msg_id) in retries {
            by_peer.entry(peer).or_default().push(msg_id.clone());
            if let Some(entry) = self.pending_iwants.get_mut(&msg_id) {
                // Remove the new asked peer from candidates so we
                // don't bounce back to it next round.
                entry.other_advertisers.retain(|p| *p != peer);
                entry.asked = peer;
                entry.sent_at = now;
            }
        }
        for (target, ids) in by_peer {
            let iwant_rpc = pb::Rpc {
                subscriptions: Vec::new(),
                publish: Vec::new(),
                control: Some(pb::ControlMessage {
                    ihave: Vec::new(),
                    iwant: vec![pb::ControlIWant { message_i_ds: ids }],
                    graft: Vec::new(),
                    prune: Vec::new(),
                    idontwant: Vec::new(),
                }),
            };
            let encoded = protocol::encode_rpc(&iwant_rpc);
            if self.connected_peers.contains_key(&target) {
                self.events.push_back(ToSwarm::NotifyHandler {
                    peer_id: target,
                    handler: NotifyHandler::Any,
                    event: HandlerIn { rpc_data: encoded },
                });
            }
        }
    }

    /// Compute the diversity-bucket keys for a peer's IP set.
    ///
    /// Each IPv4 address collapses to its /24 (`a.b.c.0`); each IPv6
    /// to its /48 (the first 48 bits). A peer with multiple known
    /// IPs contributes one bucket key per address. Eclipse-resistance
    /// uses these buckets to cap how many mesh slots any single
    /// subnet can occupy.
    ///
    /// Rationale for /24 (v4) and /48 (v6): both are the smallest
    /// allocations a typical hosting provider hands out as a single
    /// "block." A Sybil attacker who controls one /24 of cheap VPS
    /// instances can produce dozens of distinct PeerIds with
    /// independent IPs but still shares the same routing prefix —
    /// the colocation-factor penalty (per-IP) misses this case
    /// because the IPs literally differ. Bucketing at the subnet
    /// level catches it.
    fn peer_subnet_buckets(&self, peer: &PeerId) -> HashSet<[u8; 16]> {
        let mut out = HashSet::new();
        for ip in self.scorer.peer_ips(peer) {
            out.insert(subnet_bucket_key(ip));
        }
        out
    }

    /// Count mesh peers in `mesh` whose subnet bucket overlaps with
    /// `bucket`. Linear scan; mesh is small (~D = 8). Returns 0 if
    /// the candidate peer has no known IPs (which would prevent
    /// every legitimate peer from joining the mesh).
    fn count_mesh_in_subnet(
        &self,
        mesh: &HashSet<PeerId>,
        bucket: &[u8; 16],
    ) -> usize {
        mesh.iter()
            .filter(|p| self.peer_subnet_buckets(p).contains(bucket))
            .count()
    }

    /// Returns true if grafting `peer` into `mesh` would violate the
    /// per-subnet cap. If `params.mesh_peers_per_subnet == 0` the
    /// check is disabled. If the peer has no known IPs (libp2p
    /// hasn't observed an address yet), the check is skipped so the
    /// peer can still join the mesh — the IP gets recorded later
    /// via `set_peer_ips` and subsequent grafts are bucketed
    /// normally.
    fn graft_would_violate_subnet_cap(
        &self,
        mesh: &HashSet<PeerId>,
        peer: &PeerId,
    ) -> bool {
        let cap = self.params.mesh_peers_per_subnet;
        if cap == 0 {
            return false;
        }
        let candidate_buckets = self.peer_subnet_buckets(peer);
        if candidate_buckets.is_empty() {
            return false;
        }
        candidate_buckets
            .iter()
            .any(|b| self.count_mesh_in_subnet(mesh, b) >= cap)
    }

    fn heartbeat(&mut self) {
        self.heartbeat_ticks += 1;

        // 0a. IWANT follow-up. For every pending IWANT older than
        // `params.iwant_followup_time`, either retry from another
        // peer that advertised the same message, or drop it if no
        // candidates remain. Penalize the original responder so its
        // score reflects the missed gossip response — repeated
        // offenders get PRUNE'd via the score path.
        self.process_iwant_followups();

        // 0. Direct peer maintenance — reconnect missing, graft into meshes.
        if !self.direct_peers.is_empty() {
            let disconnected: Vec<PeerId> = self
                .direct_peers
                .iter()
                .filter(|p| !self.connected_peers.contains_key(p))
                .copied()
                .collect();
            if !disconnected.is_empty() {
                debug!(
                    count = disconnected.len(),
                    "direct peers disconnected, emitting NeedPeers"
                );
                self.events.push_back(ToSwarm::GenerateEvent(
                    BlossomSubEvent::NeedPeers {
                        subscriptions: self.subscriptions.iter().cloned().collect(),
                        connected: self.connected_peers.len(),
                    },
                ));
            }

            // Ensure connected direct peers are in every mesh we maintain.
            let subscriptions: Vec<Vec<u8>> = self.subscriptions.iter().cloned().collect();
            let mut direct_grafts: Vec<(PeerId, Vec<u8>)> = Vec::new();
            for bitmask in &subscriptions {
                let mesh = self.mesh.entry(bitmask.clone()).or_default();
                for &dp in &self.direct_peers {
                    if self.connected_peers.contains_key(&dp) && !mesh.contains(&dp) {
                        mesh.insert(dp);
                        direct_grafts.push((dp, bitmask.clone()));
                    }
                }
            }
            for (peer, bitmask) in direct_grafts {
                self.send_graft(&peer, &bitmask);
                debug!(%peer, bitmask = hex::encode(&bitmask), "grafted direct peer");
            }
        }

        // 1. Shift message cache (expire old entries). `seen_messages`
        // is an LRU bounded at construction; no clear() needed —
        // overflow evicts the oldest entry per insert, preserving
        // dedup for messages still propagating in the mesh.
        self.mcache.shift();

        // 2. Expire stale backoffs
        let now = Instant::now();
        self.backoffs.retain(|_, expiry| *expiry > now);

        // 3. Expire stale fanout entries
        let fanout_ttl = self.params.fanout_ttl;
        let expired_fanout: Vec<Vec<u8>> = self.fanout_last_pub
            .iter()
            .filter(|(_, last)| now.duration_since(**last) > fanout_ttl)
            .map(|(b, _)| b.clone())
            .collect();
        for bitmask in expired_fanout {
            self.fanout.remove(&bitmask);
            self.fanout_last_pub.remove(&bitmask);
            debug!(bitmask = hex::encode(&bitmask), "fanout expired");
        }

        // 4. Mesh maintenance per subscribed bitmask
        //
        // Collect all graft/prune actions first, then apply them.
        // This avoids borrow checker issues with self.mesh + self.send_*.
        let subscriptions: Vec<Vec<u8>> = self.subscriptions.iter().cloned().collect();
        let mut graft_actions: Vec<(PeerId, Vec<u8>)> = Vec::new();
        let mut prune_actions: Vec<(PeerId, Vec<u8>)> = Vec::new();

        for bitmask in &subscriptions {
            let mesh = self.mesh.entry(bitmask.clone()).or_default();

            // 4a. Remove negative-score peers from mesh
            let negative_peers: Vec<PeerId> = mesh
                .iter()
                .filter(|p| self.scorer.score(p) < 0.0)
                .copied()
                .collect();
            for peer in &negative_peers {
                mesh.remove(peer);
                self.outbound_peers
                    .entry(bitmask.clone())
                    .or_default()
                    .remove(peer);
                prune_actions.push((*peer, bitmask.clone()));
                debug!(
                    %peer,
                    bitmask = hex::encode(bitmask),
                    "pruned negative-score peer"
                );
            }

            // 4b. If under-subscribed (< D_LO): GRAFT from available peers
            if mesh.len() < self.params.d_lo {
                let needed = crate::params::D - mesh.len();
                // Subnet-diversity gate: refuse to graft a candidate
                // whose /24 (v4) or /48 (v6) already has
                // `params.mesh_peers_per_subnet` peers in the mesh.
                // Mutates `mesh` as we go so subsequent candidates
                // see updated bucket counts (one accepted graft
                // affects the bucket count for the next).
                let cap = self.params.mesh_peers_per_subnet;
                // Helper closure captures only `self.scorer` (an
                // immutable borrow of a sibling field) so it can
                // coexist with the mutable borrow of `self.mesh`
                // (`mesh`). Calling `self.peer_subnet_buckets`
                // (`&self`) here would re-borrow the parent and
                // collide.
                let scorer = &self.scorer;
                let buckets_for = |peer: &PeerId| -> HashSet<[u8; 16]> {
                    scorer
                        .peer_ips(peer)
                        .into_iter()
                        .map(subnet_bucket_key)
                        .collect()
                };

                let mut accepted_subnet_counts: HashMap<[u8; 16], usize> =
                    HashMap::new();
                if cap > 0 {
                    for peer in mesh.iter() {
                        for b in buckets_for(peer) {
                            *accepted_subnet_counts.entry(b).or_insert(0) += 1;
                        }
                    }
                }

                let mut candidates: Vec<PeerId> = Vec::with_capacity(needed);
                for (peer, subs) in self.peer_subscriptions.iter() {
                    if candidates.len() >= needed {
                        break;
                    }
                    if !subs.contains(bitmask)
                        || mesh.contains(peer)
                        || self.backoffs.contains_key(&(*peer, bitmask.clone()))
                        || scorer.score(peer) < 0.0
                    {
                        continue;
                    }
                    if cap > 0 {
                        let buckets = buckets_for(peer);
                        if !buckets.is_empty()
                            && buckets.iter().any(|b| {
                                accepted_subnet_counts.get(b).copied().unwrap_or(0)
                                    >= cap
                            })
                        {
                            debug!(
                                %peer,
                                bitmask = hex::encode(bitmask),
                                "heartbeat: skipping graft — subnet cap reached"
                            );
                            continue;
                        }
                        for b in buckets {
                            *accepted_subnet_counts.entry(b).or_insert(0) += 1;
                        }
                    }
                    candidates.push(*peer);
                }

                for peer in &candidates {
                    mesh.insert(*peer);
                    graft_actions.push((*peer, bitmask.clone()));
                }
                if !candidates.is_empty() {
                    debug!(
                        bitmask = hex::encode(bitmask),
                        grafted = candidates.len(),
                        mesh_size = mesh.len(),
                        "heartbeat: grafted peers (under D_LO)"
                    );
                }
            }

            // 4c. If over-subscribed (> D_HI): PRUNE excess peers
            if mesh.len() > self.params.d_hi {
                let excess = mesh.len() - crate::params::D;
                let outbound = self.outbound_peers
                    .get(bitmask)
                    .cloned()
                    .unwrap_or_default();

                // Score all mesh peers, keep top D_SCORE and random fill
                let mut scored: Vec<(PeerId, f64)> = mesh
                    .iter()
                    .map(|p| (*p, self.scorer.score(p)))
                    .collect();
                scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

                // Protect top D_SCORE peers and outbound peers
                let mut protected: HashSet<PeerId> = HashSet::new();
                for (peer, _) in scored.iter().take(self.params.d_score) {
                    protected.insert(*peer);
                }
                for peer in &outbound {
                    protected.insert(*peer);
                }

                // Prune unprotected peers until we reach D
                let mut pruned = 0;
                let prune_candidates: Vec<PeerId> = mesh
                    .iter()
                    .filter(|p| !protected.contains(p))
                    .copied()
                    .collect();
                for peer in prune_candidates {
                    if pruned >= excess {
                        break;
                    }
                    mesh.remove(&peer);
                    self.outbound_peers
                        .entry(bitmask.clone())
                        .or_default()
                        .remove(&peer);
                    prune_actions.push((peer, bitmask.clone()));
                    pruned += 1;
                }
                if pruned > 0 {
                    debug!(
                        bitmask = hex::encode(bitmask),
                        pruned,
                        mesh_size = mesh.len(),
                        "heartbeat: pruned excess peers (over D_HI)"
                    );
                }
            }

            // 4d. Maintain D_OUT outbound peers
            let outbound = self.outbound_peers
                .entry(bitmask.clone())
                .or_default();
            // Remove outbound peers no longer in mesh
            let mesh_ref = self.mesh.get(bitmask);
            outbound.retain(|p| mesh_ref.map_or(false, |m| m.contains(p)));
        }

        // Apply collected graft/prune actions
        for (peer, bitmask) in graft_actions {
            self.send_graft(&peer, &bitmask);
        }
        for (peer, bitmask) in prune_actions {
            self.send_prune(&peer, &bitmask);
        }

        // 5. Emit IHAVE gossip to non-mesh peers
        for bitmask in &subscriptions {
            let mesh = self.mesh.get(bitmask);
            let message_ids = self.mcache.get_gossip_ids(bitmask);
            if message_ids.is_empty() {
                continue;
            }

            // Select D_LAZY non-mesh peers that are subscribed
            let gossip_peers: Vec<PeerId> = self
                .peer_subscriptions
                .iter()
                .filter(|(p, subs)| {
                    subs.contains(bitmask)
                        && mesh.map_or(true, |m| !m.contains(p))
                        && self.scorer.score(p) >= self.scorer.thresholds.gossip_threshold
                })
                .map(|(p, _)| *p)
                .take(self.params.d_lazy)
                .collect();

            if !gossip_peers.is_empty() {
                let ihave_rpc = protocol::ihave_rpc(bitmask, &message_ids);
                let encoded = protocol::encode_rpc(&ihave_rpc);
                for peer in gossip_peers {
                    if let Some(conns) = self.connected_peers.get(&peer) {
                        if let Some(&conn) = conns.first() {
                            self.events.push_back(ToSwarm::NotifyHandler {
                                peer_id: peer,
                                handler: NotifyHandler::One(conn),
                                event: HandlerIn { rpc_data: encoded.clone() },
                            });
                        }
                    }
                }
                trace!(
                    bitmask = hex::encode(bitmask),
                    ids = message_ids.len(),
                    "heartbeat: emitted IHAVE gossip"
                );
            }
        }

        // 6. Maintain fanout meshes (for bitmasks we publish to but aren't subscribed)
        for (bitmask, fanout_peers) in &mut self.fanout {
            // Remove disconnected peers
            fanout_peers.retain(|p| self.connected_peers.contains_key(p));
            // Fill up to D if needed
            if fanout_peers.len() < crate::params::D {
                let needed = crate::params::D - fanout_peers.len();
                let candidates: Vec<PeerId> = self
                    .peer_subscriptions
                    .iter()
                    .filter(|(p, subs)| subs.contains(bitmask) && !fanout_peers.contains(p))
                    .map(|(p, _)| *p)
                    .take(needed)
                    .collect();
                for peer in candidates {
                    fanout_peers.insert(peer);
                }
            }
        }

        // 7. Signal if we need more peers for any subscription
        let mut need_peers = false;
        for bitmask in &subscriptions {
            let mesh_count = self.mesh.get(bitmask).map(|m| m.len()).unwrap_or(0);
            if mesh_count < self.params.d_lo {
                need_peers = true;
                break;
            }
        }
        if need_peers && !self.subscriptions.is_empty() {
            self.events.push_back(ToSwarm::GenerateEvent(
                BlossomSubEvent::NeedPeers {
                    subscriptions: self.subscriptions.iter().cloned().collect(),
                    connected: self.connected_peers.len(),
                },
            ));
        }

        // 8. Opportunistic grafting — every 60 heartbeat ticks, if the
        //    median score of mesh peers is below the opportunistic graft
        //    threshold, graft a non-mesh peer whose score exceeds the median.
        if self.heartbeat_ticks % 60 == 0 {
            let threshold = self.scorer.thresholds.opportunistic_graft_threshold;
            let mut opp_grafts: Vec<(PeerId, Vec<u8>)> = Vec::new();

            for bitmask in &subscriptions {
                let mesh = match self.mesh.get(bitmask) {
                    Some(m) if !m.is_empty() => m,
                    _ => continue,
                };

                // Compute median score of mesh peers.
                let mut scores: Vec<f64> = mesh
                    .iter()
                    .map(|p| self.scorer.score(p))
                    .collect();
                scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let median = scores[scores.len() / 2];

                if median >= threshold {
                    continue;
                }

                // Find a non-mesh peer subscribed to this bitmask with a
                // score above the median.
                if let Some(&candidate) = self
                    .peer_subscriptions
                    .iter()
                    .filter(|(p, subs)| {
                        subs.contains(bitmask)
                            && !mesh.contains(p)
                            && !self.backoffs.contains_key(&(**p, bitmask.clone()))
                            && self.scorer.score(p) > median
                    })
                    .map(|(p, _)| p)
                    .next()
                {
                    opp_grafts.push((candidate, bitmask.clone()));
                    debug!(
                        %candidate,
                        bitmask = hex::encode(bitmask),
                        median,
                        "opportunistic graft: median below threshold"
                    );
                }
            }

            for (peer, bitmask) in &opp_grafts {
                self.mesh
                    .entry(bitmask.clone())
                    .or_default()
                    .insert(*peer);
                self.send_graft(peer, bitmask);
            }
        }
    }

    /// Send a GRAFT message to a peer for a bitmask.
    fn send_graft(&mut self, peer: &PeerId, bitmask: &[u8]) {
        let rpc = protocol::graft_rpc(&[bitmask.to_vec()]);
        let encoded = protocol::encode_rpc(&rpc);
        if let Some(conns) = self.connected_peers.get(peer) {
            if let Some(&conn) = conns.first() {
                self.events.push_back(ToSwarm::NotifyHandler {
                    peer_id: *peer,
                    handler: NotifyHandler::One(conn),
                    event: HandlerIn { rpc_data: encoded },
                });
            }
        }
    }

    /// Send a PRUNE message to a peer for a bitmask.
    fn send_prune(&mut self, peer: &PeerId, bitmask: &[u8]) {
        let backoff_secs = self.params.prune_backoff.as_secs();
        let rpc = protocol::prune_rpc(&[bitmask.to_vec()], backoff_secs);
        let encoded = protocol::encode_rpc(&rpc);
        if let Some(conns) = self.connected_peers.get(peer) {
            if let Some(&conn) = conns.first() {
                self.events.push_back(ToSwarm::NotifyHandler {
                    peer_id: *peer,
                    handler: NotifyHandler::One(conn),
                    event: HandlerIn { rpc_data: encoded },
                });
                // Set backoff
                self.backoffs.insert(
                    (*peer, bitmask.to_vec()),
                    Instant::now() + self.params.prune_backoff,
                );
            }
        }
    }
}

/// Map an IP to its diversity bucket key. IPv4 → /24 left-padded
/// into the high 4 bytes (last 12 bytes zero). IPv6 → /48 left into
/// the first 6 bytes (remaining 10 zero). Different families never
/// collide because the v4 form has zero bytes [4..16] and the v6
/// form encodes the unmasked /48 bits in [0..6] — collisions would
/// require a v6 prefix that starts with `0x00.0x00.0x00.0x00`,
/// which is the IPv4-mapped reserved range and not used as an
/// independent v6 prefix on any production network.
pub(crate) fn subnet_bucket_key(ip: IpAddr) -> [u8; 16] {
    let mut out = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // /24 — first three octets identify the bucket; fourth
            // and beyond zeroed.
            out[..3].copy_from_slice(&octets[..3]);
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // /48 — first six bytes identify the bucket.
            out[..6].copy_from_slice(&octets[..6]);
        }
    }
    out
}

impl Default for BlossomSubBehaviour {
    fn default() -> Self {
        Self::new(0)
    }
}

impl NetworkBehaviour for BlossomSubBehaviour {
    type ConnectionHandler = BlossomSubHandler;
    type ToSwarm = BlossomSubEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.blacklisted_peers.contains(&peer) {
            return Err(ConnectionDenied::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied, "peer blacklisted"
            )));
        }
        Ok(BlossomSubHandler::new(self.protocol.clone()))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.blacklisted_peers.contains(&peer) {
            return Err(ConnectionDenied::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied, "peer blacklisted"
            )));
        }
        Ok(BlossomSubHandler::new(self.protocol.clone()))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                self.connected_peers
                    .entry(e.peer_id)
                    .or_default()
                    .push(e.connection_id);

                // Send subscriptions immediately as a "hello packet".
                if let Some(rpc_data) = &self.pending_subscribe_rpc {
                    self.events.push_back(ToSwarm::NotifyHandler {
                        peer_id: e.peer_id,
                        handler: NotifyHandler::Any,
                        event: HandlerIn {
                            rpc_data: rpc_data.clone(),
                        },
                    });
                }
            }
            FromSwarm::ConnectionClosed(e) => {
                if let Some(conns) = self.connected_peers.get_mut(&e.peer_id) {
                    conns.retain(|c| *c != e.connection_id);
                    if conns.is_empty() {
                        self.connected_peers.remove(&e.peer_id);
                        self.peer_subscriptions.remove(&e.peer_id);
                        self.peer_idontwant.remove(&e.peer_id);
                        for mesh in self.mesh.values_mut() {
                            mesh.remove(&e.peer_id);
                        }
                        // Reset pending IWANTs that were waiting on
                        // this peer — there's no point waiting for a
                        // disconnected peer's gossip response. If
                        // another advertiser exists, the next
                        // heartbeat's `process_iwant_followups`
                        // picks them up (entry stays). If this peer
                        // was the only advertiser, drop the entry.
                        let dropped_peer = e.peer_id;
                        let mut drop_ids: Vec<Vec<u8>> = Vec::new();
                        for (msg_id, entry) in self.pending_iwants.iter_mut() {
                            if entry.asked == dropped_peer {
                                // Force expiry on next heartbeat so the
                                // follow-up logic picks a different
                                // peer, by zeroing `sent_at`.
                                entry.sent_at =
                                    Instant::now() - self.params.iwant_followup_time;
                                if entry.other_advertisers.is_empty() {
                                    drop_ids.push(msg_id.clone());
                                }
                            } else {
                                entry.other_advertisers.retain(|p| *p != dropped_peer);
                            }
                        }
                        for id in drop_ids {
                            self.pending_iwants.remove(&id);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            HandlerOut::Rpc(rpc) => {
                let subs = rpc.subscriptions.len();
                let msgs = rpc.publish.len();
                if subs > 0 || msgs > 0 {
                    debug!(%peer_id, subs, msgs, "behaviour received RPC with data from handler");
                }
                self.handle_rpc(peer_id, rpc);
            }
            HandlerOut::Error(e) => {
                debug!(%peer_id, error = %e, "handler error");
            }
        }
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Run heartbeat
        if self.last_heartbeat.elapsed() >= self.params.heartbeat_interval {
            self.heartbeat();
            self.last_heartbeat = Instant::now();
        }

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod composite_tests {
    use super::*;
    use crate::protocol::pb;

    /// Build a 2-slice composite bitmask (0xC0 = 0b1100_0000) and its slices.
    fn two_slice_bitmask() -> (Vec<u8>, Vec<Vec<u8>>) {
        let bitmask = vec![0xC0];
        let slices = crate::bitmask::slice_bitmask(&bitmask);
        assert_eq!(slices.len(), 2, "expected 2-slice composite");
        (bitmask, slices)
    }

    /// Record a peer's subscription set in the behaviour so the composite
    /// machinery can classify it.
    fn seed_subscription(
        bh: &mut BlossomSubBehaviour,
        peer: PeerId,
        bitmasks: &[Vec<u8>],
    ) {
        let entry = bh.peer_subscriptions.entry(peer).or_default();
        for bm in bitmasks {
            entry.insert(bm.clone());
        }
    }

    /// Build a GRAFT-only RPC for a single bitmask.
    fn graft_rpc(bitmask: &[u8]) -> pb::Rpc {
        crate::protocol::graft_rpc(&[bitmask.to_vec()])
    }

    /// Build a PRUNE-only RPC for a single bitmask (no backoff).
    fn prune_rpc(bitmask: &[u8]) -> pb::Rpc {
        crate::protocol::prune_rpc(&[bitmask.to_vec()], 0)
    }

    #[test]
    fn graft_of_peer_subscribed_to_all_slices_classified_as_same() {
        let (bitmask, slices) = two_slice_bitmask();
        let mut bh = BlossomSubBehaviour::new(0);
        // We must be subscribed before handle_rpc will consider the GRAFT.
        bh.subscriptions.insert(bitmask.clone());
        // Pre-register composite state for the bitmask.
        bh.join_composite(bitmask.clone(), slices.clone());

        let peer = PeerId::random();
        seed_subscription(&mut bh, peer, &slices);

        // GRAFT on slice 0 — composite should classify as Same.
        bh.handle_rpc(peer, graft_rpc(&slices[0]));
        assert!(bh.composites[&bitmask].same.contains(&peer), "peer should be in same");
        assert!(!bh.composites[&bitmask].broker.contains(&peer));
        // Broker logic: all slice meshes include the peer (brokers bridge).
        for s in &slices {
            assert!(bh.mesh[s].contains(&peer), "peer missing from slice mesh");
        }
    }

    #[test]
    fn prune_of_single_slice_demotes_same_to_broker_and_keeps_in_other_slices() {
        let (bitmask, slices) = two_slice_bitmask();
        let mut bh = BlossomSubBehaviour::new(0);
        bh.subscriptions.insert(bitmask.clone());
        bh.join_composite(bitmask.clone(), slices.clone());

        let peer = PeerId::random();
        seed_subscription(&mut bh, peer, &slices);

        // Establish Same classification via GRAFT.
        bh.handle_rpc(peer, graft_rpc(&slices[0]));
        assert!(bh.composites[&bitmask].same.contains(&peer));

        // PRUNE slice 0 only.  The peer should demote to broker but still
        // appear in ALL slice meshes (brokers bridge non-subscribed slices).
        bh.handle_rpc(peer, prune_rpc(&slices[0]));

        assert!(!bh.composites[&bitmask].same.contains(&peer), "should not still be same");
        assert!(bh.composites[&bitmask].broker.contains(&peer), "should be broker");
        for s in &slices {
            assert!(
                bh.mesh[s].contains(&peer),
                "broker must remain in slice mesh after single-slice PRUNE"
            );
        }
    }

    #[test]
    fn graft_of_peer_subscribed_to_some_slices_classified_as_broker() {
        let (bitmask, slices) = two_slice_bitmask();
        let mut bh = BlossomSubBehaviour::new(0);
        bh.subscriptions.insert(bitmask.clone());
        bh.join_composite(bitmask.clone(), slices.clone());

        let peer = PeerId::random();
        // Subscribed to only ONE slice — must be broker.
        seed_subscription(&mut bh, peer, &[slices[0].clone()]);

        bh.handle_rpc(peer, graft_rpc(&slices[0]));
        assert!(!bh.composites[&bitmask].same.contains(&peer));
        assert!(bh.composites[&bitmask].broker.contains(&peer));
        // Brokers go into every slice mesh even those they don't subscribe to.
        for s in &slices {
            assert!(bh.mesh[s].contains(&peer));
        }
    }

    #[test]
    fn graft_after_partial_prune_restores_same_when_fully_subscribed() {
        let (bitmask, slices) = two_slice_bitmask();
        let mut bh = BlossomSubBehaviour::new(0);
        bh.subscriptions.insert(bitmask.clone());
        bh.join_composite(bitmask.clone(), slices.clone());

        let peer = PeerId::random();
        seed_subscription(&mut bh, peer, &slices);

        // Same → prune one slice → broker.
        bh.handle_rpc(peer, graft_rpc(&slices[0]));
        bh.handle_rpc(peer, prune_rpc(&slices[0]));
        assert!(bh.composites[&bitmask].broker.contains(&peer));

        // Re-GRAFT while peer is still subscribed to all slices — should
        // promote broker → same.
        bh.handle_rpc(peer, graft_rpc(&slices[0]));
        assert!(bh.composites[&bitmask].same.contains(&peer), "should promote to same");
        assert!(!bh.composites[&bitmask].broker.contains(&peer), "should leave broker");
    }
}

#[cfg(test)]
mod mesh_maintenance_tests {
    //! Tests that exercise the heartbeat-driven mesh maintenance
    //! loop's core invariants. These are the regressions that would
    //! catch eclipse-class bugs (an attacker manipulating mesh slots
    //! via score / backoff / subscription games) and the gossipsub
    //! flow-control properties (D_LO / D / D_HI bounds, D_SCORE +
    //! outbound protection during prune).
    //!
    //! Coverage we intentionally skip here: composite mesh
    //! same/broker classification (`composite_tests` above) and the
    //! subnet diversity gate (`subnet_diversity_tests` below). Both
    //! have dedicated suites.
    use super::*;

    fn make_peer() -> PeerId {
        PeerId::random()
    }

    /// Build a behaviour subscribed to a single bitmask, with N peers
    /// already in the mesh and `extra` additional candidates
    /// available for graft. Returns (behaviour, bitmask, mesh peers,
    /// candidate peers).
    fn setup_subscribed_with_mesh_and_candidates(
        mesh_size: usize,
        candidate_count: usize,
    ) -> (BlossomSubBehaviour, Vec<u8>, Vec<PeerId>, Vec<PeerId>) {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());

        let mesh_peers: Vec<PeerId> = (0..mesh_size).map(|_| make_peer()).collect();
        let candidates: Vec<PeerId> = (0..candidate_count).map(|_| make_peer()).collect();

        // Seed subscriptions so the heartbeat sees them as eligible.
        for p in mesh_peers.iter().chain(candidates.iter()) {
            bh.peer_subscriptions
                .entry(*p)
                .or_default()
                .insert(bitmask.clone());
        }

        // Pre-populate mesh.
        let mesh_entry = bh.mesh.entry(bitmask.clone()).or_default();
        for p in &mesh_peers {
            mesh_entry.insert(*p);
        }

        (bh, bitmask, mesh_peers, candidates)
    }

    /// Mesh below D_LO + candidates available → heartbeat grafts up
    /// to D. (Fundamental D-LO maintenance.)
    #[test]
    fn heartbeat_grafts_when_below_d_lo() {
        let d = crate::params::D;
        let d_lo = crate::params::D_LO;
        let (mut bh, bitmask, _existing, candidates) =
            setup_subscribed_with_mesh_and_candidates(d_lo - 1, d * 2);
        assert!(bh.mesh.get(&bitmask).unwrap().len() < d_lo);
        let initial = bh.mesh.get(&bitmask).unwrap().len();

        bh.heartbeat();

        let after = bh.mesh.get(&bitmask).unwrap().len();
        assert_eq!(after, d, "should graft up to D after heartbeat");
        // The new peers must be drawn from the candidate pool.
        let new_grafted: Vec<PeerId> = bh
            .mesh
            .get(&bitmask)
            .unwrap()
            .iter()
            .filter(|p| candidates.contains(p))
            .copied()
            .collect();
        assert_eq!(new_grafted.len(), d - initial);
    }

    /// Mesh above D_HI → heartbeat prunes down to D.
    #[test]
    fn heartbeat_prunes_when_above_d_hi() {
        let d = crate::params::D;
        let d_hi = crate::params::D_HI;
        // Start with d_hi + 3 — clearly above the cap.
        let (mut bh, bitmask, _mesh_peers, _) =
            setup_subscribed_with_mesh_and_candidates(d_hi + 3, 0);
        assert!(bh.mesh.get(&bitmask).unwrap().len() > d_hi);

        bh.heartbeat();

        let after = bh.mesh.get(&bitmask).unwrap().len();
        assert_eq!(after, d, "should prune down to D after heartbeat");
    }

    /// Mesh at D → heartbeat is a no-op.
    #[test]
    fn heartbeat_at_d_neither_grafts_nor_prunes() {
        let d = crate::params::D;
        let (mut bh, bitmask, mesh_peers, _) =
            setup_subscribed_with_mesh_and_candidates(d, 0);
        let before: HashSet<PeerId> =
            bh.mesh.get(&bitmask).unwrap().iter().copied().collect();

        bh.heartbeat();

        let after: HashSet<PeerId> =
            bh.mesh.get(&bitmask).unwrap().iter().copied().collect();
        assert_eq!(before, after, "mesh at D must not be modified");
        assert_eq!(after.len(), mesh_peers.len());
    }

    /// Negative-score peers in the mesh are removed by heartbeat
    /// regardless of D_LO / D_HI state.
    #[test]
    fn heartbeat_removes_negative_score_peers_from_mesh() {
        let d = crate::params::D;
        let (mut bh, bitmask, mesh_peers, _) =
            setup_subscribed_with_mesh_and_candidates(d, 0);
        let bad_peer = mesh_peers[0];
        // Force a strongly negative score on one mesh peer.
        bh.scorer.set_application_score(bad_peer, -100.0);

        bh.heartbeat();

        let mesh = bh.mesh.get(&bitmask).unwrap();
        assert!(
            !mesh.contains(&bad_peer),
            "negative-score peer must be evicted from mesh",
        );
    }

    /// During a D_HI prune, outbound peers must survive even if
    /// they're not in the top-D_SCORE band. (Eclipse defense — we
    /// trust peers we dialed.)
    ///
    /// NB: outbound protection only applies when the peer survives
    /// the prior negative-score sweep (step 4a). A peer whose score
    /// has dropped negative is considered bad regardless of dial
    /// direction. This test stays in the small-positive-score band
    /// so 4a doesn't fire and 4c's outbound check is the load-
    /// bearing assertion.
    #[test]
    fn heartbeat_protects_outbound_during_d_hi_prune() {
        let d_hi = crate::params::D_HI;
        let d_score = crate::params::D_SCORE;
        let (mut bh, bitmask, mesh_peers, _) =
            setup_subscribed_with_mesh_and_candidates(d_hi + 3, 0);

        // Give the top D_SCORE peers high scores so they fill the
        // top-score protected band. The outbound peer sits BELOW
        // that band but has a small positive score (avoids 4a).
        for (i, p) in mesh_peers.iter().take(d_score).enumerate() {
            bh.scorer.set_application_score(*p, 100.0 + i as f64);
        }
        let outbound_peer = mesh_peers[d_hi]; // outside top-D_SCORE
        bh.outbound_peers
            .entry(bitmask.clone())
            .or_default()
            .insert(outbound_peer);
        bh.scorer.set_application_score(outbound_peer, 0.1);

        bh.heartbeat();

        let mesh = bh.mesh.get(&bitmask).unwrap();
        assert!(
            mesh.contains(&outbound_peer),
            "outbound peer must survive D_HI prune even when outside top-D_SCORE band",
        );
    }

    /// During a D_HI prune, the top-`D_SCORE` peers by score must
    /// survive.
    #[test]
    fn heartbeat_protects_top_d_score_during_d_hi_prune() {
        let d_hi = crate::params::D_HI;
        let d_score = crate::params::D_SCORE;
        let (mut bh, bitmask, mesh_peers, _) =
            setup_subscribed_with_mesh_and_candidates(d_hi + 3, 0);

        // Give the first `d_score` peers a high positive score
        // (must be > 0 so they're not pruned by the negative-score
        // sweep first).
        let top_peers: Vec<PeerId> = mesh_peers.iter().take(d_score).copied().collect();
        for (i, p) in top_peers.iter().enumerate() {
            bh.scorer.set_application_score(*p, 100.0 + i as f64);
        }

        bh.heartbeat();

        let mesh = bh.mesh.get(&bitmask).unwrap();
        for p in &top_peers {
            assert!(
                mesh.contains(p),
                "top-D_SCORE peer {:?} must survive D_HI prune",
                p,
            );
        }
    }

    /// A peer in the backoff map must not be picked as a graft
    /// candidate during heartbeat under-D_LO maintenance.
    /// (Flap-graft defense.)
    #[test]
    fn heartbeat_respects_backoff_when_grafting() {
        use std::time::{Duration, Instant};
        let d_lo = crate::params::D_LO;
        // 1 peer in mesh + candidates available, but one candidate is
        // in backoff.
        let (mut bh, bitmask, _mesh, candidates) =
            setup_subscribed_with_mesh_and_candidates(d_lo - 1, 5);

        let backed_off = candidates[0];
        bh.backoffs.insert(
            (backed_off, bitmask.clone()),
            Instant::now() + Duration::from_secs(60),
        );

        bh.heartbeat();

        let mesh = bh.mesh.get(&bitmask).unwrap();
        assert!(
            !mesh.contains(&backed_off),
            "backed-off peer must not be grafted during heartbeat",
        );
    }

    /// Peers that aren't subscribed to the bitmask must not be
    /// candidates for under-D_LO graft. (Basic correctness.)
    #[test]
    fn heartbeat_does_not_graft_unsubscribed_peers() {
        let d_lo = crate::params::D_LO;
        let (mut bh, bitmask, _mesh, candidates) =
            setup_subscribed_with_mesh_and_candidates(d_lo - 1, 5);

        // Drop subscription from one candidate.
        let unsubbed = candidates[0];
        if let Some(subs) = bh.peer_subscriptions.get_mut(&unsubbed) {
            subs.remove(&bitmask);
        }

        bh.heartbeat();

        let mesh = bh.mesh.get(&bitmask).unwrap();
        assert!(
            !mesh.contains(&unsubbed),
            "unsubscribed peer must not be grafted",
        );
    }

    /// When we receive an inbound PRUNE for a bitmask, the remote
    /// peer's `backoff` hint must be honored — we shouldn't try to
    /// re-GRAFT them before the suggested window expires. This is
    /// the flap-graft defense: without it, an attacker can prune us
    /// then immediately re-graft to refresh slot ownership, which
    /// defeats the purpose of the prune.
    #[test]
    fn incoming_prune_sets_backoff() {
        use std::time::Instant;

        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());

        let peer = make_peer();
        bh.peer_subscriptions
            .entry(peer)
            .or_default()
            .insert(bitmask.clone());
        bh.mesh.entry(bitmask.clone()).or_default().insert(peer);

        // Receive a PRUNE with a 60s backoff hint.
        let rpc = crate::protocol::prune_rpc(&[bitmask.clone()], 60);
        let before = Instant::now();
        bh.handle_rpc(peer, rpc);

        // The peer should now be in our backoff map for at least
        // ~60s ahead.
        let backoff_until = bh.backoffs.get(&(peer, bitmask.clone()));
        assert!(
            backoff_until.is_some(),
            "incoming PRUNE must populate the backoffs map so we don't \
             immediately re-GRAFT — flap-graft defense",
        );
        let until = *backoff_until.unwrap();
        let elapsed = until.duration_since(before);
        assert!(
            elapsed.as_secs() >= 55 && elapsed.as_secs() <= 65,
            "expected ~60s backoff (got {}s)",
            elapsed.as_secs(),
        );
    }

    /// PRUNE with `backoff = 0` should fall back to the local
    /// `prune_backoff` parameter (not "zero, no backoff").
    /// Otherwise a peer who omits the field could trick us into
    /// allowing instant re-grafts on their own future GRAFTs.
    #[test]
    fn incoming_prune_with_zero_backoff_uses_default() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());

        let peer = make_peer();
        bh.peer_subscriptions
            .entry(peer)
            .or_default()
            .insert(bitmask.clone());
        bh.mesh.entry(bitmask.clone()).or_default().insert(peer);

        let rpc = crate::protocol::prune_rpc(&[bitmask.clone()], 0);
        bh.handle_rpc(peer, rpc);

        let backoff_until = bh.backoffs.get(&(peer, bitmask.clone()));
        assert!(
            backoff_until.is_some(),
            "PRUNE with backoff=0 must still install some backoff (default), \
             not be treated as no backoff",
        );
    }

    /// Score-pruned peers go into the backoff map so they can't be
    /// re-grafted on the next heartbeat tick. (Prevents an attacker
    /// from cycling in and out of the mesh.)
    #[test]
    fn negative_score_prune_starts_backoff_implicitly() {
        let d = crate::params::D;
        let (mut bh, bitmask, mesh_peers, _) =
            setup_subscribed_with_mesh_and_candidates(d, 5);
        let bad_peer = mesh_peers[0];
        bh.scorer.set_application_score(bad_peer, -100.0);

        bh.heartbeat();
        // First heartbeat removed bad_peer. The mesh may now be
        // below D_LO; a second heartbeat should NOT graft the same
        // bad_peer back (negative score filter on graft candidates).
        bh.heartbeat();

        let mesh = bh.mesh.get(&bitmask).unwrap();
        assert!(
            !mesh.contains(&bad_peer),
            "negative-score peer must not be re-grafted after eviction",
        );
    }
}

#[cfg(test)]
mod direct_peer_tests {
    //! Contracts for direct peers: explicit operator-pinned peers
    //! that are always-grafted into every subscribed mesh and
    //! immune to D / D_HI / score pruning.
    //!
    //! Derived from `behaviour.rs:1337-1374` (heartbeat direct-peer
    //! maintenance) and `behaviour.rs:643` (incoming GRAFT bypass).
    use super::*;

    fn make_peer() -> PeerId {
        PeerId::random()
    }

    /// `add_direct_peer` registers the peer in the direct set.
    #[test]
    fn add_direct_peer_records_membership() {
        let mut bh = BlossomSubBehaviour::default();
        let peer = make_peer();
        bh.add_direct_peer(peer);
        assert!(bh.direct_peers.contains(&peer));
    }

    /// A connected direct peer is grafted into every subscribed
    /// mesh on the next heartbeat.
    #[test]
    fn heartbeat_grafts_direct_peer_into_every_mesh() {
        let mut bh = BlossomSubBehaviour::default();
        let direct = make_peer();
        let a = vec![0xC0];
        let b = vec![0x0C];
        bh.subscribe(a.clone());
        bh.subscribe(b.clone());
        bh.connected_peers.insert(direct, Vec::new());
        bh.add_direct_peer(direct);

        bh.heartbeat();

        assert!(bh.mesh.get(&a).map_or(false, |m| m.contains(&direct)),
            "direct peer must be grafted into mesh A");
        assert!(bh.mesh.get(&b).map_or(false, |m| m.contains(&direct)),
            "direct peer must be grafted into mesh B");
    }

    /// A direct peer that disconnects causes heartbeat to emit a
    /// `NeedPeers` event so the swarm layer can reconnect.
    #[test]
    fn heartbeat_emits_need_peers_for_disconnected_direct() {
        let mut bh = BlossomSubBehaviour::default();
        let direct = make_peer();
        bh.subscribe(vec![0xC0]);
        bh.add_direct_peer(direct);
        // Direct peer is NOT in connected_peers — represents
        // disconnected state.

        bh.heartbeat();

        let need_peers_emitted = bh.events.iter().any(|ev| {
            matches!(ev,
                libp2p::swarm::ToSwarm::GenerateEvent(
                    BlossomSubEvent::NeedPeers { .. }
                ))
        });
        assert!(need_peers_emitted,
            "disconnected direct peer must trigger NeedPeers event");
    }

    /// Heartbeat does not graft a direct peer that's not currently
    /// connected. (Disconnected direct peers can't be in the mesh.)
    #[test]
    fn heartbeat_does_not_graft_disconnected_direct() {
        let mut bh = BlossomSubBehaviour::default();
        let direct = make_peer();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());
        bh.add_direct_peer(direct);
        // Not in connected_peers.

        bh.heartbeat();

        assert!(!bh.mesh.get(&bitmask).map_or(false, |m| m.contains(&direct)),
            "disconnected direct peer must not be in mesh");
    }

    /// An incoming GRAFT from a direct peer is a misconfiguration
    /// (they're already pinned). Handler ignores and does not change
    /// mesh membership for that bitmask.
    #[test]
    fn incoming_graft_from_direct_peer_is_ignored() {
        let mut bh = BlossomSubBehaviour::default();
        let direct = make_peer();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());
        bh.add_direct_peer(direct);
        bh.peer_subscriptions
            .entry(direct)
            .or_default()
            .insert(bitmask.clone());

        // Mesh starts empty for this bitmask.
        let before: HashSet<PeerId> = bh
            .mesh
            .get(&bitmask)
            .cloned()
            .unwrap_or_default();

        // Direct GRAFT — should be ignored (no mesh change from
        // this RPC alone). Heartbeat would later graft via the
        // direct-peer path, but not this RPC handler.
        let rpc = crate::protocol::graft_rpc(&[bitmask.clone()]);
        bh.handle_rpc(direct, rpc);

        let after: HashSet<PeerId> = bh
            .mesh
            .get(&bitmask)
            .cloned()
            .unwrap_or_default();
        assert_eq!(before, after,
            "GRAFT from direct peer must not mutate mesh state via the RPC");
    }
}

#[cfg(test)]
mod publish_subscribe_tests {
    //! Contracts around `publish` + `subscribe`/`unsubscribe`.
    //! Behaviors covered:
    //!   - Publish-to-unsubscribed-bitmask is rejected (no implicit
    //!     fanout — see note below).
    //!   - Subscribe + unsubscribe round-trip cleans up state.
    //!   - Duplicate publish is deduped by seen-message cache.
    //!
    //! Gap flagged: Go gossipsub's fanout behavior (publish to a
    //! bitmask we don't subscribe to → fan out to D known peers)
    //! is NOT implemented. The `fanout` + `fanout_last_pub` fields
    //! exist and the heartbeat expiry runs, but no code path
    //! populates them. Tests in this module document the current
    //! "publish requires subscription" semantics; a future port of
    //! fanout would add more tests here.
    use super::*;

    /// Publish to a bitmask we haven't subscribed to returns Err.
    /// (Current semantics — no implicit fanout.)
    #[test]
    fn publish_unsubscribed_bitmask_errors() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        let result = bh.publish(bitmask, b"hello".to_vec());
        assert!(result.is_err(), "publish to unsubscribed bitmask must error");
    }

    /// Subscribe creates an entry; publish to a subscribed bitmask
    /// returns Ok.
    #[test]
    fn publish_subscribed_bitmask_succeeds() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());
        let result = bh.publish(bitmask, b"hello".to_vec());
        assert!(result.is_ok(), "publish to subscribed bitmask must succeed");
    }

    /// Duplicate publish (same data) is silently deduped by the
    /// seen-messages cache — second publish returns Ok but no new
    /// state change occurs.
    #[test]
    fn duplicate_publish_is_deduped() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());
        let payload = b"dup".to_vec();
        let r1 = bh.publish(bitmask.clone(), payload.clone());
        assert!(r1.is_ok());
        let r2 = bh.publish(bitmask, payload);
        assert!(r2.is_ok(), "dedup must be silent, not error");
    }

    /// Subscribe then unsubscribe leaves no residual subscription
    /// state for the bitmask.
    #[test]
    fn unsubscribe_clears_subscription() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());
        assert!(bh.subscriptions.contains(&bitmask));
        bh.unsubscribe(&bitmask);
        assert!(!bh.subscriptions.contains(&bitmask),
            "unsubscribe must remove the entry");
    }

    /// After unsubscribing, publish to that bitmask errors again —
    /// confirms unsubscribe also closes the publish path.
    #[test]
    fn publish_after_unsubscribe_errors() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());
        bh.unsubscribe(&bitmask);
        let r = bh.publish(bitmask, b"x".to_vec());
        assert!(r.is_err());
    }

    /// Re-subscribing after unsubscribe restores the publish path.
    #[test]
    fn resubscribe_restores_publish_path() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());
        bh.unsubscribe(&bitmask);
        bh.subscribe(bitmask.clone());
        let r = bh.publish(bitmask, b"x".to_vec());
        assert!(r.is_ok());
    }

    /// Subscribing twice to the same bitmask is idempotent (no
    /// duplicate entries, no error).
    #[test]
    fn duplicate_subscribe_is_idempotent() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());
        bh.subscribe(bitmask.clone());
        assert_eq!(
            bh.subscriptions.iter().filter(|s| *s == &bitmask).count(),
            1,
            "double-subscribe must not duplicate"
        );
    }
}

#[cfg(test)]
mod fanout_expiry_tests {
    //! Coverage of the fanout-expiry plumbing in `heartbeat`. The
    //! population side isn't implemented (see
    //! `publish_subscribe_tests` for the gap note); these tests pin
    //! the cleanup-side contract so it doesn't silently break when
    //! fanout publish is later added.
    use super::*;
    use std::time::{Duration, Instant};

    /// A fanout entry whose last-publish is past the TTL gets
    /// removed by heartbeat. Both `fanout` and `fanout_last_pub`
    /// drop the bitmask.
    #[test]
    fn heartbeat_expires_stale_fanout() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];

        // Seed a fanout entry whose last publish is older than the
        // configured fanout_ttl.
        let ttl = bh.params.fanout_ttl;
        let stale = Instant::now() - ttl - Duration::from_secs(1);
        bh.fanout
            .entry(bitmask.clone())
            .or_default()
            .insert(PeerId::random());
        bh.fanout_last_pub.insert(bitmask.clone(), stale);

        bh.heartbeat();

        assert!(!bh.fanout.contains_key(&bitmask),
            "stale fanout must be cleaned");
        assert!(!bh.fanout_last_pub.contains_key(&bitmask),
            "stale fanout_last_pub must be cleaned");
    }

    /// A recently-published fanout entry survives heartbeat. The
    /// peer must be in `connected_peers` or section 6 of heartbeat
    /// (disconnected-peer cleanup) sweeps it independently of TTL.
    #[test]
    fn heartbeat_keeps_fresh_fanout() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        let fresh_peer = PeerId::random();

        // Pretend the peer is connected so heartbeat's
        // disconnected-cleanup pass doesn't drop it.
        bh.connected_peers.insert(fresh_peer, Vec::new());

        bh.fanout
            .entry(bitmask.clone())
            .or_default()
            .insert(fresh_peer);
        bh.fanout_last_pub.insert(bitmask.clone(), Instant::now());

        bh.heartbeat();

        assert!(bh.fanout.get(&bitmask).map_or(false, |s| s.contains(&fresh_peer)),
            "fresh fanout entry with connected peer must survive");
        assert!(bh.fanout_last_pub.contains_key(&bitmask));
    }

    /// Section 6 of heartbeat removes disconnected peers from fanout
    /// even when the TTL hasn't expired. This is the implicit
    /// pruning the fresh-fanout test had to avoid.
    #[test]
    fn heartbeat_prunes_disconnected_fanout_peers() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        let dropped_peer = PeerId::random();

        // Deliberately do NOT add the peer to connected_peers.
        bh.fanout
            .entry(bitmask.clone())
            .or_default()
            .insert(dropped_peer);
        bh.fanout_last_pub.insert(bitmask.clone(), Instant::now());

        bh.heartbeat();

        assert!(
            !bh.fanout.get(&bitmask).map_or(false, |s| s.contains(&dropped_peer)),
            "disconnected fanout peer must be swept by heartbeat",
        );
    }
}

#[cfg(test)]
mod backoff_tests {
    //! Backoff-map maintenance properties. The heartbeat sweep at
    //! `behaviour.rs:1384` calls `self.backoffs.retain(|_, e| *e > now)`
    //! — these tests pin the observable behavior of that sweep plus
    //! the (peer, bitmask) uniqueness of backoff keys.
    use super::*;
    use std::time::{Duration, Instant};

    fn make_peer() -> PeerId {
        PeerId::random()
    }

    fn fresh_behaviour() -> BlossomSubBehaviour {
        let mut bh = BlossomSubBehaviour::default();
        // Subscribe to a bitmask so the heartbeat loop enters its
        // main work — the backoff sweep at the top of `heartbeat`
        // runs regardless of subscriptions, but a subscription makes
        // the function representative of production runs.
        bh.subscribe(vec![0xC0]);
        bh
    }

    /// A backoff whose expiry is in the past gets pruned on the
    /// next heartbeat. (Required for flap-graft to release the peer
    /// after the punitive window passes.)
    #[test]
    fn heartbeat_removes_expired_backoff_entry() {
        let mut bh = fresh_behaviour();
        let bitmask = vec![0xC0];
        let peer = make_peer();
        // Expiry already in the past.
        let past = Instant::now() - Duration::from_secs(5);
        bh.backoffs.insert((peer, bitmask.clone()), past);

        bh.heartbeat();

        assert!(
            !bh.backoffs.contains_key(&(peer, bitmask)),
            "expired backoff entry should have been swept",
        );
    }

    /// A backoff whose expiry is well in the future survives the
    /// heartbeat sweep.
    #[test]
    fn heartbeat_preserves_unexpired_backoff_entry() {
        let mut bh = fresh_behaviour();
        let bitmask = vec![0xC0];
        let peer = make_peer();
        let future = Instant::now() + Duration::from_secs(120);
        bh.backoffs.insert((peer, bitmask.clone()), future);

        bh.heartbeat();

        let stored = bh.backoffs.get(&(peer, bitmask)).copied();
        assert_eq!(stored, Some(future), "unexpired backoff must persist");
    }

    /// Mixed expired + unexpired entries are partitioned correctly:
    /// only the expired ones are dropped.
    #[test]
    fn heartbeat_partitions_mixed_expiries() {
        let mut bh = fresh_behaviour();
        let bitmask = vec![0xC0];
        let past_peer = make_peer();
        let future_peer = make_peer();
        bh.backoffs
            .insert((past_peer, bitmask.clone()), Instant::now() - Duration::from_secs(1));
        bh.backoffs
            .insert((future_peer, bitmask.clone()), Instant::now() + Duration::from_secs(60));

        bh.heartbeat();

        assert!(!bh.backoffs.contains_key(&(past_peer, bitmask.clone())));
        assert!(bh.backoffs.contains_key(&(future_peer, bitmask)));
    }

    /// Backoff is keyed by (peer, bitmask) — same peer pruned from
    /// one bitmask doesn't affect their backoff state on a different
    /// bitmask.
    #[test]
    fn backoff_keys_are_per_peer_per_bitmask() {
        let mut bh = fresh_behaviour();
        let peer = make_peer();
        let a = vec![0xC0];
        let b = vec![0x0C];
        let past = Instant::now() - Duration::from_secs(1);
        let future = Instant::now() + Duration::from_secs(60);
        bh.backoffs.insert((peer, a.clone()), past);
        bh.backoffs.insert((peer, b.clone()), future);

        bh.heartbeat();

        assert!(!bh.backoffs.contains_key(&(peer, a)));
        assert!(bh.backoffs.contains_key(&(peer, b)));
    }
}

#[cfg(test)]
mod subnet_diversity_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    fn make_peer() -> PeerId {
        PeerId::random()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(parts: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            parts[0], parts[1], parts[2], parts[3],
            parts[4], parts[5], parts[6], parts[7],
        ))
    }

    /// Same /24, different host → same bucket key.
    #[test]
    fn ipv4_slash_24_buckets_match() {
        let a = subnet_bucket_key(v4(192, 0, 2, 17));
        let b = subnet_bucket_key(v4(192, 0, 2, 42));
        assert_eq!(a, b, "/24 mates must share a bucket");
    }

    /// Different /24 → different bucket keys.
    #[test]
    fn ipv4_different_slash_24_buckets_differ() {
        let a = subnet_bucket_key(v4(192, 0, 2, 17));
        let b = subnet_bucket_key(v4(192, 0, 3, 17));
        assert_ne!(a, b);
    }

    /// Same /48, different higher bits → same bucket key.
    #[test]
    fn ipv6_slash_48_buckets_match() {
        let a = subnet_bucket_key(v6([0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 1]));
        let b = subnet_bucket_key(v6([0x2001, 0xdb8, 0xabcd, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff]));
        assert_eq!(a, b, "/48 mates must share a bucket");
    }

    /// IPv4 and IPv6 buckets never collide for normal prefixes.
    #[test]
    fn v4_and_v6_buckets_do_not_collide() {
        let a = subnet_bucket_key(v4(192, 0, 2, 1));
        let b = subnet_bucket_key(v6([0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 1]));
        assert_ne!(a, b);
    }

    /// The subnet-cap helper rejects a candidate whose /24 already
    /// has `mesh_peers_per_subnet` peers in the mesh.
    #[test]
    fn graft_would_violate_subnet_cap_blocks_overpopulated_subnet() {
        let mut bh = BlossomSubBehaviour::default();
        bh.params.mesh_peers_per_subnet = 2;

        let mut existing_a = HashSet::new();
        existing_a.insert(v4(10, 0, 0, 1));
        let mut existing_b = HashSet::new();
        existing_b.insert(v4(10, 0, 0, 2));
        let mut candidate_ips = HashSet::new();
        candidate_ips.insert(v4(10, 0, 0, 3));

        let p1 = make_peer();
        let p2 = make_peer();
        let candidate = make_peer();

        bh.scorer.set_peer_ips(&p1, existing_a);
        bh.scorer.set_peer_ips(&p2, existing_b);
        bh.scorer.set_peer_ips(&candidate, candidate_ips);

        let mut mesh: HashSet<PeerId> = HashSet::new();
        mesh.insert(p1);
        mesh.insert(p2);

        assert!(
            bh.graft_would_violate_subnet_cap(&mesh, &candidate),
            "candidate sharing /24 with 2 existing mesh peers should be rejected",
        );
    }

    /// A candidate from a fresh subnet (not represented in the mesh
    /// yet) must pass the cap.
    #[test]
    fn graft_would_violate_subnet_cap_admits_fresh_subnet() {
        let mut bh = BlossomSubBehaviour::default();
        bh.params.mesh_peers_per_subnet = 2;

        let mut existing_ips = HashSet::new();
        existing_ips.insert(v4(10, 0, 0, 1));
        let mut other_ips = HashSet::new();
        other_ips.insert(v4(10, 0, 0, 2));
        let mut fresh_ips = HashSet::new();
        fresh_ips.insert(v4(192, 168, 1, 1)); // distinct /24

        let p1 = make_peer();
        let p2 = make_peer();
        let candidate = make_peer();

        bh.scorer.set_peer_ips(&p1, existing_ips);
        bh.scorer.set_peer_ips(&p2, other_ips);
        bh.scorer.set_peer_ips(&candidate, fresh_ips);

        let mut mesh: HashSet<PeerId> = HashSet::new();
        mesh.insert(p1);
        mesh.insert(p2);

        assert!(
            !bh.graft_would_violate_subnet_cap(&mesh, &candidate),
            "candidate from a fresh /24 must pass",
        );
    }

    /// When the cap is `0` (disabled), even a maxed-out subnet
    /// accepts new candidates.
    #[test]
    fn graft_would_violate_subnet_cap_zero_disables_check() {
        let mut bh = BlossomSubBehaviour::default();
        bh.params.mesh_peers_per_subnet = 0;

        let mut ips_each = HashSet::new();
        ips_each.insert(v4(10, 0, 0, 1));
        let p1 = make_peer();
        let p2 = make_peer();
        let candidate = make_peer();
        bh.scorer.set_peer_ips(&p1, ips_each.clone());
        bh.scorer.set_peer_ips(&p2, ips_each.clone());
        bh.scorer.set_peer_ips(&candidate, ips_each);

        let mut mesh: HashSet<PeerId> = HashSet::new();
        mesh.insert(p1);
        mesh.insert(p2);

        assert!(
            !bh.graft_would_violate_subnet_cap(&mesh, &candidate),
            "cap=0 must disable the check",
        );
    }

    /// A peer with no known IPs (libp2p hasn't seen its address yet)
    /// passes the cap — otherwise no peer could ever join until its
    /// IP was observed elsewhere, which is a chicken-and-egg.
    #[test]
    fn graft_would_violate_subnet_cap_admits_unknown_ip_peer() {
        let mut bh = BlossomSubBehaviour::default();
        bh.params.mesh_peers_per_subnet = 1;

        let mut ips_e = HashSet::new();
        ips_e.insert(v4(10, 0, 0, 1));
        let p1 = make_peer();
        let candidate = make_peer();
        bh.scorer.set_peer_ips(&p1, ips_e);
        // Deliberately do not call set_peer_ips for `candidate`.

        let mut mesh: HashSet<PeerId> = HashSet::new();
        mesh.insert(p1);

        assert!(
            !bh.graft_would_violate_subnet_cap(&mesh, &candidate),
            "candidate with no known IP must not be falsely blocked",
        );
    }
}

#[cfg(test)]
mod behavior_parity_tests {
    //! Cross-cutting behavior tests that pin Go-gossipsub semantics
    //! we promised to honor even where the Rust layout diverges from
    //! the Go file layout. Each test names the load-bearing
    //! invariant; if these regress, mesh stability or DoS resistance
    //! regresses with them.
    use super::*;
    use std::time::{Duration, Instant};

    fn make_peer() -> PeerId {
        PeerId::random()
    }

    /// Backoff entry that has expired must release the peer for
    /// graft on the next under-D_LO heartbeat. The sweep at the top
    /// of `heartbeat` does the structural removal; this test ties
    /// it to the graft-candidate selection downstream — the peer
    /// that was backed off should now show up in the mesh.
    #[test]
    fn expired_backoff_clears_and_peer_becomes_graft_eligible() {
        let d_lo = crate::params::D_LO;
        let bitmask = vec![0xC0];

        // Start with mesh below D_LO and 5 candidates. One of the
        // candidates is in backoff with an already-past expiry.
        let mut bh = BlossomSubBehaviour::default();
        bh.subscribe(bitmask.clone());

        // Seed mesh with d_lo - 1 peers and 5 candidates so the
        // under-D_LO graft pass kicks in.
        let mesh_peers: Vec<PeerId> = (0..d_lo - 1).map(|_| make_peer()).collect();
        let candidates: Vec<PeerId> = (0..5).map(|_| make_peer()).collect();
        for p in mesh_peers.iter().chain(candidates.iter()) {
            bh.peer_subscriptions
                .entry(*p)
                .or_default()
                .insert(bitmask.clone());
        }
        let mesh = bh.mesh.entry(bitmask.clone()).or_default();
        for p in &mesh_peers {
            mesh.insert(*p);
        }

        let target = candidates[0];
        // Already-expired backoff. The heartbeat sweep is the only
        // thing that should clear this; we don't pre-remove it.
        bh.backoffs
            .insert((target, bitmask.clone()), Instant::now() - Duration::from_secs(60));

        bh.heartbeat();

        assert!(
            !bh.backoffs.contains_key(&(target, bitmask.clone())),
            "expired backoff entry must be removed by heartbeat sweep",
        );
        // Under-D_LO graft drew from the now-clean candidate pool;
        // the target peer is no longer filtered out. We can't
        // assert the target was specifically grafted (selection is
        // randomized across the 5 candidates), but we can assert
        // the mesh grew to at least D_LO — proving the graft pass
        // ran on a pool that included our previously-blocked peer.
        let mesh = bh.mesh.get(&bitmask).unwrap();
        assert!(
            mesh.len() >= d_lo,
            "mesh should have grown to at least D_LO after backoff cleared",
        );
    }

    /// IHAVE flood from a single peer caps `pending_iwants` at
    /// 5000. This is the DoS bound: without it, an attacker
    /// enumerates message-id space and balloons our memory.
    #[test]
    fn ihave_flood_caps_pending_iwants_at_5000() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];
        bh.subscribe(bitmask.clone());

        let peer = make_peer();
        bh.connected_peers.insert(peer, Vec::new());
        bh.peer_subscriptions
            .entry(peer)
            .or_default()
            .insert(bitmask.clone());

        // Build an IHAVE RPC advertising 5500 unique message IDs.
        // Each one is a fresh 32-byte vector keyed off the index.
        let advertised: Vec<Vec<u8>> = (0..5500u32)
            .map(|i| {
                let mut id = vec![0u8; 32];
                id[..4].copy_from_slice(&i.to_be_bytes());
                id
            })
            .collect();
        let rpc = pb::Rpc {
            subscriptions: Vec::new(),
            publish: Vec::new(),
            control: Some(pb::ControlMessage {
                ihave: vec![pb::ControlIHave {
                    bitmask: bitmask.clone(),
                    message_i_ds: advertised,
                }],
                iwant: Vec::new(),
                graft: Vec::new(),
                prune: Vec::new(),
                idontwant: Vec::new(),
            }),
        };

        bh.handle_rpc(peer, rpc);

        assert!(
            bh.pending_iwants.len() <= 5000,
            "pending_iwants must be capped at 5000 (got {})",
            bh.pending_iwants.len(),
        );
        // The cap must have actually fired — if it allowed all
        // 5500, the assertion above is meaningless. Check we hit
        // the ceiling.
        assert_eq!(
            bh.pending_iwants.len(),
            5000,
            "expected the cap to be hit exactly under a 5500-entry flood",
        );
    }

    /// `refresh_scores` decays `behaviour_penalty` exponentially by
    /// `behaviour_penalty_decay` (default 0.9) on each call. After
    /// enough ticks the penalty falls below `decay_to_zero` (0.01)
    /// and is zeroed. This is what gives a peer back its score
    /// after a transient violation.
    #[test]
    fn refresh_scores_decays_behaviour_penalty_to_zero() {
        let mut bh = BlossomSubBehaviour::default();
        let peer = make_peer();

        // Mark peer connected so `refresh_scores` decays its stats
        // (disconnected peers are intentionally not decayed).
        bh.scorer.add_peer(&peer);

        // Add a penalty and confirm it's recorded.
        bh.scorer.add_penalty(&peer, 5.0);

        // Apply enough decay ticks that 5.0 * 0.9^n < 0.01.
        // 5.0 * 0.9^60 ≈ 0.009 → zeroed.
        for _ in 0..60 {
            bh.scorer.refresh_scores();
        }

        // After zeroing, the peer's overall score must no longer
        // reflect the original penalty. We can't introspect the
        // penalty field directly here, but score() exposes the
        // weighted result — with the penalty zeroed it should be
        // 0.0 (no other stats set).
        let score = bh.scorer.score(&peer);
        assert!(
            score.abs() < 1e-6,
            "score should be ~0 after behaviour_penalty fully decays (got {})",
            score,
        );
    }

    /// `refresh_scores` applies the per-tick decay multiplicatively.
    /// One tick reduces a fresh penalty by exactly the configured
    /// decay factor (modulo the `decay_to_zero` floor, which won't
    /// fire for the magnitude we use here).
    #[test]
    fn refresh_scores_single_tick_applies_decay_factor() {
        let mut bh = BlossomSubBehaviour::default();
        let peer = make_peer();
        bh.scorer.add_peer(&peer);

        // Use a penalty large enough that one decay won't cross
        // the decay_to_zero floor (0.01 default).
        bh.scorer.add_penalty(&peer, 10.0);
        let before = bh.scorer.score(&peer);

        bh.scorer.refresh_scores();

        let after = bh.scorer.score(&peer);
        // P7 (behaviour_penalty) contributes a squared excess
        // weighted by behaviour_penalty_weight (negative). After
        // one decay, the penalty shrinks → squared term shrinks
        // → score becomes less negative (i.e., increases).
        assert!(
            after > before,
            "score must increase after one decay tick (before={}, after={})",
            before,
            after,
        );
    }

    /// Leave/rejoin churn: subscribe → mesh populated → unsubscribe
    /// (drops mesh) → resubscribe → next heartbeat repopulates from
    /// candidates without carrying any stale peers from the prior
    /// mesh that have since become ineligible. The contract here is
    /// **no residual state leak** across the subscription
    /// boundary.
    #[test]
    fn leave_then_rejoin_repopulates_clean_mesh_without_stale_entries() {
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];

        // Subscribe and seed mesh with 4 peers.
        bh.subscribe(bitmask.clone());
        let original: Vec<PeerId> = (0..4).map(|_| make_peer()).collect();
        for p in &original {
            bh.peer_subscriptions
                .entry(*p)
                .or_default()
                .insert(bitmask.clone());
            bh.mesh.entry(bitmask.clone()).or_default().insert(*p);
        }
        assert_eq!(bh.mesh.get(&bitmask).unwrap().len(), 4);

        // Unsubscribe drops the mesh entry entirely.
        bh.unsubscribe(&bitmask);
        assert!(
            !bh.mesh.contains_key(&bitmask),
            "unsubscribe must remove mesh entry",
        );

        // Two of the original peers are now poisoned with a strong
        // negative score — they must NOT come back into the new
        // mesh after resubscribe even though they're still in
        // peer_subscriptions.
        let poisoned: Vec<PeerId> = original[..2].to_vec();
        for p in &poisoned {
            bh.scorer.set_application_score(*p, -1000.0);
        }

        // Resubscribe and run heartbeat to repopulate.
        bh.subscribe(bitmask.clone());
        // Add fresh candidates so heartbeat has graft material that
        // isn't poisoned.
        let fresh: Vec<PeerId> = (0..8).map(|_| make_peer()).collect();
        for p in &fresh {
            bh.peer_subscriptions
                .entry(*p)
                .or_default()
                .insert(bitmask.clone());
        }
        bh.heartbeat();

        let new_mesh = bh.mesh.get(&bitmask).cloned().unwrap_or_default();
        for poisoned_peer in &poisoned {
            assert!(
                !new_mesh.contains(poisoned_peer),
                "poisoned peer {:?} must not return to mesh after rejoin",
                poisoned_peer,
            );
        }
        assert!(
            !new_mesh.is_empty(),
            "rejoined mesh must be populated from clean candidates",
        );
    }

    /// Subscribe-then-graft contract: when we subscribe to a
    /// bitmask, peers that are already subscribed to it and
    /// connected become mesh candidates on the next heartbeat. This
    /// is the Rust shape of Go's "fanout-promotion-on-subscribe" —
    /// the Go behaviour copies fanout peers into the new mesh; the
    /// Rust path achieves the same outcome via the candidate-pool
    /// selection during the under-D_LO graft pass.
    #[test]
    fn subscribe_then_heartbeat_grafts_known_subscribers_into_mesh() {
        let d = crate::params::D;
        let mut bh = BlossomSubBehaviour::default();
        let bitmask = vec![0xC0];

        // Pre-existing connected peers, already subscribed to the
        // bitmask (mirroring fanout-having-tracked-them state).
        let known_subscribers: Vec<PeerId> = (0..d + 2).map(|_| make_peer()).collect();
        for p in &known_subscribers {
            bh.connected_peers.insert(*p, Vec::new());
            bh.peer_subscriptions
                .entry(*p)
                .or_default()
                .insert(bitmask.clone());
        }

        // Now subscribe ourselves. Mesh is empty at this point.
        bh.subscribe(bitmask.clone());
        assert!(
            bh.mesh.get(&bitmask).map_or(true, |m| m.is_empty()),
            "fresh subscribe must start with empty mesh",
        );

        // Heartbeat should graft from the known-subscriber pool.
        bh.heartbeat();

        let mesh = bh.mesh.get(&bitmask).expect("mesh must exist post-heartbeat");
        assert_eq!(
            mesh.len(),
            d,
            "heartbeat must graft up to D from the known-subscriber pool",
        );
        // Every peer in the new mesh must come from our known set.
        for p in mesh.iter() {
            assert!(
                known_subscribers.contains(p),
                "grafted peer must be drawn from known subscribers",
            );
        }
    }
}
