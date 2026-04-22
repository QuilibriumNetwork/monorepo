//! BlossomSub `NetworkBehaviour` implementation.
//!
//! Uses a custom `BlossomSubHandler` for each connection to exchange
//! protobuf RPCs over bidirectional libp2p streams.

use std::collections::{HashMap, HashSet, VecDeque};
use std::task::{Context, Poll};
use std::time::Instant;

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use tracing::debug;

use crate::handler::{BlossomSubHandler, HandlerIn, HandlerOut};
use crate::protocol::{self, pb};

// Re-export from the canonical location in quil-types.
pub use quil_types::p2p::ValidationResult;

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
    /// Seen message IDs (dedup).
    seen_messages: HashSet<Vec<u8>>,
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
    scorer: crate::scoring::PeerScorer,
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
}

impl BlossomSubBehaviour {
    pub fn new() -> Self {
        Self {
            subscriptions: HashSet::new(),
            peer_subscriptions: HashMap::new(),
            connected_peers: HashMap::new(),
            mesh: HashMap::new(),
            events: VecDeque::new(),
            seen_messages: HashSet::new(),
            mcache: crate::blossomsub::MessageCache::new(
                crate::params::HISTORY_LENGTH,
                crate::params::HISTORY_GOSSIP,
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
            debug!(bitmask = hex::encode(&bitmask), "subscribed to bitmask");
            self.rebuild_subscribe_rpc();

            // Send to all connected peers
            if let Some(rpc_data) = &self.pending_subscribe_rpc {
                let peers: Vec<(PeerId, ConnectionId)> = self
                    .connected_peers
                    .iter()
                    .filter_map(|(p, conns)| conns.first().map(|c| (*p, *c)))
                    .collect();
                for (peer, _conn) in peers {
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

        if !self.seen_messages.insert(msg_id.clone()) {
            return Ok(());
        }

        // Build the protobuf message with signing fields.
        // Go's BlossomSub with StrictSign requires: from, seqno, signature, key.
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
                    tracing::debug!(error = %e, "failed to sign pubsub message");
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
    fn handle_rpc(&mut self, peer: PeerId, rpc: pb::Rpc) {
        // Graylist gate — matches Go's BlossomSub
        // `p.peerFilter`/`Graylisted` check at the top of
        // `handleReceivedRPC`. Peers below the graylist threshold
        // have all RPC processing suppressed, including subscribes,
        // graft, prune, and publish. This is the primary defense
        // against spam from misbehaving peers.
        if self.scorer.score(&peer) < self.scorer.thresholds.graylist_threshold
            && !self.direct_peers.contains(&peer)
        {
            debug!(
                %peer,
                score = self.scorer.score(&peer),
                threshold = self.scorer.thresholds.graylist_threshold,
                "dropping RPC from graylisted peer"
            );
            return;
        }

        // Subscriptions
        for sub in &rpc.subscriptions {
            let subs = self.peer_subscriptions.entry(peer).or_default();
            if sub.subscribe {
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
            if !self.seen_messages.insert(msg_id.clone()) {
                continue; // Dedup
            }

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
                        debug!(
                            %peer,
                            bitmask = hex::encode(&msg.bitmask),
                            "message ignored by validator"
                        );
                        continue;
                    }
                    ValidationResult::Accept => {} // fall through
                }
            }

            // Slice the message bitmask and check if any slice matches
            // a local subscription (matching Go's delivery semantics).
            let slices = crate::bitmask::slice_bitmask(&msg.bitmask);
            let locally_subscribed = slices.iter()
                .any(|s| self.subscriptions.contains(s));

            if locally_subscribed {
                // Credit the sender with a delivery — peers who
                // consistently relay valid messages we care about
                // earn positive score. Matches
                // go-libp2p-blossomsub's `DeliverMessage` path.
                self.scorer.add_delivery(&peer, &msg.bitmask);

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

            // Forward to mesh peers of each slice (excluding source),
            // deduplicating so each peer only gets the message once.
            let mut forwarded_to: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
            let forward_rpc = protocol::publish_rpc(vec![msg]);
            let encoded = protocol::encode_rpc(&forward_rpc);
            for slice in &slices {
                if let Some(mesh_peers) = self.mesh.get(slice.as_slice()) {
                    for mesh_peer in mesh_peers.iter() {
                        if *mesh_peer == peer { continue; }
                        if !forwarded_to.insert(*mesh_peer) { continue; }
                        if let Some(conns) = self.connected_peers.get(mesh_peer) {
                            if let Some(&conn) = conns.first() {
                                self.events.push_back(ToSwarm::NotifyHandler {
                                    peer_id: *mesh_peer,
                                    handler: NotifyHandler::One(conn),
                                    event: HandlerIn {
                                        rpc_data: encoded.clone(),
                                    },
                                });
                            }
                        }
                    }
                }
            }
        }

        // Control messages
        if let Some(control) = rpc.control {
            for graft in &control.graft {
                if self.subscriptions.contains(&graft.bitmask) {
                    self.mesh
                        .entry(graft.bitmask.clone())
                        .or_default()
                        .insert(peer);
                    debug!(%peer, bitmask = hex::encode(&graft.bitmask), "grafted");
                }
            }
            for prune in &control.prune {
                if let Some(mesh) = self.mesh.get_mut(&prune.bitmask) {
                    mesh.remove(&peer);
                }
            }

            // Respond to IHAVE with IWANT for messages we haven't seen
            let mut wanted: Vec<Vec<u8>> = Vec::new();
            for ihave in &control.ihave {
                for msg_id in &ihave.message_i_ds {
                    if !self.seen_messages.contains(msg_id) {
                        wanted.push(msg_id.clone());
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

            // Serve IWANT requests from message cache
            for iwant in &control.iwant {
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

    /// Total mesh peers across all bitmasks.
    pub fn mesh_peer_counts(&self) -> usize {
        self.mesh.values().map(|m| m.len()).sum()
    }

    /// Get total connected peers.
    pub fn num_connected(&self) -> usize {
        self.connected_peers.len()
    }

    fn heartbeat(&mut self) {
        self.heartbeat_ticks += 1;

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

        // 1. Shift message cache (expire old entries)
        self.mcache.shift();
        if self.seen_messages.len() > 10_000 {
            self.seen_messages.clear();
        }

        // 2. Expire stale backoffs
        let now = Instant::now();
        self.backoffs.retain(|_, expiry| *expiry > now);

        // 3. Expire stale fanout entries
        let fanout_ttl = crate::params::FANOUT_TTL;
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
            if mesh.len() < crate::params::D_LO {
                let needed = crate::params::D - mesh.len();
                let candidates: Vec<PeerId> = self
                    .peer_subscriptions
                    .iter()
                    .filter(|(p, subs)| {
                        subs.contains(bitmask)
                            && !mesh.contains(p)
                            && !self.backoffs.contains_key(&(**p, bitmask.clone()))
                            && self.scorer.score(p) >= 0.0
                    })
                    .map(|(p, _)| *p)
                    .take(needed)
                    .collect();

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
            if mesh.len() > crate::params::D_HI {
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
                for (peer, _) in scored.iter().take(crate::params::D_SCORE) {
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
                .take(crate::params::D_LAZY)
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
                debug!(
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
            if mesh_count < crate::params::D_LO {
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
        let backoff_secs = crate::params::PRUNE_BACKOFF.as_secs();
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
                    Instant::now() + crate::params::PRUNE_BACKOFF,
                );
            }
        }
    }
}

impl Default for BlossomSubBehaviour {
    fn default() -> Self {
        Self::new()
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
        Ok(BlossomSubHandler::new())
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
        Ok(BlossomSubHandler::new())
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                self.connected_peers
                    .entry(e.peer_id)
                    .or_default()
                    .push(e.connection_id);

                // Send subscriptions immediately as a "hello packet"
                // (matches Go's getHelloPacket() behavior in comm.go)
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
                        for mesh in self.mesh.values_mut() {
                            mesh.remove(&e.peer_id);
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
        if self.last_heartbeat.elapsed() >= crate::params::HEARTBEAT_INTERVAL {
            self.heartbeat();
            self.last_heartbeat = Instant::now();
        }

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}
