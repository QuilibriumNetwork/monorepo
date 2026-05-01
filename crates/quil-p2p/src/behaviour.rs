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
use tracing::{debug, info, trace};

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
    /// Mirrors Go's connection gater.
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
    /// Composite meshes for multi-bit bitmasks. Key = full (unspliced) bitmask.
    composites: HashMap<Vec<u8>, CompositeMeshEntry>,
    /// Reverse index: slice bitmask -> list of composite bitmask keys managing it.
    slice_to_composite: HashMap<Vec<u8>, Vec<Vec<u8>>>,
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
            composites: HashMap::new(),
            slice_to_composite: HashMap::new(),
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

            // Establish composite mesh state for multi-slice bitmasks. Mirrors
            // Go's JoinComposite. Single-slice bitmasks fall through to the
            // simple per-slice mesh maintenance in `heartbeat`.
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
                    tracing::info!(
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
    fn handle_rpc(&mut self, peer: PeerId, rpc: pb::Rpc) {
        // Subscriptions
        for sub in &rpc.subscriptions {
            let subs = self.peer_subscriptions.entry(peer).or_default();
            if sub.subscribe {
                if subs.insert(sub.bitmask.clone()) {
                    // INFO-level log if peer subscribes to a bitmask we also
                    // subscribe to (likely a master/validator).
                    if self.subscriptions.contains(&sub.bitmask) {
                        info!(
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
            info!(
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

            // Forward to mesh peers (excluding source)
            if let Some(mesh_peers) = self.mesh.get(&msg.bitmask) {
                let forward_rpc = protocol::publish_rpc(vec![msg]);
                let encoded = protocol::encode_rpc(&forward_rpc);
                let targets: Vec<(PeerId, ConnectionId)> = mesh_peers
                    .iter()
                    .filter(|p| **p != peer)
                    .filter_map(|p| {
                        self.connected_peers
                            .get(p)
                            .and_then(|c| c.first())
                            .map(|c| (*p, *c))
                    })
                    .collect();
                for (target, conn) in targets {
                    self.events.push_back(ToSwarm::NotifyHandler {
                        peer_id: target,
                        handler: NotifyHandler::Any,
                        event: HandlerIn {
                            rpc_data: encoded.clone(),
                        },
                    });
                }
            }
        }

        // Control messages
        if let Some(control) = rpc.control {
            let mut composite_touched = false;
            for graft in &control.graft {
                // A GRAFT is addressed to a slice bitmask. Accept it if
                // either (a) we are subscribed to that exact bitmask
                // (single-slice case) or (b) the slice is composite-managed
                // (multi-slice case — Go's bs.mesh[slice] exists because
                // rebuildSliceMeshes populated it). This mirrors Go's
                // `bs.mesh[string(bitmask)]` check.
                let is_subscribed = self.subscriptions.contains(&graft.bitmask);
                let is_composite_slice =
                    self.slice_to_composite.contains_key(&graft.bitmask);
                if !is_subscribed && !is_composite_slice {
                    continue;
                }

                // Always add to the simple slice mesh (matches Go's
                // fall-through behaviour — the per-slice mesh map still
                // exists and is used for forwarding on the wire).
                self.mesh
                    .entry(graft.bitmask.clone())
                    .or_default()
                    .insert(peer);
                debug!(%peer, bitmask = hex::encode(&graft.bitmask), "grafted");

                // If this slice is managed by one or more composites,
                // classify the peer as same/broker based on its
                // subscription set. Mirrors Go blossomsub.go:1052-1084.
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
                // If this slice is managed by a composite, demote the peer
                // from `same` to `broker` rather than removing it from the
                // mesh — brokers remain in every slice mesh so traffic can
                // still bridge.  Only actually remove from the slice mesh
                // when the peer is not managed by any composite (or has
                // fully dropped out of them).  Mirrors Go blossomsub.go:1112-1144.
                let composite_managed =
                    self.slice_to_composite.contains_key(&prune.bitmask);
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
                info!(%peer, "sending subscription RPC (Identify confirmed BlossomSub)");
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
    /// Mirrors Go's JoinComposite.
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
    /// Mirrors Go's LeaveComposite.
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
    /// or `Broker` (subscribed to at least one but not all). Mirrors Go's
    /// classifyPeer — on missing data we fall back to Broker.
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
    /// Mirrors Go's rebuildSliceMeshes: every composite peer (same + broker)
    /// is present in every slice mesh, because brokers intentionally bridge
    /// non-subscribed slices — messages carry the full bitmask and overlap
    /// the broker's actual subscription.
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
                    info!(%peer_id, subs, msgs, "behaviour received RPC with data from handler");
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
        let mut bh = BlossomSubBehaviour::new();
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
        let mut bh = BlossomSubBehaviour::new();
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
        let mut bh = BlossomSubBehaviour::new();
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
        let mut bh = BlossomSubBehaviour::new();
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

