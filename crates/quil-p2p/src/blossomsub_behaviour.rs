//! Bridge from the hardened `blossomsub` crate (a fork of libp2p-gossipsub with
//! bitmask-composite topics) to the public surface that `node.rs` and the rest
//! of `quil-p2p` expect.
//!
//! Historically the BlossomSub `NetworkBehaviour` lived in-crate (in a
//! now-deleted `behaviour` module). Stage 6 of the rewrite re-pointed the
//! production path at the `blossomsub` crate while preserving the exact public
//! API, and Stage 7 deleted the old in-crate implementation entirely. The fork
//! is now the sole implementation. `BlossomSubBehaviour` is a thin newtype
//! `NetworkBehaviour` wrapper around [`blossomsub::Behaviour`]:
//!
//!  * It maps the fork's [`blossomsub::Event`] to the historical
//!    [`BlossomSubEvent`] at the swarm boundary (decoding the fork's internal
//!    `Message` back into a `pb::Message` plus the 33-byte message id).
//!  * It generates the `NeedPeers` event (the fork, like upstream gossipsub,
//!    has no such event) from a heartbeat-cadence low-mesh / direct-peer
//!    disconnect check.
//!  * Signing-identity late-binding and per-bitmask validators live INSIDE the
//!    fork (`set_signing_identity` / `register_validator`); the wrapper only
//!    forwards to them so they run on the fork's own receive/publish paths.

use std::collections::{HashMap, HashSet, VecDeque};
use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::identity::Keypair;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};

use blossomsub::pb;
use blossomsub::{IdentTopic, TopicHash};

pub use blossomsub::ValidationResult;

/// The concrete `blossomsub` behaviour we wrap (identity transform, allow-all
/// subscription filter — the BlossomSub defaults).
type Inner = blossomsub::Behaviour;

/// Events emitted by the BlossomSub behaviour to the swarm. Identical in shape
/// to the historical in-crate `BlossomSubEvent` so `node.rs`'s match arms are
/// unchanged.
#[derive(Debug)]
pub enum BlossomSubEvent {
    /// A message was received from the network.
    Message {
        propagation_source: PeerId,
        message_id: Vec<u8>,
        message: pb::Message,
    },
    /// A peer subscribed to a bitmask.
    Subscribed { peer_id: PeerId, bitmask: Vec<u8> },
    /// A peer unsubscribed from a bitmask.
    Unsubscribed { peer_id: PeerId, bitmask: Vec<u8> },
    /// We need more peers for our subscriptions — trigger DHT discovery.
    NeedPeers {
        subscriptions: Vec<Vec<u8>>,
        connected: usize,
    },
}

/// BlossomSub `NetworkBehaviour`, backed by the `blossomsub` crate.
pub struct BlossomSubBehaviour {
    /// The hardened fork behaviour that does all the real work.
    inner: Inner,
    /// Runtime-tunable mesh/gossip parameters (used for the NeedPeers cadence
    /// and low-mesh threshold `d_lo`).
    params: crate::BlossomsubParams,
    /// Mirror of our own subscriptions (bitmask bytes), for the getters and
    /// the NeedPeers computation. The fork's authoritative set is keyed by
    /// `TopicHash`; this keeps the public `Vec<u8>` view cheap.
    subscriptions: HashSet<Vec<u8>>,
    /// Direct (always-connected) peers — a disconnect triggers NeedPeers.
    direct_peers: HashSet<PeerId>,
    /// Currently connected peers → live connection count.
    connected_peers: HashMap<PeerId, usize>,
    /// Peers' advertised subscriptions, tracked from mapped Subscribed/
    /// Unsubscribed events, for `peer_subscribed_to`.
    peer_subscriptions: HashMap<PeerId, HashSet<Vec<u8>>>,
    /// Local peer id (author of outgoing messages); set via
    /// `set_signing_identity` / `set_local_peer_id`.
    local_peer_id: Option<PeerId>,
    /// Application-level score overrides, mirrored into the fork's peer score
    /// (P5). Kept here as the source of truth so `add_application_score` can
    /// read the current value (the fork exposes only a total-score getter).
    application_scores: HashMap<PeerId, f64>,
    /// Wrapper-generated events (NeedPeers) awaiting emission.
    pending_events: VecDeque<BlossomSubEvent>,
    /// Last time the NeedPeers cadence check ran.
    last_need_peers_check: std::time::Instant,
}

impl BlossomSubBehaviour {
    /// Construct with default BlossomSub parameters for `network`.
    pub fn new(network: u8) -> Self {
        Self::with_params(network, crate::BlossomsubParams::default())
    }

    /// Construct with custom mesh/gossip parameters (typically
    /// `BlossomsubParams::from_p2p_config(...)`). Maps `params` onto a
    /// `blossomsub::Config` and selects the per-network protocol id.
    pub fn with_params(network: u8, params: crate::BlossomsubParams) -> Self {
        let config = build_config(network, &params);
        // The fork fixes MessageAuthenticity at construction and its default
        // ValidationMode is Strict (which requires a signing authenticity).
        // The real signing key isn't known yet (node.rs installs it right
        // after via `set_signing_identity`), so bootstrap with a throwaway
        // signed key and late-bind the real one.
        let placeholder = Keypair::generate_ed25519();
        let inner = Inner::new(
            blossomsub::MessageAuthenticity::Signed(placeholder),
            config,
        )
        .expect("valid blossomsub config");
        Self {
            inner,
            params,
            subscriptions: HashSet::new(),
            direct_peers: HashSet::new(),
            connected_peers: HashMap::new(),
            peer_subscriptions: HashMap::new(),
            local_peer_id: None,
            application_scores: HashMap::new(),
            pending_events: VecDeque::new(),
            last_need_peers_check: std::time::Instant::now(),
        }
    }

    /// Late-bind the signing identity for published messages. `peer_id` must be
    /// the peer id of `keypair` (matches the reference behaviour, which stores
    /// both); the fork derives the author from the keypair.
    pub fn set_signing_identity(&mut self, peer_id: PeerId, keypair: Keypair) {
        self.local_peer_id = Some(peer_id);
        self.inner.set_signing_identity(keypair);
    }

    /// Set only the local peer id (test-harness / non-signing path).
    pub fn set_local_peer_id(&mut self, peer_id: PeerId) {
        self.local_peer_id = Some(peer_id);
    }

    /// Register a per-bitmask message validator. Runs on the fork's receive
    /// path before delivery/forwarding.
    pub fn register_validator(
        &mut self,
        bitmask: Vec<u8>,
        validator: impl Fn(&PeerId, &[u8]) -> ValidationResult + Send + Sync + 'static,
    ) {
        self.inner
            .register_validator(TopicHash::from_raw(bitmask), validator);
    }

    /// Subscribe to a bitmask.
    pub fn subscribe(&mut self, bitmask: Vec<u8>) {
        let topic = IdentTopic::new(bitmask.clone());
        match self.inner.subscribe(&topic) {
            Ok(_) => {
                self.subscriptions.insert(bitmask);
            }
            Err(e) => {
                tracing::debug!(error = %e, "blossomsub subscribe failed");
            }
        }
    }

    /// Unsubscribe from a bitmask.
    pub fn unsubscribe(&mut self, bitmask: &[u8]) {
        let topic = IdentTopic::new(bitmask.to_vec());
        let _ = self.inner.unsubscribe(&topic);
        self.subscriptions.remove(bitmask);
    }

    /// Publish `data` to `bitmask`. Returns `Ok(())` on success or when the
    /// message was already published (dedup), `Err` when not subscribed or on
    /// a publish error — matching the reference behaviour's contract.
    pub fn publish(&mut self, bitmask: Vec<u8>, data: Vec<u8>) -> Result<(), String> {
        if !self.subscriptions.contains(&bitmask) {
            return Err(format!("not subscribed to bitmask {}", hex::encode(&bitmask)));
        }
        match self.inner.publish(TopicHash::from_raw(bitmask), data) {
            Ok(_) => Ok(()),
            // Already-seen message: the reference behaviour treated this as a
            // successful no-op.
            Err(blossomsub::PublishError::Duplicate) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Add a direct (always-connected) peer.
    pub fn add_direct_peer(&mut self, peer: PeerId) {
        self.direct_peers.insert(peer);
        self.inner.add_explicit_peer(&peer);
    }

    /// Blacklist a peer.
    pub fn blacklist_peer(&mut self, peer: PeerId) {
        self.inner.blacklist_peer(&peer);
    }

    /// (Re)send our subscriptions to a single peer.
    pub fn send_subscriptions_to_peer(&mut self, peer: PeerId) {
        self.inner.send_subscriptions_to_peer(peer);
    }

    // -- Scoring (P5 application score) ----------------------------------

    /// Total score for a peer (0.0 if unknown to the scorer).
    pub fn score(&self, peer: &PeerId) -> f64 {
        self.inner.peer_score(peer).unwrap_or_else(|| {
            self.application_scores.get(peer).copied().unwrap_or(0.0)
        })
    }

    /// Set the application-level score for a peer (0.0 clears the override).
    pub fn set_application_score(&mut self, peer: PeerId, score: f64) {
        if score == 0.0 {
            self.application_scores.remove(&peer);
        } else {
            self.application_scores.insert(peer, score);
        }
        self.inner.set_application_score(&peer, score);
    }

    /// Add `delta` to a peer's application score.
    pub fn add_application_score(&mut self, peer: PeerId, delta: f64) {
        let entry = self.application_scores.entry(peer).or_insert(0.0);
        *entry += delta;
        let total = *entry;
        if total == 0.0 {
            self.application_scores.remove(&peer);
        }
        self.inner.set_application_score(&peer, total);
    }

    // -- Introspection getters -------------------------------------------

    /// Mesh peer count for a bitmask. Composite-aware: for a multi-slice
    /// (composite) bitmask this reports the composite mesh size, not 0.
    pub fn mesh_peers(&self, bitmask: &[u8]) -> usize {
        self.inner
            .mesh_peers_for_subscription(&TopicHash::from_raw(bitmask.to_vec()))
    }

    /// Read-only access to our own subscription set.
    pub fn subscriptions(&self) -> &HashSet<Vec<u8>> {
        &self.subscriptions
    }

    /// True iff `peer` is currently connected.
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

    /// Total connected peers (alias of `connected_count`).
    pub fn num_connected(&self) -> usize {
        self.connected_peers.len()
    }

    /// Sum of mesh peer counts across every subscription — a coarse gauge of
    /// overall mesh health. Composite-aware (see `mesh_peers`): sums over our
    /// own subscriptions using `mesh_peers_for_subscription` so composite
    /// bitmasks contribute their real mesh size instead of 0.
    pub fn mesh_peer_counts(&self) -> usize {
        self.subscriptions
            .iter()
            .map(|b| {
                self.inner
                    .mesh_peers_for_subscription(&TopicHash::from_raw(b.clone()))
            })
            .sum()
    }

    // -- NeedPeers generation --------------------------------------------

    /// On a heartbeat cadence, emit `NeedPeers` if any direct peer is
    /// disconnected or any subscription's mesh is below `d_lo`. Ported from the
    /// reference behaviour's heartbeat low-mesh + direct-peer disconnect paths.
    fn maybe_emit_need_peers(&mut self) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_need_peers_check) < self.params.heartbeat_interval {
            return;
        }
        self.last_need_peers_check = now;
        if self.subscriptions.is_empty() {
            return;
        }

        let direct_disconnected = self
            .direct_peers
            .iter()
            .any(|p| !self.connected_peers.contains_key(p));

        let mut low_mesh = false;
        for bitmask in &self.subscriptions {
            // Composite-aware count: a healthy composite mesh (keyed by slices)
            // would otherwise read as 0 and fire NeedPeers every heartbeat.
            let count = self
                .inner
                .mesh_peers_for_subscription(&TopicHash::from_raw(bitmask.clone()));
            if count < self.params.d_lo {
                low_mesh = true;
                break;
            }
        }

        if direct_disconnected || low_mesh {
            self.pending_events.push_back(BlossomSubEvent::NeedPeers {
                subscriptions: self.subscriptions.iter().cloned().collect(),
                connected: self.connected_peers.len(),
            });
        }
    }
}

impl Default for BlossomSubBehaviour {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Decode the fork's transformed `Message` back into the wire `pb::Message`
/// that `node.rs` consumes. `node.rs` reads `from`, `data`, and `bitmask`; the
/// signature/key are not needed post-validation (the fork already verified
/// them) and are left empty.
fn to_pb_message(message: blossomsub::Message) -> pb::Message {
    pb::Message {
        from: message.source.map(|p| p.to_bytes()).unwrap_or_default(),
        data: message.data,
        seqno: message
            .sequence_number
            .map(|s| s.to_be_bytes().to_vec())
            .unwrap_or_default(),
        bitmask: message.topic.into_bytes(),
        signature: Vec::new(),
        key: Vec::new(),
    }
}

impl NetworkBehaviour for BlossomSubBehaviour {
    type ConnectionHandler = <Inner as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = BlossomSubEvent;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match &event {
            FromSwarm::ConnectionEstablished(e) => {
                *self.connected_peers.entry(e.peer_id).or_insert(0) += 1;
            }
            FromSwarm::ConnectionClosed(e) => {
                if let Some(count) = self.connected_peers.get_mut(&e.peer_id) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.connected_peers.remove(&e.peer_id);
                        self.peer_subscriptions.remove(&e.peer_id);
                    }
                }
            }
            _ => {}
        }
        self.inner.on_swarm_event(event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Emit any wrapper-generated events (NeedPeers) first.
        if let Some(ev) = self.pending_events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(ev));
        }

        loop {
            match self.inner.poll(cx) {
                Poll::Ready(ToSwarm::GenerateEvent(ev)) => match ev {
                    blossomsub::Event::Message {
                        propagation_source,
                        message_id,
                        message,
                    } => {
                        return Poll::Ready(ToSwarm::GenerateEvent(BlossomSubEvent::Message {
                            propagation_source,
                            message_id: message_id.0,
                            message: to_pb_message(message),
                        }));
                    }
                    blossomsub::Event::Subscribed { peer_id, topic } => {
                        let bitmask = topic.into_bytes();
                        self.peer_subscriptions
                            .entry(peer_id)
                            .or_default()
                            .insert(bitmask.clone());
                        return Poll::Ready(ToSwarm::GenerateEvent(BlossomSubEvent::Subscribed {
                            peer_id,
                            bitmask,
                        }));
                    }
                    blossomsub::Event::Unsubscribed { peer_id, topic } => {
                        let bitmask = topic.into_bytes();
                        if let Some(s) = self.peer_subscriptions.get_mut(&peer_id) {
                            s.remove(&bitmask);
                        }
                        return Poll::Ready(ToSwarm::GenerateEvent(
                            BlossomSubEvent::Unsubscribed { peer_id, bitmask },
                        ));
                    }
                    // Not part of the historical event surface — drop and keep
                    // polling.
                    blossomsub::Event::GossipsubNotSupported { .. } => continue,
                },
                // Non-GenerateEvent ToSwarm variants (NotifyHandler, Dial, ...)
                // carry the same handler-in type; rewrap with our event type.
                // `map_out`'s closure never runs for these variants.
                Poll::Ready(other) => {
                    return Poll::Ready(other.map_out(|_| {
                        unreachable!("GenerateEvent handled above")
                    }));
                }
                Poll::Pending => {
                    self.maybe_emit_need_peers();
                    if let Some(ev) = self.pending_events.pop_front() {
                        return Poll::Ready(ToSwarm::GenerateEvent(ev));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

/// Map [`crate::BlossomsubParams`] onto a [`blossomsub::Config`], selecting the
/// per-network protocol id. Ported from the reference construction path in
/// `quil-p2p` (the `pos()`/`dur_ms()` overrides already applied when building
/// `BlossomsubParams`); here we translate the field names onto the fork's
/// gossipsub-style config knobs:
///   d → mesh_n, d_lo → mesh_n_low, d_hi → mesh_n_high,
///   d_lazy → gossip_lazy, d_out → mesh_outbound_min.
/// Fields without a fork equivalent (`d_score`, `max_idont_want_messages`) keep
/// the fork's WAN-hardened defaults (which match the `params::*` defaults).
fn build_config(network: u8, params: &crate::BlossomsubParams) -> blossomsub::Config {
    let mut builder = blossomsub::ConfigBuilder::default();
    builder
        // Per-network protocol id: mainnet `/blossomsub/2.1.0`, others suffixed
        // `-network-N`. Stage-2 left `protocol_id_for_network` unused; wire it
        // here so non-mainnet nodes negotiate a distinct protocol.
        .protocol_id(
            crate::protocol::protocol_id_for_network(network),
            blossomsub::Version::V1_1,
        )
        .history_length(params.history_length)
        .history_gossip(params.history_gossip)
        .mesh_n(params.d)
        .mesh_n_low(params.d_lo)
        .mesh_n_high(params.d_hi)
        .gossip_lazy(params.d_lazy)
        .mesh_outbound_min(params.d_out)
        .gossip_factor(params.gossip_factor)
        .heartbeat_interval(params.heartbeat_interval)
        .heartbeat_initial_delay(params.heartbeat_initial_delay)
        .fanout_ttl(params.fanout_ttl)
        .prune_backoff(params.prune_backoff)
        .unsubscribe_backoff(params.unsubscribe_backoff.as_secs())
        .iwant_followup_time(params.iwant_followup_time)
        .idontwant_message_size_threshold(params.idont_want_message_threshold)
        .mesh_peers_per_subnet(params.mesh_peers_per_subnet)
        .mcache_max_bytes(params.mcache_max_bytes)
        // Inbound signature verification (Go nodes StrictSign). Signed
        // outbound is late-bound via `set_signing_identity`.
        .validation_mode(blossomsub::ValidationMode::Strict);
    builder.build().expect("valid blossomsub config")
}

/// Multi-node end-to-end propagation over REAL libp2p swarms.
///
/// The old in-crate `test_harness::TestNetwork` wired several behaviours
/// together in-memory but only ever asserted connectivity bookkeeping — it had
/// no true "publish at A is delivered at B/C" assertion, and it depended on the
/// old behaviour's private test hooks that the `blossomsub` fork doesn't
/// expose. This is the additive coverage that fills that gap: it spins up three
/// real swarms (TCP + noise + yamux) around the production
/// [`BlossomSubBehaviour`] bridge and exercises the entire pipeline —
/// subscription exchange, StrictSign publish, LEB128+prost wire codec, real
/// transport, inbound signature verification, and event delivery — which no
/// single-behaviour unit test in either crate covers.
#[cfg(test)]
mod propagation_tests {
    use super::*;
    use futures::StreamExt;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{Multiaddr, Swarm, SwarmBuilder};
    use std::time::Duration;

    fn build_swarm() -> Swarm<BlossomSubBehaviour> {
        SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .expect("tcp transport")
            .with_behaviour(|key| {
                let mut b = BlossomSubBehaviour::new(0);
                // Sign with the swarm's own identity so `msg.from` is the local
                // peer id and StrictSign verification passes on the receiver.
                b.set_signing_identity(key.public().to_peer_id(), key.clone());
                Ok(b)
            })
            .expect("behaviour")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(30)))
            .build()
    }

    /// A message published at the hub reaches every subscribed leaf. Star
    /// topology (hub + two leaves); `flood_publish` (the BlossomSub default)
    /// delivers to all subscribed topic peers, so this is deterministic once
    /// the subscription RPCs have been exchanged — no wall-clock heartbeat
    /// dependency. Uses a single-bit bitmask so the topic is "simple" (a
    /// multi-bit bitmask would slice into composite meshes, which the
    /// `blossomsub` crate's composite tests already cover).
    #[tokio::test]
    async fn multi_node_publish_propagates_to_all_subscribers() {
        let bitmask = vec![0x80u8];
        let payload = b"quilibrium-multi-node-propagation".to_vec();

        let mut hub = build_swarm();
        let mut leaf_a = build_swarm();
        let mut leaf_b = build_swarm();

        let a_id = *leaf_a.local_peer_id();
        let b_id = *leaf_b.local_peer_id();

        hub.behaviour_mut().subscribe(bitmask.clone());
        leaf_a.behaviour_mut().subscribe(bitmask.clone());
        leaf_b.behaviour_mut().subscribe(bitmask.clone());

        hub.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");

        // Learn the hub's concrete listen address.
        let hub_addr: Multiaddr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = hub.select_next_some().await {
                break address;
            }
        };

        leaf_a.dial(hub_addr.clone()).expect("leaf_a dial");
        leaf_b.dial(hub_addr.clone()).expect("leaf_b dial");

        let mut published = false;
        let mut a_got = false;
        let mut b_got = false;

        let ok = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                tokio::select! {
                    _ = hub.select_next_some() => {}
                    ev = leaf_a.select_next_some() => {
                        if let SwarmEvent::Behaviour(BlossomSubEvent::Message { message, .. }) = ev {
                            if message.data == payload {
                                a_got = true;
                            }
                        }
                    }
                    ev = leaf_b.select_next_some() => {
                        if let SwarmEvent::Behaviour(BlossomSubEvent::Message { message, .. }) = ev {
                            if message.data == payload {
                                b_got = true;
                            }
                        }
                    }
                }

                // Publish once the hub knows both leaves are subscribed to the
                // bitmask (their SUBSCRIBE RPCs have arrived).
                if !published
                    && hub.behaviour().peer_subscribed_to(&a_id, &bitmask)
                    && hub.behaviour().peer_subscribed_to(&b_id, &bitmask)
                {
                    if hub
                        .behaviour_mut()
                        .publish(bitmask.clone(), payload.clone())
                        .is_ok()
                    {
                        published = true;
                    }
                }

                if a_got && b_got {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);

        assert!(
            ok,
            "both leaves must receive the hub's published message (published={published}, a={a_got}, b={b_got})"
        );
    }
}
