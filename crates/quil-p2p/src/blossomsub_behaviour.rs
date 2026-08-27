//! Bridge from stock libp2p `gossipsub` to the public surface that `node.rs`
//! and the rest of `quil-p2p` expect.
//!
//! swaps the hardened `blossomsub` fork for stock
//! [`libp2p::gossipsub`] to remove the custom mesh layer as a variable. The
//! public API of this module is unchanged (`BlossomSubBehaviour`,
//! `BlossomSubEvent`, `ValidationResult`, every method `node.rs` calls), so no
//! consumer outside this file changes shape.
//!
//! ## Wire note (deliberate, flag-day)
//! Stock gossipsub uses **String** topics (`TopicHash { hash: String }`) and a
//! `topic: string` RPC proto field; it cannot carry raw-byte bitmasks on the
//! wire the way the fork's `bitmask: bytes` proto did. We therefore hex-encode
//! each bitmask as the gossipsub topic string (identity-hash `IdentTopic`, so
//! the topic bytes == `hex(bitmask)` verbatim). The public API stays
//! `Vec<u8>` bitmasks — the hex is purely internal. This makes the gossip wire
//! a new **Rust-only** wire (not compatible with Go / old-blossomsub peers),
//! consistent with the rest of the re-substrate hard fork (Falcon sigs, tree).
//!
//! ## Feature parity notes
//! * **Late-bind signing identity.** Stock gossipsub fixes
//! `MessageAuthenticity` at construction. We bootstrap with a throwaway
//! signed key and rebuild the behaviour with the real key in
//! [`set_signing_identity`](BlossomSubBehaviour::set_signing_identity)
//! (always called before the swarm polls / before any subscribe, so no
//! state is lost).
//! * **Per-bitmask validators.** Stock gossipsub validates asynchronously via
//! `ValidationMode` + `report_message_validation_result`. We enable
//! `validate_messages()` and run the registered validator in `poll`,
//! reporting Accept/Reject/Ignore before surfacing the message — so a
//! validator still gates forwarding, matching the fork's receive-path hook.
//! * **Composite/overlapping-bitmask mesh: dropped** (each bitmask is an
//! exact-match topic). This is the deliberate "remove the variable" step.
//! * **Forward filter (devnet partitions): not supported on stock gossipsub.**
//! The methods remain (API compat) but are no-ops; installing one logs a
//! one-time warning. Devnet bipartite-partition tests won't partition until
//! this is re-implemented behind a wrapper hook.
//! * **`send_subscriptions_to_peer`: no-op.** Stock gossipsub re-sends
//! subscriptions automatically when a connection is (re)established.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::gossipsub;
use libp2p::identity::Keypair;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};

use crate::protocol::pb;

/// The concrete stock gossipsub behaviour we wrap.
type Inner = gossipsub::Behaviour;

/// Result of a per-bitmask message validator. Mirrors the historical
/// `blossomsub::ValidationResult` so `node.rs`'s validators are unchanged;
/// maps onto stock gossipsub's [`gossipsub::MessageAcceptance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// Deliver and forward the message.
    Accept,
    /// Drop the message and penalise the sender's score.
    Reject,
    /// Drop the message without penalising the sender (e.g. aged in transit).
    Ignore,
}

impl ValidationResult {
    fn to_acceptance(self) -> gossipsub::MessageAcceptance {
        match self {
            ValidationResult::Accept => gossipsub::MessageAcceptance::Accept,
            ValidationResult::Reject => gossipsub::MessageAcceptance::Reject,
            ValidationResult::Ignore => gossipsub::MessageAcceptance::Ignore,
        }
    }
}

/// A per-bitmask validator closure.
type Validator = Arc<dyn Fn(&PeerId, &[u8]) -> ValidationResult + Send + Sync>;

/// Events emitted by the behaviour to the swarm. Identical in shape to the
/// historical `BlossomSubEvent` so `node.rs`'s match arms are unchanged.
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

/// BlossomSub-compatible `NetworkBehaviour`, backed by stock gossipsub.
pub struct BlossomSubBehaviour {
    /// The stock gossipsub behaviour that does the real work.
    inner: Inner,
    /// The gossipsub config, kept so `set_signing_identity` can rebuild `inner`
    /// with the real signing key (stock gossipsub can't re-key in place).
    config: gossipsub::Config,
    /// Runtime-tunable mesh/gossip parameters (NeedPeers cadence, `d_lo`).
    params: crate::BlossomsubParams,
    /// Mirror of our own subscriptions (bitmask bytes), for the getters and the
    /// NeedPeers computation.
    subscriptions: HashSet<Vec<u8>>,
    /// Direct (always-connected) peers — a disconnect triggers NeedPeers.
    direct_peers: HashSet<PeerId>,
    /// Currently connected peers → live connection count.
    connected_peers: HashMap<PeerId, usize>,
    /// Peers' advertised subscriptions, tracked from Subscribed/Unsubscribed.
    peer_subscriptions: HashMap<PeerId, HashSet<Vec<u8>>>,
    /// Per-bitmask validators, run on the receive path before delivery.
    validators: HashMap<Vec<u8>, Validator>,
    /// Local peer id (author of outgoing messages).
    local_peer_id: Option<PeerId>,
    /// Application-level score overrides (source of truth for the getter).
    application_scores: HashMap<PeerId, f64>,
    /// Wrapper-generated events (NeedPeers) awaiting emission.
    pending_events: VecDeque<BlossomSubEvent>,
    /// Last time the NeedPeers cadence check ran.
    last_need_peers_check: std::time::Instant,
    /// Whether gossipsub metric families have been registered (guards against
    /// double-registration on a repeated `set_signing_identity`).
    metrics_registered: bool,
    /// Whether we've already warned that forward filters are unsupported.
    warned_forward_filter: bool,
    /// Prometheus registry carrying gossipsub's metric families plus the
    /// swarm-level `libp2p_*` families that `node.rs` registers afterward.
    metrics_registry: crate::metrics::SharedRegistry,
}

impl BlossomSubBehaviour {
    /// Construct with default parameters for `network`.
    pub fn new(network: u8) -> Self {
        Self::with_params(network, crate::BlossomsubParams::default())
    }

    /// Construct with custom mesh/gossip parameters. Bootstraps with a
    /// throwaway signed key; `set_signing_identity` rebinds the real one.
    pub fn with_params(network: u8, params: crate::BlossomsubParams) -> Self {
        let config = build_config(network, &params);
        // Bootstrap authenticity: Strict validation requires a signing key, and
        // the real one isn't known yet. `set_signing_identity` (called right
        // after construction, before the swarm polls or we subscribe) rebuilds
        // `inner` with the real key.
        let placeholder = Keypair::generate_ed25519();
        let inner = Inner::new(
            gossipsub::MessageAuthenticity::Signed(placeholder),
            config.clone(),
        )
        .expect("valid gossipsub config");
        Self {
            inner,
            config,
            params,
            subscriptions: HashSet::new(),
            direct_peers: HashSet::new(),
            connected_peers: HashMap::new(),
            peer_subscriptions: HashMap::new(),
            validators: HashMap::new(),
            local_peer_id: None,
            application_scores: HashMap::new(),
            pending_events: VecDeque::new(),
            last_need_peers_check: std::time::Instant::now(),
            metrics_registered: false,
            warned_forward_filter: false,
            metrics_registry: Arc::new(std::sync::Mutex::new(
                prometheus_client::registry::Registry::default(),
            )),
        }
    }

    /// Shared handle to this behaviour's prometheus registry.
    pub fn metrics_registry(&self) -> crate::metrics::SharedRegistry {
        self.metrics_registry.clone()
    }

    /// Late-bind the signing identity for published messages. Rebuilds `inner`
    /// with the real key (stock gossipsub can't re-key in place), registers the
    /// gossipsub metric families (once), and enables peer scoring so
    /// application-score overrides take effect.
    pub fn set_signing_identity(&mut self, peer_id: PeerId, keypair: Keypair) {
        self.local_peer_id = Some(peer_id);
        let inner = if !self.metrics_registered {
            let mut guard = self.metrics_registry.lock().unwrap();
            let sub = guard.sub_registry_with_prefix("gossipsub");
            let inner = Inner::new(
                gossipsub::MessageAuthenticity::Signed(keypair),
                self.config.clone(),
            )
            .expect("valid gossipsub config")
            .with_metrics(sub, gossipsub::MetricsConfig::default());
            drop(guard);
            self.metrics_registered = true;
            inner
        } else {
            Inner::new(
                gossipsub::MessageAuthenticity::Signed(keypair),
                self.config.clone(),
            )
            .expect("valid gossipsub config")
        };
        self.inner = inner;
        // Enable peer scoring. Two channels are active:
        //  (1) application score (`set_application_score`) — driven by the node
        //      (peer_authenticator / per-source drop-rate penalties);
        //  (2) topic P₄ (invalid-message) on GLOBAL_PEER_INFO — a `Reject` from
        //      the graduated staleness validator (only fires on >5-min-stale
        //      PeerInfo/KeyRegistry, which an honest relayer never forwards)
        //      accrues a QUADRATIC penalty, so a sustained stale/replay flood
        //      graylists the offending peer while a one-off aged message does
        //      not.
        // Every other topic-score term is ZEROED (see `build_peer_score`).
        let (score_params, thresholds) = build_peer_score();
        if let Err(e) = self.inner.with_peer_score(score_params, thresholds) {
            tracing::warn!(error = %e, "gossipsub peer-score init failed");
        }
        // Re-apply any subscriptions / explicit peers registered before the
        // rebind (defensive; in practice none exist yet).
        for bitmask in self.subscriptions.clone() {
            let _ = self.inner.subscribe(&topic_for(&bitmask));
        }
        for peer in self.direct_peers.clone() {
            self.inner.add_explicit_peer(&peer);
        }
    }

    /// Set only the local peer id (test-harness / non-signing path).
    pub fn set_local_peer_id(&mut self, peer_id: PeerId) {
        self.local_peer_id = Some(peer_id);
    }

    /// Register a per-bitmask message validator. Runs on the receive path
    /// (in `poll`) before delivery/forwarding.
    pub fn register_validator(
        &mut self,
        bitmask: Vec<u8>,
        validator: impl Fn(&PeerId, &[u8]) -> ValidationResult + Send + Sync + 'static,
    ) {
        self.validators.insert(bitmask, Arc::new(validator));
    }

    /// Install a per-(source, target) forward filter. **Unsupported on stock
    /// gossipsub** — kept for API compatibility; a no-op with a one-time warning.
    pub fn set_forward_filter(
        &mut self,
        _filter: impl Fn(&PeerId, &PeerId) -> bool + Send + Sync + 'static,
    ) {
        self.warn_forward_filter_unsupported();
    }

    /// Same as [`Self::set_forward_filter`] but boxed. No-op on stock gossipsub.
    pub fn set_forward_filter_boxed(
        &mut self,
        _filter: Box<dyn Fn(&PeerId, &PeerId) -> bool + Send + Sync>,
    ) {
        self.warn_forward_filter_unsupported();
    }

    /// Remove any installed forward filter. No-op on stock gossipsub.
    pub fn clear_forward_filter(&mut self) {}

    fn warn_forward_filter_unsupported(&mut self) {
        if !self.warned_forward_filter {
            self.warned_forward_filter = true;
            tracing::warn!(
                "gossip forward filter is unsupported on stock gossipsub; \
                 devnet network partitions will not be enforced"
            );
        }
    }

    /// Subscribe to a bitmask.
    pub fn subscribe(&mut self, bitmask: Vec<u8>) {
        match self.inner.subscribe(&topic_for(&bitmask)) {
            Ok(_) => {
                self.subscriptions.insert(bitmask);
            }
            Err(e) => {
                tracing::debug!(error = %e, "gossipsub subscribe failed");
            }
        }
    }

    /// Unsubscribe from a bitmask.
    pub fn unsubscribe(&mut self, bitmask: &[u8]) {
        let _ = self.inner.unsubscribe(&topic_for(bitmask));
        self.subscriptions.remove(bitmask);
    }

    /// Publish `data` to `bitmask`. `Ok(())` on success or dedup; `Err` when not
    /// subscribed or on a publish error — matching the historical contract.
    pub fn publish(&mut self, bitmask: Vec<u8>, data: Vec<u8>) -> Result<(), String> {
        if !self.subscriptions.contains(&bitmask) {
            return Err(format!("not subscribed to bitmask {}", hex::encode(&bitmask)));
        }
        match self.inner.publish(topic_for(&bitmask).hash(), data) {
            Ok(_) => Ok(()),
            // Already-seen message: historically a successful no-op.
            Err(gossipsub::PublishError::Duplicate) => Ok(()),
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

    /// (Re)send our subscriptions to a single peer. **No-op on stock
    /// gossipsub**, which re-sends subscriptions automatically on (re)connect.
    pub fn send_subscriptions_to_peer(&mut self, _peer: PeerId) {}

    // -- Scoring (P5 application score) ----------------------------------

    /// Total score for a peer (falls back to the mirrored application score if
    /// the scorer has no entry).
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

    /// Mesh peer count for a bitmask.
    pub fn mesh_peers(&self, bitmask: &[u8]) -> usize {
        self.inner.mesh_peers(&topic_for(bitmask).hash()).count()
    }

    /// Connected peers which advertised this exact bitmask. This becomes
    /// useful before the mesh heartbeat has populated `mesh_peers`.
    pub fn subscribed_peer_count(&self, bitmask: &[u8]) -> usize {
        self.peer_subscriptions.iter().filter(|(peer, subscriptions)| {
            self.connected_peers.contains_key(*peer) && subscriptions.contains(bitmask)
        }).count()
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

    /// Sum of mesh peer counts across every subscription.
    pub fn mesh_peer_counts(&self) -> usize {
        self.subscriptions
            .iter()
            .map(|b| self.inner.mesh_peers(&topic_for(b).hash()).count())
            .sum()
    }

    // -- NeedPeers generation --------------------------------------------

    /// On a heartbeat cadence, emit `NeedPeers` if any direct peer is
    /// disconnected or any subscription's mesh is below `d_lo`.
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
            let count = self.inner.mesh_peers(&topic_for(bitmask).hash()).count();
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

/// The identity-hash gossipsub topic for a bitmask: the topic string is
/// `hex(bitmask)`, so the on-wire topic bytes are a lossless, UTF-8-safe
/// encoding of the arbitrary bitmask bytes.
fn topic_for(bitmask: &[u8]) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(hex::encode(bitmask))
}

/// Recover the bitmask bytes from a gossipsub topic hash (identity hash, so the
/// hash string is the hex topic we published).
fn bitmask_from_topic(topic: &gossipsub::TopicHash) -> Vec<u8> {
    hex::decode(topic.as_str()).unwrap_or_default()
}

/// Decode a stock gossipsub message into the wire `pb::Message` that `node.rs`
/// consumes. `node.rs` reads `from`, `data`, and `bitmask`; the signature/key
/// are not needed post-validation (gossipsub already verified them).
fn to_pb_message(message: gossipsub::Message, bitmask: Vec<u8>) -> pb::Message {
    pb::Message {
        from: message.source.map(|p| p.to_bytes()).unwrap_or_default(),
        data: message.data,
        seqno: message
            .sequence_number
            .map(|s| s.to_be_bytes().to_vec())
            .unwrap_or_default(),
        bitmask,
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
                    gossipsub::Event::Message {
                        propagation_source,
                        message_id,
                        message,
                    } => {
                        let bitmask = bitmask_from_topic(&message.topic);
                        // `validate_messages()` is on, so we must report an
                        // outcome for every message before it is forwarded.
                        let outcome = match self.validators.get(&bitmask) {
                            Some(v) => v(&propagation_source, &message.data),
                            None => ValidationResult::Accept,
                        };
                        let _ = self.inner.report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            outcome.to_acceptance(),
                        );
                        if outcome == ValidationResult::Accept {
                            return Poll::Ready(ToSwarm::GenerateEvent(
                                BlossomSubEvent::Message {
                                    propagation_source,
                                    message_id: message_id.0,
                                    message: to_pb_message(message, bitmask),
                                },
                            ));
                        }
                        // Rejected / ignored: don't surface, keep polling.
                        continue;
                    }
                    gossipsub::Event::Subscribed { peer_id, topic } => {
                        let bitmask = bitmask_from_topic(&topic);
                        self.peer_subscriptions
                            .entry(peer_id)
                            .or_default()
                            .insert(bitmask.clone());
                        return Poll::Ready(ToSwarm::GenerateEvent(
                            BlossomSubEvent::Subscribed { peer_id, bitmask },
                        ));
                    }
                    gossipsub::Event::Unsubscribed { peer_id, topic } => {
                        let bitmask = bitmask_from_topic(&topic);
                        if let Some(s) = self.peer_subscriptions.get_mut(&peer_id) {
                            s.remove(&bitmask);
                        }
                        return Poll::Ready(ToSwarm::GenerateEvent(
                            BlossomSubEvent::Unsubscribed { peer_id, bitmask },
                        ));
                    }
                    // GossipsubNotSupported / SlowPeer / etc. — not part of the
                    // historical event surface; drop and keep polling.
                    _ => continue,
                },
                // Non-GenerateEvent ToSwarm variants carry the same handler-in
                // type; rewrap with our event type (closure never runs).
                Poll::Ready(other) => {
                    return Poll::Ready(
                        other.map_out(|_| unreachable!("GenerateEvent handled above")),
                    );
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

/// Map [`crate::BlossomsubParams`] onto a [`gossipsub::Config`], selecting the
/// per-network protocol id and setting the BlossomSub message id
/// (`[0x01] ++ SHA256(data)`). Fork-only knobs without a stock equivalent
/// (`mesh_peers_per_subnet`, `mcache_max_bytes`) are dropped.
/// Peer-score config. Two channels are active: (1) the application score
/// (`set_application_score`, driven by the node — peer_authenticator + per-source
/// drop-rate penalties); (2) topic P₄ (invalid-message) on GLOBAL_PEER_INFO, so
/// a `Reject` from the graduated staleness validator (fires ONLY on >5-min-stale
/// PeerInfo/KeyRegistry, which an honest relayer never forwards) accrues a
/// QUADRATIC penalty — a sustained stale/replay flood graylists the peer while a
/// one-off aged message does not. Every honest-peer-affecting topic term
/// (time-in-mesh, first/mesh deliveries, mesh-failure) is ZEROED: those punish
/// peers for normal WAN delivery variance and cause mesh flapping.
fn build_peer_score() -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    let mut pi_topic = gossipsub::TopicScoreParams::default();
    pi_topic.topic_weight = 1.0;
    pi_topic.time_in_mesh_weight = 0.0;
    pi_topic.first_message_deliveries_weight = 0.0;
    pi_topic.mesh_message_deliveries_weight = 0.0;
    pi_topic.mesh_failure_penalty_weight = 0.0;
    pi_topic.invalid_message_deliveries_weight = -50.0; // P₄ = weight × counter²
    pi_topic.invalid_message_deliveries_decay = 0.5; // ~halves each decay_interval → recovers
    // Keep `PeerScoreParams::default()` for everything else — notably
    // `app_specific_weight` (the existing `set_application_score` channel),
    // `ip_colocation_factor_weight` and `behaviour_penalty_weight`.
    let mut score_params = gossipsub::PeerScoreParams::default();
    // GLOBAL_PEER_INFO bitmask `[0,0,0,0]` → topic `hex("00000000")`.
    score_params
        .topics
        .insert(topic_for(&[0u8, 0, 0, 0]).hash(), pi_topic);
    // Thresholds MUST be negative now that scores can go negative (the all-zero
    // default would graylist on ANY negative — hair-trigger, since default
    // params already carry ip-colocation/behaviour penalties; negative
    // thresholds relax those too, the safer standard config). Ordered
    // gossip ≥ publish ≥ graylist. With P₄ weight −50: counter 2 → −200 (below
    // gossip, reduced IHAVE/IWANT), counter 3 → −450 (< graylist, peer ignored);
    // a one-off (counter 1 → −50) stays above all thresholds.
    let thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: -100.0,
        publish_threshold: -200.0,
        graylist_threshold: -400.0,
        accept_px_threshold: 0.0,
        opportunistic_graft_threshold: 0.0,
    };
    (score_params, thresholds)
}

fn build_config(network: u8, params: &crate::BlossomsubParams) -> gossipsub::Config {
    let mut builder = gossipsub::ConfigBuilder::default();
    builder
        .protocol_id(
            crate::protocol::protocol_id_for_network(network),
            gossipsub::Version::V1_1,
        )
        .history_length(params.history_length)
        .history_gossip(params.history_gossip)
        // Mesh-degree (D) family is DELIBERATELY left at gossipsub's own
        // defaults (mesh_n=6, mesh_n_low=5, mesh_n_high=12, gossip_lazy=6,
        // mesh_outbound_min=2) rather than the blossomsub-tuned config values
        // (D=8/D_lo=6). Higher fan-out multiplies traffic on high-rate topics
        // (e.g. GLOBAL_PEER_INFO); `params.{d,d_lo,d_hi,d_lazy,d_out}` are
        // intentionally NOT applied here.
        .gossip_factor(params.gossip_factor)
        .heartbeat_interval(params.heartbeat_interval)
        .heartbeat_initial_delay(params.heartbeat_initial_delay)
        .fanout_ttl(params.fanout_ttl)
        .prune_backoff(params.prune_backoff)
        .unsubscribe_backoff(params.unsubscribe_backoff.as_secs())
        .iwant_followup_time(params.iwant_followup_time)
        .idontwant_message_size_threshold(params.idont_want_message_threshold)
        // Per-message size cap (fork used `mcache_max_bytes` for the mcache; the
        // stock knob is the per-message transmit cap). 16 MiB matches the RPC
        // frame cap in `protocol.rs`.
        .max_transmit_size(crate::protocol::MAX_MESSAGE_SIZE)
        // Keep de-duplicated message IDs at least as long as the peer-score
        // delivery-record window (WAN margin); cost is holding 33-byte ids a bit
        // longer.
        .duplicate_cache_time(std::time::Duration::from_secs(300))
        // Run per-bitmask validators before forwarding (see module docs).
        .validate_messages()
        // BlossomSub message id = `[0x01] ++ SHA256(data)`. Stock gossipsub's
        // default id differs, so we set it explicitly to keep the dedup key
        // stable across the network.
        .message_id_fn(|message: &gossipsub::Message| {
            gossipsub::MessageId::from(crate::node::message_id(&message.data))
        })
        // Inbound signature verification (StrictSign); signed outbound is
        // late-bound via `set_signing_identity`.
        .validation_mode(gossipsub::ValidationMode::Strict);
    builder.build().expect("valid gossipsub config")
}

/// Multi-node end-to-end propagation over REAL libp2p swarms, now over stock
/// gossipsub. Spins up three real swarms (TCP + noise + yamux) around the
/// production [`BlossomSubBehaviour`] bridge and exercises the whole pipeline —
/// subscription exchange, StrictSign publish, hex-topic mapping, real
/// transport, inbound signature verification, and event delivery.
#[cfg(test)]
mod propagation_tests {
    use super::*;
    use futures::StreamExt;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{Multiaddr, Swarm, SwarmBuilder};
    use std::time::Duration;

    // The peer-score config must pass gossipsub's own validation, or
    // `with_peer_score` errors and scoring silently stays OFF (warn path).
    #[test]
    fn peer_score_config_is_valid_and_scores_peer_info() {
        let (params, thresholds) = build_peer_score();
        params.validate().expect("peer-score params must validate");
        thresholds.validate().expect("thresholds must validate");
        // GLOBAL_PEER_INFO carries the P₄ invalid-message penalty...
        let topic = topic_for(&[0u8, 0, 0, 0]).hash();
        let tp = params
            .topics
            .get(&topic)
            .expect("GLOBAL_PEER_INFO must be scored");
        assert!(
            tp.invalid_message_deliveries_weight < 0.0,
            "P4 must penalize invalid deliveries"
        );
        // ...but must NOT prune honest peers on normal delivery variance.
        assert_eq!(tp.mesh_message_deliveries_weight, 0.0);
        assert_eq!(tp.first_message_deliveries_weight, 0.0);
        assert_eq!(tp.time_in_mesh_weight, 0.0);
    }

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
                b.set_signing_identity(key.public().to_peer_id(), key.clone());
                Ok(b)
            })
            .expect("behaviour")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(30)))
            .build()
    }

    #[test]
    fn subscribed_peer_count_requires_a_live_exact_subscriber() {
        let mut behaviour = BlossomSubBehaviour::new(0);
        let topic = vec![0x0c, 0xa1];
        let peer = PeerId::random();
        let disconnected = PeerId::random();
        behaviour.peer_subscriptions.insert(peer, [topic.clone()].into_iter().collect());
        behaviour.peer_subscriptions.insert(disconnected, [topic.clone()].into_iter().collect());
        behaviour.connected_peers.insert(peer, 1);

        assert_eq!(behaviour.subscribed_peer_count(&topic), 1);
        assert_eq!(behaviour.subscribed_peer_count(&[0x0c, 0xa2]), 0);
    }

    /// A message published at the hub reaches every subscribed leaf. Star
    /// topology (hub + two leaves); flood-publish (the gossipsub default)
    /// delivers to all subscribed topic peers once SUBSCRIBE RPCs are exchanged.
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
