//! Bridge from stock libp2p `gossipsub` to the public surface that `node.rs`
//! and the rest of `quil-p2p` expect.
//!
//! This module swaps the hardened `blossomsub` fork for stock
//! [`libp2p::gossipsub`], removing the custom mesh layer. The
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
//! consistent with the rest of the Rust node's wire (Falcon signatures).
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
//! exact-match topic).
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
type Inner = gossipsub::Behaviour<gossipsub::IdentityTransform, SubscriptionLimit>;

/// How peers' subscriptions are bounded, see [`subscription_filter`].
type SubscriptionLimit = gossipsub::MaxCountSubscriptionFilter<TopicLengthLimit>;

/// The most topics one peer may be subscribed to, as far as this node records.
/// A node subscribes to a few global topics and five per shard it serves, so
/// this covers some 1,600 shards. Without a bound, every connected peer could
/// make the node hold any number of topics for it.
const MAX_PEER_TOPICS: usize = 8192;

/// The longest topic a peer may subscribe to: the hex of a 64-byte bitmask
/// (the node's bitmasks have at most 35 bytes).
const MAX_TOPIC_LEN: usize = 128;

/// Refuses topics longer than [`MAX_TOPIC_LEN`].
#[derive(Debug, Default, Clone, Copy)]
pub struct TopicLengthLimit;

impl gossipsub::TopicSubscriptionFilter for TopicLengthLimit {
    fn can_subscribe(&mut self, topic_hash: &gossipsub::TopicHash) -> bool {
        topic_hash.as_str().len() <= MAX_TOPIC_LEN
    }
}

/// The subscription filter of the gossip behaviour: at most
/// [`MAX_PEER_TOPICS`] topics per peer, each at most [`MAX_TOPIC_LEN`] long. A
/// change past the limit is dropped with the rest of its RPC; the node sends
/// one subscription change per RPC.
fn subscription_filter() -> SubscriptionLimit {
    gossipsub::MaxCountSubscriptionFilter {
        filter: TopicLengthLimit,
        max_subscribed_topics: MAX_PEER_TOPICS,
        max_subscriptions_per_request: 1024,
    }
}

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

/// A per-bitmask validator closure: forwarding peer, signed author (if the
/// message is signed) and data.
type Validator = Arc<dyn Fn(&PeerId, Option<&PeerId>, &[u8]) -> ValidationResult + Send + Sync>;

/// The validator of bitmasks without one of their own: forwarding peer,
/// bitmask and data.
type FallbackValidator = Arc<dyn Fn(&PeerId, &[u8], &[u8]) -> ValidationResult + Send + Sync>;

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
    /// Validator of the bitmasks without one in `validators` (the shard
    /// topics, which come and go with the shards served).
    fallback_validator: Option<FallbackValidator>,
    /// Local peer id (author of outgoing messages).
    local_peer_id: Option<PeerId>,
    /// Application-level score overrides (source of truth for the getter).
    application_scores: HashMap<PeerId, f64>,
    /// Wrapper-generated events (NeedPeers) awaiting emission.
    pending_events: VecDeque<BlossomSubEvent>,
    /// Last time the NeedPeers cadence check ran.
    last_need_peers_check: std::time::Instant,
    /// Operator log state for the message cache's byte budget.
    cache_pressure: CachePressure,
    /// Operator log state for gossip RPCs dropped before decoding.
    rejected_rpcs: RejectedRpcLog,
    unsent_rpcs: UnsentRpcLog,
    /// Operator log of peers answering under the message ids of releases before strict shard
    /// gossip.
    legacy_ids: LegacyIdLog,
    /// Whether gossipsub metric families have been registered (guards against
    /// double-registration on a repeated `set_signing_identity`).
    metrics_registered: bool,
    /// Whether we've already warned that forward filters are unsupported.
    warned_forward_filter: bool,
    /// Prometheus registry carrying gossipsub's metric families plus the
    /// swarm-level `libp2p_*` families that `node.rs` registers afterward.
    metrics_registry: crate::metrics::SharedRegistry,
    /// Every message copy by class, kept across `set_signing_identity`.
    traffic: Arc<crate::gossip_traffic::GossipTraffic>,
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
        let traffic: Arc<crate::gossip_traffic::GossipTraffic> = Default::default();
        let inner = Inner::new_with_subscription_filter(
            gossipsub::MessageAuthenticity::Signed(placeholder),
            config.clone(),
            subscription_filter(),
        )
        .expect("valid gossipsub config")
        .with_traffic_observer(traffic.clone());
        Self {
            inner,
            config,
            params,
            subscriptions: HashSet::new(),
            direct_peers: HashSet::new(),
            connected_peers: HashMap::new(),
            peer_subscriptions: HashMap::new(),
            validators: HashMap::new(),
            fallback_validator: None,
            local_peer_id: None,
            application_scores: HashMap::new(),
            pending_events: VecDeque::new(),
            last_need_peers_check: std::time::Instant::now(),
            cache_pressure: CachePressure::default(),
            rejected_rpcs: RejectedRpcLog::default(),
            unsent_rpcs: UnsentRpcLog::default(),
            legacy_ids: LegacyIdLog::default(),
            metrics_registered: false,
            warned_forward_filter: false,
            metrics_registry: Arc::new(std::sync::Mutex::new(
                prometheus_client::registry::Registry::default(),
            )),
            traffic,
        }
    }

    /// This behaviour's gossip traffic counters (see [`crate::gossip_traffic`]).
    pub fn traffic(&self) -> Arc<crate::gossip_traffic::GossipTraffic> {
        self.traffic.clone()
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
            let inner = Inner::new_with_subscription_filter(
                gossipsub::MessageAuthenticity::Signed(keypair),
                self.config.clone(),
                subscription_filter(),
            )
            .expect("valid gossipsub config")
            .with_metrics(sub, gossipsub::MetricsConfig::default())
            .with_traffic_observer(self.traffic.clone());
            drop(guard);
            self.metrics_registered = true;
            inner
        } else {
            Inner::new_with_subscription_filter(
                gossipsub::MessageAuthenticity::Signed(keypair),
                self.config.clone(),
                subscription_filter(),
            )
            .expect("valid gossipsub config")
            .with_traffic_observer(self.traffic.clone())
        };
        self.inner = inner;
        // The new inner behaviour's cache and rejection counters start from zero.
        self.cache_pressure = CachePressure::default();
        self.rejected_rpcs = RejectedRpcLog::default();
        self.unsent_rpcs = UnsentRpcLog::default();
        // Enable peer scoring. Two channels are active:
        //  (1) application score (`set_application_score`) — driven by the node
        //      (peer_authenticator / per-source drop-rate penalties);
        //  (2) topic P₄ (invalid-message) on every subscribed topic — a
        //      `Reject` from a validator, or a message the codec refuses (bad
        //      signature, size), accrues a QUADRATIC penalty, so a sustained
        //      flood of invalid messages graylists the offending peer while a
        //      one-off does not.
        // Every other topic-score term is ZEROED (see `build_peer_score`).
        let (score_params, thresholds) = build_peer_score();
        if let Err(e) = self.inner.with_peer_score(score_params, thresholds) {
            tracing::warn!(error = %e, "gossipsub peer-score init failed");
        }
        // Re-apply any subscriptions / explicit peers registered before the
        // rebind (defensive; in practice none exist yet).
        for bitmask in self.subscriptions.clone() {
            let _ = self.inner.subscribe(&topic_for(&bitmask));
            let _ = self
                .inner
                .set_topic_params(topic_for(&bitmask), invalid_message_topic_params());
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
        self.validators.insert(
            bitmask,
            Arc::new(
                move |peer: &PeerId, _author: Option<&PeerId>, data: &[u8]| validator(peer, data),
            ),
        );
    }

    /// Register a per-bitmask validator that also sees the message's signed
    /// author (`None` for an unsigned message).
    pub fn register_authored_validator(
        &mut self,
        bitmask: Vec<u8>,
        validator: impl Fn(&PeerId, Option<&PeerId>, &[u8]) -> ValidationResult + Send + Sync + 'static,
    ) {
        self.validators.insert(bitmask, Arc::new(validator));
    }

    /// Register the validator of every bitmask without a validator of its own
    /// (see [`register_validator`](Self::register_validator)). It also gets
    /// the bitmask, and runs on the receive path before delivery/forwarding.
    pub fn register_fallback_validator(
        &mut self,
        validator: impl Fn(&PeerId, &[u8], &[u8]) -> ValidationResult + Send + Sync + 'static,
    ) {
        self.fallback_validator = Some(Arc::new(validator));
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

    /// Subscribe to a bitmask. Its topic gets the invalid-message penalty
    /// ([`invalid_message_topic_params`]) once scoring is on.
    pub fn subscribe(&mut self, bitmask: Vec<u8>) {
        match self.inner.subscribe(&topic_for(&bitmask)) {
            Ok(_) => {
                let _ = self
                    .inner
                    .set_topic_params(topic_for(&bitmask), invalid_message_topic_params());
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
            return Err(format!(
                "not subscribed to bitmask {}",
                hex::encode(&bitmask)
            ));
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
        self.inner
            .peer_score(peer)
            .unwrap_or_else(|| self.application_scores.get(peer).copied().unwrap_or(0.0))
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
        self.peer_subscriptions
            .iter()
            .filter(|(peer, subscriptions)| {
                self.connected_peers.contains_key(*peer) && subscriptions.contains(bitmask)
            })
            .count()
    }

    /// Exempt authorized committee peers from IP-colocation only.
    pub fn set_committee_peers(&mut self, peers: HashSet<PeerId>) {
        self.inner.set_ip_colocation_peer_whitelist(peers);
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
        // The message cache's byte-budget signal shares this cadence, and so does the
        // count of RPCs dropped before decoding.
        self.cache_pressure
            .observe(self.inner.message_cache_stats(), now);
        self.rejected_rpcs
            .observe(self.inner.rejected_rpc_stats(), now);
        self.unsent_rpcs.observe(self.inner.unsent_rpc_stats(), now);
        self.legacy_ids.observe(
            crate::node::strict_shard_gossip(),
            self.inner.take_legacy_id_answers(),
            now,
        );
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

/// While the message cache evicts to stay within its byte budget, the warning repeats at this
/// interval; this long without an eviction ends the episode.
const CACHE_PRESSURE_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Operator log of the message cache's byte budget: a warning when evictions start, one per
/// [`CACHE_PRESSURE_LOG_INTERVAL`] while they continue, and an info line when they stop.
#[derive(Debug, Default)]
struct CachePressure {
    /// Counters at the previous check.
    seen: gossipsub::MessageCacheStats,
    episode: Option<CachePressureEpisode>,
}

#[derive(Debug)]
struct CachePressureEpisode {
    /// Counters before the episode's first eviction.
    base: gossipsub::MessageCacheStats,
    started: std::time::Instant,
    last_eviction: std::time::Instant,
    last_log: std::time::Instant,
}

#[derive(Debug, PartialEq, Eq)]
enum CachePressureLog {
    Started,
    Continuing,
    Ended,
}

impl CachePressure {
    fn observe(
        &mut self,
        stats: gossipsub::MessageCacheStats,
        now: std::time::Instant,
    ) -> Option<CachePressureLog> {
        let evicting = stats.evicted_messages > self.seen.evicted_messages;
        let before = std::mem::replace(&mut self.seen, stats);
        let log = match self.episode.as_mut() {
            None if evicting => CachePressureLog::Started,
            None => return None,
            Some(episode) if evicting => {
                episode.last_eviction = now;
                if now.duration_since(episode.last_log) < CACHE_PRESSURE_LOG_INTERVAL {
                    return None;
                }
                episode.last_log = now;
                CachePressureLog::Continuing
            }
            Some(episode) => {
                if now.duration_since(episode.last_eviction) < CACHE_PRESSURE_LOG_INTERVAL {
                    return None;
                }
                CachePressureLog::Ended
            }
        };
        if log == CachePressureLog::Started {
            self.episode = Some(CachePressureEpisode {
                base: before,
                started: now,
                last_eviction: now,
                last_log: now,
            });
        }
        let episode = self.episode.as_ref()?;
        let evicted_messages = stats
            .evicted_messages
            .saturating_sub(episode.base.evicted_messages);
        let evicted_bytes = stats
            .evicted_bytes
            .saturating_sub(episode.base.evicted_bytes);
        let evicted_unvalidated = stats
            .evicted_unvalidated
            .saturating_sub(episode.base.evicted_unvalidated);
        let duration_secs = now.duration_since(episode.started).as_secs();
        match log {
            CachePressureLog::Started => tracing::warn!(
                budget_bytes = stats.max_bytes,
                cached_bytes = stats.bytes,
                cached_messages = stats.messages,
                evicted_messages,
                evicted_bytes,
                "gossip message cache reached its byte budget; evicting the oldest messages, \
                 which peers can then no longer request from this node. Expected during a burst \
                 of large messages; report it with these counts if it persists"
            ),
            CachePressureLog::Continuing => tracing::warn!(
                budget_bytes = stats.max_bytes,
                cached_bytes = stats.bytes,
                cached_messages = stats.messages,
                evicted_messages,
                evicted_bytes,
                evicted_unvalidated,
                duration_secs,
                "gossip message cache still evicting to stay within its byte budget"
            ),
            CachePressureLog::Ended => {
                tracing::info!(
                    budget_bytes = stats.max_bytes,
                    cached_bytes = stats.bytes,
                    evicted_messages,
                    evicted_bytes,
                    evicted_unvalidated,
                    duration_secs,
                    "gossip message cache back within its byte budget"
                );
                self.episode = None;
            }
        }
        Some(log)
    }
}

/// While gossip RPCs are dropped before decoding, the warning repeats at this interval; this
/// long without one ends the episode.
const REJECTED_RPC_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Operator log of the gossip RPCs the pubsub codec dropped before decoding them, because they
/// carried more entries than an RPC may or were malformed: a warning when they start, one per
/// [`REJECTED_RPC_LOG_INTERVAL`] while they continue, and an info line when they stop.
#[derive(Debug, Default)]
struct RejectedRpcLog {
    /// Counters at the previous check.
    seen: gossipsub::RejectedRpcStats,
    episode: Option<RejectedRpcEpisode>,
}

#[derive(Debug)]
struct RejectedRpcEpisode {
    /// Counters before the episode's first rejection.
    base: gossipsub::RejectedRpcStats,
    /// Counters at the episode's previous line.
    logged: gossipsub::RejectedRpcStats,
    started: std::time::Instant,
    last_rejection: std::time::Instant,
    last_log: std::time::Instant,
}

#[derive(Debug, PartialEq, Eq)]
enum RejectedRpcLogLine {
    Started,
    Continuing,
    Ended,
}

impl RejectedRpcLog {
    fn observe(
        &mut self,
        stats: gossipsub::RejectedRpcStats,
        now: std::time::Instant,
    ) -> Option<RejectedRpcLogLine> {
        let rejecting = stats.rejected > self.seen.rejected;
        let before = std::mem::replace(&mut self.seen, stats);
        let line = match self.episode.as_mut() {
            None if rejecting => RejectedRpcLogLine::Started,
            None => return None,
            Some(episode) if rejecting => {
                episode.last_rejection = now;
                if now.duration_since(episode.last_log) < REJECTED_RPC_LOG_INTERVAL {
                    return None;
                }
                RejectedRpcLogLine::Continuing
            }
            Some(episode) => {
                if now.duration_since(episode.last_rejection) < REJECTED_RPC_LOG_INTERVAL {
                    return None;
                }
                RejectedRpcLogLine::Ended
            }
        };
        if line == RejectedRpcLogLine::Started {
            self.episode = Some(RejectedRpcEpisode {
                base: before,
                logged: before,
                started: now,
                last_rejection: now,
                last_log: now,
            });
        }
        let episode = self.episode.as_mut()?;
        let rejected = stats.rejected.saturating_sub(episode.logged.rejected);
        let bytes = stats.bytes.saturating_sub(episode.logged.bytes);
        let total = stats.rejected.saturating_sub(episode.base.rejected);
        let duration_secs = now.duration_since(episode.started).as_secs();
        let (last_peer, last_reason) = stats
            .last
            .map(|(peer, rejection)| (peer.to_string(), rejection.to_string()))
            .unwrap_or_default();
        episode.logged = stats;
        episode.last_log = now;
        match line {
            RejectedRpcLogLine::Started => tracing::warn!(
                rejected,
                bytes,
                %last_peer,
                %last_reason,
                "dropping gossip RPCs from remote peers before decoding them: they carry more \
                 entries than an RPC may, or are malformed. Each sender is penalised and its \
                 gossip stream closed. No action is needed on this node; report it with these \
                 fields if it persists"
            ),
            RejectedRpcLogLine::Continuing => tracing::warn!(
                rejected,
                bytes,
                total,
                %last_peer,
                %last_reason,
                duration_secs,
                "still dropping gossip RPCs from remote peers before decoding them"
            ),
            RejectedRpcLogLine::Ended => {
                tracing::info!(
                    total,
                    duration_secs,
                    "no gossip RPC dropped before decoding for a minute; the episode ended"
                );
                self.episode = None;
            }
        }
        Some(line)
    }
}

/// Gossip RPCs for peers that disconnected are summarized at most this often.
const UNSENT_RPC_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Operator log of the gossip RPCs dropped because their peer had left the connected peer
/// list: one info line per [`UNSENT_RPC_LOG_INTERVAL`] while they continue, with the count
/// since the previous line. Each is the loss of one message for one peer that disconnected.
#[derive(Debug, Default)]
struct UnsentRpcLog {
    /// Counters at the previous line.
    logged: gossipsub::UnsentRpcStats,
    last_log: Option<std::time::Instant>,
}

impl UnsentRpcLog {
    /// Returns the RPCs dropped since the previous line when one is due.
    fn observe(
        &mut self,
        stats: gossipsub::UnsentRpcStats,
        now: std::time::Instant,
    ) -> Option<u64> {
        let unsent = stats.unsent.saturating_sub(self.logged.unsent);
        if unsent == 0 {
            return None;
        }
        let since = self.last_log.map(|at| now.duration_since(at));
        if since.is_some_and(|since| since < UNSENT_RPC_LOG_INTERVAL) {
            return None;
        }
        self.logged = stats;
        self.last_log = Some(now);
        let latest_peer = stats.last.map(|peer| peer.to_string()).unwrap_or_default();
        tracing::info!(
            unsent,
            total = stats.unsent,
            %latest_peer,
            since_secs = since.map_or(0, |since| since.as_secs()),
            "gossip RPCs dropped for peers that had disconnected; the counts are since the \
             previous line. Each is one message not sent to one departed peer; nothing to do \
             unless the count stays high for hours"
        );
        Some(unsent)
    }
}

/// After strict shard gossip turns on, peers answering under pre-strict message ids are
/// ignored for this long: every upgraded node switches within seconds of the epoch's first
/// GLOBAL frame, and until then it advertises and answers under those ids too.
const LEGACY_ID_SWITCH_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

/// While peers answer under pre-strict message ids, the warning repeats at this interval; this
/// long without one ends the episode.
const LEGACY_ID_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// The most peers one line names; the line also counts them all.
const LEGACY_ID_PEERS_NAMED: usize = 8;

/// Operator log of peers on a release before strict shard gossip. Under strict shard gossip a
/// shard CW message's id names its author; such a peer still advertises and answers under the
/// content id, so it and this node break each other's gossip promises and lower each other's
/// scores until they graylist each other. The peer's own node does not say why. A warning names
/// such peers when they start answering under the content id (after
/// [`LEGACY_ID_SWITCH_GRACE`]), one per [`LEGACY_ID_LOG_INTERVAL`] while they continue, and an
/// info line when they stop.
#[derive(Debug, Default)]
struct LegacyIdLog {
    /// When strict shard gossip was first seen on, while it stays on.
    strict_since: Option<std::time::Instant>,
    /// Answers per peer since the previous line.
    pending: HashMap<PeerId, u64>,
    episode: Option<LegacyIdEpisode>,
}

#[derive(Debug)]
struct LegacyIdEpisode {
    started: std::time::Instant,
    last_answer: std::time::Instant,
    last_log: std::time::Instant,
    /// Answers in the episode, logged ones included.
    answers: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum LegacyIdLogLine {
    Started,
    Continuing,
    Ended,
}

impl LegacyIdLog {
    fn observe(
        &mut self,
        strict: bool,
        answers: HashMap<PeerId, u64>,
        now: std::time::Instant,
    ) -> Option<LegacyIdLogLine> {
        self.strict_since = if strict {
            Some(self.strict_since.unwrap_or(now))
        } else {
            None
        };
        let switched = self
            .strict_since
            .is_some_and(|since| now.duration_since(since) >= LEGACY_ID_SWITCH_GRACE);
        let answering = switched && !answers.is_empty();
        if answering {
            for (peer, count) in answers {
                if self.pending.len() < 1024 || self.pending.contains_key(&peer) {
                    *self.pending.entry(peer).or_insert(0) += count;
                }
            }
        }
        let line = match self.episode.as_mut() {
            None if answering => LegacyIdLogLine::Started,
            None => return None,
            Some(episode) if answering => {
                episode.last_answer = now;
                if now.duration_since(episode.last_log) < LEGACY_ID_LOG_INTERVAL {
                    return None;
                }
                LegacyIdLogLine::Continuing
            }
            Some(episode) => {
                if now.duration_since(episode.last_answer) < LEGACY_ID_LOG_INTERVAL {
                    return None;
                }
                LegacyIdLogLine::Ended
            }
        };
        let episode = self.episode.get_or_insert(LegacyIdEpisode {
            started: now,
            last_answer: now,
            last_log: now,
            answers: 0,
        });
        let pending = std::mem::take(&mut self.pending);
        let peers = pending.len();
        let answers: u64 = pending.values().sum();
        episode.answers += answers;
        episode.last_log = now;
        let mut ranked: Vec<_> = pending.into_iter().collect();
        ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let named = ranked
            .iter()
            .take(LEGACY_ID_PEERS_NAMED)
            .map(|(peer, count)| format!("{peer}:{count}"))
            .collect::<Vec<_>>()
            .join(",");
        let epoch = quil_types::consensus::strict_shard_gossip_epoch();
        let total = episode.answers;
        let duration_secs = now.duration_since(episode.started).as_secs();
        match line {
            LegacyIdLogLine::Started => tracing::warn!(
                peers,
                answers,
                %named,
                epoch,
                "peers answer this node's gossip requests for shard consensus messages under \
                 the message ids of releases before strict shard gossip: they run such a \
                 release, or have not yet reached the strict epoch's GLOBAL frames. Since that \
                 epoch they and upgraded nodes break each other's gossip promises and graylist \
                 each other, so their consensus messages are lost in bursts. Nothing to do on \
                 this node; whoever runs a named peer must upgrade it, or check that it follows \
                 the GLOBAL head"
            ),
            LegacyIdLogLine::Continuing => tracing::warn!(
                peers,
                answers,
                total,
                %named,
                epoch,
                duration_secs,
                "peers still answer this node's gossip requests under the message ids of \
                 releases before strict shard gossip; the counts are since the previous line"
            ),
            LegacyIdLogLine::Ended => {
                tracing::info!(
                    peers,
                    answers,
                    total,
                    %named,
                    duration_secs,
                    "no peer answered under the message ids of releases before strict shard \
                     gossip for ten minutes; the episode ended"
                );
                self.episode = None;
            }
        }
        Some(line)
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
                        let outcome =
                            match (self.validators.get(&bitmask), &self.fallback_validator) {
                                (Some(v), _) => {
                                    v(&propagation_source, message.source.as_ref(), &message.data)
                                }
                                (None, Some(v)) => v(&propagation_source, &bitmask, &message.data),
                                (None, None) => ValidationResult::Accept,
                            };
                        let _ = self.inner.report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            outcome.to_acceptance(),
                        );
                        if outcome == ValidationResult::Accept {
                            return Poll::Ready(ToSwarm::GenerateEvent(BlossomSubEvent::Message {
                                propagation_source,
                                message_id: message_id.0,
                                message: to_pb_message(message, bitmask),
                            }));
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
                        return Poll::Ready(ToSwarm::GenerateEvent(BlossomSubEvent::Subscribed {
                            peer_id,
                            bitmask,
                        }));
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

/// The score parameters of every subscribed topic: only P₄, the invalid-message
/// penalty (weight × counter²). A `Reject` from a validator, or a message the
/// codec refuses (bad signature, oversized), counts one. The counter keeps 90 %
/// a second (it kept 50 %, which forgot a flood within seconds): a one-off stays
/// above every threshold, three put the sender below the graylist threshold and
/// keep it below the gossip threshold for some seconds, and a sustained stream
/// keeps it graylisted. The delivery terms (P₁–P₃, P₃b) stay zero: they punish
/// honest peers for WAN delivery variance and made meshes flap; whether small
/// positive P₂/P₃ would help defend meshes needs measurement first.
fn invalid_message_topic_params() -> gossipsub::TopicScoreParams {
    gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        time_in_mesh_weight: 0.0,
        first_message_deliveries_weight: 0.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        invalid_message_deliveries_weight: -50.0,
        invalid_message_deliveries_decay: 0.9,
        ..Default::default()
    }
}

/// Peer-score config. Two channels are active: (1) the application score
/// (`set_application_score`, driven by the node — peer_authenticator + per-source
/// drop-rate penalties); (2) topic P₄ (invalid-message,
/// [`invalid_message_topic_params`]) on GLOBAL_FRAME and GLOBAL_PEER_INFO here,
/// and on every other topic as it is subscribed. Every honest-peer-affecting
/// topic term (time-in-mesh, first/mesh deliveries, mesh-failure) is ZEROED:
/// those punish peers for normal WAN delivery variance and cause mesh flapping.
fn build_peer_score() -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    let pi_topic = invalid_message_topic_params();
    // Keep `PeerScoreParams::default()` for everything else — notably
    // `app_specific_weight` (the existing `set_application_score` channel),
    // `ip_colocation_factor_weight` and `behaviour_penalty_weight`.
    let mut score_params = gossipsub::PeerScoreParams::default();
    // GLOBAL_FRAME `[0,0]`: the gate `Reject`s only a wrong type prefix, which
    // every build rejects, so an honest relay never forwards one; copies of
    // known frames and rate-limited frames are `Ignore`d, without penalty.
    // Invalid signatures on the topic count too.
    score_params
        .topics
        .insert(topic_for(&[0u8, 0]).hash(), pi_topic.clone());
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

/// Map [`crate::BlossomsubParams`] onto a [`gossipsub::Config`], selecting the
/// per-network protocol id and setting the BlossomSub message id
/// (`[0x01] ++ SHA256(data)`); `mcache_max_bytes` maps onto the vendored
/// crate's message-cache byte budget.
fn build_config(network: u8, params: &crate::BlossomsubParams) -> gossipsub::Config {
    let mut builder = gossipsub::ConfigBuilder::default();
    builder
        // Gossipsub 1.2: IDONTWANT is sent only to peers of that kind, and a
        // custom protocol id's kind is ours to set (both ends negotiate the
        // same id). Every build receives and honours IDONTWANT whatever kind
        // it gave us, and a decoder without the field skips it, so an older
        // peer is suppressed by our IDONTWANTs while it sends us none.
        .protocol_id(
            crate::protocol::protocol_id_for_network(network),
            gossipsub::Version::V1_2,
        )
        .history_length(params.history_length)
        .history_gossip(params.history_gossip)
        // The history windows bound the message cache by heartbeats only; this
        // bounds its bytes (oldest, validated messages evicted first).
        .mcache_max_bytes(params.mcache_max_bytes)
        // Mesh-degree (D) family is DELIBERATELY left at gossipsub's own
        // defaults (mesh_n=6, mesh_n_low=5, mesh_n_high=12, gossip_lazy=6,
        // mesh_outbound_min=2): higher fan-out multiplies traffic on
        // high-rate topics (e.g. GLOBAL_PEER_INFO). `params.d_lo` only
        // gates the under-meshed check in `maybe_emit_need_peers`.
        .gossip_factor(params.gossip_factor)
        .heartbeat_interval(params.heartbeat_interval)
        .heartbeat_initial_delay(params.heartbeat_initial_delay)
        .fanout_ttl(params.fanout_ttl)
        .prune_backoff(params.prune_backoff)
        .unsubscribe_backoff(params.unsubscribe_backoff.as_secs())
        .iwant_followup_time(params.iwant_followup_time)
        .idontwant_message_size_threshold(params.idont_want_message_threshold)
        // Per-RPC frame cap. 16 MiB matches the RPC frame cap in
        // `protocol.rs` and is the smallest that carries the largest message
        // the node gossips: a GLOBAL frame of up to 15 MiB
        // (`MAX_GOSSIP_GLOBAL_FRAME`) plus its signature and header. The
        // codec bounds each RPC's entries before decoding it, so decoding
        // stays proportional to the frame.
        .max_transmit_size(crate::protocol::MAX_MESSAGE_SIZE)
        // Keep de-duplicated message IDs at least as long as the peer-score
        // delivery-record window (WAN margin); cost is holding 33-byte ids a bit
        // longer.
        .duplicate_cache_time(std::time::Duration::from_secs(300))
        // Run per-bitmask validators before forwarding (see module docs).
        .validate_messages()
        // A node's master and standalone workers sign with one identity under
        // different transport ids (`P2PNode::new_for_worker`), and a relay
        // excludes only the source from forwarding. So a message from our own
        // identity, relayed by an honest peer, is a sibling's: check it like
        // any other, without penalising the relay. Copies of messages this
        // process published are dropped as duplicates.
        .allow_self_origin(true)
        // BlossomSub message id = `[0x01] ++ SHA256(data)`. Stock gossipsub's
        // default id differs, so we set it explicitly to keep the dedup key
        // stable across the network. Under strict shard gossip a shard CW
        // topic's id also covers the message's author
        // (`crate::node::gossip_message_id`).
        .message_id_fn(|message: &gossipsub::Message| {
            let source = message
                .source
                .map(|peer| peer.to_bytes())
                .unwrap_or_default();
            gossipsub::MessageId::from(crate::node::gossip_message_id(
                &bitmask_from_topic(&message.topic),
                &source,
                &message.data,
                crate::node::strict_shard_gossip(),
            ))
        })
        // A peer that answers an IWANT for the content id of a shard CW message under strict
        // shard gossip runs an older release (`LegacyIdLog`).
        .legacy_message_id_fn(|message: &gossipsub::Message| {
            crate::node::pre_strict_gossip_message_id(
                &bitmask_from_topic(&message.topic),
                &message.data,
                crate::node::strict_shard_gossip(),
            )
            .map(gossipsub::MessageId::from)
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

    /// Under strict shard gossip, two copies of a message with the same data
    /// and different authors get different ids on a shard CW topic, so the
    /// author's own copy is not dropped as the duplicate of a copy another
    /// peer re-published first. Every other topic, and every topic before the
    /// strict epoch, keeps the content id `[0x01] ++ SHA256(data)`.
    #[test]
    fn shard_cw_message_ids_name_their_author_when_strict() {
        let config = build_config(0, &crate::BlossomsubParams::default());
        let filter = [7u8; 32];
        let mut cw = vec![0x01u8];
        cw.extend_from_slice(&filter);
        let (genuine, reauthored) = (PeerId::random(), PeerId::random());
        let message = |bitmask: &[u8], source: PeerId| gossipsub::Message {
            source: Some(source),
            data: b"\x00vote".to_vec(),
            sequence_number: Some(1),
            topic: topic_for(bitmask).hash(),
        };
        let id = |bitmask: &[u8], source: PeerId| config.message_id(&message(bitmask, source));
        let content = gossipsub::MessageId::from(crate::node::message_id(b"\x00vote"));
        let mut legacy = vec![0x00u8];
        legacy.extend_from_slice(&filter);
        let others: [&[u8]; 6] = [
            &[0x00, 0x00, 0x00, 0x00],
            &[0x00, 0x00],
            &[0u8; 16],
            &filter,
            &legacy,
            &[0x01; 32],
        ];
        crate::node::set_strict_shard_gossip(false);
        assert_eq!(id(&cw, genuine), content);
        assert_eq!(id(&cw, reauthored), content);
        crate::node::set_strict_shard_gossip(true);
        assert_ne!(
            id(&cw, genuine),
            id(&cw, reauthored),
            "a re-authored copy of a CW message shares its author's id"
        );
        assert_ne!(id(&cw, genuine), content);
        assert_eq!(id(&cw, genuine).0.len(), 33);
        assert_eq!(id(&cw, genuine).0[0], 0x01);
        assert_eq!(id(&cw, genuine), id(&cw, genuine));
        for bitmask in others {
            assert_eq!(
                id(bitmask, genuine),
                content,
                "{} keeps the content id",
                hex::encode(bitmask)
            );
            assert_eq!(id(bitmask, reauthored), content);
        }
        crate::node::set_strict_shard_gossip(false);
    }

    #[test]
    fn build_config_applies_the_message_cache_byte_budget() {
        let params = crate::BlossomsubParams::default();
        assert_eq!(
            build_config(0, &params).mcache_max_bytes(),
            crate::params::MCACHE_MAX_BYTES
        );
    }

    #[test]
    fn cache_pressure_logs_start_bounded_repeats_and_end() {
        let stats = |evicted_messages| gossipsub::MessageCacheStats {
            evicted_messages,
            ..Default::default()
        };
        let t0 = std::time::Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        let mut pressure = CachePressure::default();
        assert_eq!(pressure.observe(stats(0), at(0)), None);
        assert_eq!(
            pressure.observe(stats(5), at(1)),
            Some(CachePressureLog::Started)
        );
        assert_eq!(pressure.observe(stats(9), at(2)), None);
        assert_eq!(pressure.observe(stats(9), at(30)), None);
        assert_eq!(
            pressure.observe(stats(12), at(61)),
            Some(CachePressureLog::Continuing)
        );
        assert_eq!(pressure.observe(stats(12), at(100)), None);
        assert_eq!(
            pressure.observe(stats(12), at(121)),
            Some(CachePressureLog::Ended)
        );
        assert_eq!(pressure.observe(stats(12), at(200)), None);
        assert_eq!(
            pressure.observe(stats(13), at(201)),
            Some(CachePressureLog::Started)
        );
    }

    /// Peers answering under pre-strict ids are named once strict shard gossip has been on for
    /// the switch grace, at most once per interval, and the episode ends after an interval
    /// without one. Before strict shard gossip, or within the grace, nothing is logged.
    #[test]
    fn legacy_id_answers_log_after_the_switch_with_bounded_repeats_and_end() {
        let (old, other) = (PeerId::random(), PeerId::random());
        let answers = |peers: &[PeerId]| -> HashMap<PeerId, u64> {
            peers.iter().map(|peer| (*peer, 2u64)).collect()
        };
        let t0 = std::time::Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        let mut log = LegacyIdLog::default();
        assert_eq!(log.observe(false, answers(&[old]), at(0)), None);
        assert_eq!(log.observe(true, answers(&[old]), at(1)), None);
        assert_eq!(log.observe(true, answers(&[old]), at(120)), None);
        assert!(log.pending.is_empty(), "answers within the grace were kept");
        assert_eq!(
            log.observe(true, answers(&[old, other]), at(121)),
            Some(LegacyIdLogLine::Started)
        );
        assert_eq!(log.observe(true, answers(&[old]), at(122)), None);
        assert_eq!(log.observe(true, answers(&[]), at(300)), None);
        assert_eq!(
            log.observe(true, answers(&[old]), at(721)),
            Some(LegacyIdLogLine::Continuing)
        );
        assert_eq!(log.episode.as_ref().map(|episode| episode.answers), Some(8));
        assert_eq!(log.observe(true, answers(&[]), at(1000)), None);
        assert_eq!(
            log.observe(true, answers(&[]), at(1321)),
            Some(LegacyIdLogLine::Ended)
        );
        assert_eq!(log.observe(true, answers(&[]), at(2000)), None);
        // Strict shard gossip off and on again: a new grace.
        assert_eq!(log.observe(false, answers(&[]), at(2001)), None);
        assert_eq!(log.observe(true, answers(&[old]), at(2002)), None);
        assert_eq!(
            log.observe(true, answers(&[old]), at(2122)),
            Some(LegacyIdLogLine::Started)
        );
    }

    /// Under strict shard gossip, only a shard CW topic's message has a pre-strict id, its
    /// content id; before it, none has.
    #[test]
    fn only_shard_cw_messages_have_a_pre_strict_id_when_strict() {
        let config = build_config(0, &crate::BlossomsubParams::default());
        let mut cw = vec![0x01u8];
        cw.extend_from_slice(&[7u8; 32]);
        let message = |bitmask: &[u8]| gossipsub::Message {
            source: Some(PeerId::random()),
            data: b"\x00vote".to_vec(),
            sequence_number: Some(1),
            topic: topic_for(bitmask).hash(),
        };
        let content = gossipsub::MessageId::from(crate::node::message_id(b"\x00vote"));
        let others: [&[u8]; 3] = [&[0x00, 0x00, 0x00, 0x00], &[7u8; 32], &[0x01; 32]];
        crate::node::set_strict_shard_gossip(false);
        assert_eq!(config.legacy_message_id(&message(&cw)), None);
        crate::node::set_strict_shard_gossip(true);
        let strict_cw = message(&cw);
        assert_eq!(config.legacy_message_id(&strict_cw), Some(content));
        assert_ne!(
            config.legacy_message_id(&strict_cw),
            Some(config.message_id(&strict_cw))
        );
        for bitmask in others {
            assert_eq!(
                config.legacy_message_id(&message(bitmask)),
                None,
                "{} has a pre-strict id",
                hex::encode(bitmask)
            );
        }
        crate::node::set_strict_shard_gossip(false);
    }

    #[test]
    fn unsent_rpcs_log_one_bounded_summary_per_interval() {
        let stats = |unsent| gossipsub::UnsentRpcStats { unsent, last: None };
        let t0 = std::time::Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        let mut log = UnsentRpcLog::default();
        assert_eq!(log.observe(stats(0), at(0)), None);
        assert_eq!(log.observe(stats(3), at(1)), Some(3));
        assert_eq!(log.observe(stats(50), at(2)), None);
        assert_eq!(log.observe(stats(60), at(40)), None);
        assert_eq!(log.observe(stats(60), at(70)), Some(57));
        assert_eq!(log.observe(stats(60), at(200)), None);
        assert_eq!(log.observe(stats(61), at(201)), Some(1));
    }

    #[test]
    fn rejected_rpc_logs_start_bounded_repeats_and_end() {
        let stats = |rejected| gossipsub::RejectedRpcStats {
            rejected,
            ..Default::default()
        };
        let t0 = std::time::Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        let mut log = RejectedRpcLog::default();
        assert_eq!(log.observe(stats(0), at(0)), None);
        assert_eq!(
            log.observe(stats(1), at(1)),
            Some(RejectedRpcLogLine::Started)
        );
        assert_eq!(log.observe(stats(40), at(2)), None);
        assert_eq!(log.observe(stats(40), at(30)), None);
        assert_eq!(
            log.observe(stats(41), at(61)),
            Some(RejectedRpcLogLine::Continuing)
        );
        assert_eq!(log.observe(stats(41), at(100)), None);
        assert_eq!(
            log.observe(stats(41), at(121)),
            Some(RejectedRpcLogLine::Ended)
        );
        assert_eq!(log.observe(stats(41), at(200)), None);
        assert_eq!(
            log.observe(stats(42), at(201)),
            Some(RejectedRpcLogLine::Started)
        );
    }

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
        // GLOBAL_FRAME is scored the same way, so its rejects penalise.
        let frame = params
            .topics
            .get(&topic_for(&[0u8, 0]).hash())
            .expect("GLOBAL_FRAME must be scored");
        assert!(frame.invalid_message_deliveries_weight < 0.0);
        assert_eq!(frame.mesh_message_deliveries_weight, 0.0);
    }

    /// A message the codec or a validator refuses on a shard topic must
    /// count against its sender's score, as it does on the global topics:
    /// unscored, invalid messages there cost the sender nothing.
    #[test]
    fn reproduces_unscored_invalid_messages_on_shard_topics() {
        let mut behaviour = BlossomSubBehaviour::new(0);
        let keypair = Keypair::generate_ed25519();
        behaviour.set_signing_identity(keypair.public().to_peer_id(), keypair);
        let shard_topic = vec![0x01; 33];
        behaviour.subscribe(shard_topic.clone());

        let penalty = behaviour
            .inner
            .get_topic_params(&topic_for(&shard_topic))
            .map_or(0.0, |params| params.invalid_message_deliveries_weight);
        assert!(
            penalty < 0.0,
            "a subscribed shard topic carries no invalid-message penalty"
        );
    }

    /// The registered validator sees the signed author of a message.
    #[test]
    fn authored_validators_see_the_author() {
        let mut behaviour = BlossomSubBehaviour::new(0);
        let author = PeerId::random();
        behaviour.register_authored_validator(vec![1], move |_, from, _| {
            if from == Some(&author) {
                ValidationResult::Accept
            } else {
                ValidationResult::Ignore
            }
        });
        behaviour.register_validator(vec![2], |_, _| ValidationResult::Reject);
        let forwarder = PeerId::random();
        let one = &behaviour.validators[&vec![1]];
        assert_eq!(
            one(&forwarder, Some(&author), b""),
            ValidationResult::Accept
        );
        assert_eq!(one(&forwarder, None, b""), ValidationResult::Ignore);
        let two = &behaviour.validators[&vec![2]];
        assert_eq!(two(&forwarder, None, b""), ValidationResult::Reject);
    }

    /// Bitmasks without a validator of their own go to the fallback, with
    /// their bitmask; those with one never do.
    #[test]
    fn the_fallback_validator_sees_unregistered_bitmasks() {
        let mut behaviour = BlossomSubBehaviour::new(0);
        behaviour.register_validator(vec![1], |_, _| ValidationResult::Accept);
        behaviour.register_fallback_validator(|_, bitmask, data| {
            if bitmask == [2] && data == b"ok" {
                ValidationResult::Accept
            } else {
                ValidationResult::Ignore
            }
        });
        let fallback = behaviour.fallback_validator.clone().unwrap();
        let peer = PeerId::random();
        assert!(behaviour.validators.contains_key(&vec![1]));
        assert_eq!(fallback(&peer, &[2], b"ok"), ValidationResult::Accept);
        assert_eq!(fallback(&peer, &[2], b"no"), ValidationResult::Ignore);
        assert_eq!(fallback(&peer, &[3], b"ok"), ValidationResult::Ignore);
    }

    /// A peer's subscriptions are bounded in number and topic length.
    #[test]
    fn peer_subscriptions_are_bounded() {
        use gossipsub::TopicSubscriptionFilter as _;
        let mut filter = subscription_filter();
        assert_eq!(filter.max_subscribed_topics, MAX_PEER_TOPICS);
        assert_eq!(filter.max_subscriptions_per_request, 1024);
        let longest = gossipsub::TopicHash::from_raw("0".repeat(MAX_TOPIC_LEN));
        let longer = gossipsub::TopicHash::from_raw("0".repeat(MAX_TOPIC_LEN + 1));
        assert!(filter.can_subscribe(&topic_for(&[0xff; 35]).hash()));
        assert!(filter.can_subscribe(&longest));
        assert!(!filter.can_subscribe(&longer));
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
        behaviour
            .peer_subscriptions
            .insert(peer, [topic.clone()].into_iter().collect());
        behaviour
            .peer_subscriptions
            .insert(disconnected, [topic.clone()].into_iter().collect());
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

    /// A message on a bitmask without a validator of its own gets the
    /// fallback validator's verdict on the receive path, and the validator
    /// sees its bitmask: a message it rejects is not delivered, one it
    /// accepts is.
    #[tokio::test]
    async fn received_messages_on_unregistered_bitmasks_get_the_fallback_verdict() {
        let bitmask = vec![0x01u8; 33];
        type Seen = Arc<std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;
        let seen: Seen = Default::default();

        let mut hub = build_swarm();
        let mut leaf = build_swarm();
        let leaf_id = *leaf.local_peer_id();
        let validated = seen.clone();
        let fallback = move |_: &PeerId, bitmask: &[u8], data: &[u8]| {
            validated
                .lock()
                .unwrap()
                .push((bitmask.to_vec(), data.to_vec()));
            if data == b"accepted" {
                ValidationResult::Accept
            } else {
                ValidationResult::Reject
            }
        };
        leaf.behaviour_mut().register_fallback_validator(fallback);
        hub.behaviour_mut().subscribe(bitmask.clone());
        leaf.behaviour_mut().subscribe(bitmask.clone());

        hub.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");
        let hub_addr: Multiaddr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = hub.select_next_some().await {
                break address;
            }
        };
        leaf.dial(hub_addr).expect("leaf dial");

        let mut published = false;
        let mut delivered = Vec::new();
        let ok = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                tokio::select! {
                    _ = hub.select_next_some() => {}
                    ev = leaf.select_next_some() => {
                        if let SwarmEvent::Behaviour(BlossomSubEvent::Message { message, .. }) = ev {
                            delivered.push(message.data);
                        }
                    }
                }
                if !published && hub.behaviour().peer_subscribed_to(&leaf_id, &bitmask) {
                    for data in [b"rejected".to_vec(), b"accepted".to_vec()] {
                        hub.behaviour_mut()
                            .publish(bitmask.clone(), data)
                            .expect("publish");
                    }
                    published = true;
                }
                let accepted = delivered.iter().any(|data| data == b"accepted");
                if accepted && seen.lock().unwrap().len() >= 2 {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);

        assert!(
            ok,
            "the fallback must see both and the accepted one arrive ({delivered:?}, {seen:?})"
        );
        assert_eq!(
            delivered,
            vec![b"accepted".to_vec()],
            "a message the fallback validator rejected was delivered"
        );
        let mut seen = seen.lock().unwrap().clone();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                (bitmask.clone(), b"accepted".to_vec()),
                (bitmask, b"rejected".to_vec()),
            ],
            "the fallback validator sees each message with its bitmask"
        );
    }

    /// IDONTWANT received, from gossipsub's own counter in `swarm`'s registry.
    fn idontwants_received(swarm: &Swarm<BlossomSubBehaviour>) -> u64 {
        crate::metrics::render(&swarm.behaviour().metrics_registry())
            .lines()
            .find_map(|line| line.strip_prefix("gossipsub_idontwant_msgs_total "))
            .and_then(|count| count.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Relays that hold a large message tell each other with IDONTWANT. The
    /// hub flood-publishes to both relays, which are in each other's mesh; a
    /// relay's first copy sends IDONTWANT to its other mesh peer, so at least
    /// one relay receives one. With the protocol classified as gossipsub 1.1
    /// none was ever sent (2026-10-17 field capture: zero IDONTWANT).
    #[tokio::test]
    async fn relays_exchange_idontwant_for_large_messages() {
        let bitmask = vec![0x80u8];
        let payload = vec![7u8; 4096];

        let mut hub = build_swarm();
        let mut relay_a = build_swarm();
        let mut relay_b = build_swarm();
        let (a_id, b_id) = (*relay_a.local_peer_id(), *relay_b.local_peer_id());

        for swarm in [&mut hub, &mut relay_a, &mut relay_b] {
            swarm.behaviour_mut().subscribe(bitmask.clone());
        }
        hub.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");
        relay_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");
        let hub_addr: Multiaddr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = hub.select_next_some().await {
                break address;
            }
        };
        let a_addr: Multiaddr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = relay_a.select_next_some().await {
                break address;
            }
        };
        relay_a.dial(hub_addr.clone()).expect("relay_a dial");
        relay_b.dial(hub_addr).expect("relay_b dial");
        relay_b.dial(a_addr).expect("relay_b dial relay_a");

        let mut published = false;
        let ok = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                tokio::select! {
                    _ = hub.select_next_some() => {}
                    _ = relay_a.select_next_some() => {}
                    _ = relay_b.select_next_some() => {}
                }
                if !published
                    && hub.behaviour().peer_subscribed_to(&a_id, &bitmask)
                    && hub.behaviour().peer_subscribed_to(&b_id, &bitmask)
                    && relay_a.behaviour().mesh_peers(&bitmask) >= 2
                    && relay_b.behaviour().mesh_peers(&bitmask) >= 2
                {
                    published = hub
                        .behaviour_mut()
                        .publish(bitmask.clone(), payload.clone())
                        .is_ok();
                }
                if published && idontwants_received(&relay_a) + idontwants_received(&relay_b) > 0 {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);

        assert!(
            ok,
            "a relay must receive IDONTWANT (published={published}, a={}, b={})",
            idontwants_received(&relay_a),
            idontwants_received(&relay_b)
        );
    }
}

/// A process restarted under its peer id must learn its peers' subscriptions
/// even while they still hold the killed process's connection. A SIGKILLed
/// QUIC peer sends no close, so the others keep its connection until their
/// idle timeout (10 s); a restart within it reconnects beside the old one.
/// `subscribed_peer_count` gates a starting worker's consensus (the CW
/// transport barrier), so a count stuck at 0 keeps the worker from its seat.
#[cfg(test)]
mod restart_tests {
    use super::*;
    use futures::StreamExt;
    use libp2p::{Multiaddr, Swarm, SwarmBuilder};
    use std::time::Duration;

    const TOPIC: [u8; 2] = [0x0c, 0xa1];
    /// Bound for connection set-up steps.
    const SETUP: Duration = Duration::from_secs(20);
    /// Time the restarted process gets to learn the hub's subscription: 30
    /// heartbeats, and past QUIC's idle timeout.
    const RELEARN: Duration = Duration::from_secs(30);

    #[derive(Clone, Copy)]
    enum Link {
        Tcp,
        Quic,
    }

    fn behaviour(key: &Keypair) -> BlossomSubBehaviour {
        let mut b = BlossomSubBehaviour::new(0);
        b.set_signing_identity(key.public().to_peer_id(), key.clone());
        b.subscribe(TOPIC.to_vec());
        b
    }

    fn swarm(key: Keypair, link: Link) -> Swarm<BlossomSubBehaviour> {
        let idle =
            |cfg: libp2p::swarm::Config| cfg.with_idle_connection_timeout(Duration::from_secs(120));
        match link {
            Link::Tcp => SwarmBuilder::with_existing_identity(key)
                .with_tokio()
                .with_tcp(
                    libp2p::tcp::Config::default(),
                    libp2p::noise::Config::new,
                    libp2p::yamux::Config::default,
                )
                .expect("tcp transport")
                .with_behaviour(behaviour)
                .expect("behaviour")
                .with_swarm_config(idle)
                .build(),
            Link::Quic => SwarmBuilder::with_existing_identity(key)
                .with_tokio()
                .with_quic()
                .with_behaviour(behaviour)
                .expect("behaviour")
                .with_swarm_config(idle)
                .build(),
        }
    }

    async fn listen(swarm: &mut Swarm<BlossomSubBehaviour>, link: Link) -> Multiaddr {
        let addr = match link {
            Link::Tcp => "/ip4/127.0.0.1/tcp/0",
            Link::Quic => "/ip4/127.0.0.1/udp/0/quic-v1",
        };
        swarm.listen_on(addr.parse().unwrap()).expect("listen");
        loop {
            if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } =
                swarm.select_next_some().await
            {
                return address;
            }
        }
    }

    /// Polls every swarm until `done` holds or `limit` passes; whether it held.
    async fn drive(
        swarms: &mut [&mut Swarm<BlossomSubBehaviour>],
        limit: Duration,
        mut done: impl FnMut(&[&mut Swarm<BlossomSubBehaviour>]) -> bool,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if done(swarms) {
                return true;
            }
            let next = futures::future::select_all(
                swarms.iter_mut().map(|s| Box::pin(s.select_next_some())),
            );
            tokio::select! {
                _ = next => {}
                _ = tokio::time::sleep_until(deadline) => return done(swarms),
            }
        }
    }

    /// Connections `behaviour` holds to `peer`.
    fn connections(behaviour: &BlossomSubBehaviour, peer: &PeerId) -> usize {
        behaviour.connected_peers.get(peer).copied().unwrap_or(0)
    }

    /// Restarts `key`'s process beside the hub: Ok when the new process
    /// learns the hub's subscription within `RELEARN`.
    async fn relearned(
        hub: &mut Swarm<BlossomSubBehaviour>,
        hub_addr: Multiaddr,
        key: Keypair,
        link: Link,
    ) -> Result<(), String> {
        let id = key.public().to_peer_id();
        let held = connections(hub.behaviour(), &id);
        let mut new = swarm(key, link);
        new.dial(hub_addr).expect("new dial");
        let ok = drive(&mut [&mut *hub, &mut new], RELEARN, |s| {
            s[1].behaviour().subscribed_peer_count(&TOPIC) > 0
        })
        .await;
        if ok {
            return Ok(());
        }
        Err(format!(
            "RESTART SUBSCRIPTIONS LOST: the restarted process learned no subscription of the \
             hub in {RELEARN:?} (hub connections to its peer id: {held} at the restart, {} now; \
             hub knows it subscribed: {}; its mesh peers: {}; connected: {})",
            connections(hub.behaviour(), &id),
            hub.behaviour().peer_subscribed_to(&id, &TOPIC),
            new.behaviour().mesh_peers(&TOPIC),
            new.behaviour().is_connected(hub.local_peer_id()),
        ))
    }

    /// TCP, the old connection still held at the restart: the hub sees the
    /// new connection as its second to the peer id, then the old one closes.
    #[tokio::test]
    async fn restart_beside_a_held_connection_relearns_peer_subscriptions() {
        let key = Keypair::generate_ed25519();
        let id = key.public().to_peer_id();
        let mut hub = swarm(Keypair::generate_ed25519(), Link::Tcp);
        let hub_addr = listen(&mut hub, Link::Tcp).await;
        let mut old = swarm(key.clone(), Link::Tcp);
        old.dial(hub_addr.clone()).expect("old dial");
        assert!(
            drive(&mut [&mut hub, &mut old], SETUP, |s| {
                s[0].behaviour().peer_subscribed_to(&id, &TOPIC)
                    && s[1].behaviour().subscribed_peer_count(&TOPIC) == 1
            })
            .await,
            "setup: the old process and the hub exchange subscriptions"
        );
        let mut new = swarm(key, Link::Tcp);
        new.dial(hub_addr).expect("new dial");
        assert!(
            drive(&mut [&mut hub, &mut old, &mut new], SETUP, |s| {
                connections(s[0].behaviour(), &id) == 2
                    && s[2].behaviour().is_connected(s[0].local_peer_id())
            })
            .await,
            "setup: the hub holds the old and the new connection"
        );
        drop(old);
        let ok = drive(&mut [&mut hub, &mut new], RELEARN, |s| {
            s[1].behaviour().subscribed_peer_count(&TOPIC) > 0
        })
        .await;
        assert!(
            ok,
            "RESTART SUBSCRIPTIONS LOST: the restarted process learned no subscription of the \
             hub in {RELEARN:?} (hub connections to its peer id: {}; its mesh peers: {})",
            connections(hub.behaviour(), &id),
            new.behaviour().mesh_peers(&TOPIC),
        );
    }

    /// Control, TCP: the hub dropped the old connection before the restart.
    #[tokio::test]
    async fn restart_after_the_old_connection_closed_relearns_peer_subscriptions() {
        let key = Keypair::generate_ed25519();
        let id = key.public().to_peer_id();
        let mut hub = swarm(Keypair::generate_ed25519(), Link::Tcp);
        let hub_addr = listen(&mut hub, Link::Tcp).await;
        let mut old = swarm(key.clone(), Link::Tcp);
        old.dial(hub_addr.clone()).expect("old dial");
        assert!(
            drive(&mut [&mut hub, &mut old], SETUP, |s| {
                s[0].behaviour().peer_subscribed_to(&id, &TOPIC)
            })
            .await,
            "setup: the hub learns the old process's subscription"
        );
        drop(old);
        assert!(
            drive(&mut [&mut hub], SETUP, |s| {
                connections(s[0].behaviour(), &id) == 0
            })
            .await,
            "setup: the hub drops the old connection"
        );
        if let Err(lost) = relearned(&mut hub, hub_addr, key, Link::Tcp).await {
            panic!("{lost}");
        }
    }

    /// Runs `key`'s QUIC process, connected to the hub, on its own runtime.
    /// Shutting that runtime down kills it as SIGKILL does: no packet leaves,
    /// so the hub keeps the connection until its idle timeout.
    fn killable(key: Keypair, hub_addr: Multiaddr) -> tokio::runtime::Runtime {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        rt.spawn(async move {
            let mut old = swarm(key, Link::Quic);
            old.dial(hub_addr).expect("old dial");
            loop {
                old.select_next_some().await;
            }
        });
        rt
    }

    /// QUIC with Ed448 identities, as a worker's: kill without a close, then
    /// restart after `delay`, when the hub should hold `held` connections to
    /// the peer id.
    async fn quic_kill_and_restart(delay: Duration, held: usize) {
        let key = Keypair::generate_ed448();
        let id = key.public().to_peer_id();
        let mut hub = swarm(Keypair::generate_ed448(), Link::Quic);
        let hub_addr = listen(&mut hub, Link::Quic).await;
        let old = killable(key.clone(), hub_addr.clone());
        let up = drive(&mut [&mut hub], SETUP, |s| {
            s[0].behaviour().peer_subscribed_to(&id, &TOPIC)
        })
        .await;
        // Let the hub's own subscription reach the old process.
        drive(&mut [&mut hub], Duration::from_secs(2), |_| false).await;
        old.shutdown_background();
        assert!(up, "setup: the hub learns the old process's subscription");
        drive(&mut [&mut hub], delay, |_| false).await;
        assert_eq!(
            connections(hub.behaviour(), &id),
            held,
            "setup: connections the hub holds to the killed process's peer id {delay:?} after \
             the kill"
        );
        if let Err(lost) = relearned(&mut hub, hub_addr, key, Link::Quic).await {
            panic!("{lost}");
        }
    }

    /// QUIC, restart 1 s after the kill (the devnet's took 5 s): the hub
    /// still holds the dead connection.
    #[tokio::test]
    async fn quic_restart_within_the_idle_timeout_relearns_peer_subscriptions() {
        quic_kill_and_restart(Duration::from_secs(1), 1).await;
    }

    /// Control, QUIC: restart 15 s after the kill, past the 10 s idle timeout.
    #[tokio::test]
    async fn quic_restart_past_the_idle_timeout_relearns_peer_subscriptions() {
        quic_kill_and_restart(Duration::from_secs(15), 0).await;
    }
}
