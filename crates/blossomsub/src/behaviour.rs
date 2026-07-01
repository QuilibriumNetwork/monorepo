// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    cmp::{max, Ordering},
    collections::HashSet,
    collections::VecDeque,
    collections::{BTreeSet, HashMap},
    fmt,
    net::IpAddr,
    task::{Context, Poll},
    time::Duration,
};

use futures::StreamExt;
use futures_ticker::Ticker;
use prometheus_client::registry::Registry;
use rand::{seq::SliceRandom, thread_rng};

use libp2p_core::{
    multiaddr::Protocol::Ip4, multiaddr::Protocol::Ip6, transport::PortUse, Endpoint, Multiaddr,
};
use libp2p_identity::Keypair;
use libp2p_identity::PeerId;
use libp2p_swarm::{
    behaviour::{AddressChange, ConnectionClosed, ConnectionEstablished, FromSwarm},
    dial_opts::DialOpts,
    ConnectionDenied, ConnectionId, NetworkBehaviour, NotifyHandler, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use web_time::{Instant, SystemTime};

use crate::backoff::BackoffStorage;
use crate::composite::{self, CompositeMeshEntry, PeerClass};
use crate::config::{Config, ValidationMode};
use crate::gossip_promises::GossipPromises;
use crate::handler::{Handler, HandlerEvent, HandlerIn};
use crate::mcache::MessageCache;
use crate::metrics::{Churn, Config as MetricsConfig, Inclusion, Metrics, Penalty};
use crate::peer_score::{PeerScore, PeerScoreParams, PeerScoreThresholds, RejectReason};
use crate::protocol::SIGNING_PREFIX;
use crate::subscription_filter::{AllowAllSubscriptionFilter, TopicSubscriptionFilter};
use crate::time_cache::DuplicateCache;
use crate::topic::{Hasher, Topic, TopicHash};
use crate::transform::{DataTransform, IdentityTransform};
use crate::types::{
    ControlAction, Message, MessageAcceptance, MessageId, PeerInfo, RawMessage, Subscription,
    SubscriptionAction,
};
use crate::types::{PeerConnections, PeerKind, RpcOut};
use crate::{pb, TopicScoreParams};
use crate::{PublishError, SubscriptionError, ValidationError};
use prost::Message as _;
use std::{cmp::Ordering::Equal, fmt::Debug};

/// Hard cap (seconds) on a PRUNE-supplied backoff before it is turned into a
/// `Duration` and added to `Instant::now()`. Peer-supplied and thus
/// attacker-controlled; an uncapped value overflows `Instant + Duration`
/// (which panics → remote DoS). 2 hours is far above any legitimate backoff
/// (`prune_backoff` is seconds) while staying nowhere near overflow.
const MAX_PEER_BACKOFF_SECS: u64 = 2 * 60 * 60;

// Upstream's 5000-line async-std integration suite is quarantined during the
// BlossomSub fork — it's replaced in Stage 7 by the deterministic
// `test_harness` port. The file is kept (behaviour/tests.rs) as a reference.
#[cfg(all(test, feature = "upstream-tests"))]
mod tests;

/// Determines if published messages should be signed or not.
///
/// Without signing, a number of privacy preserving modes can be selected.
///
/// NOTE: The default validation settings are to require signatures. The [`ValidationMode`]
/// should be updated in the [`Config`] to allow for unsigned messages.
#[derive(Clone)]
pub enum MessageAuthenticity {
    /// Message signing is enabled. The author will be the owner of the key and the sequence number
    /// will be linearly increasing.
    Signed(Keypair),
    /// Message signing is disabled.
    ///
    /// The specified [`PeerId`] will be used as the author of all published messages. The sequence
    /// number will be randomized.
    Author(PeerId),
    /// Message signing is disabled.
    ///
    /// A random [`PeerId`] will be used when publishing each message. The sequence number will be
    /// randomized.
    RandomAuthor,
    /// Message signing is disabled.
    ///
    /// The author of the message and the sequence numbers are excluded from the message.
    ///
    /// NOTE: Excluding these fields may make these messages invalid by other nodes who
    /// enforce validation of these fields. See [`ValidationMode`] in the [`Config`]
    /// for how to customise this for rust-libp2p gossipsub.  A custom `message_id`
    /// function will need to be set to prevent all messages from a peer being filtered
    /// as duplicates.
    Anonymous,
}

impl MessageAuthenticity {
    /// Returns true if signing is enabled.
    pub fn is_signing(&self) -> bool {
        matches!(self, MessageAuthenticity::Signed(_))
    }

    pub fn is_anonymous(&self) -> bool {
        matches!(self, MessageAuthenticity::Anonymous)
    }
}

/// Event that can be emitted by the gossipsub behaviour.
#[derive(Debug)]
pub enum Event {
    /// A message has been received.
    Message {
        /// The peer that forwarded us this message.
        propagation_source: PeerId,
        /// The [`MessageId`] of the message. This should be referenced by the application when
        /// validating a message (if required).
        message_id: MessageId,
        /// The decompressed message itself.
        message: Message,
    },
    /// A remote subscribed to a topic.
    Subscribed {
        /// Remote that has subscribed.
        peer_id: PeerId,
        /// The topic it has subscribed to.
        topic: TopicHash,
    },
    /// A remote unsubscribed from a topic.
    Unsubscribed {
        /// Remote that has unsubscribed.
        peer_id: PeerId,
        /// The topic it has subscribed from.
        topic: TopicHash,
    },
    /// A peer that does not support gossipsub has connected.
    GossipsubNotSupported { peer_id: PeerId },
}

/// Result of a per-bitmask message validator registered via
/// [`Behaviour::register_validator`]. Runs on the receive path BEFORE a
/// message is delivered to the application or forwarded to mesh peers,
/// mirroring the Quilibrium reference `BlossomSubBehaviour`'s validation
/// semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// Message is valid — accept, deliver, and forward.
    Accept,
    /// Message is invalid — reject, penalise the sender, and drop.
    Reject,
    /// Message should be silently ignored (neither delivered/forwarded nor penalised).
    Ignore,
}

/// A data structure for storing configuration for publishing messages. See [`MessageAuthenticity`]
/// for further details.
#[allow(clippy::large_enum_variant)]
enum PublishConfig {
    Signing {
        keypair: Keypair,
        author: PeerId,
        inline_key: Option<Vec<u8>>,
        last_seq_no: SequenceNumber,
    },
    Author(PeerId),
    RandomAuthor,
    Anonymous,
}

/// A strictly linearly increasing sequence number.
///
/// We start from the current time as unix timestamp in milliseconds.
#[derive(Debug)]
struct SequenceNumber(u64);

impl SequenceNumber {
    fn new() -> Self {
        let unix_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time to be linear")
            .as_nanos();

        Self(unix_timestamp as u64)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .checked_add(1)
            .expect("to not exhaust u64 space for sequence numbers");

        self.0
    }
}

impl PublishConfig {
    pub(crate) fn get_own_id(&self) -> Option<&PeerId> {
        match self {
            Self::Signing { author, .. } => Some(author),
            Self::Author(author) => Some(author),
            _ => None,
        }
    }
}

impl From<MessageAuthenticity> for PublishConfig {
    fn from(authenticity: MessageAuthenticity) -> Self {
        match authenticity {
            MessageAuthenticity::Signed(keypair) => {
                let public_key = keypair.public();
                let key_enc = public_key.encode_protobuf();
                let key = if key_enc.len() <= 42 {
                    // The public key can be inlined in [`pb::Message::from`], so we don't include it
                    // specifically in the [`pb::Message::key`] field.
                    None
                } else {
                    // Include the protobuf encoding of the public key in the message.
                    Some(key_enc)
                };

                PublishConfig::Signing {
                    keypair,
                    author: public_key.to_peer_id(),
                    inline_key: key,
                    last_seq_no: SequenceNumber::new(),
                }
            }
            MessageAuthenticity::Author(peer_id) => PublishConfig::Author(peer_id),
            MessageAuthenticity::RandomAuthor => PublishConfig::RandomAuthor,
            MessageAuthenticity::Anonymous => PublishConfig::Anonymous,
        }
    }
}

/// Network behaviour that handles the gossipsub protocol.
///
/// NOTE: Initialisation requires a [`MessageAuthenticity`] and [`Config`] instance. If
/// message signing is disabled, the [`ValidationMode`] in the config should be adjusted to an
/// appropriate level to accept unsigned messages.
///
/// The DataTransform trait allows applications to optionally add extra encoding/decoding
/// functionality to the underlying messages. This is intended for custom compression algorithms.
///
/// The TopicSubscriptionFilter allows applications to implement specific filters on topics to
/// prevent unwanted messages being propagated and evaluated.
pub struct Behaviour<D = IdentityTransform, F = AllowAllSubscriptionFilter> {
    /// Configuration providing gossipsub performance parameters.
    config: Config,

    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<ToSwarm<Event, HandlerIn>>,

    /// Pools non-urgent control messages between heartbeats.
    control_pool: HashMap<PeerId, Vec<ControlAction>>,

    /// Information used for publishing messages.
    publish_config: PublishConfig,

    /// An LRU Time cache for storing seen messages (based on their ID). This cache prevents
    /// duplicates from being propagated to the application and on the network.
    duplicate_cache: DuplicateCache<MessageId>,

    /// A set of connected peers, indexed by their [`PeerId`] tracking both the [`PeerKind`] and
    /// the set of [`ConnectionId`]s.
    connected_peers: HashMap<PeerId, PeerConnections>,

    /// A map of all connected peers - A map of topic hash to a list of gossipsub peer Ids.
    topic_peers: HashMap<TopicHash, BTreeSet<PeerId>>,

    /// A map of all connected peers to their subscribed topics.
    peer_topics: HashMap<PeerId, BTreeSet<TopicHash>>,

    /// A set of all explicit peers. These are peers that remain connected and we unconditionally
    /// forward messages to, outside of the scoring system.
    explicit_peers: HashSet<PeerId>,

    /// A list of peers that have been blacklisted by the user.
    /// Messages are not sent to and are rejected from these peers.
    blacklisted_peers: HashSet<PeerId>,

    /// The set of WHOLE bitmasks we subscribe to. For a simple (single-slice)
    /// bitmask this coincides with a `mesh` key; for a composite (multi-slice)
    /// bitmask the whole key lives ONLY here and in `composites` — the `mesh`
    /// is keyed by the composite's slices. Used as the authoritative "am I
    /// subscribed / should I deliver this message" check.
    subscriptions: HashSet<TopicHash>,

    /// Overlay network of connected peers - Maps SLICE topics to connected
    /// gossipsub peers. For a single-slice (simple) bitmask the slice equals
    /// the whole bitmask, so this behaves exactly like upstream gossipsub. For
    /// a multi-slice (composite) bitmask, keys are the per-bit slices and their
    /// membership is derived from `composites` via `rebuild_slice_meshes`.
    mesh: HashMap<TopicHash, BTreeSet<PeerId>>,

    /// Composite meshes for multi-bit bitmask subscriptions, keyed by the WHOLE
    /// bitmask. Maintains `D` total same+broker peers (see `composite.rs`).
    composites: HashMap<TopicHash, CompositeMeshEntry>,

    /// Reverse index: slice topic -> the composite whole-bitmask keys that own
    /// (and populate) that slice mesh.
    slice_to_composite: HashMap<TopicHash, Vec<TopicHash>>,

    /// Map of topics to list of peers that we publish to, but don't subscribe to.
    fanout: HashMap<TopicHash, BTreeSet<PeerId>>,

    /// The last publish time for fanout topics.
    fanout_last_pub: HashMap<TopicHash, Instant>,

    ///Storage for backoffs
    backoffs: BackoffStorage,

    /// Message cache for the last few heartbeats.
    mcache: MessageCache,

    /// Heartbeat interval stream.
    heartbeat: Ticker,

    /// Number of heartbeats since the beginning of time; this allows us to amortize some resource
    /// clean up -- eg backoff clean up.
    heartbeat_ticks: u64,

    /// We remember all peers we found through peer exchange, since those peers are not considered
    /// as safe as randomly discovered outbound peers. This behaviour diverges from the go
    /// implementation to avoid possible love bombing attacks in PX. When disconnecting peers will
    /// be removed from this list which may result in a true outbound rediscovery.
    px_peers: HashSet<PeerId>,

    /// Set of connected outbound peers (we only consider true outbound peers found through
    /// discovery and not by PX).
    outbound_peers: HashSet<PeerId>,

    /// Stores optional peer score data together with thresholds, decay interval and gossip
    /// promises.
    peer_score: Option<(PeerScore, PeerScoreThresholds, Ticker, GossipPromises)>,

    /// Counts the number of `IHAVE` received from each peer since the last heartbeat.
    count_received_ihave: HashMap<PeerId, usize>,

    /// Counts the number of `IWANT` that we sent the each peer since the last heartbeat.
    count_sent_iwant: HashMap<PeerId, usize>,

    /// Keeps track of IWANT messages that we are awaiting to send.
    /// This is used to prevent sending duplicate IWANT messages for the same message.
    pending_iwant_msgs: HashSet<MessageId>,

    /// Short term cache for published message ids. This is used for penalizing peers sending
    /// our own messages back if the messages are anonymous or use a random author.
    published_message_ids: DuplicateCache<MessageId>,

    /// Per-peer set of message ids a peer has told us (via IDONTWANT) it already
    /// has, so we should NOT forward those messages to it. A short-lived TTL
    /// cache (gossipsub-1.2 semantics) bounds memory against id enumeration.
    peer_idontwant: HashMap<PeerId, DuplicateCache<MessageId>>,

    /// The filter used to handle message subscriptions.
    subscription_filter: F,

    /// A general transformation function that can be applied to data received from the wire before
    /// calculating the message-id and sending to the application. This is designed to allow the
    /// user to implement arbitrary topic-based compression algorithms.
    data_transform: D,

    /// Keep track of a set of internal metrics relating to gossipsub.
    metrics: Option<Metrics>,

    /// Per-bitmask application message validators. Consulted on the receive
    /// path (see [`Behaviour::handle_received_message`]) before delivery or
    /// forwarding. A [`ValidationResult::Reject`] penalises the sender and
    /// drops the message; [`ValidationResult::Ignore`] drops it silently;
    /// [`ValidationResult::Accept`] (or no registered validator) proceeds
    /// normally. Ported from the Quilibrium reference `BlossomSubBehaviour`.
    #[allow(clippy::type_complexity)]
    validators: HashMap<TopicHash, Box<dyn Fn(&PeerId, &[u8]) -> ValidationResult + Send + Sync>>,

    /// Optional per-(source, target) forward filter. When set, a message
    /// relayed from propagation source `source` is forwarded to a mesh peer
    /// `target` only if `forward_filter(source, target)` returns true. Default
    /// is `None` (all forwards allowed). Used by the devnet test proxy to
    /// impose bipartite network partitions; equivalent to go-libp2p
    /// blossomsub's `WithForwardFilter`.
    #[allow(clippy::type_complexity)]
    forward_filter: Option<Box<dyn Fn(&PeerId, &PeerId) -> bool + Send + Sync>>,
}

/// Builds the DEFAULT peer-scoring configuration installed on every
/// `Behaviour` (see [`Behaviour::new_with_subscription_filter_and_transform`]).
///
/// Scoring is LIVE by default in BlossomSub (upstream gossipsub leaves it
/// opt-in via `with_peer_score`). The parameter VALUES below are ported by
/// meaning from the Quilibrium reference scorer in `quil-p2p/src/scoring.rs`
/// (`BitmaskScoreParams::default`, `PeerScoreParams::default`,
/// `ScoreThresholds::default`). Because topics are BITMASKS (64 shards + per-bit
/// slices) they cannot be enumerated, so a single `default_topic_params` is
/// applied to every bitmask topic rather than per-topic entries.
///
/// The thresholds are tuned so a FRESH peer at score `0.0` passes the
/// gossip / publish / graylist gates (all negative) and is simply not yet
/// eligible for PX-acceptance or opportunistic grafting (both positive) —
/// which is the correct behaviour for an unproven peer.
pub(crate) fn default_peer_score_params_and_thresholds() -> (PeerScoreParams, PeerScoreThresholds) {
    // Ported from `quil-p2p` `BitmaskScoreParams::default()`.
    let default_topic_params = TopicScoreParams {
        // bitmask_weight = 1.0
        topic_weight: 1.0,
        // P1 time-in-mesh: small positive reward, quantum 1s, cap 3600.
        time_in_mesh_weight: 1.0 / 3600.0,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 3600.0,
        // P2 first-message deliveries.
        first_message_deliveries_weight: 1.0,
        first_message_deliveries_decay: 0.5,
        first_message_deliveries_cap: 2000.0,
        // P3 mesh-message deliveries + P3b sticky mesh-failure penalty.
        //
        // CRITICAL: these two weights MUST be 0 in the UNIVERSAL fallback.
        // P3/P3b penalize a peer whose in-mesh delivery RATE falls below
        // `mesh_message_deliveries_threshold` after the activation window. That
        // is only meaningful on a topic with a GUARANTEED steady message rate.
        // Quilibrium has 64 shards, many of them quiet/low-traffic; applying a
        // negative P3/P3b weight to every bitmask would penalize an honest
        // in-mesh peer on any quiet shard by `weight * deficit^2` (e.g.
        // -1.0 * 20^2 = -400) with no topic-score cap, driving honest peers
        // negative -> mesh-evicted (score < 0) on every shard and past the
        // graylist across a handful of quiet shards -> symmetric mesh collapse.
        // The reference quil-p2p scorer never drives P3 in production either
        // (graft/add_delivery/prune are test-only), so P3 was effectively off.
        // Keep the threshold/cap/activation/decay values (harmless at weight 0);
        // enable P3 per-topic via `set_topic_params` on a known-busy bitmask if
        // ever needed.
        mesh_message_deliveries_weight: 0.0,
        mesh_message_deliveries_decay: 0.5,
        mesh_message_deliveries_cap: 100.0,
        mesh_message_deliveries_threshold: 20.0,
        // Not modelled by the quil-p2p scorer; gossipsub-canonical small window.
        mesh_message_deliveries_window: Duration::from_millis(10),
        mesh_message_deliveries_activation: Duration::from_secs(5),
        mesh_failure_penalty_weight: 0.0,
        mesh_failure_penalty_decay: 0.5,
        // P4 invalid-message deliveries.
        invalid_message_deliveries_weight: -1.0,
        invalid_message_deliveries_decay: 0.9,
    };

    // Ported from `quil-p2p` `PeerScoreParams::default()`.
    let params = PeerScoreParams {
        topics: HashMap::new(),
        default_topic_params: Some(default_topic_params),
        // bitmask_score_cap = 0.0 (no cap).
        topic_score_cap: 0.0,
        // The quil-p2p scorer folds the operator application score in raw
        // (implicit weight 1.0); P5 = application_score * app_specific_weight.
        app_specific_weight: 1.0,
        // P6 IP-colocation.
        ip_colocation_factor_weight: -10.0,
        ip_colocation_factor_threshold: 3.0,
        ip_colocation_factor_whitelist: HashSet::new(),
        // P7 behaviour penalty.
        behaviour_penalty_weight: -10.0,
        behaviour_penalty_threshold: 0.0,
        behaviour_penalty_decay: 0.9,
        decay_interval: Duration::from_secs(1),
        decay_to_zero: 0.01,
        retain_score: Duration::from_secs(3600),
    };

    // Ported from `quil-p2p` `ScoreThresholds::default()`.
    let thresholds = PeerScoreThresholds {
        gossip_threshold: -500.0,
        publish_threshold: -1000.0,
        graylist_threshold: -2500.0,
        accept_px_threshold: 1000.0,
        opportunistic_graft_threshold: 3.5,
    };

    debug_assert!(params.validate().is_ok(), "default score params must validate");
    debug_assert!(
        thresholds.validate().is_ok(),
        "default score thresholds must validate"
    );

    (params, thresholds)
}

impl<D, F> Behaviour<D, F>
where
    D: DataTransform + Default,
    F: TopicSubscriptionFilter + Default,
{
    /// Creates a Gossipsub [`Behaviour`] struct given a set of parameters specified via a
    /// [`Config`]. This has no subscription filter and uses no compression.
    pub fn new(privacy: MessageAuthenticity, config: Config) -> Result<Self, &'static str> {
        Self::new_with_subscription_filter_and_transform(
            privacy,
            config,
            None,
            F::default(),
            D::default(),
        )
    }

    /// Creates a Gossipsub [`Behaviour`] struct given a set of parameters specified via a
    /// [`Config`]. This has no subscription filter and uses no compression.
    /// Metrics can be evaluated by passing a reference to a [`Registry`].
    pub fn new_with_metrics(
        privacy: MessageAuthenticity,
        config: Config,
        metrics_registry: &mut Registry,
        metrics_config: MetricsConfig,
    ) -> Result<Self, &'static str> {
        Self::new_with_subscription_filter_and_transform(
            privacy,
            config,
            Some((metrics_registry, metrics_config)),
            F::default(),
            D::default(),
        )
    }
}

impl<D, F> Behaviour<D, F>
where
    D: DataTransform + Default,
    F: TopicSubscriptionFilter,
{
    /// Creates a Gossipsub [`Behaviour`] struct given a set of parameters specified via a
    /// [`Config`] and a custom subscription filter.
    pub fn new_with_subscription_filter(
        privacy: MessageAuthenticity,
        config: Config,
        metrics: Option<(&mut Registry, MetricsConfig)>,
        subscription_filter: F,
    ) -> Result<Self, &'static str> {
        Self::new_with_subscription_filter_and_transform(
            privacy,
            config,
            metrics,
            subscription_filter,
            D::default(),
        )
    }
}

impl<D, F> Behaviour<D, F>
where
    D: DataTransform,
    F: TopicSubscriptionFilter + Default,
{
    /// Creates a Gossipsub [`Behaviour`] struct given a set of parameters specified via a
    /// [`Config`] and a custom data transform.
    pub fn new_with_transform(
        privacy: MessageAuthenticity,
        config: Config,
        metrics: Option<(&mut Registry, MetricsConfig)>,
        data_transform: D,
    ) -> Result<Self, &'static str> {
        Self::new_with_subscription_filter_and_transform(
            privacy,
            config,
            metrics,
            F::default(),
            data_transform,
        )
    }
}

impl<D, F> Behaviour<D, F>
where
    D: DataTransform,
    F: TopicSubscriptionFilter,
{
    /// Creates a Gossipsub [`Behaviour`] struct given a set of parameters specified via a
    /// [`Config`] and a custom subscription filter and data transform.
    pub fn new_with_subscription_filter_and_transform(
        privacy: MessageAuthenticity,
        config: Config,
        metrics: Option<(&mut Registry, MetricsConfig)>,
        subscription_filter: F,
        data_transform: D,
    ) -> Result<Self, &'static str> {
        // Set up the router given the configuration settings.

        // We do not allow configurations where a published message would also be rejected if it
        // were received locally.
        validate_config(&privacy, config.validation_mode())?;

        // Scoring is LIVE by default (see `default_peer_score_params_and_thresholds`).
        // Callers may still override via `with_peer_score()`, which replaces this.
        let (score_params, score_thresholds) = default_peer_score_params_and_thresholds();
        let score_interval = Ticker::new(score_params.decay_interval);
        let peer_score = Some((
            PeerScore::new(score_params),
            score_thresholds,
            score_interval,
            GossipPromises::default(),
        ));

        Ok(Behaviour {
            metrics: metrics.map(|(registry, cfg)| Metrics::new(registry, cfg)),
            events: VecDeque::new(),
            control_pool: HashMap::new(),
            publish_config: privacy.into(),
            duplicate_cache: DuplicateCache::new(config.duplicate_cache_time()),
            topic_peers: HashMap::new(),
            peer_topics: HashMap::new(),
            explicit_peers: HashSet::new(),
            blacklisted_peers: HashSet::new(),
            subscriptions: HashSet::new(),
            mesh: HashMap::new(),
            composites: HashMap::new(),
            slice_to_composite: HashMap::new(),
            fanout: HashMap::new(),
            fanout_last_pub: HashMap::new(),
            backoffs: BackoffStorage::new(
                &config.prune_backoff(),
                config.heartbeat_interval(),
                config.backoff_slack(),
            ),
            mcache: MessageCache::new(
                config.history_gossip(),
                config.history_length(),
                config.mcache_max_bytes(),
            ),
            heartbeat: Ticker::new_with_next(
                config.heartbeat_interval(),
                config.heartbeat_initial_delay(),
            ),
            heartbeat_ticks: 0,
            px_peers: HashSet::new(),
            outbound_peers: HashSet::new(),
            peer_score,
            count_received_ihave: HashMap::new(),
            count_sent_iwant: HashMap::new(),
            pending_iwant_msgs: HashSet::new(),
            connected_peers: HashMap::new(),
            published_message_ids: DuplicateCache::new(config.published_message_ids_cache_time()),
            peer_idontwant: HashMap::new(),
            config,
            subscription_filter,
            data_transform,
            validators: HashMap::new(),
            forward_filter: None,
        })
    }
}

impl<D, F> Behaviour<D, F>
where
    D: DataTransform + Send + 'static,
    F: TopicSubscriptionFilter + Send + 'static,
{
    /// Lists the hashes of the topics we are currently subscribed to.
    pub fn topics(&self) -> impl Iterator<Item = &TopicHash> {
        self.mesh.keys()
    }

    /// Lists all mesh peers for a certain topic hash.
    pub fn mesh_peers(&self, topic_hash: &TopicHash) -> impl Iterator<Item = &PeerId> {
        self.mesh.get(topic_hash).into_iter().flat_map(|x| x.iter())
    }

    /// Mesh-size metric for a WHOLE subscription bitmask, correct for both
    /// SIMPLE and COMPOSITE topics.
    ///
    /// A COMPOSITE (multi-slice) subscription's whole bitmask never lands in
    /// `self.mesh` (that is keyed by slices — see `handle_received_message`), so
    /// `mesh_peers(whole).count()` returns 0 even when the composite mesh is
    /// fully healthy. Its mesh is the composite entry's same + broker peers, so
    /// return `total_peers()` for those. For a SIMPLE (single-slice) bitmask the
    /// whole key IS a mesh key, so return `mesh[whole].len()` as usual.
    ///
    /// Callers gauging mesh health (NeedPeers thresholds, health logging) must
    /// use this rather than `mesh_peers` so composite subscriptions are not
    /// perpetually seen as empty.
    pub fn mesh_peers_for_subscription(&self, bitmask: &TopicHash) -> usize {
        if let Some(comp) = self.composites.get(bitmask) {
            comp.total_peers()
        } else {
            self.mesh.get(bitmask).map_or(0, |s| s.len())
        }
    }

    pub fn all_mesh_peers(&self) -> impl Iterator<Item = &PeerId> {
        let mut res = BTreeSet::new();
        for peers in self.mesh.values() {
            res.extend(peers);
        }
        res.into_iter()
    }

    /// Lists all known peers and their associated subscribed topics.
    pub fn all_peers(&self) -> impl Iterator<Item = (&PeerId, Vec<&TopicHash>)> {
        self.peer_topics
            .iter()
            .map(|(peer_id, topic_set)| (peer_id, topic_set.iter().collect()))
    }

    /// Lists all known peers and their associated protocol.
    pub fn peer_protocol(&self) -> impl Iterator<Item = (&PeerId, &PeerKind)> {
        self.connected_peers.iter().map(|(k, v)| (k, &v.kind))
    }

    /// Returns the gossipsub score for a given peer, if one exists.
    pub fn peer_score(&self, peer_id: &PeerId) -> Option<f64> {
        self.peer_score
            .as_ref()
            .map(|(score, ..)| score.score(peer_id))
    }

    /// Subscribe to a topic.
    ///
    /// Returns [`Ok(true)`] if the subscription worked. Returns [`Ok(false)`] if we were already
    /// subscribed.
    pub fn subscribe<H: Hasher>(&mut self, topic: &Topic<H>) -> Result<bool, SubscriptionError> {
        tracing::debug!(%topic, "Subscribing to topic");
        let topic_hash = topic.hash();
        if !self.subscription_filter.can_subscribe(&topic_hash) {
            return Err(SubscriptionError::NotAllowed);
        }

        if self.subscriptions.contains(&topic_hash) {
            tracing::debug!(%topic, "Topic is already in the mesh");
            return Ok(false);
        }
        self.subscriptions.insert(topic_hash.clone());

        // send subscription request to all peers
        for peer in self.peer_topics.keys().copied().collect::<Vec<_>>() {
            tracing::debug!(%peer, "Sending SUBSCRIBE to peer");
            let event = RpcOut::Subscribe(topic_hash.clone());
            self.send_message(peer, event);
        }

        // call JOIN(topic)
        // this will add new peers to the mesh for the topic
        self.join(&topic_hash);
        tracing::debug!(%topic, "Subscribed to topic");
        Ok(true)
    }

    /// Unsubscribes from a topic.
    ///
    /// Returns [`Ok(true)`] if we were subscribed to this topic.
    #[allow(clippy::unnecessary_wraps)]
    pub fn unsubscribe<H: Hasher>(&mut self, topic: &Topic<H>) -> Result<bool, PublishError> {
        tracing::debug!(%topic, "Unsubscribing from topic");
        let topic_hash = topic.hash();

        if !self.subscriptions.remove(&topic_hash) {
            tracing::debug!(topic=%topic_hash, "Already unsubscribed from topic");
            // we are not subscribed
            return Ok(false);
        }

        // announce to all peers
        for peer in self.peer_topics.keys().copied().collect::<Vec<_>>() {
            tracing::debug!(%peer, "Sending UNSUBSCRIBE to peer");
            let event = RpcOut::Unsubscribe(topic_hash.clone());
            self.send_message(peer, event);
        }

        // call LEAVE(topic)
        // this will remove the topic from the mesh
        self.leave(&topic_hash);

        tracing::debug!(topic=%topic_hash, "Unsubscribed from topic");
        Ok(true)
    }

    /// Publishes a message with multiple topics to the network.
    pub fn publish(
        &mut self,
        topic: impl Into<TopicHash>,
        data: impl Into<Vec<u8>>,
    ) -> Result<MessageId, PublishError> {
        let data = data.into();
        let topic = topic.into();

        // Transform the data before building a raw_message.
        let transformed_data = self
            .data_transform
            .outbound_transform(&topic, data.clone())?;

        let raw_message = self.build_raw_message(topic, transformed_data)?;

        // calculate the message id from the un-transformed data
        let msg_id = self.config.message_id(&Message {
            source: raw_message.source,
            data, // the uncompressed form
            sequence_number: raw_message.sequence_number,
            topic: raw_message.topic.clone(),
        });

        // check that the size doesn't exceed the max transmission size
        if raw_message.raw_protobuf_len() > self.config.max_transmit_size() {
            return Err(PublishError::MessageTooLarge);
        }

        // Check the if the message has been published before
        if self.duplicate_cache.contains(&msg_id) {
            // This message has already been seen. We don't re-publish messages that have already
            // been published on the network.
            tracing::debug!(
                message=%msg_id,
                "Not publishing a message that has already been published"
            );
            return Err(PublishError::Duplicate);
        }

        tracing::trace!(message=%msg_id, "Publishing message");

        let topic_hash = raw_message.topic.clone();

        let mut recipient_peers = HashSet::new();
        if self.config.flood_publish() {
            if composite::slice_bitmask(topic_hash.as_bytes()).len() > 1 {
                // COMPOSITE flood publish (F2). A broker / covering relay
                // advertised a SUPERSET bitmask (e.g. an archive on the all-ones
                // relay bitmask), so it is absent from `topic_peers[M]` (peers
                // who advertised EXACTLY M) and the exact-match flood path would
                // silently skip it. Target every peer whose advertised
                // subscription OVERLAPS M (covers at least one slice), then union
                // in `mesh_recipients` (mesh members are always included) and
                // fanout — so a composite flood never reaches fewer peers than
                // the mesh would.
                let slices = composite::topic_slices(&topic_hash);
                for (peer, subs) in &self.peer_topics {
                    let overlaps = slices.iter().any(|s| Self::peer_covers_slice(subs, s));
                    if overlaps
                        && (self.explicit_peers.contains(peer)
                            || !self.score_below_threshold(peer, |ts| ts.publish_threshold).0)
                    {
                        recipient_peers.insert(*peer);
                    }
                }
                recipient_peers.extend(self.mesh_recipients(&topic_hash));
                if let Some(fo) = self.fanout.get(&topic_hash) {
                    recipient_peers.extend(fo.iter().copied());
                }
            } else if let Some(set) = self.topic_peers.get(&topic_hash) {
                // Simple (single-slice) bitmask: exact-match flood is correct.
                recipient_peers.extend(set.iter().filter(|p| {
                    self.explicit_peers.contains(*p)
                        || !self.score_below_threshold(p, |ts| ts.publish_threshold).0
                }));
            }
        } else {
            // Composite-aware recipient resolution: for a simple bitmask this is
            // `mesh[topic]`; for a composite it unions the composite same/broker
            // peers and the per-slice meshes (covering relays), so app-shard
            // publishes reach their composite mesh instead of the void.
            let mesh_recipients = self.mesh_recipients(&raw_message.topic);
            if !mesh_recipients.is_empty() {
                recipient_peers.extend(mesh_recipients);
            } else {
                tracing::debug!(topic=%topic_hash, "Topic not in the mesh");
                // If we have fanout peers add them to the map.
                if self.fanout.contains_key(&topic_hash) {
                    for peer in self.fanout.get(&topic_hash).expect("Topic must exist") {
                        recipient_peers.insert(*peer);
                    }
                } else {
                    // We have no fanout peers, select mesh_n of them and add them to the fanout
                    let mesh_n = self.config.mesh_n();
                    let new_peers = get_random_peers(
                        &self.topic_peers,
                        &self.connected_peers,
                        &topic_hash,
                        mesh_n,
                        {
                            |p| {
                                !self.explicit_peers.contains(p)
                                    && !self
                                        .score_below_threshold(p, |pst| pst.publish_threshold)
                                        .0
                            }
                        },
                    );
                    // Add the new peers to the fanout and recipient peers
                    self.fanout.insert(topic_hash.clone(), new_peers.clone());
                    for peer in new_peers {
                        tracing::debug!(%peer, "Peer added to fanout");
                        recipient_peers.insert(peer);
                    }
                }
                // We are publishing to fanout peers - update the time we published
                self.fanout_last_pub
                    .insert(topic_hash.clone(), Instant::now());
            }

            // Explicit peers subscribed to the topic
            for peer in self.explicit_peers.clone() {
                if self
                    .peer_topics
                    .get(&peer)
                    .map_or(false, |t| t.contains(&topic_hash))
                {
                    recipient_peers.insert(peer);
                }
            }

            // Floodsub peers
            for (peer, connections) in &self.connected_peers {
                if connections.kind == PeerKind::Floodsub
                    && !self
                        .score_below_threshold(peer, |ts| ts.publish_threshold)
                        .0
                {
                    recipient_peers.insert(*peer);
                }
            }
        }

        if recipient_peers.is_empty() {
            return Err(PublishError::InsufficientPeers);
        }

        // If the message isn't a duplicate and we have sent it to some peers add it to the
        // duplicate cache and memcache.
        self.duplicate_cache.insert(msg_id.clone());
        self.mcache.put(&msg_id, raw_message.clone());

        // If the message is anonymous or has a random author add it to the published message ids
        // cache.
        if let PublishConfig::RandomAuthor | PublishConfig::Anonymous = self.publish_config {
            if !self.config.allow_self_origin() {
                self.published_message_ids.insert(msg_id.clone());
            }
        }

        // Send to peers we know are subscribed to the topic.
        for peer_id in recipient_peers.iter() {
            tracing::trace!(peer=%peer_id, "Sending message to peer");
            self.send_message(*peer_id, RpcOut::Publish(raw_message.clone()));
        }

        tracing::debug!(message=%msg_id, "Published message");

        if let Some(metrics) = self.metrics.as_mut() {
            metrics.register_published_message(&topic_hash);
        }

        Ok(msg_id)
    }

    /// This function should be called when [`Config::validate_messages()`] is `true` after
    /// the message got validated by the caller. Messages are stored in the ['Memcache'] and
    /// validation is expected to be fast enough that the messages should still exist in the cache.
    /// There are three possible validation outcomes and the outcome is given in acceptance.
    ///
    /// If acceptance = [`MessageAcceptance::Accept`] the message will get propagated to the
    /// network. The `propagation_source` parameter indicates who the message was received by and
    /// will not be forwarded back to that peer.
    ///
    /// If acceptance = [`MessageAcceptance::Reject`] the message will be deleted from the memcache
    /// and the P₄ penalty will be applied to the `propagation_source`.
    //
    /// If acceptance = [`MessageAcceptance::Ignore`] the message will be deleted from the memcache
    /// but no P₄ penalty will be applied.
    ///
    /// This function will return true if the message was found in the cache and false if was not
    /// in the cache anymore.
    ///
    /// This should only be called once per message.
    pub fn report_message_validation_result(
        &mut self,
        msg_id: &MessageId,
        propagation_source: &PeerId,
        acceptance: MessageAcceptance,
    ) -> Result<bool, PublishError> {
        let reject_reason = match acceptance {
            MessageAcceptance::Accept => {
                let (raw_message, originating_peers) = match self.mcache.validate(msg_id) {
                    Some((raw_message, originating_peers)) => {
                        (raw_message.clone(), originating_peers)
                    }
                    None => {
                        tracing::debug!(
                            message=%msg_id,
                            "Message not in cache. Ignoring forwarding"
                        );
                        if let Some(metrics) = self.metrics.as_mut() {
                            metrics.memcache_miss();
                        }
                        return Ok(false);
                    }
                };

                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.register_msg_validation(&raw_message.topic, &acceptance);
                }

                self.forward_msg(
                    msg_id,
                    raw_message,
                    Some(propagation_source),
                    originating_peers,
                )?;
                return Ok(true);
            }
            MessageAcceptance::Reject => RejectReason::ValidationFailed,
            MessageAcceptance::Ignore => RejectReason::ValidationIgnored,
        };

        if let Some((raw_message, originating_peers)) = self.mcache.remove(msg_id) {
            if let Some(metrics) = self.metrics.as_mut() {
                metrics.register_msg_validation(&raw_message.topic, &acceptance);
            }

            // Tell peer_score about reject
            // Reject the original source, and any duplicates we've seen from other peers.
            if let Some((peer_score, ..)) = &mut self.peer_score {
                peer_score.reject_message(
                    propagation_source,
                    msg_id,
                    &raw_message.topic,
                    reject_reason,
                );
                for peer in originating_peers.iter() {
                    peer_score.reject_message(peer, msg_id, &raw_message.topic, reject_reason);
                }
            }
            Ok(true)
        } else {
            tracing::debug!(message=%msg_id, "Rejected message not in cache");
            Ok(false)
        }
    }

    /// Registers a per-bitmask message validator. The validator runs on the
    /// receive path for every inbound message tagged with `topic`, BEFORE the
    /// message is delivered to the application or forwarded to mesh peers. Only
    /// one validator per bitmask; a second call replaces the previous one.
    ///
    /// Ported from the Quilibrium reference `BlossomSubBehaviour::register_validator`.
    pub fn register_validator(
        &mut self,
        topic: TopicHash,
        validator: impl Fn(&PeerId, &[u8]) -> ValidationResult + Send + Sync + 'static,
    ) {
        self.validators.insert(topic, Box::new(validator));
    }

    /// Installs a per-(source, target) forward filter consulted before relaying
    /// each message to a mesh peer. When the filter returns `false` for a
    /// `(source, target)` pair, that target is skipped (the message is still
    /// delivered to other mesh peers). Replaces any previously installed
    /// filter. With no filter installed (the default), all forwards are
    /// allowed — preserving the standard relay behaviour.
    pub fn set_forward_filter(
        &mut self,
        filter: impl Fn(&PeerId, &PeerId) -> bool + Send + Sync + 'static,
    ) {
        self.forward_filter = Some(Box::new(filter));
    }

    /// Same as [`Self::set_forward_filter`] but accepts an already-boxed
    /// filter. Used to install a filter delivered over a command channel
    /// (which must erase the closure's concrete type).
    #[allow(clippy::type_complexity)]
    pub fn set_forward_filter_boxed(
        &mut self,
        filter: Box<dyn Fn(&PeerId, &PeerId) -> bool + Send + Sync>,
    ) {
        self.forward_filter = Some(filter);
    }

    /// Removes any installed forward filter (all forwards allowed again).
    pub fn clear_forward_filter(&mut self) {
        self.forward_filter = None;
    }

    /// Late-binds the signing identity used for published messages. Upstream
    /// gossipsub fixes the [`MessageAuthenticity`] at construction; the
    /// Quilibrium node builds the behaviour before its pubsub signing key is
    /// known and installs it afterwards, so this rebuilds the internal publish
    /// configuration to sign with `keypair`. The message author (`from`) and
    /// inline-key handling are derived from the keypair's public key, matching
    /// [`MessageAuthenticity::Signed`].
    pub fn set_signing_identity(&mut self, keypair: Keypair) {
        self.publish_config = MessageAuthenticity::Signed(keypair).into();
    }

    /// (Re)sends our current subscription set to a single peer. Upstream
    /// gossipsub sends subscriptions to a peer only at connection-establishment
    /// time; the Quilibrium node resends once Identify confirms BlossomSub
    /// support on the connection. Ported from the reference
    /// `BlossomSubBehaviour::send_subscriptions_to_peer`.
    pub fn send_subscriptions_to_peer(&mut self, peer: PeerId) {
        if !self.connected_peers.contains_key(&peer) {
            return;
        }
        for topic_hash in self.subscriptions.clone() {
            self.send_message(peer, RpcOut::Subscribe(topic_hash));
        }
    }

    /// Adds a new peer to the list of explicitly connected peers.
    pub fn add_explicit_peer(&mut self, peer_id: &PeerId) {
        tracing::debug!(peer=%peer_id, "Adding explicit peer");

        self.explicit_peers.insert(*peer_id);

        self.check_explicit_peer_connection(peer_id);
    }

    /// This removes the peer from explicitly connected peers, note that this does not disconnect
    /// the peer.
    pub fn remove_explicit_peer(&mut self, peer_id: &PeerId) {
        tracing::debug!(peer=%peer_id, "Removing explicit peer");
        self.explicit_peers.remove(peer_id);
    }

    /// Blacklists a peer. All messages from this peer will be rejected and any message that was
    /// created by this peer will be rejected.
    pub fn blacklist_peer(&mut self, peer_id: &PeerId) {
        if self.blacklisted_peers.insert(*peer_id) {
            tracing::debug!(peer=%peer_id, "Peer has been blacklisted");
        }
    }

    /// Removes a peer from the blacklist if it has previously been blacklisted.
    pub fn remove_blacklisted_peer(&mut self, peer_id: &PeerId) {
        if self.blacklisted_peers.remove(peer_id) {
            tracing::debug!(peer=%peer_id, "Peer has been removed from the blacklist");
        }
    }

    /// Activates the peer scoring system with the given parameters. This will reset all scores
    /// if there was already another peer scoring system activated. Returns an error if the
    /// params are not valid or if they got already set.
    pub fn with_peer_score(
        &mut self,
        params: PeerScoreParams,
        threshold: PeerScoreThresholds,
    ) -> Result<(), String> {
        self.with_peer_score_and_message_delivery_time_callback(params, threshold, None)
    }

    /// Activates the peer scoring system with the given parameters and a message delivery time
    /// callback. Returns an error if the parameters got already set.
    pub fn with_peer_score_and_message_delivery_time_callback(
        &mut self,
        params: PeerScoreParams,
        threshold: PeerScoreThresholds,
        callback: Option<fn(&PeerId, &TopicHash, f64)>,
    ) -> Result<(), String> {
        params.validate()?;
        threshold.validate()?;

        // NOTE: unlike upstream gossipsub, BlossomSub installs a default scoring
        // system at construction, so `peer_score` is normally already `Some`.
        // `with_peer_score` therefore REPLACES the default (resetting scores)
        // rather than erroring on a second set — this keeps the opt-in override
        // path working now that scoring is live by default.
        let interval = Ticker::new(params.decay_interval);
        let peer_score = PeerScore::new_with_message_delivery_time_callback(params, callback);
        self.peer_score = Some((peer_score, threshold, interval, GossipPromises::default()));
        Ok(())
    }

    /// Sets scoring parameters for a topic.
    ///
    /// The [`Self::with_peer_score()`] must first be called to initialise peer scoring.
    pub fn set_topic_params<H: Hasher>(
        &mut self,
        topic: Topic<H>,
        params: TopicScoreParams,
    ) -> Result<(), &'static str> {
        if let Some((peer_score, ..)) = &mut self.peer_score {
            peer_score.set_topic_params(topic.hash(), params);
            Ok(())
        } else {
            Err("Peer score must be initialised with `with_peer_score()`")
        }
    }

    /// Returns a scoring parameters for a topic if existent.
    pub fn get_topic_params<H: Hasher>(&self, topic: &Topic<H>) -> Option<&TopicScoreParams> {
        self.peer_score.as_ref()?.0.get_topic_params(&topic.hash())
    }

    /// Sets the application specific score for a peer. Returns true if scoring is active and
    /// the peer is connected or if the score of the peer is not yet expired, false otherwise.
    pub fn set_application_score(&mut self, peer_id: &PeerId, new_score: f64) -> bool {
        if let Some((peer_score, ..)) = &mut self.peer_score {
            peer_score.set_application_score(peer_id, new_score)
        } else {
            false
        }
    }

    /// Gossipsub JOIN(topic) - adds topic peers to mesh and sends them GRAFT messages.
    fn join(&mut self, topic_hash: &TopicHash) {
        tracing::debug!(topic=%topic_hash, "Running JOIN for topic");

        // if we are already in the mesh, return
        if self.mesh.contains_key(topic_hash) || self.composites.contains_key(topic_hash) {
            tracing::debug!(topic=%topic_hash, "JOIN: The topic is already in the mesh, ignoring JOIN");
            return;
        }

        // COMPOSITE path: a multi-slice (multi-bit) bitmask keeps its mesh in
        // `self.composites` (D total same+broker peers) and derives per-slice
        // meshes from it. GRAFT the selected composite members (gossipsub
        // GRAFTs the peers it adds to the mesh).
        if composite::slice_bitmask(topic_hash.as_bytes()).len() > 1 {
            if let Some(m) = self.metrics.as_mut() {
                m.joined(topic_hash)
            }
            self.join_composite(topic_hash);
            let members: Vec<PeerId> = self
                .composites
                .get(topic_hash)
                .map(|c| c.same.iter().chain(c.broker.iter()).copied().collect())
                .unwrap_or_default();
            for peer_id in members {
                tracing::debug!(peer=%peer_id, "JOIN: Sending Graft message to composite peer");
                if let Some((peer_score, ..)) = &mut self.peer_score {
                    peer_score.graft(&peer_id, topic_hash.clone());
                }
                Self::control_pool_add(
                    &mut self.control_pool,
                    peer_id,
                    ControlAction::Graft {
                        topic_hash: topic_hash.clone(),
                    },
                );
                peer_added_to_mesh(
                    peer_id,
                    vec![topic_hash],
                    &self.mesh,
                    self.peer_topics.get(&peer_id),
                    &mut self.events,
                    &self.connected_peers,
                );
            }
            tracing::debug!(topic=%topic_hash, "Completed composite JOIN for topic");
            return;
        }

        let mut added_peers = HashSet::new();

        if let Some(m) = self.metrics.as_mut() {
            m.joined(topic_hash)
        }

        // check if we have mesh_n peers in fanout[topic] and add them to the mesh if we do,
        // removing the fanout entry.
        if let Some((_, mut peers)) = self.fanout.remove_entry(topic_hash) {
            tracing::debug!(
                topic=%topic_hash,
                "JOIN: Removing peers from the fanout for topic"
            );

            // remove explicit peers, peers with negative scores, and backoffed peers
            peers.retain(|p| {
                !self.explicit_peers.contains(p)
                    && !self.score_below_threshold(p, |_| 0.0).0
                    && !self.backoffs.is_backoff_with_slack(topic_hash, p)
            });

            // Add up to mesh_n of them them to the mesh
            // NOTE: These aren't randomly added, currently FIFO
            let add_peers = std::cmp::min(peers.len(), self.config.mesh_n());
            tracing::debug!(
                topic=%topic_hash,
                "JOIN: Adding {:?} peers from the fanout for topic",
                add_peers
            );
            added_peers.extend(peers.iter().take(add_peers));

            self.mesh.insert(
                topic_hash.clone(),
                peers.into_iter().take(add_peers).collect(),
            );

            // remove the last published time
            self.fanout_last_pub.remove(topic_hash);
        }

        let fanaout_added = added_peers.len();
        if let Some(m) = self.metrics.as_mut() {
            m.peers_included(topic_hash, Inclusion::Fanout, fanaout_added)
        }

        // check if we need to get more peers, which we randomly select
        if added_peers.len() < self.config.mesh_n() {
            // get the peers
            let new_peers = get_random_peers(
                &self.topic_peers,
                &self.connected_peers,
                topic_hash,
                self.config.mesh_n() - added_peers.len(),
                |peer| {
                    !added_peers.contains(peer)
                        && !self.explicit_peers.contains(peer)
                        && !self.score_below_threshold(peer, |_| 0.0).0
                        && !self.backoffs.is_backoff_with_slack(topic_hash, peer)
                },
            );
            added_peers.extend(new_peers.clone());
            // add them to the mesh
            tracing::debug!(
                "JOIN: Inserting {:?} random peers into the mesh",
                new_peers.len()
            );
            let mesh_peers = self.mesh.entry(topic_hash.clone()).or_default();
            mesh_peers.extend(new_peers);
        }

        let random_added = added_peers.len() - fanaout_added;
        if let Some(m) = self.metrics.as_mut() {
            m.peers_included(topic_hash, Inclusion::Random, random_added)
        }

        for peer_id in added_peers {
            // Send a GRAFT control message
            tracing::debug!(peer=%peer_id, "JOIN: Sending Graft message to peer");
            if let Some((peer_score, ..)) = &mut self.peer_score {
                peer_score.graft(&peer_id, topic_hash.clone());
            }
            Self::control_pool_add(
                &mut self.control_pool,
                peer_id,
                ControlAction::Graft {
                    topic_hash: topic_hash.clone(),
                },
            );

            // If the peer did not previously exist in any mesh, inform the handler
            peer_added_to_mesh(
                peer_id,
                vec![topic_hash],
                &self.mesh,
                self.peer_topics.get(&peer_id),
                &mut self.events,
                &self.connected_peers,
            );
        }

        let mesh_peers = self.mesh_peers(topic_hash).count();
        if let Some(m) = self.metrics.as_mut() {
            m.set_mesh_peers(topic_hash, mesh_peers)
        }

        tracing::debug!(topic=%topic_hash, "Completed JOIN for topic");
    }

    /// Creates a PRUNE gossipsub action.
    fn make_prune(
        &mut self,
        topic_hash: &TopicHash,
        peer: &PeerId,
        do_px: bool,
        on_unsubscribe: bool,
    ) -> ControlAction {
        if let Some((peer_score, ..)) = &mut self.peer_score {
            peer_score.prune(peer, topic_hash.clone());
        }

        match self.connected_peers.get(peer).map(|v| &v.kind) {
            Some(PeerKind::Floodsub) => {
                tracing::error!("Attempted to prune a Floodsub peer");
            }
            Some(PeerKind::Gossipsub) => {
                // GossipSub v1.0 -- no peer exchange, the peer won't be able to parse it anyway
                return ControlAction::Prune {
                    topic_hash: topic_hash.clone(),
                    peers: Vec::new(),
                    backoff: None,
                };
            }
            None => {
                tracing::error!("Attempted to Prune an unknown peer");
            }
            _ => {} // Gossipsub 1.1 peer perform the `Prune`
        }

        // Select peers for peer exchange
        let peers = if do_px {
            get_random_peers(
                &self.topic_peers,
                &self.connected_peers,
                topic_hash,
                self.config.prune_peers(),
                |p| p != peer && !self.score_below_threshold(p, |_| 0.0).0,
            )
            .into_iter()
            .map(|p| PeerInfo { peer_id: Some(p) })
            .collect()
        } else {
            Vec::new()
        };

        let backoff = if on_unsubscribe {
            self.config.unsubscribe_backoff()
        } else {
            self.config.prune_backoff()
        };

        // update backoff
        self.backoffs.update_backoff(topic_hash, peer, backoff);

        ControlAction::Prune {
            topic_hash: topic_hash.clone(),
            peers,
            backoff: Some(backoff.as_secs()),
        }
    }

    /// Gossipsub LEAVE(topic) - Notifies mesh\[topic\] peers with PRUNE messages.
    fn leave(&mut self, topic_hash: &TopicHash) {
        tracing::debug!(topic=%topic_hash, "Running LEAVE for topic");

        // COMPOSITE path: tear down composite state (and its derived slice
        // meshes) and PRUNE the former same+broker members.
        if self.composites.contains_key(topic_hash) {
            if let Some(m) = self.metrics.as_mut() {
                m.left(topic_hash)
            }
            let members: Vec<PeerId> = self
                .composites
                .get(topic_hash)
                .map(|c| c.same.iter().chain(c.broker.iter()).copied().collect())
                .unwrap_or_default();
            self.leave_composite(topic_hash);
            for peer in members {
                tracing::debug!(%peer, "LEAVE: Sending PRUNE to composite peer");
                let on_unsubscribe = true;
                let control =
                    self.make_prune(topic_hash, &peer, self.config.do_px(), on_unsubscribe);
                Self::control_pool_add(&mut self.control_pool, peer, control);
                peer_removed_from_mesh(
                    peer,
                    topic_hash,
                    &self.mesh,
                    self.peer_topics.get(&peer),
                    &mut self.events,
                    &self.connected_peers,
                );
            }
            tracing::debug!(topic=%topic_hash, "Completed composite LEAVE for topic");
            return;
        }

        // If our mesh contains the topic, send prune to peers and delete it from the mesh
        if let Some((_, peers)) = self.mesh.remove_entry(topic_hash) {
            if let Some(m) = self.metrics.as_mut() {
                m.left(topic_hash)
            }
            for peer in peers {
                // Send a PRUNE control message
                tracing::debug!(%peer, "LEAVE: Sending PRUNE to peer");
                let on_unsubscribe = true;
                let control =
                    self.make_prune(topic_hash, &peer, self.config.do_px(), on_unsubscribe);
                Self::control_pool_add(&mut self.control_pool, peer, control);

                // If the peer did not previously exist in any mesh, inform the handler
                peer_removed_from_mesh(
                    peer,
                    topic_hash,
                    &self.mesh,
                    self.peer_topics.get(&peer),
                    &mut self.events,
                    &self.connected_peers,
                );
            }
        }
        tracing::debug!(topic=%topic_hash, "Completed LEAVE for topic");
    }

    // ----------------------------------------------------------------------
    // Composite same/broker overlap mesh (ported from quil-p2p behaviour.rs).
    // ----------------------------------------------------------------------

    /// Resolve the peers a message for `bitmask` should be sent/forwarded to.
    ///
    /// Union of:
    /// - (a) `mesh[bitmask]` — the heartbeat-maintained mesh for a SIMPLE
    ///   (single-slice) bitmask (for a composite this is always empty/absent).
    /// - (b) `composites[bitmask].{same,broker}` — if we subscribe to this exact
    ///   composite ourselves.
    /// - (c) for every slice of the bitmask, `mesh[slice]` — the per-slice
    ///   meshes, which is what lets a COVERING relay (an archive on the all-ones
    ///   bulk bitmask) forward a specific shard's traffic it never subscribed to
    ///   by exact bitmask.
    fn mesh_recipients(&self, bitmask: &TopicHash) -> Vec<PeerId> {
        let mut out: HashSet<PeerId> = HashSet::new();
        if let Some(s) = self.mesh.get(bitmask) {
            out.extend(s.iter().copied());
        }
        if let Some(comp) = self.composites.get(bitmask) {
            out.extend(comp.same.iter().copied());
            out.extend(comp.broker.iter().copied());
        }
        for slice in composite::topic_slices(bitmask) {
            if let Some(s) = self.mesh.get(&slice) {
                out.extend(s.iter().copied());
            }
        }
        out.into_iter().collect()
    }

    /// Collapse a peer's known IPs to their /24 (v4) · /48 (v6) subnet buckets.
    /// REUSES the per-peer IP set the scorer already tracks for the P6
    /// colocation-factor penalty (`PeerScore::peer_ips`) — no second IP map.
    /// Empty if scoring is disabled or the peer has no observed IP yet, in
    /// which case the subnet cap is skipped so the peer can still join (the IP
    /// gets recorded later and future grafts are bucketed normally).
    fn peer_subnet_buckets(&self, peer: &PeerId) -> HashSet<[u8; 16]> {
        let mut out = HashSet::new();
        if let Some((peer_score, ..)) = &self.peer_score {
            if let Some(ips) = peer_score.peer_ips(peer) {
                for ip in ips {
                    out.insert(subnet_bucket_key(*ip));
                }
            }
        }
        out
    }

    /// Returns true if grafting `peer` into a mesh whose current members are
    /// `members` would violate the per-subnet cap
    /// (`config.mesh_peers_per_subnet`). `0` disables the check. A peer with no
    /// known IPs is admitted (see [`Self::peer_subnet_buckets`]). Eclipse
    /// resistance: a Sybil attacker who controls a single /24 (or /48) cannot
    /// fill more than `cap` mesh slots. Ported from quil-p2p behaviour.rs.
    fn graft_would_violate_subnet_cap(&self, members: &[PeerId], peer: &PeerId) -> bool {
        let cap = self.config.mesh_peers_per_subnet();
        if cap == 0 {
            return false;
        }
        let candidate_buckets = self.peer_subnet_buckets(peer);
        if candidate_buckets.is_empty() {
            return false;
        }
        candidate_buckets.iter().any(|b| {
            members
                .iter()
                .filter(|p| self.peer_subnet_buckets(p).contains(b))
                .count()
                >= cap
        })
    }

    /// Does any advertised whole bitmask of `peer_subs` cover `slice`?
    fn peer_covers_slice(peer_subs: &BTreeSet<TopicHash>, slice: &TopicHash) -> bool {
        peer_subs
            .iter()
            .any(|b| composite::bitmask_covers(b.as_bytes(), slice.as_bytes()))
    }

    /// Establish composite mesh state for a multi-slice bitmask. Selects up to
    /// `D` (= `config.mesh_n()`) peers, preferring peers that cover ALL slices
    /// (`same`), then filling any remainder with peers covering SOME slices
    /// (`broker`). Skips peers under active backoff. Registers the reverse
    /// index and rebuilds the derived per-slice meshes.
    fn join_composite(&mut self, bitmask: &TopicHash) {
        if self.composites.contains_key(bitmask) {
            return;
        }

        let d = self.config.mesh_n();
        let mut entry = CompositeMeshEntry::new(bitmask);

        // Pick "same" peers (cover every slice) up to D.
        for (peer, subs) in &self.peer_topics {
            if entry.total_peers() >= d {
                break;
            }
            if self.backoffs.is_backoff_with_slack(bitmask, peer) {
                continue;
            }
            if entry
                .slices
                .iter()
                .all(|s| Self::peer_covers_slice(subs, s))
            {
                entry.same.insert(*peer);
            }
        }

        // Fill the remainder with "broker" peers (cover at least one slice).
        if entry.total_peers() < d {
            let candidates: Vec<PeerId> = self
                .peer_topics
                .iter()
                .filter_map(|(p, subs)| {
                    if entry.same.contains(p) {
                        return None;
                    }
                    if self.backoffs.is_backoff_with_slack(bitmask, p) {
                        return None;
                    }
                    if entry.slices.iter().any(|s| Self::peer_covers_slice(subs, s)) {
                        Some(*p)
                    } else {
                        None
                    }
                })
                .collect();
            for p in candidates {
                if entry.total_peers() >= d {
                    break;
                }
                entry.broker.insert(p);
            }
        }

        // Register the reverse index (slice -> composite).
        for slice in &entry.slices {
            self.slice_to_composite
                .entry(slice.clone())
                .or_default()
                .push(bitmask.clone());
        }

        self.composites.insert(bitmask.clone(), entry);
        self.rebuild_slice_meshes(bitmask);
    }

    /// Tear down a composite mesh — remove state, clean up the reverse index,
    /// and drop per-slice meshes no longer owned by any composite.
    fn leave_composite(&mut self, bitmask: &TopicHash) {
        let comp = match self.composites.remove(bitmask) {
            Some(c) => c,
            None => return,
        };
        for slice in &comp.slices {
            if let Some(keys) = self.slice_to_composite.get_mut(slice) {
                keys.retain(|k| k != bitmask);
                if keys.is_empty() {
                    self.slice_to_composite.remove(slice);
                }
            }
        }
        for slice in &comp.slices {
            if !self.slice_to_composite.contains_key(slice) {
                self.mesh.remove(slice);
            } else {
                // Still owned by another composite — rebuild it.
                let keys = self
                    .slice_to_composite
                    .get(slice)
                    .cloned()
                    .unwrap_or_default();
                if let Some(k) = keys.first() {
                    self.rebuild_slice_meshes(k);
                }
            }
        }
    }

    /// Classify a peer as `Same` (covers every slice of the composite) or
    /// `Broker` (covers at least one but not all). Missing data → `Broker`.
    fn classify_peer(&self, peer: &PeerId, composite_key: &TopicHash) -> PeerClass {
        let comp = match self.composites.get(composite_key) {
            Some(c) => c,
            None => return PeerClass::Broker,
        };
        let subs = match self.peer_topics.get(peer) {
            Some(s) => s,
            None => return PeerClass::Broker,
        };
        if comp.slices.iter().all(|s| Self::peer_covers_slice(subs, s)) {
            PeerClass::Same
        } else {
            PeerClass::Broker
        }
    }

    /// Re-evaluate `peer`'s membership in every under-`D` composite after its
    /// advertised subscription set changed. Closes the startup-ordering gap
    /// where `join_composite` ran before the peer announced.
    fn reclassify_composites_for_peer(&mut self, peer: PeerId) {
        let subs = match self.peer_topics.get(&peer) {
            Some(s) => s.clone(),
            None => return,
        };
        let d = self.config.mesh_n();
        let keys: Vec<TopicHash> = self.composites.keys().cloned().collect();
        for key in keys {
            let backed_off = self.backoffs.is_backoff_with_slack(&key, &peer);
            let mut changed = false;
            if let Some(comp) = self.composites.get_mut(&key) {
                if comp.same.contains(&peer)
                    || comp.broker.contains(&peer)
                    || comp.total_peers() >= d
                    || backed_off
                {
                    continue;
                }
                if comp
                    .slices
                    .iter()
                    .all(|s| Self::peer_covers_slice(&subs, s))
                {
                    comp.same.insert(peer);
                    changed = true;
                } else if comp.slices.iter().any(|s| Self::peer_covers_slice(&subs, s)) {
                    comp.broker.insert(peer);
                    changed = true;
                }
            }
            if changed {
                self.rebuild_slice_meshes(&key);
            }
        }
    }

    /// The union of `same ∪ broker` across EVERY composite that owns `slice`.
    ///
    /// A single slice can be owned by multiple composites (e.g. `0xC0` and
    /// `0xA0` both own the `0x80` slice). Rebuilding a slice mesh from only one
    /// owner would clobber the others' members (F4), so slice meshes are always
    /// recomputed as the union across all owners.
    fn composite_members_for_slice(&self, slice: &TopicHash) -> BTreeSet<PeerId> {
        let mut out = BTreeSet::new();
        if let Some(owners) = self.slice_to_composite.get(slice) {
            for owner in owners {
                if let Some(c) = self.composites.get(owner) {
                    out.extend(c.same.iter().copied());
                    out.extend(c.broker.iter().copied());
                }
            }
        }
        out
    }

    /// Rebuild the per-slice `mesh` sets from composite `same ∪ broker`
    /// membership. Every composite member is placed into EVERY slice mesh —
    /// brokers intentionally bridge non-subscribed slices, because a message
    /// carries the full bitmask which overlaps the broker's real subscription.
    ///
    /// Each affected slice mesh is recomputed as the UNION across ALL composites
    /// that own it (F4). A slice that is ALSO a simple single-bit subscription
    /// (`self.subscriptions`) is a DUAL-ROLE slice: its simple-subscription mesh
    /// peers (maintained by the normal per-slice heartbeat loop) must survive,
    /// so composite members are unioned INTO the existing mesh rather than
    /// replacing it (F3b).
    fn rebuild_slice_meshes(&mut self, composite_key: &TopicHash) {
        let slices = match self.composites.get(composite_key) {
            Some(c) => c.slices.clone(),
            None => return,
        };
        for slice in slices {
            let members = self.composite_members_for_slice(&slice);
            let dual_role = self.subscriptions.contains(&slice);
            let entry = self.mesh.entry(slice).or_default();
            if !dual_role {
                entry.clear();
            }
            entry.extend(members);
        }
    }

    /// Checks if the given peer is still connected and if not dials the peer again.
    fn check_explicit_peer_connection(&mut self, peer_id: &PeerId) {
        if !self.peer_topics.contains_key(peer_id) {
            // Connect to peer
            tracing::debug!(peer=%peer_id, "Connecting to explicit peer");
            self.events.push_back(ToSwarm::Dial {
                opts: DialOpts::peer_id(*peer_id).build(),
            });
        }
    }

    /// Determines if a peer's score is below a given `PeerScoreThreshold` chosen via the
    /// `threshold` parameter.
    fn score_below_threshold(
        &self,
        peer_id: &PeerId,
        threshold: impl Fn(&PeerScoreThresholds) -> f64,
    ) -> (bool, f64) {
        Self::score_below_threshold_from_scores(&self.peer_score, peer_id, threshold)
    }

    fn score_below_threshold_from_scores(
        peer_score: &Option<(PeerScore, PeerScoreThresholds, Ticker, GossipPromises)>,
        peer_id: &PeerId,
        threshold: impl Fn(&PeerScoreThresholds) -> f64,
    ) -> (bool, f64) {
        if let Some((peer_score, thresholds, ..)) = peer_score {
            let score = peer_score.score(peer_id);
            if score < threshold(thresholds) {
                return (true, score);
            }
            (false, score)
        } else {
            (false, 0.0)
        }
    }

    /// Handles an IHAVE control message. Checks our cache of messages. If the message is unknown,
    /// requests it with an IWANT control message.
    fn handle_ihave(&mut self, peer_id: &PeerId, ihave_msgs: Vec<(TopicHash, Vec<MessageId>)>) {
        // We ignore IHAVE gossip from any peer whose score is below the gossip threshold
        if let (true, score) = self.score_below_threshold(peer_id, |pst| pst.gossip_threshold) {
            tracing::debug!(
                peer=%peer_id,
                %score,
                "IHAVE: ignoring peer with score below threshold"
            );
            return;
        }

        // IHAVE flood protection
        let peer_have = self.count_received_ihave.entry(*peer_id).or_insert(0);
        *peer_have += 1;
        if *peer_have > self.config.max_ihave_messages() {
            tracing::debug!(
                peer=%peer_id,
                "IHAVE: peer has advertised too many times ({}) within this heartbeat \
            interval; ignoring",
                *peer_have
            );
            return;
        }

        if let Some(iasked) = self.count_sent_iwant.get(peer_id) {
            if *iasked >= self.config.max_ihave_length() {
                tracing::debug!(
                    peer=%peer_id,
                    "IHAVE: peer has already advertised too many messages ({}); ignoring",
                    *iasked
                );
                return;
            }
        }

        tracing::trace!(peer=%peer_id, "Handling IHAVE for peer");

        let mut iwant_ids = HashSet::new();

        let want_message = |id: &MessageId| {
            if self.duplicate_cache.contains(id) {
                return false;
            }

            if self.pending_iwant_msgs.contains(id) {
                return false;
            }

            self.peer_score
                .as_ref()
                .map(|(_, _, _, promises)| !promises.contains(id))
                .unwrap_or(true)
        };

        for (topic, ids) in ihave_msgs {
            // only process the message if we are subscribed
            if !self.mesh.contains_key(&topic) {
                tracing::debug!(
                    %topic,
                    "IHAVE: Ignoring IHAVE - Not subscribed to topic"
                );
                continue;
            }

            for id in ids.into_iter().filter(want_message) {
                // have not seen this message and are not currently requesting it
                if iwant_ids.insert(id) {
                    // Register the IWANT metric
                    if let Some(metrics) = self.metrics.as_mut() {
                        metrics.register_iwant(&topic);
                    }
                }
            }
        }

        if !iwant_ids.is_empty() {
            let iasked = self.count_sent_iwant.entry(*peer_id).or_insert(0);
            let mut iask = iwant_ids.len();
            if *iasked + iask > self.config.max_ihave_length() {
                iask = self.config.max_ihave_length().saturating_sub(*iasked);
            }

            // Send the list of IWANT control messages
            tracing::debug!(
                peer=%peer_id,
                "IHAVE: Asking for {} out of {} messages from peer",
                iask,
                iwant_ids.len()
            );

            // Ask in random order
            let mut iwant_ids_vec: Vec<_> = iwant_ids.into_iter().collect();
            let mut rng = thread_rng();
            iwant_ids_vec.partial_shuffle(&mut rng, iask);

            iwant_ids_vec.truncate(iask);
            *iasked += iask;

            for message_id in &iwant_ids_vec {
                // Add all messages to the pending list
                self.pending_iwant_msgs.insert(message_id.clone());
            }

            if let Some((_, _, _, gossip_promises)) = &mut self.peer_score {
                gossip_promises.add_promise(
                    *peer_id,
                    &iwant_ids_vec,
                    Instant::now() + self.config.iwant_followup_time(),
                );
            }
            tracing::trace!(
                peer=%peer_id,
                "IHAVE: Asking for the following messages from peer: {:?}",
                iwant_ids_vec
            );

            Self::control_pool_add(
                &mut self.control_pool,
                *peer_id,
                ControlAction::IWant {
                    message_ids: iwant_ids_vec,
                },
            );
        }
        tracing::trace!(peer=%peer_id, "Completed IHAVE handling for peer");
    }

    /// Handles an IWANT control message. Checks our cache of messages. If the message exists it is
    /// forwarded to the requesting peer.
    fn handle_iwant(&mut self, peer_id: &PeerId, iwant_msgs: Vec<MessageId>) {
        // We ignore IWANT gossip from any peer whose score is below the gossip threshold
        if let (true, score) = self.score_below_threshold(peer_id, |pst| pst.gossip_threshold) {
            tracing::debug!(
                peer=%peer_id,
                "IWANT: ignoring peer with score below threshold [score = {}]",
                score
            );
            return;
        }

        tracing::debug!(peer=%peer_id, "Handling IWANT for peer");

        for id in iwant_msgs {
            // If we have it and the IHAVE count is not above the threshold,
            // forward the message.
            if let Some((msg, count)) = self
                .mcache
                .get_with_iwant_counts(&id, peer_id)
                .map(|(msg, count)| (msg.clone(), count))
            {
                if count > self.config.gossip_retransimission() {
                    tracing::debug!(
                        peer=%peer_id,
                        message=%id,
                        "IWANT: Peer has asked for message too many times; ignoring request"
                    );
                } else {
                    tracing::debug!(peer=%peer_id, "IWANT: Sending cached messages to peer");
                    self.send_message(*peer_id, RpcOut::Forward(msg));
                }
            }
        }
        tracing::debug!(peer=%peer_id, "Completed IWANT handling for peer");
    }

    /// Handles GRAFT control messages. If subscribed to the topic, adds the peer to mesh, if not,
    /// responds with PRUNE messages.
    fn handle_graft(&mut self, peer_id: &PeerId, topics: Vec<TopicHash>) {
        tracing::debug!(peer=%peer_id, "Handling GRAFT message for peer");

        let mut to_prune_topics = HashSet::new();

        let mut do_px = self.config.do_px();

        // For each topic, if a peer has grafted us, then we necessarily must be in their mesh
        // and they must be subscribed to the topic. Ensure we have recorded the mapping.
        for topic in &topics {
            self.peer_topics
                .entry(*peer_id)
                .or_default()
                .insert(topic.clone());
            self.topic_peers
                .entry(topic.clone())
                .or_default()
                .insert(*peer_id);
        }

        // Snapshot the grafted topics for composite classification after the
        // main GRAFT handling (which consumes `topics`).
        let graft_topics_snapshot: Vec<TopicHash> = topics.clone();

        // we don't GRAFT to/from explicit peers; complain loudly if this happens
        if self.explicit_peers.contains(peer_id) {
            tracing::debug!(peer=%peer_id, "GRAFT: ignoring request from direct peer");
            // this is possibly a bug from non-reciprocal configuration; send a PRUNE for all topics
            to_prune_topics = topics.into_iter().collect();
            // but don't PX
            do_px = false
        } else {
            let (below_zero, score) = self.score_below_threshold(peer_id, |_| 0.0);
            let now = Instant::now();
            for topic_hash in topics {
                // COMPOSITE whole-bitmask admission (F1). A GRAFT naming a whole
                // multi-bit composite bitmask we subscribe to is NOT a key in
                // `self.mesh` (composite meshes live in `self.composites`) and is
                // NOT slice-keyed in `slice_to_composite`, so without this branch
                // it would fall into the unknown-topic `else` and be silently
                // dropped — the sender put us in their mesh but we never admit
                // them (asymmetric mesh; a covering relay can never be admitted
                // once a composite is at D). Mirror the reference's `is_subscribed`
                // admission: backoff -> PRUNE, else classify into same/broker
                // (accept-then-trim; heartbeat step-3 prunes over Dhi).
                if self.composites.contains_key(&topic_hash) {
                    // backoff enforcement on the whole bitmask
                    if let Some(backoff_time) =
                        self.backoffs.get_backoff_time(&topic_hash, peer_id)
                    {
                        if backoff_time > now {
                            tracing::debug!(
                                peer=%peer_id,
                                "[Penalty] Peer attempted composite graft within backoff, penalizing"
                            );
                            if let Some((peer_score, ..)) = &mut self.peer_score {
                                if let Some(metrics) = self.metrics.as_mut() {
                                    metrics.register_score_penalty(Penalty::GraftBackoff);
                                }
                                peer_score.add_penalty(peer_id, 1);
                            }
                            do_px = false;
                            to_prune_topics.insert(topic_hash.clone());
                            continue;
                        }
                    }
                    // negative score -> PRUNE, no admission
                    if below_zero {
                        tracing::debug!(
                            peer=%peer_id,
                            %score,
                            topic=%topic_hash,
                            "GRAFT: ignoring composite graft from negative-score peer"
                        );
                        to_prune_topics.insert(topic_hash.clone());
                        do_px = false;
                        continue;
                    }
                    // Subnet-diversity gate (eclipse resistance). Cap inbound
                    // composite GRAFTs per /24 (v4) · /48 (v6). Direct/explicit
                    // and peers we dialed (outbound) bypass. Members counted =
                    // current same ∪ broker.
                    if !self.explicit_peers.contains(peer_id)
                        && !self.outbound_peers.contains(peer_id)
                    {
                        let members: Vec<PeerId> = self
                            .composites
                            .get(&topic_hash)
                            .map(|c| c.same.iter().chain(c.broker.iter()).copied().collect())
                            .unwrap_or_default();
                        if self.graft_would_violate_subnet_cap(&members, peer_id) {
                            tracing::debug!(
                                peer=%peer_id,
                                topic=%topic_hash,
                                "GRAFT: rejected composite — subnet cap reached"
                            );
                            to_prune_topics.insert(topic_hash.clone());
                            continue;
                        }
                    }
                    // classify + admit (accept-then-trim: allowed even over D).
                    let already = self.composites.get(&topic_hash).map_or(false, |c| {
                        c.same.contains(peer_id) || c.broker.contains(peer_id)
                    });
                    let cls = self.classify_peer(peer_id, &topic_hash);
                    if let Some(comp) = self.composites.get_mut(&topic_hash) {
                        match cls {
                            PeerClass::Same => {
                                comp.broker.remove(peer_id);
                                comp.same.insert(*peer_id);
                            }
                            PeerClass::Broker => {
                                if !comp.same.contains(peer_id) {
                                    comp.broker.insert(*peer_id);
                                }
                            }
                        }
                    }
                    if !already {
                        if let Some(m) = self.metrics.as_mut() {
                            m.peers_included(&topic_hash, Inclusion::Subscribed, 1)
                        }
                    }
                    if let Some((peer_score, ..)) = &mut self.peer_score {
                        peer_score.graft(peer_id, topic_hash.clone());
                    }
                    self.rebuild_slice_meshes(&topic_hash);
                    // Inform the handler that the peer joined a mesh (it is now in
                    // the derived slice meshes).
                    peer_added_to_mesh(
                        *peer_id,
                        vec![&topic_hash],
                        &self.mesh,
                        self.peer_topics.get(peer_id),
                        &mut self.events,
                        &self.connected_peers,
                    );
                    continue;
                }
                // Precompute the subnet-cap violation while we still hold only
                // `&self` (the `get_mut` below takes a mutable borrow of
                // `self.mesh`, which would collide with `peer_subnet_buckets`).
                // Direct/explicit and outbound peers bypass the cap.
                let simple_subnet_violation = if !self.explicit_peers.contains(peer_id)
                    && !self.outbound_peers.contains(peer_id)
                {
                    let members: Vec<PeerId> = self
                        .mesh
                        .get(&topic_hash)
                        .map(|m| m.iter().copied().collect())
                        .unwrap_or_default();
                    self.graft_would_violate_subnet_cap(&members, peer_id)
                } else {
                    false
                };
                if let Some(peers) = self.mesh.get_mut(&topic_hash) {
                    // if the peer is already in the mesh ignore the graft
                    if peers.contains(peer_id) {
                        tracing::debug!(
                            peer=%peer_id,
                            topic=%&topic_hash,
                            "GRAFT: Received graft for peer that is already in topic"
                        );
                        continue;
                    }

                    // make sure we are not backing off that peer
                    if let Some(backoff_time) = self.backoffs.get_backoff_time(&topic_hash, peer_id)
                    {
                        if backoff_time > now {
                            tracing::debug!(
                                peer=%peer_id,
                                "[Penalty] Peer attempted graft within backoff time, penalizing"
                            );
                            // add behavioural penalty
                            if let Some((peer_score, ..)) = &mut self.peer_score {
                                if let Some(metrics) = self.metrics.as_mut() {
                                    metrics.register_score_penalty(Penalty::GraftBackoff);
                                }
                                peer_score.add_penalty(peer_id, 1);

                                // check the flood cutoff
                                // See: https://github.com/rust-lang/rust-clippy/issues/10061
                                #[allow(unknown_lints, clippy::unchecked_duration_subtraction)]
                                let flood_cutoff = (backoff_time
                                    + self.config.graft_flood_threshold())
                                    - self.config.prune_backoff();
                                if flood_cutoff > now {
                                    //extra penalty
                                    peer_score.add_penalty(peer_id, 1);
                                }
                            }
                            // no PX
                            do_px = false;

                            to_prune_topics.insert(topic_hash.clone());
                            continue;
                        }
                    }

                    // check the score
                    if below_zero {
                        // we don't GRAFT peers with negative score
                        tracing::debug!(
                            peer=%peer_id,
                            %score,
                            topic=%topic_hash,
                            "GRAFT: ignoring peer with negative score"
                        );
                        // we do send them PRUNE however, because it's a matter of protocol correctness
                        to_prune_topics.insert(topic_hash.clone());
                        // but we won't PX to them
                        do_px = false;
                        continue;
                    }

                    // check mesh upper bound and only allow graft if the upper bound is not reached or
                    // if it is an outbound peer
                    if peers.len() >= self.config.mesh_n_high()
                        && !self.outbound_peers.contains(peer_id)
                    {
                        to_prune_topics.insert(topic_hash.clone());
                        continue;
                    }

                    // Subnet-diversity gate (eclipse resistance). A candidate
                    // whose /24 (v4) · /48 (v6) already holds `cap` mesh peers
                    // is refused and PRUNEd back. Fires before mesh saturation,
                    // where the Dhi gate above only catches Sybils once full.
                    if simple_subnet_violation {
                        tracing::debug!(
                            peer=%peer_id,
                            topic=%topic_hash,
                            "GRAFT: rejected — subnet cap reached"
                        );
                        to_prune_topics.insert(topic_hash.clone());
                        continue;
                    }

                    // add peer to the mesh
                    tracing::debug!(
                        peer=%peer_id,
                        topic=%topic_hash,
                        "GRAFT: Mesh link added for peer in topic"
                    );

                    if peers.insert(*peer_id) {
                        if let Some(m) = self.metrics.as_mut() {
                            m.peers_included(&topic_hash, Inclusion::Subscribed, 1)
                        }
                    }

                    // If the peer did not previously exist in any mesh, inform the handler
                    peer_added_to_mesh(
                        *peer_id,
                        vec![&topic_hash],
                        &self.mesh,
                        self.peer_topics.get(peer_id),
                        &mut self.events,
                        &self.connected_peers,
                    );

                    if let Some((peer_score, ..)) = &mut self.peer_score {
                        peer_score.graft(peer_id, topic_hash);
                    }
                } else {
                    // don't do PX when there is an unknown topic to avoid leaking our peers
                    do_px = false;
                    tracing::debug!(
                        peer=%peer_id,
                        topic=%topic_hash,
                        "GRAFT: Received graft for unknown topic from peer"
                    );
                    // spam hardening: ignore GRAFTs for unknown topics
                    continue;
                }
            }
        }

        // Composite classification: a GRAFT names a SLICE. For every accepted
        // (non-pruned) grafted slice owned by one or more composites, classify
        // the peer as same/broker and rebuild the derived slice meshes. This
        // runs regardless of whether the peer was newly added to the slice mesh
        // above (it may already be a broker being promoted to same).
        let mut touched_composites: HashSet<TopicHash> = HashSet::new();
        for slice in &graft_topics_snapshot {
            if to_prune_topics.contains(slice) {
                continue;
            }
            if let Some(keys) = self.slice_to_composite.get(slice).cloned() {
                for ck in keys {
                    let cls = self.classify_peer(peer_id, &ck);
                    if let Some(comp) = self.composites.get_mut(&ck) {
                        match cls {
                            PeerClass::Same => {
                                comp.broker.remove(peer_id);
                                comp.same.insert(*peer_id);
                            }
                            PeerClass::Broker => {
                                if !comp.same.contains(peer_id) {
                                    comp.broker.insert(*peer_id);
                                }
                            }
                        }
                        touched_composites.insert(ck);
                    }
                }
            }
        }
        for ck in touched_composites {
            self.rebuild_slice_meshes(&ck);
        }

        if !to_prune_topics.is_empty() {
            // build the prune messages to send
            let on_unsubscribe = false;
            for action in to_prune_topics
                .iter()
                .map(|t| self.make_prune(t, peer_id, do_px, on_unsubscribe))
                .collect::<Vec<_>>()
            {
                self.send_message(*peer_id, RpcOut::Control(action));
            }
            // Send the prune messages to the peer
            tracing::debug!(
                peer=%peer_id,
                "GRAFT: Not subscribed to topics -  Sending PRUNE to peer"
            );
        }
        tracing::debug!(peer=%peer_id, "Completed GRAFT handling for peer");
    }

    fn remove_peer_from_mesh(
        &mut self,
        peer_id: &PeerId,
        topic_hash: &TopicHash,
        backoff: Option<u64>,
        always_update_backoff: bool,
        reason: Churn,
    ) {
        let mut update_backoff = always_update_backoff;
        if let Some(peers) = self.mesh.get_mut(topic_hash) {
            // remove the peer if it exists in the mesh
            if peers.remove(peer_id) {
                tracing::debug!(
                    peer=%peer_id,
                    topic=%topic_hash,
                    "PRUNE: Removing peer from the mesh for topic"
                );
                if let Some(m) = self.metrics.as_mut() {
                    m.peers_removed(topic_hash, reason, 1)
                }

                if let Some((peer_score, ..)) = &mut self.peer_score {
                    peer_score.prune(peer_id, topic_hash.clone());
                }

                update_backoff = true;

                // inform the handler
                peer_removed_from_mesh(
                    *peer_id,
                    topic_hash,
                    &self.mesh,
                    self.peer_topics.get(peer_id),
                    &mut self.events,
                    &self.connected_peers,
                );
            }
        }
        if update_backoff {
            let time = if let Some(backoff) = backoff {
                // CLAMP the peer-supplied backoff: it is attacker-controlled
                // (any mesh peer can PRUNE us) and flows unmodified into
                // `BackoffStorage::update_backoff` -> `Instant::now() + time`,
                // which PANICS on overflow. A malicious `backoff = u64::MAX`
                // seconds would crash the receive task (remote DoS). No
                // legitimate backoff exceeds a few multiples of prune_backoff,
                // so cap at MAX_PEER_BACKOFF (also bounds a griefing peer from
                // locking us out of a mesh for an absurd duration).
                Duration::from_secs(backoff.min(MAX_PEER_BACKOFF_SECS))
            } else {
                self.config.prune_backoff()
            };
            // is there a backoff specified by the peer? if so obey it.
            self.backoffs.update_backoff(topic_hash, peer_id, time);
        }
    }

    /// Handles PRUNE control messages. Removes peer from the mesh.
    fn handle_prune(
        &mut self,
        peer_id: &PeerId,
        prune_data: Vec<(TopicHash, Vec<PeerInfo>, Option<u64>)>,
    ) {
        tracing::debug!(peer=%peer_id, "Handling PRUNE message for peer");
        let (below_threshold, score) =
            self.score_below_threshold(peer_id, |pst| pst.accept_px_threshold);
        for (topic_hash, px, backoff) in prune_data {
            // COMPOSITE-managed slice: a slice PRUNE is a legitimate composite
            // rebalancing signal (same -> broker demotion), not a flap-graft
            // attack. Demote the peer from `same` to `broker` rather than
            // removing it from the slice mesh — brokers stay in every slice
            // mesh so traffic still bridges — and do NOT install a backoff, so a
            // subsequent slice GRAFT can promote broker -> same again.
            if let Some(keys) = self.slice_to_composite.get(&topic_hash).cloned() {
                for ck in &keys {
                    if let Some(comp) = self.composites.get_mut(ck) {
                        if comp.same.remove(peer_id) {
                            tracing::debug!(
                                peer=%peer_id,
                                topic=%topic_hash,
                                "PRUNE: demote composite peer same -> broker"
                            );
                            comp.broker.insert(*peer_id);
                        }
                        // If already a broker, leave it — it still bridges the
                        // remaining slices.
                    }
                }
                for ck in keys {
                    self.rebuild_slice_meshes(&ck);
                }
                // No mesh removal / backoff for composite slices. PX handling
                // below still applies (mesh[slice] exists).
            } else {
                self.remove_peer_from_mesh(peer_id, &topic_hash, backoff, true, Churn::Prune);
            }

            if self.mesh.contains_key(&topic_hash) {
                //connect to px peers
                if !px.is_empty() {
                    // we ignore PX from peers with insufficient score
                    if below_threshold {
                        tracing::debug!(
                            peer=%peer_id,
                            %score,
                            topic=%topic_hash,
                            "PRUNE: ignoring PX from peer with insufficient score"
                        );
                        continue;
                    }

                    // NOTE: We cannot dial any peers from PX currently as we typically will not
                    // know their multiaddr. Until SignedRecords are spec'd this
                    // remains a stub. By default `config.prune_peers()` is set to zero and
                    // this is skipped. If the user modifies this, this will only be able to
                    // dial already known peers (from an external discovery mechanism for
                    // example).
                    if self.config.prune_peers() > 0 {
                        self.px_connect(px);
                    }
                }
            }
        }
        tracing::debug!(peer=%peer_id, "Completed PRUNE handling for peer");
    }

    /// Records IDONTWANT message ids received from `peer_id`. Subsequent
    /// forwards of those messages to this peer are suppressed until the ids
    /// expire from the short-lived per-peer cache (gossipsub-1.2 semantics).
    fn handle_idontwant(&mut self, peer_id: &PeerId, message_ids: Vec<MessageId>) {
        if message_ids.is_empty() {
            return;
        }
        let ttl = self.config.duplicate_cache_time();
        let cache = self
            .peer_idontwant
            .entry(*peer_id)
            .or_insert_with(|| DuplicateCache::new(ttl));
        for id in message_ids {
            cache.insert(id);
        }
    }

    /// Returns `true` if `peer_id` has asked us (via IDONTWANT) not to send it
    /// `msg_id`.
    fn peer_does_not_want(&self, peer_id: &PeerId, msg_id: &MessageId) -> bool {
        self.peer_idontwant
            .get(peer_id)
            .map_or(false, |cache| cache.contains(msg_id))
    }

    /// Emits IDONTWANT for `msg_id` to `peers` so they can suppress in-flight
    /// duplicates of a message we've just accepted (gossipsub-1.2).
    fn send_idontwant(&mut self, msg_id: &MessageId, peers: &HashSet<PeerId>) {
        for peer in peers {
            Self::control_pool_add(
                &mut self.control_pool,
                *peer,
                ControlAction::IDontWant {
                    message_ids: vec![msg_id.clone()],
                },
            );
        }
    }

    fn px_connect(&mut self, mut px: Vec<PeerInfo>) {
        let n = self.config.prune_peers();
        // Ignore peerInfo with no ID
        //
        //TODO: Once signed records are spec'd: Can we use peerInfo without any IDs if they have a
        // signed peer record?
        px.retain(|p| p.peer_id.is_some());
        if px.len() > n {
            // only use at most prune_peers many random peers
            let mut rng = thread_rng();
            px.partial_shuffle(&mut rng, n);
            px = px.into_iter().take(n).collect();
        }

        for p in px {
            // TODO: Once signed records are spec'd: extract signed peer record if given and handle
            // it, see https://github.com/libp2p/specs/pull/217
            if let Some(peer_id) = p.peer_id {
                // mark as px peer
                self.px_peers.insert(peer_id);

                // dial peer
                self.events.push_back(ToSwarm::Dial {
                    opts: DialOpts::peer_id(peer_id).build(),
                });
            }
        }
    }

    /// Applies some basic checks to whether this message is valid. Does not apply user validation
    /// checks.
    fn message_is_valid(
        &mut self,
        msg_id: &MessageId,
        raw_message: &mut RawMessage,
        propagation_source: &PeerId,
    ) -> bool {
        tracing::debug!(
            peer=%propagation_source,
            message=%msg_id,
            "Handling message from peer"
        );

        // Reject any message from a blacklisted peer
        if self.blacklisted_peers.contains(propagation_source) {
            tracing::debug!(
                peer=%propagation_source,
                "Rejecting message from blacklisted peer"
            );
            if let Some((peer_score, .., gossip_promises)) = &mut self.peer_score {
                peer_score.reject_message(
                    propagation_source,
                    msg_id,
                    &raw_message.topic,
                    RejectReason::BlackListedPeer,
                );
                gossip_promises.reject_message(msg_id, &RejectReason::BlackListedPeer);
            }
            return false;
        }

        // Also reject any message that originated from a blacklisted peer
        if let Some(source) = raw_message.source.as_ref() {
            if self.blacklisted_peers.contains(source) {
                tracing::debug!(
                    peer=%propagation_source,
                    %source,
                    "Rejecting message from peer because of blacklisted source"
                );
                self.handle_invalid_message(
                    propagation_source,
                    raw_message,
                    RejectReason::BlackListedSource,
                );
                return false;
            }
        }

        // If we are not validating messages, assume this message is validated
        // This will allow the message to be gossiped without explicitly calling
        // `validate_message`.
        if !self.config.validate_messages() {
            raw_message.validated = true;
        }

        // reject messages claiming to be from ourselves but not locally published
        let self_published = !self.config.allow_self_origin()
            && if let Some(own_id) = self.publish_config.get_own_id() {
                own_id != propagation_source
                    && raw_message.source.as_ref().map_or(false, |s| s == own_id)
            } else {
                self.published_message_ids.contains(msg_id)
            };

        if self_published {
            tracing::debug!(
                message=%msg_id,
                source=%propagation_source,
                "Dropping message claiming to be from self but forwarded from source"
            );
            self.handle_invalid_message(propagation_source, raw_message, RejectReason::SelfOrigin);
            return false;
        }

        true
    }

    /// Handles a newly received [`RawMessage`].
    ///
    /// Forwards the message to all peers in the mesh.
    fn handle_received_message(
        &mut self,
        mut raw_message: RawMessage,
        propagation_source: &PeerId,
    ) {
        // Record the received metric
        if let Some(metrics) = self.metrics.as_mut() {
            metrics.msg_recvd_unfiltered(&raw_message.topic, raw_message.raw_protobuf_len());
        }

        // Try and perform the data transform to the message. If it fails, consider it invalid.
        let message = match self.data_transform.inbound_transform(raw_message.clone()) {
            Ok(message) => message,
            Err(e) => {
                tracing::debug!("Invalid message. Transform error: {:?}", e);
                // Reject the message and return
                self.handle_invalid_message(
                    propagation_source,
                    &raw_message,
                    RejectReason::ValidationError(ValidationError::TransformFailed),
                );
                return;
            }
        };

        // Calculate the message id on the transformed data.
        let msg_id = self.config.message_id(&message);

        // Check the validity of the message
        // Peers get penalized if this message is invalid. We don't add it to the duplicate cache
        // and instead continually penalize peers that repeatedly send this message.
        if !self.message_is_valid(&msg_id, &mut raw_message, propagation_source) {
            return;
        }

        if !self.duplicate_cache.insert(msg_id.clone()) {
            tracing::debug!(message=%msg_id, "Message already received, ignoring");
            if let Some((peer_score, ..)) = &mut self.peer_score {
                peer_score.duplicated_message(propagation_source, &msg_id, &message.topic);
            }
            self.mcache.observe_duplicate(&msg_id, propagation_source);
            return;
        }
        tracing::debug!(
            message=%msg_id,
            "Put message in duplicate_cache and resolve promises"
        );

        // Record the received message with the metrics
        if let Some(metrics) = self.metrics.as_mut() {
            metrics.msg_recvd(&message.topic);
        }

        // Tells score that message arrived (but is maybe not fully validated yet).
        // Consider the message as delivered for gossip promises.
        if let Some((peer_score, .., gossip_promises)) = &mut self.peer_score {
            peer_score.validate_message(propagation_source, &msg_id, &message.topic);
            gossip_promises.message_delivered(&msg_id);
        }

        // Add the message to our memcache
        self.mcache.put(&msg_id, raw_message.clone());

        // Application validator gate (BlossomSub extension). A per-bitmask
        // validator registered via `register_validator` runs BEFORE the
        // message is delivered to the application or forwarded to mesh peers,
        // mirroring the reference `BlossomSubBehaviour` receive-path
        // validation. The closure result is computed first so the immutable
        // borrow of `self.validators` is released before any `&mut self` call.
        let validation = self
            .validators
            .get(&message.topic)
            .map(|v| v(propagation_source, &message.data));
        match validation {
            Some(ValidationResult::Reject) => {
                self.handle_invalid_message(
                    propagation_source,
                    &raw_message,
                    RejectReason::ValidationFailed,
                );
                return;
            }
            Some(ValidationResult::Ignore) => {
                return;
            }
            // Accept or no registered validator: fall through to normal
            // delivery + forwarding.
            _ => {}
        }

        // Dispatch the message to the user if we are subscribed to the whole
        // bitmask. A COMPOSITE subscription's whole key never lands in `mesh`
        // (that is keyed by slices), so the delivery gate uses `subscriptions`.
        let subscribed = self.subscriptions.contains(&message.topic)
            || self.mesh.contains_key(&message.topic);
        // A covering RELAY (e.g. an archive on the all-ones bulk bitmask) is not
        // subscribed to this exact bitmask but owns its slices via a composite,
        // so it must still forward even though it does not deliver locally.
        let relays = composite::slice_bitmask(message.topic.as_bytes())
            .into_iter()
            .any(|s| self.slice_to_composite.contains_key(&TopicHash::from_raw(s)));
        if subscribed {
            tracing::debug!("Sending received message to user");
            self.events
                .push_back(ToSwarm::GenerateEvent(Event::Message {
                    propagation_source: *propagation_source,
                    message_id: msg_id.clone(),
                    message,
                }));
        } else if !relays {
            tracing::debug!(
                topic=%message.topic,
                "Received message on a topic we are not subscribed to"
            );
            return;
        }

        // forward the message to mesh peers, if no validation is required
        if !self.config.validate_messages() {
            if self
                .forward_msg(
                    &msg_id,
                    raw_message,
                    Some(propagation_source),
                    HashSet::new(),
                )
                .is_err()
            {
                tracing::error!("Failed to forward message. Too large");
            }
            tracing::debug!(message=%msg_id, "Completed message handling for message");
        }
    }

    // Handles invalid messages received.
    fn handle_invalid_message(
        &mut self,
        propagation_source: &PeerId,
        raw_message: &RawMessage,
        reject_reason: RejectReason,
    ) {
        if let Some((peer_score, .., gossip_promises)) = &mut self.peer_score {
            if let Some(metrics) = self.metrics.as_mut() {
                metrics.register_invalid_message(&raw_message.topic);
            }

            if let Ok(message) = self.data_transform.inbound_transform(raw_message.clone()) {
                let message_id = self.config.message_id(&message);

                peer_score.reject_message(
                    propagation_source,
                    &message_id,
                    &message.topic,
                    reject_reason,
                );

                gossip_promises.reject_message(&message_id, &reject_reason);
            } else {
                // The message is invalid, we reject it ignoring any gossip promises. If a peer is
                // advertising this message via an IHAVE and it's invalid it will be double
                // penalized, one for sending us an invalid and again for breaking a promise.
                peer_score.reject_invalid_message(propagation_source, &raw_message.topic);
            }
        }
    }

    /// Handles received subscriptions.
    fn handle_received_subscriptions(
        &mut self,
        subscriptions: &[Subscription],
        propagation_source: &PeerId,
    ) {
        tracing::debug!(
            source=%propagation_source,
            "Handling subscriptions: {:?}",
            subscriptions,
        );

        let mut unsubscribed_peers = Vec::new();

        let Some(subscribed_topics) = self.peer_topics.get_mut(propagation_source) else {
            tracing::error!(
                peer=%propagation_source,
                "Subscription by unknown peer"
            );
            return;
        };

        // Collect potential graft topics for the peer.
        let mut topics_to_graft = Vec::new();

        // Notify the application about the subscription, after the grafts are sent.
        let mut application_event = Vec::new();

        let filtered_topics = match self
            .subscription_filter
            .filter_incoming_subscriptions(subscriptions, subscribed_topics)
        {
            Ok(topics) => topics,
            Err(s) => {
                tracing::error!(
                    peer=%propagation_source,
                    "Subscription filter error: {}; ignoring RPC from peer",
                    s
                );
                return;
            }
        };

        for subscription in filtered_topics {
            // get the peers from the mapping, or insert empty lists if the topic doesn't exist
            let topic_hash = &subscription.topic_hash;
            let peer_list = self.topic_peers.entry(topic_hash.clone()).or_default();

            match subscription.action {
                SubscriptionAction::Subscribe => {
                    if peer_list.insert(*propagation_source) {
                        tracing::debug!(
                            peer=%propagation_source,
                            topic=%topic_hash,
                            "SUBSCRIPTION: Adding gossip peer to topic"
                        );
                    }

                    // add to the peer_topics mapping
                    subscribed_topics.insert(topic_hash.clone());

                    // if the mesh needs peers add the peer to the mesh
                    if !self.explicit_peers.contains(propagation_source)
                        && matches!(
                            self.connected_peers
                                .get(propagation_source)
                                .map(|v| &v.kind),
                            Some(PeerKind::Gossipsubv1_1) | Some(PeerKind::Gossipsub)
                        )
                        && !Self::score_below_threshold_from_scores(
                            &self.peer_score,
                            propagation_source,
                            |_| 0.0,
                        )
                        .0
                        && !self
                            .backoffs
                            .is_backoff_with_slack(topic_hash, propagation_source)
                    {
                        if let Some(peers) = self.mesh.get_mut(topic_hash) {
                            if peers.len() < self.config.mesh_n_low()
                                && peers.insert(*propagation_source)
                            {
                                tracing::debug!(
                                    peer=%propagation_source,
                                    topic=%topic_hash,
                                    "SUBSCRIPTION: Adding peer to the mesh for topic"
                                );
                                if let Some(m) = self.metrics.as_mut() {
                                    m.peers_included(topic_hash, Inclusion::Subscribed, 1)
                                }
                                // send graft to the peer
                                tracing::debug!(
                                    peer=%propagation_source,
                                    topic=%topic_hash,
                                    "Sending GRAFT to peer for topic"
                                );
                                if let Some((peer_score, ..)) = &mut self.peer_score {
                                    peer_score.graft(propagation_source, topic_hash.clone());
                                }
                                topics_to_graft.push(topic_hash.clone());
                            }
                        }
                    }
                    // generates a subscription event to be polled
                    application_event.push(ToSwarm::GenerateEvent(Event::Subscribed {
                        peer_id: *propagation_source,
                        topic: topic_hash.clone(),
                    }));
                }
                SubscriptionAction::Unsubscribe => {
                    if peer_list.remove(propagation_source) {
                        tracing::debug!(
                            peer=%propagation_source,
                            topic=%topic_hash,
                            "SUBSCRIPTION: Removing gossip peer from topic"
                        );
                    }

                    // remove topic from the peer_topics mapping
                    subscribed_topics.remove(topic_hash);
                    unsubscribed_peers.push((*propagation_source, topic_hash.clone()));
                    // generate an unsubscribe event to be polled
                    application_event.push(ToSwarm::GenerateEvent(Event::Unsubscribed {
                        peer_id: *propagation_source,
                        topic: topic_hash.clone(),
                    }));
                }
            }

            let prune_empty = peer_list.is_empty();
            if let Some(m) = self.metrics.as_mut() {
                m.set_topic_peers(topic_hash, peer_list.len());
            }
            // Prune the now-empty peer-supplied bitmask key so repeated
            // subscribe/unsubscribe cycles can't leak unbounded map keys.
            if prune_empty {
                self.topic_peers.remove(topic_hash);
            }
        }

        // remove unsubscribed peers from the mesh if it exists
        for (peer_id, topic_hash) in unsubscribed_peers {
            self.remove_peer_from_mesh(&peer_id, &topic_hash, None, false, Churn::Unsub);
        }

        // Potentially inform the handler if we have added this peer to a mesh for the first time.
        let topics_joined = topics_to_graft.iter().collect::<Vec<_>>();
        if !topics_joined.is_empty() {
            peer_added_to_mesh(
                *propagation_source,
                topics_joined,
                &self.mesh,
                self.peer_topics.get(propagation_source),
                &mut self.events,
                &self.connected_peers,
            );
        }

        // If we need to send grafts to peer, do so immediately, rather than waiting for the
        // heartbeat.
        for action in topics_to_graft
            .into_iter()
            .map(|topic_hash| ControlAction::Graft { topic_hash })
            .collect::<Vec<_>>()
        {
            self.send_message(*propagation_source, RpcOut::Control(action))
        }

        // Notify the application of the subscriptions
        for event in application_event {
            self.events.push_back(event);
        }

        // A newly-announcing peer that COVERS the slices of one of our under-D
        // composites should be folded into it (same/broker) — this is how a
        // covering relay joins after we already ran `join_composite`.
        self.reclassify_composites_for_peer(*propagation_source);

        tracing::trace!(
            source=%propagation_source,
            "Completed handling subscriptions from source"
        );
    }

    /// Applies penalties to peers that did not respond to our IWANT requests.
    fn apply_iwant_penalties(&mut self) {
        if let Some((peer_score, .., gossip_promises)) = &mut self.peer_score {
            for (peer, count) in gossip_promises.get_broken_promises() {
                peer_score.add_penalty(&peer, count);
                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.register_score_penalty(Penalty::BrokenPromise);
                }
            }
        }
    }

    /// Heartbeat function which shifts the memcache and updates the mesh.
    fn heartbeat(&mut self) {
        tracing::debug!("Starting heartbeat");
        let start = Instant::now();

        self.heartbeat_ticks += 1;

        let mut to_graft = HashMap::new();
        let mut to_prune = HashMap::new();
        let mut no_px = HashSet::new();

        // clean up expired backoffs
        self.backoffs.heartbeat();

        // clean up ihave counters
        self.count_sent_iwant.clear();
        self.count_received_ihave.clear();

        // apply iwant penalties
        self.apply_iwant_penalties();

        // check connections to explicit peers
        if self.heartbeat_ticks % self.config.check_explicit_peers_ticks() == 0 {
            for p in self.explicit_peers.clone() {
                self.check_explicit_peer_connection(&p);
            }
        }

        // Cache the scores of all connected peers, and record metrics for current penalties.
        let mut scores = HashMap::with_capacity(self.connected_peers.len());
        if let Some((peer_score, ..)) = &self.peer_score {
            for peer_id in self.connected_peers.keys() {
                scores
                    .entry(peer_id)
                    .or_insert_with(|| peer_score.metric_score(peer_id, self.metrics.as_mut()));
            }
        }

        // Snapshot every connected peer's /24·/48 subnet buckets ONCE, so the
        // per-topic mesh-fill loops below (which hold a mutable borrow of
        // `self.mesh` and can't call `&self` helpers) can enforce the
        // per-subnet mesh cap without re-borrowing `self`. Reuses the scorer's
        // per-peer IP set (P6) — no second IP map.
        let subnet_cap = self.config.mesh_peers_per_subnet();
        let mut peer_buckets: HashMap<PeerId, HashSet<[u8; 16]>> = HashMap::new();
        if subnet_cap > 0 {
            if let Some((peer_score, ..)) = &self.peer_score {
                for peer_id in self.connected_peers.keys() {
                    if let Some(ips) = peer_score.peer_ips(peer_id) {
                        if !ips.is_empty() {
                            peer_buckets.insert(
                                *peer_id,
                                ips.iter().map(|ip| subnet_bucket_key(*ip)).collect(),
                            );
                        }
                    }
                }
            }
        }
        // Filter a fresh graft-candidate list through the per-subnet cap,
        // seeding the accepted-bucket counts from the peers already in the
        // mesh. Each accepted candidate updates the counts for the next, so a
        // single fill can't itself over-fill one subnet. Returns the admitted
        // subset (input order preserved). A no-op passthrough when disabled.
        let subnet_filter = |existing: &[PeerId], candidates: Vec<PeerId>| -> Vec<PeerId> {
            if subnet_cap == 0 {
                return candidates;
            }
            let mut accepted: HashMap<[u8; 16], usize> = HashMap::new();
            for p in existing {
                if let Some(bs) = peer_buckets.get(p) {
                    for b in bs {
                        *accepted.entry(*b).or_insert(0) += 1;
                    }
                }
            }
            let mut kept = Vec::with_capacity(candidates.len());
            for p in candidates {
                if let Some(bs) = peer_buckets.get(&p) {
                    if !bs.is_empty()
                        && bs
                            .iter()
                            .any(|b| accepted.get(b).copied().unwrap_or(0) >= subnet_cap)
                    {
                        continue;
                    }
                    for b in bs {
                        *accepted.entry(*b).or_insert(0) += 1;
                    }
                }
                kept.push(p);
            }
            kept
        };

        // PURE composite slice meshes are maintained by the per-composite pass
        // below (D total same+broker peers), NOT by this per-slice D
        // maintenance — a slice's peers subscribe to WHOLE bitmasks, so
        // `topic_peers[slice]` is empty and per-slice grafting would be a no-op
        // that only fights `rebuild_slice_meshes`. A DUAL-ROLE slice that is
        // ALSO a simple single-bit subscription (`self.subscriptions`) is NOT
        // skipped: it must run normal D-maintenance so peers subscribed only to
        // that exact slice get grafted (F3a).
        let pure_composite_slices: HashSet<TopicHash> = self
            .slice_to_composite
            .keys()
            .filter(|s| !self.subscriptions.contains(*s))
            .cloned()
            .collect();

        // maintain the mesh for each topic
        for (topic_hash, peers) in self.mesh.iter_mut() {
            if pure_composite_slices.contains(topic_hash) {
                continue;
            }
            let explicit_peers = &self.explicit_peers;
            let backoffs = &self.backoffs;
            let topic_peers = &self.topic_peers;
            let outbound_peers = &self.outbound_peers;

            // drop all peers with negative score, without PX
            // if there is at some point a stable retain method for BTreeSet the following can be
            // written more efficiently with retain.
            let mut to_remove_peers = Vec::new();
            for peer_id in peers.iter() {
                let peer_score = *scores.get(peer_id).unwrap_or(&0.0);

                // Record the score per mesh
                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.observe_mesh_peers_score(topic_hash, peer_score);
                }

                if peer_score < 0.0 {
                    tracing::debug!(
                        peer=%peer_id,
                        score=%peer_score,
                        topic=%topic_hash,
                        "HEARTBEAT: Prune peer with negative score"
                    );

                    let current_topic = to_prune.entry(*peer_id).or_insert_with(Vec::new);
                    current_topic.push(topic_hash.clone());
                    no_px.insert(*peer_id);
                    to_remove_peers.push(*peer_id);
                }
            }

            if let Some(m) = self.metrics.as_mut() {
                m.peers_removed(topic_hash, Churn::BadScore, to_remove_peers.len())
            }

            for peer_id in to_remove_peers {
                peers.remove(&peer_id);
            }

            // too little peers - add some
            if peers.len() < self.config.mesh_n_low() {
                tracing::debug!(
                    topic=%topic_hash,
                    "HEARTBEAT: Mesh low. Topic contains: {} needs: {}",
                    peers.len(),
                    self.config.mesh_n_low()
                );
                // not enough peers - get mesh_n - current_length more
                let desired_peers = self.config.mesh_n() - peers.len();
                let peer_list = get_random_peers(
                    topic_peers,
                    &self.connected_peers,
                    topic_hash,
                    desired_peers,
                    |peer| {
                        !peers.contains(peer)
                            && !explicit_peers.contains(peer)
                            && !backoffs.is_backoff_with_slack(topic_hash, peer)
                            && *scores.get(peer).unwrap_or(&0.0) >= 0.0
                    },
                );
                // Subnet-diversity gate: drop candidates whose /24·/48 already
                // holds `subnet_cap` mesh peers (seeded from the current mesh).
                let existing: Vec<PeerId> = peers.iter().copied().collect();
                let peer_list = subnet_filter(&existing, peer_list.into_iter().collect());
                for peer in &peer_list {
                    let current_topic = to_graft.entry(*peer).or_insert_with(Vec::new);
                    current_topic.push(topic_hash.clone());
                }
                // update the mesh
                tracing::debug!("Updating mesh, new mesh: {:?}", peer_list);
                if let Some(m) = self.metrics.as_mut() {
                    m.peers_included(topic_hash, Inclusion::Random, peer_list.len())
                }
                peers.extend(peer_list);
            }

            // too many peers - remove some
            if peers.len() > self.config.mesh_n_high() {
                tracing::debug!(
                    topic=%topic_hash,
                    "HEARTBEAT: Mesh high. Topic contains: {} needs: {}",
                    peers.len(),
                    self.config.mesh_n_high()
                );
                let excess_peer_no = peers.len() - self.config.mesh_n();

                // shuffle the peers and then sort by score ascending beginning with the worst
                let mut rng = thread_rng();
                let mut shuffled = peers.iter().copied().collect::<Vec<_>>();
                shuffled.shuffle(&mut rng);
                shuffled.sort_by(|p1, p2| {
                    let score_p1 = *scores.get(p1).unwrap_or(&0.0);
                    let score_p2 = *scores.get(p2).unwrap_or(&0.0);

                    score_p1.partial_cmp(&score_p2).unwrap_or(Ordering::Equal)
                });
                // shuffle everything except the last retain_scores many peers (the best ones)
                shuffled[..peers.len() - self.config.retain_scores()].shuffle(&mut rng);

                // count total number of outbound peers
                let mut outbound = {
                    let outbound_peers = &self.outbound_peers;
                    shuffled
                        .iter()
                        .filter(|p| outbound_peers.contains(*p))
                        .count()
                };

                // remove the first excess_peer_no allowed (by outbound restrictions) peers adding
                // them to to_prune
                let mut removed = 0;
                for peer in shuffled {
                    if removed == excess_peer_no {
                        break;
                    }
                    if self.outbound_peers.contains(&peer) {
                        if outbound <= self.config.mesh_outbound_min() {
                            // do not remove anymore outbound peers
                            continue;
                        } else {
                            // an outbound peer gets removed
                            outbound -= 1;
                        }
                    }

                    // remove the peer
                    peers.remove(&peer);
                    let current_topic = to_prune.entry(peer).or_insert_with(Vec::new);
                    current_topic.push(topic_hash.clone());
                    removed += 1;
                }

                if let Some(m) = self.metrics.as_mut() {
                    m.peers_removed(topic_hash, Churn::Excess, removed)
                }
            }

            // do we have enough outbound peers?
            if peers.len() >= self.config.mesh_n_low() {
                // count number of outbound peers we have
                let outbound = { peers.iter().filter(|p| outbound_peers.contains(*p)).count() };

                // if we have not enough outbound peers, graft to some new outbound peers
                if outbound < self.config.mesh_outbound_min() {
                    let needed = self.config.mesh_outbound_min() - outbound;
                    let peer_list = get_random_peers(
                        topic_peers,
                        &self.connected_peers,
                        topic_hash,
                        needed,
                        |peer| {
                            !peers.contains(peer)
                                && !explicit_peers.contains(peer)
                                && !backoffs.is_backoff_with_slack(topic_hash, peer)
                                && *scores.get(peer).unwrap_or(&0.0) >= 0.0
                                && outbound_peers.contains(peer)
                        },
                    );
                    for peer in &peer_list {
                        let current_topic = to_graft.entry(*peer).or_insert_with(Vec::new);
                        current_topic.push(topic_hash.clone());
                    }
                    // update the mesh
                    tracing::debug!("Updating mesh, new mesh: {:?}", peer_list);
                    if let Some(m) = self.metrics.as_mut() {
                        m.peers_included(topic_hash, Inclusion::Outbound, peer_list.len())
                    }
                    peers.extend(peer_list);
                }
            }

            // should we try to improve the mesh with opportunistic grafting?
            if self.heartbeat_ticks % self.config.opportunistic_graft_ticks() == 0
                && peers.len() > 1
                && self.peer_score.is_some()
            {
                if let Some((_, thresholds, _, _)) = &self.peer_score {
                    // Opportunistic grafting works as follows: we check the median score of peers
                    // in the mesh; if this score is below the opportunisticGraftThreshold, we
                    // select a few peers at random with score over the median.
                    // The intention is to (slowly) improve an underperforming mesh by introducing
                    // good scoring peers that may have been gossiping at us. This allows us to
                    // get out of sticky situations where we are stuck with poor peers and also
                    // recover from churn of good peers.

                    // now compute the median peer score in the mesh
                    let mut peers_by_score: Vec<_> = peers.iter().collect();
                    peers_by_score.sort_by(|p1, p2| {
                        let p1_score = *scores.get(p1).unwrap_or(&0.0);
                        let p2_score = *scores.get(p2).unwrap_or(&0.0);
                        p1_score.partial_cmp(&p2_score).unwrap_or(Equal)
                    });

                    let middle = peers_by_score.len() / 2;
                    let median = if peers_by_score.len() % 2 == 0 {
                        let sub_middle_peer = *peers_by_score
                            .get(middle - 1)
                            .expect("middle < vector length and middle > 0 since peers.len() > 0");
                        let sub_middle_score = *scores.get(sub_middle_peer).unwrap_or(&0.0);
                        let middle_peer =
                            *peers_by_score.get(middle).expect("middle < vector length");
                        let middle_score = *scores.get(middle_peer).unwrap_or(&0.0);

                        (sub_middle_score + middle_score) * 0.5
                    } else {
                        *scores
                            .get(*peers_by_score.get(middle).expect("middle < vector length"))
                            .unwrap_or(&0.0)
                    };

                    // if the median score is below the threshold, select a better peer (if any) and
                    // GRAFT
                    if median < thresholds.opportunistic_graft_threshold {
                        let peer_list = get_random_peers(
                            topic_peers,
                            &self.connected_peers,
                            topic_hash,
                            self.config.opportunistic_graft_peers(),
                            |peer_id| {
                                !peers.contains(peer_id)
                                    && !explicit_peers.contains(peer_id)
                                    && !backoffs.is_backoff_with_slack(topic_hash, peer_id)
                                    && *scores.get(peer_id).unwrap_or(&0.0) > median
                            },
                        );
                        // Subnet-diversity gate on opportunistic grafts too.
                        let existing: Vec<PeerId> = peers.iter().copied().collect();
                        let peer_list =
                            subnet_filter(&existing, peer_list.into_iter().collect());
                        for peer in &peer_list {
                            let current_topic = to_graft.entry(*peer).or_insert_with(Vec::new);
                            current_topic.push(topic_hash.clone());
                        }
                        // update the mesh
                        tracing::debug!(
                            topic=%topic_hash,
                            "Opportunistically graft in topic with peers {:?}",
                            peer_list
                        );
                        if let Some(m) = self.metrics.as_mut() {
                            m.peers_included(topic_hash, Inclusion::Random, peer_list.len())
                        }
                        peers.extend(peer_list);
                    }
                }
            }
            // Register the final count of peers in the mesh
            if let Some(m) = self.metrics.as_mut() {
                m.set_mesh_peers(topic_hash, peers.len())
            }
        }

        // ---- Per-composite mesh maintenance ----
        // Maintain D TOTAL same+broker peers per composite (not D per slice):
        // evict disconnected / negative-score members, fill to D with covering
        // peers, prune excess over Dhi (dropping brokers/low-score first), then
        // rebuild the derived slice meshes. GRAFT/PRUNE are emitted through the
        // shared `to_graft`/`to_prune` maps keyed by the WHOLE composite bitmask.
        {
            let d = self.config.mesh_n();
            let d_high = self.config.mesh_n_high();
            let composite_keys: Vec<TopicHash> = self.composites.keys().cloned().collect();
            for key in composite_keys {
                let (slices, same_now, broker_now) = match self.composites.get(&key) {
                    Some(c) => (
                        c.slices.clone(),
                        c.same.iter().copied().collect::<Vec<_>>(),
                        c.broker.iter().copied().collect::<Vec<_>>(),
                    ),
                    None => continue,
                };

                // 1) Evict disconnected or negative-score members.
                let mut to_evict: Vec<PeerId> = Vec::new();
                for p in same_now.iter().chain(broker_now.iter()) {
                    let connected = self.connected_peers.contains_key(p);
                    let score = *scores.get(p).unwrap_or(&0.0);
                    if !connected || score < 0.0 {
                        to_evict.push(*p);
                    }
                }
                if !to_evict.is_empty() {
                    if let Some(comp) = self.composites.get_mut(&key) {
                        for p in &to_evict {
                            comp.same.remove(p);
                            comp.broker.remove(p);
                        }
                    }
                    for p in &to_evict {
                        to_prune.entry(*p).or_insert_with(Vec::new).push(key.clone());
                        no_px.insert(*p);
                        // Fully removed from the composite (both same and broker):
                        // score it as a mesh PRUNE (applies the sticky mesh-failure
                        // penalty if it was under-delivering). Contrast with the
                        // same->broker demotion in `handle_prune`, which is NOT scored.
                        if let Some((peer_score, ..)) = &mut self.peer_score {
                            peer_score.prune(p, key.clone());
                        }
                    }
                }

                // 2) Fill to D with covering peers (same preferred, then broker).
                let total = self
                    .composites
                    .get(&key)
                    .map(|c| c.total_peers())
                    .unwrap_or(0);
                if total < d {
                    let needed = d - total;
                    let existing: HashSet<PeerId> = self
                        .composites
                        .get(&key)
                        .map(|c| c.same.iter().chain(c.broker.iter()).copied().collect())
                        .unwrap_or_default();
                    let mut added_same: Vec<PeerId> = Vec::new();
                    let mut added_broker: Vec<PeerId> = Vec::new();
                    // Subnet-diversity gate for the composite fill: seed the
                    // accepted-bucket counts from the composite's current
                    // members so a fill can't over-fill one /24·/48.
                    let mut accepted_buckets: HashMap<[u8; 16], usize> = HashMap::new();
                    if subnet_cap > 0 {
                        for p in &existing {
                            if let Some(bs) = peer_buckets.get(p) {
                                for b in bs {
                                    *accepted_buckets.entry(*b).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                    for (peer, subs) in &self.peer_topics {
                        if added_same.len() + added_broker.len() >= needed {
                            break;
                        }
                        if existing.contains(peer)
                            || self.explicit_peers.contains(peer)
                            || self.backoffs.is_backoff_with_slack(&key, peer)
                            || *scores.get(peer).unwrap_or(&0.0) < 0.0
                        {
                            continue;
                        }
                        // Skip candidates whose subnet is already at the cap.
                        if subnet_cap > 0 {
                            if let Some(bs) = peer_buckets.get(peer) {
                                if !bs.is_empty()
                                    && bs.iter().any(|b| {
                                        accepted_buckets.get(b).copied().unwrap_or(0) >= subnet_cap
                                    })
                                {
                                    continue;
                                }
                            }
                        }
                        let selected =
                            if slices.iter().all(|s| Self::peer_covers_slice(subs, s)) {
                                added_same.push(*peer);
                                true
                            } else if slices.iter().any(|s| Self::peer_covers_slice(subs, s)) {
                                added_broker.push(*peer);
                                true
                            } else {
                                false
                            };
                        // Count the admitted peer's buckets so the next
                        // candidate in the same subnet is capped.
                        if selected && subnet_cap > 0 {
                            if let Some(bs) = peer_buckets.get(peer) {
                                for b in bs {
                                    *accepted_buckets.entry(*b).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                    if let Some(comp) = self.composites.get_mut(&key) {
                        for p in &added_same {
                            comp.same.insert(*p);
                        }
                        for p in &added_broker {
                            comp.broker.insert(*p);
                        }
                    }
                    for p in added_same.iter().chain(added_broker.iter()) {
                        to_graft.entry(*p).or_insert_with(Vec::new).push(key.clone());
                        if let Some((peer_score, ..)) = &mut self.peer_score {
                            peer_score.graft(p, key.clone());
                        }
                    }
                }

                // 3) Prune excess over Dhi down to D (brokers first, then by
                //    ascending score).
                let total = self
                    .composites
                    .get(&key)
                    .map(|c| c.total_peers())
                    .unwrap_or(0);
                if total > d_high {
                    let excess = total - d;
                    let (mut brokers, mut sames): (Vec<PeerId>, Vec<PeerId>) = self
                        .composites
                        .get(&key)
                        .map(|c| {
                            (
                                c.broker.iter().copied().collect(),
                                c.same.iter().copied().collect(),
                            )
                        })
                        .unwrap_or_default();
                    let score_of =
                        |p: &PeerId| -> f64 { *scores.get(p).unwrap_or(&0.0) };
                    brokers.sort_by(|a, b| {
                        score_of(a).partial_cmp(&score_of(b)).unwrap_or(Equal)
                    });
                    sames.sort_by(|a, b| {
                        score_of(a).partial_cmp(&score_of(b)).unwrap_or(Equal)
                    });
                    let to_drop: Vec<PeerId> = brokers
                        .into_iter()
                        .chain(sames.into_iter())
                        .take(excess)
                        .collect();
                    if let Some(comp) = self.composites.get_mut(&key) {
                        for p in &to_drop {
                            comp.same.remove(p);
                            comp.broker.remove(p);
                        }
                    }
                    for p in &to_drop {
                        to_prune.entry(*p).or_insert_with(Vec::new).push(key.clone());
                        // Fully removed from the composite: score it as a mesh PRUNE.
                        if let Some((peer_score, ..)) = &mut self.peer_score {
                            peer_score.prune(p, key.clone());
                        }
                    }
                }

                // 4) Rebuild the derived slice meshes from final membership.
                //    Inlined (rather than calling `rebuild_slice_meshes`) because
                //    `scores` holds an immutable borrow of `self.connected_peers`
                //    which forbids a whole-`&mut self` method call here; the
                //    `&self` reads + field-level `self.mesh` mutation below are
                //    disjoint and allowed. Union across all owners (F4) + preserve
                //    simple-subscription peers on dual-role slices (F3b).
                let slices = match self.composites.get(&key) {
                    Some(c) => c.slices.clone(),
                    None => Vec::new(),
                };
                for slice in slices {
                    let members = self.composite_members_for_slice(&slice);
                    let dual_role = self.subscriptions.contains(&slice);
                    let entry = self.mesh.entry(slice).or_default();
                    if !dual_role {
                        entry.clear();
                    }
                    entry.extend(members);
                }
            }
        }

        // remove expired fanout topics
        {
            let fanout = &mut self.fanout; // help the borrow checker
            let fanout_ttl = self.config.fanout_ttl();
            self.fanout_last_pub.retain(|topic_hash, last_pub_time| {
                if *last_pub_time + fanout_ttl < Instant::now() {
                    tracing::debug!(
                        topic=%topic_hash,
                        "HEARTBEAT: Fanout topic removed due to timeout"
                    );
                    fanout.remove(topic_hash);
                    return false;
                }
                true
            });
        }

        // maintain fanout
        // check if our peers are still a part of the topic
        for (topic_hash, peers) in self.fanout.iter_mut() {
            let mut to_remove_peers = Vec::new();
            let publish_threshold = match &self.peer_score {
                Some((_, thresholds, _, _)) => thresholds.publish_threshold,
                _ => 0.0,
            };
            for peer in peers.iter() {
                // is the peer still subscribed to the topic?
                let peer_score = *scores.get(peer).unwrap_or(&0.0);
                match self.peer_topics.get(peer) {
                    Some(topics) => {
                        if !topics.contains(topic_hash) || peer_score < publish_threshold {
                            tracing::debug!(
                                topic=%topic_hash,
                                "HEARTBEAT: Peer removed from fanout for topic"
                            );
                            to_remove_peers.push(*peer);
                        }
                    }
                    None => {
                        // remove if the peer has disconnected
                        to_remove_peers.push(*peer);
                    }
                }
            }
            for to_remove in to_remove_peers {
                peers.remove(&to_remove);
            }

            // not enough peers
            if peers.len() < self.config.mesh_n() {
                tracing::debug!(
                    "HEARTBEAT: Fanout low. Contains: {:?} needs: {:?}",
                    peers.len(),
                    self.config.mesh_n()
                );
                let needed_peers = self.config.mesh_n() - peers.len();
                let explicit_peers = &self.explicit_peers;
                let new_peers = get_random_peers(
                    &self.topic_peers,
                    &self.connected_peers,
                    topic_hash,
                    needed_peers,
                    |peer_id| {
                        !peers.contains(peer_id)
                            && !explicit_peers.contains(peer_id)
                            && *scores.get(peer_id).unwrap_or(&0.0) < publish_threshold
                    },
                );
                peers.extend(new_peers);
            }
        }

        if self.peer_score.is_some() {
            tracing::trace!("Mesh message deliveries: {:?}", {
                self.mesh
                    .iter()
                    .map(|(t, peers)| {
                        (
                            t.clone(),
                            peers
                                .iter()
                                .map(|p| {
                                    (
                                        *p,
                                        self.peer_score
                                            .as_ref()
                                            .expect("peer_score.is_some()")
                                            .0
                                            .mesh_message_deliveries(p, t)
                                            .unwrap_or(0.0),
                                    )
                                })
                                .collect::<HashMap<PeerId, f64>>(),
                        )
                    })
                    .collect::<HashMap<TopicHash, HashMap<PeerId, f64>>>()
            })
        }

        self.emit_gossip();

        // send graft/prunes
        if !to_graft.is_empty() | !to_prune.is_empty() {
            self.send_graft_prune(to_graft, to_prune, no_px);
        }

        // piggyback pooled control messages
        self.flush_control_pool();

        // shift the memcache
        self.mcache.shift();

        tracing::debug!("Completed Heartbeat");
        if let Some(metrics) = self.metrics.as_mut() {
            let duration = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            metrics.observe_heartbeat_duration(duration);
        }
    }

    /// Emits gossip - Send IHAVE messages to a random set of gossip peers. This is applied to mesh
    /// and fanout peers
    fn emit_gossip(&mut self) {
        let mut rng = thread_rng();
        for (topic_hash, peers) in self.mesh.iter().chain(self.fanout.iter()) {
            let mut message_ids = self.mcache.get_gossip_message_ids(topic_hash);
            if message_ids.is_empty() {
                continue;
            }

            // if we are emitting more than GossipSubMaxIHaveLength message_ids, truncate the list
            if message_ids.len() > self.config.max_ihave_length() {
                // we do the truncation (with shuffling) per peer below
                tracing::debug!(
                    "too many messages for gossip; will truncate IHAVE list ({} messages)",
                    message_ids.len()
                );
            } else {
                // shuffle to emit in random order
                message_ids.shuffle(&mut rng);
            }

            // dynamic number of peers to gossip based on `gossip_factor` with minimum `gossip_lazy`
            let n_map = |m| {
                max(
                    self.config.gossip_lazy(),
                    (self.config.gossip_factor() * m as f64) as usize,
                )
            };
            // get gossip_lazy random peers
            let to_msg_peers = get_random_peers_dynamic(
                &self.topic_peers,
                &self.connected_peers,
                topic_hash,
                n_map,
                |peer| {
                    !peers.contains(peer)
                        && !self.explicit_peers.contains(peer)
                        && !self.score_below_threshold(peer, |ts| ts.gossip_threshold).0
                },
            );

            tracing::debug!("Gossiping IHAVE to {} peers", to_msg_peers.len());

            for peer in to_msg_peers {
                let mut peer_message_ids = message_ids.clone();

                if peer_message_ids.len() > self.config.max_ihave_length() {
                    // We do this per peer so that we emit a different set for each peer.
                    // we have enough redundancy in the system that this will significantly increase
                    // the message coverage when we do truncate.
                    peer_message_ids.partial_shuffle(&mut rng, self.config.max_ihave_length());
                    peer_message_ids.truncate(self.config.max_ihave_length());
                }

                // send an IHAVE message
                Self::control_pool_add(
                    &mut self.control_pool,
                    peer,
                    ControlAction::IHave {
                        topic_hash: topic_hash.clone(),
                        message_ids: peer_message_ids,
                    },
                );
            }
        }
    }

    /// Handles multiple GRAFT/PRUNE messages and coalesces them into chunked gossip control
    /// messages.
    fn send_graft_prune(
        &mut self,
        to_graft: HashMap<PeerId, Vec<TopicHash>>,
        mut to_prune: HashMap<PeerId, Vec<TopicHash>>,
        no_px: HashSet<PeerId>,
    ) {
        // handle the grafts and overlapping prunes per peer
        for (peer, topics) in to_graft.into_iter() {
            for topic in &topics {
                // inform scoring of graft
                if let Some((peer_score, ..)) = &mut self.peer_score {
                    peer_score.graft(&peer, topic.clone());
                }

                // inform the handler of the peer being added to the mesh
                // If the peer did not previously exist in any mesh, inform the handler
                peer_added_to_mesh(
                    peer,
                    vec![topic],
                    &self.mesh,
                    self.peer_topics.get(&peer),
                    &mut self.events,
                    &self.connected_peers,
                );
            }
            let control_msgs = topics.iter().map(|topic_hash| ControlAction::Graft {
                topic_hash: topic_hash.clone(),
            });

            // If there are prunes associated with the same peer add them.
            // NOTE: In this case a peer has been added to a topic mesh, and removed from another.
            // It therefore must be in at least one mesh and we do not need to inform the handler
            // of its removal from another.

            // The following prunes are not due to unsubscribing.
            let prunes = to_prune
                .remove(&peer)
                .into_iter()
                .flatten()
                .map(|topic_hash| {
                    self.make_prune(
                        &topic_hash,
                        &peer,
                        self.config.do_px() && !no_px.contains(&peer),
                        false,
                    )
                });

            // send the control messages
            for msg in control_msgs.chain(prunes).collect::<Vec<_>>() {
                self.send_message(peer, RpcOut::Control(msg));
            }
        }

        // handle the remaining prunes
        // The following prunes are not due to unsubscribing.
        for (peer, topics) in to_prune.iter() {
            for topic_hash in topics {
                let prune = self.make_prune(
                    topic_hash,
                    peer,
                    self.config.do_px() && !no_px.contains(peer),
                    false,
                );
                self.send_message(*peer, RpcOut::Control(prune));

                // inform the handler
                peer_removed_from_mesh(
                    *peer,
                    topic_hash,
                    &self.mesh,
                    self.peer_topics.get(peer),
                    &mut self.events,
                    &self.connected_peers,
                );
            }
        }
    }

    /// Helper function which forwards a message to mesh\[topic\] peers.
    ///
    /// Returns true if at least one peer was messaged.
    #[allow(clippy::unnecessary_wraps)]
    fn forward_msg(
        &mut self,
        msg_id: &MessageId,
        message: RawMessage,
        propagation_source: Option<&PeerId>,
        originating_peers: HashSet<PeerId>,
    ) -> Result<bool, PublishError> {
        // message is fully validated inform peer_score
        if let Some((peer_score, ..)) = &mut self.peer_score {
            if let Some(peer) = propagation_source {
                peer_score.deliver_message(peer, msg_id, &message.topic);
            }
        }

        tracing::debug!(message=%msg_id, "Forwarding message");
        let mut recipient_peers = HashSet::new();

        {
            // Populate the recipient peers mapping

            // Add explicit peers
            for peer_id in &self.explicit_peers {
                if let Some(topics) = self.peer_topics.get(peer_id) {
                    if Some(peer_id) != propagation_source
                        && !originating_peers.contains(peer_id)
                        && Some(peer_id) != message.source.as_ref()
                        && topics.contains(&message.topic)
                    {
                        recipient_peers.insert(*peer_id);
                    }
                }
            }

            // add mesh peers (composite-aware: simple mesh + composite
            // same/broker + covering per-slice meshes).
            for peer_id in self.mesh_recipients(&message.topic) {
                if Some(&peer_id) != propagation_source
                    && !originating_peers.contains(&peer_id)
                    && Some(&peer_id) != message.source.as_ref()
                {
                    recipient_peers.insert(peer_id);
                }
            }
        }

        // Suppress-on-send (IDONTWANT): drop any recipient that has told us it
        // already has this message.
        recipient_peers.retain(|peer| !self.peer_does_not_want(peer, msg_id));

        // Devnet partition hook: drop the relay to a target when an installed
        // forward filter disallows propagation_source→target.
        if let (Some(filter), Some(source)) = (&self.forward_filter, propagation_source) {
            recipient_peers.retain(|peer| filter(source, peer));
        }

        // forward the message to peers
        if !recipient_peers.is_empty() {
            // Emit-on-new-message (IDONTWANT): tell our mesh recipients we now
            // have this message so they can suppress any in-flight duplicate
            // headed our way (gossipsub-1.2). Only for messages at/above the
            // size threshold — small high-rate messages (e.g. consensus votes)
            // aren't worth the extra control traffic.
            if message.data.len() >= self.config.idontwant_message_size_threshold() {
                self.send_idontwant(msg_id, &recipient_peers);
            }

            let event = RpcOut::Forward(message.clone());

            for peer in recipient_peers.iter() {
                tracing::debug!(%peer, message=%msg_id, "Sending message to peer");
                self.send_message(*peer, event.clone());
            }
            tracing::debug!("Completed forwarding message");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Constructs a [`RawMessage`] performing message signing if required.
    pub(crate) fn build_raw_message(
        &mut self,
        topic: TopicHash,
        data: Vec<u8>,
    ) -> Result<RawMessage, PublishError> {
        match &mut self.publish_config {
            PublishConfig::Signing {
                ref keypair,
                author,
                inline_key,
                last_seq_no,
            } => {
                let sequence_number = last_seq_no.next();

                let signature = {
                    let message = pb::Message {
                        from: author.to_bytes(),
                        data: data.clone(),
                        seqno: sequence_number.to_be_bytes().to_vec(),
                        bitmask: topic.clone().into_bytes(),
                        signature: Vec::new(),
                        key: Vec::new(),
                    };

                    // the signature is over the bytes "libp2p-pubsub:<protobuf-message>"
                    let mut signature_bytes = SIGNING_PREFIX.to_vec();
                    message
                        .encode(&mut signature_bytes)
                        .expect("Vec<u8> is an infallible prost encode target");
                    Some(keypair.sign(&signature_bytes)?)
                };

                Ok(RawMessage {
                    source: Some(*author),
                    data,
                    // To be interoperable with the go-implementation this is treated as a 64-bit
                    // big-endian uint.
                    sequence_number: Some(sequence_number),
                    topic,
                    signature,
                    key: inline_key.clone(),
                    validated: true, // all published messages are valid
                })
            }
            PublishConfig::Author(peer_id) => {
                Ok(RawMessage {
                    source: Some(*peer_id),
                    data,
                    // To be interoperable with the go-implementation this is treated as a 64-bit
                    // big-endian uint.
                    sequence_number: Some(rand::random()),
                    topic,
                    signature: None,
                    key: None,
                    validated: true, // all published messages are valid
                })
            }
            PublishConfig::RandomAuthor => {
                Ok(RawMessage {
                    source: Some(PeerId::random()),
                    data,
                    // To be interoperable with the go-implementation this is treated as a 64-bit
                    // big-endian uint.
                    sequence_number: Some(rand::random()),
                    topic,
                    signature: None,
                    key: None,
                    validated: true, // all published messages are valid
                })
            }
            PublishConfig::Anonymous => {
                Ok(RawMessage {
                    source: None,
                    data,
                    // To be interoperable with the go-implementation this is treated as a 64-bit
                    // big-endian uint.
                    sequence_number: None,
                    topic,
                    signature: None,
                    key: None,
                    validated: true, // all published messages are valid
                })
            }
        }
    }

    // adds a control action to control_pool
    fn control_pool_add(
        control_pool: &mut HashMap<PeerId, Vec<ControlAction>>,
        peer: PeerId,
        control: ControlAction,
    ) {
        control_pool.entry(peer).or_default().push(control);
    }

    /// Takes each per-peer pool of control actions and turns it into a SINGLE
    /// piggybacked RPC per peer (one `pb::Rpc` carrying all pooled
    /// IHAVE/IWANT/GRAFT/PRUNE/IDONTWANT sub-messages), rather than one RPC per
    /// action.
    fn flush_control_pool(&mut self) {
        for (peer, controls) in self.control_pool.drain().collect::<Vec<_>>() {
            if controls.is_empty() {
                continue;
            }
            self.send_message(peer, RpcOut::Controls(controls));
        }

        // This clears all pending IWANT messages
        self.pending_iwant_msgs.clear();
    }

    /// Send a [`RpcOut`] message to a peer. This will wrap the message in an arc if it
    /// is not already an arc.
    fn send_message(&mut self, peer_id: PeerId, rpc: RpcOut) {
        if let Some(m) = self.metrics.as_mut() {
            if let RpcOut::Publish(ref message) | RpcOut::Forward(ref message) = rpc {
                // register bytes sent on the internal metrics.
                m.msg_sent(&message.topic, message.raw_protobuf_len());
            }
        }

        self.events.push_back(ToSwarm::NotifyHandler {
            peer_id,
            event: HandlerIn::Message(rpc),
            handler: NotifyHandler::Any,
        });
    }

    fn on_connection_established(
        &mut self,
        ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint,
            other_established,
            ..
        }: ConnectionEstablished,
    ) {
        // Diverging from the go implementation we only want to consider a peer as outbound peer
        // if its first connection is outbound.

        if endpoint.is_dialer() && other_established == 0 && !self.px_peers.contains(&peer_id) {
            // The first connection is outbound and it is not a peer from peer exchange => mark
            // it as outbound peer
            self.outbound_peers.insert(peer_id);
        }

        // Add the IP to the peer scoring system
        if let Some((peer_score, ..)) = &mut self.peer_score {
            if let Some(ip) = get_ip_addr(endpoint.get_remote_address()) {
                peer_score.add_ip(&peer_id, ip);
            } else {
                tracing::trace!(
                    peer=%peer_id,
                    "Couldn't extract ip from endpoint of peer with endpoint {:?}",
                    endpoint
                )
            }
        }

        // By default we assume a peer is only a floodsub peer.
        //
        // The protocol negotiation occurs once a message is sent/received. Once this happens we
        // update the type of peer that this is in order to determine which kind of routing should
        // occur.
        self.connected_peers
            .entry(peer_id)
            .or_insert(PeerConnections {
                kind: PeerKind::Floodsub,
                connections: vec![],
            })
            .connections
            .push(connection_id);

        if other_established > 0 {
            return; // Not our first connection to this peer, hence nothing to do.
        }

        // Insert an empty set of the topics of this peer until known.
        self.peer_topics.insert(peer_id, Default::default());

        if let Some((peer_score, ..)) = &mut self.peer_score {
            peer_score.add_peer(peer_id);
        }

        // Ignore connections from blacklisted peers.
        if self.blacklisted_peers.contains(&peer_id) {
            tracing::debug!(peer=%peer_id, "Ignoring connection from blacklisted peer");
            return;
        }

        tracing::debug!(peer=%peer_id, "New peer connected");
        // We need to send our subscriptions to the newly-connected node.
        for topic_hash in self.mesh.clone().into_keys() {
            self.send_message(peer_id, RpcOut::Subscribe(topic_hash));
        }
    }

    fn on_connection_closed(
        &mut self,
        ConnectionClosed {
            peer_id,
            connection_id,
            endpoint,
            remaining_established,
            ..
        }: ConnectionClosed,
    ) {
        // Remove IP from peer scoring system
        if let Some((peer_score, ..)) = &mut self.peer_score {
            if let Some(ip) = get_ip_addr(endpoint.get_remote_address()) {
                peer_score.remove_ip(&peer_id, &ip);
            } else {
                tracing::trace!(
                    peer=%peer_id,
                    "Couldn't extract ip from endpoint of peer with endpoint {:?}",
                    endpoint
                )
            }
        }

        if remaining_established != 0 {
            // Remove the connection from the list
            if let Some(connections) = self.connected_peers.get_mut(&peer_id) {
                let index = connections
                    .connections
                    .iter()
                    .position(|v| v == &connection_id)
                    .expect("Previously established connection to peer must be present");
                connections.connections.remove(index);

                // If there are more connections and this peer is in a mesh, inform the first connection
                // handler.
                if !connections.connections.is_empty() {
                    if let Some(topics) = self.peer_topics.get(&peer_id) {
                        for topic in topics {
                            if let Some(mesh_peers) = self.mesh.get(topic) {
                                if mesh_peers.contains(&peer_id) {
                                    self.events.push_back(ToSwarm::NotifyHandler {
                                        peer_id,
                                        event: HandlerIn::JoinedMesh,
                                        handler: NotifyHandler::One(connections.connections[0]),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // remove from mesh, topic_peers, peer_topic and the fanout
            tracing::debug!(peer=%peer_id, "Peer disconnected");
            {
                let Some(topics) = self.peer_topics.get(&peer_id) else {
                    debug_assert!(
                        self.blacklisted_peers.contains(&peer_id),
                        "Disconnected node not in connected list"
                    );
                    return;
                };

                // remove peer from all mappings
                for topic in topics {
                    // check the mesh for the topic
                    if let Some(mesh_peers) = self.mesh.get_mut(topic) {
                        // check if the peer is in the mesh and remove it
                        if mesh_peers.remove(&peer_id) {
                            if let Some(m) = self.metrics.as_mut() {
                                m.peers_removed(topic, Churn::Dc, 1);
                                m.set_mesh_peers(topic, mesh_peers.len());
                            }
                        };
                    }

                    // remove from topic_peers
                    if let Some(peer_list) = self.topic_peers.get_mut(topic) {
                        if !peer_list.remove(&peer_id) {
                            // debugging purposes
                            tracing::debug!(
                                peer=%peer_id,
                                "Disconnected node: peer not in topic_peers"
                            );
                        }
                        if let Some(m) = self.metrics.as_mut() {
                            m.set_topic_peers(topic, peer_list.len())
                        }
                        // Prune the now-empty key: `topic_peers` is keyed by the
                        // peer-supplied bitmask, so leaving empty `topic ->
                        // {}` entries lets an attacker leak unbounded map keys
                        // across connect/subscribe/disconnect cycles (cleanup
                        // otherwise only shrinks the set, never the key).
                        if peer_list.is_empty() {
                            self.topic_peers.remove(topic);
                        }
                    } else {
                        tracing::debug!(
                            peer=%peer_id,
                            topic=%topic,
                            "Disconnected node: peer with topic not in topic_peers"
                        );
                    }

                    // remove from fanout
                    self.fanout
                        .get_mut(topic)
                        .map(|peers| peers.remove(&peer_id));
                }
            }

            // Remove the peer from any composite mesh membership (same/broker).
            // Composites are our fork's addition and are NOT covered by the
            // per-topic mesh/topic_peers cleanup above. A disconnected peer left
            // lingering in `same`/`broker` gets prune-iterated later by
            // `leave()`/heartbeat and — being absent from `connected_peers` —
            // trips the "unknown peer" prune warning and previously panicked in
            // `peer_removed_from_mesh`. Drop it here so composite state stays in
            // sync with the connection table.
            for comp in self.composites.values_mut() {
                comp.same.remove(&peer_id);
                comp.broker.remove(&peer_id);
            }

            // Forget px and outbound status for this peer
            self.px_peers.remove(&peer_id);
            self.outbound_peers.remove(&peer_id);

            // Remove peer from peer_topics and connected_peers
            // NOTE: It is possible the peer has already been removed from all mappings if it does not
            // support the protocol.
            self.peer_topics.remove(&peer_id);

            // If metrics are enabled, register the disconnection of a peer based on its protocol.
            if let Some(metrics) = self.metrics.as_mut() {
                let peer_kind = &self
                    .connected_peers
                    .get(&peer_id)
                    .expect("Connected peer must be registered")
                    .kind;
                metrics.peer_protocol_disconnected(peer_kind.clone());
            }

            self.connected_peers.remove(&peer_id);
            self.peer_idontwant.remove(&peer_id);

            if let Some((peer_score, ..)) = &mut self.peer_score {
                peer_score.remove_peer(&peer_id);
            }
        }
    }

    fn on_address_change(
        &mut self,
        AddressChange {
            peer_id,
            old: endpoint_old,
            new: endpoint_new,
            ..
        }: AddressChange,
    ) {
        // Exchange IP in peer scoring system
        if let Some((peer_score, ..)) = &mut self.peer_score {
            if let Some(ip) = get_ip_addr(endpoint_old.get_remote_address()) {
                peer_score.remove_ip(&peer_id, &ip);
            } else {
                tracing::trace!(
                    peer=%&peer_id,
                    "Couldn't extract ip from endpoint of peer with endpoint {:?}",
                    endpoint_old
                )
            }
            if let Some(ip) = get_ip_addr(endpoint_new.get_remote_address()) {
                peer_score.add_ip(&peer_id, ip);
            } else {
                tracing::trace!(
                    peer=%peer_id,
                    "Couldn't extract ip from endpoint of peer with endpoint {:?}",
                    endpoint_new
                )
            }
        }
    }
}

fn get_ip_addr(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Ip4(addr) => Some(IpAddr::V4(addr)),
        Ip6(addr) => Some(IpAddr::V6(addr)),
        _ => None,
    })
}

/// Map an IP to its diversity bucket key. IPv4 → /24 in the high 3 bytes
/// (rest zero). IPv6 → /48 in the first 6 bytes (rest zero). Different
/// families never collide in practice: the v4 form zeroes bytes [3..16], and
/// a real v6 /48 that starts `00.00.00` is the IPv4-mapped reserved range, not
/// used as an independent prefix. Ported from quil-p2p behaviour.rs.
pub(crate) fn subnet_bucket_key(ip: IpAddr) -> [u8; 16] {
    let mut out = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            out[..3].copy_from_slice(&octets[..3]);
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            out[..6].copy_from_slice(&octets[..6]);
        }
    }
    out
}

impl<C, F> NetworkBehaviour for Behaviour<C, F>
where
    C: Send + 'static + DataTransform,
    F: Send + 'static + TopicSubscriptionFilter,
{
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.config.protocol_config()))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.config.protocol_config()))
    }

    fn on_connection_handler_event(
        &mut self,
        propagation_source: PeerId,
        _connection_id: ConnectionId,
        handler_event: THandlerOutEvent<Self>,
    ) {
        match handler_event {
            HandlerEvent::PeerKind(kind) => {
                // We have identified the protocol this peer is using

                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.peer_protocol_connected(kind.clone());
                }

                if let PeerKind::NotSupported = kind {
                    tracing::debug!(
                        peer=%propagation_source,
                        "Peer does not support gossipsub protocols"
                    );
                    self.events
                        .push_back(ToSwarm::GenerateEvent(Event::GossipsubNotSupported {
                            peer_id: propagation_source,
                        }));
                } else if let Some(conn) = self.connected_peers.get_mut(&propagation_source) {
                    // Only change the value if the old value is Floodsub (the default set in
                    // `NetworkBehaviour::on_event` with FromSwarm::ConnectionEstablished).
                    // All other PeerKind changes are ignored.
                    tracing::debug!(
                        peer=%propagation_source,
                        peer_type=%kind,
                        "New peer type found for peer"
                    );
                    if let PeerKind::Floodsub = conn.kind {
                        conn.kind = kind;
                    }
                }
            }
            HandlerEvent::Message {
                rpc,
                invalid_messages,
            } => {
                // Handle the gossipsub RPC

                // Handle subscriptions
                // Update connected peers topics
                if !rpc.subscriptions.is_empty() {
                    self.handle_received_subscriptions(&rpc.subscriptions, &propagation_source);
                }

                // Check if peer is graylisted in which case we ignore the event
                if let (true, _) =
                    self.score_below_threshold(&propagation_source, |pst| pst.graylist_threshold)
                {
                    tracing::debug!(peer=%propagation_source, "RPC Dropped from greylisted peer");
                    return;
                }

                // Handle any invalid messages from this peer
                if self.peer_score.is_some() {
                    for (raw_message, validation_error) in invalid_messages {
                        self.handle_invalid_message(
                            &propagation_source,
                            &raw_message,
                            RejectReason::ValidationError(validation_error),
                        )
                    }
                } else {
                    // log the invalid messages
                    for (message, validation_error) in invalid_messages {
                        tracing::debug!(
                            peer=%propagation_source,
                            source=?message.source,
                            "Invalid message from peer. Reason: {:?}",
                            validation_error,
                        );
                    }
                }

                // Handle messages
                for (count, raw_message) in rpc.messages.into_iter().enumerate() {
                    // Only process the amount of messages the configuration allows.
                    if self.config.max_messages_per_rpc().is_some()
                        && Some(count) >= self.config.max_messages_per_rpc()
                    {
                        tracing::debug!("Received more messages than permitted. Ignoring further messages. Processed: {}", count);
                        break;
                    }
                    self.handle_received_message(raw_message, &propagation_source);
                }

                // Handle control messages
                // group some control messages, this minimises SendEvents (code is simplified to handle each event at a time however)
                let mut ihave_msgs = vec![];
                let mut graft_msgs = vec![];
                let mut prune_msgs = vec![];
                for control_msg in rpc.control_msgs {
                    match control_msg {
                        ControlAction::IHave {
                            topic_hash,
                            message_ids,
                        } => {
                            ihave_msgs.push((topic_hash, message_ids));
                        }
                        ControlAction::IWant { message_ids } => {
                            self.handle_iwant(&propagation_source, message_ids)
                        }
                        ControlAction::Graft { topic_hash } => graft_msgs.push(topic_hash),
                        ControlAction::Prune {
                            topic_hash,
                            peers,
                            backoff,
                        } => prune_msgs.push((topic_hash, peers, backoff)),
                        ControlAction::IDontWant { message_ids } => {
                            self.handle_idontwant(&propagation_source, message_ids)
                        }
                    }
                }
                if !ihave_msgs.is_empty() {
                    self.handle_ihave(&propagation_source, ihave_msgs);
                }
                if !graft_msgs.is_empty() {
                    self.handle_graft(&propagation_source, graft_msgs);
                }
                if !prune_msgs.is_empty() {
                    self.handle_prune(&propagation_source, prune_msgs);
                }
            }
        }
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        // update scores
        if let Some((peer_score, _, interval, _)) = &mut self.peer_score {
            while let Poll::Ready(Some(_)) = interval.poll_next_unpin(cx) {
                peer_score.refresh_scores();
            }
        }

        while let Poll::Ready(Some(_)) = self.heartbeat.poll_next_unpin(cx) {
            self.heartbeat();
        }

        Poll::Pending
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(connection_established) => {
                self.on_connection_established(connection_established)
            }
            FromSwarm::ConnectionClosed(connection_closed) => {
                self.on_connection_closed(connection_closed)
            }
            FromSwarm::AddressChange(address_change) => self.on_address_change(address_change),
            _ => {}
        }
    }
}

/// This is called when peers are added to any mesh. It checks if the peer existed
/// in any other mesh. If this is the first mesh they have joined, it queues a message to notify
/// the appropriate connection handler to maintain a connection.
fn peer_added_to_mesh(
    peer_id: PeerId,
    new_topics: Vec<&TopicHash>,
    mesh: &HashMap<TopicHash, BTreeSet<PeerId>>,
    known_topics: Option<&BTreeSet<TopicHash>>,
    events: &mut VecDeque<ToSwarm<Event, HandlerIn>>,
    connections: &HashMap<PeerId, PeerConnections>,
) {
    // Ensure there is an active connection. Mirror of `peer_removed_from_mesh`:
    // this only exists to notify the handler that a peer joined a mesh, so if
    // the peer is not connected there is nothing to do — return rather than
    // panic (a panic here kills the swarm task and exits the node).
    let Some(connection_id) = connections
        .get(&peer_id)
        .and_then(|conn| conn.connections.first().copied())
    else {
        return;
    };

    if let Some(topics) = known_topics {
        for topic in topics {
            if !new_topics.contains(&topic) {
                if let Some(mesh_peers) = mesh.get(topic) {
                    if mesh_peers.contains(&peer_id) {
                        // the peer is already in a mesh for another topic
                        return;
                    }
                }
            }
        }
    }
    // This is the first mesh the peer has joined, inform the handler
    events.push_back(ToSwarm::NotifyHandler {
        peer_id,
        event: HandlerIn::JoinedMesh,
        handler: NotifyHandler::One(connection_id),
    });
}

/// This is called when peers are removed from a mesh. It checks if the peer exists
/// in any other mesh. If this is the last mesh they have joined, we return true, in order to
/// notify the handler to no longer maintain a connection.
fn peer_removed_from_mesh(
    peer_id: PeerId,
    old_topic: &TopicHash,
    mesh: &HashMap<TopicHash, BTreeSet<PeerId>>,
    known_topics: Option<&BTreeSet<TopicHash>>,
    events: &mut VecDeque<ToSwarm<Event, HandlerIn>>,
    connections: &HashMap<PeerId, PeerConnections>,
) {
    // Ensure there is an active connection. The sole purpose of this function
    // is to notify the handler to stop maintaining the connection for a peer
    // that left a mesh — if the peer is no longer connected (e.g. a composite
    // `same`/`broker` member that disconnected before `leave`/PRUNE ran) there
    // is nothing to notify, so bail out gracefully instead of panicking. A
    // panic here kills the whole swarm task and exits the node.
    let Some(connection_id) = connections
        .get(&peer_id)
        .and_then(|c| c.connections.first())
    else {
        return;
    };

    if let Some(topics) = known_topics {
        for topic in topics {
            if topic != old_topic {
                if let Some(mesh_peers) = mesh.get(topic) {
                    if mesh_peers.contains(&peer_id) {
                        // the peer exists in another mesh still
                        return;
                    }
                }
            }
        }
    }
    // The peer is not in any other mesh, inform the handler
    events.push_back(ToSwarm::NotifyHandler {
        peer_id,
        event: HandlerIn::LeftMesh,
        handler: NotifyHandler::One(*connection_id),
    });
}

/// Helper function to get a subset of random gossipsub peers for a `topic_hash`
/// filtered by the function `f`. The number of peers to get equals the output of `n_map`
/// that gets as input the number of filtered peers.
fn get_random_peers_dynamic(
    topic_peers: &HashMap<TopicHash, BTreeSet<PeerId>>,
    connected_peers: &HashMap<PeerId, PeerConnections>,
    topic_hash: &TopicHash,
    // maps the number of total peers to the number of selected peers
    n_map: impl Fn(usize) -> usize,
    mut f: impl FnMut(&PeerId) -> bool,
) -> BTreeSet<PeerId> {
    let mut gossip_peers = match topic_peers.get(topic_hash) {
        // if they exist, filter the peers by `f`
        Some(peer_list) => peer_list
            .iter()
            .copied()
            .filter(|p| {
                f(p) && match connected_peers.get(p) {
                    Some(connections) if connections.kind == PeerKind::Gossipsub => true,
                    Some(connections) if connections.kind == PeerKind::Gossipsubv1_1 => true,
                    _ => false,
                }
            })
            .collect(),
        None => Vec::new(),
    };

    // if we have less than needed, return them
    let n = n_map(gossip_peers.len());
    if gossip_peers.len() <= n {
        tracing::debug!("RANDOM PEERS: Got {:?} peers", gossip_peers.len());
        return gossip_peers.into_iter().collect();
    }

    // we have more peers than needed, shuffle them and return n of them
    let mut rng = thread_rng();
    gossip_peers.partial_shuffle(&mut rng, n);

    tracing::debug!("RANDOM PEERS: Got {:?} peers", n);

    gossip_peers.into_iter().take(n).collect()
}

/// Helper function to get a set of `n` random gossipsub peers for a `topic_hash`
/// filtered by the function `f`.
fn get_random_peers(
    topic_peers: &HashMap<TopicHash, BTreeSet<PeerId>>,
    connected_peers: &HashMap<PeerId, PeerConnections>,
    topic_hash: &TopicHash,
    n: usize,
    f: impl FnMut(&PeerId) -> bool,
) -> BTreeSet<PeerId> {
    get_random_peers_dynamic(topic_peers, connected_peers, topic_hash, |_| n, f)
}

/// Validates the combination of signing, privacy and message validation to ensure the
/// configuration will not reject published messages.
fn validate_config(
    authenticity: &MessageAuthenticity,
    validation_mode: &ValidationMode,
) -> Result<(), &'static str> {
    match validation_mode {
        ValidationMode::Anonymous => {
            if authenticity.is_signing() {
                return Err("Cannot enable message signing with an Anonymous validation mode. Consider changing either the ValidationMode or MessageAuthenticity");
            }

            if !authenticity.is_anonymous() {
                return Err("Published messages contain an author but incoming messages with an author will be rejected. Consider adjusting the validation or privacy settings in the config");
            }
        }
        ValidationMode::Strict => {
            if !authenticity.is_signing() {
                return Err(
                    "Messages will be
                published unsigned and incoming unsigned messages will be rejected. Consider adjusting
                the validation or privacy settings in the config"
                );
            }
        }
        _ => {}
    }
    Ok(())
}

impl<C: DataTransform, F: TopicSubscriptionFilter> fmt::Debug for Behaviour<C, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Behaviour")
            .field("config", &self.config)
            .field("events", &self.events.len())
            .field("control_pool", &self.control_pool)
            .field("publish_config", &self.publish_config)
            .field("topic_peers", &self.topic_peers)
            .field("peer_topics", &self.peer_topics)
            .field("mesh", &self.mesh)
            .field("fanout", &self.fanout)
            .field("fanout_last_pub", &self.fanout_last_pub)
            .field("mcache", &self.mcache)
            .field("heartbeat", &self.heartbeat)
            .finish()
    }
}

impl fmt::Debug for PublishConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublishConfig::Signing { author, .. } => {
                f.write_fmt(format_args!("PublishConfig::Signing({author})"))
            }
            PublishConfig::Author(author) => {
                f.write_fmt(format_args!("PublishConfig::Author({author})"))
            }
            PublishConfig::RandomAuthor => f.write_fmt(format_args!("PublishConfig::RandomAuthor")),
            PublishConfig::Anonymous => f.write_fmt(format_args!("PublishConfig::Anonymous")),
        }
    }
}

// Quarantined during the fork: quickcheck property test over the native RpcOut
// fragmentation/codec (replaced by the BlossomSub wire in Stage 2).
#[cfg(all(test, feature = "upstream-tests"))]
mod local_test {
    use super::*;
    use crate::IdentTopic;
    use quickcheck::*;

    fn test_message() -> RawMessage {
        RawMessage {
            source: Some(PeerId::random()),
            data: vec![0; 100],
            sequence_number: None,
            topic: TopicHash::from_raw("test_topic"),
            signature: None,
            key: None,
            validated: false,
        }
    }

    fn test_control() -> ControlAction {
        ControlAction::IHave {
            topic_hash: IdentTopic::new("TestTopic").hash(),
            message_ids: vec![MessageId(vec![12u8]); 5],
        }
    }

    impl Arbitrary for RpcOut {
        fn arbitrary(g: &mut Gen) -> Self {
            match u8::arbitrary(g) % 5 {
                0 => RpcOut::Subscribe(IdentTopic::new("TestTopic").hash()),
                1 => RpcOut::Unsubscribe(IdentTopic::new("TestTopic").hash()),
                2 => RpcOut::Publish(test_message()),
                3 => RpcOut::Forward(test_message()),
                4 => RpcOut::Control(test_control()),
                _ => panic!("outside range"),
            }
        }
    }
}

// Stage-3 composite same/broker overlap mesh tests. These are NOT gated behind
// the quarantined `upstream-tests` feature — they run on the default test
// build. Ported from the `composites`/`join_composite`/`mesh_recipients`/broker
// tests in `quil-p2p`'s `behaviour.rs`.
#[cfg(test)]
mod composite_behaviour_tests {
    use super::*;
    use crate::config::Config;

    type Gs = Behaviour<IdentityTransform, AllowAllSubscriptionFilter>;

    fn new_gs() -> Gs {
        let keypair = Keypair::generate_ed25519();
        Behaviour::new(MessageAuthenticity::Signed(keypair), Config::default()).unwrap()
    }

    /// A two-slice (0xC0 = 0x80 | 0x40) composite bitmask and its two slices.
    fn two_slice() -> (TopicHash, [TopicHash; 2]) {
        (
            TopicHash::from_raw(vec![0xC0]),
            [TopicHash::from_raw(vec![0x80]), TopicHash::from_raw(vec![0x40])],
        )
    }

    /// Record that `peer` advertised the given WHOLE bitmasks (as a remote
    /// SUBSCRIBE would), populating `peer_topics`, `topic_peers`, and a
    /// gossipsub-v1.1 connection so mesh-add hooks (`peer_added_to_mesh`,
    /// `get_random_peers`) see it as connected.
    fn seed_peer_subs(gs: &mut Gs, peer: PeerId, subs: &[TopicHash]) {
        gs.connected_peers.entry(peer).or_insert_with(|| PeerConnections {
            kind: PeerKind::Gossipsubv1_1,
            connections: vec![ConnectionId::new_unchecked(0)],
        });
        for s in subs {
            gs.peer_topics.entry(peer).or_default().insert(s.clone());
        }
        for s in subs {
            gs.topic_peers.entry(s.clone()).or_default().insert(peer);
        }
    }

    /// join_composite forms a `same` set for a peer covering ALL slices and a
    /// `broker` set for a peer covering only SOME slices.
    #[test]
    fn composite_forms_same_and_broker_sets() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();

        let full = PeerId::random(); // covers both slices
        let partial = PeerId::random(); // covers only slice 0
        seed_peer_subs(&mut gs, full, &slices);
        seed_peer_subs(&mut gs, partial, &[slices[0].clone()]);

        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        let comp = &gs.composites[&bitmask];
        assert!(comp.same.contains(&full), "full-coverage peer must be 'same'");
        assert!(!comp.broker.contains(&full));
        assert!(comp.broker.contains(&partial), "partial peer must be 'broker'");
        assert!(!comp.same.contains(&partial));

        // Every composite member (same + broker) is in EVERY slice mesh.
        for s in &slices {
            assert!(gs.mesh[s].contains(&full));
            assert!(gs.mesh[s].contains(&partial));
        }
    }

    /// `mesh_peers_for_subscription` reports the COMPOSITE mesh size for a
    /// multi-slice bitmask, where the raw `mesh_peers(whole)` returns 0 (the
    /// whole composite key never lands in `self.mesh`, which is keyed by
    /// slices). This is the metric NeedPeers / mesh-health gauges must use so a
    /// healthy composite mesh is not perpetually seen as empty.
    #[test]
    fn mesh_peers_for_subscription_counts_composite_mesh() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();

        // Five full-coverage ("same") peers + one partial ("broker") peer → a
        // healthy composite mesh well above d_lo (mesh_n_low defaults to 5).
        for _ in 0..5 {
            let full = PeerId::random();
            seed_peer_subs(&mut gs, full, &slices);
        }
        let partial = PeerId::random();
        seed_peer_subs(&mut gs, partial, &[slices[0].clone()]);

        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        let comp = &gs.composites[&bitmask];
        let total = comp.total_peers();
        assert!(
            total >= gs.config.mesh_n_low(),
            "composite mesh (same+broker) should be a healthy >= d_lo, got {total}"
        );

        // The raw per-slice-keyed lookup on the WHOLE bitmask sees nothing…
        assert_eq!(
            gs.mesh_peers(&bitmask).count(),
            0,
            "whole composite bitmask is never a `mesh` key → raw mesh_peers == 0"
        );
        // …but the composite-aware metric reports the real mesh size.
        assert_eq!(
            gs.mesh_peers_for_subscription(&bitmask),
            total,
            "composite-aware count must equal the composite total_peers()"
        );
        assert!(
            gs.mesh_peers_for_subscription(&bitmask) >= gs.config.mesh_n_low(),
            "healthy composite mesh must be >= d_lo so NeedPeers does not fire"
        );

        // A SIMPLE (single-slice) bitmask still returns mesh[slice].len().
        let simple = slices[0].clone();
        assert_eq!(
            gs.mesh_peers_for_subscription(&simple),
            gs.mesh.get(&simple).map_or(0, |s| s.len()),
            "simple bitmask path unchanged (mesh[slice].len())"
        );
        assert!(
            gs.mesh_peers_for_subscription(&simple) > 0,
            "the single slice mesh was populated by the composite join"
        );
    }

    /// mesh_recipients(M) returns a peer that advertised a BULK (covering)
    /// bitmask even though it never subscribed to M's exact bitmask — the
    /// archive-relay case, driven by `bitmask_covers` coverage.
    #[test]
    fn mesh_recipients_returns_covering_bulk_subscriber() {
        let shard = TopicHash::from_raw(vec![0xC0]); // slices 0x80, 0x40
        let bulk = TopicHash::from_raw(vec![0xFF]); // covers both slices
        let mut gs = new_gs();

        let archive = PeerId::random();
        seed_peer_subs(&mut gs, archive, &[bulk.clone()]);
        // The archive never advertised the exact shard bitmask.
        assert!(!gs
            .topic_peers
            .get(&shard)
            .map_or(false, |s| s.contains(&archive)));

        gs.subscriptions.insert(shard.clone());
        gs.join_composite(&shard);

        // Covers all slices -> classified 'same'...
        assert!(gs.composites[&shard].same.contains(&archive));
        // ...and is therefore a valid publish/forward recipient.
        assert!(gs.mesh_recipients(&shard).contains(&archive));
    }

    /// Publishing to a multi-bit bitmask resolves to the composite mesh: the
    /// full composite key is absent from `self.mesh`, but `mesh_recipients`
    /// resolves it via the composite entry / slice meshes.
    #[test]
    fn composite_publish_resolves_to_composite_mesh() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();
        let peer = PeerId::random();
        seed_peer_subs(&mut gs, peer, &slices);
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        // The full composite key is (by design) NOT stored in self.mesh.
        assert!(gs.mesh.get(&bitmask).is_none());
        // Recipients resolved through the composite entry.
        assert!(gs.mesh_recipients(&bitmask).contains(&peer));
    }

    /// GRAFT of a peer covering ALL slices is classified 'same'; it lands in
    /// every slice mesh.
    #[test]
    fn graft_of_peer_covering_all_slices_classified_same() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        let peer = PeerId::random();
        seed_peer_subs(&mut gs, peer, &slices);

        gs.handle_graft(&peer, vec![slices[0].clone()]);
        assert!(gs.composites[&bitmask].same.contains(&peer));
        assert!(!gs.composites[&bitmask].broker.contains(&peer));
        for s in &slices {
            assert!(gs.mesh[s].contains(&peer), "broker/same must be in slice mesh");
        }
    }

    /// GRAFT of a peer covering only SOME slices is classified 'broker'; a
    /// broker is nonetheless placed into EVERY slice mesh (it bridges).
    #[test]
    fn graft_of_peer_covering_some_slices_classified_broker() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        let peer = PeerId::random();
        seed_peer_subs(&mut gs, peer, &[slices[0].clone()]);

        gs.handle_graft(&peer, vec![slices[0].clone()]);
        assert!(!gs.composites[&bitmask].same.contains(&peer));
        assert!(gs.composites[&bitmask].broker.contains(&peer));
        for s in &slices {
            assert!(gs.mesh[s].contains(&peer));
        }
    }

    /// PRUNE of a single slice demotes a 'same' peer to 'broker' but keeps it
    /// in ALL slice meshes (brokers bridge non-subscribed slices); no backoff
    /// is installed for a composite slice.
    #[test]
    fn prune_single_slice_demotes_same_to_broker_keeps_slices() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        let peer = PeerId::random();
        seed_peer_subs(&mut gs, peer, &slices);

        gs.handle_graft(&peer, vec![slices[0].clone()]);
        assert!(gs.composites[&bitmask].same.contains(&peer));

        gs.handle_prune(&peer, vec![(slices[0].clone(), Vec::new(), None)]);
        assert!(!gs.composites[&bitmask].same.contains(&peer), "no longer same");
        assert!(gs.composites[&bitmask].broker.contains(&peer), "now broker");
        for s in &slices {
            assert!(
                gs.mesh[s].contains(&peer),
                "broker must remain in slice mesh after single-slice PRUNE"
            );
        }
        // No backoff installed for a composite slice.
        assert!(!gs.backoffs.is_backoff_with_slack(&slices[0], &peer));
    }

    /// After a partial PRUNE demotes a peer to broker, re-GRAFTing it while it
    /// still covers all slices promotes broker -> same again.
    #[test]
    fn graft_after_partial_prune_restores_same() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        let peer = PeerId::random();
        seed_peer_subs(&mut gs, peer, &slices);

        gs.handle_graft(&peer, vec![slices[0].clone()]);
        gs.handle_prune(&peer, vec![(slices[0].clone(), Vec::new(), None)]);
        assert!(gs.composites[&bitmask].broker.contains(&peer));

        gs.handle_graft(&peer, vec![slices[0].clone()]);
        assert!(gs.composites[&bitmask].same.contains(&peer), "promoted to same");
        assert!(!gs.composites[&bitmask].broker.contains(&peer), "left broker");
    }

    /// join_composite never exceeds D (= mesh_n) total same+broker peers.
    #[test]
    fn d_cap_respected() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();
        let d = gs.config.mesh_n();

        // Seed more than D covering peers before joining.
        for _ in 0..(d + 4) {
            let p = PeerId::random();
            seed_peer_subs(&mut gs, p, &slices);
        }

        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        let total = gs.composites[&bitmask].total_peers();
        assert!(total <= d, "composite must not exceed D (got {total}, D={d})");
        assert_eq!(total, d, "with >D covering peers the composite fills to D");
    }

    /// A peer that announces a covering subscription AFTER we joined the
    /// composite is folded in by reclassify_composites_for_peer.
    #[test]
    fn reclassify_folds_in_late_covering_peer() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask); // no peers known yet
        assert_eq!(gs.composites[&bitmask].total_peers(), 0);

        let peer = PeerId::random();
        seed_peer_subs(&mut gs, peer, &slices);
        gs.reclassify_composites_for_peer(peer);

        assert!(gs.composites[&bitmask].same.contains(&peer));
        for s in &slices {
            assert!(gs.mesh[s].contains(&peer));
        }
    }

    /// A single-bit bitmask is its own single slice: it routes through the
    /// simple path (no composite entry) and mesh[whole] == mesh[slice].
    #[test]
    fn single_bit_bitmask_is_simple_not_composite() {
        let mut gs = new_gs();
        let topic = TopicHash::from_raw(vec![0x80]); // one slice == whole
        assert_eq!(composite::slice_bitmask(topic.as_bytes()).len(), 1);

        let peer = PeerId::random();
        seed_peer_subs(&mut gs, peer, &[topic.clone()]);
        gs.subscriptions.insert(topic.clone());
        gs.join(&topic);

        // Simple path: no composite entry, mesh keyed by the whole bitmask.
        assert!(!gs.composites.contains_key(&topic));
        assert!(gs.mesh.contains_key(&topic));
        assert!(gs.mesh_recipients(&topic).contains(&peer));
    }

    // ------------------------------------------------------------------
    // F1-F4 two-node / real-path regressions (each FAILS before its fix).
    // ------------------------------------------------------------------

    /// F1: a whole-bitmask composite GRAFT sent by node A must be ADMITTED by
    /// node B over the real `handle_graft` path (before the fix it fell into the
    /// unknown-topic branch and was silently dropped → asymmetric mesh).
    #[test]
    fn f1_two_node_composite_graft_round_trip() {
        let (bitmask, slices) = two_slice();

        // Node A subscribes and JOINs the composite; B is a covering peer, so A
        // emits GRAFT(0xC0) to B.
        let mut a = new_gs();
        let b_id = PeerId::random();
        seed_peer_subs(&mut a, b_id, &[bitmask.clone()]); // B advertised the whole 0xC0
        a.subscriptions.insert(bitmask.clone());
        a.join(&bitmask);
        // A really emitted a whole-bitmask GRAFT(0xC0) addressed to B.
        let emitted_graft = a.control_pool.get(&b_id).map_or(false, |acts| {
            acts.iter().any(|c| {
                matches!(c, ControlAction::Graft { topic_hash } if *topic_hash == bitmask)
            })
        });
        assert!(emitted_graft, "A must emit a whole-bitmask GRAFT(0xC0) to B");

        // Node B is subscribed to the same composite and receives A's GRAFT.
        let mut b = new_gs();
        let a_id = PeerId::random();
        b.subscriptions.insert(bitmask.clone());
        b.join_composite(&bitmask);
        // Seed A as a covering peer AFTER join_composite, so ONLY the GRAFT can
        // admit A (join_composite would otherwise pre-admit it and mask F1).
        seed_peer_subs(&mut b, a_id, &[bitmask.clone()]); // B learns A covers 0xC0
        assert!(
            !b.composites[&bitmask].same.contains(&a_id)
                && !b.composites[&bitmask].broker.contains(&a_id),
            "precondition: A is not yet a composite member before the GRAFT"
        );

        b.handle_graft(&a_id, vec![bitmask.clone()]);

        // A is admitted into B's composite (covers all slices -> same)...
        assert!(
            b.composites[&bitmask].same.contains(&a_id),
            "B must admit the whole-bitmask GRAFT into the composite"
        );
        // ...and is a real routing recipient in every derived slice mesh.
        assert!(b.mesh_recipients(&bitmask).contains(&a_id));
        for s in &slices {
            assert!(b.mesh[s].contains(&a_id));
        }
    }

    /// F2: default flood_publish must reach a covering relay that advertised a
    /// SUPERSET bitmask (so it is absent from `topic_peers[M]`). Before the fix
    /// the exact-match flood path skipped it entirely.
    #[test]
    fn f2_flood_publish_reaches_covering_relay() {
        assert!(
            Config::default().flood_publish(),
            "precondition: default config floods"
        );
        let bitmask = TopicHash::from_raw(vec![0xC0]);
        let bulk = TopicHash::from_raw(vec![0xFF]); // covering superset

        let mut gs = new_gs();
        let relay = PeerId::random();
        seed_peer_subs(&mut gs, relay, &[bulk.clone()]);
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);

        // The relay never advertised the exact composite bitmask.
        assert!(!gs
            .topic_peers
            .get(&bitmask)
            .map_or(false, |s| s.contains(&relay)));

        gs.publish(bitmask.clone(), b"hello".to_vec())
            .expect("composite flood publish must find recipients");

        // The relay received a Publish RPC.
        let relay_got_publish = gs.events.iter().any(|e| {
            matches!(
                e,
                ToSwarm::NotifyHandler {
                    peer_id,
                    event: HandlerIn::Message(RpcOut::Publish(_)),
                    ..
                } if *peer_id == relay
            )
        });
        assert!(
            relay_got_publish,
            "covering relay must be a flood-publish recipient"
        );
    }

    /// F4: two composites sharing a slice must BOTH contribute to that slice's
    /// mesh. Before the fix `rebuild_slice_meshes` cleared and refilled from a
    /// single owner, clobbering the other.
    #[test]
    fn f4_two_composites_sharing_slice_union() {
        // 0xC0 = 0x80|0x40, 0xA0 = 0x80|0x20 — shared slice 0x80.
        let c0 = TopicHash::from_raw(vec![0xC0]);
        let a0 = TopicHash::from_raw(vec![0xA0]);
        let shared = TopicHash::from_raw(vec![0x80]);
        // peer_c belongs ONLY to 0xC0 (advertised 0x40); peer_a ONLY to 0xA0
        // (advertised 0x20).
        let only_c40 = TopicHash::from_raw(vec![0x40]);
        let only_a20 = TopicHash::from_raw(vec![0x20]);

        let mut gs = new_gs();
        let peer_c = PeerId::random();
        let peer_a = PeerId::random();
        seed_peer_subs(&mut gs, peer_c, &[only_c40.clone()]);
        seed_peer_subs(&mut gs, peer_a, &[only_a20.clone()]);

        gs.subscriptions.insert(c0.clone());
        gs.join_composite(&c0);
        gs.subscriptions.insert(a0.clone());
        gs.join_composite(&a0);

        // Sanity: each peer is a member of exactly one composite.
        assert!(gs.composites[&c0].broker.contains(&peer_c));
        assert!(!gs.composites[&c0].same.contains(&peer_a) && !gs.composites[&c0].broker.contains(&peer_a));
        assert!(gs.composites[&a0].broker.contains(&peer_a));

        // The shared slice mesh must contain BOTH owners' members.
        assert!(
            gs.mesh[&shared].contains(&peer_c),
            "shared slice must keep 0xC0's member"
        );
        assert!(
            gs.mesh[&shared].contains(&peer_a),
            "shared slice must also hold 0xA0's member (no clobber)"
        );
    }

    /// F3: a simple single-bit subscription (0x80) that overlaps a composite
    /// slice (0xC0 owns 0x80). Q is subscribed ONLY to 0x80; JOIN(0x80) grafts
    /// it. With the composite FULL of full-coverage peers (so Q can't be
    /// absorbed as a broker), the composite rebuild must UNION its members into
    /// mesh[0x80] rather than clobbering Q (F3b), and the heartbeat must keep
    /// maintaining the dual-role slice (F3a).
    #[test]
    fn f3_simple_sub_peer_survives_overlapping_composite() {
        let simple = TopicHash::from_raw(vec![0x80]);
        let composite_bm = TopicHash::from_raw(vec![0xC0]); // slices 0x80, 0x40

        let mut gs = new_gs();
        let d = gs.config.mesh_n();

        // Q subscribes to ONLY the exact simple slice; JOIN(0x80) grafts it.
        let q = PeerId::random();
        seed_peer_subs(&mut gs, q, &[simple.clone()]);
        gs.subscriptions.insert(simple.clone());
        gs.join(&simple);
        assert!(gs.mesh[&simple].contains(&q), "JOIN must graft the simple-sub peer");

        // Fill the overlapping composite to D with full-coverage peers, so Q
        // (covers only 0x80) can NOT be admitted as a broker — it exists in
        // mesh[0x80] purely by virtue of the simple subscription.
        for _ in 0..d {
            let p = PeerId::random();
            seed_peer_subs(&mut gs, p, &[composite_bm.clone()]);
        }
        gs.subscriptions.insert(composite_bm.clone());
        gs.join_composite(&composite_bm);
        assert_eq!(
            gs.composites[&composite_bm].total_peers(),
            d,
            "composite is full of full-coverage peers"
        );
        assert!(
            !gs.composites[&composite_bm].same.contains(&q)
                && !gs.composites[&composite_bm].broker.contains(&q),
            "Q is not a composite member"
        );

        // The composite rebuild must NOT have clobbered Q from the shared
        // dual-role slice mesh (F3b).
        assert!(
            gs.mesh[&simple].contains(&q),
            "composite rebuild must preserve the simple-sub peer"
        );

        // ...and it survives a heartbeat (dual-role slice still maintained, F3a).
        gs.heartbeat();
        assert!(
            gs.mesh_recipients(&simple).contains(&q),
            "simple-subscription peer must remain routable after heartbeat"
        );
        assert!(gs.mesh[&simple].contains(&q));
    }

    // ---- Stage 5: per-subnet mesh cap (MESH_PEERS_PER_SUBNET) ----

    /// Register `peer` with the scorer and give it a known IP (so it buckets to
    /// a /24 · /48 for the subnet cap). Mirrors how connections feed `add_ip`.
    fn seed_peer_ip(gs: &mut Gs, peer: PeerId, ip: &str) {
        let ip: std::net::IpAddr = ip.parse().unwrap();
        let (ps, ..) = gs.peer_score.as_mut().expect("scoring live by default");
        ps.add_peer(peer);
        ps.add_ip(&peer, ip);
    }

    /// `subnet_bucket_key` collapses v4 to /24 and v6 to /48; different
    /// families never collide.
    #[test]
    fn subnet_bucket_key_buckets_by_prefix() {
        use std::net::IpAddr;
        let a: IpAddr = "192.0.2.17".parse().unwrap();
        let b: IpAddr = "192.0.2.200".parse().unwrap(); // same /24
        let c: IpAddr = "192.0.3.17".parse().unwrap(); // different /24
        assert_eq!(subnet_bucket_key(a), subnet_bucket_key(b));
        assert_ne!(subnet_bucket_key(a), subnet_bucket_key(c));
        let v6a: IpAddr = "2001:db8:abcd::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8:abcd:ffff::9".parse().unwrap(); // same /48
        let v6c: IpAddr = "2001:db8:abce::1".parse().unwrap(); // different /48
        assert_eq!(subnet_bucket_key(v6a), subnet_bucket_key(v6b));
        assert_ne!(subnet_bucket_key(v6a), subnet_bucket_key(v6c));
        assert_ne!(subnet_bucket_key(a), subnet_bucket_key(v6a));
    }

    /// The helper blocks a candidate whose /24 already holds `cap` mesh peers,
    /// admits a candidate in a fresh /24, and admits a peer with no known IP.
    #[test]
    fn graft_would_violate_subnet_cap_enforces_and_skips_unknown() {
        let mut gs = new_gs(); // default cap = 2, scoring live
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let same = PeerId::random();
        let fresh = PeerId::random();
        let unknown = PeerId::random(); // deliberately no IP
        seed_peer_ip(&mut gs, p1, "192.0.2.10");
        seed_peer_ip(&mut gs, p2, "192.0.2.20"); // same /24 as p1
        seed_peer_ip(&mut gs, same, "192.0.2.30"); // same /24
        seed_peer_ip(&mut gs, fresh, "198.51.100.7"); // different /24
        let mesh = vec![p1, p2]; // both in 192.0.2.0/24 -> at cap 2
        assert!(
            gs.graft_would_violate_subnet_cap(&mesh, &same),
            "a 3rd peer in a /24 already at cap must be blocked"
        );
        assert!(
            !gs.graft_would_violate_subnet_cap(&mesh, &fresh),
            "a peer in a different /24 must be admitted"
        );
        assert!(
            !gs.graft_would_violate_subnet_cap(&mesh, &unknown),
            "a peer with no observed IP must be admitted (bucketed later)"
        );
    }

    /// cap = 0 disables the check entirely.
    #[test]
    fn subnet_cap_zero_disables_check() {
        let cfg = crate::config::ConfigBuilder::from(Config::default())
            .mesh_peers_per_subnet(0)
            .build()
            .unwrap();
        let mut gs: Gs =
            Behaviour::new(MessageAuthenticity::Signed(Keypair::generate_ed25519()), cfg)
                .unwrap();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let same = PeerId::random();
        seed_peer_ip(&mut gs, p1, "192.0.2.10");
        seed_peer_ip(&mut gs, p2, "192.0.2.20");
        seed_peer_ip(&mut gs, same, "192.0.2.30");
        assert!(
            !gs.graft_would_violate_subnet_cap(&[p1, p2], &same),
            "cap 0 must never block"
        );
    }

    /// Integration (simple mesh graft, path a): with 2 mesh peers already in a
    /// /24, an inbound GRAFT from a 3rd peer in that /24 is PRUNEd (not
    /// admitted), while a GRAFT from a different /24 is admitted.
    #[test]
    fn subnet_cap_blocks_third_simple_graft_admits_other_subnet() {
        let topic = TopicHash::from_raw(vec![0x80]); // single-bit => simple mesh
        let mut gs = new_gs();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random(); // same /24 as p1/p2
        let other = PeerId::random(); // different /24
        for p in [p1, p2, p3, other] {
            seed_peer_subs(&mut gs, p, &[topic.clone()]);
        }
        seed_peer_ip(&mut gs, p1, "192.0.2.10");
        seed_peer_ip(&mut gs, p2, "192.0.2.20");
        seed_peer_ip(&mut gs, p3, "192.0.2.30");
        seed_peer_ip(&mut gs, other, "198.51.100.9");
        // Prime the mesh with p1, p2 (both 192.0.2.0/24 -> at cap 2).
        gs.mesh
            .entry(topic.clone())
            .or_default()
            .extend([p1, p2]);

        gs.handle_graft(&p3, vec![topic.clone()]);
        assert!(
            !gs.mesh[&topic].contains(&p3),
            "3rd peer in a saturated /24 must be rejected from the simple mesh"
        );

        gs.handle_graft(&other, vec![topic.clone()]);
        assert!(
            gs.mesh[&topic].contains(&other),
            "a peer in a fresh /24 must be admitted"
        );
    }

    /// Integration (composite whole-bitmask GRAFT, path b): 2 composite members
    /// in a /24 saturate it; a 3rd peer in that /24 grafting the whole bitmask
    /// is PRUNEd, while a peer in a different /24 is admitted.
    #[test]
    fn subnet_cap_blocks_third_composite_graft_admits_other_subnet() {
        let (bitmask, slices) = two_slice();
        let mut gs = new_gs();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        // Seed p1, p2 (full coverage) BEFORE join so they become composite
        // members; join_composite is a local join and does not apply the cap.
        seed_peer_subs(&mut gs, p1, &slices);
        seed_peer_subs(&mut gs, p2, &slices);
        seed_peer_ip(&mut gs, p1, "192.0.2.10");
        seed_peer_ip(&mut gs, p2, "192.0.2.20"); // same /24
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask);
        assert!(
            gs.composites[&bitmask].same.contains(&p1)
                && gs.composites[&bitmask].same.contains(&p2),
            "precondition: both same-subnet peers are composite members"
        );

        let p3 = PeerId::random(); // same /24
        seed_peer_subs(&mut gs, p3, &slices);
        seed_peer_ip(&mut gs, p3, "192.0.2.30");
        gs.handle_graft(&p3, vec![bitmask.clone()]);
        assert!(
            !gs.composites[&bitmask].same.contains(&p3)
                && !gs.composites[&bitmask].broker.contains(&p3),
            "3rd peer in a saturated /24 must be rejected from the composite"
        );

        let other = PeerId::random(); // different /24
        seed_peer_subs(&mut gs, other, &slices);
        seed_peer_ip(&mut gs, other, "198.51.100.9");
        gs.handle_graft(&other, vec![bitmask.clone()]);
        assert!(
            gs.composites[&bitmask].same.contains(&other),
            "a peer in a fresh /24 must be admitted to the composite"
        );
    }

    /// Item 5: a direct (explicit) peer receives a composite-topic publish even
    /// though it is NOT a composite member (same/broker) and not in any slice
    /// mesh — direct peers are forwarded to outside the mesh/subnet/score
    /// system. Flood is disabled so the ONLY path to the direct peer is the
    /// explicit-peer inclusion.
    #[test]
    fn direct_peer_receives_composite_publish_outside_mesh() {
        let (bitmask, _slices) = two_slice();
        let cfg = crate::config::ConfigBuilder::from(Config::default())
            .flood_publish(false)
            .build()
            .unwrap();
        let mut gs: Gs =
            Behaviour::new(MessageAuthenticity::Signed(Keypair::generate_ed25519()), cfg)
                .unwrap();
        gs.subscriptions.insert(bitmask.clone());
        gs.join_composite(&bitmask); // no seeded peers -> empty composite mesh

        let direct = PeerId::random();
        seed_peer_subs(&mut gs, direct, &[bitmask.clone()]); // advertises 0xC0
        gs.add_explicit_peer(&direct);
        assert!(
            !gs.composites[&bitmask].same.contains(&direct)
                && !gs.composites[&bitmask].broker.contains(&direct),
            "precondition: direct peer is NOT a composite member"
        );

        gs.publish(bitmask.clone(), b"hi".to_vec())
            .expect("publish must find the direct recipient");

        let got = gs.events.iter().any(|e| {
            matches!(
                e,
                ToSwarm::NotifyHandler {
                    peer_id,
                    event: HandlerIn::Message(RpcOut::Publish(_)),
                    ..
                } if *peer_id == direct
            )
        });
        assert!(
            got,
            "a direct (explicit) peer must receive the composite publish outside the mesh"
        );
    }
}

/// Stage-4 tests: scoring is LIVE on the default-constructed behaviour, control
/// batching folds to one RPC per peer, and the IDONTWANT round trip works.
///
/// Every scoring test below reaches through `gs.peer_score` (installed by
/// default). If scoring were disabled (`peer_score: None`, as upstream
/// gossipsub ships), the `expect(...)` on `gs.peer_score.as_mut()` /
/// `gs.peer_score(&peer)` would return `None` and the test would PANIC — so
/// each test genuinely fails when scoring is off (see
/// `default_behaviour_enables_scoring` for the direct assertion).
#[cfg(test)]
mod scoring_and_control_tests {
    use super::*;
    use crate::config::Config;

    type Gs = Behaviour<IdentityTransform, AllowAllSubscriptionFilter>;

    fn new_gs() -> Gs {
        let keypair = Keypair::generate_ed25519();
        Behaviour::new(MessageAuthenticity::Signed(keypair), Config::default()).unwrap()
    }

    /// Direct proof that scoring is enabled by default (upstream ships it off).
    #[test]
    fn default_behaviour_enables_scoring() {
        let gs = new_gs();
        assert!(
            gs.peer_score.is_some(),
            "peer scoring must be LIVE on the default-constructed behaviour"
        );
    }

    /// A fresh peer at score 0 must PASS the gossip/publish/graylist gates and
    /// be UNDER the accept-px/opportunistic gates (correct for an unproven peer).
    #[test]
    fn fresh_peer_passes_negative_gates_and_is_below_positive_gates() {
        let mut gs = new_gs();
        let peer = PeerId::random();
        {
            let (ps, ..) = gs.peer_score.as_mut().expect("scoring live by default");
            ps.add_peer(peer);
        }
        // gossip / publish / graylist gate on `score < threshold` (thresholds negative).
        assert!(!gs.score_below_threshold(&peer, |t| t.gossip_threshold).0);
        assert!(!gs.score_below_threshold(&peer, |t| t.publish_threshold).0);
        assert!(!gs.score_below_threshold(&peer, |t| t.graylist_threshold).0);
        // accept-px / opportunistic gate on positive thresholds — fresh peer is below.
        assert!(gs.score_below_threshold(&peer, |t| t.accept_px_threshold).0);
    }

    /// MANDATED: after in-mesh valid deliveries a well-behaved peer scores > 0
    /// (P1 time-in-mesh + P2 first-deliveries). Also proves the
    /// `default_topic_params` fallback scores an UNREGISTERED bitmask topic.
    #[test]
    fn scoring_live_well_behaved_peer_scores_positive() {
        let mut gs = new_gs();
        let peer = PeerId::random();
        // Arbitrary bitmask topic; we never register explicit params for it.
        let topic = TopicHash::from_raw(vec![0x01, 0x00]);
        {
            let (ps, ..) = gs.peer_score.as_mut().expect("scoring live by default");
            ps.add_peer(peer);
            ps.graft(&peer, topic.clone());
            for i in 0..3u8 {
                let id = MessageId::from(vec![i]);
                ps.deliver_message(&peer, &id, &topic);
            }
        }
        let score = gs
            .peer_score(&peer)
            .expect("scoring live by default");
        assert!(
            score > 0.0,
            "well-behaved in-mesh peer must score > 0 via the default topic params, got {score}"
        );
    }

    /// MANDATED: an idle behaviour (P7) penalty decays toward 0 across
    /// `refresh_scores` ticks — proving the decay path runs on the DEFAULT
    /// behaviour (not just under `with_peer_score`).
    #[test]
    fn scoring_live_idle_penalty_decays_via_refresh() {
        let mut gs = new_gs();
        let peer = PeerId::random();
        {
            let (ps, ..) = gs.peer_score.as_mut().expect("scoring live by default");
            ps.add_peer(peer);
            ps.add_penalty(&peer, 5); // P7 behaviour penalty
        }
        let s0 = gs.peer_score(&peer).expect("scoring live");
        assert!(s0 < 0.0, "behaviour penalty must be negative, got {s0}");

        // Each refresh tick decays the penalty strictly toward 0.
        let mut prev = s0;
        for _ in 0..5 {
            gs.peer_score.as_mut().unwrap().0.refresh_scores();
            let s = gs.peer_score(&peer).unwrap();
            assert!(s > prev, "penalty must decay toward 0 each tick: prev={prev}, s={s}");
            prev = s;
        }
        // With enough ticks it fully decays to 0.
        for _ in 0..80 {
            gs.peer_score.as_mut().unwrap().0.refresh_scores();
        }
        assert_eq!(
            gs.peer_score(&peer).unwrap(),
            0.0,
            "behaviour penalty must fully decay to 0"
        );
    }

    /// MANDATED: a peer sharing an IP with many others is penalized (P6
    /// IP-colocation) via `add_ip`.
    #[test]
    fn scoring_live_ip_colocation_penalized() {
        let mut gs = new_gs();
        let shared: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let mut victim = PeerId::random();
        {
            let (ps, ..) = gs.peer_score.as_mut().expect("scoring live by default");
            // ip_colocation_factor_threshold is 3.0 — 5 peers on one IP => surplus 2.
            for i in 0..5 {
                let p = PeerId::random();
                ps.add_peer(p);
                ps.add_ip(&p, shared);
                if i == 0 {
                    victim = p;
                }
            }
        }
        let s = gs.peer_score(&victim).expect("scoring live");
        // P6: (5 - 3)^2 * -10 = -40.
        assert!(s < 0.0, "IP-colocated peer must be penalized, got {s}");
        assert!((s - (-40.0)).abs() < 1e-9, "expected -40, got {s}");
    }

    /// The per-peer control pool flushes as ONE piggybacked RPC per peer, not
    /// one RPC per action.
    #[test]
    fn flush_control_pool_batches_one_rpc_per_peer() {
        let mut gs = new_gs();
        let peer = PeerId::random();
        let topic = TopicHash::from_raw(vec![0xAA]);
        gs.control_pool.entry(peer).or_default().extend(vec![
            ControlAction::IHave {
                topic_hash: topic.clone(),
                message_ids: vec![MessageId::from(vec![1])],
            },
            ControlAction::IWant {
                message_ids: vec![MessageId::from(vec![2])],
            },
            ControlAction::Graft {
                topic_hash: topic.clone(),
            },
            ControlAction::IDontWant {
                message_ids: vec![MessageId::from(vec![3])],
            },
        ]);

        gs.flush_control_pool();

        let rpcs: Vec<RpcOut> = gs
            .events
            .iter()
            .filter_map(|ev| match ev {
                ToSwarm::NotifyHandler {
                    peer_id,
                    event: HandlerIn::Message(rpc),
                    ..
                } if *peer_id == peer => Some(rpc.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            rpcs.len(),
            1,
            "control pool must flush as ONE rpc per peer, got {}",
            rpcs.len()
        );

        let pb = rpcs.into_iter().next().unwrap().into_protobuf();
        let control = pb.control.expect("batched rpc must carry a control message");
        assert_eq!(control.ihave.len(), 1);
        assert_eq!(control.iwant.len(), 1);
        assert_eq!(control.graft.len(), 1);
        assert_eq!(control.idontwant.len(), 1);
    }

    /// IDONTWANT is recorded on receive (suppress-on-send predicate) and emitted
    /// on new-message (pooled for the mesh peer).
    #[test]
    fn idontwant_record_on_receive_and_emit_on_new_message() {
        let mut gs = new_gs();
        let peer = PeerId::random();
        let msg_id = MessageId::from(vec![7, 7, 7]);

        // Record-on-receive: forward_msg's suppression predicate now returns true.
        gs.handle_idontwant(&peer, vec![msg_id.clone()]);
        assert!(
            gs.peer_does_not_want(&peer, &msg_id),
            "IDONTWANT must be recorded on receive"
        );
        assert!(
            !gs.peer_does_not_want(&peer, &MessageId::from(vec![8])),
            "an unrelated message id must not be suppressed"
        );

        // Emit-on-new-message: pooling an IDONTWANT for our mesh recipient.
        let mut mesh = HashSet::new();
        mesh.insert(peer);
        gs.send_idontwant(&msg_id, &mesh);
        let pooled = gs
            .control_pool
            .get(&peer)
            .expect("IDONTWANT must be pooled for emission");
        assert!(
            pooled.iter().any(|c| matches!(
                c,
                ControlAction::IDontWant { message_ids } if message_ids.contains(&msg_id)
            )),
            "an IDONTWANT for the new message must be pooled to the mesh peer"
        );
    }

    /// REGRESSION (consensus-halt guard): an honest in-mesh peer on a QUIET
    /// (unregistered) bitmask that delivers ZERO messages past the P3 activation
    /// window must NOT be penalized. If the default `mesh_message_deliveries_weight`
    /// (P3) or `mesh_failure_penalty_weight` (P3b) were negative, this peer would
    /// score ~ -1.0 * threshold^2 = -400 per quiet shard, get mesh-evicted
    /// (score < 0) everywhere and graylisted across a few quiet shards ->
    /// symmetric mesh collapse. Verified to FAIL at weight -1.0 and PASS at 0.0.
    #[test]
    fn scoring_live_quiet_in_mesh_peer_not_penalized() {
        let mut gs = new_gs();
        let peer = PeerId::random();
        // Unregistered, quiet bitmask — scored only via the default topic params.
        let topic = TopicHash::from_raw(vec![0x02, 0x00]);
        {
            let (ps, ..) = gs.peer_score.as_mut().expect("scoring live by default");
            ps.add_peer(peer);
            ps.graft(&peer, topic.clone());
        }
        // Advance in-mesh PAST the 5s mesh_message_deliveries_activation window
        // (real clock, matching the sleep-based peer_score tests) delivering ZERO
        // messages, so the P3 deficit would fire at full magnitude if weighted.
        std::thread::sleep(Duration::from_millis(5250));
        gs.peer_score.as_mut().unwrap().0.refresh_scores();
        let score = gs.peer_score(&peer).expect("scoring live");
        assert!(
            score >= 0.0,
            "honest quiet in-mesh peer must NOT be penalized (P3/P3b off in default \
             params), got {score}"
        );
    }

    /// FIX 2: IDONTWANT is only emitted on a newly-forwarded message that is at
    /// or above `idontwant_message_size_threshold` (default 1000 bytes) —
    /// small high-rate messages (e.g. consensus votes) don't emit it.
    #[test]
    fn idontwant_only_emitted_for_large_messages() {
        let mut gs = new_gs();
        let topic = TopicHash::from_raw(vec![0x80]); // single-bit => simple mesh
        let peer = PeerId::random();
        gs.connected_peers.insert(
            peer,
            PeerConnections {
                kind: PeerKind::Gossipsubv1_1,
                connections: vec![ConnectionId::new_unchecked(0)],
            },
        );
        gs.peer_topics.entry(peer).or_default().insert(topic.clone());
        gs.mesh.entry(topic.clone()).or_default().insert(peer);

        assert_eq!(gs.config.idontwant_message_size_threshold(), 1024);

        let mk = |data: Vec<u8>| RawMessage {
            source: Some(PeerId::random()),
            data,
            sequence_number: Some(1),
            topic: topic.clone(),
            signature: None,
            key: None,
            validated: true,
        };
        let emitted_to_peer = |gs: &Gs| {
            gs.control_pool.get(&peer).map_or(false, |v| {
                v.iter()
                    .any(|c| matches!(c, ControlAction::IDontWant { .. }))
            })
        };

        // Below threshold: no IDONTWANT emitted.
        gs.forward_msg(&MessageId::from(vec![1]), mk(vec![0u8; 10]), None, HashSet::new())
            .unwrap();
        assert!(!emitted_to_peer(&gs), "small message must NOT emit IDONTWANT");

        // At/above threshold: IDONTWANT emitted.
        let big_id = MessageId::from(vec![2]);
        gs.forward_msg(&big_id, mk(vec![0u8; 2000]), None, HashSet::new())
            .unwrap();
        assert!(
            gs.control_pool.get(&peer).map_or(false, |v| v.iter().any(|c| matches!(
                c,
                ControlAction::IDontWant { message_ids } if message_ids.contains(&big_id)
            ))),
            "large message must emit IDONTWANT"
        );
    }
}

#[cfg(test)]
mod forward_filter_tests {
    //! Tests for the per-(source, target) forward filter used by the devnet
    //! test proxy to impose bipartite network partitions. The node relays a
    //! message to its mesh peers (excluding the propagation source); an
    //! installed filter suppresses the relay for blocked (source, target)
    //! pairs only.
    use super::*;
    use crate::config::Config;

    type Gs = Behaviour<IdentityTransform, AllowAllSubscriptionFilter>;

    /// A node subscribed to `topic` with every peer in `mesh` connected,
    /// subscribed, and grafted into the (simple, single-bit) mesh.
    fn make_node(topic: &TopicHash, mesh: &[PeerId]) -> Gs {
        let keypair = Keypair::generate_ed25519();
        let mut gs: Gs =
            Behaviour::new(MessageAuthenticity::Signed(keypair), Config::default()).unwrap();
        for &p in mesh {
            gs.connected_peers.insert(
                p,
                PeerConnections {
                    kind: PeerKind::Gossipsubv1_1,
                    connections: vec![ConnectionId::new_unchecked(0)],
                },
            );
            gs.peer_topics.entry(p).or_default().insert(topic.clone());
            gs.mesh.entry(topic.clone()).or_default().insert(p);
        }
        gs
    }

    /// Forward a message relayed by propagation source `from` and return the
    /// set of peers the node forwarded it to (the NotifyHandler targets
    /// drained from the event queue).
    fn forwarded_targets(gs: &mut Gs, from: PeerId, topic: &TopicHash, data: &[u8]) -> HashSet<PeerId> {
        gs.events.clear();
        let message = RawMessage {
            source: None,
            data: data.to_vec(),
            sequence_number: Some(1),
            topic: topic.clone(),
            signature: None,
            key: None,
            validated: true,
        };
        gs.forward_msg(&MessageId::from(data.to_vec()), message, Some(&from), HashSet::new())
            .unwrap();
        gs.events
            .iter()
            .filter_map(|ev| match ev {
                ToSwarm::NotifyHandler {
                    peer_id,
                    event: HandlerIn::Message(RpcOut::Forward(m)),
                    ..
                } if m.data == data => Some(*peer_id),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn no_filter_forwards_to_all_mesh_peers_except_source() {
        let topic = TopicHash::from_raw(vec![0x80]); // single-bit => simple mesh
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut gs = make_node(&topic, &[a, b, c]);
        let targets = forwarded_targets(&mut gs, a, &topic, b"m1");
        assert_eq!(targets, HashSet::from([b, c]));
    }

    #[test]
    fn forward_filter_blocks_only_the_named_pair() {
        let topic = TopicHash::from_raw(vec![0x80]);
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut gs = make_node(&topic, &[a, b, c]);
        // Block relay from a -> c only.
        gs.set_forward_filter(move |src, dst| !(*src == a && *dst == c));
        assert_eq!(
            forwarded_targets(&mut gs, a, &topic, b"m1"),
            HashSet::from([b]),
            "a->c blocked, a->b allowed",
        );
        // The rule is directional + source-specific: messages relayed by b are
        // unaffected and still reach both a and c.
        assert_eq!(
            forwarded_targets(&mut gs, b, &topic, b"m2"),
            HashSet::from([a, c]),
        );
    }

    #[test]
    fn clear_forward_filter_restores_all_targets() {
        let topic = TopicHash::from_raw(vec![0x80]);
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut gs = make_node(&topic, &[a, b, c]);
        gs.set_forward_filter(move |src, dst| !(*src == a && *dst == c));
        assert_eq!(forwarded_targets(&mut gs, a, &topic, b"m1"), HashSet::from([b]));
        gs.clear_forward_filter();
        assert_eq!(
            forwarded_targets(&mut gs, a, &topic, b"m2"),
            HashSet::from([b, c]),
            "clearing the filter restores the blocked target",
        );
    }
}
