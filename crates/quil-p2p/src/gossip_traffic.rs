//! Gossip traffic of this process by bitmask class, always counted.
//!
//! The pubsub behaviour reports every message copy (see
//! [`libp2p::gossipsub::TrafficObserver`]), counted four ways: `received`,
//! every copy from every peer, before duplicates are dropped; `unique`, the
//! first copy of each message; `sent`, every copy queued for a peer, our own
//! publishes and forwards alike; and `published`, the messages this process
//! published, once each. Sizes are encoded message bytes (payload, signature,
//! key and header), without control messages (IHAVE, IWANT, IDONTWANT, GRAFT,
//! PRUNE) and transport overhead, so the interface carries somewhat more.
//!
//! Each process counts its own swarm: the master's, and each standalone
//! worker's.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use libp2p::gossipsub::{TopicHash, TrafficObserver};

pub use libp2p::gossipsub::TrafficKind;

/// How often the swarm loop logs the traffic of the last interval.
pub(crate) const LOG_INTERVAL: Duration = Duration::from_secs(600);

/// The traffic class of a gossip bitmask, from the bitmask layout the engine
/// uses (`quil_engine::bitmasks`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GossipClass {
    /// Shard consensus (CW) other than votes: certificates, resolver
    /// requests and responses, and blocks (`0x01 || appFilter`).
    ShardConsensus,
    /// Shard frames (the 32-byte `appFilter`).
    ShardFrames,
    /// Shard votes: the CW vote channel, and the per-shard vote and timeout
    /// topic (`0x00 || appFilter`).
    Votes,
    /// Every GLOBAL topic but peer info: consensus, frames, CW channels,
    /// prover messages and alerts.
    Global,
    /// Peer info and key registry messages (`GLOBAL_PEER_INFO`).
    PeerInfo,
    /// Shard prover and dispatch topics, and any other bitmask.
    Other,
}

const CLASSES: usize = 6;

/// Length of a shard's `appFilter`, the shard frame bitmask.
const APP_FILTER_LEN: usize = 32;
/// The CW channel of votes, in the low bits of a shard CW payload's first
/// byte; the top bit flags a nonce.
const CW_VOTE_CHANNEL: u8 = 0;
const CW_NONCE_FLAG: u8 = 0x80;

impl GossipClass {
    pub const ALL: [GossipClass; CLASSES] = [
        GossipClass::ShardConsensus,
        GossipClass::ShardFrames,
        GossipClass::Votes,
        GossipClass::Global,
        GossipClass::PeerInfo,
        GossipClass::Other,
    ];

    /// The class's name in logs and in the node's status.
    pub const fn name(self) -> &'static str {
        match self {
            GossipClass::ShardConsensus => "shard_consensus",
            GossipClass::ShardFrames => "shard_frames",
            GossipClass::Votes => "votes",
            GossipClass::Global => "global",
            GossipClass::PeerInfo => "peer_info",
            GossipClass::Other => "other",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.name() == name)
    }

    /// The class of a message with payload `data` on `bitmask`.
    pub fn of_bitmask(bitmask: &[u8], data: &[u8]) -> Self {
        classify(bitmask.len(), |i| bitmask.get(i).copied(), data)
    }

    /// The class of a message on a gossip topic, whose string is the hex
    /// of its bitmask. Decodes only the bytes it needs, without allocating.
    pub fn of_topic(topic: &str, data: &[u8]) -> Self {
        let hex = topic.as_bytes();
        if hex.len() % 2 != 0 {
            return GossipClass::Other;
        }
        classify(hex.len() / 2, |i| hex_byte(hex, i), data)
    }

    fn index(self) -> usize {
        self as usize
    }
}

fn hex_byte(hex: &[u8], i: usize) -> Option<u8> {
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    Some(nibble(*hex.get(2 * i)?)? << 4 | nibble(*hex.get(2 * i + 1)?)?)
}

fn classify(len: usize, byte: impl Fn(usize) -> Option<u8>, data: &[u8]) -> GossipClass {
    let zero = |n: usize| (0..n).all(|i| byte(i) == Some(0));
    match len {
        // GLOBAL_CONSENSUS, GLOBAL_PROVER, GLOBAL_ALERT.
        1 | 3 | 16 if zero(len) => GossipClass::Global,
        // GLOBAL_FRAME and the GLOBAL CW channels.
        2 if byte(0) == Some(0) && matches!(byte(1), Some(0 | 0x10..=0x13)) => GossipClass::Global,
        4 if zero(4) => GossipClass::PeerInfo,
        APP_FILTER_LEN => GossipClass::ShardFrames,
        33 => match byte(0) {
            Some(0) => GossipClass::Votes,
            Some(1) if data.first().is_some_and(|b| b & !CW_NONCE_FLAG == CW_VOTE_CHANNEL) => {
                GossipClass::Votes
            }
            Some(1) => GossipClass::ShardConsensus,
            _ => GossipClass::Other,
        },
        _ => GossipClass::Other,
    }
}

/// Messages and their encoded bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flow {
    pub messages: u64,
    pub bytes: u64,
}

impl Flow {
    fn since(self, earlier: Flow) -> Flow {
        Flow {
            messages: self.messages.saturating_sub(earlier.messages),
            bytes: self.bytes.saturating_sub(earlier.bytes),
        }
    }

    fn add(self, other: Flow) -> Flow {
        Flow {
            messages: self.messages.saturating_add(other.messages),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }
}

/// One class's traffic, counted four ways (see the module docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClassTraffic {
    pub received: Flow,
    pub unique: Flow,
    pub sent: Flow,
    pub published: Flow,
}

impl ClassTraffic {
    fn since(self, earlier: ClassTraffic) -> ClassTraffic {
        ClassTraffic {
            received: self.received.since(earlier.received),
            unique: self.unique.since(earlier.unique),
            sent: self.sent.since(earlier.sent),
            published: self.published.since(earlier.published),
        }
    }

    fn add(self, other: ClassTraffic) -> ClassTraffic {
        ClassTraffic {
            received: self.received.add(other.received),
            unique: self.unique.add(other.unique),
            sent: self.sent.add(other.sent),
            published: self.published.add(other.published),
        }
    }
}

#[derive(Default)]
struct Counter {
    messages: AtomicU64,
    bytes: AtomicU64,
}

impl Counter {
    fn add(&self, bytes: usize) {
        self.messages.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn load(&self) -> Flow {
        Flow {
            messages: self.messages.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct ClassCounters {
    received: Counter,
    unique: Counter,
    sent: Counter,
    published: Counter,
}

/// This process's gossip traffic since it started, by class. Lock-free: one
/// pair of relaxed atomic additions per message copy.
pub struct GossipTraffic {
    started: Instant,
    classes: [ClassCounters; CLASSES],
}

impl Default for GossipTraffic {
    fn default() -> Self {
        Self { started: Instant::now(), classes: Default::default() }
    }
}

impl GossipTraffic {
    /// Count one message copy of `bytes` encoded bytes, observed as `kind`.
    pub fn record(&self, kind: TrafficKind, class: GossipClass, bytes: usize) {
        let counters = &self.classes[class.index()];
        let counter = match kind {
            TrafficKind::Received => &counters.received,
            TrafficKind::FirstReceived => &counters.unique,
            TrafficKind::Sent => &counters.sent,
            TrafficKind::Published => &counters.published,
        };
        counter.add(bytes);
    }

    pub fn snapshot(&self) -> GossipTrafficSnapshot {
        GossipTrafficSnapshot {
            uptime: self.started.elapsed(),
            classes: std::array::from_fn(|i| {
                let counters = &self.classes[i];
                ClassTraffic {
                    received: counters.received.load(),
                    unique: counters.unique.load(),
                    sent: counters.sent.load(),
                    published: counters.published.load(),
                }
            }),
        }
    }
}

impl TrafficObserver for GossipTraffic {
    fn observe(&self, kind: TrafficKind, topic: &TopicHash, data: &[u8], bytes: usize) {
        self.record(kind, GossipClass::of_topic(topic.as_str(), data), bytes);
    }
}

/// The counters at one moment, or their change over an interval.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GossipTrafficSnapshot {
    /// Time the counts cover: since the process started, or the interval.
    pub uptime: Duration,
    pub classes: [ClassTraffic; CLASSES],
}

impl GossipTrafficSnapshot {
    pub fn class(&self, class: GossipClass) -> ClassTraffic {
        self.classes[class.index()]
    }

    /// Every class together.
    pub fn total(&self) -> ClassTraffic {
        self.classes.iter().fold(ClassTraffic::default(), |total, class| total.add(*class))
    }

    /// The traffic between `earlier` and this snapshot.
    pub fn since(&self, earlier: &GossipTrafficSnapshot) -> GossipTrafficSnapshot {
        GossipTrafficSnapshot {
            uptime: self.uptime.saturating_sub(earlier.uptime),
            classes: std::array::from_fn(|i| self.classes[i].since(earlier.classes[i])),
        }
    }

    /// The node status form (`node.proto` `GossipTraffic`).
    pub fn to_proto(&self) -> quil_types::proto::node::GossipTraffic {
        let flow = |flow: Flow| (flow.messages, flow.bytes);
        quil_types::proto::node::GossipTraffic {
            uptime_ms: u64::try_from(self.uptime.as_millis()).unwrap_or(u64::MAX),
            classes: GossipClass::ALL
                .iter()
                .map(|class| {
                    let traffic = self.class(*class);
                    let (received_messages, received_bytes) = flow(traffic.received);
                    let (unique_messages, unique_bytes) = flow(traffic.unique);
                    let (sent_messages, sent_bytes) = flow(traffic.sent);
                    let (published_messages, published_bytes) = flow(traffic.published);
                    quil_types::proto::node::GossipClassTraffic {
                        class: class.name().to_string(),
                        received_messages,
                        received_bytes,
                        unique_messages,
                        unique_bytes,
                        sent_messages,
                        sent_bytes,
                        published_messages,
                        published_bytes,
                    }
                })
                .collect(),
        }
    }
}

/// Megabits per second, shown with three decimals.
struct Mbps(f64);

impl Mbps {
    fn of(flow: Flow, over: Duration) -> Mbps {
        let secs = over.as_secs_f64();
        Mbps(if secs > 0.0 { flow.bytes as f64 * 8.0 / 1e6 / secs } else { 0.0 })
    }
}

impl std::fmt::Display for Mbps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.3}", self.0)
    }
}

/// One line with this process's gossip traffic over `interval`: per class,
/// Mbit/s received (every copy) and sent (every copy); in total, also the
/// unique share received and this process's own publishes.
pub(crate) fn log_interval(interval: &GossipTrafficSnapshot) {
    let over = interval.uptime;
    let rx = |class: GossipClass| Mbps::of(interval.class(class).received, over);
    let tx = |class: GossipClass| Mbps::of(interval.class(class).sent, over);
    let total = interval.total();
    tracing::info!(
        scope = "local",
        interval_secs = over.as_secs(),
        shard_consensus_in_mbps = %rx(GossipClass::ShardConsensus),
        shard_consensus_out_mbps = %tx(GossipClass::ShardConsensus),
        shard_frames_in_mbps = %rx(GossipClass::ShardFrames),
        shard_frames_out_mbps = %tx(GossipClass::ShardFrames),
        votes_in_mbps = %rx(GossipClass::Votes),
        votes_out_mbps = %tx(GossipClass::Votes),
        global_in_mbps = %rx(GossipClass::Global),
        global_out_mbps = %tx(GossipClass::Global),
        peer_info_in_mbps = %rx(GossipClass::PeerInfo),
        peer_info_out_mbps = %tx(GossipClass::PeerInfo),
        other_in_mbps = %rx(GossipClass::Other),
        other_out_mbps = %tx(GossipClass::Other),
        total_in_mbps = %Mbps::of(total.received, over),
        total_unique_in_mbps = %Mbps::of(total.unique, over),
        total_out_mbps = %Mbps::of(total.sent, over),
        total_published_mbps = %Mbps::of(total.published, over),
        "gossip traffic by class"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_filter() -> Vec<u8> {
        let mut filter = vec![0u8; APP_FILTER_LEN];
        filter[3] = 0x10;
        filter[17] = 0x02;
        filter[30] = 0x80;
        filter
    }

    fn prefixed(prefix: &[u8]) -> Vec<u8> {
        [prefix, app_filter().as_slice()].concat()
    }

    #[test]
    fn each_bitmask_layout_has_its_class_by_bytes_and_by_topic() {
        use GossipClass::*;
        let cases: Vec<(Vec<u8>, Vec<u8>, GossipClass)> = vec![
            (vec![0], vec![1], Global),
            (vec![0, 0], vec![1], Global),
            (vec![0, 0x10], vec![1], Global),
            (vec![0, 0x13], vec![1], Global),
            (vec![0, 0, 0], vec![1], Global),
            (vec![0; 16], vec![1], Global),
            (vec![0, 0, 0, 0], vec![1], PeerInfo),
            (app_filter(), vec![1], ShardFrames),
            (prefixed(&[0]), vec![7], Votes),
            // Shard CW: the vote channel with and without a nonce, then
            // certificates, resolver and blocks.
            (prefixed(&[1]), vec![0x80, 1, 2], Votes),
            (prefixed(&[1]), vec![0x00, 1, 2], Votes),
            (prefixed(&[1]), vec![0x81, 1, 2], ShardConsensus),
            (prefixed(&[1]), vec![0x82], ShardConsensus),
            (prefixed(&[1]), vec![0x03], ShardConsensus),
            (prefixed(&[1]), vec![], ShardConsensus),
            (prefixed(&[0, 0]), vec![1], Other),
            (prefixed(&[0, 0, 0]), vec![1], Other),
            (vec![0, 0x14], vec![1], Other),
            (vec![0, 0, 1], vec![1], Other),
            (vec![], vec![1], Other),
        ];
        for (bitmask, data, class) in cases {
            assert_eq!(GossipClass::of_bitmask(&bitmask, &data), class, "{}", hex::encode(&bitmask));
            assert_eq!(GossipClass::of_topic(&hex::encode(&bitmask), &data), class, "{}", hex::encode(&bitmask));
        }
        assert_eq!(GossipClass::of_topic("0", &[]), GossipClass::Other, "odd-length topic");
        assert_eq!(GossipClass::of_topic("zz", &[]), GossipClass::Other, "not hex");
        for class in GossipClass::ALL {
            assert_eq!(GossipClass::from_name(class.name()), Some(class));
        }
    }

    #[test]
    fn observed_copies_count_in_their_class_and_flow() {
        let traffic = GossipTraffic::default();
        let topic = |bitmask: &[u8]| TopicHash::from_raw(hex::encode(bitmask));
        let cw = topic(&prefixed(&[1]));
        let peer_info = topic(&[0, 0, 0, 0]);
        // A vote arrives from three peers, the first copy is new, and it is
        // forwarded to two.
        for _ in 0..3 {
            traffic.observe(TrafficKind::Received, &cw, &[0x80, 9], 100);
        }
        traffic.observe(TrafficKind::FirstReceived, &cw, &[0x80, 9], 100);
        traffic.observe(TrafficKind::Sent, &cw, &[0x80, 9], 100);
        traffic.observe(TrafficKind::Sent, &cw, &[0x80, 9], 100);
        // A certificate this process publishes to two peers.
        traffic.observe(TrafficKind::Sent, &cw, &[0x81], 300);
        traffic.observe(TrafficKind::Sent, &cw, &[0x81], 300);
        traffic.observe(TrafficKind::Published, &cw, &[0x81], 300);
        traffic.observe(TrafficKind::Received, &peer_info, &[1], 50);
        let before = traffic.snapshot();

        let votes = before.class(GossipClass::Votes);
        assert_eq!(votes.received, Flow { messages: 3, bytes: 300 });
        assert_eq!(votes.unique, Flow { messages: 1, bytes: 100 });
        assert_eq!(votes.sent, Flow { messages: 2, bytes: 200 });
        assert_eq!(votes.published, Flow::default());
        let consensus = before.class(GossipClass::ShardConsensus);
        assert_eq!(consensus.sent, Flow { messages: 2, bytes: 600 });
        assert_eq!(consensus.published, Flow { messages: 1, bytes: 300 });
        assert_eq!(consensus.received, Flow::default());
        assert_eq!(before.class(GossipClass::PeerInfo).received, Flow { messages: 1, bytes: 50 });
        for class in [GossipClass::ShardFrames, GossipClass::Global, GossipClass::Other] {
            assert_eq!(before.class(class), ClassTraffic::default(), "{}", class.name());
        }
        assert_eq!(before.total().received, Flow { messages: 4, bytes: 350 });
        assert_eq!(before.total().sent, Flow { messages: 4, bytes: 800 });

        traffic.observe(TrafficKind::Received, &peer_info, &[1], 70);
        let interval = traffic.snapshot().since(&before);
        assert_eq!(interval.class(GossipClass::PeerInfo).received, Flow { messages: 1, bytes: 70 });
        assert_eq!(interval.class(GossipClass::Votes), ClassTraffic::default());

        let status = before.to_proto();
        assert_eq!(status.classes.len(), GossipClass::ALL.len());
        let votes = status.classes.iter().find(|c| c.class == "votes").unwrap();
        assert_eq!((votes.received_messages, votes.received_bytes, votes.unique_bytes, votes.sent_bytes), (3, 300, 100, 200));
    }

    #[test]
    fn rates_are_megabits_per_second_of_the_interval() {
        let flow = Flow { messages: 10, bytes: 75_000_000 };
        assert_eq!(Mbps::of(flow, Duration::from_secs(600)).to_string(), "1.000");
        assert_eq!(Mbps::of(flow, Duration::ZERO).to_string(), "0.000");
    }
}
