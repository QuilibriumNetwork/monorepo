use std::sync::Arc;

use quil_types::thread_probe::{self as probe, Section as ProbeSection};
use tracing::{debug, error, info, warn};

use quil_lifecycle::Supervisor;

/// Gossiped or submitted prover messages being verified on the blocking pool.
/// The collector runs 4 verifications at once; the rest only queue. The cap
/// leaves 32 queued per running verification, so it binds only on a flood.
pub(crate) static SHARD_FRAME_VERIFY_TASKS: quil_engine::spawn_gate::SpawnGate =
    quil_engine::spawn_gate::SpawnGate::new("shard-frame-verify", 128);

/// "verified peer build identity" lines per status interval for peers that
/// are neither registered provers nor genesis archives (those are always
/// logged): anyone can mint such peers. Peers republish every 30 minutes,
/// so a mainnet node of about 100 peers logs about two per interval.
const OTHER_BUILD_LINES_PER_STATUS: u32 = 32;

/// Messages queued for the loop, after the shard consensus lane took its own:
/// as many as the network task queues for the lane.
const LOOP_QUEUE: usize = 4096;

/// Authors whose router drops one status interval attributes; the status line
/// names the top eight of them.
const MAX_DROP_SOURCES: usize = 1024;

/// Verified GLOBAL_ALERTs remembered so their copies are not shown again.
const MAX_ALERTS_SEEN: usize = 64;

pub(crate) struct MessageLoopArgs {
    /// Standalone workers, when this node runs them: direct shard consensus
    /// messages for their shards are handed to them.
    pub remote_workers:
        Arc<std::sync::OnceLock<Arc<quil_engine::remote_worker::RemoteWorkerManager>>>,
    /// This node's committee key, as a shard CW addressee tag: a transmission
    /// that names another member is dropped before it reaches a shard engine.
    pub local_cw_tag: [u8; quil_engine::bitmasks::SHARD_CW_ADDRESSEE_LEN],
    pub clock_store: Arc<quil_store::RocksClockStore>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
    pub msg_rx: tokio::sync::mpsc::Receiver<quil_p2p::node::ReceivedMessage>,
    pub consensus_loopback_rx: tokio::sync::mpsc::Receiver<quil_p2p::node::ReceivedMessage>,
    /// Peers' `SubmitGlobalConsensus` deliveries: committee members' and
    /// other callers' queues.
    pub remote_consensus: super::consensus_intake::RemoteConsensusQueues,
    pub global_msg_tx:
        tokio::sync::broadcast::Sender<quil_types::proto::global::StreamGlobalMessagesResponse>,
    pub archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
    pub mtls_seed: Option<[u8; 57]>,
    /// The FALCON network-identity signing key (`q-prover-key`) for outbound
    /// :8340 PQNoise dials — the prover-tree bootstrap sync uses this, NOT the
    /// legacy Ed448 `mtls_seed` (which the migrated transport can no longer
    /// decode). Present iff we have a transport identity.
    pub prover_falcon_key: Option<Vec<u8>>,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    pub frame_validator: quil_engine::frame_validator::GlobalFrameVerifier,
    pub message_collector: Arc<quil_engine::message_collector::MessageCollector>,
    pub coverage_monitor: Arc<quil_engine::coverage::CoverageMonitor>,
    pub worker_allocator: Arc<quil_engine::worker_allocator::WorkerAllocator>,
    pub prover_pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
    /// Commonware-simplex inbound router, set post-spawn at the
    /// activation site when `config.engine.consensus_committee` is non-empty.
    /// Unset (the default) → the simplex path is off and this adds no overhead.
    pub cw_router: Arc<std::sync::OnceLock<Arc<crate::cw_consensus_bridge::CwInboundRouter>>>,
    /// Atomic GLOBAL finalization pipeline (archives with CW GLOBAL consensus).
    pub global_finalization:
        Arc<std::sync::OnceLock<Arc<quil_engine::global_finalization::GlobalFinalizationPipeline>>>,
    /// Reports when readers of the two cells above start and stop falling back.
    pub activation_waits: Arc<super::activation_wait::ActivationWaits>,
    pub peer_info_cache:
        Arc<parking_lot::RwLock<std::collections::HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>,
    pub shard_engines: Arc<
        parking_lot::RwLock<
            std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
        >,
    >,
    pub signer_registry: Arc<quil_p2p::SignerRegistry>,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub last_global_head_frame: Arc<std::sync::atomic::AtomicU64>,
    /// Stamped on every gossip-delivered `GLOBAL_FRAME` so the RPC poller can
    /// back off while the mesh is carrying the head.
    pub gossip_freshness: Arc<quil_rpc::GossipFreshness>,
    pub genesis_archive_peer_ids: std::collections::HashSet<Vec<u8>>,
    pub genesis_prover_addrs: std::collections::HashSet<Vec<u8>>,
    pub alert_pubkey: Vec<u8>,
    pub network: u8,
    /// CRDT + genesis seed for the at-cutover prover-tree reset on regular nodes
    /// (they apply frames here, not in the archive materializer). Deterministic:
    /// every node rebuilds the identical prover tree from the genesis committee.
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub genesis_seed: String,
    pub archive_mode: bool,
    pub prover_lifecycle: Arc<quil_engine::provers::lifecycle::ProverLifecycle>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    pub worker_manager: Arc<dyn quil_engine::worker::WorkerManager>,
    pub prover_address: [u8; 32],
    pub p2p_handle: quil_p2p::node::P2PHandle,
    pub time_reel: Option<Arc<quil_engine::time_reel::GlobalTimeReel>>,
    pub spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
    /// Archive-only: ingests full app-shard frames received on the bulk
    /// shard subscription and materializes them into the archive's CRDT.
    /// `None` on non-archive nodes.
    pub archive_app_shard_ingest:
        Option<Arc<std::sync::Mutex<quil_engine::archive_ingest::ArchiveAppShardIngest>>>,
    /// Explorer recent-message ring. `Some` only when the explorer service
    /// is enabled; every inbound gossip message is recorded for the
    /// `GET /messages` endpoint. `None` (the default) means no overhead.
    pub recent_messages: Option<Arc<quil_explorer::RecentMessageRing>>,
    /// The most-asked effective settings (`EffectiveConfig::status_brief`),
    /// repeated in every `node status` line so a recent log window answers
    /// them after the startup line rotated away.
    pub config_brief: String,
}

/// The engines a message on `bitmask` reaches as a submission: every engine
/// whose application's submission topic it is. Every shard of an application
/// shares that topic (a wallet knows only the application). Routed to the
/// first matching engine only, each node gave a submission to one of its
/// shards, so a bundle routed to any other shard was never proposed there
/// (wallet-k16).
fn submission_engines<'a, H>(bitmask: &[u8], entries: &'a [(Vec<u8>, H)]) -> Vec<&'a H> {
    entries
        .iter()
        .filter(|(filter, _)| {
            bitmask == quil_engine::bitmasks::app_prover_bitmask(filter).as_slice()
        })
        .map(|(_, handle)| handle)
        .collect()
}

/// A shard-frame message no local engine takes, on a node without an archive
/// ingest. (An archive queues it for its ingest thread
/// (`archive_ingest_queue`), which verifies it before anything is stored: an
/// unverified store let one forged far-future frame pin the head the archive
/// serves.)
///
/// CLUSTER MASTER: a full app-shard frame the master received via
/// `shard_frame_bitmask` gossip for a filter its REMOTE workers cover — no
/// local engine handle. Mirror it into the master clock
/// store so the store-backed `AppShardService::get_app_shard_frame` serves it;
/// without this, cluster reads hit an empty master store (thread-mode/local
/// frames are mirrored by the worker drain). The filter is the frame header's
/// `address`; the bitmask check confirms this really is a shard-frame message
/// for it (and that non-frame mesh traffic is skipped). Only a frame that
/// verifies is mirrored ([`ShardMirror::offer`]): any peer can publish on the
/// topic, and one unverified far-future frame pinned the head this node
/// serves, as it did an archive's.
///
/// The check runs on the mirror's own thread ([`MirrorFeed`]); this loop
/// reads only the frame's header, counts its request bundles unread and
/// queues it under its sender's key ([`MirrorState::sender_key`]). A frame
/// carrying more bundles and requests, or storage openings, than a frame
/// may is refused first ([`frame_within_bound`]): it takes no room in the
/// queue, and the mirror's worker never decodes it. Checked
/// here, a peer's frame of many bundles held the loop for seconds, and the
/// check reads the execution engines that GLOBAL execution locks. True when
/// the frame was queued.
fn unrouted_shard_message(
    bitmask: &[u8],
    sender: MirrorSender<'_>,
    data: Vec<u8>,
    feed: &MirrorFeed,
) -> bool {
    if !frame_within_bound("cluster mirror", sender.via, &data) {
        return false;
    }
    let Ok(outline) = <FrameOutline as prost::Message>::decode(data.as_slice()) else {
        return false;
    };
    let Some(address) = outline.header.map(|header| header.address) else {
        return false;
    };
    // A peer can grind an address of any length onto a subscribed topic
    // (3 of 256 bits, hashed from the whole address): a longer address
    // than any shard's would make every key the worker builds from it as
    // long as the peer likes.
    if address.is_empty()
        || address.len() > quil_cw_consensus::handoff::MAX_FILTER_BYTES
        || bitmask != quil_engine::bitmasks::shard_frame_bitmask(&address).as_slice()
    {
        return false;
    }
    feed.offer_sent(bitmask, &address, sender, data, outline.requests.len());
    true
}

/// Whether gossiped shard frame `data` carries no more bundles and
/// requests, or storage openings, than a frame may
/// ([`quil_engine::frame_bound`]), counted unread. A refusal is logged with `via`, the connected peer it came from.
fn frame_within_bound(source: &'static str, via: &[u8], data: &[u8]) -> bool {
    quil_engine::frame_bound::admit_frame(source, Some(via), data)
}

/// Who sent a gossiped shard frame, as the mirror's queue keys it
/// ([`MirrorState::sender_key`]).
#[derive(Clone, Copy)]
struct MirrorSender<'a> {
    /// The gossip message's signer: any key its publisher chose.
    signer: &'a [u8],
    /// The connected peer it arrived from (gossip's propagation source).
    via: &'a [u8],
}

/// The sender of `received` for the mirror's queue. A publisher signs each
/// message with any key it likes, so signers cost nothing to multiply; each
/// connected peer takes one of the node's bounded connections, and a
/// committee member's key is not the publisher's to choose.
fn mirror_sender(received: &quil_p2p::node::ReceivedMessage) -> MirrorSender<'_> {
    MirrorSender {
        signer: &received.from,
        via: &received.via,
    }
}

/// The frame's shard (its header's address), read without its bundles.
fn frame_filter(data: &[u8]) -> Option<Vec<u8>> {
    <FrameHeaderOnly as prost::Message>::decode(data)
        .ok()?
        .header
        .map(|header| header.address)
        .filter(|address| !address.is_empty())
}

/// A shard frame read for its header only: its bundles are skipped, not
/// counted.
#[derive(Clone, PartialEq, prost::Message)]
struct FrameHeaderOnly {
    #[prost(message, optional, tag = "1")]
    header: Option<quil_types::proto::global::FrameHeader>,
}

/// What the loop reads of a gossiped shard frame before it queues it: the
/// header, and the request bundles, counted and skipped unread.
#[derive(Clone, PartialEq, prost::Message)]
struct FrameOutline {
    #[prost(message, optional, tag = "1")]
    header: Option<quil_types::proto::global::FrameHeader>,
    #[prost(message, repeated, tag = "2")]
    requests: Vec<SkippedBundle>,
}

/// A request bundle, skipped unread.
#[derive(Clone, PartialEq, prost::Message)]
struct SkippedBundle {}

/// Check a queued shard frame for the mirror, on the mirror's thread:
/// mirror it into `clock_store` once it verifies, hold it, or count why
/// not.
fn mirror_queued(
    clock_store: &dyn quil_types::store::ClockStore,
    mirror: &ShardMirror,
    data: &[u8],
) {
    let now = std::time::Instant::now();
    let frame = match <quil_types::proto::global::AppShardFrame as prost::Message>::decode(data) {
        Ok(frame) => frame,
        Err(error) => {
            // Its outline decoded on the loop: a request bundle does not.
            MIRROR_REFUSALS.note(
                &Default::default(),
                format!("does not decode: {error}"),
                now,
            );
            return;
        }
    };
    if let Err(reason) = mirror.offer(clock_store, &frame, data) {
        MIRROR_REFUSALS.note(&frame, reason, now);
    }
    mirror.summarize(now);
}

/// Frames queued for the mirror's check per gossip topic. A shard's frames
/// arrive about one per 11 s (a mainnet master store copy: 0.06 to 0.09 a
/// second per shard), so this is minutes of one shard's frames while the
/// check waits, and a peer that floods a topic fills only that topic's
/// room. A topic lists only senders with frames queued, so it also bounds
/// the senders ([`MirrorState::sender_key`]) a topic tracks.
const MIRROR_QUEUED_PER_TOPIC: usize = 16;
/// Bytes the frames queued for the mirror's check take, bookkeeping
/// included; past it the sender queuing the most bytes on the topic
/// queuing the most loses its largest frame. Genuine frames on a mainnet
/// master store copy took at most 198 KB, most far less: this queues
/// hundreds of them, or four of a peer's 16 MiB gossip messages.
const MIRROR_QUEUED_BYTES: usize = 64 << 20;
/// What checking one carried request bundle costs, in bytes of encoding
/// that cost as much: on a mainnet master store copy the check took about
/// 1.9 ms per bundle and 12 ms per MB.
const MIRROR_BUNDLE_COST_BYTES: usize = 160 << 10;
/// Bookkeeping bytes per queued frame besides its encoding, its topic and
/// its sender.
const MIRROR_QUEUED_ENTRY_OVERHEAD: usize = std::mem::size_of::<QueuedFrame>() + 64;
/// How often the frames the mirror's queue dropped, and the checks that
/// panicked, are summarized.
const MIRROR_QUEUE_SUMMARY: std::time::Duration = std::time::Duration::from_secs(600);
/// The most of a caught panic's text a line quotes.
const MIRROR_PANIC_TEXT: usize = 200;
/// How long the mirror's worker uses a shard's committee members it read
/// ([`ShardMembers`]) before it reads them again.
const MIRROR_MEMBERS_REFRESH: std::time::Duration = std::time::Duration::from_secs(60);
/// Shards whose committee members the mirror's worker keeps. A peer names
/// any filter it likes, so past it the longest-read shard with no members
/// goes first, then the longest-read of all.
const MIRROR_MEMBER_SHARDS: usize = 1024;

/// A gossiped shard frame queued for the mirror's check.
struct QueuedFrame {
    data: Vec<u8>,
    /// What its check costs, estimated from its bytes and bundles.
    cost: usize,
    arrival: u64,
}

/// The frames one sender queued on a gossip topic, and the bytes they take.
struct SenderFrames {
    /// The sender's key ([`MirrorState::sender_key`]).
    peer: Vec<u8>,
    frames: Vec<QueuedFrame>,
    bytes: usize,
}

/// The frames queued on one gossip topic: per sender, and in all. A sender
/// is listed only while it has frames queued.
#[derive(Default)]
struct TopicFrames {
    senders: Vec<SenderFrames>,
    frames: usize,
    bytes: usize,
}

/// Which of a sender's frames a bound drops.
#[derive(Clone, Copy)]
enum Evict {
    /// The costliest to check: past the topic's bound.
    Costliest,
    /// The largest: past the byte bound.
    Largest,
}

/// Frames the mirror's queue dropped, and their encoded bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct QueueDrops {
    frames: u64,
    bytes: u64,
}

/// The shard frames queued for the mirror's check, per gossip topic and,
/// within a topic, per sender ([`MirrorState::sender_key`]): the committee
/// member that signed it, else the connected peer it arrived from, never a
/// signer the node does not know, which a publisher mints freely.
/// The worker takes the topics in turn. Within a topic it takes the sender
/// queuing the fewest frames, of equal counts the one whose cheapest frame
/// is cheapest, then the earliest, and that sender's cheapest frame. So a
/// peer that floods one topic delays another topic's frame by at most one
/// check per other topic with frames queued, and another sender's frame on
/// its own topic by at most the frame in check, however small and many its
/// frames and whatever keys it signs them with.
///
/// Past a topic's bound ([`MIRROR_QUEUED_PER_TOPIC`]) the sender queuing
/// the most frames there loses its costliest frame; of equal counts the
/// sender with the costliest frame, and only then the sender whose frame
/// arrived. So an arrival drops another sender's frame only when that
/// sender queues more frames there, or as many with a costlier one. Past
/// the byte bound ([`MIRROR_QUEUED_BYTES`]) the sender queuing the most
/// bytes on the topic queuing the most loses its largest frame.
///
/// Topics, not filters: a peer names any filter it likes, but only the
/// topics this node subscribes reach it. Peers that hold many connections
/// count as many senders: one-frame senders on a full topic then lose
/// their costliest frames first, so cheap frames from many connections
/// can still crowd out a costlier genuine one.
struct MirrorQueue {
    topics: std::collections::HashMap<Vec<u8>, TopicFrames>,
    /// Topics with queued frames, in turn order.
    turns: std::collections::VecDeque<Vec<u8>>,
    bytes: usize,
    byte_cap: usize,
    arrivals: u64,
    dropped: QueueDrops,
    /// When a line was last logged.
    reported: Option<std::time::Instant>,
    /// Whether the last line reported drops.
    dropping: bool,
}

/// A line about the frames the mirror's queue dropped.
#[derive(Debug, PartialEq, Eq)]
struct QueueLine {
    /// Dropped since the last line; none in the line that says drops ended.
    dropped: QueueDrops,
    queued: usize,
    queued_bytes: usize,
    topics: usize,
    interval_s: Option<u64>,
}

impl MirrorQueue {
    fn new(byte_cap: usize) -> Self {
        Self {
            topics: Default::default(),
            turns: Default::default(),
            bytes: 0,
            byte_cap,
            arrivals: 0,
            dropped: QueueDrops::default(),
            reported: None,
            dropping: false,
        }
    }

    /// The bytes `frame`, queued on `topic` from `peer`, takes.
    fn size(topic: &[u8], peer: &[u8], frame: &QueuedFrame) -> usize {
        frame.data.len() + topic.len() + peer.len() + MIRROR_QUEUED_ENTRY_OVERHEAD
    }

    /// Frames queued.
    fn len(&self) -> usize {
        self.topics.values().map(|queued| queued.frames).sum()
    }

    /// Queue `data`, a frame on `topic` from `peer` carrying `bundles`
    /// request bundles, then drop what the bounds ask. Finding the sender
    /// and the one to lose a frame reads the topic's frames (at most
    /// [`MIRROR_QUEUED_PER_TOPIC`] and the arriving one); finding the topic
    /// queuing the most bytes reads one entry per queued topic, only past
    /// the byte bound.
    fn push(&mut self, topic: &[u8], peer: &[u8], data: Vec<u8>, bundles: usize) {
        self.arrivals += 1;
        let frame = QueuedFrame {
            cost: data
                .len()
                .saturating_add(bundles.saturating_mul(MIRROR_BUNDLE_COST_BYTES)),
            arrival: self.arrivals,
            data,
        };
        let size = Self::size(topic, peer, &frame);
        let queued = self.topics.entry(topic.to_vec()).or_default();
        if queued.frames == 0 {
            self.turns.push_back(topic.to_vec());
        }
        let index = match queued.senders.iter().position(|sender| sender.peer == peer) {
            Some(index) => index,
            None => {
                queued.senders.push(SenderFrames {
                    peer: peer.to_vec(),
                    frames: Vec::new(),
                    bytes: 0,
                });
                queued.senders.len() - 1
            }
        };
        let sender = &mut queued.senders[index];
        sender.frames.push(frame);
        sender.bytes += size;
        queued.frames += 1;
        queued.bytes += size;
        self.bytes += size;
        if queued.frames > MIRROR_QUEUED_PER_TOPIC {
            let most = (0..queued.senders.len()).max_by_key(|&index| {
                let sender = &queued.senders[index];
                let costliest = sender.frames.iter().map(|frame| frame.cost).max();
                (sender.frames.len(), costliest, sender.peer == peer)
            });
            if let Some(most) = most {
                self.drop_frame(topic, most, Evict::Costliest);
            }
        }
        while self.bytes > self.byte_cap {
            let Some(heaviest) = self
                .topics
                .iter()
                .max_by(|(topic, queued), (other, other_queued)| {
                    queued
                        .bytes
                        .cmp(&other_queued.bytes)
                        .then_with(|| topic.cmp(other))
                })
                .map(|(topic, _)| topic.clone())
            else {
                break;
            };
            let most = self.topics.get(&heaviest).and_then(|queued| {
                (0..queued.senders.len()).max_by_key(|&index| {
                    let sender = &queued.senders[index];
                    (sender.bytes, sender.frames.len())
                })
            });
            if !most.is_some_and(|most| self.drop_frame(&heaviest, most, Evict::Largest)) {
                break;
            }
        }
    }

    /// Drop the costliest or the largest frame, of equal ones the latest,
    /// of the sender at `index` in `topic`'s list, and count it.
    /// False when there was none.
    fn drop_frame(&mut self, topic: &[u8], index: usize, evict: Evict) -> bool {
        let Some(queued) = self.topics.get_mut(topic) else {
            return false;
        };
        let Some(sender) = queued.senders.get_mut(index) else {
            return false;
        };
        let Some(victim) = (0..sender.frames.len()).max_by_key(|&at| {
            let frame = &sender.frames[at];
            let weight = match evict {
                Evict::Costliest => frame.cost,
                Evict::Largest => frame.data.len(),
            };
            (weight, frame.arrival)
        }) else {
            return false;
        };
        let frame = sender.frames.swap_remove(victim);
        let size = Self::size(topic, &sender.peer, &frame);
        sender.bytes -= size;
        if sender.frames.is_empty() {
            queued.senders.remove(index);
        }
        queued.frames -= 1;
        queued.bytes -= size;
        let emptied = queued.frames == 0;
        self.bytes -= size;
        self.dropped.frames += 1;
        self.dropped.bytes += frame.data.len() as u64;
        if emptied {
            self.topics.remove(topic);
            self.turns.retain(|turn| turn.as_slice() != topic);
        }
        true
    }

    /// The next frame to check: of the topic whose turn it is, of the sender
    /// queuing the fewest frames there (of equal counts the one whose
    /// cheapest frame is cheapest, then the earliest), the cheapest, of
    /// equal costs the earliest. Reads the topic's frames.
    fn pop(&mut self) -> Option<Vec<u8>> {
        while let Some(topic) = self.turns.pop_front() {
            let Some(queued) = self.topics.get_mut(&topic) else {
                continue;
            };
            let next = queued
                .senders
                .iter()
                .enumerate()
                .filter_map(|(at, sender)| {
                    sender
                        .frames
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, frame)| (frame.cost, frame.arrival))
                        .map(|(index, frame)| {
                            let key = (sender.frames.len(), frame.cost, frame.arrival);
                            (key, at, index)
                        })
                })
                .min_by_key(|(key, _, _)| *key);
            let Some((_, at, index)) = next else {
                self.topics.remove(&topic);
                continue;
            };
            let sender = &mut queued.senders[at];
            let frame = sender.frames.swap_remove(index);
            let size = Self::size(&topic, &sender.peer, &frame);
            sender.bytes -= size;
            if sender.frames.is_empty() {
                queued.senders.remove(at);
            }
            queued.frames -= 1;
            queued.bytes -= size;
            let emptied = queued.frames == 0;
            self.bytes -= size;
            if emptied {
                self.topics.remove(&topic);
            } else {
                self.turns.push_back(topic);
            }
            return Some(frame.data);
        }
        None
    }

    /// Drop every queued frame, counted: no worker will check them.
    fn clear(&mut self) {
        for frame in self
            .topics
            .values()
            .flat_map(|queued| queued.senders.iter())
            .flat_map(|sender| sender.frames.iter())
        {
            self.dropped.frames += 1;
            self.dropped.bytes += frame.data.len() as u64;
        }
        self.topics.clear();
        self.turns.clear();
        self.bytes = 0;
    }

    /// The line due at `now` about dropped frames, if one is: at most one
    /// per [`MIRROR_QUEUE_SUMMARY`], with the drops since the last, and one
    /// more once an interval passed without drops.
    fn summarize(&mut self, now: std::time::Instant) -> Option<QueueLine> {
        if self
            .reported
            .is_some_and(|last| now.saturating_duration_since(last) < MIRROR_QUEUE_SUMMARY)
            || (self.dropped == QueueDrops::default() && !self.dropping)
        {
            return None;
        }
        let dropped = std::mem::take(&mut self.dropped);
        self.dropping = dropped != QueueDrops::default();
        let since = self.reported.replace(now);
        Some(QueueLine {
            dropped,
            queued: self.len(),
            queued_bytes: self.bytes,
            topics: self.topics.len(),
            interval_s: since.map(|last| now.saturating_duration_since(last).as_secs()),
        })
    }
}

impl QueueLine {
    /// Log it, with how long the frame in check has been checked
    /// (`checking_s`) and whether the mirror's worker runs.
    fn log(&self, checking_s: Option<u64>, running: bool) {
        let QueueDrops { frames, bytes } = self.dropped;
        if !running {
            error!(
                frames,
                bytes,
                interval_s = self.interval_s,
                scope = "this node",
                action = "restart the node and report the 'shard mirror worker' error logged \
                          before this",
                "gossiped shard frames were not mirrored for serving: the shard mirror worker \
                 is not running"
            );
        } else if frames > 0 {
            warn!(
                frames,
                bytes,
                queued = self.queued,
                queued_bytes = self.queued_bytes,
                topics = self.topics,
                checking_s,
                interval_s = self.interval_s,
                scope = "peer",
                check = "a long checking_s means the check waits, usually for the execution \
                         engines GLOBAL execution holds; else a peer floods shard frame topics \
                         with frames the check refuses (see the mirror refusal lines); this \
                         node serves no frame at a dropped genuine frame's number",
                "gossiped shard frames queued for the mirror's check were dropped: its queue \
                 was full"
            );
        } else {
            info!(
                queued = self.queued,
                queued_bytes = self.queued_bytes,
                interval_s = self.interval_s,
                scope = "peer",
                "gossiped shard frames queued for the mirror's check are no longer dropped"
            );
        }
    }
}

/// Checks by the mirror's worker that panicked: logged at once, then at
/// most once per [`MIRROR_QUEUE_SUMMARY`] with the count since. A peer's
/// frame can make the check panic (the class group VDF code panics on some
/// malformed outputs), so a line per panic would let it flood the log.
#[derive(Default)]
struct MirrorPanics {
    /// Since the last line.
    panics: u64,
    /// The first of those: its text, and its frame's encoded bytes.
    first: Option<(String, usize)>,
    /// When a line was last logged.
    reported: Option<std::time::Instant>,
}

/// A line about the checks that panicked.
#[derive(Debug, PartialEq, Eq)]
struct PanicLine {
    panics: u64,
    panic: String,
    frame_bytes: usize,
    interval_s: Option<u64>,
}

impl MirrorPanics {
    /// The check of a frame of `frame_bytes` panicked at `now` with
    /// `panic`; the line due, if one is.
    fn note(
        &mut self,
        now: std::time::Instant,
        panic: String,
        frame_bytes: usize,
    ) -> Option<PanicLine> {
        self.panics += 1;
        self.first.get_or_insert((panic, frame_bytes));
        self.due(now)
    }

    /// The line due at `now`, if one is: panics not logged yet, and no line
    /// within [`MIRROR_QUEUE_SUMMARY`].
    fn due(&mut self, now: std::time::Instant) -> Option<PanicLine> {
        if self.panics == 0
            || self
                .reported
                .is_some_and(|last| now.saturating_duration_since(last) < MIRROR_QUEUE_SUMMARY)
        {
            return None;
        }
        let (panic, frame_bytes) = self.first.take().unwrap_or_default();
        let since = self.reported.replace(now);
        Some(PanicLine {
            panics: std::mem::take(&mut self.panics),
            panic,
            frame_bytes,
            interval_s: since.map(|last| now.saturating_duration_since(last).as_secs()),
        })
    }
}

impl PanicLine {
    fn log(&self) {
        warn!(
            panics = self.panics,
            panic = %self.panic,
            frame_bytes = self.frame_bytes,
            interval_s = self.interval_s,
            scope = "this node",
            action = "report this line: the check should refuse a malformed frame, not panic",
            "the shard mirror's check of gossiped frames panicked: those frames were not \
             mirrored; the worker continues"
        );
    }
}

/// The text of a caught panic on one line, cut to [`MIRROR_PANIC_TEXT`]
/// characters.
fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a panic without text")
        .chars()
        .take(MIRROR_PANIC_TEXT)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// The loop's end of the queue the mirror checks gossiped shard frames
/// from, on its own thread ([`MirrorQueue`]): the loop never waits for the
/// check, nor for the locks it takes.
struct MirrorFeed {
    shared: Arc<MirrorShared>,
}

struct MirrorShared {
    state: std::sync::Mutex<MirrorState>,
    queued: std::sync::Condvar,
    /// Notified when the worker ends.
    ended: std::sync::Condvar,
    /// The worker's thread, joined once it ended
    /// ([`MirrorShared::wait_ended`]).
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

struct MirrorState {
    queue: MirrorQueue,
    /// Since when the worker checks a frame.
    checking: Option<std::time::Instant>,
    /// False once the worker failed to start or ended.
    running: bool,
    /// The worker is to stop: the loop's end is gone, or the node stops
    /// ([`stop_shard_mirrors`]).
    closed: bool,
    panics: MirrorPanics,
    /// Per shard, its committee members as the worker last read them.
    members: std::collections::HashMap<Vec<u8>, ShardMembers>,
}

/// A shard's committee members in the committed GLOBAL session, as peer
/// IDs, and when the mirror's worker read them.
struct ShardMembers {
    peers: std::collections::HashSet<Vec<u8>>,
    read: std::time::Instant,
}

impl MirrorState {
    /// The key a frame of shard `filter` from `sender` queues under: its
    /// signer when that is a member of the shard's committee as the worker
    /// last read it, so a relay that delivers a member's frame first does
    /// not own it; else the connected peer it arrived from. A frame of a
    /// shard the worker has not read yet queues under its connection.
    fn sender_key<'a>(&self, filter: &[u8], sender: MirrorSender<'a>) -> &'a [u8] {
        if self
            .members
            .get(filter)
            .is_some_and(|members| members.peers.contains(sender.signer))
        {
            sender.signer
        } else {
            sender.via
        }
    }

    /// Whether shard `filter`'s members were read within
    /// [`MIRROR_MEMBERS_REFRESH`] of `now`.
    fn members_fresh(&self, filter: &[u8], now: std::time::Instant) -> bool {
        self.members.get(filter).is_some_and(|members| {
            now.saturating_duration_since(members.read) < MIRROR_MEMBERS_REFRESH
        })
    }

    /// Keep shard `filter`'s members `peers`, read at `now`, within
    /// [`MIRROR_MEMBER_SHARDS`].
    fn keep_members(&mut self, filter: Vec<u8>, peers: Vec<Vec<u8>>, now: std::time::Instant) {
        if !self.members.contains_key(&filter) && self.members.len() >= MIRROR_MEMBER_SHARDS {
            let gone = self
                .members
                .iter()
                .min_by_key(|(_, members)| (!members.peers.is_empty(), members.read))
                .map(|(filter, _)| filter.clone());
            if let Some(gone) = gone {
                self.members.remove(&gone);
            }
        }
        self.members.insert(
            filter,
            ShardMembers {
                peers: peers.into_iter().collect(),
                read: now,
            },
        );
    }
}

impl MirrorShared {
    fn lock(&self) -> std::sync::MutexGuard<'_, MirrorState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Ask the worker to stop: it checks no queued frame after the one in
    /// check, if any.
    fn close(&self) {
        self.lock().closed = true;
        self.queued.notify_all();
    }

    /// Wait up to `grace` for the worker to end, then join its thread.
    /// Whether it ended.
    fn wait_ended(&self, grace: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + grace;
        let mut state = self.lock();
        while state.running {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            state = match self.ended.wait_timeout(state, left) {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        drop(state);
        let thread = self
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(thread) = thread {
            // It ended: this waits only for its return.
            let _ = thread.join();
        }
        true
    }
}

/// Marks the mirror's worker ended, however it ends, and drops (counted)
/// the frames still queued: no worker will check them.
struct MirrorRunning(Arc<MirrorShared>);

impl Drop for MirrorRunning {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.running = false;
        state.queue.clear();
        drop(state);
        self.0.ended.notify_all();
        if std::thread::panicking() {
            error!(
                scope = "this node",
                action = "restart the node and report this line",
                "shard mirror worker stopped: gossiped shard frames are not mirrored for serving"
            );
        }
    }
}

/// The mirror workers this process started ([`MirrorFeed::spawn`]), for
/// [`stop_shard_mirrors`].
static MIRROR_WORKERS: std::sync::Mutex<Vec<std::sync::Weak<MirrorShared>>> =
    std::sync::Mutex::new(Vec::new());

/// The mirror workers whose state still exists.
fn live_mirror_workers() -> Vec<Arc<MirrorShared>> {
    MIRROR_WORKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter_map(std::sync::Weak::upgrade)
        .collect()
}

/// Ask the shard mirror workers to stop before the process exits: each
/// ends after the frame in check, without checking the frames queued, and
/// drops the store handles its check holds. Does not wait: see
/// [`wait_for_shard_mirrors`]. Returns how many were running.
pub(crate) fn stop_shard_mirrors() -> usize {
    live_mirror_workers()
        .iter()
        .filter(|worker| {
            worker.close();
            worker.lock().running
        })
        .count()
}

/// Wait up to `grace` for the shard mirror workers to end after
/// [`stop_shard_mirrors`], joining each. Returns how many still run.
pub(crate) fn wait_for_shard_mirrors(grace: std::time::Duration) -> usize {
    let started = std::time::Instant::now();
    live_mirror_workers()
        .iter()
        .filter(|worker| !worker.wait_ended(grace.saturating_sub(started.elapsed())))
        .count()
}

impl MirrorFeed {
    /// A queue no worker takes from yet.
    fn new() -> Self {
        Self {
            shared: Arc::new(MirrorShared {
                state: std::sync::Mutex::new(MirrorState {
                    queue: MirrorQueue::new(MIRROR_QUEUED_BYTES),
                    checking: None,
                    running: true,
                    closed: false,
                    panics: MirrorPanics::default(),
                    members: Default::default(),
                }),
                queued: std::sync::Condvar::new(),
                ended: std::sync::Condvar::new(),
                thread: std::sync::Mutex::new(None),
            }),
        }
    }

    /// Start the worker thread: it hands each queued frame to `check`,
    /// reads a shard's committee members (peer IDs) with `members` before
    /// it checks the shard's frame, at most once per
    /// [`MIRROR_MEMBERS_REFRESH`] (`None`: no registered shard, nothing is
    /// kept), and is listed for [`stop_shard_mirrors`].
    fn spawn(
        check: impl FnMut(&[u8]) + Send + 'static,
        members: impl FnMut(&[u8]) -> Option<Vec<Vec<u8>>> + Send + 'static,
    ) -> Self {
        let feed = Self::new();
        let shared = feed.shared.clone();
        // The worker logs where its spawner does.
        let dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
        let started = std::thread::Builder::new()
            .name("shard-mirror".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || run_mirror(shared, check, members))
            });
        match started {
            Ok(thread) => {
                *feed
                    .shared
                    .thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(thread);
                let mut workers = MIRROR_WORKERS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                workers.retain(|worker| worker.strong_count() > 0);
                workers.push(Arc::downgrade(&feed.shared));
            }
            Err(error) => {
                feed.shared.lock().running = false;
                error!(
                    %error,
                    scope = "this node",
                    action = "restart the node; if it repeats, check the host's thread and \
                              memory limits and report this line",
                    "shard mirror worker did not start: gossiped shard frames are not mirrored \
                     for serving"
                );
            }
        }
        feed
    }

    /// Queue `data`, a frame of shard `filter` on `topic` from `sender`
    /// carrying `bundles` request bundles, under its sender's key
    /// ([`MirrorState::sender_key`]).
    fn offer_sent(
        &self,
        topic: &[u8],
        filter: &[u8],
        sender: MirrorSender<'_>,
        data: Vec<u8>,
        bundles: usize,
    ) {
        self.queue_under(
            topic,
            |state| state.sender_key(filter, sender),
            data,
            bundles,
        );
    }

    /// Queue `data`, a frame on `topic` from `peer` carrying `bundles`
    /// request bundles.
    #[cfg(test)]
    fn offer(&self, topic: &[u8], peer: &[u8], data: Vec<u8>, bundles: usize) {
        self.queue_under(topic, |_| peer, data, bundles);
    }

    /// Queue `data`, a frame on `topic` carrying `bundles` request bundles,
    /// under the sender key `key` gives, without waiting for its check;
    /// dropped and counted when its worker is not running, dropped when it
    /// was stopped.
    fn queue_under<'a>(
        &self,
        topic: &[u8],
        key: impl FnOnce(&MirrorState) -> &'a [u8],
        data: Vec<u8>,
        bundles: usize,
    ) {
        let now = std::time::Instant::now();
        let mut state = self.shared.lock();
        if state.closed {
            // The node stops: nothing is checked any more.
            return;
        }
        if state.running {
            let peer = key(&state);
            state.queue.push(topic, peer, data, bundles);
        } else {
            state.queue.dropped.frames += 1;
            state.queue.dropped.bytes += data.len() as u64;
        }
        let line = state.queue.summarize(now);
        let checking_s = state
            .checking
            .map(|since| now.saturating_duration_since(since).as_secs());
        let running = state.running;
        drop(state);
        self.shared.queued.notify_one();
        if let Some(line) = line {
            line.log(checking_s, running);
        }
    }

    /// The next queued frame, taken without a worker.
    #[cfg(test)]
    fn take(&self) -> Option<Vec<u8>> {
        self.shared.lock().queue.pop()
    }
}

impl Drop for MirrorFeed {
    fn drop(&mut self) {
        self.shared.close();
    }
}

/// The mirror's worker: check each queued frame until it is stopped, read
/// the committee members of the shards it checks, and say when drops ended
/// and when checks panicked.
fn run_mirror(
    shared: Arc<MirrorShared>,
    check: impl FnMut(&[u8]),
    members: impl FnMut(&[u8]) -> Option<Vec<Vec<u8>>>,
) {
    let _running = MirrorRunning(shared.clone());
    // Dropped before `_running`: the store handles the check and the
    // members reader hold are released before the worker is marked ended.
    let mut check_frame = check;
    let mut read_members = members;
    let mut state = shared.lock();
    loop {
        if state.closed {
            return;
        }
        if let Some(data) = state.queue.pop() {
            let now = std::time::Instant::now();
            state.checking = Some(now);
            drop(state);
            // The frame is decoded off the queue lock, which the loop takes;
            // under it only the (bounded) address is looked up.
            let stale =
                frame_filter(&data).filter(|filter| !shared.lock().members_fresh(filter, now));
            if let Some(filter) = stale {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    read_members(&filter)
                })) {
                    // A shard with no committed session has no members: its
                    // frames queue under their connection.
                    Ok(Some(peers)) => shared.lock().keep_members(filter, peers, now),
                    // No registered shard: nothing is kept for it.
                    Ok(None) => {}
                    Err(panic) => {
                        let panic = format!(
                            "reading a shard's committee members: {}",
                            panic_text(panic.as_ref())
                        );
                        let line = shared.lock().panics.note(now, panic, data.len());
                        if let Some(line) = line {
                            line.log();
                        }
                    }
                }
            }
            // The default panic hook still prints each panic: quieting it
            // takes a process-wide hook (`std::panic::set_hook`), which this
            // worker leaves alone for every other thread's sake. The line
            // below is the bounded record.
            let panicked =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check_frame(&data)))
                    .err()
                    .map(|panic| panic_text(panic.as_ref()));
            let frame_bytes = data.len();
            drop(data);
            let now = std::time::Instant::now();
            state = shared.lock();
            state.checking = None;
            // Due on its interval however long the queue stays full.
            let line = match panicked {
                Some(panic) => state.panics.note(now, panic, frame_bytes),
                None => state.panics.due(now),
            };
            if let Some(line) = line {
                drop(state);
                line.log();
                state = shared.lock();
            }
            continue;
        }
        let now = std::time::Instant::now();
        let dropped = state.queue.summarize(now);
        let panicked = state.panics.due(now);
        if dropped.is_some() || panicked.is_some() {
            let running = state.running;
            drop(state);
            if let Some(line) = dropped {
                line.log(None, running);
            }
            if let Some(line) = panicked {
                line.log();
            }
            state = shared.lock();
            continue;
        }
        state = match shared.queued.wait_timeout(state, MIRROR_QUEUE_SUMMARY) {
            Ok((state, _)) => state,
            Err(poisoned) => poisoned.into_inner().0,
        };
    }
}

/// The validator a node without an archive ingest checks gossiped shard
/// frames with before it mirrors them, built as the archive ingest builds
/// its own ([`quil_engine::archive_ingest::ArchiveAppShardIngest::new`]).
fn shard_mirror_validator(
    prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
    clock_store: Arc<dyn quil_types::store::ClockStore>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
) -> quil_engine::frame_validator::BlsAppFrameValidator {
    quil_engine::frame_validator::BlsAppFrameValidator::new(
        prover_registry,
        Arc::new(quil_crypto::FalconKeyConstructor),
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
    )
    .with_clock_store(clock_store)
    .with_handoff_authority(crdt)
}

/// Whether a gossiped shard frame may be mirrored for serving, else why not:
/// the checks the archive ingest makes of a frame's header. A frame with a
/// certificate needs its committee's certificate and the output its anchored
/// GLOBAL frame determines; one without, to be the frame GLOBAL committed.
/// Possession is not checked: the quorum checked it, and serving needs none.
fn mirror_admits(
    validator: &quil_engine::frame_validator::BlsAppFrameValidator,
    frame: &quil_types::proto::global::AppShardFrame,
) -> Result<(), String> {
    let certified = frame
        .header
        .as_ref()
        .and_then(|header| header.public_key_signature_bls48581.as_ref())
        .is_some_and(|signature| !signature.signature.is_empty());
    let verified = if certified {
        validator.validate_certified_without_storage(frame)
    } else if validator.committed_by_global(frame) {
        validator.validate_linked_without_storage(frame)
    } else {
        return Err("no certificate, and not the frame GLOBAL committed".into());
    };
    match verified {
        Ok(true) => Ok(()),
        Ok(false) => Err("certificate refused".into()),
        Err(error) => Err(error.to_string()),
    }
}

/// Frames without a certificate held per shard until a certified child links
/// to them, as many as the archive ingest holds.
const MIRROR_HELD_PER_SHARD: usize = 32;
/// Frames held per shard at one frame number. Past it the longest held there
/// goes, so impostors at the real frame's number cannot keep it out for good.
const MIRROR_HELD_PER_NUMBER: usize = 4;
/// How far from a shard's stored head, above or below, a frame without a
/// certificate is held; at or below the head only at a number with no
/// stored frame, so a gap behind a later certified frame still fills.
const MIRROR_HOLD_WINDOW: u64 = MIRROR_HELD_PER_SHARD as u64;
/// Bytes all held frames take, bookkeeping included; past it the shard
/// holding the most bytes loses its largest frame (of equal sizes, the
/// farthest). A held frame of `n` bytes goes only while its shard holds
/// nothing larger and no shard holds more bytes, so only while frames are
/// held for more than about `MIRROR_HELD_BYTES / (MIRROR_HELD_PER_SHARD *
/// n)` shards: frames padded toward [`MIRROR_HELD_FRAME_BYTES`] go before a
/// small one. A held frame near that size has no such margin.
const MIRROR_HELD_BYTES: usize = 64 << 20;
/// Largest encoding of a frame held for its certified child. The genuine
/// frames held on a mainnet master store copy carried no requests; this
/// leaves room for a notarized frame that carries some, while a peer's
/// 16 MiB frame is refused before any check and never held.
const MIRROR_HELD_FRAME_BYTES: usize = 1 << 20;
/// Most request bundles a frame may carry for the mirror to check them. The
/// check converts each bundle, locks its addresses and commits it to a
/// tree on the message loop, so without a bound one 16 MiB frame of tiny
/// bundles buys hundreds of thousands of commits there. Shard frames are
/// paced to one per GLOBAL frame, and mainnet ones carry far fewer (most
/// none); a frame over the bound is refused before any check, and the next
/// frame that verifies is mirrored.
const MIRROR_MAX_REQUESTS: usize = 1024;
/// Bookkeeping bytes per held frame besides its encoding and its filter
/// (counted twice): its key, its value, its shard's share of the size index
/// and a B-tree node share.
const MIRROR_HELD_ENTRY_OVERHEAD: usize = 2 * std::mem::size_of::<HeldKey>()
    + std::mem::size_of::<(u64, Vec<u8>)>()
    + std::mem::size_of::<u64>()
    + 64;
/// Frames a bound evicted that are remembered, so that a certified child
/// naming one shows a real frame was lost.
const MIRROR_EVICTED_REMEMBERED: usize = 1024;
/// How often the frames held for their certified child are summarized.
const MIRROR_HOLD_SUMMARY: std::time::Duration = std::time::Duration::from_secs(600);

/// What a node without an archive ingest mirrors of the shard frames
/// gossiped for shards no local engine runs: a frame that verifies at once
/// ([`mirror_admits`]), and one final only through its certified child.
/// Simplex finalizes a view's notarized ancestors with the child's
/// certificate, so such a frame never carries one of its own; the archive
/// ingest holds it until a certified child links to it, and so does this.
/// Either way the carried requests must match the header's root.
struct ShardMirror {
    validator: quil_engine::frame_validator::BlsAppFrameValidator,
    /// The shards the prover registry names, as the archive ingest tracks
    /// them: only their frames are held.
    tracked: quil_engine::archive_ingest::TrackedShards,
    /// Recomputes a frame's requests root; none in tests, where a frame with
    /// requests is refused.
    execution: Option<Arc<quil_execution::ExecutionEngineManager>>,
    has_forest: bool,
    held: std::sync::Mutex<HeldFrames>,
}

/// The key of a held frame: its filter, number and output identity. Keyed
/// by identity, so a well-formed impostor does not replace the real frame.
type HeldKey = (Vec<u8>, u64, [u8; 32]);

/// What happened to held frames since the last summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HoldCounts {
    /// Frames held.
    held: u64,
    /// Held frames mirrored once a certified child linked to them.
    released: u64,
    /// Held frames a bound evicted.
    evicted: u64,
    /// Held frames dropped as far below a mirrored frame.
    pruned: u64,
    /// Evicted frames a certified child later named: real frames lost.
    lost: u64,
}

/// Frames without a certificate whose header and requests verify otherwise,
/// each with its arrival count and encoding; a size index finds the shard
/// holding the most bytes without a scan.
struct HeldFrames {
    frames: std::collections::BTreeMap<HeldKey, (u64, Vec<u8>)>,
    /// Bytes each shard's held frames take.
    shard_bytes: std::collections::HashMap<Vec<u8>, usize>,
    /// The same, ordered by bytes.
    by_size: std::collections::BTreeSet<(usize, Vec<u8>)>,
    bytes: usize,
    byte_cap: usize,
    arrivals: u64,
    evicted: std::collections::VecDeque<HeldKey>,
    evicted_keys: std::collections::HashSet<HeldKey>,
    counts: HoldCounts,
    reported: Option<std::time::Instant>,
}

/// What [`ShardMirror::offer`] did with a frame it did not refuse.
#[derive(Debug, PartialEq, Eq)]
enum Mirrored {
    /// Mirrored, with the held ancestors it links to.
    Stored,
    /// A copy of the frame stored at its number: nothing to check or store.
    Known,
    /// Held until a certified child links to it.
    Held,
}

/// The mirror a node without an archive ingest checks gossiped shard frames
/// with: the validator built as the archive ingest builds its own, and the
/// shards its prover registry names.
fn shard_mirror(
    prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
    clock_store: Arc<dyn quil_types::store::ClockStore>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    execution: Option<Arc<quil_execution::ExecutionEngineManager>>,
) -> ShardMirror {
    ShardMirror {
        tracked: quil_engine::archive_ingest::TrackedShards::new(
            prover_registry.clone(),
            crdt.clone(),
        ),
        has_forest: crdt.has_forest(),
        validator: shard_mirror_validator(prover_registry, clock_store, crdt),
        execution,
        held: std::sync::Mutex::new(HeldFrames::new(MIRROR_HELD_BYTES)),
    }
}

impl ShardMirror {
    /// Mirror gossiped `frame` (encoded as `data`) into `clock_store` once it
    /// verifies, hold it while it waits for its certified child, else say
    /// why not. A copy of the frame stored at its number is not checked
    /// again ([`stored_already`]).
    fn offer(
        &self,
        clock_store: &dyn quil_types::store::ClockStore,
        frame: &quil_types::proto::global::AppShardFrame,
        data: &[u8],
    ) -> Result<Mirrored, String> {
        if over_request_bound(frame) {
            return Err(format!(
                "carries {} request bundles, more than the {MIRROR_MAX_REQUESTS} checked",
                frame.requests.len()
            ));
        }
        let header = frame.header.as_ref().ok_or("no header")?;
        if stored_already(clock_store, header) {
            // Another writer (the worker drain) may have stored it: release
            // the parents held for it, as storing it here would have.
            self.release_held(clock_store, header);
            return Ok(Mirrored::Known);
        }
        let certified = header
            .public_key_signature_bls48581
            .as_ref()
            .is_some_and(|signature| !signature.signature.is_empty());
        match mirror_admits(&self.validator, frame) {
            Ok(()) => {}
            Err(reason) if certified => return Err(reason),
            Err(_) => return self.hold(clock_store, frame, data),
        }
        self.body_matches(frame)?;
        self.store(clock_store, header, data);
        Ok(Mirrored::Stored)
    }

    /// Whether `frame`'s carried requests match its header's root, as the
    /// archive ingest checks them: the certificate covers only the header.
    fn body_matches(&self, frame: &quil_types::proto::global::AppShardFrame) -> Result<(), String> {
        quil_engine::archive_ingest::requests_match_root(
            frame,
            self.execution.as_deref(),
            None,
            self.has_forest,
        )
        .map_err(|mismatch| mismatch.to_string())
    }

    /// Mirror an authenticated frame, then the held ancestors it links to.
    fn store(
        &self,
        clock_store: &dyn quil_types::store::ClockStore,
        header: &quil_types::proto::global::FrameHeader,
        data: &[u8],
    ) {
        super::worker_manager::mirror_shard_frame_to_clock_store(
            clock_store,
            &header.address,
            data,
        );
        self.release_held(clock_store, header);
    }

    /// Mirror the held frames the stored frame of `header` links down to,
    /// each through its child, unless a frame is stored at its number, and
    /// forget held frames too far below it to be owed.
    fn release_held(
        &self,
        clock_store: &dyn quil_types::store::ClockStore,
        header: &quil_types::proto::global::FrameHeader,
    ) {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut child = header.clone();
        while let (Some(below), Ok(identity)) = (
            child.frame_number.checked_sub(1),
            <[u8; 32]>::try_from(child.parent_selector.as_slice()),
        ) {
            let Some((parent, data)) = held.take_parent(&header.address, below, identity, &child)
            else {
                break;
            };
            // A frame another writer (the worker drain) stored at that
            // number stays, the held copy goes, and the walk goes on from
            // the stored frame: a held frame below links to it or stays.
            match clock_store.get_shard_clock_frame_header(&header.address, below) {
                Ok(stored) => child = stored,
                Err(_) => {
                    super::worker_manager::mirror_shard_frame_to_clock_store(
                        clock_store,
                        &header.address,
                        &data,
                    );
                    child = parent;
                }
            }
        }
        // A frame this far below a mirrored one is no ancestor still owed.
        held.prune_below(
            &header.address,
            header.frame_number.saturating_sub(MIRROR_HOLD_WINDOW),
        );
    }

    /// Hold a frame without a certificate of a registered shard, within
    /// [`MIRROR_HOLD_WINDOW`] of its stored head at a number with no stored
    /// frame and at most [`MIRROR_HELD_FRAME_BYTES`], whose header and
    /// requests verify otherwise; or mirror it when its stored child links
    /// to it.
    fn hold(
        &self,
        clock_store: &dyn quil_types::store::ClockStore,
        frame: &quil_types::proto::global::AppShardFrame,
        data: &[u8],
    ) -> Result<Mirrored, String> {
        let header = frame.header.as_ref().ok_or("no header")?;
        if !self.tracked.registered(&header.address) {
            return Err("no certificate, and the prover registry names no such shard".into());
        }
        let linked = header
            .frame_number
            .checked_add(1)
            .and_then(|number| {
                clock_store
                    .get_shard_clock_frame_header(&header.address, number)
                    .ok()
            })
            .is_some_and(|child| {
                quil_engine::frame_validator::app_frame_links_to_child(header, &child)
            });
        if !linked {
            let head = clock_store
                .get_latest_shard_clock_frame_number(&header.address)
                .ok()
                .flatten();
            if let Some(head) = head {
                if header.frame_number.abs_diff(head) > MIRROR_HOLD_WINDOW {
                    return Err(format!(
                        "no certificate, and more than {MIRROR_HOLD_WINDOW} frames from the \
                         stored head {head}"
                    ));
                }
                let stored = header.frame_number <= head
                    && clock_store
                        .get_shard_clock_frame_header(&header.address, header.frame_number)
                        .is_ok();
                if stored {
                    return Err("no certificate, and a frame is stored at its number".into());
                }
            }
            if data.len() > MIRROR_HELD_FRAME_BYTES {
                return Err(format!(
                    "no certificate, and {} bytes, more than the {MIRROR_HELD_FRAME_BYTES} held",
                    data.len()
                ));
            }
        }
        match self.validator.validate_linked_without_storage(frame) {
            Ok(true) => {}
            Ok(false) => return Err("no certificate, and the header does not verify".into()),
            Err(error) => return Err(format!("no certificate, and {error}")),
        }
        self.body_matches(frame)?;
        if linked {
            self.store(clock_store, header, data);
            return Ok(Mirrored::Stored);
        }
        let identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
            .map_err(|_| "no certificate, and no output identity".to_string())?;
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                (header.address.clone(), header.frame_number, identity),
                data.to_vec(),
            );
        Ok(Mirrored::Held)
    }

    /// Log what happened to held frames since the last line, at most once
    /// per [`MIRROR_HOLD_SUMMARY`] and only when something did; a warn when
    /// a real frame was lost to a bound. The counts logged, if a line was.
    fn summarize(&self, now: std::time::Instant) -> Option<HoldCounts> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let since = held.reported;
        if since.is_some_and(|last| now.saturating_duration_since(last) < MIRROR_HOLD_SUMMARY)
            || held.counts == HoldCounts::default()
        {
            return None;
        }
        held.reported = Some(now);
        let counts = std::mem::take(&mut held.counts);
        let (holding, holding_bytes) = (held.frames.len(), held.bytes);
        drop(held);
        let interval_s = since.map(|last| now.saturating_duration_since(last).as_secs());
        if counts.lost > 0 {
            warn!(
                lost = counts.lost,
                held = counts.held,
                released = counts.released,
                evicted = counts.evicted,
                pruned = counts.pruned,
                holding,
                holding_bytes,
                interval_s,
                scope = "peer",
                check = "a hold bound evicted real frames before their certified child arrived, \
                         so this node serves no frame at those numbers; many evictions mean a \
                         peer floods shard frame topics with well-formed frames",
                "shard frames held for their certified child were lost to a bound"
            );
        } else {
            info!(
                held = counts.held,
                released = counts.released,
                evicted = counts.evicted,
                pruned = counts.pruned,
                holding,
                holding_bytes,
                interval_s,
                scope = "peer",
                check = "none: a notarized frame is final through its certified child; evictions \
                         without losses are frames no certified child named",
                "shard frames without a certificate were held for their certified child before \
                 mirroring"
            );
        }
        Some(counts)
    }
}

impl HeldFrames {
    fn new(byte_cap: usize) -> Self {
        Self {
            frames: Default::default(),
            shard_bytes: Default::default(),
            by_size: Default::default(),
            bytes: 0,
            byte_cap,
            arrivals: 0,
            evicted: Default::default(),
            evicted_keys: Default::default(),
            counts: HoldCounts::default(),
            reported: None,
        }
    }

    /// The bytes a frame of `data` held under `key` takes.
    fn cost(key: &HeldKey, data: &[u8]) -> usize {
        data.len() + 2 * key.0.len() + MIRROR_HELD_ENTRY_OVERHEAD
    }

    fn remove(&mut self, key: &HeldKey) -> Option<Vec<u8>> {
        let (_, data) = self.frames.remove(key)?;
        let cost = Self::cost(key, &data);
        self.bytes -= cost;
        self.account(&key.0, |bytes| bytes - cost);
        Some(data)
    }

    /// Set `filter`'s held bytes to `change` of them, in both indexes.
    fn account(&mut self, filter: &[u8], change: impl FnOnce(usize) -> usize) {
        let before = self.shard_bytes.get(filter).copied().unwrap_or(0);
        let after = change(before);
        if before > 0 {
            self.by_size.remove(&(before, filter.to_vec()));
        }
        if after > 0 {
            self.shard_bytes.insert(filter.to_vec(), after);
            self.by_size.insert((after, filter.to_vec()));
        } else {
            self.shard_bytes.remove(filter);
        }
    }

    /// Evict `key` for a bound, remembering it.
    fn evict(&mut self, key: &HeldKey) {
        if self.remove(key).is_none() {
            return;
        }
        self.counts.evicted += 1;
        if self.evicted_keys.insert(key.clone()) {
            self.evicted.push_back(key.clone());
        }
        while self.evicted.len() > MIRROR_EVICTED_REMEMBERED {
            if let Some(oldest) = self.evicted.pop_front() {
                self.evicted_keys.remove(&oldest);
            }
        }
    }

    /// The held frame `number` of `filter` with output identity `identity`,
    /// taken when it links to `child`. A frame a bound evicted is counted
    /// lost.
    fn take_parent(
        &mut self,
        filter: &[u8],
        number: u64,
        identity: [u8; 32],
        child: &quil_types::proto::global::FrameHeader,
    ) -> Option<(quil_types::proto::global::FrameHeader, Vec<u8>)> {
        let key = (filter.to_vec(), number, identity);
        let Some((_, data)) = self.frames.get(&key) else {
            if self.evicted_keys.remove(&key) {
                self.evicted.retain(|evicted| evicted != &key);
                self.counts.lost += 1;
            }
            return None;
        };
        let parent =
            <quil_types::proto::global::AppShardFrame as prost::Message>::decode(data.as_slice())
                .ok()
                .and_then(|frame| frame.header)
                .filter(|parent| {
                    quil_engine::frame_validator::app_frame_links_to_child(parent, child)
                })?;
        let data = self.remove(&key)?;
        self.counts.released += 1;
        Some((parent, data))
    }

    /// Drop `filter`'s held frames numbered below `stale`.
    fn prune_below(&mut self, filter: &[u8], stale: u64) {
        let below: std::ops::Range<HeldKey> =
            (filter.to_vec(), 0, [0; 32])..(filter.to_vec(), stale, [0; 32]);
        let owed: Vec<HeldKey> = self
            .frames
            .range(below)
            .map(|(key, _)| key.clone())
            .collect();
        for key in owed {
            if self.remove(&key).is_some() {
                self.counts.pruned += 1;
            }
        }
    }

    /// Hold `data` under `key`, unless held already. Past the bounds go, in
    /// turn: the longest held at its number; the shard's farthest frame
    /// (frames held below the stored head can make that the next one); the
    /// largest frame of the shard holding the most bytes, of equal sizes the
    /// farthest ([`MIRROR_HELD_BYTES`]). Each step reads one number's
    /// frames, one shard's (at most [`MIRROR_HELD_PER_SHARD`]) or the size
    /// index, never the whole map.
    fn insert(&mut self, key: HeldKey, data: Vec<u8>) -> bool {
        if self.frames.contains_key(&key) {
            return false;
        }
        let number: std::ops::RangeInclusive<HeldKey> =
            (key.0.clone(), key.1, [0; 32])..=(key.0.clone(), key.1, [0xff; 32]);
        let shard: std::ops::RangeInclusive<HeldKey> =
            (key.0.clone(), 0, [0; 32])..=(key.0.clone(), u64::MAX, [0xff; 32]);
        self.arrivals += 1;
        let cost = Self::cost(&key, &data);
        self.bytes += cost;
        self.account(&key.0, |bytes| bytes + cost);
        self.frames.insert(key, (self.arrivals, data));
        self.counts.held += 1;
        if self.frames.range(number.clone()).count() > MIRROR_HELD_PER_NUMBER {
            let oldest = self
                .frames
                .range(number)
                .min_by_key(|(_, (arrival, _))| *arrival)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.evict(&oldest);
            }
        }
        if self.frames.range(shard.clone()).count() > MIRROR_HELD_PER_SHARD {
            let farthest = self
                .frames
                .range(shard)
                .next_back()
                .map(|(key, _)| key.clone());
            if let Some(farthest) = farthest {
                self.evict(&farthest);
            }
        }
        while self.bytes > self.byte_cap {
            let Some((_, heaviest)) = self.by_size.last() else {
                break;
            };
            let heaviest: std::ops::RangeInclusive<HeldKey> =
                (heaviest.clone(), 0, [0; 32])..=(heaviest.clone(), u64::MAX, [0xff; 32]);
            let Some(largest) = self
                .frames
                .range(heaviest)
                .max_by(|(key, (_, data)), (other, (_, other_data))| {
                    data.len()
                        .cmp(&other_data.len())
                        .then_with(|| key.cmp(other))
                })
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.evict(&largest);
        }
        true
    }
}

/// Whether the frame stored at `header`'s number has this header, its
/// storage attestation aside. The stored copy's requests matched it, so a
/// copy carrying other requests is no frame to mirror, and its check, which
/// a peer's frame of many bundles makes cost seconds, is skipped. Reads
/// only the stored header, not the stored requests.
fn stored_already(
    clock_store: &dyn quil_types::store::ClockStore,
    header: &quil_types::proto::global::FrameHeader,
) -> bool {
    clock_store
        .get_shard_clock_frame_header(&header.address, header.frame_number)
        .is_ok_and(|mut stored| {
            stored
                .storage_attestation
                .clone_from(&header.storage_attestation);
            &stored == header
        })
}

/// Whether `frame` carries more request bundles than the mirror checks:
/// [`ShardMirror::offer`] refuses it first, before its certificate is.
fn over_request_bound(frame: &quil_types::proto::global::AppShardFrame) -> bool {
    frame.requests.len() > MIRROR_MAX_REQUESTS
}

/// How often the gossiped shard frames refused for the mirror are summarized.
const MIRROR_REFUSAL_SUMMARY: std::time::Duration = std::time::Duration::from_secs(600);

/// Gossiped shard frames this node refused to mirror: one line at the first,
/// then at most one per [`MIRROR_REFUSAL_SUMMARY`] with the counts since.
static MIRROR_REFUSALS: MirrorRefusals = MirrorRefusals::new();

/// Refusals since the last line, and when it was logged.
struct RefusalState {
    /// Frames refused.
    refused: u64,
    /// Of those, frames over the request bundle bound ([`over_request_bound`]),
    /// refused before their certificate was checked.
    over_bound: u64,
    last: Option<std::time::Instant>,
}

struct MirrorRefusals {
    state: std::sync::Mutex<RefusalState>,
}

impl MirrorRefusals {
    const fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(RefusalState {
                refused: 0,
                over_bound: 0,
                last: None,
            }),
        }
    }

    /// `frame` was refused for `reason` at `now`; the counts logged
    /// (refused, and of those over the bundle bound), if a line is due.
    fn note(
        &self,
        frame: &quil_types::proto::global::AppShardFrame,
        reason: String,
        now: std::time::Instant,
    ) -> Option<(u64, u64)> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.refused += 1;
        if over_request_bound(frame) {
            state.over_bound += 1;
        }
        if state
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < MIRROR_REFUSAL_SUMMARY)
        {
            return None;
        }
        let refused = std::mem::take(&mut state.refused);
        let over_bound = std::mem::take(&mut state.over_bound);
        let since = state.last.replace(now);
        drop(state);
        let header = frame.header.as_ref();
        info!(
            refused,
            over_bound,
            interval_s = since.map(|last| now.saturating_duration_since(last).as_secs()),
            filter = %hex::encode(header.map(|h| h.address.as_slice()).unwrap_or_default()),
            frame = header.map(|h| h.frame_number),
            %reason,
            scope = "peer",
            check = "frames that verify later are mirrored as they arrive; many refusals with \
                     a missing anchored GLOBAL frame mean this node's GLOBAL view lags; a \
                     refused certificate, header or requests is a peer's forged frame (a frame \
                     without a certificate that verifies otherwise is held for its certified \
                     child, not refused); over_bound frames carried more request bundles than \
                     the mirror checks and were refused unchecked, forged or genuine: this \
                     node serves no frame at a genuine one's number",
            "gossiped shard frames were not mirrored for serving: they did not verify, or \
             carried more request bundles than are checked (the latest named)"
        );
        Some((refused, over_bound))
    }
}

/// Admits a GLOBAL_PROVER message: a capacity message is charged to its
/// member's share from the message's signer, or its direct sender.
pub(super) fn admit_prover_message(
    collector: &quil_engine::message_collector::MessageCollector,
    rank: u64,
    received: quil_p2p::node::ReceivedMessage,
    provenance: quil_engine::message_collector::Provenance,
) -> quil_engine::message_collector::SubmitOutcome {
    collector.add_message_outcome_by(rank, received.data, provenance, &received.from)
}

/// An app-shard frame an archive fetched to fill a gap, fed back through the
/// consensus loopback under the frame's own gossip topic, as if gossiped.
pub(crate) fn gap_fetched_frame_message(
    filter: &[u8],
    data: Vec<u8>,
) -> quil_p2p::node::ReceivedMessage {
    quil_p2p::node::ReceivedMessage {
        bitmask: quil_engine::bitmasks::shard_frame_bitmask(filter),
        data,
        from: Vec::new(),
        via: Vec::new(),
        direct: false,
    }
}

/// The stream endpoints a verified archive's PeerInfo names, each pinned to
/// the archive that signed it before the pool dials it, so that whoever
/// answers there must be that archive. An endpoint pinned to another
/// archive is left out (its pin stays), as is every endpoint of a record
/// whose peer id does not parse.
pub(crate) fn archive_record_endpoints(
    info: &quil_p2p::CanonicalPeerInfo,
    network: u8,
) -> Vec<String> {
    let Ok(peer) = quil_p2p::PeerId::from_bytes(&info.peer_id) else {
        return Vec::new();
    };
    let mut endpoints = Vec::new();
    for reach in &info.reachability {
        for ma in &reach.stream_multiaddrs {
            let Some(addr) =
                crate::util::multiaddr::multiaddr_to_host_port_with_network(ma, network)
            else {
                continue;
            };
            if let Err(held) = quil_rpc::archive_client::pin_archive_peer(&addr, peer) {
                warn!(
                    peer = %peer,
                    endpoint = %addr,
                    pinned_to = %held,
                    scope = "peer",
                    "archive record names an endpoint pinned to another archive: not dialed"
                );
                continue;
            }
            if !endpoints.contains(&addr) {
                endpoints.push(addr);
            }
        }
    }
    endpoints
}

/// Add a verified archive record's stream endpoints to `pool`, each pinned
/// to that archive first ([`archive_record_endpoints`]); returns the first.
pub(crate) async fn add_archive_record_endpoints(
    pool: &quil_rpc::ArchiveEndpointPool,
    info: &quil_p2p::CanonicalPeerInfo,
    network: u8,
) -> Option<String> {
    let endpoints = archive_record_endpoints(info, network);
    let first = endpoints.first().cloned();
    for addr in endpoints {
        pool.add(addr).await;
    }
    first
}

/// The members `read` gives of shard `filter`, none when no session names
/// them, only if the prover registry names the shard: a peer names any
/// filter it likes, and only registered shards are read and kept.
fn registered_shard_members(
    tracked: &quil_engine::archive_ingest::TrackedShards,
    filter: &[u8],
    read: impl FnOnce() -> Option<Vec<Vec<u8>>>,
) -> Option<Vec<Vec<u8>>> {
    tracked
        .registered(filter)
        .then(|| read().unwrap_or_default())
}

/// The peer IDs of shard `filter`'s committee members in the committed
/// GLOBAL session, if it has one: the mirror queues a frame its member
/// signed under the member ([`MirrorState::sender_key`]).
fn shard_member_peers(
    global: &Arc<quil_hypergraph::HypergraphCrdt>,
    filter: &[u8],
) -> Option<Vec<Vec<u8>>> {
    use quil_execution::global_intrinsic::handoff::{self, CommittedView};
    let view = CommittedView::capture(global).ok()?;
    let session = handoff::head(&view, filter).ok()??;
    Some(
        session
            .members
            .iter()
            .map(|key| quil_p2p::peer_id_from_falcon_pubkey(key))
            .collect(),
    )
}

fn shard_sender_key(
    keys: &mut super::shard_sender::ShardSenderKeys,
    peer: &[u8],
    peer_info_key: Option<Vec<u8>>,
    global: &Arc<quil_hypergraph::HypergraphCrdt>,
    filter: &[u8],
) -> Vec<u8> {
    keys.resolve(peer, peer_info_key, || {
        use quil_execution::global_intrinsic::handoff::{self, CommittedView};
        let view = CommittedView::capture(global).ok()?;
        handoff::head(&view, filter)
            .ok()?
            .map(|session| session.members)
    })
}

pub(crate) fn spawn(sup: &mut Supervisor<anyhow::Error>, args: MessageLoopArgs) {
    let MessageLoopArgs {
        remote_workers: remote_workers_for_recv,
        local_cw_tag,
        clock_store: clock_store_recv,
        exec_manager: exec_mgr_for_recv,
        msg_rx,
        mut consensus_loopback_rx,
        remote_consensus:
            super::consensus_intake::RemoteConsensusQueues {
                members: mut remote_members_rx,
                others: mut remote_others_rx,
            },
        global_msg_tx: gmtx_for_recv,
        archive_pool: pool_for_recv,
        mtls_seed: _mtls_seed_for_recv,
        prover_falcon_key: prover_falcon_for_recv,
        hg_store: hg_store_for_recv,
        frame_validator: frame_validator_for_recv,
        message_collector: mc_for_recv,
        coverage_monitor: coverage_for_recv,
        worker_allocator: wa_for_recv,
        prover_pipeline: pp_for_recv,
        peer_info_cache: pic_for_recv,
        shard_engines: shard_engines_for_recv,
        signer_registry: sr_for_recv,
        current_frame: cf_for_recv,
        last_global_head_frame: lhf_for_recv,
        gossip_freshness: gossip_freshness_for_recv,
        genesis_archive_peer_ids: genesis_archive_peer_ids_for_recv,
        genesis_prover_addrs: genesis_prover_addrs_for_recv,
        alert_pubkey: alert_pubkey_for_recv,
        network: network_for_recv,
        crdt: crdt_for_recv,
        genesis_seed: genesis_seed_for_recv,
        archive_mode: archive_mode_recv,
        config_brief,
        prover_lifecycle: pl_for_recv,
        prover_registry: pr_for_recv,
        worker_manager: wm_for_recv,
        prover_address: pa_for_recv,
        p2p_handle: p2p_for_recv,
        time_reel: time_reel_for_recv,
        spawner,
        archive_app_shard_ingest,
        recent_messages: recent_messages_for_recv,
        cw_router: cw_router_for_recv,
        global_finalization: global_finalization_for_recv,
        activation_waits: activation_waits_for_recv,
    } = args;
    // Shard consensus messages go to their engines from their own task, so
    // that the loop's GLOBAL work holds back only the loop's messages.
    let shard_sender_keys = Arc::new(std::sync::Mutex::new(
        super::shard_sender::ShardSenderKeys::default(),
    ));
    let loop_queue_drops = Arc::new(super::shard_cw_lane::LoopQueueDrops::default());
    let inbound = msg_rx;
    let (to_loop, mut msg_rx) = tokio::sync::mpsc::channel(LOOP_QUEUE);
    {
        let engines = shard_engines_for_recv.clone();
        let peer_infos = pic_for_recv.clone();
        let global = crdt_for_recv.clone();
        let keys = shard_sender_keys.clone();
        let ring = recent_messages_for_recv.clone();
        let drops = loop_queue_drops.clone();
        sup.run_until_cancelled("shard-cw-lane", move |_| async move {
            super::shard_cw_lane::run(inbound, to_loop, drops, move |received| {
                let Some((filter, handle)) = engines.read().iter().find_map(|(filter, handle)| {
                    (quil_engine::bitmasks::shard_cw_bitmask(filter) == received.bitmask)
                        .then(|| (filter.clone(), handle.clone()))
                }) else {
                    return false;
                };
                if let Some(ring) = &ring {
                    ring.push_received(&received.from, &received.bitmask, &received.data);
                }
                // A transmission naming another member is dropped here, unread.
                if let Some((channel, cw_bytes)) =
                    quil_engine::bitmasks::shard_cw_admit(&filter, &received.data, &local_cw_tag)
                {
                    let peer_info_key = peer_infos
                        .read()
                        .get(&received.from)
                        .map(|info| info.public_key.clone());
                    let from_key = shard_sender_key(
                        &mut keys
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                        &received.from,
                        peer_info_key,
                        &global,
                        &filter,
                    );
                    tracing::debug!(filter = %hex::encode(&filter), channel,
                        sender_known = !from_key.is_empty(), bytes = cw_bytes.len(),
                        "routing shard CW message to its engine");
                    handle.send(quil_engine::app_engine::AppEngineMessage::CwIn {
                        channel,
                        from: from_key,
                        data: cw_bytes.to_vec(),
                    });
                }
                true
            })
            .await;
            Ok(())
        });
    }
    // Gossiped application frames and the ingest's retry pass run on their
    // own thread: GLOBAL execution holds the ingest while it sequences
    // application frames, and this loop must never wait for it.
    let archive_ingest_queue = archive_app_shard_ingest.map(|ingest| {
        // Verified without holding the ingest, which is held only to admit.
        let verifier = ingest.lock().unwrap_or_else(|p| p.into_inner()).verifier();
        // Frames naming no shard the archive tracks never take queue room.
        let admits = verifier.clone();
        let retrying = ingest.clone();
        let queue = super::archive_ingest_queue::ArchiveIngestQueue::spawn(
            super::archive_ingest_queue::QUEUE_FRAMES,
            super::archive_ingest_queue::QUEUE_BYTES,
            super::archive_ingest_queue::RETRY_EVERY,
            Some(super::stall_watch::watch(
                ProbeSection::ArchiveIngest,
                super::stall_watch::ARCHIVE_INGEST_IMPACT,
                super::stall_watch::ARCHIVE_INGEST_STALL_AFTER,
            )),
            move |data| quil_engine::archive_ingest::ingest_gossiped(&ingest, &verifier, data),
            move || quil_engine::archive_ingest::lock_ingest(&retrying).retry_pending(),
        );
        (queue, admits)
    });
    // A node without an archive ingest (a cluster master) mirrors the shard
    // frames gossiped for shards no local engine runs, once they verify, on
    // the mirror's own thread: this loop only queues them.
    let mirror_feed = archive_ingest_queue.is_none().then(|| {
        let mirror = shard_mirror(
            pr_for_recv.clone(),
            clock_store_recv.clone(),
            crdt_for_recv.clone(),
            Some(exec_mgr_for_recv.clone()),
        );
        let clock = clock_store_recv.clone();
        let global = crdt_for_recv.clone();
        let tracked = mirror.tracked.clone();
        MirrorFeed::spawn(
            move |data| mirror_queued(clock.as_ref(), &mirror, data),
            move |filter| {
                registered_shard_members(&tracked, filter, || shard_member_peers(&global, filter))
            },
        )
    });
    // GLOBAL_FRAME admission state shared with the gossip gate: a frame this
    // loop accepted is neither forwarded nor checked again, and a header whose
    // certificate and VDF verified skips both checks on later copies.
    let global_frame_gate_for_recv = p2p_for_recv.global_frame_gate();

    // Global bitmasks for BlossomSub topic subscriptions.
    const GLOBAL_CONSENSUS: &[u8] = &[0x00];
    const GLOBAL_FRAME: &[u8] = &[0x00, 0x00];
    const GLOBAL_PROVER: &[u8] = &[0x00, 0x00, 0x00];
    const GLOBAL_PEER_INFO: &[u8] = &[0x00, 0x00, 0x00, 0x00];
    const GLOBAL_ALERT: &[u8] = &[0u8; 16];

    // Per-bitmask validator gate. Malformed bytes are dropped here so
    // the dispatch loop below stays cheap. Topics without a registered
    // validator fall through unchanged.
    let message_router = Arc::new(quil_engine::message_router::MessageRouter::new());
    message_router.register_validator(
        GLOBAL_PEER_INFO.to_vec(),
        quil_engine::message_router::validator_global_peer_info(),
    );
    message_router.register_validator(
        GLOBAL_PROVER.to_vec(),
        quil_engine::message_router::validator_global_prover(),
    );
    message_router.register_validator(
        GLOBAL_FRAME.to_vec(),
        quil_engine::message_router::validator_global_frame(),
    );
    message_router.register_validator(
        GLOBAL_CONSENSUS.to_vec(),
        quil_engine::message_router::validator_global_consensus(),
    );
    let router_for_recv = message_router.clone();

    let reward_issuer: Arc<quil_engine::OptRewardIssuance> =
        Arc::new(quil_engine::OptRewardIssuance);
    let archive_mode_for_recv: bool = archive_mode_recv;

    // Bundle every cache/map we want to size-report in the 30s
    // status tick. Cheap clone (all Arc inside) so it can move into
    // the recv-loop closure alongside everything else.
    let mem_sources = crate::mem_stats::StructuralSources {
        peer_info_cache: pic_for_recv.clone(),
        shard_engines: shard_engines_for_recv.clone(),
        signer_registry: sr_for_recv.clone(),
        prover_registry: pr_for_recv.clone(),
        time_reel: time_reel_for_recv.clone(),
    };

    // A blocked loop holds every inbound message; the watchdog names where.
    let loop_probe = super::stall_watch::watch(
        ProbeSection::MessageLoop,
        super::stall_watch::MESSAGE_LOOP_IMPACT,
        super::stall_watch::MESSAGE_LOOP_STALL_AFTER,
    );
    sup.spawn("message-loop", move |recv_token| probe::task_probed(loop_probe, async move {
        let mut time_reel_rx = time_reel_for_recv
            .as_ref()
            .and_then(|tr| tr.take_event_rx());
        let mut frames_received: u64 = 0;
        let mut peer_infos_received: u64 = 0;
        let mut peer_info_digest_cache: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        // Peers whose build identity this run has logged.
        let mut peer_builds_logged: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut other_build_lines_left = OTHER_BUILD_LINES_PER_STATUS;
        // Bounds of the PeerInfo cache; the records restored from the last
        // run are indexed first.
        let mut peer_info_bounds = super::peer_info_bounds::PeerInfoBounds::default();
        peer_info_bounds.adopt(&mut pic_for_recv.write(), |info| {
            super::peer_info_bounds::preferred(info, &genesis_archive_peer_ids_for_recv, &*pr_for_recv)
        });
        let mut archive_peers_seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut drain_raise_watch = super::drain_raise_watch::RaiseWatch::default();
        // When the loop started: archives announce themselves about every
        // thirty minutes, so the first one is verified up to that long after it.
        let loop_started = std::time::Instant::now();
        let mut consensus_msgs_received: u64 = 0;
        let mut prover_msgs_received: u64 = 0;
        let mut router_drops: u64 = 0;
        // Per-topic drop counters so we can tell which validator is
        // doing the rejecting. Without these, all four global
        // validators' drops are lumped into `router_drops` and we
        // can't distinguish a peer-info flood from a frame flood
        // from per-shard noise.
        let mut router_drops_peer_info: u64 = 0;
        let mut router_drops_prover: u64 = 0;
        let mut router_drops_frame: u64 = 0;
        let mut router_drops_consensus: u64 = 0;
        let mut router_drops_alert: u64 = 0;
        let mut router_drops_other: u64 = 0;
        // Per-reason aggregation (validator reject string -> count).
        // Bounded by the static set of `&'static str` reasons the
        // validators emit; size <= ~20 keys in practice.
        let mut router_drops_by_reason: std::collections::HashMap<&'static str, u64> =
            std::collections::HashMap::new();
        // Per-SOURCE aggregation (signed author -> dropped-message count) since
        // the last status line. Distinguishes a targeted flood (drops
        // concentrated on one/few authors → blacklist candidate) from systemic
        // backlog aging (drops spread across many → this node is overloaded,
        // not attacked). Authors are free to mint, so at most
        // `MAX_DROP_SOURCES` are tracked per status interval; drops of further
        // authors are counted in `router_drops_untracked_sources`.
        let mut router_drops_by_source: std::collections::HashMap<Vec<u8>, u64> =
            std::collections::HashMap::new();
        let mut router_drops_untracked_sources: u64 = 0;
        // Digests of the GLOBAL_ALERTs already verified and shown: a copy is
        // neither verified nor shown again (the signature covers no time, so
        // an alert can be re-broadcast at will).
        let mut alerts_seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut status_timer = tokio::time::interval(std::time::Duration::from_secs(30));
        status_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut global_execution = super::global_execution::GlobalExecution::default();
        // Shard CW topics this node takes direct messages on for its
        // standalone workers, kept in step with the shards they run, and
        // those whose worker lacks `DeliverShardConsensus` (an older build).
        let mut remote_direct_timer = tokio::time::interval(std::time::Duration::from_secs(5));
        remote_direct_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut committee_peer_timer = tokio::time::interval(std::time::Duration::from_secs(5));
        committee_peer_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let committee_peer_busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut peer_policy_unavailable = super::committee_peer_policy::Unavailability::default();
        let mut committee_builds = super::committee_builds::CommitteeBuilds::default();
        let mut committee_builds_checked = std::time::Instant::now();
        let mut host_memory_watch = crate::mem_stats::HostMemoryWatch::default();
        let mut last_committee_peers = std::collections::HashSet::new();
        let mut epoch_writes = super::disk_writes::EpochWrites::default();
        let mut pending_committee_policy: Option<(std::collections::HashSet<quil_p2p::PeerId>, Arc<std::sync::atomic::AtomicBool>)> = None;
        let mut remote_direct_allowed: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let remote_direct_unsupported: Arc<parking_lot::Mutex<std::collections::HashSet<Vec<u8>>>> =
            Default::default();
        // Track the highest frame number we've fully executed (through
        // the execution manager + lifecycle). New frames arriving via
        // gossip can be wildly out of order; only execute consecutive
        // frames starting from `last_executed + 1` so prover-state
        // dependent ops (ProverConfirm/Resume against a prover the
        // previous frame registered) don't fail spuriously. Seeded
        // from the latest frame already in the clock store so a
        // restart picks up where it left off.
        let mut last_executed_frame: u64 = clock_store_recv
            .get_latest_global_frame()
            .ok()
            .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
            .unwrap_or(0);
        // Epoch of the last frame whose crossing triggered a registry refresh.
        // Prover ALLOCATIONS only take effect at epoch boundaries
        // (`effective_status` is epoch-quantized: activation/departure/expiry all
        // flip on `epoch_for_frame` boundaries), so the shared prover-registry
        // cache — which drives every worker's app-shard COMMITTEE and this loop's
        // `on_new_frame` reconcile — only needs to be refreshed once per epoch.
        // Refreshing per-frame is both wasteful (a full O(N) store scan) and, on
        // the recv path, was simply ABSENT: `on_new_frame` reconciled against a
        // never-refreshed cache on non-archive nodes. Track the epoch and refresh
        // exactly on a boundary crossing.
        let mut last_committee_epoch: u64 =
            quil_types::consensus::epoch_for_frame(last_executed_frame);
        loop {
            // Its timers bring the loop round at least every five seconds.
            probe::beat();
            tokio::select! {
                _ = remote_direct_timer.tick() => {
                    probe::step(ProbeSection::LoopRemoteDirect);
                    if let Some(remote) = remote_workers_for_recv.get() {
                        let served: std::collections::HashSet<Vec<u8>> = remote
                            .served_filters()
                            .iter()
                            .map(|filter| quil_engine::bitmasks::shard_cw_bitmask(filter))
                            .collect();
                        let in_process: std::collections::HashSet<Vec<u8>> = shard_engines_for_recv
                            .read()
                            .keys()
                            .map(|filter| quil_engine::bitmasks::shard_cw_bitmask(filter))
                            .collect();
                        let unsupported = remote_direct_unsupported.lock().clone();
                        for topic in &served {
                            if !unsupported.contains(topic) && remote_direct_allowed.insert(topic.clone()) {
                                p2p_for_recv.allow_direct(topic.clone()).await;
                            }
                        }
                        let released: Vec<Vec<u8>> = remote_direct_allowed
                            .iter()
                            .filter(|topic| !served.contains(*topic) || unsupported.contains(*topic))
                            .cloned()
                            .collect();
                        for topic in released {
                            remote_direct_allowed.remove(&topic);
                            if !in_process.contains(&topic) {
                                p2p_for_recv.revoke_direct(topic).await;
                            }
                        }
                    }
                }
                _ = committee_peer_timer.tick() => {
                    probe::step(ProbeSection::LoopCommitteePeers);
                    if !committee_peer_busy.load(std::sync::atomic::Ordering::Acquire) {
                        if let Some((peers, applied)) = pending_committee_policy.take() {
                            if applied.load(std::sync::atomic::Ordering::Acquire) { last_committee_peers = peers; }
                        }
                    }
                    use quil_execution::global_intrinsic::handoff::{self, CommittedView};
                    let mut filters: std::collections::BTreeSet<Vec<u8>> =
                        shard_engines_for_recv.read().keys().cloned().collect();
                    if let Some(remote) = remote_workers_for_recv.get() {
                        filters.extend(remote.served_filters());
                    }
                    // Read one committed snapshot, then drop it before any await.
                    let desired = CommittedView::capture(&crdt_for_recv).and_then(|view|
                        super::committee_peer_policy::collect(&filters, |filter| handoff::head(&view, filter)));
                    match desired {
                        Ok(peers) if peers != last_committee_peers => {
                            peer_policy_unavailable.recovered(std::time::Instant::now());
                            if committee_peer_busy.compare_exchange(false, true,
                                std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Relaxed).is_ok()
                            {
                                let guard = super::committee_peer_policy::RefreshGuard(committee_peer_busy.clone());
                                let p2p = p2p_for_recv.clone();
                                // Keep a failed update retryable, including timeout/cancellation.
                                let expected = peers.clone();
                                let applied = Arc::new(std::sync::atomic::AtomicBool::new(false));
                                let applied_for_task = applied.clone();
                                spawner.detach("committee-peer-policy", async move {
                                    let _guard = guard;
                                    match tokio::time::timeout(std::time::Duration::from_secs(2), p2p.set_committee_peers(peers)).await {
                                        Ok(Ok(count)) => {
                                            applied_for_task.store(true, std::sync::atomic::Ordering::Release);
                                            info!(committee_peers = count, "committed committee IP-colocation exemptions refreshed");
                                        }
                                        Ok(Err(error)) => warn!(%error, "committee peer policy refresh failed"),
                                        Err(_) => warn!("committee peer policy refresh timed out"),
                                    }
                                    Ok(())
                                });
                                // Result is observed on the next tick, without blocking ingress.
                                pending_committee_policy = Some((expected, applied));
                            }
                        }
                        Ok(_) => {
                            peer_policy_unavailable.recovered(std::time::Instant::now());
                        }
                        Err(error) => {
                            peer_policy_unavailable.failed(&error, std::time::Instant::now());
                        }
                    }
                    // Which build each member of a served committee runs, by its
                    // verified PeerInfo (committee_builds.rs).
                    committee_builds.retain(&filters);
                    let now = std::time::Instant::now();
                    let builds_due = now.duration_since(committee_builds_checked) >= std::time::Duration::from_secs(60);
                    if builds_due {
                        committee_builds_checked = now;
                    }
                    if let Some(view) = builds_due.then(|| CommittedView::capture(&crdt_for_recv).ok()).flatten() {
                        for filter in &filters {
                            let Ok(Some(session)) = handoff::head(&view, filter) else { continue };
                            let Ok(id) = session.id() else { continue };
                            if !committee_builds.due(filter, id, now) {
                                continue;
                            }
                            // Each member's build, release and reported GLOBAL head;
                            // this node and members without PeerInfo report no head.
                            let (mut builds, mut releases, mut heads) = (Vec::new(), Vec::new(), Vec::new());
                            {
                                // A head reported over an hour ago is not current:
                                // a live member republishes every 30 minutes.
                                let now_ms = super::peer_info_file::unix_millis();
                                let infos = pic_for_recv.read();
                                for key in &session.members {
                                    if quil_engine::bitmasks::shard_cw_addressee_tag(key) == local_cw_tag {
                                        builds.push(super::committee_builds::Build::ThisNode);
                                        releases.push(super::committee_builds::Release::ThisNode);
                                        heads.push(None);
                                    } else {
                                        let info = infos.get(&quil_p2p::peer_id_from_falcon_pubkey(key));
                                        builds.push(super::committee_builds::Build::of(info.map(|info| info.build_fingerprint())));
                                        releases.push(super::committee_builds::Release::of(info.map(|info| info.release())));
                                        heads.push(info.filter(|info| super::peer_info_file::head_is_current(info, now_ms))
                                            .map(|info| info.last_global_head_frame));
                                    }
                                }
                            }
                            let global_head = lhf_for_recv.load(std::sync::atomic::Ordering::Relaxed);
                            let behind = super::committee_builds::behind_global(&heads, global_head);
                            let behind_list = if behind.is_empty() { "none".to_string() } else { behind.join(",") };
                            info!(
                                scope = "peer",
                                filter = %hex::encode(filter),
                                generation = session.generation,
                                session = %hex::encode(id),
                                members = builds.len(),
                                builds = %super::committee_builds::groups(&builds),
                                releases = %super::committee_builds::release_groups(&releases),
                                global_head,
                                behind_global = %behind_list,
                                "app committee member builds by member index"
                            );
                            if !behind.is_empty() {
                                warn!(
                                    scope = "peer",
                                    filter = %hex::encode(filter),
                                    generation = session.generation,
                                    members = builds.len(),
                                    behind = behind.len(),
                                    behind_global = %behind_list,
                                    behind_releases = %super::committee_builds::behind_releases(&heads, &releases, global_head),
                                    global_head,
                                    action = super::committee_builds::BEHIND_ACTION,
                                    "app committee members behind GLOBAL"
                                );
                            }
                            if committee_builds.caught_up(filter, !behind.is_empty()) {
                                info!(
                                    scope = "peer",
                                    filter = %hex::encode(filter),
                                    generation = session.generation,
                                    members = builds.len(),
                                    global_head,
                                    "app committee members caught up with GLOBAL"
                                );
                            }
                        }
                    }
                }
                _ = status_timer.tick() => {
                    probe::step(ProbeSection::LoopStatus);
                    if let Some((queue, _)) = archive_ingest_queue.as_ref() {
                        queue.report_dropped(30);
                    }
                    // Periodic allocation status snapshot.
                    let peer_count = p2p_for_recv.peer_count();
                    // Archive endpoints in use (seeded at startup or learned);
                    // `archive_peers` counts only archives verified from their
                    // own PeerInfo since start.
                    // An await: a step, since a section guard cannot cross it.
                    probe::step(ProbeSection::StatusArchivePool);
                    let archive_endpoints = pool_for_recv.len().await;
                    probe::step(ProbeSection::LoopStatus);
                    // Resolver messages delivered point-to-point instead of to
                    // the shard topic, cumulative since start.
                    let direct = p2p_for_recv.direct_stats();
                    let sender_keys = {
                        let keys = shard_sender_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        (keys.peer_info, keys.session, keys.cached, keys.unresolved)
                    };
                    let latest_frame = {
                        let _read = probe::section(ProbeSection::LatestGlobalFrameRead);
                        clock_store_recv.get_latest_global_frame()
                    }
                        .ok()
                        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
                        .unwrap_or(0);
                    global_execution.observe(std::time::Instant::now(), cf_for_recv.materialized(), cf_for_recv.effective());
                    // This process's disk writes, one line per epoch.
                    if latest_frame > 0 {
                        epoch_writes.observe(
                            quil_types::consensus::epoch_for_frame(latest_frame),
                            std::time::Instant::now(),
                        );
                    }
                    // Strict GLOBAL_PEER_INFO validation follows the GLOBAL head.
                    let strict_peer_info = quil_types::consensus::strict_peer_info_active(latest_frame);
                    if quil_p2p::set_strict_peer_info_validation(strict_peer_info) != strict_peer_info {
                        info!(
                            frame = latest_frame,
                            epoch = quil_types::consensus::strict_peer_info_epoch(),
                            strict = strict_peer_info,
                            "GLOBAL_PEER_INFO validation changed: when strict, peers forwarding invalid PeerInfo, KeyRegistry or alerts are penalised and KeyRegistry records with an unsigned timestamp are refused"
                        );
                    }
                    // Strict shard gossip follows it too.
                    let strict_shard_gossip = quil_types::consensus::strict_shard_gossip_active(latest_frame);
                    if quil_p2p::set_strict_shard_gossip(strict_shard_gossip) != strict_shard_gossip {
                        info!(
                            frame = latest_frame,
                            epoch = quil_types::consensus::strict_shard_gossip_epoch(),
                            strict = strict_shard_gossip,
                            "shard gossip validation changed: when strict, peers forwarding a message no leader can propose on a shard's dispatch or submission topic are penalised and shard CW message ids name their author"
                        );
                    }
                    {
                        let _write = probe::section(ProbeSection::StatusPeerInfoCache);
                        peer_info_bounds.expire(&mut pic_for_recv.write(), super::peer_info_file::unix_millis());
                    }
                    other_build_lines_left = OTHER_BUILD_LINES_PER_STATUS;
                    let (active, pending, total_allocs) = {
                        use quil_types::consensus::{EffectiveStatus, ProverRegistry};
                        let info = {
                            let _read = probe::section(ProbeSection::ProverInfoRead);
                            pr_for_recv.get_prover_info(&pa_for_recv)
                        };
                        match info {
                            Ok(Some(info)) => {
                                let mut a = 0usize;
                                let mut p = 0usize;
                                let mut total = 0usize;
                                for alloc in &info.allocations {
                                    match alloc.effective_status(latest_frame) {
                                        EffectiveStatus::Active => {
                                            a += 1;
                                            total += 1;
                                        }
                                        EffectiveStatus::Joining => {
                                            p += 1;
                                            total += 1;
                                        }
                                        EffectiveStatus::Paused | EffectiveStatus::Leaving => {
                                            total += 1;
                                        }
                                        _ => {}
                                    }
                                }
                                (a, p, total)
                            }
                            _ => (0, 0, 0),
                        }
                    };
                    info!(
                        peers = peer_count,
                        frame = latest_frame,
                        frames_received,
                        active_shards = active,
                        pending_joins = pending,
                        total_allocations = total_allocs,
                        peer_infos = peer_infos_received,
                        cw_sender_peer_info = sender_keys.0,
                        cw_sender_session = sender_keys.1,
                        cw_sender_cached = sender_keys.2,
                        cw_sender_unresolved = sender_keys.3,
                        loop_queue_full = loop_queue_drops.total(),
                        archive_endpoints,
                        archive_peers = archive_peers_seen.len(),
                        consensus_msgs = consensus_msgs_received,
                        prover_msgs = prover_msgs_received,
                        router_drops,
                        direct_delivered = direct.delivered,
                        direct_fallbacks = direct.fallbacks,
                        direct_refused = direct.refused,
                        direct_not_connected = direct.not_connected,
                        direct_unsupported = direct.unsupported,
                        direct_failed = direct.failed,
                        direct_received = direct.received,
                        direct_received_refused = direct.received_refused,
                        gossip_received = direct.gossip_received,
                        gossip_received_queue_full = direct.gossip_received_queue_full,
                        gossip_received_queue_closed = direct.gossip_received_queue_closed,
                        rdrop_peer_info = router_drops_peer_info,
                        rdrop_prover = router_drops_prover,
                        rdrop_frame = router_drops_frame,
                        rdrop_consensus = router_drops_consensus,
                        rdrop_alert = router_drops_alert,
                        rdrop_other = router_drops_other,
                        rdrop_reasons = %{
                            // Render as `reason1=N,reason2=M,...` sorted
                            // descending by count so the most-common
                            // cause is first. Bounded to top 8 to keep
                            // the log line under control.
                            let mut entries: Vec<(&&str, &u64)> =
                                router_drops_by_reason.iter().collect();
                            entries.sort_by(|a, b| b.1.cmp(a.1));
                            entries.into_iter().take(8)
                                .map(|(k, v)| format!("{}={}", k, v))
                                .collect::<Vec<_>>()
                                .join(",")
                        },
                        // Top drop sources: `peer(short-hex)=count`, most first.
                        // A single peer dominating ⇒ targeted flood; even spread
                        // ⇒ this node is backlog-aging (overloaded), not attacked.
                        drop_sources = %{
                            let mut entries: Vec<(&Vec<u8>, &u64)> =
                                router_drops_by_source.iter().collect();
                            entries.sort_by(|a, b| b.1.cmp(a.1));
                            entries.into_iter().take(8)
                                .map(|(k, v)| {
                                    let h = hex::encode(k);
                                    let short = if h.len() > 12 { &h[..12] } else { &h };
                                    format!("{}={}", short, v)
                                })
                                .collect::<Vec<_>>()
                                .join(",")
                        },
                        config = %config_brief,
                        drop_sources_untracked = router_drops_untracked_sources,
                        "node status"
                    );
                    // Drop sources are reported per status interval.
                    router_drops_by_source.clear();
                    router_drops_untracked_sources = 0;
                    // Resolver traffic of the shards this process runs.
                    quil_engine::resolver_traffic::ResolverTraffic::process().log();
                    // Forest reads this node served to syncing peers (since
                    // start): cache hits take no storage slot.
                    let forest = quil_rpc::global_service::forest_read_stats();
                    if forest.cache.hits + forest.cache.misses + forest.refused + forest.listed > 0 {
                        info!(
                            cache_hits = forest.cache.hits,
                            cache_misses = forest.cache.misses,
                            cache_mb = forest.cache.bytes / (1024 * 1024),
                            cache_entries = forest.cache.entries,
                            refused_busy = forest.refused,
                            queued = forest.queued,
                            leaves_listed = forest.listed,
                            "forest reads served",
                        );
                    }
                    // Memory snapshot. Logged separately so the size
                    // fields don't crowd `node status`; growth between
                    // ticks is the diagnosis signal.
                    let (replica_loads, replica_loads_peak) =
                        quil_store::replica_store::replica_load_bytes();
                    let sizes = {
                        let _read = probe::section(ProbeSection::StatusMemorySnapshot);
                        mem_sources.snapshot(
                            archive_peers_seen.len(),
                            peer_info_digest_cache.len(),
                        )
                    };
                    let proc_mem = crate::mem_stats::process_memory();
                    let host_mem = crate::mem_stats::host_memory();
                    let (rocksdb_stores, rocksdb_memtables, rocksdb_table_readers) =
                        quil_store::open_stores_memory();
                    let global_frames = clock_store_recv.global_frame_cache_stats();
                    let global_mempool = {
                        let _read = probe::section(ProbeSection::StatusCollectorTotals);
                        mc_for_recv.pending_totals()
                    };
                    info!(
                        rss_mb = proc_mem
                            .map(|m| crate::mem_stats::fmt_mb(m.rss_bytes))
                            .unwrap_or_else(|| "?".to_string()),
                        vsize_mb = proc_mem
                            .map(|m| crate::mem_stats::fmt_mb(m.vsize_bytes))
                            .unwrap_or_else(|| "?".to_string()),
                        // Whole host (all processes), from /proc/meminfo;
                        // omitted when unavailable.
                        host_mem_total_mb = host_mem.map(|h| crate::mem_stats::fmt_mb(h.total_bytes)),
                        host_mem_available_mb = host_mem.map(|h| crate::mem_stats::fmt_mb(h.available_bytes)),
                        host_swap_total_mb = host_mem.map(|h| crate::mem_stats::fmt_mb(h.swap_total_bytes)),
                        host_swap_used_mb = host_mem.map(|h| crate::mem_stats::fmt_mb(h.swap_used_bytes)),
                        peer_info_cache = sizes.peer_info_cache,
                        // Its bounds (peer_info_bounds.rs): memory held, and
                        // records evicted, expired and refused since start.
                        peer_info_cache_mb = %crate::mem_stats::fmt_mb(peer_info_bounds.bytes() as u64),
                        peer_info_evicted = peer_info_bounds.evicted,
                        peer_info_expired = peer_info_bounds.expired,
                        peer_info_refused = peer_info_bounds.refused,
                        shard_engines = sizes.shard_engines,
                        signer_registry = sizes.signer_registry,
                        archive_peers_seen = sizes.archive_peers_seen,
                        peer_info_digest_cache = sizes.peer_info_digest_cache,
                        prover_registry_addresses = sizes.prover_registry_addresses,
                        prover_registry_filters = sizes.prover_registry_filters,
                        time_reel_nodes = sizes.time_reel_nodes,
                        time_reel_pending = sizes.time_reel_pending,
                        time_reel_equivocators = sizes.time_reel_equivocators,
                        app_engine_frame_store = sizes.app_engine_frame_store,
                        // Shard mempools, summed over this process's engines,
                        // and the GLOBAL one.
                        app_engine_mempool_messages = sizes.app_engine_mempool_messages,
                        app_engine_mempool_mb = %crate::mem_stats::fmt_mb(sizes.app_engine_mempool_bytes as u64),
                        global_mempool_messages = global_mempool.0,
                        global_mempool_mb = %crate::mem_stats::fmt_mb(global_mempool.1 as u64),
                        // Arrival stamps the shard engines keep for the
                        // routing fallback, per shard at most 65,536 plus
                        // the bundles of one leader's turn.
                        app_engine_routing_seen = sizes.app_engine_routing_seen,
                        app_engine_proposal_cache = sizes.app_engine_proposal_cache,
                        app_engine_pending_certified_parents = sizes.app_engine_pending_certified_parents,
                        // Finalized GLOBAL frames cached with their request
                        // bundles, the heap they hold and its byte budget.
                        global_frame_cache = global_frames.frames,
                        global_frame_cache_mb = %crate::mem_stats::fmt_mb(global_frames.held_bytes as u64),
                        global_frame_cache_budget_mb = %crate::mem_stats::fmt_mb(global_frames.budget_bytes as u64),
                        // Pinned RocksDB views of live execution branches in
                        // this process; each retains superseded versions on disk.
                        execution_views_held = quil_forest::ExecutionViewAdmission::process().active(),
                        // Whole storage replicas held now and at most since
                        // the last snapshot: seals and settlements, admitted
                        // as storage jobs; a frame reads only the nodes it
                        // opens. Then the cached leaf caps frames open with.
                        replica_loads_mb = %crate::mem_stats::fmt_mb(replica_loads),
                        replica_loads_peak_mb = %crate::mem_stats::fmt_mb(replica_loads_peak),
                        replica_leaf_cache_mb = %crate::mem_stats::fmt_mb(
                            quil_store::replica_store::leaf_cache_bytes() as u64
                        ),
                        // The block cache this process's stores share
                        // (archives keep their own): used and capacity.
                        rocksdb_shared_cache_mb = quil_store::shared_block_cache_memory()
                            .map(|(used, _)| crate::mem_stats::fmt_mb(used)),
                        rocksdb_shared_cache_capacity_mb = quil_store::shared_block_cache_memory()
                            .map(|(_, capacity)| crate::mem_stats::fmt_mb(capacity)),
                        // Every RocksDB store open in this process (the
                        // master's and each thread worker's): memtables and
                        // table readers, beside jemalloc's `allocated_mb`.
                        rocksdb_open_stores = rocksdb_stores,
                        rocksdb_memtables_mb = %crate::mem_stats::fmt_mb(rocksdb_memtables),
                        rocksdb_table_readers_mb = %crate::mem_stats::fmt_mb(rocksdb_table_readers),
                        // What storage jobs hold through their admission
                        // reservations (mostly labelling buffers), which a
                        // memory watch subtracts from `allocated_mb`.
                        labelling_buffers_mb = %crate::mem_stats::fmt_mb(
                            quil_engine::storage_jobs::held_bytes()
                                .saturating_sub(quil_engine::storage_jobs::verifier_bytes())
                        ),
                        verifier_reserved_mb = %crate::mem_stats::fmt_mb(
                            quil_engine::storage_jobs::verifier_bytes()
                        ),
                        "memory snapshot"
                    );
                    if let Some(h) = host_mem {
                        match host_memory_watch.observe(&h, std::time::Instant::now()) {
                            crate::mem_stats::HostMemoryAction::Warn { low_secs } => warn!(
                                scope = "this host",
                                low_secs,
                                host_mem_available_mb = %crate::mem_stats::fmt_mb(h.available_bytes),
                                host_mem_total_mb = %crate::mem_stats::fmt_mb(h.total_bytes),
                                host_swap_used_mb = %crate::mem_stats::fmt_mb(h.swap_used_bytes),
                                host_swap_total_mb = %crate::mem_stats::fmt_mb(h.swap_total_bytes),
                                "host memory low: available memory is below 10% of total \
                                 (all processes on this host, not only this node); the \
                                 host may swap or kill processes. Reduce dataWorkerCount \
                                 or check other processes on the host. Repeats every 10 \
                                 minutes while it holds"
                            ),
                            crate::mem_stats::HostMemoryAction::Cleared { low_secs } => info!(
                                scope = "this host",
                                low_secs,
                                host_mem_available_mb = %crate::mem_stats::fmt_mb(h.available_bytes),
                                host_mem_total_mb = %crate::mem_stats::fmt_mb(h.total_bytes),
                                "host memory recovered: available memory is back above 10% of total"
                            ),
                            crate::mem_stats::HostMemoryAction::None => {}
                        }
                    }
                    // jemalloc allocator stats — PROCESS-GLOBAL, so this single
                    // line captures the master, every worker thread, AND the
                    // C++ RocksDB allocations. The decisive OOM signal:
                    //   allocated rising → true live-heap leak
                    //   allocated flat, resident hi → fragmentation, not a leak
                    // Compare `allocated_mb` across ticks to tell them apart.
                    if let Some(j) = crate::mem_stats::jemalloc_stats() {
                        info!(
                            allocated_mb = %crate::mem_stats::fmt_mb(j.allocated),
                            active_mb = %crate::mem_stats::fmt_mb(j.active),
                            resident_mb = %crate::mem_stats::fmt_mb(j.resident),
                            retained_mb = %crate::mem_stats::fmt_mb(j.retained),
                            mapped_mb = %crate::mem_stats::fmt_mb(j.mapped),
                            "jemalloc stats"
                        );
                        // Localize the leak BY ALLOCATION SIZE: the dominant
                        // size class says small-objects-leak vs big-buffers-leak
                        // and the exact byte size to cross-reference. Sampled
                        // here (cheap mallctl reads), so the next status tick on
                        // an affected node pins where the 40 GB lives.
                        let br = crate::mem_stats::jemalloc_size_classes();
                        info!(
                            breakdown = %crate::mem_stats::fmt_breakdown(&br),
                            "jemalloc size classes"
                        );
                    }
                }
                msg = async {
                    // Merge the network receive channel, the
                    // self-loopback channel and peers' direct consensus
                    // deliveries — all produce `ReceivedMessage`s that go
                    // through the same dispatch logic. This is how the
                    // proposer's own proposal reaches its own
                    // `vote_aggregator` and event_loop without relying on
                    // BlossomSub self-echo (which doesn't happen). The
                    // node's own messages come first, then committee
                    // members' deliveries, then gossip; other callers'
                    // deliveries wait until none of those does.
                    tokio::select! {
                        biased;
                        m = consensus_loopback_rx.recv() => m,
                        Some(m) = remote_members_rx.recv() => Some(m.into_message()),
                        m = msg_rx.recv() => m,
                        Some(m) = remote_others_rx.recv() => Some(m.into_message()),
                    }
                } => {
                    match msg {
                        Some(mut received) => {
                            probe::step(ProbeSection::LoopMessage);
                            // Explorer tap: record every inbound gossip
                            // message for the `GET /messages` endpoint.
                            // Only present when the explorer is enabled,
                            // so this is a no-op otherwise.
                            if let Some(ring) = &recent_messages_for_recv {
                                ring.push_received(
                                    &received.from,
                                    &received.bitmask,
                                    &received.data,
                                );
                            }

                            // Forward to connected StreamGlobalMessages
                            // subscribers (workers) — ONLY peer-info.
                            //
                            // In Go, `broadcastGlobalMessage` is called
                            // from GLOBAL_FRAME, GLOBAL_PROVER, and
                            // GLOBAL_PEER_INFO handlers. But on a
                            // non-archive master those handlers don't
                            // fire (not subscribed). The only messages
                            // arriving here are GLOBAL_PEER_INFO (from
                            // the mesh) and GLOBAL_CONSENSUS (from the
                            // self-loopback when the master produces
                            // its own proposals/votes). Workers don't
                            // need either — they get global frames
                            // from the archive poller, prover messages
                            // via direct gRPC, and per-shard consensus
                            // from their own mesh subscriptions.
                            // Forwarding the loopback's
                            // GLOBAL_CONSENSUS was the source of QC
                            // verification failures (all-zero sig/pk,
                            // 0xFF bitmask from genesis QC data) and
                            // OOM (on archive masters, the [0xFF;32]
                            // catch-all subscription fed every shard's
                            // traffic into the broadcast channel).
                            //
                            // The only bitmask workers still need from
                            // the master stream is GLOBAL_PEER_INFO
                            // (peer discovery for their own mesh): a PeerInfo
                            // is forwarded below once verified.

                            // A copy of a GLOBAL frame this loop already accepted,
                            // or a stale one, is dropped before any decode. The
                            // gossip gate drops most; this catches copies queued
                            // before the first one was accepted.
                            if received.bitmask.as_slice() == GLOBAL_FRAME
                                && quil_p2p::global_frame_gate::peek_frame_number(&received.data)
                                    .is_some_and(|frame| {
                                        global_frame_gate_for_recv.status(frame)
                                            != quil_p2p::FrameStatus::New
                                    })
                            {
                                debug!("gossip global frame already accepted or stale — dropping");
                                continue;
                            }

                            // Per-topic validator gate. Malformed bytes are
                            // dropped before they reach a queue.
                            // Unregistered topics fall through.
                            let route_outcome = router_for_recv
                                .route(&received.bitmask, &received.data);
                            if !route_outcome.should_dispatch() {
                                router_drops += 1;
                                if let Some(reason) = route_outcome.reject_reason() {
                                    *router_drops_by_reason.entry(reason).or_insert(0) += 1;
                                }
                                // Attribute the drop to its signed author, up to
                                // `MAX_DROP_SOURCES` authors per status interval.
                                if !received.from.is_empty() {
                                    if let Some(count) = router_drops_by_source.get_mut(&received.from) {
                                        *count += 1;
                                    } else if router_drops_by_source.len() < MAX_DROP_SOURCES {
                                        router_drops_by_source.insert(received.from.clone(), 1);
                                    } else {
                                        router_drops_untracked_sources += 1;
                                    }
                                }
                                // Categorize for operator visibility.
                                let topic = match received.bitmask.as_slice() {
                                    GLOBAL_PEER_INFO => {
                                        router_drops_peer_info += 1;
                                        "peer_info"
                                    }
                                    GLOBAL_PROVER => {
                                        router_drops_prover += 1;
                                        "prover"
                                    }
                                    GLOBAL_FRAME => {
                                        router_drops_frame += 1;
                                        "frame"
                                    }
                                    GLOBAL_CONSENSUS => {
                                        router_drops_consensus += 1;
                                        "consensus"
                                    }
                                    GLOBAL_ALERT => {
                                        router_drops_alert += 1;
                                        "alert"
                                    }
                                    _ => {
                                        router_drops_other += 1;
                                        "shard/unknown"
                                    }
                                };
                                let type_prefix = if received.data.len() >= 4 {
                                    format!("0x{:08x}", u32::from_be_bytes(
                                        received.data[..4].try_into().unwrap_or([0;4])
                                    ))
                                } else {
                                    format!("short({}B)", received.data.len())
                                };
                                debug!(
                                    topic,
                                    type_prefix,
                                    len = received.data.len(),
                                    total_dropped = router_drops,
                                    "router validator dropped message",
                                );
                                continue;
                            }

                            // Commonware-simplex routing: when the simplex
                            // router is wired (committee configured), a message on
                            // one of its channel bitmasks is fed to the engine and
                            // the legacy dispatch below is skipped. Off by default
                            // (router unset) → zero overhead.
                            let router = cw_router_for_recv.get();
                            activation_waits_for_recv.cw_router.observe(router.is_some(), None);
                            if let Some(router) = router {
                                if router.route(
                                    &received.bitmask,
                                    &received.from,
                                    received.data.clone(),
                                ) {
                                    continue;
                                }
                            }

                            match received.bitmask.as_slice() {
                            GLOBAL_PEER_INFO => {
                                probe::step(ProbeSection::LoopPeerInfo);
                                match quil_p2p::classify_peer_info_message(&received.data) {
                                    Ok(quil_p2p::PeerInfoMessage::PeerInfo(info)) => {
                                        peer_infos_received += 1;
                                        // Signature validation MOVED here from the
                                        // route validator (which now does timestamp
                                        // only — Falcon verify inline on the recv
                                        // loop was starving it and overflowing the
                                        // per-peer send queue). Runs AFTER retrieval,
                                        // BEFORE the entry is cached/trusted, so an
                                        // unverified/spoofed PeerInfo never reaches
                                        // the peer_info_cache or the archive
                                        // admission gate below.
                                        //   1. Falcon key/sig lengths (897 / 666).
                                        //   2. peer_id ↔ signing-pubkey binding —
                                        //      without it an attacker signs with
                                        //      their OWN key but sets peer_id to a
                                        //      genesis archive's, impersonating it to
                                        //      the admission gate.
                                        //   3. Falcon verify (empty domain, matching
                                        //      `Signer::sign` = sign_with_domain(m,&[])).
                                        // Records restored at startup pass the same checks.
                                        if !super::peer_info_file::verified(&info) {
                                            continue;
                                        }
                                        // Workers learn committee keys from it.
                                        let _ = gmtx_for_recv.send(
                                            quil_types::proto::global::StreamGlobalMessagesResponse {
                                                data: received.data.clone(),
                                                bitmask: received.bitmask.clone(),
                                            },
                                        );
                                        // Dedup: hash PeerInfo with timestamp zeroed
                                        // (mirrors Go's hashPeerInfo). Skip if seen.
                                        let mut dedup_info = info.clone();
                                        dedup_info.timestamp = 0;
                                        let dedup_payload = quil_p2p::encode_canonical_peer_info(
                                            &dedup_info,
                                            &dedup_info.public_key,
                                            &dedup_info.signature,
                                        );
                                        use sha2::Digest as _;
                                        let digest: [u8; 32] = sha2::Sha256::digest(&dedup_payload).into();
                                        if !peer_info_digest_cache.insert(digest) {
                                            continue;
                                        }
                                        if peer_info_digest_cache.len() > 10_000 {
                                            peer_info_digest_cache.clear();
                                        }
                                        if !info.peer_id.is_empty() {
                                            let preferred = super::peer_info_bounds::preferred(
                                                &info,
                                                &genesis_archive_peer_ids_for_recv,
                                                &*pr_for_recv,
                                            );
                                            let mut cache = pic_for_recv.write();
                                            let fingerprint = info.build_fingerprint();
                                            // Logged at each peer's first PeerInfo of
                                            // this run too, also when a record restored
                                            // from the last run already names its build.
                                            let build_changed = !peer_builds_logged.contains(&info.peer_id) || cache.get(&info.peer_id).map(|old| {
                                                old.build_fingerprint() != fingerprint
                                                    || old.version != info.version
                                                    || old.patch_number != info.patch_number
                                            }).unwrap_or(true);
                                            let admitted = peer_info_bounds.admit(&mut cache, info.clone(), preferred).admitted();
                                            drop(cache);
                                            if admitted && build_changed && (preferred || other_build_lines_left > 0) {
                                                if !preferred {
                                                    other_build_lines_left -= 1;
                                                }
                                                peer_builds_logged.insert(info.peer_id.clone());
                                                if peer_builds_logged.len() > 10_000 {
                                                    peer_builds_logged.clear();
                                                }
                                                info!(
                                                    peer = %bs58::encode(&info.peer_id).into_string(),
                                                    version = %quil_config::format_version(&info.version),
                                                    patch = %hex::encode(&info.patch_number),
                                                    build_fingerprint = %fingerprint.map(hex::encode).unwrap_or_else(|| "unavailable".into()),
                                                    local_build_fingerprint = env!("QUIL_BUILD_FINGERPRINT"),
                                                    "verified peer build identity"
                                                );
                                            }
                                        }
                                        // Only ARCHIVE-capable peers go into the
                                        // poll pool. Plain peers reject every
                                        // GetGlobalFrame call with "not currently
                                        // syncable".
                                        if info.is_archive() {
                                            // Validate against genesis archive peers.
                                            // The peer_id in PeerInfo is raw bytes;
                                            // genesis has base58 peer IDs. Convert
                                            // PeerInfo peer_id to hex for comparison
                                            // against genesis BLS pubkey hashes.
                                            let peer_hex = bs58::encode(&info.peer_id).into_string();
                                            // On testnet/devnet (network != 0) the genesis
                                            // archive list isn't ours, so we accept any
                                            // archive-claiming peer. Mainnet keeps the
                                            // strict allowlist check below.
                                            let is_genesis_archive = network_for_recv != 0
                                                || genesis_archive_peer_ids_for_recv
                                                    .contains(&info.peer_id);
                                            if !is_genesis_archive {
                                                debug!(
                                                    peer = peer_hex,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "FAKE ARCHIVE — peer claims archive capability but is not a genesis archive peer"
                                                );
                                                continue;
                                            }
                                            // A decommissioned genesis archive is never
                                            // polled or dialed, even from a PeerInfo
                                            // still circulating after it went away.
                                            if network_for_recv == 0
                                                && quil_config::DECOMMISSIONED_GENESIS_ARCHIVES.contains(&peer_hex.as_str())
                                            {
                                                debug!(peer = peer_hex, "ignoring decommissioned genesis archive");
                                                continue;
                                            }
                                            let is_new = archive_peers_seen.insert(info.peer_id.clone());
                                            if is_new {
                                                info!(
                                                    peer = peer_hex,
                                                    head_frame = info.last_global_head_frame,
                                                    total = archive_peers_seen.len(),
                                                    secs_since_start = loop_started.elapsed().as_secs(),
                                                    "verified genesis archive peer"
                                                );
                                            }
                                            if archive_mode_for_recv {
                                                let (raise_frame, _) = quil_execution::global_intrinsic::handoff::drain_anchor_raise();
                                                let head = lhf_for_recv.load(std::sync::atomic::Ordering::Relaxed);
                                                if super::drain_raise_watch::behind_raise(raise_frame, head, quil_config::SUBPATCH_NUMBER, info.release_subpatch())
                                                    && drain_raise_watch.due(&info.peer_id, std::time::Instant::now())
                                                {
                                                    warn!(
                                                        scope = "peer",
                                                        peer = peer_hex,
                                                        peer_release = %info.release(),
                                                        release = %quil_config::display_version(),
                                                        head_frame = head,
                                                        raise_frame,
                                                        action = "upgrade that archive before the raise frame",
                                                        "an archive runs an older release than this node as the drain anchor raise nears: a build without the raise executes drain headers this one refuses, and their state differs once one is packed"
                                                    );
                                                }
                                            }
                                            // Authenticated network-head hint for the poller's
                                            // reconcile: this PeerInfo is signed and genesis-archive
                                            // verified, so its advertised head lets the poller decide
                                            // "am I behind?" without an RPC head-fetch.
                                            gossip_freshness_for_recv
                                                .note_network_head(info.last_global_head_frame);
                                            let first_addr = add_archive_record_endpoints(&pool_for_recv, &info, network_for_recv).await;
                                            info!(
                                                peer = bs58::encode(&info.peer_id).into_string(),
                                                head_frame = info.last_global_head_frame,
                                                total_archives = archive_peers_seen.len(),
                                                "discovered archive peer"
                                            );
                                            // First archive: sync all four
                                            // CRDT phases of the global
                                            // prover tree sequentially. Each
                                            // ensure_prover_tree call either
                                            // loads the cached blob from
                                            // RocksDB or pulls + verifies +
                                            // persists from this archive.
                                            // Skip in archive mode — archives
                                            // have full history locally and
                                            // the legacy whole-tree blob
                                            // sync path isn't populated by
                                            // migrated stores (per-vertex
                                            // data at `0x30` is, but blob
                                            // cache at `0x2F` is not), so
                                            // calling this against another
                                            // archive that's also fresh
                                            // from migration just trades
                                            // "no tree data available"
                                            // errors back and forth.
                                            if is_new && archive_peers_seen.len() == 1
                                                && !archive_mode_for_recv {
                                                if let (Some(seed), Some(addr)) =
                                                    (prover_falcon_for_recv.clone(), first_addr)
                                                {
                                                    let store = hg_store_for_recv.clone();
                                                    let cs = clock_store_recv.clone();
                                                    let crdt_for_bootstrap = exec_mgr_for_recv.crdt();
                                                    spawner.detach("prover-tree-bootstrap", async move {
                                                        // Pin sync against the most-recent verified
                                                        // frame's prover_tree_commitment (when
                                                        // available). Empty during bootstrap before
                                                        // any frame is stored.
                                                        let expected_root = cs
                                                            .get_latest_global_frame()
                                                            .ok()
                                                            .and_then(|f| f.header.map(|h| h.prover_tree_commitment))
                                                            .unwrap_or_default();
                                                        // Onboarding: swap the ephemeral in-memory
                                                        // forest for the persistent RocksDB one (+ QUIL
                                                        // partition) BEFORE syncing, so synced state is
                                                        // durable and produced roots are network-consistent.
                                                        // No-op once persistent.
                                                        if quil_forest_migrate::install_forest_for_sync(
                                                            crdt_for_bootstrap.as_ref(), store.as_ref(),
                                                            network_for_recv == 0,
                                                        ) {
                                                            info!("prover-tree-bootstrap: installed persistent forest for onboarding sync");
                                                        }
                                                        // Forest sync of the global prover shard
                                                        // (single-shard, all 4 phases + blobs).
                                                        match crate::forest_sync::sync_single_shard_verified(
                                                            &addr, &seed, crdt_for_bootstrap, &[0xffu8; 32], &expected_root,
                                                        ).await {
                                                            Ok(conv) => {
                                                                info!(addr = %addr, match_ok = conv.is_some(), "prover tree bootstrap synced");
                                                            }
                                                            Err(e) => {
                                                                warn!(addr = %addr, error = %e, "prover tree bootstrap sync failed");
                                                            }
                                                        }

                                                        // Build the in-memory ProverRegistry
                                                        // from the persisted vertex store.
                                                        let mut registry =
                                                            quil_execution::InMemoryProverRegistry::new();
                                                        registry.refresh(store.as_ref())?;
                                                        info!(
                                                            provers_visited = registry.provers_visited(),
                                                            allocations_visited = registry.allocations_visited(),
                                                            rewards_visited = registry.rewards_visited(),
                                                            distinct_provers = registry.distinct_provers(),
                                                            distinct_filters = registry.distinct_filters(),
                                                            "prover registry refreshed"
                                                        );

                                                        // Sample a few active provers.
                                                        let all_active =
                                                            registry.get_all_active_app_shard_provers();
                                                        info!(
                                                            active_count = all_active.len(),
                                                            "active prover count from registry"
                                                        );
                                                        for prover in all_active.iter().take(3) {
                                                            info!(
                                                                address = %hex::encode(&prover.address),
                                                                seniority = prover.seniority,
                                                                available_storage = prover.available_storage,
                                                                allocations = prover.allocations.len(),
                                                                "  active prover"
                                                            );
                                                        }
                                                        Ok(())
                                                    });
                                                }
                                            }
                                        } else if peer_infos_received <= 5
                                            || peer_infos_received % 100 == 0
                                        {
                                            info!(
                                                total_peer_infos = peer_infos_received,
                                                total_archives = archive_peers_seen.len(),
                                                "PeerInfo discovery progress"
                                            );
                                        }
                                    }
                                    Ok(quil_p2p::PeerInfoMessage::KeyRegistry) => {
                                        // Decode and stash in the signer registry so
                                        // consensus-message BLS signatures from the
                                        // announcing peer can later be verified using
                                        // the prover key bound to its Ed448 identity.
                                        // Older-timestamp replays are ignored inside
                                        // `SignerRegistry::update`.
                                        match quil_p2p::decode_canonical_key_registry(&received.data) {
                                            Ok(reg) => {
                                                let identity_len = reg.ed448_pubkey.len();
                                                let prover_len = reg.bls_pubkey.len();
                                                // Finding B: `update` verifies the
                                                // identity↔prover cross-signatures and
                                                // rejects (returns false) any binding
                                                // whose sigs don't validate, so a peer
                                                // can't inject an arbitrary Ed448→BLS
                                                // pairing.
                                                // Strict validation refuses a KeyRegistry
                                                // whose timestamp is not signed.
                                                let strict = quil_p2p::strict_peer_info_validation();
                                                if sr_for_recv.update_with(reg, strict, |prover_key| {
                                                    super::peer_info_bounds::registered_prover(prover_key, &*pr_for_recv)
                                                }) {
                                                    debug!(
                                                        identity_len,
                                                        prover_len,
                                                        total_entries = sr_for_recv.len(),
                                                        "ingested KeyRegistry"
                                                    );
                                                } else {
                                                    debug!(
                                                        identity_len,
                                                        prover_len,
                                                        "rejected KeyRegistry: invalid cross-signature or timestamp signature, unsigned timestamp under strict validation, empty key, or stale replay"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                debug!(error = %e, "failed to decode KeyRegistry");
                                            }
                                        }
                                    }
                                    Ok(quil_p2p::PeerInfoMessage::Unknown(prefix)) => {
                                        debug!(prefix = format!("0x{:04x}", prefix),
                                            "unknown PEER_INFO bitmask message type");
                                    }
                                    Err(e) => {
                                        debug!(error = %e, "failed to decode PeerInfo");
                                    }
                                }
                            }
                            GLOBAL_FRAME => {
                                probe::step(ProbeSection::LoopGlobalFrame);
                                // Try canonical bytes first (the wire format),
                                // fall back to proto decode (archive poller uses proto).
                                let frame_result: std::result::Result<quil_types::proto::global::GlobalFrame, _> =
                                    quil_engine::consensus_wire::decode_global_frame(&received.data)
                                        .or_else(|canonical_err| {
                                            debug!(error = %canonical_err, "canonical decode failed, trying proto");
                                            prost::Message::decode(received.data.as_slice())
                                                .map_err(|e| quil_types::error::QuilError::InvalidArgument(
                                                    format!("failed to decode Protobuf message: {} (canonical: {})", e, canonical_err)
                                                ))
                                        });
                                match frame_result {
                                    Ok(frame) => {
                                        let frame_num = frame.header.as_ref()
                                            .map(|h| h.frame_number).unwrap_or(0);

                                        // Validate prover is a genesis prover
                                        if let Some(h) = frame.header.as_ref() {
                                            if !genesis_prover_addrs_for_recv.contains(&h.prover) {
                                                debug!(
                                                    frame = frame_num,
                                                    prover = hex::encode(&h.prover),
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "INVALID PROVER — not a genesis prover, possible attacker"
                                                );
                                                continue;
                                            }
                                        }

                                        // Frame-number sanity (cheap, pre-cert). Gossip is
                                        // head-only, so a legit frame sits at ~the network head;
                                        // one implausibly far beyond our head can only be a forged
                                        // number aimed at poisoning the head atomic / gossip-head
                                        // target. Shed it before the (Falcon) cert verify below. The
                                        // margin is deliberately huge (~1M frames ≈ months) so a
                                        // genuinely behind node still follows the real head; a node
                                        // that far behind uses the state-jump path, not gossip.
                                        {
                                            const MAX_HEAD_LEAD: u64 = 1_000_000;
                                            let head_now = lhf_for_recv
                                                .load(std::sync::atomic::Ordering::Relaxed);
                                            if frame_num > head_now.saturating_add(MAX_HEAD_LEAD) {
                                                debug!(
                                                    frame = frame_num,
                                                    head = head_now,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "gossip global frame implausibly far ahead — dropping",
                                                );
                                                continue;
                                            }
                                        }

                                        // A header whose certificate and VDF already verified
                                        // (an earlier copy, possibly with another body) skips
                                        // both checks; its body is still bound to the requests
                                        // root below. Keyed by the decoded header, so encoding
                                        // variants of one header share an entry.
                                        let header_digest: Option<[u8; 32]> =
                                            frame.header.as_ref().map(|h| {
                                                <sha2::Sha256 as sha2::Digest>::digest(
                                                    prost::Message::encode_to_vec(h),
                                                )
                                                .into()
                                            });
                                        let header_verified = header_digest.is_some_and(|digest| {
                                            global_frame_gate_for_recv.header_verified(&digest)
                                        });

                                        // UNTRUSTED SOURCE GATE. This frame came off the open
                                        // GLOBAL_FRAME gossip mesh (any peer can publish), not the
                                        // mTLS-authenticated archive poller. The VDF proof below is
                                        // PUBLICLY COMPUTABLE — it authenticates nothing — and the
                                        // genesis-prover check above is a public-address allowlist.
                                        // So require a committee FINALIZATION cert (CWCT) that
                                        // verifies against the fixed global committee: this proves
                                        // the committee actually finalized the frame. Fails closed
                                        // (no committee / no cert / bad cert ⇒ drop) and runs BEFORE
                                        // the expensive VDF verify so forged frames are cheap to shed.
                                        // Legit gossip + archive frames both carry this cert.
                                        match frame.header.as_ref() {
                                            Some(h) if header_verified
                                                || frame_validator_for_recv
                                                    .verify_global_finalization_cert(h) => {}
                                            _ => {
                                                debug!(
                                                    frame = frame_num,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "gossip global frame missing/invalid committee finalization cert — dropping",
                                                );
                                                continue;
                                            }
                                        }

                                        // Verify VDF proof before storing.
                                        // Wrap in catch_unwind — the classgroup can panic
                                        // on malformed VDF output from canonical decode bugs.
                                        let validate_result = if header_verified {
                                            Ok(Ok(true))
                                        } else {
                                            std::panic::catch_unwind(
                                                std::panic::AssertUnwindSafe(|| {
                                                    let _validate = probe::section(ProbeSection::GlobalFrameValidation);
                                                    frame_validator_for_recv.validate(&frame)
                                                })
                                            )
                                        };
                                        match validate_result {
                                            Ok(Ok(true)) => {}
                                            Ok(Ok(false)) => {
                                                // Validator returned false — either VDF or BLS
                                                // signature check rejected it. The specific
                                                // reason is logged by `GlobalFrameVerifier::validate`.
                                                debug!(frame = frame_num, "frame rejected by validator — dropping");
                                                continue;
                                            }
                                            Ok(Err(e)) => {
                                                debug!(frame = frame_num, error = %e, "VDF validation error — dropping frame");
                                                continue;
                                            }
                                            Err(_) => {
                                                debug!(
                                                    frame = frame_num,
                                                    output_len = frame.header.as_ref().map(|h| h.output.len()).unwrap_or(0),
                                                    "VDF validation PANIC — frame output likely corrupted, dropping"
                                                );
                                                continue;
                                            }
                                        }
                                        if let Some(digest) = header_digest.filter(|_| !header_verified) {
                                            global_frame_gate_for_recv.mark_header_verified(digest, frame_num);
                                        }

                                        // BIND THE BODY TO THE AUTHENTICATED HEADER. The cert + VDF
                                        // above authenticate the header (incl. `requests_root`), but
                                        // `frame.requests` is a separate field. An attacker could keep
                                        // a real frame's valid header+cert+VDF and swap in a different
                                        // request set — each request is still intrinsic-validated on
                                        // execution, but a receiver would compute a DIVERGENT state for
                                        // this frame. Recompute the requests root from the carried body
                                        // and require it to equal the authenticated `requests_root`.
                                        // (The mTLS poller path trusts its source; this gate is for the
                                        // untrusted gossip mesh.)
                                        // Bound the work an attacker can force. Recomputing the
                                        // requests root builds a commitment tree over every bundle and
                                        // converts every request. A real header+cert can be REPLAYED
                                        // with a maximally-large tampered body (a 16 MiB frame packs
                                        // millions of minimal bundles) to burn seconds of CPU before
                                        // the root mismatch is detected — the check is inherently
                                        // build-then-compare. Shed oversized bodies here, cheaply
                                        // (O(bundles) length reads, no tree work), before the recompute.
                                        // Typical global frames are far under these caps; a rare genuinely
                                        // huge frame simply isn't followed over gossip and is instead
                                        // fetched by the RPC poller (which has no such cap and trusts its
                                        // mTLS source), so correctness is preserved.
                                        {
                                            const MAX_GOSSIP_GLOBAL_BUNDLES: usize = 65_536;
                                            const MAX_GOSSIP_GLOBAL_REQUESTS: usize = 65_536;
                                            let total_requests: usize =
                                                frame.requests.iter().map(|b| b.requests.len()).sum();
                                            if frame.requests.len() > MAX_GOSSIP_GLOBAL_BUNDLES
                                                || total_requests > MAX_GOSSIP_GLOBAL_REQUESTS
                                            {
                                                debug!(
                                                    frame = frame_num,
                                                    bundles = frame.requests.len(),
                                                    requests = total_requests,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "gossip global frame body oversized — dropping (poller fetches if real)",
                                                );
                                                continue;
                                            }
                                        }

                                        // Recompute runs on the ATTACKER-CONTROLLED body (before the
                                        // match rejects a forgery), so contain any panic in the
                                        // canonical-encoding / tree path exactly like the VDF verify
                                        // above — a panic ⇒ treat as invalid ⇒ drop, never crash the
                                        // recv loop.
                                        let requests_root_ok = std::panic::catch_unwind(
                                            std::panic::AssertUnwindSafe(|| {
                                                let _check = probe::section(ProbeSection::GlobalFrameRequestsRoot);
                                                match frame.header.as_ref() {
                                                    Some(h) => frame_validator_for_recv
                                                        .verify_global_requests_root(h, &frame.requests),
                                                    None => false,
                                                }
                                            }),
                                        )
                                        .unwrap_or(false);
                                        if !requests_root_ok {
                                            debug!(
                                                frame = frame_num,
                                                from = bs58::encode(&received.from).into_string(),
                                                "gossip global frame body does not match authenticated requests_root — dropping",
                                            );
                                            continue;
                                        }
                                        quil_engine::own_prover_ops::tracker().observe_frame(frame_num, &frame.requests);
                                        super::seat_certificates::observe_frame(&frame);

                                        // An archive with atomic finalization keeps the
                                        // authenticated frame as a durable certified
                                        // candidate; its worker publishes it together
                                        // with the execution state.
                                        let stored = {
                                            let _store = probe::section(ProbeSection::GlobalFrameStore);
                                            let pipeline = global_finalization_for_recv.get();
                                            activation_waits_for_recv.global_finalization.observe(pipeline.is_some(), Some(frame_num));
                                            if pipeline.is_some_and(|pipeline| pipeline.offer_synced(&frame))
                                            {
                                                Ok(())
                                            } else {
                                                clock_store_recv.put_global_frame(&frame, None)
                                            }
                                        };
                                        match stored {
                                            Ok(()) => {
                                                frames_received += 1;
                                                global_frame_gate_for_recv.mark_accepted(frame_num);
                                                // `observe` / `fetch_max` never
                                                // regress these counters below
                                                // an already-seen value (e.g.
                                                // if a stale duplicate frame
                                                // arrives out-of-order via
                                                // BlossomSub).
                                                cf_for_recv.observe(frame_num);
                                                lhf_for_recv.fetch_max(frame_num, std::sync::atomic::Ordering::Relaxed);
                                                // Signal the RPC poller that gossip is delivering the
                                                // head, so it backs off its redundant per-second fetch.
                                                gossip_freshness_for_recv.stamp(frame_num);

                                                // Frame execution dispatches on node mode:
                                                //
                                                //   * Archive nodes need contiguous frame
                                                //     history (clients sync from us; gaps
                                                //     break their replay). We drain the
                                                //     clock store in order from
                                                //     `last_executed + 1` forward and
                                                //     wait for missing predecessors.
                                                //
                                                //   * Non-archive nodes only need to
                                                //     follow the chain head. BlossomSub
                                                //     gossip is unordered; stale / backfill
                                                //     frames are noise. We skip any frame
                                                //     whose number is not strictly newer
                                                //     than what we've already executed,
                                                //     and never wait for missing
                                                //     predecessors — they're already past.
                                                let frames_to_execute: Vec<(u64, quil_types::proto::global::GlobalFrame)> =
                                                if archive_mode_recv || (network_for_recv != 99
                                                    && quil_types::consensus::committee_handoff_active(frame_num)) {
                                                    // Archives have their serial materializer. Session-enabled
                                                    // regulars follow authenticated GLOBAL snapshots: their local
                                                    // shard metadata can lag a split/merge freeze, so replay
                                                    // against it can accept a join the archive rejected and
                                                    // permanently add noncanonical prover records. Neither
                                                    // role may also execute GLOBAL state from gossip. Legacy
                                                    // networks and standalone devnet retain inline execution.
                                                    Vec::new()
                                                } else if let Some(ref reel) = time_reel_for_recv {
                                                    if let Err(e) = reel.insert(Arc::new(frame.clone())) {
                                                        debug!(
                                                            frame = frame_num,
                                                            error = %e,
                                                            "time reel rejected frame",
                                                        );
                                                    }
                                                    // Drain events — execute frames the reel promotes to head.
                                                    let mut out = Vec::new();
                                                    if let Some(ref mut rx) = time_reel_rx {
                                                        while let Ok(event) = rx.try_recv() {
                                                            match event.event_type {
                                                                quil_engine::time_reel::TimeReelEventType::NewHead |
                                                                quil_engine::time_reel::TimeReelEventType::ForkDetected => {
                                                                    let head_num = event.frame.header.as_ref()
                                                                        .map(|h| h.frame_number).unwrap_or(0);
                                                                    if head_num > last_executed_frame {
                                                                        last_executed_frame = head_num;
                                                                        let f: quil_types::proto::global::GlobalFrame =
                                                                            (*event.frame).clone();
                                                                        out.push((head_num, f));
                                                                    }
                                                                    if event.event_type == quil_engine::time_reel::TimeReelEventType::ForkDetected {
                                                                        info!(
                                                                            new_head = head_num,
                                                                            "time reel: fork detected, switching to new head"
                                                                        );
                                                                    }
                                                                }
                                                                quil_engine::time_reel::TimeReelEventType::EquivocationDetected => {
                                                                    warn!(
                                                                        msg = %event.message,
                                                                        "time reel: equivocation detected"
                                                                    );
                                                                }
                                                            }
                                                        }
                                                    }
                                                    out
                                                } else if frame_num > last_executed_frame {
                                                    last_executed_frame = frame_num;
                                                    vec![(frame_num, frame.clone())]
                                                } else {
                                                    debug!(
                                                        frame = frame_num,
                                                        last_executed = last_executed_frame,
                                                        "non-archive: skipping stale/backfill frame",
                                                    );
                                                    Vec::new()
                                                };

                                                for (exec_num, exec_frame) in frames_to_execute {
                                                    // At-cutover prover-tree reset on regular nodes — run
                                                    // LOCALLY, BEFORE processing the cutover frame, exactly as
                                                    // the archive materializer does (which resets before it
                                                    // materializes the frame). The reset is a deterministic pure
                                                    // function of (cutover frame, genesis committee), so every
                                                    // node rebuilds the identical prover tree from empty — the
                                                    // forest JMT is put-only, so a wipe can't propagate through
                                                    // incremental sync. Running it here converges regulars
                                                    // immediately instead of via the slow mismatch-recovery
                                                    // full re-pull. `== cutover` fires exactly once (in-order
                                                    // gossip application), matching the archive's reset frame.
                                                    let v1_reset = exec_num
                                                        == quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame()
                                                        && !crate::unified_consolidation::boot_reset_applied(&hg_store_for_recv);
                                                    let v2_reset = exec_num
                                                        == quil_execution::global_intrinsic::materialize::quil_grid_reset_v2_frame()
                                                        && !crate::unified_consolidation::grid_reset_v2_applied(&hg_store_for_recv);
                                                    let v3_reset = exec_num
                                                        == quil_execution::global_intrinsic::materialize::quil_prover_reset_v3_frame()
                                                        && !crate::unified_consolidation::prover_reset_v3_applied(&hg_store_for_recv);
                                                    let v4_reset = exec_num
                                                        == quil_execution::global_intrinsic::materialize::quil_prover_reset_v4_frame()
                                                        && !crate::unified_consolidation::prover_reset_v4_applied(&hg_store_for_recv);
                                                    let v5_reset = exec_num
                                                        == quil_execution::global_intrinsic::materialize::quil_prover_reset_v5_frame()
                                                        && !crate::unified_consolidation::prover_reset_v5_applied(&hg_store_for_recv);
                                                    if !archive_mode_recv && (v1_reset || v2_reset || v3_reset || v4_reset || v5_reset) {
                                                        match quil_engine::genesis::reset_prover_tree_to_genesis(
                                                            &crdt_for_recv,
                                                            &hg_store_for_recv,
                                                            exec_num,
                                                            network_for_recv,
                                                            &genesis_seed_for_recv,
                                                            &[],
                                                        ) {
                                                            Ok(n) => {
                                                                info!(seeded = n, frame = exec_num, v2 = v2_reset, v3 = v3_reset, v4 = v4_reset, v5 = v5_reset, "regular at-reset prover-tree reset complete");
                                                                if v5_reset {
                                                                    crate::unified_consolidation::mark_prover_reset_v5_applied(&hg_store_for_recv);
                                                                } else if v4_reset {
                                                                    crate::unified_consolidation::mark_prover_reset_v4_applied(&hg_store_for_recv);
                                                                } else if v3_reset {
                                                                    crate::unified_consolidation::mark_prover_reset_v3_applied(&hg_store_for_recv);
                                                                } else if v2_reset {
                                                                    crate::unified_consolidation::mark_grid_reset_v2_applied(&hg_store_for_recv);
                                                                }
                                                            }
                                                            Err(e) => warn!(error = %e, frame = exec_num, "regular at-reset prover-tree reset FAILED"),
                                                        }
                                                    }
                                                    let executed = {
                                                        let _execute = probe::section(ProbeSection::GlobalFrameExecution);
                                                        quil_engine::frame_processor::process_global_frame_with_rewards(
                                                            &exec_mgr_for_recv,
                                                            &exec_frame,
                                                            &num_bigint::BigInt::from(1),
                                                            Some(reward_issuer.as_ref() as &dyn quil_types::consensus::RewardIssuance),
                                                            Some(pr_for_recv.as_ref() as &dyn quil_types::consensus::ProverRegistry),
                                                        )
                                                    };
                                                    match executed {
                                                        Ok((applied, skipped)) => {
                                                            info!(
                                                                frame = exec_num,
                                                                total = frames_received,
                                                                applied,
                                                                skipped,
                                                                "received + processed GlobalFrame"
                                                            );
                                                            coverage_for_recv.check(exec_num);
                                                            // Epoch-boundary registry refresh: repopulate the
                                                            // shared prover-registry cache from the just-
                                                            // materialized store when we cross into a new epoch,
                                                            // so the committee + `on_new_frame` reconcile read
                                                            // the new epoch's allocations. Allocations are
                                                            // epoch-stable, so one refresh per boundary is
                                                            // sufficient (and avoids a per-frame full scan). This
                                                            // is the previously-missing recv-path refresh.
                                                            let exec_epoch =
                                                                quil_types::consensus::epoch_for_frame(exec_num);
                                                            if exec_epoch != last_committee_epoch {
                                                                let refreshed = {
                                                                    let _refresh = probe::section(ProbeSection::ProverRegistryRefresh);
                                                                    pr_for_recv.refresh_from_store(hg_store_for_recv.as_ref())
                                                                };
                                                                match refreshed {
                                                                    Ok(()) => {
                                                                        last_committee_epoch = exec_epoch;
                                                                        debug!(frame = exec_num, epoch = exec_epoch,
                                                                            "epoch boundary — refreshed prover registry");
                                                                    }
                                                                    Err(error) => warn!(frame = exec_num, %error,
                                                                        "prover registry refresh failed; will retry"),
                                                                }
                                                            }
                                                            if !archive_mode_recv {
                                                                let reconciled = {
                                                                    let _reconcile = probe::section(ProbeSection::AllocationReconcile);
                                                                    wa_for_recv.on_new_frame_by("frame receive", exec_num)
                                                                };
                                                                if let Err(e) = reconciled {
                                                                    warn!(error = %e, "worker allocation failed");
                                                                }
                                                            }
                                                            let frame_difficulty = exec_frame.header.as_ref()
                                                                .map(|h| h.difficulty)
                                                                .unwrap_or(0);
                                                            pl_for_recv.set_prover_root_verified_frame(exec_num);
                                                            if !archive_mode_recv {
                                                                let evaluated = {
                                                                    let _evaluate = probe::section(ProbeSection::LifecycleEvaluate);
                                                                    pl_for_recv.evaluate(
                                                                        exec_num,
                                                                        frame_difficulty as u64,
                                                                        pr_for_recv.as_ref(),
                                                                        wm_for_recv.as_ref(),
                                                                    )
                                                                };
                                                                match evaluated {
                                                                    Ok(actions) => {
                                                                        for action in actions {
                                                                            if pl_for_recv.action_is_new(&action) { info!(frame = exec_num, ?action, "prover lifecycle action"); }
                                                                            pp_for_recv.dispatch(action);
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        debug!(error = %e, "prover lifecycle evaluation skipped");
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            info!(
                                                                frame = exec_num,
                                                                total = frames_received,
                                                                error = %e,
                                                                "received GlobalFrame (processing failed)"
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "failed to store frame");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let prefix = if received.data.len() >= 8 {
                                            hex::encode(&received.data[..8])
                                        } else {
                                            hex::encode(&received.data)
                                        };
                                        debug!(
                                            error = %e,
                                            bytes = received.data.len(),
                                            prefix = %prefix,
                                            "GLOBAL_FRAME decode failed"
                                        );
                                    }
                                }
                            }
                            GLOBAL_CONSENSUS => {
                                // Legacy Jolteon (in-house quil-consensus)
                                // gossip topic. The commonware-simplex GLOBAL
                                // consensus path delivers proposals/votes/certs
                                // point-to-point over :8340 and routes them
                                // through `cw_router`, so these gossip messages
                                // are no longer decoded/aggregated here — count
                                // and drop.
                                consensus_msgs_received += 1;
                            }
                            GLOBAL_PROVER => {
                                prover_msgs_received += 1;
                                // Tag with the CONSENSUS RANK (matches the
                                // gRPC submit path and the leader's
                                // `collect_for_rank`). `frames_received` is a
                                // session-local counter in the wrong space, so
                                // relayed prover messages were never collected.
                                let current_rank = cf_for_recv.effective_rank();
                                // Shard frames are verified before they are
                                // held: off this loop.
                                if mc_for_recv.requires_verification(&received.data) {
                                    // At most SHARD_FRAME_VERIFY_TASKS wait on the
                                    // blocking pool; the sender's relays cover a drop.
                                    if let Some(permit) = SHARD_FRAME_VERIFY_TASKS.try_enter() {
                                        let (collector, message) = (mc_for_recv.clone(), received.clone());
                                        // Only an active prover's message may have a
                                        // frame held before it can be verified.
                                        let (signers, provers) = (sr_for_recv.clone(), pr_for_recv.clone());
                                        tokio::task::spawn_blocking(move || {
                                            let _permit = permit;
                                            let provenance = if super::grpc::peer_is_active_prover(
                                                &signers,
                                                provers.as_ref(),
                                                &message.from,
                                            ) {
                                                quil_engine::message_collector::Provenance::Prover
                                            } else {
                                                quil_engine::message_collector::Provenance::Other
                                            };
                                            admit_prover_message(&collector, current_rank, message, provenance)
                                        });
                                    }
                                } else {
                                    // Storage epoch proofs from active provers
                                    // are held apart from any other signer's;
                                    // the lookup runs only for them.
                                    let provenance = quil_engine::message_collector::sender_provenance(
                                        &received.data,
                                        || {
                                            super::grpc::peer_is_active_prover(
                                                &sr_for_recv,
                                                pr_for_recv.as_ref(),
                                                &received.from,
                                            )
                                        },
                                    );
                                    admit_prover_message(
                                        &mc_for_recv,
                                        current_rank,
                                        received.clone(),
                                        provenance,
                                    );
                                }
                            }
                            GLOBAL_ALERT => {
                                // Mirrors Go's alert validation at
                                // `message_validation.go:641-657` +
                                // `handleAlertMessage` at
                                // `message_processors.go:810`. The
                                // alert's Ed448 signature must verify
                                // against the configured `alertKey`
                                // with domain `"GLOBAL_ALERT" || message`.
                                // Canonical format:
                                //   [u32 type=0x0911][u32 msg_len][msg][u32 sig_len][sig]
                                let alert_id = quil_p2p::node::message_id(&received.data);
                                if alert_pubkey_for_recv.is_empty() || alert_pubkey_for_recv.len() != 57 {
                                    debug!("GLOBAL_ALERT received but no valid alertKey configured — dropping");
                                } else if alerts_seen.contains(&alert_id) {
                                    debug!("GLOBAL ALERT already shown — dropping the copy");
                                } else if received.data.len() >= 12 {
                                    let d = &received.data;
                                    let mut c = 4usize; // skip type prefix
                                    let msg_len = u32::from_be_bytes(d[c..c+4].try_into().unwrap_or([0;4])) as usize;
                                    c += 4;
                                    if msg_len <= 1000 && c + msg_len + 4 <= d.len() {
                                        let msg = &d[c..c+msg_len];
                                        c += msg_len;
                                        let sig_len = u32::from_be_bytes(d[c..c+4].try_into().unwrap_or([0;4])) as usize;
                                        c += 4;
                                        // The signature covers no trailing bytes, so
                                        // an alert carrying any is refused.
                                        if sig_len == 114 && c + sig_len == d.len() {
                                            let sig = &d[c..c+sig_len];
                                            let mut signed = Vec::with_capacity(b"GLOBAL_ALERT".len() + msg_len);
                                            signed.extend_from_slice(b"GLOBAL_ALERT");
                                            signed.extend_from_slice(msg);
                                            if quil_crypto::ed448_verify(&alert_pubkey_for_recv, &signed, sig) {
                                                let msg_str = String::from_utf8_lossy(msg);
                                                warn!(message = %msg_str, "GLOBAL ALERT (verified)");
                                                coverage_for_recv.emit_alert(&msg_str);
                                                // Bounded: genuine alerts are rare.
                                                if alerts_seen.len() >= MAX_ALERTS_SEEN {
                                                    alerts_seen.clear();
                                                }
                                                alerts_seen.insert(alert_id);
                                            } else {
                                                debug!("GLOBAL ALERT rejected — signature invalid");
                                            }
                                        } else if sig_len == 114 && c + sig_len < d.len() {
                                            debug!(trailing = d.len() - c - sig_len, "GLOBAL ALERT rejected — trailing bytes");
                                        } else {
                                            debug!(sig_len, "GLOBAL ALERT rejected — bad signature length");
                                        }
                                    } else {
                                        debug!(msg_len, "GLOBAL ALERT rejected — bad message length");
                                    }
                                }
                            }
                            _ => {
                                // Per-shard routing: if the bitmask matches one
                                // of the four bitmasks for an active shard
                                // engine on this node, forward the bytes to
                                // the engine via its `AppEngineHandle`. The
                                // worker thread loops own messages back via
                                // `app_handle.send(...)`, so we must not also
                                // route self-published messages here — the
                                // BlossomSub mesh already drops self-echoes.
                                let bm = received.bitmask.as_slice();
                                // Snapshot the active filter set under the read
                                // lock, then drop it before doing per-handle
                                // sends (the channel is bounded; sends are
                                // try_send).
                                let entries: Vec<(Vec<u8>, quil_engine::app_engine::AppEngineHandle)> = {
                                    let map = shard_engines_for_recv.read();
                                    map.iter()
                                        .map(|(f, h)| (f.clone(), h.clone()))
                                        .collect()
                                };
                                // An application's submission topic is shared by
                                // every shard of it: each of this node's engines
                                // of that application gets the submission.
                                // A message with one destination is moved to it, not
                                // copied; nothing reads `received.data` once routed.
                                let submitted = submission_engines(bm, &entries);
                                if let Some((last, others)) = submitted.split_last() {
                                    for handle in others {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Prover(received.data.clone()));
                                    }
                                    last.send(quil_engine::app_engine::AppEngineMessage::Prover(std::mem::take(&mut received.data)));
                                }
                                let mut routed = !submitted.is_empty();
                                for (filter, handle) in entries.iter().filter(|_| submitted.is_empty()) {
                                    if bm == quil_engine::bitmasks::shard_consensus_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Consensus(std::mem::take(&mut received.data)));
                                        routed = true;
                                        break;
                                    }
                                    if bm == quil_engine::bitmasks::shard_frame_bitmask(filter).as_slice() {
                                        if frame_within_bound("shard frame topic", &received.via, &received.data) {
                                            handle.send(quil_engine::app_engine::AppEngineMessage::Frame(std::mem::take(&mut received.data)));
                                        }
                                        routed = true;
                                        break;
                                    }
                                    if bm == quil_engine::bitmasks::shard_dispatch_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Dispatch(std::mem::take(&mut received.data)));
                                        routed = true;
                                        break;
                                    }
                                    // Resolve the authenticated gossip/direct sender's
                                    // Falcon identity through PeerInfo or the committed
                                    // session. Worker vote/certificate verification and
                                    // session membership checks remain unchanged.
                                    if bm == quil_engine::bitmasks::shard_cw_bitmask(filter).as_slice() {
                                        // A transmission naming another member is dropped
                                        // here, unread.
                                        if let Some((channel, cw_bytes)) =
                                            quil_engine::bitmasks::shard_cw_admit(filter, &received.data, &local_cw_tag)
                                        {
                                            let peer_info_key = pic_for_recv.read().get(&received.from)
                                                .map(|info| info.public_key.clone());
                                            let from_key = shard_sender_key(
                                                &mut shard_sender_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
                                                &received.from, peer_info_key, &crdt_for_recv, filter);
                                            tracing::debug!(filter = %hex::encode(filter), channel,
                                                sender_known = !from_key.is_empty(), bytes = cw_bytes.len(),
                                                "routing shard CW message to its engine");
                                            handle.send(quil_engine::app_engine::AppEngineMessage::CwIn {
                                                channel,
                                                from: from_key,
                                                data: cw_bytes.to_vec(),
                                            });
                                        }
                                        routed = true;
                                        break;
                                    }
                                }
                                // A committee member's message sent to this node
                                // directly, for a shard one of its standalone
                                // workers runs: hand it to that worker.
                                if !routed && received.direct {
                                    if let Some(remote) = remote_workers_for_recv.get().cloned() {
                                        let served = remote
                                            .served_filters()
                                            .into_iter()
                                            .find(|filter| quil_engine::bitmasks::shard_cw_bitmask(filter).as_slice() == bm);
                                        if let Some(filter) = served {
                                            // The worker counts what it is handed.
                                            let elsewhere = quil_engine::bitmasks::shard_cw_addressee(&received.data)
                                                .is_some_and(|tag| tag != local_cw_tag);
                                            if let Some((channel, cw_bytes)) =
                                                quil_engine::bitmasks::shard_cw_split_payload(&received.data)
                                                    .filter(|_| !elsewhere)
                                            {
                                                let peer_info_key = pic_for_recv.read().get(&received.from)
                                                    .map(|info| info.public_key.clone());
                                                let from_key = shard_sender_key(
                                                    &mut shard_sender_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
                                                    &received.from, peer_info_key, &crdt_for_recv, &filter);
                                                let data = cw_bytes.to_vec();
                                                let topic = bm.to_vec();
                                                let p2p = p2p_for_recv.clone();
                                                let unsupported = remote_direct_unsupported.clone();
                                                spawner.detach("shard-cw-forward", async move {
                                                    use quil_engine::remote_worker::RemoteDelivery;
                                                    if remote.deliver_shard_consensus(&filter, channel, data, from_key).await
                                                        == RemoteDelivery::Unsupported
                                                    {
                                                        // Senders fall back to the topic,
                                                        // which the worker hears itself.
                                                        warn!(filter = %hex::encode(&filter),
                                                            "standalone worker lacks direct shard delivery; refusing direct messages for its shard");
                                                        unsupported.lock().insert(topic.clone());
                                                        p2p.revoke_direct(topic).await;
                                                    }
                                                    Ok(())
                                                });
                                            }
                                            routed = true;
                                        }
                                    }
                                }
                                if !routed {
                                    match archive_ingest_queue.as_ref() {
                                        Some((queue, admits)) => {
                                            if super::archive_ingest_queue::may_carry_shard_frame(bm)
                                                && admits.may_queue(&received.data)
                                                && frame_within_bound("archive ingest queue", &received.via, &received.data)
                                            {
                                                queue.offer(std::mem::take(&mut received.data));
                                            }
                                        }
                                        None => {
                                            if let Some(feed) = mirror_feed.as_ref() {
                                                let data = std::mem::take(&mut received.data);
                                                unrouted_shard_message(
                                                    bm,
                                                    mirror_sender(&received),
                                                    data,
                                                    feed,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            }
                        }
                        None => {
                            info!("message channel closed");
                            break;
                        }
                    }
                }
                _ = recv_token.cancelled() => {
                    break;
                }
            }
        }
        info!(
            frames = frames_received,
            peer_infos = peer_infos_received,
            "message receiver stopped"
        );
        Ok(())
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Any peer can publish on a shard's frame topic. A node without an
    /// archive ingest (a cluster master) must not make a gossiped frame with
    /// no certificate, numbered `u64::MAX`, the head it serves.
    #[test]
    fn reproduces_a_forged_far_future_shard_frame_becoming_the_mirrored_head() {
        let shard = Shard::new();
        let topic = shard.topic();
        shard.hear(&topic, &shard.frame(u64::MAX));
        let forged = shard.latest();
        shard.hear(&topic, &shard.frame(8));
        let after_next = shard.latest();
        assert_ne!(
            forged,
            Some(u64::MAX),
            "VULNERABLE: a gossiped shard frame with no certificate, numbered {}, was \
             mirrored unverified and became the head this node serves; after the next \
             frame (8) the head is {after_next:?}",
            u64::MAX
        );
    }

    /// A submission reaches every engine of its application on this node, and
    /// no engine of another application or topic.
    #[test]
    fn a_submission_reaches_every_shard_engine_of_its_application() {
        let app = [0x11u8; 32];
        let shard = |bits: &[bool]| quil_forest::encode_shard_bit_path(&app, bits);
        let other = quil_forest::encode_shard_bit_path(&[0x22u8; 32], &[true]);
        let entries = vec![
            (shard(&[false]), 1u8),
            (shard(&[true, false]), 2),
            (other.clone(), 3),
            (shard(&[true, true]), 4),
        ];
        let topic = quil_engine::bitmasks::app_prover_bitmask(&app);
        assert_eq!(submission_engines(&topic, &entries), vec![&1, &2, &4]);
        let own_frames = quil_engine::bitmasks::shard_frame_bitmask(&shard(&[false]));
        assert!(
            submission_engines(&own_frames, &entries).is_empty(),
            "a per-shard topic is not a submission"
        );
        assert_eq!(
            submission_engines(&quil_engine::bitmasks::app_prover_bitmask(&other), &entries),
            vec![&3]
        );
    }

    /// A shard of one committee member, and the validator a cluster master
    /// checks its gossiped frames with, over a prover registry and a clock
    /// store holding the member and the GLOBAL anchor.
    struct Shard {
        signer: quil_crypto::FalconSigner,
        filter: Vec<u8>,
        global_frame: u64,
        global_output: Vec<u8>,
        clock: Arc<quil_store::testing::InMemoryClockStore>,
        mirror: ShardMirror,
        feed: MirrorFeed,
    }

    impl Shard {
        fn new() -> Self {
            Self::registered(true)
        }

        /// The shard, named in the registry's shard summaries or not.
        fn registered(named: bool) -> Self {
            use quil_types::consensus::{ProverAllocationInfo, ProverInfo, ProverStatus};
            use quil_types::crypto::Signer as _;
            quil_crypto::init();
            let filter = vec![0x33; 32];
            let global_frame = quil_types::consensus::epoch_length_frames() * 11 + 3;
            let epoch = quil_types::consensus::epoch_for_frame(global_frame);
            let global_output = vec![9; 516];
            let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
            clock.seed_frame(quil_types::proto::global::GlobalFrame {
                header: Some(quil_types::proto::global::GlobalFrameHeader {
                    frame_number: global_frame,
                    output: global_output.clone(),
                    ..Default::default()
                }),
                requests: vec![],
            });
            let signer = quil_crypto::FalconSigner::generate();
            let registry = Arc::new(quil_engine::test_support::TestProverRegistry::with_prover(
                ProverInfo {
                    public_key: signer.public_key().to_vec(),
                    address: vec![7; 32],
                    status: ProverStatus::Active,
                    kick_frame_number: 0,
                    allocations: vec![ProverAllocationInfo {
                        status: ProverStatus::Active,
                        confirmation_filter: filter.clone(),
                        rejection_filter: vec![],
                        join_frame_number: 1,
                        leave_frame_number: 0,
                        pause_frame_number: 0,
                        resume_frame_number: 0,
                        kick_frame_number: 0,
                        join_confirm_frame_number: 0,
                        join_reject_frame_number: 0,
                        leave_confirm_frame_number: 0,
                        leave_reject_frame_number: 0,
                        last_active_frame_number: global_frame,
                        epoch,
                        ring: 0,
                        vertex_address: vec![],
                        last_signed_frame_number: 0,
                    }],
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: vec![],
                },
            ));
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(quil_types::crypto::NoopInclusionProver),
            ));
            if named {
                registry.set_summaries(vec![quil_types::consensus::ProverShardSummary {
                    filter: filter.clone(),
                    status_counts: Default::default(),
                    total_size: 0,
                }]);
            }
            let mirror = shard_mirror(registry, clock.clone(), crdt, None);
            Self {
                signer,
                filter,
                global_frame,
                global_output,
                clock,
                mirror,
                feed: MirrorFeed::new(),
            }
        }

        /// Frame `number`, anchored to the GLOBAL frame, without a
        /// certificate.
        fn frame(&self, number: u64) -> quil_types::proto::global::AppShardFrame {
            quil_types::proto::global::AppShardFrame {
                header: Some(quil_types::proto::global::FrameHeader {
                    address: self.filter.clone(),
                    frame_number: number,
                    rank: number,
                    global_frame_number: self.global_frame,
                    timestamp: 1,
                    state_roots: vec![vec![0; 32]; 4],
                    requests_root: vec![0; 32],
                    prover: vec![7; 32],
                    output: vec![number as u8; 516],
                    ..Default::default()
                }),
                ..Default::default()
            }
        }

        /// Frame `number` with its deterministic output and the member's
        /// finalization certificate.
        fn certified(&self, number: u64) -> quil_types::proto::global::AppShardFrame {
            self.certified_after(number, vec![])
        }

        /// Frame `number` built on the frame whose output identity is
        /// `parent_selector`, notarized: its deterministic output, no
        /// certificate of its own.
        fn notarized(
            &self,
            number: u64,
            parent_selector: Vec<u8>,
        ) -> quil_types::proto::global::AppShardFrame {
            let mut frame = self.certified_after(number, parent_selector);
            frame.header.as_mut().unwrap().public_key_signature_bls48581 = None;
            frame
        }

        /// The certified frame after `parent`, linking to it.
        fn certified_child(
            &self,
            parent: &quil_types::proto::global::AppShardFrame,
        ) -> quil_types::proto::global::AppShardFrame {
            let parent = parent.header.as_ref().unwrap();
            self.certified_after(
                parent.frame_number + 1,
                quil_crypto::poseidon::hash_bytes_to_32(&parent.output)
                    .unwrap()
                    .to_vec(),
            )
        }

        /// [`Self::certified`], built on `parent_selector`.
        fn certified_after(
            &self,
            number: u64,
            parent_selector: Vec<u8>,
        ) -> quil_types::proto::global::AppShardFrame {
            use quil_cw_consensus::{
                _consensus::{
                    simplex::{
                        scheme::Namespace,
                        types::{Finalization, Proposal, Subject},
                    },
                    types::{Epoch, Round, View},
                },
                _crypto::{sha256::Digest, Signer as _},
                _utils::{ordered::Set, N3f1},
                app_cert::{encode_finalization, wrap_cert_for_header},
                falcon_base::FalconPrivateKey,
                falcon_scheme::Generic,
                falcon_simplex::SimplexFalconScheme,
            };
            use quil_types::crypto::Signer as _;
            let mut frame = self.frame(number);
            let h = frame.header.as_mut().unwrap();
            h.parent_selector = parent_selector;
            let rho = quil_crypto::porep::derive_storage_beacon(
                h.global_frame_number,
                &self.global_output,
            );
            h.output = quil_crypto::porep::deterministic_app_frame_output(
                &h.parent_selector,
                &h.requests_root,
                &h.state_roots,
                &rho,
                h.frame_number,
                h.rank,
                &h.prover,
                h.difficulty,
                h.fee_multiplier_vote,
                h.timestamp,
                &h.storage_attestation_root,
                quil_execution::global_intrinsic::frame_header::fee_total_from_bytes(&h.fee_total),
                &h.settlements,
                &h.accumulator,
                &h.spends,
            );
            let key =
                FalconPrivateKey::from_bytes(self.signer.private_key(), self.signer.public_key())
                    .unwrap();
            let participants: Set<_> = vec![key.public_key()].try_into().unwrap();
            let mut namespace = b"appshard".to_vec();
            namespace.extend_from_slice(&h.address);
            let scheme = Generic::<Namespace>::signer(&namespace, participants, key).unwrap();
            let proposal = Proposal::new(
                Round::new(Epoch::new(0), View::new(h.rank)),
                View::new(h.rank - 1),
                Digest(quil_crypto::poseidon::hash_bytes_to_32(&h.output).unwrap()),
            );
            let vote = scheme
                .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                    proposal: &proposal,
                })
                .unwrap();
            let certificate = scheme
                .assemble::<SimplexFalconScheme, _, N3f1>(vec![vote])
                .unwrap();
            h.public_key_signature_bls48581 =
                Some(quil_types::proto::keys::Bls48581AggregateSignature {
                    signature: wrap_cert_for_header(&encode_finalization(&Finalization {
                        proposal,
                        certificate,
                    })),
                    bitmask: vec![1],
                    ..Default::default()
                });
            frame
        }

        /// `frame` heard on `bitmask`: queued as the loop queues it, then
        /// checked as the mirror's worker checks it.
        fn hear(&self, bitmask: &[u8], frame: &quil_types::proto::global::AppShardFrame) {
            unrouted_shard_message(
                bitmask,
                MirrorSender {
                    signer: b"peer",
                    via: b"peer",
                },
                prost::Message::encode_to_vec(frame),
                &self.feed,
            );
            while let Some(data) = self.feed.take() {
                mirror_queued(self.clock.as_ref(), &self.mirror, &data);
            }
        }

        fn topic(&self) -> Vec<u8> {
            quil_engine::bitmasks::shard_frame_bitmask(&self.filter)
        }

        fn latest(&self) -> Option<u64> {
            use quil_types::store::ClockStore as _;
            self.clock
                .get_latest_shard_clock_frame(&self.filter)
                .ok()
                .and_then(|frame| frame.header)
                .map(|header| header.frame_number)
        }
    }

    /// A cluster master (no archive ingest) mirrors a certified frame on its
    /// shard's frame topic for serving, and not a message on another topic. An
    /// archive queues the frame for its ingest instead; a frame it fetched to
    /// fill a gap arrives under the frame's own topic, which the queue takes.
    #[test]
    fn only_a_cluster_master_mirrors_a_verified_frame() {
        use quil_types::store::ClockStore as _;
        let shard = Shard::new();
        let topic = shard.topic();
        let frame = shard.certified(7);
        assert_eq!(mirror_admits(&shard.mirror.validator, &frame), Ok(()));
        shard.hear(&topic, &frame);
        assert_eq!(
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, 7, false)
                .unwrap(),
            frame
        );
        assert_eq!(shard.latest(), Some(7));
        shard.hear(&[], &shard.certified(8));
        assert!(
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, 8, false)
                .is_err(),
            "not a shard-frame message"
        );
        shard.hear(&topic, &shard.certified(8));
        assert_eq!(
            shard.latest(),
            Some(8),
            "the next certified frame is mirrored"
        );

        let fetched = gap_fetched_frame_message(
            &shard.filter,
            prost::Message::encode_to_vec(&shard.certified(9)),
        );
        assert_eq!(fetched.bitmask, topic);
        assert!(super::super::archive_ingest_queue::may_carry_shard_frame(
            &fetched.bitmask
        ));
    }

    /// R112-D-2: an endpoint a verified archive's PeerInfo names is pinned
    /// to that archive before the pool dials it, so whoever answers there
    /// must be that archive. Another archive's record naming the same
    /// endpoint neither re-pins nor adds it.
    #[test]
    fn r112_d2_a_gossiped_archive_endpoint_is_pinned_to_its_record() {
        use quil_rpc::archive_client::pinned_archive_peer;
        let peer = || {
            quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
                .unwrap()
                .public()
                .to_peer_id()
        };
        let (a, b) = (peer(), peer());
        let record = |peer: quil_p2p::PeerId, addrs: &[&str]| quil_p2p::CanonicalPeerInfo {
            peer_id: peer.to_bytes(),
            reachability: vec![quil_p2p::CanonicalReachability {
                stream_multiaddrs: addrs.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let shared = "203.0.113.7:8340";
        assert_eq!(
            archive_record_endpoints(&record(a, &["/ip4/203.0.113.7/tcp/8340"]), 0),
            vec![shared.to_string()]
        );
        assert_eq!(
            pinned_archive_peer(shared),
            Some(a),
            "R112-D-2: a gossiped archive endpoint is dialed unpinned"
        );
        let other = archive_record_endpoints(
            &record(
                b,
                &["/ip4/203.0.113.7/tcp/8340", "/ip4/203.0.113.8/tcp/8340"],
            ),
            0,
        );
        assert_eq!(
            (other, pinned_archive_peer(shared)),
            (vec!["203.0.113.8:8340".to_string()], Some(a)),
            "R112-D-2: another archive's record took over an endpoint pinned to the first"
        );
        assert_eq!(pinned_archive_peer("203.0.113.8:8340"), Some(b));
    }

    /// R112-D-2: what the gossip handler adds to the archive pool is pinned
    /// to the archive whose record named it.
    #[tokio::test]
    async fn r112_d2_the_gossip_handler_adds_archive_endpoints_pinned() {
        let peer = quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
            .unwrap()
            .public()
            .to_peer_id();
        let info = quil_p2p::CanonicalPeerInfo {
            peer_id: peer.to_bytes(),
            reachability: vec![quil_p2p::CanonicalReachability {
                stream_multiaddrs: vec!["/ip4/203.0.113.21/tcp/8340".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let pool = quil_rpc::ArchiveEndpointPool::new(std::time::Duration::ZERO);
        let first = add_archive_record_endpoints(&pool, &info, 0).await;
        assert_eq!(first.as_deref(), Some("203.0.113.21:8340"));
        assert_eq!(pool.get_all().await, vec!["203.0.113.21:8340".to_string()]);
        assert_eq!(
            quil_rpc::archive_client::pinned_archive_peer("203.0.113.21:8340"),
            Some(peer),
            "R112-D-2: the gossip handler added an archive endpoint unpinned"
        );
    }

    /// Any peer can publish on a shard's frame topic: a frame without a
    /// certificate, with one that does not verify, or one whose header the
    /// certificate does not cover is not mirrored, so a forged far-future
    /// frame cannot pin the head this node serves.
    #[test]
    fn a_gossiped_shard_frame_that_does_not_verify_is_not_mirrored() {
        let shard = Shard::new();
        let topic = shard.topic();
        shard.hear(&topic, &shard.certified(7));
        let unsigned = shard.frame(u64::MAX);
        let mut altered = shard.certified(8);
        altered.header.as_mut().unwrap().frame_number = u64::MAX;
        let mut garbage = shard.frame(u64::MAX);
        garbage
            .header
            .as_mut()
            .unwrap()
            .public_key_signature_bls48581 =
            Some(quil_types::proto::keys::Bls48581AggregateSignature {
                signature: quil_cw_consensus::app_cert::wrap_cert_for_header(&[0xab; 64]),
                bitmask: vec![1],
                ..Default::default()
            });
        for forged in [&unsigned, &altered, &garbage] {
            assert!(mirror_admits(&shard.mirror.validator, forged).is_err());
            shard.hear(&topic, forged);
            assert_eq!(shard.latest(), Some(7), "the forged frame is not mirrored");
        }
        shard.hear(&topic, &shard.certified(8));
        assert_eq!(shard.latest(), Some(8), "the honest chain still advances");
    }

    /// Simplex finalizes a notarized frame through its certified child, so a
    /// genuine frame can come without a certificate of its own (mainnet
    /// shards make several a day). It is held and mirrored once a certified
    /// child links to it, whichever arrives first; a frame without a
    /// certificate that no certified child links to is not.
    #[test]
    fn a_frame_final_only_through_its_certified_child_is_mirrored() {
        use quil_types::store::ClockStore as _;
        let shard = Shard::new();
        let topic = shard.topic();
        let stored = |number| {
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, number, false)
                .ok()
        };
        shard.hear(&topic, &shard.certified(6));
        let parent = shard.notarized(7, selector(&shard.certified(6)));
        let impostor = shard.notarized(7, vec![1; 32]);
        assert!(mirror_admits(&shard.mirror.validator, &parent).is_err());
        shard.hear(&topic, &impostor);
        shard.hear(&topic, &parent);
        assert_eq!(stored(7), None, "no certified child links to it yet");
        assert_eq!(shard.latest(), Some(6));
        shard.hear(&topic, &shard.certified_child(&parent));
        assert_eq!(
            (stored(7), shard.latest()),
            (Some(parent.clone()), Some(8)),
            "FINAL-THROUGH-CHILD: a frame final only through its certified child was not \
             mirrored once the child arrived"
        );

        let late = shard.notarized(9, selector(&shard.certified_child(&parent)));
        shard.hear(&topic, &shard.certified_child(&late));
        assert_eq!(shard.latest(), Some(10));
        shard.hear(&topic, &late);
        assert_eq!(
            stored(9),
            Some(late),
            "FINAL-THROUGH-CHILD: a frame final only through its certified child was not \
             mirrored when the child came first"
        );

        let orphan = shard.notarized(11, vec![0; 32]);
        shard.hear(&topic, &orphan);
        assert_eq!(stored(11), None, "no certified child links to it");
        assert_eq!(shard.latest(), Some(10));
    }

    /// The certificate covers the header only: a copy whose carried requests
    /// do not match the header's root is neither mirrored nor held, and so
    /// does not keep out the genuine copy that follows.
    #[test]
    fn a_copy_whose_requests_do_not_match_its_header_is_not_mirrored() {
        use quil_types::store::ClockStore as _;
        let shard = Shard::new();
        let topic = shard.topic();
        let stored = |number| {
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, number, false)
                .ok()
        };
        let tampered = |frame: &quil_types::proto::global::AppShardFrame| {
            let mut frame = frame.clone();
            frame.requests = vec![Default::default()];
            frame
        };
        let genuine = shard.certified(6);
        shard.hear(&topic, &tampered(&genuine));
        assert_eq!(
            stored(6),
            None,
            "BODY-UNBOUND: a certified header carrying requests its root does not commit to \
             was mirrored"
        );
        shard.hear(&topic, &genuine);
        assert_eq!(stored(6), Some(genuine.clone()));

        let parent = shard.notarized(7, selector(&genuine));
        assert!(
            shard
                .mirror
                .offer(
                    shard.clock.as_ref(),
                    &tampered(&parent),
                    &prost::Message::encode_to_vec(&tampered(&parent)),
                )
                .is_err(),
            "BODY-UNBOUND: a frame without a certificate whose requests do not match was held"
        );
        shard.hear(&topic, &parent);
        shard.hear(&topic, &shard.certified_child(&parent));
        assert_eq!(stored(7), Some(parent), "the genuine copy is mirrored");
    }

    /// A frame without a certificate is held only for a shard the prover
    /// registry names, and only within [`MIRROR_HOLD_WINDOW`] of the shard's
    /// stored head at a number with no stored frame.
    #[test]
    fn a_frame_is_held_only_for_a_registered_shard_near_its_head() {
        let offer = |shard: &Shard, frame: &quil_types::proto::global::AppShardFrame| {
            shard.mirror.offer(
                shard.clock.as_ref(),
                frame,
                &prost::Message::encode_to_vec(frame),
            )
        };
        let unnamed = Shard::registered(false);
        let frame = unnamed.notarized(7, vec![1; 32]);
        assert!(
            offer(&unnamed, &frame).is_err(),
            "HOLD-BOUND: a frame of a shard the registry does not name was held"
        );

        let shard = Shard::new();
        let topic = shard.topic();
        shard.hear(&topic, &shard.certified(6));
        let far = shard.notarized(6 + MIRROR_HOLD_WINDOW + 1, vec![1; 32]);
        assert!(
            offer(&shard, &far).is_err(),
            "HOLD-BOUND: a frame past the window above the stored head was held"
        );
        assert!(
            offer(&shard, &shard.notarized(6, vec![1; 32])).is_err(),
            "HOLD-BOUND: a frame at the stored head's number was held"
        );
        assert_eq!(
            offer(
                &shard,
                &shard.notarized(6 + MIRROR_HOLD_WINDOW, vec![1; 32])
            ),
            Ok(Mirrored::Held)
        );
    }

    /// Two frames without a certificate in a row are mirrored by the
    /// certified frame after them, whichever of them arrived first.
    #[test]
    fn a_certified_frame_mirrors_two_held_ancestors() {
        use quil_types::store::ClockStore as _;
        for parent_first in [true, false] {
            let shard = Shard::new();
            let topic = shard.topic();
            let stored = |number| {
                shard
                    .clock
                    .get_shard_clock_frame(&shard.filter, number, false)
                    .ok()
            };
            shard.hear(&topic, &shard.certified(6));
            let first = shard.notarized(7, selector(&shard.certified(6)));
            let second = shard.notarized(8, selector(&first));
            if parent_first {
                shard.hear(&topic, &first);
                shard.hear(&topic, &second);
            } else {
                shard.hear(&topic, &second);
                shard.hear(&topic, &first);
            }
            assert_eq!((stored(7), stored(8)), (None, None));
            shard.hear(&topic, &shard.certified_child(&second));
            assert_eq!(
                (stored(7), stored(8), shard.latest()),
                (Some(first), Some(second), Some(9)),
                "both held ancestors are mirrored (parent first: {parent_first})"
            );
        }
    }

    /// The hold's bounds: a duplicate is held once; past the per-number bound
    /// the longest held there goes; past the per-shard bound the farthest
    /// frame; pruning drops what lies below; an evicted frame a child names
    /// counts as lost; the byte count returns to zero in both indexes.
    #[test]
    fn held_frames_evict_in_order_and_keep_their_byte_count() {
        let key =
            |filter: u8, number: u64, identity: u8| (vec![filter; 35], number, [identity; 32]);
        let child = quil_types::proto::global::FrameHeader::default();
        let mut held = HeldFrames::new(usize::MAX);
        assert!(held.insert(key(1, 5, 1), vec![0; 10]));
        let bytes = held.bytes;
        assert!(
            !held.insert(key(1, 5, 1), vec![0; 10]),
            "a duplicate is held once"
        );
        assert_eq!(held.bytes, bytes);
        for identity in 2..=(MIRROR_HELD_PER_NUMBER as u8 + 1) {
            held.insert(key(1, 5, identity), vec![0; 10]);
        }
        assert!(
            !held.frames.contains_key(&key(1, 5, 1)),
            "the longest held at its number goes"
        );
        assert_eq!(held.counts.evicted, 1);

        let mut held = HeldFrames::new(usize::MAX);
        for number in 1..=MIRROR_HELD_PER_SHARD as u64 + 1 {
            held.insert(key(1, number, 0), vec![0; 10]);
        }
        assert!(
            held.frames.contains_key(&key(1, 1, 0))
                && !held
                    .frames
                    .contains_key(&key(1, MIRROR_HELD_PER_SHARD as u64 + 1, 0)),
            "EVICTION-ORDER: past the per-shard bound the farthest frame goes, not the next"
        );
        assert_eq!(
            held.take_parent(&[1; 35], MIRROR_HELD_PER_SHARD as u64 + 1, [0; 32], &child),
            None
        );
        assert_eq!(
            held.counts.lost, 1,
            "an evicted frame a child names is lost"
        );
        held.prune_below(&[1; 35], 11);
        assert_eq!(held.frames.len(), MIRROR_HELD_PER_SHARD - 10);
        assert_eq!(held.counts.pruned, 10);

        let one = HeldFrames::cost(&key(1, 1, 0), &[0; 1000]);
        let mut held = HeldFrames::new(usize::MAX);
        for filter in 1..=3 {
            held.insert(key(filter, 1, 0), vec![0; 1000]);
        }
        assert_eq!(held.bytes, 3 * one);
        for filter in 1..=3 {
            held.remove(&key(filter, 1, 0));
        }
        assert_eq!(
            (held.bytes, held.shard_bytes.len(), held.by_size.len()),
            (0, 0, 0)
        );
    }

    /// Past the byte bound the shard holding the most bytes loses its
    /// largest frame, of equal sizes the farthest, so frames sent to other
    /// shards do not push out a lighter shard's frames, however long held.
    #[test]
    fn held_bytes_evict_from_the_shard_holding_the_most() {
        let key =
            |filter: u8, number: u64, identity: u8| (vec![filter; 35], number, [identity; 32]);
        let one = HeldFrames::cost(&key(1, 1, 0), &[0; 1000]);
        let mut held = HeldFrames::new(4 * one);
        held.insert(key(1, 7, 0), vec![0; 1000]);
        for number in 1..=3 {
            held.insert(key(2, number, 0), vec![0; 1000]);
        }
        held.insert(key(3, 1, 0), vec![0; 1000]);
        assert!(
            held.frames.contains_key(&key(1, 7, 0)),
            "BYTE-EVICTION: past the byte bound a frame of the shard holding the fewest \
             bytes was evicted"
        );
        assert!(
            !held.frames.contains_key(&key(2, 3, 0))
                && held.frames.contains_key(&key(2, 1, 0))
                && held.frames.len() == 4,
            "BYTE-EVICTION: past the byte bound the farthest of the equal frames of the shard \
             holding the most bytes goes"
        );
        assert_eq!(
            (
                held.bytes,
                held.shard_bytes.get([2u8; 35].as_slice()).copied()
            ),
            (4 * one, Some(2 * one))
        );
    }

    /// Past the byte bound a real frame does not go ahead of impostors padded
    /// at its number. The attack: three frames padded toward the size bound
    /// at the real next frame's number, their identities ground to sort
    /// below it so it is its shard's farthest frame; frames on other shards,
    /// each lighter than its shard, filling the bound until the real frame's
    /// arrival crosses it. The heaviest shard's largest frame goes, an
    /// impostor.
    #[test]
    fn held_bytes_evict_padded_impostors_before_the_real_frame() {
        let key =
            |filter: u8, number: u64, identity: u8| (vec![filter; 35], number, [identity; 32]);
        let real = key(1, 9, 0x80);
        let real_data = vec![0; 2000];
        let real_cost = HeldFrames::cost(&real, &real_data);
        let padded = MIRROR_HELD_FRAME_BYTES;
        let mut held = HeldFrames::new(MIRROR_HELD_BYTES);
        let impostors: Vec<HeldKey> = (1..MIRROR_HELD_PER_NUMBER as u8)
            .map(|identity| key(1, 9, identity))
            .collect();
        for impostor in &impostors {
            held.insert(impostor.clone(), vec![0; padded]);
        }
        let victim = held.bytes + real_cost;
        // Two frames per other shard, each at most padded, to within half the
        // real frame's cost of the bound.
        let (mut filter, mut number) = (2u8, 1);
        loop {
            let empty = HeldFrames::cost(&key(filter, number, 0), &[]);
            let wanted = (MIRROR_HELD_BYTES - held.bytes).saturating_sub(real_cost / 2);
            if wanted <= empty {
                break;
            }
            held.insert(
                key(filter, number, 0),
                vec![0; (wanted - empty).min(padded)],
            );
            if number == 2 {
                (filter, number) = (filter + 1, 1);
            } else {
                number += 1;
            }
        }
        assert!(held.shard_bytes.values().all(|&bytes| bytes < victim));
        assert!(held.bytes <= MIRROR_HELD_BYTES && held.bytes + real_cost > MIRROR_HELD_BYTES);
        assert_eq!(held.counts.evicted, 0);
        assert!(
            held.shard_bytes.len() > 30,
            "frames on about 31 other shards"
        );

        held.insert(real.clone(), real_data);
        assert!(
            held.frames.contains_key(&real),
            "BYTE-STEERING: past the byte bound the real frame, the smallest of the heaviest \
             shard, was evicted ahead of the impostors padded at its number"
        );
        assert_eq!(held.counts.evicted, 1);
        assert_eq!(
            impostors
                .iter()
                .filter(|impostor| held.frames.contains_key(*impostor))
                .count(),
            impostors.len() - 1,
            "one padded impostor goes"
        );
        assert!(held.bytes <= MIRROR_HELD_BYTES);
    }

    /// A frame over the check's bounds is refused before any check: one
    /// carrying more request bundles than [`MIRROR_MAX_REQUESTS`], and one
    /// without a certificate larger than [`MIRROR_HELD_FRAME_BYTES`], which
    /// is never held.
    #[test]
    fn a_frame_over_the_check_bounds_is_refused_before_its_check() {
        let shard = Shard::new();
        let topic = shard.topic();
        shard.hear(&topic, &shard.certified(6));
        let offer = |frame: &quil_types::proto::global::AppShardFrame, data: &[u8]| {
            shard.mirror.offer(shard.clock.as_ref(), frame, data)
        };
        let carrying = |count: usize| {
            let mut frame = shard.certified(7);
            frame.requests = vec![Default::default(); count];
            frame
        };
        let within = carrying(MIRROR_MAX_REQUESTS);
        let over = carrying(MIRROR_MAX_REQUESTS + 1);
        let reason = |frame: &quil_types::proto::global::AppShardFrame| {
            offer(frame, &prost::Message::encode_to_vec(frame)).unwrap_err()
        };
        assert!(
            !reason(&within).contains("request bundles, more than"),
            "a frame within the bound reaches the body check"
        );
        assert!(
            reason(&over).contains("request bundles, more than"),
            "BODY-BOUND: a frame carrying more request bundles than the bound reached the \
             body check: {}",
            reason(&over)
        );

        let notarized = shard.notarized(7, selector(&shard.certified(6)));
        let mut large = prost::Message::encode_to_vec(&notarized);
        // An unknown field: the frame decodes the same.
        prost::encoding::encode_key(15, prost::encoding::WireType::LengthDelimited, &mut large);
        prost::encoding::encode_varint(MIRROR_HELD_FRAME_BYTES as u64, &mut large);
        large.resize(large.len() + MIRROR_HELD_FRAME_BYTES, 0);
        assert_eq!(
            <quil_types::proto::global::AppShardFrame as prost::Message>::decode(large.as_slice())
                .ok(),
            Some(notarized.clone())
        );
        assert!(
            offer(&notarized, &large).is_err(),
            "HOLD-SIZE: a frame without a certificate larger than the bound was held"
        );
        assert_eq!(
            offer(&notarized, &prost::Message::encode_to_vec(&notarized)),
            Ok(Mirrored::Held)
        );
    }

    /// A frame without a certificate below the stored head, at a number with
    /// no stored frame, is held: a certified frame stored ahead of a gap does
    /// not keep the gap's frames out. One at a stored number, or further than
    /// [`MIRROR_HOLD_WINDOW`] below the head, is not.
    #[test]
    fn a_frame_below_the_stored_head_fills_its_gap() {
        use quil_types::store::ClockStore as _;
        let shard = Shard::new();
        let topic = shard.topic();
        let stored = |number| {
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, number, false)
                .ok()
        };
        let base = MIRROR_HOLD_WINDOW + 8;
        shard.hear(&topic, &shard.certified(base));
        let gap = shard.notarized(base + 1, selector(&shard.certified(base)));
        let child = shard.certified_child(&gap);
        let ahead = shard.certified_child(&child);
        shard.hear(&topic, &ahead);
        assert_eq!(shard.latest(), Some(base + 3));
        shard.hear(&topic, &gap);
        shard.hear(&topic, &child);
        assert_eq!(
            stored(base + 1),
            Some(gap),
            "GAP-BELOW-HEAD: a frame without a certificate below the stored head was not \
             mirrored once its certified child arrived"
        );
        let offer = |frame: &quil_types::proto::global::AppShardFrame| {
            shard.mirror.offer(
                shard.clock.as_ref(),
                frame,
                &prost::Message::encode_to_vec(frame),
            )
        };
        assert!(
            offer(&shard.notarized(base, vec![1; 32])).is_err(),
            "a frame at a stored number is not held"
        );
        assert!(
            offer(&shard.notarized(base + 3 - MIRROR_HOLD_WINDOW - 1, vec![1; 32])).is_err(),
            "a frame past the window below the stored head is not held"
        );
        assert_eq!(
            offer(&shard.notarized(base + 3 - MIRROR_HOLD_WINDOW, vec![1; 32])),
            Ok(Mirrored::Held)
        );
    }

    /// The hold's counts are logged at once, then at most once per interval,
    /// and only when something happened.
    #[test]
    fn held_frames_are_summarized_per_interval() {
        let shard = Shard::new();
        let offer = |frame: &quil_types::proto::global::AppShardFrame| {
            shard.mirror.offer(
                shard.clock.as_ref(),
                frame,
                &prost::Message::encode_to_vec(frame),
            )
        };
        let start = std::time::Instant::now();
        assert_eq!(shard.mirror.summarize(start), None, "nothing happened");
        assert_eq!(offer(&shard.certified(6)), Ok(Mirrored::Stored));
        assert_eq!(
            offer(&shard.notarized(7, selector(&shard.certified(6)))),
            Ok(Mirrored::Held)
        );
        assert_eq!(
            shard.mirror.summarize(start).map(|counts| counts.held),
            Some(1)
        );
        assert_eq!(offer(&shard.notarized(8, vec![1; 32])), Ok(Mirrored::Held));
        assert_eq!(shard.mirror.summarize(start), None);
        assert_eq!(
            shard
                .mirror
                .summarize(start + MIRROR_HOLD_SUMMARY)
                .map(|counts| counts.held),
            Some(1)
        );
    }

    /// Wait for `done`, failing with `what` once 30 s pass without it.
    fn wait_for(what: &str, done: impl Fn() -> bool) {
        let started = std::time::Instant::now();
        while !done() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(30),
                "{what}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The lines logged while installed, on this thread and on the threads
    /// it starts with its dispatcher (the mirror's worker).
    #[derive(Clone, Default)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl Capture {
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_writer(self.clone())
                    .with_ansi(false)
                    .finish(),
            )
        }

        fn lines_with(&self, text: &str) -> Vec<String> {
            String::from_utf8_lossy(&self.0.lock().unwrap())
                .lines()
                .filter(|line| line.contains(text))
                .map(str::to_owned)
                .collect()
        }
    }

    /// The loop queues a gossiped shard frame and goes on while the mirror's
    /// check waits, as it waits for the execution engines GLOBAL execution
    /// holds, also past the frames a topic queues: those past its bound are
    /// dropped, never waited for. The worker checks the frames queued once
    /// it can.
    #[test]
    fn the_loop_queues_frames_for_the_mirror_without_waiting() {
        let offered = 2 * 3 * MIRROR_QUEUED_PER_TOPIC;
        let kept = 2 * MIRROR_QUEUED_PER_TOPIC;
        let engines = Arc::new(std::sync::Mutex::new(()));
        let checked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let held = engines.lock().unwrap();
        let feed = {
            let (engines, checked) = (engines.clone(), checked.clone());
            MirrorFeed::spawn(
                move |data| {
                    let _engines = engines
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    checked.lock().unwrap().push(data.to_vec());
                },
                |_| None,
            )
        };
        let started = std::time::Instant::now();
        for frame in 0..offered {
            feed.offer(
                &[(frame % 2) as u8; 32],
                b"peer",
                (frame as u16).to_be_bytes().repeat(50),
                0,
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "LOOP-WAITS: queuing frame {frame} waited for the mirror's check"
            );
        }
        drop(held);
        // Progress, with a generous overall cap.
        let mut last = (usize::MAX, std::time::Instant::now());
        loop {
            let (left, checking) = {
                let state = feed.shared.lock();
                (state.queue.len(), state.checking.is_some())
            };
            if left == 0 && !checking {
                break;
            }
            if left != last.0 {
                last = (left, std::time::Instant::now());
            }
            assert!(
                last.1.elapsed() < std::time::Duration::from_secs(30),
                "the worker stopped with {left} frames queued"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut checked = checked.lock().unwrap().clone();
        let count = checked.len();
        // Each topic kept its bound; the worker may have taken one more into
        // its check before the rest arrived.
        assert!(
            (kept..=kept + 1).contains(&count),
            "{count} of {offered} offered frames checked"
        );
        checked.sort();
        checked.dedup();
        assert_eq!(checked.len(), count, "a frame was checked twice");
    }

    /// A peer that floods one topic with costly frames delays another
    /// topic's frame by one check (one other topic queues frames here), and
    /// another sender's frame on its own topic by one of its frames.
    #[test]
    fn a_flood_delays_other_topics_and_senders_by_one_turn() {
        let (flooded, other) = ([1u8; 32], [2u8; 32]);
        let mut queue = MirrorQueue::new(MIRROR_QUEUED_BYTES);
        for _ in 0..MIRROR_QUEUED_PER_TOPIC - 2 {
            queue.push(&flooded, b"flood", vec![0xee; 1 << 20], MIRROR_MAX_REQUESTS);
        }
        queue.push(&other, b"genuine", vec![2; 2000], 1);
        queue.push(&flooded, b"genuine", vec![1; 2000], 1);
        let first: Vec<Vec<u8>> = std::iter::from_fn(|| queue.pop()).take(3).collect();
        assert!(
            first.contains(&vec![2; 2000]) && first.contains(&vec![1; 2000]),
            "QUEUE-FAIRNESS: a flood's frames were checked before the genuine ones"
        );
        assert_eq!(
            std::iter::from_fn(|| queue.pop()).count(),
            MIRROR_QUEUED_PER_TOPIC - 3
        );
        assert_eq!(queue.dropped, QueueDrops::default());
        assert_eq!(queue.bytes, 0);
        assert!(queue.topics.is_empty() && queue.turns.is_empty());
    }

    /// A peer that floods a topic, faster than the worker checks, with
    /// frames smaller (so cheaper) than a genuine one neither evicts another
    /// sender's frame on that topic nor keeps it from its turn: the topic's
    /// bound drops the flood's own frames.
    #[test]
    fn a_small_frame_flood_from_one_sender_leaves_another_senders_frame_checked() {
        let topic = [1u8; 32];
        let genuine = vec![2; 2000];
        let mut queue = MirrorQueue::new(MIRROR_QUEUED_BYTES);
        for flood in 0..MIRROR_QUEUED_PER_TOPIC {
            queue.push(&topic, b"flood", vec![flood as u8; 100], 0);
        }
        queue.push(&topic, b"genuine", genuine.clone(), 1);
        for flood in 0..2 * MIRROR_QUEUED_PER_TOPIC {
            queue.push(&topic, b"flood", vec![flood as u8; 100], 0);
        }
        assert_eq!(queue.dropped.frames, 2 * MIRROR_QUEUED_PER_TOPIC as u64 + 1);
        let first: Vec<Vec<u8>> = std::iter::from_fn(|| queue.pop()).take(2).collect();
        assert!(
            first.contains(&genuine),
            "QUEUE-SENDERS: a small-frame flood from one sender evicted or delayed another \
             sender's frame"
        );
    }

    /// Gossip signers are free to mint, connections are not: the mirror's
    /// queue keys senders on the connected peer a frame arrived from. Many
    /// signers on one connection are one sender, which loses its own frames
    /// past the topic's bound; one-frame senders on many connections lose
    /// their costliest frames first and wait behind a cheaper genuine one.
    /// Either way a genuine frame arriving into a full topic is kept and
    /// checked first.
    #[test]
    fn many_signers_or_connections_neither_evict_nor_delay_a_genuine_frame() {
        let shard = Shard::new();
        let topic = shard.topic();
        let genuine = prost::Message::encode_to_vec(&shard.certified(7));
        let offer = |feed: &MirrorFeed, from: &[u8], via: &[u8], data: &[u8]| {
            let mut received = quil_p2p::node::ReceivedMessage {
                bitmask: topic.clone(),
                data: data.to_vec(),
                from: from.to_vec(),
                via: via.to_vec(),
                direct: false,
            };
            let data = std::mem::take(&mut received.data);
            assert!(unrouted_shard_message(
                &topic,
                mirror_sender(&received),
                data,
                feed
            ));
        };

        let cheap = prost::Message::encode_to_vec(&shard.frame(7));
        assert!(cheap.len() < genuine.len());
        let feed = MirrorFeed::new();
        for signer in 0..MIRROR_QUEUED_PER_TOPIC as u8 {
            offer(&feed, &[signer; 8], b"one connection", &cheap);
        }
        offer(&feed, b"prover", b"honest", &genuine);
        assert_eq!(
            feed.take(),
            Some(genuine.clone()),
            "SYBIL-SIGNERS: frames signed by many keys on one connection evicted or delayed \
             another connection's genuine frame"
        );

        let mut costly = shard.frame(7);
        costly.requests = vec![Default::default(); 8];
        let costly = prost::Message::encode_to_vec(&costly);
        let feed = MirrorFeed::new();
        for connection in 0..MIRROR_QUEUED_PER_TOPIC as u8 {
            offer(&feed, &[connection; 8], &[connection; 8], &costly);
        }
        offer(&feed, b"prover", b"honest", &genuine);
        assert_eq!(feed.shared.lock().queue.len(), MIRROR_QUEUED_PER_TOPIC);
        assert_eq!(
            feed.take(),
            Some(genuine),
            "SYBIL-CONNECTIONS: one-frame senders on many connections evicted or delayed a \
             cheaper genuine frame"
        );
    }

    /// A relay that delivers a committee member's frame first does not own
    /// it: once the worker read the shard's members, a frame a member signed
    /// queues under the member, so the relay's own cheaper frames on that
    /// connection neither evict it nor go first. The worker reads a shard's
    /// members once per interval.
    #[test]
    fn a_member_frame_relayed_first_is_kept_from_the_relays_frames() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let shard = Shard::new();
        let topic = shard.topic();
        let genuine = prost::Message::encode_to_vec(&shard.certified(7));
        let cheap = prost::Message::encode_to_vec(&shard.frame(7));
        let member = b"member".to_vec();
        let offer = |feed: &MirrorFeed, from: &[u8], data: &[u8]| {
            let received = quil_p2p::node::ReceivedMessage {
                bitmask: topic.clone(),
                data: Vec::new(),
                from: from.to_vec(),
                via: b"relay".to_vec(),
                direct: false,
            };
            assert!(unrouted_shard_message(
                &topic,
                mirror_sender(&received),
                data.to_vec(),
                feed
            ));
        };

        let feed = MirrorFeed::new();
        feed.shared.lock().keep_members(
            shard.filter.clone(),
            vec![member.clone()],
            std::time::Instant::now(),
        );
        offer(&feed, &member, &genuine);
        for signer in 0..MIRROR_QUEUED_PER_TOPIC as u8 {
            offer(&feed, &[signer; 8], &cheap);
        }
        assert_eq!(
            feed.take(),
            Some(genuine.clone()),
            "FIRST-RELAY: a relay's own frames evicted or delayed a member's frame it relayed first"
        );

        let reads = Arc::new(AtomicUsize::new(0));
        let checked = Arc::new(AtomicUsize::new(0));
        let feed = {
            let (reads, checked, member) = (reads.clone(), checked.clone(), member.clone());
            MirrorFeed::spawn(
                move |_| {
                    checked.fetch_add(1, SeqCst);
                },
                move |_| {
                    reads.fetch_add(1, SeqCst);
                    Some(vec![member.clone()])
                },
            )
        };
        for _ in 0..3 {
            offer(&feed, &member, &genuine);
        }
        wait_for("the worker did not check the queued frames", || {
            checked.load(SeqCst) == 3
        });
        assert_eq!(
            reads.load(SeqCst),
            1,
            "MEMBERS-UNCACHED: the worker read a shard's members for each of its frames"
        );
        assert!(feed
            .shared
            .lock()
            .members_fresh(&shard.filter, std::time::Instant::now()));
    }

    /// A frame carrying more bundles and requests than a frame may is
    /// refused before the loop reads its header and takes no room in the
    /// mirror's queue; one at the limit is queued, and one cut short too
    /// is refused.
    #[test]
    fn frames_past_the_frame_bound_are_refused_before_the_mirror_queue() {
        use quil_engine::frame_bound::MAX_APP_FRAME_ITEMS;
        use quil_types::proto::global::{MessageBundle, MessageRequest};
        let shard = Shard::new();
        let topic = shard.topic();
        let carrying = |items: usize| {
            let mut frame = shard.frame(7);
            frame.requests = vec![
                MessageBundle {
                    requests: vec![MessageRequest::default(); items - 2],
                    timestamp: 5,
                },
                MessageBundle::default(),
            ];
            prost::Message::encode_to_vec(&frame)
        };
        let peer = MirrorSender {
            signer: b"peer",
            via: b"peer",
        };
        let feed = MirrorFeed::new();
        assert!(
            !unrouted_shard_message(&topic, peer, carrying(MAX_APP_FRAME_ITEMS + 1), &feed)
                && feed.take().is_none(),
            "FRAME-BOUND: a frame past the bound was queued for the mirror"
        );
        let over = carrying(MAX_APP_FRAME_ITEMS + 1);
        assert!(!unrouted_shard_message(
            &topic,
            peer,
            over[..over.len() - 1].to_vec(),
            &feed
        ));
        let at = carrying(MAX_APP_FRAME_ITEMS);
        assert!(unrouted_shard_message(&topic, peer, at.clone(), &feed));
        assert_eq!(feed.take(), Some(at), "a frame at the bound is queued");
    }

    /// The worker reads and keeps committee members only for shards the
    /// prover registry names, and the loop refuses an address longer than
    /// any shard's: frames naming made-up shards, or an address of any
    /// length ground onto a subscribed topic, cost no read and no key. A
    /// member read that panics is counted with the checks that panic.
    #[test]
    fn members_are_read_and_kept_only_for_registered_shards() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let shard = Shard::new();
        let topic = shard.topic();
        let frame_at = |address: Vec<u8>| {
            let mut frame = shard.frame(7);
            frame.header.as_mut().unwrap().address = address;
            prost::Message::encode_to_vec(&frame)
        };
        let peer = MirrorSender {
            signer: b"peer",
            via: b"peer",
        };

        let feed = MirrorFeed::new();
        // The whole address picks the topic: the long address is offered on
        // its own topic, as one ground onto a subscribed topic would be.
        let long = [shard.filter.as_slice(), &[7; 64]].concat();
        let long_topic = quil_engine::bitmasks::shard_frame_bitmask(&long);
        assert!(
            !unrouted_shard_message(&long_topic, peer, frame_at(long), &feed)
                && feed.take().is_none(),
            "LONG-ADDRESS: an address longer than any shard filter was queued"
        );

        let reads = Arc::new(AtomicUsize::new(0));
        let checked = Arc::new(AtomicUsize::new(0));
        let feed = {
            let (reads, checked) = (reads.clone(), checked.clone());
            let tracked = shard.mirror.tracked.clone();
            MirrorFeed::spawn(
                move |_| {
                    checked.fetch_add(1, SeqCst);
                },
                move |filter| {
                    registered_shard_members(&tracked, filter, || {
                        reads.fetch_add(1, SeqCst);
                        Some(vec![b"member".to_vec()])
                    })
                },
            )
        };
        feed.offer(&topic, b"peer", frame_at(shard.filter.clone()), 0);
        for suffix in 0..8u8 {
            let made_up = [shard.filter.as_slice(), &[suffix; 32]].concat();
            feed.offer(&topic, b"peer", frame_at(made_up), 0);
        }
        wait_for("the worker did not check the queued frames", || {
            checked.load(SeqCst) == 9
        });
        let kept: Vec<Vec<u8>> = feed.shared.lock().members.keys().cloned().collect();
        assert_eq!(
            (kept, reads.load(SeqCst)),
            (vec![shard.filter.clone()], 1),
            "MEMBERS-ANY-SHARD: members were read or kept for a shard the registry does not name"
        );

        let capture = Capture::default();
        let _logs = capture.install();
        let checked = Arc::new(AtomicUsize::new(0));
        let feed = {
            let checked = checked.clone();
            MirrorFeed::spawn(
                move |_| {
                    checked.fetch_add(1, SeqCst);
                },
                |_| panic!("a planted members panic"),
            )
        };
        feed.offer(&topic, b"peer", frame_at(shard.filter.clone()), 0);
        wait_for("a members read that panics stopped the worker", || {
            checked.load(SeqCst) == 1
        });
        assert_eq!(
            capture
                .lines_with("reading a shard's committee members: a planted members panic")
                .len(),
            1,
            "MEMBERS-PANIC: a members read that panicked was not counted"
        );
    }

    /// Past its bounds the queue drops a sender's costliest frame (past the
    /// topic's bound) or the largest frame of the sender queuing the most
    /// bytes (past the byte bound), not a genuine frame that came last, and
    /// its byte count returns to zero.
    #[test]
    fn the_mirror_queue_drops_the_costliest_frame_past_its_bounds() {
        let topic = [1u8; 32];
        let mut queue = MirrorQueue::new(1 << 20);
        for _ in 0..3 {
            queue.push(&topic, b"flood", vec![0xee; 300 << 10], MIRROR_MAX_REQUESTS);
        }
        queue.push(&[2; 32], b"genuine", vec![2; 1000], 1);
        queue.push(&topic, b"genuine", vec![1; 200 << 10], 1);
        assert!(queue.bytes <= 1 << 20);
        assert_eq!(
            queue.dropped,
            QueueDrops {
                frames: 1,
                bytes: 300 << 10
            },
            "QUEUE-EVICTION: past the byte bound a genuine frame was dropped before a flood's"
        );
        let left: Vec<Vec<u8>> = std::iter::from_fn(|| queue.pop()).collect();
        assert_eq!(left.len(), 4);
        assert!(left.contains(&vec![1; 200 << 10]) && left.contains(&vec![2; 1000]));
        assert_eq!(queue.bytes, 0);

        let mut queue = MirrorQueue::new(MIRROR_QUEUED_BYTES);
        queue.push(&topic, b"peer", vec![0xee; 4000], MIRROR_MAX_REQUESTS);
        for frame in 0..MIRROR_QUEUED_PER_TOPIC {
            queue.push(&topic, b"peer", vec![frame as u8; 1000], 1);
        }
        assert_eq!(queue.dropped.frames, 1);
        assert!(
            std::iter::from_fn(|| queue.pop()).all(|data| data.len() == 1000),
            "QUEUE-EVICTION: past the topic's bound a genuine frame was dropped before a flood's"
        );
    }

    /// Dropped frames are logged at once, then at most once per interval
    /// with the counts since, and once more when an interval passed without.
    #[test]
    fn mirror_queue_drops_are_summarized_per_interval() {
        let mut queue = MirrorQueue::new(1000);
        let start = std::time::Instant::now();
        assert_eq!(queue.summarize(start), None, "nothing dropped");
        queue.push(&[1; 32], b"peer", vec![0; 2000], 0);
        let first = queue
            .summarize(start)
            .expect("QUEUE-DROPS: a dropped frame logged no line");
        assert_eq!(
            first.dropped,
            QueueDrops {
                frames: 1,
                bytes: 2000
            }
        );
        first.log(Some(1), true);
        queue.push(&[1; 32], b"peer", vec![0; 2000], 0);
        queue.push(&[2; 32], b"peer", vec![0; 3000], 0);
        assert_eq!(queue.summarize(start + MIRROR_QUEUE_SUMMARY / 2), None);
        let next = queue.summarize(start + MIRROR_QUEUE_SUMMARY).unwrap();
        assert_eq!(
            (next.dropped, next.interval_s),
            (
                QueueDrops {
                    frames: 2,
                    bytes: 5000
                },
                Some(MIRROR_QUEUE_SUMMARY.as_secs())
            )
        );
        let ended = queue
            .summarize(start + 2 * MIRROR_QUEUE_SUMMARY)
            .expect("a line says the drops ended");
        assert_eq!(ended.dropped, QueueDrops::default());
        ended.log(None, true);
        assert_eq!(queue.summarize(start + 3 * MIRROR_QUEUE_SUMMARY), None);
    }

    /// A check that panics is caught: the worker goes on with the next
    /// frame, and one line, with the first panic's text, covers the panics
    /// of an interval. A worker that ends anyway is marked so: the frames
    /// still queued and those offered later are dropped and counted, and
    /// the loop logs that the worker is not running.
    #[test]
    fn a_panicking_or_stopped_mirror_worker_is_detected_and_logged() {
        let capture = Capture::default();
        let _logs = capture.install();
        let checked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let feed = {
            let checked = checked.clone();
            MirrorFeed::spawn(
                move |data| {
                    if data == b"panic" {
                        panic!("a planted panic");
                    }
                    checked.lock().unwrap().push(data.to_vec());
                },
                |_| None,
            )
        };
        for data in [&b"panic"[..], b"panic", b"panic", b"after"] {
            feed.offer(&[1; 32], b"peer", data.to_vec(), 0);
        }
        wait_for("WORKER-PANIC: a panicking check stopped the worker", || {
            checked.lock().unwrap().as_slice() == [b"after".to_vec()]
        });
        let lines = capture.lines_with("the shard mirror's check of gossiped frames panicked");
        assert_eq!(lines.len(), 1, "PANIC-LINES: {lines:?}");
        assert!(
            lines[0].contains("a planted panic") && lines[0].contains("panics=1"),
            "{lines:?}"
        );
        let mut panics = std::mem::take(&mut feed.shared.lock().panics);
        assert_eq!(
            panics.panics, 2,
            "the panics after the line were not counted"
        );
        let later = std::time::Instant::now() + MIRROR_QUEUE_SUMMARY;
        assert_eq!(
            panics.due(std::time::Instant::now()),
            None,
            "PANIC-LINES: a second line within the interval"
        );
        assert_eq!(panics.due(later).map(|line| line.panics), Some(2));
        assert_eq!(panics.due(later + MIRROR_QUEUE_SUMMARY), None);

        let stopped = MirrorFeed::new();
        stopped.offer(&[1; 32], b"peer", b"queued".to_vec(), 0);
        let shared = stopped.shared.clone();
        let dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
        let ended = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                let _running = MirrorRunning(shared);
                panic!("a planted stop");
            })
        })
        .join();
        assert!(ended.is_err());
        assert_eq!(capture.lines_with("shard mirror worker stopped").len(), 1);
        stopped.offer(&[1; 32], b"peer", b"late".to_vec(), 0);
        let state = stopped.shared.lock();
        assert!(
            !state.running && state.queue.len() == 0,
            "WORKER-DEAD: a worker that ended was taken for running"
        );
        drop(state);
        assert_eq!(
            capture
                .lines_with("the shard mirror worker is not running")
                .len(),
            1,
            "WORKER-DEAD: no line said the worker is not running"
        );
    }

    /// At shutdown the worker checks no queued frame after the one in check,
    /// drops its check with the store handles that holds, and is joined;
    /// the wait for it is bounded while a check runs. The node's stop
    /// ([`stop_shard_mirrors`]) lists it.
    #[test]
    fn the_mirror_worker_stops_without_checking_queued_frames() {
        let gate = Arc::new(std::sync::Mutex::new(()));
        let checked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stores = Arc::new(());
        let held = gate.lock().unwrap();
        let feed = {
            let (gate, checked, stores) = (gate.clone(), checked.clone(), stores.clone());
            MirrorFeed::spawn(
                move |data| {
                    let _stores = &stores;
                    let _gate = gate
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    checked.lock().unwrap().push(data.to_vec());
                },
                |_| None,
            )
        };
        let shared = feed.shared.clone();
        assert!(
            live_mirror_workers()
                .iter()
                .any(|worker| Arc::ptr_eq(worker, &shared)),
            "the worker is not listed for the node's stop"
        );
        for frame in 0..3u8 {
            feed.offer(&[1; 32], b"peer", vec![frame; 10], 0);
        }
        wait_for("the worker took no frame into its check", || {
            shared.lock().checking.is_some()
        });
        drop(feed);
        assert!(
            !shared.wait_ended(std::time::Duration::from_millis(100)),
            "the worker ended while its check waited"
        );
        drop(held);
        assert!(
            shared.wait_ended(std::time::Duration::from_secs(30)),
            "the worker did not end"
        );
        assert_eq!(
            checked.lock().unwrap().len(),
            1,
            "CLOSE-DRAINS: the worker checked queued frames after it was stopped"
        );
        assert_eq!(
            Arc::strong_count(&stores),
            1,
            "the check outlived the worker"
        );
        assert!(
            shared.thread.lock().unwrap().is_none(),
            "the worker was not joined"
        );
        assert_eq!(shared.lock().queue.len(), 0);
    }

    /// A copy of a mirrored frame is not checked again: the stored copy's
    /// requests matched the header, so a copy carrying others is no frame to
    /// mirror, and a peer cannot make the mirror check a stored frame's
    /// header against costly requests of its own. A copy whose header
    /// differs anywhere but its storage attestation is checked.
    #[test]
    fn a_copy_of_a_mirrored_frame_is_not_checked_again() {
        use quil_types::store::ClockStore as _;
        let shard = Shard::new();
        let offer = |frame: &quil_types::proto::global::AppShardFrame| {
            shard.mirror.offer(
                shard.clock.as_ref(),
                frame,
                &prost::Message::encode_to_vec(frame),
            )
        };
        let genuine = shard.certified(7);
        shard.hear(&shard.topic(), &genuine);
        let mut copy = genuine.clone();
        copy.requests = vec![Default::default(); 3];
        copy.header.as_mut().unwrap().storage_attestation = vec![1; 8];
        assert_eq!(
            offer(&copy),
            Ok(Mirrored::Known),
            "STORED-RECHECKED: a copy of a stored frame was checked again"
        );
        assert_eq!(
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, 7, false)
                .unwrap(),
            genuine
        );
        let altered: [fn(&mut quil_types::proto::global::FrameHeader); 2] = [
            |header| header.timestamp += 1,
            |header| header.parent_selector = vec![1; 32],
        ];
        for alter in altered {
            let mut other = genuine.clone();
            alter(other.header.as_mut().unwrap());
            assert_ne!(
                offer(&other),
                Ok(Mirrored::Known),
                "KNOWN-LOOSE: a copy whose header differs from the stored frame's was taken \
                 as known"
            );
        }
        let mut next = shard.certified(8);
        next.requests = vec![Default::default()];
        assert!(offer(&next).is_err(), "a frame not stored is checked");
    }

    /// A copy of a frame another writer stored (the worker drain, for a
    /// shard a local engine ran) releases the parent the mirror holds for
    /// it, as mirroring that frame itself would have.
    #[test]
    fn a_copy_of_a_frame_stored_elsewhere_releases_its_held_parent() {
        use quil_types::store::ClockStore as _;
        let shard = Shard::new();
        let topic = shard.topic();
        let stored = |number| {
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, number, false)
                .ok()
        };
        shard.hear(&topic, &shard.certified(6));
        let parent = shard.notarized(7, selector(&shard.certified(6)));
        shard.hear(&topic, &parent);
        let child = shard.certified_child(&parent);
        super::super::worker_manager::mirror_shard_frame_to_clock_store(
            shard.clock.as_ref(),
            &shard.filter,
            &prost::Message::encode_to_vec(&child),
        );
        assert_eq!((stored(7), shard.latest()), (None, Some(8)));
        shard.hear(&topic, &child);
        assert_eq!(
            stored(7),
            Some(parent),
            "KNOWN-KEEPS-HELD: a copy of a frame stored elsewhere left its held parent \
             unmirrored"
        );
    }

    /// A held parent does not replace the frame another writer (the worker
    /// drain) stored at its number when its child releases it.
    #[test]
    fn a_held_parent_does_not_replace_a_frame_stored_at_its_number() {
        use quil_types::store::ClockStore as _;
        let shard = Shard::new();
        let topic = shard.topic();
        let stored = |number| {
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, number, false)
                .ok()
        };
        shard.hear(&topic, &shard.certified(6));
        let parent = shard.notarized(7, selector(&shard.certified(6)));
        shard.hear(&topic, &parent);
        let mut drained = parent.clone();
        drained.header.as_mut().unwrap().storage_attestation = vec![5; 8];
        let child = shard.certified_child(&parent);
        for frame in [&drained, &child] {
            super::super::worker_manager::mirror_shard_frame_to_clock_store(
                shard.clock.as_ref(),
                &shard.filter,
                &prost::Message::encode_to_vec(frame),
            );
        }
        assert_eq!(
            (stored(7), shard.latest()),
            (Some(drained.clone()), Some(8))
        );
        shard.hear(&topic, &child);
        assert_eq!(
            stored(7),
            Some(drained),
            "RELEASE-OVERWRITES: a held parent replaced the frame stored at its number"
        );
    }

    /// When a frame another writer stored stays in place of a held one, the
    /// walk down the held frames goes on from the stored frame: a held frame
    /// that links only to the held copy stays held.
    #[test]
    fn the_held_walk_goes_on_from_a_frame_stored_in_place_of_a_held_one() {
        use quil_types::store::ClockStore as _;
        let shard = Shard::new();
        let topic = shard.topic();
        let stored = |number| {
            shard
                .clock
                .get_shard_clock_frame(&shard.filter, number, false)
                .ok()
        };
        shard.hear(&topic, &shard.certified(5));
        let grandparent = shard.notarized(6, selector(&shard.certified(5)));
        shard.hear(&topic, &grandparent);
        let parent = shard.notarized(7, selector(&grandparent));
        shard.hear(&topic, &parent);
        // Stored by the worker drain: the parent's output, another parent.
        let mut drained = parent.clone();
        drained.header.as_mut().unwrap().parent_selector = vec![9; 32];
        let child = shard.certified_child(&parent);
        for frame in [&drained, &child] {
            super::super::worker_manager::mirror_shard_frame_to_clock_store(
                shard.clock.as_ref(),
                &shard.filter,
                &prost::Message::encode_to_vec(frame),
            );
        }
        assert_eq!(
            (stored(6), stored(7), shard.latest()),
            (None, Some(drained.clone()), Some(8))
        );
        shard.hear(&topic, &child);
        assert_eq!(stored(7), Some(drained));
        assert_eq!(
            stored(6),
            None,
            "WALK-FROM-HELD: a held frame was mirrored below a stored frame it does not link to"
        );
    }

    /// The output identity a child names its parent by.
    fn selector(frame: &quil_types::proto::global::AppShardFrame) -> Vec<u8> {
        quil_crypto::poseidon::hash_bytes_to_32(&frame.header.as_ref().unwrap().output)
            .unwrap()
            .to_vec()
    }

    /// Refusals log one line at once, then at most one per interval with the
    /// counts since the last; frames over the bundle bound are counted
    /// apart.
    #[test]
    fn mirror_refusals_are_summarized_per_interval() {
        let refusals = MirrorRefusals::new();
        let frame = quil_types::proto::global::AppShardFrame::default();
        let over = quil_types::proto::global::AppShardFrame {
            requests: vec![Default::default(); MIRROR_MAX_REQUESTS + 1],
            ..Default::default()
        };
        let start = std::time::Instant::now();
        assert_eq!(refusals.note(&frame, "first".into(), start), Some((1, 0)));
        for _ in 0..2 {
            assert_eq!(refusals.note(&frame, "again".into(), start), None);
        }
        assert_eq!(refusals.note(&over, "bound".into(), start), None);
        assert_eq!(
            refusals.note(&frame, "later".into(), start + MIRROR_REFUSAL_SUMMARY),
            Some((4, 1)),
            "OVER-BOUND: refusals over the bundle bound were not counted apart"
        );
    }
}
