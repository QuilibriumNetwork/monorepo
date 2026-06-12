//! App shard consensus engine: runs HotStuff/BFT consensus for a single
//! application shard, producing and validating AppShardFrames.
//!
//! Each worker thread creates one of these when assigned a filter via
//! the `Respawn` command. The engine:
//! 1. Spawns a HotStuff event loop with per-shard committee/voting/leader
//! 2. Processes inbound messages through validation → routing → handlers
//! 3. Collects messages for frame production via the leader provider
//! 4. Handles consensus events (finalization, equivocation, rank changes)

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use quil_consensus::committee::DynamicCommittee;
use quil_consensus::event_handler::HotStuffEventHandler;
use quil_consensus::event_loop::EventLoop;
use quil_consensus::forest::Forks;
use quil_consensus::models::{
    AggregatedSignature, Identity, Proposal, QuorumCertificate, SignedProposal,
    State, TimeoutCertificate, Unique,
};
use quil_consensus::pacemaker::{
    HotStuffPacemaker, StaticProposalDurationProvider, TimeoutConfig, TimeoutController,
};
use quil_consensus::safety_rules::SafetyRules;
use quil_consensus::signer::VotingProviderSigner;
use quil_consensus::state_producer::StateProducer;

use quil_types::consensus::ProverRegistry;
use quil_types::crypto::FrameProver;
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;

use crate::app_glue::{
    AppConsensusEvent, AppConsumer, AppFinalizer, AppFollower,
    AppParticipantConsumer,
};
use crate::app_types::{
    AppEventLoopHandle, AppGenesisQC, AppShardState, AppShardVote, AppShardVoteFactory,
    build_app_genesis_certified_state,
};
use crate::committee::ProverRegistryCommittee;
use crate::consensus_wire;
use crate::message_collector::MessageCollector;
use crate::message_router::{classify_consensus_message, ConsensusMessageKind};
use crate::provers::proposer;
use crate::voting_provider::{AddressDerivation, BlsVotingProvider};

const CONSENSUS_QUEUE_SIZE: usize = 1000;
const MAX_APP_MESSAGES_PER_RANK: usize = 100;

// =====================================================================
// Inbound messages to the app engine
// =====================================================================

/// Inbound messages from the master/network to the app engine.
#[derive(Debug)]
pub enum AppEngineMessage {
    /// A consensus message (proposal/vote/timeout) for this shard.
    Consensus(Vec<u8>),
    /// A prover message (join/leave/confirm) for this shard.
    Prover(Vec<u8>),
    /// An app shard frame from another prover.
    Frame(Vec<u8>),
    /// A dispatch message (token/compute/hypergraph op) for this shard.
    Dispatch(Vec<u8>),
    /// A global frame for time synchronization.
    GlobalFrame(Vec<u8>),
    /// A peer info message.
    PeerInfo(Vec<u8>),
    /// Update the engine's halted flag. Set to `true` when the network
    /// (or this filter specifically) is in a coverage halt — the
    /// leader's pre-propose gate observes this and skips producing
    /// frames so the halt window doesn't keep producing rewardable
    /// shard work. Mirrors Go's behavior where the app workers stop
    /// frame production while any shard is halted.
    SetHalted(bool),
}

// =====================================================================
// Outbound events from the app engine
// =====================================================================

/// Outbound events from the app engine to the master.
#[derive(Debug)]
pub enum AppEngineEvent {
    /// Engine produced a new shard frame.
    FrameProduced {
        filter: Vec<u8>,
        frame_number: u64,
        frame_data: Vec<u8>,
    },
    /// Shard frame finalized — emit the canonical FrameHeader bytes so
    /// the master can publish them on `GLOBAL_PROVER` (mirroring Go's
    /// `submitShardFrameToMaster` → `publishProverMessage` path so app
    /// shard work is credited toward rewards by global archives).
    ShardFrameFinalized {
        filter: Vec<u8>,
        header_canonical_bytes: Vec<u8>,
    },
    /// Engine produced a vote for a proposal.
    VoteProduced {
        filter: Vec<u8>,
        vote_data: Vec<u8>,
    },
    /// Engine produced a timeout state.
    TimeoutProduced {
        filter: Vec<u8>,
        timeout_data: Vec<u8>,
    },
    /// Engine detected equivocation (double propose).
    EquivocationDetected {
        filter: Vec<u8>,
        first_frame: u64,
        second_frame: u64,
    },
    /// Shard consensus is halted (coverage or error).
    Halted {
        filter: Vec<u8>,
        reason: String,
    },
    /// Engine requests sync for missing ancestor frames.
    AncestorSyncRequested {
        filter: Vec<u8>,
        missing_frames: Vec<u64>,
    },
    /// A certified parent was sealed (state committed via materializer).
    ParentSealed {
        filter: Vec<u8>,
        parent_rank: u64,
    },
}

// =====================================================================
// Handle for sending messages to the engine
// =====================================================================

/// Snapshot of per-shard `AppConsensusEngine` internal sizes,
/// published atomically by the engine each loop iteration. Read
/// without acquiring any consensus-side locks; size deltas surface
/// in the `memory snapshot` log so a per-shard cache that's bleeding
/// memory shows up directly.
#[derive(Debug, Default, Clone, Copy)]
pub struct AppEngineSizes {
    pub frame_store: usize,
    pub message_spillover: usize,
    pub proposal_cache: usize,
    pub pending_certified_parents: usize,
    pub current_rank: u64,
}

/// Atomic publish slot for [`AppEngineSizes`]. Cheap to clone (one
/// `Arc`); the engine writes through a mutex on each iteration,
/// readers take a quick lock to copy out.
#[derive(Debug, Default, Clone)]
pub struct SharedAppEngineSizes(Arc<std::sync::Mutex<AppEngineSizes>>);

impl SharedAppEngineSizes {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn snapshot(&self) -> AppEngineSizes {
        *self.0.lock().unwrap()
    }
    pub fn store(&self, s: AppEngineSizes) {
        *self.0.lock().unwrap() = s;
    }
}

/// Handle for sending messages to an app engine. Cloneable — the
/// master holds one, and it can be shared across message routing tasks.
#[derive(Clone, Debug)]
pub struct AppEngineHandle {
    pub filter: Vec<u8>,
    msg_tx: mpsc::Sender<AppEngineMessage>,
    sizes: SharedAppEngineSizes,
}

impl AppEngineHandle {
    /// Send a message to the app engine (non-blocking, drops on full).
    pub fn send(&self, msg: AppEngineMessage) {
        let _ = self.msg_tx.try_send(msg);
    }

    /// Tell the engine whether the network is in a coverage halt. The
    /// engine forwards the value to its leader provider so propose
    /// attempts during the halt window are skipped.
    pub fn set_halted(&self, halted: bool) {
        let _ = self.msg_tx.try_send(AppEngineMessage::SetHalted(halted));
    }

    /// Read the engine's most-recently-published internal sizes.
    /// Returns the last value the engine wrote — may be a few
    /// hundred milliseconds stale, which is fine for the 30 s
    /// memory snapshot tick.
    pub fn sizes(&self) -> AppEngineSizes {
        self.sizes.snapshot()
    }
}

// =====================================================================
// AppLeaderProvider — produces shard frames via VDF
// =====================================================================

/// App shard leader provider. Collects messages and produces VDF-backed
/// shard frames when this node is the elected leader.
struct AppLeaderProvider {
    filter: Vec<u8>,
    clock_store: Arc<dyn ClockStore>,
    frame_prover: Arc<dyn FrameProver>,
    prover_registry: Arc<dyn ProverRegistry>,
    message_collector: Arc<MessageCollector>,
    fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager>,
    local_prover_address: Vec<u8>,
    #[allow(dead_code)]
    local_public_key: Vec<u8>,
    current_difficulty: Arc<std::sync::atomic::AtomicU32>,
    reward_greedy: bool,
    /// Per-shard hypergraph CRDT used to compute `state_roots` per
    /// frame. Optional: when missing the leader emits the
    /// 4 × 64-byte zero placeholder.
    hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// Execution engine used to derive per-message locked-address sets
    /// for `requests_root`. Required for Go interop on non-empty frames.
    execution_engine: Option<Arc<quil_execution::ExecutionEngineManager>>,
    /// Inclusion prover for `requests_root` tree commit.
    inclusion_prover: Option<Arc<dyn quil_types::crypto::InclusionProver>>,
    app_address: Vec<u8>,
    /// Shared halt flag (set by the engine's `SetHalted` handler).
    /// `prove_next_state` short-circuits when set so the leader stops
    /// producing frames during coverage halts.
    halted: Arc<std::sync::atomic::AtomicBool>,
    /// Minimum number of Active provers on this shard before the
    /// leader will produce frames. Network-dependent: mainnet uses
    /// `HALT_RISK_PROVER_COUNT` (3) so single-prover shards can't
    /// drive consensus alone; testnet uses 1 so a single-prover
    /// test cluster still progresses. Plumbed from
    /// `config.p2p.network` in `worker_manager::init`.
    min_active_provers_for_propose: u64,
}

impl quil_consensus::leader_provider::LeaderProvider<AppShardState> for AppLeaderProvider {
    fn get_next_leaders(&self, _prior: Option<&State<AppShardState>>) -> Result<Vec<Identity>> {
        let provers = self.prover_registry.get_active_provers(&self.filter)?;
        if provers.is_empty() {
            return Err(QuilError::Consensus("no active provers for shard".into()));
        }
        let mut leaders: Vec<Identity> = provers
            .iter()
            .map(|p| crate::committee::address_to_identity(&p.address))
            .collect();
        leaders.sort();
        Ok(leaders)
    }

    fn prove_next_state(
        &self,
        rank: u64,
        _filter: &[u8],
        prior_state_id: &Identity,
    ) -> Result<State<AppShardState>> {
        // Coverage halt gate. Mirrors Go's `app_consensus_engine.go`
        // which stops producing frames while the network is in a
        // halt window — without this the workers keep accruing
        // rewardable shard work during a halt and the network can't
        // recover cleanly. The engine flips this flag from
        // `AppEngineMessage::SetHalted` driven by the master's
        // halt-state watcher.
        //
        // `NoVote` (not `Consensus`) — `propose_for_new_rank_if_primary`
        // catches `is_no_vote` errors and logs+returns Ok, letting the
        // consensus event loop keep running. A `Consensus` error here
        // bubbles up through `state_producer.make_state_proposal` →
        // `on_receive_quorum_certificate` → `event_loop.run()`'s
        // `return Err(...)`, which permanently kills the shard's
        // event loop. Because `runtime_state.rs`'s halt broadcaster
        // fans `set_halted(true)` to EVERY engine on the first
        // network-wide halt (not just halted-shard engines), any
        // healthy shard mid-QC at that moment loses its consensus
        // loop and can't recover even after halts clear. Treating
        // halt as a per-round skip mirrors the NoVote shape used for
        // safety-rules declines.
        if self.halted.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(QuilError::NoVote(
                "coverage halt active — skipping shard frame production".into(),
            ));
        }
        // Minimum-active-provers gate. A shard needs at least
        // `min_active_provers_for_propose` Active provers before any
        // of them start producing frames — proposing as a sole
        // prover (or two-prover pair) on mainnet is wasted work
        // that the network rejects (sub-quorum) and produces no
        // rewardable output. Mainnet uses `HALT_RISK_PROVER_COUNT`
        // (3) so the threshold lines up with the protocol's
        // coverage-halt classification; testnet uses 1 so a single-
        // prover test cluster still progresses. Below the
        // threshold the expected behavior is "wait for more provers
        // to join," never "drive consensus alone." Without this
        // gate, a node that lands as the first Active on a fresh
        // mainnet shard burns CPU on VDF compute every round forever
        // — exactly the wedge seen on workers 19/20 (sole proposer,
        // frame 5 staged at ranks 12 → 600+ without ever committing).
        //
        // `NoVote` (not `Consensus`) for the same reason as the
        // halt gate above — bubbling a `Consensus` error here
        // kills the event loop. Caught by
        // `propose_for_new_rank_if_primary`'s `is_no_vote` arm.
        let active_count = self
            .prover_registry
            .get_active_provers(&self.filter)
            .map(|p| p.len())
            .unwrap_or(0);
        if (active_count as u64) < self.min_active_provers_for_propose {
            return Err(QuilError::NoVote(format!(
                "shard has {} active prover(s); minimum {} required to propose",
                active_count,
                self.min_active_provers_for_propose,
            )));
        }
        // Get latest shard frame number
        let prior_frame_number = self.clock_store
            .get_latest_shard_clock_frame(&self.filter)
            .ok()
            .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
            .unwrap_or(0);
        let frame_number = prior_frame_number + 1;

        // Collect pending messages
        let messages = self.message_collector.collect_for_rank(rank);
        debug!(
            filter = hex::encode(&self.filter),
            frame = frame_number,
            rank,
            messages = messages.len(),
            "producing shard frame"
        );

        // Pull previous frame's full output for `parent` derivation.
        // Empty for the first frame (genesis); the prover handles that
        // by emitting a 32-byte zero parent.
        let previous_frame_output = self.clock_store
            .get_latest_shard_clock_frame(&self.filter)
            .ok()
            .and_then(|f| f.header.as_ref().map(|h| h.output.clone()))
            .unwrap_or_default();

        let difficulty = self.current_difficulty
            .load(std::sync::atomic::Ordering::Relaxed);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Compute fee multiplier vote: base from sliding window +
        // traffic adjustment.
        let previous_timestamp_ms = self.clock_store
            .get_latest_shard_clock_frame(&self.filter)
            .ok()
            .and_then(|f| f.header.as_ref().map(|h| h.timestamp))
            .unwrap_or(now_ms - 10_000); // assume 10s if no prior frame
        let fee_multiplier_vote = crate::fees::compute_fee_multiplier_vote(
            self.fee_manager.as_ref(),
            &self.filter,
            now_ms,
            previous_timestamp_ms,
            self.reward_greedy,
        );

        // Per-frame shard state roots: 4 × 64-byte phase commitments
        // (vertex_adds / vertex_removes / hyperedge_adds /
        // hyperedge_removes) from the hypergraph CRDT for this shard.
        // Mirrors Go's `hypergraph.CommitShard(frame_number, app_address)`
        // path: a real (non-empty) commit returns the four roots; an
        // empty/missing shard returns four 64-byte zero placeholders.
        // After commit, the live add-tree root is published as a
        // snapshot generation so sync clients can pin against the same
        // state our header advertises (`hypergraph/snapshot_manager.go`).
        let zero_roots = || vec![vec![0u8; 64]; 4];
        let state_roots: Vec<Vec<u8>> = match self.hypergraph.as_ref() {
            Some(hg) => {
                let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(
                    &self.filter[..self.filter.len().min(32)],
                    256,
                    3,
                );
                let mut l2 = [0u8; 32];
                let copy_len = self.filter.len().min(32);
                l2[..copy_len].copy_from_slice(&self.filter[..copy_len]);
                let shard_key = quil_types::store::ShardKey { l1, l2 };
                match hg.commit(frame_number) {
                    Ok(by_shard) => {
                        let four = by_shard.get(&shard_key).cloned().unwrap_or_else(zero_roots);
                        // Pad up to 4 in case CommitShard returned fewer.
                        let mut out = four;
                        while out.len() < 4 {
                            out.push(vec![0u8; 64]);
                        }
                        // Publish the shard's vertex-adds root as a
                        // snapshot generation so sync clients pinning
                        // this header can fetch matching CRDT data.
                        if !out[0].is_empty() && out[0].iter().any(|b| *b != 0) {
                            hg.publish_snapshot(out[0].clone(), frame_number);
                        }
                        out
                    }
                    Err(e) => {
                        warn!(
                            filter = hex::encode(&self.filter),
                            frame = frame_number,
                            error = %e,
                            "hypergraph commit failed — emitting zero state_roots"
                        );
                        zero_roots()
                    }
                }
            }
            None => zero_roots(),
        };

        // Per-frame requests root over the messages included in this
        // proposal. Mirrors Go's `calculateRequestsRoot` +
        // `executionManager.Lock` flow: for each message,
        //   hash    = sha3_256(payload)
        //   address = self.app_address[..32]   (per Go message_processors.go:1318-1322)
        //   payload = the raw MessageBundle bytes
        // Then call `execution_engine.lock(frame, address, payload)`
        // to get the locked-address vector and insert
        // `(hash, concat(locked_addresses))` into a
        // `VectorCommitmentTree`. The final root is
        // `sha3_256(tree.commit())[..32] || serialize_non_lazy(tree)`.
        // Empty messages → 64-byte zero buffer, matching Go.
        let requests_root: Vec<u8> = compute_requests_root(
            &messages,
            &self.app_address,
            frame_number,
            self.execution_engine.as_deref(),
            self.inclusion_prover.as_deref(),
        )?;

        // Compute VDF proof (blocking). Including timestamp + fee in
        // the challenge ensures consecutive ranks within the same frame
        // produce distinct outputs and therefore distinct identities.
        // Go passes `getProverAddress()` = `poseidon(pubkey)` (32 bytes)
        // as the `prover` field in the frame header, NOT the raw G2
        // public key (585 bytes). Using the raw pubkey would produce
        // headers that other nodes can't match to the prover registry
        // (which is keyed by poseidon address).
        let header = self.frame_prover.prove_frame_header(
            &previous_frame_output,
            &self.filter,
            &requests_root,
            &state_roots,
            &self.local_prover_address,
            now_ms,
            difficulty,
            fee_multiplier_vote,
            frame_number,
        )?;

        let state = AppShardState::new(
            self.filter.clone(),
            frame_number,
            rank,
            now_ms,
            difficulty,
            header.output.clone(),
            header.parent_selector.clone(),
            self.local_prover_address.clone(),
            requests_root,
            state_roots,
            Vec::new(),   // signature — filled during signing
            fee_multiplier_vote,
        );

        Ok(State {
            rank,
            identifier: state.identity().clone(),
            proposer_id: crate::committee::address_to_identity(&self.local_prover_address),
            parent_qc_identity: prior_state_id.clone(),
            parent_qc_rank: rank.saturating_sub(1),
            // Leader-side construction: the parent QC trait object
            // is attached to the wrapping `Proposal`, not threaded
            // through `LeaderProvider::prove_next_state`. Receivers
            // populate the field on the wire-decode side.
            parent_quorum_certificate: None,
            timestamp: now_ms as u64,
            state,
        })
    }
}

// =====================================================================
// AppConsensusEngine — the main per-shard engine
// =====================================================================

/// Dependencies required to construct an AppConsensusEngine.
pub struct AppEngineDeps {
    pub clock_store: Arc<dyn ClockStore>,
    pub prover_registry: Arc<dyn ProverRegistry>,
    pub frame_prover: Arc<dyn FrameProver>,
    pub message_collector: Arc<MessageCollector>,
    pub fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager>,
    pub local_prover_address: Vec<u8>,
    pub local_bls_pubkey: Vec<u8>,
    pub bls_signer: Box<dyn quil_types::crypto::Signer>,
    pub reward_greedy: bool,
    /// Minimum Active prover count required before this engine's
    /// `AppLeaderProvider` will produce frames. Mainnet=3, testnet=1.
    /// See `AppLeaderProvider::min_active_provers_for_propose`.
    pub min_active_provers_for_propose: u64,
    /// Callback for publishing finalized canonical FrameHeader bytes
    /// on `GLOBAL_PROVER` for reward attribution. See
    /// `WorkerConsensusDeps::coverage_publish`.
    pub coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    /// Hypergraph CRDT used to derive per-frame shard `state_roots`
    /// (4 phase commitments) for the FrameHeader VDF challenge. When
    /// absent the engine falls back to 4 × 64-byte zero placeholders —
    /// fine for tests but breaks Go peers' VDF verification on real
    /// shards with state.
    pub hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// Execution engine used to compute the per-message locked-address
    /// vectors (`tx_map`) that feed `requests_root`. Required for Go
    /// VDF interop on non-empty frames; without it `requests_root`
    /// reduces to a tree over `(msg.hash, "")` pairs which doesn't
    /// match Go's commitment.
    pub execution_engine: Option<Arc<quil_execution::ExecutionEngineManager>>,
    /// Inclusion prover used to commit the `requests_root` tree.
    pub inclusion_prover: Option<Arc<dyn quil_types::crypto::InclusionProver>>,
    /// Backing KV store for persistent consensus + liveness state. When
    /// `Some`, app shard `ConsensusState` (finalized_rank /
    /// latest_acknowledged_rank) and `LivenessState` (current_rank /
    /// latest_QC) survive restarts. `None` falls back to the in-memory
    /// stub — fine for tests, dangerous in production because a
    /// restart can re-vote for a conflicting QC after a crash.
    pub kv_db: Option<Arc<dyn quil_types::store::KvDb>>,
}

/// App shard consensus engine. Owns a HotStuff event loop and
/// processes messages for a single shard identified by `filter`.
pub struct AppConsensusEngine {
    /// CPU core this engine runs on.
    pub core_id: u32,
    /// Shard filter (bloom filter bytes).
    pub filter: Vec<u8>,
    /// App address (Poseidon hash of filter).
    pub app_address: Vec<u8>,

    // Dependencies
    clock_store: Arc<dyn ClockStore>,
    prover_registry: Arc<dyn ProverRegistry>,
    frame_prover: Arc<dyn FrameProver>,
    message_collector: Arc<MessageCollector>,
    fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager>,
    reward_greedy: bool,
    /// Per-network minimum Active prover count required before
    /// `prove_next_state` will produce a frame. Plumbed through
    /// `AppEngineDeps` from the master's network config.
    min_active_provers_for_propose: u64,
    hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    execution_engine: Option<Arc<quil_execution::ExecutionEngineManager>>,
    inclusion_prover: Option<Arc<dyn quil_types::crypto::InclusionProver>>,

    // Consensus state
    current_difficulty: Arc<std::sync::atomic::AtomicU32>,
    current_rank: u64,
    shard_frame_number: u64,

    // Message queues
    _pending_messages: VecDeque<Vec<u8>>,
    /// Spillover messages when current rank is full.
    message_spillover: HashMap<u64, Vec<Vec<u8>>>,

    // Proposal/frame caches
    proposal_cache: HashMap<u64, Vec<u8>>,
    frame_store: HashMap<String, Vec<u8>>,

    // Certified parent sealing: parent data waiting for child QC
    pending_certified_parents: HashMap<u64, Vec<u8>>,
    /// Ranks queued for parent sealing (set by sync handler, drained in loop).
    pending_seal_rank: Option<u64>,

    // Channels
    cancel: CancellationToken,
    msg_rx: Option<mpsc::Receiver<AppEngineMessage>>,
    event_tx: mpsc::UnboundedSender<AppEngineEvent>,
    consensus_event_rx: Option<mpsc::UnboundedReceiver<AppConsensusEvent>>,
    consensus_event_tx: mpsc::UnboundedSender<AppConsensusEvent>,

    // HotStuff event loop handle (set after consensus starts)
    consensus_handle: Option<AppEventLoopHandle>,

    // Per-shard vote aggregator — set after consensus starts so peer
    // votes received over the network can be tallied alongside the
    // local self-loopback path.
    vote_aggregator: Option<Arc<crate::app_vote_aggregation::AppVoteAggregation>>,

    // Per-shard timeout aggregator. Populated alongside `vote_aggregator`
    // in `start_consensus`; receives wire timeout states from
    // `handle_timeout_state` so peer timeouts can form a TC.
    timeout_aggregator:
        Option<Arc<crate::app_timeout_aggregation::AppTimeoutAggregation>>,

    // Identity
    local_prover_address: Vec<u8>,
    local_bls_pubkey: Vec<u8>,

    // Halt state — shared with the leader provider so it can short
    // circuit `prove_next_state` during a coverage halt. Atomic so
    // the read path (consensus event loop on a separate thread) and
    // the write path (engine's recv loop) don't need locks.
    halted: Arc<std::sync::atomic::AtomicBool>,

    /// Callback that publishes finalized FrameHeader canonical bytes
    /// on `GLOBAL_PROVER`. Optional so legacy/test paths still work.
    coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,

    /// Backing KV store for persistent consensus + liveness state.
    /// `None` falls back to the in-memory stub.
    kv_db: Option<Arc<dyn quil_types::store::KvDb>>,

    /// Atomic publish slot for engine sizes. Updated each event-loop
    /// iteration so external memory snapshots can read internal
    /// cache sizes without taking the engine's locks.
    sizes: SharedAppEngineSizes,
}

impl AppConsensusEngine {
    /// Returns the engine and a handle for sending messages to it.
    pub fn new(
        core_id: u32,
        filter: Vec<u8>,
        deps: AppEngineDeps,
        event_tx: mpsc::UnboundedSender<AppEngineEvent>,
    ) -> (Self, AppEngineHandle) {
        let (msg_tx, msg_rx) = mpsc::channel(CONSENSUS_QUEUE_SIZE);
        let (consensus_event_tx, consensus_event_rx) = mpsc::unbounded_channel();

        let app_address = quil_crypto::poseidon::hash_bytes_to_32(&filter)
            .map(|h| h.to_vec())
            .unwrap_or_else(|_| filter.clone());

        let sizes = SharedAppEngineSizes::new();
        let handle = AppEngineHandle {
            filter: filter.clone(),
            msg_tx,
            sizes: sizes.clone(),
        };

        let engine = Self {
            core_id,
            filter: filter.clone(),
            app_address,
            clock_store: deps.clock_store,
            prover_registry: deps.prover_registry,
            frame_prover: deps.frame_prover,
            message_collector: deps.message_collector,
            fee_manager: deps.fee_manager,
            reward_greedy: deps.reward_greedy,
            min_active_provers_for_propose: deps.min_active_provers_for_propose,
            hypergraph: deps.hypergraph,
            execution_engine: deps.execution_engine,
            inclusion_prover: deps.inclusion_prover,
            current_difficulty: Arc::new(std::sync::atomic::AtomicU32::new(50000)),
            current_rank: 0,
            shard_frame_number: 0,
            _pending_messages: VecDeque::with_capacity(MAX_APP_MESSAGES_PER_RANK),
            message_spillover: HashMap::new(),
            proposal_cache: HashMap::new(),
            frame_store: HashMap::new(),
            pending_certified_parents: HashMap::new(),
            pending_seal_rank: None,
            cancel: CancellationToken::new(),
            msg_rx: Some(msg_rx),
            event_tx,
            consensus_event_rx: Some(consensus_event_rx),
            consensus_event_tx,
            consensus_handle: None,
            vote_aggregator: None,
            timeout_aggregator: None,
            local_prover_address: deps.local_prover_address,
            local_bls_pubkey: deps.local_bls_pubkey,
            halted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            coverage_publish: deps.coverage_publish,
            kv_db: deps.kv_db,
            sizes,
        };
        (engine, handle)
    }

    /// Publish current internal sizes to the handle's atomic snapshot.
    /// Called from the event loop after any mutation that could change
    /// one of the tracked caches. Cheap — single small mutex lock.
    fn publish_sizes(&self) {
        self.sizes.store(AppEngineSizes {
            frame_store: self.frame_store.len(),
            message_spillover: self.message_spillover.values().map(|v| v.len()).sum(),
            proposal_cache: self.proposal_cache.len(),
            pending_certified_parents: self.pending_certified_parents.len(),
            current_rank: self.current_rank,
        });
    }

    /// Start the app shard consensus loop. Runs on the worker thread's
    /// tokio runtime and processes messages until cancelled.
    ///
    /// Lifecycle:
    /// 1. Initialize from latest shard frame in clock store
    /// 2. Start HotStuff event loop for this shard
    /// 3. Enter message processing loop
    /// 4. Process inbound messages (consensus/prover/frame/dispatch)
    /// 5. Process consensus events (finalization/equivocation/rank changes)
    pub async fn run(
        mut self,
        bls_signer: Box<dyn quil_types::crypto::Signer>,
    ) {
        let mut msg_rx = self.msg_rx.take().expect("msg_rx already taken");
        let mut consensus_event_rx = self.consensus_event_rx.take().expect("consensus_event_rx already taken");

        info!(
            core_id = self.core_id,
            filter = hex::encode(&self.filter),
            "app consensus engine starting"
        );

        // Initialize from stored state
        match self.clock_store.get_latest_shard_clock_frame(&self.filter) {
            Ok(frame) => {
                if let Some(h) = frame.header.as_ref() {
                    self.shard_frame_number = h.frame_number;
                    info!(
                        core_id = self.core_id,
                        shard_frame = self.shard_frame_number,
                        "resuming from stored shard frame"
                    );
                }
            }
            Err(_) => {
                info!(core_id = self.core_id, "no stored shard frames, starting fresh");
                // Clear stale persisted consensus state for this shard.
                // `KvConsensusStore` persists the pacemaker's
                // `LivenessState` (current_rank, latest QC) across
                // restart, but the forks tree is in-memory only. If the
                // previous session advanced the rank without ever
                // committing a shard frame (single-prover shards with no
                // wire-QC peer to drive the commit path), the new event
                // loop boots with the old `current_rank` while the
                // forks tree is empty → every proposal fails with
                // `leader skipping: parent state not in forks tree`.
                // Deleting both keys here forces the bootstrap closure
                // (rank=1, genesis QC) to fire on first read.
                if let Some(kv) = self.kv_db.as_ref() {
                    let _ = kv.delete(&quil_store::encoding::consensus_liveness_key(&self.filter));
                    let _ = kv.delete(&quil_store::encoding::consensus_state_key(&self.filter));
                }
            }
        }

        // Start the HotStuff event loop for this shard
        match self.start_consensus(bls_signer) {
            Ok((handle, vote_agg, timeout_agg)) => {
                self.consensus_handle = Some(handle);
                self.vote_aggregator = Some(vote_agg);
                self.timeout_aggregator = Some(timeout_agg);
                info!(
                    core_id = self.core_id,
                    filter = hex::encode(&self.filter),
                    "shard HotStuff event loop running"
                );
            }
            Err(e) => {
                warn!(
                    core_id = self.core_id,
                    error = %e,
                    "failed to start shard consensus — running in passive mode"
                );
            }
        }

        // Frame cleanup timer — remove stale cached frames every 60s
        let mut cleanup_timer = tokio::time::interval(Duration::from_secs(60));
        cleanup_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                // Consensus events (highest priority)
                event = consensus_event_rx.recv() => {
                    match event {
                        Some(ce) => self.handle_consensus_event(ce).await,
                        None => {
                            info!(core_id = self.core_id, "consensus event channel closed");
                            break;
                        }
                    }
                }

                // Inbound network messages
                msg = msg_rx.recv() => {
                    match msg {
                        Some(AppEngineMessage::Consensus(data)) => {
                            self.handle_consensus_message(&data);
                        }
                        Some(AppEngineMessage::Prover(data)) => {
                            self.handle_prover_message(&data);
                        }
                        Some(AppEngineMessage::Frame(data)) => {
                            self.handle_frame_message(&data);
                        }
                        Some(AppEngineMessage::Dispatch(data)) => {
                            self.handle_dispatch_message(&data);
                        }
                        Some(AppEngineMessage::GlobalFrame(data)) => {
                            self.handle_global_frame_message(&data);
                        }
                        Some(AppEngineMessage::PeerInfo(data)) => {
                            self.handle_peer_info_message(&data);
                        }
                        Some(AppEngineMessage::SetHalted(halted)) => {
                            let prev = self.halted.swap(
                                halted,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            if prev != halted {
                                info!(
                                    core_id = self.core_id,
                                    filter = hex::encode(&self.filter),
                                    halted,
                                    "shard halt state changed"
                                );
                            }
                        }
                        None => {
                            info!(core_id = self.core_id, "message channel closed");
                            break;
                        }
                    }
                }

                // Periodic cleanup
                _ = cleanup_timer.tick() => {
                    self.cleanup_frame_store();
                }

                // Shutdown
                _ = self.cancel.cancelled() => {
                    info!(
                        core_id = self.core_id,
                        filter = hex::encode(&self.filter),
                        "app consensus engine stopping"
                    );
                    break;
                }
            }

            // Process any pending parent seal (queued by QC handler)
            if let Some(child_rank) = self.pending_seal_rank.take() {
                self.try_seal_parent_with_child(child_rank).await;
            }

            // Publish cache sizes so external memory snapshots can
            // see per-shard internal growth. Cheap mutex lock, runs
            // at message cadence (not per-tick), which is fine for
            // a 30 s diagnostic log.
            self.publish_sizes();
        }

        // Shutdown consensus event loop
        if let Some(handle) = self.consensus_handle.take() {
            handle.shutdown();
        }
    }

    /// Stop the engine.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    // ---------------------------------------------------------------
    // Consensus event loop startup
    // ---------------------------------------------------------------

    fn start_consensus(
        &self,
        bls_signer: Box<dyn quil_types::crypto::Signer>,
    ) -> Result<(
        AppEventLoopHandle,
        Arc<crate::app_vote_aggregation::AppVoteAggregation>,
        Arc<crate::app_timeout_aggregation::AppTimeoutAggregation>,
    )> {
        let filter = self.filter.clone();

        // Identify the rank + output of the latest finalized shard
        // frame. These pin the trusted root of the forks tree AND
        // seed the bootstrap `LivenessState` so the leader's first
        // proposal at `current_rank = genesis_rank + 1` can find its
        // parent state in the tree. On a brand-new shard with no
        // stored frames this is (0, zero-bytes), matching the legacy
        // genesis bootstrap. On a resumed shard it's the actual
        // rank/output of the most recent finalized frame.
        let (genesis_output, genesis_rank) = self.clock_store
            .get_latest_shard_clock_frame(&filter)
            .ok()
            .and_then(|f| f.header.as_ref().map(|h| (h.output.clone(), h.rank)))
            .unwrap_or_else(|| (vec![0u8; 32], 0));

        // Liveness-gap reset: if the persisted
        // `LivenessState.current_rank` sits more than one rank above
        // the latest finalized frame's rank, the previous session
        // advanced through one or more rounds without finalizing
        // (timeouts, equivocations, peer dropout). The persisted
        // `latest_quorum_certificate` then references a state that's
        // not in the forks tree we'll seed below (and not in any
        // clock-frame entry either), so the leader at `current_rank`
        // logs `parent state not in forks tree` and never proposes.
        //
        // Wipe the persisted liveness + consensus rows so the
        // bootstrap closures below rebuild them at
        // `current_rank = genesis_rank + 1` with the trusted root's
        // identity as the latest QC. The unfinalized rank progression
        // is discarded — the network is free to re-form a QC for the
        // same logical work at a higher rank, and the per-shard
        // pacemaker's timeout backoff resets anyway.
        if let Some(kv) = self.kv_db.as_ref() {
            let liveness_key = quil_store::encoding::consensus_liveness_key(&filter);
            let codec = crate::app_glue::AppConsensusCodec { filter: filter.clone() };
            let persisted_rank: Option<u64> = match kv.get(&liveness_key) {
                Ok(Some(bytes)) => crate::consensus_store::ConsensusStateCodec::<AppShardVote>::decode_liveness_state(&codec, &bytes)
                    .ok()
                    .map(|l| l.current_rank),
                _ => None,
            };
            if let Some(persisted) = persisted_rank {
                if persisted > genesis_rank.saturating_add(1) {
                    info!(
                        core_id = self.core_id,
                        filter = hex::encode(&filter),
                        persisted_current_rank = persisted,
                        trusted_rank = genesis_rank,
                        "resetting persisted liveness: current_rank ahead of latest finalized frame"
                    );
                    let _ = kv.delete(&liveness_key);
                    let _ = kv.delete(&quil_store::encoding::consensus_state_key(&filter));
                }
            }
        }

        // Leader provider
        let leader_provider = Arc::new(AppLeaderProvider {
            filter: filter.clone(),
            clock_store: self.clock_store.clone(),
            frame_prover: self.frame_prover.clone(),
            prover_registry: self.prover_registry.clone(),
            message_collector: self.message_collector.clone(),
            fee_manager: self.fee_manager.clone(),
            local_prover_address: self.local_prover_address.clone(),
            local_public_key: self.local_bls_pubkey.clone(),
            current_difficulty: self.current_difficulty.clone(),
            reward_greedy: self.reward_greedy,
            hypergraph: self.hypergraph.clone(),
            execution_engine: self.execution_engine.clone(),
            inclusion_prover: self.inclusion_prover.clone(),
            app_address: self.app_address.clone(),
            halted: self.halted.clone(),
            min_active_provers_for_propose: self.min_active_provers_for_propose,
        });

        // Committee (from prover registry for this shard)
        let committee = Arc::new(ProverRegistryCommittee::new(
            self.prover_registry.clone(),
            filter.clone(),
            &self.local_prover_address,
            self.local_bls_pubkey.clone(),
        ));

        // BLS voting provider
        let derive_address: AddressDerivation = Arc::new(|pubkey: &[u8]| {
            quil_crypto::poseidon::hash_bytes_to_32(pubkey)
                .unwrap_or_default()
                .to_vec()
        });
        // App shard domain separation — MUST match Go byte-for-byte
        // (`node/consensus/app/consensus_voting_provider.go:139,211`).
        // Go appends the app address so different shards have distinct
        // domains; we mirror that here using `self.app_address`. Using
        // a poseidon hash like the earlier Rust port would do is
        // safe between two Rust nodes but breaks the moment any peer
        // (or a migrated store carrying Go-signed QCs) shows up.
        let mut vote_domain = b"appshard".to_vec();
        vote_domain.extend_from_slice(&self.app_address);
        let mut timeout_domain = b"appshardtimeout".to_vec();
        timeout_domain.extend_from_slice(&self.app_address);
        // Hold onto the vote and timeout domains so we can later build
        // the per-shard `AppVoteAggregation` and `AppTimeoutAggregation`
        // without rederiving them.
        let vote_domain_for_agg = vote_domain.clone();
        let vote_domain_for_to = vote_domain.clone();
        let timeout_domain_for_to = timeout_domain.clone();

        let factory = Arc::new(AppShardVoteFactory { filter: filter.clone() });

        // Shared multi-proof precomputer. Populated asynchronously by
        // `AppParticipantConsumer`'s rank-change hooks (which run
        // `tokio::task::spawn_blocking`), consumed synchronously by
        // the `MultiProofProvider` below during `sign_vote`. Single-
        // prover shards short-circuit inside the precomputer so the
        // cache stays empty and votes take the 74-byte aggregate path.
        let multi_proof_precomputer = Arc::new(
            crate::multi_proof_cache::ShardMultiProofPrecomputer::new(
                self.frame_prover.clone(),
                self.prover_registry.clone(),
                self.local_prover_address.clone(),
                filter.clone(),
            ),
        );
        // Multi-proof producer: invoked at every `sign_vote` to attach
        // this voter's 516-byte VDF contribution. A cache miss
        // returns empty (vote sent without aux); for multi-prover
        // shards that means the QC won't include this voter's
        // multi-proof share — but precompute is kicked off on every
        // rank change so misses only happen if the vote arrives
        // faster than the VDF completes.
        let multi_proof_provider: crate::voting_provider::MultiProofProvider<AppShardState> = {
            let precomputer = multi_proof_precomputer.clone();
            Arc::new(move |state: &State<AppShardState>| -> Vec<u8> {
                precomputer.get_for_state(state)
            })
        };

        // Use `new_with_filter` so vote / timeout signing uses the
        // shard's `app_address` (poseidon(filter)) — both the local
        // `AppVoteAggregation` and the global archive
        // `verify_frame_header_signature` reconstruct the message
        // from `header.address`, which the wire frame carries as
        // `app_address`. Passing the raw `filter` here would sign
        // over one buffer (filter || identity || rank) while every
        // verifier reconstructs another (app_address || identity ||
        // rank), and every aggregate BLS check would fail. Mirrors
        // Go's `consensus_voting_provider.go:204-211`.
        let voting_provider: Arc<dyn quil_consensus::voting_provider::VotingProvider<AppShardState, AppShardVote>> =
            Arc::new(
                BlsVotingProvider::<AppShardState, AppShardVote, AppShardVoteFactory>::new_with_filter(
                    Arc::from(bls_signer),
                    vote_domain,
                    timeout_domain,
                    derive_address,
                    factory,
                    self.app_address.clone(),
                )
                .with_multi_proof_provider(multi_proof_provider),
            );
        let voting_provider_for_agg = voting_provider.clone();
        let voting_provider_for_to = voting_provider.clone();
        let signer: Arc<dyn quil_consensus::signer::Signer<AppShardState, AppShardVote>> =
            Arc::new(VotingProviderSigner::new(voting_provider));

        // Timeout config
        let timeout_cfg = TimeoutConfig::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            1.5,
            3,
            Duration::from_secs(30),
        )?;
        let timeout_ctrl = TimeoutController::new(timeout_cfg);
        let duration_provider = Arc::new(StaticProposalDurationProvider::new(
            Duration::from_secs(10),
        ));

        // Consumer/notifier — keep a concrete `Arc<AppConsumer>` so we
        // can install the vote aggregator after the event loop spawns
        // (the aggregator needs the loop handle, which the loop only
        // gives us after construction).
        let consumer_concrete = Arc::new(AppConsumer::new(
            filter.clone(),
            self.consensus_event_tx.clone(),
        ));
        let consumer: Arc<dyn quil_consensus::event_handler::Consumer<AppShardState, AppShardVote>> =
            consumer_concrete.clone();
        // Build the shared multi-proof precomputer. Used by:
        //  - `AppParticipantConsumer` to fire-and-forget compute on
        //    every rank change (off the consensus thread)
        //  - `MultiProofProvider` to do sync cache lookups during
        //    `sign_vote`
        // Single-prover shards short-circuit inside the precomputer
        // (no committee work → no entries cached).
        let multi_proof_precomputer = Arc::new(
            crate::multi_proof_cache::ShardMultiProofPrecomputer::new(
                self.frame_prover.clone(),
                self.prover_registry.clone(),
                self.local_prover_address.clone(),
                filter.clone(),
            ),
        );
        let participant: Arc<dyn quil_consensus::pacemaker::ParticipantConsumer<AppShardState, AppShardVote>> =
            Arc::new(
                AppParticipantConsumer::new(filter.clone())
                    .with_multi_proof_precomputer(
                        multi_proof_precomputer.clone(),
                        self.current_difficulty.clone(),
                    ),
            );

        // Consensus store: persistent if a KV backend is wired in
        // (production), in-memory stub otherwise (tests).
        let store: Arc<dyn quil_consensus::event_handler::ConsensusStore<AppShardVote>> =
            match self.kv_db.as_ref() {
                Some(kv) => Arc::new(crate::consensus_store::KvConsensusStore::new(
                    kv.clone(),
                    Arc::new(crate::app_glue::AppConsensusCodec { filter: filter.clone() }),
                    {
                        // Bootstrap consensus state for a fresh shard:
                        // finalized at the trusted root's rank (0 for
                        // a true genesis bootstrap, the latest
                        // finalized frame's rank on resume), no later
                        // timeout yet.
                        let bootstrap_rank = genesis_rank;
                        Arc::new(move |f: &[u8]| quil_consensus::models::ConsensusState::<AppShardVote> {
                            filter: f.to_vec(),
                            finalized_rank: bootstrap_rank,
                            latest_acknowledged_rank: bootstrap_rank,
                            latest_timeout: None,
                        })
                    },
                    {
                        // Bootstrap liveness so the leader's first
                        // proposal lands on top of the trusted root.
                        // `current_rank = genesis_rank + 1` matches
                        // the forks tree's seed (built below at
                        // `genesis_rank` with identity
                        // `poseidon(genesis_output)`), and the QC
                        // identity must hash the same output. Without
                        // both, the parent-state lookup at
                        // `event_handler.rs:469` misses and every
                        // proposal aborts as `parent state not in
                        // forks tree`.
                        let filter_cap = filter.clone();
                        let bootstrap_rank = genesis_rank;
                        let bootstrap_output = genesis_output.clone();
                        Arc::new(move |_f: &[u8]| quil_consensus::models::LivenessState {
                            filter: filter_cap.clone(),
                            current_rank: bootstrap_rank.saturating_add(1),
                            latest_quorum_certificate: Arc::new(
                                crate::app_types::AppGenesisQC::for_output(
                                    filter_cap.clone(),
                                    &bootstrap_output,
                                    bootstrap_rank,
                                ),
                            ),
                            prior_rank_timeout_certificate: None,
                        })
                    },
                )),
                None => Arc::new(AppMemConsensusStore::new(filter.clone())),
            };

        // Pacemaker
        let pacemaker = HotStuffPacemaker::<AppShardState, AppShardVote>::new(
            filter.clone(),
            timeout_ctrl,
            duration_provider,
            participant,
            store.clone(),
        )?;

        // Safety rules
        let safety_rules = Arc::new(Mutex::new(
            SafetyRules::<AppShardState, AppShardVote>::new(
                filter.clone(),
                signer,
                store,
                committee.clone() as Arc<dyn DynamicCommittee>,
            )?,
        ));

        let state_producer = Arc::new(StateProducer::new(
            safety_rules.clone(),
            leader_provider as Arc<dyn quil_consensus::leader_provider::LeaderProvider<AppShardState>>,
        ));

        // Trusted root for the forks tree, anchored at the latest
        // finalized shard frame's (rank, output). The bootstrap
        // closures above feed the consensus event loop a matching
        // `LivenessState` (`current_rank = genesis_rank + 1`, QC
        // identity = `poseidon(genesis_output)`) so the leader's
        // first parent-state lookup resolves against this entry.
        let trusted_root = build_app_genesis_certified_state(
            &filter,
            self.shard_frame_number,
            &genesis_output,
            genesis_rank,
        );
        info!(
            core_id = self.core_id,
            filter = hex::encode(&filter),
            trusted_rank = genesis_rank,
            shard_frame = self.shard_frame_number,
            "seeding forks tree with trusted root",
        );

        // Forks
        let finalizer: Arc<dyn quil_consensus::forest::Finalizer> =
            Arc::new(AppFinalizer::new(filter.clone()));
        // Stage proposed shard frames on incorporation so the next-rank
        // leader can chain a proposal on top via `prove_next_state`.
        // Mirrors the global path: without this, the leader at rank
        // N+1 can't find its rank-N parent and falls into perpetual
        // timeout. Hook writes via `stage_shard_clock_frame`
        // (`clock_shard_staged_key`) keyed by the state's identifier,
        // which matches the QC's `selector` so the QC-arrival commit
        // can later locate it.
        let incorp_clock_store = Arc::clone(&self.clock_store);
        let incorp_filter = filter.clone();
        let incorporated_hook: crate::app_glue::AppIncorporatedStateHook =
            Arc::new(move |state| {
                let s = &state.state;
                let header = quil_types::proto::global::FrameHeader {
                    address: s.filter.clone(),
                    frame_number: s.frame_number,
                    rank: state.rank,
                    timestamp: s.timestamp,
                    difficulty: s.difficulty,
                    output: s.output.clone(),
                    parent_selector: s.parent_selector.clone(),
                    requests_root: s.requests_root.clone(),
                    state_roots: s.state_roots.clone(),
                    prover: s.prover.clone(),
                    fee_multiplier_vote: s.fee_multiplier,
                    // Signature is reconstructed later when the QC's
                    // aggregate sig is applied; the staged frame
                    // doesn't need it (the next-rank leader only
                    // reads identity-bearing fields like `output`).
                    public_key_signature_bls48581: None,
                    ..Default::default()
                };
                let frame = quil_types::proto::global::AppShardFrame {
                    header: Some(header),
                    requests: Vec::new(),
                };
                // NoTxn shim — stage write goes direct to RocksDB.
                struct NoTxn;
                impl quil_types::store::Transaction for NoTxn {
                    fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
                    fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                    fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                    fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                    fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                    fn new_iter(
                        &self,
                        _: &[u8],
                        _: &[u8],
                    ) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
                        Err(quil_types::error::QuilError::NotFound("noop".into()))
                    }
                    fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                    fn as_any(&self) -> &dyn std::any::Any { self }
                }
                let no_txn = NoTxn;
                let identity = quil_crypto::poseidon::hash_bytes_to_32(&s.output)
                    .map(|h| h.to_vec())
                    .unwrap_or_default();
                match incorp_clock_store.stage_shard_clock_frame(
                    &identity,
                    &frame,
                    &no_txn,
                ) {
                    Ok(()) => tracing::info!(
                        filter = hex::encode(&incorp_filter),
                        frame = s.frame_number,
                        rank = state.rank,
                        identity = %hex::encode(&identity),
                        "staged shard frame candidate",
                    ),
                    Err(e) => tracing::warn!(
                        error = %e,
                        filter = hex::encode(&incorp_filter),
                        frame = s.frame_number,
                        rank = state.rank,
                        "failed to stage shard frame candidate",
                    ),
                }
            });
        // Shared QC cache: populated by the vote aggregator (locally
        // formed QCs + peer proposal parent QCs), read by the
        // follower on finalization to rehydrate the certifying QC
        // the forest strips. Seeded with the genesis/trusted-root QC
        // so the first finalization at the trusted rank still has
        // an aggregate sig (empty bitmask, empty bls bytes — but
        // valid canonical encoding) to ship.
        let qc_store = Arc::new(crate::app_glue::QcStore::new());
        qc_store.insert(Arc::new(crate::app_types::AppGenesisQC::for_output(
            filter.clone(),
            &genesis_output,
            genesis_rank,
        )));
        let follower: Arc<dyn quil_consensus::forest::FollowerConsumer<AppShardState>> =
            Arc::new(AppFollower::with_incorporated_hook(
                filter.clone(),
                self.app_address.clone(),
                self.consensus_event_tx.clone(),
                self.coverage_publish.clone(),
                Some(incorporated_hook),
                qc_store.clone(),
            ));
        let forks = Forks::<AppShardState>::new(trusted_root, finalizer, follower)?;

        // Event handler — keep a concrete `committee_for_agg` clone so
        // the vote aggregator (built post-handler) sees the same
        // committee instance the event handler uses for self-id /
        // quorum thresholds.
        let committee_for_agg = committee.clone();
        let handler = Arc::new(HotStuffEventHandler::new(
            Arc::new(Mutex::new(pacemaker)),
            state_producer,
            Arc::new(Mutex::new(forks)),
            safety_rules,
            committee as Arc<dyn quil_consensus::committee::Replicas>,
            consumer,
        ));

        // Event loop
        let (event_loop, handle) = EventLoop::new(handler, Instant::now());

        // Per-shard vote aggregator. Its
        // `OnQuorumCertificateCreated` callback feeds formed QCs
        // back into the event loop via `handle`. We also keep an
        // `Arc` clone on the engine so peer votes routed via
        // `handle_vote` reach the same aggregator.
        let (vote_aggregator_for_engine, timeout_aggregator_for_engine) = {
            use std::sync::OnceLock;
            let bls_ctor: Arc<dyn quil_types::crypto::BlsConstructor> =
                Arc::new(quil_crypto::Bls48581KeyConstructor);
            let handle_cell: Arc<OnceLock<crate::app_types::AppEventLoopHandle>> =
                Arc::new(OnceLock::new());
            let _ = handle_cell.set(handle.clone());
            let committee_for_to = committee_for_agg.clone();
            let agg = Arc::new(crate::app_vote_aggregation::AppVoteAggregation::new(
                filter.clone(),
                self.app_address.clone(),
                committee_for_agg,
                voting_provider_for_agg,
                handle_cell.clone(),
                bls_ctor.clone(),
                vote_domain_for_agg,
                // Same `proposal_duration` the pacemaker uses for its
                // `target_publication_time` (10s). The aggregator
                // delays QC submission so single-prover shards don't
                // race past this cadence — see `make_on_qc_created`.
                Duration::from_secs(10),
                qc_store.clone(),
            ));
            consumer_concrete.set_aggregator(agg.clone());

            let to_agg = Arc::new(
                crate::app_timeout_aggregation::AppTimeoutAggregation::new(
                    filter.clone(),
                    committee_for_to,
                    voting_provider_for_to,
                    handle_cell,
                    bls_ctor,
                    vote_domain_for_to,
                    timeout_domain_for_to,
                ),
            );
            (agg, to_agg)
        };

        let filter_for_loop = filter.clone();
        // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
        tokio::spawn(async move {
            if let Err(e) = event_loop.run().await {
                tracing::error!(
                    filter = hex::encode(&filter_for_loop),
                    error = %e,
                    "shard consensus event loop exited with error"
                );
            }
        });

        Ok((
            handle,
            vote_aggregator_for_engine,
            timeout_aggregator_for_engine,
        ))
    }

    // ---------------------------------------------------------------
    // Message handlers
    // ---------------------------------------------------------------

    /// Handle a consensus protocol message (proposal/vote/timeout).
    fn handle_consensus_message(&mut self, data: &[u8]) {
        if self.halted.load(std::sync::atomic::Ordering::Relaxed) || data.len() < 4 {
            return;
        }

        let tp = u32::from_be_bytes(data[..4].try_into().unwrap());
        let kind = classify_consensus_message(tp);

        match kind {
            Some(ConsensusMessageKind::AppShardProposal) => {
                self.handle_app_shard_proposal(data);
            }
            Some(ConsensusMessageKind::ProposalVote) => {
                self.handle_vote(data);
            }
            Some(ConsensusMessageKind::TimeoutState) => {
                self.handle_timeout_state(data);
            }
            Some(ConsensusMessageKind::QuorumCertificate) => {
                self.handle_quorum_certificate(data);
            }
            Some(ConsensusMessageKind::TimeoutCertificate) => {
                self.handle_timeout_certificate(data);
            }
            _ => {
                debug!(
                    core_id = self.core_id,
                    type_prefix = format!("0x{:08x}", tp),
                    "unrecognized consensus message type"
                );
            }
        }
    }

    fn handle_app_shard_proposal(&mut self, data: &[u8]) {
        // Decode AppShardProposal from canonical bytes (full reconstruction).
        let proposal = match AppShardProposal::from_canonical_bytes(data) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    core_id = self.core_id,
                    error = %e,
                    "failed to decode shard proposal"
                );
                return;
            }
        };

        // Reject proposals for other shards. Master subscribes to the
        // per-shard consensus bitmask which is filter-prefixed, so this
        // is a defense-in-depth check.
        if !proposal.header.address.is_empty() && proposal.header.address != self.app_address {
            debug!(
                core_id = self.core_id,
                proposal_address = %hex::encode(&proposal.header.address),
                local_address = %hex::encode(&self.app_address),
                "dropping shard proposal addressed to a different shard"
            );
            return;
        }

        debug!(
            core_id = self.core_id,
            rank = proposal.header.rank,
            frame = proposal.header.frame_number,
            "received shard proposal"
        );

        // Always keep the raw bytes cached by rank — replay/resync paths
        // re-emit them from `pop_cached_proposal()`.
        self.cache_proposal(proposal.header.rank, data.to_vec());

        // Build the proto FrameHeader needed by `AppShardState::from_header`.
        let proto_header = quil_types::proto::global::FrameHeader {
            address: proposal.header.address.clone(),
            frame_number: proposal.header.frame_number,
            rank: proposal.header.rank,
            timestamp: proposal.header.timestamp,
            difficulty: proposal.header.difficulty,
            output: proposal.header.output.clone(),
            parent_selector: proposal.header.parent_selector.clone(),
            requests_root: proposal.header.requests_root.clone(),
            state_roots: proposal.header.state_roots.clone(),
            prover: proposal.header.prover.clone(),
            fee_multiplier_vote: proposal.header.fee_multiplier_vote as u64,
            // Re-wrapping the canonical-bytes BLS sig into the prost
            // wrapper would require parsing it; the consensus pipeline
            // doesn't read this field via the proto, so leave it None.
            public_key_signature_bls48581: None,
        };

        let state = AppShardState::from_header(&proto_header, &self.filter);
        // Override the signature with the raw bytes from the canonical
        // sig blob — `from_header` reads via the prost wrapper which we
        // intentionally left empty.
        let state = {
            let sig = proposal.header.public_key_signature_bls48581.clone();
            AppShardState::new(
                state.filter.clone(),
                state.frame_number,
                state.rank,
                proposal.header.timestamp,
                state.difficulty,
                state.output.clone(),
                state.parent_selector.clone(),
                state.prover.clone(),
                state.requests_root.clone(),
                state.state_roots.clone(),
                sig,
                state.fee_multiplier,
            )
        };
        let identity = state.identity().clone();

        // Embed the parent QC and prior TC as trait objects so the
        // forks tree's parent-state lookup matches what the safety
        // rules expect.
        let parent_qc = wire_qc_to_trait(&proposal.parent_qc, &self.filter);
        let prior_tc: Option<Arc<dyn TimeoutCertificate>> = proposal
            .prior_tc
            .as_ref()
            .map(|tc| wire_tc_to_trait(tc, &self.filter));

        // Build the proposer identity from the wire vote's address —
        // the leader's vote always rides along with the proposal, and
        // its `address` field is the proposer's identity.
        let proposer_id: Identity = if !proposal.vote.address.is_empty() {
            proposal.vote.address.clone()
        } else if !proposal.header.prover.is_empty() {
            proposal.header.prover.clone()
        } else {
            Vec::new()
        };

        let typed_state = State {
            rank: proposal.header.rank,
            identifier: identity.clone(),
            proposer_id: proposer_id.clone(),
            parent_qc_identity: parent_qc.identity().clone(),
            parent_qc_rank: parent_qc.rank(),
            // Mirror Go's `models.State.ParentQuorumCertificate` so
            // downstream consumers (notably `AppFollower` on
            // finalization) can read the aggregated signature without
            // a QC-store lookup. The QC is the one the proposal
            // carried as its parent_qc — same Arc cloned twice into
            // the State and the wrapping Proposal below.
            parent_quorum_certificate: Some(parent_qc.clone()),
            timestamp: proposal.header.timestamp as u64,
            state,
        };

        // Build the leader's own vote ride-along from the wire payload.
        let vote = AppShardVote::new(
            identity,
            proposal.header.rank,
            proposal.vote.address.clone(),
            proposal.vote.timestamp,
            proposal.vote.signature.clone(),
            Vec::new(),
            self.filter.clone(),
        );

        let signed = SignedProposal {
            proposal: Proposal {
                state: typed_state,
                parent_quorum_certificate: parent_qc.clone(),
                previous_rank_timeout_certificate: prior_tc.clone(),
            },
            vote,
        };

        // Surface the proposal's parent QC (and optional prior TC) to
        // the event loop BEFORE submitting the proposal itself — the
        // event handler's `on_receive_proposal` deliberately ignores
        // the embedded parent QC and relies on a separate
        // `on_receive_quorum_certificate` to advance the pacemaker.
        // Without this, peers stay at rank N forever while the leader
        // (which formed the QC locally via its vote aggregator) races
        // ahead to rank N+1, and votes for rank N+1 are rejected with
        // "proposal rank does not match current rank". Mirror of the
        // global e2e harness's WireMsg::Proposal arm.
        if let Some(handle) = self.consensus_handle.as_ref() {
            let handle = handle.clone();
            let qc_for_submit = parent_qc.clone();
            let tc_for_submit = prior_tc.clone();
            let signed_for_submit = signed;
            tokio::spawn(async move {
                handle.submit_quorum_certificate(qc_for_submit);
                if let Some(tc) = tc_for_submit {
                    handle.submit_timeout_certificate(tc);
                }
                if !handle.submit_proposal(signed_for_submit).await {
                    debug!("shard event loop rejected proposal (cancelled?)");
                }
            });
        } else {
            debug!(
                core_id = self.core_id,
                "shard proposal received but consensus handle not yet ready"
            );
        }
    }

    fn handle_vote(&mut self, data: &[u8]) {
        let wire_vote = match consensus_wire::ProposalVote::from_canonical_bytes(data) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "failed to decode vote");
                return;
            }
        };

        // Drop votes for other shards.
        if !wire_vote.filter.is_empty() && wire_vote.filter != self.filter {
            debug!(
                core_id = self.core_id,
                vote_filter = %hex::encode(&wire_vote.filter),
                local_filter = %hex::encode(&self.filter),
                "dropping vote addressed to a different shard"
            );
            return;
        }

        debug!(
            core_id = self.core_id,
            rank = wire_vote.rank,
            "received shard vote"
        );

        // Feed the vote into the per-shard aggregator. When the
        // weighted threshold is met the aggregator's
        // `OnQuorumCertificateCreated` callback pushes the resulting QC
        // back into the event loop.
        if let Some(agg) = self.vote_aggregator.as_ref() {
            let typed_vote =
                crate::app_vote_aggregation::wire_vote_to_app_shard_vote(
                    wire_vote,
                    self.filter.clone(),
                );
            agg.handle_vote(typed_vote);
        } else {
            debug!(
                core_id = self.core_id,
                "shard vote received but aggregator not yet wired"
            );
        }
    }

    fn handle_timeout_state(&mut self, data: &[u8]) {
        let ts = match consensus_wire::TimeoutState::from_canonical_bytes(data) {
            Ok(t) => t,
            Err(e) => {
                debug!(error = %e, "failed to decode timeout state");
                return;
            }
        };

        if !ts.vote.filter.is_empty() && ts.vote.filter != self.filter {
            debug!(
                core_id = self.core_id,
                "dropping timeout addressed to a different shard"
            );
            return;
        }

        debug!(
            core_id = self.core_id,
            tick = ts.timeout_tick,
            rank = ts.vote.rank,
            "received shard timeout state"
        );

        if let Some(agg) = self.timeout_aggregator.as_ref() {
            let typed = crate::app_timeout_aggregation::wire_timeout_to_app_typed(
                ts,
                self.filter.clone(),
            );
            agg.handle_timeout(typed);
        } else {
            debug!(
                core_id = self.core_id,
                "shard timeout received but aggregator not yet wired"
            );
        }
    }

    fn handle_quorum_certificate(&mut self, data: &[u8]) {
        match consensus_wire::QuorumCertificate::from_canonical_bytes(data) {
            Ok(qc) => {
                let child_rank = qc.rank;
                debug!(
                    core_id = self.core_id,
                    rank = child_rank,
                    "received shard QC"
                );

                // Commit the QC'd frame so the next-rank leader can
                // chain a proposal on top via `prove_next_state`
                // (which reads `GetLatestShardClockFrame`). Mirrors
                // Go's `OnQuorumCertificateTriggeredRankChange`
                // (`node/consensus/app/app_consensus_engine.go:2843`):
                // after the QC arrives, the QC's own frame is
                // committed (latest-index advances). We rely on the
                // staged frame written by `AppFollower`'s incorporated
                // hook keyed by the same selector (= state identity =
                // qc.selector).
                match self.clock_store.new_transaction(false) {
                    Ok(txn) => {
                        if let Err(e) = self.clock_store.commit_shard_clock_frame(
                            &self.filter,
                            qc.frame_number,
                            &qc.selector,
                            txn.as_ref(),
                            false,
                        ) {
                            warn!(
                                core_id = self.core_id,
                                rank = qc.rank,
                                frame = qc.frame_number,
                                error = %e,
                                "failed to commit shard frame on QC",
                            );
                        } else if let Err(e) = txn.commit() {
                            warn!(
                                core_id = self.core_id,
                                rank = qc.rank,
                                frame = qc.frame_number,
                                error = %e,
                                "shard frame commit txn failed",
                            );
                        } else {
                            info!(
                                core_id = self.core_id,
                                rank = qc.rank,
                                frame = qc.frame_number,
                                identity = %hex::encode(&qc.selector),
                                "committed shard frame on QC",
                            );
                        }
                    }
                    Err(e) => warn!(
                        core_id = self.core_id,
                        error = %e,
                        "could not create txn for QC commit",
                    ),
                }

                if let Some(ref handle) = self.consensus_handle {
                    let qc_trait = wire_qc_to_trait(&qc, &self.filter);
                    handle.submit_quorum_certificate(qc_trait);
                }
                // Seal the parent whose child QC just arrived
                self.pending_seal_rank = Some(child_rank);
            }
            Err(e) => {
                debug!(error = %e, "failed to decode QC");
            }
        }
    }

    fn handle_timeout_certificate(&mut self, data: &[u8]) {
        match consensus_wire::TimeoutCertificate::from_canonical_bytes(data) {
            Ok(tc) => {
                debug!(
                    core_id = self.core_id,
                    rank = tc.rank,
                    "received shard TC"
                );
                if let Some(ref handle) = self.consensus_handle {
                    let tc = wire_tc_to_trait(&tc, &self.filter);
                    handle.submit_timeout_certificate(tc);
                }
            }
            Err(e) => {
                debug!(error = %e, "failed to decode TC");
            }
        }
    }

    /// Handle a prover message (MessageBundle containing prover ops).
    fn handle_prover_message(&mut self, data: &[u8]) {
        if self.halted.load(std::sync::atomic::Ordering::Relaxed) || data.len() < 4 {
            return;
        }
        // Add to message collector for inclusion in next frame
        self.add_app_message(data);
    }

    /// Handle a frame message (AppShardFrame from another prover).
    fn handle_frame_message(&mut self, data: &[u8]) {
        if self.halted.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if let Ok(frame) = prost::Message::decode(data) {
            let frame: quil_types::proto::global::AppShardFrame = frame;
            if let Some(h) = frame.header.as_ref() {
                // Validate: filter must match this shard
                if h.address != self.app_address {
                    return;
                }

                if h.frame_number > self.shard_frame_number {
                    debug!(
                        core_id = self.core_id,
                        remote_frame = h.frame_number,
                        local_frame = self.shard_frame_number,
                        "received newer shard frame"
                    );

                    // Cache in frame store (keyed by output hash)
                    use sha2::{Digest, Sha256};
                    let frame_id = hex::encode(Sha256::digest(&h.output));
                    self.frame_store.insert(frame_id, data.to_vec());

                    // Shard frame persistence is done via stage + commit
                    // through the clock store's transaction API during
                    // finalization. The frame is cached locally for now.
                }
            }
        }
    }

    /// Handle a dispatch message (token/compute/hypergraph operation).
    fn handle_dispatch_message(&mut self, data: &[u8]) {
        if self.halted.load(std::sync::atomic::Ordering::Relaxed) || data.len() < 4 {
            return;
        }
        // Dispatch messages are collected for inclusion in frames
        self.add_app_message(data);
    }

    /// Handle a global frame message (for time sync).
    ///
    /// Extracts the global frame number and difficulty, then aligns
    /// the shard frame number if behind. Shard frame N is produced
    /// alongside global frame N+1.
    fn handle_global_frame_message(&mut self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }

        let global_frame = match crate::consensus_wire::decode_global_frame(data) {
            Ok(f) => f,
            Err(e) => {
                debug!(
                    core_id = self.core_id,
                    error = %e,
                    "failed to decode global frame for time sync"
                );
                return;
            }
        };

        let header = match global_frame.header.as_ref() {
            Some(h) => h,
            None => return,
        };

        let global_frame_number = header.frame_number;
        let global_difficulty = header.difficulty;

        debug!(
            core_id = self.core_id,
            global_frame = global_frame_number,
            shard_frame = self.shard_frame_number,
            difficulty = global_difficulty,
            "global frame time sync"
        );

        // Align shard frame number: shard frame N corresponds to
        // global frame N+1. If the shard is behind, advance it.
        let expected_shard_frame = global_frame_number.saturating_sub(1);
        if self.shard_frame_number < expected_shard_frame {
            info!(
                core_id = self.core_id,
                shard_frame = self.shard_frame_number,
                expected = expected_shard_frame,
                global_frame = global_frame_number,
                "shard behind global — advancing frame number"
            );
            self.shard_frame_number = expected_shard_frame;
        }

        // Update difficulty from global frame header
        self.current_difficulty.store(
            global_difficulty,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Handle a peer info message.
    fn handle_peer_info_message(&mut self, data: &[u8]) {
        // Peer info is used for address book management; the app
        // engine just logs receipt for now.
        debug!(
            core_id = self.core_id,
            len = data.len(),
            "peer info received by shard engine"
        );
    }

    // ---------------------------------------------------------------
    // Message collection with spillover
    // ---------------------------------------------------------------

    /// Add an application message to the message collector for
    /// inclusion in the next frame. If the current rank's buffer is
    /// full, spill over to the next rank.
    fn add_app_message(&mut self, data: &[u8]) {
        let rank = self.current_rank;
        if !self.message_collector.add_message(rank, data.to_vec()) {
            // Buffer full — spill to next rank
            let next_rank = rank + 1;
            self.message_spillover
                .entry(next_rank)
                .or_insert_with(Vec::new)
                .push(data.to_vec());
        }
    }

    /// Flush spillover messages into the collector for the target rank.
    /// Called on rank change (ControlEventAppNewHead equivalent).
    fn flush_deferred_messages(&mut self, target_rank: u64) {
        if let Some(messages) = self.message_spillover.remove(&target_rank) {
            for msg in messages {
                self.message_collector.add_message(target_rank, msg);
            }
        }
    }

    // ---------------------------------------------------------------
    // Consensus event handling
    // ---------------------------------------------------------------

    async fn handle_consensus_event(&mut self, event: AppConsensusEvent) {
        match event {
            AppConsensusEvent::Finalized {
                frame_number,
                rank,
                state_id,
                canonical_header_bytes,
            } => {
                debug!(
                    core_id = self.core_id,
                    filter = hex::encode(&self.filter),
                    frame = frame_number,
                    rank,
                    "shard frame finalized"
                );
                self.shard_frame_number = frame_number;

                // Promote the staged frame keyed by `state_id` to the
                // canonical clock-store record. The wire-QC path in
                // `handle_quorum_certificate` does the same when a QC
                // arrives from a peer; but in a single-prover shard
                // (or any case where the QC forms locally before any
                // peer sends one), `handle_quorum_certificate` never
                // fires. Without this commit, `prove_next_state` keeps
                // reading the genesis frame from the store and every
                // rank re-proposes `frame=1`, so the shard never
                // advances past its first frame.
                match self.clock_store.new_transaction(false) {
                    Ok(txn) => {
                        if let Err(e) = self.clock_store.commit_shard_clock_frame(
                            &self.filter,
                            frame_number,
                            &state_id,
                            txn.as_ref(),
                            false,
                        ) {
                            warn!(
                                core_id = self.core_id,
                                rank,
                                frame = frame_number,
                                error = %e,
                                "failed to commit finalized shard frame",
                            );
                        } else if let Err(e) = txn.commit() {
                            warn!(
                                core_id = self.core_id,
                                rank,
                                frame = frame_number,
                                error = %e,
                                "finalized shard frame txn failed",
                            );
                        } else {
                            info!(
                                core_id = self.core_id,
                                rank,
                                frame = frame_number,
                                identity = %hex::encode(&state_id),
                                "committed finalized shard frame",
                            );
                        }
                    }
                    Err(e) => warn!(
                        core_id = self.core_id,
                        error = %e,
                        "could not create txn for finalized commit",
                    ),
                }
                // The follower already encoded the canonical FrameHeader
                // for `coverage_publish`; forward those same bytes as
                // `ShardFrameFinalized` so the master can wrap them in
                // a `MessageBundle{Shard: header}` and publish on
                // `GLOBAL_PROVER`. Re-loading from the clock store
                // would require shard-frame persistence that hasn't
                // happened yet at this point in the pipeline.
                //
                // Coverage-halt gate: even though `handle_consensus_message`
                // drops new incoming messages while halted, the biased
                // `tokio::select!` polls `consensus_event_rx` BEFORE
                // `msg_rx`, so any consensus event queued from votes
                // processed pre-halt will still arrive here for a window
                // after `SetHalted(true)` lands. We keep the local
                // clock-store commit (so the forks tree stays consistent
                // with the network's view) but drop the externally-visible
                // emissions: no `ShardFrameFinalized` to the drain (which
                // would publish a reward proof on `GLOBAL_PROVER`), and
                // the follower's `coverage_publish` closure has a mirror
                // halt check so its synchronous publish path is also
                // suppressed.
                let halted = self.halted.load(std::sync::atomic::Ordering::Relaxed);
                if halted {
                    debug!(
                        core_id = self.core_id,
                        frame = frame_number,
                        "suppressing ShardFrameFinalized emit — coverage halt active",
                    );
                } else if let Some(bytes) = canonical_header_bytes {
                    let _ = self
                        .event_tx
                        .send(AppEngineEvent::ShardFrameFinalized {
                            filter: self.filter.clone(),
                            header_canonical_bytes: bytes,
                        });
                } else {
                    warn!(
                        core_id = self.core_id,
                        frame = frame_number,
                        "finalized state has no canonical header bytes — skipping coverage publish",
                    );
                }
                // Flush spillover for the next rank
                self.flush_deferred_messages(rank + 1);
                // Check for missing ancestors and request sync if needed
                let missing = self.collect_missing_ancestors(frame_number);
                if !missing.is_empty() {
                    self.request_ancestor_sync(&missing).await;
                }
            }

            AppConsensusEvent::DoublePropose { first_frame, second_frame } => {
                warn!(
                    core_id = self.core_id,
                    filter = hex::encode(&self.filter),
                    first_frame,
                    second_frame,
                    "equivocation detected on shard"
                );
                let _ = self.event_tx.send(AppEngineEvent::EquivocationDetected {
                    filter: self.filter.clone(),
                    first_frame,
                    second_frame,
                });
            }

            AppConsensusEvent::RankChange { old_rank, new_rank } => {
                debug!(
                    core_id = self.core_id,
                    old = old_rank,
                    new = new_rank,
                    "shard rank changed"
                );
                self.current_rank = new_rank;
                self.flush_deferred_messages(new_rank);
            }

            AppConsensusEvent::OwnVote { data, .. } => {
                let _ = self.event_tx.send(AppEngineEvent::VoteProduced {
                    filter: self.filter.clone(),
                    vote_data: data,
                });
            }

            AppConsensusEvent::OwnTimeout { data } => {
                let _ = self.event_tx.send(AppEngineEvent::TimeoutProduced {
                    filter: self.filter.clone(),
                    timeout_data: data,
                });
            }

            AppConsensusEvent::OwnProposal { data, frame_number, rank } => {
                debug!(
                    core_id = self.core_id,
                    filter = hex::encode(&self.filter),
                    frame = frame_number,
                    rank,
                    "shard frame produced"
                );
                let _ = self.event_tx.send(AppEngineEvent::FrameProduced {
                    filter: self.filter.clone(),
                    frame_number,
                    frame_data: data,
                });
            }
        }
    }

    // ---------------------------------------------------------------
    // Proposal cache management
    // ---------------------------------------------------------------

    /// Cache a proposal by rank. Used when a proposal arrives before the
    /// consensus event loop is ready to process it.
    pub fn cache_proposal(&mut self, rank: u64, data: Vec<u8>) {
        debug!(
            core_id = self.core_id,
            rank,
            len = data.len(),
            "caching proposal"
        );
        self.proposal_cache.insert(rank, data);
    }

    /// Remove and return a cached proposal for the given rank.
    pub fn pop_cached_proposal(&mut self, rank: u64) -> Option<Vec<u8>> {
        self.proposal_cache.remove(&rank)
    }

    /// Drain proposal cache entries older than `current_rank - 10`.
    /// Called periodically or on rank change to bound memory.
    pub fn drain_proposal_cache(&mut self) {
        let cutoff = self.current_rank.saturating_sub(10);
        self.proposal_cache.retain(|&rank, _| rank >= cutoff);
    }

    // ---------------------------------------------------------------
    // Certified parent sealing
    // ---------------------------------------------------------------

    /// Register a parent's state data for later sealing. When the child
    /// rank's QC arrives, `try_seal_parent_with_child` commits the
    /// parent state through the frame materializer path.
    pub fn register_pending_certified_parent(&mut self, rank: u64, data: Vec<u8>) {
        debug!(
            core_id = self.core_id,
            rank,
            len = data.len(),
            "registering pending certified parent"
        );
        self.pending_certified_parents.insert(rank, data);
    }

    /// When a child QC arrives at `child_rank`, seal the parent at
    /// `child_rank - 1` by persisting its state through the clock store
    /// via the stage + commit path. Emits a `ParentSealed` event on success.
    pub async fn try_seal_parent_with_child(&mut self, child_rank: u64) {
        let parent_rank = child_rank.saturating_sub(1);
        let parent_data = match self.pending_certified_parents.remove(&parent_rank) {
            Some(d) => d,
            None => return,
        };

        debug!(
            core_id = self.core_id,
            parent_rank,
            child_rank,
            "sealing certified parent"
        );

        // Decode the parent frame and persist via stage + commit.
        let frame = match <quil_types::proto::global::AppShardFrame as prost::Message>::decode(
            parent_data.as_slice(),
        ) {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    core_id = self.core_id,
                    parent_rank,
                    error = %e,
                    "failed to decode parent frame for sealing"
                );
                return;
            }
        };

        let header = match frame.header.as_ref() {
            Some(h) => h,
            None => return,
        };

        let txn = match self.clock_store.new_transaction(false) {
            Ok(t) => t,
            Err(e) => {
                warn!(core_id = self.core_id, error = %e, "failed to create txn for seal");
                return;
            }
        };

        // Stage the frame, then commit it
        if let Err(e) = self.clock_store.stage_shard_clock_frame(
            &header.parent_selector,
            &frame,
            txn.as_ref(),
        ) {
            warn!(core_id = self.core_id, parent_rank, error = %e, "failed to stage sealed parent");
            return;
        }

        if let Err(e) = self.clock_store.commit_shard_clock_frame(
            &self.filter,
            header.frame_number,
            &header.parent_selector,
            txn.as_ref(),
            false, // not a backfill
        ) {
            warn!(core_id = self.core_id, parent_rank, error = %e, "failed to commit sealed parent");
            return;
        }

        if let Err(e) = txn.commit() {
            warn!(core_id = self.core_id, parent_rank, error = %e, "sealed parent txn commit failed");
            return;
        }

        let _ = self.event_tx.send(AppEngineEvent::ParentSealed {
            filter: self.filter.clone(),
            parent_rank,
        });

        // Prune old pending parents (same cutoff as proposals)
        let cutoff = self.current_rank.saturating_sub(10);
        self.pending_certified_parents.retain(|&r, _| r >= cutoff);
    }

    // ---------------------------------------------------------------
    // Missing ancestor collection
    // ---------------------------------------------------------------

    /// Find gaps in the shard frame chain between frame 1 and
    /// `target_rank`. Returns a list of missing frame numbers.
    pub fn collect_missing_ancestors(&self, target_rank: u64) -> Vec<u64> {
        let start = if self.shard_frame_number > 0 {
            self.shard_frame_number
        } else {
            1
        };

        // Don't scan unbounded ranges — cap at 100 lookback
        let scan_start = if target_rank > 100 {
            target_rank.saturating_sub(100).max(start)
        } else {
            start
        };

        let mut missing = Vec::new();
        for frame_num in scan_start..target_rank {
            match self.clock_store.get_shard_clock_frame(
                &self.filter,
                frame_num,
                false, // don't truncate
            ) {
                Ok(_) => {} // frame exists
                Err(_) => {
                    missing.push(frame_num);
                }
            }
        }

        if !missing.is_empty() {
            debug!(
                core_id = self.core_id,
                target_rank,
                gaps = missing.len(),
                "found missing ancestor frames"
            );
        }

        missing
    }

    /// Emit an event requesting sync for the given missing frame numbers.
    /// The master process handles the actual network request.
    pub async fn request_ancestor_sync(&self, missing: &[u64]) {
        if missing.is_empty() {
            return;
        }
        info!(
            core_id = self.core_id,
            filter = hex::encode(&self.filter),
            count = missing.len(),
            first = missing[0],
            last = missing[missing.len() - 1],
            "requesting ancestor sync"
        );
        let _ = self.event_tx.send(AppEngineEvent::AncestorSyncRequested {
            filter: self.filter.clone(),
            missing_frames: missing.to_vec(),
        });
    }

    // ---------------------------------------------------------------
    // Frame store cleanup
    // ---------------------------------------------------------------

    fn cleanup_frame_store(&mut self) {
        // Remove cached frames older than 10 minutes. In practice the
        // frame store grows slowly (one entry per received frame), but
        // we bound memory by evicting stale entries.
        if self.frame_store.len() > 100 {
            // Simple approach: keep only the most recent 50 entries
            let mut entries: Vec<_> = self.frame_store.drain().collect();
            entries.truncate(50);
            self.frame_store = entries.into_iter().collect();
        }
        // Also prune old spillover entries
        let cutoff = self.current_rank.saturating_sub(10);
        self.message_spillover.retain(|&rank, _| rank >= cutoff);
        // Prune old proposal cache and pending parents
        self.drain_proposal_cache();
        self.pending_certified_parents.retain(|&r, _| r >= cutoff);
    }
}

// =====================================================================
// In-memory consensus store for app shards
// =====================================================================

struct AppMemConsensusStore {
    _filter: Vec<u8>,
    consensus: Mutex<Option<quil_consensus::models::ConsensusState<AppShardVote>>>,
    liveness: Mutex<Option<quil_consensus::models::LivenessState>>,
}

impl AppMemConsensusStore {
    fn new(filter: Vec<u8>) -> Self {
        Self {
            _filter: filter,
            consensus: Mutex::new(None),
            liveness: Mutex::new(None),
        }
    }
}

impl quil_consensus::event_handler::ConsensusStore<AppShardVote> for AppMemConsensusStore {
    fn get_consensus_state(
        &self,
        filter: &[u8],
    ) -> Result<quil_consensus::models::ConsensusState<AppShardVote>> {
        match self.consensus.lock().unwrap().clone() {
            Some(state) => Ok(state),
            None => Ok(quil_consensus::models::ConsensusState {
                filter: filter.to_vec(),
                finalized_rank: 0,
                latest_acknowledged_rank: 0,
                latest_timeout: None,
            }),
        }
    }

    fn put_consensus_state(
        &self,
        state: &quil_consensus::models::ConsensusState<AppShardVote>,
    ) -> Result<()> {
        *self.consensus.lock().unwrap() = Some(state.clone());
        Ok(())
    }

    fn get_liveness_state(
        &self,
        filter: &[u8],
    ) -> Result<quil_consensus::models::LivenessState> {
        match self.liveness.lock().unwrap().clone() {
            Some(state) => Ok(state),
            // Mirror the bootstrap fixup applied in `consensus_activation`
            // for the global chain: `current_rank` starts at 1 so the
            // event handler's happy-path check `qc.rank() + 1 == cur_rank`
            // passes against the rank-0 genesis QC. With `current_rank=0`
            // here the loop falls into the recovery branch which
            // requires a `prior_rank_tc` — none exists on a fresh
            // shard, so the engine exits with "expecting TC because QC
            // (0) is not for prior rank (0 - 1)".
            None => Ok(quil_consensus::models::LivenessState {
                filter: filter.to_vec(),
                current_rank: 1,
                // Identity must match the genesis `AppShardState` from
                // `build_app_genesis_certified_state` (output =
                // 32 zero bytes for a fresh shard with no stored
                // frame). Otherwise the event handler can't resolve
                // the parent state and the leader silently waits.
                latest_quorum_certificate: Arc::new(
                    AppGenesisQC::for_output(filter.to_vec(), &vec![0u8; 32], 0),
                ),
                prior_rank_timeout_certificate: None,
            }),
        }
    }

    fn put_liveness_state(
        &self,
        state: &quil_consensus::models::LivenessState,
    ) -> Result<()> {
        *self.liveness.lock().unwrap() = Some(state.clone());
        Ok(())
    }
}

// =====================================================================
// Message validation
// =====================================================================

// Re-export from the canonical location in quil-types.
pub use quil_types::p2p::ValidationResult;

impl AppConsensusEngine {
    /// Validate a consensus message before processing.
    pub fn validate_consensus_message(data: &[u8]) -> ValidationResult {
        if data.len() < 4 {
            return ValidationResult::Reject;
        }

        let tp = u32::from_be_bytes(data[..4].try_into().unwrap());
        match classify_consensus_message(tp) {
            Some(ConsensusMessageKind::AppShardProposal) => {
                // Basic structural validation
                match AppShardProposal::from_canonical_bytes(data) {
                    Ok(_) => ValidationResult::Accept,
                    Err(_) => ValidationResult::Reject,
                }
            }
            Some(ConsensusMessageKind::ProposalVote) => {
                match consensus_wire::ProposalVote::from_canonical_bytes(data) {
                    Ok(_) => ValidationResult::Accept,
                    Err(_) => ValidationResult::Reject,
                }
            }
            Some(ConsensusMessageKind::TimeoutState) => {
                match consensus_wire::TimeoutState::from_canonical_bytes(data) {
                    Ok(_) => ValidationResult::Accept,
                    Err(_) => ValidationResult::Reject,
                }
            }
            Some(ConsensusMessageKind::QuorumCertificate) => {
                match consensus_wire::QuorumCertificate::from_canonical_bytes(data) {
                    Ok(_) => ValidationResult::Accept,
                    Err(_) => ValidationResult::Reject,
                }
            }
            Some(ConsensusMessageKind::TimeoutCertificate) => {
                match consensus_wire::TimeoutCertificate::from_canonical_bytes(data) {
                    Ok(_) => ValidationResult::Accept,
                    Err(_) => ValidationResult::Reject,
                }
            }
            _ => ValidationResult::Ignore,
        }
    }

    /// Validate a prover message (MessageBundle).
    pub fn validate_prover_message(data: &[u8]) -> ValidationResult {
        if data.len() < 4 {
            return ValidationResult::Reject;
        }
        let tp = u32::from_be_bytes(data[..4].try_into().unwrap());
        // MessageBundle type prefix
        if tp == 0x0312 {
            ValidationResult::Accept
        } else if (0x0301..=0x031A).contains(&tp) {
            // Direct prover op
            ValidationResult::Accept
        } else {
            ValidationResult::Ignore
        }
    }

    /// Validate a frame message (AppShardFrame).
    pub fn validate_frame_message(data: &[u8], app_address: &[u8]) -> ValidationResult {
        if let Ok(frame) = <quil_types::proto::global::AppShardFrame as prost::Message>::decode(data) {
            if let Some(h) = frame.header.as_ref() {
                // Address must match this shard
                if h.address != app_address {
                    return ValidationResult::Ignore;
                }
                // Must have a BLS signature
                if h.public_key_signature_bls48581.is_none() {
                    return ValidationResult::Reject;
                }
                ValidationResult::Accept
            } else {
                ValidationResult::Reject
            }
        } else {
            ValidationResult::Reject
        }
    }

    /// Validate a dispatch message (InboxMessage / HubAddInbox / HubDeleteInbox).
    pub fn validate_dispatch_message(data: &[u8]) -> ValidationResult {
        if data.len() < 4 {
            return ValidationResult::Reject;
        }
        // Basic structural check — full validation happens during processing
        ValidationResult::Accept
    }
}

// =====================================================================
// AppShardProposal wire type (wraps consensus_wire for decode)
// =====================================================================

mod consensus_wire_ext {
    use crate::consensus_wire::{
        ProposalVote as WireVote, QuorumCertificate as WireQc,
        TimeoutCertificate as WireTc,
    };
    use quil_execution::global_intrinsic::frame_header::FrameHeader as CanonicalFrameHeader;
    use quil_types::error::{QuilError, Result};

    const TYPE_APP_SHARD_PROPOSAL: u32 = 0x0318;
    const TYPE_APP_SHARD_FRAME: u32 = 0x030F;

    /// Fully-decoded AppShardProposal — mirrors Go's
    /// `protobufs.AppShardProposal.FromCanonicalBytes`.
    pub struct AppShardProposal {
        /// Decoded `AppShardFrame` header.
        pub header: CanonicalFrameHeader,
        /// Inner state bytes (the AppShardFrame canonical-bytes payload).
        /// We keep them around in case downstream wants to re-cache the
        /// raw proposal bytes by rank.
        #[allow(dead_code)]
        pub state_bytes: Vec<u8>,
        pub parent_qc: WireQc,
        pub prior_tc: Option<WireTc>,
        pub vote: WireVote,
    }

    fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32> {
        if *cursor + 4 > data.len() {
            return Err(QuilError::Serialization("short u32 read".into()));
        }
        let v = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into().unwrap());
        *cursor += 4;
        Ok(v)
    }

    fn read_lp(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
        let len = read_u32(data, cursor)? as usize;
        if *cursor + len > data.len() {
            return Err(QuilError::Serialization(format!(
                "short read of {} bytes at offset {} (have {})",
                len,
                *cursor,
                data.len(),
            )));
        }
        let v = data[*cursor..*cursor + len].to_vec();
        *cursor += len;
        Ok(v)
    }

    impl AppShardProposal {
        pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
            if data.len() < 4 {
                return Err(QuilError::Serialization("too short".into()));
            }
            let mut c = 0usize;
            let tp = read_u32(data, &mut c)?;
            if tp != TYPE_APP_SHARD_PROPOSAL {
                return Err(QuilError::Serialization(format!(
                    "expected AppShardProposal type 0x{:08x}, got 0x{:08x}",
                    TYPE_APP_SHARD_PROPOSAL, tp,
                )));
            }

            let state_bytes = read_lp(data, &mut c)?;
            let header = decode_app_shard_frame_header(&state_bytes)?;

            let parent_qc_bytes = read_lp(data, &mut c)?;
            let parent_qc = WireQc::from_canonical_bytes(&parent_qc_bytes)?;

            let prior_tc_bytes = read_lp(data, &mut c)?;
            let prior_tc = if prior_tc_bytes.is_empty() {
                None
            } else {
                Some(WireTc::from_canonical_bytes(&prior_tc_bytes)?)
            };

            let vote_bytes = read_lp(data, &mut c)?;
            let vote = WireVote::from_canonical_bytes(&vote_bytes)?;

            Ok(Self {
                header,
                state_bytes,
                parent_qc,
                prior_tc,
                vote,
            })
        }
    }

    /// Decode the canonical-bytes payload of an `AppShardFrame` enough
    /// to extract the embedded `FrameHeader`. Mirrors Go's
    /// `protobufs.AppShardFrame.FromCanonicalBytes`. The request list is
    /// skipped — proposals carry the full bundle on the wire but the
    /// consensus pipeline only needs the header.
    fn decode_app_shard_frame_header(data: &[u8]) -> Result<CanonicalFrameHeader> {
        let mut c = 0usize;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_APP_SHARD_FRAME {
            return Err(QuilError::Serialization(format!(
                "expected AppShardFrame type 0x{:08x}, got 0x{:08x}",
                TYPE_APP_SHARD_FRAME, tp,
            )));
        }
        let header_bytes = read_lp(data, &mut c)?;
        if header_bytes.is_empty() {
            return Err(QuilError::Serialization(
                "AppShardFrame: empty header".into(),
            ));
        }
        CanonicalFrameHeader::from_canonical_bytes(&header_bytes)
    }
}

// Re-export for handle_app_shard_proposal
use consensus_wire_ext::AppShardProposal;

// =====================================================================
// Wire-format → trait-object conversions for QC/TC submission
// =====================================================================

/// Wrapper that implements `AggregatedSignature` over wire-format data.
#[derive(Debug)]
struct WireAggSig {
    signature: Vec<u8>,
    public_key: Vec<u8>,
    bitmask: Vec<u8>,
}

impl AggregatedSignature for WireAggSig {
    fn signature(&self) -> &[u8] { &self.signature }
    fn public_key(&self) -> &[u8] { &self.public_key }
    fn bitmask(&self) -> &[u8] { &self.bitmask }
}

impl From<&consensus_wire::AggregateSignature> for WireAggSig {
    fn from(agg: &consensus_wire::AggregateSignature) -> Self {
        Self {
            signature: agg.signature.clone(),
            public_key: agg.public_key.clone(),
            bitmask: agg.bitmask.clone(),
        }
    }
}

/// Wrapper implementing `QuorumCertificate` over a decoded wire QC.
#[derive(Debug)]
struct WireQC {
    filter: Vec<u8>,
    rank: u64,
    frame_number: u64,
    /// Hex-encoded selector — used as the trait `Identity`.
    identity: Identity,
    timestamp: u64,
    agg_sig: Arc<dyn AggregatedSignature>,
}

impl QuorumCertificate for WireQC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn frame_number(&self) -> u64 { self.frame_number }
    fn identity(&self) -> &Identity { &self.identity }
    fn timestamp(&self) -> u64 { self.timestamp }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { self.agg_sig.as_ref() }
    fn equals(&self, other: &dyn QuorumCertificate) -> bool {
        self.rank == other.rank() && self.identity == *other.identity()
    }
}

/// Wrapper implementing `TimeoutCertificate` over a decoded wire TC.
#[derive(Debug)]
struct WireTC {
    filter: Vec<u8>,
    rank: u64,
    latest_ranks: Vec<u64>,
    latest_qc: Arc<dyn QuorumCertificate>,
    agg_sig: Arc<dyn AggregatedSignature>,
}

impl TimeoutCertificate for WireTC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
    fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { self.latest_qc.as_ref() }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { self.agg_sig.as_ref() }
    fn equals(&self, other: &dyn TimeoutCertificate) -> bool {
        self.rank == other.rank()
    }
}

/// Build the per-frame `requests_root` for an app shard proposal.
///
/// Mirrors Go's `calculateRequestsRoot` (with the
/// `addAppMessage` framing from `message_processors.go:1316-1322`):
///
/// - per message: `hash = sha3_256(payload)`, address = the shard's
///   32-byte app address, payload = the raw MessageBundle bytes
///   collected from the dispatch bitmask;
/// - call `execution_engine.lock(frame, address, payload)` to get the
///   locked-address vector;
/// - insert `(hash, concat(locked_addresses))` into a
///   `VectorCommitmentTree`;
/// - prepend `sha3_256(tree.commit(prover))[..32]` to
///   `serialize_non_lazy(tree)`.
///
/// Zero messages → 64-byte zero buffer, matching Go.
///
/// Returns `Err` if the engine has messages to commit but the
/// execution engine or inclusion prover are missing — those are
/// required for byte-for-byte parity with Go peers during VDF
/// challenge verification.
fn compute_requests_root(
    messages: &[Vec<u8>],
    app_address: &[u8],
    frame_number: u64,
    execution_engine: Option<&quil_execution::ExecutionEngineManager>,
    inclusion_prover: Option<&dyn quil_types::crypto::InclusionProver>,
) -> Result<Vec<u8>> {
    use sha3::{Digest, Sha3_256};

    if messages.is_empty() {
        return Ok(vec![0u8; 64]);
    }

    let exec = execution_engine.ok_or_else(|| {
        QuilError::Consensus(
            "compute_requests_root: execution engine not wired but messages present".into(),
        )
    })?;
    let prover = inclusion_prover.ok_or_else(|| {
        QuilError::Consensus(
            "compute_requests_root: inclusion prover not wired but messages present".into(),
        )
    })?;

    // Snapshot the address bytes Go uses for the lock call — the shard's
    // 32-byte app address (Poseidon hash of the filter).
    let addr_for_lock: Vec<u8> = if app_address.len() >= 32 {
        app_address[..32].to_vec()
    } else {
        app_address.to_vec()
    };

    let mut tree = quil_tries::VectorCommitmentTree::new();
    for payload in messages {
        let hash: [u8; 32] = Sha3_256::digest(payload).into();
        let locked = exec
            .lock(frame_number, &addr_for_lock, payload)
            .unwrap_or_else(|_| Vec::new());
        let value: Vec<u8> = locked.into_iter().flatten().collect();
        tree.insert(&hash, &value, &[], &num_bigint::BigInt::from(0))?;
    }
    // Mirror Go's `executionManager.Unlock()` call after the per-message
    // lock loop completes.
    let _ = exec.unlock();

    let commitment = tree.commit(prover);
    if commitment.len() != 64 && commitment.len() != 74 {
        return Err(QuilError::Consensus(format!(
            "requests_root: invalid commitment length {}",
            commitment.len()
        )));
    }
    let commit_hash = Sha3_256::digest(&commitment);

    let mut serialized = quil_tries::serialize_tree(tree.root.as_ref())?;
    let mut out = Vec::with_capacity(32 + serialized.len());
    out.extend_from_slice(&commit_hash);
    out.append(&mut serialized);
    Ok(out)
}

/// Convert a decoded wire-format `QuorumCertificate` into a trait object
/// suitable for submission to the HotStuff event loop.
fn wire_qc_to_trait(
    wire: &consensus_wire::QuorumCertificate,
    filter: &[u8],
) -> Arc<dyn QuorumCertificate> {
    Arc::new(WireQC {
        filter: filter.to_vec(),
        rank: wire.rank,
        frame_number: wire.frame_number,
        identity: wire.selector.clone(),
        timestamp: wire.timestamp,
        agg_sig: Arc::new(WireAggSig::from(&wire.aggregate_signature)),
    })
}

/// Convert a decoded wire-format `TimeoutCertificate` into a trait object
/// suitable for submission to the HotStuff event loop.
fn wire_tc_to_trait(
    wire: &consensus_wire::TimeoutCertificate,
    filter: &[u8],
) -> Arc<dyn TimeoutCertificate> {
    // Build the embedded QC (required by the trait). Fall back to a
    // zero-valued genesis QC if the wire TC has no embedded QC.
    let latest_qc: Arc<dyn QuorumCertificate> = match &wire.latest_quorum_certificate {
        Some(inner) => wire_qc_to_trait(inner, filter),
        None => Arc::new(crate::app_types::AppGenesisQC::for_output(
            filter.to_vec(),
            &vec![0u8; 32],
            0,
        )),
    };

    Arc::new(WireTC {
        filter: filter.to_vec(),
        rank: wire.rank,
        latest_ranks: wire.latest_ranks.clone(),
        latest_qc,
        agg_sig: Arc::new(WireAggSig::from(&wire.aggregate_signature)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_short_consensus_message() {
        assert_eq!(
            AppConsensusEngine::validate_consensus_message(&[0, 0]),
            ValidationResult::Reject
        );
    }

    #[test]
    fn validation_ignores_unknown_consensus_type() {
        let data = 0xDEADBEEFu32.to_be_bytes();
        assert_eq!(
            AppConsensusEngine::validate_consensus_message(&data),
            ValidationResult::Ignore
        );
    }

    #[test]
    fn validation_accepts_prover_message_bundle() {
        let mut data = 0x0312u32.to_be_bytes().to_vec();
        data.extend_from_slice(&[0u8; 100]);
        assert_eq!(
            AppConsensusEngine::validate_prover_message(&data),
            ValidationResult::Accept
        );
    }

    #[test]
    fn validation_accepts_direct_prover_op() {
        let data = 0x0301u32.to_be_bytes();
        assert_eq!(
            AppConsensusEngine::validate_prover_message(&data),
            ValidationResult::Accept
        );
    }

    #[test]
    fn validation_ignores_non_prover_message() {
        let data = 0xFFFFu32.to_be_bytes();
        assert_eq!(
            AppConsensusEngine::validate_prover_message(&data),
            ValidationResult::Ignore
        );
    }

    #[test]
    fn validation_rejects_dispatch_too_short() {
        assert_eq!(
            AppConsensusEngine::validate_dispatch_message(&[0]),
            ValidationResult::Reject
        );
    }

    #[test]
    fn app_shard_proposal_wrong_type() {
        let data = 0x0317u32.to_be_bytes();
        assert!(AppShardProposal::from_canonical_bytes(&data).is_err());
    }

    #[test]
    fn app_shard_proposal_too_short() {
        let data = [0u8; 2];
        assert!(AppShardProposal::from_canonical_bytes(&data).is_err());
    }
}
