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
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use quil_consensus::models::{Identity, State, Unique};

use quil_types::consensus::{AppFrameValidator, ProverRegistry};
use quil_types::crypto::FrameProver;
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;

use crate::app_types::AppShardState;

#[path = "app_parent.rs"]
mod app_parent;
pub use app_parent::{AppParentExecutor, PrivateAppParent};
use app_parent::{PRIVATE_PARENT_MESSAGE_BYTES, PRIVATE_PARENT_MESSAGE_ITEMS};
use crate::consensus_wire;
use crate::frame_validator::BlsAppFrameValidator;
use crate::message_collector::MessageCollector;
use crate::message_router::{classify_consensus_message, ConsensusMessageKind};

const CONSENSUS_QUEUE_SIZE: usize = 1000;
const MAX_APP_MESSAGES_PER_RANK: usize = 100;
/// Consecutive `commit_frame` failures on a received frame before it's
/// dropped and repaired via a shard sync instead of retried-from-zero.
const MAX_MATERIALIZE_RETRIES: u32 = 3;

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
    /// A background shard-tree sync converged the CRDT to the state a
    /// finalized header advertised (`state_roots[0]`), catching this node
    /// up to `synced_to_frame`. The engine fast-forwards its
    /// `last_materialized_frame` to this height (the sync supplied the
    /// state for every frame at/below it), persists the durable cursor,
    /// and drops now-stale buffered frames. Without this, a tree sync
    /// would fix CRDT state but leave the materialization cursor behind,
    /// so the gap would re-fire forever and later-arriving full frames
    /// could be re-applied on top of the already-synced tree.
    ShardSyncCompleted { synced_to_frame: u64 },
    /// Authenticate an archive anchor before a background sync mutates the
    /// worker's trees. An accepted request gates propose/vote until completion.
    ValidateShardSyncAnchor {
        anchor: quil_types::proto::global::AppShardFrame,
        predecessor: Option<quil_types::proto::global::AppShardFrame>,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// The certified origin state a shard with no frame of its own syncs
    /// against (`app_handoff::origin_anchors`).
    OriginAnchors {
        reply: tokio::sync::oneshot::Sender<Vec<(Vec<u8>, [[u8; 32]; 4])>>,
    },
    /// A bounded archive fetch supplies one missing finalized frame. Validate
    /// and replay it on the engine actor so derived history advances with data.
    ReplayArchiveFrame {
        frame: quil_types::proto::global::AppShardFrame,
        /// The certified frame after `frame`, when `frame` has no certificate.
        child: Option<quil_types::proto::global::AppShardFrame>,
        reply: tokio::sync::oneshot::Sender<Result<u64>>,
    },
    /// A worker with no local app-shard clock head fetched an archive anchor and
    /// synced its tree to that anchor's pre-state. The engine validates the
    /// certified frames, checkpoints the predecessor, replays the anchor itself
    /// and acknowledges only after installing the resulting lineage.
    ShardBootstrapCompleted {
        anchor: quil_types::proto::global::AppShardFrame,
        predecessor: Option<quil_types::proto::global::AppShardFrame>,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// (commonware-simplex) A frame this shard's simplex engine FINALIZED
    /// (prost-encoded `AppShardFrame`). Routed from `AppSeamFinalizer::on_finalized`
    /// (which runs on the simplex engine thread) into the engine run loop so it
    /// materializes on the worker's `&mut self`. Trusted — simplex already
    /// certified it via quorum — so it SKIPS the BLS-quorum-signature check that
    /// `Frame` requires (a CW frame carries a Falcon certificate, not a BLS
    /// aggregate in the header). `cert` is the serialized simplex finalization
    /// certificate, attached to the reward-coverage bundle for global-level
    /// verification.
    CwFinalizedFrame {
        frame: Vec<u8>,
        cert: Vec<u8>,
        /// Whether this node's application validator sealed these exact bytes
        /// before finalization (vs. a certificate-only replica). Gates the
        /// finalize-time proposal re-validation — see `handle_cw_finalized_frame`.
        locally_verified: bool,
        /// Ancestors this finalization makes final that never finalized on
        /// their own (encoded frames, lowest first, with their verified flag).
        implied: Vec<(Vec<u8>, bool)>,
    },
    /// The running committee session finalized its terminal seal (`seal` bytes,
    /// finalization `cert`). The run loop submits it to the global chain as a
    /// `CommitteeHandoff` and stops extending the closed session.
    CwSealed {
        seal: Vec<u8>,
        cert: Vec<u8>,
    },
    /// An inbound commonware-simplex message from a committee peer, demuxed
    /// from `shard_cw_bitmask` gossip. `channel` = CW channel id; `from` = the
    /// sender's committee Falcon public-key bytes (resolved by the master from
    /// the gossip sender); `data` = the CW message. Fed into the simplex engine
    /// via the `AppConsensusCwHandle` (channels 0/1/2 → `inbound[ch]`, 3 → block).
    CwIn {
        channel: u64,
        from: Vec<u8>,
        data: Vec<u8>,
    },
    /// The master installed the CW subscription and observed a connected peer.
    /// Do not start simplex before this barrier: earlier messages failed with
    /// `NoPeersSubscribedToTopic` and were historically discarded.
    CwTransportReady,
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
    /// A finalized shard frame, fully assembled as a prost
    /// `AppShardFrame { header, requests }` — published on
    /// `shard_frame_bitmask` so followers and archives can decode,
    /// verify (`requests` vs the reward-proof `requests_root`), and
    /// materialize the shard's state. This is the authoritative
    /// state-distribution channel; `FrameProduced` (proposal-time,
    /// header-only) is unrelated.
    FullFrameProduced {
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
    /// Engine requests a PROACTIVE bootstrap of the covered shard's committed
    /// DATA into its own CRDT — emitted on becoming bound (Joining) with no local
    /// data, so the member is staged BEFORE it must produce/attest at Active
    /// (rather than waiting for a consensus catch-up trigger that never fires
    /// while it produces on empty state). Handled identically to the
    /// [`Self::AncestorSyncRequested`] bootstrap by the worker's shard syncer.
    ShardDataBootstrapRequested {
        filter: Vec<u8>,
    },
    /// A certified parent was sealed (state committed via materializer).
    ParentSealed {
        filter: Vec<u8>,
        parent_rank: u64,
    },
    /// An outbound commonware-simplex message for this shard's committee.
    /// `channel` is the CW channel id (0=vote,1=cert,2=resolver,3=block). The
    /// master publishes it on `shard_cw_bitmask` with the channel tagged in the
    /// payload (`shard_cw_frame_payload`); peers demux it back to this shard's
    /// engine `CwIn`. Emitted by the engine's `AppConsensusTransport`.
    CwOut {
        filter: Vec<u8>,
        channel: u64,
        bytes: Vec<u8>,
        /// The committee keys it is addressed to, for the resolver channel
        /// only (empty otherwise): a node may deliver it to just those
        /// members, falling back to the topic.
        recipients: Vec<Vec<u8>>,
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
    cancel: CancellationToken,
    materialized: Arc<std::sync::atomic::AtomicU64>,
    pub filter: Vec<u8>,
    msg_tx: mpsc::Sender<AppEngineMessage>,
    sizes: SharedAppEngineSizes,
    execution: crate::worker_execution::SharedWorkerExecution,
    fee_snapshot: Arc<std::sync::Mutex<Option<quil_execution::pricing::AppFeeSnapshot>>>,
}

impl AppEngineHandle {
    pub fn execution(&self) -> quil_types::proto::node::WorkerExecution { self.execution.snapshot() }
    pub fn execution_state(&self, state: &str, blocker: &str) { self.execution.state(state, blocker); }
    /// A handle for `filter` whose messages arrive on the returned receiver.
    #[cfg(test)]
    pub(crate) fn for_test(filter: Vec<u8>) -> (Self, mpsc::Receiver<AppEngineMessage>) {
        let (msg_tx, receiver) = mpsc::channel(16);
        let handle = Self {
            cancel: CancellationToken::new(),
            materialized: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            filter,
            msg_tx,
            sizes: SharedAppEngineSizes::new(),
            execution: Default::default(),
            fee_snapshot: Arc::new(std::sync::Mutex::new(None)),
        };
        (handle, receiver)
    }

    /// Request cooperative shutdown. The task owner must also await its join.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// Send a message to the app engine (non-blocking, drops on full).
    pub fn send(&self, msg: AppEngineMessage) {
        let _ = self.msg_tx.try_send(msg);
    }

    pub(crate) async fn validate_sync_anchor(
        &self,
        anchor: quil_types::proto::global::AppShardFrame,
        predecessor: Option<quil_types::proto::global::AppShardFrame>,
    ) -> Result<bool> {
        let (reply, receive) = tokio::sync::oneshot::channel();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            self.msg_tx.send(AppEngineMessage::ValidateShardSyncAnchor { anchor, predecessor, reply })
                .await.map_err(|_| QuilError::ExecutionUnavailable("shard engine stopped before sync validation".into()))?;
            receive.await.map_err(|_| QuilError::ExecutionUnavailable("shard sync validation was cancelled".into()))
        }).await.map_err(|_| QuilError::ExecutionUnavailable("shard sync validation timed out".into()))?
    }

    pub(crate) async fn origin_anchors(&self) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
        let (reply, receive) = tokio::sync::oneshot::channel();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            self.msg_tx.send(AppEngineMessage::OriginAnchors { reply })
                .await.map_err(|_| QuilError::ExecutionUnavailable("shard engine stopped before origin lookup".into()))?;
            receive.await.map_err(|_| QuilError::ExecutionUnavailable("origin lookup was cancelled".into()))
        }).await.map_err(|_| QuilError::ExecutionUnavailable("origin lookup timed out".into()))?
    }

    pub(crate) async fn complete_archive_sync(
        &self,
        anchor: quil_types::proto::global::AppShardFrame,
        predecessor: Option<quil_types::proto::global::AppShardFrame>,
    ) -> Result<()> {
        let (reply, receive) = tokio::sync::oneshot::channel();
        self.msg_tx.send(AppEngineMessage::ShardBootstrapCompleted { anchor, predecessor, reply }).await
            .map_err(|_| QuilError::ExecutionUnavailable("shard engine stopped before sync completion".into()))?;
        // Keep the worker's in-flight guard until the actor finishes. A timeout
        // here could start another tree install during the first anchor replay.
        // Actor shutdown drops the reply and releases the waiting worker.
        let installed = receive.await
            .map_err(|_| QuilError::ExecutionUnavailable("shard sync completion was cancelled".into()))?;
        if installed { Ok(()) } else {
            Err(QuilError::ExecutionUnavailable("shard engine rejected sync completion".into()))
        }
    }

    pub(crate) fn materialized_frame(&self) -> u64 {
        self.materialized.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) async fn replay_archive_frame(
        &self,
        frame: quil_types::proto::global::AppShardFrame,
        child: Option<quil_types::proto::global::AppShardFrame>,
    ) -> Result<u64> {
        let (reply, receive) = tokio::sync::oneshot::channel();
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            self.msg_tx.send(AppEngineMessage::ReplayArchiveFrame { frame, child, reply })
                .await.map_err(|_| QuilError::ExecutionUnavailable("shard engine stopped before archive replay".into()))?;
            receive.await.map_err(|_| QuilError::ExecutionUnavailable("archive replay was cancelled".into()))?
        }).await.map_err(|_| QuilError::ExecutionUnavailable("archive replay timed out".into()))?
    }

    /// Tell the engine whether the network is in a coverage halt. The
    /// engine forwards the value to its leader provider so propose
    /// attempts during the halt window are skipped.
    pub fn set_halted(&self, halted: bool) {
        let _ = self.msg_tx.try_send(AppEngineMessage::SetHalted(halted));
    }

    /// Release the CW startup barrier after the master observes a usable peer.
    pub fn set_cw_transport_ready(&self) {
        let _ = self.msg_tx.try_send(AppEngineMessage::CwTransportReady);
    }

    pub(crate) async fn send_cw_transport_ready(&self) -> bool {
        self.msg_tx.send(AppEngineMessage::CwTransportReady).await.is_ok()
    }

    /// Only a quote for the current materialized cursor is available. A new
    /// commit is hidden until the engine advances that cursor; sync/restart
    /// without captured pricing inputs yields no quote.
    pub fn fee_snapshot(&self) -> Option<quil_execution::pricing::AppFeeSnapshot> {
        if self.msg_tx.is_closed() { return None; }
        let snapshot = *self.fee_snapshot.lock().ok()?;
        snapshot.filter(|s| s.frame_number == self.materialized.load(std::sync::atomic::Ordering::SeqCst))
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
// AppLeaderProvider — produces shard frames with deterministic outputs
// =====================================================================

/// App-shard proposal/QC cadence in milliseconds. Production paces frames at
/// 10 s (the leader defers its proposal broadcast and the aggregator defers QC
/// submission to `rank_entry + proposal_duration`). Tests set this small so the
/// in-process multi-node harness reaches finalization quickly without the
/// proposal-broadcast deferral desyncing votes from proposals. A process-global
/// knob mirroring `verify::set_confirm_window_frames`.
static APP_PROPOSAL_DURATION_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(10_000);

/// Override the app-shard proposal/QC cadence (milliseconds). Test-only.
pub fn set_app_proposal_duration_ms(ms: u64) {
    APP_PROPOSAL_DURATION_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}

/// The configured app-shard proposal/QC cadence.
fn app_proposal_duration() -> Duration {
    Duration::from_millis(APP_PROPOSAL_DURATION_MS.load(std::sync::atomic::Ordering::Relaxed))
}

/// No-op transaction for direct clock-store writes (the RocksClockStore takes a
/// direct-write fallback when the txn isn't its own `RocksClockTxn`). Used to
/// persist received global frames into a cluster worker's clock store.
struct AppNoopTxn;
impl quil_types::store::Transaction for AppNoopTxn {
    fn get(&self, _: &[u8]) -> Result<Option<Vec<u8>>> { Ok(None) }
    fn set(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn delete(&self, _: &[u8]) -> Result<()> { Ok(()) }
    fn delete_range(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
    fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
    fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
    fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn quil_types::store::Iterator>> {
        Err(QuilError::Internal("iterator not supported on AppNoopTxn".into()))
    }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

struct AppLeaderProvider {
    filter: Vec<u8>,
    clock_store: Arc<dyn ClockStore>,
    /// Shared with the engine: fee totals of materialized frames, so the
    /// proposal carries the previous frame's total (`FrameHeader.fee_total`).
    frame_outflows: Arc<FrameOutflows>,
    /// Store to resolve the GLOBAL anchor (`anchor_gfn`/ρ_N) from — the
    /// master's clock_store on a worker; equals `clock_store` elsewhere. See
    /// `AppEngineDeps::global_anchor_store`.
    global_anchor_store: Arc<dyn ClockStore>,
    frame_prover: Arc<dyn FrameProver>,
    prover_registry: Arc<dyn ProverRegistry>,
    message_collector: Arc<MessageCollector>,
    /// The engine's own collector. A proposal over a private parent collects
    /// from a copy (`message_collector`); what it holds back or finds already
    /// decided still has to reach this one.
    mempool: Arc<MessageCollector>,
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
    /// Storage-attestation SOURCE crdt = the MASTER's hypergraph (holds the
    /// covered shard's committed coin data, forest-synced). The prover REPLICATES
    /// from this into its OWN per-worker `replica_store` (`kv_db`) and attests
    /// those replicas — true per-prover PoRep possession. Distinct from
    /// `hypergraph` (the per-worker app-shard state). None → fall back to
    /// `hypergraph` (archive/tests, where a single crdt holds everything).
    storage_source_hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// When this shard, retiring through a recorded split or merge, may only
    /// finalize empty frames (`crate::shard_drain`). `None`: never.
    pub(crate) shard_drain: Option<Arc<crate::shard_drain::ShardDrain>>,
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
    /// Shared mirror of the engine's `shard_mat_frame` (last materialized shard
    /// frame). STRICT GATE: never propose frame N until this node has applied
    /// N-1. A worker MAY skip old frames and catch up (state-jump / shard sync),
    /// but once it produces it must be materialized to the parent — mirroring the
    /// global `compute_prover_root` gate. Without this a lagging proposer emits a
    /// stale-`state_roots` frame that voters (fail-closed at N-1) only reject
    /// after the fact.
    shard_mat_frame: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Requests this node collected per frame it proposed, decoded to
    /// proto `MessageBundle`s. The leader (writer) records the bundles
    /// it included when proving a frame; the engine (reader) retrieves
    /// them at finalization to (a) self-materialize and (b) assemble the
    /// FULL `AppShardFrame{header, requests}` published on
    /// `shard_frame_bitmask` so archives/followers can materialize.
    /// `requests_root` is computed over these bundles' canonical
    /// encodings, so it is recomputable/verifiable from the frame.
    frame_requests: Arc<std::sync::Mutex<
        std::collections::HashMap<u64, Vec<quil_types::proto::global::MessageBundle>>,
    >>,
    /// KV backing the member's persisted PoRep replicas. Present iff this node
    /// participates in storage (built into a `ReplicaStore` in `prove_next_state`
    /// to assemble the proposer's self storage-attestation).
    kv_db: Option<Arc<dyn quil_types::store::KvDb>>,
    /// Serialized `StorageAttestation` (openings) this node assembled for each
    /// frame it proposed, keyed by frame number. Shared `Arc<Mutex>` with the
    /// engine: the leader (writer) stashes the blob at prove time; the engine's
    /// `AppFrameAssembler` (reader) attaches it to the full `AppShardFrame` so
    /// followers/archives + the global reward audit see the openings. Mirrors
    /// `frame_requests`. Under commonware-simplex, votes carry no payload, so this
    /// is a PROPOSER SELF-attestation (single member = the frame's prover), NOT
    /// the legacy multi-member committee attestation assembled from vote openings.
    frame_attestations: Arc<std::sync::Mutex<std::collections::HashMap<u64, Vec<u8>>>>,
    /// Order-independent fingerprint of THIS CW instance's committee (the fixed
    /// simplex validator set built at `start_consensus_cw`). The finalization
    /// cert a proposed frame receives is signed by exactly this committee, but
    /// every verifier reconstructs the committee from the frame's stamped
    /// `global_frame_number`. If the active set moved since this instance was
    /// built (epoch boundary, deferred activation, empty-committee floor), the
    /// cert becomes unverifiable — so `prove_next_state` declines to propose
    /// until the run loop rebuilds the instance. See `AppConsensusEngine::committee_fp`.
    /// `None` under an authorized committee session: its members are fixed by
    /// GLOBAL authorization and verifiers resolve them by generation, so a
    /// registry change cannot make the certificate unverifiable.
    instance_committee_fp: Option<[u8; 32]>,
    /// Set for an authorized committee session with a virtual genesis. Unset
    /// for generation zero, which chains on its legacy frames.
    session_genesis: Option<SessionGenesis>,
    /// Runs under an authorized committee session, generation zero included.
    under_session: bool,
    /// Raised by the session's parent reader while its closing request is
    /// pending: frames stay request-free so the last outflows get relayed and
    /// the terminal seal can follow (`app_handoff::DRAIN_FRAMES`).
    session_closing: Arc<std::sync::atomic::AtomicBool>,
    /// Builds on a private selected-parent branch: never syncs shard data or
    /// seals replicas into the canonical stores.
    private_parent: bool,
    /// When each bundle reached this shard, for the routing fallback
    /// (`routed_selection`); shared with the engine, which stamps arrivals.
    routing_seen: RoutingClock,
}

/// When each submission reached a shard's collector, keyed by the SHA3 of its
/// canonical bytes: the routing fallback counts a helper's wait from arrival.
/// Counted from a shard's first collection instead, a helper whose leaders
/// seldom reached collection was admitted long after its turn.
type RoutingClock = Arc<std::sync::Mutex<HashMap<[u8; 32], RoutingSeen>>>;

#[derive(Clone, Copy)]
struct RoutingSeen {
    arrived: std::time::Instant,
    /// Whether this shard has logged holding it for its designated shard.
    logged: bool,
}

/// How long an arrival stays stamped once no collection holds it.
const ROUTING_CLOCK_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// How long each collected bundle has waited since it reached this shard, and
/// whether this is the first collection to hold it. A bundle without a stamped
/// arrival starts waiting now; a bundle without confidential operations does
/// not wait. Stamps that no collection holds expire after
/// [`ROUTING_CLOCK_TTL`].
fn routing_waits(
    clock: &RoutingClock,
    hashes: &[[u8; 32]],
    operations: &[usize],
    now: std::time::Instant,
) -> (Vec<std::time::Duration>, Vec<bool>) {
    let mut seen = clock.lock().unwrap_or_else(|e| e.into_inner());
    seen.retain(|hash, entry| hashes.contains(hash) || now.saturating_duration_since(entry.arrived) < ROUTING_CLOCK_TTL);
    hashes.iter().zip(operations).map(|(hash, ops)| {
        if *ops == 0 {
            return (std::time::Duration::ZERO, false);
        }
        let entry = seen.entry(*hash).or_insert(RoutingSeen { arrived: now, logged: false });
        let first = !std::mem::replace(&mut entry.logged, true);
        (now.saturating_duration_since(entry.arrived), first)
    }).unzip()
}

fn stamp_arrival(clock: &RoutingClock, canonical: &[u8], now: std::time::Instant) {
    use sha3::{Digest, Sha3_256};
    let hash: [u8; 32] = Sha3_256::digest(canonical).into();
    clock.lock().unwrap_or_else(|e| e.into_inner())
        .entry(hash)
        .or_insert(RoutingSeen { arrived: now, logged: false });
}

/// Anchor to `latest − K`, not the bleeding-edge head: app-shard committees are
/// multi-member and each member's synced global head differs by a few frames, so
/// anchoring to a private latest would fork cross-member verification. `K` is a
/// small safety margin (≤ the lockstep window `W`) that keeps the anchor on a
/// frame all members already hold.
const GLOBAL_ANCHOR_SAFETY_MARGIN: u64 = quil_execution::token_intrinsic::constants::GLOBAL_ANCHOR_SAFETY_MARGIN;

/// Resolve the GLOBAL anchor `(frame_number, output)` an app shard binds to:
/// `latest_global − K`, present in every member's store. `(0, empty)` when the
/// global chain is shorter than the margin (the zero-anchor beacon). The
/// frame the producer stamps as `header.global_frame_number` is this number, so
/// proposer and verifier resolve the SAME committee epoch from it.
///
/// Free function so BOTH the `AppLeaderProvider` (propose/leader) and the
/// `AppConsensusEngine` (CW committee activation) compute the identical anchor.
pub(crate) fn resolve_global_anchor(store: &dyn ClockStore) -> (u64, Vec<u8>) {
    let gf_to_anchor = |f: quil_types::proto::global::GlobalFrame| -> (u64, Vec<u8>) {
        let n = f.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
        let o = f.header.as_ref().map(|h| h.output.clone()).unwrap_or_default();
        (n, o)
    };
    let latest_gfn = store
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    if latest_gfn > GLOBAL_ANCHOR_SAFETY_MARGIN {
        let target = latest_gfn - GLOBAL_ANCHOR_SAFETY_MARGIN;
        match store.get_global_clock_frame(target) {
            Ok(f) => gf_to_anchor(f),
            Err(_) => match store.get_latest_global_clock_frame() {
                Ok(f) => gf_to_anchor(f),
                Err(_) => (0u64, Vec::new()),
            },
        }
    } else if latest_gfn > 0 {
        match store.get_latest_global_clock_frame() {
            Ok(f) => gf_to_anchor(f),
            Err(_) => (0u64, Vec::new()),
        }
    } else {
        (0u64, Vec::new())
    }
}

/// The 32-byte application a shard filter belongs to. A sub-shard's filter is
/// the application address followed by its path; only a whole-application
/// shard's filter IS the address. Records keyed by application (the fee and
/// anchor snapshot wallets and mint-claim witnesses read) must use this, or a
/// split application silently publishes none.
pub(crate) fn application_of_filter(filter: &[u8]) -> Option<[u8; 32]> {
    filter.get(..32)?.try_into().ok()
}

/// A proposal must extend Simplex's chosen parent, not a different local tip.
fn cw_app_parent(
    latest: Result<quil_types::proto::global::AppShardFrame>,
    filter: &[u8],
    prior_frame_number: u64,
    prior_identity: &[u8],
) -> Result<Option<quil_types::proto::global::FrameHeader>> {
    let header = match latest {
        Ok(frame) => frame.header.ok_or_else(|| QuilError::Internal(
            "app consensus parent frame has no header".into(),
        ))?,
        Err(QuilError::NotFound(_)) => {
            if prior_frame_number == 0
                && prior_identity == quil_crypto::poseidon::hash_bytes_to_32(&[0; 32])?
            {
                return Ok(None);
            }
            return Err(QuilError::NoVote("chosen app consensus parent is not available locally".into()));
        }
        Err(error) => return Err(error),
    };
    if header.address != filter || header.frame_number != prior_frame_number
        || quil_crypto::poseidon::hash_bytes_to_32(&header.output)? != prior_identity
    {
        return Err(QuilError::NoVote(
            "chosen app consensus parent differs from the local shard head; wait for catch-up".into(),
        ));
    }
    Ok(Some(header))
}

/// The authorized virtual genesis of a committee session, as the leader needs
/// it: the first data frame extends `output` (identity `id`) at `base_frame`.
#[derive(Clone, Debug)]
pub(crate) struct SessionGenesis {
    pub base_frame: u64,
    pub id: [u8; 32],
    pub output: Vec<u8>,
}

/// [`cw_app_parent`] for a committee session. Returns the local parent header
/// (frame number, anchor, timestamp) and the output the new header must name as
/// its predecessor. A session's first frame names the authorized genesis, never
/// the predecessor committee's last output, and no later frame may reach below
/// the session's base.
fn cw_session_parent(
    latest: Result<quil_types::proto::global::AppShardFrame>,
    filter: &[u8],
    prior_frame_number: u64,
    prior_identity: &[u8],
    genesis: Option<&SessionGenesis>,
) -> Result<(Option<quil_types::proto::global::FrameHeader>, Vec<u8>)> {
    let Some(genesis) = genesis else {
        let header = cw_app_parent(latest, filter, prior_frame_number, prior_identity)?;
        let output = header.as_ref().map(|h| h.output.clone()).unwrap_or_else(|| vec![0; 32]);
        return Ok((header, output));
    };
    if prior_identity == genesis.id && prior_frame_number == genesis.base_frame {
        let header = match latest {
            Ok(frame) => Some(frame.header.ok_or_else(|| QuilError::Internal(
                "app consensus parent frame has no header".into(),
            ))?),
            Err(QuilError::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        let local = header.as_ref().map_or(0, |h| h.frame_number);
        if local != genesis.base_frame || header.as_ref().is_some_and(|h| h.address != filter) {
            return Err(QuilError::NoVote(
                "local shard head is not the session's base frame; wait for recovery".into(),
            ));
        }
        return Ok((header, genesis.output.clone()));
    }
    let header = cw_app_parent(latest, filter, prior_frame_number, prior_identity)?
        .filter(|h| h.frame_number > genesis.base_frame)
        .ok_or_else(|| QuilError::NoVote(
            "chosen parent precedes the committee session's genesis".into(),
        ))?;
    let output = header.output.clone();
    Ok((Some(header), output))
}

impl AppLeaderProvider {
    /// A leader over a private selected-parent branch: its frame chain, state,
    /// execution manager and outflows, the parent as the materialized height,
    /// and a copy of the pending messages (collection would prune the public
    /// window). A frame proposed without existing replicas carries no storage
    /// attestation; this leader never seals.
    fn for_parent(&self, parent: &PrivateAppParent, rank: u64) -> Result<Self> {
        let collector = Arc::new(MessageCollector::new());
        for bytes in self.message_collector.snapshot_for_execution(
            rank,
            PRIVATE_PARENT_MESSAGE_BYTES,
            PRIVATE_PARENT_MESSAGE_ITEMS,
        )? {
            collector.add_message(rank, bytes);
        }
        Ok(Self {
            filter: self.filter.clone(),
            clock_store: parent.clock.clone(),
            frame_outflows: parent.outflows.clone(),
            global_anchor_store: self.global_anchor_store.clone(),
            frame_prover: self.frame_prover.clone(),
            prover_registry: self.prover_registry.clone(),
            message_collector: collector,
            mempool: self.mempool.clone(),
            fee_manager: self.fee_manager.clone(),
            local_prover_address: self.local_prover_address.clone(),
            local_public_key: self.local_public_key.clone(),
            current_difficulty: self.current_difficulty.clone(),
            reward_greedy: self.reward_greedy,
            hypergraph: Some(parent.crdt.clone()),
            storage_source_hypergraph: self.storage_source_hypergraph.clone(),
            shard_drain: self.shard_drain.clone(),
            execution_engine: Some(parent.manager.clone()),
            inclusion_prover: self.inclusion_prover.clone(),
            app_address: self.app_address.clone(),
            halted: self.halted.clone(),
            min_active_provers_for_propose: self.min_active_provers_for_propose,
            shard_mat_frame: Arc::new(std::sync::atomic::AtomicU64::new(parent.frame_number)),
            frame_requests: self.frame_requests.clone(),
            kv_db: self.kv_db.clone(),
            frame_attestations: self.frame_attestations.clone(),
            routing_seen: self.routing_seen.clone(),
            instance_committee_fp: self.instance_committee_fp,
            session_genesis: self.session_genesis.clone(),
            under_session: self.under_session,
            session_closing: self.session_closing.clone(),
            private_parent: true,
        })
    }

    fn resolve_global_anchor(&self) -> (u64, Vec<u8>) {
        resolve_global_anchor(self.global_anchor_store.as_ref())
    }

    /// The GLOBAL frame whose EPOCH defines this shard's committee. Prover
    /// lifecycle (join/leave activation, epoch re-confirm) is GLOBAL-frame-defined
    /// (`JoinConfirmFrameNumber`/`Epoch` are written by the global intrinsic), so
    /// the committee MUST be read at a global frame — the app-shard-local counter
    /// is UNRELATED to global (it free-runs), so evaluating `effective_status`
    /// against it compared app-shard-epochs to global-epoch thresholds. Use the
    /// same `latest − K` anchor the frame stamps, so proposer and verifier agree.
    fn committee_anchor_gfn(&self) -> u64 {
        self.resolve_global_anchor().0
    }
}

impl quil_consensus::leader_provider::LeaderProvider<AppShardState> for AppLeaderProvider {
    fn get_next_leaders(&self, _prior: Option<&State<AppShardState>>) -> Result<Vec<Identity>> {
        // Committee epoch is GLOBAL-frame-defined (lifecycle activation/expiry are
        // global-chain events), so read the committee at the GLOBAL anchor, NOT
        // the app-shard-local clock tip (which is unrelated to global). Every
        // member resolves the same `latest − K` anchor → same epoch → same
        // leader set. See `committee_anchor_gfn`.
        let committee_frame = self.committee_anchor_gfn();
        let provers = self.prover_registry.get_active_provers(&self.filter, committee_frame)?;
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
        prior_frame_number: u64,
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
        // mainnet shard repeatedly prepares frames it cannot finalize
        // — the sole proposer re-stages the same frame across hundreds
        // of ranks without ever committing.
        //
        // `NoVote` (not `Consensus`) for the same reason as the
        // halt gate above — bubbling a `Consensus` error here
        // kills the event loop. Caught by
        // `propose_for_new_rank_if_primary`'s `is_no_vote` arm.
        // Resolve the GLOBAL anchor ONCE, up front: it defines BOTH the committee
        // epoch (below) AND the frame's `global_frame_number`/ρ_N (further down),
        // and they MUST be the same value so the verifier — which reads
        // `header.global_frame_number` — reconstructs the identical committee.
        // (Reading `latest_global` twice could straddle a newly-arrived global
        // frame and desync the committee from the header.)
        let (anchor_gfn, anchor_output) = self.resolve_global_anchor();
        tracing::debug!(
            prior_frame_number,
            anchor_gfn,
            latest_stored_global = self.global_anchor_store.get_latest_global_clock_frame().ok()
                .and_then(|f| f.header.map(|h| h.frame_number)),
            "app proposal global anchor",
        );
        // Committee epoch is GLOBAL-frame-defined; read it at the anchor, NOT the
        // app-shard-local clock tip (unrelated to global). See `committee_anchor_gfn`.
        let committee_frame = anchor_gfn;
        let active = self
            .prover_registry
            .get_active_provers(&self.filter, committee_frame)
            .unwrap_or_default();
        let active_count = active.len();
        if (active_count as u64) < self.min_active_provers_for_propose {
            return Err(QuilError::NoVote(format!(
                "shard has {} active prover(s); minimum {} required to propose",
                active_count,
                self.min_active_provers_for_propose,
            )));
        }
        // Epoch-straddle guard — prevents an UNVERIFIABLE finalization cert.
        // The cert this frame will get is signed by THIS simplex instance's
        // fixed committee. Every verifier instead reconstructs the committee
        // from the frame's stamped `global_frame_number` (= `anchor_gfn` here) —
        // i.e. the CURRENT active set at that anchor. If that set has moved
        // since this instance was built (an epoch boundary crossed, a prover's
        // deferred activation reached its epoch, or the empty-committee floor
        // shifted), the cert is signed by a committee no verifier reconstructs
        // and the frame is permanently unverifiable (the persistent
        // "app shard frame CW finalization cert verification failed" storm).
        // Decline to propose until the run loop's committee-change detection
        // rebuilds the instance with the current set (≤ the 10s `cw_retry_timer`).
        // NoVote (not Consensus) → the view nullifies without killing the loop.
        let current_fp = AppConsensusEngine::committee_fp(
            &active.iter().map(|p| p.public_key.clone()).collect::<Vec<_>>(),
        );
        if self.instance_committee_fp.is_some_and(|fp| fp != current_fp) {
            return Err(QuilError::NoVote(
                "active committee moved since the CW instance was built — declining \
                 to propose until it rebuilds (prevents an unverifiable cross-committee \
                 finalization cert)"
                    .to_string(),
            ));
        }
        // Effective-Active proposing gate (storage frames only). A prover that is
        // NOT yet effective-`Active` for THIS shard at the frame's epoch (freshly
        // joined + still inside its deferred-activation epoch, or admitted only by
        // the empty-committee floor) has no storage leaf-root registration for the
        // CURRENT epoch — its confirm registers "encode-ahead" for the NEXT epoch.
        // Proposing a storage frame now produces an attestation whose leaf roots are
        // for a future epoch, so no verifier matches it and the finalized frame is
        // dropped ("app shard frame storage attestation rejected") — the shard
        // stalls. Decline until this prover is Active for the epoch it would anchor
        // to. Consensus stays live (the floor keeps the committee non-empty) but
        // never mints an unverifiable storage frame.
        if anchor_gfn > 0 {
            let eff_active = self
                .prover_registry
                .get_prover_info(&self.local_prover_address)
                .ok()
                .flatten()
                .map(|info| {
                    info.allocations.iter().any(|a| {
                        a.confirmation_filter == self.filter
                            && match a.effective_status(anchor_gfn) {
                                quil_types::consensus::EffectiveStatus::Active => true,
                                // A session member that has asked to leave still
                                // holds this epoch's leaf roots, and its session
                                // needs request-free frames before it can seal.
                                quil_types::consensus::EffectiveStatus::Leaving => self.under_session,
                                _ => false,
                            }
                    })
                })
                .unwrap_or(false);
            if !eff_active {
                return Err(QuilError::NoVote(
                    "local prover not effective-Active for this shard at the frame's \
                     epoch — declining to propose (storage attestation would have no \
                     current-epoch leaf roots)"
                        .to_string(),
                ));
            }
        }
        let (parent_header, previous_frame_output) = cw_session_parent(
            self.clock_store.get_latest_shard_clock_frame(&self.filter),
            &self.filter, prior_frame_number, prior_state_id, self.session_genesis.as_ref(),
        )?;
        let prior_frame_number = parent_header.as_ref().map_or(0, |h| h.frame_number);
        let parent_anchor_gfn = parent_header.as_ref().map_or(0, |h| h.global_frame_number);
        let frame_number = prior_frame_number.checked_add(1).ok_or_else(||
            QuilError::NoVote("app shard frame number exhausted".into()))?;

        // CADENCE GATE: pace app-shard production to the GLOBAL anchor. The
        // global materializer folds EVERY app-shard frame produced between two
        // global frames into the next global frame's `requests`; a shard finalizing
        // many frames per global frame balloons that request set (N× attestation
        // verifies + apply-due tombstone scans), slowing the global chain, which lets
        // still more shard frames accumulate — a feedback loop. Bound it to ≤1 frame
        // per global anchor: decline until the global head has advanced past the
        // parent frame's anchor. The decision reads the PARENT's committed anchor
        // (which every node agrees on), so rotating leaders cannot collectively
        // out-run the global cadence — after a frame anchored at G, none propose the
        // next until their global head passes G. Only in storage-frame mode
        // (`anchor_gfn > 0`) and past genesis; rewards are per-global-frame, so at
        // most one rewardable shard frame per global frame is the intended rate.
        // NoVote → the view nullifies without killing the loop (mirrors the guards
        // above); the leader resumes the instant the global head advances.
        if anchor_gfn > 0 && prior_frame_number > 0 && anchor_gfn <= parent_anchor_gfn {
            return Err(QuilError::NoVote(format!(
                "app-shard cadence gate: global anchor {anchor_gfn} has not advanced \
                 past parent frame {prior_frame_number}'s anchor {parent_anchor_gfn} — \
                 pacing production to \u{2264}1 shard frame per global frame",
            )));
        }

        // STRICT GATE (mirrors the global `compute_prover_root`): never produce
        // frame N until this node has MATERIALIZED the parent N-1. `state_roots`
        // below reads the committed shard state and MUST equal N-1's — a lagging
        // proposer would otherwise emit a stale root that voters (fail-closed at
        // N-1) reject after the fact. Catching up is fine (skip old frames via
        // shard sync); producing on unapplied state is not. `NoVote` = skip this
        // round (not `Consensus`, which would kill the event loop); the node
        // resumes proposing once its materializer reaches N-1.
        if prior_frame_number > 0 {
            let materialized =
                self.shard_mat_frame.load(std::sync::atomic::Ordering::SeqCst);
            if materialized < prior_frame_number {
                return Err(QuilError::NoVote(format!(
                    "cannot produce shard frame {frame_number}: parent {prior_frame_number} \
                     not materialized (at {materialized}) — catching up",
                )));
            }
        }

        // Collect pending messages (raw canonical bytes from the
        // dispatch bitmask), then decode each into a proto MessageBundle.
        // These bundles ARE the frame's `requests`: they get published in
        // the full AppShardFrame at finalization and materialized into
        // shard state. `requests_root` is computed below over their
        // canonical RE-encodings (not the raw collected bytes) so that an
        // archive can recompute it byte-for-byte from `frame.requests`.
        // A shard a recorded split or merge is retiring finalizes only empty
        // frames near its flip: GLOBAL may refuse them (crate::shard_drain).
        let draining = self.shard_drain.as_ref().is_some_and(|drain| drain.drains_at(anchor_gfn));
        if draining {
            info!(frame = frame_number, anchor = anchor_gfn, "retiring shard drains: proposing an empty frame");
        }
        let raw_messages = if draining || self.session_closing.load(std::sync::atomic::Ordering::Acquire) {
            Vec::new()
        } else {
            self.message_collector.collect_for_rank(rank)
        };
        let mut request_bundles: Vec<quil_types::proto::global::MessageBundle> =
            Vec::with_capacity(raw_messages.len());
        let mut canonical_requests: Vec<Vec<u8>> = Vec::with_capacity(raw_messages.len());
        // The collected message each kept bundle came from.
        let mut origins: Vec<usize> = Vec::with_capacity(raw_messages.len());
        for (index, raw) in raw_messages.iter().enumerate() {
            match crate::consensus_wire::decode_message_bundle(raw) {
                Ok(bundle) => {
                    match crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundle) {
                        Ok(canon) => {
                            canonical_requests.push(canon);
                            request_bundles.push(bundle);
                            origins.push(index);
                        }
                        Err(e) => debug!(error = %e, "dropping un-re-encodable request bundle"),
                    }
                }
                Err(e) => debug!(error = %e, "dropping undecodable dispatch message"),
            }
        }
        let retain_kept = |keep: &[bool], bundles: &mut Vec<quil_types::proto::global::MessageBundle>,
                           canonical: &mut Vec<Vec<u8>>, origins: &mut Vec<usize>| {
            let mut next = keep.iter();
            bundles.retain(|_| *next.next().unwrap_or(&true));
            let mut next = keep.iter();
            canonical.retain(|_| *next.next().unwrap_or(&true));
            let mut next = keep.iter();
            origins.retain(|_| *next.next().unwrap_or(&true));
        };
        // Every shard of the application collects every submission, and any
        // one of them may execute it. Once the global commit has decided a
        // bundle, whichever shard relayed it, it is done: drop it from the
        // mempool instead of verifying its proofs again.
        if let Some(manager) = self.execution_engine.as_ref() {
            let global = self.storage_source_hypergraph.clone().unwrap_or_else(|| manager.crdt());
            let done: Vec<bool> = canonical_requests
                .iter()
                .map(|canon| quil_execution::ExecutionEngineManager::decided_globally(global.clone(), &self.app_address, canon))
                .collect();
            let finished: Vec<Vec<u8>> = done.iter().zip(&origins)
                .filter(|(done, _)| **done)
                .map(|(_, origin)| raw_messages[*origin].clone())
                .collect();
            if !finished.is_empty() {
                info!(frame = frame_number, rank, dropped = finished.len(), "dropping bundles the global commit already decided");
                self.mempool.mark_finalized(&finished);
                let keep: Vec<bool> = done.iter().map(|done| !done).collect();
                retain_kept(&keep, &mut request_bundles, &mut canonical_requests, &mut origins);
            }
        }
        // Each confidential bundle is proposed by one designated shard of the
        // application, chosen by its hash over the live shards, instead of by
        // every shard that collected it. One the
        // designated shard has not taken within `ROUTED_FALLBACK` is proposed
        // by any shard, so a stalled or halted shard strands nothing. Bundles
        // routed elsewhere are held, not dropped.
        let operations: Vec<usize> = canonical_requests
            .iter()
            .map(|canon| quil_execution::ExecutionEngineManager::confidential_operation_count(&self.app_address, canon))
            .collect();
        if operations.iter().any(|ops| *ops > 0) {
            let listed = self.prover_registry.get_prover_shard_summaries(anchor_gfn)
                .map(|summaries| live_app_shards(&self.app_address, &summaries))
                .unwrap_or_default();
            let listed_count = listed.len();
            let shards = producing_shards(listed, anchor_gfn, |filter| {
                self.prover_registry.get_active_provers(filter, anchor_gfn).ok().map(|provers| {
                    provers.iter()
                        .flat_map(|prover| prover.allocations.iter())
                        .filter(|allocation| allocation.confirmation_filter == filter)
                        .map(|allocation| allocation.last_active_frame_number)
                        .max()
                        .unwrap_or(0)
                })
            });
            let hashes: Vec<[u8; 32]> = canonical_requests.iter().map(|canon| {
                use sha3::{Digest, Sha3_256};
                Sha3_256::digest(canon).into()
            }).collect();
            let now = std::time::Instant::now();
            let (waited, first_seen) = routing_waits(&self.routing_seen, &hashes, &operations, now);
            let keep = routed_selection(&self.filter, &shards, &hashes, &operations, &waited, ROUTED_FALLBACK);
            for ((((hash, ops), waited), keep), first) in hashes.iter().zip(&operations).zip(&waited).zip(&keep).zip(&first_seen) {
                if *ops == 0 {
                    continue;
                }
                let designated = (!shards.is_empty()).then(|| {
                    let index = u64::from_be_bytes(hash[..8].try_into().unwrap()) % shards.len() as u64;
                    hex::encode(&shards[index as usize][shards[index as usize].len().min(32)..])
                });
                if *first && !*keep {
                    // Once per bundle and shard: when this shard takes it.
                    let admitted_after_s = routing_offset(&self.filter, &shards, hash)
                        .map_or(ROUTED_FALLBACK.as_secs(), |offset| offset * ROUTED_FALLBACK.as_secs());
                    info!(frame = frame_number, bundle = %hex::encode(&hash[..4]), designated = ?designated,
                        admitted_after_s, shards = shards.len(), listed = listed_count,
                        "confidential bundle held for its designated shard");
                }
                if *keep {
                    info!(frame = frame_number, bundle = %hex::encode(&hash[..4]), shards = shards.len(),
                        designated = ?designated, waited_s = waited.as_secs(),
                        "proposing a confidential bundle routed here (or past the routing fallback)");
                } else {
                    debug!(frame = frame_number, bundle = %hex::encode(&hash[..4]), designated = ?designated,
                        waited_s = waited.as_secs(), "confidential bundle left to its designated shard");
                }
            }
            let routed_away: Vec<Vec<u8>> = keep.iter().zip(&origins)
                .filter(|(keep, _)| !**keep)
                .map(|(_, origin)| raw_messages[*origin].clone())
                .collect();
            if !routed_away.is_empty() {
                debug!(frame = frame_number, rank, routed_away = routed_away.len(), shards = shards.len(),
                    "leaving confidential bundles to their designated shards");
                self.mempool.carry_forward(rank, &routed_away);
                retain_kept(&keep, &mut request_bundles, &mut canonical_requests, &mut origins);
            }
        }
        // Proof-verification budget: keep only as many confidential token
        // operations as the configured worker concurrency can verify within
        // the per-frame budget at the measured mean duration, so a finalized
        // frame never carries more proof work than materialization can
        // complete before the next proposal is due. The rest are held back,
        // not dropped: they are carried to this rank so that waiting behind
        // other work never ages them out of the retention window.
        let capacity = self
            .execution_engine
            .as_ref()
            .map(|manager| manager.token_verification_capacity())
            .unwrap_or(usize::MAX);
        if capacity != usize::MAX {
            let operations: Vec<usize> = canonical_requests
                .iter()
                .map(|canon| quil_execution::ExecutionEngineManager::confidential_operation_count(&self.app_address, canon))
                .collect();
            let keep = verification_budget_selection(&operations, capacity);
            let held: Vec<Vec<u8>> = keep.iter().zip(&origins)
                .filter(|(keep, _)| !**keep)
                .map(|(_, origin)| raw_messages[*origin].clone())
                .collect();
            if !held.is_empty() {
                info!(frame = frame_number, rank, deferred = held.len(), capacity, "deferring confidential token bundles beyond the proof-verification budget");
                self.mempool.carry_forward(rank, &held);
                retain_kept(&keep, &mut request_bundles, &mut canonical_requests, &mut origins);
            }
        }
        // The leader executes these after finalization like every member;
        // start verifying their proofs now.
        if let Some(exec) = self.execution_engine.as_ref() {
            prewarm_proof_verdicts(exec, &self.app_address, &canonical_requests);
        }
        // Deliveries of globally committed outputs this shard owns, each its
        // own bundle, after the
        // collected requests. Every member derives the same pending set from
        // certified GLOBAL state; a delivery that cannot be proven yet is
        // simply proposed by a later frame.
        if let (Some(manager), true) = (self.execution_engine.as_ref(), anchor_gfn > 0 && !draining) {
            let global = self.storage_source_hypergraph.clone().unwrap_or_else(|| manager.crdt());
            let clock_store = self.clock_store.clone();
            let operation = move |source_filter: &[u8], source_frame: u64, tx_id: &[u8; 32]| -> Option<(u32, Vec<u8>)> {
                // The frame of the shard that executed it: this shard's own on
                // a whole-application shard, another's on a split one — which a
                // node fetches ahead of time (`pending_delivery_sources`).
                let frame = clock_store.get_shard_clock_frame(source_filter, source_frame, false).ok()?;
                frame.requests.iter()
                    .flat_map(|bundle| bundle.requests.iter())
                    .find_map(|request| match request.request.as_ref()? {
                        quil_types::proto::global::message_request::Request::TokenOperation(op)
                            if op.canonical_bytes.len() >= 4
                                && quil_execution::token_intrinsic::global_commit_tx_id(&op.canonical_bytes) == *tx_id =>
                        {
                            Some((u32::from_be_bytes(op.canonical_bytes[..4].try_into().ok()?), op.canonical_bytes.clone()))
                        }
                        _ => None,
                    })
            };
            match manager.coin_deliveries(global, self.global_anchor_store.as_ref(), &self.filter, anchor_gfn, &operation) {
                Ok(deliveries) if !deliveries.is_empty() => {
                    let count = deliveries.len();
                    for bytes in deliveries {
                        let bundle = quil_types::proto::global::MessageBundle {
                            requests: vec![quil_types::proto::global::MessageRequest {
                                timestamp: 0,
                                request: Some(quil_types::proto::global::message_request::Request::TokenOperation(
                                    quil_types::proto::token::TokenOperation { canonical_bytes: bytes },
                                )),
                            }],
                            timestamp: 0,
                        };
                        match crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundle) {
                            Ok(canon) => {
                                canonical_requests.push(canon);
                                request_bundles.push(bundle);
                            }
                            Err(e) => warn!(error = %e, "dropping un-encodable coin delivery"),
                        }
                    }
                    info!(frame = frame_number, deliveries = count, "proposing coin deliveries");
                }
                Ok(_) => {}
                Err(e) => warn!(frame = frame_number, error = %e, "coin delivery collection failed"),
            }
        }
        // Stash the bundles so the engine can retrieve them at
        // finalization (to self-materialize + publish the full frame).
        if let Ok(mut map) = self.frame_requests.lock() {
            map.insert(frame_number, request_bundles);
            // Bound memory: keep only recent frames.
            let cutoff = frame_number.saturating_sub(64);
            map.retain(|&fnum, _| fnum >= cutoff);
        }
        debug!(
            filter = hex::encode(&self.filter),
            frame = frame_number,
            rank,
            messages = canonical_requests.len(),
            "producing shard frame"
        );

        // Match the implicit genesis output used to initialize Simplex. App
        // frames use deterministic outputs without a VDF.
        let difficulty = self.current_difficulty
            .load(std::sync::atomic::Ordering::Relaxed);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Compute fee multiplier vote: base from sliding window +
        // traffic adjustment.
        let previous_timestamp_ms = parent_header.as_ref()
            .map(|h| h.timestamp).unwrap_or(now_ms - 10_000); // assume 10s at genesis
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
        // DETERMINISTIC PRE-STATE ROOTS (consensus-rule change).
        // Previously `state_roots` came from `hg.commit(N)`, which DRAINS the
        // pending deltas (`std::mem::take`) — but at propose time there are none
        // (frame N's requests execute at materialize, not here), so a clean
        // shard got `zero_roots`: a non-deterministic, near-always-zero header
        // root that could not serve as the catch-up trust anchor and could not
        // be execution-validated. Instead read the 4 phase roots of the CURRENT
        // COMMITTED state (== N-1, since N is not yet materialized) via the
        // version-exact accessor `compute_shard_root` — the SAME value
        // `commit_inner` would put in the header, but read-only and
        // deterministic. Every node (leader + validators) computes these
        // identically, and `deterministic_app_frame_output` binds them, so the
        // per-shard digest is well-defined and the verifier can compare against
        // its own local pre-state (see the proposal check in `activate_...`).
        // Order is canonical [vertex.adds, vertex.removes, hyperedge.adds,
        // hyperedge.removes]; `state_roots[0]` (vertex-adds) stays the sync
        // anchor. Empty (never-committed) phases normalize to the zero root so
        // the 4-root shape holds.
        // NOTE: the unified flip is driven from AppConsensusEngine's run loop
        // (`maybe_flip_unified_at_cutover`) on the SHARED CRDT before produce, so
        // by the time this producer computes `state_roots` the CRDT already
        // reflects the cutover — no flip needed here (this is AppLeaderProvider,
        // which shares the worker's CRDT Arc with the engine).
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
                let zero = vec![0u8; if hg.has_forest() { 32 } else { 64 }];
                let out: Vec<Vec<u8>> = [
                    ("vertex", "adds"),
                    ("vertex", "removes"),
                    ("hyperedge", "adds"),
                    ("hyperedge", "removes"),
                ]
                .iter()
                .map(|(s, p)| {
                    // Sharded unified model: the per-shard `state_root` is the
                    // covered SUBTREE root (computable from partial, subtree-only
                    // storage), NOT `compute_shard_root(app)` (the whole-app
                    // aggregate a subtree-only worker cannot reproduce). Gated on
                    // the worker CRDT being unified (flipped at the cutover);
                    // legacy pre-cutover keeps the aggregate so in-flight frames
                    // don't fork. Unsplit app is a no-op (subtree root == app root).
                    let r = if hg.unified_tree() {
                        hg.sub_shard_commitment_for_filter(s, p, &self.filter)
                    } else {
                        hg.compute_shard_root(s, p, &shard_key)
                    };
                    if r.is_empty() { zero.clone() } else { r }
                })
                .collect();
                // Publish the shard's vertex-adds root as a snapshot generation
                // (binding a real point-in-time DB snapshot) so sync clients
                // pinning this header get root-consistent CRDT data.
                if out[0].iter().any(|b| *b != 0) {
                    if let Err(e) = hg.publish_snapshot_capturing(out[0].clone(), frame_number) {
                        warn!(
                            filter = hex::encode(&self.filter),
                            frame = frame_number,
                            error = %e,
                            "failed to capture snapshot for published shard root"
                        );
                    }
                }
                out
            }
            None => zero_roots(),
        };

        // Per-frame requests root over the messages included in this
        // proposal. Mirrors Go's `calculateRequestsRoot` +
        // `executionManager.Lock` flow: for each message,
        //   hash = sha3_256(payload)
        //   address = self.app_address[..32] (per Go message_processors.go:1318-1322)
        //   payload = the raw MessageBundle bytes
        // Then call `execution_engine.lock(frame, address, payload)`
        // to get the locked-address vector and insert
        // `(hash, concat(locked_addresses))` into a
        // `VectorCommitmentTree`. The final root is
        // `sha3_256(tree.commit())[..32] || serialize_non_lazy(tree)`.
        // Empty messages → 64-byte zero buffer, matching Go.
        let requests_root: Vec<u8> = compute_requests_root(
            &canonical_requests,
            &self.app_address,
            frame_number,
            self.execution_engine.as_deref(),
            self.inclusion_prover.as_deref(),
            self.hypergraph.as_ref().map(|h| h.has_forest()).unwrap_or(false),
        )?;

        // Assemble the header fields for the deterministic app output.
        // Go passes `getProverAddress()` = `poseidon(pubkey)` (32 bytes)
        // as the `prover` field in the frame header, NOT the raw G2
        // public key (585 bytes). Using the raw pubkey would produce
        // headers that other nodes can't match to the prover registry
        // (which is keyed by poseidon address).
        // `storage_attestation_root` is assembled out-of-band at QC time from
        // the committee's vote openings (set on the finalized frame), so the
        // produced header carries an empty root.
        let storage_attestation_root: Vec<u8> = Vec::new();
        // Previous-frame fee total for the shard's provers. Frame N's
        // requests execute after finalization, so the
        // verifiable total at proposal time is frame N-1's; an unknown total
        // (fresh restart without the entry) proposes zero and is nullified by
        // validators that hold it, which only costs this view.
        let fee_total: u128 = if frame_number == 0 { 0 } else {
            materialized_fee_total(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, frame_number - 1)
                .unwrap_or(0)
        };
        // Settlement relay window (frames N-32 ..= N-1). Unknown entries for any
        // window frame propose an empty relay, which holders nullify (one view).
        let settlements: Vec<u8> =
            settlement_relay(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, frame_number)
                .unwrap_or_default();
        // This shard's accumulator report for the canonical application root:
        // frame N-1's, when it changed or on the heartbeat. Unknown records
        // propose empty, which members holding them decline (one view).
        let accumulator: Vec<u8> =
            accumulator_field(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, frame_number)
                .unwrap_or_default();
        // Spend relay for the global commit (frames N-8 ..= N-1). Unknown
        // records propose empty, which members holding them decline.
        let spends: Vec<u8> =
            spend_relay(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, frame_number)
                .unwrap_or_default();
        // Anchor the deterministic app output to the global storage beacon.
        // `anchor_gfn` /
        // `anchor_output` were resolved ONCE up top (`resolve_global_anchor`, =
        // `latest − K`) — the SAME value that gated the committee epoch above — so
        // this frame's committee, its stamped `global_frame_number`, and the
        // verifier's committee (read from that stamped number) are all consistent.
        // Storage attestation is always-on (no fork-height gate): a frame is a
        // storage frame iff it has a real global frame to anchor ρ_N to. The
        // only non-anchored case is genesis / tests with no global chain
        // (`anchor_gfn == 0`), which uses the zero-anchor beacon.
        let storage_active = anchor_gfn > 0;
        // App-shard frames do NOT use a VDF at all. `prove_frame_header` no longer
        // solves one; the header's `output` is the deterministic ρ_N-bound digest
        // computed below (`deterministic_app_frame_output`). ρ_N binds freshness to
        // the anchored GLOBAL VDF output; a genesis / no-global-anchor frame uses a
        // ZERO-ANCHOR beacon (`derive_storage_beacon(0, ..)`) — still fully
        // deterministic, just no ρ_N freshness (none exists pre-global-chain).
        let rho_n = if storage_active {
            quil_crypto::porep::derive_storage_beacon(anchor_gfn, &anchor_output)
        } else {
            quil_crypto::porep::derive_storage_beacon(0, &anchor_output)
        };
        let mut header = self.frame_prover.prove_frame_header(
            &previous_frame_output,
            &self.filter,
            &requests_root,
            &state_roots,
            &self.local_prover_address,
            now_ms,
            difficulty,
            fee_multiplier_vote,
            frame_number,
            &storage_attestation_root,
            anchor_gfn,
        )?;
        if storage_active {
            // PROPOSER SELF-ATTESTATION (CW PoRep port). Legacy Jolteon assembled
            // the committee `StorageAttestation` from every member's per-vote
            // openings at QC time. Simplex votes carry no payload, so under CW the
            // proposer attests its OWN storage: build this node's openings for the
            // shard, assemble a single-member attestation, and stamp the 74-byte
            // BLS48-581 G1 root onto the header. The serialized openings ride in a
            // side map (`frame_attestations`) the assembler attaches to the full
            // frame. NOTE: single-member — other committee members are NOT proven
            // to store. Best-effort: any failure leaves the root
            // empty (legacy frame), never blocks frame production.
            // PER-PROVER POSSESSION: the worker seals + attests from its OWN crdt
            // (`self.hypergraph`) and OWN `replica_store` (`kv_db`). The covered
            // shard's committed data is SYNCED into that own crdt from the sync
            // source (the master's forest-filled hypergraph) — the in-process
            // analogue of the network forest-sync a cluster/process worker runs.
            // Archive/tests wire no separate source, so the own crdt already holds
            // everything and the sync is a no-op.
            if let (Some(kv), Some(own_crdt)) = (self.kv_db.as_ref(), self.hypergraph.as_ref()) {
                let epoch = quil_types::consensus::epoch_for_frame(anchor_gfn);
                let replica_store =
                    quil_store::replica_store::ReplicaStore::new(kv.clone());
                // Attest from replicas already sealed for this epoch. If none exist
                // yet: (1) SYNC the covered shard's data into the worker's OWN crdt,
                // (2) SDR-seal its sub-shard into its OWN replica_store, (3) attest.
                // SDR is slow, so gating on "openings empty" runs this ~once/epoch.
                let mut opening_blob = crate::app_shard_metadata::build_vote_openings(
                    own_crdt,
                    &replica_store,
                    &self.filter,
                    &self.local_prover_address,
                    epoch,
                    &rho_n,
                )
                .unwrap_or_default();
                if opening_blob.is_empty() && !self.private_parent {
                    // (1) worker-side shard-data sync into its OWN store.
                    if let Some(source) = self.storage_source_hypergraph.as_ref() {
                        let app_addr = &self.filter[..self.filter.len().min(32)];
                        match crate::app_shard_metadata::sync_app_shard_to_own_crdt(
                            source, own_crdt, app_addr, anchor_gfn,
                        ) {
                            Ok(n) if n > 0 => tracing::info!(
                                frame = frame_number, copied = n,
                                "worker-side shard-data sync into own store"
                            ),
                            Err(e) => warn!(frame = frame_number, error = %e, "worker shard sync failed"),
                            _ => {}
                        }
                    }
                    // (2) SDR-seal from the worker's OWN crdt into its OWN replica_store.
                    if let Err(e) = crate::app_shard_metadata::compute_storage_confirm(
                        own_crdt,
                        &replica_store,
                        &[self.filter.clone()],
                        &self.local_prover_address,
                        epoch,
                        quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                        &quil_crypto::sdr::SdrParams::default(),
                    ) {
                        warn!(frame = frame_number, error = %e, "storage self-seal failed");
                    }
                    // (3) attest from the worker's OWN replicas.
                    opening_blob = crate::app_shard_metadata::build_vote_openings(
                        own_crdt,
                        &replica_store,
                        &self.filter,
                        &self.local_prover_address,
                        epoch,
                        &rho_n,
                    )
                    .unwrap_or_default();
                }
                {
                    if !opening_blob.is_empty() {
                        let blob = opening_blob;
                        let mut openings =
                            crate::app_shard_metadata::decode_vote_openings(&blob);
                        // Validators reject the whole frame for an opening whose
                        // leaf this member has not registered for the active
                        // epoch. After a split every member seals its new child's
                        // leaves before any confirm could register them, so every
                        // child frame was rejected for the split's first two
                        // epochs. Attach only registered openings: an unattested
                        // frame is valid and forgoes its storage reward.
                        let sealed = openings.len();
                        openings.retain(|o| {
                            matches!(
                                self.prover_registry.get_leaf_root(&o.member_id, &o.shard_id, epoch),
                                Ok(Some((root, blocks, registered)))
                                    if registered == epoch && root == o.leaf_root && blocks == o.num_blocks
                            )
                        });
                        if openings.len() < sealed {
                            info!(
                                frame = frame_number,
                                epoch,
                                unregistered = sealed - openings.len(),
                                "app-shard proof: omitting openings for leaves not registered this epoch"
                            );
                        }
                        if !openings.is_empty() {
                            // EMPTY bitmask: a CW frame header carries no BLS
                            // aggregate, so the validator reads an empty bitmask
                            // for the root's Fiat-Shamir challenge. The producer
                            // MUST fold the same bytes or the recomputed root
                            // diverges and the frame is rejected. The openings
                            // self-identify their member, so no participant bitmap
                            // is needed for a single-member self-attestation.
                            let (att, root) =
                                quil_crypto::porep::build_frame_storage_attestation(
                                    &openings,
                                    frame_number,
                                    &rho_n,
                                    &[],
                                    quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                                );
                            header.storage_attestation_root = root;
                            if let Ok(mut map) = self.frame_attestations.lock() {
                                map.insert(
                                    frame_number,
                                    prost::Message::encode_to_vec(&att),
                                );
                            }
                            info!(
                                frame = frame_number,
                                openings = openings.len(),
                                "app-shard proof: storage attestation generated + attached to frame header"
                            );
                        } else {
                            warn!(
                                frame = frame_number,
                                "app-shard proof: vote-openings decoded EMPTY — frame carries NO storage attestation (the global storage gate will withhold this shard's reward)"
                            );
                        }
                    } else {
                        warn!(
                            frame = frame_number,
                            "app-shard proof: build_vote_openings produced nothing (no readable replicas for this shard) — frame carries NO storage attestation (the global storage gate will withhold this shard's reward)"
                        );
                    }
                }
            }
        }

        // ALWAYS set the app-shard frame output to the deterministic ρ_N-bound
        // digest — for storage frames AND genesis (zero-anchor ρ_N). NO VDF.
        // Bind to the canonical-state fields that actually ride the wire
        // (`AppShardState` below takes `requests_root`/`state_roots` from these
        // locals, not from `header.*`), so the verifier — which recomputes from
        // the wire header — derives the identical output.
        header.output = quil_crypto::porep::deterministic_app_frame_output(
            &header.parent_selector,
            &requests_root,
            &state_roots,
            &rho_n,
            frame_number,
            rank,
            &self.local_prover_address,
            // Use the LOCALS that ride the wire via `AppShardState` (below),
            // NOT `header.*` — the verifier recomputes from the reconstructed
            // wire header, which carries these locals. (`header.*` from
            // `prove_frame_header` can differ, e.g. fee_multiplier_vote.)
            difficulty,
            fee_multiplier_vote,
            now_ms,
            // Stamped in the storage block above (empty for genesis) and carried
            // on the wire via `AppShardState.storage_attestation_root` — matches
            // the verifier.
            &header.storage_attestation_root,
            fee_total,
            &settlements,
            &accumulator,
            &spends,
        );

        let mut state = AppShardState::new(
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
            header.storage_attestation_root.clone(),
            header.global_frame_number,
            fee_total,
        );
        state.settlements = settlements;
        state.accumulator = accumulator;
        state.spends = spends;

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

/// App-shard CW transport: emits each outbound simplex message as an
/// `AppEngineEvent::CwOut` on the engine's event channel. The master publishes
/// it on `shard_cw_bitmask` gossip (or the in-memory harness routes it to peers).
/// `deliver` runs on the simplex thread → a plain channel send (no runtime
/// needed). Votes, certificates and blocks go to the whole shard committee via
/// gossip. Resolver messages keep their recipients (one member each): sent to
/// the whole topic, every subscriber received every response, 163–171 Mbit/s
/// on one regular node (2026-10-04). For a single-prover shard nothing is
/// delivered anywhere (simplex handles its own messages internally).
struct EngineCwTransport {
    filter: Vec<u8>,
    event_tx: mpsc::UnboundedSender<AppEngineEvent>,
}
impl crate::cw_app_seams::AppConsensusTransport for EngineCwTransport {
    fn deliver(
        &self,
        channel: u64,
        recipients: Vec<quil_cw_consensus::falcon_base::FalconPublicKey>,
        bytes: Vec<u8>,
    ) {
        let recipients = if channel == crate::cw_app_seams::CW_APP_RESOLVER_CHANNEL {
            crate::resolver_traffic::ResolverTraffic::process().note_sent(&self.filter, &bytes);
            recipients.iter().map(|key| key.as_ref().to_vec()).collect()
        } else {
            Vec::new()
        };
        let _ = self.event_tx.send(AppEngineEvent::CwOut {
            filter: self.filter.clone(),
            channel,
            bytes,
            recipients,
        });
    }
}

/// Dependencies required to construct an AppConsensusEngine.
/// Fetches one certified app-shard frame by `(filter, frame number)`.
pub type DeliveryFrameSource = Arc<
    dyn Fn(Vec<u8>, u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<quil_types::proto::global::AppShardFrame>> + Send>>
        + Send
        + Sync,
>;

pub struct AppEngineDeps {
    pub clock_store: Arc<dyn ClockStore>,
    /// Store to resolve the GLOBAL clock-frame anchor from (`anchor_gfn` /
    /// ρ_N). Distinct from `clock_store` on a worker: a thread/cluster worker's
    /// own `clock_store` holds only its APP-SHARD chain, while the global frames
    /// live in the master's clock_store (fed by the frame poller). Storage
    /// attestation needs `get_latest_global_clock_frame() > 0`, so the anchor
    /// read MUST use the master's store, not the worker's. `None` → fall back to
    /// `clock_store` (correct for the archive/tests where a single store holds
    /// both). Without this, a worker anchors to genesis (`anchor_gfn = 0`),
    /// uses the zero-anchor beacon without a storage attestation, and earns no rewards.
    pub global_anchor_store: Option<Arc<dyn ClockStore>>,
    /// Committed GLOBAL authorization records. Thread workers use the master's
    /// CRDT; an app-only worker store cannot supply historical committees.
    pub global_hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
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
    /// (4 phase commitments) for the deterministic app digest. When
    /// absent the engine falls back to 4 × 64-byte zero placeholders —
    /// suitable only for tests without shard state.
    pub hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// Storage-attestation SOURCE crdt = the MASTER's hypergraph (covered shard's
    /// committed coin data). On a thread-worker this differs from `hypergraph`
    /// (per-worker state); the prover replicates FROM here into its own
    /// `replica_store`. None → fall back to `hypergraph`. See `AppLeaderProvider`.
    pub storage_source_hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// The node's committed shard topology (the master's shards store: the
    /// grid and recorded pending changes), from which a shard retiring
    /// through a split or merge drains (`crate::shard_drain`). `None` never
    /// drains (cluster workers, tests).
    pub topology: Option<Arc<dyn quil_types::store::ShardsStore>>,
    /// Fetch a certified app-shard frame this node does not hold. A split
    /// application's outputs are delivered by the shard owning their block,
    /// which is rarely the shard that executed them, so the owner must read
    /// those bytes from another shard's frame — from an archive, which holds
    /// every frame. `None` (whole-application shards, tests) simply never
    /// fetches: the delivery waits, and nothing else changes.
    pub delivery_frame_source: Option<DeliveryFrameSource>,
    /// Execution engine used to compute the per-message locked-address
    /// vectors (`tx_map`) that feed `requests_root`. Required to bind non-empty
    /// frames to the addresses their requests access.
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
    /// When true, drive this shard's consensus with commonware-simplex +
    /// Falcon (EQUAL VOTES) instead of the legacy quil-consensus HotStuff loop.
    /// Off by default → legacy path unchanged.
    pub app_consensus_cw: bool,
    /// DB config used to derive the PERSISTENT per-shard simplex-journal
    /// directory (Go parity: `app_consensus_engine.go:718` — core 0 →
    /// `db.path`, worker core N → `worker_paths[N-1]` / `worker_path_prefix`).
    /// An empty resolved path ⇒ ephemeral journal (tests). Default is fine for
    /// callers that don't persist app-shard consensus.
    pub db_config: quil_config::DbConfig,
    /// Unified-cutover consolidation hook, `Fn(filter, global_frame) -> ok`.
    /// Invoked once, on THIS worker's CRDT, at the moment its anchored global
    /// frame reaches `UNIFIED_TREE_CUTOVER_FRAME` — BEFORE flipping the CRDT to
    /// unified — to fold the covered app's pre-cutover per-sub-shard trees into
    /// its single app.l2 tree (so the first unified subtree `state_root` reflects
    /// pre-cutover data). Built by the node (`worker_state_builder`) capturing the
    /// worker's hg store; `None` (tests / no-migrate) skips consolidation and just
    /// flips. Returns `false` to abort the flip this cycle (retried next).
    pub unified_cutover_hook:
        Option<Arc<dyn Fn(&[u8], u64) -> bool + Send + Sync>>,
}

/// The persistent base directory for a core's app-shard simplex journals,
/// mirroring Go's `app_consensus_engine.go:718-726`: core 0 (master) uses
/// `db.path`; a worker core `N` uses `worker_paths[N-1]` when present, else
/// `worker_path_prefix` with `%d` → `N`. An empty resolved path yields `None`
/// (ephemeral random-temp journal — tests / callers without a data dir).
pub(crate) fn cw_app_storage_base(
    db: &quil_config::DbConfig,
    core_id: u32,
) -> Option<std::path::PathBuf> {
    let path = if core_id > 0 {
        if (db.worker_paths.len() as u32) >= core_id {
            db.worker_paths[(core_id - 1) as usize].clone()
        } else if !db.worker_path_prefix.is_empty() {
            db.worker_path_prefix.replace("%d", &core_id.to_string())
        } else {
            db.path.clone()
        }
    } else {
        db.path.clone()
    };
    if path.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(path))
    }
}

/// Preserve incompatible simplex journals for recovery and diagnosis before
/// opening a new session. Call only after joining the previous host. I/O errors
/// stop startup; a failed rename must never fall through to journal replay.
/// The caller supplies the complete session descriptor, not just membership.
pub fn reset_stale_cw_journal(
    journal_dir: &std::path::Path,
    fingerprint: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;
    let fp_path = journal_dir.with_extension("cw-fp");
    let previous = match std::fs::read(&fp_path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if previous.as_deref() == Some(fingerprint) {
        return Ok(());
    }
    let retired = journal_dir.with_extension("retired");
    std::fs::create_dir_all(&retired)?;
    let mut generation = 0u64;
    let archive = loop {
        let candidate = retired.join(generation.to_string());
        match std::fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                generation = generation.checked_add(1).ok_or_else(||
                    std::io::Error::other("journal archive generation exhausted"))?;
            }
            Err(e) => return Err(e),
        }
    };
    if let Some(previous) = previous {
        let mut file = std::fs::File::create(archive.join("fingerprint"))?;
        file.write_all(&previous)?;
        file.sync_all()?;
    }
    if journal_dir.try_exists()? {
        std::fs::rename(journal_dir, archive.join("journal"))?;
        warn!(dir = %journal_dir.display(), archive = %archive.display(),
            "preserved incompatible CW journal before starting a new session");
    }
    // Write and sync before atomically publishing the new fingerprint.
    let staged = archive.join("next-fingerprint");
    let mut file = std::fs::File::create(&staged)?;
    file.write_all(fingerprint)?;
    file.sync_all()?;
    std::fs::rename(&staged, &fp_path)?;
    std::fs::File::open(&archive)?.sync_all()?;
    std::fs::File::open(&retired)?.sync_all()?;
    if let Some(parent) = journal_dir.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

const APP_CW_EPOCH: u64 = 0;

/// Prepare a persistent app journal and return its stable genesis anchor.
/// Same-session restarts retain BOTH votes and the original genesis, even if
/// the local finalized head advanced. This is local replay configuration, not
/// a protocol for choosing a common checkpoint across changing committees.
///
/// `adopt_candidate`: the candidate head must become the genesis, because
/// another committee certified it and this one cannot resume past it from an
/// older genesis. A journal of an older genesis is then retired even when its
/// committee and key match; one already anchored at the candidate is kept.
fn prepare_app_cw_journal(
    journal_dir: &std::path::Path,
    peers: &[quil_cw_consensus::falcon_base::FalconPublicKey],
    filter: &[u8],
    local_key: &[u8],
    candidate_anchor: [u8; 32],
    candidate_frame: u64,
    adopt_candidate: bool,
) -> std::io::Result<([u8; 32], u64)> {
    use sha2::{Digest, Sha256};
    const VERSION: &[u8; 5] = b"QLAS\x01";
    let mut h = Sha256::new();
    h.update(b"quil/app-cw-session/v1");
    h.update(APP_CW_EPOCH.to_le_bytes());
    for bytes in [filter, local_key] {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    h.update((peers.len() as u64).to_le_bytes());
    for pk in peers {
        h.update((pk.as_ref().len() as u64).to_le_bytes());
        h.update(pk.as_ref());
    }
    let context: [u8; 32] = h.finalize().into();
    let previous = match std::fs::read(journal_dir.with_extension("cw-fp")) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if let Some(bytes) = previous.as_ref() {
        // Only the old 32-byte committee hash is a recognized legacy record.
        // Corrupt/unknown descriptors must not silently discard vote history.
        if !bytes.starts_with(VERSION) && (bytes.len() != 32 || bytes.starts_with(b"QLAS")) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                "unknown app consensus session descriptor"));
        }
        if bytes.starts_with(VERSION) {
            if bytes.len() != 77 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                    "truncated or trailing app consensus session descriptor"));
            }
            if bytes[5..37] == context {
                let anchor: [u8; 32] = bytes[37..69].try_into().unwrap();
                let frame = u64::from_le_bytes(bytes[69..77].try_into().unwrap());
                if candidate_frame < frame || (candidate_frame == frame && candidate_anchor != anchor) {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                        "local shard head does not contain the persisted consensus genesis; synchronize before replay"));
                }
                if !adopt_candidate || candidate_frame == frame {
                    return Ok((anchor, frame));
                }
            }
        }
    }
    let mut descriptor = VERSION.to_vec();
    descriptor.extend_from_slice(&context);
    descriptor.extend_from_slice(&candidate_anchor);
    descriptor.extend_from_slice(&candidate_frame.to_le_bytes());
    reset_stale_cw_journal(journal_dir, &descriptor)?;
    Ok((candidate_anchor, candidate_frame))
}

/// App shard consensus engine. Owns a HotStuff event loop and
/// processes messages for a single shard identified by `filter`.
pub struct AppConsensusEngine {
    /// Fetches certified frames of shards this node does not hold, so their
    /// committed outputs can be delivered here.
    delivery_frame_source: Option<DeliveryFrameSource>,
    // NOTE: `global_anchor_store` (added below near `clock_store`) resolves the
    // GLOBAL frame anchor; `clock_store` serves this shard's own chain.
    /// CPU core this engine runs on.
    pub core_id: u32,
    /// Persistent base dir for this core's app-shard simplex journals (Go
    /// parity, `cw_app_storage_base`). `None` ⇒ ephemeral journal.
    cw_storage_base: Option<std::path::PathBuf>,
    /// Shard filter (bloom filter bytes).
    pub filter: Vec<u8>,
    /// App address (Poseidon hash of filter).
    pub app_address: Vec<u8>,

    // Dependencies
    clock_store: Arc<dyn ClockStore>,
    /// Store for the GLOBAL clock-frame anchor (see `AppEngineDeps`). On a
    /// worker this is the master's clock_store (has global frames); elsewhere
    /// it equals `clock_store`.
    global_anchor_store: Arc<dyn ClockStore>,
    global_hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
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
    /// Storage-attestation SOURCE crdt (master's hypergraph). See `AppEngineDeps`.
    storage_source_hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// See `AppEngineDeps::topology`.
    shard_drain: Option<Arc<crate::shard_drain::ShardDrain>>,
    /// Unified-cutover consolidation hook (see `AppEngineDeps`).
    unified_cutover_hook:
        Option<Arc<dyn Fn(&[u8], u64) -> bool + Send + Sync>>,
    execution_engine: Option<Arc<quil_execution::ExecutionEngineManager>>,
    inclusion_prover: Option<Arc<dyn quil_types::crypto::InclusionProver>>,

    // Consensus state
    current_difficulty: Arc<std::sync::atomic::AtomicU32>,
    current_rank: u64,
    /// Arrival times of submissions, shared with the leader provider.
    routing_seen: RoutingClock,
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
    // Only parents for which a child QC has already triggered sealing.
    retry_parent_seals: std::collections::BTreeSet<u64>,
    /// Ranks queued for parent sealing (set by sync handler, drained in loop).
    pending_seal_rank: Option<u64>,
    /// Highest shard frame number whose requests have been materialized
    /// into the hypergraph. Idempotency gate so a frame is never
    /// materialized twice (mirrors Go `lastMaterializedFrame`,
    /// app_consensus_engine.go:1444-1449).
    last_materialized_frame: u64,
    /// Thread-safe mirror of `last_materialized_frame` for the CW proposal
    /// check, which runs on the simplex thread. Bumped alongside the
    /// field via [`Self::set_materialized_frame`] wherever the materialized
    /// shard state advances. Only ever raised AFTER the state is committed, so
    /// it never OVER-reports. The `state_roots` pre-state gate is now FAIL-CLOSED:
    /// a voter not exactly at N-1 nullifies (cannot validate the declared
    /// pre-state) rather than signing blind — closing the frame-number-jump
    /// bypass of the pre-state check. A lagging voter catches up via shard sync,
    /// then votes.
    shard_mat_frame: std::sync::Arc<std::sync::atomic::AtomicU64>,
    execution: crate::worker_execution::SharedWorkerExecution,
    /// Shared with the CW proposer/verifier: whether this member has staged the
    /// covered sub-shard's committed data into its own CRDT. Gates propose/vote
    /// (see [`crate::cw_app_seams::AppSeamProposer`]) so a joining member neither
    /// produces attestation-less frames nor forks the shard on empty state. Set
    /// true when the join-time data bootstrap converges, or immediately when the
    /// data is already present (archive / restart / shared-state).
    data_ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// This member joined the first session of a merged shard and has not yet
    /// inherited the merged range: its own data covers only the source it came
    /// from, so "some data under the prefix" does not mean "staged".
    inherit_pending: std::sync::atomic::AtomicBool,
    /// Proposals whose declared pre-state this member's own state did not
    /// reproduce, since the last frame it materialized. A member whose store
    /// holds only part of the shard's range (a legacy merge's source) refuses
    /// every proposal from a member holding the other part, and no frame ever
    /// finalizes; past `PRE_STATE_MISMATCH_BOOTSTRAP` it inherits the range
    /// from an archive, as the session path does for a merged shard.
    pre_state_mismatches: Arc<std::sync::atomic::AtomicU64>,
    /// `(materialized frame at the last check, last self-heal bootstrap)`.
    pre_state_heal: (u64, Option<std::time::Instant>),
    /// Shared with the leader provider: requests this node collected for
    /// frames it proposed (proto `MessageBundle`s), keyed by frame
    /// number. Read at finalization to self-materialize + assemble the
    /// full `AppShardFrame` for publication.
    frame_requests: Arc<std::sync::Mutex<
        std::collections::HashMap<u64, Vec<quil_types::proto::global::MessageBundle>>,
    >>,
    /// Shared with the leader provider (mirrors `frame_requests`): the serialized
    /// proposer self storage-attestation (`StorageAttestation` openings) for each
    /// frame this node proposed. The `AppFrameAssembler` reads it to attach the
    /// openings to the full `AppShardFrame`. See `AppLeaderProvider::frame_attestations`.
    frame_attestations: Arc<std::sync::Mutex<std::collections::HashMap<u64, Vec<u8>>>>,
    /// `requests_root` of frames this node FINALIZED through (BLS-verified)
    /// consensus, keyed by frame number. The trust anchor for materializing
    /// a full frame received on the wire as a follower: the received
    /// frame's recomputed `requests_root` must equal the one we finalized.
    finalized_requests_roots: HashMap<u64, Vec<u8>>,
    /// Full `AppShardFrame`s received on `shard_frame_bitmask`, buffered
    /// by frame number until they can be materialized in order.
    received_full_frames: HashMap<u64, quil_types::proto::global::AppShardFrame>,
    pending_follower_clock: Option<(u64, quil_types::proto::global::AppShardFrame)>,
    /// Consecutive `commit_frame` failure counts per frame number, so a
    /// frame that can't be materialized is dropped + repaired via sync
    /// rather than retried-from-zero forever. Cleared on success.
    materialize_failures: HashMap<u64, u32>,

    // Channels
    cancel: CancellationToken,
    msg_rx: Option<mpsc::Receiver<AppEngineMessage>>,
    event_tx: mpsc::UnboundedSender<AppEngineEvent>,

    // App digest, storage and committee validator for this shard. Used by the inbound
    // proposal gate and the follower full-frame path before
    // materialization.
    app_frame_validator: Option<Arc<BlsAppFrameValidator>>,
    storage_history_source: Option<crate::storage_history::GlobalVertexProofSource>,
    /// Archive source of a predecessor's outgoing records, for a successor
    /// member that cannot re-derive its sealed history locally.
    outgoing_history_source: Option<crate::app_handoff::OutgoingHistorySource>,
    global_anchor_source: Option<crate::global_anchor::GlobalAnchorSource>,
    /// Committees that certified legacy frames, when today's registry no
    /// longer reproduces them (see `historical_committee`).
    historical_committee_source: Option<crate::historical_committee::HistoricalCommitteeSource>,

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
    /// Drive this shard with commonware-simplex + Falcon instead of legacy.
    app_consensus_cw: bool,
    /// Handle to the running simplex engine (kept alive; the outbound drain
    /// + block ingress live in it). Populated by `start_consensus_cw`.
    cw_handle: Option<crate::cw_app_seams::AppConsensusCwHandle>,
    /// Fingerprint (sorted-member hash) of the committee the running `cw_handle`
    /// was built with. The run loop recomputes the active-prover set each tick
    /// and, when it changes, tears down the old simplex instance and rebuilds —
    /// commonware-simplex has a FIXED validator set per instance, so a membership
    /// change (a prover activating/leaving) requires a fresh instance. This is
    /// what lets a shard grow from a 1-member floor committee (formed before the
    /// second prover's deferred activation) to the real N-member committee.
    cw_committee_fp: Option<[u8; 32]>,
    /// The authorized committee session the running `cw_handle` was built for.
    /// `None` on the legacy registry-committee path.
    cw_session: Option<quil_cw_consensus::handoff::Session>,
    /// Shared with the session's parent reader and the leader (request-free
    /// frames while the session closes).
    session_closing: Arc<std::sync::atomic::AtomicBool>,
    /// Executes an unfinalized selected parent for the running consensus host.
    private_parents: Option<Arc<AppParentExecutor>>,
    /// A finalized terminal seal: `(session id, canonical CommitteeHandoff)`.
    /// Republished until GLOBAL state records it; the sealed session is never
    /// restarted, since every later view could only nullify.
    sealed_session: Option<([u8; 32], Vec<u8>)>,
    /// When this member last published its closing certificate.
    seal_published_at: Option<std::time::Instant>,
    /// Self-clone of the inbound message sender, so `on_finalized` (running
    /// on the simplex thread) can inject `CwFinalizedFrame` into this run loop.
    self_msg_tx: mpsc::Sender<AppEngineMessage>,

    /// Atomic publish slot for engine sizes. Updated each event-loop
    /// iteration so external memory snapshots can read internal
    /// cache sizes without taking the engine's locks.
    sizes: SharedAppEngineSizes,
    fee_snapshot: Arc<std::sync::Mutex<Option<quil_execution::pricing::AppFeeSnapshot>>>,
    /// Fee total (QUIL base units) of every frame this engine materialized,
    /// keyed by frame number. The next proposal carries the previous frame's
    /// total in `FrameHeader.fee_total`; validators compare against their own
    /// entry (fail-closed), and the clock store persists it across restarts.
    frame_outflows: Arc<FrameOutflows>,
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

        // The shard's app address IS the domain — the same 32-byte value
        // the master assigns as `filter` (Go's `appAddress`). It must NOT
        // be re-hashed: `filter` is already the intrinsic-computed domain
        // (e.g. `QUIL_TOKEN_ADDRESS = poseidon("q_mainnet_token")` for the
        // QUIL shard), and the per-shard pubsub bitmask is `bloom(filter)`
        // (see `shard_app_filter`), which must equal Go's
        // `bloom(appAddress)` — pinning `filter == appAddress == domain`.
        // This address is what routes a message to its intrinsic engine
        // and is the lock address for `requests_root`; an extra
        // `poseidon` here (the prior behavior) yielded an address that
        // matches no domain, so every app-shard tx fell through to the
        // hypergraph engine and `requests_root` diverged from Go.
        let app_address = filter.clone();

        // A sub-shard's private block summary is outside its synced range.
        // Rebuild on restart too: a crash can occur after state import but
        // before the completion message invalidates the old summary.
        if quil_forest::decode_shard_filter_or_root(&filter, 32)
            .is_some_and(|(_, shard)| !shard.is_empty())
        {
            if let Some(manager) = deps.execution_engine.as_ref() {
                manager.rebuild_block_summary_before_report(&filter);
            }
        }

        let sizes = SharedAppEngineSizes::new();
        let fee_snapshot = Arc::new(std::sync::Mutex::new(None));
        let shard_mat_frame = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let execution = crate::worker_execution::SharedWorkerExecution::default();
        execution.state("starting", "waiting for transport");
        let handle = AppEngineHandle {
            execution: execution.clone(),
            cancel: cancel.clone(),
            materialized: shard_mat_frame.clone(),
            fee_snapshot: fee_snapshot.clone(),
            filter: filter.clone(),
            msg_tx: msg_tx.clone(),
            sizes: sizes.clone(),
        };

        // Global anchor resolves from the master's store on a worker (where the
        // shard-local `clock_store` has no global frames); falls back to
        // `clock_store` for the archive/tests (single store holds both).
        let global_anchor_store = deps
            .global_anchor_store
            .unwrap_or_else(|| deps.clock_store.clone());

        let cw_storage_base = cw_app_storage_base(&deps.db_config, core_id);
        let engine = Self {
            core_id,
            cw_storage_base,
            filter: filter.clone(),
            app_address,
            clock_store: deps.clock_store,
            global_anchor_store,
            global_hypergraph: deps.global_hypergraph,
            prover_registry: deps.prover_registry,
            frame_prover: deps.frame_prover,
            message_collector: deps.message_collector,
            fee_manager: deps.fee_manager,
            reward_greedy: deps.reward_greedy,
            min_active_provers_for_propose: deps.min_active_provers_for_propose,
            hypergraph: deps.hypergraph,
            storage_source_hypergraph: deps.storage_source_hypergraph,
            shard_drain: deps.topology.map(|topology| Arc::new(crate::shard_drain::ShardDrain::new(filter.clone(), topology))),
            delivery_frame_source: deps.delivery_frame_source,
            unified_cutover_hook: deps.unified_cutover_hook,
            execution_engine: deps.execution_engine,
            inclusion_prover: deps.inclusion_prover,
            current_difficulty: Arc::new(std::sync::atomic::AtomicU32::new(50000)),
            current_rank: 0,
            routing_seen: Default::default(),
            shard_frame_number: 0,
            _pending_messages: VecDeque::with_capacity(MAX_APP_MESSAGES_PER_RANK),
            message_spillover: HashMap::new(),
            proposal_cache: HashMap::new(),
            frame_store: HashMap::new(),
            pending_certified_parents: HashMap::new(),
            retry_parent_seals: std::collections::BTreeSet::new(),
            pending_seal_rank: None,
            last_materialized_frame: 0,
            shard_mat_frame,
            execution,
            data_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            inherit_pending: std::sync::atomic::AtomicBool::new(false),
            pre_state_mismatches: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pre_state_heal: (0, None),
            frame_requests: Arc::new(std::sync::Mutex::new(HashMap::new())),
            frame_attestations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            finalized_requests_roots: HashMap::new(),
            received_full_frames: HashMap::new(),
            pending_follower_clock: None,
            materialize_failures: HashMap::new(),
            cancel,
            msg_rx: Some(msg_rx),
            event_tx,
            app_frame_validator: None,
            storage_history_source: None,
            outgoing_history_source: None,
            global_anchor_source: None,
            historical_committee_source: None,
            local_prover_address: deps.local_prover_address,
            local_bls_pubkey: deps.local_bls_pubkey,
            halted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            coverage_publish: deps.coverage_publish,
            kv_db: deps.kv_db,
            app_consensus_cw: deps.app_consensus_cw,
            cw_handle: None,
            cw_committee_fp: None,
            cw_session: None,
            session_closing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            private_parents: None,
            sealed_session: None,
            seal_published_at: None,
            self_msg_tx: msg_tx,
            sizes,
            fee_snapshot,
            frame_outflows: Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
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

    /// Restore from the state store whenever execution is configured. The KV
    /// fallback is only for engines without state execution.
    fn load_materialized_cursor(&self) -> Result<u64> {
        if let Some(manager) = &self.execution_engine {
            return manager.read_app_materialized_cursor(&self.filter);
        }
        let value = match &self.kv_db {
            Some(kv) => kv.get(&quil_store::encoding::consensus_materialized_cursor_key(&self.filter))?,
            None => None,
        };
        match value {
            None => Ok(0),
            Some(bytes) => Ok(u64::from_be_bytes(bytes.as_slice().try_into().map_err(|_|
                QuilError::ExecutionUnavailable("malformed application materialized cursor".into()))?)),
        }
    }

    /// Save an external-sync checkpoint to the store used by cursor restore.
    /// The state import precedes this separate transaction. Publish in-memory
    /// progress only after success so a failed checkpoint can be retried.
    fn persist_materialized_cursor(&self, frame: u64) -> Result<()> {
        if let Some(manager) = &self.execution_engine {
            return manager.checkpoint_app_materialized_cursor(frame, &self.filter);
        }
        let kv = self.kv_db.as_ref().ok_or_else(|| QuilError::ExecutionUnavailable(
            "no store for application sync checkpoint".into()))?;
        kv.set(&quil_store::encoding::consensus_materialized_cursor_key(&self.filter),
            &frame.to_be_bytes())
    }

    /// Run a frame's `requests` through the execution engines on the
    /// blocking thread pool, off the engine's `tokio::select!` task.
    /// Materialization is CPU- and DB-bound; running it inline on the
    /// runtime worker thread head-of-line-blocks this worker's other
    /// async work (its consensus loop, its gRPC server) for the whole
    /// frame. `spawn_blocking` frees the runtime thread while the work
    /// runs. Ordering is unchanged: the caller `.await`s to completion
    /// before the engine polls its next event (the engine still holds
    /// `&mut self` exclusively across the await — no new reentrancy).
    /// Returns `Ok((0, 0))` with a warning if no execution engine is
    /// wired (matches the prior inline `if let Some(exec)` skip).
    async fn materialize_offloaded(
        &self,
        requests: Vec<quil_types::proto::global::MessageBundle>,
        frame_number: u64,
        difficulty: u32,
        fee_multiplier_vote: u64,
        global_frame_number: u64,
    ) -> Result<(usize, usize)> {
        let exec = match self.execution_engine.clone() {
            Some(e) => e,
            None => return Ok((0, 0)),
        };
        let collector = self.message_collector.clone();
        // Price from the network size certified by global consensus on the
        // anchored global frame — identical on every member — never from this
        // engine's own CRDT, which holds only the shards it covers.
        let world_size = certified_world_size(self.global_anchor_store.as_ref(), global_frame_number)?;
        let app_address = self.app_address.clone();
        let fee_snapshot = self.fee_snapshot.clone();
        let frame_outflows = self.frame_outflows.clone();
        let clock_store = self.clock_store.clone();
        let filter = self.filter.clone();
        let result = tokio::task::spawn_blocking(move || {
            let materialized = materialize_app_shard_requests(
                exec.as_ref(),
                &requests,
                frame_number,
                difficulty,
                world_size,
                fee_multiplier_vote,
                &app_address,
                global_frame_number,
            )?;
            let digest = quil_execution::token_intrinsic::accumulator_header::report_digest(&materialized.accumulator_report);
            let previous = materialized_accumulator_digest(&frame_outflows, clock_store.as_ref(), &filter, frame_number.saturating_sub(1));
            if !materialized.accumulator_report.is_empty() && previous.as_ref() != Some(&digest) {
                let local_root = exec.local_application_root_digest(&filter).ok().flatten()
                    .map(|root| hex::encode(&root[..8])).unwrap_or_default();
                info!(
                    frame = frame_number,
                    filter = %hex::encode(&filter),
                    report = %hex::encode(&digest[..8]),
                    local_root = %local_root,
                    "shard accumulator report changed",
                );
            }
            // The durable transaction already contains every history record.
            // Memory becomes visible only after that transaction succeeds.
            update_outflow(&frame_outflows, frame_number, |outflow| {
                outflow.fee_total = Some(materialized.fee_total);
                outflow.settlements = Some(materialized.settlements);
                outflow.spends = Some(materialized.spends);
                outflow.accumulator = Some(digest);
            });
            let result = (materialized.processed, materialized.skipped, materialized.taken);
            if let Some(application) = application_of_filter(&app_address) {
                *fee_snapshot.lock().unwrap_or_else(|e| e.into_inner()) = Some(quil_execution::pricing::AppFeeSnapshot {
                    application, frame_number, global_frame_number,
                    difficulty: difficulty as u64, world_state_bytes: world_size, fee_multiplier_vote,
                });
            }
            Ok(result)
        })
        .await
        .map_err(|e| QuilError::Internal(format!("materialize task panicked: {e}")))?;
        // The bundles that took effect, in the canonical encoding the
        // collector holds them in (`canonical_app_message`), are consumed.
        result.map(|(processed, skipped, taken)| {
            collector.mark_finalized(&taken);
            (processed, skipped)
        })
    }

    /// Recompute a received frame's `requests_root` on the blocking
    /// thread pool (the inclusion-prover commit is CPU-heavy). Same
    /// rationale as [`materialize_offloaded`].
    async fn recompute_requests_root_offloaded(
        &self,
        canonical: Vec<Vec<u8>>,
        frame_number: u64,
    ) -> Result<Vec<u8>> {
        let exec = self.execution_engine.clone();
        let prover = self.inclusion_prover.clone();
        let app_address = self.app_address.clone();
        let use_forest = self.hypergraph.as_ref().map(|h| h.has_forest()).unwrap_or(false);
        tokio::task::spawn_blocking(move || {
            compute_requests_root(
                &canonical,
                &app_address,
                frame_number,
                exec.as_deref(),
                prover.as_deref(),
                use_forest,
            )
        })
        .await
        .map_err(|e| QuilError::Internal(format!("requests_root task panicked: {e}")))?
    }

    /// Advance `last_materialized_frame` to a synced height reported by a
    /// background shard-tree sync, persist the cursor, and drop now-stale
    /// buffered frames + finalized-root entries. Idempotent: a sync that
    /// reports a height we're already past is a no-op.
    /// Advance the materialized-frame cursor (field + thread-safe mirror for the
    /// CW proposal check). Use this instead of assigning `last_materialized_frame`
    /// directly so `shard_mat_frame` stays consistent.
    /// This member executed certified frame `n` itself; extend its audited
    /// outgoing history so a restart need not re-audit it.
    fn extend_audited_history(&self, n: u64) {
        let (Some(session), Some(manager)) = (self.cw_session.as_ref(), self.execution_engine.as_ref()) else {
            return;
        };
        if session.filter != self.filter {
            return;
        }
        if let Err(error) = crate::app_history_recovery::extend_audited(manager, session, n) {
            debug!(frame = n, %error, "audited outgoing history not extended");
        }
    }

    /// When this shard's session was authorized from a GLOBAL fence below
    /// the local head, rewind the shard to the fence
    /// ([`crate::app_handoff::rewind_past_fence`]) and bring the engine's own
    /// view back with it: materialized frame, head, fee window and the
    /// finalized records of the discarded frames. True when it rewound.
    fn rewind_past_fence(&mut self) -> Result<bool> {
        let (Some(global), Some(shard)) = (
            self.global_hypergraph.clone(), self.execution_engine.as_ref().map(|m| m.crdt()),
        ) else {
            return Ok(false);
        };
        if quil_types::consensus::committee_handoff_policy().is_none() {
            return Ok(false);
        }
        let global_frame = self.global_anchor_store.get_latest_global_clock_frame().ok()
            .and_then(|f| f.header.map(|h| h.frame_number)).unwrap_or(0);
        let crate::app_handoff::SessionChoice::Session(session) =
            crate::app_handoff::resolve(&global, &self.filter, global_frame)?
        else {
            return Ok(false);
        };
        let Some(fence) = crate::app_handoff::rewind_past_fence(&global, &shard, self.clock_store.as_ref(), &session)? else {
            return Ok(false);
        };
        self.set_materialized_frame(fence);
        self.shard_frame_number = fence;
        let _ = self.fee_manager.rewind_to_frame(&self.filter, fence);
        if let Some(base) = self.cw_storage_base.as_ref() {
            let directory = base.join("cw-app-consensus").join(format!("finalized-{}", hex::encode(&self.filter)));
            if let Ok(records) = crate::cw_app_seams::FinalizedRecords::open(directory) {
                records.discard_above(fence);
            }
        }
        Ok(true)
    }

    fn set_materialized_frame(&mut self, n: u64) {
        let prev = self.last_materialized_frame;
        self.execution.materialized(n);
        self.last_materialized_frame = n;
        if let Some(parents) = self.private_parents.as_ref() {
            parents.retire_through(n);
        }
        self.shard_mat_frame
            .store(n, std::sync::atomic::Ordering::Relaxed);
        // The CW verify gate nullifies any proposal where `mat + 1 != N`
        // (app_engine.rs ~2326). If this line never logs a non-zero `now`, the
        // shard is wedged at genesis: every proposal is nullified, nothing
        // finalizes, and `mat` can never advance (self-sustaining deadlock).
        info!(
            filter = %hex::encode(&self.filter[..self.filter.len().min(8)]),
            prev,
            now = n,
            "app-shard materialized height advanced"
        );
    }

    /// Persist a certified shard frame as the shard clock head so the next
    /// `prove_next_state` (which reads `get_latest_shard_clock_frame`) chains on
    /// it. MUST be called by EVERY path that advances the materialized cursor —
    /// not only the CW-finalize handler, but also the leader self-materialize and
    /// the follower catch-up drain. Otherwise a node that materializes a frame
    /// OUTSIDE its own finalize handler (e.g. draining `received_full_frames`
    /// after a frame-sync) advances `mat` while the clock head stalls, and the
    /// (co-located, in cluster mode separate-process) proposer then reads the
    /// stale clock and RE-PROPOSES the already-materialized frame N — which every
    /// voter nullifies (`mat+1 != N`), producing a view-churn storm that never
    /// makes progress. Keeping clock-head == mat on every path removes that whole
    /// divergence class. Idempotent + monotonic: `commit_shard_clock_frame` only
    /// bumps the latest-index pointer when `frame_number` exceeds the current
    /// head (clock.rs:1152), so re-committing or filling a gap below the head can
    /// never regress it.
    fn commit_shard_clock_head(
        &self,
        frame: &quil_types::proto::global::AppShardFrame,
        frame_number: u64,
    ) -> Result<()> {
        let header = frame.header.as_ref().ok_or_else(|| QuilError::InvalidArgument(
            "shard clock frame has no header".into()))?;
        if header.frame_number != frame_number || header.address != self.filter {
            return Err(QuilError::InvalidArgument("shard clock frame context mismatch".into()));
        }
        let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?.to_vec();
        // The clock store resolves staged bytes from committed storage, so
        // staging must finish before the canonical/head transaction is built.
        let txn = self.clock_store.new_transaction(false)?;
        if let Err(error) = self.clock_store.stage_shard_clock_frame(&selector, frame, txn.as_ref()) {
            let _ = txn.abort();
            return Err(error);
        }
        txn.commit()?;
        let txn = self.clock_store.new_transaction(false)?;
        if let Err(error) = self.clock_store.commit_shard_clock_frame(
            &self.filter, frame_number, &selector, txn.as_ref(), false,
        ) {
            let _ = txn.abort();
            return Err(error);
        }
        txn.commit()
    }

    async fn reconcile_with_sync(&mut self, synced_to_frame: u64) -> Result<()> {
        // Do this before any buffered follower replay, including a sync to
        // the existing cursor. Otherwise the first replay persists an empty
        // or stale accumulator report alongside the imported coin state.
        if let Some(manager) = self.execution_engine.as_ref() {
            manager.rebuild_block_summary_before_report(&self.filter);
        }
        if synced_to_frame <= self.last_materialized_frame {
            return Ok(());
        }
        debug!(
            core_id = self.core_id,
            from = self.last_materialized_frame,
            to = synced_to_frame,
            "fast-forwarding materialized cursor from shard sync"
        );
        self.persist_materialized_cursor(synced_to_frame)?;
        self.set_materialized_frame(synced_to_frame);
        // Anything at/below the synced height is now covered by the
        // synced tree; drop stale buffers so they can't be re-applied.
        self.received_full_frames
            .retain(|&f, _| f > synced_to_frame);
        self.finalized_requests_roots
            .retain(|&f, _| f > synced_to_frame);
        // Continue materializing any contiguous frames we still hold.
        self.try_materialize_follower_frames().await;
        Ok(())
    }

    /// Wire a bounded historical proof source before the engine is started.
    pub fn with_storage_history_source(mut self, source: Option<crate::storage_history::GlobalVertexProofSource>) -> Self {
        self.storage_history_source = source;
        self.app_frame_validator = None;
        self
    }

    /// Wire the archive source of predecessor outgoing history
    /// ([`crate::app_handoff::recover_sealed_history`]).
    pub fn with_outgoing_history_source(mut self, source: Option<crate::app_handoff::OutgoingHistorySource>) -> Self {
        self.outgoing_history_source = source;
        self
    }

    pub fn with_global_anchor_source(mut self, source: Option<crate::global_anchor::GlobalAnchorSource>) -> Self {
        self.global_anchor_source = source;
        self.app_frame_validator = None;
        self
    }

    /// Wire the source of historical legacy committees before the engine is
    /// started.
    pub fn with_historical_committee_source(
        mut self,
        source: Option<crate::historical_committee::HistoricalCommitteeSource>,
    ) -> Self {
        self.historical_committee_source = source;
        self.app_frame_validator = None;
        self
    }

    /// The newer certified head when the running legacy instance started from
    /// an adopted head as genesis (`AppConsensusCwHandle::adopted_genesis`),
    /// has finalized nothing since, and this member's head has moved past it:
    /// the members did not share that head, and the ones behind caught up.
    fn adopted_genesis_superseded(&self) -> Option<u64> {
        let handle = self.cw_handle.as_ref()?;
        let genesis = handle.adopted_genesis?;
        if handle.finalized.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        let head = self.clock_store.get_latest_shard_clock_frame(&self.filter).ok()?;
        let header = head.header.as_ref()?;
        let certified = header.public_key_signature_bls48581.as_ref()
            .is_some_and(|signature| quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature).is_some());
        (certified && header.frame_number > genesis).then_some(header.frame_number)
    }

    /// Shared digest, storage and committee validator, independent of the
    /// currently running consensus host, for restart and follower replay.
    fn frame_validator(&mut self) -> Arc<BlsAppFrameValidator> {
        if let Some(validator) = self.app_frame_validator.as_ref() {
            return validator.clone();
        }
        // `.with_clock_store` is REQUIRED for storage-active frames: the validator
        // recomputes the deterministic ρ_N-bound output from the anchored global
        // frame's VDF output (resolved from our own clock store, never the wire).
        // Without it, verifying any storage frame fails "anchored global frame
        // unavailable for ρ_N" and the CW round never finalizes.
        let mut validator =
            BlsAppFrameValidator::new(
                self.prover_registry.clone(),
                Arc::new(quil_crypto::FalconKeyConstructor),
                self.frame_prover.clone(),
            )
            // Anchor store: the validator recomputes ρ_N from the anchored
            // GLOBAL frame, which on a worker lives only in the master's store.
            .with_clock_store(self.global_anchor_store.clone());
        if let Some(crdt) = &self.global_hypergraph {
            validator = validator.with_handoff_authority(crdt.clone());
        }
        if let Some(source) = &self.storage_history_source {
            validator = validator.with_storage_history_source(source.clone());
        }
        if let Some(source) = &self.global_anchor_source {
            validator = validator.with_global_anchor_source(source.clone());
        }
        if let Some(source) = &self.historical_committee_source {
            validator = validator.with_historical_committee_source(source.clone());
        }
        let validator = Arc::new(validator);
        self.app_frame_validator = Some(validator.clone());
        validator
    }

    async fn replay_archive_frame(
        &mut self,
        frame: quil_types::proto::global::AppShardFrame,
        child: Option<quil_types::proto::global::AppShardFrame>,
    ) -> Result<u64> {
        let validator = self.frame_validator();
        let uncertified = frame.header.as_ref()
            .and_then(|header| header.public_key_signature_bls48581.as_ref())
            .is_none_or(|signature| signature.signature.is_empty());
        if !uncertified {
            let retained = storage_history_retained(&validator, &frame).await;
            return self.replay_archive_frame_with(frame, |frame| {
                validate_certified_frame(&validator, frame, retained)
            }).await;
        }
        // Final only through its certified child: authenticate the child and
        // the link first, then the frame itself as a proposal. Its storage
        // history is fetched on the strength of the child's certificate: asked
        // for a certificate of its own, every such replay failed.
        let child = child.ok_or_else(|| QuilError::InvalidSignature(
            "archive replay frame has no certificate and no certified child".into()))?;
        let child_retained = storage_history_retained(&validator, &child).await;
        let linked = frame.header.as_ref().zip(child.header.as_ref())
            .is_some_and(|(parent, child)| crate::frame_validator::app_frame_links_to_child(parent, child));
        if !linked || !validate_certified_frame(&validator, &child, child_retained)? {
            return Err(QuilError::InvalidSignature("archive replay frame is not final through a certified child".into()));
        }
        let retained = match validator.prepare_storage_history_of_linked(&frame).await {
            Ok(()) => true,
            Err(error) => {
                warn!(frame = frame.header.as_ref().map_or(0, |header| header.frame_number), %error,
                    "storage history of a frame final through its child unavailable; validating it without possession");
                false
            }
        };
        self.replay_archive_frame_with(frame, |frame| {
            if retained {
                return validate_app_frame_panic_safe(&validator, frame, true);
            }
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| validator.validate_linked_without_storage(frame))) {
                Ok(result) => result,
                Err(_) => Err(QuilError::Internal("linked frame validation panicked".into())),
            }
        }).await
    }

    async fn replay_archive_frame_with<F>(
        &mut self,
        frame: quil_types::proto::global::AppShardFrame,
        validate: F,
    ) -> Result<u64>
    where F: FnOnce(&quil_types::proto::global::AppShardFrame) -> Result<bool> {
        let header = frame.header.as_ref().ok_or_else(|| {
            QuilError::InvalidArgument("archive replay frame has no header".into())
        })?;
        if header.address != self.filter {
            return Err(QuilError::InvalidArgument("archive replay frame belongs to another shard".into()));
        }
        let number = header.frame_number;
        if number <= self.last_materialized_frame {
            return Ok(self.last_materialized_frame);
        }
        if number != self.last_materialized_frame + 1 {
            return Err(QuilError::ExecutionUnavailable("archive replay would skip a materialization gap".into()));
        }
        if !validate(&frame)? {
            return Err(QuilError::InvalidSignature("archive replay certificate rejected".into()));
        }
        let previous = if number > 1 {
            Some(self.clock_store.get_shard_clock_frame(&self.filter, number - 1, false)?)
        } else { None };
        let genesis = self.first_frame_genesis(&frame)?;
        archive_bootstrap_predecessor_height_in(&self.filter, &frame, previous.as_ref(), genesis.as_ref())
            .map_err(|error| QuilError::InvalidArgument(error.into()))?;
        let hg = self.hypergraph.as_ref().ok_or_else(|| {
            QuilError::ExecutionUnavailable("archive replay has no local state".into())
        })?;
        if self.execution_engine.is_none() {
            return Err(QuilError::ExecutionUnavailable("archive replay has no executor".into()));
        }
        let app: [u8; 32] = self.filter.get(..32).and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| QuilError::InvalidArgument("invalid archive replay filter".into()))?;
        let shard = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3), l2: app,
        };
        for (i, (set, phase)) in [("vertex", "adds"), ("vertex", "removes"),
                                 ("hyperedge", "adds"), ("hyperedge", "removes")].iter().enumerate() {
            let mut root = if hg.unified_tree() {
                hg.sub_shard_commitment_for_filter(set, phase, &self.filter)
            } else { hg.compute_shard_root(set, phase, &shard) };
            if root.is_empty() { root = vec![0; if hg.has_forest() { 32 } else { 64 }]; }
            if root != header.state_roots[i] {
                return Err(QuilError::ExecutionUnavailable(format!("archive replay pre-state mismatch at phase {i}")));
            }
        }
        let canonical = frame.requests.iter()
            .map(crate::consensus_wire::proto_message_bundle_to_canonical_bytes)
            .collect::<Result<Vec<_>>>()?;
        if self.recompute_requests_root_offloaded(canonical, number).await? != header.requests_root {
            return Err(QuilError::InvalidArgument("archive replay body does not match its certified root".into()));
        }
        if self.finalized_requests_roots.get(&number).is_some_and(|root| root != &header.requests_root) {
            return Err(QuilError::InvalidSignature("conflicting finalized archive replay frame".into()));
        }
        // No archive write occurs before all checks above. Replay uses the same
        // ordered materializer as live followers, including persisted outflows.
        self.commit_shard_clock_head(&frame, number)?;
        self.finalized_requests_roots.insert(number, header.requests_root.clone());
        self.received_full_frames.insert(number, frame);
        self.try_materialize_follower_frames().await;
        if self.last_materialized_frame < number {
            return Err(QuilError::ExecutionUnavailable("archive replay materialization did not commit".into()));
        }
        if let Some(header) = self.received_full_frames.get(&number).and_then(|f| f.header.clone())
            .or_else(|| self.clock_store.get_shard_clock_frame(&self.filter, number, false).ok().and_then(|f| f.header))
        {
            self.adopt_certified_relays(&header);
        }
        self.data_ready.store(true, std::sync::atomic::Ordering::Release);
        Ok(self.last_materialized_frame)
    }

    async fn validate_archive_sync_anchor(
        &mut self,
        anchor: &quil_types::proto::global::AppShardFrame,
        predecessor: Option<&quil_types::proto::global::AppShardFrame>,
    ) -> Result<u64> {
        let validator = self.frame_validator();
        let anchor_history = storage_history_retained(&validator, anchor).await;
        let predecessor_history = match predecessor {
            Some(previous) => storage_history_retained(&validator, previous).await,
            None => true,
        };
        let genesis = self.first_frame_genesis(anchor)?;
        let mut first = true;
        validate_archive_sync_anchor_in(
            &self.filter, self.last_materialized_frame, anchor, predecessor, genesis.as_ref(),
            |frame| {
                let retained = if std::mem::take(&mut first) { anchor_history } else { predecessor_history };
                validate_certified_frame(&validator, frame, retained)
            },
        )
    }

    /// A finalized header carries the quorum-certified fee total of its
    /// previous frame and the settlement and spend windows it relays. A member
    /// that reached those frames by sync rather than by materializing them has
    /// no local records; adopting the certified ones lets it validate the next
    /// header instead of nullifying until it materializes a frame itself. A
    /// local record that disagrees is a divergence: keep it. Runs for frames
    /// finalized live and for certified frames replayed from an archive (the
    /// anchor a bootstrap ends on is such a frame, and without this every
    /// member that joined by sync nullified the first header after it).
    fn adopt_certified_relays(&self, header: &quil_types::proto::global::FrameHeader) {
        if header.frame_number <= 1 {
            return;
        }
        let previous = header.frame_number - 1;
        let certified = quil_execution::global_intrinsic::frame_header::fee_total_from_bytes(&header.fee_total);
        match materialized_fee_total(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, previous) {
            None => record_fee_total(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, previous, certified),
            Some(local) if local != certified => warn!(
                core_id = self.core_id, frame = header.frame_number, local, certified,
                "cw finalized frame: certified previous-frame fee total differs from the local materialization",
            ),
            Some(_) => {}
        }
        adopt_certified_settlements(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, header);
        adopt_certified_spends(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, header);
        adopt_certified_accumulator(&self.frame_outflows, self.clock_store.as_ref(), &self.filter, header);
    }

    /// The authorized genesis `frame` must name as its parent when it is the
    /// first data frame of a committee session, per committed GLOBAL state.
    /// `None` for every other frame and for legacy (generation-zero) frames.
    fn first_frame_genesis(
        &self,
        frame: &quil_types::proto::global::AppShardFrame,
    ) -> Result<Option<[u8; 32]>> {
        let (Some(global), Some(header)) = (self.global_hypergraph.as_ref(), frame.header.as_ref()) else {
            return Ok(None);
        };
        let Some(generation) = header.public_key_signature_bls48581.as_ref()
            .and_then(|s| quil_cw_consensus::app_cert::unwrap_cert_from_header(&s.signature))
            .and_then(quil_cw_consensus::app_cert::unverified_finalization_epoch)
            .filter(|generation| *generation > 0)
        else {
            return Ok(None);
        };
        use quil_execution::global_intrinsic::handoff;
        let view = handoff::CommittedView::capture(global)?;
        Ok(handoff::session_at_generation(&view, &header.address, generation)?
            .filter(|session| header.frame_number == session.base_frame + 1)
            .map(|session| session.genesis))
    }

    /// Frame N advertises state after N-1, so install certified frame N-1 as
    /// the clock head after the worker tree has synced to N's roots.
    async fn install_archive_bootstrap(
        &mut self,
        anchor: quil_types::proto::global::AppShardFrame,
        predecessor: Option<quil_types::proto::global::AppShardFrame>,
    ) -> bool {
        let synced_to = match self.validate_archive_sync_anchor(&anchor, predecessor.as_ref()).await {
            Ok(height) => height,
            Err(error) => {
                warn!(core_id = self.core_id, error = %error, "archive sync completion rejected");
                return false;
            }
        };
        // Frame-one bootstraps have no predecessor and skip reconciliation.
        // Their anchor replay still needs a summary of the newly imported data.
        if let Some(manager) = self.execution_engine.as_ref() {
            manager.rebuild_block_summary_before_report(&self.filter);
        }
        let anchor_n = anchor.header.as_ref().expect("validated above").frame_number;
        if synced_to > 0 {
            let predecessor = predecessor.expect("validated above");
            if let Err(error) = self.commit_shard_clock_head(&predecessor, synced_to) {
                warn!(core_id = self.core_id, synced_to, error = %error,
                    "app-shard bootstrap clock persistence failed");
                return false;
            }
            if let Err(error) = self.reconcile_with_sync(synced_to).await {
                warn!(core_id = self.core_id, synced_to, error = %error,
                    "app-shard bootstrap checkpoint failed");
                return false;
            }
        }
        // In particular, syncing the pre-state of frame 1 must not leave a
        // joining member at clock/cursor zero, proposing frame 1 again while
        // existing members are already at 1 and require frame 2.
        if let Err(error) = self.replay_archive_frame(anchor, None).await {
            warn!(core_id = self.core_id, anchor_frame = anchor_n, %error,
                "app-shard bootstrap anchor replay failed");
            return false;
        }
        info!(core_id = self.core_id, anchor_frame = anchor_n, synced_to,
            "app-shard bootstrap installed predecessor and replayed certified anchor");
        true
    }

    /// At the moment this worker's anchored global frame reaches the unified
    /// cutover, fold its covered app's pre-cutover per-sub-shard trees into the
    /// single app.l2 tree (the consolidation hook) and flip its CRDT to unified —
    /// so the per-shard `state_root` becomes the covered SUBTREE root
    /// (computable from partial storage). Idempotent: a no-op once unified or
    /// before the cutover. Every worker on the shard runs it at the same anchored
    /// frame over committed state, so producers and verifiers flip together and
    /// agree on the post-cutover roots. Called before producing/validating a frame.
    fn maybe_flip_unified_at_cutover(&self) {
        let Some(hg) = self.hypergraph.as_ref() else {
            return;
        };
        if hg.unified_tree() {
            return;
        }
        let (anchor_gfn, _) = resolve_global_anchor(self.global_anchor_store.as_ref());
        if anchor_gfn
            < quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame()
        {
            return;
        }
        if let Some(hook) = self.unified_cutover_hook.as_ref() {
            if !hook(&self.filter, anchor_gfn) {
                tracing::warn!(
                    core_id = self.core_id,
                    anchor_gfn,
                    "unified cutover consolidation failed — deferring flip this cycle"
                );
                return;
            }
        }
        hg.set_unified_tree(true);
        tracing::info!(
            core_id = self.core_id,
            anchor_gfn,
            "worker app-tree unified commitment ACTIVATED at cutover"
        );
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
    /// Fetch and store the certified frames holding the bytes of everything
    /// committed to this shard that it has not delivered yet. On a
    /// whole-application shard every
    /// source is a frame this node already has and nothing is fetched; on a
    /// split one the sources are other shards' frames, which only an archive
    /// holds. A frame that does not arrive simply leaves the delivery waiting.
    /// Re-request the covered shard's data bootstrap while propose/vote is
    /// gated on it.
    ///
    /// The request made at committee build fires when the worker is spawned,
    /// which on a fresh boot is before peer discovery has put any archive in
    /// the pool: the syncer then resolves an EMPTY endpoint ("invalid URI"),
    /// gives up, and nothing retries it until the next committee rebuild. A
    /// node restarting into a SPLIT application has no stored frames for its
    /// child shard either, so it takes the bootstrap branch, fails it once, and
    /// sits gated indefinitely — every member doing the same leaves the shard
    /// with no proposer at all. `data_ready` is sticky and the worker keeps one
    /// sync in flight, so this is a no-op once the data lands.
    fn request_data_bootstrap_if_unstaged(&self) {
        if self.data_ready.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if self.covered_data_staged() {
            self.data_ready.store(true, std::sync::atomic::Ordering::Release);
            return;
        }
        let _ = self.event_tx.send(AppEngineEvent::ShardDataBootstrapRequested {
            filter: self.filter.clone(),
        });
    }

    async fn fetch_delivery_sources(&self) {
        let (Some(manager), Some(fetch)) = (self.execution_engine.as_ref(), self.delivery_frame_source.as_ref()) else {
            return;
        };
        let global = match self.storage_source_hypergraph.as_ref().or(self.hypergraph.as_ref()) {
            Some(crdt) => crdt.clone(),
            None => return,
        };
        let sources = match manager.pending_delivery_sources(global, &self.filter) {
            Ok(sources) => sources,
            Err(error) => {
                debug!(filter = hex::encode(&self.filter), %error, "delivery sources unavailable");
                return;
            }
        };
        for (filter, frame_number) in sources {
            // Already here: this shard's own frames, and anything fetched
            // earlier. Nothing is refetched.
            if self.clock_store.get_shard_clock_frame(&filter, frame_number, false).is_ok() {
                continue;
            }
            let Some(frame) = fetch(filter.clone(), frame_number).await else {
                debug!(filter = hex::encode(&filter), frame = frame_number, "delivery source frame not available yet");
                continue;
            };
            let Some(header) = frame.header.as_ref() else { continue };
            if header.address != filter || header.frame_number != frame_number {
                warn!(filter = hex::encode(&filter), frame = frame_number, "delivery source frame is not the one requested");
                continue;
            }
            let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
                .map(|hash| hash.to_vec())
                .unwrap_or_default();
            let stored = self.clock_store.new_transaction(false).ok().and_then(|txn| {
                self.clock_store.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).ok()?;
                txn.commit().ok()?;
                let txn = self.clock_store.new_transaction(false).ok()?;
                self.clock_store.commit_shard_clock_frame(&filter, frame_number, &selector, txn.as_ref(), true).ok()?;
                txn.commit().ok()
            });
            if stored.is_some() {
                info!(filter = hex::encode(&filter), frame = frame_number, "fetched a delivery's source frame");
            } else {
                warn!(filter = hex::encode(&filter), frame = frame_number, "storing a delivery's source frame failed");
            }
        }
    }

    pub async fn run(
        mut self,
        // A FACTORY (not a single signer) so the passive-mode retry below can
        // obtain a fresh signer: the committee may not be buildable on the first
        // attempt (a cluster worker's registry is still syncing), and
        // `start_consensus_cw` consumes the signer, so a retry needs another.
        bls_signer_factory: std::sync::Arc<
            dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync,
        >,
    ) {
        let mut msg_rx = self.msg_rx.take().expect("msg_rx already taken");

        info!(
            core_id = self.core_id,
            filter = hex::encode(&self.filter),
            "app consensus engine starting"
        );

        // Restore the durable materialized-frame cursor so the
        // idempotency gate (and gap detection) resume where the prior
        // session left off rather than re-materializing from 0. This is
        // the CRDT-application height; it may legitimately lag the clock
        // frame height below (the frame is finalized in the clock store
        // before its requests are materialized — a crash in that window
        // leaves cursor < clock height, healed by gossip replay of the
        // missing full frame or a shard sync).
        // Early: a shard layout not loaded yet defers the check to consensus start.
        match self.rewind_past_fence() {
            Err(error @ QuilError::ExecutionUnavailable(_)) => {
                debug!(core_id = self.core_id, %error, "fence rewind check deferred to consensus start");
            }
            Err(error) => warn!(core_id = self.core_id, %error, "could not rewind shard state past a fenced checkpoint"),
            Ok(_) => {}
        }
        // A node that starts past the committee-handoff flag day discards its
        // legacy app history before restoring a cursor into it.
        if let Err(error) = self.discard_legacy_history_if_due().await {
            warn!(core_id = self.core_id, %error, "legacy app history could not be discarded at startup");
        }
        let restored_cursor = match self.load_materialized_cursor() {
            Ok(cursor) => cursor,
            Err(error) => {
                tracing::error!(core_id = self.core_id, error = %error, "cannot restore application execution cursor; refusing startup");
                return;
            }
        };
        self.set_materialized_frame(restored_cursor);
        if self.last_materialized_frame > 0 {
            info!(
                core_id = self.core_id,
                materialized = self.last_materialized_frame,
                "restored materialized-frame cursor"
            );
        }

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
                    // The stored head is certified: a member whose earlier life
                    // reached it by sync may hold no relay records for the
                    // frames its header carries, and a stalled chain sends no
                    // newer header to adopt them from.
                    if h.frame_number <= self.last_materialized_frame {
                        self.adopt_certified_relays(h);
                    }
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

        // ONE-TIME startup sync of the covered shard's committed data from the
        // storage source (the master's genesis-seeded/forest-filled hypergraph)
        // into this worker's OWN crdt, BEFORE consensus can propose or verify.
        // Per-worker stores start empty; the seeded genesis coins live only in
        // the master store. The storage-attestation path (`prove_next_state`)
        // syncs them lazily, but that runs AFTER `state_roots` is computed, so the
        // first proposal reads an un-synced (zero) pre-state root while later
        // verifiers read the synced (non-zero) root → every proposal is nullified
        // (state_roots mismatch) and the app-shard CW churns views + leaks journal
        // buffers. Syncing here makes the own crdt's committed root deterministic
        // from frame 1 (mat=0) on every node, so leader and verifier agree. No-op
        // for archives/tests (no separate source) and for empty shards (copied=0).
        if let (Some(source), Some(own_crdt)) =
            (self.storage_source_hypergraph.as_ref(), self.hypergraph.as_ref())
        {
            let app_addr = self.filter[..self.filter.len().min(32)].to_vec();
            match crate::app_shard_metadata::sync_app_shard_to_own_crdt(
                source.as_ref(),
                own_crdt.as_ref(),
                &app_addr,
                0,
            ) {
                Ok(n) if n > 0 => info!(
                    core_id = self.core_id,
                    copied = n,
                    "startup: synced app-shard seed data into own crdt (deterministic pre-state)"
                ),
                Err(e) => warn!(
                    core_id = self.core_id,
                    error = %e,
                    "startup app-shard sync into own crdt failed"
                ),
                _ => {}
            }
        }

        // A CW engine must not emit its first simplex messages until its topic
        // is subscribed locally and a remote subscriber is present. The master
        // sends `CwTransportReady` after that condition becomes true.
        let mut cw_transport_ready = false;
        info!(core_id = self.core_id, filter = hex::encode(&self.filter),
            "waiting for CW topic transport readiness before starting consensus");

        // Frame cleanup timer — remove stale cached frames every 60s
        let mut cleanup_timer = tokio::time::interval(Duration::from_secs(60));
        cleanup_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Passive-mode retry timer: if the committee wasn't buildable on the first
        // attempt (cluster worker's registry still syncing / provers not yet
        // Active), retry until it starts. Cheap no-op once running.
        let mut cw_retry_timer = tokio::time::interval(Duration::from_secs(10));
        cw_retry_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Pull the frames this shard's pending deliveries read their bytes
        // from, so a proposal finds them locally instead of blocking on I/O.
        let mut delivery_source_timer = tokio::time::interval(Duration::from_secs(10));
        delivery_source_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                // Inbound network messages
                msg = msg_rx.recv() => {
                    // Flip this worker's CRDT to unified (+ consolidate) once
                    // its anchored global frame reaches the cutover, BEFORE any
                    // produce/validate/materialize below computes a `state_root`.
                    // Idempotent + cheap after the flip (a `bool` load).
                    self.maybe_flip_unified_at_cutover();
                    match msg {
                        Some(AppEngineMessage::Consensus(_data)) => {
                            // Legacy HotStuff consensus wire messages are no
                            // longer processed — the commonware-simplex path
                            // carries consensus over `CwIn`. Drop.
                        }
                        Some(AppEngineMessage::Prover(data)) => {
                            self.handle_prover_message(&data);
                        }
                        Some(AppEngineMessage::Frame(data)) => {
                            self.handle_frame_message(&data).await;
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
                        Some(AppEngineMessage::ReplayArchiveFrame { frame, child, reply }) => {
                            if !reply.is_closed() {
                                let result = self.replay_archive_frame(frame, child).await;
                                let _ = reply.send(result);
                            }
                        }
                        Some(AppEngineMessage::OriginAnchors { reply }) => {
                            let anchors = match self.global_hypergraph.as_ref() {
                                Some(global) if quil_types::consensus::committee_handoff_policy().is_some() => {
                                    crate::app_handoff::origin_anchors(global, &self.filter).unwrap_or_else(|error| {
                                        warn!(core_id = self.core_id, %error, "origin anchors unavailable");
                                        Vec::new()
                                    })
                                }
                                _ => Vec::new(),
                            };
                            let _ = reply.send(anchors);
                        }
                        Some(AppEngineMessage::ValidateShardSyncAnchor { anchor, predecessor, reply }) => {
                            let valid = match self.validate_archive_sync_anchor(&anchor, predecessor.as_ref()).await {
                                Ok(_) => true,
                                Err(error) => {
                                    warn!(core_id = self.core_id, error = %error, "archive sync anchor rejected before tree writes");
                                    false
                                }
                            };
                            if valid && !reply.is_closed() {
                                self.data_ready.store(false, std::sync::atomic::Ordering::Release);
                            }
                            let _ = reply.send(valid);
                        }
                        Some(AppEngineMessage::ShardSyncCompleted { synced_to_frame }) => {
                            if let Err(error) = self.reconcile_with_sync(synced_to_frame).await {
                                warn!(core_id = self.core_id, synced_to_frame, error = %error,
                                    "shard sync checkpoint failed; readiness not advanced");
                                continue;
                            }
                            // Covered data is now staged — un-gate propose/vote.
                            self.inherit_pending.store(false, std::sync::atomic::Ordering::Release);
                            self.data_ready.store(true, std::sync::atomic::Ordering::Release);
                        }
                        Some(AppEngineMessage::ShardBootstrapCompleted { anchor, predecessor, reply }) => {
                            if !self.install_archive_bootstrap(anchor, predecessor).await {
                                let _ = reply.send(false);
                                continue;
                            }
                            // Covered data is now staged — un-gate propose/vote. The
                            // cw_handle is rebuilt below and reads this same flag.
                            self.inherit_pending.store(false, std::sync::atomic::Ordering::Release);
                            self.data_ready.store(true, std::sync::atomic::Ordering::Release);
                            if let Some(old) = self.cw_handle.take() {
                                if let Err(e) = old.shutdown_and_join().await {
                                    warn!(core_id = self.core_id, error = %e, "old app consensus host stopped with an error");
                                }
                            }
                            let _ = reply.send(true);
                        }
                        Some(AppEngineMessage::CwFinalizedFrame {
                            frame,
                            cert,
                            locally_verified,
                            implied,
                        }) => {
                            self.handle_cw_finalized_frame(&frame, &cert, locally_verified, implied)
                                .await;
                        }
                        Some(AppEngineMessage::CwSealed { seal, cert }) => {
                            self.handle_cw_sealed(&seal, cert).await;
                        }
                        Some(AppEngineMessage::CwIn { channel, from, data }) => {
                            if let Some(h) = self.cw_handle.as_ref() {
                                if channel == crate::cw_app_seams::CW_APP_BLOCK_CHANNEL {
                                    // Authorize the block channel like channels 0/1/2:
                                    // require the sender key to
                                    // resolve (the master resolves it from committee
                                    // membership) before storing. Previously channel 3
                                    // ingested any bytes, ignoring `from` — letting an
                                    // unresolved peer feed/overwrite the block store
                                    // (the block is still verified at `verify`, so this
                                    // is authorization/DoS hardening, not a safety hole).
                                    if quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(&from).is_some() {
                                        if let Ok(frame) = <quil_types::proto::global::AppShardFrame as prost::Message>::decode(data.as_slice()) {
                                            if let Some(header) = frame.header.as_ref() {
                                                let cursor = self.shard_mat_frame.load(std::sync::atomic::Ordering::Relaxed);
                                                if header.frame_number > cursor.saturating_add(1) {
                                                    let _ = self.event_tx.send(AppEngineEvent::AncestorSyncRequested {
                                                        filter: self.filter.clone(),
                                                        missing_frames: vec![cursor.saturating_add(1)],
                                                    });
                                                }
                                            }
                                        }
                                        (h.ingest_block)(data);
                                    } else {
                                        tracing::debug!(
                                            core_id = self.core_id,
                                            "cw app block: unresolved sender key, dropping block",
                                        );
                                    }
                                } else if (channel as usize) < h.inbound.len() {
                                    match quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(&from) {
                                        Some(pk) => {
                                            let _ = h.inbound[channel as usize].send(
                                                quil_cw_consensus::p2p_bridge::inbound_message(pk, data),
                                            );
                                        }
                                        None => tracing::debug!(
                                            core_id = self.core_id,
                                            "cw app inbound: unresolved sender key, dropping"
                                        ),
                                    }
                                }
                            }
                        }
                        Some(AppEngineMessage::CwTransportReady) => {
                            if !cw_transport_ready {
                                cw_transport_ready = true;
                                match self.start_consensus_cw((bls_signer_factory)()).await {
                                    Ok(handle) => {
                                        self.cw_handle = Some(handle);
                                        info!(core_id = self.core_id, filter = hex::encode(&self.filter),
                                            "shard commonware-simplex consensus running after transport readiness");
                                    }
                                    Err(e) => warn!(core_id = self.core_id, error = %e,
                                        "failed to start shard simplex after transport readiness — will retry"),
                                }
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
                    self.retry_certified_parent_seals().await;
                    if self.pending_follower_clock.is_some() {
                        self.try_materialize_follower_frames().await;
                    }
                    self.cleanup_frame_store();
                }

                // Passive-mode CW retry: keep trying to start simplex until the
                // committee is buildable (the shard's active provers are present
                // in this node's registry). No-op once running.
                _ = delivery_source_timer.tick() => {
                    self.fetch_delivery_sources().await;
                    self.request_data_bootstrap_if_unstaged();
                }

                _ = cw_retry_timer.tick() => {
                    // A held finalized frame (transient materialization fault)
                    // is retried here, not only when another frame arrives.
                    if self.received_full_frames.contains_key(&(self.last_materialized_frame + 1)) {
                        self.try_materialize_follower_frames().await;
                    }
                    self.heal_disagreeing_pre_state();
                    if let Err(error) = self.discard_legacy_history_if_due().await {
                        warn!(core_id = self.core_id, %error, "legacy app history could not be discarded; will retry");
                    }
                    // This timer also handles dynamic-committee rebuilds below.
                    // Keep *both* paths behind the transport barrier: otherwise
                    // a timer tick while CW is still waiting for a subscribed
                    // peer can instantiate simplex and emit the very startup
                    // messages that the barrier is meant to prevent.
                    self.maintain_committee_session().await;
                    if self.cw_handle.as_ref().is_some_and(|h| h.is_dead()) {
                        error!(core_id = self.core_id, filter = hex::encode(&self.filter),
                            "app consensus host died; rebuilding it");
                        if let Some(dead) = self.cw_handle.take() {
                            let _ = dead.shutdown_and_join().await;
                        }
                    }
                    if cw_transport_ready && self.cw_handle.is_none() {
                        // Passive-mode retry: keep trying until the committee is
                        // buildable (active provers present in this registry).
                        match self.start_consensus_cw((bls_signer_factory)()).await {
                            Ok(handle) => {
                                self.cw_handle = Some(handle);
                                info!(
                                    core_id = self.core_id,
                                    filter = hex::encode(&self.filter),
                                    "shard commonware-simplex consensus started on retry (EQUAL VOTES)"
                                );
                            }
                            Err(e) => {
                                // Under committee sessions this is the only
                                // trace of why a shard is not running yet.
                                if quil_types::consensus::committee_handoff_policy().is_some() {
                                    info!(core_id = self.core_id, error = %e, "cw retry: app consensus not startable yet");
                                } else {
                                    debug!(
                                        core_id = self.core_id,
                                        error = %e,
                                        "cw retry: committee not yet buildable"
                                    );
                                }
                            }
                        }
                    } else if cw_transport_ready && self.cw_session.is_none() {
                        // DYNAMIC COMMITTEE (legacy registry committees only; an
                        // authorized session changes through its handoff): if the shard's active-prover set
                        // changed since this instance was built (e.g. a prover's
                        // deferred activation reached its epoch, growing a 1-member
                        // floor committee to the real N-member set), tear down the
                        // old simplex instance (fixed validator set) and rebuild
                        // with the new committee.
                        let members = self.compute_committee_members();
                        let fp = Self::committee_fp(&members);
                        if !members.is_empty() && Some(fp) != self.cw_committee_fp {
                            info!(
                                core_id = self.core_id,
                                filter = hex::encode(&self.filter),
                                members = members.len(),
                                "app-shard committee changed — rebuilding CW consensus"
                            );
                            if let Some(old) = self.cw_handle.take() {
                                if let Err(e) = old.shutdown_and_join().await {
                                    warn!(core_id = self.core_id, error = %e, "old app consensus host stopped with an error");
                                }
                            }
                            match self.start_consensus_cw((bls_signer_factory)()).await {
                                Ok(handle) => {
                                    self.cw_handle = Some(handle);
                                    info!(
                                        core_id = self.core_id,
                                        filter = hex::encode(&self.filter),
                                        members = members.len(),
                                        "app-shard CW consensus rebuilt with new committee"
                                    );
                                }
                                Err(e) => {
                                    warn!(core_id = self.core_id, error = %e, "committee rebuild failed — will retry");
                                }
                            }
                        } else if let Some(head) = self.adopted_genesis_superseded() {
                            // Its members never agreed on the head it started
                            // from; start again from the newer certified one.
                            info!(
                                core_id = self.core_id,
                                filter = hex::encode(&self.filter),
                                head,
                                "legacy app consensus never finalized from its adopted genesis — restarting from the newer certified head"
                            );
                            if let Some(old) = self.cw_handle.take() {
                                if let Err(e) = old.shutdown_and_join().await {
                                    warn!(core_id = self.core_id, error = %e, "old app consensus host stopped with an error");
                                }
                            }
                            match self.start_consensus_cw((bls_signer_factory)()).await {
                                Ok(handle) => self.cw_handle = Some(handle),
                                Err(e) => warn!(core_id = self.core_id, error = %e, "app consensus restart failed — will retry"),
                            }
                        }
                    }
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
            self.execution.observe();
            self.publish_sizes();
        }
        if let Some(old) = self.cw_handle.take() {
            if let Err(e) = old.shutdown_and_join().await {
                warn!(core_id = self.core_id, error = %e, "app consensus host stopped with an error");
            }
        }
    }

    /// Stop the engine.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    // ---------------------------------------------------------------
    // Consensus event loop startup
    // ---------------------------------------------------------------

    /// Start commonware-simplex + Falcon consensus for this shard, reusing
    /// the SAME `AppLeaderProvider` construction as the legacy path. EQUAL VOTES:
    /// the committee is the shard's active provers' Falcon keys, count-based.
    /// Returns the handle (the run loop stores it in `self.cw_handle`). Must be
    /// called from within the worker's tokio runtime (spawns the outbound drain).
    ///
    /// N=1 first cut: uses a no-op transport (a single-prover shard self-proposes
    /// and self-finalizes; there are no peers to deliver to). Multi-node gossip
    /// transport is the next wiring step.
    /// The current committee's member Falcon pubkeys, read at the GLOBAL anchor
    /// epoch (`committee_anchor_gfn`), matching the leader provider + produced/
    /// verified frames. Empty when unresolved (drives the passive-mode retry).
    fn compute_committee_members(&self) -> Vec<Vec<u8>> {
        let (committee_anchor, _) = resolve_global_anchor(self.global_anchor_store.as_ref());
        let committee_frame = if committee_anchor > 0 {
            committee_anchor
        } else {
            self.clock_store
                .get_latest_shard_clock_frame(&self.filter)
                .ok()
                .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
                .unwrap_or(0)
                .saturating_add(1)
        };
        self.prover_registry
            .get_active_provers(&self.filter, committee_frame)
            .map(|a| a.iter().map(|p| p.public_key.clone()).collect())
            .unwrap_or_default()
    }

    /// A finalized terminal seal: stop the closed session's host and submit the
    /// closing certificate. Every member that observes the finalization submits;
    /// the global intrinsic accepts the identical seal idempotently.
    async fn handle_cw_sealed(&mut self, seal: &[u8], cert: Vec<u8>) {
        let Some(session) = self.cw_session.clone() else { return };
        let submission = match (session.id(), crate::app_handoff::submission(seal, cert)) {
            (Ok(id), Ok(bytes)) => (id, bytes),
            (id, bytes) => {
                warn!(core_id = self.core_id, id_ok = id.is_ok(), error = ?bytes.err(),
                    "finalized terminal seal could not be encoded for submission");
                return;
            }
        };
        info!(core_id = self.core_id, filter = hex::encode(&self.filter),
            session = hex::encode(submission.0), "app committee session sealed; submitting closing certificate");
        if let Some(publish) = self.coverage_publish.as_ref() {
            publish(submission.1.clone());
        }
        self.sealed_session = Some(submission);
        self.seal_published_at = Some(std::time::Instant::now());
        if let Some(old) = self.cw_handle.take() {
            if let Err(e) = old.shutdown_and_join().await {
                warn!(core_id = self.core_id, error = %e, "sealed app consensus host stopped with an error");
            }
        }
    }

    /// Timer-driven session upkeep: republish an unrecorded closing certificate,
    /// and stop a host whose session was retired or superseded so the retry
    /// path resolves the successor.
    async fn maintain_committee_session(&mut self) {
        let Some(global) = self.global_hypergraph.clone() else {
            return;
        };
        let Some(session) = self.cw_session.clone() else {
            self.adopt_registered_session(&global).await;
            return;
        };
        // Every member of the closing committee submits the seal; a copy
        // already in flight needs no repeat until it has had time to land.
        // Resubmissions are spaced a minute apart, staggered per member, so a
        // committee's members do not flood GLOBAL in step while their views of
        // it lag.
        let resubmit_after = std::time::Duration::from_secs(
            60 + u64::from(self.local_bls_pubkey.last().copied().unwrap_or(0) % 30),
        );
        let due = self.seal_published_at.is_none_or(|at| at.elapsed() >= resubmit_after);
        if let (Some((_, submission)), true) = (self.sealed_session.as_ref(), due) {
            let view = quil_execution::global_intrinsic::handoff::CommittedView::capture(&global);
            let recorded = view.and_then(|view|
                quil_execution::global_intrinsic::handoff::schedule::seal_submitted(&view, &session));
            if matches!(recorded, Ok(false)) {
                if let Some(publish) = self.coverage_publish.as_ref() {
                    publish(submission.clone());
                }
                self.seal_published_at = Some(std::time::Instant::now());
            }
        }
        match crate::app_handoff::still_current(&global, &session) {
            Ok(true) => {}
            Ok(false) => {
                info!(core_id = self.core_id, filter = hex::encode(&self.filter),
                    generation = session.generation, "app committee session retired; resolving its successor");
                if let Some(old) = self.cw_handle.take() {
                    if let Err(e) = old.shutdown_and_join().await {
                        warn!(core_id = self.core_id, error = %e, "retired app consensus host stopped with an error");
                    }
                }
                self.cw_session = None;
            }
            Err(error) => debug!(core_id = self.core_id, error = %error, "committee session status unavailable"),
        }
    }

    /// A legacy instance whose shard GLOBAL has since registered (generation
    /// zero): stop it, so the retry path restarts it
    /// under that session, over the same journal, committee and namespace and
    /// inside the handoff automaton that drains and seals it.
    ///
    /// On a flag day (`quil_types::consensus::LegacyHistory::Discard`) the legacy instance stops at
    /// activation whether or not the first session is authorized yet: GLOBAL
    /// accepts no legacy frame from then on.
    async fn adopt_registered_session(&mut self, global: &Arc<quil_hypergraph::HypergraphCrdt>) {
        let Some(policy) = quil_types::consensus::committee_handoff_policy() else { return };
        if self.cw_handle.is_none() {
            return;
        }
        let global_frame = self.global_anchor_store.get_latest_global_clock_frame().ok()
            .and_then(|f| f.header.map(|h| h.frame_number)).unwrap_or(0);
        let stop = match crate::app_handoff::resolve(global, &self.filter, global_frame) {
            Ok(crate::app_handoff::SessionChoice::Session(session)) => {
                info!(core_id = self.core_id, filter = hex::encode(&self.filter),
                    generation = session.generation, base_frame = session.base_frame,
                    "legacy app shard registered as a committee session; restarting its consensus under it");
                true
            }
            Ok(crate::app_handoff::SessionChoice::Pending(why))
                if policy.legacy_history == quil_types::consensus::LegacyHistory::Discard =>
            {
                info!(core_id = self.core_id, filter = hex::encode(&self.filter), global_frame, why,
                    "committee sessions activated: legacy app consensus stops; its history is discarded");
                true
            }
            Ok(_) => false,
            Err(error) => {
                debug!(core_id = self.core_id, %error, "committee session registration unreadable");
                false
            }
        };
        if stop {
            if let Some(old) = self.cw_handle.take() {
                if let Err(e) = old.shutdown_and_join().await {
                    warn!(core_id = self.core_id, error = %e, "legacy app consensus host stopped with an error");
                }
            }
        }
    }

    /// Committee-handoff flag day (`LegacyHistory::Discard`): once this
    /// node's GLOBAL chain reaches activation, discard the application frame
    /// history this engine's store holds (`ClockStore::discard_app_frame_history`:
    /// every shard's frames, per-frame records and cursors), keeping the
    /// application state, before any session runs here. The store records
    /// that it ran, so it runs once. A running legacy host stops first.
    /// Returns whether it discarded.
    async fn discard_legacy_history_if_due(&mut self) -> Result<bool> {
        let Some(policy) = quil_types::consensus::committee_handoff_policy()
            .filter(|policy| policy.legacy_history == quil_types::consensus::LegacyHistory::Discard)
        else {
            return Ok(false);
        };
        let global_frame = self.global_anchor_store.get_latest_global_clock_frame().ok()
            .and_then(|f| f.header.map(|h| h.frame_number)).unwrap_or(0);
        if global_frame < policy.activation_frame || self.clock_store.app_frame_history_discarded()?.is_some() {
            return Ok(false);
        }
        if let Some(old) = self.cw_handle.take() {
            if let Err(e) = old.shutdown_and_join().await {
                warn!(core_id = self.core_id, error = %e, "legacy app consensus host stopped with an error");
            }
        }
        self.clock_store.discard_app_frame_history(global_frame)?;
        // What this engine holds of the discarded chain.
        self.set_materialized_frame(0);
        self.shard_frame_number = 0;
        let _ = self.fee_manager.rewind_to_frame(&self.filter, 0);
        self.frame_outflows.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.received_full_frames.clear();
        self.pending_follower_clock = None;
        self.finalized_requests_roots.clear();
        self.materialize_failures.clear();
        self.message_spillover.clear();
        self.proposal_cache.clear();
        self.pending_certified_parents.clear();
        self.retry_parent_seals.clear();
        self.pending_seal_rank = None;
        self.frame_requests.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.frame_attestations.lock().unwrap_or_else(|e| e.into_inner()).clear();
        if let Some(parents) = self.private_parents.as_ref() {
            parents.clear();
        }
        if let Some(base) = self.cw_storage_base.as_ref() {
            let directory = base.join("cw-app-consensus").join(format!("finalized-{}", hex::encode(&self.filter)));
            if let Ok(records) = crate::cw_app_seams::FinalizedRecords::open(directory) {
                records.discard_above(0);
            }
        }
        forget_legacy_relay_boundaries();
        info!(core_id = self.core_id, filter = hex::encode(&self.filter), global_frame,
            "committee-handoff flag day: legacy app frame history discarded; application state kept");
        Ok(true)
    }

    /// After this store discarded its legacy history, finalized records this
    /// shard kept from a legacy instance (its own, or an earlier assignment's
    /// left beside it) are not replayed into a session.
    fn drop_discarded_finalized_records(&self) -> Result<()> {
        let Some(policy) = quil_types::consensus::committee_handoff_policy() else { return Ok(()) };
        if policy.legacy_history != quil_types::consensus::LegacyHistory::Discard
            || self.clock_store.app_frame_history_discarded()?.is_none()
        {
            return Ok(());
        }
        let Some(base) = self.cw_storage_base.as_ref() else { return Ok(()) };
        let directory = base.join("cw-app-consensus").join(format!("finalized-{}", hex::encode(&self.filter)));
        if !directory.exists() {
            return Ok(());
        }
        let records = crate::cw_app_seams::FinalizedRecords::open(directory)
            .map_err(|e| QuilError::Internal(format!("open finalized app frames: {e}")))?;
        let dropped = records.discard_anchored_before(policy.activation_frame);
        if dropped > 0 {
            info!(core_id = self.core_id, filter = hex::encode(&self.filter), dropped,
                "dropped finalized app frames of the discarded legacy history");
        }
        Ok(())
    }

    /// Order-independent fingerprint of a committee member set.
    fn committee_fp(members: &[Vec<u8>]) -> [u8; 32] {
        use sha2::Digest as _;
        let mut sorted: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
        sorted.sort_unstable();
        let mut h = sha2::Sha256::new();
        for m in sorted {
            h.update(m);
        }
        h.finalize().into()
    }

    /// Inherit the shard's range from an archive once proposals keep failing
    /// this member's pre-state check while no frame materializes. A legacy
    /// merge's members each hold only their source's range (the session path
    /// inherits it up front, `app_handoff::merged_from`); they refuse each
    /// other's proposals and the merged shard never finalizes a frame. Rate
    /// limited; the bootstrap re-gates proposing and voting until installed.
    fn heal_disagreeing_pre_state(&mut self) {
        use std::sync::atomic::Ordering;
        let (seen, last) = self.pre_state_heal;
        if self.last_materialized_frame != seen {
            self.pre_state_heal = (self.last_materialized_frame, last);
            self.pre_state_mismatches.store(0, Ordering::Release);
            return;
        }
        let mismatches = self.pre_state_mismatches.load(Ordering::Acquire);
        if mismatches < PRE_STATE_MISMATCH_BOOTSTRAP
            || self.inherit_pending.load(Ordering::Acquire)
            || last.is_some_and(|at| at.elapsed() < PRE_STATE_HEAL_INTERVAL)
        {
            return;
        }
        warn!(core_id = self.core_id, filter = hex::encode(&self.filter), mismatches,
            materialized = self.last_materialized_frame,
            "proposals keep failing this member's pre-state and no frame materializes: inheriting the shard's range from an archive");
        self.pre_state_heal = (seen, Some(std::time::Instant::now()));
        self.pre_state_mismatches.store(0, Ordering::Release);
        self.inherit_pending.store(true, Ordering::Release);
        self.data_ready.store(false, Ordering::Release);
        let _ = self.event_tx.send(AppEngineEvent::ShardDataBootstrapRequested { filter: self.filter.clone() });
    }

    /// Whether this member's own CRDT holds committed data in the covered
    /// subtree. Unified trees are read directly from the persisted forest;
    /// metadata buckets may be absent after sync. Empty subtrees require the
    /// authenticated bootstrap/replay path before readiness becomes sticky.
    fn covered_data_staged(&self) -> bool {
        if self.inherit_pending.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let Some(hg) = self.hypergraph.as_ref() else {
            return true;
        };
        crate::app_shard_metadata::has_committed_shard_data(hg, &self.filter)
    }

    async fn start_consensus_cw(
        &mut self,
        signer: Box<dyn quil_types::crypto::Signer>,
    ) -> Result<crate::cw_app_seams::AppConsensusCwHandle> {
        let result = self.start_consensus_cw_observed(signer).await;
        match &result {
            Ok(_) => self.execution.state("running", ""),
            Err(error) => {
                let text = error.to_string();
                let blocker = if text.contains("sealed checkpoint") { "checkpoint mismatch" }
                    else if text.contains("awaiting its successor") { "awaiting successor" }
                    else if text.contains("bootstrap") || text.contains("authenticated GLOBAL") { "state unavailable" }
                    else { "consensus startup unavailable" };
                self.execution.state("blocked", blocker);
            }
        }
        result
    }

    async fn start_consensus_cw_observed(
        &mut self,
        bls_signer: Box<dyn quil_types::crypto::Signer>,
    ) -> Result<crate::cw_app_seams::AppConsensusCwHandle> {
        let filter = self.filter.clone();
        let app_address = self.app_address.clone();
        self.discard_legacy_history_if_due().await?;
        self.drop_discarded_finalized_records()?;
        self.rewind_past_fence()?;

        // Candidate anchor for a NEW local session. An existing journal reuses
        // its persisted genesis below. Different members' heads may disagree;
        // common committee-transition checkpoints remain a separate requirement.
        let recovered_head = match self.clock_store.get_latest_shard_clock_frame(&filter) {
            Ok(frame) => Some(frame),
            Err(QuilError::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        if let Some(frame) = recovered_head.as_ref() {
            // Warms the registrations the head's attestation names; the head
            // was validated when it was stored, so a history no archive
            // retains any longer does not stop consensus from starting.
            storage_history_retained(&self.frame_validator(), frame).await;
        }
        let (genesis_output, mut genesis_frame_number) = match recovered_head.as_ref() {
            Some(frame) => {
                let header = frame.header.as_ref().ok_or_else(|| QuilError::Internal(
                    "app consensus latest shard frame has no header".into(),
                ))?;
                if header.address != filter {
                    return Err(QuilError::Internal("app consensus head belongs to another shard".into()));
                }
                (header.output.clone(), header.frame_number)
            }
            None => (vec![0u8; 32], 0),
        };
        let mut genesis_id = quil_crypto::poseidon::hash_bytes_to_32(&genesis_output)
            .map_err(|e| QuilError::Crypto(format!("app genesis poseidon: {e}")))?;

        // An authorized committee session fixes the members, namespace, epoch
        // and genesis; the registry-derived committee is the legacy path only.
        let session = match self.global_hypergraph.as_ref() {
            Some(global) => {
                let global_frame = self.global_anchor_store.get_latest_global_clock_frame().ok()
                    .and_then(|f| f.header.map(|h| h.frame_number)).unwrap_or(0);
                match crate::app_handoff::resolve(global, &filter, global_frame)? {
                    crate::app_handoff::SessionChoice::Legacy => None,
                    crate::app_handoff::SessionChoice::Pending(reason) => {
                        return Err(QuilError::Consensus(format!("app committee session unavailable: {reason}")));
                    }
                    crate::app_handoff::SessionChoice::Session(session) => Some(session),
                }
            }
            None if quil_types::consensus::committee_handoff_policy().is_some() => {
                return Err(QuilError::ExecutionUnavailable(
                    "app committee sessions need this worker's authenticated GLOBAL state".into()));
            }
            None => None,
        };
        let mut session_genesis = None;
        if let Some(session) = session.as_ref() {
            let session_id = session.id()?;
            if self.sealed_session.as_ref().is_some_and(|(id, _)| *id == session_id) {
                return Err(QuilError::Consensus("app committee session is sealed; awaiting its successor".into()));
            }
            // The execution manager's CRDT is where state, cursor and outgoing
            // history commit together; checkpoints must come from that store.
            let (Some(global), Some(shard)) = (
                self.global_hypergraph.clone(), self.execution_engine.as_ref().map(|m| m.crdt()),
            ) else {
                return Err(QuilError::ExecutionUnavailable("app committee session needs shard state".into()));
            };
            let global = &global;
            // A member that joined a same-filter predecessor through an
            // archive-anchored jump holds none of its outgoing records before the
            // anchor. Rebuild them from the predecessor's certified headers, so
            // the successor check re-derives the sealed history instead of
            // accepting it on state-root equality.
            if let Some(manager) = self.execution_engine.clone() {
                let view = quil_execution::global_intrinsic::handoff::CommittedView::capture(global)?;
                for (source, checkpoint) in quil_execution::global_intrinsic::handoff::origins(&view, &session.id()?)? {
                    if source.filter != session.filter || self.last_materialized_frame != checkpoint.frame {
                        continue;
                    }
                    match crate::app_history_recovery::recover(
                        &source, manager.clone(), self.clock_store.clone(), self.frame_validator(),
                        self.delivery_frame_source.as_ref(), checkpoint.frame,
                    ).await {
                        Ok(true) => {}
                        Ok(false) => {
                            return Err(QuilError::ExecutionUnavailable(
                                "predecessor outgoing history recovery is still in progress".into()));
                        }
                        Err(error) => warn!(
                            filter = hex::encode(&session.filter), generation = source.generation, %error,
                            "predecessor outgoing history could not be recovered from certified headers",
                        ),
                    }
                }
            }
            // What certified headers could not rebuild (an omitted report with
            // no carry, a header this member cannot fetch), an archive's
            // records can, accepted only against the sealed history root.
            if let Some(fetch) = self.outgoing_history_source.as_ref() {
                if let Err(error) = crate::app_handoff::recover_sealed_history(global, &shard, session, fetch).await {
                    warn!(filter = hex::encode(&session.filter), generation = session.generation, %error,
                        "predecessor outgoing history could not be recovered from an archive");
                }
            }
            if let Err(error) = crate::app_handoff::successor_state_matches(global, &shard, self.clock_store.as_ref(), session) {
                // A member that did not run (or did not finish) the predecessor
                // recovers its sealed state through the shard sync: a replay of
                // the missing frames from an archive when it has a lineage, the
                // archive's certified tip otherwise. Nothing else requests it,
                // and the retry loop would otherwise ask this question forever.
                if matches!(error, QuilError::ExecutionUnavailable(_)) {
                    let _ = self.event_tx.send(AppEngineEvent::ShardDataBootstrapRequested {
                        filter: self.filter.clone(),
                    });
                }
                return Err(error);
            }
            if session.generation == 0 {
                // Generation zero continues the legacy instance: the same journal,
                // genesis, epoch and namespace, resumed from
                // this member's certified head. That head must include the legacy
                // tip GLOBAL registered; a member behind it catches up first.
                if self.last_materialized_frame < session.base_frame {
                    let _ = self.event_tx.send(AppEngineEvent::ShardDataBootstrapRequested {
                        filter: self.filter.clone(),
                    });
                    return Err(QuilError::ExecutionUnavailable(format!(
                        "generation zero starts at the legacy tip {}; materialized through {}",
                        session.base_frame, self.last_materialized_frame,
                    )));
                }
            } else {
                let view = quil_execution::global_intrinsic::handoff::CommittedView::capture(global)?;
                session_genesis = Some(SessionGenesis {
                    base_frame: session.base_frame,
                    id: session.genesis,
                    output: quil_execution::global_intrinsic::handoff::schedule::genesis_output(&view, session)?,
                });
                genesis_id = session.genesis;
                genesis_frame_number = session.base_frame;
            }
        }
        // Generation zero is the legacy instance under a session: its journal and
        // chaining stay legacy, while its committee, drain and seal are the session's.
        let continues_legacy = session.as_ref().is_none_or(|session| session.generation == 0);

        // Committee = active provers' Falcon public keys (count-based, no
        // seniority), evaluated at the GLOBAL anchor epoch — the SAME frame the
        // leader provider (`committee_anchor_gfn`) and produced/verified frames
        // use. Reading it at the app-shard `genesis_frame_number` (unrelated to
        // global) would seed the simplex `peers` set from the wrong epoch, out of
        // step with the leader schedule. Falls back to the shard anchor pre-fork
        // (global chain absent → both are epoch 0).
        let member_pubkeys = match session.as_ref() {
            Some(session) => session.members.clone(),
            None => self.compute_committee_members(),
        };
        // Record the committee fingerprint so the run loop can detect a
        // membership change and rebuild (dynamic committee).
        self.cw_committee_fp = Some(Self::committee_fp(&member_pubkeys));
        let my_sk = bls_signer.private_key().to_vec();
        let my_pk = bls_signer.public_key().to_vec();
        let (scheme, peers) = match session.as_ref() {
            Some(session) => crate::cw_app_seams::build_session_committee(session, &my_sk, &my_pk),
            None => crate::cw_app_seams::build_app_committee(&member_pubkeys, &my_sk, &my_pk, &app_address),
        }
                .ok_or_else(|| {
                    QuilError::Consensus(
                        "app CW committee build failed (this node's key not in the active set?)"
                            .into(),
                    )
                })?;

        if let (Some(session), Some(manager)) = (session.as_ref(), self.execution_engine.clone()) {
            let validator = self.frame_validator();
            let recovered = crate::app_history_recovery::recover(
                session, manager, self.clock_store.clone(), validator,
                self.delivery_frame_source.as_ref(), self.last_materialized_frame,
            ).await;
            // A completed batch may have corrected old records. No host is
            // running yet, so its parent/history cache will be built afresh.
            self.frame_outflows.lock().unwrap_or_else(|e| e.into_inner()).clear();
            if !recovered? {
                return Err(QuilError::ExecutionUnavailable("outgoing history recovery is still in progress".into()));
            }
        }

        // Leader provider — identical construction to the legacy path.
        let app_leader = Arc::new(AppLeaderProvider {
            filter: filter.clone(),
            clock_store: self.clock_store.clone(),
            frame_outflows: self.frame_outflows.clone(),
            global_anchor_store: self.global_anchor_store.clone(),
            frame_prover: self.frame_prover.clone(),
            prover_registry: self.prover_registry.clone(),
            message_collector: self.message_collector.clone(),
            mempool: self.message_collector.clone(),
            fee_manager: self.fee_manager.clone(),
            local_prover_address: self.local_prover_address.clone(),
            local_public_key: self.local_bls_pubkey.clone(),
            current_difficulty: self.current_difficulty.clone(),
            reward_greedy: self.reward_greedy,
            hypergraph: self.hypergraph.clone(),
            storage_source_hypergraph: self.storage_source_hypergraph.clone(),
            shard_drain: self.shard_drain.clone(),
            execution_engine: self.execution_engine.clone(),
            inclusion_prover: self.inclusion_prover.clone(),
            app_address: app_address.clone(),
            halted: self.halted.clone(),
            min_active_provers_for_propose: self.min_active_provers_for_propose,
            shard_mat_frame: self.shard_mat_frame.clone(),
            frame_requests: self.frame_requests.clone(),
            kv_db: self.kv_db.clone(),
            frame_attestations: self.frame_attestations.clone(),
            routing_seen: self.routing_seen.clone(),
            // Pin the committee this instance signs with, so the leader can
            // refuse to propose frames whose verifier-reconstructed committee
            // would no longer match (epoch-straddle guard).
            instance_committee_fp: session.is_none().then(|| Self::committee_fp(&member_pubkeys)),
            session_genesis,
            under_session: session.is_some(),
            session_closing: self.session_closing.clone(),
            private_parent: false,
        });
        let leader_provider: Arc<
            dyn quil_consensus::leader_provider::LeaderProvider<AppShardState>,
        > = app_leader.clone();

        // `.with_clock_store` is REQUIRED for storage-active frames: the validator
        // recomputes the deterministic ρ_N-bound output from the anchored global
        // frame's VDF output (resolved from our own clock store, never the wire).
        // Without it, verifying any storage frame fails "anchored global frame
        // unavailable for ρ_N" and the CW round never finalizes.
        let validator = self.frame_validator();

        // Assembler: read the leader's recorded request bundles for the produced
        // frame (`frame_requests` is a shared `Arc<Mutex>`) + build the full frame.
        let assemble: crate::cw_app_seams::AppFrameAssembler = {
            let frame_requests = self.frame_requests.clone();
            let frame_attestations = self.frame_attestations.clone();
            Arc::new(move |state| {
                let fnum = state.state.frame_number;
                let reqs = frame_requests
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&fnum).cloned())
                    .unwrap_or_default();
                let attestation = frame_attestations
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&fnum).cloned())
                    .unwrap_or_default();
                Some(crate::cw_app_seams::app_frame_from_state(state, reqs, attestation))
            })
        };

        // on_finalized: route the finalized frame back into THIS engine's run
        // loop (it runs on the simplex thread → `try_send` into `msg_tx`), where
        // `handle_cw_finalized_frame` materializes it on `&mut self`.
        let on_finalized: crate::cw_app_seams::AppFinalizedSink = {
            let msg_tx = self.self_msg_tx.clone();
            Arc::new(move |frame, cert, locally_verified, implied| {
                let mut buf = Vec::new();
                if prost::Message::encode(&frame, &mut buf).is_err() {
                    return false;
                }
                let implied = implied.into_iter()
                    .map(|(ancestor, verified)| (prost::Message::encode_to_vec(&ancestor), verified))
                    .collect();
                msg_tx.try_send(AppEngineMessage::CwFinalizedFrame {
                    frame: buf,
                    cert,
                    locally_verified,
                    implied,
                }).is_ok()
            })
        };
        // App shards resolve their parent from the shard clock store, so no
        // notarize-candidate write is needed (unlike global).
        let on_notarized: crate::cw_app_seams::AppFrameSink = Arc::new(|_frame| {});

        let transport: Arc<dyn crate::cw_app_seams::AppConsensusTransport> =
            Arc::new(EngineCwTransport {
                filter: filter.clone(),
                event_tx: self.event_tx.clone(),
            });

        let partition = format!("app-{}", hex::encode(&app_address));
        // Persistent per-shard journal dir (Go parity) so app-shard consensus
        // resumes across restarts instead of replaying from its genesis floor;
        // `None` (no data dir → tests / cluster workers) stays ephemeral.
        let cw_app_storage_dir = self
            .cw_storage_base
            .as_ref()
            .map(|base| base.join("cw-app-consensus").join(&partition));
        // Each session journals apart: its ID binds members, generation and
        // genesis, so there is no earlier descriptor to reconcile or retire.
        // Generation zero keeps the legacy journal: the same namespace, epoch and
        // committee, so its recorded votes still bind this member.
        let cw_app_storage_dir = match session.as_ref().filter(|_| !continues_legacy) {
            Some(session) => cw_app_storage_dir
                .map(|dir| Ok::<_, QuilError>(dir.join(format!("session-{}", hex::encode(session.id()?)))))
                .transpose()?,
            None => cw_app_storage_dir,
        };
        let candidate_anchor = (genesis_id, genesis_frame_number);
        // A legacy head another committee certified cannot be this committee's
        // finalized floor. Once it validates under the committee that did
        // certify it, the instance starts from it as genesis, and a journal of
        // an older genesis is retired (see `cw_app_seams::restart_finalization`).
        let adopt_head = match (session.as_ref(), recovered_head.as_ref()) {
            (None, Some(frame)) => {
                let mut namespace = b"appshard".to_vec();
                namespace.extend_from_slice(&filter);
                let foreign = frame.header.as_ref().is_some_and(|header| {
                    header.frame_number > 0
                        && matches!(
                            crate::cw_app_seams::restart_finalization(header, &peers, &namespace, APP_CW_EPOCH, true),
                            Ok(None)
                        )
                });
                foreign && matches!(validate_app_frame_panic_safe(&self.frame_validator(), frame, false), Ok(true))
            }
            _ => false,
        };
        if let Some(dir) = cw_app_storage_dir.as_ref().filter(|_| continues_legacy) {
            (genesis_id, genesis_frame_number) = prepare_app_cw_journal(
                dir, &peers, &filter, &my_pk, genesis_id, genesis_frame_number, adopt_head,
            ).map_err(|e| QuilError::Internal(format!("prepare app consensus journal: {e}")))?;
        }
        if (genesis_id, genesis_frame_number) != candidate_anchor {
            let empty_genesis = quil_crypto::poseidon::hash_bytes_to_32(&[0u8; 32])?;
            if genesis_frame_number != 0 || genesis_id != empty_genesis {
                let frame = self.clock_store.get_shard_clock_frame(&filter, genesis_frame_number, false)?;
                let header = frame.header.ok_or_else(|| QuilError::Internal(
                    "persisted app consensus genesis frame has no header".into(),
                ))?;
                if header.frame_number != genesis_frame_number
                    || quil_crypto::poseidon::hash_bytes_to_32(&header.output)? != genesis_id
                {
                    return Err(QuilError::Consensus(
                        "persisted app consensus genesis disagrees with local shard history".into(),
                    ));
                }
            }
        }
        let genesis_digest = quil_cw_consensus::adapters::digest_from_identity(genesis_id);
        info!(filter = %hex::encode(&filter), genesis_frame_number,
            genesis = %hex::encode(genesis_id), persistent = cw_app_storage_dir.is_some(),
            "starting app CW consensus session");
        // Body-root cross-check for the CW verify path. The
        // lightweight seam validator can't recompute the body root (no exec /
        // inclusion prover), so build a closure over THIS engine's deps that
        // recomputes `requests_root` from the carried `frame.requests` and
        // compares it to the declared root — exactly as the follower/archive
        // ingest paths do. An honest member then never signs a proposal whose
        // body doesn't match its (about-to-be-certified) root, so conflicting
        // bodies under one digest can't diverge replica state. `None` when the
        // engine has no exec/inclusion/hypergraph → voting disabled.
        let requests_root_check: Option<crate::cw_app_seams::AppRequestsRootCheck> =
            match (
                self.execution_engine.clone(),
                self.inclusion_prover.clone(),
                self.hypergraph.clone(),
            ) {
                (Some(exec), Some(incl), Some(hg)) => Some(build_requests_root_check(
                    exec,
                    incl,
                    hg,
                    self.app_address.clone(),
                    self.shard_mat_frame.clone(),
                    self.frame_outflows.clone(),
                    self.clock_store.clone(),
                    self.filter.clone(),
                    self.shard_drain.clone(),
                    Some(self.pre_state_mismatches.clone()),
                )),
                _ => None,
            };
        // Stage-gate: the CW proposer/verifier are gated on `data_ready` until this
        // member holds the covered sub-shard's committed DATA in its own CRDT.
        // Without it, `build_vote_openings` yields no storage openings → the frame
        // carries no attestation → the global proof-of-storage gate zeroes the shard
        // reward (and producing on empty state forks the shard + churns the CW
        // re-seed). Re-evaluated on each committee (re)build. The check reads the
        // FOREST (`covered_data_staged`), NOT the write-time size bucket — a synced tree
        // populates the forest but not that bucket. `data_ready` is STICKY: once set
        // (forest has data, or a bootstrap converged — the latter covers a genuinely
        // EMPTY shard, which has nothing to stage yet must still produce), a later
        // rebuild never flips it back off. If not yet staged, kick off a PROACTIVE
        // data bootstrap now (while Joining) so we're ready before Active.
        // A merged shard's first session: every member holds one source's data
        // and must inherit the whole merged range from an archive first, or the
        // members' pre-state roots disagree and no frame can be verified (the
        // merge sits at frame 1 with every proposal failing the state-root check).
        if !self.data_ready.load(std::sync::atomic::Ordering::Relaxed) {
            if let (Some(global), Some(session)) = (self.global_hypergraph.as_ref(), session.as_ref()) {
                match crate::app_handoff::merged_from(global, session) {
                    Ok(true) => {
                        // Whether or not the range still has to be inherited, this
                        // member's block summary describes its source shard's
                        // blocks; the report must fold the merged range.
                        if let Some(manager) = self.execution_engine.as_ref() {
                            manager.rebuild_block_summary_before_report(&self.filter);
                            // A frame this member already materialized with the
                            // old summary recorded that report; the next header
                            // is verified against the record, so refresh it.
                            let cursor = self.last_materialized_frame;
                            // The report a frame carries is gated by the GLOBAL
                            // frame that frame cites, as when it was materialized.
                            let anchor = self.clock_store.get_shard_clock_frame(&self.filter, cursor, false).ok()
                                .and_then(|frame| frame.header.map(|header| header.global_frame_number));
                            if let (true, Some(anchor)) = (cursor > 0, anchor) {
                                if let Ok(report) = manager.shard_accumulator_report(&self.filter, anchor) {
                                    record_frame_accumulator(
                                        &self.frame_outflows, self.clock_store.as_ref(), &self.filter, cursor, &report,
                                    );
                                }
                            }
                        }
                        if recovered_head.is_none() {
                            info!(core_id = self.core_id, filter = hex::encode(&self.filter),
                                "app-shard: first session of a merged shard — inheriting the merged range before consensus");
                            self.inherit_pending.store(true, std::sync::atomic::Ordering::Release);
                        }
                    }
                    Ok(false) => {}
                    Err(error) => warn!(core_id = self.core_id, %error, "could not read the session's activating request"),
                }
            }
        }
        if self.covered_data_staged() {
            self.data_ready.store(true, std::sync::atomic::Ordering::Release);
        } else if !self.data_ready.load(std::sync::atomic::Ordering::Relaxed) {
            info!(
                core_id = self.core_id,
                filter = hex::encode(&self.filter),
                "app-shard: covered data not staged — gating propose/vote and requesting proactive data bootstrap"
            );
            let _ = self.event_tx.send(AppEngineEvent::ShardDataBootstrapRequested {
                filter: self.filter.clone(),
            });
        }

        // A selected parent that is notarized but not yet materialized is
        // executed privately so the shard never stalls on it.
        self.private_parents = match (
            self.execution_engine.clone(),
            self.inclusion_prover.clone(),
            requests_root_check.clone(),
        ) {
            (Some(exec), Some(incl), Some(check)) => Some(Arc::new(AppParentExecutor::new(
                self.filter.clone(),
                self.app_address.clone(),
                exec.clone(),
                exec.crdt(),
                self.clock_store.clone(),
                self.global_anchor_store.clone(),
                self.frame_outflows.clone(),
                incl,
                {
                    let validator = validator.clone();
                    Arc::new(move |frame: &quil_types::proto::global::AppShardFrame| {
                        validator.validate_notarized_parent(frame)
                    })
                },
                check,
                self.shard_mat_frame.clone(),
                app_leader.clone(),
                session.as_ref().filter(|_| !continues_legacy).map(|s| (s.base_frame, s.genesis)),
            ))),
            _ => None,
        };
        self.session_closing.store(false, std::sync::atomic::Ordering::Release);
        let epoch = session.as_ref().map_or(APP_CW_EPOCH, |session| session.generation);
        let session_host = match session.as_ref() {
            Some(session) => {
                let (Some(global), Some(shard)) = (
                    self.global_hypergraph.clone(), self.execution_engine.as_ref().map(|m| m.crdt()),
                ) else {
                    return Err(QuilError::ExecutionUnavailable("app committee session needs shard state".into()));
                };
                let source = crate::app_handoff::ParentSource::new(
                    session.clone(), global, shard, self.clock_store.clone(), self.session_closing.clone(),
                )?;
                let msg_tx = self.self_msg_tx.clone();
                let read_private_parent = self.private_parents.clone().map(|parents| {
                    let source = source.clone();
                    let last_reported = Arc::new(std::sync::atomic::AtomicU64::new(0));
                    Arc::new(move |context: quil_cw_consensus::adapters::ProposalContext| {
                        parents
                            .prepare(context.parent, context.parent_view)
                            .and_then(|parent| source.read_private(context, &parent))
                            .inspect_err(|error| {
                                // The consensus automaton discards this error, so
                                // it is the only trace of why an unfinalized
                                // parent was not used; at most twice a minute.
                                use std::sync::atomic::Ordering;
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |d| d.as_secs());
                                let last = last_reported.load(Ordering::Relaxed);
                                if now >= last + 30 && last_reported
                                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                                    .is_ok()
                                {
                                    tracing::info!(view = context.view, parent_view = context.parent_view, %error,
                                        "unfinalized session parent not executable privately");
                                }
                            })
                    }) as quil_cw_consensus::handoff::automaton::ParentReader
                });
                Some(crate::cw_app_seams::SessionHost {
                    session: session.clone(),
                    read_parent: source.reader(),
                    read_private_parent,
                    on_sealed: Arc::new(move |seal, cert| {
                        msg_tx.try_send(AppEngineMessage::CwSealed { seal, cert }).is_ok()
                    }),
                })
            }
            None => None,
        };
        // Kept per filter, not per session, so a frame finalized just before a
        // handoff is still delivered after a restart into the next session.
        let finalized_records = self.cw_storage_base.as_ref()
            .filter(|_| self.execution_engine.is_some())
            .map(|base| (
                base.join("cw-app-consensus").join(format!("finalized-{}", hex::encode(&self.filter))),
                self.shard_mat_frame.clone(),
            ));
        // This host numbers its views afresh; keep what is held collectable.
        self.message_collector.rebase_ranks();
        let handle = crate::cw_app_seams::activate_app_consensus_cw(
            scheme,
            peers,
            leader_provider,
            validator,
            assemble,
            on_notarized,
            on_finalized,
            filter,
            partition,
            epoch,
            genesis_digest,
            genesis_frame_number,
            recovered_head,
            30, // leader_timeout_secs (localnet default)
            transport,
            cw_app_storage_dir,
            requests_root_check,
            self.data_ready.clone(),
            session_host,
            self.private_parents.clone(),
            finalized_records,
        )?;
        if let Some(session) = session.as_ref() {
            info!(filter = %hex::encode(&self.filter), generation = session.generation,
                base_frame = session.base_frame, members = session.members.len(),
                session = %hex::encode(session.id()?), "app committee session host started");
        }
        self.cw_session = session;
        Ok(handle)
    }

    // ---------------------------------------------------------------
    // Message handlers
    // ---------------------------------------------------------------

    /// Handle a prover message (MessageBundle containing prover ops).
    fn handle_prover_message(&mut self, data: &[u8]) {
        if self.halted.load(std::sync::atomic::Ordering::Relaxed) || data.len() < 4 {
            return;
        }
        // Add to message collector for inclusion in next frame
        self.add_app_message(data);
    }

    /// Handle a frame message (AppShardFrame from another prover).
    /// Materialize a simplex-FINALIZED app frame. The frame is already
    /// certified by the CW committee quorum, so — unlike [`handle_frame_message`]
    /// — this does NOT run the BLS-aggregate-signature gate (a CW frame carries a
    /// Falcon certificate, not a BLS aggregate in its header). Whether this node
    /// proposed the frame or received it, the flow is the same: apply the
    /// requests, seal the shard clock head, advance + persist the durable cursor,
    /// and publish the full frame for followers/archives on `shard_frame_bitmask`.
    /// Whether a frame's carried body hashes to its declared `requests_root`
    /// (always true without an execution engine, which has nothing to apply).
    fn body_matches_requests_root(&self, frame: &quil_types::proto::global::AppShardFrame) -> bool {
        let (Some(exec), Some(header)) = (self.execution_engine.as_ref(), frame.header.as_ref()) else {
            return true;
        };
        let canonical: Vec<Vec<u8>> = frame
            .requests
            .iter()
            .filter_map(|b| crate::consensus_wire::proto_message_bundle_to_canonical_bytes(b).ok())
            .collect();
        let use_forest = self.hypergraph.as_ref().map(|h| h.has_forest()).unwrap_or(false);
        canonical.len() == frame.requests.len()
            && compute_requests_root(
                &canonical,
                &self.app_address,
                header.frame_number,
                Some(exec.as_ref()),
                self.inclusion_prover.as_deref(),
                use_forest,
            )
            .map(|root| root == header.requests_root)
            .unwrap_or(false)
    }

    /// Commit, materialize and publish the ancestors a finalization makes
    /// final that never finalized on their own (see
    /// `AppSeamFinalizer::implied_ancestors`), lowest first, before the
    /// finalized frame itself. Every ancestor must link exactly to its child,
    /// pass proposal validation unless this node sealed it, and match its
    /// body root; otherwise none is applied and the finalized frame waits for
    /// catch-up as before. Ancestors carry no certificate of their own: they
    /// are committed without moving the latest head, and earn no reward (only
    /// the certified frame's header is submitted).
    async fn apply_implied_ancestors(
        &mut self,
        descendant: &quil_types::proto::global::AppShardFrame,
        implied: Vec<(Vec<u8>, bool)>,
    ) {
        let Some(descendant_header) = descendant.header.as_ref() else { return };
        let mut ancestors = Vec::with_capacity(implied.len());
        for (bytes, verified) in implied {
            let Ok(frame) = <quil_types::proto::global::AppShardFrame as prost::Message>::decode(bytes.as_slice()) else {
                warn!(core_id = self.core_id, "implied app frame: undecodable — none applied");
                return;
            };
            ancestors.push((frame, verified));
        }
        for (index, (frame, verified)) in ancestors.iter().enumerate() {
            let child = ancestors.get(index + 1).and_then(|(next, _)| next.header.as_ref()).unwrap_or(descendant_header);
            let links = frame.header.as_ref().is_some_and(|header| {
                header.address == self.app_address && crate::frame_validator::app_frame_links_to_child(header, child)
            });
            let valid = *verified || self.app_frame_validator.as_ref().is_some_and(|validator| {
                matches!(validate_app_frame_panic_safe(validator, frame, /* proposal */ true), Ok(true))
            });
            if !links || !valid || !self.body_matches_requests_root(frame) {
                warn!(core_id = self.core_id, frame = frame.header.as_ref().map_or(0, |h| h.frame_number),
                    links, valid, "implied app frame failed authentication — none applied");
                return;
            }
        }
        for (frame, _) in ancestors {
            let Some(header) = frame.header.clone() else { continue };
            let frame_number = header.frame_number;
            if frame_number <= self.last_materialized_frame {
                continue;
            }
            self.adopt_certified_relays(&header);
            let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output).map(|h| h.to_vec()).unwrap_or_default();
            let committed = self.clock_store.new_transaction(false).ok().and_then(|txn| {
                self.clock_store.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).ok()?;
                txn.commit().ok()?;
                let txn = self.clock_store.new_transaction(false).ok()?;
                self.clock_store.commit_shard_clock_frame(&self.filter, frame_number, &selector, txn.as_ref(), true).ok()?;
                txn.commit().ok()
            });
            if committed.is_none() {
                warn!(core_id = self.core_id, frame = frame_number, "implied app frame: clock commit failed — later ones wait for catch-up");
                return;
            }
            info!(core_id = self.core_id, frame = frame_number,
                "implied app frame committed (finalized by a certified descendant)");
            if frame_number == self.last_materialized_frame + 1 && self.execution_engine.is_some() {
                match self
                    .materialize_offloaded(
                        frame.requests.clone(),
                        frame_number,
                        header.difficulty,
                        header.fee_multiplier_vote,
                        header.global_frame_number,
                    )
                    .await
                {
                    Ok(_) => {
                        self.set_materialized_frame(frame_number);
                        self.extend_audited_history(frame_number);
                    }
                    Err(error) => {
                        warn!(core_id = self.core_id, frame = frame_number, %error,
                            "implied app frame materialize failed (cursor held; will retry)");
                        self.finalized_requests_roots.entry(frame_number).or_insert_with(|| header.requests_root.clone());
                        self.received_full_frames.entry(frame_number).or_insert_with(|| frame.clone());
                    }
                }
            } else {
                self.finalized_requests_roots.entry(frame_number).or_insert_with(|| header.requests_root.clone());
                self.received_full_frames.entry(frame_number).or_insert_with(|| frame.clone());
            }
            let _ = self.event_tx.send(AppEngineEvent::FullFrameProduced {
                filter: self.filter.clone(),
                frame_number,
                frame_data: prost::Message::encode_to_vec(&frame),
            });
        }
    }

    async fn handle_cw_finalized_frame(
        &mut self,
        data: &[u8],
        cert: &[u8],
        locally_verified: bool,
        implied: Vec<(Vec<u8>, bool)>,
    ) {
        let mut frame: quil_types::proto::global::AppShardFrame = match prost::Message::decode(data) {
            Ok(f) => f,
            Err(e) => {
                warn!(core_id = self.core_id, error = %e, "cw finalized frame: undecodable");
                return;
            }
        };
        // DEV-ONLY fault injection: also drop the CW-finalization path for the
        // range [df, df+8) so this node's `last_materialized_frame` genuinely
        // STALLS (CW materialization is sequential) — it then falls onto the
        // gossip follower path (whose same range is dropped in the receive
        // handler), leaving frames buffered AHEAD of a hole → gap detection →
        // step-4 catch-up sync. Unset in prod (QUIL_APP_SYNC_DROP_FRAME).
        if let Some(fnum) = frame.header.as_ref().map(|h| h.frame_number) {
            let fault_drop = std::env::var("QUIL_APP_SYNC_DROP_FRAME")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .map(|df| fnum >= df && fnum < df + 8)
                .unwrap_or(false);
            if fault_drop {
                tracing::warn!(
                    core_id = self.core_id,
                    frame = fnum,
                    "FAULT-INJECT (QUIL_APP_SYNC_DROP_FRAME): dropping CW-finalized \
                     frame to stall the materializer and force a step-4 sync"
                );
                return;
            }
        }
        // SECURITY — post-verification substitution defense,
        // gated on `locally_verified` (#594 "preserve finalized app shard frames").
        //
        // When `locally_verified`, these `data` bytes are the EXACT sequence this
        // node's application validator accepted and the `BlockStore` SEALED at
        // proposal time (peer ingress can no longer substitute them). Re-running
        // PROPOSAL validation here would recompute the deterministic output from
        // fields whose backing is MUTABLE local state (storage attestations,
        // global-frame anchors, state_roots) — which can legitimately drift
        // between our vote and finalization — and would DROP a frame we already
        // voted for, losing a validly-finalized app-shard frame. So skip it for
        // sealed bytes.
        //
        // A certificate-only replica (e.g. replay/catch-up) may learn the
        // finalization cert WITHOUT locally verifying the block; those unsealed
        // bytes still take the defensive re-validation path before anything
        // touches the clock store or materializer. It RECOMPUTES `header.output`
        // from the declared fields and drops any frame whose fields don't
        // reproduce it — catching a substituted/internally-inconsistent header.
        if !locally_verified {
            if let Some(v) = self.app_frame_validator.as_ref() {
                match validate_app_frame_panic_safe(v, &frame, /* proposal */ true) {
                    Ok(true) => {}
                    other => {
                        warn!(
                            core_id = self.core_id,
                            result = ?other,
                            "cw finalized frame: unverified bytes failed re-validation \
                             (substitution or inconsistent header) — dropping",
                        );
                        return;
                    }
                }
            }
        }
        // SECURITY — body-root cross-check (also the body-swap case of the
        // substitution defense above). The re-validation above binds the
        // DECLARED `requests_root` through output recomputation, but not the
        // carried body; a finalize-time
        // BlockStore overwrite can keep the whole header (hence the certified
        // digest) while swapping `frame.requests`. Recompute the body root from
        // the carried requests and DROP on mismatch, so no CW replica ever
        // materializes a body its certified root does not cover. (Dropping a
        // substituted body stalls at worst — recoverable via catch-up — whereas
        // materializing it would be an unrecoverable state divergence.)
        if !self.body_matches_requests_root(&frame) {
            warn!(
                core_id = self.core_id,
                frame = frame.header.as_ref().map_or(0, |h| h.frame_number),
                "cw finalized frame: requests_root mismatch (carried body does not \
                 match the certified root) — dropping (post-verification body swap)",
            );
            return;
        }
        if !implied.is_empty() {
            self.apply_implied_ancestors(&frame, implied).await;
        }
        if let Some(header) = frame.header.as_ref() {
            self.adopt_certified_relays(header);
        }
        // Attach the simplex FINALIZATION cert to the frame header so every
        // downstream reader — the shard clock store (served to followers via
        // sync), the full frame gossiped on `shard_frame_bitmask`, and archives —
        // can verify this CW-finalized frame against the shard committee. CW
        // frames carry NO header aggregate; the cert rides in the sig field's
        // `signature` bytes with the CWCT magic, which `BlsAppFrameValidator`
        // (follower/archive path) and the global reward path both detect and
        // verify via `app_cert::verify_finalization`. Empty cert (shouldn't
        // happen post-genesis) leaves the field untouched.
        if !cert.is_empty() {
            if let Some(h) = frame.header.as_mut() {
                h.public_key_signature_bls48581 =
                    Some(quil_types::proto::keys::Bls48581AggregateSignature {
                        public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                            key_value: Vec::new(),
                        }),
                        signature: quil_cw_consensus::app_cert::wrap_cert_for_header(cert),
                        bitmask: Vec::new(),
                    });
            }
        }
        let Some(header) = frame.header.clone() else { return };
        if !header.address.is_empty() && header.address != self.app_address {
            return;
        }
        let frame_number = header.frame_number;

        // Persist the finalized frame to the shard clock store so the NEXT
        // `prove_next_state` (which reads `get_latest_shard_clock_frame`) chains
        // on it — otherwise the chain stalls re-proposing on genesis. The legacy
        // path stages in the incorporated hook + commits on QC; the CW path does
        // both here at finalize (stage then commit, separate txns like legacy).
        let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
            .map(|h| h.to_vec())
            .unwrap_or_default();
        if let Ok(txn) = self.clock_store.new_transaction(false) {
            if let Err(e) = self.clock_store.stage_shard_clock_frame(&selector, &frame, txn.as_ref()) {
                warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw stage shard frame failed");
            } else {
                let _ = txn.commit();
            }
        }
        if let Ok(txn) = self.clock_store.new_transaction(false) {
            if let Err(e) = self.clock_store.commit_shard_clock_frame(
                &self.filter,
                frame_number,
                &selector,
                txn.as_ref(),
                false,
            ) {
                warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw commit shard frame failed");
            } else {
                let _ = txn.commit();
            }
        }

        if frame_number <= self.last_materialized_frame || self.execution_engine.is_none() {
            // Already materialized (or nothing to apply); still (re)publish below.
        } else if frame_number != self.last_materialized_frame + 1 {
            // Leapfrog guard: a finalized frame more than one
            // ahead of the cursor means intermediate frames are missing (e.g. a
            // prior frame failed fatally). Materializing here would apply N+k on
            // state missing N..N+k-1's mutations and permanently skip them. Refuse;
            // the follower/shard-sync path fills the gap strictly (== last+1).
            warn!(
                core_id = self.core_id, frame = frame_number,
                cursor = self.last_materialized_frame,
                "cw-finalized frame ahead of cursor; deferring to catch-up (not skipping)",
            );
            // Kept for the ordered follower path, which applies it from its
            // committed clock header once the missing frames are filled in.
            self.finalized_requests_roots.entry(frame_number).or_insert_with(|| header.requests_root.clone());
            self.received_full_frames.entry(frame_number).or_insert_with(|| frame.clone());
            self.adopt_linked_parents(&header);
        } else {
            // Use the CERTIFIED header difficulty (bound into the frame output),
            // not this node's local `current_difficulty` — they can differ when
            // materializing another leader's finalized frame, and the reward path
            // must use the value the committee certified.
            let difficulty = header.difficulty;
            match self
                .materialize_offloaded(
                    frame.requests.clone(),
                    frame_number,
                    difficulty,
                    header.fee_multiplier_vote,
                    header.global_frame_number,
                )
                .await
            {
                Ok((processed, skipped)) => {
                    self.set_materialized_frame(frame_number);
                    self.extend_audited_history(frame_number);
                    debug!(core_id = self.core_id, frame = frame_number, processed, skipped,
                        "materialized cw-finalized shard frame");
                }
                // Cursor NOT advanced on error → the frame is retried instead of
                // being silently skipped. The frame is kept so the
                // follower path retries it on the retry timer as well as on the
                // next finalize/sync: when every member of a committee hits the
                // same transient fault (e.g. a busy proof worker), no later
                // frame is finalized, since nobody may propose past a frame it
                // has not materialized, and "next finalize" never comes.
                Err(e) => {
                    warn!(core_id = self.core_id, frame = frame_number, error = %e,
                        "cw-finalized materialize failed (cursor held; will retry)");
                    self.finalized_requests_roots.entry(frame_number).or_insert_with(|| header.requests_root.clone());
                    self.received_full_frames.entry(frame_number).or_insert_with(|| frame.clone());
                }
            }
        }

        // Publish the full frame for followers/archives on `shard_frame_bitmask`.
        let mut buf = Vec::new();
        if prost::Message::encode(&frame, &mut buf).is_ok() {
            let _ = self.event_tx.send(AppEngineEvent::FullFrameProduced {
                filter: self.filter.clone(),
                frame_number,
                frame_data: buf,
            });
        }

        // Reward attribution: emit the certified header canonical bytes so the
        // master publishes them on GLOBAL_PROVER, and fire the direct coverage
        // callback — global archives credit this shard's work off these. The
        // legacy path did this from its finalization consumer; the CW path must
        // do it here or app-shard provers earn no rewards. The CW frame carries
        // no BLS aggregate sig in the header (simplex certifies it instead), so
        // `public_key_signature_bls48581` is empty — verification of CW shard
        // frames checks the deterministic output, storage and committee certificate.
        let canon = quil_execution::global_intrinsic::frame_header::FrameHeader {
            address: header.address.clone(),
            frame_number: header.frame_number,
            rank: header.rank,
            timestamp: header.timestamp,
            difficulty: header.difficulty,
            output: header.output.clone(),
            parent_selector: header.parent_selector.clone(),
            requests_root: header.requests_root.clone(),
            state_roots: header.state_roots.clone(),
            prover: header.prover.clone(),
            fee_multiplier_vote: header.fee_multiplier_vote as i64,
            // Carry the simplex finalization cert (magic-prefixed) in the sig
            // field so the global reward path can verify CW-finalized shard work
            // against the shard committee.
            public_key_signature_bls48581: quil_cw_consensus::app_cert::wrap_cert_for_header(cert),
            storage_attestation_root: header.storage_attestation_root.clone(),
            global_frame_number: header.global_frame_number,
            storage_attestation: frame
                .storage_attestation
                .as_ref()
                .map(prost::Message::encode_to_vec)
                .unwrap_or_default(),
            fee_total: header.fee_total.clone(),
            settlements: header.settlements.clone(),
            accumulator: header.accumulator.clone(),
            spends: header.spends.clone(),
        };
        if let Ok(canon_bytes) = canon.to_canonical_bytes() {
            let _ = self.event_tx.send(AppEngineEvent::ShardFrameFinalized {
                filter: self.filter.clone(),
                header_canonical_bytes: canon_bytes.clone(),
            });
            if let Some(cb) = self.coverage_publish.as_ref() {
                cb(canon_bytes);
            }
        }
    }

    async fn handle_frame_message(&mut self, data: &[u8]) {
        if self.halted.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if let Ok(frame) = prost::Message::decode(data) {
            let frame: quil_types::proto::global::AppShardFrame = frame;
            if let Some(h) = frame.header.as_ref() {
                // Validate: address must match this shard
                if h.address != self.app_address {
                    return;
                }
                let frame_number = h.frame_number;

                if let Some(validator) = self.app_frame_validator.as_ref() {
                    if let Err(error) = validator.prepare_storage_history(&frame).await {
                        debug!(core_id = self.core_id, frame = frame_number, %error,
                            "follower frame historical registration unavailable");
                        return;
                    }
                }

                // Run the full app-shard digest, storage and committee
                // frame validator before buffering for follower
                // materialization. The archive ingest path already does
                // this; the follower path did not. Untrusted header
                // fields (e.g. `fee_multiplier_vote`) are read downstream.
                // A frame with no certificate of its own is one a certified
                // descendant finalized: every check but the quorum here, and
                // it is applied only once that descendant is committed and
                // links to it (`adopt_linked_parents`).
                let certified = h.public_key_signature_bls48581.as_ref().is_some_and(|s| !s.signature.is_empty());
                match self.app_frame_validator.as_ref() {
                    Some(v) => match validate_app_frame_panic_safe(v, &frame, /* proposal */ !certified) {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(
                                core_id = self.core_id,
                                frame = frame_number,
                                "rejecting app-shard follower frame: failed validation",
                            );
                            return;
                        }
                        Err(e) => {
                            warn!(
                                core_id = self.core_id,
                                frame = frame_number,
                                error = %e,
                                "rejecting app-shard follower frame: validation error",
                            );
                            return;
                        }
                    },
                    None => {
                        debug!(
                            core_id = self.core_id,
                            frame = frame_number,
                            "app frame received but validator not ready — dropping",
                        );
                        return;
                    }
                }

                // Cache in frame store (keyed by output hash) — kept for
                // the existing output-hash lookup path.
                use sha2::{Digest, Sha256};
                let frame_id = hex::encode(Sha256::digest(&h.output));
                self.frame_store.insert(frame_id, data.to_vec());

                // DEV-ONLY fault injection: drop a specific app-frame on receipt
                // to force a PERSISTENT materialization gap (a locally-dropped
                // frame can't be refilled by gossip — it's re-dropped on every
                // receipt), exercising the step-4 catch-up sync. Unset in prod;
                // set QUIL_APP_SYNC_DROP_FRAME=<app_frame_number> to reproduce a
                // deeply-behind node. Re-read per receipt (rare, dev-only path).
                // Drops a small RANGE [df, df+8) so a single node falls behind
                // even across the frames it happens to lead (a leader
                // self-materializes and doesn't hit this receive path).
                let fault_drop = std::env::var("QUIL_APP_SYNC_DROP_FRAME")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|df| frame_number >= df && frame_number < df + 8)
                    .unwrap_or(false);
                if fault_drop {
                    tracing::warn!(
                        core_id = self.core_id,
                        frame = frame_number,
                        "FAULT-INJECT (QUIL_APP_SYNC_DROP_FRAME): dropping received \
                         app-frame to force a step-4 catch-up sync"
                    );
                } else if frame_number > self.last_materialized_frame {
                    // Buffer the full frame (header+requests) for follower
                    // materialization, but only if it's still ahead of what
                    // we've materialized (avoid unbounded re-buffering of old
                    // frames). The buffer is materialized in strict order
                    // against the finalized (trusted) requests_root.
                    self.received_full_frames.insert(frame_number, frame);
                    if !certified {
                        if let Ok(child) = self.clock_store.get_shard_clock_frame(&self.filter, frame_number + 1, false) {
                            if let Some(child) = child.header {
                                self.adopt_linked_parents(&child);
                            }
                        }
                    }
                    self.try_materialize_follower_frames().await;
                }
            }
        }
    }

    /// Commit the buffered frames below a committed, certified `child` that
    /// have no certificate of their own but link to it, down the chain, so
    /// the ordered follower path can apply them. Their certified descendant
    /// finalized them; without this, a member that learned only that
    /// descendant's certificate waited for them forever.
    fn adopt_linked_parents(&mut self, child: &quil_types::proto::global::FrameHeader) {
        let mut child = child.clone();
        while child.frame_number > self.last_materialized_frame + 1 {
            let number = child.frame_number - 1;
            let Some(parent) = self.received_full_frames.get(&number).cloned() else { return };
            let Some(header) = parent.header.clone() else { return };
            let uncertified = header.public_key_signature_bls48581.as_ref().is_none_or(|s| s.signature.is_empty());
            if !uncertified || !crate::frame_validator::app_frame_links_to_child(&header, &child) {
                return;
            }
            if self.clock_store.get_shard_clock_frame(&self.filter, number, false).is_err() {
                let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output).map(|h| h.to_vec()).unwrap_or_default();
                let committed = self.clock_store.new_transaction(false).ok().and_then(|txn| {
                    self.clock_store.stage_shard_clock_frame(&selector, &parent, txn.as_ref()).ok()?;
                    txn.commit().ok()?;
                    let txn = self.clock_store.new_transaction(false).ok()?;
                    self.clock_store.commit_shard_clock_frame(&self.filter, number, &selector, txn.as_ref(), true).ok()?;
                    txn.commit().ok()
                });
                if committed.is_none() {
                    return;
                }
                info!(core_id = self.core_id, frame = number, "implied app frame adopted under its certified descendant");
            }
            self.finalized_requests_roots.entry(number).or_insert_with(|| header.requests_root.clone());
            child = header;
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

        // Persist the global frame into the (cluster worker's) clock store so the
        // committee anchor is CURRENT. A cluster worker's `global_anchor_store`
        // falls back to this `clock_store` (deps pass None), and the committee is
        // read at the global anchor (`committee_anchor_gfn`) — without storing the
        // received global frames the anchor stays 0, the committee is computed at
        // epoch 0 where every prover is still Joining (deferred activation), and
        // `build_app_committee` fails ("this node's key not in the active set").
        // The master path stores its own frames; this feeds the worker's copy.
        // (No-op-txn direct write; global frames use a distinct key prefix from
        // the shard chain, so there's no collision with the worker's own frames.)
        if let Err(e) = self.clock_store.put_global_clock_frame(&global_frame, &AppNoopTxn) {
            debug!(core_id = self.core_id, error = %e, "worker: store global frame for anchor failed");
        }
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
        let data = canonical_app_message(data);
        stamp_arrival(&self.routing_seen, &data, std::time::Instant::now());
        if !self.message_collector.add_message_newest(data.clone()) {
            // Buffer full — spill to next rank
            let next_rank = self.current_rank + 1;
            self.message_spillover
                .entry(next_rank)
                .or_insert_with(Vec::new)
                .push(data);
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

    /// Materialize buffered received full frames in strict order, as a
    /// follower. Each is gated by: it is exactly the next frame to
    /// materialize, we hold the finalized (trusted) `requests_root` for
    /// it, and the frame's `requests` recompute to that root. A mismatch
    /// rejects the frame (it didn't come from the consensus-finalized
    /// frame). Out-of-order frames stay buffered until the gap fills
    /// (or a future sync resolves it).
    async fn try_materialize_follower_frames(&mut self) {
        if let Some((height, frame)) = self.pending_follower_clock.as_ref() {
            if let Err(error) = self.commit_shard_clock_head(frame, *height) {
                warn!(core_id = self.core_id, frame = *height, error = %error,
                    "follower clock retry failed");
                return;
            }
            self.received_full_frames.remove(height);
            self.materialize_failures.remove(height);
            self.pending_follower_clock = None;
        }
        loop {
            let next = self.last_materialized_frame + 1;
            let trusted_root = match self.finalized_requests_roots.get(&next) {
                Some(r) => r.clone(),
                None => break, // not finalized through consensus yet
            };
            let mut frame = match self.received_full_frames.get(&next) {
                Some(f) => f.clone(),
                None => break, // full frame not received yet
            };
            // Validate address + capture the fee vote (Copy) so we don't
            // hold a borrow of `frame.header` across the awaits below.
            // Execution metadata must come from the finalized clock header;
            // matching request bytes alone does not authenticate the wire header.
            let trusted_header = match self.clock_store.get_shard_clock_frame(&self.filter, next, false) {
                Ok(f) => match f.header {
                    Some(h) if h.frame_number == next && h.address == self.app_address
                        && h.requests_root == trusted_root => h,
                    _ => break,
                },
                Err(e) => {
                    warn!(core_id=self.core_id, frame=next, error=%e, "finalized execution header unavailable");
                    break;
                }
            };
            let fee_multiplier_vote = trusted_header.fee_multiplier_vote;
            let header_difficulty = trusted_header.difficulty;
            let global_frame_number = trusted_header.global_frame_number;
            // Persist the certified execution header, not the received body's header.
            frame.header = Some(trusted_header);

            // Recompute requests_root over the frame's requests (canonical
            // encodings) and require it to equal what we finalized.
            let canonical: Vec<Vec<u8>> = frame
                .requests
                .iter()
                .filter_map(|b| {
                    crate::consensus_wire::proto_message_bundle_to_canonical_bytes(b).ok()
                })
                .collect();
            if canonical.len() != frame.requests.len() {
                warn!(core_id = self.core_id, frame = next,
                    "received frame has un-re-encodable requests; rejecting");
                self.received_full_frames.remove(&next);
                break;
            }
            let recomputed = match self.recompute_requests_root_offloaded(canonical, next).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(core_id = self.core_id, frame = next, error = %e,
                        "requests_root recompute failed");
                    break;
                }
            };
            if recomputed != trusted_root {
                warn!(core_id = self.core_id, frame = next,
                    "received frame requests_root mismatch with finalized header — rejecting");
                self.received_full_frames.remove(&next);
                break;
            }

            // Verified authentic — materialize. Preserve the old
            // "no execution engine → stop" behavior (the offload helper
            // would otherwise report 0 processed and falsely advance).
            if self.execution_engine.is_none() {
                break;
            }
            // Certified difficulty from the received frame's header.
            let difficulty = header_difficulty;
            match self
                .materialize_offloaded(
                    frame.requests.clone(),
                    next,
                    difficulty,
                    fee_multiplier_vote,
                    global_frame_number,
                )
                .await
            {
                Ok((processed, skipped)) => {
                    self.set_materialized_frame(next);
                    self.extend_audited_history(next);
                    // Advance the clock head in lockstep with the cursor. This is
                    // the critical case: a follower drains finalized frames it
                    // received via frame-sync WITHOUT running its own finalize
                    // handler for them, so nothing else writes the clock head —
                    // leaving mat > clock and triggering a re-propose/nullify storm.
                    if let Err(error) = self.commit_shard_clock_head(&frame, next) {
                        warn!(core_id = self.core_id, frame = next, error = %error,
                            "follower clock persistence failed after state commit; queued for retry");
                        self.pending_follower_clock = Some((next, frame));
                        return;
                    }
                    self.received_full_frames.remove(&next);
                    self.materialize_failures.remove(&next);
                    debug!(core_id = self.core_id, frame = next, processed, skipped,
                        "materialized received shard frame (follower)");
                }
                Err(e) if quil_execution::token_intrinsic::is_proof_worker_busy(&e) => {
                    // Local contention for the proof worker: the frame is
                    // fine and a shard sync would not relieve it. Keep the
                    // frame and retry without counting toward the drop;
                    // shards sharing a node's single slot hit this while
                    // verifying different submissions.
                    info!(core_id = self.core_id, frame = next,
                        "materialize of received shard frame waits for the proof worker");
                    break;
                }
                Err(e) => {
                    // A materialize error here is a hard `commit_frame`
                    // (store) failure, not a bad bundle (those are
                    // skipped inside materialize). Re-running re-applies
                    // already-committed bundles — safe under CRDT
                    // set-semantics + spent-markers, but wasteful. Bound
                    // the retries: after `MAX_MATERIALIZE_RETRIES`,
                    // stop blindly replaying and route the frame to the
                    // authoritative repair path (a shard sync), which
                    // rebuilds state from an archive rather than from
                    // this (apparently un-committable) full frame.
                    let attempts = self
                        .materialize_failures
                        .entry(next)
                        .and_modify(|n| *n += 1)
                        .or_insert(1);
                    if *attempts >= MAX_MATERIALIZE_RETRIES {
                        warn!(core_id = self.core_id, frame = next, attempts = *attempts, error = %e,
                            "materialize of received shard frame failed repeatedly — dropping frame, requesting shard sync");
                        self.received_full_frames.remove(&next);
                        self.materialize_failures.remove(&next);
                        let _ = self.event_tx.send(AppEngineEvent::AncestorSyncRequested {
                            filter: self.filter.clone(),
                            missing_frames: vec![next],
                        });
                    } else {
                        warn!(core_id = self.core_id, frame = next, attempts = *attempts, error = %e,
                            "materialize of received shard frame failed — will retry");
                    }
                    break;
                }
            }
        }
        // Gap detection: if frames are buffered AHEAD of the next one we
        // need but the next one is missing, this node is behind and the
        // gap won't self-heal from gossip — it needs a shard sync (step
        // 4). Surface it and signal via AncestorSyncRequested (the
        // existing event; its handler is the sync-client integration
        // point still to be wired).
        let next_needed = self.last_materialized_frame + 1;
        let ahead: Vec<u64> = self
            .received_full_frames
            .keys()
            .copied()
            .filter(|&f| f > next_needed)
            .collect();
        if !self.received_full_frames.contains_key(&next_needed) && !ahead.is_empty() {
            warn!(
                core_id = self.core_id,
                missing_from = next_needed,
                buffered_ahead = ahead.len(),
                "app-shard frame gap — node behind; shard sync needed (step 4)"
            );
            let _ = self.event_tx.send(AppEngineEvent::AncestorSyncRequested {
                filter: self.filter.clone(),
                missing_frames: vec![next_needed],
            });
        }

        // Bound the received-frame buffer to recent + future frames.
        let cutoff = self.last_materialized_frame.saturating_sub(8);
        self.received_full_frames.retain(|&f, _| f > cutoff);
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
        let parent_data = match self.pending_certified_parents.get(&parent_rank).cloned() {
            Some(d) => d,
            None => return,
        };
        self.retry_parent_seals.insert(parent_rank);

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
                self.pending_certified_parents.remove(&parent_rank);
                self.retry_parent_seals.remove(&parent_rank);
                return;
            }
        };

        let header = match frame.header.as_ref() {
            Some(h) => h,
            None => {
                self.pending_certified_parents.remove(&parent_rank);
                self.retry_parent_seals.remove(&parent_rank);
                return;
            }
        };

        // Materialize the certified parent's requests into hypergraph
        // state BEFORE sealing the clock frame — token/compute/hypergraph
        // engines run here. Mirrors Go `addCertifiedState → materialize`
        // (app_consensus_engine.go:2996), which gates the clock commit on
        // a successful materialize. The idempotency gate
        // (`last_materialized_frame`) makes a repeat seal a no-op. If
        // materialize fails we DON'T seal: re-queue the parent so a later
        // attempt can retry, rather than committing an un-materialized
        // frame.
        // Leapfrog guard: only materialize the immediate next frame.
        // If the certified parent is more than one ahead of the cursor, retain
        // it for retry after the follower/shard-sync path fills the gap. Materializing
        // N+k on state missing N..N+k-1 would silently skip their mutations.
        if header.frame_number > self.last_materialized_frame + 1 {
            warn!(
                core_id = self.core_id, parent_rank, frame = header.frame_number,
                cursor = self.last_materialized_frame,
                "certified parent ahead of cursor; deferring sealing until catch-up",
            );
            return;
        } else if header.frame_number == self.last_materialized_frame + 1 {
            // Scalars up front so no borrow of `self`/`frame` survives
            // into the result arms where we mutate
            // `self.last_materialized_frame` / `pending_certified_parents`.
            let frame_number = header.frame_number;
            let fee_multiplier_vote = header.fee_multiplier_vote;
            // Certified difficulty from the sealed parent's header.
            let header_difficulty = header.difficulty;
            if self.execution_engine.is_some() {
                let difficulty = header_difficulty;
                // Offloaded to the blocking pool (off the engine task).
                let result = self
                    .materialize_offloaded(
                        frame.requests.clone(),
                        frame_number,
                        difficulty,
                        fee_multiplier_vote,
                        header.global_frame_number,
                    )
                    .await;
                match result {
                    Ok((processed, skipped)) => {
                        // Only advertise the cursor after the atomic
                        // state/cursor commit. Advancing on Err would
                        // push the cursor past the CRDT (the unsafe
                        // direction) and silently skip this frame's
                        // mutations on restart.
                        self.set_materialized_frame(frame_number);
                        self.extend_audited_history(frame_number);
                        debug!(
                            core_id = self.core_id,
                            frame = frame_number,
                            processed,
                            skipped,
                            "materialized sealed app-shard frame"
                        );
                    }
                    Err(e) => {
                        warn!(
                            core_id = self.core_id,
                            parent_rank,
                            frame = frame_number,
                            error = %e,
                            "app-shard materialize failed; retaining certified parent for retry"
                        );
                        return;
                    }
                }
            } else {
                warn!(core_id = self.core_id, parent_rank, frame = frame_number,
                    "cannot seal certified parent without execution state");
                return;
            }
        }

        // Stage and commit in separate transactions, keyed by the frame's own
        // selector. The durable clock store reads the staged bytes from
        // committed storage, so staging and committing in one transaction left
        // the sealed parent uncommitted, with its staged copy stored forever.
        let frame_number = header.frame_number;
        if let Err(e) = self.commit_shard_clock_head(&frame, frame_number) {
            warn!(core_id = self.core_id, parent_rank, error = %e, "failed to persist sealed parent");
            return;
        }

        self.pending_certified_parents.remove(&parent_rank);
        self.retry_parent_seals.remove(&parent_rank);
        let _ = self.event_tx.send(AppEngineEvent::ParentSealed {
            filter: self.filter.clone(),
            parent_rank,
        });

        // Prune old pending parents (same cutoff as proposals)
        let cutoff = self.current_rank.saturating_sub(10);
        self.pending_certified_parents.retain(|&r, _| r >= cutoff || self.retry_parent_seals.contains(&r));
    }

    /// Retry only previously authorized seals, in rank order, at cleanup cadence.
    async fn retry_certified_parent_seals(&mut self) {
        let ranks: Vec<_> = self.retry_parent_seals.iter().copied().collect();
        for rank in ranks {
            if let Some(child_rank) = rank.checked_add(1) {
                self.try_seal_parent_with_child(child_rank).await;
            }
        }
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
        self.pending_certified_parents.retain(|&r, _| r >= cutoff || self.retry_parent_seals.contains(&r));
    }
}

/// Verify the structural relation between an archive anchor N and its required
/// predecessor N-1. Certificate validation remains in `install_archive_bootstrap`;
/// keeping this portion pure makes the fail-closed bootstrap boundary testable.
fn validate_archive_sync_anchor(
    filter: &[u8],
    materialized: u64,
    anchor: &quil_types::proto::global::AppShardFrame,
    predecessor: Option<&quil_types::proto::global::AppShardFrame>,
    validate: impl FnMut(&quil_types::proto::global::AppShardFrame) -> Result<bool>,
) -> Result<u64> {
    validate_archive_sync_anchor_in(filter, materialized, anchor, predecessor, None, validate)
}

fn validate_archive_sync_anchor_in(
    filter: &[u8],
    materialized: u64,
    anchor: &quil_types::proto::global::AppShardFrame,
    predecessor: Option<&quil_types::proto::global::AppShardFrame>,
    session_genesis: Option<&[u8; 32]>,
    mut validate: impl FnMut(&quil_types::proto::global::AppShardFrame) -> Result<bool>,
) -> Result<u64> {
    let height = archive_bootstrap_predecessor_height_in(filter, anchor, predecessor, session_genesis)
        .map_err(|e| QuilError::InvalidArgument(e.into()))?;
    if height < materialized {
        return Err(QuilError::ExecutionUnavailable("archive sync anchor is behind materialized state".into()));
    }
    if anchor.header.as_ref().unwrap().state_roots.iter().any(|root| root.len() != 32) {
        return Err(QuilError::InvalidArgument("archive sync requires four 32-byte phase anchors".into()));
    }
    for frame in std::iter::once(anchor).chain(predecessor) {
        if !validate(frame)? {
            return Err(QuilError::InvalidSignature("archive sync frame failed certificate validation".into()));
        }
    }
    Ok(height)
}

fn archive_bootstrap_predecessor_height(
    app_address: &[u8],
    anchor: &quil_types::proto::global::AppShardFrame,
    predecessor: Option<&quil_types::proto::global::AppShardFrame>,
) -> std::result::Result<u64, &'static str> {
    archive_bootstrap_predecessor_height_in(app_address, anchor, predecessor, None)
}

/// `session_genesis` is the authorized genesis of the committee session whose
/// FIRST data frame is `anchor` (see [`AppConsensusEngine::first_frame_genesis`]).
/// That frame names the genesis, not its predecessor's output; the certificate
/// check binds the pairing, and the predecessor is still the sealed base frame.
fn archive_bootstrap_predecessor_height_in(
    app_address: &[u8],
    anchor: &quil_types::proto::global::AppShardFrame,
    predecessor: Option<&quil_types::proto::global::AppShardFrame>,
    session_genesis: Option<&[u8; 32]>,
) -> std::result::Result<u64, &'static str> {
    let anchor_header = anchor.header.as_ref().ok_or("anchor has no header")?;
    if anchor_header.frame_number == 0 {
        return Err("anchor is genesis");
    }
    if anchor_header.address != app_address || anchor_header.state_roots.len() != 4 {
        return Err("malformed or wrong-shard anchor");
    }
    let synced_to = anchor_header.frame_number - 1;
    if synced_to == 0 {
        return Ok(0);
    }
    let predecessor = predecessor.ok_or("archive omitted predecessor")?;
    let previous_header = predecessor.header.as_ref().ok_or("predecessor has no header")?;
    if previous_header.address != app_address || previous_header.frame_number != synced_to {
        return Err("non-contiguous or wrong-shard predecessor");
    }
    let expected_parent = quil_crypto::poseidon::hash_bytes_to_32(&previous_header.output)
        .map(|h| h.to_vec())
        .map_err(|_| "invalid predecessor output")?;
    if anchor_header.parent_selector != expected_parent
        && session_genesis.map(|g| g.as_slice()) != Some(anchor_header.parent_selector.as_slice())
    {
        return Err("anchor does not link to predecessor");
    }
    Ok(synced_to)
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

/// Build the per-frame `requests_root` for an app shard proposal.
///
/// Mirrors Go's `calculateRequestsRoot` (with the
/// `addAppMessage` framing from `message_processors.go:1316-1322`):
///
/// - per message: `hash = sha3_256(payload)`, address = the shard's
/// 32-byte app address, payload = the raw MessageBundle bytes
/// collected from the dispatch bitmask;
/// - call `execution_engine.lock(frame, address, payload)` to get the
/// locked-address vector;
/// - insert `(hash, concat(locked_addresses))` into a
/// `VectorCommitmentTree`;
/// - prepend `sha3_256(tree.commit(prover))[..32]` to
/// `serialize_non_lazy(tree)`.
///
/// Zero messages → 64-byte zero buffer, matching Go.
///
/// Returns `Err` if the engine has messages to commit but the
/// execution engine or inclusion prover are missing — those are
/// required to reproduce the request commitment during verification.
pub(crate) fn compute_requests_root(
    messages: &[Vec<u8>],
    app_address: &[u8],
    frame_number: u64,
    execution_engine: Option<&quil_execution::ExecutionEngineManager>,
    inclusion_prover: Option<&dyn quil_types::crypto::InclusionProver>,
    // A migrated node commits the requests to a hash-Merkle JMT (32B
    // root) instead of the KZG vector-commitment tree — removing BLS48-581 from
    // the per-frame message commitment. All nodes are migrated post-fork, so
    // the flag is uniform for any given frame and the app digest stays
    // consistent. `inclusion_prover` is unused on the forest path.
    use_forest: bool,
) -> Result<Vec<u8>> {
    use sha3::{Digest, Sha3_256};

    if messages.is_empty() {
        return Ok(vec![0u8; if use_forest { 32 } else { 64 }]);
    }

    let exec = execution_engine.ok_or_else(|| {
        QuilError::Consensus(
            "compute_requests_root: execution engine not wired but messages present".into(),
        )
    })?;

    // Snapshot the address bytes Go uses for the lock call — the shard's
    // 32-byte app address (Poseidon hash of the filter).
    let addr_for_lock: Vec<u8> = if app_address.len() >= 32 {
        app_address[..32].to_vec()
    } else {
        app_address.to_vec()
    };

    // Build the per-message leaves once (identical for both schemes). The leaf
    // key is SHA3-256(index_be ‖ payload) — prefixing the canonical execution
    // POSITION binds the commitment to request ORDER and MULTIPLICITY. A
    // keyed JMT/VC tree is otherwise order-independent and
    // collapses duplicate payloads, so a reordered body (e.g. two conflicting
    // lattice spends `[A,B]` vs `[B,A]`) would share one certified `requests_root`
    // yet execute to divergent state on different replicas. FLAG-DAY: changes the
    // root → the deterministic frame output → the app-frame digest.
    let mut leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(messages.len());
    for (i, payload) in messages.iter().enumerate() {
        let mut keyed = (i as u64).to_be_bytes().to_vec();
        keyed.extend_from_slice(payload);
        let hash: [u8; 32] = Sha3_256::digest(&keyed).into();
        let locked = exec
            .lock(frame_number, &addr_for_lock, payload)
            .unwrap_or_else(|_| Vec::new());
        let value: Vec<u8> = locked.into_iter().flatten().collect();
        leaves.push((hash.to_vec(), value));
    }
    // Mirror Go's `executionManager.Unlock()` call after the per-message
    // lock loop completes.
    let _ = exec.unlock();

    if use_forest {
        // Hash-Merkle (JMT) commitment over the messages — the requests_root is
        // the 32-byte root. No KZG. Deterministic; verifier recomputes identically.
        let root = quil_forest::commit(&quil_forest::MemTreeStore::default(), 0, leaves)
            .map_err(|e| QuilError::Consensus(format!("requests_root JMT commit: {e}")))?;
        return Ok(root.0.to_vec());
    }

    // Legacy KZG path (non-migrated nodes).
    let prover = inclusion_prover.ok_or_else(|| {
        QuilError::Consensus(
            "compute_requests_root: inclusion prover not wired but messages present".into(),
        )
    })?;
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (hash, value) in &leaves {
        tree.insert(hash, value, &[], &num_bigint::BigInt::from(0))?;
    }
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

/// Materialize an app-shard frame's `requests` into hypergraph state —
/// the Rust port of Go `AppConsensusEngine.materialize`
/// (app_consensus_engine.go:1457-1546). This is what actually runs the
/// token / compute / hypergraph engines for a shard: each bundle is
/// dispatched by address to its intrinsic engine, which applies its
/// state changes (token spends + spent-markers, compute outputs,
/// hyperedge mutations) into the per-shard CRDT.
///
/// Per bundle, in `frame.requests` slice order (Go fans these out over
/// an errgroup but relies on CRDT commutativity for determinism; a
/// serial loop in the same order is deterministic and a safe superset):
/// 1. canonical-encode the bundle,
/// 2. cost basis → baseline fee (`GetBaselineFee/cost`, or 0 when the
/// bundle has zero cost),
/// 3. `fee = baseline * fee_multiplier_vote` — the app-shard path
/// multiplies by the header's vote; the global path does not
/// (app_consensus_engine.go:1515 vs frame_materializer.go:217),
/// 4. `process_message(frame, fee, app_address[..32], bytes)` —
/// address is the shard's own app address (NOT the global
/// 0xFF*32), which routes dispatch to the right engine.
///
/// BEST-EFFORT per bundle: a bundle that fails to encode or dispatch is
/// SKIPPED (logged), not fatal — mirroring the Rust global materializer
/// (`frame_materializer.rs`), and deliberately NOT Go's app-side
/// fail-fast. Blocking the frame on a single bad bundle would let one
/// malformed/unroutable request permanently stall a shard's clock chain
/// (the caller seals regardless of this result). The only hard error is
/// a `commit_frame` failure. No `validate_message` is run: app-shard
/// validity/signature gating happens upstream at message ingest, and the
/// per-tx crypto/double-spend checks live inside the engines'
/// `process_message`. Engines self-commit their changeset per message
/// (the Rust model — see the token engine's `commit_state`);
/// `commit_frame` then flushes the CRDT phase trees to the backing store.
///
/// Returns `(processed, skipped)`.
/// The network world-state size certified by global consensus on global frame
/// `global_frame_number` (the frame an app-shard frame is anchored to). Frame 0
/// (no anchor: genesis / pre-chain tests) prices at size zero. A missing anchor
/// frame is an infrastructure fault: the frame must be retried, never priced
/// from a substitute, or replicas could disagree on whether a fee suffices.
/// Voter checks of a proposal against the state it declares as its pre-state:
/// the body root, `state_roots`, the previous frame's fee total and the relay
/// windows. The canonical engine and a private selected-parent branch build it
/// over their own handles.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_requests_root_check(
    exec: Arc<quil_execution::ExecutionEngineManager>,
    incl: Arc<dyn quil_types::crypto::InclusionProver>,
    hg: Arc<quil_hypergraph::HypergraphCrdt>,
    app_addr: Vec<u8>,
    shard_mat: Arc<std::sync::atomic::AtomicU64>,
    frame_outflows_for_verify: Arc<FrameOutflows>,
    clock_for_verify: Arc<dyn ClockStore>,
    filter: Vec<u8>,
    drain: Option<Arc<crate::shard_drain::ShardDrain>>,
    pre_state_mismatches: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> crate::cw_app_seams::AppRequestsRootCheck {
    let filter_for_fees = filter.clone();
    // Shard key derived from the filter, same as the leader's `state_roots`
    // construction (single derivation, captured).
    let shard_key = {
        let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(
            &filter[..filter.len().min(32)],
            256,
            3,
        );
        let mut l2 = [0u8; 32];
        let copy_len = filter.len().min(32);
        l2[..copy_len].copy_from_slice(&filter[..copy_len]);
        quil_types::store::ShardKey { l1, l2 }
    };
    // Captured for the sharded verifier recompute (subtree root, mirrors
    // the leader's `state_roots` build).
    let filter_for_verify = filter;
    Arc::new(
        move |frame: &quil_types::proto::global::AppShardFrame| -> bool {
            let Some(header) = frame.header.as_ref() else {
                return false;
            };
            // A retiring shard finalizes only empty frames near its flip
            // (crate::shard_drain).
            if !frame.requests.is_empty()
                && drain.as_ref().is_some_and(|drain| drain.drains_at(header.global_frame_number))
            {
                tracing::warn!(frame = header.frame_number, anchor = header.global_frame_number,
                    "cw app verify: a retiring shard's proposal carries requests inside its drain");
                return false;
            }
            // (a) Body-root check — always.
            let canonical: Vec<Vec<u8>> = frame
                .requests
                .iter()
                .filter_map(|b| {
                    crate::consensus_wire::proto_message_bundle_to_canonical_bytes(b)
                        .ok()
                })
                .collect();
            if canonical.len() != frame.requests.len() {
                return false;
            }
            let req_ok = match compute_requests_root(
                &canonical,
                &app_addr,
                header.frame_number,
                Some(exec.as_ref()),
                Some(incl.as_ref()),
                hg.has_forest(),
            ) {
                Ok(r) => r == header.requests_root,
                Err(_) => false,
            };
            if !req_ok {
                return false;
            }
            // The body is bound to its root: its proofs are what this frame
            // will execute if finalized.
            prewarm_proof_verdicts(&exec, &app_addr, &canonical);
            // (b) Pre-state `state_roots` check. FAIL-CLOSED: a voter
            // must be EXACTLY at N-1 to
            // validate the declared pre-state via the deterministic
            // `compute_shard_root`. Previously a voter not at N-1
            // (lagging, OR a leader that JUMPED `frame_number` so the
            // gate went false on every honest voter) fell through and
            // SIGNED unvalidatable roots — a pre-state check bypass. Now it
            // NULLIFIES instead; a genuinely-lagging voter catches up
            // out-of-band (shard sync) and validates future frames, so
            // no forged root is ever signed. Matches the leader's
            // construction: 4 phases in canonical order, empty → zero.
            let n = header.frame_number;
            if n > 0 {
                let mat =
                    shard_mat.load(std::sync::atomic::Ordering::Relaxed);
                if mat + 1 != n {
                    tracing::warn!(
                        frame = n, mat,
                        "cw app verify: not at N-1, cannot validate declared \
                         pre-state (frame-number jump or lag) — nullify",
                    );
                    return false;
                }
                if header.state_roots.len() != 4 {
                    tracing::warn!(
                        frame = n, roots = header.state_roots.len(),
                        "cw app verify: header.state_roots not 4 phases — nullify",
                    );
                    return false;
                }
                let zero =
                    vec![0u8; if hg.has_forest() { 32 } else { 64 }];
                let phases = [
                    ("vertex", "adds"),
                    ("vertex", "removes"),
                    ("hyperedge", "adds"),
                    ("hyperedge", "removes"),
                ];
                for (i, (s, p)) in phases.iter().enumerate() {
                    // Recompute the SAME per-shard root the leader
                    // committed: subtree root under unified, whole-app
                    // aggregate under legacy. Gated symmetrically with
                    // the producer on `unified_tree()`.
                    let mut local = if hg.unified_tree() {
                        hg.sub_shard_commitment_for_filter(s, p, &filter_for_verify)
                    } else {
                        hg.compute_shard_root(s, p, &shard_key)
                    };
                    if local.is_empty() {
                        local = zero.clone();
                    }
                    if local != header.state_roots[i] {
                        tracing::warn!(
                            frame = n,
                            phase = i,
                            "cw app verify: state_roots mismatch vs local \
                             pre-state (false pre-state root) — nullify",
                        );
                        if let Some(count) = pre_state_mismatches.as_ref() {
                            count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        }
                        return false;
                    }
                }
                // (c) Previous-frame fee total (paid to the shard's
                // provers by the global materializer). FAIL-CLOSED like
                // the pre-state roots: a voter that cannot confirm the
                // total it materialized for N-1 must not sign it.
                let declared = quil_execution::global_intrinsic::frame_header::fee_total_from_bytes(&header.fee_total);
                match materialized_fee_total(
                    &frame_outflows_for_verify, clock_for_verify.as_ref(), &filter_for_fees, n - 1,
                ) {
                    Some(local_total) if local_total == declared => {}
                    other => {
                        tracing::warn!(
                            frame = n, declared, local = ?other,
                            "cw app verify: fee_total does not match the locally \
                             materialized previous frame — nullify",
                        );
                        return false;
                    }
                }
                // (d) Settlement relay window: exactly the entries this
                // member materialized for frames N-32 ..= N-1, fail-closed.
                match settlement_relay(
                    &frame_outflows_for_verify, clock_for_verify.as_ref(), &filter_for_fees, n,
                ) {
                    Some(local) if local == header.settlements => {}
                    other => {
                        tracing::warn!(
                            frame = n,
                            declared_bytes = header.settlements.len(),
                            local_bytes = ?other.as_ref().map(Vec::len),
                            "cw app verify: settlement relay does not match the locally \
                             materialized window — nullify",
                        );
                        return false;
                    }
                }
                // (e) Accumulator report: exactly what this member's own
                // materialization of N-1 (and N-2) says the header
                // carries, fail-closed like the fields above.
                match accumulator_field(
                    &frame_outflows_for_verify, clock_for_verify.as_ref(), &filter_for_fees, n,
                ) {
                    Some(local) if local == header.accumulator => {}
                    other => {
                        tracing::warn!(
                            frame = n,
                            declared_bytes = header.accumulator.len(),
                            local_bytes = ?other.as_ref().map(Vec::len),
                            "cw app verify: accumulator report does not match the locally \
                             materialized shard state — nullify",
                        );
                        return false;
                    }
                }
                // (f) Spend relay: exactly the entries this member
                // materialized for frames N-8 ..= N-1, fail-closed.
                match spend_relay(
                    &frame_outflows_for_verify, clock_for_verify.as_ref(), &filter_for_fees, n,
                ) {
                    Some(local) if local == header.spends => {}
                    other => {
                        tracing::warn!(
                            frame = n,
                            declared_bytes = header.spends.len(),
                            local_bytes = ?other.as_ref().map(Vec::len),
                            "cw app verify: spend relay does not match the locally \
                             materialized window — nullify",
                        );
                        return false;
                    }
                }
            }
            true
        },
    )
}

/// Background proof warm-ups in flight, by bundle digest.
static PROOF_PREWARM: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>> =
    std::sync::LazyLock::new(Default::default);
/// Warm-up threads at most in flight; later proposals simply verify at
/// materialization, as before.
const MAX_PROOF_PREWARMS: usize = 2;

/// Claim warm-ups for the `bundles` not already in flight; `None` if all are.
fn claim_proof_prewarm(bundles: &[Vec<u8>]) -> Option<Vec<[u8; 32]>> {
    use sha2::{Digest as _, Sha256};
    let mut in_flight = PROOF_PREWARM.lock().unwrap_or_else(|p| p.into_inner());
    let claimed: Vec<[u8; 32]> = bundles
        .iter()
        .map(|bundle| Sha256::digest(bundle).into())
        .filter(|digest| in_flight.insert(*digest))
        .collect();
    (!claimed.is_empty()).then_some(claimed)
}

fn release_proof_prewarm(claimed: &[[u8; 32]]) {
    let mut in_flight = PROOF_PREWARM.lock().unwrap_or_else(|p| p.into_inner());
    for digest in claimed {
        in_flight.remove(digest);
    }
}

static PROOF_PREWARM_THREADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Start verifying a proposal's confidential proofs in the background once its
/// body is bound to its declared requests root, so the materialization after
/// finalization finds the verdicts cached (`verify_in_worker`'s cache, keyed by
/// the same application and bundle bytes) instead of verifying first. Live, a
/// transfer's frame spent 10.6 s verifying after finalization, delaying the
/// next frame that relays its spend. Verdicts are deterministic; this changes
/// only when they are computed. Bounded: at most [`MAX_PROOF_PREWARMS`] threads,
/// and a body already warming is not warmed again.
pub(crate) fn prewarm_proof_verdicts(
    exec: &Arc<quil_execution::ExecutionEngineManager>,
    app_address: &[u8],
    canonical: &[Vec<u8>],
) {
    let addr = app_address[..app_address.len().min(32)].to_vec();
    let bundles: Vec<Vec<u8>> = canonical
        .iter()
        .filter(|bundle| quil_execution::ExecutionEngineManager::confidential_operation_count(&addr, bundle) > 0)
        .cloned()
        .collect();
    if bundles.is_empty() {
        return;
    }
    let threads = &PROOF_PREWARM_THREADS;
    if threads
        .fetch_update(std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire, |n| {
            (n < MAX_PROOF_PREWARMS).then_some(n + 1)
        })
        .is_err()
    {
        return;
    }
    let Some(claimed) = claim_proof_prewarm(&bundles) else {
        threads.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        return;
    };
    let exec = exec.clone();
    let spawned = std::thread::Builder::new().name("proof-prewarm".into()).spawn(move || {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = bundles.into_iter().map(|bundle| (addr.clone(), bundle)).collect();
        exec.preverify_bundles(&pairs);
        release_proof_prewarm(&claimed);
        PROOF_PREWARM_THREADS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    });
    if spawned.is_err() {
        threads.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

pub(crate) fn certified_world_size(store: &dyn ClockStore, global_frame_number: u64) -> Result<u64> {
    if global_frame_number == 0 {
        return Ok(0);
    }
    let frame = store.get_global_clock_frame(global_frame_number).map_err(|e| {
        QuilError::ExecutionUnavailable(format!(
            "anchored global frame {global_frame_number} unavailable for fee pricing: {e}"
        ))
    })?;
    Ok(frame.header.map(|h| h.world_state_size).unwrap_or(0))
}

/// Per-frame outflow records of a shard: the fee total and the settlement
/// entries each materialized (or certified) frame produced. `None` = unknown.
#[derive(Clone, Debug, Default)]
pub(crate) struct FrameOutflow {
    fee_total: Option<u128>,
    settlements: Option<Vec<quil_execution::token_intrinsic::settlement_record::SettlementEntry>>,
    /// Digest of the shard's accumulator report at this frame (empty: none).
    accumulator: Option<Vec<u8>>,
    /// Encoded spend entries the frame relays for the global commit.
    spends: Option<Vec<Vec<u8>>>,
}

pub(crate) type FrameOutflows = std::sync::Mutex<std::collections::BTreeMap<u64, FrameOutflow>>;

fn update_outflow(outflows: &FrameOutflows, frame_number: u64, update: impl FnOnce(&mut FrameOutflow)) {
    if let Ok(mut map) = outflows.lock() {
        update(map.entry(frame_number).or_default());
        while map.len() > 4096 {
            let oldest = *map.keys().next().unwrap();
            map.remove(&oldest);
        }
    }
}

/// Record a materialized frame's fee total in memory and in the clock store.
pub(crate) fn record_fee_total(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
    fee_total: u128,
) {
    update_outflow(outflows, frame_number, |o| o.fee_total = Some(fee_total));
    if let Err(error) = clock_store.put_shard_frame_fee_total(filter, frame_number, fee_total) {
        warn!(frame = frame_number, error = %error, "failed to persist shard frame fee total");
    }
}

/// A collected application message in the canonical encoding a finalized
/// frame's bundle re-encodes to, so materializing the frame consumes it from
/// the collector. A message that does not decode is kept as received.
fn canonical_app_message(data: &[u8]) -> Vec<u8> {
    crate::consensus_wire::decode_message_bundle(data)
        .ok()
        .and_then(|bundle| crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundle).ok())
        .unwrap_or_else(|| data.to_vec())
}

/// How long a confidential bundle waits for each shard in its order before
/// the next one also proposes it. Longer than the global commit takes to
/// decide a bundle and reach the shards (about 75 s in practice), after which
/// the others drop it: at 30 s every bundle was executed again by one or two
/// fallback shards.
const ROUTED_FALLBACK: std::time::Duration = std::time::Duration::from_secs(120);

/// Pre-state mismatches, with no frame materialized, after which a member
/// inherits its shard's range from an archive (`heal_disagreeing_pre_state`).
const PRE_STATE_MISMATCH_BOOTSTRAP: u64 = 6;

/// At most one such self-heal per this interval.
const PRE_STATE_HEAL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// The application's shards that can take submissions: filters under the
/// application with Active provers, less any whose strict bit-path
/// descendant has them too (a split-away parent the registry still lists).
/// Sorted, so every shard derives the same designation. `address` is the
/// application or, as a shard engine holds it, a shard filter under it.
fn live_app_shards(address: &[u8], summaries: &[quil_types::consensus::ProverShardSummary]) -> Vec<Vec<u8>> {
    let application = &address[..address.len().min(32)];
    let active: Vec<(Vec<u8>, Vec<bool>)> = summaries
        .iter()
        .filter(|summary| summary.status_counts.get(&quil_types::consensus::ProverStatus::Active).copied().unwrap_or(0) > 0)
        .filter_map(|summary| {
            let (app, bits) = quil_forest::decode_shard_filter_or_root(&summary.filter, 32)?;
            (app == application).then(|| (summary.filter.clone(), bits))
        })
        .collect();
    let mut live: Vec<Vec<u8>> = active
        .iter()
        .filter(|(_, bits)| !active.iter().any(|(_, other)| other.len() > bits.len() && quil_forest::bit_path_starts_with(other, bits)))
        .map(|(filter, _)| filter.clone())
        .collect();
    live.sort();
    live.dedup();
    live
}

/// Shards credited within this many GLOBAL frames count as producing. Kept
/// short: an epoch re-confirmation also sets the last-active frame, so a
/// halted shard reads as producing for this long after each one (a 120-frame
/// window kept a halted shard listed).
const ROUTING_ACTIVITY_FRAMES: u64 = 30;

/// The listed shards that still produce frames: GLOBAL moves an allocation's
/// last-active frame whenever it takes one of the shard's frames, reward or
/// not. A shard whose provers stay Active but whose frames stopped was still
/// designated, and every bundle routed to it waited out the fallback.
/// `last_active` gives a shard's latest last-active frame, `None` when the
/// registry cannot say (the shard is kept). Early chains keep every shard.
fn producing_shards(
    shards: Vec<Vec<u8>>,
    anchor: u64,
    last_active: impl Fn(&[u8]) -> Option<u64>,
) -> Vec<Vec<u8>> {
    if anchor <= ROUTING_ACTIVITY_FRAMES {
        return shards;
    }
    shards
        .into_iter()
        .filter(|filter| last_active(filter).is_none_or(|frame| frame.saturating_add(ROUTING_ACTIVITY_FRAMES) >= anchor))
        .collect()
}

/// How many places after its designated shard this shard sits in a bundle's
/// order, `None` when it is not listed.
fn routing_offset(filter: &[u8], shards: &[Vec<u8>], hash: &[u8; 32]) -> Option<u64> {
    let count = shards.len() as u64;
    let designated = u64::from_be_bytes(hash[..8].try_into().unwrap()) % count.max(1);
    shards.iter().position(|shard| shard.as_slice() == filter).map(|position| (position as u64 + count - designated) % count)
}

/// Which collected bundles this shard proposes now: every bundle without a
/// confidential operation, and each confidential one this shard is admitted
/// to. A bundle's order over `shards` starts at its designated shard (its hash
/// modulo the count) and continues through the sorted list; one more shard is
/// admitted for every `fallback` it has waited, so a backlogged designated
/// shard gets one helper rather than every shard at once. A
/// shard missing from the list is admitted once the bundle has waited
/// `fallback`. With no live shard list every bundle is this shard's, as
/// before routing.
fn routed_selection(
    filter: &[u8],
    shards: &[Vec<u8>],
    hashes: &[[u8; 32]],
    operations: &[usize],
    waited: &[std::time::Duration],
    fallback: std::time::Duration,
) -> Vec<bool> {
    hashes
        .iter()
        .zip(operations)
        .zip(waited)
        .map(|((hash, ops), waited)| {
            if *ops == 0 || shards.is_empty() {
                return true;
            }
            let admitted = 1 + waited.as_secs() / fallback.as_secs().max(1);
            match routing_offset(filter, shards, hash) {
                Some(offset) => offset < admitted,
                None => *waited >= fallback,
            }
        })
        .collect()
}

/// Which collected bundles a proposal carries under the proof-verification
/// budget: `operations[i]` is bundle `i`'s count of confidential operations.
/// Bundles without any are always carried; confidential ones are taken in
/// collection (arrival) order while they fit `capacity`, the first even when
/// it alone exceeds it. Every shard of the application collects the same
/// submissions in much the same order, so the shards a node works for carry
/// the same bundle at about the same time and its one cached verdict serves
/// them all: the budget is per proposal, but a node's proof worker is shared.
fn verification_budget_selection(operations: &[usize], capacity: usize) -> Vec<bool> {
    let mut scheduled = 0usize;
    operations
        .iter()
        .map(|&ops| {
            if ops > 0 && scheduled > 0 && scheduled + ops > capacity {
                false
            } else {
                scheduled += ops;
                true
            }
        })
        .collect()
}

/// The fee total of a materialized frame, from memory or the clock store.
/// Whether `frame_number` predates this release's relay records: anchored
/// below the relay activation frame (`global_commit::relay_activation_frame`).
/// Such a frame relays nothing — a zero fee total and empty settlement, spend
/// and accumulator records — whatever this member stored for it. The mainnet
/// build that made it wrote no records at all, and a member that materializes
/// one with this build records its own values, so the rule reads the frame's
/// certified anchor, which every member agrees on.
///
/// Anchors rise along a shard's chain, so the boundary is remembered per shard
/// and each side of it is read from the clock store at most once.
/// `(filter, activation frame)` → (highest frame known to precede it, lowest
/// frame known to relay), learned from stored frames by [`legacy_relay_frame`].
static LEGACY_RELAY_BOUNDARY: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<(Vec<u8>, u64), (u64, u64)>>,
> = std::sync::OnceLock::new();

/// Forget every learned relay boundary: the frame chains they were learned
/// from were discarded, and the frames now numbered alike are new.
pub(crate) fn forget_legacy_relay_boundaries() {
    if let Some(Ok(mut map)) = LEGACY_RELAY_BOUNDARY.get().map(|map| map.lock()) {
        map.clear();
    }
}

pub fn legacy_relay_frame(clock_store: &dyn ClockStore, filter: &[u8], frame_number: u64) -> bool {
    use std::collections::HashMap;
    use std::sync::Mutex;
    let from = quil_execution::token_intrinsic::global_commit::relay_activation_frame();
    if from == 0 || frame_number == 0 {
        return false;
    }
    if from == u64::MAX {
        return true;
    }
    let boundary = LEGACY_RELAY_BOUNDARY.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (filter.to_vec(), from);
    if let Some(&(legacy_through, relaying_from)) = boundary.lock().ok().and_then(|map| map.get(&key).copied()).as_ref() {
        if frame_number <= legacy_through {
            return true;
        }
        if frame_number >= relaying_from {
            return false;
        }
    }
    let Some(anchor) = clock_store.get_shard_clock_frame(filter, frame_number, false).ok()
        .and_then(|frame| frame.header).map(|header| header.global_frame_number)
    else {
        return false;
    };
    let legacy = anchor < from;
    if let Ok(mut map) = boundary.lock() {
        let entry = map.entry(key).or_insert((0, u64::MAX));
        if legacy {
            entry.0 = entry.0.max(frame_number);
        } else {
            entry.1 = entry.1.min(frame_number);
        }
    }
    legacy
}

pub(crate) fn materialized_fee_total(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
) -> Option<u128> {
    // The genesis frame executes no requests; it is never materialized, so
    // there is no record to read.
    if frame_number == 0 || legacy_relay_frame(clock_store, filter, frame_number) {
        return Some(0);
    }
    if let Some(total) = outflows.lock().ok().and_then(|map| map.get(&frame_number).and_then(|o| o.fee_total)) {
        return Some(total);
    }
    clock_store.get_shard_frame_fee_total(filter, frame_number).ok().flatten()
}

/// Record the settlement entries a frame produced, in memory and in the clock
/// store. Entries arrive canonical (materialization caps and orders them).
pub(crate) fn record_frame_settlements(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
    entries: &[quil_execution::token_intrinsic::settlement_record::SettlementEntry],
) {
    use quil_execution::token_intrinsic::settlement_record;
    let (entries, bytes) = match settlement_record::canonical_frame_entries(entries)
        .and_then(|sorted| settlement_record::encode_entries(&sorted).map(|bytes| (sorted, bytes)))
    {
        Ok(pair) => pair,
        Err(error) => {
            // Unreachable for materialized frames (the materializer enforces
            // the cap and receipts are unique by spent images). Leaving the
            // record unknown makes this member nullify rather than relay a
            // different window.
            warn!(frame = frame_number, error = %error, "noncanonical settlement entries not recorded");
            return;
        }
    };
    if let Err(error) = clock_store.put_shard_frame_settlements(filter, frame_number, &bytes) {
        warn!(frame = frame_number, error = %error, "failed to persist shard frame settlements");
    }
    update_outflow(outflows, frame_number, |o| o.settlements = Some(entries));
}

/// The settlement entries of a frame, from memory or the clock store.
pub(crate) fn materialized_frame_settlements(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
) -> Option<Vec<quil_execution::token_intrinsic::settlement_record::SettlementEntry>> {
    if frame_number == 0 || legacy_relay_frame(clock_store, filter, frame_number) {
        return Some(Vec::new());
    }
    if let Some(entries) = outflows.lock().ok().and_then(|map| map.get(&frame_number).and_then(|o| o.settlements.clone())) {
        return Some(entries);
    }
    let bytes = clock_store.get_shard_frame_settlements(filter, frame_number).ok().flatten()?;
    let entries = quil_execution::token_intrinsic::settlement_record::decode_entries(&bytes).ok()?;
    update_outflow(outflows, frame_number, |o| o.settlements = Some(entries.clone()));
    Some(entries)
}

/// The settlement relay header `frame_number` must carry, or `None` when any
/// frame of its window is unknown to this member.
pub(crate) fn settlement_relay(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
) -> Option<Vec<u8>> {
    use quil_execution::token_intrinsic::settlement_record;
    let mut frames = Vec::new();
    for frame in settlement_record::relay_window(frame_number) {
        let entries = materialized_frame_settlements(outflows, clock_store, filter, frame)?;
        if !entries.is_empty() {
            frames.push((frame, entries));
        }
    }
    settlement_record::encode_relay(&frames).ok()
}

/// The spend entries of a materialized frame, from memory or the clock store.
pub(crate) fn materialized_frame_spends(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
) -> Option<Vec<Vec<u8>>> {
    if frame_number == 0 || legacy_relay_frame(clock_store, filter, frame_number) {
        return Some(Vec::new());
    }
    if let Some(entries) = outflows.lock().ok().and_then(|map| map.get(&frame_number).and_then(|o| o.spends.clone())) {
        return Some(entries);
    }
    let bytes = clock_store.get_shard_frame_spends(filter, frame_number).ok().flatten()?;
    let entries = quil_execution::token_intrinsic::spend_relay::decode_frame_entries(&bytes).ok()?;
    update_outflow(outflows, frame_number, |o| o.spends = Some(entries.clone()));
    Some(entries)
}

/// The spend relay header `frame_number` must carry, or `None` when any frame
/// of its window is unknown to this member.
pub(crate) fn spend_relay(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
) -> Option<Vec<u8>> {
    use quil_execution::token_intrinsic::spend_relay;
    let mut frames = Vec::new();
    for frame in spend_relay::relay_window(frame_number) {
        let entries = materialized_frame_spends(outflows, clock_store, filter, frame)?;
        if !entries.is_empty() {
            frames.push((frame, entries));
        }
    }
    spend_relay::encode_relay(&frames).ok()
}

/// Record the accumulator report a materialized frame left the shard with: its
/// digest per frame (memory and clock store) and the report bytes once per
/// digest. Frame headers carry the report from these records.
pub(crate) fn record_frame_accumulator(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
    report: &[u8],
) {
    let digest = quil_execution::token_intrinsic::accumulator_header::report_digest(report);
    if let Err(error) = clock_store.put_shard_frame_accumulator(filter, frame_number, &digest, report) {
        warn!(frame = frame_number, error = %error, "failed to persist shard frame accumulator report");
        return;
    }
    update_outflow(outflows, frame_number, |o| o.accumulator = Some(digest));
}

/// Adopt only the report established by a quorum-certified header. A carried
/// report describes N-1. An empty heartbeat also establishes that N-1 has no
/// report, because every nonempty report must be carried on that frame.
///
/// Other empty fields are ambiguous: N-1 may have no report OR a nonempty one
/// unchanged across the carry window. In particular, neither an older record
/// nor this member's later cursor determines that window. Persisting a guess
/// here changes the handoff history and can split a closing committee even
/// when all members agree on state. Missing history must be recovered through
/// authenticated replay; existing conflicting records are kept for diagnosis.
pub(crate) fn adopt_certified_accumulator(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    header: &quil_types::proto::global::FrameHeader,
) {
    use quil_execution::token_intrinsic::accumulator_header::{report_digest, HEARTBEAT_FRAMES};
    let n = header.frame_number;
    if n <= 1 || header.address != filter
        || (header.accumulator.is_empty() && n % HEARTBEAT_FRAMES != 0)
    {
        return;
    }
    let certified = report_digest(&header.accumulator);
    match materialized_accumulator_digest(outflows, clock_store, filter, n - 1) {
        None => record_frame_accumulator(outflows, clock_store, filter, n - 1, &header.accumulator),
        Some(local) if local != certified => warn!(
            frame = n, filter = %hex::encode(filter),
            local = %hex::encode(local), certified = %hex::encode(certified),
            "certified accumulator report differs from local history; recovery required",
        ),
        Some(_) => {}
    }
}

/// The accumulator-report digest of a materialized frame, from memory or the
/// clock store. The genesis frame holds no coins; a frame before the relay
/// activation frame reports nothing (an empty digest is never carried).
pub(crate) fn materialized_accumulator_digest(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
) -> Option<Vec<u8>> {
    if frame_number == 0 || legacy_relay_frame(clock_store, filter, frame_number) {
        return Some(Vec::new());
    }
    if let Some(digest) = outflows.lock().ok().and_then(|map| map.get(&frame_number).and_then(|o| o.accumulator.clone())) {
        return Some(digest);
    }
    let digest = clock_store.get_shard_frame_accumulator(filter, frame_number).ok().flatten()?;
    update_outflow(outflows, frame_number, |o| o.accumulator = Some(digest.clone()));
    Some(digest)
}

/// The accumulator field header `frame_number` must carry: the report of frame
/// `frame_number - 1` when it changed from the frame before or on the
/// heartbeat, otherwise empty. `None` when a needed record is unknown to this
/// member — a proposer then proposes empty and a voter refuses to sign.
pub(crate) fn accumulator_field(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
) -> Option<Vec<u8>> {
    use quil_execution::token_intrinsic::accumulator_header;
    if frame_number == 0 {
        return Some(Vec::new());
    }
    let last = materialized_accumulator_digest(outflows, clock_store, filter, frame_number - 1)?;
    // Newest first, stopping at the first difference: that alone decides.
    let mut earlier = Vec::new();
    for back in 2..=accumulator_header::CARRY_WINDOW_FRAMES + 1 {
        let digest = match frame_number.checked_sub(back) {
            Some(frame) if frame > 0 => materialized_accumulator_digest(outflows, clock_store, filter, frame)?,
            _ => Vec::new(),
        };
        let differs = digest != last;
        earlier.push(digest);
        if differs {
            break;
        }
    }
    if !accumulator_header::header_carries(frame_number, &earlier, &last) {
        return Some(Vec::new());
    }
    let report = clock_store.get_shard_accumulator_report(filter, &last).ok().flatten()?;
    (accumulator_header::report_digest(&report) == last).then_some(report)
}

/// Adopt the quorum-certified relay window of a finalized header for window
/// frames this member has no record of (reached by sync). A local record that
/// disagrees is a divergence and is kept.
pub(crate) fn adopt_certified_settlements(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    header: &quil_types::proto::global::FrameHeader,
) {
    use quil_execution::token_intrinsic::settlement_record;
    let certified = match settlement_record::decode_relay(header.frame_number, &header.settlements) {
        Ok(frames) => frames,
        Err(error) => {
            warn!(frame = header.frame_number, error = %error, "cw finalized frame: malformed certified settlement relay");
            return;
        }
    };
    for frame in settlement_record::relay_window(header.frame_number) {
        let entries = certified.iter().find(|(f, _)| *f == frame).map(|(_, e)| e.clone()).unwrap_or_default();
        match materialized_frame_settlements(outflows, clock_store, filter, frame) {
            None => record_frame_settlements(outflows, clock_store, filter, frame, &entries),
            Some(local) if local != entries => warn!(
                frame = header.frame_number, source_frame = frame,
                local = local.len(), certified = entries.len(),
                "cw finalized frame: certified settlement entries differ from the local materialization",
            ),
            Some(_) => {}
        }
    }
}


/// Persist a frame's spend entries (memory and clock store).
pub(crate) fn record_frame_spends(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
    entries: &[Vec<u8>],
) {
    use quil_execution::token_intrinsic::spend_relay;
    let bytes = match spend_relay::encode_frame_entries(entries) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(frame = frame_number, error = %error, "noncanonical spend entries not recorded");
            return;
        }
    };
    if let Err(error) = clock_store.put_shard_frame_spends(filter, frame_number, &bytes) {
        warn!(frame = frame_number, error = %error, "failed to persist shard frame spends");
    }
    update_outflow(outflows, frame_number, |o| o.spends = Some(entries.to_vec()));
}

/// The spend counterpart of [`adopt_certified_settlements`].
pub(crate) fn adopt_certified_spends(
    outflows: &FrameOutflows,
    clock_store: &dyn ClockStore,
    filter: &[u8],
    header: &quil_types::proto::global::FrameHeader,
) {
    use quil_execution::token_intrinsic::spend_relay;
    let certified = match spend_relay::decode_relay(header.frame_number, &header.spends) {
        Ok(frames) => frames,
        Err(error) => {
            warn!(frame = header.frame_number, error = %error, "cw finalized frame: malformed certified spend relay");
            return;
        }
    };
    for frame in spend_relay::relay_window(header.frame_number) {
        let entries = certified.iter().find(|(f, _)| *f == frame).map(|(_, e)| e.clone()).unwrap_or_default();
        match materialized_frame_spends(outflows, clock_store, filter, frame) {
            None => record_frame_spends(outflows, clock_store, filter, frame, &entries),
            Some(local) if local != entries => warn!(
                frame = header.frame_number, source_frame = frame,
                local = local.len(), certified = entries.len(),
                "cw finalized frame: certified spend entries differ from the local materialization",
            ),
            Some(_) => {}
        }
    }
}

pub(crate) struct MaterializedAppFrame {
    pub(crate) processed: usize,
    pub(crate) skipped: usize,
    /// Canonical bytes of the bundles that took effect. Only these leave the
    /// collector: a skipped bundle may be valid later (a refund before its
    /// deadline at this frame's anchor) or was only over a per-frame cap.
    pub(crate) taken: Vec<Vec<u8>>,
    fee_total: u128,
    settlements: Vec<quil_execution::token_intrinsic::settlement_record::SettlementEntry>,
    spends: Vec<Vec<u8>>,
    accumulator_report: Vec<u8>,
}

pub(crate) fn materialize_app_shard_requests(
    execution_manager: &quil_execution::ExecutionEngineManager,
    requests: &[quil_types::proto::global::MessageBundle],
    frame_number: u64,
    difficulty: u32,
    world_size: u64,
    fee_multiplier_vote: u64,
    app_address: &[u8],
    global_frame_number: u64,
) -> Result<MaterializedAppFrame> {
    let addr: &[u8] = if app_address.len() >= 32 {
        &app_address[..32]
    } else {
        app_address
    };
    // Which part of the application this frame's shard holds, from its
    // certified filter. Every replica — and an archive re-executing the frame —
    // decodes the same filter, so an operation that needs the whole
    // application is refused identically everywhere rather than as an
    // infrastructure fault that would fail the frame and retry forever.
    let shard = shard_path_of_filter(app_address);

    // Verify every confidential token proof of the frame concurrently before
    // the sequential state loop below; the loop then finds verdicts cached.
    let canonical: Vec<(Vec<u8>, Vec<u8>)> = requests
        .iter()
        .filter_map(|bundle| crate::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle).ok())
        .map(|bytes| (addr.to_vec(), bytes))
        .collect();
    let preverify_start = std::time::Instant::now();
    execution_manager.preverify_bundles(&canonical);
    if preverify_start.elapsed() > std::time::Duration::from_secs(1) {
        info!(frame = frame_number, seconds = preverify_start.elapsed().as_secs_f64(), "app-shard materialize: concurrent proof pre-verification");
    }

    let mut processed = 0usize;
    let mut skipped = 0usize;
    let mut taken: Vec<Vec<u8>> = Vec::new();
    // Proof-bound QUIL fees of every admitted operation; the next frame
    // header carries the total for the shard's provers.
    let mut fee_total: u128 = 0;
    // Relay entries of the frame's admitted settlements, capped per frame.
    // Only the QUIL token shard executes settlements.
    let mut settlements: Vec<quil_execution::token_intrinsic::settlement_record::SettlementEntry> = Vec::new();
    let settles_quil = addr == quil_execution::domains::QUIL_TOKEN.as_slice();
    // Spend entries of the confidential operations this frame verified, for
    // the global commit. Capped per frame before execution, like settlements.
    let mut spends: Vec<Vec<u8>> = Vec::new();
    for bundle in requests {
        let bundle_bytes =
            match crate::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle) {
                // Re-encode too short / un-encodable are DETERMINISTIC (a pure
                // function of the bundle bytes, which are part of the finalized
                // body every replica agreed on via `requests_root`), so every
                // replica skips identically — safe. Log at info for visibility
                // (a malformed bundle inside a certified frame is notable).
                Ok(b) if b.len() >= 4 => b,
                Ok(_) => {
                    info!(frame = frame_number, "app-shard materialize: skipping bundle that re-encodes too short (<4B)");
                    skipped += 1;
                    continue;
                }
                Err(e) => {
                    info!(frame = frame_number, error = %e, "app-shard materialize: skipping un-encodable bundle");
                    skipped += 1;
                    continue;
                }
            };

        // Settlements beyond the per-frame relay cap are skipped before
        // execution: a pure function of the finalized body, identical on
        // every replica. A malformed settlement fails admission below anyway.
        let bundle_settlements = if settles_quil {
            execution_manager.message_settlements(&bundle_bytes).unwrap_or_default()
        } else {
            Vec::new()
        };
        let bundle_spends = execution_manager.message_spend_entries(addr, &bundle_bytes, frame_number).unwrap_or_default();
        if spends.len() + bundle_spends.len() > quil_execution::token_intrinsic::spend_relay::MAX_ENTRIES_PER_FRAME {
            info!(frame = frame_number, "app-shard materialize: skipping bundle beyond the per-frame spend relay cap");
            skipped += 1;
            continue;
        }
        if settlements.len() + bundle_settlements.len()
            > quil_execution::token_intrinsic::settlement_record::MAX_ENTRIES_PER_FRAME
        {
            info!(frame = frame_number, "app-shard materialize: skipping bundle beyond the per-frame settlement cap");
            skipped += 1;
            continue;
        }

        // Price the bundle at the venue where its operations COMMIT. One whose
        // operations all commit through the global frame is charged the global
        // vote of one — the price the wallet was quoted (`GetTokenFeeQuote`
        // answers QUIL from the global snapshot, vote 1) and the price the
        // global frame itself uses. Charging this shard's own, much larger fee
        // vote here rejects operations the global frame would accept, at a
        // price no wallet was ever quoted. The fee CREDITED to this shard is
        // unaffected: `fee_total` comes from the operations' declared fees.
        let bundle_vote = if execution_manager.message_commits_globally(addr, &bundle_bytes) {
            1
        } else {
            fee_multiplier_vote
        };
        let fee = match execution_manager.get_cost(&bundle_bytes)
            .and_then(|cost| crate::rewards::fee_multiplier_for_cost(execution_manager.pricing_network(), difficulty as u64, world_size, &cost, bundle_vote)) {
            Ok(fee) => fee,
            Err(e) if e.is_execution_unavailable() => return Err(e),
            Err(e) => {
                info!(frame = frame_number, error = %e, "app-shard materialize: skipping bundle with invalid fee cost");
                skipped += 1;
                continue;
            }
        };

        match execution_manager.process_message_with_context(
            quil_types::execution::FrameExecutionContext {
                frame_number,
                finalized_global_frame: (global_frame_number != 0).then_some(global_frame_number),
                shard,
                // Workers and archives replay app-shard frames alike: always
                // in the application venue, never committing inline.
                venue: Some(quil_types::execution::Venue::Application),
            }, &fee, addr, &bundle_bytes,
        ) {
            Ok(_) => {
                processed += 1;
                fee_total = fee_total.saturating_add(
                    execution_manager.message_token_fees(addr, &bundle_bytes).unwrap_or(0),
                );
                taken.push(bundle_bytes.clone());
                for entry in bundle_settlements {
                    if !settlements.iter().any(|e| e.receipt == entry.receipt) {
                        settlements.push(entry);
                    }
                }
                spends.extend(bundle_spends);
            }
            Err(e) => {
                // DIVERGENCE GUARD. Skipping a failed bundle
                // and still advancing the cursor is only safe when the failure
                // is DETERMINISTIC — a function of (bundle, agreed pre-state)
                // that every replica hits identically (bad signature, semantic
                // rejection, missing referenced entity). With pre-state now
                // validated, all replicas share the same N-1 state,
                // so those skip in lockstep and stay consistent. But an
                // INFRASTRUCTURE / TRANSIENT failure (store / IO) can succeed on
                // one replica and fail on another; skipping it would advance the
                // cursor past work that landed elsewhere → permanent, unrecoverable
                // state divergence. Make those FATAL: return Err so the caller's
                // success arm is NOT taken, the cursor does NOT advance, and the
                // frame is retried (a transient fault clears on retry; a
                // persistent one halts THIS node loudly rather than silently
                // forking its state). NB deterministic errors must stay skippable
                // — marking them fatal would permanently halt the shard, since
                // every retry re-hits the same rejection.
                if e.is_execution_unavailable() {
                    warn!(
                        frame = frame_number,
                        error = %e,
                        "app-shard materialize: INFRASTRUCTURE failure on a finalized \
                         bundle — refusing to skip (would diverge state); failing the \
                         frame for retry",
                    );
                    return Err(e);
                }
                info!(frame = frame_number, error = %e, "app-shard materialize: skipping bundle that failed deterministic validation (all replicas skip identically)");
                skipped += 1;
            }
        }
    }

    settlements.sort();
    let accumulator_report = execution_manager.commit_frame_with_app_history(
        frame_number, app_address, fee_total, &settlements, &spends, global_frame_number,
    )?;
    Ok(MaterializedAppFrame { processed, skipped, taken, fee_total, settlements, spends, accumulator_report })
}

/// The data-address bit path of the shard a filter names: empty for a bare
/// application address (a shard holding the whole application), the decoded
/// path for a sub-shard, and [`ShardPath::UNKNOWN`] for a filter that decodes
/// as neither — which is then never treated as holding the whole application.
///
/// [`ShardPath::UNKNOWN`]: quil_types::execution::ShardPath::UNKNOWN
pub(crate) fn shard_path_of_filter(filter: &[u8]) -> quil_types::execution::ShardPath {
    use quil_types::execution::ShardPath;
    match quil_forest::decode_shard_filter_or_root(filter, 32) {
        Some((_, bits)) => ShardPath::from_bits(&bits),
        None => ShardPath::UNKNOWN,
    }
}

/// Run a [`BlsAppFrameValidator`] with panic containment. A panic while
/// validating untrusted frame or storage-proof bytes is a validation failure
/// rather than unwinding the receive task. Mirrors the global frame
/// path's `catch_unwind` (`message_loop.rs`).
/// Fetch the historical storage registrations a certified frame's attestation
/// names. False when they cannot be had: the frame is then validated on its
/// certificate alone ([`validate_certified_frame`]).
async fn storage_history_retained(
    validator: &BlsAppFrameValidator,
    frame: &quil_types::proto::global::AppShardFrame,
) -> bool {
    // Every certified frame taken from an archive or the local store passes
    // here before it is validated: a legacy certificate today's registry no
    // longer reproduces gets its historical committees first.
    if let Err(error) = validator.prepare_historical_committee(frame).await {
        warn!(frame = frame.header.as_ref().map_or(0, |header| header.frame_number), %error,
            "historical committee of a certified legacy frame unavailable");
    }
    match validator.prepare_storage_history(frame).await {
        Ok(()) => true,
        Err(error) => {
            warn!(frame = frame.header.as_ref().map_or(0, |header| header.frame_number), %error,
                "storage history of a certified frame unavailable; validating its certificate without possession");
            false
        }
    }
}

/// A certified frame, with its possession proof when `retained`.
fn validate_certified_frame(
    validator: &BlsAppFrameValidator,
    frame: &quil_types::proto::global::AppShardFrame,
    retained: bool,
) -> Result<bool> {
    if retained {
        return validate_app_frame_panic_safe(validator, frame, false);
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| validator.validate_certified_without_storage(frame))) {
        Ok(result) => result,
        Err(_) => Err(QuilError::Internal("certified frame validation panicked".into())),
    }
}

pub(crate) fn validate_app_frame_panic_safe(
    validator: &BlsAppFrameValidator,
    frame: &quil_types::proto::global::AppShardFrame,
    proposal: bool,
) -> Result<bool> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if proposal {
            validator.validate_proposal(frame)
        } else {
            validator.validate(frame)
        }
    })) {
        Ok(r) => r,
        Err(_) => Err(QuilError::Crypto(
            "app-shard frame validation panicked (malformed input)".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolver messages carry the members they are addressed to; votes,
    /// certificates and blocks go to the whole topic.
    #[test]
    fn only_resolver_messages_carry_their_recipients() {
        use crate::cw_app_seams::AppConsensusTransport as _;
        let (event_tx, mut events) = mpsc::unbounded_channel();
        let transport = EngineCwTransport { filter: vec![1; 32], event_tx };
        let member = quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(&[5; 897]).unwrap();
        for (channel, expected) in [
            (crate::cw_app_seams::CW_APP_RESOLVER_CHANNEL, vec![vec![5u8; 897]]),
            (0, Vec::new()),
            (1, Vec::new()),
            (crate::cw_app_seams::CW_APP_BLOCK_CHANNEL, Vec::new()),
        ] {
            transport.deliver(channel, vec![member.clone()], vec![channel as u8]);
            match events.try_recv().unwrap() {
                AppEngineEvent::CwOut { channel: sent, recipients, .. } => {
                    assert_eq!((sent, recipients), (channel, expected));
                }
                _ => panic!("expected a CwOut"),
            }
        }
    }

    /// Each confidential bundle is proposed by exactly one live shard, the
    /// same one whichever shard asks, and by one more for each fallback period
    /// it waits. Plain bundles, and every bundle when no shard list is known,
    /// are proposed as before.
    #[test]
    fn each_submission_is_routed_to_one_shard_and_gains_one_helper_per_fallback() {
        use std::time::Duration;
        let app = [0x11u8; 32];
        let shards: Vec<Vec<u8>> = [[false, false], [false, true], [true, false], [true, true]]
            .iter()
            .map(|bits| quil_forest::encode_shard_bit_path(&app, bits))
            .collect();
        let hashes: Vec<[u8; 32]> = (0..64u8).map(|n| {
            use sha3::{Digest, Sha3_256};
            Sha3_256::digest([n]).into()
        }).collect();
        let operations = vec![1; hashes.len()];
        let fresh = vec![Duration::ZERO; hashes.len()];
        let fallback = Duration::from_secs(30);
        let mut taken = vec![0; hashes.len()];
        for shard in &shards {
            let keep = routed_selection(shard, &shards, &hashes, &operations, &fresh, fallback);
            for (i, keep) in keep.iter().enumerate() {
                taken[i] += usize::from(*keep);
            }
            assert!(keep.iter().any(|k| *k) && keep.iter().any(|k| !*k), "the bundles spread over the shards");
        }
        assert!(taken.iter().all(|n| *n == 1), "exactly one shard proposes each bundle");
        // Each fallback period admits one more shard, in the bundle's order.
        for (periods, expected) in [(1u32, 2), (2, 3), (3, 4), (9, 4)] {
            let waited = vec![fallback * periods; hashes.len()];
            let mut taken = vec![0; hashes.len()];
            for shard in &shards {
                for (i, keep) in routed_selection(shard, &shards, &hashes, &operations, &waited, fallback).iter().enumerate() {
                    taken[i] += usize::from(*keep);
                }
            }
            assert!(taken.iter().all(|n| *n == expected), "{periods} periods: {expected} shards");
        }
        let half = vec![fallback / 2; hashes.len()];
        let early = routed_selection(&shards[0], &shards, &hashes, &operations, &half, fallback);
        assert_eq!(early, routed_selection(&shards[0], &shards, &hashes, &operations, &fresh, fallback), "no helper before a full period");
        // A shard missing from the list helps once the bundle has waited a period.
        let outsider = quil_forest::encode_shard_bit_path(&app, &[true, true, true]);
        assert!(routed_selection(&outsider, &shards, &hashes, &operations, &fresh, fallback).iter().all(|k| !*k));
        let late = vec![fallback; hashes.len()];
        assert!(routed_selection(&outsider, &shards, &hashes, &operations, &late, fallback).iter().all(|k| *k));
        let plain = vec![0; hashes.len()];
        assert!(routed_selection(&shards[0], &shards, &hashes, &plain, &fresh, fallback).iter().all(|k| *k));
        assert!(routed_selection(&shards[0], &[], &hashes, &operations, &fresh, fallback).iter().all(|k| *k));
    }

    /// The live shards are this application's filters with Active provers,
    /// less a split-away parent the registry still lists, sorted.
    #[test]
    fn the_live_shards_leave_out_split_away_parents_and_idle_shards() {
        use quil_types::consensus::{ProverShardSummary, ProverStatus};
        let app = [0x11u8; 32];
        let summary = |filter: Vec<u8>, active: u32| ProverShardSummary {
            filter,
            status_counts: std::collections::HashMap::from([(ProverStatus::Active, active)]),
            total_size: 0,
        };
        let path = |bits: &[bool]| quil_forest::encode_shard_bit_path(&app, bits);
        let summaries = vec![
            summary(path(&[true]), 3),
            summary(path(&[false]), 2),
            summary(path(&[false, true]), 4),
            summary(path(&[true, true]), 0),
            summary(quil_forest::encode_shard_bit_path(&[0x22; 32], &[true]), 5),
        ];
        let mut expected = vec![path(&[true]), path(&[false, true])];
        expected.sort();
        assert_eq!(live_app_shards(&app, &summaries), expected);
        assert_eq!(live_app_shards(&path(&[false, true]), &summaries), expected, "a shard engine passes its own filter");
        assert_eq!(live_app_shards(&app, &[summary(app.to_vec(), 4)]), vec![app.to_vec()], "a whole-application shard");
    }

    /// A bundle's wait counts from its arrival at the shard, however late a
    /// collection first holds it; a stamp no collection holds expires.
    #[test]
    fn a_bundle_waits_from_its_arrival() {
        use sha3::{Digest, Sha3_256};
        use std::time::Duration;
        let clock: RoutingClock = Default::default();
        let t0 = std::time::Instant::now();
        let (a, b, c) = (b"bundle a".to_vec(), b"bundle b".to_vec(), b"bundle c".to_vec());
        let hash = |bytes: &[u8]| -> [u8; 32] { Sha3_256::digest(bytes).into() };
        stamp_arrival(&clock, &a, t0);
        stamp_arrival(&clock, &c, t0);
        stamp_arrival(&clock, &a, t0 + Duration::from_secs(50));
        let (waits, first) = routing_waits(&clock, &[hash(&a), hash(&b)], &[1, 1], t0 + Duration::from_secs(300));
        assert_eq!(waits, vec![Duration::from_secs(300), Duration::ZERO], "a re-delivery keeps the first arrival");
        assert_eq!(first, vec![true, true]);
        let (waits, first) = routing_waits(&clock, &[hash(&a), hash(&b)], &[1, 0], t0 + Duration::from_secs(400));
        assert_eq!(waits, vec![Duration::from_secs(400), Duration::ZERO]);
        assert_eq!(first, vec![false, false]);
        let late = ROUTING_CLOCK_TTL + Duration::from_secs(1);
        let (waits, _) = routing_waits(&clock, &[hash(&a)], &[1], t0 + late);
        assert_eq!(waits, vec![late], "a bundle still collected keeps waiting past the expiry");
        let held = clock.lock().unwrap();
        assert!(held.contains_key(&hash(&a)), "a bundle still collected keeps its arrival");
        assert!(!held.contains_key(&hash(&c)), "an old stamp no collection holds expires");
    }

    /// A listed shard whose frames stopped reaching GLOBAL is not designated;
    /// one the registry cannot speak for is kept, and an early chain keeps all.
    #[test]
    fn a_shard_whose_frames_stopped_is_not_designated() {
        let shards = vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]];
        let last_active = |filter: &[u8]| match filter[0] {
            1 => Some(1000 - ROUTING_ACTIVITY_FRAMES / 2),
            2 => Some(1000 - ROUTING_ACTIVITY_FRAMES),
            3 => Some(1000 - ROUTING_ACTIVITY_FRAMES - 1),
            _ => None,
        };
        assert_eq!(producing_shards(shards.clone(), 1000, last_active), vec![vec![1u8], vec![2u8], vec![4u8]]);
        assert_eq!(producing_shards(shards.clone(), ROUTING_ACTIVITY_FRAMES, |_| Some(0)), shards);
        // The order a bundle's helpers follow starts at its designated shard.
        let hash = [0u8; 32];
        assert_eq!(routing_offset(&[1u8], &shards, &hash), Some(0));
        assert_eq!(routing_offset(&[3u8], &shards, &hash), Some(2));
        assert_eq!(routing_offset(&[9u8], &shards, &hash), None);
    }

    /// The budget takes confidential bundles in arrival order while they fit,
    /// the first even over budget, and never holds back a bundle without any.
    #[test]
    fn the_verification_budget_takes_submissions_in_arrival_order() {
        assert_eq!(verification_budget_selection(&[1, 0, 1, 1, 0], 1), vec![true, true, false, false, true]);
        assert_eq!(verification_budget_selection(&[2, 2, 1], 3), vec![true, false, true]);
        assert_eq!(verification_budget_selection(&[5, 1], 1), vec![true, false]);
        assert_eq!(verification_budget_selection(&[0, 0], 1), vec![true, true]);
        assert_eq!(verification_budget_selection(&[1, 1, 1], 3), vec![true, true, true]);
    }

    /// The collector holds a submission in the encoding a finalized frame's
    /// bundle re-encodes to, so materializing that frame consumes it, even
    /// when the bytes received re-encode differently; bytes that are no
    /// bundle are kept as received.
    #[test]
    fn a_collected_submission_is_consumed_by_the_frame_that_carries_it() {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let request = |tp: u32| Some(CanonicalMessageRequest {
            inner_type_prefix: tp,
            inner_bytes: [tp.to_be_bytes().as_slice(), &[9; 48]].concat(),
        });
        // A request type the proto conversion does not carry re-encodes as
        // an empty slot.
        let received = CanonicalMessageBundle { requests: vec![request(0x0512), request(0x7777)], timestamp: 7 }
            .to_canonical_bytes()
            .unwrap();
        let held = canonical_app_message(&received);
        assert_ne!(held, received);
        assert_eq!(canonical_app_message(&held), held);
        assert_eq!(canonical_app_message(b"not a bundle"), b"not a bundle".to_vec());
        let collector = MessageCollector::new();
        collector.add_message(3, held);
        collector.add_message(3, b"other".to_vec());
        // What a member materializing the finalized frame marks consumed.
        let carried = crate::consensus_wire::decode_message_bundle(&received).unwrap();
        collector.mark_finalized(&[crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&carried).unwrap()]);
        assert_eq!(collector.collect_for_rank(4), vec![b"other".to_vec()]);
        assert!(!collector.add_message(5, canonical_app_message(&received)), "a consumed submission is not collected again");
    }

    /// A body already warming is not warmed again until its warm-up ends.
    #[test]
    fn a_proof_warm_up_claims_each_body_once_while_in_flight() {
        let (a, b) = (b"proof body a".to_vec(), b"proof body b".to_vec());
        let first = claim_proof_prewarm(&[a.clone()]).expect("first claim");
        assert!(claim_proof_prewarm(&[a.clone()]).is_none(), "already in flight");
        let second = claim_proof_prewarm(&[a.clone(), b.clone()]).expect("the new body");
        assert_eq!(second.len(), 1);
        release_proof_prewarm(&first);
        release_proof_prewarm(&second);
        assert!(claim_proof_prewarm(&[a.clone(), b.clone()]).map(|c| { release_proof_prewarm(&c); c.len() }) == Some(2));
    }

    /// A header carries its shard's accumulator report exactly when the report
    /// changed in the previous frame or on the heartbeat; the rule survives a
    /// restart from the clock store; and an unknown record makes the field
    /// unknown rather than empty, so a voter declines instead of guessing.
    #[test]
    fn accumulator_field_follows_changes_heartbeats_and_restarts() {
        use quil_execution::token_intrinsic::accumulator_header::HEARTBEAT_FRAMES;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let outflows = FrameOutflows::default();
        // Frames 1..=3 hold no coins; frame 4 gets report A; 5..=40 keep it;
        // frame 41 changes to report B.
        let (a, b) = (b"report a".to_vec(), b"report b".to_vec());
        for frame in 1..=41u64 {
            let report = match frame { 1..=3 => Vec::new(), 41 => b.clone(), _ => a.clone() };
            record_frame_accumulator(&outflows, &clock, &filter, frame, &report);
        }
        let field = |outflows: &FrameOutflows, frame| accumulator_field(outflows, &clock, &filter, frame);
        assert_eq!(field(&outflows, 1).unwrap(), Vec::<u8>::new(), "genesis holds nothing");
        assert_eq!(field(&outflows, 4).unwrap(), Vec::<u8>::new(), "frame 3 holds nothing");
        assert_eq!(field(&outflows, 5).unwrap(), a, "frame 4 changed: carried");
        let window = quil_execution::token_intrinsic::accumulator_header::CARRY_WINDOW_FRAMES;
        assert_eq!(field(&outflows, 4 + window).unwrap(), a, "re-carried through the window");
        assert_eq!(field(&outflows, 5 + window).unwrap(), Vec::<u8>::new(), "unchanged past the window: not carried");
        assert_eq!(field(&outflows, HEARTBEAT_FRAMES).unwrap(), a, "heartbeat: carried");
        assert_eq!(field(&outflows, 42).unwrap(), b, "frame 41 changed: carried");
        // After a restart the same fields come back from the clock store.
        let restarted = FrameOutflows::default();
        for frame in [5, 6, 13, 14, HEARTBEAT_FRAMES, 42] {
            assert_eq!(field(&restarted, frame), field(&outflows, frame));
        }
        // A member missing a window frame's record cannot know the field.
        let other_filter = [filter.clone(), vec![0x01]].concat();
        let fresh = FrameOutflows::default();
        record_frame_accumulator(&fresh, &clock, &other_filter, 41, &b);
        assert!(accumulator_field(&fresh, &clock, &other_filter, 42).is_none());
    }

    #[test]
    fn certified_accumulator_adoption_never_guesses_an_omitted_window() {
        use quil_execution::token_intrinsic::accumulator_header::report_digest;
        let directory = std::env::temp_dir().join(format!(
            "quil-accumulator-adoption-{}-{}", std::process::id(), rand::random::<u64>(),
        ));
        std::fs::create_dir(&directory).unwrap();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let report = b"authenticated report";
        {
            let db = quil_store::RocksDb::open(&directory).unwrap();
            let clock = quil_store::RocksClockStore::new(db.inner());
            let outflows = FrameOutflows::default();
            // An old empty report and a later nonempty one cannot resolve the
            // omitted fields in between. Both used to fill guessed records.
            record_frame_accumulator(&outflows, &clock, &filter, 68, &[]);
            record_frame_accumulator(&outflows, &clock, &filter, 80, report);
            let mut header = quil_types::proto::global::FrameHeader {
                address: filter.clone(), frame_number: 77, ..Default::default()
            };
            adopt_certified_accumulator(&outflows, &clock, &filter, &header);
            for n in 69..=79 {
                assert!(clock.get_shard_frame_accumulator(&filter, n).unwrap().is_none());
            }
            // Carrying a report authenticates exactly the preceding frame,
            // not the older carry window or the current materialized cursor.
            header.accumulator = report.to_vec();
            adopt_certified_accumulator(&outflows, &clock, &filter, &header);
            assert_eq!(clock.get_shard_frame_accumulator(&filter, 76).unwrap(), Some(report_digest(report)));
            header.frame_number = 76;
            header.accumulator.clear();
            adopt_certified_accumulator(&outflows, &clock, &filter, &header);
            assert!(clock.get_shard_frame_accumulator(&filter, 75).unwrap().is_none());
            // An empty heartbeat does establish an empty predecessor report,
            // but it says nothing about earlier frames' reports.
            header.frame_number = 96;
            adopt_certified_accumulator(&outflows, &clock, &filter, &header);
            assert_eq!(clock.get_shard_frame_accumulator(&filter, 95).unwrap(), Some(Vec::new()));
            assert!(clock.get_shard_frame_accumulator(&filter, 94).unwrap().is_none());
        }
        let db = quil_store::RocksDb::open(&directory).unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let fresh = FrameOutflows::default();
        assert_eq!(materialized_accumulator_digest(&fresh, &clock, &filter, 76), Some(report_digest(report)));
        assert_eq!(materialized_accumulator_digest(&fresh, &clock, &filter, 95), Some(Vec::new()));
        assert!(materialized_accumulator_digest(&fresh, &clock, &filter, 75).is_none());
        assert!(accumulator_field(&fresh, &clock, &filter, 77).is_none(),
            "incomplete history must still prevent a vote after reopen");
        drop(clock);
        drop(db);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn certified_accumulator_adoption_preserves_conflicts_and_filter_boundaries() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let outflows = FrameOutflows::default();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        record_frame_accumulator(&outflows, &clock, &filter, 31, b"local report");
        let original = clock.get_shard_frame_accumulator(&filter, 31).unwrap();
        let mut header = quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 32, ..Default::default()
        };
        adopt_certified_accumulator(&outflows, &clock, &filter, &header);
        header.accumulator = b"conflicting certified report".to_vec();
        adopt_certified_accumulator(&outflows, &clock, &filter, &header);
        assert_eq!(clock.get_shard_frame_accumulator(&filter, 31).unwrap(), original);
        header.address = vec![9; 32];
        header.frame_number = 64;
        adopt_certified_accumulator(&outflows, &clock, &filter, &header);
        assert!(clock.get_shard_frame_accumulator(&filter, 63).unwrap().is_none());
        assert!(clock.get_shard_frame_accumulator(&header.address, 63).unwrap().is_none());
        header.address = filter.clone();
        header.frame_number = 1;
        adopt_certified_accumulator(&outflows, &clock, &filter, &header);
        assert!(clock.get_shard_frame_accumulator(&filter, 0).unwrap().is_none());
    }

    #[test]
    fn settlement_relay_window_records_proposes_and_adopts_after_restart() {
        use quil_execution::token_intrinsic::settlement_record::{decode_relay, SettlementEntry};
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let entry = |r: u8| SettlementEntry { receipt: [r; 32], parameter_context: [1; 32], destination: [2; 32], context: [3; 32], settlement: 9, payment_address: [0; 32], payment: 0, claimant: [0; 32] };
        let outflows = FrameOutflows::default();
        // Frames 1..=40 materialized; 5 and 39 produced settlements.
        for frame in 1..=40u64 {
            let entries = match frame { 5 => vec![entry(7), entry(4)], 39 => vec![entry(8)], _ => Vec::new() };
            record_frame_settlements(&outflows, &clock, &filter, frame, &entries);
        }
        // Header 37 still carries frame 5; header 38 no longer does.
        let relay_37 = settlement_relay(&outflows, &clock, &filter, 37).unwrap();
        assert_eq!(decode_relay(37, &relay_37).unwrap(), vec![(5, vec![entry(4), entry(7)])]);
        let relay_41 = settlement_relay(&outflows, &clock, &filter, 41).unwrap();
        assert_eq!(decode_relay(41, &relay_41).unwrap(), vec![(39, vec![entry(8)])]);
        assert!(settlement_relay(&outflows, &clock, &filter, 1).unwrap().is_empty());

        // After a restart the records come back from the clock store.
        let restarted = FrameOutflows::default();
        assert_eq!(settlement_relay(&restarted, &clock, &filter, 41).unwrap(), relay_41);
        // A frame of the window this member never recorded makes the relay
        // unknown (the member nullifies instead of relaying a partial window).
        let other_filter = [filter.clone(), vec![0x01]].concat();
        let fresh = FrameOutflows::default();
        record_frame_settlements(&fresh, &clock, &other_filter, 40, &[]);
        assert!(settlement_relay(&fresh, &clock, &other_filter, 41).is_none());
        // Adopting the certified header 41 fills the window.
        let header = quil_types::proto::global::FrameHeader { frame_number: 41, settlements: relay_41.clone(), ..Default::default() };
        adopt_certified_settlements(&fresh, &clock, &other_filter, &header);
        assert_eq!(settlement_relay(&fresh, &clock, &other_filter, 41).unwrap(), relay_41);
        // A certified window never overwrites a local record.
        let conflicting = quil_types::proto::global::FrameHeader { frame_number: 41, settlements: Vec::new(), ..Default::default() };
        adopt_certified_settlements(&fresh, &clock, &other_filter, &conflicting);
        assert_eq!(settlement_relay(&fresh, &clock, &other_filter, 41).unwrap(), relay_41);
    }

    /// Shard frames anchored below the relay activation frame were made by the
    /// mainnet build, which writes no relay records. They relay nothing, so the
    /// first frame after the upgrade can be proposed and voted; what a member
    /// stored for one does not change that. From the activation frame on, the
    /// records decide, and with no activation frame nothing changes.
    #[test]
    fn frames_before_relay_activation_relay_nothing() {
        use quil_execution::token_intrinsic::global_commit::set_relay_activation_frame_for_thread;
        use quil_types::store::ClockStore as _;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let filter = quil_forest::encode_shard_bit_path(&[0x42; 32], &[true]);
        let store = |number: u64, anchor: u64| {
            let header = quil_types::proto::global::FrameHeader {
                address: filter.clone(), frame_number: number, global_frame_number: anchor,
                output: vec![number as u8; 516], ..Default::default()
            };
            let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap();
            let frame = quil_types::proto::global::AppShardFrame { header: Some(header), ..Default::default() };
            let txn = clock.new_transaction(false).unwrap();
            clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
            txn.commit().unwrap();
            let txn = clock.new_transaction(false).unwrap();
            clock.commit_shard_clock_frame(&filter, number, &selector, txn.as_ref(), false).unwrap();
            txn.commit().unwrap();
        };
        // Frames 1..=40 from the mainnet build, with none of their records;
        // frame 41 is the first anchored at the activation frame.
        for number in 1..=40 {
            store(number, 899 + number);
        }
        store(41, 1000);
        set_relay_activation_frame_for_thread(Some(1000));
        let outflows = FrameOutflows::default();
        assert_eq!(materialized_fee_total(&outflows, &clock, &filter, 40), Some(0));
        assert_eq!(settlement_relay(&outflows, &clock, &filter, 41).map(|relay| relay.is_empty()), Some(true));
        assert_eq!(spend_relay(&outflows, &clock, &filter, 41).map(|relay| relay.is_empty()), Some(true));
        assert_eq!(accumulator_field(&outflows, &clock, &filter, 41), Some(Vec::new()));
        // A member that materialized a legacy frame with this build recorded its
        // own values; they are not relayed.
        record_fee_total(&outflows, &clock, &filter, 40, 123);
        record_frame_accumulator(&outflows, &clock, &filter, 40, b"report");
        assert_eq!(materialized_fee_total(&outflows, &clock, &filter, 40), Some(0));
        assert_eq!(accumulator_field(&outflows, &clock, &filter, 41), Some(Vec::new()));
        // From the activation frame on, the records decide.
        assert_eq!(materialized_fee_total(&outflows, &clock, &filter, 41), None);
        record_fee_total(&outflows, &clock, &filter, 41, 7);
        assert_eq!(materialized_fee_total(&outflows, &clock, &filter, 41), Some(7));
        // No activation frame: every frame relays its records, as before.
        set_relay_activation_frame_for_thread(Some(0));
        assert_eq!(materialized_fee_total(&outflows, &clock, &filter, 40), Some(123));
        set_relay_activation_frame_for_thread(None);
    }

    #[test]
    fn spend_relay_window_adopts_a_certified_header_for_frames_reached_by_sync() {
        use quil_execution::token_intrinsic::spend_relay::decode_relay;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let outflows = FrameOutflows::default();
        for frame in 1..=40u64 {
            let entries = if frame == 36 { vec![vec![9u8; 32]] } else { Vec::new() };
            record_frame_spends(&outflows, &clock, &filter, frame, &entries);
        }
        let relay_41 = spend_relay(&outflows, &clock, &filter, 41).unwrap();
        assert_eq!(decode_relay(41, &relay_41).unwrap(), vec![(36, vec![vec![9u8; 32]])]);

        // A member that reached frame 40 by sync holds only frame 40.
        let fresh = FrameOutflows::default();
        let other_filter = [filter.clone(), vec![0x01]].concat();
        record_frame_spends(&fresh, &clock, &other_filter, 40, &[]);
        assert!(spend_relay(&fresh, &clock, &other_filter, 41).is_none());
        let header = quil_types::proto::global::FrameHeader { frame_number: 41, spends: relay_41.clone(), ..Default::default() };
        adopt_certified_spends(&fresh, &clock, &other_filter, &header);
        assert_eq!(spend_relay(&fresh, &clock, &other_filter, 41).unwrap(), relay_41);
        let conflicting = quil_types::proto::global::FrameHeader { frame_number: 41, spends: Vec::new(), ..Default::default() };
        adopt_certified_spends(&fresh, &clock, &other_filter, &conflicting);
        assert_eq!(spend_relay(&fresh, &clock, &other_filter, 41).unwrap(), relay_41);
    }

    #[test]
    fn app_fee_snapshot_requires_matching_cursor_and_live_engine() {
        let (msg_tx, receiver) = mpsc::channel(1);
        let materialized = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stored = Arc::new(std::sync::Mutex::new(None));
        let handle = AppEngineHandle { execution: Default::default(), cancel: CancellationToken::new(), filter: vec![7; 32], msg_tx,
            sizes: SharedAppEngineSizes::new(), materialized: materialized.clone(), fee_snapshot: stored.clone() };
        assert!(handle.fee_snapshot().is_none());
        let snapshot = quil_execution::pricing::AppFeeSnapshot {
            application: [7; 32], frame_number: 42, global_frame_number: 100,
            difficulty: 50_000, world_state_bytes: 1_234, fee_multiplier_vote: 100,
        };
        *stored.lock().unwrap() = Some(snapshot);
        assert!(handle.fee_snapshot().is_none()); // commit not advertised yet
        materialized.store(42, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(handle.fee_snapshot(), Some(snapshot));
        materialized.store(43, std::sync::atomic::Ordering::SeqCst);
        assert!(handle.fee_snapshot().is_none()); // sync advanced without pricing inputs
        materialized.store(42, std::sync::atomic::Ordering::SeqCst);
        drop(receiver);
        assert!(handle.fee_snapshot().is_none()); // old handle after engine shutdown
    }

    fn bootstrap_frame(
        address: Vec<u8>,
        frame_number: u64,
        output: Vec<u8>,
        parent_selector: Vec<u8>,
    ) -> quil_types::proto::global::AppShardFrame {
        quil_types::proto::global::AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address,
                frame_number,
                output,
                parent_selector,
                state_roots: vec![vec![1], vec![2], vec![3], vec![4]],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_session_first_frame_links_to_its_authorized_genesis_only_when_named() {
        let address = vec![0xaa; 32];
        let genesis = [0x66; 32];
        let predecessor = bootstrap_frame(address.clone(), 7, vec![0x43; 32], vec![]);
        let anchor = bootstrap_frame(address.clone(), 8, vec![0x44; 32], genesis.to_vec());
        assert!(archive_bootstrap_predecessor_height(&address, &anchor, Some(&predecessor)).is_err());
        assert_eq!(archive_bootstrap_predecessor_height_in(&address, &anchor, Some(&predecessor), Some(&genesis)), Ok(7));
        assert!(archive_bootstrap_predecessor_height_in(&address, &anchor, Some(&predecessor), Some(&[0x67; 32])).is_err());
        assert!(archive_bootstrap_predecessor_height_in(&address, &anchor, None, Some(&genesis)).is_err(),
            "the sealed base frame is still required");
    }

    #[test]
    fn a_sub_shard_filter_names_its_application() {
        let app = [0x11u8; 32];
        assert_eq!(application_of_filter(&app), Some(app));
        assert_eq!(application_of_filter(&[app.as_slice(), &[0x00, 0x04, 0x10]].concat()), Some(app));
        assert_eq!(application_of_filter(&app[..31]), None);
    }

    #[test]
    fn session_proposals_extend_the_authorized_genesis_and_never_reach_below_it() {
        let filter = vec![0xaa; 32];
        let head = bootstrap_frame(filter.clone(), 7, vec![0x43; 32], vec![]);
        let head_id = quil_crypto::poseidon::hash_bytes_to_32(&[0x43; 32]).unwrap();
        let output = vec![0x77; 32];
        let genesis = SessionGenesis {
            base_frame: 7, id: quil_crypto::poseidon::hash_bytes_to_32(&output).unwrap(), output: output.clone(),
        };
        // The successor's first frame names the authorized genesis output while
        // numbering and pacing continue from the predecessor's sealed head.
        let (parent, previous) = cw_session_parent(Ok(head.clone()), &filter, 7, &genesis.id, Some(&genesis)).unwrap();
        assert_eq!((parent, previous), (head.header.clone(), output.clone()));
        // Extending the predecessor's last output directly would bypass the handoff.
        assert!(matches!(cw_session_parent(Ok(head.clone()), &filter, 7, &head_id, Some(&genesis)), Err(QuilError::NoVote(_))));
        // A member that has not recovered the sealed head (or ran past it) waits.
        let behind = bootstrap_frame(filter.clone(), 6, vec![0x42; 32], vec![]);
        assert!(matches!(cw_session_parent(Ok(behind), &filter, 7, &genesis.id, Some(&genesis)), Err(QuilError::NoVote(_))));
        assert!(matches!(cw_session_parent(Err(QuilError::NotFound("none".into())), &filter, 7, &genesis.id, Some(&genesis)), Err(QuilError::NoVote(_))));
        assert!(matches!(cw_session_parent(Err(QuilError::Store("disk".into())), &filter, 7, &genesis.id, Some(&genesis)), Err(QuilError::Store(_))));
        // Later frames use the ordinary exact-parent rule.
        let next = bootstrap_frame(filter.clone(), 8, vec![0x44; 32], vec![]);
        let next_id = quil_crypto::poseidon::hash_bytes_to_32(&[0x44; 32]).unwrap();
        let (parent, previous) = cw_session_parent(Ok(next.clone()), &filter, 8, &next_id, Some(&genesis)).unwrap();
        assert_eq!((parent, previous), (next.header, vec![0x44; 32]));
        // A split child starts at frame zero with no local frames at all.
        let child = SessionGenesis { base_frame: 0, ..genesis.clone() };
        let (parent, previous) = cw_session_parent(Err(QuilError::NotFound("none".into())), &filter, 0, &child.id, Some(&child)).unwrap();
        assert_eq!((parent, previous), (None, output));
        // Without a session the legacy rule and its empty genesis are unchanged.
        let empty = quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap();
        assert_eq!(cw_session_parent(Err(QuilError::NotFound("none".into())), &filter, 0, &empty, None).unwrap(), (None, vec![0; 32]));
    }

    #[test]
    fn cw_proposals_require_the_exact_consensus_parent() {
        let filter = vec![0xaa; 32];
        let frame = bootstrap_frame(filter.clone(), 7, vec![0x43; 32], vec![]);
        let id = quil_crypto::poseidon::hash_bytes_to_32(&[0x43; 32]).unwrap();
        assert_eq!(cw_app_parent(Ok(frame.clone()), &filter, 7, &id).unwrap(), frame.header);
        assert!(matches!(cw_app_parent(Ok(frame.clone()), &filter, 6, &id), Err(QuilError::NoVote(_))));
        assert!(matches!(cw_app_parent(Ok(frame.clone()), &filter, 7, &[0; 32]), Err(QuilError::NoVote(_))));
        assert!(matches!(cw_app_parent(Ok(frame), &[0xbb; 32], 7, &id), Err(QuilError::NoVote(_))));
        assert!(matches!(cw_app_parent(Err(QuilError::Store("disk unavailable".into())), &filter, 0, &id), Err(QuilError::Store(_))));
        assert!(cw_app_parent(Ok(Default::default()), &filter, 0, &id).is_err());
        let empty = quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap();
        assert!(cw_app_parent(Err(QuilError::NotFound("empty".into())), &filter, 0, &empty).unwrap().is_none());
        assert!(matches!(cw_app_parent(Err(QuilError::NotFound("missing".into())), &filter, 7, &id), Err(QuilError::NoVote(_))));
    }

    #[test]
    fn archive_bootstrap_accepts_contiguous_anchor_and_predecessor() {
        let address = vec![0xaa; 32];
        let predecessor = bootstrap_frame(address.clone(), 6, vec![0x42; 32], vec![]);
        let parent_selector = quil_crypto::poseidon::hash_bytes_to_32(&[0x42; 32])
            .unwrap()
            .to_vec();
        let anchor = bootstrap_frame(address.clone(), 7, vec![0x43; 32], parent_selector);

        assert_eq!(
            archive_bootstrap_predecessor_height(&address, &anchor, Some(&predecessor)),
            Ok(6)
        );
    }

    #[test]
    fn archive_bootstrap_rejects_missing_or_unlinked_predecessor() {
        let address = vec![0xbb; 32];
        let predecessor = bootstrap_frame(address.clone(), 6, vec![0x42; 32], vec![]);
        let anchor = bootstrap_frame(address.clone(), 7, vec![0x43; 32], vec![0; 32]);

        assert_eq!(
            archive_bootstrap_predecessor_height(&address, &anchor, None),
            Err("archive omitted predecessor")
        );
        assert_eq!(
            archive_bootstrap_predecessor_height(&address, &anchor, Some(&predecessor)),
            Err("anchor does not link to predecessor")
        );
    }

    #[test]
    fn archive_bootstrap_allows_first_frame_without_predecessor() {
        let address = vec![0xcc; 32];
        let anchor = bootstrap_frame(address.clone(), 1, vec![0x42; 32], vec![]);

        assert_eq!(
            archive_bootstrap_predecessor_height(&address, &anchor, None),
            Ok(0)
        );
    }

    #[test]
    fn archive_sync_requires_certificates_for_both_frames_and_never_regresses() {
        let filter = vec![0xcc; 32];
        let predecessor = bootstrap_frame(filter.clone(), 599, vec![0x42; 32], vec![]);
        let mut anchor = bootstrap_frame(filter.clone(), 600, vec![0x43; 32],
            quil_crypto::poseidon::hash_bytes_to_32(&[0x42; 32]).unwrap().to_vec());
        anchor.header.as_mut().unwrap().state_roots = vec![vec![1; 32]; 4];
        let mut checked = Vec::new();
        assert_eq!(validate_archive_sync_anchor(&filter, 129, &anchor, Some(&predecessor), |frame| {
            checked.push(frame.header.as_ref().unwrap().frame_number);
            Ok(true)
        }).unwrap(), 599);
        assert_eq!(checked, [600, 599]);
        for rejected in [599, 600] {
            assert!(validate_archive_sync_anchor(&filter, 129, &anchor, Some(&predecessor), |frame| {
                Ok(frame.header.as_ref().unwrap().frame_number != rejected)
            }).is_err());
        }
        assert!(validate_archive_sync_anchor(&filter, 600, &anchor, Some(&predecessor), |_| {
            panic!("a regressed anchor reached certificate validation")
        }).is_err());
        let other_filter = [&filter[..], &[1]].concat();
        assert!(validate_archive_sync_anchor(&other_filter, 0, &anchor, Some(&predecessor), |_| Ok(true)).is_err());
    }

    /// Go parity (`app_consensus_engine.go:718`): core 0 → `db.path`; worker
    /// core N → `worker_paths[N-1]` else `worker_path_prefix` (`%d`→N); empty
    /// resolved path → `None` (ephemeral).
    #[test]
    fn cw_app_storage_base_matches_go_derivation() {
        use std::path::PathBuf;
        let db = quil_config::DbConfig {
            path: "/data/store".into(),
            worker_path_prefix: "/data/worker-%d".into(),
            worker_paths: vec!["/data/w1".into(), "/data/w2".into()],
            ..Default::default()
        };
        // master
        assert_eq!(cw_app_storage_base(&db, 0), Some(PathBuf::from("/data/store")));
        // worker cores covered by explicit worker_paths
        assert_eq!(cw_app_storage_base(&db, 1), Some(PathBuf::from("/data/w1")));
        assert_eq!(cw_app_storage_base(&db, 2), Some(PathBuf::from("/data/w2")));
        // worker core beyond worker_paths → prefix with %d substitution
        assert_eq!(cw_app_storage_base(&db, 3), Some(PathBuf::from("/data/worker-3")));

        // Empty db.path (test default) → None (ephemeral journal).
        let empty = quil_config::DbConfig { path: String::new(), worker_path_prefix: String::new(), worker_paths: vec![], ..Default::default() };
        assert_eq!(cw_app_storage_base(&empty, 0), None);
    }

    #[test]
    fn app_cw_journal_preserves_history_on_change() {
        use quil_cw_consensus::falcon_base::FalconPublicKey;
        let pk = |b: u8| FalconPublicKey::from_bytes(&[b; 897]).unwrap();
        let committee_a = vec![pk(0x01), pk(0x02), pk(0x03)];
        let committee_b = vec![pk(0x01), pk(0x02), pk(0x04)]; // one member replaced

        let base = std::env::temp_dir().join(format!(
            "quil-cwjournal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let journal_dir = base.join("cw-app-consensus").join("app-deadbeef");
        let file = journal_dir.join("journal-file");
        let repopulate = || {
            std::fs::create_dir_all(&journal_dir).unwrap();
            std::fs::write(&file, b"votes").unwrap();
        };

        // First call has no stored fingerprint → preserves the unknown journal,
        // then records committee A's fingerprint.
        repopulate();
        prepare_app_cw_journal(&journal_dir, &committee_a, b"shard", b"signer", [1; 32], 10, false).unwrap();
        // Same committee → journal preserved (a moved head does NOT reset it).
        repopulate();
        assert_eq!(prepare_app_cw_journal(&journal_dir, &committee_a, b"shard", b"signer", [2; 32], 20, false).unwrap(), ([1; 32], 10));
        assert!(file.exists(), "same committee must keep the journal");
        let descriptor_path = journal_dir.with_extension("cw-fp");
        let descriptor = std::fs::read(&descriptor_path).unwrap();
        // A regressed or conflicting local head must not silently rebase votes.
        assert!(prepare_app_cw_journal(&journal_dir, &committee_a, b"shard", b"signer", [1; 32], 9, false).is_err());
        assert!(prepare_app_cw_journal(&journal_dir, &committee_a, b"shard", b"signer", [2; 32], 10, false).is_err());
        assert_eq!(std::fs::read(&descriptor_path).unwrap(), descriptor);
        assert_eq!(std::fs::read(&file).unwrap(), b"votes");
        let mut trailing = descriptor.clone();
        trailing.push(0);
        let mut unknown_version = descriptor.clone();
        unknown_version[4] = 2;
        for malformed in [trailing, descriptor[..20].to_vec(), unknown_version] {
            std::fs::write(&descriptor_path, &malformed).unwrap();
            assert!(prepare_app_cw_journal(&journal_dir, &committee_a, b"shard", b"signer", [2; 32], 20, false).is_err());
            assert_eq!(std::fs::read(&descriptor_path).unwrap(), malformed);
            assert_eq!(std::fs::read(&file).unwrap(), b"votes");
        }
        std::fs::write(&descriptor_path, descriptor).unwrap();
        // Changed committee → old journal archived and isolated.
        prepare_app_cw_journal(&journal_dir, &committee_b, b"shard", b"signer", [2; 32], 20, false).unwrap();
        assert!(!file.exists(), "new session must not replay another committee's votes");
        let retired = journal_dir.with_extension("retired");
        assert_eq!(std::fs::read(retired.join("0/journal/journal-file")).unwrap(), b"votes");
        assert_eq!(std::fs::read(retired.join("1/journal/journal-file")).unwrap(), b"votes");
        assert!(retired.join("1/fingerprint").exists());
        let mut reversed = committee_b.clone();
        reversed.reverse();
        for (members, filter, signer) in [
            (&committee_b, &b"shard"[..], &b"other signer"[..]),
            (&committee_b, &b"other shard"[..], &b"other signer"[..]),
            (&reversed, &b"other shard"[..], &b"other signer"[..]),
        ] {
            repopulate();
            prepare_app_cw_journal(&journal_dir, members, filter, signer, [2; 32], 20, false).unwrap();
            assert!(!file.exists(), "signer, shard and ordered participants all bind the journal");
        }
        let blocked = base.join("blocked-parent");
        std::fs::write(&blocked, b"preserve me").unwrap();
        assert!(reset_stale_cw_journal(&blocked.join("journal"), &[1]).is_err());
        assert_eq!(std::fs::read(blocked).unwrap(), b"preserve me");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_adopted_head_retires_an_older_genesis_of_the_same_committee() {
        use quil_cw_consensus::falcon_base::FalconPublicKey;
        let pk = |b: u8| FalconPublicKey::from_bytes(&[b; 897]).unwrap();
        let committee = vec![pk(0x01), pk(0x02), pk(0x03)];
        let base = std::env::temp_dir().join(format!(
            "quil-cwadopt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let journal_dir = base.join("cw-app-consensus").join("app-deadbeef");
        let file = journal_dir.join("journal-file");
        let repopulate = || {
            std::fs::create_dir_all(&journal_dir).unwrap();
            std::fs::write(&file, b"votes").unwrap();
        };
        let prepare = |anchor: u8, frame: u64, adopt: bool| {
            prepare_app_cw_journal(&journal_dir, &committee, b"shard", b"signer", [anchor; 32], frame, adopt)
        };

        // The committee's instance began at frame 0; another committee then
        // certified the head this member recovered.
        repopulate();
        assert_eq!(prepare(0, 0, false).unwrap(), ([0; 32], 0));
        repopulate();
        assert_eq!(prepare(5, 40, false).unwrap(), ([0; 32], 0), "a moved head keeps the genesis");
        assert!(file.exists());
        assert_eq!(prepare(5, 40, true).unwrap(), ([5; 32], 40), "an adopted head is the new genesis");
        assert!(!file.exists(), "votes of the older genesis are not replayed");
        let retired = journal_dir.with_extension("retired");
        assert_eq!(std::fs::read(retired.join("1/journal/journal-file")).unwrap(), b"votes");

        // Restarting on the same adopted head keeps its votes, and a head
        // this committee then finalized past it resumes from it.
        repopulate();
        assert_eq!(prepare(5, 40, true).unwrap(), ([5; 32], 40));
        assert_eq!(prepare(6, 41, false).unwrap(), ([5; 32], 40));
        assert!(file.exists(), "the adopted instance's own votes are kept");
        // Never a head below or beside the genesis already adopted.
        assert!(prepare(4, 39, true).is_err());
        assert!(prepare(4, 40, true).is_err());
        assert!(file.exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Build an Application-mode ExecutionEngineManager backed by an
    /// in-memory CRDT + noop crypto, for exercising the app-shard
    /// materialize plumbing.
    fn app_test_manager() -> (
        std::sync::Arc<quil_execution::ExecutionEngineManager>,
        std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    ) {
        use std::sync::Arc;
        use quil_types::crypto::NoopInclusionProver;
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let mgr = Arc::new(quil_execution::ExecutionEngineManager::new(
            Arc::new(NoopInclusionProver),
            crypto.key_manager.clone(),
            crdt.clone(),
            crypto.circuit_compiler.clone(),
            crypto.clock_store.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            false, // application mode (no global engine)
        ));
        (mgr, crdt)
    }

    #[test]
    fn app_shard_materialize_empty_frame_commits() {
        let (mgr, _crdt) = app_test_manager();
        // No requests → nothing processed, commit_frame still succeeds.
        let materialized = materialize_app_shard_requests(
            mgr.as_ref(),
            &[],
            1,
            50_000,
            0,
            1,
            &quil_execution::domains::QUIL_TOKEN,
            0,
        )
        .unwrap();
        assert_eq!(materialized.processed, 0);
        assert_eq!(materialized.skipped, 0);
    }

    #[tokio::test]
    async fn archive_replay_authenticates_before_writes_and_retains_materialization_history() {
        let rocks = quil_store::RocksDb::open_in_memory().unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(rocks.inner()));
        let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store.clone(), prover.clone()));
        crdt.set_forest(quil_forest::Forest::with_namespace(rocks.inner(), quil_store::FOREST_NAMESPACE));
        let clock = Arc::new(quil_store::RocksClockStore::new(rocks.inner()));
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
            prover.clone(), crypto.key_manager, crdt.clone(), crypto.circuit_compiler,
            clock.clone(), Arc::new(quil_execution::testing::NoopHypergraphConfigResolver), false,
        ));
        let (events, _received) = mpsc::unbounded_channel();
        let private = [7; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
        let deps = AppEngineDeps {
            delivery_frame_source: None,
            clock_store: clock.clone(), global_anchor_store: None, global_hypergraph: None,
            prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
            frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            message_collector: Arc::new(MessageCollector::new()),
            fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
            local_prover_address: vec![1; 32], local_bls_pubkey: vec![],
            bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
            reward_greedy: false, min_active_provers_for_propose: 1,
            coverage_publish: None, hypergraph: Some(crdt.clone()), storage_source_hypergraph: None, topology: None,
            execution_engine: Some(manager), inclusion_prover: Some(prover), kv_db: None,
            app_consensus_cw: false, db_config: Default::default(), unified_cutover_hook: None,
        };
        let app = quil_execution::domains::QUIL_TOKEN;
        let (mut engine, _) = AppConsensusEngine::new(1, app.to_vec(), deps, events);
        let shard = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3), l2: app,
        };
        let roots = [("vertex", "adds"), ("vertex", "removes"),
                     ("hyperedge", "adds"), ("hyperedge", "removes")].iter()
            .map(|(set, phase)| crdt.compute_shard_root(set, phase, &shard)).collect();
        let frame = quil_types::proto::global::AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: app.to_vec(), frame_number: 1, difficulty: 50000,
                output: vec![1; 32], state_roots: roots,
                requests_root: engine.recompute_requests_root_offloaded(vec![], 1).await.unwrap(),
                ..Default::default()
            }), ..Default::default()
        };
        // The production entry requires a ready certificate validator.
        assert!(engine.replay_archive_frame(frame.clone(), None).await.is_err());
        assert!(engine.replay_archive_frame_with(frame.clone(), |_| Ok(false)).await.is_err());
        let mut bad_body = frame.clone();
        bad_body.header.as_mut().unwrap().requests_root = vec![9; 32];
        assert!(engine.replay_archive_frame_with(bad_body, |_| Ok(true)).await.is_err());
        assert!(clock.get_latest_shard_clock_frame(&app).is_err());
        assert_eq!(engine.load_materialized_cursor().unwrap(), 0);

        store.fail_commit_for_test(true);
        assert!(engine.replay_archive_frame_with(frame.clone(), |_| Ok(true)).await.is_err());
        assert_eq!(engine.last_materialized_frame, 0);
        assert!(engine.frame_outflows.lock().unwrap().is_empty());
        assert!(clock.get_shard_frame_fee_total(&app, 1).unwrap().is_none());
        assert!(clock.get_shard_frame_settlements(&app, 1).unwrap().is_none());
        assert!(clock.get_shard_frame_spends(&app, 1).unwrap().is_none());
        assert!(clock.get_shard_frame_accumulator(&app, 1).unwrap().is_none());
        store.fail_commit_for_test(false);
        assert_eq!(engine.replay_archive_frame_with(frame, |_| Ok(true)).await.unwrap(), 1);
        assert_eq!(engine.load_materialized_cursor().unwrap(), 1);
        // A new reader, with no in-memory records, still has the outflow history
        // needed to build the next frame's report and relay windows.
        let fresh_clock = quil_store::RocksClockStore::new(rocks.inner());
        let fresh = FrameOutflows::default();
        assert_eq!(materialized_fee_total(&fresh, &fresh_clock, &app, 1), Some(0));
        assert!(settlement_relay(&fresh, &fresh_clock, &app, 2).is_some());
        assert!(spend_relay(&fresh, &fresh_clock, &app, 2).is_some());
        assert!(materialized_accumulator_digest(&fresh, &fresh_clock, &app, 1).is_some());
    }

    #[tokio::test]
    async fn app_fee_snapshot_requires_successful_commit_and_cursor() {
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store.clone(), prover.clone()));
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
            prover.clone(), crypto.key_manager.clone(), crdt.clone(), crypto.circuit_compiler,
            crypto.clock_store.clone(), Arc::new(quil_execution::testing::NoopHypergraphConfigResolver), false,
        ));
        let (events, _received) = mpsc::unbounded_channel();
        let private = [7; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
        // Anchored global frames carry the certified world size fees price from.
        let anchors = Arc::new(quil_store::testing::InMemoryClockStore::new());
        for (number, size) in [(100u64, 1234u64), (101, 2345)] {
            anchors.seed_frame(quil_types::proto::global::GlobalFrame {
                header: Some(quil_types::proto::global::GlobalFrameHeader {
                    frame_number: number, world_state_size: size, ..Default::default()
                }),
                requests: vec![],
            });
        }
        let deps = AppEngineDeps {
            delivery_frame_source: None,
            clock_store: crypto.clock_store, global_anchor_store: Some(anchors.clone() as Arc<dyn ClockStore>), global_hypergraph: None,
            prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
            frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            message_collector: Arc::new(MessageCollector::new()),
            fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
            local_prover_address: vec![1; 32], local_bls_pubkey: vec![],
            bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
            reward_greedy: false, min_active_provers_for_propose: 1,
            coverage_publish: None, hypergraph: Some(crdt), storage_source_hypergraph: None, topology: None,
            execution_engine: Some(manager), inclusion_prover: Some(prover), kv_db: None,
            app_consensus_cw: false, db_config: Default::default(), unified_cutover_hook: None,
        };
        let application = quil_execution::domains::QUIL_TOKEN;
        let (mut engine, handle) = AppConsensusEngine::new(1, application.to_vec(), deps, events);
        assert!(handle.fee_snapshot().is_none());
        // An anchor this member does not hold is an infrastructure fault: the
        // frame is retried rather than priced from a substitute size.
        let missing = engine.materialize_offloaded(vec![], 1, 50_000, 7, 555).await.unwrap_err();
        assert!(missing.is_execution_unavailable());
        assert_eq!(engine.load_materialized_cursor().unwrap(), 0);
        engine.materialize_offloaded(vec![], 1, 50_000, 7, 100).await.unwrap();
        assert_eq!(engine.load_materialized_cursor().unwrap(), 1);
        assert!(handle.fee_snapshot().is_none()); // durable state/cursor precede advertised cursor
        engine.set_materialized_frame(1);
        let first = handle.fee_snapshot().unwrap();
        assert_eq!(first, quil_execution::pricing::AppFeeSnapshot {
            application, frame_number: 1, global_frame_number: 100,
            difficulty: 50_000, world_state_bytes: 1234, fee_multiplier_vote: 7,
        });
        for (index, failure) in [(true, false), (false, true)].into_iter().enumerate() {
            let next = index as u64 + 2;
            let previous = handle.fee_snapshot().unwrap();
            store.fail_commit_setup(failure.0, failure.1);
            if failure.0 { assert!(engine.load_materialized_cursor().is_err()); }
            assert!(engine.materialize_offloaded(vec![], next, 60_000, 9, 101).await.is_err());
            assert_eq!(handle.fee_snapshot(), Some(previous));
            assert_eq!(engine.last_materialized_frame, next - 1);
            store.fail_commit_setup(false, false);
            assert_eq!(engine.load_materialized_cursor().unwrap(), next - 1);
            engine.materialize_offloaded(vec![], next, 60_000, 9, 101).await.unwrap();
            assert!(handle.fee_snapshot().is_none());
            engine.set_materialized_frame(next);
            assert_eq!(handle.fee_snapshot().unwrap().frame_number, next);
        }
        engine.received_full_frames.insert(4, Default::default());
        engine.finalized_requests_roots.insert(4, vec![1; 32]);
        store.fail_commit_setup(true, false);
        assert!(engine.reconcile_with_sync(4).await.is_err());
        assert_eq!(engine.last_materialized_frame, 3);
        assert_eq!(handle.fee_snapshot().unwrap().frame_number, 3);
        assert!(engine.received_full_frames.contains_key(&4));
        assert!(engine.finalized_requests_roots.contains_key(&4));
        store.fail_commit_setup(false, false);
        assert_eq!(engine.load_materialized_cursor().unwrap(), 3);
        engine.reconcile_with_sync(4).await.unwrap();
        assert_eq!(engine.last_materialized_frame, 4);
        assert!(engine.received_full_frames.is_empty());
        assert!(engine.finalized_requests_roots.is_empty());
        assert!(handle.fee_snapshot().is_none()); // sync has no pricing snapshot
        assert_eq!(engine.load_materialized_cursor().unwrap(), 4);
        engine.reconcile_with_sync(3).await.unwrap();
        assert_eq!(engine.load_materialized_cursor().unwrap(), 4);
        use quil_types::store::HypergraphStore;
        let txn = store.new_transaction(false).unwrap();
        txn.set(&quil_store::encoding::consensus_materialized_cursor_key(&application), b"bad").unwrap();
        txn.commit().unwrap();
        assert!(engine.load_materialized_cursor().is_err());
    }

    /// A sealed parent lands in a durable clock store: canonical, at the head,
    /// with no staged copy left behind. The durable store reads staged bytes
    /// from committed storage, so a single stage-and-commit transaction left the
    /// parent uncommitted (the in-memory store used above hid it).
    #[tokio::test]
    async fn a_sealed_parent_is_committed_to_a_durable_clock_store() {
        use prost::Message;
        use quil_types::store::KvDb as _;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let (events, mut received) = mpsc::unbounded_channel();
        let private = [7; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
        let deps = AppEngineDeps {
            delivery_frame_source: None,
            clock_store: clock.clone(), global_anchor_store: None, global_hypergraph: None,
            prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
            frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            message_collector: Arc::new(MessageCollector::new()),
            fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
            local_prover_address: vec![1; 32], local_bls_pubkey: vec![],
            bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
            reward_greedy: false, min_active_provers_for_propose: 1,
            coverage_publish: None, hypergraph: None, storage_source_hypergraph: None, topology: None,
            execution_engine: None, inclusion_prover: None, kv_db: None,
            app_consensus_cw: false, db_config: Default::default(), unified_cutover_hook: None,
        };
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (mut engine, _handle) = AppConsensusEngine::new(1, filter.clone(), deps, events);
        let frame = quil_types::proto::global::AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: filter.clone(), frame_number: 2, rank: 2, output: vec![5; 32],
                parent_selector: vec![3; 32], ..Default::default()
            }), ..Default::default()
        };
        engine.pending_certified_parents.insert(2, frame.encode_to_vec());
        engine.set_materialized_frame(1);
        let (manager, crdt) = app_test_manager();
        engine.execution_engine = Some(manager);
        engine.hypergraph = Some(crdt);
        engine.try_seal_parent_with_child(3).await;
        assert_eq!(engine.last_materialized_frame, 2);
        assert!(matches!(received.try_recv().unwrap(), AppEngineEvent::ParentSealed { parent_rank: 2, .. }));
        assert_eq!(clock.get_shard_clock_frame(&filter, 2, false).unwrap(), frame);
        assert_eq!(clock.get_latest_shard_clock_frame(&filter).unwrap(), frame);
        let selector = quil_crypto::poseidon::hash_bytes_to_32(&[5; 32]).unwrap();
        for staged in [&selector[..], &[3; 32][..]] {
            assert!(db.get(&quil_store::encoding::clock_shard_staged_key(staged, 2)).unwrap().is_none(),
                "no staged copy outlives the seal");
        }
    }

    #[tokio::test]
    async fn app_shard_materialize_parent_sealing_waits_for_state_and_retries() {
        use prost::Message;
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (events, mut received) = mpsc::unbounded_channel();
        let private = [7; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
        let deps = AppEngineDeps {
            delivery_frame_source: None,
            clock_store: clock.clone(), global_anchor_store: None, global_hypergraph: None,
            prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
            frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            message_collector: Arc::new(MessageCollector::new()),
            fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
            local_prover_address: vec![1; 32], local_bls_pubkey: vec![],
            bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
            reward_greedy: false, min_active_provers_for_propose: 1,
            coverage_publish: None, hypergraph: None, storage_source_hypergraph: None, topology: None,
            execution_engine: None, inclusion_prover: None, kv_db: None,
            app_consensus_cw: false, db_config: Default::default(), unified_cutover_hook: None,
        };
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (mut engine, _handle) = AppConsensusEngine::new(1, filter.clone(), deps, events);
        let frame = quil_types::proto::global::AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                // Every certified app frame carries an output; the clock store
                // keys it by that output's digest.
                address: filter.clone(), frame_number: 2, rank: 2, output: vec![5; 32],
                parent_selector: vec![3; 32], ..Default::default()
            }), ..Default::default()
        };
        engine.pending_certified_parents.insert(2, frame.encode_to_vec());
        // Merely caching a parent does not authorize timer-driven sealing.
        engine.retry_certified_parent_seals().await;
        assert!(engine.retry_parent_seals.is_empty());
        // A missing predecessor must not advance the clock or lose the body.
        engine.try_seal_parent_with_child(3).await;
        assert!(engine.pending_certified_parents.contains_key(&2));
        assert!(received.try_recv().is_err());
        assert!(clock.get_shard_clock_frame(&filter, 2, false).is_err());
        // Reaching the predecessor is insufficient without an executor.
        engine.set_materialized_frame(1);
        engine.try_seal_parent_with_child(3).await;
        assert!(engine.pending_certified_parents.contains_key(&2));
        assert!(received.try_recv().is_err());
        assert!(clock.get_shard_clock_frame(&filter, 2, false).is_err());
        let (manager, crdt) = app_test_manager();
        engine.execution_engine = Some(manager);
        engine.hypergraph = Some(crdt);
        clock.fail_next_shard_stage();
        engine.try_seal_parent_with_child(3).await;
        assert_eq!(engine.last_materialized_frame, 2);
        assert!(engine.pending_certified_parents.contains_key(&2));
        assert!(received.try_recv().is_err());
        assert!(clock.get_shard_clock_frame(&filter, 2, false).is_err());
        // State was already committed; retrying the clock must not require
        // the executor or reapply token state changes.
        engine.execution_engine = None;
        engine.current_rank = 100;
        engine.cleanup_frame_store();
        assert!(engine.pending_certified_parents.contains_key(&2));
        assert!(engine.retry_parent_seals.contains(&2));
        engine.retry_certified_parent_seals().await;
        assert_eq!(engine.last_materialized_frame, 2);
        assert!(!engine.pending_certified_parents.contains_key(&2));
        assert!(engine.retry_parent_seals.is_empty());
        assert!(matches!(received.try_recv().unwrap(), AppEngineEvent::ParentSealed { parent_rank: 2, .. }));
        assert!(clock.get_shard_clock_frame(&filter, 2, false).is_ok());
        engine.try_seal_parent_with_child(3).await;
        assert!(received.try_recv().is_err());

        let (manager, crdt) = app_test_manager();
        engine.execution_engine = Some(manager);
        engine.hypergraph = Some(crdt);
        let root = engine.recompute_requests_root_offloaded(vec![], 3).await.unwrap();
        let mut follower = bootstrap_frame(filter.clone(), 3, vec![4; 32], vec![]);
        follower.header.as_mut().unwrap().requests_root = root.clone();
        engine.commit_shard_clock_head(&follower, 3).unwrap();
        engine.finalized_requests_roots.insert(3, root);
        engine.received_full_frames.insert(3, follower.clone());
        clock.fail_next_shard_stage();
        engine.try_materialize_follower_frames().await;
        assert_eq!(engine.last_materialized_frame, 3);
        assert!(engine.pending_follower_clock.is_some());
        assert!(engine.received_full_frames.contains_key(&3));
        // A clock-only retry must work without an executor and leave the cursor unchanged.
        engine.execution_engine = None;
        engine.try_materialize_follower_frames().await;
        assert_eq!(engine.last_materialized_frame, 3);
        assert!(engine.pending_follower_clock.is_none());
        assert!(!engine.received_full_frames.contains_key(&3));
        assert!(engine.commit_shard_clock_head(&follower, 4).is_err());
        assert!(engine.commit_shard_clock_head(&Default::default(), 4).is_err());
        for (creation, commit) in [(1, 0), (2, 0), (0, 1), (0, 2)] {
            clock.fail_clock_transaction(creation, commit);
            assert!(engine.commit_shard_clock_head(&follower, 3).is_err());
            clock.fail_clock_transaction(0, 0);
            engine.commit_shard_clock_head(&follower, 3).unwrap();
        }
    }

    /// After a restart, finalized frames can reach the engine past a gap (a
    /// replayed record behind a newer finalization). The later frame is not
    /// applied over the gap, and is not dropped either.
    #[tokio::test]
    async fn a_finalized_frame_ahead_of_the_cursor_is_applied_once_the_gap_fills() {
        use prost::Message;
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (events, _received) = mpsc::unbounded_channel();
        let private = [7; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
        let (manager, crdt) = app_test_manager();
        let deps = AppEngineDeps {
            delivery_frame_source: None,
            clock_store: clock.clone(), global_anchor_store: None, global_hypergraph: None,
            prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
            frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            message_collector: Arc::new(MessageCollector::new()),
            fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
            local_prover_address: vec![1; 32], local_bls_pubkey: vec![],
            bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
            reward_greedy: false, min_active_provers_for_propose: 1,
            coverage_publish: None, hypergraph: Some(crdt), storage_source_hypergraph: None, topology: None,
            execution_engine: Some(manager), inclusion_prover: None, kv_db: None,
            app_consensus_cw: false, db_config: Default::default(), unified_cutover_hook: None,
        };
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (mut engine, _handle) = AppConsensusEngine::new(1, filter.clone(), deps, events);
        let mut frames = Vec::new();
        for number in 1..=2 {
            let mut frame = bootstrap_frame(filter.clone(), number, vec![number as u8; 32], vec![]);
            let header = frame.header.as_mut().unwrap();
            header.rank = number;
            header.requests_root = engine.recompute_requests_root_offloaded(vec![], number).await.unwrap();
            frames.push(frame.encode_to_vec());
        }
        engine.handle_cw_finalized_frame(&frames[1], &[], true, Vec::new()).await;
        assert_eq!(engine.last_materialized_frame, 0);
        assert!(clock.get_shard_clock_frame(&filter, 2, false).is_ok());
        engine.handle_cw_finalized_frame(&frames[0], &[], true, Vec::new()).await;
        assert_eq!(engine.last_materialized_frame, 1);
        engine.try_materialize_follower_frames().await;
        assert_eq!(engine.last_materialized_frame, 2);
        assert!(engine.received_full_frames.is_empty());
    }

    /// A member built frame 3 on a notarized frame 2 that never finalized on
    /// its own; 3's finalization makes 2 final. Otherwise GLOBAL halts
    /// because no member ever commits 2.
    #[tokio::test]
    async fn a_certified_frame_brings_the_notarized_parent_it_makes_final() {
        use prost::Message;
        let build = |events| {
            let private = [7; 57];
            let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
            let (manager, crdt) = app_test_manager();
            let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
            let deps = AppEngineDeps {
                delivery_frame_source: None,
                clock_store: clock.clone(), global_anchor_store: None, global_hypergraph: None,
                prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
                frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
                message_collector: Arc::new(MessageCollector::new()),
                fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
                local_prover_address: vec![1; 32], local_bls_pubkey: vec![],
                bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
                reward_greedy: false, min_active_provers_for_propose: 1,
                coverage_publish: None, hypergraph: Some(crdt), storage_source_hypergraph: None, topology: None,
                execution_engine: Some(manager), inclusion_prover: None, kv_db: None,
                app_consensus_cw: false, db_config: Default::default(), unified_cutover_hook: None,
            };
            let (engine, _handle) = AppConsensusEngine::new(1, quil_execution::domains::QUIL_TOKEN.to_vec(), deps, events);
            (engine, clock)
        };
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (events, mut received) = mpsc::unbounded_channel();
        let (mut engine, clock) = build(events);
        let mut frames: Vec<quil_types::proto::global::AppShardFrame> = Vec::new();
        for number in 1..=3u64 {
            let parent = frames.last().map(|parent: &quil_types::proto::global::AppShardFrame| {
                quil_crypto::poseidon::hash_bytes_to_32(&parent.header.as_ref().unwrap().output).unwrap().to_vec()
            }).unwrap_or_default();
            let mut frame = bootstrap_frame(filter.clone(), number, vec![number as u8; 32], parent);
            let header = frame.header.as_mut().unwrap();
            header.rank = number;
            header.requests_root = engine.recompute_requests_root_offloaded(vec![], number).await.unwrap();
            frames.push(frame);
        }
        engine.handle_cw_finalized_frame(&frames[0].encode_to_vec(), &[], true, Vec::new()).await;
        engine.handle_cw_finalized_frame(&frames[2].encode_to_vec(), &[], true,
            vec![(frames[1].encode_to_vec(), true)]).await;
        assert_eq!(engine.last_materialized_frame, 3);
        let implied = clock.get_shard_clock_frame(&filter, 2, false).unwrap();
        assert!(implied.header.unwrap().public_key_signature_bls48581.is_none(), "it has no certificate of its own");
        assert_eq!(clock.get_latest_shard_clock_frame(&filter).unwrap().header.unwrap().frame_number, 3);
        let (mut full, mut rewarded) = (Vec::new(), 0);
        while let Ok(event) = received.try_recv() {
            match event {
                AppEngineEvent::FullFrameProduced { frame_number, .. } => full.push(frame_number),
                AppEngineEvent::ShardFrameFinalized { .. } => rewarded += 1,
                _ => {}
            }
        }
        assert_eq!(full, vec![1, 2, 3], "every frame is published for archives and followers");
        assert_eq!(rewarded, 2, "only the certified frames are submitted for reward");

        // An ancestor that does not link is not applied; the frame waits.
        let (events, _received) = mpsc::unbounded_channel();
        let (mut engine, clock) = build(events);
        let mut stranger = frames[1].clone();
        stranger.header.as_mut().unwrap().output = vec![0xee; 32];
        engine.handle_cw_finalized_frame(&frames[0].encode_to_vec(), &[], true, Vec::new()).await;
        engine.handle_cw_finalized_frame(&frames[2].encode_to_vec(), &[], true,
            vec![(stranger.encode_to_vec(), true)]).await;
        assert_eq!(engine.last_materialized_frame, 1);
        assert!(clock.get_shard_clock_frame(&filter, 2, false).is_err());

        // A member that never held 2's body: it arrives by gossip with no
        // certificate, and is adopted under the certified 3 it links to.
        let (events, _received) = mpsc::unbounded_channel();
        let (mut engine, clock) = build(events);
        engine.handle_cw_finalized_frame(&frames[0].encode_to_vec(), &[], true, Vec::new()).await;
        engine.received_full_frames.insert(2, stranger);
        engine.handle_cw_finalized_frame(&frames[2].encode_to_vec(), &[], true, Vec::new()).await;
        assert!(clock.get_shard_clock_frame(&filter, 2, false).is_err(), "a frame that does not link is not adopted");
        engine.received_full_frames.insert(2, frames[1].clone());
        let child = clock.get_shard_clock_frame(&filter, 3, false).unwrap().header.unwrap();
        engine.adopt_linked_parents(&child);
        engine.try_materialize_follower_frames().await;
        assert_eq!(engine.last_materialized_frame, 3);
        assert_eq!(clock.get_latest_shard_clock_frame(&filter).unwrap().header.unwrap().frame_number, 3);
    }

    #[test]
    fn app_shard_materialize_iterates_each_bundle() {
        let (mgr, _crdt) = app_test_manager();
        // Two (empty) bundles routed to the token domain: each is
        // dispatched to the token engine and the frame committed. Proves
        // the seal-time pass iterates frame.requests, routes by the
        // shard app address, and calls commit_frame — the wiring that was
        // missing (app-shard frames previously only hit the clock store).
        let bundles = vec![
            quil_types::proto::global::MessageBundle::default(),
            quil_types::proto::global::MessageBundle::default(),
        ];
        let materialized = materialize_app_shard_requests(
            mgr.as_ref(),
            &bundles,
            2,
            50_000,
            0,
            7, // non-trivial fee_multiplier_vote exercises the app-specific multiply
            &quil_execution::domains::QUIL_TOKEN,
            913, // global anchor deliberately differs from app frame 2
        )
        .unwrap();
        assert_eq!(materialized.processed, 2);
        let empty = crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundles[0]).unwrap();
        assert_eq!(materialized.taken, vec![empty.clone(), empty], "both took effect");
    }

    /// Only the bundles that took effect are reported taken, and so consumed
    /// from the collector; a skipped one stays to be proposed again.
    #[test]
    fn a_skipped_bundle_is_not_taken() {
        use quil_types::proto::global::{message_request::Request, MessageBundle, MessageRequest};
        let (mgr, _crdt) = app_test_manager();
        // A handoff request that does not decode: the bundle is skipped
        // identically on every replica.
        let rejected = MessageBundle {
            requests: vec![MessageRequest { timestamp: 1, request: Some(Request::CommitteeHandoff(vec![7; 40])) }],
            timestamp: 1,
        };
        let bundles = vec![MessageBundle::default(), rejected];
        let materialized = materialize_app_shard_requests(
            mgr.as_ref(), &bundles, 2, 50_000, 0, 1, &quil_execution::domains::QUIL_TOKEN, 913,
        )
        .unwrap();
        assert_eq!((materialized.processed, materialized.skipped), (1, 1));
        assert_eq!(materialized.taken, vec![crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundles[0]).unwrap()]);
    }

    /// A REAL, signed hypergraph `VertexAdd` (structurally-valid confidential
    /// field + a genuine Falcon write-key signature) MUTATES shard state: it
    /// materializes into the CRDT, and the committed `state_roots` (the 4
    /// phase-tree roots the frame header advertises) change, with the vertex-adds
    /// root becoming non-zero. This is the full write → materialize → state_roots
    /// chain — the root the global reward audit reconstructs and PoRep's per-epoch
    /// leaf re-registration re-encodes — now live for hypergraph shards.
    ///
    /// The vertex data uses the NEW commit-and-encrypt confidential scheme
    /// (`encrypted_to_vertex_tree`), NOT Go's legacy verenc — the Rust node's
    /// materialize (`HypergraphExecutionEngine::invoke_hypergraph_op`) already
    /// diverges from Go there; the fix that made this test go green was flushing
    /// the engine's `HypergraphState` changeset to the CRDT (`state.commit()` in
    /// the hypergraph engine's `process_message`), which previously never ran.
    #[test]
    fn app_shard_real_write_mutates_state_and_roots() {
        use quil_types::proto::hypergraph::VertexAdd;
        use quil_execution::hypergraph_intrinsic::confidential;
        use quil_execution::hypergraph_intrinsic::vertex_ops::{
            vertex_add_domain_separator, vertex_add_signing_message,
        };
        use quil_types::crypto::Signer as _;
        use std::sync::Arc;

        // The hypergraph engine verifies a VertexAdd's signature with real Falcon
        // (`falcon_verify`) against the domain's WRITE key — so use a real key +
        // a resolver that returns its public key. (The write key IS the auth we're
        // NOT stubbing; the KZG/inclusion prover is stubbed via NoopInclusionProver.)
        let signer = quil_crypto::FalconSigner::generate();
        struct KeyResolver(Vec<u8>);
        impl quil_execution::hypergraph_intrinsic::HypergraphConfigResolver for KeyResolver {
            fn write_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> {
                Some(self.0.clone())
            }
        }
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let mgr = quil_execution::ExecutionEngineManager::new(
            Arc::new(quil_types::crypto::NoopInclusionProver),
            Arc::new(crate::test_support::AcceptAllKeyManager),
            crdt.clone(),
            crypto.circuit_compiler.clone(),
            crypto.clock_store.clone(),
            Arc::new(KeyResolver(signer.public_key().to_vec())),
            false, // application mode
        );

        // The hypergraph BASE domain routes directly to the hypergraph engine
        // (no per-domain metadata-vertex deploy needed), so a VertexAdd here
        // materializes into the CRDT.
        let domain = quil_execution::hypergraph_intrinsic::hypergraph_base_domain().to_vec();

        // Committed shard root helper: the 4 phase-tree roots for `domain`'s shard.
        let shard_roots = |frame: u64| -> Vec<Vec<u8>> {
            let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&domain, 256, 3);
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(&domain);
            let sk = quil_types::store::ShardKey { l1, l2 };
            crdt.commit(frame).unwrap().get(&sk).cloned().unwrap_or_default()
        };

        // Baseline: empty shard. (NB: `crdt.commit` is dirty-based — it returns
        // only shards changed since the last commit and clears the dirty set — so
        // we must NOT commit before the write, or the write's commit comes back
        // empty. We commit exactly ONCE, after the write.)
        use num_traits::Zero as _;
        let size_before = crdt.total_size();
        assert!(size_before.is_zero(), "fresh shard must start empty");

        // A real VertexAdd carries commit-and-encrypt confidential fields. The
        // consensus check is STRUCTURAL (correct KEM/AEAD sizes), so a
        // well-formed field with placeholder bytes materializes — a genuine
        // vertex write into the CRDT, not a stub that only rides `requests_root`.
        let field = confidential::ConfidentialField {
            commitment: [7u8; 32],
            kem_ct: vec![0u8; confidential::KEM_CT_LEN],
            nonce: [0u8; confidential::NONCE_LEN],
            aead_ct: vec![0u8; confidential::SALT_LEN + confidential::TAG_LEN],
        };
        assert!(confidential::verify_structural(&field), "field must be structurally valid");
        let chunks: Vec<Vec<u8>> = vec![confidential::encode(&field)];
        let data =
            quil_execution::hypergraph_intrinsic::conversions::pack_vertex_add_proof_chunks(&chunks)
                .unwrap();
        let data_address = vec![0x22u8; 32];

        // Sign `separator || signing_message` over the SAME chunks with the write
        // key (mirrors `quil_client::vertex_write::build_vertex_add`).
        let separator = vertex_add_domain_separator(&domain).unwrap();
        let message = vertex_add_signing_message(&domain, &data_address, &chunks).unwrap();
        let mut signed = separator;
        signed.extend_from_slice(&message);
        let signature = signer.sign_with_domain(&signed, &[]).unwrap();

        let proto_vadd = VertexAdd {
            domain: domain.clone(),
            data_address,
            data,
            signature,
        };
        // Build the CANONICAL dispatch bundle directly — the wire form the shard
        // message collector holds and the execution engine decodes — and drive
        // `process_message` here so we can capture `state_roots` with a single
        // explicit `crdt.commit(1)` below. (The full production path
        // `materialize_app_shard_requests` — proto MessageBundle → proto→canonical
        // → process_message — also carries hypergraph ops now; the byte-exact
        // proto↔canonical round-trip is covered by
        // `consensus_wire::tests::hypergraph_vertex_add_survives_bundle_round_trip`.
        // We avoid it here only because its internal `commit_frame` would consume
        // the dirty set before we can read the committed roots.)
        let vadd_canon =
            quil_execution::hypergraph_intrinsic::types::VertexAdd::from_proto(&proto_vadd)
                .to_canonical_bytes()
                .unwrap();
        let bundle_bytes = quil_execution::message_envelope::CanonicalMessageBundle {
            requests: vec![Some(
                quil_execution::message_envelope::CanonicalMessageRequest::wrap(vadd_canon).unwrap(),
            )],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap();

        // 1. The op is ACCEPTED — it passes validation (structural proofs +
        //    real Falcon write-key signature verify). This is a genuinely valid
        //    write, not a stub.
        mgr.process_message(1, &num_bigint::BigInt::from(0), &domain, &bundle_bytes)
            .expect("a well-formed, signed VertexAdd must pass validation");

        // 2. The write MATERIALIZED into the CRDT: the vertex is present and the
        //    shard's live size grew.
        let mut app = [0u8; 32];
        app.copy_from_slice(&domain);
        let loc = quil_hypergraph::addressing::Location {
            app_address: app,
            data_address: [0x22u8; 32],
        };
        assert!(
            crdt.get_vertex_data(&loc).is_some(),
            "vertex must be present in the CRDT after materialize"
        );
        assert!(
            crdt.total_size() > size_before,
            "shard live size must grow after a real write"
        );

        // 3. The committed state_roots the frame header advertises reflect the
        //    write: the vertex-adds root (`state_roots[0]`) for this shard is
        //    non-zero. This is the real write → materialize → state_roots chain —
        //    the root the global reward audit reconstructs and PoRep's per-epoch
        //    leaf re-registration re-encodes.
        let roots_after = shard_roots(1);
        assert!(
            roots_after
                .first()
                .map(|r| r.iter().any(|b| *b != 0))
                .unwrap_or(false),
            "vertex-adds root (state_roots[0]) must be non-zero after a real write; got {roots_after:?}"
        );
    }

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

#[cfg(test)]
mod shard_path_tests {
    use super::shard_path_of_filter;
    use quil_types::execution::ShardPath;

    /// The executing shard comes from the frame's certified filter in every
    /// encoding a filter uses, and a filter that decodes as none of them is
    /// never mistaken for the whole application.
    #[test]
    fn a_filter_names_the_part_of_its_application_a_shard_holds() {
        let app = [0x11u8; 32];
        // A bare application address: the root shard, holding all of it.
        assert_eq!(shard_path_of_filter(&app), ShardPath::WHOLE);
        // The genesis 64-way grid: `app ‖ index`, six bits per level.
        let mut genesis = app.to_vec();
        genesis.push(0b101101);
        assert_eq!(
            shard_path_of_filter(&genesis).bits(),
            Some(vec![true, false, true, true, false, true])
        );
        // A deep split: `app ‖ bit length ‖ packed bits`, including one bit.
        for bits in [vec![true], vec![false, true, true, false, false, true, false, true, true]] {
            let filter = quil_forest::encode_shard_bit_path(&app, &bits);
            let shard = shard_path_of_filter(&filter);
            assert!(!shard.is_whole());
            assert_eq!(shard.bits(), Some(bits));
        }
        // Too short to name an application, or a malformed encoding.
        assert_eq!(shard_path_of_filter(&app[..31]), ShardPath::UNKNOWN);
        let mut malformed = quil_forest::encode_shard_bit_path(&app, &[true, false, true]);
        *malformed.last_mut().unwrap() |= 1; // a padding bit set
        assert_eq!(shard_path_of_filter(&malformed), ShardPath::UNKNOWN);
    }
}
