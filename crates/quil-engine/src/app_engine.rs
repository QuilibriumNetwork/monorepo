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
use tracing::{debug, info, warn};

use quil_consensus::models::{Identity, State, Unique};

use quil_types::consensus::{AppFrameValidator, ProverRegistry};
use quil_types::crypto::FrameProver;
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;

use crate::app_types::AppShardState;
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
    /// (P3 / commonware-simplex) A frame this shard's simplex engine FINALIZED
    /// (prost-encoded `AppShardFrame`). Routed from `AppSeamFinalizer::on_finalized`
    /// (which runs on the simplex engine thread) into the engine run loop so it
    /// materializes on the worker's `&mut self`. Trusted — simplex already
    /// certified it via quorum — so it SKIPS the BLS-quorum-signature check that
    /// `Frame` requires (a CW frame carries a Falcon certificate, not a BLS
    /// aggregate in the header). `cert` is the serialized simplex finalization
    /// certificate, attached to the reward-coverage bundle for global-level
    /// verification.
    CwFinalizedFrame { frame: Vec<u8>, cert: Vec<u8> },
    /// (P3) An inbound commonware-simplex message from a committee peer, demuxed
    /// from `shard_cw_bitmask` gossip. `channel` = CW channel id; `from` = the
    /// sender's committee Falcon public-key bytes (resolved by the master from
    /// the gossip sender); `data` = the CW message. Fed into the simplex engine
    /// via the `AppConsensusCwHandle` (channels 0/1/2 → `inbound[ch]`, 3 → block).
    CwIn {
        channel: u64,
        from: Vec<u8>,
        data: Vec<u8>,
    },
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
    /// A certified parent was sealed (state committed via materializer).
    ParentSealed {
        filter: Vec<u8>,
        parent_rank: u64,
    },
    /// (P3) An outbound commonware-simplex message for this shard's committee.
    /// `channel` is the CW channel id (0=vote,1=cert,2=resolver,3=block). The
    /// master publishes it on `shard_cw_bitmask` with the channel tagged in the
    /// payload (`shard_cw_frame_payload`); peers demux it back to this shard's
    /// engine `CwIn`. Emitted by the engine's `AppConsensusTransport`.
    CwOut {
        filter: Vec<u8>,
        channel: u64,
        bytes: Vec<u8>,
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

/// App shard leader provider. Collects messages and produces VDF-backed
/// shard frames when this node is the elected leader.
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
    /// Store to resolve the GLOBAL anchor (`anchor_gfn`/ρ_N) from — the
    /// master's clock_store on a worker; equals `clock_store` elsewhere. See
    /// `AppEngineDeps::global_anchor_store`.
    global_anchor_store: Arc<dyn ClockStore>,
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
    /// Storage-attestation SOURCE crdt = the MASTER's hypergraph (holds the
    /// covered shard's committed coin data, forest-synced). The prover REPLICATES
    /// from this into its OWN per-worker `replica_store` (`kv_db`) and attests
    /// those replicas — true per-prover PoRep possession. Distinct from
    /// `hypergraph` (the per-worker app-shard state). None → fall back to
    /// `hypergraph` (archive/tests, where a single crdt holds everything).
    storage_source_hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
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
        std::collections::HashMap<(u64, u64), Vec<quil_types::proto::global::MessageBundle>>,
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
    frame_attestations:
        Arc<std::sync::Mutex<std::collections::HashMap<(u64, u64), Vec<u8>>>>,
    /// Order-independent fingerprint of THIS CW instance's committee (the fixed
    /// simplex validator set built at `start_consensus_cw`). The finalization
    /// cert a proposed frame receives is signed by exactly this committee, but
    /// every verifier reconstructs the committee from the frame's stamped
    /// `global_frame_number`. If the active set moved since this instance was
    /// built (epoch boundary, deferred activation, empty-committee floor), the
    /// cert becomes unverifiable — so `prove_next_state` declines to propose
    /// until the run loop rebuilds the instance. See `AppConsensusEngine::committee_fp`.
    instance_committee_fp: [u8; 32],
}

/// Anchor to `latest − K`, not the bleeding-edge head: app-shard committees are
/// multi-member and each member's synced global head differs by a few frames, so
/// anchoring to a private latest would fork cross-member verification. `K` is a
/// small safety margin (≤ the lockstep window `W`) that keeps the anchor on a
/// frame all members already hold.
const GLOBAL_ANCHOR_SAFETY_MARGIN: u64 = 4;

/// Resolve the GLOBAL anchor `(frame_number, output)` an app shard binds to:
/// `latest_global − K`, present in every member's store. `(0, empty)` when the
/// global chain is shorter than the margin (genesis/tests → legacy VDF). The
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

impl AppLeaderProvider {
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
        // mainnet shard burns CPU on VDF compute every round forever
        // — exactly the wedge seen on workers 19/20 (sole proposer,
        // frame 5 staged at ranks 12 → 600+ without ever committing).
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
        if current_fp != self.instance_committee_fp {
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
                            && a.effective_status(anchor_gfn)
                                == quil_types::consensus::EffectiveStatus::Active
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
        // Build on the parent selected by Simplex, not whatever frame happens
        // to be the clock-store head when this callback runs. Simplex may enter
        // view V+1 as soon as V is certified, before V's finalization callback
        // has committed/materialized it locally. Re-reading the store in that
        // window used N-1 as the parent again and produced a second frame N.
        //
        // App-shard state roots are the materialized pre-state, so unlike the
        // global chain we deliberately wait until the selected parent is both
        // canonical and materialized. A NoVote only nullifies this view; once
        // the finalization callback catches up, the next view can safely build
        // N+1 from the exact parent bytes and identity.
        let materialized = self
            .shard_mat_frame
            .load(std::sync::atomic::Ordering::SeqCst);
        if materialized != prior_frame_number {
            return Err(QuilError::NoVote(format!(
                "cannot build on consensus parent {prior_frame_number}: local materialized \
                 frame is {materialized} — waiting for exact parent state",
            )));
        }

        let (previous_frame_output, previous_timestamp_ms) = if prior_frame_number == 0 {
            (Vec::new(), None)
        } else {
            let prior = self
                .clock_store
                .get_shard_clock_frame(&self.filter, prior_frame_number, false)
                .map_err(|e| {
                    QuilError::NoVote(format!(
                        "cannot build on consensus parent {prior_frame_number}: \
                         canonical frame unavailable ({e})",
                    ))
                })?;
            let header = prior.header.as_ref().ok_or_else(|| {
                QuilError::NoVote(format!(
                    "cannot build on consensus parent {prior_frame_number}: frame has no header",
                ))
            })?;
            let local_parent_id = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
                .map_err(|e| QuilError::Crypto(format!("app parent poseidon: {e}")))?
                .to_vec();
            if local_parent_id != *prior_state_id {
                return Err(QuilError::NoVote(format!(
                    "cannot build on consensus parent {prior_frame_number}: local identity {} \
                     differs from selected identity {} — waiting for exact parent",
                    hex::encode(local_parent_id),
                    hex::encode(prior_state_id),
                )));
            }
            (header.output.clone(), Some(header.timestamp))
        };
        let frame_number = prior_frame_number.checked_add(1).ok_or_else(|| {
            QuilError::NoVote("cannot produce app frame after u64::MAX parent".into())
        })?;

        // Collect pending messages (raw canonical bytes from the
        // dispatch bitmask), then decode each into a proto MessageBundle.
        // These bundles ARE the frame's `requests`: they get published in
        // the full AppShardFrame at finalization and materialized into
        // shard state. `requests_root` is computed below over their
        // canonical RE-encodings (not the raw collected bytes) so that an
        // archive can recompute it byte-for-byte from `frame.requests`.
        let raw_messages = self.message_collector.collect_for_rank(rank);
        let mut request_bundles: Vec<quil_types::proto::global::MessageBundle> =
            Vec::with_capacity(raw_messages.len());
        let mut canonical_requests: Vec<Vec<u8>> = Vec::with_capacity(raw_messages.len());
        for raw in &raw_messages {
            match crate::consensus_wire::decode_message_bundle(raw) {
                Ok(bundle) => {
                    match crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundle) {
                        Ok(canon) => {
                            canonical_requests.push(canon);
                            request_bundles.push(bundle);
                        }
                        Err(e) => debug!(error = %e, "dropping un-re-encodable request bundle"),
                    }
                }
                Err(e) => debug!(error = %e, "dropping undecodable dispatch message"),
            }
        }
        // Stash the bundles so the engine can retrieve them at
        // finalization (to self-materialize + publish the full frame).
        if let Ok(mut map) = self.frame_requests.lock() {
            map.insert((frame_number, rank), request_bundles);
            // Bound memory: keep only recent frames.
            let cutoff = frame_number.saturating_sub(64);
            map.retain(|&(fnum, _), _| fnum >= cutoff);
        }
        debug!(
            filter = hex::encode(&self.filter),
            frame = frame_number,
            rank,
            messages = canonical_requests.len(),
            "producing shard frame"
        );

        let difficulty = self.current_difficulty
            .load(std::sync::atomic::Ordering::Relaxed);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Compute fee multiplier vote: base from sliding window +
        // traffic adjustment.
        let previous_timestamp_ms = previous_timestamp_ms.unwrap_or(now_ms - 10_000);
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
        // DETERMINISTIC PRE-STATE ROOTS (audit #3+#6, consensus-rule change).
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
                    let r = hg.compute_shard_root(s, p, &shard_key);
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

        // Compute VDF proof (blocking). Including timestamp + fee in
        // the challenge ensures consecutive ranks within the same frame
        // produce distinct outputs and therefore distinct identities.
        // Go passes `getProverAddress()` = `poseidon(pubkey)` (32 bytes)
        // as the `prover` field in the frame header, NOT the raw G2
        // public key (585 bytes). Using the raw pubkey would produce
        // headers that other nodes can't match to the prover registry
        // (which is keyed by poseidon address).
        // `storage_attestation_root` is assembled out-of-band at QC time from
        // the committee's vote openings (set on the finalized frame), so the
        // produced header carries an empty root.
        let storage_attestation_root: Vec<u8> = Vec::new();
        // At/after the storage fork the app-shard VDF is omitted: anchor to the
        // global frame and replace `header.output` with the deterministic ρ_N-bound
        // output (freshness from ρ_N, lockstep with the global VDF). `anchor_gfn` /
        // `anchor_output` were resolved ONCE up top (`resolve_global_anchor`, =
        // `latest − K`) — the SAME value that gated the committee epoch above — so
        // this frame's committee, its stamped `global_frame_number`, and the
        // verifier's committee (read from that stamped number) are all consistent.
        // Storage attestation is always-on (no fork-height gate): a frame is a
        // storage frame iff it has a real global frame to anchor ρ_N to. The
        // only non-anchored case is genesis / tests with no global chain
        // (`anchor_gfn == 0`), which keep the legacy app-shard VDF.
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
        // The app output is now a compact deterministic digest rather than the
        // legacy 516-byte VDF output, so FrameProver cannot derive the parent
        // selector from `previous_frame_output[..516]`. Bind the wire header to
        // the exact Simplex parent identity directly. Preserve the all-zero
        // selector for the synthetic frame-0 floor.
        if prior_frame_number > 0 {
            header.parent_selector = prior_state_id.clone();
        }
        if storage_active {
            // PROPOSER SELF-ATTESTATION (CW PoRep port). Legacy Jolteon assembled
            // the committee `StorageAttestation` from every member's per-vote
            // openings at QC time. Simplex votes carry no payload, so under CW the
            // proposer attests its OWN storage: build this node's openings for the
            // shard, assemble a single-member attestation, and stamp the 74-byte
            // BLS48-581 G1 root onto the header. The serialized openings ride in a
            // side map (`frame_attestations`) the assembler attaches to the full
            // frame. NOTE: single-member — other committee members are NOT proven
            // to store; see CUTOVER §7. Best-effort: any failure leaves the root
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
                if opening_blob.is_empty() {
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
                        let openings =
                            crate::app_shard_metadata::decode_vote_openings(&blob);
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
                                    (frame_number, rank),
                                    prost::Message::encode_to_vec(&att),
                                );
                            }
                        }
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
        );

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
            header.storage_attestation_root.clone(),
            header.global_frame_number,
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

/// (P3) App-shard CW transport: emits each outbound simplex message as an
/// `AppEngineEvent::CwOut` on the engine's event channel. The master publishes
/// it on `shard_cw_bitmask` gossip (or the in-memory harness routes it to peers).
/// `deliver` runs on the simplex thread → a plain channel send (no runtime
/// needed). Recipients are dropped: the master fans out to the whole shard
/// committee via gossip, a safe superset. For a single-prover shard nothing is
/// delivered anywhere (simplex handles its own messages internally).
struct EngineCwTransport {
    filter: Vec<u8>,
    event_tx: mpsc::UnboundedSender<AppEngineEvent>,
}
impl crate::cw_app_seams::AppConsensusTransport for EngineCwTransport {
    fn deliver(
        &self,
        channel: u64,
        _recipients: Vec<quil_cw_consensus::falcon_base::FalconPublicKey>,
        bytes: Vec<u8>,
    ) {
        let _ = self.event_tx.send(AppEngineEvent::CwOut {
            filter: self.filter.clone(),
            channel,
            bytes,
        });
    }
}

/// Dependencies required to construct an AppConsensusEngine.
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
    /// silently degrades to the legacy app-shard VDF path, and earns no rewards.
    pub global_anchor_store: Option<Arc<dyn ClockStore>>,
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
    /// Storage-attestation SOURCE crdt = the MASTER's hypergraph (covered shard's
    /// committed coin data). On a thread-worker this differs from `hypergraph`
    /// (per-worker state); the prover replicates FROM here into its own
    /// `replica_store`. None → fall back to `hypergraph`. See `AppLeaderProvider`.
    pub storage_source_hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
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
    /// (P3) When true, drive this shard's consensus with commonware-simplex +
    /// Falcon (EQUAL VOTES) instead of the legacy quil-consensus HotStuff loop.
    /// Off by default → legacy path unchanged.
    pub app_consensus_cw: bool,
    /// DB config used to derive the PERSISTENT per-shard simplex-journal
    /// directory (Go parity: `app_consensus_engine.go:718` — core 0 →
    /// `db.path`, worker core N → `worker_paths[N-1]` / `worker_path_prefix`).
    /// An empty resolved path ⇒ ephemeral journal (tests). Default is fine for
    /// callers that don't persist app-shard consensus.
    pub db_config: quil_config::DbConfig,
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

/// Discard a stale persistent simplex journal when the committee changed.
///
/// commonware's journal records THIS node's own votes by their participant
/// INDEX (position in the committee) and, on replay, asserts every journaled
/// vote is our own (`is_signer`) — it PANICS otherwise ("replaying notarize
/// from another signer", `voter/round.rs:569`). That assumes a STATIC validator
/// set. App-shard committees are DYNAMIC — as provers join/leave the shard the
/// participant set (and hence our index) shifts — so a journal written under one
/// committee is invalid under a changed one and would crash the node on restart.
///
/// Guard: fingerprint the committee (SHA-256 over the ordered peer keys — the
/// exact order commonware assigns indices from) and compare it to the
/// fingerprint the journal was written for (kept in a SIBLING file so wiping the
/// journal dir preserves it). On a mismatch, delete the stale journal so
/// consensus restarts cleanly from its genesis floor instead of panicking. On a
/// match, keep it (a genuine crash-recovery resume, the whole point of
/// persistence). Global consensus uses a fixed genesis-archive committee, so it
/// never trips this; only app-shard journals need the guard.
/// Discard a stale persistent CW simplex journal when the `fingerprint` it was
/// written for no longer matches. The fingerprint MUST fold in everything that,
/// if changed, makes the journal's stored state unusable on replay:
///  - the **committee** (participant set + order → vote indices; a change trips
///    commonware's "replaying notarize from another signer" panic);
///  - the **re-seed point** (genesis identity — the frame the engine floors at).
///    The journal is persistent but `block_meta` (digest→frame-number) is NOT,
///    so on restart the journal can restore the engine to a parent whose digest
///    the freshly-seeded `block_meta` can't resolve — the proposer then
///    nullifies because it cannot prove the selected parent's height, causing a
///    total production halt. This happens whenever the committed head MOVES
///    between runs (the
///    fresh genesis differs from the journal's floor). Resetting re-floors
///    consensus at the current committed head, consistent with `block_meta`.
///
/// The fingerprint is kept in a SIBLING file so wiping the journal dir preserves
/// it. On a match the journal is a valid crash-recovery resume and is kept.
pub fn reset_stale_cw_journal(journal_dir: &std::path::Path, fingerprint: &[u8]) {
    let fp_path = journal_dir.with_extension("cw-fp");
    if std::fs::read(&fp_path).ok().as_deref() == Some(fingerprint) {
        return; // same committee + re-seed → resume the journal
    }
    if journal_dir.exists() {
        warn!(
            dir = %journal_dir.display(),
            "CW committee or re-seed point changed since last run — discarding \
             stale simplex journal (replaying it would panic or stall production)"
        );
        let _ = std::fs::remove_dir_all(journal_dir);
    }
    if let Some(parent) = fp_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&fp_path, fingerprint);
}

/// App-shard journal guard: fingerprint = committee (ordered peer keys) ONLY.
///
/// This resets the journal ONLY when the COMMITTEE changes (participant set /
/// order → vote indices), which is the case that trips commonware's "replaying
/// notarize from another signer" panic. It deliberately does NOT fold in the
/// re-seed head: a moved head is NORMAL (consensus finalizes ahead of
/// materialization), and resetting on it would DISCARD finalized-but-
/// unmaterialized progress and re-floor consensus at the materialized head. The
/// restart/block_meta case is handled by resolving the parent from the
/// BlockStore/candidate store, not by deleting the journal.
fn reset_stale_app_journal(
    journal_dir: &std::path::Path,
    peers: &[quil_cw_consensus::falcon_base::FalconPublicKey],
) {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for pk in peers {
        h.update(pk.as_ref());
    }
    let fp: [u8; 32] = h.finalize().into();
    reset_stale_cw_journal(journal_dir, &fp);
}

/// App shard consensus engine. Owns a HotStuff event loop and
/// processes messages for a single shard identified by `filter`.
pub struct AppConsensusEngine {
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
    /// Highest shard frame number whose requests have been materialized
    /// into the hypergraph. Idempotency gate so a frame is never
    /// materialized twice (mirrors Go `lastMaterializedFrame`,
    /// app_consensus_engine.go:1444-1449).
    last_materialized_frame: u64,
    /// Thread-safe mirror of `last_materialized_frame` for the CW proposal
    /// check, which runs on the simplex thread (audit #3). Bumped alongside the
    /// field via [`Self::set_materialized_frame`] wherever the materialized
    /// shard state advances. Only ever raised AFTER the state is committed, so
    /// it never OVER-reports. The `state_roots` pre-state gate is now FAIL-CLOSED:
    /// a voter not exactly at N-1 nullifies (cannot validate the declared
    /// pre-state) rather than signing blind — closing the frame-number-jump
    /// bypass of audit #3. A lagging voter catches up via shard sync, then votes.
    shard_mat_frame: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Shared with the leader provider: requests this node collected for
    /// frames it proposed (proto `MessageBundle`s), keyed by frame
    /// number and Simplex view/rank. Read at finalization to self-materialize
    /// and assemble the full `AppShardFrame` for publication.
    frame_requests: Arc<std::sync::Mutex<
        std::collections::HashMap<(u64, u64), Vec<quil_types::proto::global::MessageBundle>>,
    >>,
    /// Shared with the leader provider (mirrors `frame_requests`): the serialized
    /// proposer self storage-attestation (`StorageAttestation` openings) for each
    /// frame this node proposed. The `AppFrameAssembler` reads it to attach the
    /// openings to the full `AppShardFrame`. See `AppLeaderProvider::frame_attestations`.
    frame_attestations:
        Arc<std::sync::Mutex<std::collections::HashMap<(u64, u64), Vec<u8>>>>,
    /// `requests_root` of frames this node FINALIZED through (BLS-verified)
    /// consensus, keyed by frame number. The trust anchor for materializing
    /// a full frame received on the wire as a follower: the received
    /// frame's recomputed `requests_root` must equal the one we finalized.
    finalized_requests_roots: HashMap<u64, Vec<u8>>,
    /// Full `AppShardFrame`s received on `shard_frame_bitmask`, buffered
    /// by frame number until they can be materialized in order.
    received_full_frames: HashMap<u64, quil_types::proto::global::AppShardFrame>,
    /// Consecutive `commit_frame` failure counts per frame number, so a
    /// frame that can't be materialized is dropped + repaired via sync
    /// rather than retried-from-zero forever. Cleared on success.
    materialize_failures: HashMap<u64, u32>,

    // Channels
    cancel: CancellationToken,
    msg_rx: Option<mpsc::Receiver<AppEngineMessage>>,
    event_tx: mpsc::UnboundedSender<AppEngineEvent>,

    // Frame (VDF + BLS) validator for this shard. Used by the inbound
    // proposal gate and the follower full-frame path before
    // materialization.
    app_frame_validator: Option<Arc<BlsAppFrameValidator>>,

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
    /// (P3) Drive this shard with commonware-simplex + Falcon instead of legacy.
    app_consensus_cw: bool,
    /// (P3) Handle to the running simplex engine (kept alive; the outbound drain
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
    /// Lossless, ordered handoff from the dedicated Simplex runtime thread to
    /// this engine's finalization handler. Finalizations are safety-critical and
    /// must not compete for capacity with the best-effort inbound message queue.
    cw_finalized_tx: mpsc::UnboundedSender<(Vec<u8>, Vec<u8>)>,
    cw_finalized_rx: Option<mpsc::UnboundedReceiver<(Vec<u8>, Vec<u8>)>>,

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
        let (cw_finalized_tx, cw_finalized_rx) = mpsc::unbounded_channel();

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

        let sizes = SharedAppEngineSizes::new();
        let handle = AppEngineHandle {
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
            prover_registry: deps.prover_registry,
            frame_prover: deps.frame_prover,
            message_collector: deps.message_collector,
            fee_manager: deps.fee_manager,
            reward_greedy: deps.reward_greedy,
            min_active_provers_for_propose: deps.min_active_provers_for_propose,
            hypergraph: deps.hypergraph,
            storage_source_hypergraph: deps.storage_source_hypergraph,
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
            last_materialized_frame: 0,
            shard_mat_frame: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            frame_requests: Arc::new(std::sync::Mutex::new(HashMap::new())),
            frame_attestations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            finalized_requests_roots: HashMap::new(),
            received_full_frames: HashMap::new(),
            materialize_failures: HashMap::new(),
            cancel: CancellationToken::new(),
            msg_rx: Some(msg_rx),
            event_tx,
            app_frame_validator: None,
            local_prover_address: deps.local_prover_address,
            local_bls_pubkey: deps.local_bls_pubkey,
            halted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            coverage_publish: deps.coverage_publish,
            kv_db: deps.kv_db,
            app_consensus_cw: deps.app_consensus_cw,
            cw_handle: None,
            cw_committee_fp: None,
            cw_finalized_tx,
            cw_finalized_rx: Some(cw_finalized_rx),
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

    /// Read the durable per-shard materialized-frame cursor (8-byte BE
    /// `u64`), or 0 if absent/unreadable. Initialized into
    /// `last_materialized_frame` at startup so the in-memory idempotency
    /// gate survives restart instead of resetting to 0.
    fn load_materialized_cursor(&self) -> u64 {
        self.kv_db
            .as_ref()
            .and_then(|kv| {
                kv.get(&quil_store::encoding::consensus_materialized_cursor_key(&self.filter))
                    .ok()
                    .flatten()
            })
            .filter(|v| v.len() == 8)
            .map(|v| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v[..8]);
                u64::from_be_bytes(b)
            })
            .unwrap_or(0)
    }

    /// Persist the durable per-shard materialized-frame cursor. MUST be
    /// called only AFTER the frame's `commit_frame` succeeded, so the
    /// stored cursor never claims a height the CRDT hasn't reached. The
    /// safe failure direction is cursor < CRDT height (a redundant
    /// re-materialize on restart, which the CRDT's set semantics +
    /// spent-markers make idempotent), never cursor > CRDT height (which
    /// would silently skip a frame's mutations).
    fn persist_materialized_cursor(&self, frame: u64) {
        if let Some(kv) = self.kv_db.as_ref() {
            if let Err(e) = kv.set(
                &quil_store::encoding::consensus_materialized_cursor_key(&self.filter),
                &frame.to_be_bytes(),
            ) {
                warn!(
                    core_id = self.core_id,
                    frame,
                    error = %e,
                    "failed to persist materialized cursor"
                );
            }
        }
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
        world_size: u64,
        fee_multiplier_vote: u64,
    ) -> Result<(usize, usize)> {
        let exec = match self.execution_engine.clone() {
            Some(e) => e,
            None => return Ok((0, 0)),
        };
        let app_address = self.app_address.clone();
        tokio::task::spawn_blocking(move || {
            materialize_app_shard_requests(
                exec.as_ref(),
                &requests,
                frame_number,
                difficulty,
                world_size,
                fee_multiplier_vote,
                &app_address,
            )
        })
        .await
        .map_err(|e| QuilError::Internal(format!("materialize task panicked: {e}")))?
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
    /// directly so `shard_mat_frame` stays consistent (audit #3).
    fn set_materialized_frame(&mut self, n: u64) {
        self.last_materialized_frame = n;
        self.shard_mat_frame
            .store(n, std::sync::atomic::Ordering::Relaxed);
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
    ) {
        let Some(header) = frame.header.as_ref() else {
            return;
        };
        let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
            .map(|h| h.to_vec())
            .unwrap_or_default();
        if let Ok(txn) = self.clock_store.new_transaction(false) {
            if let Err(e) =
                self.clock_store
                    .stage_shard_clock_frame(&selector, frame, txn.as_ref())
            {
                warn!(core_id = self.core_id, frame = frame_number, error = %e, "stage shard clock head failed");
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
                warn!(core_id = self.core_id, frame = frame_number, error = %e, "commit shard clock head failed");
            } else {
                let _ = txn.commit();
            }
        }
    }

    async fn reconcile_with_sync(&mut self, synced_to_frame: u64) {
        if synced_to_frame <= self.last_materialized_frame {
            return;
        }
        debug!(
            core_id = self.core_id,
            from = self.last_materialized_frame,
            to = synced_to_frame,
            "fast-forwarding materialized cursor from shard sync"
        );
        self.set_materialized_frame(synced_to_frame);
        self.persist_materialized_cursor(synced_to_frame);
        // Anything at/below the synced height is now covered by the
        // synced tree; drop stale buffers so they can't be re-applied.
        self.received_full_frames
            .retain(|&f, _| f > synced_to_frame);
        self.finalized_requests_roots
            .retain(|&f, _| f > synced_to_frame);
        // Continue materializing any contiguous frames we still hold.
        self.try_materialize_follower_frames().await;
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
        // A FACTORY (not a single signer) so the passive-mode retry below can
        // obtain a fresh signer: the committee may not be buildable on the first
        // attempt (a cluster worker's registry is still syncing), and
        // `start_consensus_cw` consumes the signer, so a retry needs another.
        bls_signer_factory: std::sync::Arc<
            dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync,
        >,
    ) {
        let mut msg_rx = self.msg_rx.take().expect("msg_rx already taken");
        let mut cw_finalized_rx = self
            .cw_finalized_rx
            .take()
            .expect("cw_finalized_rx already taken");

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
        let restored_cursor = self.load_materialized_cursor();
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

        // Start the shard consensus driver: commonware-simplex (P3) + Falcon.
        match self.start_consensus_cw((bls_signer_factory)()) {
            Ok(handle) => {
                self.cw_handle = Some(handle);
                info!(
                    core_id = self.core_id,
                    filter = hex::encode(&self.filter),
                    "shard commonware-simplex consensus running (EQUAL VOTES)"
                );
            }
            Err(e) => {
                warn!(
                    core_id = self.core_id,
                    error = %e,
                    "failed to start shard simplex consensus — will retry (passive until committee is present)"
                );
            }
        }

        // Frame cleanup timer — remove stale cached frames every 60s
        let mut cleanup_timer = tokio::time::interval(Duration::from_secs(60));
        cleanup_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Passive-mode retry timer: if the committee wasn't buildable on the first
        // attempt (cluster worker's registry still syncing / provers not yet
        // Active), retry until it starts. Cheap no-op once running.
        let mut cw_retry_timer = tokio::time::interval(Duration::from_secs(10));
        cw_retry_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                finalized = cw_finalized_rx.recv() => {
                    if let Some((frame, cert)) = finalized {
                        self.handle_cw_finalized_frame(&frame, &cert).await;
                    }
                }

                // Inbound network messages
                msg = msg_rx.recv() => {
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
                        Some(AppEngineMessage::ShardSyncCompleted { synced_to_frame }) => {
                            self.reconcile_with_sync(synced_to_frame).await;
                        }
                        Some(AppEngineMessage::CwFinalizedFrame { frame, cert }) => {
                            self.handle_cw_finalized_frame(&frame, &cert).await;
                        }
                        Some(AppEngineMessage::CwIn { channel, from, data }) => {
                            if let Some(h) = self.cw_handle.as_ref() {
                                if channel == crate::cw_app_seams::CW_APP_BLOCK_CHANNEL {
                                    // Authorize the block channel like channels 0/1/2
                                    // (audit residual #1): require the sender key to
                                    // resolve (the master resolves it from committee
                                    // membership) before storing. Previously channel 3
                                    // ingested any bytes, ignoring `from` — letting an
                                    // unresolved peer feed/overwrite the block store
                                    // (the block is still verified at `verify`, so this
                                    // is authorization/DoS hardening, not a safety hole).
                                    if quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(&from).is_some() {
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

                // Passive-mode CW retry: keep trying to start simplex until the
                // committee is buildable (the shard's active provers are present
                // in this node's registry). No-op once running.
                _ = cw_retry_timer.tick() => {
                    if self.cw_handle.is_none() {
                        // Passive-mode retry: keep trying until the committee is
                        // buildable (active provers present in this registry).
                        match self.start_consensus_cw((bls_signer_factory)()) {
                            Ok(handle) => {
                                self.cw_handle = Some(handle);
                                info!(
                                    core_id = self.core_id,
                                    filter = hex::encode(&self.filter),
                                    "shard commonware-simplex consensus started on retry (EQUAL VOTES)"
                                );
                            }
                            Err(e) => {
                                debug!(
                                    core_id = self.core_id,
                                    error = %e,
                                    "cw retry: committee not yet buildable"
                                );
                            }
                        }
                    } else {
                        // DYNAMIC COMMITTEE: if the shard's active-prover set
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
                                old.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            match self.start_consensus_cw((bls_signer_factory)()) {
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
            self.publish_sizes();
        }
    }

    /// Stop the engine.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    // ---------------------------------------------------------------
    // Consensus event loop startup
    // ---------------------------------------------------------------

    /// (P3) Start commonware-simplex + Falcon consensus for this shard, reusing
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

    fn start_consensus_cw(
        &mut self,
        bls_signer: Box<dyn quil_types::crypto::Signer>,
    ) -> Result<crate::cw_app_seams::AppConsensusCwHandle> {
        let filter = self.filter.clone();
        let app_address = self.app_address.clone();

        // Genesis anchor = the latest finalized shard frame's output/number (or
        // zero on a fresh shard). All committee members compute the same digest.
        let (genesis_output, genesis_frame_number) = self
            .clock_store
            .get_latest_shard_clock_frame(&filter)
            .ok()
            .and_then(|f| f.header.as_ref().map(|h| (h.output.clone(), h.frame_number)))
            .unwrap_or_else(|| (vec![0u8; 32], 0));
        let genesis_id = quil_crypto::poseidon::hash_bytes_to_32(&genesis_output)
            .map_err(|e| QuilError::Crypto(format!("app genesis poseidon: {e}")))?;
        let genesis_digest = quil_cw_consensus::adapters::digest_from_identity(genesis_id);

        // Committee = active provers' Falcon public keys (count-based, no
        // seniority), evaluated at the GLOBAL anchor epoch — the SAME frame the
        // leader provider (`committee_anchor_gfn`) and produced/verified frames
        // use. Reading it at the app-shard `genesis_frame_number` (unrelated to
        // global) would seed the simplex `peers` set from the wrong epoch, out of
        // step with the leader schedule. Falls back to the shard anchor pre-fork
        // (global chain absent → both are epoch 0).
        let member_pubkeys = self.compute_committee_members();
        // Record the committee fingerprint so the run loop can detect a
        // membership change and rebuild (dynamic committee).
        self.cw_committee_fp = Some(Self::committee_fp(&member_pubkeys));
        let my_sk = bls_signer.private_key().to_vec();
        let my_pk = bls_signer.public_key().to_vec();
        let (scheme, peers) =
            crate::cw_app_seams::build_app_committee(&member_pubkeys, &my_sk, &my_pk, &app_address)
                .ok_or_else(|| {
                    QuilError::Consensus(
                        "app CW committee build failed (this node's key not in the active set?)"
                            .into(),
                    )
                })?;

        // Leader provider — identical construction to the legacy path.
        let leader_provider: Arc<
            dyn quil_consensus::leader_provider::LeaderProvider<AppShardState>,
        > = Arc::new(AppLeaderProvider {
            filter: filter.clone(),
            clock_store: self.clock_store.clone(),
            global_anchor_store: self.global_anchor_store.clone(),
            frame_prover: self.frame_prover.clone(),
            prover_registry: self.prover_registry.clone(),
            message_collector: self.message_collector.clone(),
            fee_manager: self.fee_manager.clone(),
            local_prover_address: self.local_prover_address.clone(),
            local_public_key: self.local_bls_pubkey.clone(),
            current_difficulty: self.current_difficulty.clone(),
            reward_greedy: self.reward_greedy,
            hypergraph: self.hypergraph.clone(),
            storage_source_hypergraph: self.storage_source_hypergraph.clone(),
            execution_engine: self.execution_engine.clone(),
            inclusion_prover: self.inclusion_prover.clone(),
            app_address: app_address.clone(),
            halted: self.halted.clone(),
            min_active_provers_for_propose: self.min_active_provers_for_propose,
            shard_mat_frame: self.shard_mat_frame.clone(),
            frame_requests: self.frame_requests.clone(),
            kv_db: self.kv_db.clone(),
            frame_attestations: self.frame_attestations.clone(),
            // Pin the committee this instance signs with, so the leader can
            // refuse to propose frames whose verifier-reconstructed committee
            // would no longer match (epoch-straddle guard).
            instance_committee_fp: Self::committee_fp(&member_pubkeys),
        });

        // `.with_clock_store` is REQUIRED for storage-active frames: the validator
        // recomputes the deterministic ρ_N-bound output from the anchored global
        // frame's VDF output (resolved from our own clock store, never the wire).
        // Without it, verifying any storage frame fails "anchored global frame
        // unavailable for ρ_N" and the CW round never finalizes.
        let validator = Arc::new(
            BlsAppFrameValidator::new(
                self.prover_registry.clone(),
                Arc::new(quil_crypto::FalconKeyConstructor),
                self.frame_prover.clone(),
            )
            // Anchor store: the validator recomputes ρ_N from the anchored
            // GLOBAL frame, which on a worker lives only in the master's store.
            .with_clock_store(self.global_anchor_store.clone()),
        );
        // The follower frame path (`handle_frame_message`) runs this same
        // VDF + BLS validator before materializing received full frames.
        self.app_frame_validator = Some(validator.clone());

        // Assembler: read the leader's recorded request bundles for the produced
        // frame (`frame_requests` is a shared `Arc<Mutex>`) + build the full frame.
        let assemble: crate::cw_app_seams::AppFrameAssembler = {
            let frame_requests = self.frame_requests.clone();
            let frame_attestations = self.frame_attestations.clone();
            Arc::new(move |state| {
                let fnum = state.state.frame_number;
                let key = (fnum, state.state.rank);
                let reqs = frame_requests
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&key).cloned())
                    .unwrap_or_default();
                let attestation = frame_attestations
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&key).cloned())
                    .unwrap_or_default();
                Some(crate::cw_app_seams::app_frame_from_state(state, reqs, attestation))
            })
        };

        // on_finalized: route the finalized frame back into THIS engine's run
        // loop over a dedicated unbounded channel. A bounded `try_send` here can
        // drop the certified parent while Simplex advances to its child, leaving
        // the worker permanently unable to materialize the selected parent.
        let on_finalized: crate::cw_app_seams::AppFinalizedSink = {
            let finalized_tx = self.cw_finalized_tx.clone();
            Arc::new(move |frame, cert| {
                let mut buf = Vec::new();
                if prost::Message::encode(&frame, &mut buf).is_ok() {
                    let _ = finalized_tx.send((buf, cert));
                }
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
        // Before commonware opens the journal, discard it if this shard's
        // committee changed since it was written (else replay panics with
        // "replaying notarize from another signer"). See `reset_stale_app_journal`.
        if let Some(dir) = cw_app_storage_dir.as_ref() {
            reset_stale_app_journal(dir, &peers);
        }
        // Body-root cross-check for the CW verify path (audit Finding #2). The
        // lightweight seam validator can't recompute the body root (no exec /
        // inclusion prover), so build a closure over THIS engine's deps that
        // recomputes `requests_root` from the carried `frame.requests` and
        // compares it to the declared root — exactly as the follower/archive
        // ingest paths do. An honest member then never signs a proposal whose
        // body doesn't match its (about-to-be-certified) root, so conflicting
        // bodies under one digest can't diverge replica state. `None` when the
        // engine has no exec/inclusion/hypergraph (tests) → check skipped.
        let requests_root_check: Option<crate::cw_app_seams::AppRequestsRootCheck> =
            match (
                self.execution_engine.clone(),
                self.inclusion_prover.clone(),
                self.hypergraph.clone(),
            ) {
                (Some(exec), Some(incl), Some(hg)) => {
                    let app_addr = self.app_address.clone();
                    let shard_mat = self.shard_mat_frame.clone();
                    // Shard key derived from the filter, same as the leader's
                    // `state_roots` construction (single derivation, captured).
                    let shard_key = {
                        let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(
                            &self.filter[..self.filter.len().min(32)],
                            256,
                            3,
                        );
                        let mut l2 = [0u8; 32];
                        let copy_len = self.filter.len().min(32);
                        l2[..copy_len].copy_from_slice(&self.filter[..copy_len]);
                        quil_types::store::ShardKey { l1, l2 }
                    };
                    Some(Arc::new(
                        move |frame: &quil_types::proto::global::AppShardFrame| -> bool {
                            let Some(header) = frame.header.as_ref() else {
                                return false;
                            };
                            // (a) Body-root check (audit #2) — always.
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
                            // (b) Pre-state `state_roots` check (audit #3, +#3-bypass
                            // fix). FAIL-CLOSED: a voter must be EXACTLY at N-1 to
                            // validate the declared pre-state via the deterministic
                            // `compute_shard_root`. Previously a voter not at N-1
                            // (lagging, OR a leader that JUMPED `frame_number` so the
                            // gate went false on every honest voter) fell through and
                            // SIGNED unvalidatable roots — the audit-#3 bypass. Now it
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
                                    let mut local = hg.compute_shard_root(s, p, &shard_key);
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
                                        return false;
                                    }
                                }
                            }
                            true
                        },
                    ) as crate::cw_app_seams::AppRequestsRootCheck)
                }
                _ => None,
            };
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
            0, // epoch (genesis committee generation)
            genesis_digest,
            genesis_frame_number,
            30, // leader_timeout_secs (localnet default; app VDF ~ shard difficulty)
            transport,
            cw_app_storage_dir,
            requests_root_check,
        );
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
    /// Materialize a simplex-FINALIZED app frame (P3). The frame is already
    /// certified by the CW committee quorum, so — unlike [`handle_frame_message`]
    /// — this does NOT run the BLS-aggregate-signature gate (a CW frame carries a
    /// Falcon certificate, not a BLS aggregate in its header). Mirrors the
    /// self-materialize half of [`distribute_and_materialize_own_frame`]: apply
    /// the requests, advance + persist the durable cursor, and publish the full
    /// frame for followers/archives on `shard_frame_bitmask`.
    async fn handle_cw_finalized_frame(&mut self, data: &[u8], cert: &[u8]) {
        let mut frame: quil_types::proto::global::AppShardFrame = match prost::Message::decode(data) {
            Ok(f) => f,
            Err(e) => {
                warn!(core_id = self.core_id, error = %e, "cw finalized frame: undecodable");
                return;
            }
        };
        // SECURITY — post-verification substitution defense (audit Finding #1).
        // These finalized `data` bytes are a FRESH read of the mutable
        // `BlockStore` (the reporter re-reads by digest at finalize), so they
        // can differ from the bytes the committee actually verified at proposal
        // time: the store is last-writer-wins and the block channel (3) has no
        // committee admission. A substitution keeps the certified
        // `Poseidon(output)` digest (so the finalization cert still verifies)
        // while changing every other header field and the body. Re-run PROPOSAL
        // validation here before anything touches the clock store or
        // materializer: it RECOMPUTES the deterministic output from the declared
        // fields (parent_selector, requests_root, state_roots, ρ_N, frame_number,
        // rank, prover) and rejects any frame whose fields don't reproduce
        // `header.output`. Honest frames (same bytes as verified) pass; a
        // substituted/internally-inconsistent header is dropped. (Validate the
        // PRISTINE frame, before the cert is attached below.)
        if let Some(v) = self.app_frame_validator.as_ref() {
            match validate_app_frame_panic_safe(v, &frame, /* proposal */ true) {
                Ok(true) => {}
                other => {
                    warn!(
                        core_id = self.core_id,
                        result = ?other,
                        "cw finalized frame: failed re-validation (post-verification \
                         substitution or inconsistent header) — dropping",
                    );
                    return;
                }
            }
        }
        // SECURITY — body-root cross-check (audit Finding #2, and the body-swap
        // case of #1). The re-validation above binds the DECLARED `requests_root`
        // through output recomputation, but not the carried body; a finalize-time
        // BlockStore overwrite can keep the whole header (hence the certified
        // digest) while swapping `frame.requests`. Recompute the body root from
        // the carried requests and DROP on mismatch, so no CW replica ever
        // materializes a body its certified root does not cover. (Dropping a
        // substituted body stalls at worst — recoverable via catch-up — whereas
        // materializing it would be an unrecoverable state divergence.)
        if let (Some(exec), Some(header)) =
            (self.execution_engine.as_ref(), frame.header.as_ref())
        {
            let canonical: Vec<Vec<u8>> = frame
                .requests
                .iter()
                .filter_map(|b| {
                    crate::consensus_wire::proto_message_bundle_to_canonical_bytes(b).ok()
                })
                .collect();
            let use_forest = self
                .hypergraph
                .as_ref()
                .map(|h| h.has_forest())
                .unwrap_or(false);
            let ok = canonical.len() == frame.requests.len()
                && compute_requests_root(
                    &canonical,
                    &self.app_address,
                    header.frame_number,
                    Some(exec.as_ref()),
                    self.inclusion_prover.as_deref(),
                    use_forest,
                )
                .map(|r| r == header.requests_root)
                .unwrap_or(false);
            if !ok {
                warn!(
                    core_id = self.core_id,
                    frame = header.frame_number,
                    "cw finalized frame: requests_root mismatch (carried body does not \
                     match the certified root) — dropping (post-verification body swap)",
                );
                return;
            }
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

        // Finalization callbacks must be monotonic at the application boundary,
        // even if the consensus host replays a callback or ever hands us a
        // conflicting certified block at an already-committed height. The old
        // path overwrote the canonical `(filter, frame_number)` value, skipped
        // materialization via the cursor check, and still republished + awarded
        // coverage. Never replace an existing height with a different identity.
        // An identical replay may retry materialization after a prior transient
        // failure, but it is not published or rewarded a second time.
        let already_committed = match self.clock_store.get_latest_shard_clock_frame(&self.filter) {
            Ok(latest) => {
                let Some(latest_header) = latest.header.as_ref() else {
                    warn!(core_id = self.core_id, "cw finalized frame: canonical head has no header");
                    return;
                };
                if frame_number < latest_header.frame_number {
                    warn!(
                        core_id = self.core_id,
                        frame = frame_number,
                        canonical = latest_header.frame_number,
                        "cw finalized frame: stale finalization below canonical head — dropping",
                    );
                    return;
                }
                if frame_number == latest_header.frame_number {
                    if latest_header.output != header.output {
                        warn!(
                            core_id = self.core_id,
                            frame = frame_number,
                            "cw finalized frame: conflicting identity at canonical height — dropping",
                        );
                        return;
                    }
                    true
                } else {
                    let Some(expected_frame_number) =
                        latest_header.frame_number.checked_add(1)
                    else {
                        warn!(core_id = self.core_id, "cw finalized frame: canonical height overflow");
                        return;
                    };
                    if frame_number != expected_frame_number {
                        warn!(
                            core_id = self.core_id,
                            frame = frame_number,
                            expected = expected_frame_number,
                            "cw finalized frame: gap above canonical head — dropping",
                        );
                        return;
                    }
                    let expected_parent = if latest_header.frame_number == 0 {
                        vec![0u8; 32]
                    } else {
                        match quil_crypto::poseidon::hash_bytes_to_32(&latest_header.output) {
                            Ok(id) => id.to_vec(),
                            Err(e) => {
                                warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw finalized frame: canonical parent identity failed");
                                return;
                            }
                        }
                    };
                    if header.parent_selector != expected_parent {
                        warn!(
                            core_id = self.core_id,
                            frame = frame_number,
                            "cw finalized frame: parent selector does not extend canonical head — dropping",
                        );
                        return;
                    }
                    false
                }
            }
            Err(QuilError::NotFound(_)) => {
                if frame_number != 1 || header.parent_selector != vec![0u8; 32] {
                    warn!(
                        core_id = self.core_id,
                        frame = frame_number,
                        "cw finalized frame: non-genesis child without canonical parent — dropping",
                    );
                    return;
                }
                false
            }
            Err(e) => {
                warn!(
                    core_id = self.core_id,
                    frame = frame_number,
                    error = %e,
                    "cw finalized frame: cannot read canonical head — dropping",
                );
                return;
            }
        };

        // Persist the finalized frame to the shard clock store so the NEXT
        // `prove_next_state` can resolve the exact consensus parent. Persistence
        // is a prerequisite for all downstream effects: never publish or reward
        // a frame that this worker failed to make durable.
        if !already_committed {
            let selector = match quil_crypto::poseidon::hash_bytes_to_32(&header.output) {
                Ok(h) => h.to_vec(),
                Err(e) => {
                    warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw shard frame selector failed");
                    return;
                }
            };
            let txn = match self.clock_store.new_transaction(false) {
                Ok(txn) => txn,
                Err(e) => {
                    warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw stage shard frame transaction failed");
                    return;
                }
            };
            if let Err(e) = self
                .clock_store
                .stage_shard_clock_frame(&selector, &frame, txn.as_ref())
            {
                warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw stage shard frame failed");
                return;
            }
            if let Err(e) = txn.commit() {
                warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw stage shard frame transaction commit failed");
                return;
            }

            let txn = match self.clock_store.new_transaction(false) {
                Ok(txn) => txn,
                Err(e) => {
                    warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw commit shard frame transaction failed");
                    return;
                }
            };
            if let Err(e) = self.clock_store.commit_shard_clock_frame(
                &self.filter,
                frame_number,
                &selector,
                txn.as_ref(),
                false,
            ) {
                warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw commit shard frame failed");
                return;
            }
            if let Err(e) = txn.commit() {
                warn!(core_id = self.core_id, frame = frame_number, error = %e, "cw commit shard frame transaction commit failed");
                return;
            }
        }

        if frame_number <= self.last_materialized_frame || self.execution_engine.is_none() {
            // Already materialized (or nothing to apply); still (re)publish below.
        } else if frame_number != self.last_materialized_frame + 1 {
            // Leapfrog guard (audit Finding #4): a finalized frame more than one
            // ahead of the cursor means intermediate frames are missing (e.g. a
            // prior frame failed fatally). Materializing here would apply N+k on
            // state missing N..N+k-1's mutations and permanently skip them. Refuse;
            // the follower/shard-sync path fills the gap strictly (== last+1).
            warn!(
                core_id = self.core_id, frame = frame_number,
                cursor = self.last_materialized_frame,
                "cw-finalized frame ahead of cursor; deferring to catch-up (not skipping)",
            );
        } else {
            let world_size = self
                .hypergraph
                .as_ref()
                .map(|hg| {
                    use num_traits::ToPrimitive;
                    hg.total_size().to_u64().unwrap_or(0)
                })
                .unwrap_or(0);
            // Use the CERTIFIED header difficulty (bound into the frame output),
            // not this node's local `current_difficulty` — they can differ when
            // materializing another leader's finalized frame, and the reward path
            // must use the value the committee certified (audit hardening #2).
            let difficulty = header.difficulty;
            match self
                .materialize_offloaded(
                    frame.requests.clone(),
                    frame_number,
                    difficulty,
                    world_size,
                    header.fee_multiplier_vote,
                )
                .await
            {
                Ok((processed, skipped)) => {
                    self.set_materialized_frame(frame_number);
                    self.persist_materialized_cursor(frame_number);
                    debug!(core_id = self.core_id, frame = frame_number, processed, skipped,
                        "materialized cw-finalized shard frame");
                }
                // Cursor NOT advanced on error → the frame is retried on the next
                // finalize/sync instead of being silently skipped (Finding #4).
                Err(e) => warn!(core_id = self.core_id, frame = frame_number, error = %e,
                    "cw-finalized materialize failed (cursor held; will retry)"),
            }
        }

        // An identical callback replay was already published/rewarded when it
        // first became canonical. It may have retried materialization above, but
        // must not appear as a second finalized frame to downstream consumers.
        if already_committed {
            return;
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
        // frames is by VDF + committee cert, not the header agg sig.
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

                // Run the full VDF + BLS app-shard
                // frame validator before buffering for follower
                // materialization. The archive ingest path already does
                // this; the follower path did not. Untrusted header
                // fields (e.g. `fee_multiplier_vote`) are read downstream.
                match self.app_frame_validator.as_ref() {
                    Some(v) => match validate_app_frame_panic_safe(v, &frame, /* proposal */ false) {
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

                // Buffer the full frame (header+requests) for follower
                // materialization, but only if it's still ahead of what
                // we've materialized (avoid unbounded re-buffering of old
                // frames). The buffer is materialized in strict order
                // against the finalized (trusted) requests_root.
                if frame_number > self.last_materialized_frame {
                    self.received_full_frames.insert(frame_number, frame);
                    self.try_materialize_follower_frames().await;
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

    /// On finalizing a frame THIS node proposed: assemble the full
    /// `AppShardFrame { header, requests }`, materialize its requests
    /// into local shard state, and publish the full frame on
    /// `shard_frame_bitmask`. No-op if this node didn't propose the frame
    /// (no collected requests on hand — it materializes on receipt
    /// instead). `header_canonical_bytes` is the certified header.
    async fn distribute_and_materialize_own_frame(
        &mut self,
        frame_number: u64,
        header_canonical_bytes: &[u8],
    ) {
        // Decode the certified canonical header into a proto FrameHeader.
        // This is the header THIS node finalized through BLS-verified
        // consensus, so its `requests_root` is the trust anchor for
        // materializing the matching full frame (whether ours or a
        // follower's received from the proposer).
        let canon = match quil_execution::global_intrinsic::frame_header::FrameHeader::from_canonical_bytes(
            header_canonical_bytes,
        ) {
            Ok(h) => h,
            Err(e) => {
                warn!(core_id = self.core_id, frame = frame_number, error = %e,
                    "could not decode finalized header");
                return;
            }
        };
        // Record the trusted requests_root and bound the map.
        self.finalized_requests_roots
            .insert(frame_number, canon.requests_root.clone());
        let root_cutoff = frame_number.saturating_sub(256);
        self.finalized_requests_roots
            .retain(|&f, _| f >= root_cutoff);

        // Requests are present only if WE proposed this frame. A follower
        // has none here and materializes from the received full frame
        // (try_materialize_follower_frames below).
        let requests = match self
            .frame_requests
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&(frame_number, canon.rank)))
        {
            Some(r) => r,
            None => {
                // Follower path: maybe the full frame already arrived.
                self.try_materialize_follower_frames().await;
                return;
            }
        };

        let proto_header = quil_types::proto::global::FrameHeader {
            address: canon.address.clone(),
            frame_number: canon.frame_number,
            rank: canon.rank,
            timestamp: canon.timestamp,
            difficulty: canon.difficulty,
            output: canon.output.clone(),
            parent_selector: canon.parent_selector.clone(),
            requests_root: canon.requests_root.clone(),
            state_roots: canon.state_roots.clone(),
            prover: canon.prover.clone(),
            fee_multiplier_vote: canon.fee_multiplier_vote as u64,
            // Carry the quorum aggregate BLS cert into the gossiped frame
            // so any receiver (follower or archive) can verify it against
            // the shard committee via BlsAppFrameValidator. The canonical
            // header's sig blob is the same AggregateSignature the global
            // engine quorum-verifies as the reward proof
            // (intrinsic.rs:599-634).
            public_key_signature_bls48581: if canon.public_key_signature_bls48581.is_empty() {
                None
            } else {
                quil_execution::hypergraph_intrinsic::canonical::AggregateSignature::from_canonical_bytes(
                    &canon.public_key_signature_bls48581,
                )
                .ok()
                .map(|sig| quil_types::proto::keys::Bls48581AggregateSignature {
                    public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                        key_value: sig
                            .public_key
                            .as_ref()
                            .map(|k| k.key_value.clone())
                            .unwrap_or_default(),
                    }),
                    signature: sig.signature.clone(),
                    bitmask: sig.bitmask.clone(),
                })
            },
            storage_attestation_root: canon.storage_attestation_root.clone(),
            global_frame_number: canon.global_frame_number,
            storage_attestation: canon.storage_attestation.clone(),
        };

        // PoRep: the committee `StorageAttestation` was assembled once, at
        // finalization (`AppFollower::enrich_with_storage_attestation`), and
        // bound onto the canonical header (root + serialized openings) that
        // `canon` was decoded from. Surface it on the full proto frame for
        // archives — `proto_header.storage_attestation_root` already carries
        // `canon.storage_attestation_root` (set above). Empty = legacy frame.
        let storage_attestation = if canon.storage_attestation.is_empty() {
            None
        } else {
            <quil_types::proto::global::StorageAttestation as prost::Message>::decode(
                canon.storage_attestation.as_slice(),
            )
            .ok()
        };

        let fee_multiplier_vote = proto_header.fee_multiplier_vote;
        // Capture the certified difficulty before `proto_header` is moved into
        // the frame — materialize must use the value bound into the frame output,
        // which can differ from `current_difficulty` if a difficulty adjustment
        // landed between producing this header and materializing it (hardening #2).
        let header_difficulty = proto_header.difficulty;
        let frame = quil_types::proto::global::AppShardFrame {
            header: Some(proto_header),
            requests: requests.clone(),
            storage_attestation,
        };

        // Step 2: self-materialize into local shard state (idempotent).
        // Offloaded to the blocking pool so it doesn't HOL-block the
        // engine's runtime thread.
        if self.execution_engine.is_some()
            && frame_number > self.last_materialized_frame
            && frame_number != self.last_materialized_frame + 1
        {
            // Leapfrog guard (Finding #4): don't materialize past a gap.
            warn!(
                core_id = self.core_id, frame = frame_number,
                cursor = self.last_materialized_frame,
                "own shard frame ahead of cursor; deferring to catch-up (not skipping)",
            );
        } else if frame_number == self.last_materialized_frame + 1 && self.execution_engine.is_some() {
            let world_size = self
                .hypergraph
                .as_ref()
                .map(|hg| {
                    use num_traits::ToPrimitive;
                    hg.total_size().to_u64().unwrap_or(0)
                })
                .unwrap_or(0);
            let difficulty = header_difficulty;
            match self
                .materialize_offloaded(
                    requests.clone(),
                    frame_number,
                    difficulty,
                    world_size,
                    fee_multiplier_vote,
                )
                .await
            {
                Ok((processed, skipped)) => {
                    self.set_materialized_frame(frame_number);
                    // Persist AFTER commit_frame succeeded (inside
                    // materialize_app_shard_requests) so the durable
                    // cursor never outruns the CRDT.
                    self.persist_materialized_cursor(frame_number);
                    debug!(core_id = self.core_id, frame = frame_number, processed, skipped,
                        "self-materialized own shard frame");
                }
                // Cursor held on error → retried on next finalize/sync (Finding #4).
                Err(e) => warn!(core_id = self.core_id, frame = frame_number, error = %e,
                    "self-materialize of own shard frame failed (cursor held; will retry)"),
            }
        }

        // Step 1: publish the full frame for followers/archives.
        let mut buf = Vec::new();
        if prost::Message::encode(&frame, &mut buf).is_ok() {
            let _ = self.event_tx.send(AppEngineEvent::FullFrameProduced {
                filter: self.filter.clone(),
                frame_number,
                frame_data: buf,
            });
        }
    }

    /// Materialize buffered received full frames in strict order, as a
    /// follower. Each is gated by: it is exactly the next frame to
    /// materialize, we hold the finalized (trusted) `requests_root` for
    /// it, and the frame's `requests` recompute to that root. A mismatch
    /// rejects the frame (it didn't come from the consensus-finalized
    /// frame). Out-of-order frames stay buffered until the gap fills
    /// (or a future sync resolves it).
    async fn try_materialize_follower_frames(&mut self) {
        loop {
            let next = self.last_materialized_frame + 1;
            let trusted_root = match self.finalized_requests_roots.get(&next) {
                Some(r) => r.clone(),
                None => break, // not finalized through consensus yet
            };
            let frame = match self.received_full_frames.get(&next) {
                Some(f) => f.clone(),
                None => break, // full frame not received yet
            };
            // Validate address + capture the fee vote (Copy) so we don't
            // hold a borrow of `frame.header` across the awaits below.
            let (fee_multiplier_vote, header_difficulty) = match frame.header.as_ref() {
                Some(h) if h.address == self.app_address => (h.fee_multiplier_vote, h.difficulty),
                _ => {
                    self.received_full_frames.remove(&next);
                    break;
                }
            };

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
            let world_size = self
                .hypergraph
                .as_ref()
                .map(|hg| {
                    use num_traits::ToPrimitive;
                    hg.total_size().to_u64().unwrap_or(0)
                })
                .unwrap_or(0);
            // Certified difficulty from the received frame's header (hardening #2).
            let difficulty = header_difficulty;
            match self
                .materialize_offloaded(
                    frame.requests.clone(),
                    next,
                    difficulty,
                    world_size,
                    fee_multiplier_vote,
                )
                .await
            {
                Ok((processed, skipped)) => {
                    self.set_materialized_frame(next);
                    self.persist_materialized_cursor(next);
                    // Advance the clock head in lockstep with the cursor. This is
                    // the critical case: a follower drains finalized frames it
                    // received via frame-sync WITHOUT running its own finalize
                    // handler for them, so nothing else writes the clock head —
                    // leaving mat > clock and triggering a re-propose/nullify storm.
                    self.commit_shard_clock_head(&frame, next);
                    self.received_full_frames.remove(&next);
                    self.materialize_failures.remove(&next);
                    debug!(core_id = self.core_id, frame = next, processed, skipped,
                        "materialized received shard frame (follower)");
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

        // Materialize the certified parent's requests into hypergraph
        // state BEFORE sealing the clock frame — token/compute/hypergraph
        // engines run here. Mirrors Go `addCertifiedState → materialize`
        // (app_consensus_engine.go:2996), which gates the clock commit on
        // a successful materialize. The idempotency gate
        // (`last_materialized_frame`) makes a repeat seal a no-op. If
        // materialize fails we DON'T seal: re-queue the parent so a later
        // attempt can retry, rather than committing an un-materialized
        // frame.
        // Leapfrog guard (Finding #4): only materialize the immediate next frame.
        // If the certified parent is more than one ahead of the cursor, seal the
        // clock frame (the chain advances) but DON'T materialize past the gap —
        // the strict follower/shard-sync path fills it (== last+1). Materializing
        // N+k on state missing N..N+k-1 would silently skip their mutations.
        if header.frame_number > self.last_materialized_frame + 1 {
            warn!(
                core_id = self.core_id, parent_rank, frame = header.frame_number,
                cursor = self.last_materialized_frame,
                "sealed parent ahead of cursor; sealing clock frame, deferring materialize to catch-up",
            );
        } else if header.frame_number == self.last_materialized_frame + 1 {
            // Scalars up front so no borrow of `self`/`frame` survives
            // into the result arms where we mutate
            // `self.last_materialized_frame` / `pending_certified_parents`.
            let frame_number = header.frame_number;
            let fee_multiplier_vote = header.fee_multiplier_vote;
            // Certified difficulty from the sealed parent's header (hardening #2).
            let header_difficulty = header.difficulty;
            if self.execution_engine.is_some() {
                let world_size = self
                    .hypergraph
                    .as_ref()
                    .map(|hg| {
                        use num_traits::ToPrimitive;
                        hg.total_size().to_u64().unwrap_or(0)
                    })
                    .unwrap_or(0);
                let difficulty = header_difficulty;
                // Offloaded to the blocking pool (off the engine task).
                let result = self
                    .materialize_offloaded(
                        frame.requests.clone(),
                        frame_number,
                        difficulty,
                        world_size,
                        fee_multiplier_vote,
                    )
                    .await;
                // Best-effort: we seal the clock frame regardless of the
                // materialize outcome (it never blocks consensus
                // progress). A commit_frame error only means the CRDT
                // flush failed — log it; the clock chain still advances,
                // matching prior behavior where app-shard frames weren't
                // materialized at all. Advance the idempotency gate so we
                // don't re-attempt this frame.
                match result {
                    Ok((processed, skipped)) => {
                        // Only advance + persist the cursor on a
                        // successful commit_frame. Advancing on Err would
                        // push the cursor past the CRDT (the unsafe
                        // direction) and silently skip this frame's
                        // mutations on restart.
                        self.set_materialized_frame(frame_number);
                        self.persist_materialized_cursor(frame_number);
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
                            "app-shard materialize commit failed (sealing anyway; cursor not advanced)"
                        );
                    }
                }
            }
        }

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
/// required for byte-for-byte parity with Go peers during VDF
/// challenge verification.
pub(crate) fn compute_requests_root(
    messages: &[Vec<u8>],
    app_address: &[u8],
    frame_number: u64,
    execution_engine: Option<&quil_execution::ExecutionEngineManager>,
    inclusion_prover: Option<&dyn quil_types::crypto::InclusionProver>,
    // Phase-3: a migrated node commits the requests to a hash-Merkle JMT (32B
    // root) instead of the KZG vector-commitment tree — removing BLS48-581 from
    // the per-frame message commitment. All nodes are migrated post-fork, so
    // the flag is uniform for any given frame and the VDF challenge stays
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
    // POSITION binds the commitment to request ORDER and MULTIPLICITY (audit
    // Finding #2). A keyed JMT/VC tree is otherwise order-independent and
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
pub(crate) fn materialize_app_shard_requests(
    execution_manager: &quil_execution::ExecutionEngineManager,
    requests: &[quil_types::proto::global::MessageBundle],
    frame_number: u64,
    difficulty: u32,
    world_size: u64,
    fee_multiplier_vote: u64,
    app_address: &[u8],
) -> Result<(usize, usize)> {
    use num_bigint::BigInt;
    use num_traits::{ToPrimitive, Zero};

    let addr: &[u8] = if app_address.len() >= 32 {
        &app_address[..32]
    } else {
        app_address
    };

    let mut processed = 0usize;
    let mut skipped = 0usize;
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

        let cost_basis = execution_manager
            .get_cost(&bundle_bytes)
            .unwrap_or_else(|_| BigInt::zero());
        let fee = if cost_basis.is_zero() {
            BigInt::zero()
        } else {
            let cost_u64 = cost_basis.to_u64().unwrap_or(1);
            let baseline = crate::rewards::get_baseline_fee(
                difficulty as u64,
                world_size,
                cost_u64,
                crate::rewards::QUIL_TOKEN_UNITS,
            );
            &baseline / &cost_basis
        };
        let fee = fee * BigInt::from(fee_multiplier_vote);

        match execution_manager.process_message(frame_number, &fee, addr, &bundle_bytes) {
            Ok(_) => processed += 1,
            Err(e) => {
                // DIVERGENCE GUARD (audit Finding #4). Skipping a failed bundle
                // and still advancing the cursor is only safe when the failure
                // is DETERMINISTIC — a function of (bundle, agreed pre-state)
                // that every replica hits identically (bad signature, semantic
                // rejection, missing referenced entity). With pre-state now
                // validated (audit #3), all replicas share the same N-1 state,
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
                use quil_types::error::QuilError;
                if matches!(e, QuilError::Store(_) | QuilError::Io(_)) {
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

    execution_manager.commit_frame(frame_number)?;
    Ok((processed, skipped))
}

/// Run a [`BlsAppFrameValidator`] with panic containment. Malformed VDF
/// output from a peer message can panic inside the classgroup code; a
/// panic here must be treated as a validation failure (drop the frame)
/// rather than unwinding the receive task. Mirrors the global frame
/// path's `catch_unwind` (`message_loop.rs`).
fn validate_app_frame_panic_safe(
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

    use quil_consensus::leader_provider::LeaderProvider as _;
    use quil_types::crypto::Signer as _;

    fn test_shard_frame(
        filter: &[u8],
        frame_number: u64,
        output_byte: u8,
    ) -> quil_types::proto::global::AppShardFrame {
        quil_types::proto::global::AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: filter.to_vec(),
                frame_number,
                output: vec![output_byte; 516],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn commit_test_shard_frame(
        store: &dyn ClockStore,
        filter: &[u8],
        frame_number: u64,
        output_byte: u8,
    ) -> Vec<u8> {
        let frame = test_shard_frame(filter, frame_number, output_byte);
        let output = &frame.header.as_ref().expect("test frame header").output;
        let selector = quil_crypto::poseidon::hash_bytes_to_32(output)
            .expect("test frame output hashes")
            .to_vec();

        let txn = store.new_transaction(false).expect("stage transaction");
        store
            .stage_shard_clock_frame(&selector, &frame, txn.as_ref())
            .expect("stage test shard frame");
        txn.commit().expect("commit staged test shard frame");

        let txn = store.new_transaction(false).expect("canonical transaction");
        store
            .commit_shard_clock_frame(filter, frame_number, &selector, txn.as_ref(), false)
            .expect("commit canonical test shard frame");
        txn.commit().expect("commit test shard head");
        selector
    }

    fn test_app_leader_provider(
        clock_store: Arc<dyn ClockStore>,
        filter: Vec<u8>,
        materialized: Arc<std::sync::atomic::AtomicU64>,
    ) -> AppLeaderProvider {
        let prover_address = vec![0x33; 32];
        let prover_public_key = vec![0x44; 897];
        let registry = Arc::new(crate::test_support::TestProverRegistry::with_prover(
            quil_types::consensus::ProverInfo {
                public_key: prover_public_key.clone(),
                address: prover_address.clone(),
                status: quil_types::consensus::ProverStatus::Active,
                kick_frame_number: 0,
                allocations: Vec::new(),
                available_storage: 0,
                seniority: 1,
                delegate_address: Vec::new(),
            },
        ));

        AppLeaderProvider {
            filter: filter.clone(),
            clock_store: clock_store.clone(),
            global_anchor_store: clock_store,
            frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            prover_registry: registry,
            message_collector: Arc::new(MessageCollector::new()),
            fee_manager: Arc::new(crate::InMemoryDynamicFeeManager::new(32)),
            local_prover_address: prover_address,
            local_public_key: prover_public_key.clone(),
            current_difficulty: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            reward_greedy: false,
            hypergraph: None,
            storage_source_hypergraph: None,
            execution_engine: None,
            inclusion_prover: None,
            app_address: filter,
            halted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            min_active_provers_for_propose: 1,
            shard_mat_frame: materialized,
            frame_requests: Arc::new(std::sync::Mutex::new(HashMap::new())),
            kv_db: None,
            frame_attestations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            instance_committee_fp: AppConsensusEngine::committee_fp(&[prover_public_key]),
        }
    }

    /// Regression for #591. Simplex may enter view V+1 with V as its certified
    /// parent before V's finalization callback has persisted/materialized it.
    /// The app proposer must not consult the stale store head and emit another
    /// frame numbered N+1. It waits; after N+1 is applied, the next proposal is
    /// N+2 and chains to the exact consensus parent identity.
    #[test]
    fn app_leader_waits_for_unfinalized_simplex_parent() {
        let filter = vec![0xAA; 32];
        let store = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let materialized = Arc::new(std::sync::atomic::AtomicU64::new(7));
        commit_test_shard_frame(store.as_ref(), &filter, 7, 0x07);
        let provider = test_app_leader_provider(
            store.clone() as Arc<dyn ClockStore>,
            filter.clone(),
            materialized.clone(),
        );

        // Adjacent Simplex view: frame 8 is the certified consensus parent, but
        // the finalization callback has not advanced the store/materializer yet.
        let pending_parent_identity = vec![0x88; 32];
        let err = provider
            .prove_next_state(9, &filter, 8, &pending_parent_identity)
            .expect_err("must not reuse frame number 8 while its parent is unapplied");
        assert!(
            err.is_no_vote(),
            "unapplied consensus parent must defer the view: {err}"
        );

        // Once that exact parent is durable and materialized, production may
        // advance. Its output hashes to the identity Simplex supplied.
        let committed_parent_identity = commit_test_shard_frame(store.as_ref(), &filter, 8, 0x08);
        materialized.store(8, std::sync::atomic::Ordering::SeqCst);
        let state = provider
            .prove_next_state(10, &filter, 8, &committed_parent_identity)
            .expect("proposal resumes after the consensus parent is applied");

        assert_eq!(state.state.frame_number, 9);
        assert_eq!(state.state.parent_selector, committed_parent_identity);
        assert_eq!(state.parent_qc_identity, committed_parent_identity);
    }

    /// A finalized frame has exactly one durable value, one full-frame publish,
    /// and one reward/coverage emission. Replaying the same finalization or a
    /// conflicting block at that height must not overwrite or emit again.
    #[tokio::test]
    async fn cw_finalization_is_persisted_and_published_once_per_height() {
        let filter = vec![0xAB; 32];
        let store = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let signer = quil_crypto::FalconSigner::generate();
        let prover_public_key = signer.public_key().to_vec();
        let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&prover_public_key)
            .expect("test prover public key hashes")
            .to_vec();
        let registry = Arc::new(crate::test_support::TestProverRegistry::with_prover(
            quil_types::consensus::ProverInfo {
                public_key: prover_public_key.clone(),
                address: prover_address.clone(),
                status: quil_types::consensus::ProverStatus::Active,
                kick_frame_number: 0,
                allocations: Vec::new(),
                available_storage: 0,
                seniority: 1,
                delegate_address: Vec::new(),
            },
        ));
        let coverage_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let coverage_count_for_callback = coverage_count.clone();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let deps = AppEngineDeps {
            clock_store: store.clone() as Arc<dyn ClockStore>,
            global_anchor_store: None,
            prover_registry: registry,
            frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            message_collector: Arc::new(MessageCollector::new()),
            fee_manager: Arc::new(crate::InMemoryDynamicFeeManager::new(32)),
            local_prover_address: prover_address,
            local_bls_pubkey: prover_public_key,
            bls_signer: Box::new(signer),
            reward_greedy: false,
            min_active_provers_for_propose: 1,
            coverage_publish: Some(Arc::new(move |_| {
                coverage_count_for_callback.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
            hypergraph: None,
            storage_source_hypergraph: None,
            execution_engine: None,
            inclusion_prover: None,
            kv_db: None,
            app_consensus_cw: true,
            db_config: quil_config::DbConfig::default(),
        };
        let (mut engine, _handle) = AppConsensusEngine::new(1, filter.clone(), deps, event_tx);

        // Canonical parent N is durable. The incoming N+1 frame must link to
        // that exact identity; this also exercises the finalizer's no-gap and
        // parent-selector guards rather than bypassing them with an empty store.
        let parent_identity = commit_test_shard_frame(store.as_ref(), &filter, 7, 0x07);

        let mut gap = test_shard_frame(&filter, 9, 0x09);
        gap.header.as_mut().expect("gap frame header").parent_selector = parent_identity.clone();
        engine
            .handle_cw_finalized_frame(&prost::Message::encode_to_vec(&gap), &[])
            .await;
        assert!(event_rx.try_recv().is_err(), "gap finalization must not publish");
        assert_eq!(coverage_count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            store
                .get_latest_shard_clock_frame(&filter)
                .expect("gap must leave parent canonical")
                .header
                .expect("canonical parent header")
                .frame_number,
            7,
            "finalizer must not skip a canonical height"
        );

        let mut wrong_parent = test_shard_frame(&filter, 8, 0x18);
        wrong_parent.header.as_mut().expect("wrong-parent frame header").parent_selector =
            vec![0xFF; 32];
        engine
            .handle_cw_finalized_frame(&prost::Message::encode_to_vec(&wrong_parent), &[])
            .await;
        assert!(
            event_rx.try_recv().is_err(),
            "wrong-parent finalization must not publish"
        );
        assert_eq!(coverage_count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            store
                .get_latest_shard_clock_frame(&filter)
                .expect("wrong parent must leave canonical head unchanged")
                .header
                .expect("canonical parent header")
                .frame_number,
            7
        );

        let mut frame = test_shard_frame(&filter, 8, 0x08);
        frame.header.as_mut().expect("frame header").parent_selector = parent_identity;
        let encoded = prost::Message::encode_to_vec(&frame);
        engine.handle_cw_finalized_frame(&encoded, &[]).await;

        let first_events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert_eq!(
            first_events
                .iter()
                .filter(|e| matches!(e, AppEngineEvent::FullFrameProduced { .. }))
                .count(),
            1,
            "first finalization publishes one full frame"
        );
        assert_eq!(
            first_events
                .iter()
                .filter(|e| matches!(e, AppEngineEvent::ShardFrameFinalized { .. }))
                .count(),
            1,
            "first finalization emits one rewardable header"
        );
        assert_eq!(coverage_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            store
                .get_latest_shard_clock_frame(&filter)
                .expect("first finalization persisted")
                .header
                .expect("persisted frame header")
                .output,
            vec![0x08; 516]
        );

        engine.handle_cw_finalized_frame(&encoded, &[]).await;
        assert!(
            event_rx.try_recv().is_err(),
            "identical finalization replay must not republish"
        );
        assert_eq!(
            coverage_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "identical finalization replay must not earn coverage twice"
        );

        let mut conflicting = frame;
        conflicting.header.as_mut().expect("conflicting frame header").output = vec![0xF8; 516];
        engine
            .handle_cw_finalized_frame(&prost::Message::encode_to_vec(&conflicting), &[])
            .await;
        assert!(
            event_rx.try_recv().is_err(),
            "conflicting same-height finalization must not publish"
        );
        assert_eq!(coverage_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            store
                .get_latest_shard_clock_frame(&filter)
                .expect("canonical head remains readable")
                .header
                .expect("canonical head has a header")
                .output,
            vec![0x08; 516],
            "conflicting same-height finalization must not overwrite canonical data"
        );
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
    fn reset_stale_app_journal_keeps_same_committee_wipes_changed() {
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

        // First call has no stored fingerprint → treated as a change (wipes),
        // then records committee A's fingerprint.
        repopulate();
        reset_stale_app_journal(&journal_dir, &committee_a);
        // Same committee → journal preserved (a moved head does NOT reset it).
        repopulate();
        reset_stale_app_journal(&journal_dir, &committee_a);
        assert!(file.exists(), "same committee must keep the journal");
        // Changed committee → journal wiped.
        reset_stale_app_journal(&journal_dir, &committee_b);
        assert!(!file.exists(), "changed committee must discard the stale journal");

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
        let (processed, skipped) = materialize_app_shard_requests(
            mgr.as_ref(),
            &[],
            1,
            50_000,
            0,
            1,
            &quil_execution::domains::QUIL_TOKEN,
        )
        .unwrap();
        assert_eq!(processed, 0);
        assert_eq!(skipped, 0);
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
        let (processed, _skipped) = materialize_app_shard_requests(
            mgr.as_ref(),
            &bundles,
            2,
            50_000,
            0,
            7, // non-trivial fee_multiplier_vote exercises the app-specific multiply
            &quil_execution::domains::QUIL_TOKEN,
        )
        .unwrap();
        assert_eq!(processed, 2);
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
