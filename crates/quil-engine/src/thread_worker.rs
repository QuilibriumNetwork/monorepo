//! Thread-based worker manager with CPU core pinning.
//!
//! Each worker thread runs its own single-threaded tokio runtime and
//! communicates with the master via `tokio::sync::mpsc` channels. Core
//! affinity is set via the `core_affinity` crate, spreading workers over
//! NUMA nodes (`worker_pinning`); `new_current_thread` gives each
//! worker its own isolated runtime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use quil_types::error::{QuilError, Result};
use quil_types::thread_probe::{
    install as install_probe, probed, Section as ProbeSection, ThreadProbe,
};

use crate::worker::{WorkerInfo, WorkerManager};

/// Message from master to worker.
#[derive(Debug)]
pub enum MasterToWorker {
    /// Assign a new filter (shard) to this worker.
    ///
    /// `start_consensus`:
    ///   * `true` — tear down any existing engine and (re)spawn the
    /// `AppConsensusEngine`. Used for `Active`/`Paused`
    /// allocations.
    /// * `false` — record the filter binding for TUI visibility,
    /// cancel any running engine, but do NOT spawn a new one.
    /// Used while an allocation is `Joining` and there is no
    /// Active prover under this filter yet (the engine's
    /// `leader_for_rank` would fail and the loop would die).
    /// Mirrors Go's `worker.Filter`-set / `worker.Allocated=false`
    /// state from `worker_allocator.go:421-440`.
    Respawn {
        filter: Vec<u8>,
        start_consensus: bool,
    },
    /// Remove application payload outside `keep` from this worker's store,
    /// once its running engine serves only kept scopes and the binding has
    /// settled.
    EvictPayload { keep: Vec<Vec<u8>> },
    /// Request the worker to compute a join proof.
    CreateJoinProof {
        challenge: [u8; 32],
        difficulty: u32,
        ids: Vec<Vec<u8>>,
        prover_index: u32,
        reply: tokio::sync::oneshot::Sender<Result<Vec<u8>>>,
    },
}

/// Message from worker to master.
#[derive(Debug)]
pub enum WorkerToMaster {
    /// Worker has completed a respawn and is ready.
    Ready { core_id: u32 },
    /// Worker produced an app shard frame.
    FrameProduced {
        core_id: u32,
        filter: Vec<u8>,
        frame_number: u64,
        frame_data: Vec<u8>,
    },
    /// Worker finalized a full app shard frame (header+requests) for the
    /// master to publish on `shard_frame_bitmask` (state distribution).
    FullFrameProduced {
        core_id: u32,
        filter: Vec<u8>,
        frame_number: u64,
        frame_data: Vec<u8>,
    },
    /// Shard frame finalized — canonical FrameHeader bytes for the
    /// master to wrap in a `MessageBundle{Shard: header}` and publish
    /// on `GLOBAL_PROVER`.
    ShardFrameFinalized {
        core_id: u32,
        filter: Vec<u8>,
        header_canonical_bytes: Vec<u8>,
    },
    /// Worker produced a vote — to be published on the per-shard
    /// consensus bitmask (`0x00 || filter`) so peers can collect it.
    /// Self-loopback to own engine is handled at the worker thread.
    VoteProduced {
        core_id: u32,
        filter: Vec<u8>,
        vote_data: Vec<u8>,
    },
    /// Worker produced a timeout — to be published on the per-shard
    /// consensus bitmask. Same self-loopback semantics as VoteProduced.
    TimeoutProduced {
        core_id: u32,
        filter: Vec<u8>,
        timeout_data: Vec<u8>,
    },
    /// Periodic heartbeat from an active shard worker.
    ShardHeartbeat { core_id: u32, filter: Vec<u8> },
    /// An outbound commonware-simplex message for a shard's committee.
    /// The master publishes it on `shard_cw_bitmask(filter)` with the channel
    /// tagged into the payload (`shard_cw_frame_payload(channel, bytes)`).
    CwConsensus {
        core_id: u32,
        filter: Vec<u8>,
        channel: u64,
        bytes: Vec<u8>,
        /// Committee keys a resolver message is addressed to (empty: the
        /// whole topic); see `AppEngineEvent::CwOut`.
        recipients: Vec<Vec<u8>>,
    },
    /// A shard worker has spun up an `AppConsensusEngine` for `filter`.
    /// The master uses this to populate a `filter → AppEngineHandle`
    /// registry so peer messages on the per-shard bitmasks can be
    /// routed to the right engine, and to subscribe BlossomSub to the
    /// per-shard frame/consensus/prover/dispatch bitmasks.
    ShardActivated {
        core_id: u32,
        filter: Vec<u8>,
        handle: crate::app_engine::AppEngineHandle,
    },
    /// A shard worker has torn down its `AppConsensusEngine` for
    /// `filter`. Master removes the registry entry and unsubscribes
    /// from per-shard bitmasks (no peer here will produce or relay
    /// shard messages once we leave it).
    ShardDeactivated { core_id: u32, filter: Vec<u8> },
}

/// State of a single worker thread.
struct WorkerState {
    core_id: u32,
    filter: Vec<u8>,
    /// Frame number when a join proposal was submitted for this worker.
    /// 0 once the allocation is confirmed active in the registry.
    pending_filter_frame: u64,
    /// When true, the lifecycle skips this worker during
    /// auto-allocation; operators pin filters via external tooling.
    manually_managed: bool,
    /// Whether the worker's filter is fully active in the registry
    /// (allocation Status=Active or Paused).
    allocated: bool,
    cancel: CancellationToken,
    tx: mpsc::Sender<MasterToWorker>,
    /// Kept so the spawned worker task is owned by the supervisor; shutdown
    /// goes through `cancel`, so the handle is never awaited.
    #[allow(dead_code)]
    handle: Option<JoinHandle<()>>,
    execution_handle: Arc<Mutex<Option<crate::app_engine::AppEngineHandle>>>,
}

/// Shared state that worker threads need for consensus.
/// Set via `set_consensus_deps` after initialization.
pub struct WorkerConsensusDeps {
    pub prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
    pub frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    pub message_collector: Arc<crate::message_collector::MessageCollector>,
    pub clock_store: Arc<dyn quil_types::store::ClockStore>,
    pub fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager>,
    pub local_prover_address: Vec<u8>,
    pub local_bls_pubkey: Vec<u8>,
    /// Factory for creating BLS signers for each worker engine.
    /// Each engine needs its own signer (Box<dyn Signer> is not Clone).
    pub bls_signer_factory: Arc<dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync>,
    /// Whether the node uses reward-greedy strategy for fee adjustment.
    pub reward_greedy: bool,
    /// Minimum Active prover count required before a shard's leader
    /// will produce frames. Mainnet=3 (matches halt-risk floor),
    /// testnet=1 (single-prover clusters still progress). See
    /// `AppLeaderProvider::min_active_provers_for_propose`.
    pub min_active_provers_for_propose: u64,
    /// Drive app-shard consensus with commonware-simplex + Falcon.
    pub app_consensus_cw: bool,
    /// DB config → persistent per-shard simplex-journal dir (Go parity).
    pub db_config: quil_config::DbConfig,
    /// Callback that publishes finalized canonical FrameHeader bytes
    /// on `GLOBAL_PROVER` so archives credit our shard work toward
    /// rewards. AppFollower invokes this directly from the consensus
    /// event loop to avoid hopping through the worker→master channel
    /// chain.
    pub coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    /// Hypergraph CRDT used to derive per-frame `state_roots` for the
    /// FrameHeader VDF challenge.
    pub hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// The master's committed shard topology, from which a retiring shard
    /// drains (`AppEngineDeps::topology`).
    pub topology: Option<Arc<dyn quil_types::store::ShardsStore>>,
    /// Execution engine for the per-message `Lock` calls that feed
    /// `requests_root`.
    pub execution_engine: Option<Arc<quil_execution::ExecutionEngineManager>>,
    /// Inclusion prover for the `requests_root` tree commit.
    pub inclusion_prover: Option<Arc<dyn quil_types::crypto::InclusionProver>>,
    /// Invoked once on each worker thread after core-affinity pinning.
    pub worker_init: Option<Arc<dyn Fn(u32) + Send + Sync>>,
    /// Builds the per-worker store + CRDT + execution-engine bundle.
    /// Called once on the worker thread after `worker_init`. When
    /// present, its outputs override the shared `clock_store`,
    /// `hypergraph`, `execution_engine`, and `inclusion_prover`
    /// fields on this struct for that worker. The master keeps its
    /// own global state; each worker writes app-shard frames and
    /// shard data into its own RocksDB.
    pub worker_state_builder:
        Option<Arc<dyn Fn(u32) -> std::result::Result<WorkerOwnedDeps, String> + Send + Sync>>,
    /// Master-side KV-store handle, used when no per-worker
    /// `worker_state_builder` is wired. App-shard `ConsensusState` and
    /// `LivenessState` are persisted here so a restart preserves
    /// finalized rank / latest QC.
    pub kv_db: Option<Arc<dyn quil_types::store::KvDb>>,
}

/// Per-worker state: each worker thread owns its own RocksDB and the
/// stores / CRDT / execution engine layered on top.
#[derive(Clone)]
pub struct WorkerOwnedDeps {
    pub clock_store: Arc<dyn quil_types::store::ClockStore>,
    pub hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
    pub execution_engine: Arc<quil_execution::ExecutionEngineManager>,
    pub inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    /// Per-worker KV-store handle used by the app-shard consensus
    /// engine for persisting `ConsensusState` / `LivenessState`.
    /// Optional — `worker_state_builder` implementations that don't
    /// expose a KV handle leave this `None` and the engine falls
    /// back to the in-memory consensus stub.
    pub kv_db: Option<Arc<dyn quil_types::store::KvDb>>,
    /// Archive-direct shard-tree syncer bound to THIS worker's CRDT/store.
    /// Handles the step-4 app-shard catch-up (`AncestorSyncRequested`) when the
    /// worker falls far enough behind that gossip can't fill the gap — it pulls
    /// the shard subtree from an archive and the engine fast-forwards its cursor.
    /// `None` in shared-state mode (or when no archive/key is wired), where the
    /// event is simply skipped. Mirrors the `worker_node.rs` (multi-process) path.
    pub shard_syncer: Option<Arc<dyn crate::prover_tree_syncer::ProverTreeSyncer>>,
    /// Unified-cutover consolidation hook bound to THIS worker's CRDT/store
    /// (see `AppEngineDeps::unified_cutover_hook`). Built by the node
    /// (`worker_state_builder`); `None` skips consolidation (still flips).
    pub unified_cutover_hook: Option<Arc<dyn Fn(&[u8], u64) -> bool + Send + Sync>>,
    /// Fetches certified frames of other shards, for the outputs this shard
    /// owns but did not execute (see `AppEngineDeps::delivery_frame_source`).
    pub delivery_frame_source: Option<crate::app_engine::DeliveryFrameSource>,
    pub storage_history_source: Option<crate::storage_history::GlobalVertexProofSource>,
    /// Archive source of a predecessor's outgoing records for successor checks.
    pub outgoing_history_source: Option<crate::app_handoff::OutgoingHistorySource>,
    /// Committees that certified legacy frames today's registry no longer
    /// reproduces (see `historical_committee`).
    pub historical_committee_source: Option<crate::historical_committee::HistoricalCommitteeSource>,
    /// Authenticated archive copies of GLOBAL frames the master never held,
    /// which app frames this worker validates are anchored to.
    pub global_anchor_source: Option<crate::global_anchor::GlobalAnchorSource>,
}

/// How long a stopping worker's engine gets to tear down before its thread
/// is cancelled ([`ThreadWorkerManager::stop_worker`]).
const ENGINE_TEARDOWN: std::time::Duration = std::time::Duration::from_secs(2);
/// How long a retired worker's thread may take to end (closing its own
/// stores) before the node says it has not.
const RETIRE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether worker `core_id` recovers nothing of `filter` from an archive:
/// the seat on it is one this node gives up (`WorkerAllocator::gives_up`),
/// or, the worker holding no frame of the shard (`cold`), one whose leave
/// is confirmed (`WorkerAllocator::departing_install`). `withheld` keeps
/// this engine's last answer, so each change is logged once: withholding
/// starts, or ends because the seat is served again.
fn recovery_withheld(
    gate: &std::sync::RwLock<Option<crate::worker_allocator::RecoveryGate>>,
    withheld: &std::sync::atomic::AtomicBool,
    core_id: u32,
    filter: &[u8],
    cold: bool,
) -> bool {
    let gate = gate.read().unwrap_or_else(|e| e.into_inner()).clone();
    let (frame, seat) = gate.map_or((0, None), |gate| gate(filter, cold));
    match (
        &seat,
        withheld.swap(seat.is_some(), std::sync::atomic::Ordering::Relaxed),
    ) {
        (Some(seat), false) => info!(core_id, filter = %hex::encode(filter), frame = seat.frame,
            allocation_epoch = seat.allocation_epoch, current_epoch = seat.current_epoch,
            reason = seat.cause.reason(), scope = "this node's worker", action = seat.cause.action(),
            "archive recovery withheld for a seat this node gives up"),
        (None, true) => {
            info!(core_id, filter = %hex::encode(filter), frame, scope = "this node's worker",
            "archive recovery resumes: this node no longer gives up the seat")
        }
        _ => {}
    }
    seat.is_some()
}

/// Thread-based worker manager. Worker N is pinned to slot N of the
/// pinning layout; slot 0 is left to the master.
pub struct ThreadWorkerManager {
    workers: Mutex<HashMap<u32, WorkerState>>,
    /// Channel for workers to send events back to master.
    master_rx: Mutex<Option<mpsc::Receiver<WorkerToMaster>>>,
    master_tx: mpsc::Sender<WorkerToMaster>,
    /// Configured worker count, or available CPUs less the master's (at least one).
    num_cores: u32,
    /// The core each worker is pinned to, read once at startup.
    layout: crate::worker_pinning::PinLayout,
    /// Shared consensus dependencies — set after construction.
    consensus_deps: Mutex<Option<Arc<WorkerConsensusDeps>>>,
    /// What workers ask before they recover a shard from an archive; set
    /// once the allocator exists, after the workers may have started.
    recovery_gate: Arc<std::sync::RwLock<Option<crate::worker_allocator::RecoveryGate>>>,
    /// Optional persistent registry — when wired, every state
    /// change (filter assigned, manually_managed flipped) is
    /// flushed so it survives restarts. Mirrors Go's
    /// `engine.workerStore` plumbing.
    worker_store: Mutex<Option<Arc<dyn quil_types::store::WorkerStore>>>,
    /// The shards whose data each worker's own store holds
    /// ([`WorkerManager::shard_data`]), read by the worker when its store
    /// opens, at each change of its binding and after each eviction that
    /// may have changed it.
    shard_data: Arc<ShardData>,
}

/// The shards whose data each worker's store holds, by core, and when a
/// failed read of each was last warned about.
#[derive(Default)]
struct ShardData {
    state: Mutex<ShardDataState>,
    warned: Mutex<HashMap<u32, std::time::Instant>>,
}

#[derive(Default)]
struct ShardDataState {
    held: HashMap<u32, Vec<(Vec<u8>, u64)>>,
    /// Per core, the latest read begun or withdrawal, numbered from `next`:
    /// a read records its result only while it is still the latest, so a
    /// read that ends after a newer one or after a withdrawal is dropped.
    latest: HashMap<u32, u64>,
    next: u64,
}

/// How often a worker's failed shard-data read is warned about again.
const SHARD_DATA_WARN_REPEAT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

impl ShardData {
    /// Record the shards whose data worker `core_id`'s store holds
    /// ([`crate::worker_payload_eviction::held_shards`]), for binding. The
    /// read takes a point read and leaf counts per lineage the store keeps,
    /// seconds under I/O pressure, so it runs on the runtime's blocking pool
    /// and the calling worker thread goes on at once; the handle ends with
    /// how it was recorded. A failed read leaves none recorded for it, and
    /// is warned about at once, then every [`SHARD_DATA_WARN_REPEAT`].
    fn publish(
        self: &Arc<Self>,
        core_id: u32,
        crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> tokio::task::JoinHandle<crate::worker_payload_eviction::Publish> {
        let ticket = self.begin(core_id);
        tokio::spawn(self.clone().read(core_id, ticket, crdt.clone()))
    }

    /// Number a read of worker `core_id`'s shards as its latest.
    fn begin(&self, core_id: u32) -> u64 {
        let mut state = self.state.lock().unwrap();
        state.next += 1;
        let ticket = state.next;
        state.latest.insert(core_id, ticket);
        ticket
    }

    /// The read numbered `ticket`, on the blocking pool, then its record.
    async fn read(
        self: Arc<Self>,
        core_id: u32,
        ticket: u64,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> crate::worker_payload_eviction::Publish {
        let started = std::time::Instant::now();
        let read =
            tokio::task::spawn_blocking(move || crate::worker_payload_eviction::held_shards(&crdt))
                .await
                .unwrap_or_else(|error| {
                    Err(QuilError::Internal(format!(
                        "shard data read task failed: {error}"
                    )))
                });
        self.record(core_id, ticket, read, started.elapsed())
    }

    fn record(
        &self,
        core_id: u32,
        ticket: u64,
        read: Result<crate::worker_payload_eviction::HeldShards>,
        took: std::time::Duration,
    ) -> crate::worker_payload_eviction::Publish {
        use crate::worker_payload_eviction::Publish;
        let mut state = self.state.lock().unwrap();
        if state.latest.get(&core_id) != Some(&ticket) {
            return Publish::Superseded { took };
        }
        let error = match read {
            Ok(read) => {
                let (lineages, held) = (read.lineages, read.held.len());
                state.held.insert(core_id, read.held);
                return Publish::Read {
                    lineages,
                    held,
                    took,
                };
            }
            Err(error) => error,
        };
        state.held.remove(&core_id);
        drop(state);
        let now = std::time::Instant::now();
        let mut warned = self.warned.lock().unwrap();
        if warned
            .get(&core_id)
            .is_none_or(|at| now.saturating_duration_since(*at) >= SHARD_DATA_WARN_REPEAT)
        {
            warned.insert(core_id, now);
            warn!(core_id, error = %quil_forest::storage_health::redact_paths(&error.to_string()),
                scope = "this node",
                action = "binding gives this worker no preference for the shards its store holds; check the \
                    worker's store if it persists",
                "this worker's shard data could not be read");
        }
        Publish::Failed { took }
    }

    /// Record none for worker `core_id`, while its store may lose shards; a
    /// read begun earlier records nothing.
    fn forget(&self, core_id: u32) {
        let mut state = self.state.lock().unwrap();
        state.next += 1;
        let ticket = state.next;
        state.latest.insert(core_id, ticket);
        state.held.remove(&core_id);
    }

    /// Whether shards are recorded for worker `core_id`.
    fn holds(&self, core_id: u32) -> bool {
        self.state.lock().unwrap().held.contains_key(&core_id)
    }

    fn snapshot(&self) -> HashMap<u32, Vec<(Vec<u8>, u64)>> {
        self.state.lock().unwrap().held.clone()
    }
}

/// One eviction run of worker `core_id` for `keep`, spawned on its thread's
/// runtime: the passes ([`crate::worker_payload_eviction::run_passes`]),
/// then a read of the shards its store holds, only where the passes may
/// have changed them or none is recorded, then one line on the run. Every
/// store read runs on the blocking pool, so the worker's thread keeps
/// voting meanwhile. `evicting` is set while it runs; a rebind meanwhile
/// withdraws the worker's record rather than read it, leaving the read to
/// this run's end.
async fn eviction_run<R>(
    core_id: u32,
    filter: String,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    keep: Vec<Vec<u8>>,
    storage: Option<(std::path::PathBuf, R)>,
    bound: Arc<dyn Fn() -> bool + Send + Sync>,
    shard_data: Arc<ShardData>,
    evicting: Arc<std::sync::atomic::AtomicBool>,
) -> (
    crate::worker_payload_eviction::PassReport,
    crate::worker_payload_eviction::Publish,
)
where
    R: Fn(&[u8]) -> bool + Send + 'static,
{
    let started = std::time::Instant::now();
    // Withdrawn just before the payload deletion: from then until the read
    // below, the store may hold a shard's forest without its payload.
    let table = shard_data.clone();
    let before_delete: Arc<dyn Fn() + Send + Sync> = Arc::new(move || table.forget(core_id));
    let report = crate::worker_payload_eviction::run_passes(
        core_id,
        filter.clone(),
        crdt.clone(),
        keep,
        storage,
        bound,
        before_delete,
    )
    .await;
    // In one poll with the check below: a rebind handled before it withdrew
    // the record, one handled after it reads the store itself.
    evicting.store(false, std::sync::atomic::Ordering::SeqCst);
    let publish = if report.changed || !shard_data.holds(core_id) {
        let ticket = shard_data.begin(core_id);
        shard_data.clone().read(core_id, ticket, crdt).await
    } else {
        crate::worker_payload_eviction::Publish::Skipped
    };
    crate::worker_payload_eviction::log_run(core_id, &filter, &report, &publish, started.elapsed());
    (report, publish)
}

impl ThreadWorkerManager {
    /// Auto-size the worker pool to the available CPU cores (minus one for
    /// the master). Equivalent to `new_with_count(0)`.
    pub fn new() -> Self {
        Self::new_with_count(0)
    }

    /// Create a thread-worker manager with an explicit worker count.
    ///
    /// `configured` is `engine.data_worker_count` from config:
    ///   * `> 0` → honor it exactly (the operator asked for N local workers);
    ///     this is what makes a `dataWorkerCount: 1` localnet run a single
    ///     worker instead of silently spinning up `cpu-1`.
    ///   * `<= 0` (the default) → auto-size to `available_parallelism - 1`,
    ///     at least one. Unlike the core list used for pinning, this honors
    ///     cgroup CPU quotas.
    ///
    /// This count is also the node's allocation capacity.
    pub fn new_with_count(configured: i32) -> Self {
        let layout = crate::worker_pinning::PinLayout::detect();
        let cpu_default = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(4)
            .saturating_sub(1)
            .max(1);
        let num_cores = if configured > 0 {
            configured as u32
        } else {
            cpu_default
        };

        let (master_tx, master_rx) = mpsc::channel(256);

        let (cores_per_node, workers_per_node) = layout.per_node(num_cores);
        info!(
            available_cores = layout.len(),
            configured_worker_count = configured,
            worker_cores = num_cores,
            pinning = layout.order(),
            numa_nodes = cores_per_node.len(),
            cores_per_node = %crate::worker_pinning::node_counts(&cores_per_node),
            workers_per_node = %crate::worker_pinning::node_counts(&workers_per_node),
            unpinned_workers = layout.unpinned(num_cores),
            "thread worker manager initialized"
        );

        Self {
            workers: Mutex::new(HashMap::new()),
            master_rx: Mutex::new(Some(master_rx)),
            master_tx,
            num_cores,
            layout,
            consensus_deps: Mutex::new(None),
            recovery_gate: Arc::default(),
            worker_store: Mutex::new(None),
            shard_data: Default::default(),
        }
    }

    /// Set consensus dependencies for worker threads. Call after
    /// the prover registry and frame prover are initialized.
    pub fn set_consensus_deps(&self, deps: WorkerConsensusDeps) {
        *self.consensus_deps.lock().unwrap() = Some(Arc::new(deps));
    }

    /// Wire a persistent worker registry. Once set, every
    /// `set_worker_filter` / `set_manually_managed` /
    /// `deallocate_worker` call also writes through to the store, so
    /// the operator's intent (manual mode + filter pin) carries
    /// across restarts.
    pub fn set_worker_store(&self, store: Arc<dyn quil_types::store::WorkerStore>) {
        *self.worker_store.lock().unwrap() = Some(store);
    }

    /// Cancel every worker thread and join each one that finishes within
    /// `deadline`, returning the core ids of those still running then. A
    /// worker closes its own RocksDB stores as its thread ends; returning
    /// from `main` first lets process exit destroy RocksDB's static state
    /// under that thread, which aborts ("pthread lock: Invalid argument").
    pub fn shutdown_workers(&self, deadline: std::time::Duration) -> Vec<u32> {
        let handles: Vec<(u32, JoinHandle<()>)> = self
            .workers
            .lock()
            .unwrap()
            .values_mut()
            .filter_map(|w| {
                w.cancel.cancel();
                w.handle.take().map(|handle| (w.core_id, handle))
            })
            .collect();
        join_within(handles, deadline)
    }

    /// Stop worker `core_id` so its own stores close, keeping its allocation
    /// (filter, allocated, manual mode): its engine is torn down first, as
    /// for an idle worker, so the master drops its routing, then its thread
    /// is cancelled and joined within `deadline`. Commands sent while it is
    /// stopped change only the allocation, which [`Self::restart_worker`]
    /// applies. Returns whether the thread ended.
    pub fn stop_worker(&self, core_id: u32, deadline: std::time::Duration) -> bool {
        let Some(tx) = self
            .workers
            .lock()
            .unwrap()
            .get(&core_id)
            .map(|w| w.tx.clone())
        else {
            return true;
        };
        if tx
            .try_send(MasterToWorker::Respawn {
                filter: Vec::new(),
                start_consensus: true,
            })
            .is_ok()
        {
            std::thread::sleep(ENGINE_TEARDOWN);
        }
        let handle = {
            let mut workers = self.workers.lock().unwrap();
            let Some(w) = workers.get_mut(&core_id) else {
                return true;
            };
            w.cancel.cancel();
            *w.execution_handle.lock().unwrap() = None;
            w.handle.take()
        };
        handle.is_none_or(|handle| join_within(vec![(core_id, handle)], deadline).is_empty())
    }

    /// Start a worker stopped by [`Self::stop_worker`] on a new thread, which
    /// reopens its own stores, and bind it to the allocation it has now. If
    /// the worker builder cannot reopen them, the thread ends at once rather
    /// than run the worker on the master's stores. A worker whose thread
    /// still runs is never replaced.
    pub fn restart_worker(&self, core_id: u32) -> Result<()> {
        match self.workers.lock().unwrap().get(&core_id) {
            None => {
                return Err(QuilError::InvalidArgument(format!(
                    "worker {core_id} has no state to restart"
                )))
            }
            Some(w)
                if w.handle
                    .as_ref()
                    .is_some_and(|handle| !handle.is_finished()) =>
            {
                return Err(QuilError::ExecutionUnavailable(format!(
                    "worker {core_id}'s thread still runs"
                )));
            }
            Some(_) => {}
        }
        let fresh = self.spawn_worker(core_id, true)?;
        self.mutate(core_id, move |w| {
            w.cancel = fresh.cancel;
            w.tx = fresh.tx;
            w.handle = fresh.handle;
            w.execution_handle = fresh.execution_handle;
            if !w.filter.is_empty() {
                let _ = w.tx.try_send(MasterToWorker::Respawn {
                    filter: w.filter.clone(),
                    start_consensus: w.allocated,
                });
            }
        });
        Ok(())
    }

    /// Whether worker `core_id`'s thread still runs (opening its stores, or
    /// serving).
    pub fn worker_running(&self, core_id: u32) -> bool {
        self.workers
            .lock()
            .unwrap()
            .get(&core_id)
            .and_then(|w| w.handle.as_ref())
            .is_some_and(|handle| !handle.is_finished())
    }

    /// Returns persisted worker state for the given core, when a
    /// store is wired and an entry exists.
    pub fn load_persisted(&self, core_id: u32) -> Option<quil_types::store::PersistedWorkerInfo> {
        self.worker_store
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|s| s.get_worker(core_id).ok().flatten())
    }

    /// All persisted entries (sorted by core_id). Empty when no
    /// store is wired.
    pub fn load_all_persisted(&self) -> Vec<quil_types::store::PersistedWorkerInfo> {
        self.worker_store
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|s| s.range_workers().ok())
            .unwrap_or_default()
    }

    fn persist_worker(&self, w: &WorkerState) {
        if let Some(store) = self.worker_store.lock().unwrap().as_ref() {
            let info = quil_types::store::PersistedWorkerInfo {
                core_id: w.core_id,
                filter: w.filter.clone(),
                manually_managed: w.manually_managed,
                allocated: w.allocated,
                pending_filter_frame: w.pending_filter_frame,
            };
            if let Err(e) = store.put_worker(&info) {
                tracing::warn!(
                    core_id = w.core_id,
                    error = %e,
                    "worker_store put failed"
                );
            }
        }
    }

    /// Take the master-side receiver. Call once during startup to get
    /// the channel for processing worker events.
    pub fn take_master_rx(&self) -> Option<mpsc::Receiver<WorkerToMaster>> {
        self.master_rx.lock().unwrap().take()
    }

    /// Number of worker cores available (total CPUs minus 1 for master).
    pub fn num_worker_cores(&self) -> u32 {
        self.num_cores
    }

    /// Spawn a worker thread pinned to the given core. The thread runs
    /// its own single-threaded tokio runtime and listens for commands
    /// on the `MasterToWorker` channel.
    /// `own_stores`: the worker restarts after a stop to reopen its stores,
    /// so it must not fall back to the master's when they do not open.
    fn spawn_worker(&self, core_id: u32, own_stores: bool) -> Result<WorkerState> {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel::<MasterToWorker>(32);
        let master_tx = self.master_tx.clone();
        let cancel_clone = cancel.clone();
        let consensus_deps = self.consensus_deps.lock().unwrap().clone();
        let recovery_gate = self.recovery_gate.clone();
        let execution_handle = Arc::new(Mutex::new(None::<crate::app_engine::AppEngineHandle>));
        let execution_slot = execution_handle.clone();
        let shard_data = self.shard_data.clone();
        let core = self.layout.core(core_id);
        let numa_node = self.layout.node(core_id);

        let handle = std::thread::Builder::new()
            .name(format!("worker-{}", core_id))
            .spawn(move || {
                // Pin before the worker allocates: its memory goes to the
                // NUMA node of the core that first touches it.
                let mut cpu = None;
                if let Some(core) = core {
                    if core_affinity::set_for_current(core) {
                        cpu = Some(core.id);
                    } else {
                        warn!(core_id, "failed to pin thread to core");
                    }
                }

                if let Some(deps) = consensus_deps.as_ref() {
                    if let Some(init) = deps.worker_init.as_ref() {
                        init(core_id);
                    }
                }

                // After `worker_init`, so a failure lands in this worker's log.
                run_falcon_self_test(core_id, cpu);

                // Confirms per-worker log routing is wired: this line
                // emits from the worker's OS thread and must land in
                // `worker-<core_id>.log`. If the file stays empty
                // after spawn, the routing is broken (thread-local
                // tag missing, file registry not populated, etc).
                info!(core_id, cpu, numa_node, "worker thread up");

                let worker_owned: Option<WorkerOwnedDeps> =
                    consensus_deps
                        .as_ref()
                        .and_then(|d| d.worker_state_builder.as_ref())
                        .and_then(|b| match b(core_id) {
                            Ok(o) => Some(o),
                            Err(e) if own_stores => {
                                tracing::error!(core_id,
                                    error = %quil_forest::storage_health::redact_paths(&e),
                                    "worker_state_builder failed");
                                None
                            }
                            Err(e) => {
                                tracing::error!(
                                    core_id,
                                    error = %e,
                                    "worker_state_builder failed; falling back to shared state",
                                );
                                None
                            }
                        });
                if own_stores && worker_owned.is_none()
                    && consensus_deps.as_ref().is_some_and(|d| d.worker_state_builder.is_some())
                {
                    tracing::error!(
                        core_id,
                        scope = "this node",
                        "worker could not reopen its own store after it was stopped; it stays stopped rather than \
                         run on the master's stores: restart the node"
                    );
                    return;
                }

                // Create per-thread tokio runtime
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to create worker tokio runtime");

                // A watchdog on another thread names what blocks this one
                // (worker_stall): the probe marks this thread's tasks and
                // synchronous sections, and the heartbeat stops while one
                // of them blocks it.
                let probe = ThreadProbe::new();
                let probe_installed = install_probe(probe.clone());
                crate::worker_stall::watch(core_id, &probe);
                rt.spawn(crate::worker_stall::heartbeat(Arc::downgrade(&probe), crate::worker_stall::HEARTBEAT));

                rt.block_on(probed(ProbeSection::WorkerLoop, async move {
                    if let Some(owned) = worker_owned.as_ref() {
                        shard_data.publish(core_id, &owned.hypergraph);
                    }
                    let mut current_filter: Vec<u8> = Vec::new();
                    let mut engine_cancel: Option<tokio_util::sync::CancellationToken> = None;
                    // The last engine's mempool and its application. A split or
                    // merge moves this worker to another shard of the same
                    // application; submissions the retired shard held (it
                    // drains before its flip) go on to the replacement's
                    // engine instead of being dropped with the old engine.
                    let mut retained_mempool: Option<(Vec<u8>, Arc<crate::message_collector::MessageCollector>)> = None;
                    // When the engine generation last changed: eviction waits for
                    // the previous engine's detached tasks to finish with its scope.
                    let mut bound_since = std::time::Instant::now();
                    let evicting = Arc::new(std::sync::atomic::AtomicBool::new(false));

                    // Per-worker memory tick. Each worker owns its own RocksDB
                    // (block cache + memtables + table readers) in this thread,
                    // invisible to the master's structural snapshot. Logging it
                    // here attributes the RocksDB share of process RSS per worker
                    // — the key number when a node running N workers OOMs.
                    let worker_db = worker_owned
                        .as_ref()
                        .and_then(|d| d.kv_db.clone());
                    let mut mem_tick =
                        tokio::time::interval(std::time::Duration::from_secs(60));
                    mem_tick.set_missed_tick_behavior(
                        tokio::time::MissedTickBehavior::Skip,
                    );

                    // Notify master we're ready
                    let _ = master_tx
                        .send(WorkerToMaster::Ready { core_id })
                        .await;

                    loop {
                        tokio::select! {
                            _ = mem_tick.tick() => {
                                if let Some(db) = worker_db.as_ref() {
                                    let bytes = db.approximate_memory_bytes();
                                    info!(
                                        core_id,
                                        worker_db_mb = bytes as f64 / (1024.0 * 1024.0),
                                        filter = hex::encode(&current_filter),
                                        "worker rocksdb memory",
                                    );
                                }
                            }
                            cmd = rx.recv() => {
                                match cmd {
                                    Some(MasterToWorker::Respawn { filter, start_consensus }) => {
                                        bound_since = std::time::Instant::now();
                                        probe.set_filter(&filter);
                                        // Retire telemetry before replacing the engine generation.
                                        *execution_slot.lock().unwrap() = None;
                                        // Stop existing engine if any
                                        if let Some(cancel) = engine_cancel.take() {
                                            cancel.cancel();
                                            // Give the engine a moment to clean up
                                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                        }
                                        // The shard it leaves holds data here. A running
                                        // eviction may still drop shards: its end reads them.
                                        if let Some(owned) = worker_owned.as_ref() {
                                            if evicting.load(std::sync::atomic::Ordering::SeqCst) {
                                                shard_data.forget(core_id);
                                            } else {
                                                shard_data.publish(core_id, &owned.hypergraph);
                                            }
                                        }

                                        if filter.is_empty() {
                                            info!(core_id, "worker idle (no filter)");
                                            current_filter.clear();
                                        } else if !start_consensus {
                                            // Filter binding only — engine
                                            // not started until allocation
                                            // becomes Active (mirrors
                                            // Go's worker.Allocated=false
                                            // state).
                                            info!(
                                                core_id,
                                                filter = hex::encode(&filter),
                                                "worker filter pinned (consensus deferred until Active)"
                                            );
                                            current_filter = filter.clone();
                                        } else {
                                            info!(
                                                core_id,
                                                filter = hex::encode(&filter),
                                                "worker assigned to shard"
                                            );
                                            current_filter = filter.clone();

                                            // Compute app address from filter
                                            let _app_address = quil_crypto::poseidon::hash_bytes_to_32(&filter)
                                                .map(|h| h.to_vec())
                                                .unwrap_or_default();

                                            // Spawn AppConsensusEngine on this thread's runtime
                                            let ec = tokio_util::sync::CancellationToken::new();
                                            engine_cancel = Some(ec.clone());
                                            let master_tx_clone = master_tx.clone();
                                            let filter_clone = filter.clone();
                                            let deps = consensus_deps.clone();
                                            let recovery_gate = recovery_gate.clone();
                                            let execution_slot = execution_slot.clone();
                                            let owned = worker_owned.clone();
                                            let application = filter[..filter.len().min(32)].to_vec();
                                            let mempool = match retained_mempool.take() {
                                                Some((retained_application, mempool)) if retained_application == application => {
                                                    // The new engine numbers its views from the start.
                                                    mempool.rebase_ranks();
                                                    info!(core_id, pending = mempool.total_pending(),
                                                        "carrying the previous shard's pending submissions to the new shard");
                                                    mempool
                                                }
                                                _ => Arc::new(crate::message_collector::MessageCollector::new()),
                                            };
                                            retained_mempool = Some((application, mempool.clone()));
                                            // TODO
                                            tokio::spawn(async move {
                                                info!(core_id, filter = hex::encode(&filter_clone), "app engine spawned");

                                                if let Some(ref deps) = deps {
                                                    // Per-worker state when wired; otherwise
                                                    // the master's shared state.
                                                    let clock_store = owned
                                                        .as_ref()
                                                        .map(|o| o.clock_store.clone())
                                                        .unwrap_or_else(|| deps.clock_store.clone());
                                                    let hypergraph = owned
                                                        .as_ref()
                                                        .map(|o| Some(o.hypergraph.clone()))
                                                        .unwrap_or_else(|| deps.hypergraph.clone());
                                                    let execution_engine = owned
                                                        .as_ref()
                                                        .map(|o| Some(o.execution_engine.clone()))
                                                        .unwrap_or_else(|| deps.execution_engine.clone());
                                                    let inclusion_prover = owned
                                                        .as_ref()
                                                        .map(|o| Some(o.inclusion_prover.clone()))
                                                        .unwrap_or_else(|| deps.inclusion_prover.clone());
                                                    let kv_db = owned
                                                        .as_ref()
                                                        .and_then(|o| o.kv_db.clone())
                                                        .or_else(|| deps.kv_db.clone());

                                                    // Create the AppConsensusEngine with full HotStuff integration
                                                    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
                                                    let engine_deps = crate::app_engine::AppEngineDeps {
                                                        delivery_frame_source: owned.as_ref().and_then(|o| o.delivery_frame_source.clone()),
                                                        clock_store,
                                                        // Global anchor ALWAYS comes from the master's
                                                        // shared store (`deps.clock_store`), which the
                                                        // frame poller fills with synced global frames.
                                                        // The worker-owned `clock_store` above holds only
                                                        // this shard's chain, so anchoring to it would give
                                                        // `anchor_gfn = 0` → legacy VDF path → no rewards.
                                                        global_anchor_store: Some(deps.clock_store.clone()),
                                                        global_hypergraph: deps.hypergraph.clone(),
                                                        prover_registry: deps.prover_registry.clone(),
                                                        frame_prover: deps.frame_prover.clone(),
                                                        // Each shard keeps its own mempool. Shared with the
                                                        // master's GLOBAL collector and every other shard on
                                                        // the node, a submission was pruned by whichever
                                                        // collection or GLOBAL finalization came first, and
                                                        // ranks (each shard's views, GLOBAL's frames) had no
                                                        // common meaning: routed bundles reached at most
                                                        // one shard per node.
                                                        message_collector: mempool,
                                                        fee_manager: deps.fee_manager.clone(),
                                                        local_prover_address: deps.local_prover_address.clone(),
                                                        local_bls_pubkey: deps.local_bls_pubkey.clone(),
                                                        bls_signer: (deps.bls_signer_factory)(),
                                                        reward_greedy: deps.reward_greedy,
                                                        min_active_provers_for_propose: deps.min_active_provers_for_propose,
                                                        coverage_publish: deps.coverage_publish.clone(),
                                                        hypergraph,
                                                        // Storage-attestation SOURCE = the MASTER's
                                                        // hypergraph (`deps.hypergraph`), which the
                                                        // master's forest-sync fills with the covered
                                                        // shard's committed coin data. The worker
                                                        // replicates FROM this into its own replica_store
                                                        // (per-prover PoRep possession). The per-worker
                                                        // `hypergraph` above only holds this shard's own
                                                        // materialized app-frames, so attesting from it
                                                        // would find no coins.
                                                        storage_source_hypergraph: deps.hypergraph.clone(),
                                                        topology: deps.topology.clone(),
                                                        execution_engine,
                                                        inclusion_prover,
                                                        kv_db,
                                                        app_consensus_cw: deps.app_consensus_cw,
                                                        db_config: deps.db_config.clone(),
                                                        // Per-worker consolidation hook (bound to this
                                                        // worker's CRDT/store by worker_state_builder).
                                                        unified_cutover_hook: owned
                                                            .as_ref()
                                                            .and_then(|o| o.unified_cutover_hook.clone()),
                                                    };
                                                    let (engine, app_handle) = crate::app_engine::AppConsensusEngine::new(
                                                        core_id,
                                                        filter_clone.clone(),
                                                        engine_deps,
                                                        event_tx,
                                                    );
                                                    *execution_slot.lock().unwrap() = Some(app_handle.clone());
                                                    let engine = engine.with_storage_history_source(
                                                        owned.as_ref().and_then(|o| o.storage_history_source.clone()),
                                                    ).with_outgoing_history_source(
                                                        owned.as_ref().and_then(|o| o.outgoing_history_source.clone()),
                                                    ).with_historical_committee_source(
                                                        owned.as_ref().and_then(|o| o.historical_committee_source.clone()),
                                                    ).with_global_anchor_source(
                                                        owned.as_ref().and_then(|o| o.global_anchor_source.clone()),
                                                    );

                                                    // Tell the master a shard engine just came online.
                                                    // The master uses this handle to route peer
                                                    // consensus / frame / prover / dispatch messages
                                                    // back to the worker thread.
                                                    let _ = master_tx_clone.send(
                                                        WorkerToMaster::ShardActivated {
                                                            core_id,
                                                            filter: filter_clone.clone(),
                                                            handle: app_handle.clone(),
                                                        }
                                                    ).await;

                                                    // Forward engine events to master AND self-loopback
                                                    // own proposals/votes/timeouts back to the engine's
                                                    // input. BlossomSub silently drops self-published
                                                    // messages, so without explicit loopback the
                                                    // proposer's own vote never reaches its own
                                                    // vote_aggregator and a 1-of-1 quorum (single-prover
                                                    // case) can never close — consensus stalls in
                                                    // rank-timeout loops indefinitely.
                                                    let master_tx_events = master_tx_clone.clone();
                                                    let loopback_handle = app_handle.clone();
                                                    let _filter_for_events = filter_clone.clone();
                                                    // Step-4 app-shard catch-up (AncestorSyncRequested): the
                                                    // per-worker archive-direct syncer + this shard's clock store
                                                    // (for the finalized-header pin), and a single-in-flight guard.
                                                    let sync_syncer =
                                                        owned.as_ref().and_then(|o| o.shard_syncer.clone());
                                                    let sync_clock =
                                                        owned.as_ref().map(|o| o.clock_store.clone());
                                                    let sync_in_progress = std::sync::Arc::new(
                                                        std::sync::atomic::AtomicBool::new(false),
                                                    );
                                                    // Whether this engine's archive recovery is
                                                    // withheld for a seat this node gives up.
                                                    let withheld = Arc::new(std::sync::atomic::AtomicBool::new(false));
                                                    let withheld_filter = filter_clone.clone();
                                                    tokio::spawn(probed(ProbeSection::EngineEvents, async move {
                                                        while let Some(event) = event_rx.recv().await {
                                                            match event {
                                                                crate::app_engine::AppEngineEvent::FrameProduced { filter, frame_number, frame_data } => {
                                                                    // Self-loopback: feed our own proposal back to
                                                                    // the engine's Frame input so the participant
                                                                    // observes its own proposal in the consensus
                                                                    // pipeline.
                                                                    loopback_handle.send(
                                                                        crate::app_engine::AppEngineMessage::Frame(
                                                                            frame_data.clone(),
                                                                        ),
                                                                    );
                                                                    let _ = master_tx_events.send(
                                                                        WorkerToMaster::FrameProduced {
                                                                            core_id,
                                                                            filter,
                                                                            frame_number,
                                                                            frame_data,
                                                                        }
                                                                    ).await;
                                                                }
                                                                crate::app_engine::AppEngineEvent::FullFrameProduced { filter, frame_number, frame_data } => {
                                                                    // Forward to the master to publish on
                                                                    // shard_frame_bitmask (no loopback — the
                                                                    // producing engine already self-materialized).
                                                                    let _ = master_tx_events.send(
                                                                        WorkerToMaster::FullFrameProduced {
                                                                            core_id,
                                                                            filter,
                                                                            frame_number,
                                                                            frame_data,
                                                                        }
                                                                    ).await;
                                                                }
                                                                crate::app_engine::AppEngineEvent::VoteProduced { filter, vote_data } => {
                                                                    // Self-loopback so own vote reaches own
                                                                    // vote_aggregator (critical for single-prover
                                                                    // 1-of-1 QC formation).
                                                                    loopback_handle.send(
                                                                        crate::app_engine::AppEngineMessage::Consensus(
                                                                            vote_data.clone(),
                                                                        ),
                                                                    );
                                                                    let _ = master_tx_events.send(
                                                                        WorkerToMaster::VoteProduced {
                                                                            core_id,
                                                                            filter,
                                                                            vote_data,
                                                                        }
                                                                    ).await;
                                                                }
                                                                crate::app_engine::AppEngineEvent::TimeoutProduced { filter, timeout_data } => {
                                                                    loopback_handle.send(
                                                                        crate::app_engine::AppEngineMessage::Consensus(
                                                                            timeout_data.clone(),
                                                                        ),
                                                                    );
                                                                    let _ = master_tx_events.send(
                                                                        WorkerToMaster::TimeoutProduced {
                                                                            core_id,
                                                                            filter,
                                                                            timeout_data,
                                                                        }
                                                                    ).await;
                                                                }
                                                                crate::app_engine::AppEngineEvent::ShardFrameFinalized { filter, header_canonical_bytes } => {
                                                                    let _ = master_tx_events.send(
                                                                        WorkerToMaster::ShardFrameFinalized {
                                                                            core_id,
                                                                            filter,
                                                                            header_canonical_bytes,
                                                                        }
                                                                    ).await;
                                                                }
                                                                crate::app_engine::AppEngineEvent::CwOut { filter, channel, bytes, recipients } => {
                                                                    let _ = master_tx_events.send(
                                                                        WorkerToMaster::CwConsensus {
                                                                            core_id,
                                                                            filter,
                                                                            channel,
                                                                            bytes,
                                                                            recipients,
                                                                        }
                                                                    ).await;
                                                                }
                                                                crate::app_engine::AppEngineEvent::AncestorSyncRequested { filter, .. }
                                                                | crate::app_engine::AppEngineEvent::ShardDataBootstrapRequested { filter } => {
                                                                    let (Some(syncer), Some(clock)) =
                                                                        (sync_syncer.clone(), sync_clock.clone())
                                                                    else { continue };
                                                                    if sync_in_progress.swap(true, std::sync::atomic::Ordering::SeqCst) {
                                                                        continue;
                                                                    }
                                                                    match clock.get_latest_shard_clock_frame(&filter) {
                                                                        Ok(_) | Err(quil_types::error::QuilError::NotFound(_)) => {}
                                                                        Err(error) => {
                                                                            warn!(filter = %hex::encode(&filter), %error, "cannot determine local shard lineage for sync");
                                                                            sync_in_progress.store(false, std::sync::atomic::Ordering::SeqCst);
                                                                            continue;
                                                                        }
                                                                    };
                                                                    let lb = loopback_handle.clone();
                                                                    let flag = sync_in_progress.clone();
                                                                    struct ReleaseSyncFlag(Arc<std::sync::atomic::AtomicBool>);
                                                                    impl Drop for ReleaseSyncFlag {
                                                                        fn drop(&mut self) {
                                                                            self.0.store(false, std::sync::atomic::Ordering::SeqCst);
                                                                        }
                                                                    }
                                                                    let release_sync = ReleaseSyncFlag(flag);
                                                                    // Nothing renews a seat this node gives up, so
                                                                    // the recovery asks before it reads an archive.
                                                                    let gate = recovery_gate.clone();
                                                                    let withheld = withheld.clone();
                                                                    tokio::spawn(probed(ProbeSection::ArchiveRecovery, async move {
                                                                        let _release_sync = release_sync;
                                                                        // A node's workers share its archive identity and
                                                                        // so its per-peer read slots: a few recover at a
                                                                        // time rather than all failing busy together. A
                                                                        // replay onto held frames goes before checkpoint
                                                                        // installs; a blocked successor session or an
                                                                        // owed re-anchor goes first. A tree install past
                                                                        // the hold limit hands its turn back and queues
                                                                        // again (recovery_turns).
                                                                        let lineage = || match clock.get_latest_shard_clock_frame(&filter) {
                                                                            Ok(frame) => Ok(Some(frame)),
                                                                            Err(quil_types::error::QuilError::NotFound(_)) => Ok(None),
                                                                            Err(error) => Err(error),
                                                                        };
                                                                        // Without a frame of the shard the recovery
                                                                        // installs it, which a departing seat skips.
                                                                        let given_up = || recovery_withheld(
                                                                            &gate, &withheld, core_id, &filter, matches!(lineage(), Ok(None)),
                                                                        );
                                                                        let _ = crate::prover_tree_syncer::recover_in_turns(
                                                                            &crate::recovery_turns::SHARD_RECOVERY_TURNS, syncer.as_ref(), &filter,
                                                                            core_id, &lb, lb.execution_record(), &lineage, given_up,
                                                                        ).await;
                                                                    }));
                                                                }
                                                                _ => {
                                                                    // Equivocation/Halted/ParentSealed —
                                                                    // informational; engine handles them internally
                                                                    // or they require no master mediation in local mode.
                                                                    debug!(core_id, "engine event: {:?}", event);
                                                                }
                                                            }
                                                        }
                                                        if withheld.load(std::sync::atomic::Ordering::Relaxed) {
                                                            info!(core_id, filter = %hex::encode(&withheld_filter),
                                                                scope = "this node's worker",
                                                                "archive recovery no longer withheld: the worker's engine on the seat \
                                                                 this node gives up stopped");
                                                        }
                                                    }));

                                                    // Spawn the engine as its own task so it schedules
                                                    // independently of the cancellation watcher and any
                                                    // tasks spawned by the inner consensus event loop.
                                                    // Sharing a task via `tokio::select!` here was making
                                                    // the engine's own select starve under load.
                                                    let signer_factory = deps.bls_signer_factory.clone();
                                                    let mut engine_handle = tokio::spawn(probed(ProbeSection::AppEngine, async move {
                                                        engine.run(signer_factory).await;
                                                    }));
                                                    tokio::select! {
                                                        _ = ec.cancelled() => {
                                                            info!(core_id, "app engine cancelled");
                                                            engine_handle.abort();
                                                        }
                                                        _ = &mut engine_handle => {
                                                            info!(core_id, "app engine exited");
                                                        }
                                                    }
                                                    app_handle.execution_state("stopped", "engine exited");
                                                    // Tell the master to evict the routing entry +
                                                    // unsubscribe from per-shard bitmasks.
                                                    let _ = master_tx_clone.send(
                                                        WorkerToMaster::ShardDeactivated {
                                                            core_id,
                                                            filter: filter_clone.clone(),
                                                        }
                                                    ).await;
                                                } else {
                                                    // No consensus deps — heartbeat-only mode
                                                    loop {
                                                        tokio::select! {
                                                            _ = ec.cancelled() => {
                                                                info!(core_id, "app engine cancelled (heartbeat mode)");
                                                                break;
                                                            }
                                                            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                                                                let _ = master_tx_clone.send(
                                                                    WorkerToMaster::ShardHeartbeat {
                                                                        core_id,
                                                                        filter: filter_clone.clone(),
                                                                    }
                                                                ).await;
                                                            }
                                                        }
                                                    }
                                                }
                                            });
                                        }
                                        let _ = master_tx
                                            .send(WorkerToMaster::Ready { core_id })
                                            .await;
                                    }
                                    Some(MasterToWorker::EvictPayload { keep }) => {
                                        let Some(owned) = worker_owned.clone() else { continue };
                                        let serving = execution_slot.lock().unwrap().as_ref()
                                            .is_some_and(|h| h.filter == current_filter && h.is_running());
                                        if let Some(reason) = crate::worker_payload_eviction::deferral(
                                            &current_filter, &keep, serving, bound_since.elapsed()) {
                                            info!(core_id, reason, "worker payload eviction deferred");
                                            continue;
                                        }
                                        if evicting.swap(true, std::sync::atomic::Ordering::SeqCst) {
                                            continue;
                                        }
                                        let flag = evicting.clone();
                                        let crdt = owned.hypergraph.clone();
                                        let filter = hex::encode(&current_filter);
                                        let storage = consensus_deps.clone().and_then(|deps|
                                            crate::app_engine::cw_app_storage_base(&deps.db_config, core_id).map(|base| (base,
                                                move |shard: &[u8]| deps.hypergraph.as_ref().is_none_or(|global|
                                                    crate::app_handoff::retains_worker(global, shard, &deps.local_bls_pubkey)))));
                                        // Still serving the binding the passes start for: a
                                        // rebind retires the engine first.
                                        let (slot, binding) = (execution_slot.clone(), current_filter.clone());
                                        let bound: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move ||
                                            slot.lock().unwrap().as_ref().is_some_and(|h| h.filter == binding && h.is_running()));
                                        tokio::spawn(probed(ProbeSection::PayloadEviction, eviction_run(
                                            core_id, filter, crdt, keep, storage, bound, shard_data.clone(), flag)));
                                    }
                                    Some(MasterToWorker::CreateJoinProof {
                                        challenge,
                                        difficulty,
                                        ids,
                                        prover_index,
                                        reply,
                                    }) => {
                                        // VDF proof computation on this core-pinned thread.
                                        // Uses the vdf crate directly (same as WesolowskiFrameProver).
                                        let ids_vec: Vec<Vec<u8>> = ids;
                                        let proof = vdf::wesolowski_solve_multi(
                                            2048, &challenge, difficulty, &ids_vec, prover_index,
                                        );
                                        let _ = reply.send(Ok(proof));
                                    }
                                    None => {
                                        info!(core_id, "worker channel closed");
                                        break;
                                    }
                                }
                            }
                            _ = cancel_clone.cancelled() => {
                                info!(core_id, "worker shutdown requested");
                                // Stop engine if running
                                if let Some(cancel) = engine_cancel.take() {
                                    cancel.cancel();
                                }
                                break;
                            }
                        }
                    }
                }));
                drop(probe_installed);
            })
            .map_err(|e| QuilError::Internal(format!("failed to spawn worker thread: {}", e)))?;

        Ok(WorkerState {
            core_id,
            filter: Vec::new(),
            pending_filter_frame: 0,
            manually_managed: false,
            allocated: false,
            cancel,
            tx,
            handle: Some(handle),
            execution_handle,
        })
    }
}

impl ThreadWorkerManager {
    /// Mutate a worker's in-memory state under lock, snapshot the
    /// post-mutation state, drop the lock, then persist the snapshot.
    /// All five setter methods follow this exact pattern; centralizing
    /// here ensures any future setter inherits the snapshot+persist
    /// contract correctly. Returns `None` if the worker doesn't
    /// exist, otherwise the snapshot for caller inspection.
    fn mutate<F>(&self, core_id: u32, f: F) -> Option<WorkerState>
    where
        F: FnOnce(&mut WorkerState),
    {
        let snapshot = {
            let mut workers = self.workers.lock().unwrap();
            workers.get_mut(&core_id).map(|w| {
                f(w);
                snapshot_state(w)
            })
        };
        if let Some(snap) = &snapshot {
            self.persist_worker(snap);
        }
        snapshot
    }
}

impl WorkerManager for ThreadWorkerManager {
    fn allocation_capacity(&self) -> Result<usize> {
        Ok(self.num_cores as usize)
    }

    fn set_recovery_gate(&self, gate: crate::worker_allocator::RecoveryGate) {
        *self
            .recovery_gate
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(gate);
    }

    fn evict_payload(&self, core_id: u32, keep: Vec<Vec<u8>>) -> Result<()> {
        let workers = self
            .workers
            .lock()
            .map_err(|_| QuilError::Internal("worker table poisoned".into()))?;
        let worker = workers
            .get(&core_id)
            .ok_or_else(|| QuilError::InvalidArgument("eviction worker missing".into()))?;
        worker
            .tx
            .try_send(MasterToWorker::EvictPayload { keep })
            .map_err(|e| QuilError::ExecutionUnavailable(format!("payload eviction: {e}")))
    }

    fn set_worker_filter(&self, core_id: u32, filter: &[u8], start_consensus: bool) -> Result<()> {
        // Spawn-if-missing happens before mutate because spawn_worker
        // returns Result and we want to surface that error path.
        {
            let mut workers = self.workers.lock().unwrap();
            if !workers.contains_key(&core_id) {
                let state = self.spawn_worker(core_id, false)?;
                workers.insert(core_id, state);
            }
        }
        let owned_filter = filter.to_vec();
        self.mutate(core_id, move |w| {
            w.filter = owned_filter.clone();
            // A worker running consensus is allocated. Left unset, the
            // allocator's next pass took an Active allocation bound this way
            // for a Joining→Active transition and restarted the engine it had
            // just started, which can lose a finalized frame.
            w.allocated = start_consensus && !owned_filter.is_empty();
            let _ = w.tx.try_send(MasterToWorker::Respawn {
                filter: owned_filter,
                start_consensus,
            });
        });
        Ok(())
    }

    fn deallocate_worker(&self, core_id: u32) -> Result<()> {
        // Drop the filter binding and stop any running consensus
        // engine, but KEEP the worker thread alive in the HashMap so
        // it shows up in `range_workers()` as Idle. Without this,
        // every expired-Joining / Rejected / Kicked allocation
        // disappeared from `GetWorkerInfo` permanently and the TUI
        // top-pane lost rows it should have kept as "Idle".
        self.mutate(core_id, |w| {
            w.filter.clear();
            w.allocated = false;
            w.pending_filter_frame = 0;
            // Send empty-filter Respawn so the worker tears down its
            // engine and goes idle without exiting the loop.
            let _ = w.tx.try_send(MasterToWorker::Respawn {
                filter: Vec::new(),
                start_consensus: true,
            });
        });
        Ok(())
    }

    /// Cores above the configured count drain: the count is the capacity,
    /// and a record left from a larger configuration keeps serving only
    /// until its seat departs.
    fn is_draining(&self, core_id: u32) -> bool {
        core_id > self.num_cores
    }

    /// Remove an idle draining worker from the pool and its persisted record,
    /// cancel its thread and join it off the caller's thread, so a lifecycle
    /// tick does not wait for the worker's stores to close. Logs once, when
    /// the thread has ended (or has not within [`RETIRE_DEADLINE`]).
    fn retire_worker(&self, core_id: u32) -> Result<()> {
        if !self.is_draining(core_id) {
            return Err(QuilError::InvalidArgument(format!(
                "worker {core_id} is within the configured count of {}",
                self.num_cores
            )));
        }
        let (state, running) = {
            let mut workers = self.workers.lock().unwrap();
            match workers.get(&core_id) {
                None => return Ok(()),
                Some(w) if !w.filter.is_empty() || w.pending_filter_frame != 0 => {
                    return Err(QuilError::InvalidArgument(format!(
                        "worker {core_id} still holds a seat or a pending join"
                    )));
                }
                Some(_) => {}
            }
            let state = workers.remove(&core_id).expect("checked above");
            (state, workers.len())
        };
        state.cancel.cancel();
        self.shard_data.forget(core_id);
        let deleted = match self.worker_store.lock().unwrap().as_ref() {
            Some(store) => store.delete_worker(core_id).map_err(|e| e.to_string()),
            None => Ok(()),
        };
        if let Err(error) = &deleted {
            warn!(core_id, %error, scope = "this node",
                action = "none needed: an idle record above the configured count is not restored at startup",
                "retired draining worker's persisted record could not be deleted");
        }
        let configured = self.num_cores;
        let join = move || {
            let started = std::time::Instant::now();
            let ended = state.handle.is_none_or(|handle| {
                join_within(vec![(core_id, handle)], RETIRE_DEADLINE).is_empty()
            });
            if ended {
                info!(core_id, configured, running, waited_ms = started.elapsed().as_millis() as u64,
                    scope = "this node",
                    "draining worker retired: it was above the configured worker count and held no seat or \
                     join, so its thread stopped and its record was removed; its store stays on disk");
            } else {
                warn!(core_id, configured, running, waited_secs = RETIRE_DEADLINE.as_secs(), scope = "this node",
                    action = "it ends when its stores close; report it if the worker still runs after a restart",
                    "draining worker removed from the pool, but its thread has not ended");
            }
        };
        if let Err(error) = std::thread::Builder::new()
            .name(format!("retire-worker-{core_id}"))
            .spawn(join)
        {
            warn!(core_id, %error, scope = "this node", "could not start the thread that waits for a retired worker");
        }
        Ok(())
    }

    fn shard_data(&self) -> HashMap<u32, Vec<(Vec<u8>, u64)>> {
        self.shard_data.snapshot()
    }

    fn check_workers_connected(&self) -> Result<Vec<u32>> {
        let workers = self.workers.lock().unwrap();
        Ok(workers.keys().copied().collect())
    }

    fn worker_execution(&self) -> Vec<(u32, Vec<u8>, quil_types::proto::node::WorkerExecution)> {
        self.workers
            .lock()
            .unwrap()
            .values()
            .filter_map(|w| {
                let slot = w.execution_handle.lock().unwrap();
                let h = slot.as_ref()?;
                // A queued rebind must never attribute the previous engine to the new filter.
                (h.filter == w.filter).then(|| (w.core_id, w.filter.clone(), h.execution()))
            })
            .collect()
    }

    fn range_workers(&self) -> Result<Vec<WorkerInfo>> {
        let workers = self.workers.lock().unwrap();
        Ok(workers
            .values()
            .map(|w| WorkerInfo {
                core_id: w.core_id,
                filter: w.filter.clone(),
                available_storage: 0,
                total_storage: 0,
                manually_managed: w.manually_managed,
                pending_filter_frame: w.pending_filter_frame,
                allocated: w.allocated,
            })
            .collect())
    }

    fn respawn_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
        self.allocate_worker(core_id, filter)
    }

    fn set_pending_filter_frame(&self, core_id: u32, frame: u64) -> Result<()> {
        self.mutate(core_id, |w| w.pending_filter_frame = frame);
        Ok(())
    }

    fn set_manually_managed(&self, core_id: u32, manually_managed: bool) -> Result<()> {
        let mut changed = false;
        let snap = self.mutate(core_id, |w| {
            changed = w.manually_managed != manually_managed;
            w.manually_managed = manually_managed;
        });
        if changed && snap.is_some() {
            // Mode flips are operator-driven and rare — log at info
            // so the toggle is visible in operator diagnostics.
            info!(
                core_id,
                mode = if manually_managed { "manual" } else { "auto" },
                "worker management mode changed"
            );
        }
        Ok(())
    }

    fn set_allocated(&self, core_id: u32, allocated: bool) -> Result<()> {
        self.mutate(core_id, |w| w.allocated = allocated);
        Ok(())
    }

    fn shutdown(&self, deadline: std::time::Duration) -> Vec<u32> {
        self.shutdown_workers(deadline)
    }
}

/// Capture the persistable subset of a `WorkerState` while we hold
/// the lock. The struct returned is `Send` and can outlive the
/// mutex guard, letting `persist_worker` write through without
/// re-acquiring the lock.
fn snapshot_state(w: &WorkerState) -> WorkerState {
    WorkerState {
        core_id: w.core_id,
        filter: w.filter.clone(),
        pending_filter_frame: w.pending_filter_frame,
        manually_managed: w.manually_managed,
        allocated: w.allocated,
        cancel: w.cancel.clone(),
        tx: w.tx.clone(),
        // Don't move/clone the join handle — it's tied to the live
        // worker thread and the snapshot is a read-only view.
        handle: None,
        execution_handle: w.execution_handle.clone(),
    }
}

/// Join each thread that finishes within `deadline`; return the ids of the
/// rest, which are left detached.
fn join_within(mut handles: Vec<(u32, JoinHandle<()>)>, deadline: std::time::Duration) -> Vec<u32> {
    let started = std::time::Instant::now();
    loop {
        let (finished, running): (Vec<_>, Vec<_>) =
            handles.into_iter().partition(|(_, h)| h.is_finished());
        for (core_id, handle) in finished {
            if handle.join().is_err() {
                warn!(core_id, "worker thread panicked while stopping");
            }
        }
        handles = running;
        if handles.is_empty() || started.elapsed() >= deadline {
            return handles.into_iter().map(|(core_id, _)| core_id).collect();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Messages the worker's startup Falcon self-test signs.
const FALCON_SELF_TEST_MESSAGES: u32 = 8;
/// FN-DSA context of the self-test signatures, apart from every consensus domain.
const FALCON_SELF_TEST_DOMAIN: &[u8] = b"quil-worker-self-test";

/// Sign the self-test messages and count the signatures that fail to verify
/// (or that `sign` fails to produce).
fn falcon_self_test_failures(
    mut sign: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    verify: impl Fn(&[u8], &[u8]) -> bool,
) -> u32 {
    (0..FALCON_SELF_TEST_MESSAGES)
        .filter(|i| {
            let msg = format!("quilibrium worker falcon self-test {i}");
            !sign(msg.as_bytes()).is_some_and(|sig| verify(msg.as_bytes(), &sig))
        })
        .count() as u32
}

/// Check that this worker's core signs valid Falcon signatures. Falcon signing
/// runs on floating point while verification is integer-only, so a core that
/// miscomputes floating point signs invalid signatures it can still detect;
/// such a worker fails every archive handshake and casts votes nobody counts.
/// Key generation is fixed-point integer code, so the shared test key is valid
/// whichever thread generates it.
fn run_falcon_self_test(core_id: u32, cpu: Option<usize>) {
    use quil_types::crypto::Signer as _;
    static KEY: std::sync::OnceLock<quil_crypto::FalconSigner> = std::sync::OnceLock::new();
    let key = KEY.get_or_init(quil_crypto::FalconSigner::generate);
    let failures = falcon_self_test_failures(
        |m| key.sign_with_domain(m, FALCON_SELF_TEST_DOMAIN).ok(),
        |m, sig| quil_crypto::falcon_verify(key.public_key(), sig, m, FALCON_SELF_TEST_DOMAIN),
    );
    if failures > 0 {
        tracing::error!(
            core_id,
            cpu,
            failures,
            attempts = FALCON_SELF_TEST_MESSAGES,
            "CPU core {} signs invalid Falcon signatures: this worker cannot connect to \
             archives or cast valid votes. The cause is the CPU core (hardware fault or \
             unstable overclock/undervolt): test that core, e.g. with a per-core stress \
             test, or exclude it from the node's workers",
            cpu.unwrap_or(core_id as usize),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allocator's recovery gate reaches this manager's recovery path,
    /// at the frame the allocator last reconciled at: nothing is withheld
    /// before it is installed or before the first reconcile; then a seat this
    /// node gives up is, until the seat is served again.
    #[test]
    fn the_allocators_recovery_gate_reaches_thread_workers() {
        use quil_types::consensus::{
            epoch_length_frames, ProverAllocationInfo, ProverInfo, ProverStatus,
        };
        use std::sync::atomic::{AtomicBool, Ordering};
        let e = epoch_length_frames();
        let filter = vec![3u8; 32];
        let manager = Arc::new(ThreadWorkerManager::new_with_count(1));
        let withheld = AtomicBool::new(false);
        assert!(
            !recovery_withheld(&manager.recovery_gate, &withheld, 1, &filter, false),
            "no gate installed"
        );
        let lapsed = ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: filter.clone(),
            rejection_filter: vec![],
            join_frame_number: 1,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 2,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 100,
            last_signed_frame_number: 0,
            epoch: 2,
            ring: 0,
            vertex_address: vec![],
        };
        let prover = ProverInfo {
            public_key: vec![0xBB; 585],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![lapsed],
            available_storage: 0,
            seniority: 100,
            delegate_address: vec![],
        };
        let allocator = Arc::new(crate::worker_allocator::WorkerAllocator::new(
            manager.clone(),
            Arc::new(crate::test_support::TestProverRegistry::with_prover(prover)),
            vec![0xAA; 32],
        ));
        allocator.install_recovery_gate();
        assert!(
            !recovery_withheld(&manager.recovery_gate, &withheld, 1, &filter, false),
            "before the first reconcile"
        );
        allocator.on_new_frame(3 * e + 5).unwrap();
        assert!(
            !recovery_withheld(&manager.recovery_gate, &withheld, 1, &filter, false),
            "in its recovery epoch"
        );
        allocator.on_new_frame(20 * e + 5).unwrap();
        assert!(
            recovery_withheld(&manager.recovery_gate, &withheld, 1, &filter, false),
            "lapsed 18 epochs"
        );
        assert!(withheld.load(Ordering::Relaxed));
        // A renewal of the seat starts: it is served again.
        let renewal = allocator
            .submission_attempts
            .begin(
                std::slice::from_ref(&filter),
                20 * e + 5,
                crate::submission_attempts::OpKind::Confirm,
            )
            .unwrap();
        assert!(
            !recovery_withheld(&manager.recovery_gate, &withheld, 1, &filter, false),
            "its renewal runs"
        );
        assert!(!withheld.load(Ordering::Relaxed), "withholding ended");
        drop(renewal);
    }

    /// A worker holding no frame of a seat whose leave is confirmed installs
    /// nothing for it when the install would end after the seat departs; one
    /// holding frames of it still replays them, a seat whose leave is
    /// unconfirmed still installs, and nothing is withheld before the first
    /// reconcile.
    #[test]
    fn a_cold_install_of_a_departing_seat_is_withheld() {
        use quil_types::consensus::{
            epoch_length_frames, ProverAllocationInfo, ProverInfo, ProverStatus,
        };
        use std::sync::atomic::AtomicBool;
        let e = epoch_length_frames();
        let filter = vec![3u8; 32];
        let leaving = |confirm: u64| ProverAllocationInfo {
            status: ProverStatus::Leaving,
            confirmation_filter: filter.clone(),
            rejection_filter: vec![],
            join_frame_number: 1,
            leave_frame_number: 10 * e + 3,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 2,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: confirm,
            leave_reject_frame_number: 0,
            last_active_frame_number: 100,
            last_signed_frame_number: 0,
            epoch: 11,
            ring: 0,
            vertex_address: vec![],
        };
        // Installing this many leaves outlasts the notice left at 11e+9.
        let leaves = 2 * e * quil_types::consensus::ideal_frame_time_ms_at(11 * e + 9) / 1000
            * crate::worker_allocator::FASTEST_INSTALL_LEAVES_PER_SEC;
        let gate_for = |allocation: ProverAllocationInfo, published: u64| {
            let manager = Arc::new(ThreadWorkerManager::new_with_count(1));
            let prover = ProverInfo {
                public_key: vec![0xBB; 585],
                address: vec![0xAA; 32],
                status: ProverStatus::Active,
                kick_frame_number: 0,
                allocations: vec![allocation],
                available_storage: 0,
                seniority: 100,
                delegate_address: vec![],
            };
            let allocator = Arc::new(crate::worker_allocator::WorkerAllocator::new(
                manager.clone(),
                Arc::new(crate::test_support::TestProverRegistry::with_prover(prover)),
                vec![0xAA; 32],
            ));
            allocator.install_recovery_gate();
            allocator.publish_allocation_priority_with_evidence(
                published,
                vec![(filter.clone(), false, 1.into())],
                std::collections::HashMap::from([(
                    filter.clone(),
                    crate::worker_allocator::AllocationPriorityEvidence::sized(published, leaves),
                )]),
            );
            (manager, allocator)
        };
        let withheld = AtomicBool::new(false);
        let (manager, allocator) = gate_for(leaving(11 * e + 4), 11 * e + 9);
        assert!(
            !recovery_withheld(&manager.recovery_gate, &withheld, 1, &filter, true),
            "before the first reconcile"
        );
        allocator.on_new_frame(11 * e + 9).unwrap();
        assert!(
            recovery_withheld(&manager.recovery_gate, &withheld, 1, &filter, true),
            "a cold install of a departing seat"
        );
        let replay = AtomicBool::new(false);
        assert!(
            !recovery_withheld(&manager.recovery_gate, &replay, 1, &filter, false),
            "a replay onto held frames of a departing seat"
        );
        let (manager, allocator) = gate_for(leaving(0), 10 * e + 9);
        allocator.on_new_frame(10 * e + 9).unwrap();
        let unconfirmed = AtomicBool::new(false);
        assert!(
            !recovery_withheld(&manager.recovery_gate, &unconfirmed, 1, &filter, true),
            "an unconfirmed leave still installs"
        );
    }

    #[test]
    fn join_within_waits_for_finishing_threads_and_reports_the_rest() {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = closed.clone();
        let slow = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let stuck = std::thread::spawn(move || {
            let _ = wait.recv();
        });
        let running = join_within(
            vec![(1, slow), (2, stuck)],
            std::time::Duration::from_secs(1),
        );
        assert!(
            closed.load(std::sync::atomic::Ordering::SeqCst),
            "a thread finishing within the deadline is joined"
        );
        assert_eq!(
            running,
            vec![2],
            "a thread still running at the deadline is reported"
        );
        drop(release);
    }

    #[tokio::test]
    async fn shutdown_workers_stops_and_joins_every_worker() {
        let mgr = ThreadWorkerManager::new();
        let _rx = mgr.take_master_rx().unwrap();
        mgr.allocate_worker(1, b"test-filter").unwrap();
        mgr.allocate_worker(2, b"other-filter").unwrap();
        let running = tokio::task::spawn_blocking(move || {
            mgr.shutdown_workers(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap();
        assert!(running.is_empty(), "workers still running: {running:?}");
        #[cfg(target_os = "linux")]
        {
            // pthread_join returns once the kernel clears the thread's id,
            // before it releases the task, so a joined thread can stay listed
            // for a moment; by then it carries PF_EXITING. A thread that was
            // never joined is still running without it.
            const PF_EXITING: u64 = 0x4;
            let names: Vec<String> = std::fs::read_dir("/proc/self/task")
                .unwrap()
                .filter_map(|task| {
                    let path = task.ok()?.path();
                    let name = std::fs::read_to_string(path.join("comm"))
                        .ok()?
                        .trim()
                        .to_string();
                    let stat = std::fs::read_to_string(path.join("stat")).ok()?;
                    let flags: u64 = stat
                        .rsplit_once(')')?
                        .1
                        .split_whitespace()
                        .nth(6)?
                        .parse()
                        .ok()?;
                    (flags & PF_EXITING == 0).then_some(name)
                })
                .collect();
            assert!(
                !names
                    .iter()
                    .any(|name| name == "worker-1" || name == "worker-2"),
                "a joined worker thread is gone: {names:?}"
            );
        }
    }

    /// A stopped worker's thread ends and its allocation stays; restarted, it
    /// runs on a new thread with the allocation it has then.
    #[tokio::test]
    async fn a_stopped_worker_restarts_with_its_allocation() {
        let mgr = Arc::new(ThreadWorkerManager::new());
        let mut rx = mgr.take_master_rx().unwrap();
        async fn ready(rx: &mut mpsc::Receiver<WorkerToMaster>) -> bool {
            let wait = std::time::Duration::from_secs(5);
            loop {
                match tokio::time::timeout(wait, rx.recv()).await {
                    Ok(Some(WorkerToMaster::Ready { core_id: 1 })) => return true,
                    Ok(Some(_)) => continue,
                    _ => return false,
                }
            }
        }
        mgr.set_worker_filter(1, b"active-filter", true).unwrap();
        assert!(ready(&mut rx).await);
        let stopping = mgr.clone();
        let stopped = tokio::task::spawn_blocking(move || {
            stopping.stop_worker(1, std::time::Duration::from_secs(5))
        });
        assert!(stopped.await.unwrap(), "the worker thread ends");
        #[cfg(target_os = "linux")]
        {
            let running = std::fs::read_dir("/proc/self/task")
                .unwrap()
                .filter_map(|task| {
                    let path = task.ok()?.path();
                    let name = std::fs::read_to_string(path.join("comm")).ok()?;
                    let stat = std::fs::read_to_string(path.join("stat")).ok()?;
                    let flags: u64 = stat
                        .rsplit_once(')')?
                        .1
                        .split_whitespace()
                        .nth(6)?
                        .parse()
                        .ok()?;
                    (name.trim() == "worker-1" && flags & 0x4 == 0).then_some(())
                })
                .count();
            assert_eq!(running, 0, "no worker-1 thread runs while stopped");
        }
        assert!(
            mgr.worker_execution().is_empty(),
            "a stopped worker reports nothing of its own"
        );
        while let Ok(Some(_)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
        {}
        mgr.set_worker_filter(1, b"moved-filter", true).unwrap();
        let workers = mgr.range_workers().unwrap();
        assert_eq!(
            (workers[0].filter.as_slice(), workers[0].allocated),
            (&b"moved-filter"[..], true)
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
                .await
                .is_err(),
            "a stopped worker runs nothing"
        );
        mgr.restart_worker(1).unwrap();
        assert!(ready(&mut rx).await, "the new thread starts");
        assert!(
            ready(&mut rx).await,
            "and applies the allocation it has now"
        );
        assert!(
            mgr.restart_worker(2).is_err(),
            "only a known worker restarts"
        );
        let mgr_done = mgr.clone();
        let running = tokio::task::spawn_blocking(move || {
            mgr_done.shutdown_workers(std::time::Duration::from_secs(5))
        });
        assert!(running.await.unwrap().is_empty());
    }

    /// The next `Ready` from worker 1 within five seconds, if any.
    async fn worker_ready(rx: &mut mpsc::Receiver<WorkerToMaster>) -> bool {
        let wait = std::time::Duration::from_secs(5);
        loop {
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(WorkerToMaster::Ready { core_id: 1 })) => return true,
                Ok(Some(_)) => continue,
                _ => return false,
            }
        }
    }

    /// A builder of worker stores over `dir`, as the node's opens its own
    /// RocksDB per worker; it fails while `fail` is set.
    fn store_builder(
        dir: std::path::PathBuf,
        fail: Arc<std::sync::atomic::AtomicBool>,
    ) -> Arc<dyn Fn(u32) -> std::result::Result<WorkerOwnedDeps, String> + Send + Sync> {
        Arc::new(move |core_id: u32| {
            if fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("the store cannot be opened".into());
            }
            let db = Arc::new(quil_store::RocksDb::open(&dir).map_err(|e| e.to_string())?);
            db.inner()
                .register_store(quil_forest::StoreRole::Worker(core_id));
            let clock_store: Arc<dyn quil_types::store::ClockStore> =
                Arc::new(quil_store::RocksClockStore::new(db.inner()));
            let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
                Arc::new(quil_tries::ShaInclusionProver);
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
                inclusion_prover.clone(),
            ));
            let execution_engine = Arc::new(quil_execution::ExecutionEngineManager::new(
                inclusion_prover.clone(),
                Arc::new(quil_crypto::DefaultKeyManager::new()),
                crdt.clone(),
                Arc::new(quil_execution::testing::NoopCircuitCompiler),
                clock_store.clone(),
                Arc::new(
                    quil_execution::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(
                        crdt.clone(),
                    ),
                ),
                true,
            ));
            Ok(WorkerOwnedDeps {
                clock_store,
                hypergraph: crdt,
                execution_engine,
                inclusion_prover,
                kv_db: Some(db as Arc<dyn quil_types::store::KvDb>),
                shard_syncer: None,
                unified_cutover_hook: None,
                delivery_frame_source: None,
                storage_history_source: None,
                outgoing_history_source: None,
                historical_committee_source: None,
                global_anchor_source: None,
            })
        })
    }

    fn consensus_deps(
        builder: Arc<dyn Fn(u32) -> std::result::Result<WorkerOwnedDeps, String> + Send + Sync>,
    ) -> WorkerConsensusDeps {
        let master = quil_store::RocksDb::open_in_memory().unwrap();
        WorkerConsensusDeps {
            prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
            frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            message_collector: Arc::new(crate::message_collector::MessageCollector::new()),
            clock_store: Arc::new(quil_store::RocksClockStore::new(master.inner())),
            fee_manager: Arc::new(crate::InMemoryDynamicFeeManager::new(32)),
            local_prover_address: vec![1; 32],
            local_bls_pubkey: Vec::new(),
            bls_signer_factory: Arc::new(|| -> Box<dyn quil_types::crypto::Signer> {
                unreachable!("no engine starts in this test")
            }),
            reward_greedy: false,
            min_active_provers_for_propose: 1,
            app_consensus_cw: false,
            db_config: quil_config::DbConfig::default(),
            coverage_publish: None,
            hypergraph: None,
            topology: None,
            execution_engine: None,
            inclusion_prover: None,
            worker_init: None,
            worker_state_builder: Some(builder),
            kv_db: None,
        }
    }

    async fn store_open_becomes(open: bool) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while quil_forest::storage_health::store_open(quil_forest::StoreRole::Worker(1)) != open {
            if std::time::Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        true
    }

    /// A worker stopped to reopen its store closes it and, restarted,
    /// reopens it through the worker builder; when the store cannot be
    /// opened, the restarted worker stays stopped: no thread runs, it
    /// reports nothing and it never falls back to the master's stores.
    #[tokio::test]
    async fn a_restarted_worker_reopens_its_own_store_or_stays_stopped() {
        struct TempDir(std::path::PathBuf);
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let temp = TempDir(std::env::temp_dir().join(format!(
            "quil-worker-reopen-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        )));
        let dir = temp.0.clone();
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mgr = Arc::new(ThreadWorkerManager::new());
        mgr.set_consensus_deps(consensus_deps(store_builder(dir.clone(), fail.clone())));
        let mut rx = mgr.take_master_rx().unwrap();
        let drain = |rx: &mut mpsc::Receiver<WorkerToMaster>| while rx.try_recv().is_ok() {};
        let stop = |mgr: &Arc<ThreadWorkerManager>| {
            let mgr = mgr.clone();
            tokio::task::spawn_blocking(move || {
                mgr.stop_worker(1, std::time::Duration::from_secs(10))
            })
        };

        mgr.set_worker_filter(1, b"pinned-filter", false).unwrap();
        assert!(
            worker_ready(&mut rx).await,
            "the worker starts on its own store"
        );
        assert!(store_open_becomes(true).await);
        assert!(stop(&mgr).await.unwrap());
        assert!(
            store_open_becomes(false).await,
            "its store closes with the worker"
        );
        drain(&mut rx);

        mgr.restart_worker(1).unwrap();
        assert!(
            worker_ready(&mut rx).await && worker_ready(&mut rx).await,
            "restarted on its allocation"
        );
        assert!(store_open_becomes(true).await, "the store is reopened");
        assert!(mgr.worker_running(1));
        assert!(
            mgr.restart_worker(1).is_err(),
            "a running worker is never replaced"
        );
        assert!(stop(&mgr).await.unwrap());
        assert!(!mgr.worker_running(1));
        assert!(store_open_becomes(false).await);
        drain(&mut rx);

        fail.store(true, std::sync::atomic::Ordering::SeqCst);
        mgr.restart_worker(1).unwrap();
        assert!(
            !worker_ready(&mut rx).await,
            "no worker runs without its own store"
        );
        assert!(!mgr.worker_running(1), "its thread ended");
        assert!(!quil_forest::storage_health::store_open(
            quil_forest::StoreRole::Worker(1)
        ));
        assert!(mgr.worker_execution().is_empty(), "it reports nothing");
        let mgr_done = mgr.clone();
        let running = tokio::task::spawn_blocking(move || {
            mgr_done.shutdown_workers(std::time::Duration::from_secs(5))
        });
        assert!(running.await.unwrap().is_empty());
        drop(temp);
    }

    #[test]
    fn worker_manager_construction() {
        let mgr = ThreadWorkerManager::new();
        assert!(mgr.num_worker_cores() > 0 || cfg!(target_os = "linux"));
    }

    /// The automatic count follows `available_parallelism`, which honors a
    /// cgroup CPU quota; the affinity core list (used only for pinning) does not.
    #[test]
    fn automatic_worker_count_honors_cpu_quota() {
        let expected = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(4)
            .saturating_sub(1)
            .max(1);
        assert_eq!(
            ThreadWorkerManager::new_with_count(0).num_worker_cores(),
            expected
        );
        assert_eq!(ThreadWorkerManager::new_with_count(3).num_worker_cores(), 3);
    }

    #[test]
    fn range_workers_empty_initially() {
        let mgr = ThreadWorkerManager::new();
        let workers = mgr.range_workers().unwrap();
        assert!(workers.is_empty());
    }

    #[tokio::test]
    async fn allocate_and_deallocate_worker() {
        let mgr = ThreadWorkerManager::new();
        let mut rx = mgr.take_master_rx().unwrap();

        // Allocate worker on core 1
        mgr.allocate_worker(1, b"test-filter").unwrap();

        // Should receive Ready event
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;

        match msg {
            Ok(Some(WorkerToMaster::Ready { core_id })) => {
                assert_eq!(core_id, 1);
            }
            _ => {
                // May get Ready twice (initial + respawn)
            }
        }

        // Check worker is listed
        let workers = mgr.range_workers().unwrap();
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].core_id, 1);

        // Deallocate — worker stays listed (now Idle) so the TUI's
        // top pane keeps showing it. Filter is cleared.
        mgr.deallocate_worker(1).unwrap();
        let workers = mgr.range_workers().unwrap();
        assert_eq!(workers.len(), 1);
        assert!(workers[0].filter.is_empty());
        assert!(!workers[0].allocated);
    }

    // ---- master↔worker boundary coverage -----------------
    use quil_types::store::WorkerStore as _;

    /// In-memory `WorkerStore` for the persist-across-restart path.
    #[derive(Default)]
    struct MemWorkerStore(std::sync::Mutex<HashMap<u32, quil_types::store::PersistedWorkerInfo>>);
    impl quil_types::store::WorkerStore for MemWorkerStore {
        fn get_worker(
            &self,
            core_id: u32,
        ) -> quil_types::error::Result<Option<quil_types::store::PersistedWorkerInfo>> {
            Ok(self.0.lock().unwrap().get(&core_id).cloned())
        }
        fn put_worker(
            &self,
            w: &quil_types::store::PersistedWorkerInfo,
        ) -> quil_types::error::Result<()> {
            self.0.lock().unwrap().insert(w.core_id, w.clone());
            Ok(())
        }
        fn delete_worker(&self, core_id: u32) -> quil_types::error::Result<()> {
            self.0.lock().unwrap().remove(&core_id);
            Ok(())
        }
        fn range_workers(
            &self,
        ) -> quil_types::error::Result<Vec<quil_types::store::PersistedWorkerInfo>> {
            Ok(self.0.lock().unwrap().values().cloned().collect())
        }
    }

    /// `set_worker_filter` flushes the filter binding through to the wired
    /// `WorkerStore` (the operator-intent-survives-restart path), and
    /// `load_persisted` reads it back. Master→worker boundary, persistence leg.
    #[tokio::test]
    async fn set_worker_filter_persists_to_worker_store() {
        let mgr = ThreadWorkerManager::new();
        let store = Arc::new(MemWorkerStore::default());
        mgr.set_worker_store(store.clone());
        let _rx = mgr.take_master_rx();

        mgr.set_worker_filter(1, b"shard-filter", false).unwrap();

        let persisted = store.get_worker(1).unwrap().expect("worker persisted");
        assert_eq!(persisted.filter, b"shard-filter");
        assert!(!persisted.manually_managed);
        // load_persisted reads through the same store.
        let lp = mgr.load_persisted(1).expect("load_persisted hit");
        assert_eq!(lp.filter, b"shard-filter");
    }

    /// A worker above the configured count drains; once it holds no seat and
    /// no join it is retired: dropped from the pool with its persisted
    /// record. Workers within the count, or holding a seat or join, are not.
    #[tokio::test]
    async fn an_idle_draining_worker_is_retired_with_its_record() {
        let mgr = ThreadWorkerManager::new_with_count(1);
        let store = Arc::new(MemWorkerStore::default());
        mgr.set_worker_store(store.clone());
        let _rx = mgr.take_master_rx();
        mgr.set_worker_filter(1, &[], false).unwrap();
        mgr.set_worker_filter(2, &[], false).unwrap();
        mgr.set_worker_filter(3, b"seat", false).unwrap();
        mgr.set_worker_filter(4, &[], false).unwrap();
        mgr.set_pending_filter_frame(4, 90).unwrap();
        assert_eq!(
            mgr.draining_workers(),
            std::collections::HashSet::from([2, 3, 4])
        );
        assert!(!mgr.is_draining(1) && mgr.is_draining(5));

        assert!(mgr.retire_worker(1).is_err(), "within the configured count");
        assert!(mgr.retire_worker(3).is_err(), "still holds a seat");
        assert!(mgr.retire_worker(4).is_err(), "still holds a join");
        mgr.retire_worker(2).unwrap();
        let cores: Vec<u32> = {
            let mut c: Vec<u32> = mgr
                .range_workers()
                .unwrap()
                .iter()
                .map(|w| w.core_id)
                .collect();
            c.sort();
            c
        };
        assert_eq!(cores, vec![1, 3, 4]);
        assert!(
            store.get_worker(2).unwrap().is_none(),
            "its record is deleted"
        );
        assert!(store.get_worker(3).unwrap().is_some());
        mgr.retire_worker(2).unwrap();
        let mgr = Arc::new(mgr);
        let done = mgr.clone();
        tokio::task::spawn_blocking(move || {
            done.shutdown_workers(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap();
    }

    /// Toggling manual-management mode flushes through to the store while
    /// preserving the filter — operator pins survive a restart.
    #[tokio::test]
    async fn set_manually_managed_persists_and_keeps_filter() {
        let mgr = ThreadWorkerManager::new();
        let store = Arc::new(MemWorkerStore::default());
        mgr.set_worker_store(store.clone());
        let _rx = mgr.take_master_rx();

        mgr.set_worker_filter(1, b"f", false).unwrap();
        mgr.set_manually_managed(1, true).unwrap();

        let p = store.get_worker(1).unwrap().expect("persisted");
        assert!(p.manually_managed, "manual mode flushed");
        assert_eq!(p.filter, b"f", "filter preserved across the mode flip");
    }

    /// `set_worker_filter(start_consensus=true)` spawns the worker thread,
    /// which signals `Ready` back to the master and is listed with its filter.
    /// Exercises the real master→worker `Respawn` send over the channel.
    #[tokio::test]
    async fn set_worker_filter_spawns_worker_and_signals_ready() {
        let mgr = ThreadWorkerManager::new();
        let mut rx = mgr.take_master_rx().unwrap();

        mgr.set_worker_filter(1, b"active-filter", true).unwrap();

        // The spawned worker thread sends Ready back over the boundary.
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
        assert!(
            matches!(msg, Ok(Some(WorkerToMaster::Ready { core_id: 1 }))),
            "expected Ready from core 1, got {msg:?}"
        );
        let workers = mgr.range_workers().unwrap();
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].filter, b"active-filter");
        assert!(
            workers[0].allocated,
            "a worker running consensus is allocated"
        );
        mgr.set_worker_filter(1, b"joining-filter", false).unwrap();
        assert!(!mgr.range_workers().unwrap()[0].allocated);
    }

    fn self_test_key() -> quil_crypto::FalconSigner {
        quil_crypto::FalconSigner::generate()
    }

    fn self_test_with(key: &quil_crypto::FalconSigner, corrupt: impl Fn(u32) -> bool) -> u32 {
        use quil_types::crypto::Signer as _;
        let mut calls = 0;
        falcon_self_test_failures(
            |m| {
                calls += 1;
                let mut sig = key.sign_with_domain(m, FALCON_SELF_TEST_DOMAIN).ok()?;
                if corrupt(calls) {
                    sig[100] ^= 0x01;
                }
                Some(sig)
            },
            |m, sig| quil_crypto::falcon_verify(key.public_key(), sig, m, FALCON_SELF_TEST_DOMAIN),
        )
    }

    /// A worker's shard data is withdrawn while an eviction pass may drop
    /// shards from its store, and read again after it.
    #[tokio::test]
    async fn shard_data_is_withdrawn_during_an_eviction_and_read_again_after() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store,
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let filter = vec![0x21; 32];
        db.inner()
            .put(
                quil_store::encoding::consensus_materialized_cursor_key(&filter),
                9u64.to_be_bytes(),
            )
            .unwrap();
        let table = Arc::new(ShardData::default());
        table.publish(3, &crdt).await.unwrap();
        assert_eq!(
            table.snapshot(),
            HashMap::from([(3, vec![(filter.clone(), 9)])])
        );
        table.forget(3);
        assert!(
            table.snapshot().is_empty(),
            "withdrawn while the passes run"
        );
        table.publish(3, &crdt).await.unwrap();
        assert_eq!(table.snapshot(), HashMap::from([(3, vec![(filter, 9)])]));
    }

    /// A read that ends after a withdrawal, or after a newer read began,
    /// records nothing: what stands is the newer state.
    #[test]
    fn a_read_overtaken_by_a_withdrawal_or_a_newer_read_records_nothing() {
        use crate::worker_payload_eviction::{HeldShards, Publish};
        let zero = std::time::Duration::ZERO;
        let read = |n: u8| {
            Ok(HeldShards {
                lineages: 1,
                held: vec![(vec![n], n as u64)],
            })
        };
        let table = ShardData::default();
        let first = table.begin(3);
        table.forget(3);
        assert_eq!(
            table.record(3, first, read(1), zero),
            Publish::Superseded { took: zero }
        );
        assert!(!table.holds(3), "a withdrawal stands over an older read");
        let (older, newer) = (table.begin(3), table.begin(3));
        let other = table.begin(4);
        assert!(matches!(
            table.record(3, newer, read(2), zero),
            Publish::Read {
                lineages: 1,
                held: 1,
                ..
            }
        ));
        assert_eq!(
            table.record(3, older, read(1), zero),
            Publish::Superseded { took: zero }
        );
        assert!(matches!(
            table.record(4, other, read(4), zero),
            Publish::Read { .. }
        ));
        assert_eq!(
            table.snapshot(),
            HashMap::from([(3, vec![(vec![2], 2)]), (4, vec![(vec![4], 4)])]),
            "a newer read stands over an older one; other workers are their own"
        );
    }

    /// An eviction run whose passes delete payload withdraws the worker's
    /// record before the deletion and reads the shards its store holds
    /// again after the passes, off the worker's thread: the thread keeps
    /// beating while that read waits on the store. A run that then changes
    /// nothing keeps the record without reading the store.
    #[test]
    fn an_eviction_run_reads_the_shards_held_off_the_worker_thread_only_after_a_change() {
        use crate::worker_payload_eviction::Publish;
        use std::sync::atomic::{AtomicBool, Ordering};
        let delay = std::time::Duration::from_millis(3000);
        let (db, crdt, reads, filter) = shard_data_reads::slow_store(delay);
        let app = shard_data_reads::APP;
        let shard = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3),
            l2: app,
        };
        let mut id = app.to_vec();
        id.extend([129u8; 32]);
        // Payload of the half the worker left, for the payload pass to delete.
        let left =
            quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard, &id, 0);
        db.inner().put(&left, b"left").unwrap();
        let table = Arc::new(ShardData::default());
        let runs = Arc::new(Mutex::new(Vec::new()));
        let (worker_table, worker_crdt, seen) = (table.clone(), crdt.clone(), runs.clone());
        let (reports, longest) =
            shard_data_reads::on_worker_thread(reads.clone(), move || async move {
                worker_table.publish(5, &worker_crdt).await.unwrap();
                for _ in 0..2 {
                    let evicting = Arc::new(AtomicBool::new(true));
                    // Asked between the passes: whether the record was withdrawn.
                    let (record, withdrawn) =
                        (worker_table.clone(), Arc::new(AtomicBool::new(false)));
                    let saw = withdrawn.clone();
                    let bound: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
                        if !record.holds(5) {
                            saw.store(true, Ordering::SeqCst);
                        }
                        true
                    });
                    let no_storage: Option<(std::path::PathBuf, fn(&[u8]) -> bool)> = None;
                    let (report, publish) = tokio::spawn(probed(
                        ProbeSection::PayloadEviction,
                        eviction_run(
                            5,
                            "test".into(),
                            worker_crdt.clone(),
                            vec![filter.clone()],
                            no_storage,
                            bound,
                            worker_table.clone(),
                            evicting.clone(),
                        ),
                    ))
                    .await
                    .unwrap();
                    assert!(!evicting.load(Ordering::SeqCst), "the run clears its flag");
                    seen.lock().unwrap().push((
                        report.changed,
                        withdrawn.load(Ordering::SeqCst),
                        publish,
                    ));
                }
            });
        shard_data_reads::assert_beating(&reports, longest);
        assert!(
            db.inner().get(&left).unwrap().is_none(),
            "the payload outside the kept scope stays"
        );
        let runs = runs.lock().unwrap().clone();
        assert!(
            matches!(
                runs[0],
                (
                    true,
                    true,
                    Publish::Read {
                        lineages: 1,
                        held: 0,
                        ..
                    }
                )
            ),
            "a run that deletes withdraws the record, then reads it again: {runs:?}"
        );
        assert_eq!(
            runs[1],
            (false, false, Publish::Skipped),
            "a run that changes nothing keeps the record unread"
        );
        assert_eq!(
            reads.done.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the store was read at the start and after the deleting run only"
        );
        assert_eq!(table.snapshot(), HashMap::from([(5, Vec::new())]));
    }

    /// A run whose forest pass fails may have dropped a shard before the
    /// failure: its end reads the shards held again, though the record
    /// stood throughout.
    #[tokio::test]
    async fn a_run_whose_forest_pass_fails_reads_the_shards_held_again() {
        use crate::worker_payload_eviction::Publish;
        let (_db, crdt, reads, filter) = shard_data_reads::slow_store(std::time::Duration::ZERO);
        let table = Arc::new(ShardData::default());
        table.publish(5, &crdt).await.unwrap();
        // A staged mutation of the application: both passes refuse.
        let location = quil_hypergraph::Location {
            app_address: shard_data_reads::APP,
            data_address: [1; 32],
        };
        crdt.add_vertex(&location, &[1; 48]).unwrap();
        let no_storage: Option<(std::path::PathBuf, fn(&[u8]) -> bool)> = None;
        let (report, publish) = eviction_run(
            5,
            "test".into(),
            crdt,
            vec![filter],
            no_storage,
            Arc::new(|| true),
            table.clone(),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )
        .await;
        assert!(report.changed, "{report:?}");
        assert!(matches!(publish, Publish::Read { .. }), "{publish:?}");
        assert_eq!(reads.done.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// A rebind during a run that changes nothing withdraws the record; the
    /// run's end reads it again rather than leave the worker without one.
    #[tokio::test]
    async fn a_record_withdrawn_during_a_run_is_read_again_at_its_end() {
        use crate::worker_payload_eviction::Publish;
        let (_db, crdt, reads, filter) = shard_data_reads::slow_store(std::time::Duration::ZERO);
        let table = Arc::new(ShardData::default());
        table.publish(5, &crdt).await.unwrap();
        let rebind = table.clone();
        let bound: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
            rebind.forget(5);
            true
        });
        let no_storage: Option<(std::path::PathBuf, fn(&[u8]) -> bool)> = None;
        let (report, publish) = eviction_run(
            5,
            "test".into(),
            crdt,
            vec![filter],
            no_storage,
            bound,
            table.clone(),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )
        .await;
        assert!(!report.changed, "{report:?}");
        assert!(matches!(publish, Publish::Read { .. }), "{publish:?}");
        assert!(table.holds(5));
        assert_eq!(reads.done.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn falcon_self_test_passes_a_good_signer_quickly() {
        let started = std::time::Instant::now();
        let key = self_test_key();
        let keygen = started.elapsed();
        let started = std::time::Instant::now();
        assert_eq!(self_test_with(&key, |_| false), 0);
        let test = started.elapsed();
        eprintln!(
            "falcon self-test: keygen {keygen:?}, {FALCON_SELF_TEST_MESSAGES} sign+verify {test:?}"
        );
        assert!(
            test < std::time::Duration::from_millis(100),
            "self-test took {test:?}"
        );
    }

    #[test]
    fn falcon_self_test_counts_every_corrupt_signature() {
        let key = self_test_key();
        assert_eq!(self_test_with(&key, |_| true), FALCON_SELF_TEST_MESSAGES);
        assert_eq!(
            self_test_with(&key, |n| n % 4 == 0),
            FALCON_SELF_TEST_MESSAGES / 4
        );
    }
}

/// Reads of the shards a worker's store holds, which take a point read and
/// leaf counts per lineage, against a store whose reads wait on the disk.
#[cfg(test)]
mod shard_data_reads {
    use super::*;
    use crate::worker_stall::{heartbeat, StallReport, StallWatch};
    use quil_types::store::{ChangeRecord, HypergraphStore, ShardKey, Transaction};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    pub(super) const APP: [u8; 32] = [0x21; 32];

    /// Store reads that waited, and those waiting now.
    #[derive(Default)]
    pub(super) struct Reads {
        pub(super) waiting: AtomicUsize,
        pub(super) done: AtomicUsize,
    }

    /// A worker store whose reads of incomplete-sync markers, which the read
    /// of the shards held makes per lineage, take `delay`.
    struct SlowReads {
        inner: Arc<dyn HypergraphStore>,
        delay: Duration,
        reads: Arc<Reads>,
    }

    struct SlowTxn {
        inner: Box<dyn Transaction>,
        delay: Duration,
        reads: Arc<Reads>,
    }

    impl Transaction for SlowTxn {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            if key.starts_with(b"quil/forest-sync/incomplete/v1/") {
                self.reads.waiting.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(self.delay);
                self.reads.waiting.fetch_sub(1, Ordering::SeqCst);
                self.reads.done.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.get(key)
        }
        fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.inner.set(key, value)
        }
        fn commit(self: Box<Self>) -> Result<()> {
            self.inner.commit()
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.inner.delete(key)
        }
        fn abort(self: Box<Self>) -> Result<()> {
            self.inner.abort()
        }
        fn new_iter(
            &self,
            lower: &[u8],
            upper: &[u8],
        ) -> Result<Box<dyn quil_types::store::Iterator>> {
            self.inner.new_iter(lower, upper)
        }
        fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
            self.inner.delete_range(lower, upper)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self.inner.as_any()
        }
    }

    impl HypergraphStore for SlowReads {
        // Forest maintenance refuses a store it cannot identify.
        fn backing_store_identity(&self) -> Option<quil_types::store::BackingStoreIdentity> {
            self.inner.backing_store_identity()
        }
        fn new_transaction(&self, indexed: bool) -> Result<Box<dyn Transaction>> {
            Ok(Box::new(SlowTxn {
                inner: self.inner.new_transaction(indexed)?,
                delay: self.delay,
                reads: self.reads.clone(),
            }))
        }
        fn get_node_by_key(
            &self,
            set: &str,
            phase: &str,
            shard: &ShardKey,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>> {
            self.inner.get_node_by_key(set, phase, shard, key)
        }
        fn get_node_by_path(
            &self,
            set: &str,
            phase: &str,
            shard: &ShardKey,
            path: &[i32],
        ) -> Result<Option<Vec<u8>>> {
            self.inner.get_node_by_path(set, phase, shard, path)
        }
        fn insert_node(
            &self,
            txn: &dyn Transaction,
            set: &str,
            phase: &str,
            shard: &ShardKey,
            key: &[u8],
            path: &[i32],
            data: &[u8],
        ) -> Result<()> {
            self.inner
                .insert_node(txn, set, phase, shard, key, path, data)
        }
        fn save_root(
            &self,
            txn: &dyn Transaction,
            set: &str,
            phase: &str,
            shard: &ShardKey,
            data: &[u8],
        ) -> Result<()> {
            self.inner.save_root(txn, set, phase, shard, data)
        }
        fn delete_node(
            &self,
            txn: &dyn Transaction,
            set: &str,
            phase: &str,
            shard: &ShardKey,
            key: &[u8],
            path: &[i32],
        ) -> Result<()> {
            self.inner.delete_node(txn, set, phase, shard, key, path)
        }
        fn set_covered_prefix(&self, covered_prefix: &[i32]) -> Result<()> {
            self.inner.set_covered_prefix(covered_prefix)
        }
        fn set_shard_commit(
            &self,
            txn: &dyn Transaction,
            frame: u64,
            phase: &str,
            set: &str,
            shard_address: &[u8],
            commitment: &[u8],
        ) -> Result<()> {
            self.inner
                .set_shard_commit(txn, frame, phase, set, shard_address, commitment)
        }
        fn get_shard_commit(
            &self,
            frame: u64,
            phase: &str,
            set: &str,
            shard_address: &[u8],
        ) -> Result<Vec<u8>> {
            self.inner
                .get_shard_commit(frame, phase, set, shard_address)
        }
        fn get_root_commits(&self, frame: u64) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
            self.inner.get_root_commits(frame)
        }
        fn load_vertex_underlying_raw(
            &self,
            set: &str,
            phase: &str,
            shard: &ShardKey,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>> {
            self.inner
                .load_vertex_underlying_raw(set, phase, shard, key)
        }
        fn save_vertex_underlying(
            &self,
            txn: &dyn Transaction,
            set: &str,
            phase: &str,
            shard: &ShardKey,
            key: &[u8],
            data: &[u8],
        ) -> Result<()> {
            self.inner
                .save_vertex_underlying(txn, set, phase, shard, key, data)
        }
        fn for_each_vertex_underlying(
            &self,
            set: &str,
            phase: &str,
            shard: &ShardKey,
            callback: &mut dyn FnMut(Vec<u8>, Vec<u8>),
        ) -> Result<usize> {
            self.inner
                .for_each_vertex_underlying(set, phase, shard, callback)
        }
        fn apply_snapshot(&self, path: &str) -> Result<()> {
            self.inner.apply_snapshot(path)
        }
        fn set_alt_shard_commit(
            &self,
            txn: &dyn Transaction,
            frame: u64,
            shard_address: &[u8],
            vertex_adds: &[u8],
            vertex_removes: &[u8],
            hyperedge_adds: &[u8],
            hyperedge_removes: &[u8],
        ) -> Result<()> {
            self.inner.set_alt_shard_commit(
                txn,
                frame,
                shard_address,
                vertex_adds,
                vertex_removes,
                hyperedge_adds,
                hyperedge_removes,
            )
        }
        fn get_latest_alt_shard_commit(
            &self,
            shard_address: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
            self.inner.get_latest_alt_shard_commit(shard_address)
        }
        fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> {
            self.inner.range_alt_shard_addresses()
        }
        fn reap_old_changesets(&self, txn: &dyn Transaction, frame: u64) -> Result<()> {
            self.inner.reap_old_changesets(txn, frame)
        }
        fn track_change(
            &self,
            txn: &dyn Transaction,
            key: &[u8],
            old_value: Option<&[u8]>,
            frame: u64,
            phase: &str,
            set: &str,
            shard: &ShardKey,
        ) -> Result<()> {
            self.inner
                .track_change(txn, key, old_value, frame, phase, set, shard)
        }
        fn get_changes(
            &self,
            frame_start: u64,
            frame_end: u64,
            phase: &str,
            set: &str,
            shard: &ShardKey,
        ) -> Result<Vec<ChangeRecord>> {
            self.inner
                .get_changes(frame_start, frame_end, phase, set, shard)
        }
        fn untrack_change(
            &self,
            txn: &dyn Transaction,
            key: &[u8],
            frame: u64,
            phase: &str,
            set: &str,
            shard: &ShardKey,
        ) -> Result<()> {
            self.inner
                .untrack_change(txn, key, frame, phase, set, shard)
        }
    }

    /// A unified worker store keeping one lineage, the lower half of
    /// [`APP`] at cursor 9, whose read of the shards held waits `delay`.
    pub(super) fn slow_store(
        delay: Duration,
    ) -> (
        quil_store::RocksDb,
        Arc<quil_hypergraph::HypergraphCrdt>,
        Arc<Reads>,
        Vec<u8>,
    ) {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let reads = Arc::new(Reads::default());
        let store = Arc::new(SlowReads {
            inner: Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            delay,
            reads: reads.clone(),
        });
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store,
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        let filter = quil_forest::encode_shard_bit_path(&APP, &[false]);
        db.inner()
            .put(
                quil_store::encoding::consensus_materialized_cursor_key(&filter),
                9u64.to_be_bytes(),
            )
            .unwrap();
        (db, crdt, reads, filter)
    }

    /// Run `work` on a thread set up as a node's worker thread: a
    /// current-thread runtime whose heartbeat a watchdog follows. Returns
    /// the watchdog's reports and the longest the heartbeat was overdue
    /// while a store read waited.
    pub(super) fn on_worker_thread<F, Fut>(
        reads: Arc<Reads>,
        work: F,
    ) -> (Vec<StallReport>, Option<u64>)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()>,
    {
        let probe = ThreadProbe::new();
        // Well above the heartbeat, for parallel test load; the reads wait
        // twice as long, so a thread they block is reported.
        let mut watch = StallWatch::new(Duration::from_millis(1500), Duration::from_millis(300));
        watch.add(5, &probe);
        let observer = probe.clone();
        let worker = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let installed = install_probe(probe.clone());
            rt.spawn(heartbeat(Arc::downgrade(&probe), Duration::from_millis(50)));
            rt.block_on(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                work().await;
            });
            drop(installed);
        });
        let (mut reports, mut longest) = (Vec::new(), None);
        while !worker.is_finished() {
            let now = quil_types::thread_probe::now_ms();
            reports.extend(watch.poll(now));
            if reads.waiting.load(Ordering::SeqCst) > 0 {
                let overdue = now.saturating_sub(observer.snapshot().last_beat_ms);
                longest = Some(longest.map_or(overdue, |l: u64| l.max(overdue)));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Err(panic) = worker.join() {
            std::panic::resume_unwind(panic);
        }
        (reports, longest)
    }

    pub(super) fn assert_beating(reports: &[StallReport], longest: Option<u64>) {
        let blocked: Vec<String> = reports
            .iter()
            .filter_map(|report| match report {
                StallReport::Blocked { blocked, place, .. } => Some(format!(
                    "blocked {:.1}s in {}",
                    blocked.as_secs_f32(),
                    place.describe()
                )),
                _ => None,
            })
            .collect();
        assert!(
            blocked.is_empty(),
            "the worker thread stalled while its store was read: {}",
            blocked.join("; ")
        );
        let longest = longest.expect("no store read waited while the thread was watched");
        assert!(
            longest < 1000,
            "the worker thread's heartbeat was {longest} ms overdue while a store read waited"
        );
    }

    /// Recording the shards a worker's store holds, as the end of each
    /// eviction run does, leaves the worker's thread beating while the
    /// store's reads wait. Each due worker of a node runs at once, so a
    /// read on its thread held its votes for as long as its store took.
    #[test]
    fn recording_the_shards_held_leaves_the_worker_thread_beating() {
        let (_db, crdt, reads, _) = slow_store(Duration::from_millis(3000));
        let table = Arc::new(ShardData::default());
        let worker_table = table.clone();
        let (reports, longest) = on_worker_thread(reads.clone(), move || async move {
            let recorder = worker_table.clone();
            tokio::spawn(probed(ProbeSection::PayloadEviction, async move {
                recorder.publish(5, &crdt);
            }))
            .await
            .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            while worker_table.snapshot().is_empty() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the shards held were never recorded"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        assert_beating(&reports, longest);
        assert_eq!(table.snapshot(), HashMap::from([(5, Vec::new())]));
        assert_eq!(reads.done.load(Ordering::SeqCst), 1);
    }
}
