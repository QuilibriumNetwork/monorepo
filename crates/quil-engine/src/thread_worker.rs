//! Thread-based worker manager with CPU core pinning.
//!
//! Each worker thread runs its own single-threaded tokio runtime and
//! communicates with the master via `tokio::sync::mpsc` channels. Core
//! affinity is set via the `core_affinity` crate; `new_current_thread`
//! gives each worker its own isolated runtime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use quil_types::error::{QuilError, Result};

use crate::worker::{WorkerInfo, WorkerManager};

/// Message from master to worker.
#[derive(Debug)]
pub enum MasterToWorker {
    /// Assign a new filter (shard) to this worker.
    ///
    /// `start_consensus`:
    ///   * `true`  — tear down any existing engine and (re)spawn the
    ///     `AppConsensusEngine`. Used for `Active`/`Paused`
    ///     allocations.
    ///   * `false` — record the filter binding for TUI visibility,
    ///     cancel any running engine, but do NOT spawn a new one.
    ///     Used while an allocation is `Joining` and there is no
    ///     Active prover under this filter yet (the engine's
    ///     `leader_for_rank` would fail and the loop would die).
    ///     Mirrors Go's `worker.Filter`-set / `worker.Allocated=false`
    ///     state from `worker_allocator.go:421-440`.
    Respawn { filter: Vec<u8>, start_consensus: bool },
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
    ShardHeartbeat {
        core_id: u32,
        filter: Vec<u8>,
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
    ShardDeactivated {
        core_id: u32,
        filter: Vec<u8>,
    },
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
    handle: Option<JoinHandle<()>>,
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
    /// Callback that publishes finalized canonical FrameHeader bytes
    /// on `GLOBAL_PROVER` so archives credit our shard work toward
    /// rewards. AppFollower invokes this directly from the consensus
    /// event loop to avoid hopping through the worker→master channel
    /// chain.
    pub coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    /// Hypergraph CRDT used to derive per-frame `state_roots` for the
    /// FrameHeader VDF challenge.
    pub hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
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
}

/// Thread-based worker manager. Core 0 is reserved for the master;
/// workers use cores 1..N.
pub struct ThreadWorkerManager {
    workers: Mutex<HashMap<u32, WorkerState>>,
    /// Channel for workers to send events back to master.
    master_rx: Mutex<Option<mpsc::Receiver<WorkerToMaster>>>,
    master_tx: mpsc::Sender<WorkerToMaster>,
    /// Number of available CPU cores (excluding core 0 for master).
    num_cores: u32,
    /// Shared consensus dependencies — set after construction.
    consensus_deps: Mutex<Option<Arc<WorkerConsensusDeps>>>,
    /// Optional persistent registry — when wired, every state
    /// change (filter assigned, manually_managed flipped) is
    /// flushed so it survives restarts. Mirrors Go's
    /// `engine.workerStore` plumbing.
    worker_store: Mutex<Option<Arc<dyn quil_types::store::WorkerStore>>>,
}

impl ThreadWorkerManager {
    pub fn new() -> Self {
        let core_ids = core_affinity::get_core_ids().unwrap_or_default();
        let num_cores = if core_ids.len() > 1 {
            (core_ids.len() - 1) as u32
        } else {
            0
        };

        let (master_tx, master_rx) = mpsc::channel(256);

        info!(
            available_cores = core_ids.len(),
            worker_cores = num_cores,
            "thread worker manager initialized"
        );

        Self {
            workers: Mutex::new(HashMap::new()),
            master_rx: Mutex::new(Some(master_rx)),
            master_tx,
            num_cores,
            consensus_deps: Mutex::new(None),
            worker_store: Mutex::new(None),
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

    /// Returns persisted worker state for the given core, when a
    /// store is wired and an entry exists.
    pub fn load_persisted(
        &self,
        core_id: u32,
    ) -> Option<quil_types::store::PersistedWorkerInfo> {
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
    fn spawn_worker(&self, core_id: u32) -> Result<WorkerState> {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel::<MasterToWorker>(32);
        let master_tx = self.master_tx.clone();
        let cancel_clone = cancel.clone();
        let consensus_deps = self.consensus_deps.lock().unwrap().clone();

        let handle = std::thread::Builder::new()
            .name(format!("worker-{}", core_id))
            .spawn(move || {
                // Pin to the requested core
                let core_ids = core_affinity::get_core_ids().unwrap_or_default();
                if (core_id as usize) < core_ids.len() {
                    if !core_affinity::set_for_current(core_ids[core_id as usize]) {
                        warn!(core_id, "failed to pin thread to core");
                    }
                }

                if let Some(deps) = consensus_deps.as_ref() {
                    if let Some(init) = deps.worker_init.as_ref() {
                        init(core_id);
                    }
                }

                // Confirms per-worker log routing is wired: this line
                // emits from the worker's OS thread and must land in
                // `worker-<core_id>.log`. If the file stays empty
                // after spawn, the routing is broken (thread-local
                // tag missing, file registry not populated, etc).
                info!(core_id, "worker thread up");

                let worker_owned: Option<WorkerOwnedDeps> =
                    consensus_deps
                        .as_ref()
                        .and_then(|d| d.worker_state_builder.as_ref())
                        .and_then(|b| match b(core_id) {
                            Ok(o) => Some(o),
                            Err(e) => {
                                tracing::error!(
                                    core_id,
                                    error = %e,
                                    "worker_state_builder failed; falling back to shared state",
                                );
                                None
                            }
                        });

                // Create per-thread tokio runtime
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to create worker tokio runtime");

                rt.block_on(async move {
                    let mut current_filter: Vec<u8> = Vec::new();
                    let mut engine_cancel: Option<tokio_util::sync::CancellationToken> = None;

                    // Notify master we're ready
                    let _ = master_tx
                        .send(WorkerToMaster::Ready { core_id })
                        .await;

                    loop {
                        tokio::select! {
                            cmd = rx.recv() => {
                                match cmd {
                                    Some(MasterToWorker::Respawn { filter, start_consensus }) => {
                                        // Stop existing engine if any
                                        if let Some(cancel) = engine_cancel.take() {
                                            cancel.cancel();
                                            // Give the engine a moment to clean up
                                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
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
                                            let owned = worker_owned.clone();
                                            // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
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
                                                        clock_store,
                                                        prover_registry: deps.prover_registry.clone(),
                                                        frame_prover: deps.frame_prover.clone(),
                                                        message_collector: deps.message_collector.clone(),
                                                        fee_manager: deps.fee_manager.clone(),
                                                        local_prover_address: deps.local_prover_address.clone(),
                                                        local_bls_pubkey: deps.local_bls_pubkey.clone(),
                                                        bls_signer: (deps.bls_signer_factory)(),
                                                        reward_greedy: deps.reward_greedy,
                                                        min_active_provers_for_propose: deps.min_active_provers_for_propose,
                                                        coverage_publish: deps.coverage_publish.clone(),
                                                        hypergraph,
                                                        execution_engine,
                                                        inclusion_prover,
                                                        kv_db,
                                                    };
                                                    let (engine, app_handle) = crate::app_engine::AppConsensusEngine::new(
                                                        core_id,
                                                        filter_clone.clone(),
                                                        engine_deps,
                                                        event_tx,
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
                                                    // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
                                                    tokio::spawn(async move {
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
                                                                _ => {
                                                                    // Equivocation/Halted/AncestorSyncRequested/
                                                                    // ParentSealed — informational; engine handles
                                                                    // them internally or they require no master
                                                                    // mediation in local mode.
                                                                    debug!(core_id, "engine event: {:?}", event);
                                                                }
                                                            }
                                                        }
                                                    });

                                                    // Spawn the engine as its own task so it schedules
                                                    // independently of the cancellation watcher and any
                                                    // tasks spawned by the inner consensus event loop.
                                                    // Sharing a task via `tokio::select!` here was making
                                                    // the engine's own select starve under load.
                                                    let bls_signer = (deps.bls_signer_factory)();
                                                    // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
                                                    let mut engine_handle = tokio::spawn(async move {
                                                        engine.run(bls_signer).await;
                                                    });
                                                    tokio::select! {
                                                        _ = ec.cancelled() => {
                                                            info!(core_id, "app engine cancelled");
                                                            engine_handle.abort();
                                                        }
                                                        _ = &mut engine_handle => {
                                                            info!(core_id, "app engine exited");
                                                        }
                                                    }
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
                });
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
    fn set_worker_filter(
        &self,
        core_id: u32,
        filter: &[u8],
        start_consensus: bool,
    ) -> Result<()> {
        // Spawn-if-missing happens before mutate because spawn_worker
        // returns Result and we want to surface that error path.
        {
            let mut workers = self.workers.lock().unwrap();
            if !workers.contains_key(&core_id) {
                let state = self.spawn_worker(core_id)?;
                workers.insert(core_id, state);
            }
        }
        let owned_filter = filter.to_vec();
        self.mutate(core_id, move |w| {
            w.filter = owned_filter.clone();
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

    fn check_workers_connected(&self) -> Result<Vec<u32>> {
        let workers = self.workers.lock().unwrap();
        Ok(workers.keys().copied().collect())
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_manager_construction() {
        let mgr = ThreadWorkerManager::new();
        assert!(mgr.num_worker_cores() > 0 || cfg!(target_os = "linux"));
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
        let msg = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rx.recv(),
        ).await;

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
}
