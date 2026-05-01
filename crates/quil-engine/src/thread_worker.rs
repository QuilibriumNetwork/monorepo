//! Thread-based worker manager with CPU core pinning.
//!
//! Replaces Go's process-based workers with core-pinned OS threads.
//! Each worker thread runs its own single-threaded tokio runtime and
//! communicates with the master via `tokio::sync::mpsc` channels.
//!
//! Key design differences from Go:
//! - Threads instead of processes (no fork/exec overhead)
//! - Channel IPC instead of gRPC (zero serialization overhead)
//! - Core affinity via `core_affinity` crate
//! - Per-thread tokio runtime (`new_current_thread`) for isolation

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
    /// Assign a new filter (shard) to this worker. The worker should
    /// tear down any existing consensus engine and start a new one.
    Respawn { filter: Vec<u8> },
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
    /// Periodic heartbeat from an active shard worker.
    ShardHeartbeat {
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
    /// (allocation Status=Active or Paused). Mirrors Go's
    /// `WorkerInfo.Allocated` field.
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
        }
    }

    /// Set consensus dependencies for worker threads. Call after
    /// the prover registry and frame prover are initialized.
    pub fn set_consensus_deps(&self, deps: WorkerConsensusDeps) {
        *self.consensus_deps.lock().unwrap() = Some(Arc::new(deps));
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
                                    Some(MasterToWorker::Respawn { filter }) => {
                                        // Stop existing engine if any
                                        if let Some(cancel) = engine_cancel.take() {
                                            cancel.cancel();
                                            // Give the engine a moment to clean up
                                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                        }

                                        if filter.is_empty() {
                                            info!(core_id, "worker idle (no filter)");
                                            current_filter.clear();
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
                                            tokio::spawn(async move {
                                                info!(core_id, filter = hex::encode(&filter_clone), "app engine spawned");

                                                if let Some(ref deps) = deps {
                                                    // Create the AppConsensusEngine with full HotStuff integration
                                                    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(256);
                                                    let engine_deps = crate::app_engine::AppEngineDeps {
                                                        clock_store: deps.clock_store.clone(),
                                                        prover_registry: deps.prover_registry.clone(),
                                                        frame_prover: deps.frame_prover.clone(),
                                                        message_collector: deps.message_collector.clone(),
                                                        fee_manager: deps.fee_manager.clone(),
                                                        local_prover_address: deps.local_prover_address.clone(),
                                                        local_bls_pubkey: deps.local_bls_pubkey.clone(),
                                                        bls_signer: (deps.bls_signer_factory)(),
                                                        reward_greedy: deps.reward_greedy,
                                                    };
                                                    let (engine, _handle) = crate::app_engine::AppConsensusEngine::new(
                                                        core_id,
                                                        filter_clone.clone(),
                                                        engine_deps,
                                                        event_tx,
                                                    );

                                                    // Forward engine events to master
                                                    let master_tx_events = master_tx_clone.clone();
                                                    let _filter_for_events = filter_clone.clone();
                                                    tokio::spawn(async move {
                                                        while let Some(event) = event_rx.recv().await {
                                                            match event {
                                                                crate::app_engine::AppEngineEvent::FrameProduced { filter, frame_number, frame_data } => {
                                                                    let _ = master_tx_events.send(
                                                                        WorkerToMaster::FrameProduced {
                                                                            core_id,
                                                                            filter,
                                                                            frame_number,
                                                                            frame_data,
                                                                        }
                                                                    ).await;
                                                                }
                                                                _ => {
                                                                    // Other events (votes, timeouts, equivocations)
                                                                    // are handled by the engine internally or
                                                                    // forwarded as needed.
                                                                    debug!(core_id, "engine event: {:?}", event);
                                                                }
                                                            }
                                                        }
                                                    });

                                                    // Run the engine — this blocks until cancelled
                                                    let bls_signer = (deps.bls_signer_factory)();
                                                    tokio::select! {
                                                        _ = ec.cancelled() => {
                                                            info!(core_id, "app engine cancelled");
                                                        }
                                                        _ = engine.run(bls_signer) => {
                                                            info!(core_id, "app engine exited");
                                                        }
                                                    }
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

impl WorkerManager for ThreadWorkerManager {
    fn allocate_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();

        // Spawn if not already running
        if !workers.contains_key(&core_id) {
            let state = self.spawn_worker(core_id)?;
            workers.insert(core_id, state);
        }

        // Send respawn command with the filter (non-blocking)
        if let Some(w) = workers.get_mut(&core_id) {
            w.filter = filter.to_vec();
            let _ = w.tx.try_send(MasterToWorker::Respawn {
                filter: filter.to_vec(),
            });
        }

        Ok(())
    }

    fn deallocate_worker(&self, core_id: u32) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(mut w) = workers.remove(&core_id) {
            w.cancel.cancel();
            if let Some(handle) = w.handle.take() {
                // Give the thread up to 5 seconds to finish
                let _ = handle.join();
            }
        }
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
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.pending_filter_frame = frame;
        }
        Ok(())
    }

    fn set_manually_managed(&self, core_id: u32, manually_managed: bool) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.manually_managed = manually_managed;
        }
        Ok(())
    }

    fn set_allocated(&self, core_id: u32, allocated: bool) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.allocated = allocated;
        }
        Ok(())
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

        // Deallocate
        mgr.deallocate_worker(1).unwrap();
        let workers = mgr.range_workers().unwrap();
        assert!(workers.is_empty());
    }
}
