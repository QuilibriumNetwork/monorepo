//! Worker allocation logic. Port of
//! `node/consensus/global/worker_allocator.go`.
//!
//! Decides which shards this node's workers should handle. On each
//! new global frame, reconciles the prover registry's allocations
//! against the running worker threads and spawns/stops as needed.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::info;

use quil_types::consensus::{ProverRegistry, ProverStatus};
use quil_types::error::Result;

use crate::worker::WorkerManager;
#[cfg(test)]
use crate::worker::WorkerInfo;

/// Proposal never landed in the registry within this many frames → clear.
pub const PROPOSAL_TIMEOUT_FRAMES: u64 = 10;
/// Pending join/leave not confirmed within this many frames → clear.
pub const PENDING_FILTER_GRACE_FRAMES: u64 = 720;
/// Confirm join after this many frames.
pub const CONFIRM_WINDOW_FRAMES: u64 = 360;
/// Minimum frames between join attempts.
///
/// Single source of truth — ProverLifecycle consults
/// `WorkerAllocator::last_join_attempt()` and this constant via
/// `join_proposal_ready`, matching Go's per-allocator field at
/// `worker_allocator.go:1306`.
pub const JOIN_COOLDOWN_FRAMES: u64 = 4;

/// Snapshot of the current allocation state across the network.
#[derive(Debug, Clone)]
pub struct AllocationSnapshot {
    /// Number of active provers per shard filter.
    pub shard_prover_counts: HashMap<Vec<u8>, usize>,
    /// Total active provers across all shards.
    pub total_active_provers: usize,
    /// Total number of shards.
    pub total_shards: usize,
}

/// Tracks the mapping between workers and their shard assignments.
pub struct WorkerAllocator {
    worker_manager: Arc<dyn WorkerManager>,
    prover_registry: Arc<dyn ProverRegistry>,
    /// This node's prover address (32 bytes).
    local_prover_address: Vec<u8>,
    /// Last frame where a join was attempted (debounce).
    last_join_attempt_frame: std::sync::atomic::AtomicU64,
}

impl WorkerAllocator {
    pub fn new(
        worker_manager: Arc<dyn WorkerManager>,
        prover_registry: Arc<dyn ProverRegistry>,
        local_prover_address: Vec<u8>,
    ) -> Self {
        Self {
            worker_manager,
            prover_registry,
            local_prover_address,
            last_join_attempt_frame: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Most recent frame at which this node emitted a join proposal.
    /// Single source of truth for the join-proposal cooldown gate —
    /// `ProverLifecycle::join_proposal_ready` reads this.
    pub fn last_join_attempt(&self) -> u64 {
        self.last_join_attempt_frame
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record that this node emitted a join proposal at `frame_number`.
    /// Called by ProverLifecycle just before it returns ProposeJoin so
    /// the next 4 frames are cooled down.
    pub fn set_last_join_attempt(&self, frame_number: u64) {
        self.last_join_attempt_frame
            .store(frame_number, std::sync::atomic::Ordering::Relaxed);
    }

    /// Called on each new global frame. Reconciles the prover registry's
    /// allocations against running worker threads.
    ///
    /// Key timing constants:
    /// - `PROPOSAL_TIMEOUT_FRAMES = 10`: proposal never landed → clear filter
    /// - `PENDING_FILTER_GRACE_FRAMES = 720`: pending join not confirmed → clear
    pub fn on_new_frame(&self, frame_number: u64) -> Result<()> {
        // Get our prover info from the registry
        let prover_info = self
            .prover_registry
            .get_prover_info(&self.local_prover_address)?;

        let Some(prover) = prover_info else {
            // Not registered — nothing to reconcile
            return Ok(());
        };

        // Build lookup from filter → allocation status
        let alloc_by_filter: HashMap<Vec<u8>, &quil_types::consensus::ProverAllocationInfo> = prover
            .allocations
            .iter()
            .map(|a| (a.confirmation_filter.clone(), a))
            .collect();

        // Get current worker assignments
        let workers = self.worker_manager.range_workers()?;

        for worker in &workers {
            if worker.filter.is_empty() {
                continue; // idle worker — nothing to reconcile
            }

            match alloc_by_filter.get(&worker.filter) {
                Some(alloc) => {
                    match alloc.status {
                        ProverStatus::Active | ProverStatus::Paused => {
                            // Confirmed allocation — worker is correctly assigned
                        }
                        ProverStatus::Joining => {
                            // Pending join — check if it's been too long
                            if alloc.join_frame_number > 0
                                && frame_number > alloc.join_frame_number + PENDING_FILTER_GRACE_FRAMES
                            {
                                info!(
                                    core_id = worker.core_id,
                                    filter = hex::encode(&worker.filter),
                                    join_frame = alloc.join_frame_number,
                                    "join expired after 720 frames, clearing worker"
                                );
                                self.worker_manager.deallocate_worker(worker.core_id)?;
                            }
                        }
                        ProverStatus::Left | ProverStatus::Rejected | ProverStatus::Kicked => {
                            // Allocation ended — clear immediately
                            info!(
                                core_id = worker.core_id,
                                filter = hex::encode(&worker.filter),
                                status = ?alloc.status,
                                "allocation ended, clearing worker"
                            );
                            self.worker_manager.deallocate_worker(worker.core_id)?;
                        }
                        _ => {}
                    }
                }
                None => {
                    // Worker has a filter but no matching registry allocation.
                    // This means our proposal was never picked up.
                    if worker.pending_filter_frame > 0
                        && frame_number > worker.pending_filter_frame + PROPOSAL_TIMEOUT_FRAMES
                    {
                        info!(
                            core_id = worker.core_id,
                            filter = hex::encode(&worker.filter),
                            pending_since = worker.pending_filter_frame,
                            "proposal timed out after 10 frames, clearing worker"
                        );
                        self.worker_manager.deallocate_worker(worker.core_id)?;
                    } else if worker.pending_filter_frame == 0
                        && frame_number > PENDING_FILTER_GRACE_FRAMES
                    {
                        // Legacy case: filter was set but no pending frame tracked.
                        // Give 720-frame grace then clear.
                        info!(
                            core_id = worker.core_id,
                            filter = hex::encode(&worker.filter),
                            "orphaned filter with no pending frame, clearing worker"
                        );
                        self.worker_manager.deallocate_worker(worker.core_id)?;
                    }
                }
            }
        }

        // Assign unallocated active/joining filters to idle workers
        let assigned_filters: std::collections::HashSet<Vec<u8>> = self
            .worker_manager
            .range_workers()?
            .iter()
            .filter(|w| !w.filter.is_empty())
            .map(|w| w.filter.clone())
            .collect();

        let mut idle_workers: Vec<u32> = self
            .worker_manager
            .range_workers()?
            .iter()
            .filter(|w| w.filter.is_empty() && !w.manually_managed)
            .map(|w| w.core_id)
            .collect();
        idle_workers.sort();

        for alloc in &prover.allocations {
            if alloc.status != ProverStatus::Active && alloc.status != ProverStatus::Joining {
                continue;
            }
            if assigned_filters.contains(&alloc.confirmation_filter) {
                continue;
            }
            if let Some(core_id) = idle_workers.pop() {
                info!(
                    core_id,
                    filter = hex::encode(&alloc.confirmation_filter),
                    status = ?alloc.status,
                    "assigning shard to worker"
                );
                self.worker_manager
                    .allocate_worker(core_id, &alloc.confirmation_filter)?;
            }
        }

        Ok(())
    }

    /// Check if this node should propose a join for unallocated shards.
    /// Returns the filters that need join proposals.
    pub fn pending_join_filters(&self) -> Result<Vec<Vec<u8>>> {
        let prover_info = self
            .prover_registry
            .get_prover_info(&self.local_prover_address)?;

        let Some(prover) = prover_info else {
            return Ok(Vec::new());
        };

        Ok(prover
            .allocations
            .iter()
            .filter(|a| a.status == ProverStatus::Joining)
            .map(|a| a.confirmation_filter.clone())
            .collect())
    }

    /// Number of idle workers available for new shard assignments.
    pub fn idle_worker_count(&self) -> Result<usize> {
        let workers = self.worker_manager.range_workers()?;
        Ok(workers.iter().filter(|w| w.filter.is_empty()).count())
    }

    /// Build a snapshot of the current allocation state across all shards.
    /// Used by the ProversManager for scoring and decision-making.
    pub fn collect_allocation_snapshot(&self) -> Result<AllocationSnapshot> {
        let all_provers = self.prover_registry.get_all_active_app_shard_provers()?;

        let mut shard_prover_counts: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut total_provers = 0usize;

        for prover in &all_provers {
            for alloc in &prover.allocations {
                if alloc.status == ProverStatus::Active {
                    *shard_prover_counts
                        .entry(alloc.confirmation_filter.clone())
                        .or_default() += 1;
                    total_provers += 1;
                }
            }
        }

        let total_shards = shard_prover_counts.len();
        Ok(AllocationSnapshot {
            shard_prover_counts,
            total_active_provers: total_provers,
            total_shards,
        })
    }

    /// Log the current allocation status.
    pub fn log_status(&self) -> Result<()> {
        let workers = self.worker_manager.range_workers()?;
        let active = workers.iter().filter(|w| !w.filter.is_empty()).count();
        let idle = workers.len() - active;
        info!(
            total_workers = workers.len(),
            active,
            idle,
            "worker allocation status"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::consensus::*;
    use std::sync::Mutex;

    struct MockWorkerManager {
        workers: Mutex<HashMap<u32, Vec<u8>>>,
    }

    impl MockWorkerManager {
        fn new() -> Self {
            Self {
                workers: Mutex::new(HashMap::new()),
            }
        }
    }

    impl WorkerManager for MockWorkerManager {
        fn allocate_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
            self.workers
                .lock()
                .unwrap()
                .insert(core_id, filter.to_vec());
            Ok(())
        }

        fn deallocate_worker(&self, core_id: u32) -> Result<()> {
            self.workers.lock().unwrap().remove(&core_id);
            Ok(())
        }

        fn check_workers_connected(&self) -> Result<Vec<u32>> {
            Ok(self.workers.lock().unwrap().keys().copied().collect())
        }

        fn range_workers(&self) -> Result<Vec<WorkerInfo>> {
            Ok(self
                .workers
                .lock()
                .unwrap()
                .iter()
                .map(|(&id, f)| WorkerInfo {
                    core_id: id,
                    filter: f.clone(),
                    available_storage: 0,
                    total_storage: 0,
                    manually_managed: false,
                    pending_filter_frame: 0,
                })
                .collect())
        }

        fn respawn_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
            self.allocate_worker(core_id, filter)
        }
    }

    struct MockRegistry {
        prover: Mutex<Option<ProverInfo>>,
    }

    impl MockRegistry {
        fn with_prover(info: ProverInfo) -> Self {
            Self {
                prover: Mutex::new(Some(info)),
            }
        }
    }

    impl ProverRegistry for MockRegistry {
        fn refresh(&self) -> Result<()> { Ok(()) }
        fn get_all_active_app_shard_provers(&self) -> Result<Vec<ProverInfo>> { Ok(vec![]) }
        fn get_prover_info(&self, _addr: &[u8]) -> Result<Option<ProverInfo>> {
            Ok(self.prover.lock().unwrap().clone())
        }
        fn get_next_prover(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>> { Ok(vec![]) }
        fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<Vec<u8>>> { Ok(vec![]) }
        fn get_active_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> { Ok(vec![]) }
        fn get_prover_count(&self, _: &[u8]) -> Result<usize> { Ok(0) }
        fn get_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> { Ok(vec![]) }
        fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> Result<Vec<ProverInfo>> { Ok(vec![]) }
        fn update_prover_activity(&self, _: &[u8], _: &[u8], _: u64) -> Result<()> { Ok(()) }
        fn get_prover_shard_summaries(&self) -> Result<Vec<ProverShardSummary>> { Ok(vec![]) }
        fn prune_orphan_joins(&self, _: u64) -> Result<()> { Ok(()) }
        fn evict_inactive_provers(&self, _: u64, _: u64, _: &std::collections::HashMap<String, u64>) -> Result<Vec<Vec<u8>>> { Ok(vec![]) }
        fn current_frame(&self) -> u64 { 0 }
    }

    fn make_alloc(filter: Vec<u8>) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: filter,
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
            vertex_address: vec![],
        }
    }

    #[test]
    fn no_prover_does_nothing() {
        let wm = Arc::new(MockWorkerManager::new());
        let reg = Arc::new(MockRegistry { prover: Mutex::new(None) });
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.on_new_frame(100).unwrap();
        assert!(wm.range_workers().unwrap().is_empty());
    }

    #[test]
    fn allocates_active_filters_to_idle_workers() {
        let wm = Arc::new(MockWorkerManager::new());
        // Pre-create 2 idle workers
        wm.allocate_worker(1, &[]).unwrap();
        wm.allocate_worker(2, &[]).unwrap();

        let prover = ProverInfo {
            public_key: vec![0xBB; 585],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![
                make_alloc(vec![0x01; 32]),
                make_alloc(vec![0x02; 32]),
            ],
            available_storage: 0,
            seniority: 100,
            delegate_address: vec![],
        };

        let reg = Arc::new(MockRegistry::with_prover(prover));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.on_new_frame(101).unwrap();

        let workers = wm.range_workers().unwrap();
        assert_eq!(workers.len(), 2);
        let assigned: Vec<Vec<u8>> = workers.iter().map(|w| w.filter.clone()).collect();
        assert!(assigned.contains(&vec![0x01; 32]));
        assert!(assigned.contains(&vec![0x02; 32]));
    }

    #[test]
    fn deallocates_stale_filters() {
        let wm = Arc::new(MockWorkerManager::new());
        // Worker with a filter that's no longer active
        wm.allocate_worker(1, &[0x99; 32]).unwrap();

        let prover = ProverInfo {
            public_key: vec![],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![], // no active allocations
            available_storage: 0,
            seniority: 0,
            delegate_address: vec![],
        };

        let reg = Arc::new(MockRegistry::with_prover(prover));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        // Frame must be > PENDING_FILTER_GRACE_FRAMES (720) for orphaned
        // filters with pending_filter_frame=0 to be cleared.
        alloc.on_new_frame(1000).unwrap();

        // Worker should have been deallocated
        assert!(wm.range_workers().unwrap().is_empty());
    }
}
