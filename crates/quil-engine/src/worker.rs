use quil_types::error::Result;

/// Worker manager: coordinates data worker processes for parallel
/// proof computation across shards.
pub trait WorkerManager: Send + Sync {
    fn allocate_worker(&self, core_id: u32, filter: &[u8]) -> Result<()>;
    fn deallocate_worker(&self, core_id: u32) -> Result<()>;
    fn check_workers_connected(&self) -> Result<Vec<u32>>;
    fn range_workers(&self) -> Result<Vec<WorkerInfo>>;
    fn respawn_worker(&self, core_id: u32, filter: &[u8]) -> Result<()>;

    /// Record the frame at which a join proposal was submitted for this
    /// worker. `reconcileWorkerAllocations` uses this to detect stale
    /// proposals (cleared after PROPOSAL_TIMEOUT_FRAMES if the registry
    /// never picked them up). Cleared back to 0 on confirmed allocation.
    ///
    /// Mirrors Go's `WorkerInfo.PendingFilterFrame` field.
    fn set_pending_filter_frame(&self, core_id: u32, frame: u64) -> Result<()> {
        let _ = (core_id, frame);
        Ok(())
    }

    /// Set the `manually_managed` flag on a worker. When set, the
    /// lifecycle skips the worker during auto-allocation — useful
    /// when an operator wants to pin a worker to a specific filter
    /// via external tooling.
    ///
    /// Mirrors Go's `WorkerInfo.ManuallyManaged` field.
    fn set_manually_managed(&self, core_id: u32, manually_managed: bool) -> Result<()> {
        let _ = (core_id, manually_managed);
        Ok(())
    }

    /// Set the `allocated` flag — true when the worker's filter has a
    /// confirmed Active or Paused allocation in the registry, false
    /// when filter-pinned but awaiting confirm. Mirrors Go's
    /// `WorkerInfo.Allocated` field. The lifecycle layer reads this
    /// to compute `unallocatedWorkerCount`, which caps confirms in
    /// `decide_joins`.
    fn set_allocated(&self, core_id: u32, allocated: bool) -> Result<()> {
        let _ = (core_id, allocated);
        Ok(())
    }
}

/// Information about a worker process.
#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub core_id: u32,
    pub filter: Vec<u8>,
    pub available_storage: u64,
    pub total_storage: u64,
    pub manually_managed: bool,
    /// Frame number when this worker's filter was proposed (pending join).
    /// 0 means the allocation is confirmed (active).
    /// Used for expiry: if `frame_number - pending_filter_frame > 10`, the
    /// proposal timed out and the filter should be cleared.
    pub pending_filter_frame: u64,
    /// Whether the worker's filter is fully active in the registry
    /// (allocation Status=Active or Paused). When false but `filter` is
    /// set, the worker is "filter-pinned" awaiting confirm or has just
    /// been provisioned for a pending allocation.
    ///
    /// Mirrors Go's `WorkerInfo.Allocated` field at
    /// `types/store/worker.go:10`. `unallocatedWorkerCount` in
    /// `proposer.go:537-553` counts workers with `!Allocated` — the
    /// availableWorkers cap in `decide_joins` derives from this count.
    pub allocated: bool,
}
