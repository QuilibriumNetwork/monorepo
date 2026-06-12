use quil_types::error::Result;

/// Worker manager: coordinates data worker processes for parallel
/// proof computation across shards.
pub trait WorkerManager: Send + Sync {
    /// Bind `core_id` to `filter` and (re)start the consensus engine.
    /// Equivalent to `set_worker_filter(core_id, filter, true)`.
    /// Kept as the default for callers that always want full
    /// consensus startup (e.g. dataWorkerFilters config-load).
    fn allocate_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
        self.set_worker_filter(core_id, filter, true)
    }

    /// Bind `core_id` to `filter`. `start_consensus`:
    ///   * `true`  — also (re)start `AppConsensusEngine` for this
    ///     filter. Use for `Active`/`Paused` allocations.
    ///   * `false` — record the filter binding only; do NOT spawn a
    ///     consensus engine. Use for `Joining` allocations whose
    ///     prover isn't Active yet (the engine's `leader_for_rank`
    ///     would die immediately). Mirrors Go's
    ///     `worker.Filter`-set / `worker.Allocated=false` state.
    fn set_worker_filter(
        &self,
        core_id: u32,
        filter: &[u8],
        start_consensus: bool,
    ) -> Result<()>;

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

/// Classified snapshot of every worker known to a `WorkerManager`,
/// taken once and consulted by the lifecycle, the allocator, and
/// RPC handlers. Centralizing the partitioning avoids the subtle
/// drift that arose when individual sites inlined their own
/// `range_workers().iter().filter(...)` calls.
///
/// Iterator helpers borrow from `all`, so they're zero-cost — no
/// extra allocations to walk a single bucket. Use `snapshot` to
/// build one; pass it by reference where consumers only need to
/// inspect, by value where they want to retain it across an
/// asynchronous boundary.
#[derive(Debug, Clone)]
pub struct WorkerView {
    /// Every worker in `range_workers()` order.
    pub all: Vec<WorkerInfo>,
}

impl WorkerView {
    /// Take a snapshot from a worker manager. On error, returns an
    /// empty view — matching the existing pattern in main.rs and
    /// the RPC layer, where individual call sites silently bailed
    /// to an empty `Vec` if `range_workers` failed.
    pub fn snapshot(wm: &dyn WorkerManager) -> Self {
        Self {
            all: wm.range_workers().unwrap_or_default(),
        }
    }

    /// Construct directly from a worker list. Useful for tests or
    /// for sites that already hold a `Vec<WorkerInfo>` (e.g. the
    /// RPC server's pre-cached workers_view).
    pub fn from_workers(all: Vec<WorkerInfo>) -> Self {
        Self { all }
    }

    /// Total number of workers.
    pub fn count(&self) -> usize {
        self.all.len()
    }

    /// Number of workers whose filter is set (allocated or
    /// filter-pinned-awaiting-confirm). The RPC layer's
    /// `allocated_workers` field maps to this.
    pub fn filter_set_count(&self) -> usize {
        self.filter_set().count()
    }

    /// Workers with `manually_managed = true`. The lifecycle skips
    /// these during auto-allocation.
    pub fn manual(&self) -> impl Iterator<Item = &WorkerInfo> {
        self.all.iter().filter(|w| w.manually_managed)
    }

    /// Workers eligible for auto-allocation: empty filter AND not
    /// manually managed AND no pending proposal in flight. The
    /// lifecycle's "free worker" cap is `free_auto().count()`.
    pub fn free_auto(&self) -> impl Iterator<Item = &WorkerInfo> {
        self.all
            .iter()
            .filter(|w| w.filter.is_empty() && !w.manually_managed && w.pending_filter_frame == 0)
    }

    /// Workers whose filter field is non-empty (either confirmed
    /// allocations or filter-pinned awaiting confirm).
    pub fn filter_set(&self) -> impl Iterator<Item = &WorkerInfo> {
        self.all.iter().filter(|w| !w.filter.is_empty())
    }

    /// Workers awaiting a pending proposal: empty filter but
    /// `pending_filter_frame > 0`. These should be considered
    /// "in flight" for capacity calculations but neither free nor
    /// allocated.
    pub fn pending(&self) -> impl Iterator<Item = &WorkerInfo> {
        self.all
            .iter()
            .filter(|w| w.filter.is_empty() && w.pending_filter_frame > 0)
    }
}
