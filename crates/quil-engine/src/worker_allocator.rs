//! Worker allocation logic. Port of
//! `node/consensus/global/worker_allocator.go`.
//!
//! Decides which shards this node's workers should handle. On each
//! new global frame, reconciles the prover registry's allocations
//! against the running worker threads and spawns/stops as needed.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info, warn};

use quil_types::consensus::{ProverRegistry, ProverStatus};
use quil_types::error::Result;

use crate::worker::WorkerManager;
#[cfg(test)]
use crate::worker::WorkerInfo;

// =====================================================================
// Config-driven static filter pinning
// =====================================================================

/// Result of applying `engine.data_worker_filters` from config.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigFilterApplyStats {
    /// Workers we successfully pinned + marked manually_managed.
    pub applied: usize,
    /// Slots skipped because the worker already had a non-empty filter
    /// (persisted state from a prior gRPC edit takes precedence).
    pub skipped_existing: usize,
    /// Slots skipped because no worker exists at that core_id (more
    /// filters than worker threads).
    pub skipped_missing_core: usize,
    /// Entries skipped because they were empty or whitespace.
    pub skipped_empty: usize,
    /// Entries skipped because hex decode failed.
    pub invalid: usize,
}

/// Apply `engine.data_worker_filters` to the worker manager. Each
/// entry is a hex string (with optional `0x` prefix); index `i` in the
/// array maps to `core_id = i + 1` (core 0 is the master).
///
/// Behavior:
///
/// - Empty / whitespace entries are skipped — they encode "operator
///   deliberately wants worker (i+1) left idle / auto-managed."
/// - Invalid hex is logged and counted as `invalid`. Decoding is
///   tolerant: leading `0x` (any case) is stripped first.
/// - If no worker exists at `core_id` (the operator declared more
///   filters than CPU cores), the entry is skipped with a warning.
/// - **Persisted state wins**: if a worker already has a non-empty
///   `filter` (restored from the worker store from a prior gRPC edit,
///   or already pinned by some earlier startup step), config does NOT
///   override it. This means an operator who flipped the assignment
///   via `NodeService::set_manually_managed` + `request_join` keeps
///   their runtime decision across restarts.
/// - Otherwise: pin the filter with `set_worker_filter(core_id,
///   filter, start_consensus=false)` and mark the worker
///   `manually_managed=true`. `start_consensus=false` because we
///   don't yet know whether a matching registry allocation exists —
///   the auto-allocator will start the consensus engine when it
///   observes the alloc transition to Active.
///
/// **NOTE on parity with Go.** Go's reference uses
/// `engine.DataWorkerFilters` only to build per-shard PeerInfo
/// reachability advertisements (see
/// `node/consensus/global/global_consensus_engine.go:1596-1610`). Worker
/// allocation in Go comes from the prover registry alone. This Rust
/// behavior is an *extension* — operators who set
/// `dataWorkerFilters` in YAML get declarative worker→filter pinning
/// in addition to the PeerInfo advertisement role. Both behaviors
/// share the same config field but are wired independently. (PeerInfo
/// integration of `data_worker_filters` is a separate, currently
/// unwired gap.)
pub fn apply_config_worker_filters(
    worker_manager: &dyn WorkerManager,
    config_filters: &[String],
) -> ConfigFilterApplyStats {
    let mut stats = ConfigFilterApplyStats::default();

    if config_filters.is_empty() {
        return stats;
    }

    // Snapshot current worker state (post-persisted-restore,
    // post-pre-allocation). We read once instead of per-iteration to
    // avoid a race where a concurrent reconcile mutates the workers
    // mid-pass; the startup ordering already guarantees the
    // allocator's reconcile loop hasn't started, but this is also
    // simpler and cheaper.
    let current: HashMap<u32, Vec<u8>> = match worker_manager.range_workers() {
        Ok(v) => v.into_iter().map(|w| (w.core_id, w.filter)).collect(),
        Err(e) => {
            warn!(
                error = %e,
                "apply_config_worker_filters: range_workers failed; aborting"
            );
            return stats;
        }
    };

    for (i, hex_str) in config_filters.iter().enumerate() {
        let trimmed = hex_str.trim();
        let stripped = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if stripped.is_empty() {
            stats.skipped_empty += 1;
            continue;
        }

        let filter_bytes = match hex::decode(stripped) {
            Ok(b) if !b.is_empty() => b,
            Ok(_) => {
                // Decoded successfully to zero bytes — treat as empty.
                stats.skipped_empty += 1;
                continue;
            }
            Err(e) => {
                stats.invalid += 1;
                warn!(
                    index = i,
                    value = %hex_str,
                    error = %e,
                    "data_worker_filters: invalid hex; skipping"
                );
                continue;
            }
        };

        let core_id = (i as u32) + 1;
        let Some(existing) = current.get(&core_id) else {
            stats.skipped_missing_core += 1;
            warn!(
                index = i,
                core_id,
                "data_worker_filters: no worker at core_id; skipping (more filters than CPU cores?)"
            );
            continue;
        };

        if !existing.is_empty() {
            stats.skipped_existing += 1;
            debug!(
                core_id,
                existing_filter = hex::encode(existing),
                config_filter = hex::encode(&filter_bytes),
                "data_worker_filters: worker already has a filter; persisted state wins"
            );
            continue;
        }

        // `start_consensus=false`: don't spin up the AppConsensusEngine
        // yet. The auto-allocator's first reconcile pass will start
        // the engine when it observes the registry alloc for this
        // filter transition to Active.
        if let Err(e) = worker_manager.set_worker_filter(core_id, &filter_bytes, false) {
            warn!(
                core_id,
                error = %e,
                "data_worker_filters: set_worker_filter failed; skipping"
            );
            continue;
        }
        if let Err(e) = worker_manager.set_manually_managed(core_id, true) {
            warn!(
                core_id,
                error = %e,
                "data_worker_filters: set_manually_managed failed (filter still pinned)"
            );
            // Don't bail out — the filter pin succeeded; the manual
            // flag is best-effort. Operator can re-flip via gRPC.
        }
        stats.applied += 1;
        info!(
            core_id,
            filter = hex::encode(&filter_bytes),
            "data_worker_filters: pinned worker to declared filter (manually_managed=true)"
        );
    }

    stats
}

/// Proposal never landed in the registry within this many frames → clear.
pub const PROPOSAL_TIMEOUT_FRAMES: u64 = 10;
/// Pending join/leave not confirmed within this many frames → clear.
pub const PENDING_FILTER_GRACE_FRAMES: u64 = 720;
// Confirm window lives on `ProverLifecycle` so testnet bootstraps can
// override it to a small value. Mainnet default is 360 — see
// `crate::provers::lifecycle::DEFAULT_CONFIRM_WINDOW_FRAMES`.
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
/// The cooldown kinds tracked by [`WorkerAllocator`]. Each gates a
/// distinct proposer side-effect (join, forced-reject batch,
/// seniority merge). Adding a new cooldown is a single enum variant
/// plus a `[AtomicU64; N]` constant update — no parallel
/// getter/setter pair to maintain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cooldown {
    /// Last frame at which a ProverJoin was proposed. 4-frame
    /// cooldown — `ProverLifecycle::propose_ready` reads this.
    Join = 0,
    /// Last frame at which a forced-reject batch was emitted for
    /// excess pending joins. Matches Go's `engine.lastRejectFrame`
    /// at `worker_allocator.go:1395-1412`.
    Reject = 1,
    /// Last frame at which a seniority-merge attempt was made.
    /// 10-frame cooldown (worker_allocator.go:980-998).
    SeniorityMerge = 2,
}

const COOLDOWN_KINDS: usize = 3;

pub struct WorkerAllocator {
    worker_manager: Arc<dyn WorkerManager>,
    prover_registry: Arc<dyn ProverRegistry>,
    /// This node's prover address (32 bytes).
    local_prover_address: Vec<u8>,
    /// Per-`Cooldown` last-attempt-frame counter. Indexed by
    /// `Cooldown as usize`. A separate `[AtomicU64; N]` instead of
    /// a `HashMap` because the kind set is small, fixed, and
    /// known at compile time — no need to pay for hashing or
    /// allocation on every access.
    cooldowns: [std::sync::atomic::AtomicU64; COOLDOWN_KINDS],
    /// Cached aggregated-seniority estimate for our local peer IDs
    /// (own + any `multisig_prover_enrollment_paths`), computed once at
    /// startup from `seniority_compat::get_aggregated_seniority`. Matches
    /// Go's `estimateSeniorityFromConfig` return value. `u64::MAX`
    /// sentinel means "not yet computed"; lifecycle treats that as 0.
    config_seniority_estimate: std::sync::atomic::AtomicU64,
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
            cooldowns: [
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
            ],
            config_seniority_estimate: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Cached config-derived seniority estimate. Computed once at
    /// startup by the node binary (which has the config + local peer
    /// key available). 0 if not wired.
    pub fn config_seniority_estimate(&self) -> u64 {
        let v = self
            .config_seniority_estimate
            .load(std::sync::atomic::Ordering::Relaxed);
        if v == u64::MAX { 0 } else { v }
    }

    /// Record the config-derived seniority estimate at startup.
    pub fn set_config_seniority_estimate(&self, estimate: u64) {
        self.config_seniority_estimate
            .store(estimate, std::sync::atomic::Ordering::Relaxed);
    }

    /// Most recent frame at which this node attempted `kind`. The
    /// canonical read for cooldown gates — see
    /// `LifecycleReadiness::propose_ready`.
    pub fn last_attempt(&self, kind: Cooldown) -> u64 {
        self.cooldowns[kind as usize].load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record an attempt of `kind` at `frame_number`. Monotonic via
    /// `fetch_max` so out-of-order callers can't accidentally
    /// regress the cooldown clock.
    pub fn record_attempt(&self, kind: Cooldown, frame_number: u64) {
        self.cooldowns[kind as usize]
            .fetch_max(frame_number, std::sync::atomic::Ordering::Relaxed);
    }

    // ---------------------------------------------------------------
    // Compatibility shims — callers gradually migrating to the
    // `Cooldown` enum can keep using these named methods.
    // ---------------------------------------------------------------

    pub fn last_seniority_merge_attempt(&self) -> u64 {
        self.last_attempt(Cooldown::SeniorityMerge)
    }
    pub fn set_last_seniority_merge_attempt(&self, frame_number: u64) {
        self.record_attempt(Cooldown::SeniorityMerge, frame_number);
    }
    pub fn last_reject_attempt(&self) -> u64 {
        self.last_attempt(Cooldown::Reject)
    }
    pub fn set_last_reject_attempt(&self, frame_number: u64) {
        self.record_attempt(Cooldown::Reject, frame_number);
    }
    pub fn last_join_attempt(&self) -> u64 {
        self.last_attempt(Cooldown::Join)
    }

    /// Record that this node emitted a join proposal at `frame_number`.
    /// Called by ProverLifecycle just before it returns ProposeJoin so
    /// the next 4 frames are cooled down.
    pub fn set_last_join_attempt(&self, frame_number: u64) {
        self.record_attempt(Cooldown::Join, frame_number);
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
                // Idle worker — but check for an expired pending-join
                // marker. `submit_join` sets `pending_filter_frame`
                // BEFORE the alloc lands in the registry (so the
                // lifecycle's `free_auto()` won't re-pick the same
                // worker mid-flight). If the join never lands
                // (archive silently rejected the bundle, network
                // drop, or the alloc-binding pass below didn't see
                // a matching alloc within the 10-frame window), the
                // marker would otherwise persist indefinitely and
                // the worker stays excluded from `free_auto()` —
                // wedging the entire lifecycle (no free workers →
                // `allow_proposals = false` → no new ProposeJoin).
                // Mirror the 10-frame `PROPOSAL_TIMEOUT_FRAMES`
                // ceiling used below for filter-pinned-but-
                // unallocated workers.
                if worker.pending_filter_frame > 0
                    && frame_number
                        > worker.pending_filter_frame + PROPOSAL_TIMEOUT_FRAMES
                {
                    // Warn, not info — silent failures are exactly the
                    // class of bug this telemetry needs to surface. A
                    // submit_join returned Ok (no transport error
                    // visible) but the alloc never showed up in the
                    // registry within 10 frames, which means an
                    // archive accepted the bundle and then dropped
                    // it during materialization (typical causes:
                    // stale frame_number on archive-side materialize,
                    // BLS / VDF rejection, prover-state gate). The
                    // operator can spot a string of these in the log
                    // and dig in before the lifecycle's retry burns
                    // more attempts.
                    warn!(
                        core_id = worker.core_id,
                        pending_since = worker.pending_filter_frame,
                        frames_elapsed = frame_number - worker.pending_filter_frame,
                        "join submitted but no alloc landed in registry within 10 frames \
                         — archive likely dropped the bundle silently"
                    );
                    let _ = self
                        .worker_manager
                        .set_pending_filter_frame(worker.core_id, 0);
                }
                continue;
            }

            match alloc_by_filter.get(&worker.filter) {
                Some(alloc) => {
                    // Tier-5 #8/#9: compute desired_allocated AFTER the
                    // expired-join/leave reset, mirroring Go's
                    // worker_allocator.go:421-422 + 781-816. Paused
                    // counts as "desired allocated" alongside Active —
                    // the registry maintains the filter binding while
                    // the worker pauses.
                    let mut desired_allocated = matches!(
                        alloc.status,
                        ProverStatus::Active | ProverStatus::Paused
                    );

                    match alloc.status {
                        ProverStatus::Active | ProverStatus::Paused => {
                            // Confirmed allocation — worker is correctly assigned
                        }
                        ProverStatus::Joining => {
                            // Expired Joining → implicitly rejected
                            // by the protocol; clear the worker.
                            // Uses `effective_status` to consolidate
                            // the 720-frame grace check.
                            if alloc.effective_status(frame_number)
                                == quil_types::consensus::EffectiveStatus::ExpiredJoining
                            {
                                desired_allocated = false;
                                info!(
                                    core_id = worker.core_id,
                                    filter = hex::encode(&worker.filter),
                                    join_frame = alloc.join_frame_number,
                                    "join expired after 720 frames, clearing worker"
                                );
                                self.worker_manager.deallocate_worker(worker.core_id)?;
                            }
                        }
                        ProverStatus::Rejected | ProverStatus::Kicked => {
                            // Allocation terminally ended — clear
                            // immediately. `Rejected` = join was
                            // rejected; `Kicked` = leave-confirmed
                            // (alloc status byte 5) OR evicted.
                            //
                            // `ProverStatus::Leaving` deliberately
                            // does NOT belong here — it's the
                            // in-flight state (alloc status byte 3,
                            // matching Go's `ProverStatusLeaving`).
                            // The allocation isn't terminal yet; the
                            // worker must stay bound until a Confirm
                            // flips it to `Kicked` or a Reject flips
                            // it back to `Active`.
                            desired_allocated = false;
                            debug!(
                                core_id = worker.core_id,
                                filter = hex::encode(&worker.filter),
                                status = ?alloc.status,
                                "allocation ended, clearing worker"
                            );
                            self.worker_manager.deallocate_worker(worker.core_id)?;
                        }
                        ProverStatus::Leaving => {
                            // Leave in flight — keep the worker bound
                            // until Confirm/Reject resolves.
                        }
                        _ => {}
                    }

                    // Plumb desired_allocated → WorkerInfo.allocated.
                    // The lifecycle layer reads this for
                    // unallocatedWorkerCount → decide_joins
                    // availableWorkers cap (Go proposer.go:537-553).
                    if worker.allocated != desired_allocated {
                        // Joining → Active transition: the engine
                        // wasn't started when we filter-pinned the
                        // worker (start_consensus=false). Now that
                        // the prover is Active, kick off the
                        // AppConsensusEngine for this filter.
                        if !worker.allocated && desired_allocated {
                            info!(
                                core_id = worker.core_id,
                                filter = hex::encode(&worker.filter),
                                "alloc transitioned to Active — starting consensus engine"
                            );
                            self.worker_manager.set_worker_filter(
                                worker.core_id,
                                &worker.filter,
                                true,
                            )?;
                        }
                        let _ = self
                            .worker_manager
                            .set_allocated(worker.core_id, desired_allocated);
                    }
                }
                None => {
                    // Worker has a filter but no matching registry allocation.
                    // This means our proposal was never picked up.
                    // Filter-pinned but unallocated — flag accordingly.
                    if worker.allocated {
                        let _ = self.worker_manager.set_allocated(worker.core_id, false);
                    }
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

        // Manually-managed-but-unbound workers — the operator picked
        // these via the TUI's worker-selector at join time. We
        // consume them first when binding new Joining/Active
        // allocations to filters, so the user's selection is
        // honored. Sorted ascending so `pop()` gives the
        // highest-numbered first (matches `idle_workers` ordering;
        // operators typically pick contiguous low-numbered workers).
        let mut manual_pending: Vec<u32> = self
            .worker_manager
            .range_workers()?
            .iter()
            .filter(|w| w.filter.is_empty() && w.manually_managed)
            .map(|w| w.core_id)
            .collect();
        manual_pending.sort();

        for alloc in &prover.allocations {
            // Bind the filter for any non-expired allocation —
            // including Joining — so the TUI and the user can see
            // which worker owns which filter from the moment the
            // join lands. Mirrors Go's `worker_allocator.go:404-440`
            // where `freeWorkers[0]` gets `worker.Filter = alloc.ConfirmationFilter`
            // regardless of status, and `worker.Allocated` separately
            // tracks Active/Paused.
            //
            // Skip terminal states and allocations past the
            // 720-frame grace (won't ever confirm). One predicate
            // covers both via `effective_status`.
            use quil_types::consensus::EffectiveStatus;
            match alloc.effective_status(frame_number) {
                EffectiveStatus::Active
                | EffectiveStatus::Paused
                | EffectiveStatus::Joining => {}
                _ => continue,
            }
            if assigned_filters.contains(&alloc.confirmation_filter) {
                continue;
            }
            // Prefer a manually-pending (user-picked) worker before
            // falling back to the auto-managed idle pool.
            let pick = manual_pending.pop().or_else(|| idle_workers.pop());
            if let Some(core_id) = pick {
                let start_consensus = matches!(
                    alloc.status,
                    ProverStatus::Active | ProverStatus::Paused
                );
                let manual = !manual_pending
                    .contains(&core_id)  // we just popped it
                    && self
                        .worker_manager
                        .range_workers()
                        .ok()
                        .and_then(|ws| ws.into_iter().find(|w| w.core_id == core_id))
                        .map(|w| w.manually_managed)
                        .unwrap_or(false);
                info!(
                    core_id,
                    filter = hex::encode(&alloc.confirmation_filter),
                    status = ?alloc.status,
                    start_consensus,
                    manual,
                    "assigning shard to worker"
                );
                self.worker_manager.set_worker_filter(
                    core_id,
                    &alloc.confirmation_filter,
                    start_consensus,
                )?;
            }
        }

        Ok(())
    }

    /// Check if this node should propose a join for unallocated shards.
    /// Returns the filters of allocations currently Joining and still
    /// within the 720-frame grace window. Allocations whose Joining
    /// status has already expired (no Confirm/Reject within
    /// `PENDING_FILTER_GRACE_FRAMES`) are excluded so the caller
    /// doesn't re-propose them — they're effectively rejected and
    /// will be replaced by fresh proposals.
    pub fn pending_join_filters(&self, frame_number: u64) -> Result<Vec<Vec<u8>>> {
        let prover_info = self
            .prover_registry
            .get_prover_info(&self.local_prover_address)?;

        let Some(prover) = prover_info else {
            return Ok(Vec::new());
        };

        Ok(prover
            .allocations
            .iter()
            .filter(|a| {
                a.effective_status(frame_number)
                    == quil_types::consensus::EffectiveStatus::Joining
            })
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

    use crate::test_support::{TestProverRegistry, TestWorkerManager as MockWorkerManager};

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
        let reg = Arc::new(TestProverRegistry::new());
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

        let reg = Arc::new(TestProverRegistry::with_prover(prover));
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

        let reg = Arc::new(TestProverRegistry::with_prover(prover));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        // Frame must be > PENDING_FILTER_GRACE_FRAMES (720) for orphaned
        // filters with pending_filter_frame=0 to be cleared.
        alloc.on_new_frame(1000).unwrap();

        // Worker should have been deallocated
        assert!(wm.range_workers().unwrap().is_empty());
    }

    // -----------------------------------------------------------------
    // apply_config_worker_filters
    // -----------------------------------------------------------------

    fn find_worker(wm: &MockWorkerManager, core_id: u32) -> WorkerInfo {
        wm.range_workers()
            .unwrap()
            .into_iter()
            .find(|w| w.core_id == core_id)
            .expect("worker not found")
    }

    #[test]
    fn apply_config_worker_filters_empty_config_is_noop() {
        let wm = MockWorkerManager::new();
        wm.allocate_worker(1, &[]).unwrap();

        let stats = apply_config_worker_filters(&wm, &[]);
        assert_eq!(stats, ConfigFilterApplyStats::default());

        let w = find_worker(&wm, 1);
        assert!(w.filter.is_empty());
        assert!(!w.manually_managed);
    }

    #[test]
    fn apply_config_worker_filters_pins_idle_workers_with_manual_flag() {
        let wm = MockWorkerManager::new();
        wm.allocate_worker(1, &[]).unwrap();
        wm.allocate_worker(2, &[]).unwrap();
        wm.allocate_worker(3, &[]).unwrap();

        // Index 0 -> core 1, index 1 -> core 2, index 2 (empty) -> skip.
        let cfg = vec![
            "0xaabbccdd".into(),
            "11223344".into(),
            "".into(),
        ];

        let stats = apply_config_worker_filters(&wm, &cfg);
        assert_eq!(stats.applied, 2);
        assert_eq!(stats.skipped_empty, 1);
        assert_eq!(stats.skipped_existing, 0);
        assert_eq!(stats.skipped_missing_core, 0);
        assert_eq!(stats.invalid, 0);

        let w1 = find_worker(&wm, 1);
        assert_eq!(w1.filter, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(w1.manually_managed);

        let w2 = find_worker(&wm, 2);
        assert_eq!(w2.filter, vec![0x11, 0x22, 0x33, 0x44]);
        assert!(w2.manually_managed);

        let w3 = find_worker(&wm, 3);
        assert!(w3.filter.is_empty());
        assert!(!w3.manually_managed);
    }

    #[test]
    fn apply_config_worker_filters_persisted_state_wins_over_config() {
        let wm = MockWorkerManager::new();
        // Core 1 was already pinned (persisted-restore happened
        // before this call). Operator's gRPC-driven assignment should
        // survive a YAML override.
        wm.allocate_worker(1, &[0xDE, 0xAD]).unwrap();
        wm.allocate_worker(2, &[]).unwrap();

        let cfg = vec!["0xbeef".into(), "0xcafe".into()];
        let stats = apply_config_worker_filters(&wm, &cfg);
        assert_eq!(stats.applied, 1, "only core 2 should apply");
        assert_eq!(stats.skipped_existing, 1);

        let w1 = find_worker(&wm, 1);
        assert_eq!(w1.filter, vec![0xDE, 0xAD], "core 1 unchanged");
        assert!(!w1.manually_managed, "core 1 manual flag untouched");

        let w2 = find_worker(&wm, 2);
        assert_eq!(w2.filter, vec![0xCA, 0xFE]);
        assert!(w2.manually_managed);
    }

    #[test]
    fn apply_config_worker_filters_skips_missing_cores() {
        let wm = MockWorkerManager::new();
        wm.allocate_worker(1, &[]).unwrap();

        // 3 filters but only 1 worker -> 2 skipped_missing_core.
        let cfg = vec!["aa".into(), "bb".into(), "cc".into()];
        let stats = apply_config_worker_filters(&wm, &cfg);
        assert_eq!(stats.applied, 1);
        assert_eq!(stats.skipped_missing_core, 2);

        let w1 = find_worker(&wm, 1);
        assert_eq!(w1.filter, vec![0xAA]);
    }

    #[test]
    fn apply_config_worker_filters_invalid_hex_is_counted_and_logged() {
        let wm = MockWorkerManager::new();
        wm.allocate_worker(1, &[]).unwrap();
        wm.allocate_worker(2, &[]).unwrap();

        let cfg = vec!["not hex at all".into(), "bb".into()];
        let stats = apply_config_worker_filters(&wm, &cfg);
        assert_eq!(stats.applied, 1, "core 2 still pins");
        assert_eq!(stats.invalid, 1);

        let w1 = find_worker(&wm, 1);
        assert!(w1.filter.is_empty(), "invalid entry leaves core 1 idle");
        assert!(!w1.manually_managed);

        let w2 = find_worker(&wm, 2);
        assert_eq!(w2.filter, vec![0xBB]);
        assert!(w2.manually_managed);
    }

    #[test]
    fn apply_config_worker_filters_strips_0x_prefix_case_insensitive() {
        let wm = MockWorkerManager::new();
        wm.allocate_worker(1, &[]).unwrap();
        wm.allocate_worker(2, &[]).unwrap();
        wm.allocate_worker(3, &[]).unwrap();

        let cfg = vec![
            "0xab".into(),
            "0XCD".into(),
            "ef".into(),
        ];
        let stats = apply_config_worker_filters(&wm, &cfg);
        assert_eq!(stats.applied, 3);

        assert_eq!(find_worker(&wm, 1).filter, vec![0xAB]);
        assert_eq!(find_worker(&wm, 2).filter, vec![0xCD]);
        assert_eq!(find_worker(&wm, 3).filter, vec![0xEF]);
    }

    #[test]
    fn apply_config_worker_filters_whitespace_only_entry_is_empty() {
        let wm = MockWorkerManager::new();
        wm.allocate_worker(1, &[]).unwrap();

        let cfg = vec!["   ".into()];
        let stats = apply_config_worker_filters(&wm, &cfg);
        assert_eq!(stats.applied, 0);
        assert_eq!(stats.skipped_empty, 1);

        assert!(find_worker(&wm, 1).filter.is_empty());
    }
}
