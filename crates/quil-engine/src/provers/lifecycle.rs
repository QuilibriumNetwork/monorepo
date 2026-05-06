//! Prover lifecycle coordinator. Determines what the node should do
//! on each new frame: propose joins/leaves, confirm pending proposals,
//! or reject inferior ones.
//!
//! Port of Go's `evaluateForProposals` + `collectAllocationSnapshot`
//! in `node/consensus/global/worker_allocator.go`.
//!
//! Split of responsibilities with `WorkerAllocator`:
//!   - `WorkerAllocator::on_new_frame`: reconciles registry state with
//!     running workers (assigns filters to idle cores, clears stale
//!     filters). Pure state sync, no proposals.
//!   - `ProverLifecycle::evaluate`: examines registry + worker state
//!     and returns the full list of actions to submit this frame
//!     (matching Go's `evaluateForProposals`, which can emit Propose
//!     + Decide actions in the same cycle). The caller dispatches each
//!     through the submission pipeline; per-address locking in the
//!     consensus engine serializes them so only one takes effect per
//!     affected prover address per frame. The single cooldown timer
//!     lives on the `WorkerAllocator`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use num_bigint::BigInt;
use tracing::info;

use quil_types::consensus::{ProverRegistry, ProverShardSummary, ProverStatus};
use quil_types::error::Result;

use crate::halt_state::HaltState;
use crate::provers::proposer::{self, ShardDescriptor, Strategy};
use crate::worker::WorkerManager;
use crate::worker_allocator::WorkerAllocator;

/// Confirm window for pending joins/leaves (matches Go's 360 frames).
/// This is the mainnet default; testnet bootstraps may override via
/// [`ProverLifecycle::set_confirm_window_frames`] so a 4-node smoke
/// test doesn't need to wait an hour for each join cycle.
pub const DEFAULT_CONFIRM_WINDOW_FRAMES: u64 = 360;
/// Cap on join filters per cycle (matches Go's 100).
pub const MAX_PROPOSALS_PER_CYCLE: usize = 100;
/// Max proposals per single PlanAndAllocate call in Go (worker_allocator.go:215).
pub const GO_PLAN_ALLOCATE_CAP: usize = 100;

/// Result of evaluating the current frame for prover lifecycle actions.
pub enum LifecycleAction {
    /// Nothing to do this frame.
    Noop,
    /// Submit a ProverJoin for these filters.
    ProposeJoin {
        filters: Vec<Vec<u8>>,
        /// Worker core IDs this proposal maps to (for pending_filter_frame).
        worker_ids: Vec<u32>,
        /// Frame the proposal is anchored at.
        frame_number: u64,
    },
    /// Submit a ProverConfirm for these filters.
    ConfirmJoins {
        filters: Vec<Vec<u8>>,
        frame_number: u64,
    },
    /// Submit a ProverReject for these filters.
    RejectJoins {
        filters: Vec<Vec<u8>>,
        frame_number: u64,
    },
    /// Submit a ProverLeave for these filters.
    ProposeLeave {
        filters: Vec<Vec<u8>>,
        frame_number: u64,
    },
    /// Submit a ProverConfirm for these leave filters.
    ConfirmLeaves {
        filters: Vec<Vec<u8>>,
        frame_number: u64,
    },
    /// Submit a ProverReject for these leave filters (stay on shard).
    RejectLeaves {
        filters: Vec<Vec<u8>>,
        frame_number: u64,
    },
    /// Submit a ProverSeniorityMerge to raise on-chain seniority. The
    /// caller (prover pipeline) owns the multisig helper Ed448 signers
    /// loaded at startup — the frame number is the only per-call data.
    ProposeSeniorityMerge {
        frame_number: u64,
    },
}

impl std::fmt::Debug for LifecycleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom Debug — render `filters: Vec<Vec<u8>>` as hex strings
        // instead of the default `[10, 20, 30]` decimal byte dump, so
        // the log line `prover lifecycle action ... ProposeJoin { ... }`
        // stays operator-readable.
        fn hex_list(filters: &[Vec<u8>]) -> Vec<String> {
            filters.iter().map(|b| hex::encode(b)).collect()
        }
        match self {
            Self::Noop => f.write_str("Noop"),
            Self::ProposeJoin { filters, worker_ids, frame_number } => f
                .debug_struct("ProposeJoin")
                .field("filters", &hex_list(filters))
                .field("worker_ids", worker_ids)
                .field("frame_number", frame_number)
                .finish(),
            Self::ConfirmJoins { filters, frame_number } => f
                .debug_struct("ConfirmJoins")
                .field("filters", &hex_list(filters))
                .field("frame_number", frame_number)
                .finish(),
            Self::RejectJoins { filters, frame_number } => f
                .debug_struct("RejectJoins")
                .field("filters", &hex_list(filters))
                .field("frame_number", frame_number)
                .finish(),
            Self::ProposeLeave { filters, frame_number } => f
                .debug_struct("ProposeLeave")
                .field("filters", &hex_list(filters))
                .field("frame_number", frame_number)
                .finish(),
            Self::ConfirmLeaves { filters, frame_number } => f
                .debug_struct("ConfirmLeaves")
                .field("filters", &hex_list(filters))
                .field("frame_number", frame_number)
                .finish(),
            Self::RejectLeaves { filters, frame_number } => f
                .debug_struct("RejectLeaves")
                .field("filters", &hex_list(filters))
                .field("frame_number", frame_number)
                .finish(),
            Self::ProposeSeniorityMerge { frame_number } => f
                .debug_struct("ProposeSeniorityMerge")
                .field("frame_number", frame_number)
                .finish(),
        }
    }
}

/// Tracks the lifecycle state for this node's prover.
pub struct ProverLifecycle {
    /// This node's prover address (32 bytes, Poseidon hash of BLS pubkey).
    pub prover_address: Vec<u8>,
    /// Whether a VDF computation is currently in progress. While set,
    /// the lifecycle must not start another join proposal (VDF is
    /// expensive and multiple overlapping computations would thrash).
    proof_in_progress: AtomicBool,
    /// Whether the initial prover-tree sync has completed.
    initial_sync_complete: AtomicBool,
    /// The frame at which `proverRoot` was most recently verified.
    /// Matches Go's `materializer.proverRootVerifiedFrame`. Gates
    /// proposals on the registry being current.
    prover_root_verified_frame: AtomicU64,
    /// The most recently observed frame number.
    last_observed_frame: AtomicU64,
    /// Reward strategy. Matches `config.engine.data_greedy`.
    pub strategy: Strategy,
    /// Issuance units constant (default 8_000_000_000).
    pub units: u64,
    /// WorkerAllocator holds the single-source-of-truth join cooldown timer.
    allocator: Arc<WorkerAllocator>,
    /// Shared halt state — proposals pause while any shard is in a
    /// coverage halt. Populated by the coverage-event subscriber.
    halt_state: Arc<HaltState>,
    /// Real per-shard byte sizes keyed by confirmation filter, derived
    /// from `ShardsStore::range_app_shards`. Tier-5 #3: used to populate
    /// `ShardDescriptor.size` in `build_proposal_descriptors` and
    /// `build_decide_descriptors` so reward scoring matches Go's
    /// `shard.Size.Uint64()` from `worker_allocator.go:855-893`.
    /// Falls back to the registry's prover-count proxy when empty.
    shard_sizes_by_filter: RwLock<HashMap<Vec<u8>, u64>>,
    /// Frame window between a join (or leave) proposal and its
    /// confirm/reject. Defaults to `DEFAULT_CONFIRM_WINDOW_FRAMES`
    /// (360, mainnet); can be lowered to a small value for testnet
    /// bootstraps via `set_confirm_window_frames`.
    confirm_window_frames: AtomicU64,
    /// Optional `ShardsStore` handle. When wired, `evaluate` calls
    /// `range_app_shards` on each tick and treats every (shard_key,
    /// prefix) entry as a known confirmation filter. This is what
    /// lets the proposer see app shards that exist in genesis but
    /// have no provers allocated yet (mirrors Go's
    /// `worker_allocator.go:599` flow). Without this, the proposer
    /// only sees filters that already have at least one allocation
    /// in the registry — which on a fresh testnet means only the
    /// global filter, which is explicitly skipped, so no joins
    /// are ever proposed.
    shards_store: RwLock<Option<Arc<dyn quil_types::store::ShardsStore>>>,
}

impl ProverLifecycle {
    pub fn new(
        prover_address: Vec<u8>,
        allocator: Arc<WorkerAllocator>,
        halt_state: Arc<HaltState>,
    ) -> Self {
        Self {
            prover_address,
            proof_in_progress: AtomicBool::new(false),
            initial_sync_complete: AtomicBool::new(false),
            prover_root_verified_frame: AtomicU64::new(0),
            last_observed_frame: AtomicU64::new(0),
            strategy: Strategy::RewardGreedy,
            units: proposer::DEFAULT_UNITS,
            allocator,
            halt_state,
            shard_sizes_by_filter: RwLock::new(HashMap::new()),
            confirm_window_frames: AtomicU64::new(DEFAULT_CONFIRM_WINDOW_FRAMES),
            shards_store: RwLock::new(None),
        }
    }

    /// Wire a `ShardsStore` so `evaluate` can discover shards that
    /// have no allocations yet. Mainnet's worker allocator does this
    /// by iterating the local shards-store on every frame; we mirror
    /// that without the gRPC sub-shard fetch step (the local store
    /// already has the canonical set of shards on every node).
    pub fn set_shards_store(
        &self,
        shards_store: Arc<dyn quil_types::store::ShardsStore>,
    ) {
        if let Ok(mut guard) = self.shards_store.write() {
            *guard = Some(shards_store);
        }
    }

    /// Override the confirm window. Mainnet uses 360 frames (the
    /// default); testnet bootstraps lower this so the join → confirm
    /// cycle finishes in minutes instead of an hour. Mainnet nodes
    /// must NOT call this — they require the full 360-frame
    /// observation window for the protocol to be sound.
    pub fn set_confirm_window_frames(&self, frames: u64) {
        self.confirm_window_frames
            .store(frames, std::sync::atomic::Ordering::Relaxed);
    }

    /// Current confirm window — see `set_confirm_window_frames`.
    pub fn confirm_window_frames(&self) -> u64 {
        self.confirm_window_frames
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Populate the per-shard byte size map. Caller is the consensus
    /// loop, which calls `range_app_shards` once per frame and passes
    /// the resulting `filter → size` map here. Without this, the
    /// proposer falls back to the registry's prover-count proxy and
    /// reward scoring diverges from Go.
    pub fn set_shard_sizes(&self, sizes: HashMap<Vec<u8>, u64>) {
        if let Ok(mut guard) = self.shard_sizes_by_filter.write() {
            *guard = sizes;
        }
    }

    /// Mark initial sync as complete. Proposals are gated on this.
    pub fn set_sync_complete(&self) {
        self.initial_sync_complete.store(true, Ordering::Relaxed);
    }

    /// Mark VDF proof computation as in-progress / done.
    pub fn set_proof_in_progress(&self, in_progress: bool) {
        self.proof_in_progress.store(in_progress, Ordering::Relaxed);
    }

    /// Update the latest-verified frame. Called by the caller whenever
    /// the prover tree has been re-synced / re-verified at a given
    /// frame height.
    pub fn set_prover_root_verified_frame(&self, frame: u64) {
        self.prover_root_verified_frame.store(frame, Ordering::Relaxed);
    }

    /// Update the most recently observed frame number.
    pub fn set_last_observed_frame(&self, frame: u64) {
        self.last_observed_frame.fetch_max(frame, Ordering::Relaxed);
    }

    /// Configure reward strategy.
    pub fn set_strategy(&mut self, strategy: Strategy) {
        self.strategy = strategy;
    }

    /// Record a successful `ProverJoin` submission at `frame_number`.
    /// Called by the pipeline AFTER `publish_prover_message` succeeds
    /// so transient archive failures don't burn the 4-frame join
    /// cooldown and skip legitimate retry opportunities. Matches Go's
    /// post-success cooldown semantics at `worker_allocator.go:224`.
    pub fn record_join_attempt(&self, frame_number: u64) {
        self.allocator.set_last_join_attempt(frame_number);
    }

    /// Port of Go's `selectExcessPendingFilters` at
    /// `worker_allocator.go:1319-1385`. Returns filters that should be
    /// force-rejected because the number of non-expired pending joins
    /// exceeds our worker capacity minus active allocations.
    ///
    /// Go uses `config.Engine.DataWorkerCount` for capacity; we use the
    /// total worker count (`workers.len()`) which is equivalent since
    /// workers are provisioned from `data_worker_count`.
    ///
    /// Mirrors Go's `rand.Shuffle(pending)` so each node submits an
    /// independent random subset of excess filters — over time this
    /// converges every shard's pending list back to capacity without
    /// any single shard being preferentially rejected.
    fn select_excess_pending_filters(
        &self,
        active_filters: &[Vec<u8>],
        joining_filters: &[(Vec<u8>, u64)],
        worker_capacity: usize,
    ) -> Vec<Vec<u8>> {
        if worker_capacity == 0 {
            return Vec::new();
        }

        let active = active_filters.len();
        let last_observed = self.last_observed_frame.load(Ordering::Relaxed);

        let mut pending: Vec<Vec<u8>> = joining_filters.iter()
            .filter(|(filter, join_frame)| {
                if filter.is_empty() { return false; }
                // Skip expired joins — implicitly rejected.
                last_observed <= *join_frame + crate::worker_allocator::PENDING_FILTER_GRACE_FRAMES
            })
            .map(|(f, _)| f.clone())
            .collect();

        let allowed = worker_capacity.saturating_sub(active);
        if pending.len() <= allowed {
            return Vec::new();
        }

        let excess = pending.len() - allowed;
        // Random shuffle — matches Go's `rand.Shuffle(pending)` at
        // worker_allocator.go:1380-1382.
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        pending.shuffle(&mut rng);
        pending.truncate(excess);
        pending
    }

    /// Pick auto-managed Active filters to leave when the prover holds
    /// Returns lowest-scoring active filters when the auto-managed
    /// active count exceeds non-manually-managed worker capacity.
    /// Manually-managed pins are excluded entirely.
    fn select_excess_active_filters(
        &self,
        active_filters: &[Vec<u8>],
        workers: &[crate::worker::WorkerInfo],
        allocated_descriptors: &[ShardDescriptor],
        difficulty: u64,
        world_bytes: &BigInt,
    ) -> Vec<Vec<u8>> {
        let mm_filters: std::collections::HashSet<Vec<u8>> = workers
            .iter()
            .filter(|w| w.manually_managed && !w.filter.is_empty())
            .map(|w| w.filter.clone())
            .collect();

        let auto_capacity = workers.iter().filter(|w| !w.manually_managed).count();

        let auto_active_count = active_filters
            .iter()
            .filter(|f| !mm_filters.contains(*f))
            .count();

        if auto_active_count <= auto_capacity {
            return Vec::new();
        }
        let surplus = auto_active_count - auto_capacity;

        let ranked = proposer::rank_allocated_by_score_ascending(
            allocated_descriptors,
            difficulty,
            world_bytes,
            self.units,
            self.strategy,
            &mm_filters,
        );

        // Pick lowest-scoring `surplus` filters from `ranked`. A
        // filter that's `Active` but absent from `allocated_descriptors`
        // is, in practice, a size-0 shard (build_decide_descriptors
        // skipped it). Mirroring Go's `worker_allocator.go:821-824` —
        // where `if size == 0 { continue }` lands BEFORE
        // `leaveProposalCandidates = append(...)` — we deliberately
        // do NOT pick those for leave. They count toward
        // auto_active_count for capacity but stay put.
        let mut picks: Vec<Vec<u8>> = Vec::with_capacity(surplus.min(ranked.len()));
        for (f, _) in ranked {
            if picks.len() == surplus {
                break;
            }
            picks.push(f);
        }
        picks.truncate(MAX_PROPOSALS_PER_CYCLE);
        picks
    }

    /// Returns `Some(reason)` if the prover tree isn't fresh enough
    /// at `frame_number` for any lifecycle action.
    fn tree_synced(&self, frame_number: u64) -> Option<&'static str> {
        if self.last_observed_frame.load(Ordering::Relaxed) == 0 {
            return Some("awaiting initial frame");
        }
        if !self.initial_sync_complete.load(Ordering::Relaxed) {
            return Some("awaiting prover root sync");
        }
        let verified = self.prover_root_verified_frame.load(Ordering::Relaxed);
        if verified == 0 || verified < frame_number {
            return Some("latest frame not yet verified");
        }
        None
    }

    /// Returns `(ready, reason_if_not)` for the propose paths. Layered
    /// on top of `tree_synced`.
    fn join_proposal_ready(&self, frame_number: u64) -> (bool, &'static str) {
        if let Some(reason) = self.tree_synced(frame_number) {
            return (false, reason);
        }
        if self.halt_state.any_halted() {
            return (false, "shard coverage halt active");
        }
        let last_attempt = self.allocator.last_join_attempt();
        if last_attempt != 0 {
            if frame_number <= last_attempt {
                tracing::debug!(
                    last_attempt,
                    frame_number,
                    "join cooldown: frame not newer than last attempt"
                );
                return (false, "waiting for newer frame");
            }
            let gap = frame_number - last_attempt;
            if gap < crate::worker_allocator::JOIN_COOLDOWN_FRAMES {
                tracing::debug!(
                    last_attempt,
                    frame_number,
                    gap,
                    required = crate::worker_allocator::JOIN_COOLDOWN_FRAMES,
                    "join cooldown active"
                );
                return (false, "cooldown between join attempts");
            }
        }
        (true, "")
    }

    /// Evaluate the current frame and determine what lifecycle actions
    /// to take. Mirrors Go's `evaluateForProposals` at
    /// `worker_allocator.go:161-345`, which can emit multiple actions
    /// in a single cycle (a ProposeJoin, DecideJoins, ProposeLeave and
    /// DecideLeaves may all fire together). The caller dispatches each;
    /// per-address locks in the submission path ensure only one takes
    /// effect per affected prover address per frame.
    ///
    /// `difficulty` must be the current frame's difficulty (used in PoMW basis).
    pub fn evaluate(
        &self,
        frame_number: u64,
        difficulty: u64,
        registry: &dyn ProverRegistry,
        worker_manager: &dyn WorkerManager,
    ) -> Result<Vec<LifecycleAction>> {
        self.set_last_observed_frame(frame_number);

        // Unconditional gates — nothing to emit.
        if self.proof_in_progress.load(Ordering::Relaxed) {
            return Ok(Vec::new());
        }
        if self.prover_address.is_empty() {
            return Ok(Vec::new());
        }

        // No actions emit until the registry view is current.
        if let Some(reason) = self.tree_synced(frame_number) {
            tracing::debug!(
                frame = frame_number,
                reason,
                "skipping lifecycle evaluation — tree not synced"
            );
            return Ok(Vec::new());
        }

        // Gather inputs
        let summaries = registry.get_prover_shard_summaries()?;
        let prover_info = registry.get_prover_info(&self.prover_address)?;
        let workers = worker_manager.range_workers()?;

        // Discover shard filters from the local `ShardsStore`.
        // Mainnet seeds many shards at genesis (per
        // `genesis.go:177-194`) and Go's `worker_allocator.go:599`
        // iterates them via `RangeAppShards()` to surface filters
        // that have no allocations yet. Without this step the
        // proposer would never see those shards because
        // `get_prover_shard_summaries` only includes filters with
        // at least one allocation. The filter for each entry is
        // `shard_key || prefix.byte()` (Go: `shardInfo.L2 ||
        // byte(p)` for each `p` in `shard.Prefix`).
        let shards_store_filters: Vec<Vec<u8>> = match self
            .shards_store
            .read()
            .ok()
            .and_then(|g| g.clone())
        {
            Some(ss) => match ss.range_app_shards() {
                Ok(shards) => shards
                    .into_iter()
                    .map(|s| {
                        // Wire filter = L2 || prefix.byte() per Go
                        // (`worker_allocator.go:758`). The shards-store
                        // returns shard_key = L1(3) || L2(32); strip
                        // the leading 3 bytes of L1.
                        let l2_start = if s.shard_key.len() >= 3 { 3 } else { 0 };
                        let mut filter = s.shard_key[l2_start..].to_vec();
                        for p in &s.prefix {
                            filter.push(*p as u8);
                        }
                        filter
                    })
                    .filter(|f| !f.is_empty())
                    .collect(),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };

        // Joining / Left allocations past the 720-frame grace are
        // implicitly rejected on-chain. Skip them everywhere — including
        // `all_our_filters` — so the slot can be re-proposed.
        let mut joining_filters: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut active_filters: Vec<Vec<u8>> = Vec::new();
        let mut leaving_filters: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut all_our_filters: Vec<Vec<u8>> = Vec::new();

        if let Some(ref prover) = prover_info {
            for alloc in &prover.allocations {
                match alloc.status {
                    ProverStatus::Joining => {
                        if frame_number
                            > alloc.join_frame_number
                                + crate::worker_allocator::PENDING_FILTER_GRACE_FRAMES
                        {
                            continue;
                        }
                        all_our_filters.push(alloc.confirmation_filter.clone());
                        joining_filters
                            .push((alloc.confirmation_filter.clone(), alloc.join_frame_number));
                    }
                    ProverStatus::Active => {
                        all_our_filters.push(alloc.confirmation_filter.clone());
                        active_filters.push(alloc.confirmation_filter.clone());
                    }
                    ProverStatus::Left => {
                        if frame_number
                            > alloc.leave_frame_number
                                + crate::worker_allocator::PENDING_FILTER_GRACE_FRAMES
                        {
                            continue;
                        }
                        all_our_filters.push(alloc.confirmation_filter.clone());
                        leaving_filters
                            .push((alloc.confirmation_filter.clone(), alloc.leave_frame_number));
                    }
                    _ => {
                        all_our_filters.push(alloc.confirmation_filter.clone());
                    }
                }
            }
        }

        // Build separate descriptor views.
        //
        // - `proposal_descriptors`: shards *we are not on* scored with the
        //   joiner ring (predicted ring after we join). Used for
        //   ProposeJoin + as the base for the decide_candidates set.
        // - `decide_all_descriptors`: every shard scored with its current
        //   ring — used only to splice in pending-to-decide entries.
        // - `allocated_descriptors`: shards *we are on*, scored with the
        //   current ring — used for plan_leaves.
        let shard_sizes_snapshot = self
            .shard_sizes_by_filter
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        let proposal_descriptors = build_proposal_descriptors(
            &summaries,
            &all_our_filters,
            &shard_sizes_snapshot,
            &shards_store_filters,
        );
        let decide_all_descriptors =
            build_decide_descriptors(&summaries, &shard_sizes_snapshot);
        let allocated_descriptors: Vec<ShardDescriptor> = decide_all_descriptors.iter()
            .filter(|d| all_our_filters.contains(&d.filter))
            .cloned()
            .collect();

        let world_bytes = compute_world_bytes_from_summaries(&summaries);

        // A worker counts as free only when:
        //   * its filter slot is empty,
        //   * it isn't manually-managed,
        //   * and it has no in-flight proposal (`pending_filter_frame`
        //     stays set until the registry commits the join and the
        //     reconciler installs the filter, or until 10 frames pass
        //     and the proposal times out).
        // The third condition prevents over-proposing while a join is
        // still in flight: between `submit_join` (which records the
        // pending frame) and registry confirmation, the worker has an
        // empty filter but a non-zero pending frame.
        let free_worker_ids: Vec<u32> = workers.iter()
            .filter(|w| {
                w.filter.is_empty()
                    && !w.manually_managed
                    && w.pending_filter_frame == 0
            })
            .map(|w| w.core_id)
            .collect();
        let allow_proposals = !free_worker_ids.is_empty();

        // Go's canPropose (cooldown + readiness). Checked once per
        // evaluate so both propose paths see the same decision.
        let (can_propose, skip_reason) = self.join_proposal_ready(frame_number);

        let mut actions: Vec<LifecycleAction> = Vec::new();
        let mut join_proposed_this_cycle = false;

        // Seniority-merge check — matches Go's `checkAndSubmitSeniorityMerge`
        // at worker_allocator.go:963-1011. When our on-chain seniority
        // trails the config-derived estimate (from
        // `compat::GetAggregatedSeniority` across own + enrolled peer
        // IDs) and both the join- and seniority-merge cooldowns (10
        // frames each) have elapsed, emit a `ProposeSeniorityMerge`
        // action. The pipeline owns the multisig Ed448 signer set and
        // produces the signed `ProverSeniorityMerge` message from this
        // trigger.
        let config_estimate = self.allocator.config_seniority_estimate();
        let current_seniority = prover_info.as_ref().map(|p| p.seniority).unwrap_or(0);
        if config_estimate > current_seniority && prover_info.is_some() {
            let last_merge = self.allocator.last_seniority_merge_attempt();
            let last_join = self.allocator.last_join_attempt();
            const MERGE_COOLDOWN: u64 = 10;
            let merge_cd_ok =
                last_merge == 0 || frame_number.saturating_sub(last_merge) >= MERGE_COOLDOWN;
            let join_cd_ok =
                last_join == 0 || frame_number.saturating_sub(last_join) >= MERGE_COOLDOWN;
            if merge_cd_ok && join_cd_ok {
                info!(
                    frame = frame_number,
                    current_seniority,
                    config_estimate,
                    delta = config_estimate - current_seniority,
                    "emitting ProverSeniorityMerge to raise on-chain seniority"
                );
                // Record attempt eagerly so duplicate evaluates within
                // the cooldown don't re-emit; the pipeline will log if
                // the actual submission fails.
                self.allocator.set_last_seniority_merge_attempt(frame_number);
                actions.push(LifecycleAction::ProposeSeniorityMerge { frame_number });
            }
        }

        // 0) Excess-pending-joins check — matches Go's
        //    `checkExcessPendingJoins` / `selectExcessPendingFilters` /
        //    `rejectExcessPending` (worker_allocator.go:1024-1436).
        //    When the number of non-expired Joining allocations exceeds
        //    (worker_capacity - active_allocations), force-reject the
        //    excess so the prover's pending filters don't grow unbounded
        //    after a shard freeze. Has its own cooldown separate from the
        //    join cooldown (4 frames between reject batches).
        let excess_rejects =
            self.select_excess_pending_filters(&active_filters, &joining_filters, workers.len());
        if !excess_rejects.is_empty() {
            let last_reject = self.allocator.last_reject_attempt();
            let cooldown_ok = last_reject == 0
                || (frame_number > last_reject
                    && frame_number - last_reject >= crate::worker_allocator::JOIN_COOLDOWN_FRAMES);
            if cooldown_ok {
                let mut filters = excess_rejects;
                if filters.len() > MAX_PROPOSALS_PER_CYCLE {
                    filters.truncate(MAX_PROPOSALS_PER_CYCLE);
                }
                info!(
                    frame = frame_number,
                    rejections = filters.len(),
                    "forced rejection of excess pending joins"
                );
                self.allocator.set_last_reject_attempt(frame_number);
                actions.push(LifecycleAction::RejectJoins { filters, frame_number });
            } else {
                tracing::debug!(
                    frame = frame_number,
                    last_reject,
                    "deferring forced join rejections — cooldown"
                );
            }
        }

        // Surplus-active leave: proactively shed the worst-scoring
        // active filters when count exceeds auto-managed worker
        // capacity. Shares the join cooldown.
        if !active_filters.is_empty() && !join_proposed_this_cycle {
            let surplus = self.select_excess_active_filters(
                &active_filters,
                &workers,
                &allocated_descriptors,
                difficulty,
                &world_bytes,
            );
            if !surplus.is_empty() {
                let last_join = self.allocator.last_join_attempt();
                let cooldown_ok = last_join == 0
                    || (frame_number > last_join
                        && frame_number - last_join
                            >= crate::worker_allocator::JOIN_COOLDOWN_FRAMES);
                if cooldown_ok {
                    self.allocator.set_last_join_attempt(frame_number);
                    info!(
                        frame = frame_number,
                        leaves = surplus.len(),
                        "proposing leaves for surplus actives (worker count reduced)"
                    );
                    actions.push(LifecycleAction::ProposeLeave {
                        filters: surplus,
                        frame_number,
                    });
                    // Don't propose joins or score-driven leaves in
                    // the same cycle as a surplus-active leave.
                    join_proposed_this_cycle = true;
                } else {
                    tracing::debug!(
                        frame = frame_number,
                        last_join,
                        "deferring surplus-active leaves — cooldown"
                    );
                }
            }
        }

        // 1) ProposeJoin — gated on allowProposals && canPropose.
        //    Mirrors worker_allocator.go:210-247. Pure score-driven —
        //    Go has no halt-risk override; coverage halts are handled
        //    upstream by the coverage monitor's halt-grace logic.
        if !proposal_descriptors.is_empty() && allow_proposals {
            if can_propose {
                let proposals = proposer::plan_and_allocate(
                    &proposal_descriptors,
                    difficulty,
                    &world_bytes,
                    self.units,
                    &free_worker_ids,
                    MAX_PROPOSALS_PER_CYCLE,
                    self.strategy,
                );

                if !proposals.is_empty() {
                    // Cooldown set in `ProverPipeline::submit_join`
                    // AFTER `publish_prover_message` succeeds. Setting
                    // here would burn the 4-frame cooldown on every
                    // transient archive/VDF failure, matching Go's
                    // post-success semantics at worker_allocator.go:224
                    // (where the bump is gated on `err == nil &&
                    // len(proposals) > 0`).
                    let prev_attempt = self.allocator.last_join_attempt();
                    join_proposed_this_cycle = true;

                    let worker_ids: Vec<u32> = proposals.iter().map(|p| p.worker_id).collect();
                    let filters: Vec<Vec<u8>> = proposals.into_iter().map(|p| p.filter).collect();

                    info!(
                        filters = filters.len(),
                        frame = frame_number,
                        prev_join_attempt = prev_attempt,
                        cooldown_frames = crate::worker_allocator::JOIN_COOLDOWN_FRAMES,
                        strategy = ?self.strategy,
                        "proposing join for shards"
                    );

                    actions.push(LifecycleAction::ProposeJoin {
                        filters,
                        worker_ids,
                        frame_number,
                    });
                }
            } else {
                tracing::debug!(
                    frame = frame_number,
                    reason = skip_reason,
                    "skipping join proposals"
                );
            }
        }

        // 2) DecideJoins — independent of cooldown. Matches
        //    worker_allocator.go:268-297.
        let confirm_window = self.confirm_window_frames();
        let ready_join_filters: Vec<Vec<u8>> = joining_filters.iter()
            .filter(|(_, jf)| frame_number >= *jf + confirm_window)
            .map(|(f, _)| f.clone())
            .collect();

        if !ready_join_filters.is_empty() {
            let pending_set: std::collections::HashSet<Vec<u8>> = ready_join_filters.iter().cloned().collect();
            let mut decide_candidates = proposal_descriptors.clone();
            for d in &decide_all_descriptors {
                if pending_set.contains(&d.filter) {
                    decide_candidates.push(d.clone());
                }
            }

            // Tier-5 #5: cap confirmations at unallocated worker count
            // (Go `proposer.go:518-531`). `unallocatedWorkerCount` =
            // count(workers where !allocated). Mirrors Go's gate so a
            // node with more pending confirms than free workers doesn't
            // commit to allocations it can't service.
            let available_workers = workers.iter().filter(|w| !w.allocated).count();

            let (reject, confirm) = proposer::decide_joins(
                &decide_candidates,
                &ready_join_filters,
                difficulty,
                &world_bytes,
                self.units,
                self.strategy,
                available_workers,
            );

            if !reject.is_empty() {
                actions.push(LifecycleAction::RejectJoins {
                    filters: reject,
                    frame_number,
                });
            }
            if !confirm.is_empty() {
                actions.push(LifecycleAction::ConfirmJoins {
                    filters: confirm,
                    frame_number,
                });
            }
        }

        // 3) ProposeLeave — gated on canPropose && !joinProposedThisCycle.
        //    Matches worker_allocator.go:299-316. Go also updates
        //    lastJoinAttemptFrame on successful leave proposals (L310)
        //    so we mirror that here. Pure score-driven — Go has no
        //    halt-risk override.
        if can_propose
            && !join_proposed_this_cycle
            && !active_filters.is_empty()
            && !proposal_descriptors.is_empty()
        {
            let leave_candidates = proposer::plan_leaves(
                &allocated_descriptors,
                &proposal_descriptors,
                difficulty,
                &world_bytes,
                self.units,
                self.strategy,
            );

            if !leave_candidates.is_empty() {
                self.allocator.set_last_join_attempt(frame_number);
                info!(
                    leave_proposals = leave_candidates.len(),
                    frame = frame_number,
                    "proposing leaves for overcrowded shards"
                );
                actions.push(LifecycleAction::ProposeLeave {
                    filters: leave_candidates,
                    frame_number,
                });
            }
        }

        // 4) DecideLeaves — independent of cooldown. Matches
        //    worker_allocator.go:318-344.
        let ready_leave_filters: Vec<Vec<u8>> = leaving_filters.iter()
            .filter(|(_, lf)| frame_number >= *lf + confirm_window)
            .map(|(f, _)| f.clone())
            .collect();

        if !ready_leave_filters.is_empty() {
            let (reject, confirm) = proposer::decide_leaves(
                &decide_all_descriptors,
                &ready_leave_filters,
                difficulty,
                &world_bytes,
                self.units,
                self.strategy,
            );

            if !reject.is_empty() {
                actions.push(LifecycleAction::RejectLeaves {
                    filters: reject,
                    frame_number,
                });
            }
            if !confirm.is_empty() {
                actions.push(LifecycleAction::ConfirmLeaves {
                    filters: confirm,
                    frame_number,
                });
            }
        }

        Ok(actions)
    }
}

/// Build descriptors for shards we are NOT currently allocated to,
/// scored with the joiner ring (predicted ring after we join).
///
/// Mirrors Go's `proposalDescriptors` at `worker_allocator.go:857-868`.
/// `shard_sizes` overrides the registry's `total_size` (which is just a
/// prover-count proxy) with real shard byte sizes from the shards
/// store — Tier-5 #3.
fn build_proposal_descriptors(
    summaries: &[ProverShardSummary],
    our_filters: &[Vec<u8>],
    shard_sizes: &HashMap<Vec<u8>, u64>,
    shards_store_filters: &[Vec<u8>],
) -> Vec<ShardDescriptor> {
    let mut out: Vec<ShardDescriptor> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        std::collections::HashSet::new();
    for s in summaries {
        if s.filter.is_empty() {
            continue;
        }
        if our_filters.contains(&s.filter) {
            continue;
        }
        // Skip empty shards (size == 0). Mirrors Go's
        // `worker_allocator.go` which `continue`s when
        // `new(big.Int).SetBytes(shard.Size) == 0`. Without this,
        // freshly-genesis'd shards default to size=1 and look join-
        // worthy, causing the lifecycle to propose joins on shards
        // with no actual data.
        let raw_size = shard_sizes
            .get(&s.filter)
            .copied()
            .unwrap_or(s.total_size);
        if raw_size == 0 {
            continue;
        }
        let active = s.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0);
        let joining = s.status_counts.get(&ProverStatus::Joining).copied().unwrap_or(0);
        let total = (active + joining) as usize;
        let ri = proposer::compute_shard_ring_info(total);
        out.push(ShardDescriptor {
            filter: s.filter.clone(),
            size: raw_size,
            ring: ri.joiner_ring,
            shards: 1,
            active_on_ring: ri.active_on_joiner_ring,
        });
        seen.insert(s.filter.clone());
    }
    // Surface shards-store-only filters (no allocations yet) as
    // empty-ring descriptors. Mirrors Go's worker allocator at
    // `worker_allocator.go:763-868` where `proverRegistry.GetProvers(bp)`
    // returns an empty list for unallocated shards but the descriptor
    // is still built (with active=joining=0, ring=0) so the proposer
    // can score and pick it. Skip when no real size is known — Go's
    // `if size == 0 { continue }` applies here too.
    for filter in shards_store_filters {
        if filter.is_empty() {
            continue;
        }
        if seen.contains(filter) {
            continue;
        }
        if our_filters.contains(filter) {
            continue;
        }
        let raw_size = shard_sizes.get(filter).copied().unwrap_or(0);
        if raw_size == 0 {
            continue;
        }
        let ri = proposer::compute_shard_ring_info(0);
        out.push(ShardDescriptor {
            filter: filter.clone(),
            size: raw_size,
            ring: ri.joiner_ring,
            shards: 1,
            active_on_ring: ri.active_on_joiner_ring,
        });
    }
    out
}

/// Build descriptors for every shard scored with its *current* ring.
/// Used both as the base for decide operations (where pending-matching
/// entries are spliced in) and for plan_leaves (allocated view).
///
/// Mirrors Go's `decideDescriptors` at `worker_allocator.go:884-893`.
/// Tier-5 #3: see `build_proposal_descriptors` doc.
fn build_decide_descriptors(
    summaries: &[ProverShardSummary],
    shard_sizes: &HashMap<Vec<u8>, u64>,
) -> Vec<ShardDescriptor> {
    summaries.iter().filter_map(|s| {
        if s.filter.is_empty() {
            return None;
        }
        // Skip empty shards. Same reasoning as build_proposal_descriptors:
        // Go's worker_allocator skips when `size == 0`, and decide
        // scoring on a phantom-sized shard would otherwise produce
        // garbage rejection / leave decisions.
        let raw_size = shard_sizes
            .get(&s.filter)
            .copied()
            .unwrap_or(s.total_size);
        if raw_size == 0 {
            return None;
        }
        let active = s.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0);
        let joining = s.status_counts.get(&ProverStatus::Joining).copied().unwrap_or(0);
        let total = (active + joining) as usize;
        let ri = proposer::compute_shard_ring_info(total);
        Some(ShardDescriptor {
            filter: s.filter.clone(),
            size: raw_size,
            ring: ri.current_ring,
            shards: 1,
            active_on_ring: ri.active_on_current_ring,
        })
    }).collect()
}

fn compute_world_bytes_from_summaries(summaries: &[ProverShardSummary]) -> BigInt {
    let total: u64 = summaries.iter()
        .map(|s| if s.total_size > 0 { s.total_size } else { 1 })
        .sum();
    BigInt::from(total.max(1))
}

#[cfg(test)]
mod proposal_loop_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use quil_types::consensus::{
        ProverAllocationInfo, ProverInfo, ProverShardSummary, ProverStatus,
    };

    use crate::halt_state::HaltState;
    use crate::worker::{WorkerInfo, WorkerManager};
    use crate::worker_allocator::{WorkerAllocator, JOIN_COOLDOWN_FRAMES};

    struct ConfigurableRegistry {
        prover: Mutex<Option<ProverInfo>>,
        summaries: Mutex<Vec<ProverShardSummary>>,
        current_frame: std::sync::atomic::AtomicU64,
    }

    impl ConfigurableRegistry {
        fn new() -> Self {
            Self {
                prover: Mutex::new(None),
                summaries: Mutex::new(Vec::new()),
                current_frame: std::sync::atomic::AtomicU64::new(0),
            }
        }

        fn set_prover(&self, info: ProverInfo) {
            *self.prover.lock().unwrap() = Some(info);
        }

        fn set_summaries(&self, s: Vec<ProverShardSummary>) {
            *self.summaries.lock().unwrap() = s;
        }

        #[allow(dead_code)]
        fn set_current_frame(&self, frame: u64) {
            self.current_frame.store(frame, Ordering::Relaxed);
        }
    }

    impl ProverRegistry for ConfigurableRegistry {
        fn refresh(&self) -> Result<()> { Ok(()) }
        fn get_all_active_app_shard_provers(&self) -> Result<Vec<ProverInfo>> { Ok(vec![]) }
        fn get_prover_info(&self, _: &[u8]) -> Result<Option<ProverInfo>> {
            Ok(self.prover.lock().unwrap().clone())
        }
        fn get_next_prover(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>> { Ok(vec![]) }
        fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<Vec<u8>>> { Ok(vec![]) }
        fn get_active_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> { Ok(vec![]) }
        fn get_prover_count(&self, _: &[u8]) -> Result<usize> { Ok(0) }
        fn get_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> { Ok(vec![]) }
        fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> Result<Vec<ProverInfo>> { Ok(vec![]) }
        fn update_prover_activity(&self, _: &[u8], _: &[u8], _: u64) -> Result<()> { Ok(()) }
        fn get_prover_shard_summaries(&self) -> Result<Vec<ProverShardSummary>> {
            Ok(self.summaries.lock().unwrap().clone())
        }
        fn prune_orphan_joins(&self, _: u64) -> Result<()> { Ok(()) }
        fn evict_inactive_provers(&self, _: u64, _: u64, _: &HashMap<String, u64>) -> Result<Vec<Vec<u8>>> {
            Ok(vec![])
        }
        fn current_frame(&self) -> u64 {
            self.current_frame.load(Ordering::Relaxed)
        }
    }

    struct ConfigurableWorkerManager {
        workers: Mutex<HashMap<u32, WorkerInfo>>,
    }

    impl ConfigurableWorkerManager {
        fn new() -> Self {
            Self { workers: Mutex::new(HashMap::new()) }
        }

        fn add(&self, info: WorkerInfo) {
            self.workers.lock().unwrap().insert(info.core_id, info);
        }
    }

    impl WorkerManager for ConfigurableWorkerManager {
        fn allocate_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
            let mut g = self.workers.lock().unwrap();
            let entry = g.entry(core_id).or_insert(WorkerInfo {
                core_id,
                filter: vec![],
                available_storage: 0,
                total_storage: 0,
                manually_managed: false,
                pending_filter_frame: 0,
                allocated: false,
            });
            entry.filter = filter.to_vec();
            entry.allocated = !filter.is_empty();
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
            let mut out: Vec<WorkerInfo> =
                self.workers.lock().unwrap().values().cloned().collect();
            out.sort_by_key(|w| w.core_id);
            Ok(out)
        }
        fn respawn_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
            self.allocate_worker(core_id, filter)
        }
    }

    fn make_lifecycle(
        prover_address: Vec<u8>,
        wm: Arc<dyn WorkerManager>,
        reg: Arc<dyn ProverRegistry>,
    ) -> Arc<ProverLifecycle> {
        let allocator = Arc::new(WorkerAllocator::new(wm, reg, prover_address.clone()));
        let halt = Arc::new(HaltState::new());
        let lifecycle = Arc::new(ProverLifecycle::new(prover_address, allocator, halt));
        lifecycle.set_confirm_window_frames(2);
        lifecycle.set_sync_complete();
        lifecycle
    }

    fn idle_worker(core_id: u32) -> WorkerInfo {
        WorkerInfo {
            core_id,
            filter: vec![],
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: false,
        }
    }

    fn allocated_worker(core_id: u32, filter: Vec<u8>) -> WorkerInfo {
        WorkerInfo {
            core_id,
            filter,
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: true,
        }
    }

    fn alloc(filter: Vec<u8>, status: ProverStatus, join_frame: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status,
            confirmation_filter: filter,
            rejection_filter: vec![],
            join_frame_number: join_frame,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: if status == ProverStatus::Active { join_frame + 1 } else { 0 },
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            vertex_address: vec![],
        }
    }

    fn prover(address: Vec<u8>, allocations: Vec<ProverAllocationInfo>) -> ProverInfo {
        ProverInfo {
            public_key: vec![0xAA; 74],
            address,
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations,
            available_storage: 1 << 30,
            seniority: 0,
            delegate_address: vec![],
        }
    }

    fn shard_summary(filter: Vec<u8>, active: u32) -> ProverShardSummary {
        let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
        if active > 0 {
            counts.insert(ProverStatus::Active, active);
        }
        ProverShardSummary {
            filter,
            status_counts: counts,
            total_size: 1_000_000,
        }
    }

    fn filter_bytes(byte: u8) -> Vec<u8> {
        vec![byte; 8]
    }

    fn count_proposed_joins(actions: &[LifecycleAction]) -> usize {
        actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeJoin { filters, .. } => Some(filters.len()),
                _ => None,
            })
            .sum()
    }

    fn count_rejects(actions: &[LifecycleAction]) -> usize {
        actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::RejectJoins { filters, .. } => Some(filters.len()),
                _ => None,
            })
            .sum()
    }

    fn count_proposed_leaves(actions: &[LifecycleAction]) -> usize {
        actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.len()),
                _ => None,
            })
            .sum()
    }

    #[test]
    fn join_cooldown_blocks_then_releases() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(idle_worker(1));
        wm.add(idle_worker(2));
        reg.set_summaries(vec![
            shard_summary(filter_bytes(0x01), 1),
            shard_summary(filter_bytes(0x02), 1),
            shard_summary(filter_bytes(0x03), 1),
            shard_summary(filter_bytes(0x04), 1),
        ]);
        reg.set_prover(prover(address.clone(), vec![]));

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(count_proposed_joins(&actions) > 0, "expected joins on first cycle");

        lifecycle.record_join_attempt(100);

        for offset in 1..JOIN_COOLDOWN_FRAMES {
            let f = 100 + offset;
            lifecycle.set_prover_root_verified_frame(f);
            let actions = lifecycle.evaluate(f, 1, reg.as_ref(), wm.as_ref()).unwrap();
            assert_eq!(
                count_proposed_joins(&actions),
                0,
                "join cooldown breached at frame {} (offset {})",
                f,
                offset
            );
        }

        let after_cd = 100 + JOIN_COOLDOWN_FRAMES;
        lifecycle.set_prover_root_verified_frame(after_cd);
        let actions = lifecycle.evaluate(after_cd, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(
            count_proposed_joins(&actions) > 0,
            "expected joins to resume past cooldown"
        );
    }

    #[test]
    fn excess_pending_joins_get_rejected() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // capacity=2, active=1, allowed_pending=1, pending=4 → 3 rejects.
        wm.add(allocated_worker(1, filter_bytes(0xA1)));
        wm.add(allocated_worker(2, filter_bytes(0xB1)));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 50),
            alloc(filter_bytes(0xB2), ProverStatus::Joining, 99),
            alloc(filter_bytes(0xB3), ProverStatus::Joining, 99),
            alloc(filter_bytes(0xB4), ProverStatus::Joining, 99),
            alloc(filter_bytes(0xB5), ProverStatus::Joining, 99),
        ];
        reg.set_prover(prover(address.clone(), allocs));
        reg.set_summaries(vec![
            shard_summary(filter_bytes(0xA1), 1),
            shard_summary(filter_bytes(0xB2), 1),
            shard_summary(filter_bytes(0xB3), 1),
            shard_summary(filter_bytes(0xB4), 1),
            shard_summary(filter_bytes(0xB5), 1),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let rejected = count_rejects(&actions);
        assert_eq!(
            rejected, 3,
            "expected 3 excess pending joins rejected (capacity=2, active=1, allowed=1, pending=4 → excess=3); got {} in {:?}",
            rejected, actions
        );
    }

    /// `plan_leaves` is score-driven: leaves emit when an allocated
    /// shard scores < 67% of the best unallocated alternative.
    #[test]
    fn overcrowded_actives_get_leave_proposed() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(allocated_worker(1, filter_bytes(0xA1)));
        wm.add(allocated_worker(2, filter_bytes(0xA2)));
        wm.add(allocated_worker(3, filter_bytes(0xA3)));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA3), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        // Allocated 0xA1..0xA3 at ring 8 (very low score),
        // unallocated 0xC0/0xC1 at ring 0 (high score).
        let crowded = |filter: Vec<u8>, active: u32, size: u64| {
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, active);
            ProverShardSummary { filter, status_counts: counts, total_size: size }
        };
        reg.set_summaries(vec![
            crowded(filter_bytes(0xA1), 64, 1_000_000),
            crowded(filter_bytes(0xA2), 64, 1_000_000),
            crowded(filter_bytes(0xA3), 64, 1_000_000),
            crowded(filter_bytes(0xC0), 1, 10_000_000),
            crowded(filter_bytes(0xC1), 1, 10_000_000),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let proposed = count_proposed_leaves(&actions);
        assert!(
            proposed > 0,
            "expected ProposeLeave when allocated shards score below the 67% threshold of unallocated alternatives; got {:?}",
            actions
        );
    }

    #[test]
    fn joins_never_exceed_free_worker_count() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // 1 free worker, 1 already allocated, 10 candidate shards.
        wm.add(idle_worker(1));
        wm.add(allocated_worker(2, filter_bytes(0xA1)));

        let allocs = vec![alloc(filter_bytes(0xA1), ProverStatus::Active, 10)];
        reg.set_prover(prover(address.clone(), allocs));

        let mut summaries = Vec::new();
        summaries.push(shard_summary(filter_bytes(0xA1), 1));
        for i in 0..10u8 {
            summaries.push(shard_summary(filter_bytes(0x10 + i), 1));
        }
        reg.set_summaries(summaries);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let proposed = count_proposed_joins(&actions);
        assert_eq!(
            proposed, 1,
            "expected at most 1 join (only 1 free worker); got {} in {:?}",
            proposed, actions
        );
    }

    #[test]
    fn moving_to_fewer_cores_proposes_leaves_for_surplus() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        for i in 1..=4u32 {
            let f = filter_bytes(0xA0 + i as u8);
            wm.add(allocated_worker(i, f));
        }

        let mut allocs = Vec::new();
        let mut summaries = Vec::new();
        for i in 1..=10u8 {
            let f = filter_bytes(0xA0 + i);
            allocs.push(alloc(f.clone(), ProverStatus::Active, 10));
            // Higher index → more crowded → lower score → picked first.
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, i as u32 * 2);
            summaries.push(ProverShardSummary {
                filter: f,
                status_counts: counts,
                total_size: 1_000_000,
            });
        }
        reg.set_prover(prover(address.clone(), allocs));
        reg.set_summaries(summaries);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let proposed = count_proposed_leaves(&actions);
        assert_eq!(
            proposed, 6,
            "expected 6 leaves for 10 actives on 4 workers; got {} in {:?}",
            proposed, actions
        );
    }

    /// Counterpart: when the active count exactly matches the worker
    /// count, no surplus, no leaves.
    #[test]
    fn at_capacity_no_excess_active_leaves() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        for i in 1..=4u32 {
            let f = filter_bytes(0xA0 + i as u8);
            wm.add(allocated_worker(i, f));
        }

        let mut allocs = Vec::new();
        let mut summaries = Vec::new();
        for i in 1..=4u8 {
            let f = filter_bytes(0xA0 + i);
            allocs.push(alloc(f.clone(), ProverStatus::Active, 10));
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, 4);
            summaries.push(ProverShardSummary {
                filter: f,
                status_counts: counts,
                total_size: 1_000_000,
            });
        }
        reg.set_prover(prover(address.clone(), allocs));
        reg.set_summaries(summaries);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let proposed = count_proposed_leaves(&actions);
        assert_eq!(
            proposed, 0,
            "no surplus expected when active count == worker count; got {} in {:?}",
            proposed, actions
        );
    }

    #[test]
    fn manually_managed_filters_never_surplus_leaved() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        let pinned_filter = filter_bytes(0xA1);
        let mut mm_worker = allocated_worker(1, pinned_filter.clone());
        mm_worker.manually_managed = true;
        wm.add(mm_worker);
        wm.add(allocated_worker(2, filter_bytes(0xA2)));

        let mut allocs = Vec::new();
        let mut summaries = Vec::new();
        for i in 1..=5u8 {
            let f = filter_bytes(0xA0 + i);
            allocs.push(alloc(f.clone(), ProverStatus::Active, 10));
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, 4);
            summaries.push(ProverShardSummary {
                filter: f,
                status_counts: counts,
                total_size: 1_000_000,
            });
        }
        reg.set_prover(prover(address.clone(), allocs));
        reg.set_summaries(summaries);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let leaves: Vec<&Vec<Vec<u8>>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters),
                _ => None,
            })
            .collect();
        assert!(!leaves.is_empty(), "expected ProposeLeave for surplus");
        for filter_set in &leaves {
            for f in *filter_set {
                assert_ne!(
                    f, &pinned_filter,
                    "manually-managed filter must not be in leave set"
                );
            }
        }
    }

    #[test]
    fn excess_active_leave_respects_cooldown() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        for i in 1..=2u32 {
            let f = filter_bytes(0xA0 + i as u8);
            wm.add(allocated_worker(i, f));
        }

        let mut allocs = Vec::new();
        let mut summaries = Vec::new();
        for i in 1..=8u8 {
            let f = filter_bytes(0xA0 + i);
            allocs.push(alloc(f.clone(), ProverStatus::Active, 10));
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, 4);
            summaries.push(ProverShardSummary {
                filter: f,
                status_counts: counts,
                total_size: 1_000_000,
            });
        }
        reg.set_prover(prover(address.clone(), allocs));
        reg.set_summaries(summaries);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(200);

        let actions = lifecycle.evaluate(200, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(count_proposed_leaves(&actions) > 0, "expected leaves on first cycle");

        for offset in 1..JOIN_COOLDOWN_FRAMES {
            let f = 200 + offset;
            lifecycle.set_prover_root_verified_frame(f);
            let actions = lifecycle.evaluate(f, 1, reg.as_ref(), wm.as_ref()).unwrap();
            assert_eq!(
                count_proposed_leaves(&actions),
                0,
                "surplus-active leave fired during cooldown at frame {}",
                f
            );
        }

        let after_cd = 200 + JOIN_COOLDOWN_FRAMES;
        lifecycle.set_prover_root_verified_frame(after_cd);
        let actions = lifecycle.evaluate(after_cd, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(
            count_proposed_leaves(&actions) > 0,
            "expected surplus-active leaves to resume past cooldown"
        );
    }

    #[test]
    fn unsynced_tree_emits_nothing() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(idle_worker(1));
        wm.add(allocated_worker(2, filter_bytes(0xA1)));
        wm.add(allocated_worker(3, filter_bytes(0xA2)));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA3), ProverStatus::Joining, 10),
            alloc(filter_bytes(0xA4), ProverStatus::Joining, 10),
            alloc(filter_bytes(0xA5), ProverStatus::Joining, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));
        let mut summaries = Vec::new();
        for i in 1..=5u8 {
            summaries.push(shard_summary(filter_bytes(0xA0 + i), 1));
        }
        for i in 0..5u8 {
            summaries.push(shard_summary(filter_bytes(0xC0 + i), 1));
        }
        reg.set_summaries(summaries);

        // Construct without the usual sync setup so the gate is honest.
        let allocator = Arc::new(WorkerAllocator::new(
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
            address.clone(),
        ));
        let halt = Arc::new(HaltState::new());
        let lifecycle = Arc::new(ProverLifecycle::new(address, allocator, halt));
        lifecycle.set_confirm_window_frames(2);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(
            actions.is_empty(),
            "unsynced tree must emit no actions; got {:?}",
            actions
        );

        lifecycle.set_sync_complete();
        lifecycle.set_prover_root_verified_frame(50);
        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(
            actions.is_empty(),
            "stale verified frame must emit no actions; got {:?}",
            actions
        );

        lifecycle.set_prover_root_verified_frame(100);
        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(
            !actions.is_empty(),
            "actions should emit once tree is synced; got empty"
        );
    }

    /// Workers with a non-zero `pending_filter_frame` (an in-flight
    /// join proposal that hasn't been confirmed in the registry yet)
    /// must NOT be counted as free. Without this gate, the lifecycle
    /// proposes another join for the same worker on the next cycle,
    /// piling up pending allocations.
    #[test]
    fn workers_with_pending_filter_frame_are_not_free() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // Worker has empty filter (registry hasn't confirmed yet) but
        // a pending proposal recorded by submit_join.
        let mut pending_worker = idle_worker(1);
        pending_worker.pending_filter_frame = 95;
        wm.add(pending_worker);

        reg.set_prover(prover(address.clone(), vec![]));
        reg.set_summaries(vec![
            shard_summary(filter_bytes(0xC0), 1),
            shard_summary(filter_bytes(0xC1), 1),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert_eq!(
            count_proposed_joins(&actions),
            0,
            "must not propose joins for workers with in-flight proposals; got {:?}",
            actions
        );
    }

    /// Joining allocations past the 720-frame grace window are
    /// implicitly rejected on-chain; they must not block fresh joins
    /// for the same filter, count toward excess-pending, or appear in
    /// `decide_joins`.
    #[test]
    fn expired_joins_are_skipped() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(idle_worker(1));

        // Joined at frame 10, current frame 800 → 790 frames past join,
        // well over the 720-frame grace.
        let allocs = vec![alloc(filter_bytes(0xA1), ProverStatus::Joining, 10)];
        reg.set_prover(prover(address.clone(), allocs));
        // Only the expired-shard summary; no alternatives. Without the
        // skip, `proposal_descriptors` would be empty → no
        // `ProposeJoin` could fire.
        reg.set_summaries(vec![shard_summary(filter_bytes(0xA1), 1)]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(800);

        let actions = lifecycle.evaluate(800, 1, reg.as_ref(), wm.as_ref()).unwrap();

        // Expired joins must not be force-rejected.
        assert_eq!(
            count_rejects(&actions),
            0,
            "expired joins must not be force-rejected; got {:?}",
            actions
        );

        let proposed_filters: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeJoin { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            proposed_filters,
            vec![filter_bytes(0xA1)],
            "expected fresh ProposeJoin for shard whose prior join expired; got {:?}",
            actions
        );
    }

    #[test]
    fn no_free_workers_means_no_joins() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(allocated_worker(1, filter_bytes(0xA1)));
        wm.add(allocated_worker(2, filter_bytes(0xA2)));
        wm.add(allocated_worker(3, filter_bytes(0xA3)));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA3), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        let mut summaries = Vec::new();
        for i in 0..20u8 {
            summaries.push(shard_summary(filter_bytes(0xA1 + i), 1));
        }
        reg.set_summaries(summaries);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let proposed = count_proposed_joins(&actions);
        assert_eq!(
            proposed, 0,
            "fully-allocated node must not propose joins; got {} in {:?}",
            proposed, actions
        );
    }
}
