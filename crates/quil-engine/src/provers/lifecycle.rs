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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use num_bigint::BigInt;
use tracing::info;

use quil_types::consensus::{ProverRegistry, ProverShardSummary, ProverStatus};
use quil_types::error::Result;

use crate::halt_state::HaltState;
use crate::provers::proposer::{self, ShardDescriptor, Strategy};
use crate::worker::WorkerManager;
use crate::worker_allocator::WorkerAllocator;

/// Confirm window for pending joins/leaves (matches Go's 360 frames).
pub const CONFIRM_WINDOW_FRAMES: u64 = 360;
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
    /// Network halt threshold (from CoverageThresholds). Shards with
    /// `active_count <= halt_threshold + 1` are considered "halt risk"
    /// and get priority allocation under the RewardGreedy strategy —
    /// free workers cover them first, and ring-2+ workers will leave
    /// their current shard to free up capacity.
    ///
    /// Defaults to `u64::MAX` (halt-risk override disabled) until the
    /// caller wires in the real threshold via `set_halt_threshold`.
    halt_threshold: u64,
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
            halt_threshold: u64::MAX,
        }
    }

    /// Wire the coverage-halt threshold (from `CoverageThresholds`)
    /// into the lifecycle. Enables the RewardGreedy halt-risk
    /// override: free workers and ring-2+ allocations will cover /
    /// leave for shards on the verge of halting, bypassing normal
    /// reward scoring.
    pub fn set_halt_threshold(&mut self, threshold: u64) {
        self.halt_threshold = threshold;
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

    /// Port of Go's `joinProposalReady` at `worker_allocator.go:1273-1317`.
    /// Returns `(ready, reason_if_not)`.
    fn join_proposal_ready(&self, frame_number: u64) -> (bool, &'static str) {
        if self.last_observed_frame.load(Ordering::Relaxed) == 0 {
            return (false, "awaiting initial frame");
        }
        if !self.initial_sync_complete.load(Ordering::Relaxed) {
            return (false, "awaiting prover root sync");
        }
        let verified = self.prover_root_verified_frame.load(Ordering::Relaxed);
        if verified == 0 || verified < frame_number {
            return (false, "latest frame not yet verified");
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

        // Gather inputs
        let summaries = registry.get_prover_shard_summaries()?;
        let prover_info = registry.get_prover_info(&self.prover_address)?;
        let workers = worker_manager.range_workers()?;

        // Partition self's allocations by status.
        let mut joining_filters: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut active_filters: Vec<Vec<u8>> = Vec::new();
        let mut leaving_filters: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut all_our_filters: Vec<Vec<u8>> = Vec::new();

        if let Some(ref prover) = prover_info {
            for alloc in &prover.allocations {
                all_our_filters.push(alloc.confirmation_filter.clone());
                match alloc.status {
                    ProverStatus::Joining => {
                        joining_filters.push((alloc.confirmation_filter.clone(), alloc.join_frame_number));
                    }
                    ProverStatus::Active => {
                        active_filters.push(alloc.confirmation_filter.clone());
                    }
                    ProverStatus::Left => {
                        leaving_filters.push((alloc.confirmation_filter.clone(), alloc.leave_frame_number));
                    }
                    _ => {}
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
        let proposal_descriptors = build_proposal_descriptors(&summaries, &all_our_filters);
        let decide_all_descriptors = build_decide_descriptors(&summaries);
        let allocated_descriptors: Vec<ShardDescriptor> = decide_all_descriptors.iter()
            .filter(|d| all_our_filters.contains(&d.filter))
            .cloned()
            .collect();

        let world_bytes = compute_world_bytes_from_summaries(&summaries);

        // Identify halt-risk shards the node could cover: not halted
        // yet, but within one departure of the halt threshold. Empty
        // unless `set_halt_threshold` has been wired. Used only under
        // `Strategy::RewardGreedy` — DataGreedy already prioritizes
        // small/underserved shards by size. Excludes shards we're
        // already allocated to and shards that are currently halted
        // (the halt_state gate takes precedence).
        let halt_risk_filters: std::collections::HashSet<Vec<u8>> =
            if self.strategy == Strategy::RewardGreedy && self.halt_threshold != u64::MAX {
                summaries.iter()
                    .filter(|s| {
                        if s.filter.is_empty() { return false; }
                        if all_our_filters.contains(&s.filter) { return false; }
                        if self.halt_state.is_halted(&s.filter) { return false; }
                        let active = s.status_counts
                            .get(&ProverStatus::Active).copied().unwrap_or(0);
                        (active as u64) <= self.halt_threshold.saturating_add(1)
                    })
                    .map(|s| s.filter.clone())
                    .collect()
            } else {
                std::collections::HashSet::new()
            };

        // Go's allowProposals: a free worker exists (matches
        // `worker_allocator.go:171-181`). Only gates Propose{Join,Leave};
        // Decide{Joins,Leaves} always run.
        let free_worker_ids: Vec<u32> = workers.iter()
            .filter(|w| w.filter.is_empty() && !w.manually_managed)
            .map(|w| w.core_id)
            .collect();
        let allow_proposals = !free_worker_ids.is_empty();

        // Go's canPropose (cooldown + readiness). Checked once per
        // evaluate so both propose paths see the same decision.
        let (can_propose, skip_reason) = self.join_proposal_ready(frame_number);

        let mut actions: Vec<LifecycleAction> = Vec::new();
        let mut join_proposed_this_cycle = false;

        // 1) ProposeJoin — gated on allowProposals && canPropose.
        //    Mirrors worker_allocator.go:210-247.
        //
        //    RewardGreedy halt-risk override: if any halt-risk shards
        //    are available, assign free workers to them first (ordered
        //    most-urgent first) before running normal reward-scored
        //    plan_and_allocate on the remaining workers/shards.
        if !proposal_descriptors.is_empty() && allow_proposals {
            if can_propose {
                let (mut halt_risk_proposals, remaining_workers, remaining_descriptors) =
                    allocate_halt_risk(
                        &proposal_descriptors,
                        &halt_risk_filters,
                        &summaries,
                        &free_worker_ids,
                    );

                let scored_proposals = proposer::plan_and_allocate(
                    &remaining_descriptors,
                    difficulty,
                    &world_bytes,
                    self.units,
                    &remaining_workers,
                    MAX_PROPOSALS_PER_CYCLE.saturating_sub(halt_risk_proposals.len()),
                    self.strategy,
                );
                halt_risk_proposals.extend(scored_proposals);
                let proposals = halt_risk_proposals;

                if !proposals.is_empty() {
                    // Reserve the cooldown slot on success, matching
                    // worker_allocator.go:224. Only set when we actually
                    // emit a join — bare Decide actions don't consume it.
                    let prev_attempt = self.allocator.last_join_attempt();
                    self.allocator.set_last_join_attempt(frame_number);
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
        let ready_join_filters: Vec<Vec<u8>> = joining_filters.iter()
            .filter(|(_, jf)| frame_number >= *jf + CONFIRM_WINDOW_FRAMES)
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

            let (reject, confirm) = proposer::decide_joins(
                &decide_candidates,
                &ready_join_filters,
                difficulty,
                &world_bytes,
                self.units,
                self.strategy,
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
        //    so we mirror that here.
        //
        //    RewardGreedy halt-risk override: if halt-risk shards are
        //    available, also propose to leave our ring-2+ active
        //    allocations (they're on well-covered shards, so it's safe
        //    to vacate them) so we free up capacity to cover the
        //    halt-risk shard on a subsequent cycle.
        if can_propose
            && !join_proposed_this_cycle
            && !active_filters.is_empty()
            && !proposal_descriptors.is_empty()
        {
            let mut leave_candidates = proposer::plan_leaves(
                &allocated_descriptors,
                &proposal_descriptors,
                difficulty,
                &world_bytes,
                self.units,
                self.strategy,
            );

            // Halt-risk override: augment leave list with ring-2+
            // allocations up to the number of halt-risk shards we'd
            // want to cover. Deduplicates against whatever plan_leaves
            // already produced.
            if !halt_risk_filters.is_empty() {
                let mut already_leaving: std::collections::HashSet<Vec<u8>> =
                    leave_candidates.iter().cloned().collect();
                let mut budget = halt_risk_filters.len();
                let mut ring_heavy: Vec<(u8, Vec<u8>)> = allocated_descriptors.iter()
                    .filter(|d| d.ring >= 2)
                    .filter(|d| !already_leaving.contains(&d.filter))
                    .map(|d| (d.ring, d.filter.clone()))
                    .collect();
                // Highest ring (most over-covered) first; then filter bytes for
                // deterministic ordering on ties.
                ring_heavy.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
                for (_ring, filter) in ring_heavy {
                    if budget == 0 { break; }
                    if already_leaving.insert(filter.clone()) {
                        leave_candidates.push(filter);
                        budget -= 1;
                    }
                }
            }

            if !leave_candidates.is_empty() {
                self.allocator.set_last_join_attempt(frame_number);
                info!(
                    leave_proposals = leave_candidates.len(),
                    halt_risk_shards = halt_risk_filters.len(),
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
            .filter(|(_, lf)| frame_number >= *lf + CONFIRM_WINDOW_FRAMES)
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
fn build_proposal_descriptors(
    summaries: &[ProverShardSummary],
    our_filters: &[Vec<u8>],
) -> Vec<ShardDescriptor> {
    summaries.iter().filter_map(|s| {
        if s.filter.is_empty() {
            return None;
        }
        if our_filters.contains(&s.filter) {
            return None;
        }
        let active = s.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0);
        let joining = s.status_counts.get(&ProverStatus::Joining).copied().unwrap_or(0);
        let total = (active + joining) as usize;
        let ri = proposer::compute_shard_ring_info(total);
        Some(ShardDescriptor {
            filter: s.filter.clone(),
            size: if s.total_size > 0 { s.total_size } else { 1 },
            ring: ri.joiner_ring,
            shards: 1,
            active_on_ring: ri.active_on_joiner_ring,
        })
    }).collect()
}

/// Build descriptors for every shard scored with its *current* ring.
/// Used both as the base for decide operations (where pending-matching
/// entries are spliced in) and for plan_leaves (allocated view).
///
/// Mirrors Go's `decideDescriptors` at `worker_allocator.go:884-893`.
fn build_decide_descriptors(summaries: &[ProverShardSummary]) -> Vec<ShardDescriptor> {
    summaries.iter().filter_map(|s| {
        if s.filter.is_empty() {
            return None;
        }
        let active = s.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0);
        let joining = s.status_counts.get(&ProverStatus::Joining).copied().unwrap_or(0);
        let total = (active + joining) as usize;
        let ri = proposer::compute_shard_ring_info(total);
        Some(ShardDescriptor {
            filter: s.filter.clone(),
            size: if s.total_size > 0 { s.total_size } else { 1 },
            ring: ri.current_ring,
            shards: 1,
            active_on_ring: ri.active_on_current_ring,
        })
    }).collect()
}

/// RewardGreedy halt-risk override: pre-assign free workers to
/// halt-risk shards (ordered most-urgent first) before normal reward
/// scoring. Returns `(proposals_for_halt_risk, remaining_worker_ids,
/// remaining_descriptors)`.
///
/// Urgency order: lowest active count first; ties broken by smallest
/// shard size (cheapest to help), then filter bytes (deterministic).
fn allocate_halt_risk(
    proposal_descriptors: &[ShardDescriptor],
    halt_risk_filters: &std::collections::HashSet<Vec<u8>>,
    summaries: &[ProverShardSummary],
    free_worker_ids: &[u32],
) -> (Vec<proposer::Proposal>, Vec<u32>, Vec<ShardDescriptor>) {
    if halt_risk_filters.is_empty() || free_worker_ids.is_empty() {
        return (Vec::new(), free_worker_ids.to_vec(), proposal_descriptors.to_vec());
    }

    // Build (active_count, size, descriptor) tuples for halt-risk
    // descriptors so we can order by urgency.
    let active_by_filter: std::collections::HashMap<Vec<u8>, u64> = summaries.iter()
        .map(|s| {
            let active = s.status_counts
                .get(&ProverStatus::Active).copied().unwrap_or(0) as u64;
            (s.filter.clone(), active)
        })
        .collect();

    let mut halt_risk_ordered: Vec<(u64, u64, ShardDescriptor)> = proposal_descriptors.iter()
        .filter(|d| halt_risk_filters.contains(&d.filter))
        .map(|d| {
            let active = active_by_filter.get(&d.filter).copied().unwrap_or(0);
            (active, d.size, d.clone())
        })
        .collect();
    halt_risk_ordered.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.filter.cmp(&b.2.filter))
    });

    let mut proposals: Vec<proposer::Proposal> = Vec::new();
    let mut consumed_workers: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut consumed_filters: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();

    let mut worker_iter = free_worker_ids.iter().copied();
    for (_active, _size, d) in halt_risk_ordered {
        let Some(worker_id) = worker_iter.next() else { break; };
        consumed_workers.insert(worker_id);
        consumed_filters.insert(d.filter.clone());
        // Halt-risk assignments bypass reward scoring — expected_reward
        // is zero (PoMW reward is still computed at claim time based on
        // actual shard state). shards_denominator follows the joiner
        // ring view like normal allocations.
        proposals.push(proposer::Proposal {
            worker_id,
            filter: d.filter.clone(),
            expected_reward: BigInt::from(0),
            world_state_bytes: 0,
            shard_size_bytes: d.size,
            ring: d.ring,
            shards_denominator: d.shards as u64,
        });
    }

    let remaining_workers: Vec<u32> = free_worker_ids.iter()
        .copied()
        .filter(|id| !consumed_workers.contains(id))
        .collect();
    let remaining_descriptors: Vec<ShardDescriptor> = proposal_descriptors.iter()
        .filter(|d| !consumed_filters.contains(&d.filter))
        .cloned()
        .collect();

    (proposals, remaining_workers, remaining_descriptors)
}

fn compute_world_bytes_from_summaries(summaries: &[ProverShardSummary]) -> BigInt {
    let total: u64 = summaries.iter()
        .map(|s| if s.total_size > 0 { s.total_size } else { 1 })
        .sum();
    BigInt::from(total.max(1))
}
