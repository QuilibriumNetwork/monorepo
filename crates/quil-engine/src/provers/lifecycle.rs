//! Prover lifecycle coordinator. Determines what the node should do
//! on each new frame: propose joins/leaves, confirm pending proposals,
//! or reject inferior ones.
//!
//! Port of Go's `evaluateForProposals` + `collectAllocationSnapshot`
//! in `node/consensus/global/worker_allocator.go`.
//!
//! Split of responsibilities with `WorkerAllocator`:
//! - `WorkerAllocator::on_new_frame`: reconciles registry state with
//! running workers (assigns filters to idle cores, clears stale
//! filters). Pure state sync, no proposals.
//! - `ProverLifecycle::evaluate`: examines registry + worker state
//! and returns the full list of actions to submit this frame
//! (matching Go's `evaluateForProposals`, which can emit Propose
//! + Decide actions in the same cycle). The caller dispatches each
//! through the submission pipeline; per-address locking in the
//! consensus engine serializes them so only one takes effect per
//! affected prover address per frame. The single cooldown timer
//! lives on the `WorkerAllocator`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use num_bigint::BigInt;
use tracing::info;

use quil_types::consensus::{ProverRegistry, ProverShardSummary, ProverStatus};
use quil_types::error::Result;

use crate::halt_state::HaltState;
use crate::provers::proposer::{self, ShardDescriptor, Strategy};
use crate::worker::{WorkerManager, WorkerView};
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
/// Per-filter cooldown between successive Leave proposals on the same
/// filter. Suppresses duplicate Leave publishes during the
/// publish→archive-materialize→registry-sync round-trip. Wider than
/// `JOIN_COOLDOWN_FRAMES` because Leave round-trips include both
/// archive-side materialization and the (~5-minute-cadence) prover
/// tree sync that updates our local view of allocation status. 20
/// frames ≈ 10 minutes on mainnet, comfortably spanning one full
/// sync cycle so the next plan_leaves cycle sees the Leaving status.
pub const LEAVE_COOLDOWN_FRAMES: u64 = 20;
/// Minimum frames an allocation must have been Active (since its join
/// confirmed) before it is eligible for a *pure-score* leave. A freshly
/// established, producing allocation is "fine" — shedding it to chase a
/// marginally-higher unallocated shard is the churn this dwell prevents
/// (workers leaving good allocations, rejoining elsewhere, then leaving
/// again). Health-driven leaves (empty / orphan / halt-risk-deficit swap)
/// ignore the dwell. Matches one confirm window so a holding is kept at
/// least as long as it took to establish it.
pub const SCORE_LEAVE_MIN_HOLD_FRAMES: u64 = DEFAULT_CONFIRM_WINDOW_FRAMES;
/// Per-filter cooldown between successive Join proposals on the same
/// filter. Closes the orphan-Joining gap created by
/// `PROPOSAL_TIMEOUT_FRAMES` (10) being shorter than typical
/// bundle-to-local-registry round-trip latency. When the worker-level
/// pending marker times out, the worker goes back into `free_auto`
/// and the next cycle can re-pick the same filter via a fresh bundle
/// — but the prior bundle is still on the wire. Both eventually land,
/// the registry holds two Joining allocs for the same filter (or
/// overlapping cycles dilute the worker budget), and the assignment
/// loop runs out of idle workers, leaving the excess as orphans
/// (Joining alloc with no worker bound, observed in the wild:
/// 5 overlapping ProposeJoin cycles for the same ~13
/// halt-risk filters within 45 frames produced 22 unique Joining
/// allocs against 13 available worker slots, leaving ~9 orphans).
/// 30 frames ≈ 15 minutes on mainnet, well past the worst-case
/// archive materialize + prover-tree sync round-trip we've seen.
pub const JOIN_FILTER_COOLDOWN_FRAMES: u64 = 30;

/// Backoff before re-proposing a join to a shard that *rejected* our
/// last join. `JOIN_FILTER_COOLDOWN_FRAMES` only gates re-proposal off
/// the last join *attempt*, so a contested shard that keeps rejecting us
/// is re-hammered every ~cooldown forever (observed: a single filter
/// oscillating Joining↔Rejected for hours, ~480 rejected allocs on one
/// node, workers saturated by never-confirming pending joins). When our
/// allocation lands in Rejected, hold off re-proposing that filter for
/// this window so the node tries *other* (less contested) unallocated
/// shards instead of fighting for the same one. Matches one confirm
/// window. Tunable.
pub const JOIN_REJECT_BACKOFF_FRAMES: u64 = DEFAULT_CONFIRM_WINDOW_FRAMES;

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
    /// Re-confirm Active allocations whose storage epoch went stale: re-encode
    /// fresh-epoch SDR replicas + re-register leaf roots (a ProverConfirm at the
    /// current frame), then prune replicas below the new epoch. PoRep epoch
    /// rotation — without it the storage audit evicts the prover next epoch.
    ReconfirmEpoch {
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
            Self::ReconfirmEpoch { filters, frame_number } => f
                .debug_struct("ReconfirmEpoch")
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

/// Allocations this prover holds on-chain that NOTHING is working — the
/// "Leave regardless of score" set.
///
/// Candidates are `active` UNION `expired_epoch`. Including `expired_epoch` is
/// what makes the sweep terminating rather than one-shot: being orphaned is
/// precisely what makes an allocation expire, since no worker means no proofs
/// and so a missed per-epoch re-confirm at the next boundary, after which the
/// allocation leaves `active`. Sweeping `active` alone therefore gave an orphan
/// a single epoch of eligibility and no way back, so an orphan that survived one
/// boundary became permanently unsheddable. Observed in the wild as a node
/// holding 35 allocations against 15 workers, the 20 unbound ones all reading
/// `re-confirm!`, with no Leave ever proposed.
///
/// `expired_epoch` deliberately does NOT join `active` itself — that set is
/// coverage accounting and an unconfirmed allocation genuinely does not count.
/// This widens only who may be SHED.
///
/// Excluded: filters a worker is bound to (including in-flight joins, whose
/// `worker.filter` is set at submit time), operator-pinned filters, and filters
/// already mid-Leave.
pub(crate) fn orphaned_allocation_filters(
    active_filters: &[Vec<u8>],
    expired_epoch_filters: &[Vec<u8>],
    bound_filters: &std::collections::HashSet<Vec<u8>>,
    manually_managed_filters: &std::collections::HashSet<Vec<u8>>,
    pending_leave_filters: &std::collections::HashSet<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    active_filters
        .iter()
        .chain(expired_epoch_filters.iter())
        .filter(|f| seen.insert(f.as_slice()))
        .filter(|f| !bound_filters.contains(*f))
        .filter(|f| !manually_managed_filters.contains(*f))
        .filter(|f| !pending_leave_filters.contains(*f))
        .cloned()
        .collect()
}


/// Allocations partitioned by their effective status at a given
/// frame. Lifecycle's `evaluate` collects these once and dispatches
/// each downstream subroutine against the appropriate slice. Pulling
/// the partitioning out of the inline match expression makes it
/// testable in isolation — important because mis-bucketing has been
/// a recurring source of regressions (`tree.Delete` was wrongly
/// removing expired Joining allocs that should have been bucketed as
/// ExpiredJoining and left alone).
#[derive(Debug, Default)]
pub struct AllocationBuckets {
    /// Allocs in Joining (still within grace) — eligible for confirm.
    pub joining: Vec<(Vec<u8>, u64)>,
    /// Allocs in Active — drive surplus / leave decisions.
    pub active: Vec<Vec<u8>>,
    /// Allocs in Leaving (still within grace) — eligible for leave-confirm.
    pub leaving: Vec<(Vec<u8>, u64)>,
    /// Every filter we own (Joining, Active, Paused, Leaving) but
    /// NOT terminal/expired. The "are we already on this shard" set.
    pub all_ours: Vec<Vec<u8>>,
    /// On-chain Active allocations whose recorded storage epoch is stale
    /// (`EffectiveStatus::ExpiredEpoch`) — must re-confirm fresh leaf roots
    /// for the current epoch to keep counting + avoid the storage audit.
    pub expired_epoch: Vec<Vec<u8>>,
}

impl AllocationBuckets {
    /// Partition a prover's allocation list by effective status at
    /// `frame_number`. Terminal and expired statuses (Rejected,
    /// Kicked, ExpiredJoining, ExpiredLeaving, Unknown) are
    /// excluded from every bucket — the lifecycle treats them as
    /// "doesn't exist," which prevents `plan_leaves` from
    /// proposing a Leave for an allocation the network already
    /// considers terminal.
    pub fn from_allocations(
        allocations: &[quil_types::consensus::ProverAllocationInfo],
        frame_number: u64,
    ) -> Self {
        use quil_types::consensus::{EffectiveStatus, ProverStatus};
        let mut buckets = AllocationBuckets::default();
        for alloc in allocations {
            match alloc.effective_status(frame_number) {
                EffectiveStatus::Joining => {
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                    // Only a NOT-YET-CONFIRMED join (raw byte still Joining) is
                    // eligible for confirm. A join that already confirmed reads
                    // as Joining too — deferred activation keeps it out of the
                    // committee until the next epoch boundary — but its raw byte
                    // is Active and it must NOT be re-confirmed. It owns the slot
                    // (all_ours) and its worker prepares during the wait.
                    if alloc.status == ProverStatus::Joining {
                        buckets
                            .joining
                            .push((alloc.confirmation_filter.clone(), alloc.join_frame_number));
                    }
                }
                EffectiveStatus::Active => {
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                    buckets.active.push(alloc.confirmation_filter.clone());
                    // Proactive per-epoch re-confirm. An allocation registered
                    // only for the current epoch (alloc.epoch == current) is
                    // still Active now but flips ExpiredEpoch at the next
                    // boundary — and, worse, the global storage audit at the new
                    // epoch finds no leaf-root registration for it. Re-confirming
                    // NOW registers current+1 (and encodes its replica ahead), so
                    // the member stays continuously Active/attesting. The prior
                    // ExpiredEpoch-ONLY trigger only fired after expiry, yielding
                    // an every-other-epoch cadence with a coverage/attestation
                    // gap at each boundary. Global (empty-filter) allocations are
                    // exempt (no storage epoch). Stays in `active` so it keeps
                    // counting for coverage; the re-confirm is cooldown-gated
                    // downstream so it isn't re-published every frame.
                    if !alloc.confirmation_filter.is_empty()
                        && alloc.epoch
                            <= quil_types::consensus::epoch_for_frame(frame_number)
                    {
                        buckets.expired_epoch.push(alloc.confirmation_filter.clone());
                    }
                }
                EffectiveStatus::Leaving => {
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                    // A confirmed leave still serves until the next epoch, but
                    // must not submit another confirmation while serving notice.
                    if alloc.leave_confirm_frame_number == 0 {
                        buckets.leaving.push((
                            alloc.confirmation_filter.clone(),
                            alloc.leave_frame_number,
                        ));
                    }
                }
                EffectiveStatus::Paused => {
                    // We still own the alloc — keep it in `all_ours`
                    // so the proposer doesn't re-propose joining the
                    // same shard — but neither active (no
                    // surplus/leave pressure) nor joining/leaving
                    // (no decide-pending action).
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                }
                // ExpiredEpoch: the prover holds an on-chain Active allocation
                // but hasn't re-confirmed its leaf roots for the current epoch.
                // Recoverable, not terminal — keep it in `all_ours` (we still
                // own the shard, so don't re-propose a join) but NOT in `active`
                // (it doesn't count toward coverage until re-confirmed), and
                // queue it for the per-epoch re-confirm (PoRep increment E).
                EffectiveStatus::ExpiredEpoch => {
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                    buckets.expired_epoch.push(alloc.confirmation_filter.clone());
                }
                // Expired, but the NETWORK has not forgotten it. Expiry is
                // computed from elapsed frames and never written back, so the
                // raw `Status` byte on chain is still Joining/Leaving, and
                // `verify_prover_join_allocations_expired` refuses a re-join
                // until `REJOIN_WINDOW_FRAMES` after JoinFrameNumber. Treating
                // it as "doesn't exist" here makes the proposer re-propose a
                // join the network always drops (`0x0312 existing allocation
                // still active`) — the node keeps spending its free workers on
                // the one filter it cannot take, which after split/merge churn
                // left whole nodes carrying no shard at all. So keep it out of
                // every ACTION bucket exactly as before (no Leave for something
                // already terminal on chain) but keep it in `all_ours` until the
                // window passes, so those workers go to a shard it CAN join.
                EffectiveStatus::ExpiredJoining | EffectiveStatus::ExpiredLeaving => {
                    if frame_number < alloc.join_frame_number.saturating_add(
                        quil_execution::global_intrinsic::verify::REJOIN_WINDOW_FRAMES)
                    {
                        buckets.all_ours.push(alloc.confirmation_filter.clone());
                    }
                }
                // Terminal / past-grace. Treat as "doesn't exist":
                // don't push anywhere, otherwise these would leak
                // into `allocated_descriptors` and `plan_leaves`
                // may emit a Leave for an allocation that's already
                // terminal on-chain.
                // Historic: superseded by a reassignment. Treat as "doesn't
                // exist" like the terminals — crucially NOT in `all_ours`, so the
                // proposer is free to re-propose joining this shard, which
                // reactivates the retained slot (the reversibility the status
                // exists for) instead of hitting a permanent delete-tombstone.
                // Rejected and Historic are the two the on-chain verifier also
                // skips, so re-proposing them is accepted.
                EffectiveStatus::Rejected
                | EffectiveStatus::Kicked
                | EffectiveStatus::Historic
                | EffectiveStatus::Unknown => {}
            }
        }
        buckets
    }
}

/// Snapshot of every gate the lifecycle consults when deciding what
/// to emit on a given frame. Populated once at the top of
/// [`ProverLifecycle::evaluate`] (and exposed via
/// [`ProverLifecycle::readiness_for`] for diagnostics) so each
/// downstream branch consults a single, consistent set of conditions
/// rather than re-reading atomics one by one. Each gate carries the
/// *positive* meaning ("ok to proceed") and the readiness checkers
/// below report the first failure as a stable `&'static str` reason
/// suitable for logging.
#[derive(Debug, Clone, Copy)]
pub struct LifecycleReadiness {
    /// Frame the readiness was evaluated at. Lets callers cross-check
    /// the readiness snapshot against the frame they intend to act on.
    pub frame_number: u64,
    /// At least one frame has been observed (via BlossomSub recv,
    /// archive poller, or startup clock-store seed). Cold-start
    /// nodes will fail this gate.
    pub frame_seen: bool,
    /// Initial prover-tree sync has reported completion. Set by
    /// the bootstrap path once we've drained the initial archive
    /// fetch.
    pub initial_sync_complete: bool,
    /// The local prover-tree root commitment has been verified at
    /// or past `frame_number` against an archive snapshot.
    pub tree_verified: bool,
    /// Initial `GetAppShards` refresh has completed at least once.
    /// Gates auto-pick branches (Propose*) but NOT confirm/seniority
    /// branches (those depend only on local pending state).
    pub shard_info_loaded: bool,
    /// Enough frames have elapsed since the last join attempt to
    /// allow another. Driven by `WorkerAllocator::last_join_attempt`
    /// + `JOIN_COOLDOWN_FRAMES`.
    pub join_cooldown_ok: bool,
    /// This node has a non-empty prover address (loaded from keys).
    /// Without one we can't sign anything.
    pub identity_known: bool,
    /// VDF proof generation is NOT currently in flight. While a
    /// proof is being computed, the lifecycle defers all evaluation
    /// to avoid layering an additional join proposal on top of an
    /// expensive in-progress computation.
    pub proof_idle: bool,
}

impl LifecycleReadiness {
    /// Minimum readiness for any lifecycle action (including
    /// confirms and seniority-merge): the local view must be valid
    /// and the registry must be current at the target frame.
    /// Returns `Err(reason)` on the first failing gate; reasons are
    /// stable strings suitable for trace logging.
    pub fn baseline_ready(&self) -> std::result::Result<(), &'static str> {
        if !self.proof_idle {
            return Err("proof in progress");
        }
        if !self.identity_known {
            return Err("prover address not set");
        }
        if !self.frame_seen {
            return Err("awaiting initial frame");
        }
        if !self.initial_sync_complete {
            return Err("awaiting prover root sync");
        }
        if !self.tree_verified {
            return Err("latest frame not yet verified");
        }
        Ok(())
    }

    pub fn propose_ready(&self) -> std::result::Result<(), &'static str> {
        self.baseline_ready()?;
        if !self.join_cooldown_ok {
            return Err("cooldown between join attempts");
        }
        Ok(())
    }

    /// Auto-pick readiness: propose_ready + initial `GetAppShards`
    /// data is in. Required for paths that automatically choose
    /// shards from the remote-sourced size cache (vs. confirming a
    /// proposal that came in over the wire).
    pub fn auto_pick_ready(&self) -> std::result::Result<(), &'static str> {
        self.propose_ready()?;
        if !self.shard_info_loaded {
            return Err("shard info not yet loaded");
        }
        Ok(())
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
    /// Shared node-level current-frame tracker. Consulted by the
    /// readiness snapshot for the `frame_seen` gate; populated by
    /// the BlossomSub recv path, archive poller, finalize hook,
    /// and frame materializer. Replaces the lifecycle's prior
    /// `last_observed_frame: AtomicU64` — that mirror was a
    /// duplicate of the same value and had to be set by callers
    /// of `evaluate`, which was a synchronization invariant
    /// they often forgot.
    current_frame: Arc<crate::current_frame::CurrentFrame>,
    /// Reward strategy. Matches `config.engine.data_greedy`. Set
    /// at construction; treated as immutable for the lifetime of
    /// the lifecycle (production never changes it after startup,
    /// and the previous `&mut self` setter forced every holder
    /// into a `mut` binding for a one-time init write).
    strategy: Strategy,
    /// Issuance units constant (default 8_000_000_000).
    units: u64,
    /// WorkerAllocator holds the single-source-of-truth join cooldown timer.
    allocator: Arc<WorkerAllocator>,
    /// Shared halt state — proposals pause while any shard is in a
    /// coverage halt. Populated by the coverage-event subscriber.
    halt_state: Arc<HaltState>,
    /// Per-shard byte sizes derived from the local hypergraph CRDT
    /// (`local_app_shard_get_sizes` walks `vertex_adds`). Authoritative
    /// for shards this node holds data for — everything else is 0 and
    /// excluded by the writer at the point of insertion. Refreshed
    /// every frame by the archive poller's `on_frame` closure.
    ///
    /// **Split from a previous single-cache design**: a single
    /// `shard_sizes_by_filter` field was overwritten on each
    /// `set_local_shard_sizes` / `set_remote_shard_sizes` call. The per-frame
    /// local writer clobbered the (~60-frame-cadence) remote writer,
    /// leaving the lifecycle with a near-empty score map for 59 out
    /// of every 60 frames. Splitting into two caches lets each writer
    /// own its source-of-truth without racing.
    local_shard_sizes: RwLock<HashMap<Vec<u8>, (u64, u64)>>,
    /// Per-shard (byte size, data-shard count) pairs from the most recent successful
    /// `GetAppShards` archive fetch. Authoritative for shards we are
    /// NOT allocated to (the local cache would have 0 / missing
    /// entries for those). Refreshed every 60 frames or on first-
    /// success by the `shard_info_refresh` task; setting it flips the
    /// `shard_info_loaded` gate.
    remote_shard_sizes: RwLock<HashMap<Vec<u8>, (u64, u64)>>,
    /// Shards the last archive refresh reported frozen by a recorded split
    /// or merge that has not applied yet. The chain refuses a whole join
    /// that names one, so they are not join candidates.
    frozen_shards: RwLock<std::collections::HashSet<Vec<u8>>>,
    /// Shards the synced registry shows live allocations on that the
    /// archive sizes do not include, as of the last `evaluate`. A split
    /// moves the parent's allocations to its children as the registry
    /// syncs; until the sizes refresh, the children that got no
    /// allocation are invisible to the proposer.
    unsized_live_shards: RwLock<std::collections::HashSet<Vec<u8>>>,
    /// The unsized live shards an archive refresh has already failed to
    /// report; they do not ask for another refresh.
    settled_unsized_shards: RwLock<std::collections::HashSet<Vec<u8>>>,
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
    /// Per-filter "last frame we proposed Leave on this filter."
    /// Used to suppress duplicate Leave publishes during the
    /// publish→archive→materialize→sync round-trip — without this,
    /// every cycle within that window re-proposes Leave on the same
    /// filter (the local registry still shows it Active until the
    /// round-trip completes), and the pipeline republishes
    /// identical bundles. Entries older than `LEAVE_COOLDOWN_FRAMES`
    /// are pruned lazily on read so the map can't grow unbounded.
    last_leave_attempt: RwLock<HashMap<Vec<u8>, u64>>,
    /// Per-filter "last frame we proposed Join on this filter."
    /// Worker-level `pending_filter_frame` already prevents re-using
    /// the same worker slot mid-flight, but it times out after 10
    /// frames (`PROPOSAL_TIMEOUT_FRAMES`) — after which the worker
    /// is freed for reuse, and the next cycle can propose a Join
    /// for a DIFFERENT filter via that worker even though the first
    /// bundle is still in flight on the wire. When both bundles
    /// eventually materialize, the registry ends up with more
    /// Joining allocs than we have workers for, and the excess
    /// becomes orphans (alloc Joining, no worker bound). This map
    /// gates `plan_and_allocate` candidate selection so a filter
    /// with a recent in-flight bundle isn't re-picked until the
    /// cooldown elapses. Pruned lazily on read.
    last_join_attempt: RwLock<HashMap<Vec<u8>, u64>>,
    /// Set to true after the first successful `GetAppShards` refresh
    /// (`set_remote_shard_sizes`). Gates `ProposeJoin` and `ProposeLeave`:
    /// the lifecycle must not auto-pick shards while it lacks any
    /// remote-sourced size data, because picking on local-only data
    /// (which is 0 for shards we're not on) makes "empty" shards look
    /// identical to genuinely-uninteresting ones. The local cache
    /// (`set_local_shard_sizes`) does NOT flip this flag — local data is
    /// only authoritative for shards we already hold. Confirm /
    /// leave-confirm / seniority-merge paths run regardless of this
    /// gate since they depend on local pending state, not shard sizes.
    shard_info_loaded: AtomicBool,
    pub(crate) confirmation_attempts: Arc<crate::confirmation_attempts::ConfirmationAttempts>,
}

impl ProverLifecycle {
    /// Construct a lifecycle backed by the given `CurrentFrame`
    /// tracker. The lifecycle reads from the tracker for the
    /// `frame_seen` readiness gate; it never writes back, so any
    /// site that already advances the shared tracker (BlossomSub
    /// recv, archive poller, materializer) covers the lifecycle
    /// automatically.
    pub fn new(
        prover_address: Vec<u8>,
        allocator: Arc<WorkerAllocator>,
        halt_state: Arc<HaltState>,
        current_frame: Arc<crate::current_frame::CurrentFrame>,
        strategy: Strategy,
    ) -> Self {
        Self {
            prover_address,
            proof_in_progress: AtomicBool::new(false),
            initial_sync_complete: AtomicBool::new(false),
            prover_root_verified_frame: AtomicU64::new(0),
            current_frame,
            strategy,
            units: proposer::DEFAULT_UNITS,
            allocator,
            halt_state,
            local_shard_sizes: RwLock::new(HashMap::new()),
            remote_shard_sizes: RwLock::new(HashMap::new()),
            frozen_shards: RwLock::new(std::collections::HashSet::new()),
            unsized_live_shards: RwLock::new(std::collections::HashSet::new()),
            settled_unsized_shards: RwLock::new(std::collections::HashSet::new()),
            confirm_window_frames: AtomicU64::new(DEFAULT_CONFIRM_WINDOW_FRAMES),
            shards_store: RwLock::new(None),
            last_leave_attempt: RwLock::new(HashMap::new()),
            last_join_attempt: RwLock::new(HashMap::new()),
            shard_info_loaded: AtomicBool::new(false),
            confirmation_attempts: Arc::new(crate::confirmation_attempts::ConfirmationAttempts::default()),
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

    /// Test-only handle to the shared halt state, so tests can simulate
    /// degraded-coverage / prover-only mode and assert leave proposals
    /// are suppressed.
    #[cfg(test)]
    pub(crate) fn halt_state(&self) -> &Arc<HaltState> {
        &self.halt_state
    }

    /// Populate the **local** per-shard byte size map (sizes derived
    /// from this node's CRDT vertex-adds). Caller is the archive
    /// poller's `on_frame` closure; it computes sizes per frame via
    /// `local_app_shard_get_sizes`. Routes to `local_shard_sizes`
    /// only — the remote cache is untouched.
    ///
    /// **Does NOT flip `shard_info_loaded`** — local data is only
    /// authoritative for shards we already hold; to unblock the
    /// `ProposeJoin` / `ProposeLeave` gate, the remote refresh task
    /// must succeed at least once via `set_remote_shard_sizes`.
    pub fn set_local_shard_sizes(&self, sizes: HashMap<Vec<u8>, u64>) {
        self.set_local_shard_metrics(sizes.into_iter().map(|(f, n)| (f, (n, 1))).collect());
    }

    /// Replace byte sizes and data-shard counts together, from one local scan.
    pub fn set_local_shard_metrics(&self, sizes: HashMap<Vec<u8>, (u64, u64)>) {
        if let Ok(mut guard) = self.local_shard_sizes.write() {
            *guard = sizes;
        }
    }

    /// Populate the **remote** per-shard byte size map (sizes from a
    /// successful `GetAppShards` archive fetch) and flip
    /// `shard_info_loaded` to true. After the first successful call,
    /// `ProposeJoin` and `ProposeLeave` are eligible to fire.
    ///
    /// Missing-from-refresh filters are dropped from the remote
    /// cache: the entire remote map is replaced atomically with the
    /// fresh fetch. The local cache is untouched, so partial remote
    /// refreshes do NOT lose local data for shards we hold.
    pub fn set_remote_shard_sizes(&self, sizes: HashMap<Vec<u8>, u64>) {
        self.set_remote_shard_metrics(sizes.into_iter().map(|(f, n)| (f, (n, 1))).collect());
    }

    /// Replace byte sizes and data-shard counts together, from one archive response.
    pub fn set_remote_shard_metrics(&self, sizes: HashMap<Vec<u8>, (u64, u64)>) {
        if let (Ok(mut lacking), Ok(mut settled)) =
            (self.unsized_live_shards.write(), self.settled_unsized_shards.write())
        {
            lacking.retain(|filter| !sizes.contains_key(filter));
            *settled = lacking.clone();
        }
        if let Ok(mut guard) = self.remote_shard_sizes.write() {
            *guard = sizes;
        }
        self.shard_info_loaded.store(true, Ordering::Relaxed);
    }

    /// Replace the shards the last archive refresh reported frozen by a
    /// pending split or merge. See `frozen_shards`.
    pub fn set_frozen_shards(&self, frozen: std::collections::HashSet<Vec<u8>>) {
        if let Ok(mut guard) = self.frozen_shards.write() {
            *guard = frozen;
        }
    }

    /// True when the synced registry shows a live shard the archive sizes
    /// lack and no refresh has yet come back without it: the topology
    /// changed since the last refresh, so the refresh should not wait for
    /// its cadence.
    pub fn wants_shard_info_refresh(&self) -> bool {
        match (self.unsized_live_shards.read(), self.settled_unsized_shards.read()) {
            (Ok(lacking), Ok(settled)) => lacking.iter().any(|filter| !settled.contains(filter)),
            _ => false,
        }
    }

    /// Merged read of the two size caches. Remote entries form the
    /// base map (authoritative for shards we're not on); local
    /// entries override / fill in (authoritative for shards we
    /// hold). Cloned per call — typical map sizes are O(thousands)
    /// at most, called once per `evaluate` (~10 s cadence), so the
    /// alloc cost is negligible. Returned by value so callers
    /// don't hold either lock during proposal building.
    pub fn merged_shard_sizes(&self) -> HashMap<Vec<u8>, u64> {
        self.merged_shard_metrics().into_iter().map(|(f, (bytes, _))| (f, bytes)).collect()
    }

    fn merged_shard_metrics(&self) -> HashMap<Vec<u8>, (u64, u64)> {
        let mut merged = self
            .remote_shard_sizes
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        if let Ok(local) = self.local_shard_sizes.read() {
            for (k, v) in local.iter() {
                merged.insert(k.clone(), *v);
            }
        }
        merged
    }

    /// True once the lifecycle has successfully consumed at least one
    /// remote `GetAppShards` response. Until this is set,
    /// `ProposeJoin` and `ProposeLeave` paths short-circuit (no
    /// auto-pick decisions). Used both as the gate inside `evaluate`
    /// and exposed for observability.
    pub fn shard_info_loaded(&self) -> bool {
        self.shard_info_loaded.load(Ordering::Relaxed)
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

    /// Record a successful `ProverJoin` submission at `frame_number`.
    /// Called by the pipeline AFTER `publish_prover_message` succeeds
    /// so transient archive failures don't burn the 4-frame join
    /// cooldown and skip legitimate retry opportunities. Matches Go's
    /// post-success cooldown semantics at `worker_allocator.go:224`.
    pub fn record_join_attempt(&self, frame_number: u64) {
        self.allocator.set_last_join_attempt(frame_number);
    }

    /// Serialize discretionary replacement waves until the workers from the
    /// previous wave are available. Per-cycle pairing cannot prevent the same
    /// destination from funding another leave while its first source still
    /// serves notice. Use chain state so this also survives restarts.
    fn replacement_leave_pending(
        &self,
        prover: Option<&quil_types::consensus::ProverInfo>,
        workers: &[crate::worker::WorkerInfo],
        frame_number: u64,
    ) -> bool {
        use quil_types::consensus::EffectiveStatus;
        let auto_bound: std::collections::HashSet<&Vec<u8>> = workers.iter()
            .filter(|w| !w.manually_managed && !w.filter.is_empty())
            .map(|w| &w.filter)
            .collect();
        if prover.is_some_and(|p| p.allocations.iter().any(|a| {
            auto_bound.contains(&a.confirmation_filter)
                && a.effective_status(frame_number) == EffectiveStatus::Leaving
        })) {
            return true;
        }
        // Before publication, the registry still calls the source Active.
        // Keep the existing bounded retry window for a failed submission.
        self.last_leave_attempt.read().map(|attempts| attempts.iter().any(|(filter, last)| {
            auto_bound.contains(filter)
                && frame_number.saturating_sub(*last) < LEAVE_COOLDOWN_FRAMES
        })).unwrap_or(true)
    }

    /// Drop filters whose last Leave proposal is within
    /// `LEAVE_COOLDOWN_FRAMES` of `frame_number`. Also opportunistically
    /// prunes expired entries from the cooldown map so it can't grow
    /// unbounded.
    fn filter_recent_leave_attempts(
        &self,
        candidates: Vec<Vec<u8>>,
        frame_number: u64,
    ) -> Vec<Vec<u8>> {
        let Ok(mut guard) = self.last_leave_attempt.write() else {
            return candidates;
        };
        // Lazy prune: drop entries that are past the cooldown window.
        guard.retain(|_, last| {
            frame_number.saturating_sub(*last) < LEAVE_COOLDOWN_FRAMES
        });
        candidates
            .into_iter()
            .filter(|f| {
                guard
                    .get(f)
                    .map(|&last| {
                        frame_number.saturating_sub(last) >= LEAVE_COOLDOWN_FRAMES
                    })
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Stamp the per-filter Leave cooldown map. Called immediately
    /// before pushing a ProposeLeave action so the next cycle's
    /// `filter_recent_leave_attempts` excludes these filters.
    fn record_leave_attempts(&self, filters: &[Vec<u8>], frame_number: u64) {
        let Ok(mut guard) = self.last_leave_attempt.write() else {
            return;
        };
        for f in filters {
            guard.insert(f.clone(), frame_number);
        }
    }

    /// Build a set of filters with an in-flight Join proposal — i.e.,
    /// any filter we stamped in `last_join_attempt` within the last
    /// `JOIN_FILTER_COOLDOWN_FRAMES`. Used by the propose path to
    /// exclude these filters from the candidate set passed to
    /// `plan_and_allocate`, preventing the orphan-Joining failure
    /// mode where overlapping cycles propose the same filter via
    /// different workers and both bundles eventually materialize.
    /// Also opportunistically prunes expired entries so the map
    /// can't grow unbounded.
    fn filters_with_inflight_join(&self, frame_number: u64) -> std::collections::HashSet<Vec<u8>> {
        let Ok(mut guard) = self.last_join_attempt.write() else {
            return std::collections::HashSet::new();
        };
        // Lazy prune.
        guard.retain(|_, last| {
            frame_number.saturating_sub(*last) < JOIN_FILTER_COOLDOWN_FRAMES
        });
        guard.keys().cloned().collect()
    }

    /// Stamp the per-filter Join cooldown map. Called immediately
    /// before pushing a ProposeJoin action so the next cycle excludes
    /// these filters from `plan_and_allocate`'s candidate pool until
    /// `JOIN_FILTER_COOLDOWN_FRAMES` elapses.
    fn record_join_filter_attempts(&self, filters: &[Vec<u8>], frame_number: u64) {
        let Ok(mut guard) = self.last_join_attempt.write() else {
            return;
        };
        for f in filters {
            guard.insert(f.clone(), frame_number);
        }
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
        let last_observed = self.current_frame.effective();

        let mut pending: Vec<Vec<u8>> = joining_filters.iter()
            .filter(|(filter, join_frame)| {
                if filter.is_empty() { return false; }
                // Skip expired joins — implicitly rejected. Uses
                // the same grace constant as `effective_status`.
                last_observed
                    <= *join_frame
                        + quil_types::consensus::ALLOCATION_GRACE_FRAMES
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
    /// Returns lowest-scoring active filters when total active allocs
    /// exceed total worker capacity. Manually-managed pins are
    /// protected — they're never picked as leave candidates — but
    /// they DO count toward capacity (an idle manual worker is still
    /// a worker, capable of hosting whichever filter the operator
    /// pins next).
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
        let bound_filters: std::collections::HashSet<Vec<u8>> = workers
            .iter()
            .filter(|w| !w.filter.is_empty())
            .map(|w| w.filter.clone())
            .collect();

        // Total worker capacity, NOT auto-only. The previous
        // `!w.manually_managed` filter caused phantom-surplus leaves
        // during the TUI's manual-join window — when the operator
        // flips workers to manual *before* the matching alloc lands,
        // those workers are idle (`filter.is_empty()` so absent from
        // `mm_filters`) and the surplus calc subtracted them from
        // capacity while still counting all actives, falsely
        // concluding "too many allocs, propose leave."
        let total_capacity = workers.len();

        let total_active_count = active_filters.len();

        if total_active_count <= total_capacity {
            return Vec::new();
        }
        let surplus = total_active_count - total_capacity;

        // Shed the worst-scoring allocations, bound or not.
        //
        // This used to shed orphans (Active, no worker bound) first and
        // score-blind, on the reasoning that "no worker does the work,
        // so leaving them costs nothing." It costs the difference in
        // score. Which allocations hold a worker is decided by bind
        // order in the allocator, not by value: a crashed worker, a
        // reduced core count, or a join batch that outran the idle pool
        // all leave whatever they held bound and push the rest out in
        // arrival order. `WorkerAllocator::rebind_surplus_by_priority`
        // exists to correct exactly that — it moves workers off the
        // worst-ranked bound allocations onto the best-ranked orphans —
        // and its doc comment states the contract this function is
        // meant to honour: "the surplus-leave path sheds them,
        // lowest-scoring first — the same order used here, so the
        // shards left unbound are the ones it will propose leaving."
        //
        // Shedding orphans first broke that contract, and it also raced
        // ahead of the correction: a leave marks the allocation
        // `Leaving`, and the rebind only promotes a *steady*
        // `Active`/`Paused` orphan, so once shed it can never be
        // reclaimed. The score-blind rule therefore always won.
        //
        // Observed on mainnet 2026-09-09: 27 allocations against 15
        // workers; of the 14 shed, four were on the best-paying ring the
        // node held while five bound allocations two rings down were
        // kept, and the allocator logged `no_eligible_orphan: 12 unbound
        // allocation(s), none steady Active/Paused` on every reconcile.
        //
        // Ties break toward the unbound allocation, so an equal-scoring
        // running worker is never stopped for nothing.
        //
        // Exclusion set: manually-managed pins + any shard whose
        // post-leave Active count would land at or below the halt-risk
        // threshold (`active_count <= HALT_RISK_PROVER_COUNT + 1`,
        // matching `plan_leaves` and `decide_leaves`). Shedding a shard
        // already at the threshold OR one our departure would push into
        // it would immediately worsen the network's exposure. Operators
        // dealing with chronic capacity pressure should reduce worker
        // count or add manual pins, not auto-shed halt-risk-adjacent
        // shards.
        //
        // The shield protects coverage we are actually providing, so it
        // covers bound allocations only. An allocation with no worker
        // runs nothing: it counts towards the shard's Active total
        // on-chain while contributing no proofs, so our departure costs
        // the shard no coverage it was really getting — and holding it
        // is not free either. Nothing encodes the replica or registers
        // leaf roots for the epoch, so the FrameHeader possession audit
        // evicts us from that shard anyway, and meanwhile the slot is
        // kept from a prover who could staff it. Shielding an
        // allocation we cannot staff protects a number, not a shard.
        // This also matches the pre-ranking behaviour, where orphans
        // bypassed the shield entirely. It does not make a halt-risk
        // orphan likely to be shed: few provers means a low ring, which
        // scores high, so the ranking keeps it anyway — and
        // `priority_key` gives it the top rebind tier.
        let mut excluded = mm_filters.clone();
        for d in allocated_descriptors {
            if d.size > 0
                && d.active_count <= proposer::HALT_RISK_PROVER_COUNT + 1
                && bound_filters.contains(&d.filter)
            {
                excluded.insert(d.filter.clone());
            }
        }
        let mut ranked = proposer::rank_allocated_by_score_ascending(
            allocated_descriptors,
            difficulty,
            world_bytes,
            self.units,
            self.strategy,
            &excluded,
        );
        ranked.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| bound_filters.contains(&a.0).cmp(&bound_filters.contains(&b.0)))
        });
        // A filter that's `Active` but absent from `allocated_descriptors`
        // is, in practice, a size-0 shard (build_decide_descriptors
        // skipped it). Mirroring Go's `worker_allocator.go:821-824` —
        // where `if size == 0 { continue }` lands BEFORE
        // `leaveProposalCandidates = append(...)` — we deliberately
        // do NOT pick those here. The empty-allocated path in the
        // main ProposeLeave block surfaces them.
        let mut picks: Vec<Vec<u8>> =
            ranked.into_iter().take(surplus).map(|(f, _)| f).collect();
        picks.truncate(MAX_PROPOSALS_PER_CYCLE);
        picks
    }

    /// Snapshot every lifecycle gate at once, returning a single
    /// `LifecycleReadiness` struct that branches in `evaluate` can
    /// consult uniformly. Centralizing gate logic here keeps "why
    /// didn't I propose this frame" answerable from one place — no
    /// more `Option<&'static str>` ↔ `(bool, &'static str)` jumble.
    pub fn readiness_for(&self, frame_number: u64) -> LifecycleReadiness {
        let last_attempt = self.allocator.last_join_attempt();
        let join_cooldown_ok = last_attempt == 0
            || (frame_number > last_attempt
                && frame_number - last_attempt
                    >= crate::worker_allocator::JOIN_COOLDOWN_FRAMES);
        LifecycleReadiness {
            frame_number,
            frame_seen: self.current_frame.is_ready(),
            initial_sync_complete: self.initial_sync_complete.load(Ordering::Relaxed),
            tree_verified: {
                let verified = self.prover_root_verified_frame.load(Ordering::Relaxed);
                verified > 0 && verified >= frame_number
            },
            shard_info_loaded: self.shard_info_loaded(),
            join_cooldown_ok,
            identity_known: !self.prover_address.is_empty(),
            proof_idle: !self.proof_in_progress.load(Ordering::Relaxed),
        }
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
        // Reject bogus zero-frame inputs. Mainnet genesis is frame
        // 244200, never 0; a `frame_number == 0` arriving here means
        // the caller resolved a malformed header (e.g. archive
        // returned a frame with no header or header.frame_number=0)
        // or read a cold-start `last_received_frame` that hasn't
        // been populated yet. Either way, propose-path cooldown
        // logic compares `frame_number <= last_join_attempt` and a
        // zero input shifts the comparison into "always cooldown
        // active," silently blocking every join proposal. Bail
        // before doing any work.
        if frame_number == 0 {
            tracing::debug!(
                "skipping lifecycle evaluation — frame_number is 0 (degenerate input)"
            );
            return Ok(Vec::new());
        }

        // `CurrentFrame` is advanced upstream by the BlossomSub
        // recv path / archive poller / materializer — every
        // reachable production caller of `evaluate` has already
        // observed `frame_number`. Tests seed `current_frame`
        // explicitly in their lifecycle constructor.

        // Take a single snapshot of every gate up-front and consult
        // it via the readiness helpers below. This collapses what
        // used to be 3+ independent atomic reads scattered through
        // the function into one consistent view per call.
        let readiness = self.readiness_for(frame_number);
        if let Err(reason) = readiness.baseline_ready() {
            tracing::debug!(
                frame = frame_number,
                reason,
                "skipping lifecycle evaluation — baseline gate"
            );
            return Ok(Vec::new());
        }

        // Gather inputs
        let summaries = registry.get_prover_shard_summaries(frame_number)?;
        let prover_info = registry.get_prover_info(&self.prover_address)?;
        let workers = worker_manager.range_workers()?;
        let worker_view = WorkerView::from_workers(workers.clone());

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
                        // Canonical prefix → filter (sentinel-aware).
                        quil_forest::shard_prefix_to_filter(&s.shard_key[l2_start..], &s.prefix)
                    })
                    .filter(|f| !f.is_empty())
                    .collect(),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        // Shards that topology changes this node has recorded but not applied
        // yet will create: merge targets and split children. The synced
        // registry shows the moved allocations a few frames before the local
        // grid flips, while the grid and the archive sizes still name the old
        // shards.
        let arriving_shards: std::collections::HashSet<Vec<u8>> = self
            .shards_store
            .read()
            .ok()
            .and_then(|g| g.clone())
            .and_then(|ss| ss.all_pending_shard_changes().ok())
            .unwrap_or_default()
            .into_iter()
            .flat_map(|change| match change.kind {
                quil_types::store::ShardChangeKind::Merge => vec![change.parent],
                quil_types::store::ShardChangeKind::Split => change.children,
            })
            .collect();

        // Joining / Leaving allocations past the 720-frame grace are
        // implicitly rejected on-chain. The buckets helper filters
        // them out — see `AllocationBuckets::from_allocations`.
        let buckets = prover_info
            .as_ref()
            .map(|p| AllocationBuckets::from_allocations(&p.allocations, frame_number))
            .unwrap_or_default();
        let joining_filters = buckets.joining;
        let active_filters = buckets.active;
        let leaving_filters = buckets.leaving;
        let all_our_filters = buckets.all_ours;
        // Cloned because the re-confirm path below consumes the original and
        // the orphan-leave sweep needs it again: an ExpiredEpoch allocation is
        // still on-chain Active, so it is a valid Leave target when nothing is
        // working it.
        let expired_epoch_filters = buckets.expired_epoch;
        tracing::info!(
            frame = frame_number,
            epoch = quil_types::consensus::epoch_for_frame(frame_number),
            have_prover_info = prover_info.is_some(),
            allocations = prover_info.as_ref().map(|p| p.allocations.len()).unwrap_or(0),
            joining = joining_filters.len(),
            active = active_filters.len(),
            leaving = leaving_filters.len(),
            expired_epoch = expired_epoch_filters.len(),
            allocation_epochs = ?prover_info.as_ref().map(|p| p.allocations.iter()
                .map(|a| (a.epoch, a.status, a.confirmation_filter.len())).collect::<Vec<_>>()),
            "lifecycle allocation buckets"
        );
        // A rejected leave may be epoch-expired until its renewal round-trip
        // completes. Do not turn that recoverable transition into another leave,
        // even if reconcile has not restored the worker yet. Bound the grace by
        // the rejection epoch; genuinely abandoned allocations remain sweepable.
        let recovery_filters: std::collections::HashSet<Vec<u8>> = prover_info
            .as_ref()
            .map(|p| p.allocations.iter()
                .filter(|a| crate::worker_allocator::rejected_leave_recovery_pending(a, frame_number))
                .map(|a| a.confirmation_filter.clone()).collect())
            .unwrap_or_default();
        let expired_epoch_for_orphan_sweep: Vec<Vec<u8>> = expired_epoch_filters.iter()
            .filter(|f| !recovery_filters.contains(*f)).cloned().collect();

        // Build separate descriptor views.
        //
        // - `proposal_descriptors`: shards *we are not on* scored with the
        //   joiner ring (predicted ring after we join). Used for
        //   ProposeJoin + as the base for the decide_candidates set.
        // - `decide_all_descriptors`: every shard scored with its current
        //   ring — used only to splice in pending-to-decide entries.
        // - `allocated_descriptors`: shards we are *Active* on, scored
        //   with the current ring — used for plan_leaves. Joining
        //   shards must NOT be in here: plan_leaves treats them as
        //   real allocations and may pick the just-joined shard as
        //   the worst-scoring one to shed, immediately proposing
        //   Leave for it. Observed in the wild as: ProposeJoin
        //   accepted by archive → status flips Rejected→Joining in
        //   local registry → next evaluate() cycle plan_leaves picks
        //   the same filter to leave → archive eventually rejects
        //   the unconfirmed Joining → operator-visible symptom is
        //   "joins never confirm."
        // Merged view: remote sizes (authoritative for shards we're
        // not on) overlaid by local sizes (authoritative for shards
        // we hold data for). See `merged_shard_sizes` for the rule.
        let shard_metrics = self.merged_shard_metrics();
        let shard_sizes_snapshot: HashMap<Vec<u8>, u64> = shard_metrics.iter()
            .map(|(f, (bytes, _))| (f.clone(), *bytes)).collect();
        // Live allocations on a filter an archive refresh has already come
        // back without, and that neither the local grid nor a recorded change
        // names, are left on a retired shard (a legacy merge moves only
        // committee members). They neither make the filter a shard nor its
        // ancestors split parents, and our own are left.
        let retired: std::collections::HashSet<Vec<u8>> = self
            .settled_unsized_shards
            .read()
            .map(|settled| {
                settled
                    .iter()
                    .filter(|f| !shards_store_filters.contains(*f) && !arriving_shards.contains(*f))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let current_summaries: Vec<ProverShardSummary> =
            summaries.iter().filter(|s| !retired.contains(&s.filter)).cloned().collect();
        let known_shards = known_shard_filters(&current_summaries, &shard_sizes_snapshot, &shards_store_filters);
        let remote_shards: std::collections::HashSet<Vec<u8>> = match self.remote_shard_sizes.read() {
            Ok(remote) => {
                if let Ok(mut lacking) = self.unsized_live_shards.write() {
                    *lacking = unsized_live_filters(&summaries, &remote);
                }
                remote.keys().cloned().collect()
            }
            Err(_) => std::collections::HashSet::new(),
        };
        // Live shards the sizes lack, awaiting the refresh they asked for.
        let awaiting_refresh: std::collections::HashSet<Vec<u8>> =
            match (self.unsized_live_shards.read(), self.settled_unsized_shards.read()) {
                (Ok(lacking), Ok(settled)) => lacking.difference(&settled).cloned().collect(),
                _ => std::collections::HashSet::new(),
            };
        // A leave cannot be undone, so proposing one off a split-away parent,
        // or confirming one regardless of score, needs every view to agree
        // the parent is split away.
        let settled_split_away = |filter: &Vec<u8>| {
            !awaiting_refresh.contains(filter)
                && is_settled_split_parent(filter, &known_shards, &shards_store_filters, &remote_shards, &arriving_shards)
        };
        let mut proposal_descriptors = build_proposal_descriptors(
            &current_summaries,
            &all_our_filters,
            &shard_sizes_snapshot,
            &shards_store_filters,
        );
        // Recently-rejected join backoff: drop any shard that rejected our
        // join within the last `JOIN_REJECT_BACKOFF_FRAMES`. A Rejected
        // allocation is terminal so it's excluded from `all_our_filters`
        // and would otherwise reappear as a join candidate immediately —
        // producing the Joining↔Rejected oscillation that saturates
        // workers with never-confirming pending joins. Backing it off
        // steers the proposer to other (less contested) unallocated
        // shards. Also keeps these out of the plan_leaves comparison set
        // (they're not realistically available to us right now).
        let reject_backoff: std::collections::HashSet<Vec<u8>> = prover_info
            .as_ref()
            .map(|p| {
                p.allocations
                    .iter()
                    .filter(|a| {
                        a.status == ProverStatus::Rejected
                            && a.join_reject_frame_number > 0
                            && frame_number
                                < a.join_reject_frame_number
                                    .saturating_add(JOIN_REJECT_BACKOFF_FRAMES)
                    })
                    .map(|a| a.confirmation_filter.clone())
                    .collect()
            })
            .unwrap_or_default();
        if !reject_backoff.is_empty() {
            proposal_descriptors.retain(|d| !reject_backoff.contains(&d.filter));
        }
        // A shard a pending split or merge has frozen: the chain refuses the
        // whole join if it names one, taking the other shards with it.
        if let Ok(frozen) = self.frozen_shards.read() {
            if !frozen.is_empty() {
                proposal_descriptors.retain(|d| !frozen.contains(&d.filter));
            }
        }
        for descriptor in &mut proposal_descriptors {
            descriptor.shards = shard_metrics[&descriptor.filter].1;
        }
        // Missing reward metadata cannot establish a profitable destination.
        proposal_descriptors.retain(|d| self.strategy != Strategy::RewardGreedy || d.shards > 0);
        let mut decide_all_descriptors =
            build_decide_descriptors(&summaries, &shard_sizes_snapshot);
        for descriptor in &mut decide_all_descriptors {
            descriptor.shards = shard_metrics[&descriptor.filter].1;
        }
        // Leave economics use the allocation's confirmed reward ring, as the
        // reward calculator does, rather than the last member's ring. Keep the
        // generic descriptors for join confirmation policy.
        let mut held_descriptors = decide_all_descriptors.clone();
        if let Some(prover) = &prover_info {
            for descriptor in &mut held_descriptors {
                if let Some(allocation) = prover.allocations.iter()
                    .find(|a| a.confirmation_filter == descriptor.filter && a.is_live(frame_number))
                {
                    descriptor.ring = allocation.ring;
                }
            }
        }
        let allocated_descriptors: Vec<ShardDescriptor> = held_descriptors.iter()
            .filter(|d| active_filters.contains(&d.filter)
                && (self.strategy != Strategy::RewardGreedy || d.shards > 0))
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
        let free_worker_ids: Vec<u32> = worker_view.free_auto().map(|w| w.core_id).collect();

        // ...but "free" is a statement about the worker, not about the
        // slot. `free_auto` reads worker state only, so it cannot see a
        // slot already owed to an allocation we hold that nothing has
        // bound yet. After a restart every worker starts with an empty
        // filter while the registry still holds every allocation from
        // before, and those filters are only installed when the
        // allocator's reconcile next runs. A join cycle that clears its
        // readiness gates first sees a fully idle fleet, proposes a
        // second full set of joins on top of the set we already own,
        // and the reconcile then has nowhere to put the surplus.
        //
        // Observed on mainnet 2026-09-09: the first cycle to clear the
        // gates after a restart logged `free_workers=15
        // total_workers=15` while the prover held 13 Active
        // allocations, proposed a 14-filter join, and 14 seconds later
        // the allocator reported `orphan_count=35`. Twelve of those
        // allocations never received a worker and were shed at the next
        // epoch boundary — four of them on the best-paying ring the
        // node held.
        //
        // `JOIN_FILTER_COOLDOWN_FRAMES` does not cover this: it guards
        // against the *same* filter being proposed by overlapping
        // cycles, and here a single cycle proposed fourteen filters it
        // had never proposed before.
        //
        // Leaving allocations are excluded — they are departing and
        // will not claim a slot. Everything else in `all_ours` will.
        let worker_bound_filters: std::collections::HashSet<Vec<u8>> =
            worker_view.filter_set().map(|w| w.filter.clone()).collect();
        let departing_filters: std::collections::HashSet<&Vec<u8>> =
            leaving_filters.iter().map(|(f, _)| f).collect();
        let unbound_held_count = all_our_filters
            .iter()
            .filter(|f| !departing_filters.contains(f))
            .filter(|f| !worker_bound_filters.contains(*f))
            .count();
        let assignable_worker_ids: Vec<u32> = free_worker_ids
            .iter()
            .copied()
            .take(free_worker_ids.len().saturating_sub(unbound_held_count))
            .collect();
        let allow_proposals = !assignable_worker_ids.is_empty();

        // Go's canPropose (cooldown + readiness + halt). The
        // readiness snapshot was captured at the top of evaluate;
        // both propose paths see the same decision.
        let propose_check = readiness.propose_ready();
        let can_propose = propose_check.is_ok();
        let skip_reason = propose_check.err().unwrap_or("");

        // Remote `GetAppShards` gate. Auto-pick decisions (join,
        // surplus-leave, score-leave) require shard size data sourced
        // from an archive — local registry summaries and the local
        // shards-store are NOT authoritative for this purpose. Until
        // we've consumed at least one successful `GetAppShards`
        // refresh, all auto-pick paths short-circuit. Confirm/leave-
        // confirm and seniority-merge paths run regardless since
        // they depend on local pending state, not shard sizes.
        let shard_info_ready = readiness.shard_info_loaded;
        if shard_info_ready {
            // Publish this frame's ranking for the worker allocator.
            // Scoring needs archive-sourced sizes, the world-byte
            // total and the frame difficulty, none of which the
            // allocator can reach — and its reconcile also runs from
            // the archive poller and the frame-receive path, outside
            // this function. Without the snapshot it binds workers in
            // registry order, which decides arbitrarily which shards
            // go unbound when we hold more allocations than workers.
            let halt_risk_by_filter: HashMap<Vec<u8>, bool> = decide_all_descriptors
                .iter()
                .map(|d| {
                    (
                        d.filter.clone(),
                        d.size > 0 && d.active_count <= proposer::HALT_RISK_PROVER_COUNT,
                    )
                })
                .collect();
            let priority_entries: Vec<(Vec<u8>, bool, BigInt)> =
                proposer::rank_allocated_by_score_ascending(
                    &decide_all_descriptors,
                    difficulty,
                    &world_bytes,
                    self.units,
                    self.strategy,
                    &std::collections::HashSet::new(),
                )
                .into_iter()
                .map(|(filter, score)| {
                    let halt_risk =
                        halt_risk_by_filter.get(&filter).copied().unwrap_or(false);
                    (filter, halt_risk, score)
                })
                .collect();
            self.allocator
                .publish_allocation_priority(frame_number, priority_entries);
        }
        if !shard_info_ready {
            tracing::debug!(
                frame = frame_number,
                "deferring auto-allocation: no remote GetAppShards data yet"
            );
        }

        let mut actions: Vec<LifecycleAction> = Vec::new();
        let mut join_proposed_this_cycle = false;

        // PoRep epoch rotation: any Active allocation whose recorded storage
        // epoch is not registered ahead must confirm leaf roots for the next
        // epoch — otherwise the global storage audit evicts it. Gate behind the
        // per-filter cooldown so the confirm isn't re-published every frame
        // while the round-trip is in flight. This runs regardless of coverage
        // halts: a prover maintaining its own storage commitment is never the
        // cause of a halt and must not be evicted for one.
        if !expired_epoch_filters.is_empty() {
            // The pipeline reserves filters before spawning and records cooldown
            // only after publication; failed preparation is retried promptly.
            actions.push(LifecycleAction::ReconfirmEpoch {
                filters: expired_epoch_filters,
                frame_number,
            });
        }

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
                let reject_summary: Vec<String> = filters
                    .iter()
                    .map(hex::encode)
                    .collect();
                let allowed = workers.len().saturating_sub(active_filters.len());
                info!(
                    frame = frame_number,
                    active_count = active_filters.len(),
                    pending_count = joining_filters.len(),
                    worker_capacity = workers.len(),
                    allowed_pending = allowed,
                    rejections = filters.len(),
                    ?reject_summary,
                    reason = "pending join count exceeds remaining worker capacity",
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
        if shard_info_ready && !active_filters.is_empty() && !join_proposed_this_cycle {
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
                    let mm_count = workers
                        .iter()
                        .filter(|w| w.manually_managed && !w.filter.is_empty())
                        .count();
                    let leave_summary: Vec<String> = surplus
                        .iter()
                        .map(hex::encode)
                        .collect();
                    info!(
                        frame = frame_number,
                        active_count = active_filters.len(),
                        worker_capacity = workers.len(),
                        manually_managed_pinned = mm_count,
                        surplus = surplus.len(),
                        ?leave_summary,
                        reason = "capacity reduction (active count exceeds worker count)",
                        "proposing leaves for surplus actives"
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
        if shard_info_ready && !proposal_descriptors.is_empty() && allow_proposals {
            // Operator-visibility pass: the proposer only sees what
            // ends up in `proposal_descriptors`. Halt-risk shards we
            // are already on (skipped in `build_proposal_descriptors`
            // because `our_filters` matches) or shards with no size
            // data both look identical to "not picked" downstream.
            // This log makes the candidate-side picture explicit so a
            // missing prioritization can be traced to the right
            // cause: candidate filtering vs. picker output.
            let proposal_halt_risk = proposal_descriptors
                .iter()
                .filter(|d| d.size > 0
                    && d.active_count <= proposer::HALT_RISK_PROVER_COUNT)
                .count();
            let our_halt_risk = summaries
                .iter()
                .filter(|s| {
                    if !all_our_filters.contains(&s.filter) { return false; }
                    let raw_size = shard_sizes_snapshot.get(&s.filter).copied().unwrap_or(0);
                    if raw_size == 0 { return false; }
                    let active = s.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0);
                    active as u64 <= proposer::HALT_RISK_PROVER_COUNT
                })
                .count();
            let no_size_count = summaries
                .iter()
                .filter(|s| !s.filter.is_empty()
                    && !all_our_filters.contains(&s.filter)
                    && shard_sizes_snapshot.get(&s.filter).copied().unwrap_or(0) == 0)
                .count();
            // Registry-health signals. `summaries_count == 0` together
            // with a non-zero `candidates` is the smoking gun for an
            // empty/clobbered prover registry: every descriptor in
            // that case came from `build_proposal_descriptors`'
            // shards-store fallback (loop 2) which writes
            // `total_active_joining: 0` — so the proposer treats every
            // shard as halt-risk-eligible. `phantom_descriptors` is
            // the count of descriptors carrying that
            // shards-store-only `total_active_joining == 0` marker.
            let summaries_count = summaries.len();
            let phantom_descriptors = proposal_descriptors
                .iter()
                .filter(|d| d.total_active_joining == 0)
                .count();
            info!(
                frame = frame_number,
                free_workers = free_worker_ids.len(),
                assignable_workers = assignable_worker_ids.len(),
                unbound_held = unbound_held_count,
                total_workers = workers.len(),
                candidates = proposal_descriptors.len(),
                halt_risk_among_candidates = proposal_halt_risk,
                halt_risk_among_our_shards = our_halt_risk,
                summaries_skipped_no_size = no_size_count,
                summaries_count,
                phantom_descriptors,
                can_propose,
                skip_reason,
                strategy = ?self.strategy,
                "auto-allocation candidate snapshot"
            );

            if can_propose {
                // Per-filter Join cooldown: exclude any filter we've
                // already proposed Join for within the last
                // `JOIN_FILTER_COOLDOWN_FRAMES`. Closes the orphan-
                // Joining gap where the worker-level
                // `PROPOSAL_TIMEOUT_FRAMES` (10) frees a worker for
                // re-use after 10 frames but the prior bundle is still
                // in flight on the wire — both eventually land, and
                // the registry ends up with more Joining allocs than
                // worker slots. See `JOIN_FILTER_COOLDOWN_FRAMES`
                // docstring for the production trace.
                let inflight_filters = self.filters_with_inflight_join(frame_number);
                let pre_cooldown_candidates = proposal_descriptors.len();
                let proposal_descriptors_filtered: Vec<proposer::ShardDescriptor> =
                    proposal_descriptors
                        .iter()
                        .filter(|d| !inflight_filters.contains(&d.filter))
                        .cloned()
                        .collect();
                let join_cooldown_suppressed =
                    pre_cooldown_candidates.saturating_sub(proposal_descriptors_filtered.len());

                let proposals = proposer::plan_and_allocate(
                    &proposal_descriptors_filtered,
                    difficulty,
                    &world_bytes,
                    self.units,
                    &assignable_worker_ids,
                    MAX_PROPOSALS_PER_CYCLE,
                    self.strategy,
                    Some(&self.prover_address),
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

                    // Stamp the per-filter Join cooldown before
                    // emitting the action so the next cycle sees
                    // these filters as in-flight and excludes them.
                    self.record_join_filter_attempts(&filters, frame_number);

                    info!(
                        filters = filters.len(),
                        frame = frame_number,
                        prev_join_attempt = prev_attempt,
                        cooldown_frames = crate::worker_allocator::JOIN_COOLDOWN_FRAMES,
                        join_cooldown_suppressed,
                        strategy = ?self.strategy,
                        "proposing join for shards"
                    );

                    actions.push(LifecycleAction::ProposeJoin {
                        filters,
                        worker_ids,
                        frame_number,
                    });
                } else if join_cooldown_suppressed > 0 {
                    tracing::debug!(
                        frame = frame_number,
                        join_cooldown_suppressed,
                        "no join candidates after applying per-filter cooldown",
                    );
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
        //
        // Bucketed by mode: filters bound to manually_managed workers
        // are confirmed at window-maturity regardless of score; if
        // there are more manual-bound pending allocs than available
        // workers, the excess is rejected on capacity grounds only
        // (no score-based reject). Filters bound to auto workers or
        // currently unbound flow through the existing score-driven
        // `decide_joins` against the remaining capacity.
        // Epoch-aligned: a join proposed in epoch E is confirmed in EXACTLY
        // epoch E+1 (the chain rejects confirms outside that slot). We emit the
        // confirm anywhere within E+1; dedup/cooldown handles repeats.
        let cur_epoch = quil_types::consensus::epoch_for_frame(frame_number);
        let ready_join_filters: Vec<Vec<u8>> = joining_filters.iter()
            .filter(|(_, jf)| cur_epoch == quil_types::consensus::epoch_for_frame(*jf) + 1)
            .map(|(f, _)| f.clone())
            .collect();

        if !ready_join_filters.is_empty() {
            // A pending join on a shard that has since split, or has retired,
            // is rejected: the chain no longer confirms it, and it holds a
            // worker until it lapses.
            let (split_away, ready_join_filters): (Vec<Vec<u8>>, Vec<Vec<u8>>) = ready_join_filters
                .into_iter()
                .partition(|f| is_split_parent(f, &known_shards) || retired.contains(f));
            let manual_bound_filters: std::collections::HashSet<Vec<u8>> = workers
                .iter()
                .filter(|w| w.manually_managed && !w.filter.is_empty())
                .map(|w| w.filter.clone())
                .collect();

            let (manual_ready, auto_ready): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
                ready_join_filters
                    .iter()
                    .cloned()
                    .partition(|f| manual_bound_filters.contains(f));

            // Cap confirmations at unallocated worker count
            // (Go `proposer.go:518-531`). `unallocatedWorkerCount` =
            // count(workers where !allocated). Mirrors Go's gate so a
            // node with more pending confirms than free workers doesn't
            // commit to allocations it can't service.
            let available_workers = workers.iter().filter(|w| !w.allocated).count();

            // Manual bucket: confirm up to capacity, reject excess
            // (capacity-only, deterministic lexicographic order so
            // ties resolve identically across nodes).
            let (manual_confirm, manual_reject): (Vec<Vec<u8>>, Vec<Vec<u8>>) = {
                let mut sorted = manual_ready;
                sorted.sort();
                if sorted.len() <= available_workers {
                    (sorted, Vec::new())
                } else {
                    let confirms: Vec<Vec<u8>> = sorted
                        .iter()
                        .take(available_workers)
                        .cloned()
                        .collect();
                    let rejects: Vec<Vec<u8>> = sorted
                        .into_iter()
                        .skip(available_workers)
                        .collect();
                    (confirms, rejects)
                }
            };

            // Auto bucket: existing score-driven decide_joins with
            // capacity reduced by manual confirms already committed.
            let auto_capacity = available_workers.saturating_sub(manual_confirm.len());
            let mut decide_candidates = proposal_descriptors.clone();
            let pending_set: std::collections::HashSet<Vec<u8>> =
                auto_ready.iter().cloned().collect();
            for d in &decide_all_descriptors {
                if pending_set.contains(&d.filter) {
                    decide_candidates.push(d.clone());
                }
            }
            let (auto_reject, auto_confirm) = proposer::decide_joins(
                &decide_candidates,
                &auto_ready,
                difficulty,
                &world_bytes,
                self.units,
                self.strategy,
                auto_capacity,
            );

            let mut combined_reject = split_away;
            combined_reject.extend(manual_reject);
            combined_reject.extend(auto_reject);
            let mut combined_confirm = manual_confirm;
            combined_confirm.extend(auto_confirm);

            // Per-message cap: each LifecycleAction maps 1:1 to a
            // submitted canonical-bytes message, which is single-type
            // (ConfirmJoins or RejectJoins) and capped at 100
            // filters. Manual entries are placed first so they
            // survive truncation; truncated filters stay Joining and
            // re-enter the decision on the next frame.
            if combined_reject.len() > MAX_PROPOSALS_PER_CYCLE {
                combined_reject.truncate(MAX_PROPOSALS_PER_CYCLE);
            }
            if combined_confirm.len() > MAX_PROPOSALS_PER_CYCLE {
                combined_confirm.truncate(MAX_PROPOSALS_PER_CYCLE);
            }

            if !combined_reject.is_empty() {
                actions.push(LifecycleAction::RejectJoins {
                    filters: combined_reject,
                    frame_number,
                });
            }
            if !combined_confirm.is_empty() {
                actions.push(LifecycleAction::ConfirmJoins {
                    filters: combined_confirm,
                    frame_number,
                });
            }
        }

        // A worker or recent submission already reserves its destination even
        // before the allocation appears in the registry. It cannot fund a leave.
        let inflight = self.filters_with_inflight_join(frame_number);
        let available_replacements: Vec<ShardDescriptor> = proposal_descriptors.iter()
            .filter(|d| !inflight.contains(&d.filter)
                && !workers.iter().any(|w| w.filter == d.filter))
            .cloned().collect();

        // 3) ProposeLeave — score-driven (Go-aligned, mirrors
        //    worker_allocator.go:299-316) plus empty-allocated leaves
        //    (intentionally divergent from Go). The divergent branch
        //    frees workers that ended up on shards with zero data:
        //    Go's worker_allocator.go:821-824 and proposer.go:333 both
        //    `continue` on `size == 0`, so neither plan_leaves nor the
        //    surplus-active path can ever surface an empty allocated
        //    shard as a leave candidate. The worker sits stuck until
        //    network coverage-halt eviction (slow) or operator action.
        //    Surfacing empty allocated filters directly here is safe
        //    because `decide_leaves` auto-confirms any pending leave
        //    whose filter isn't in the scored list — and size==0
        //    shards aren't, by the same rule.
        // Do NOT propose leaves while in degraded-coverage / prover-only
        // mode: coverage data is stale/unreliable there, so the halt-risk
        // counts that drive `plan_leaves` (and its swap path) are false
        // positives. A node stuck in prover-only mode was observed
        // proposing swap leaves against a phantom halt-risk shard for
        // hours. Halt-risk swaps are still wanted — but only
        // off a trustworthy coverage view, i.e. when not halted.
        // `expired_epoch` counts toward "we hold something worth evaluating"
        // alongside `active`: a prover whose every allocation went ExpiredEpoch
        // (all of them orphaned, e.g. after losing its workers) would otherwise
        // skip the leave sweep entirely and never shed anything.
        if shard_info_ready
            && can_propose
            && !join_proposed_this_cycle
            && !(active_filters.is_empty() && expired_epoch_for_orphan_sweep.is_empty())
            && !self.halt_state.any_halted()
        {
            let manually_managed_filters: std::collections::HashSet<Vec<u8>> = workers
                .iter()
                .filter(|w| w.manually_managed && !w.filter.is_empty())
                .map(|w| w.filter.clone())
                .collect();
            let pending_leave_filters: std::collections::HashSet<Vec<u8>> = leaving_filters
                .iter()
                .map(|(f, _)| f.clone())
                .collect();
            // Filters that any worker is currently bound to (pending
            // joins included, since `worker.filter` is set at submit
            // time before the alloc activates). An Active filter NOT
            // in this set is an orphan — the prover still owns the
            // allocation but nothing is doing the work. Used only to
            // break score ties below; being an orphan is no longer by
            // itself a reason to leave.
            let bound_filters: std::collections::HashSet<Vec<u8>> = workers
                .iter()
                .filter(|w| !w.filter.is_empty())
                .map(|w| w.filter.clone())
                .collect();

            // Empty-allocated filters: `Some(0)` means the size map has
            // a real "shard is empty" data point, distinct from `None`
            // (no data yet → decision deferred). Exclude operator-
            // pinned filters and filters already mid-Leave.
            let empty_allocated_filters: Vec<Vec<u8>> = active_filters
                .iter()
                .filter(|f| !manually_managed_filters.contains(*f))
                .filter(|f| !pending_leave_filters.contains(*f))
                .filter(|f| matches!(shard_sizes_snapshot.get(*f), Some(0)))
                .cloned()
                .collect();

            // Unrecoverable orphans: on-chain allocations with no worker
            // bound that nothing can ever staff. Always propose leave
            // regardless of shard score — there is no useful work to
            // retain and no path back.
            //
            // ExpiredEpoch allocations MUST be candidates here, not just
            // `active` ones. Being orphaned is precisely what makes an
            // allocation expire: no worker means no proofs, so it misses the
            // per-epoch re-confirm at the next boundary and drops out of
            // `active`. Sweeping only `active` therefore gave the orphan path a
            // one-epoch window and no way back — an orphan that survived a
            // single boundary became permanently unsheddable, which is how a
            // node ends up holding far more allocations than it has workers with
            // no automatic way out. Observed in the wild: 35 allocations against
            // 15 workers, the 20 unbound ones all reading `re-confirm!`, and
            // zero Leave proposals for as long as they stayed that way.
            //
            // They stay OUT of `active` itself — that set is coverage
            // accounting, and an unconfirmed allocation genuinely does not
            // count. This only widens who may be shed.
            //
            // Ranking cannot rescue these, which is why they stay a
            // score-blind sweep while Active orphans do not:
            // `rebind_surplus_by_priority` promotes only a *steady*
            // `Active`/`Paused` orphan, so an ExpiredEpoch one can
            // neither be staffed nor score its way back into
            // contention. Retaining a high-scoring one would rebuild
            // the same deadlock this sweep exists to break. An Active
            // orphan is recoverable, so it is ranked with everything
            // else below instead of being shed on sight.
            let unrecoverable_orphan_filters = orphaned_allocation_filters(
                &[],
                &expired_epoch_for_orphan_sweep,
                &bound_filters,
                &manually_managed_filters,
                &pending_leave_filters,
            );
            // Over-capacity filters: allocations this prover cannot
            // staff, worst-scoring first.
            //
            // This used to be "every Active allocation with no worker
            // bound, leave it regardless of score." But which
            // allocations hold a worker is decided by bind order in the
            // allocator, not by score — a worker lost to a crash, a
            // reduced core count, or a join batch that outran the idle
            // pool all leave whatever they held bound and push the rest
            // out in arrival order. `rebind_surplus_by_priority` exists
            // to correct exactly that: it moves workers off the
            // worst-ranked bound allocations onto the best-ranked
            // orphans. It only promotes an orphan that is still
            // *steady* `Active`/`Paused`, so proposing Leave the moment
            // an allocation is unbound marks it `Leaving` and makes it
            // permanently ineligible — the score-blind rule wins the
            // race against the score-aware one, and the shed set ends
            // up decided by bind order after all.
            //
            // Observed on mainnet 2026-09-09: of 27 allocations against
            // 15 workers, the 14 shed included four on the best ring
            // the node held while five bound allocations two rings down
            // were kept, and the allocator logged `no_eligible_orphan:
            // 12 unbound allocation(s), none steady Active/Paused` on
            // every reconcile for hours.
            //
            // So shed by rank instead: only the count we cannot staff,
            // taken worst-scoring first across the whole held set,
            // bound or not. That is the same ordering the rebind path
            // uses, which restores the invariant its doc comment
            // already claims — "the shards left unbound are the ones it
            // will propose leaving." Ties break toward the unbound one
            // so an equal-scoring running worker is not stopped for
            // nothing. With no over-capacity nothing is shed: an orphan
            // that fits within worker capacity gets a worker on the
            // next reconcile, and leaving it would throw away a live
            // allocation to fix a transient. That still covers the
            // original "extra allocation lingers, shows as -1 in the
            // TUI" case — with slack it is bound, without slack it is
            // shed if it really is among the worst.
            let sheddable_filters: Vec<Vec<u8>> = active_filters
                .iter()
                .filter(|f| !manually_managed_filters.contains(*f))
                .filter(|f| !pending_leave_filters.contains(*f))
                .cloned()
                .collect();
            // Capacity for auto-managed allocations is the worker count
            // less the operator's pins, matching the set above.
            let auto_worker_capacity = workers.iter().filter(|w| !w.manually_managed).count();
            let overcapacity = sheddable_filters.len().saturating_sub(auto_worker_capacity);
            let overcapacity_filters: Vec<Vec<u8>> = if overcapacity == 0 {
                Vec::new()
            } else {
                let sheddable: std::collections::HashSet<&Vec<u8>> =
                    sheddable_filters.iter().collect();
                // Excluded from the ranking: anything not sheddable, and
                // the halt-risk shield from `plan_leaves` — `active_count`
                // includes us, so a shard at or below
                // `HALT_RISK_PROVER_COUNT + 1` drops into halt risk the
                // moment we go. As in `select_excess_active_filters`, the
                // shield covers bound allocations only: an unbound one
                // contributes no proofs, so our leaving costs the shard
                // no coverage it was really getting, and holding it only
                // waits for the possession audit to evict us.
                let excluded: std::collections::HashSet<Vec<u8>> = allocated_descriptors
                    .iter()
                    .filter(|d| {
                        !sheddable.contains(&d.filter)
                            || (d.size > 0
                                && d.active_count <= proposer::HALT_RISK_PROVER_COUNT + 1
                                && bound_filters.contains(&d.filter))
                    })
                    .map(|d| d.filter.clone())
                    .collect();
                let mut ranked = proposer::rank_allocated_by_score_ascending(
                    &allocated_descriptors,
                    difficulty,
                    &world_bytes,
                    self.units,
                    self.strategy,
                    &excluded,
                );
                ranked.sort_by(|a, b| {
                    a.1.cmp(&b.1).then_with(|| {
                        bound_filters
                            .contains(&a.0)
                            .cmp(&bound_filters.contains(&b.0))
                    })
                });
                ranked.into_iter().take(overcapacity).map(|(f, _)| f).collect()
            };

            // SPLIT-PARENT filters — an Active filter that has been
            // SPLIT, i.e. some registered shard is a strict bit-path DESCENDANT of
            // it. A deep split REMOVES the parent, so its shard no longer exists and
            // the worker is stuck on a phantom (the E+2 reassignment that should
            // have moved it does not survive re-materialization — see #127).
            // Propose leave so `decide_joins` re-covers a real child via ProverJoin
            // (canonical, persists). Detected purely from the shard-filter set, so
            // it does not depend on the reassignment landing. A leaf has no
            // descendants → not flagged → stable, no churn.
            let split_parent_filters: Vec<Vec<u8>> = active_filters
                .iter()
                .filter(|f| !manually_managed_filters.contains(*f))
                .filter(|f| !pending_leave_filters.contains(*f))
                .filter(|f| settled_split_away(f))
                .cloned()
                .collect();
            // Active allocations on a retired shard: the chain credits none
            // of its frames, and the worker can cover a real shard.
            let retired_filters: Vec<Vec<u8>> = active_filters
                .iter()
                .filter(|f| !manually_managed_filters.contains(*f))
                .filter(|f| !pending_leave_filters.contains(*f))
                .filter(|f| retired.contains(*f))
                .cloned()
                .collect();

            // Min-hold dwell: allocations confirmed within the last
            // `SCORE_LEAVE_MIN_HOLD_FRAMES` are exempt from pure-score
            // leaves so a freshly-established, producing holding isn't
            // churned to chase a marginally-better unallocated shard.
            // (Halt-risk swap, empty, and orphan leaves ignore this.)
            let min_hold_filters: std::collections::HashSet<Vec<u8>> = prover_info
                .as_ref()
                .map(|p| {
                    p.allocations
                        .iter()
                        .filter(|a| {
                            a.join_confirm_frame_number > 0
                                && frame_number
                                    < a.join_confirm_frame_number
                                        .saturating_add(SCORE_LEAVE_MIN_HOLD_FRAMES)
                        })
                        .map(|a| a.confirmation_filter.clone())
                        .collect()
                })
                .unwrap_or_default();

            // Score-driven candidates — only meaningful when there are
            // unallocated alternatives to compare against.
            // A halt-risk swap sheds only an allocation whose shard would
            // release this node; see `proposer::releasable_member`.
            let releasable = |filter: &[u8]| {
                let mut members = Vec::new();
                for status in [ProverStatus::Active, ProverStatus::Leaving] {
                    if let Ok(provers) = registry.get_provers_by_status(filter, status) {
                        members.extend(provers.into_iter().map(|p| p.address));
                    }
                }
                proposer::releasable_member(&self.prover_address, filter, &members)
            };
            // The pending-confirm bucket excludes confirmed leaves serving
            // notice, so inspect effective allocation status instead. This
            // only gates discretionary replacements; cleanup and confirmation
            // below retain their own eligibility and security checks.
            let replacement_pending = self.replacement_leave_pending(
                prover_info.as_ref(), &workers, frame_number,
            );
            if replacement_pending && !proposal_descriptors.is_empty() {
                info!(frame = frame_number,
                    "replacement leaves deferred until pending departures release their workers");
            }
            let replacement_descriptors = if replacement_pending {
                &[][..]
            } else {
                available_replacements.as_slice()
            };
            let score_candidates: Vec<Vec<u8>> = if !proposal_descriptors.is_empty() {
                proposer::plan_leaves_releasing_spread(
                    &allocated_descriptors,
                    replacement_descriptors,
                    difficulty,
                    &world_bytes,
                    self.units,
                    self.strategy,
                    assignable_worker_ids.len(),
                    &min_hold_filters,
                    &releasable,
                    Some(&self.prover_address),
                )
            } else {
                Vec::new()
            };
            let score_driven_count = score_candidates.len();

            let mut leave_candidates = score_candidates;
            for f in &empty_allocated_filters {
                if !leave_candidates.contains(f) {
                    leave_candidates.push(f.clone());
                }
            }
            let empty_shard_count = leave_candidates.len() - score_driven_count;
            for f in &unrecoverable_orphan_filters {
                if !leave_candidates.contains(f) {
                    leave_candidates.push(f.clone());
                }
            }
            let unrecoverable_orphan_count =
                leave_candidates.len() - score_driven_count - empty_shard_count;
            for f in &overcapacity_filters {
                if !leave_candidates.contains(f) {
                    leave_candidates.push(f.clone());
                }
            }
            let overcapacity_count = leave_candidates.len()
                - score_driven_count
                - empty_shard_count
                - unrecoverable_orphan_count;
            for f in &split_parent_filters {
                if !leave_candidates.contains(f) {
                    leave_candidates.push(f.clone());
                }
            }
            let split_parent_count = leave_candidates.len()
                - score_driven_count
                - empty_shard_count
                - unrecoverable_orphan_count
                - overcapacity_count;
            if split_parent_count > 0 {
                tracing::info!(
                    split_parent_count,
                    frame = frame_number,
                    "lifecycle: proposing leave off split-away parent shard(s) → workers re-cover children"
                );
            }
            for f in &retired_filters {
                if !leave_candidates.contains(f) {
                    leave_candidates.push(f.clone());
                }
            }
            let retired_count = leave_candidates.len()
                - score_driven_count
                - empty_shard_count
                - unrecoverable_orphan_count
                - overcapacity_count
                - split_parent_count;
            if retired_count > 0 {
                tracing::info!(
                    retired_count,
                    frame = frame_number,
                    "lifecycle: proposing leave off retired shard(s) the archives and local grid no longer list"
                );
            }

            // Per-filter Leave cooldown: drop any filter we already
            // proposed Leave on within the last `LEAVE_COOLDOWN_FRAMES`
            // frames. Until that window elapses we don't know whether
            // the prior bundle landed at the archive, materialized, or
            // round-tripped back into our local registry. Re-publishing
            // the same Leave bundle every 4-frame `JOIN_COOLDOWN_FRAMES`
            // tick is the wire-side symptom of this: an identical
            // 3-filter Leave action re-emitted ~every 4 frames for
            // 30+ minutes on a single node.
            let pre_cooldown_count = leave_candidates.len();
            leave_candidates = self.filter_recent_leave_attempts(
                leave_candidates,
                frame_number,
            );
            let cooldown_suppressed =
                pre_cooldown_count.saturating_sub(leave_candidates.len());

            if leave_candidates.len() > MAX_PROPOSALS_PER_CYCLE {
                leave_candidates.truncate(MAX_PROPOSALS_PER_CYCLE);
            }

            if !leave_candidates.is_empty() {
                self.allocator.set_last_join_attempt(frame_number);
                self.record_leave_attempts(&leave_candidates, frame_number);
                let leave_summary: Vec<String> = leave_candidates
                    .iter()
                    .map(hex::encode)
                    .collect();
                info!(
                    frame = frame_number,
                    allocated = allocated_descriptors.len(),
                    unallocated_candidates = proposal_descriptors.len(),
                    leave_proposals = leave_candidates.len(),
                    score_driven = score_driven_count,
                    empty_allocated = empty_shard_count,
                    unrecoverable_orphans = unrecoverable_orphan_count,
                    overcapacity = overcapacity_count,
                    auto_worker_capacity,
                    cooldown_suppressed,
                    ?leave_summary,
                    "proposing leaves (score-driven + empty + over-capacity)"
                );
                actions.push(LifecycleAction::ProposeLeave {
                    filters: leave_candidates,
                    frame_number,
                });
            } else if cooldown_suppressed > 0 {
                tracing::debug!(
                    frame = frame_number,
                    cooldown_suppressed,
                    "all leave candidates suppressed by per-filter cooldown",
                );
            }
        }

        // 4) DecideLeaves — independent of cooldown. Matches
        //    worker_allocator.go:318-344.
        //
        // Bucketed by mode: filters bound to manually_managed workers
        // confirm at window-maturity unconditionally (operator drove
        // the leave via gRPC, so the registry-side score should not
        // veto). Auto-bound and unbound leaves flow through the
        // existing score-driven `decide_leaves`.
        // Epoch-aligned: a leave proposed in epoch E is confirmed in EXACTLY
        // epoch E+1 (departs at the E+2 boundary).
        let ready_leave_filters: Vec<Vec<u8>> = leaving_filters.iter()
            .filter(|(_, lf)| cur_epoch == quil_types::consensus::epoch_for_frame(*lf) + 1)
            .map(|(f, _)| f.clone())
            .collect();

        if !ready_leave_filters.is_empty() {
            let manual_bound_filters: std::collections::HashSet<Vec<u8>> = workers
                .iter()
                .filter(|w| w.manually_managed && !w.filter.is_empty())
                .map(|w| w.filter.clone())
                .collect();
            // Filters any worker is currently bound to — used to
            // identify orphans (leaves with no worker). Orphans skip
            // the score-driven decide because there's nothing to
            // retain; they confirm unconditionally. Without this the
            // orphan leave gets rejected when the shard score is
            // healthy (≥ 67% of best), looping forever and never
            // clearing the stale allocation.
            let bound_filters: std::collections::HashSet<Vec<u8>> = workers
                .iter()
                .filter(|w| !w.filter.is_empty())
                .map(|w| w.filter.clone())
                .collect();

            // Three-way partition: manual-pinned, orphan (no worker
            // bound, or a split-away parent), and auto-bound. Manual + orphan
            // always confirm; auto-bound goes through score-driven decide.
            //
            // A split-away parent no longer exists as a shard, so its score
            // means nothing. Scoring it rejected the very leave the lifecycle
            // proposed to re-cover the children: once rejects took effect,
            // provers stayed on the dead parent, the split proposer counted
            // them and staged a second root split, and every session retired.
            let mut manual_ready: Vec<Vec<u8>> = Vec::new();
            let mut orphan_ready: Vec<Vec<u8>> = Vec::new();
            let mut auto_ready: Vec<Vec<u8>> = Vec::new();
            for f in &ready_leave_filters {
                if manual_bound_filters.contains(f) {
                    manual_ready.push(f.clone());
                } else if !bound_filters.contains(f) || settled_split_away(f) || retired.contains(f)
                    || shard_sizes_snapshot.get(f) == Some(&0) {
                    orphan_ready.push(f.clone());
                } else {
                    auto_ready.push(f.clone());
                }
            }

            // Auto bucket: score-driven decide_leaves on auto-bound.
            let (mut auto_reject, auto_confirm) = proposer::decide_leaves_against_replacements(
                &held_descriptors,
                &available_replacements,
                &auto_ready,
                difficulty,
                &world_bytes,
                self.units,
                self.strategy,
            );

            // Halt-risk swap: `plan_leaves` sheds healthy allocations to
            // free workers for halt-risk shards no free worker can cover,
            // and the score rule above rejects every leave off a healthy
            // shard, so a swap never completed: the regular nodes proposed
            // and rejected the same leaves each epoch while data shards had
            // no prover. While the demand
            // stands, confirm the leaves the shard can spare.
            let mut swap_demand =
                proposer::halt_risk_swap_demand(&available_replacements, assignable_worker_ids.len());
            let mut swap_confirm: Vec<Vec<u8>> = Vec::new();
            auto_reject.retain(|filter| {
                if swap_demand == 0 {
                    return true;
                }
                let addresses = |status| {
                    registry
                        .get_provers_by_status(filter, status)
                        .map(|provers| provers.into_iter().map(|p| p.address).collect::<Vec<_>>())
                        .unwrap_or_default()
                };
                let active = addresses(ProverStatus::Active).len();
                let leaving = addresses(ProverStatus::Leaving);
                if !proposer::chosen_to_depart(&self.prover_address, filter, active, &leaving) {
                    return true;
                }
                swap_confirm.push(filter.clone());
                swap_demand -= 1;
                false
            });

            // Manual + orphan: always confirm at window, no auto-reject.
            // Order: auto confirms, then swaps, then orphans, then
            // manuals — stable per-frame ordering for the log.
            let mut combined_confirm = auto_confirm;
            combined_confirm.extend(swap_confirm);
            combined_confirm.extend(orphan_ready);
            combined_confirm.extend(manual_ready);

            // Per-message cap: each LifecycleAction maps 1:1 to a
            // submitted canonical-bytes message (single-type, 100
            // filters max). Truncated filters stay Leaving and
            // re-enter the decision on the next frame.
            if auto_reject.len() > MAX_PROPOSALS_PER_CYCLE {
                auto_reject.truncate(MAX_PROPOSALS_PER_CYCLE);
            }
            if combined_confirm.len() > MAX_PROPOSALS_PER_CYCLE {
                combined_confirm.truncate(MAX_PROPOSALS_PER_CYCLE);
            }

            if !auto_reject.is_empty() {
                actions.push(LifecycleAction::RejectLeaves {
                    filters: auto_reject,
                    frame_number,
                });
            }
            if !combined_confirm.is_empty() {
                actions.push(LifecycleAction::ConfirmLeaves {
                    filters: combined_confirm,
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
/// store.
/// Some registered shard is a strict bit-path descendant of `filter`: the
/// filter has been split and no longer exists as a shard.
pub(crate) fn is_split_parent<'a>(filter: &[u8], shards: impl IntoIterator<Item = &'a Vec<u8>>) -> bool {
    let Some((fa, fb)) = quil_forest::decode_shard_filter_or_root(filter, 32) else {
        return false;
    };
    shards.into_iter().any(|g| {
        matches!(
            quil_forest::decode_shard_filter_or_root(g, 32),
            Some((ga, gb))
                if ga == fa
                    && gb.len() > fb.len()
                    && quil_forest::bit_path_starts_with(&gb, &fb)
        )
    })
}

/// Filters known to be current shards, for telling a split-away parent:
/// the local grid, the sizes the archives report, and every filter holding
/// a live allocation in the synced registry. A split moves the parent's live
/// allocations to its children, so the registry shows the children as soon
/// as it syncs. A regular node's own grid never flips, and the archives'
/// sizes refresh on a cadence; a join to a split-away root can land in that
/// gap. Only live allocations count: a merge leaves the children's
/// allocations Historic, and the merged parent is a shard again.
fn known_shard_filters(
    summaries: &[ProverShardSummary],
    shard_sizes: &HashMap<Vec<u8>, u64>,
    grid: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let live = summaries.iter().filter(|s| has_live_allocation(s));
    live.map(|s| s.filter.clone())
        .chain(shard_sizes.keys().cloned())
        .chain(grid.iter().cloned())
        .collect()
}

pub(crate) fn has_live_allocation(summary: &ProverShardSummary) -> bool {
    [ProverStatus::Active, ProverStatus::Joining, ProverStatus::Paused, ProverStatus::Leaving]
        .iter()
        .any(|status| summary.status_counts.get(status).copied().unwrap_or(0) > 0)
}

/// Shards with live allocations in the synced registry that the archive
/// sizes do not include. See `ProverLifecycle::unsized_live_shards`. A
/// merged parent looks split away until the sizes refresh (the old sizes
/// still name its children), so it asks for the refresh like any other; a
/// refresh that comes back without a filter settles it.
fn unsized_live_filters<V>(
    summaries: &[ProverShardSummary],
    remote_sizes: &HashMap<Vec<u8>, V>,
) -> std::collections::HashSet<Vec<u8>> {
    summaries
        .iter()
        .filter(|s| !s.filter.is_empty() && has_live_allocation(s))
        .filter(|s| !remote_sizes.contains_key(&s.filter))
        .map(|s| s.filter.clone())
        .collect()
}

/// A split-away parent the lifecycle may leave: a known shard descends from
/// it, and no view still holds it as a shard. The local grid, the latest
/// archive sizes, and a recorded merge not yet applied each say it is one.
/// Otherwise, when the registry syncs the merged parent's allocations a few
/// frames before the local grid flips, while the grid and the sizes still
/// name the children, every member leaves the merged shard.
pub(crate) fn is_settled_split_parent(
    filter: &Vec<u8>,
    known: &[Vec<u8>],
    grid: &[Vec<u8>],
    remote_shards: &std::collections::HashSet<Vec<u8>>,
    arriving_shards: &std::collections::HashSet<Vec<u8>>,
) -> bool {
    !grid.contains(filter)
        && !remote_shards.contains(filter)
        && !arriving_shards.contains(filter)
        && is_split_parent(filter, known)
}

fn build_proposal_descriptors(
    summaries: &[ProverShardSummary],
    our_filters: &[Vec<u8>],
    shard_sizes: &HashMap<Vec<u8>, u64>,
    shards_store_filters: &[Vec<u8>],
) -> Vec<ShardDescriptor> {
    let mut out: Vec<ShardDescriptor> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        std::collections::HashSet::new();
    let known = known_shard_filters(summaries, shard_sizes, shards_store_filters);
    for s in summaries {
        if s.filter.is_empty() {
            continue;
        }
        if our_filters.contains(&s.filter) {
            continue;
        }
        // A split-away parent keeps its old allocations (and possibly a size
        // entry) but is not a shard any more; joining it strands a worker.
        // See `known_shard_filters` for why the reported sizes alone lag.
        if is_split_parent(&s.filter, &known) {
            continue;
        }
        // Skip shards we don't have real byte-size data for. The
        // registry's `total_size` is a prover-count proxy (sum of
        // status_counts; see `prover_registry.rs:450`), NOT bytes —
        // falling back to it lets joins fire on shards that have
        // provers but zero actual data, exactly the symptom users
        // report. Only consider a shard a join candidate when
        // `shard_sizes` has a real entry > 0. Mirrors Go's
        // `worker_allocator.go` which uses
        // `new(big.Int).SetBytes(shard.Size)` from the shards-store
        // and `continue`s on zero.
        let raw_size = match shard_sizes.get(&s.filter).copied() {
            Some(n) if n > 0 => n,
            _ => continue,
        };
        let active = s.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0);
        let joining = s.status_counts.get(&ProverStatus::Joining).copied().unwrap_or(0);
        let total = (active + joining) as usize;
        let ri = proposer::compute_shard_ring_info(total);
        out.push(ShardDescriptor {
            filter: s.filter.clone(),
            size: raw_size,
            // Contention-dampened joiner ring (see JOIN_CONTENTION_MARGIN):
            // score as if a few other provers also pile onto this shard,
            // so near-ring-boundary shards aren't over-proposed.
            ring: proposer::dampened_joiner_ring(total),
            shards: 1,
            active_on_ring: ri.active_on_joiner_ring,
            total_active_joining: total as u64,
            active_count: active as u64,
        });
        seen.insert(s.filter.clone());
    }
    // Surface shards with no allocations yet as empty-ring
    // descriptors. Mirrors Go's worker allocator at
    // `worker_allocator.go:763-868` where `proverRegistry.GetProvers(bp)`
    // returns an empty list for unallocated shards but the descriptor
    // is still built (with active=joining=0, ring=0) so the proposer
    // can score and pick it. Skip when no real size is known — Go's
    // `if size == 0 { continue }` applies here too. Both the local grid
    // and the sizes the archives report name them: a regular node's own
    // grid never flips, so a split's children that got no allocation
    // appear only in the archive sizes.
    let mut sized: Vec<&Vec<u8>> = shard_sizes.keys().collect();
    sized.sort();
    for filter in shards_store_filters.iter().chain(sized) {
        if filter.is_empty() {
            continue;
        }
        if seen.contains(filter) || is_split_parent(filter, &known) {
            continue;
        }
        if our_filters.contains(filter) {
            continue;
        }
        let raw_size = shard_sizes.get(filter).copied().unwrap_or(0);
        if raw_size == 0 {
            continue;
        }
        seen.insert(filter.clone());
        let ri = proposer::compute_shard_ring_info(0);
        out.push(ShardDescriptor {
            filter: filter.clone(),
            size: raw_size,
            ring: ri.joiner_ring,
            shards: 1,
            active_on_ring: ri.active_on_joiner_ring,
            // 0 active+joining → halt-risk-eligible. The proposer's
            // bucket-by-halt-risk pass picks these first.
            total_active_joining: 0,
            active_count: 0,
        });
    }
    out
}

/// Build descriptors for every shard scored with its *current* ring.
/// Used both as the base for decide operations (where pending-matching
/// entries are spliced in) and for plan_leaves (allocated view).
///
/// Mirrors Go's `decideDescriptors` at `worker_allocator.go:884-893`.
/// See `build_proposal_descriptors` doc for `shard_sizes`.
fn build_decide_descriptors(
    summaries: &[ProverShardSummary],
    shard_sizes: &HashMap<Vec<u8>, u64>,
) -> Vec<ShardDescriptor> {
    summaries.iter().filter_map(|s| {
        if s.filter.is_empty() {
            return None;
        }
        // Same byte-size requirement as `build_proposal_descriptors`.
        // `s.total_size` is a prover-count proxy, not bytes — using
        // it as a fallback would let `plan_leaves` and `decide_joins`
        // score shards on phantom data and emit incorrect
        // leave/reject decisions.
        let raw_size = match shard_sizes.get(&s.filter).copied() {
            Some(n) if n > 0 => n,
            _ => return None,
        };
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
            total_active_joining: total as u64,
            active_count: active as u64,
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
mod buckets_tests {
    use super::*;
    use quil_types::consensus::{ALLOCATION_GRACE_FRAMES, ProverAllocationInfo, ProverStatus};

    fn alloc(
        filter: u8,
        status: ProverStatus,
        join: u64,
        leave: u64,
    ) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status,
            confirmation_filter: vec![filter],
            rejection_filter: Vec::new(),
            join_frame_number: join,
            leave_frame_number: leave,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            epoch: 0,
            ring: 0,
            vertex_address: Vec::new(),
        }
    }

    /// Serializes every test whose expectations depend on the process-global
    /// epoch length: `an_expired_join_the_chain_still_blocks_is_not_re_proposed`
    /// overrides it, and the rest compute their frames from the 720 default, so
    /// without one lock they race.
    static EPOCH_LENGTH: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn epoch_length_guard() -> std::sync::MutexGuard<'static, ()> {
        EPOCH_LENGTH.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn buckets_partition_by_effective_status_at_frame() {
        let _epoch = epoch_length_guard();
        let allocations = vec![
            alloc(0x01, ProverStatus::Joining, 100, 0),
            alloc(0x02, ProverStatus::Active, 50, 0),
            alloc(0x03, ProverStatus::Leaving, 50, 500),
            alloc(0x04, ProverStatus::Paused, 50, 0),
        ];
        let b = AllocationBuckets::from_allocations(&allocations, 600);
        assert_eq!(b.joining.len(), 1, "1 joining within grace");
        assert_eq!(b.active.len(), 1);
        assert_eq!(b.leaving.len(), 1, "1 leaving within grace");
        // joining + active + leaving + paused all owned
        assert_eq!(b.all_ours.len(), 4);
    }

    /// An expired join the NETWORK still blocks must not be re-proposed.
    ///
    /// Expiry is epoch-relative (`effective_status`) while the chain's refusal
    /// is a fixed `REJOIN_WINDOW_FRAMES` from JoinFrameNumber, so with short
    /// epochs an allocation reads ExpiredJoining here long before the network
    /// will accept a re-join. Proposing one anyway is dropped as `0x0312
    /// existing allocation still active`, and the node spends its free workers
    /// re-proposing that same filter instead of joining a shard it can have —
    /// which is how split/merge churn left whole nodes carrying no shard.
    /// (At the mainnet epoch length the window has always passed by the time a
    /// join expires, so this only bites on short-epoch networks.)
    #[test]
    fn an_expired_join_the_chain_still_blocks_is_not_re_proposed() {
        let _epoch = epoch_length_guard();
        let window = quil_execution::global_intrinsic::verify::REJOIN_WINDOW_FRAMES;
        let previous = quil_types::consensus::epoch_length_frames();
        quil_types::consensus::set_epoch_length_frames(60);
        let join_frame = 100u64;
        // Two epochs past the join: expired locally.
        let expired_at = 60 * (quil_types::consensus::epoch_for_frame(join_frame) + 2);
        let allocation = alloc(0x09, ProverStatus::Joining, join_frame, 0);
        assert_eq!(allocation.effective_status(expired_at),
            quil_types::consensus::EffectiveStatus::ExpiredJoining);

        // Inside the chain's window: owned, so the proposer leaves it alone.
        assert!(expired_at < join_frame + window, "fixture must sit inside the window");
        let blocked = AllocationBuckets::from_allocations(&[allocation.clone()], expired_at);
        assert_eq!(blocked.all_ours.len(), 1, "an expired join the chain still blocks stays owned");
        // ...but it is not an ACTION: no re-confirm, no Leave for something the
        // chain already treats as gone.
        assert!(blocked.joining.is_empty());
        assert!(blocked.active.is_empty());
        assert!(blocked.leaving.is_empty());

        // Past the window the network accepts a re-join, so it becomes a
        // candidate again.
        let free = AllocationBuckets::from_allocations(&[allocation], join_frame + window);
        assert!(free.all_ours.is_empty(), "past the window the shard is re-joinable");

        quil_types::consensus::set_epoch_length_frames(previous);
    }

    /// The end the expired-join fix exists for: while the chain still refuses a
    /// re-join, that shard must not be offered to the proposer at all, so the
    /// node's free worker goes to one it CAN join. Before it, the proposer
    /// re-picked the blocked filter every cycle, the archive dropped each join
    /// as `0x0312 existing allocation still active`, and the worker sat idle
    /// while shards ran under quorum.
    #[test]
    fn a_free_worker_goes_to_a_joinable_shard_not_the_blocked_one() {
        use crate::provers::proposer::{plan_and_allocate, Strategy};
        use quil_types::consensus::ProverShardSummary;
        let _epoch = epoch_length_guard();
        let window = quil_execution::global_intrinsic::verify::REJOIN_WINDOW_FRAMES;
        let previous = quil_types::consensus::epoch_length_frames();
        quil_types::consensus::set_epoch_length_frames(60);

        let blocked_filter = vec![0x0Au8];
        let open_filter = vec![0x0Bu8];
        let join_frame = 100u64;
        let blocked = alloc(0x0A, ProverStatus::Joining, join_frame, 0);
        // Two epochs on: expired by this node's reckoning, still inside the
        // chain's re-join window.
        let at = 60 * (quil_types::consensus::epoch_for_frame(join_frame) + 2);
        assert!(at < join_frame + window, "fixture must sit inside the window");

        let summary = |filter: &Vec<u8>| {
            let mut status_counts = std::collections::HashMap::new();
            status_counts.insert(ProverStatus::Active, 3u32);
            ProverShardSummary { filter: filter.clone(), status_counts, total_size: 3 }
        };
        let summaries = vec![summary(&blocked_filter), summary(&open_filter)];
        let shard_sizes: std::collections::HashMap<Vec<u8>, u64> =
            [(blocked_filter.clone(), 500_000u64), (open_filter.clone(), 500_000u64)]
                .into_iter().collect();

        let ours = AllocationBuckets::from_allocations(&[blocked.clone()], at).all_ours;
        let descriptors = super::build_proposal_descriptors(&summaries, &ours, &shard_sizes, &[]);
        assert!(descriptors.iter().all(|d| d.filter != blocked_filter),
            "a shard the chain would refuse must not be a candidate");
        assert!(descriptors.iter().any(|d| d.filter == open_filter));
        let proposals = plan_and_allocate(
            &descriptors, 50_000, &num_bigint::BigInt::from(20_000_000u64),
            1_000_000, &[0], 1, Strategy::RewardGreedy, None,
        );
        assert_eq!(proposals.len(), 1, "the free worker is still spent");
        assert_eq!(proposals[0].filter, open_filter,
            "it goes to the shard this node can actually join");

        // Past the window the network accepts a re-join, so it is a candidate
        // again and nothing is permanently forfeited.
        let later = join_frame + window;
        let ours_later = AllocationBuckets::from_allocations(&[blocked], later).all_ours;
        assert!(ours_later.is_empty());
        let reopened = super::build_proposal_descriptors(&summaries, &ours_later, &shard_sizes, &[]);
        assert!(reopened.iter().any(|d| d.filter == blocked_filter),
            "past the window the shard is offered again");

        quil_types::consensus::set_epoch_length_frames(previous);
    }

    // After a split, provers still held allocations on the parent and it
    // kept a size entry, so joins targeted a shard that no longer existed.
    #[test]
    fn a_split_away_parent_is_not_a_join_candidate() {
        let app = [0x11u8; 32];
        let parent = quil_forest::encode_shard_bit_path(&app, &[]);
        let left = quil_forest::encode_shard_bit_path(&app, &[false]);
        let right = quil_forest::encode_shard_bit_path(&app, &[true]);
        let summary = |filter: &Vec<u8>| {
            let mut status_counts = std::collections::HashMap::new();
            status_counts.insert(ProverStatus::Active, 4u32);
            ProverShardSummary { filter: filter.clone(), status_counts, total_size: 4 }
        };
        let summaries = vec![summary(&parent), summary(&left), summary(&right)];
        let shard_sizes: std::collections::HashMap<Vec<u8>, u64> =
            [(parent.clone(), 900_000u64), (left.clone(), 500_000u64), (right.clone(), 400_000u64)]
                .into_iter().collect();
        assert!(super::is_split_parent(&parent, shard_sizes.keys()));
        assert!(!super::is_split_parent(&left, shard_sizes.keys()));
        let descriptors = super::build_proposal_descriptors(&summaries, &[], &shard_sizes, &[parent.clone()]);
        assert!(descriptors.iter().all(|d| d.filter != parent), "the split-away parent is not a join candidate");
        assert_eq!(descriptors.len(), 2, "both children are");
    }

    // Seconds after the root splits, the sizes the archives report can still
    // name only the root, so every regular would propose a join to it and the
    // chain would confirm them. The local grid already has the children.
    #[test]
    fn the_grid_marks_a_split_away_parent_before_the_reported_sizes_do() {
        let app = [0x12u8; 32];
        let parent = quil_forest::encode_shard_bit_path(&app, &[]);
        let children = [false, true].map(|bit| quil_forest::encode_shard_bit_path(&app, &[bit])).to_vec();
        let mut status_counts = std::collections::HashMap::new();
        status_counts.insert(ProverStatus::Active, 0u32);
        let summaries = vec![ProverShardSummary { filter: parent.clone(), status_counts, total_size: 0 }];
        let stale_sizes: std::collections::HashMap<Vec<u8>, u64> = [(parent.clone(), 2552u64)].into_iter().collect();
        let before_grid = super::build_proposal_descriptors(&summaries, &[], &stale_sizes, &[]);
        assert!(before_grid.iter().any(|d| d.filter == parent), "without the grid the root looks joinable");
        let descriptors = super::build_proposal_descriptors(&summaries, &[], &stale_sizes, &children);
        assert!(descriptors.iter().all(|d| d.filter != parent), "the grid shows the root is split away");
    }

    // The next width run: a regular node's own grid never flips, so it
    // still held only the root, and the archives' sizes had not refreshed.
    // The synced registry already showed the moved allocations on the
    // children.
    #[test]
    fn live_allocations_on_children_mark_a_split_away_parent() {
        let app = [0x14u8; 32];
        let parent = quil_forest::encode_shard_bit_path(&app, &[]);
        let children = [false, true].map(|bit| quil_forest::encode_shard_bit_path(&app, &[bit])).to_vec();
        let summary = |filter: &Vec<u8>, status: ProverStatus| {
            let mut status_counts = std::collections::HashMap::new();
            status_counts.insert(status, 2u32);
            ProverShardSummary { filter: filter.clone(), status_counts, total_size: 2 }
        };
        let stale_sizes: std::collections::HashMap<Vec<u8>, u64> = [(parent.clone(), 2552u64)].into_iter().collect();
        let stale_grid = vec![parent.clone()];

        let split = vec![
            summary(&parent, ProverStatus::Historic),
            summary(&children[0], ProverStatus::Active),
            summary(&children[1], ProverStatus::Active),
        ];
        let descriptors = super::build_proposal_descriptors(&split, &[], &stale_sizes, &stale_grid);
        assert!(descriptors.iter().all(|d| d.filter != parent), "the registry shows the root is split away");

        // After a merge the children's allocations are Historic and the
        // parent is a shard again.
        let merged = vec![
            summary(&parent, ProverStatus::Active),
            summary(&children[0], ProverStatus::Historic),
            summary(&children[1], ProverStatus::Historic),
        ];
        let descriptors = super::build_proposal_descriptors(&merged, &[], &stale_sizes, &stale_grid);
        assert!(descriptors.iter().any(|d| d.filter == parent), "a merged parent stays joinable");
    }

    // Three shards split at frame 304 and each moves its one active prover
    // to one child. The other three children hold data but no allocation,
    // and the regular nodes' grids still hold only the old shards, so no
    // regular would ever propose a join to them.
    #[test]
    fn a_split_child_with_no_allocation_is_a_join_candidate() {
        let app = [0x16u8; 32];
        let parent = quil_forest::encode_shard_bit_path(&app, &[false]);
        let staffed = quil_forest::encode_shard_bit_path(&app, &[false, false]);
        let empty = quil_forest::encode_shard_bit_path(&app, &[false, true]);
        let summary = |filter: &Vec<u8>, status: ProverStatus| {
            let mut status_counts = std::collections::HashMap::new();
            status_counts.insert(status, 1u32);
            ProverShardSummary { filter: filter.clone(), status_counts, total_size: 1 }
        };
        let summaries = vec![summary(&parent, ProverStatus::Historic), summary(&staffed, ProverStatus::Active)];
        let archive_sizes: std::collections::HashMap<Vec<u8>, u64> =
            [(staffed.clone(), 64u64), (empty.clone(), 64u64)].into_iter().collect();
        let descriptors = super::build_proposal_descriptors(&summaries, &[], &archive_sizes, &[parent.clone()]);
        let unallocated = descriptors.iter().find(|d| d.filter == empty).expect("the empty child is a candidate");
        assert_eq!(unallocated.total_active_joining, 0);
        assert!(descriptors.iter().any(|d| d.filter == staffed));
        assert!(descriptors.iter().all(|d| d.filter != parent));
        assert_eq!(descriptors.len(), 2, "each shard is described once");

        let ours = super::build_proposal_descriptors(&summaries, &[empty.clone()], &archive_sizes, &[parent.clone()]);
        assert!(ours.iter().all(|d| d.filter != empty), "not a shard we already hold");
        let flipped = super::build_proposal_descriptors(&summaries, &[], &archive_sizes, &[staffed.clone(), empty.clone()]);
        assert_eq!(flipped.len(), 2, "a grid that has flipped names the same shards once");
    }

    // The same run: the registry synced the moved allocations at once, but
    // the archive sizes waited for their cadence. The children the registry
    // shows ask for an early refresh; the parent the sizes still name does not.
    #[test]
    fn live_shards_the_archive_sizes_lack_are_reported_unsized() {
        let app = [0x17u8; 32];
        let parent = quil_forest::encode_shard_bit_path(&app, &[true]);
        let child = quil_forest::encode_shard_bit_path(&app, &[true, true]);
        let summary = |filter: &Vec<u8>, status: ProverStatus| {
            let mut status_counts = std::collections::HashMap::new();
            status_counts.insert(status, 1u32);
            ProverShardSummary { filter: filter.clone(), status_counts, total_size: 1 }
        };
        let stale: std::collections::HashMap<Vec<u8>, u64> = [(parent.clone(), 128u64)].into_iter().collect();
        let summaries = vec![summary(&parent, ProverStatus::Active), summary(&child, ProverStatus::Active)];
        let lacking = super::unsized_live_filters(&summaries, &stale);
        assert_eq!(lacking, std::collections::HashSet::from([child.clone()]));

        let historic = vec![summary(&child, ProverStatus::Historic)];
        assert!(super::unsized_live_filters(&historic, &stale).is_empty(), "only live allocations count");
        let fresh: std::collections::HashMap<Vec<u8>, u64> = [(child.clone(), 64u64)].into_iter().collect();
        assert_eq!(
            super::unsized_live_filters(&summaries, &fresh),
            std::collections::HashSet::from([parent.clone()]),
            "a split-away parent still holding live allocations asks once; the refresh that omits it settles it",
        );
    }

    /// Deferred activation: an allocation whose RAW byte is Active but whose
    /// effective_status is `Joining` (confirmed, awaiting the E+2 activation
    /// boundary) is OWNED (`all_ours`) but must NOT be re-confirmed (`joining`
    /// bucket, gated on the raw Joining byte) nor counted `active` yet — the
    /// committee stays frozen until activation. Guards against re-confirm storms.
    #[test]
    fn deferred_active_is_owned_but_not_reconfirmed_or_counted() {
        let _epoch = epoch_length_guard();
        let e = 720u64;
        let deferred = ProverAllocationInfo {
            status: ProverStatus::Active,
            join_confirm_frame_number: 2 * e + 100, // confirmed epoch 2 → activation epoch 3
            epoch: 100,                             // high → not epoch-expired
            ..alloc(0x07, ProverStatus::Active, 0, 0)
        };
        // Evaluate in epoch 2 (before activation epoch 3) → effective = Joining.
        let b = AllocationBuckets::from_allocations(&[deferred], 2 * e + 500);
        assert_eq!(b.all_ours.len(), 1, "deferred-active allocation is owned");
        assert!(b.joining.is_empty(), "no re-confirm for an already-confirmed (deferred) join");
        assert!(b.active.is_empty(), "not counted active until the E+2 boundary");
    }

    #[test]
    fn confirmed_leave_is_owned_until_departure_without_reconfirming() {
        let _epoch = epoch_length_guard();
        let e = quil_types::consensus::EPOCH_LENGTH_FRAMES;
        let leaving = ProverAllocationInfo {
            leave_confirm_frame_number: 2 * e + 10,
            ..alloc(0x07, ProverStatus::Leaving, 1, e + 1)
        };
        let before = AllocationBuckets::from_allocations(&[leaving.clone()], 2 * e + 20);
        assert_eq!(before.all_ours.len(), 1);
        assert!(before.leaving.is_empty());
        let after = AllocationBuckets::from_allocations(&[leaving], 3 * e);
        assert!(after.all_ours.is_empty());
        assert!(after.leaving.is_empty());
    }

    #[test]
    fn expired_joining_and_leaving_are_excluded_from_all_ours() {
        let _epoch = epoch_length_guard();
        // Epoch-aligned: a join/leave proposed in epoch 0 must settle in epoch 1;
        // by epoch 2 (current_epoch > proposed_epoch + 1) it's implicitly expired.
        // By then the chain's `REJOIN_WINDOW_FRAMES` has long passed (epoch 2 is
        // frame 1441, the window ended at 721), so these really are re-joinable —
        // see `an_expired_join_the_chain_still_blocks_is_not_re_proposed` for the
        // short-epoch case where it has not.
        let allocations = vec![
            alloc(0x01, ProverStatus::Joining, 1, 0),
            alloc(0x02, ProverStatus::Leaving, 1, 2),
        ];
        let b = AllocationBuckets::from_allocations(
            &allocations,
            2 * quil_types::consensus::EPOCH_LENGTH_FRAMES + 1, // epoch 2
        );
        assert!(b.joining.is_empty(), "expired joining excluded");
        assert!(b.leaving.is_empty(), "expired leaving excluded");
        assert!(b.all_ours.is_empty(), "expired allocs not in all_ours");
    }

    #[test]
    fn rejected_and_kicked_excluded() {
        let _epoch = epoch_length_guard();
        let allocations = vec![
            alloc(0x01, ProverStatus::Rejected, 100, 0),
            alloc(0x02, ProverStatus::Kicked, 100, 0),
        ];
        let b = AllocationBuckets::from_allocations(&allocations, 200);
        assert!(b.all_ours.is_empty());
        assert!(b.joining.is_empty());
        assert!(b.active.is_empty());
        assert!(b.leaving.is_empty());
    }

    #[test]
    fn stale_epoch_active_alloc_buckets_into_reconfirm() {
        let _epoch = epoch_length_guard();
        // Storage attestation is always-on: an Active alloc recorded at epoch 0,
        // evaluated at frame 1000 (epoch 1 > 0), is ExpiredEpoch.
        let b = AllocationBuckets::from_allocations(
            &[alloc(0x02, ProverStatus::Active, 50, 0)],
            1000,
        );
        assert_eq!(
            b.expired_epoch,
            vec![vec![0x02]],
            "stale-epoch active alloc must queue for re-confirm",
        );
        assert!(
            b.active.is_empty(),
            "an expired-epoch alloc must NOT count as active coverage",
        );
        assert_eq!(
            b.all_ours,
            vec![vec![0x02]],
            "still owned — don't re-propose a join for it",
        );
    }

    #[test]
    fn current_epoch_active_alloc_queues_proactive_reconfirm() {
        let _epoch = epoch_length_guard();
        // Registered only for the current epoch (1), evaluated during epoch 1.
        // Still Active (counts for coverage), but must re-confirm NOW to register
        // epoch 2 — otherwise it flips ExpiredEpoch at the next boundary and the
        // storage audit finds no registration for epoch 2. Proactive per-epoch
        // re-confirm (not the old ExpiredEpoch-only, every-other-epoch cadence).
        let mut a = alloc(0x02, ProverStatus::Active, 50, 0);
        a.epoch = 1;
        let b = AllocationBuckets::from_allocations(&[a], 1000);
        assert_eq!(b.active, vec![vec![0x02]], "still counts for coverage");
        assert_eq!(
            b.expired_epoch,
            vec![vec![0x02]],
            "current-epoch alloc must proactively re-confirm for next epoch",
        );
    }

    #[test]
    fn alloc_registered_ahead_does_not_reconfirm() {
        let _epoch = epoch_length_guard();
        // Already re-confirmed this epoch: registered for epoch 2 (current+1)
        // while evaluated during epoch 1. No further re-confirm this epoch.
        let mut a = alloc(0x02, ProverStatus::Active, 50, 0);
        a.epoch = 2;
        let b = AllocationBuckets::from_allocations(&[a], 1000);
        assert_eq!(b.active, vec![vec![0x02]]);
        assert!(
            b.expired_epoch.is_empty(),
            "an alloc already registered for next epoch must not re-confirm again",
        );
    }

    #[test]
    fn global_empty_filter_alloc_never_reconfirms() {
        let _epoch = epoch_length_guard();
        // Global (empty ConfirmationFilter) allocations do no storage attestation
        // and are exempt from epoch expiry — they must never queue a re-confirm.
        let mut a = alloc(0x02, ProverStatus::Active, 50, 0);
        a.confirmation_filter = Vec::new();
        a.epoch = 0;
        let b = AllocationBuckets::from_allocations(&[a], 1000);
        assert!(
            b.expired_epoch.is_empty(),
            "global empty-filter alloc must never re-confirm",
        );
    }
}

#[cfg(test)]
mod shard_size_cache_tests {
    use super::*;
    use std::sync::Arc;

    use crate::halt_state::HaltState;
    use crate::worker_allocator::WorkerAllocator;
    use crate::test_support::{TestProverRegistry, TestWorkerManager};

    fn make_lifecycle() -> ProverLifecycle {
        let wm = Arc::new(TestWorkerManager::new());
        let reg = Arc::new(TestProverRegistry::new());
        let allocator = Arc::new(WorkerAllocator::new(wm, reg, vec![0xAA; 32]));
        let halt = Arc::new(HaltState::new());
        let cf = crate::current_frame::CurrentFrame::new();
        ProverLifecycle::new(vec![0xAA; 32], allocator, halt, cf, Strategy::RewardGreedy)
    }

    // An unsized live shard asks for a refresh once. A refresh that
    // reports it settles it; one that does not report it (a stale husk
    // the archives never list) settles it too, so it cannot keep the
    // refresh off its cadence.
    #[test]
    fn an_unsized_live_shard_asks_for_one_refresh() {
        let lc = make_lifecycle();
        let set_unsized = |filters: &[&[u8]]| {
            *lc.unsized_live_shards.write().unwrap() = filters.iter().map(|f| f.to_vec()).collect();
        };
        assert!(!lc.wants_shard_info_refresh());
        set_unsized(&[b"child"]);
        assert!(lc.wants_shard_info_refresh());
        lc.set_remote_shard_sizes(HashMap::from([(b"child".to_vec(), 64u64)]));
        assert!(!lc.wants_shard_info_refresh(), "the refresh reported it");

        set_unsized(&[b"husk"]);
        assert!(lc.wants_shard_info_refresh());
        lc.set_remote_shard_sizes(HashMap::new());
        set_unsized(&[b"husk"]);
        assert!(!lc.wants_shard_info_refresh(), "a refresh already came back without it");
        set_unsized(&[b"husk", b"new child"]);
        assert!(lc.wants_shard_info_refresh(), "a new one still asks");
    }

    /// The bug this split fixes: a per-frame local writer used to
    /// clobber the periodic remote writer's data. The split caches
    /// + merged-read guarantee that calling `set_local_shard_sizes` (per
    /// frame) cannot evict remote-sourced entries the lifecycle
    /// needs for proposal scoring.
    #[test]
    fn local_writer_does_not_clobber_remote_entries() {
        let lc = make_lifecycle();
        // Remote refresh: sizes for shards A, B, C, D (we hold
        // none of them — typical fresh-node state).
        let mut remote = HashMap::new();
        remote.insert(b"shard-A".to_vec(), 1000);
        remote.insert(b"shard-B".to_vec(), 2000);
        remote.insert(b"shard-C".to_vec(), 3000);
        remote.insert(b"shard-D".to_vec(), 4000);
        lc.set_remote_shard_sizes(remote);
        assert!(lc.shard_info_loaded(), "gate flips on first remote refresh");

        // Per-frame local writer: we only hold data for shard A.
        // In the old single-cache design, this would have shrunk
        // the cache from 4 entries to 1, losing B/C/D.
        let mut local = HashMap::new();
        local.insert(b"shard-A".to_vec(), 1500); // newer, larger local value
        lc.set_local_shard_sizes(local);

        let merged = lc.merged_shard_sizes();
        assert_eq!(merged.len(), 4, "remote entries B/C/D must survive");
        assert_eq!(merged.get(b"shard-A".as_ref()), Some(&1500),
            "local value wins for shards we hold");
        assert_eq!(merged.get(b"shard-B".as_ref()), Some(&2000));
        assert_eq!(merged.get(b"shard-C".as_ref()), Some(&3000));
        assert_eq!(merged.get(b"shard-D".as_ref()), Some(&4000));
    }

    #[test]
    fn remote_replace_drops_stale_remote_entries() {
        let lc = make_lifecycle();
        let mut remote1 = HashMap::new();
        remote1.insert(b"A".to_vec(), 100);
        remote1.insert(b"B".to_vec(), 200);
        lc.set_remote_shard_sizes(remote1);

        // A subsequent remote fetch shouldn't carry stale B.
        let mut remote2 = HashMap::new();
        remote2.insert(b"A".to_vec(), 150);
        lc.set_remote_shard_sizes(remote2);

        let merged = lc.merged_shard_sizes();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged.get(b"A".as_ref()), Some(&150));
        assert!(merged.get(b"B".as_ref()).is_none(),
            "stale remote entries are dropped on the next replace");
    }

    #[test]
    fn local_only_data_is_available_before_remote_refresh() {
        let lc = make_lifecycle();
        // No remote yet (fresh-startup state). The gate stays
        // closed but the lifecycle still has access to local
        // sizes for its own held shards.
        let mut local = HashMap::new();
        local.insert(b"shard-A".to_vec(), 500);
        lc.set_local_shard_sizes(local);

        assert!(!lc.shard_info_loaded(),
            "local writer must not flip the gate");
        let merged = lc.merged_shard_sizes();
        assert_eq!(merged.get(b"shard-A".as_ref()), Some(&500));
    }
}

#[cfg(test)]
mod proposal_loop_tests {
    use super::*;
    use std::sync::Mutex;

    use quil_types::consensus::{
        ProverAllocationInfo, ProverInfo, ProverShardSummary, ProverStatus,
    };

    use crate::halt_state::HaltState;
    use crate::test_support::TestProverRegistry;
    use crate::worker::{WorkerInfo, WorkerManager};
    use crate::worker_allocator::{WorkerAllocator, JOIN_COOLDOWN_FRAMES};

    /// Local alias — `TestProverRegistry` is the shared crate-wide
    /// mock; the existing tests refer to it by this name.
    type ConfigurableRegistry = TestProverRegistry;

    /// Local alias — `TestWorkerManager` is the shared mock.
    type ConfigurableWorkerManager = crate::test_support::TestWorkerManager;

    fn make_lifecycle(
        prover_address: Vec<u8>,
        wm: Arc<dyn WorkerManager>,
        reg: Arc<dyn ProverRegistry>,
    ) -> Arc<ProverLifecycle> {
        let allocator =
            Arc::new(WorkerAllocator::new(wm, reg.clone(), prover_address.clone()));
        let halt = Arc::new(HaltState::new());
        let current_frame = crate::current_frame::CurrentFrame::new();
        // Seed `frame_seen` for the test harness — production
        // advances current_frame via the BlossomSub recv path
        // before any `evaluate` call lands. Tests bypass that
        // path, so we observe a sentinel here to keep the gate
        // open. Subsequent test-driven evaluates advance it
        // naturally inside `CurrentFrame`'s monotonic `fetch_max`.
        current_frame.observe(1);
        let lifecycle = Arc::new(ProverLifecycle::new(
            prover_address,
            allocator,
            halt,
            current_frame,
            Strategy::RewardGreedy,
        ));
        lifecycle.set_confirm_window_frames(2);
        lifecycle.set_sync_complete();
        // Seed byte-sizes from the registry's summaries. Tests
        // typically `set_summaries` before constructing the
        // lifecycle, so this captures their intent.
        seed_sizes_from_registry(&lifecycle, reg.as_ref());
        lifecycle
    }

    /// Seed the lifecycle's per-filter byte-size map from the
    /// registry's summaries. Production wires this from the local
    /// hypergraph each frame; tests call it after `set_summaries`
    /// so the proposer's size-zero skip doesn't drop every shard.
    /// Each summary's `total_size` is reused as the byte-size hint
    /// (in tests it's just whatever the test wrote — fine).
    fn seed_sizes_from_registry(
        lc: &ProverLifecycle,
        reg: &dyn ProverRegistry,
    ) {
        use std::collections::HashMap;
        // Test helper — test `ConfigurableRegistry` ignores
        // frame_number for summaries.
        let _ = lc; // keep parameter used for future test-side gating
        let summaries = reg.get_prover_shard_summaries(0).unwrap_or_default();
        let sizes: HashMap<Vec<u8>, u64> = summaries
            .iter()
            .filter(|s| !s.filter.is_empty() && s.total_size > 0)
            .map(|s| (s.filter.clone(), s.total_size))
            .collect();
        // Use `set_remote_shard_sizes` (not `set_local_shard_sizes`) so the
        // `shard_info_loaded` gate flips to true. Tests simulate a
        // fully-synced node that has already consumed a GetAppShards
        // refresh; without this, every propose path short-circuits.
        lc.set_remote_shard_sizes(sizes);
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
            // join_confirm 0 = genesis/no deferred-activation: an Active alloc
            // reads Active immediately (these tests run in epoch 0 and exercise
            // active/leave/surplus decisions, not the deferred-activation gate).
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            // Far-future epoch = never epoch-expires. These tests isolate
            // join/leave/surplus/cooldown decisions from the orthogonal storage
            // re-confirm cycle, so an Active alloc reads Active at any eval frame.
            epoch: u64::MAX,
            last_active_frame_number: 0,
            ring: 0,
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

    /// Collect the distinct shard filters a single `evaluate` cycle proposed
    /// joins for (across all `ProposeJoin` actions).
    fn proposed_join_filters(actions: &[LifecycleAction]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for a in actions {
            if let LifecycleAction::ProposeJoin { filters, .. } = a {
                out.extend(filters.iter().cloned());
            }
        }
        out
    }

    #[test]
    fn confirmed_ring_protects_an_early_high_reward_holding() {
        let address = vec![0xCD; 32];
        let held = filter_bytes(0xA1);
        let alternative = filter_bytes(0xA2);
        let wm = Arc::new(ConfigurableWorkerManager::new());
        wm.add(allocated_worker(1, held.clone()));
        let reg = Arc::new(ConfigurableRegistry::new());
        let mut holding = alloc(held.clone(), ProverStatus::Active, 10);
        holding.ring = 1;
        reg.set_prover(prover(address.clone(), vec![holding]));
        reg.set_summaries(vec![shard_summary(held.clone(), 53), shard_summary(alternative.clone(), 8)]);
        let lc = make_lifecycle(address, wm.clone(), reg.clone());
        lc.set_remote_shard_metrics(HashMap::from([(held, (1_000_000, 100)), (alternative, (1_000_000, 100))]));
        lc.set_prover_root_verified_frame(100);
        let actions = lc.evaluate(100, 50_000, reg.as_ref(), wm.as_ref()).unwrap();
        assert_eq!(count_proposed_leaves(&actions), 0, "our ring 1 earns as much as the alternative; actions={actions:?}");
    }

    #[test]
    fn data_shard_counts_prevent_a_false_reward_upgrade() {
        let address = vec![0xCD; 32];
        let held = filter_bytes(0xA1);
        let alternative = filter_bytes(0xA2);
        let wm = Arc::new(ConfigurableWorkerManager::new());
        wm.add(allocated_worker(1, held.clone()));
        let reg = Arc::new(ConfigurableRegistry::new());
        reg.set_prover(prover(address.clone(), vec![alloc(held.clone(), ProverStatus::Active, 10)]));
        reg.set_summaries(vec![shard_summary(held.clone(), 8), shard_summary(alternative.clone(), 8)]);
        let lc = make_lifecycle(address, wm.clone(), reg.clone());
        lc.set_remote_shard_metrics(HashMap::from([(held, (1_000_000, 1)), (alternative, (100_000_000, 1_000_000))]));
        lc.set_prover_root_verified_frame(100);
        let actions = lc.evaluate(100, 50_000, reg.as_ref(), wm.as_ref()).unwrap();
        assert_eq!(count_proposed_leaves(&actions), 0, "larger bytes do not imply higher per-worker rewards; actions={actions:?}");
    }

    #[test]
    fn a_join_reserved_this_cycle_cannot_also_fund_a_leave() {
        let address = vec![0xCD; 32];
        let held = filter_bytes(0xA1);
        let alternative = filter_bytes(0xA2);
        let wm = Arc::new(ConfigurableWorkerManager::new());
        wm.add(allocated_worker(1, held.clone()));
        wm.add(idle_worker(2));
        let reg = Arc::new(ConfigurableRegistry::new());
        reg.set_prover(prover(address.clone(), vec![alloc(held.clone(), ProverStatus::Active, 10)]));
        reg.set_summaries(vec![shard_summary(held.clone(), 8), shard_summary(alternative.clone(), 8)]);
        let lc = make_lifecycle(address, wm.clone(), reg.clone());
        lc.set_remote_shard_metrics(HashMap::from([(held, (1_000_000, 1)), (alternative.clone(), (100_000_000, 1))]));
        for frame in [100, 101] {
            lc.set_prover_root_verified_frame(frame);
            let actions = lc.evaluate(frame, 50_000, reg.as_ref(), wm.as_ref()).unwrap();
            if frame == 100 { assert_eq!(proposed_join_filters(&actions), vec![alternative.clone()]); }
            assert_eq!(count_proposed_leaves(&actions), 0, "pending join already reserves the reward opportunity; actions={actions:?}");
        }
        // Without the reserved destination, a genuinely superior alternative
        // must still justify leaving when no worker is free to take it.
        wm.set_worker_filter(2, &filter_bytes(0xA3), true).unwrap();
        let frame = 100 + JOIN_FILTER_COOLDOWN_FRAMES;
        lc.set_prover_root_verified_frame(frame);
        let actions = lc.evaluate(frame, 50_000, reg.as_ref(), wm.as_ref()).unwrap();
        assert_eq!(count_proposed_leaves(&actions), 1, "expired reservation releases the destination; actions={actions:?}");
    }

    #[test]
    fn a_favorable_pending_leave_is_rejected_at_its_window() {
        let address = vec![0xCD; 32];
        let held = filter_bytes(0xA1);
        let better_held = filter_bytes(0xA2);
        let available = filter_bytes(0xA3);
        let wm = Arc::new(ConfigurableWorkerManager::new());
        wm.add(allocated_worker(1, held.clone()));
        wm.add(allocated_worker(2, better_held.clone()));
        let reg = Arc::new(ConfigurableRegistry::new());
        let mut leaving = alloc(held.clone(), ProverStatus::Leaving, 10);
        leaving.ring = 1;
        leaving.leave_frame_number = 10;
        reg.set_prover(prover(address.clone(), vec![leaving, alloc(better_held.clone(), ProverStatus::Active, 10)]));
        reg.set_summaries(vec![shard_summary(held.clone(), 53), shard_summary(better_held.clone(), 59), shard_summary(available.clone(), 8)]);
        let lc = make_lifecycle(address, wm.clone(), reg.clone());
        lc.set_remote_shard_metrics(HashMap::from([(held.clone(), (1_000_000, 1)), (better_held, (100_000_000, 1)), (available.clone(), (100_000, 1))]));
        lc.set_prover_root_verified_frame(720);
        let actions = lc.evaluate(720, 50_000, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(actions.iter().any(|a| matches!(a, LifecycleAction::RejectLeaves { filters, .. } if filters.contains(&held))), "keep a profitable holding despite a richer shard we already hold; actions={actions:?}");
        assert!(!actions.iter().any(|a| matches!(a, LifecycleAction::ConfirmLeaves { filters, .. } if filters.contains(&held))));
        // A genuinely better, unreserved destination still confirms the leave.
        lc.set_remote_shard_metrics(HashMap::from([(held.clone(), (1_000_000, 1)), (available, (100_000_000, 1))]));
        let actions = lc.evaluate(720, 50_000, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(actions.iter().any(|a| matches!(a, LifecycleAction::ConfirmLeaves { filters, .. } if filters.contains(&held))), "genuine upgrades remain possible; actions={actions:?}");
    }

    /// REPRODUCTION of the "one prover ⇒ many allocations" multi-coverage that
    /// the static reassign/rekey/proposer reads could not explain (the field
    /// data showed 45/49/45 provers on three DIFFERENT-branch deep shards,
    /// |00∩01| = 45 — i.e. the same ~45 nodes each covering many distinct-branch
    /// shards at once). This is NOT reassignment and NOT a bug in any single
    /// path: it's the coverage model. A node runs `worker_count` data workers,
    /// and `decide_joins` greedily proposes a join for EVERY under-covered shard
    /// up to its free-worker count in a SINGLE cycle. Give one node enough idle
    /// workers and enough halt-risk shards spread across different top-of-tree
    /// branches, and it lays claim to all of them at once.
    #[test]
    fn rejected_leave_renews_before_orphan_cleanup_and_grace_is_bounded() {
        let address = vec![0xCD; 32];
        let held = filter_bytes(0xA1);
        let wm = Arc::new(ConfigurableWorkerManager::new());
        wm.add(idle_worker(1));
        let reg = Arc::new(ConfigurableRegistry::new());
        let mut recovering = alloc(held.clone(), ProverStatus::Active, 10);
        recovering.epoch = 0;
        recovering.leave_frame_number = 10;
        recovering.leave_reject_frame_number = 721;
        reg.set_prover(prover(address.clone(), vec![recovering]));
        reg.set_summaries(vec![shard_summary(held.clone(), 50)]);
        let lc = make_lifecycle(address, wm.clone(), reg.clone());
        for frame in [725, 1439] {
            lc.set_prover_root_verified_frame(frame);
            let actions = lc.evaluate(frame, 50_000, reg.as_ref(), wm.as_ref()).unwrap();
            assert!(actions.iter().any(|a| matches!(a, LifecycleAction::ReconfirmEpoch { filters, .. } if filters.contains(&held))));
            assert_eq!(count_proposed_leaves(&actions), 0,
                "renewal must not race orphan cleanup after rejecting a leave; actions={actions:?}");
        }
        lc.set_prover_root_verified_frame(1440);
        let actions = lc.evaluate(1440, 50_000, reg.as_ref(), wm.as_ref()).unwrap();
        assert_eq!(count_proposed_leaves(&actions), 1,
            "a failed, unstaffed recovery remains eligible for bounded cleanup; actions={actions:?}");
    }

    #[test]
    fn one_prover_covers_many_distinct_branch_shards_in_one_cycle() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // A real multi-core data-worker node: many idle workers.
        for c in 1..=8u32 {
            wm.add(idle_worker(c));
        }

        // Eight halt-risk shards, one per distinct top-2-bit branch
        // (first byte 0x00, 0x20, .. 0xE0 → assign_child_index buckets
        // 0,1,..7). Each is under-covered (active = 1 ≤ HALT_RISK+1) so it is
        // a join target, and each has real size so the size>0 gate passes.
        let branch_bytes = [0x00u8, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0];
        let summaries: Vec<_> = branch_bytes
            .iter()
            .map(|b| shard_summary(filter_bytes(*b), 1))
            .collect();
        reg.set_summaries(summaries);
        // The node starts with NO on-chain allocations — every join below is a
        // fresh allocation this single prover is about to acquire.
        reg.set_prover(prover(address.clone(), vec![]));

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let joined = proposed_join_filters(&actions);

        // THE REPRODUCTION: one prover, one cycle, MANY shards.
        assert!(
            joined.len() > 1,
            "expected one node to claim many shards at once, got {}",
            joined.len()
        );
        // Every claimed shard is distinct and on a different top-2-bit branch —
        // exactly the cross-branch overlap (|00∩01|) seen on mainnet.
        let mut branches: Vec<u8> = joined.iter().map(|f| f[0] >> 6).collect();
        branches.sort_unstable();
        branches.dedup();
        assert!(
            branches.len() > 1,
            "one prover should span multiple tree branches; spanned {:?}",
            branches
        );
        println!(
            "one prover proposed joins for {} shards across {} distinct branches \
             in a single cycle — this is the multi-allocation source",
            joined.len(),
            branches.len()
        );
    }

    // A split staged at frame 247 freezes three shards until it applies at
    // 304. The chain refuses a whole join that names one of them in that
    // window, so the other shards in it are never staffed either.
    #[test]
    fn a_shard_frozen_by_a_pending_split_is_not_proposed() {
        let address = vec![0xCEu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());
        for c in 1..=2u32 {
            wm.add(idle_worker(c));
        }
        let frozen = filter_bytes(0x00);
        let open = filter_bytes(0x80);
        reg.set_summaries(vec![shard_summary(frozen.clone(), 1), shard_summary(open.clone(), 1)]);
        reg.set_prover(prover(address.clone(), vec![]));
        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);
        lifecycle.set_frozen_shards(std::collections::HashSet::from([frozen.clone()]));

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert_eq!(proposed_join_filters(&actions), vec![open]);
    }

    /// SURPLUS-WORKER regime = the cascade. `lifecycle`'s join path has NO
    /// crowding gate (the ≤ HALT_RISK+1 gate lives in the LEAVE/coverage path,
    /// not here): a node fills every FREE worker with any shard it isn't already
    /// on, however crowded. So a beefy multi-worker node re-covers post-split
    /// children even at a healthy ~22 active — splitting sheds NO coverage,
    /// per-shard count rebounds, the >32 trigger re-arms. This is mainnet
    /// (|00∩01| = 45: nodes with spare workers on many different-branch shards).
    #[test]
    fn surplus_worker_node_recovers_post_split_children() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // Spare workers — MORE free workers than candidate shards.
        for c in 1..=8u32 {
            wm.add(idle_worker(c));
        }

        // Realistic post-split children: ~22/23 active each (a 45-prover shard
        // halved). Not halt-risk, not crowded — the "healthy" band.
        let child_a = filter_bytes(0x00);
        let child_b = filter_bytes(0x40);
        reg.set_summaries(vec![
            shard_summary(child_a.clone(), 22),
            shard_summary(child_b.clone(), 23),
        ]);
        reg.set_prover(prover(address.clone(), vec![]));

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let joined = proposed_join_filters(&actions);

        // Re-covers BOTH — coverage does not shed across a split. Multiply over
        // every spare-worker node and each child rebounds toward node-count →
        // >32 → re-split → cascade.
        assert!(
            joined.iter().any(|f| f == &child_a) && joined.iter().any(|f| f == &child_b),
            "surplus node should re-cover both children (no join crowding gate); got {:?}",
            joined
        );
        println!(
            "surplus-worker node re-covered BOTH post-split children (22/23 active) — \
             no join crowding gate, coverage doesn't shed → cascade"
        );
    }

    /// WORKER-CONSTRAINED regime = convergence — this is your 40-nodes/1-worker
    /// case. The join cap is the FREE-WORKER count. Give the node fewer free
    /// workers than candidate shards and it can only take a subset: with 1 free
    /// worker and 2 post-split children it joins exactly ONE, leaving the other
    /// at its reduced count. Aggregate: 40 one-worker nodes split 40→20/20 and
    /// STAY there, because none has a spare worker to re-cover the sibling. The
    /// distinguishing variable between cascade and convergence is free workers,
    /// not any threshold.
    #[test]
    fn worker_constrained_node_covers_only_a_subset() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // Exactly ONE free worker — fewer than the candidate shards.
        wm.add(idle_worker(1));

        let child_a = filter_bytes(0x00);
        let child_b = filter_bytes(0x40);
        reg.set_summaries(vec![
            shard_summary(child_a.clone(), 22),
            shard_summary(child_b.clone(), 23),
        ]);
        reg.set_prover(prover(address.clone(), vec![]));

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let joined = proposed_join_filters(&actions);

        // Capped at the single free worker → covers exactly ONE child. The
        // sibling keeps its reduced post-split coverage → split converges.
        assert_eq!(
            joined.len(),
            1,
            "one free worker must cap joins at 1 (constrained → converges); got {:?}",
            joined
        );
        println!(
            "worker-constrained node (1 free worker) covered only 1 of 2 children — \
             free-worker cap is what makes 40→20/20 STICK (convergence)"
        );
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
    fn rejected_join_is_backed_off_then_retried() {
        // A shard that recently rejected our join must NOT be re-proposed
        // until JOIN_REJECT_BACKOFF_FRAMES elapse — this breaks the
        // Joining↔Rejected oscillation that saturates workers with
        // never-confirming pending joins. After the backoff the shard is
        // eligible again.
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(idle_worker(1));
        wm.add(idle_worker(2));
        reg.set_summaries(vec![
            shard_summary(filter_bytes(0x01), 1),
            shard_summary(filter_bytes(0x02), 1),
        ]);
        // We hold a recently-Rejected allocation for 0x01 (rejected @ 90).
        let mut rejected = alloc(filter_bytes(0x01), ProverStatus::Rejected, 50);
        rejected.join_reject_frame_number = 90;
        reg.set_prover(prover(address.clone(), vec![rejected]));

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );

        let proposed = |actions: &[LifecycleAction]| -> Vec<Vec<u8>> {
            actions
                .iter()
                .filter_map(|a| match a {
                    LifecycleAction::ProposeJoin { filters, .. } => Some(filters.clone()),
                    _ => None,
                })
                .flatten()
                .collect()
        };

        // Within backoff (frame 100 < 90 + JOIN_REJECT_BACKOFF_FRAMES):
        // 0x01 must NOT be proposed.
        lifecycle.set_prover_root_verified_frame(100);
        let a = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let p = proposed(&a);
        assert!(
            !p.contains(&filter_bytes(0x01)),
            "recently-rejected shard 0x01 must be backed off; proposed={:?}",
            p
        );

        // Past the backoff: 0x01 is joinable again.
        let after = 90 + JOIN_REJECT_BACKOFF_FRAMES + 1;
        lifecycle.set_prover_root_verified_frame(after);
        let a = lifecycle.evaluate(after, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let p = proposed(&a);
        assert!(
            p.contains(&filter_bytes(0x01)),
            "shard 0x01 must be joinable again after the reject backoff; proposed={:?}",
            p
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
        // Evaluate well past SCORE_LEAVE_MIN_HOLD_FRAMES (360) so the
        // anti-churn dwell doesn't exempt these allocations (join_confirm
        // = 11) from score-driven leaves.
        lifecycle.set_prover_root_verified_frame(500);

        let actions = lifecycle.evaluate(500, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let proposed = count_proposed_leaves(&actions);
        assert!(
            proposed > 0,
            "expected ProposeLeave when allocated shards score below the threshold of unallocated alternatives; got {:?}",
            actions
        );
    }

    /// Regression: in degraded-coverage / prover-only mode the coverage
    /// view is stale, so halt-risk counts are false positives. Leave
    /// proposals (incl. the halt-risk swap) must be suppressed entirely —
    /// the exact same setup that proposes a leave above must propose NONE
    /// once `halt_state` reports halted.
    #[test]
    fn leaves_suppressed_in_prover_only_mode() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(allocated_worker(1, filter_bytes(0xA1)));
        wm.add(allocated_worker(2, filter_bytes(0xA2)));
        wm.add(allocated_worker(3, filter_bytes(0xA3)));

        reg.set_prover(prover(
            address.clone(),
            vec![
                alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
                alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
                alloc(filter_bytes(0xA3), ProverStatus::Active, 10),
            ],
        ));

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
        lifecycle.set_prover_root_verified_frame(500);
        // Degraded coverage → prover-only mode.
        lifecycle.halt_state().mark_halted(filter_bytes(0xC0));
        assert!(lifecycle.halt_state().any_halted());

        let actions = lifecycle.evaluate(500, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert_eq!(
            count_proposed_leaves(&actions),
            0,
            "no leaves may be proposed while halted (stale coverage → phantom \
             halt-risk); got {:?}",
            actions
        );
    }

    // Exercise the public evaluator with the same candidate demand over
    // multiple registry snapshots, rather than only testing one planner call.
    fn pending_replacement_fixture(halt_risk: bool) -> (
        Arc<ProverLifecycle>, Arc<ConfigurableRegistry>, Arc<ConfigurableWorkerManager>,
        Vec<u8>, Vec<ProverAllocationInfo>,
    ) {
        let address = vec![0xCD; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());
        let mut allocations = Vec::new();
        let mut summaries = Vec::new();
        for core in 1..=8 {
            let filter = filter_bytes(0xA0 + core as u8);
            wm.add(allocated_worker(core, filter.clone()));
            allocations.push(alloc(filter.clone(), ProverStatus::Active, 10));
            summaries.push(shard_summary(filter, 64));
        }
        // Tiny halt-risk destinations force the swap path, not score leaves.
        // Healthy, large destinations force score replacement instead.
        for byte in 0xC0..0xC4 {
            let mut summary = shard_summary(filter_bytes(byte), if halt_risk { 1 } else { 8 });
            summary.total_size = if halt_risk { 1 } else { 100_000_000 };
            summaries.push(summary);
        }
        let mut members = vec![prover(address.clone(), allocations.clone())];
        for byte in 0..63 { members.push(prover(vec![byte; 32], Vec::new())); }
        reg.set_provers(members);
        reg.set_summaries(summaries);
        let lc = make_lifecycle(address.clone(), wm.clone(), reg.clone());
        (lc, reg, wm, address, allocations)
    }

    fn proposed_leave_filters(actions: &[LifecycleAction]) -> Vec<Vec<u8>> {
        actions.iter().filter_map(|action| match action {
            LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
            _ => None,
        }).flatten().collect()
    }

    #[test]
    fn pending_replacement_leaves_do_not_fund_the_same_demand_again() {
        for halt_risk in [false, true] {
            let (lc, reg, wm, address, mut allocations) = pending_replacement_fixture(halt_risk);
            lc.set_prover_root_verified_frame(500);
            let first = proposed_leave_filters(&lc.evaluate(500, 1, reg.as_ref(), wm.as_ref()).unwrap());
            assert!(!first.is_empty(), "control must propose replacements, halt_risk={halt_risk}");
            assert!(first.len() < allocations.len());

            // Before registry publication, the submitted wave is in flight.
            lc.set_prover_root_verified_frame(504);
            assert!(proposed_leave_filters(&lc.evaluate(504, 1, reg.as_ref(), wm.as_ref()).unwrap()).is_empty(),
                "publication lag must not cause a second replacement wave");

            for a in &mut allocations {
                if first.contains(&a.confirmation_filter) {
                    a.status = ProverStatus::Leaving;
                    a.leave_frame_number = 500;
                }
            }
            reg.set_prover(prover(address.clone(), allocations.clone()));
            // Outlive the short publication cooldown: chain state must keep
            // the reservation alive, even after a process restart.
            let restarted = make_lifecycle(address.clone(), wm.clone(), reg.clone());
            restarted.set_prover_root_verified_frame(530);
            assert!(proposed_leave_filters(&restarted.evaluate(530, 1, reg.as_ref(), wm.as_ref()).unwrap()).is_empty(),
                "registered pending leaves must prevent further shedding");

            // Confirmed leaves serve notice through the next boundary. They
            // are absent from the leave-confirm bucket but still occupy cores.
            for a in &mut allocations {
                if first.contains(&a.confirmation_filter) {
                    a.leave_confirm_frame_number = 721;
                }
            }
            reg.set_prover(prover(address.clone(), allocations.clone()));
            restarted.set_prover_root_verified_frame(730);
            assert!(proposed_leave_filters(&restarted.evaluate(730, 1, reg.as_ref(), wm.as_ref()).unwrap()).is_empty(),
                "confirmed departures must remain reserved until the boundary");

            // Reconciliation releases their workers at the departure boundary.
            for core in 1..=8 {
                if first.contains(&filter_bytes(0xA0 + core as u8)) { wm.add(idle_worker(core)); }
            }
            restarted.set_prover_root_verified_frame(1441);
            let actions = restarted.evaluate(1441, 1, reg.as_ref(), wm.as_ref()).unwrap();
            assert!(count_proposed_joins(&actions) > 0, "freed cores must join destinations");
            assert_eq!(count_proposed_leaves(&actions), 0, "join before shedding more holdings");
        }
    }

    #[test]
    fn failed_replacement_leaves_release_the_reservation() {
        for registered in [false, true] {
            let (lc, reg, wm, address, mut allocations) = pending_replacement_fixture(false);
            lc.set_prover_root_verified_frame(500);
            let first = proposed_leave_filters(&lc.evaluate(500, 1, reg.as_ref(), wm.as_ref()).unwrap());
            assert!(!first.is_empty());
            if registered {
                for a in &mut allocations {
                    if first.contains(&a.confirmation_filter) {
                        // A rejected leave restores Active; it does not reject
                        // the allocation itself.
                        a.leave_frame_number = 500;
                        a.leave_reject_frame_number = 510;
                    }
                }
                reg.set_prover(prover(address.clone(), allocations));
            }
            lc.set_prover_root_verified_frame(530);
            assert!(count_proposed_leaves(&lc.evaluate(530, 1, reg.as_ref(), wm.as_ref()).unwrap()) > 0,
                "unpublished/rejected proposals must not reserve capacity forever");
        }
    }

    #[test]
    fn pending_replacement_leaves_preserve_cleanup_and_manual_independence() {
        let (lc, reg, wm, address, mut allocations) = pending_replacement_fixture(false);
        allocations[0].status = ProverStatus::Leaving;
        allocations[0].leave_frame_number = 500;
        let empty_filter = allocations[1].confirmation_filter.clone();
        reg.set_prover(prover(address.clone(), allocations.clone()));
        lc.set_local_shard_sizes(HashMap::from([(empty_filter.clone(), 0)]));
        lc.set_prover_root_verified_frame(530);
        let leaves = proposed_leave_filters(&lc.evaluate(530, 1, reg.as_ref(), wm.as_ref()).unwrap());
        assert_eq!(leaves, vec![empty_filter], "independent empty-shard cleanup still runs");

        // A manual worker's departure is not replacement capacity for the
        // auto-managed pool and must not stop that pool's decisions.
        let manual = WorkerInfo { manually_managed: true,
            ..allocated_worker(1, allocations[0].confirmation_filter.clone()) };
        wm.add(manual);
        let restarted = make_lifecycle(address, wm.clone(), reg.clone());
        restarted.set_prover_root_verified_frame(530);
        assert!(count_proposed_leaves(&restarted.evaluate(530, 1, reg.as_ref(), wm.as_ref()).unwrap()) > 0);
    }

    #[test]
    fn expired_replacement_leaves_do_not_block_the_remaining_workers() {
        let (lc, reg, wm, address, mut allocations) = pending_replacement_fixture(false);
        allocations[0].status = ProverStatus::Leaving;
        allocations[0].leave_frame_number = 500;
        reg.set_prover(prover(address, allocations));
        lc.set_prover_root_verified_frame(1441);
        assert!(count_proposed_leaves(&lc.evaluate(1441, 1, reg.as_ref(), wm.as_ref()).unwrap()) > 0,
            "an unconfirmed leave past its epoch window must not reserve capacity forever");
    }

    /// Per-filter Leave cooldown: a filter we just proposed Leave on
    /// must not be re-proposed until LEAVE_COOLDOWN_FRAMES have
    /// elapsed. Without the cooldown, every cycle within the
    /// publish→archive-materialize→registry-sync round-trip
    /// re-emits an identical Leave bundle for the same filters —
    /// observed as a 30+-minute loop of the
    /// same 3-filter ProposeLeave being emitted every 4 frames.
    #[test]
    fn leave_cooldown_suppresses_repeat_proposal_within_window() {
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

        // Same shape as `overcrowded_actives_get_leave_proposed`:
        // allocated 0xA1..0xA3 are deep-ring (low score), unallocated
        // 0xC0/0xC1 are ring 0 (high score). plan_leaves picks the
        // allocated below the 67% threshold.
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
        // Past the score-leave dwell (360) so allocations (join_confirm
        // = 11) are eligible for score-driven leaves.
        lifecycle.set_prover_root_verified_frame(500);

        // First cycle proposes leaves.
        let actions = lifecycle.evaluate(500, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let first_leaves: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            !first_leaves.is_empty(),
            "expected first cycle to produce ProposeLeave; got {:?}",
            actions,
        );

        // Second cycle, 4 frames later (well within LEAVE_COOLDOWN_FRAMES=20)
        // — must NOT re-propose Leave on the same filters.
        // Bump prover_root_verified_frame so the readiness gate passes.
        lifecycle.set_prover_root_verified_frame(504);
        let actions = lifecycle.evaluate(504, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let repeat_leaves: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        for f in &first_leaves {
            assert!(
                !repeat_leaves.contains(f),
                "filter {} re-proposed Leave within cooldown window; \
                 first_leaves={:?} repeat_leaves={:?}",
                hex::encode(f),
                first_leaves,
                repeat_leaves,
            );
        }
    }

    /// Per-filter Leave cooldown expires after LEAVE_COOLDOWN_FRAMES:
    /// once enough frames have passed, the same filter is eligible
    /// for Leave again. (Without this, a stuck Leave that never
    /// materializes would lock the filter forever.)
    #[test]
    fn leave_cooldown_expires_after_window() {
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
        // Past the score-leave dwell (360) so the allocations (join_confirm
        // = 11) are score-leave eligible.
        lifecycle.set_prover_root_verified_frame(500);
        let _ = lifecycle.evaluate(500, 1, reg.as_ref(), wm.as_ref()).unwrap();

        // After the cooldown window, the same filters should be
        // eligible again. (Use frame 500 + LEAVE_COOLDOWN_FRAMES.)
        let later_frame = 500 + LEAVE_COOLDOWN_FRAMES;
        lifecycle.set_prover_root_verified_frame(later_frame);
        let actions = lifecycle.evaluate(later_frame, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let leaves: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            !leaves.is_empty(),
            "expected Leave to be proposed again after LEAVE_COOLDOWN_FRAMES elapsed; got {:?}",
            actions,
        );
    }

    /// Per-filter Join cooldown: a filter we just proposed Join on
    /// must NOT be re-picked by `plan_and_allocate` within
    /// `JOIN_FILTER_COOLDOWN_FRAMES`. Without this, the 10-frame
    /// `PROPOSAL_TIMEOUT_FRAMES` (which clears the worker-level
    /// pending marker) lets the same filter get re-proposed via a
    /// different worker while the prior bundle is still on the wire
    /// — both eventually materialize and the registry ends up with
    /// excess Joining allocs (one per cycle) but only one worker
    /// slot, producing orphan Joining allocs.
    #[test]
    fn join_cooldown_suppresses_repeat_proposal_within_window() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // Two idle workers to make joins possible.
        wm.add(idle_worker(1));
        wm.add(idle_worker(2));

        // Empty prover info — no allocations yet.
        reg.set_prover(prover(address.clone(), vec![]));

        // Two attractive unallocated shards (high score). Both halt-
        // risk so they're prioritized by the join-side bucket pass.
        let crowded = |filter: Vec<u8>, active: u32, size: u64| {
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, active);
            ProverShardSummary { filter, status_counts: counts, total_size: size }
        };
        reg.set_summaries(vec![
            crowded(filter_bytes(0xC0), 1, 10_000_000),
            crowded(filter_bytes(0xC1), 1, 10_000_000),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        // First cycle proposes Joins.
        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let first_joins: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeJoin { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            !first_joins.is_empty(),
            "expected first cycle to produce ProposeJoin; got {:?}",
            actions,
        );

        // Second cycle 5 frames later (within JOIN_FILTER_COOLDOWN_FRAMES=30):
        // none of the just-proposed filters may be re-picked.
        // Bump prover_root_verified_frame so the readiness gate passes.
        lifecycle.set_prover_root_verified_frame(105);
        let actions = lifecycle.evaluate(105, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let repeat_joins: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeJoin { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        for f in &first_joins {
            assert!(
                !repeat_joins.contains(f),
                "filter {} re-proposed Join within cooldown window; \
                 first_joins={:?} repeat_joins={:?}",
                hex::encode(f),
                first_joins,
                repeat_joins,
            );
        }
    }

    /// Per-filter Join cooldown expires after JOIN_FILTER_COOLDOWN_FRAMES.
    /// If a published bundle never materializes (archive silently
    /// dropped it, network drop, etc.) we must eventually be able
    /// to re-attempt — otherwise the filter is locked out forever.
    #[test]
    fn join_cooldown_expires_after_window() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(idle_worker(1));
        reg.set_prover(prover(address.clone(), vec![]));

        let crowded = |filter: Vec<u8>, active: u32, size: u64| {
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, active);
            ProverShardSummary { filter, status_counts: counts, total_size: size }
        };
        reg.set_summaries(vec![crowded(filter_bytes(0xC0), 1, 10_000_000)]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);
        let _ = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();

        // After the cooldown window, the same filter is eligible
        // again. Frame 100 + JOIN_FILTER_COOLDOWN_FRAMES = 130.
        let later_frame = 100 + JOIN_FILTER_COOLDOWN_FRAMES;
        lifecycle.set_prover_root_verified_frame(later_frame);
        let actions = lifecycle.evaluate(later_frame, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let joins: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeJoin { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            !joins.is_empty(),
            "expected Join to be proposed again after JOIN_FILTER_COOLDOWN_FRAMES elapsed; got {:?}",
            actions,
        );
    }

    /// Regression: workers allocated to a shard with `Some(0)` in
    /// `merged_shard_sizes` (i.e. the size data is real and says the
    /// shard is empty) cannot leave via `plan_leaves` (score_shards
    /// skips size==0) or via the surplus-active path (no surplus when
    /// active count == worker count). The lifecycle's explicit
    /// empty-allocated leave path closes that gap. Go-divergent.
    #[test]
    fn empty_allocated_shard_triggers_leave_proposal() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(allocated_worker(1, filter_bytes(0xA1)));

        let allocs = vec![alloc(filter_bytes(0xA1), ProverStatus::Active, 10)];
        reg.set_prover(prover(address.clone(), allocs));
        // Summaries seed the cycle's size map via the test helper, but
        // we override remote sizes below so 0xA1 reads as Some(0).
        reg.set_summaries(vec![shard_summary(filter_bytes(0xA1), 1)]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        // Real "shard is empty" data point. The empty-allocated path
        // distinguishes this from `None` (no data yet, decision
        // deferred); the test would fail under the Go-aligned behavior
        // because score_shards would skip 0xA1 and plan_leaves would
        // emit nothing.
        let mut sizes = std::collections::HashMap::new();
        sizes.insert(filter_bytes(0xA1), 0u64);
        lifecycle.set_remote_shard_sizes(sizes);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let leave_filters: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            leave_filters.contains(&filter_bytes(0xA1)),
            "expected ProposeLeave for empty-allocated 0xA1; got {:?}",
            actions
        );
    }

    /// Inverse: `None` in the size map (no data yet) must NOT trigger
    /// the empty-allocated leave path. Only `Some(0)` does. This
    /// prevents a freshly-joined shard whose size hasn't arrived from
    /// the local size source yet from being prematurely abandoned.
    #[test]
    fn unknown_size_does_not_trigger_empty_leave() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(allocated_worker(1, filter_bytes(0xA1)));

        let allocs = vec![alloc(filter_bytes(0xA1), ProverStatus::Active, 10)];
        reg.set_prover(prover(address.clone(), allocs));
        reg.set_summaries(vec![shard_summary(filter_bytes(0xA1), 1)]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        // Replace the seeded remote sizes with an empty map so
        // `merged_shard_sizes.get(0xA1)` returns None.
        lifecycle.set_remote_shard_sizes(std::collections::HashMap::new());

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let leave_filters: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            !leave_filters.contains(&filter_bytes(0xA1)),
            "no leave should fire when size is None (no data yet); got {:?}",
            actions
        );
    }

    /// The leave sweep must stay reachable when epoch expiry empties the
    /// active bucket. The bound allocation can recover by re-confirming;
    /// only the unbound allocation should receive a Leave proposal.
    #[test]
    fn all_expired_allocations_still_propose_leave_for_the_unbound_one() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());
        let bound = filter_bytes(0xA1);
        let orphan = filter_bytes(0xA2);
        wm.add(allocated_worker(1, bound.clone()));
        let mut allocations = vec![
            alloc(bound.clone(), ProverStatus::Active, 10),
            alloc(orphan.clone(), ProverStatus::Active, 10),
        ];
        for allocation in &mut allocations {
            allocation.epoch = 5;
        }
        let frame = 6 * quil_types::consensus::EPOCH_LENGTH_FRAMES;
        let buckets = AllocationBuckets::from_allocations(&allocations, frame);
        assert!(buckets.active.is_empty());
        assert_eq!(buckets.expired_epoch.len(), 2);
        reg.set_prover(prover(address.clone(), allocations));
        reg.set_summaries(vec![
            shard_summary(bound.clone(), 10),
            shard_summary(orphan.clone(), 10),
        ]);
        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(frame);
        let actions = lifecycle.evaluate(frame, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let leaves: Vec<Vec<u8>> = actions.iter().filter_map(|action| match action {
            LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
            _ => None,
        }).flatten().collect();
        assert_eq!(leaves, vec![orphan], "expired orphan must remain reachable; got {actions:?}");
    }

    /// Over-capacity sheds by score, not by which allocation happens to
    /// hold a worker.
    ///
    /// User report: "extra allocation from earlier issues, in the TUI it
    /// shows as -1 for the worker id, never leaves successfully". The
    /// original fix shed every unbound Active filter unconditionally.
    /// That threw away value: bind order is decided by the allocator's
    /// arrival order, so the orphan is just as likely to be the best
    /// allocation the prover holds. Here 0xA3 is unbound *and* the
    /// highest-scoring of the three, so the worst-scoring 0xA1 goes
    /// instead and `rebind_surplus_by_priority` moves its worker onto
    /// 0xA3.
    #[test]
    fn overcapacity_sheds_the_worst_scoring_not_the_unbound() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // Two workers for three allocations. 0xA3 is the orphan.
        wm.add(allocated_worker(1, filter_bytes(0xA1)));
        wm.add(allocated_worker(2, filter_bytes(0xA2)));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA3), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        // Same prover count on all three (so ring, and therefore the
        // halt-risk shield, are identical) and score ordered purely by
        // size: 0xA1 worst, 0xA3 best.
        let sized = |filter: Vec<u8>, active: u32, size: u64| {
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, active);
            ProverShardSummary { filter, status_counts: counts, total_size: size }
        };
        reg.set_summaries(vec![
            sized(filter_bytes(0xA1), 10, 1_000_000),
            sized(filter_bytes(0xA2), 10, 5_000_000),
            sized(filter_bytes(0xA3), 10, 9_000_000),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let leave_filters: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            leave_filters.contains(&filter_bytes(0xA1)),
            "expected ProposeLeave for the worst-scoring 0xA1; got {:?}",
            actions
        );
        assert!(
            !leave_filters.contains(&filter_bytes(0xA3)),
            "must NOT shed the best-scoring allocation just because it is \
             unbound; got {:?}",
            actions
        );
    }

    /// Same shape, inverted: when the unbound allocation really is the
    /// worst one, it is the one shed. Without this the test above would
    /// pass for a rule that simply never sheds an orphan.
    #[test]
    fn overcapacity_sheds_the_unbound_when_it_is_the_worst() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(allocated_worker(1, filter_bytes(0xA1)));
        wm.add(allocated_worker(2, filter_bytes(0xA2)));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA3), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        let sized = |filter: Vec<u8>, active: u32, size: u64| {
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, active);
            ProverShardSummary { filter, status_counts: counts, total_size: size }
        };
        reg.set_summaries(vec![
            sized(filter_bytes(0xA1), 10, 9_000_000),
            sized(filter_bytes(0xA2), 10, 5_000_000),
            sized(filter_bytes(0xA3), 10, 1_000_000),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let leave_filters: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            leave_filters.contains(&filter_bytes(0xA3)),
            "expected ProposeLeave for the worst-scoring (and unbound) 0xA3; \
             got {:?}",
            actions
        );
    }

    /// An unbound allocation that fits inside worker capacity is a
    /// transient — the allocator's next reconcile binds a worker to it.
    /// Shedding it would throw away a live allocation to fix nothing.
    #[test]
    fn an_unbound_allocation_within_capacity_is_not_shed() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // Three workers, two allocations: 0xA2 is unbound but there is
        // an idle worker waiting for it.
        wm.add(allocated_worker(1, filter_bytes(0xA1)));
        wm.add(idle_worker(2));
        wm.add(idle_worker(3));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        let sized = |filter: Vec<u8>, active: u32, size: u64| {
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, active);
            ProverShardSummary { filter, status_counts: counts, total_size: size }
        };
        reg.set_summaries(vec![
            sized(filter_bytes(0xA1), 10, 1_000_000),
            sized(filter_bytes(0xA2), 10, 1_000_000),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert_eq!(
            count_proposed_leaves(&actions),
            0,
            "an orphan inside capacity must wait for a rebind, not be shed; \
             got {:?}",
            actions
        );
    }

    /// The halt-risk shield covers coverage we actually provide, so it
    /// applies to bound allocations only. 0xA1 is the worst-scoring
    /// allocation the prover holds and sits on a halt-risk shard, but a
    /// worker is running it, so it is protected; 0xA3 is on an equally
    /// thin shard with no worker, contributes no proofs, and goes.
    #[test]
    fn halt_risk_shield_covers_bound_allocations_only() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(allocated_worker(1, filter_bytes(0xA1)));
        wm.add(allocated_worker(2, filter_bytes(0xA2)));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA3), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        let sized = |filter: Vec<u8>, active: u32, size: u64| {
            let mut counts: HashMap<ProverStatus, u32> = HashMap::new();
            counts.insert(ProverStatus::Active, active);
            ProverShardSummary { filter, status_counts: counts, total_size: size }
        };
        reg.set_summaries(vec![
            sized(filter_bytes(0xA1), 3, 1_000),
            sized(filter_bytes(0xA2), 10, 50_000_000),
            sized(filter_bytes(0xA3), 3, 1_000),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();
        let leave_filters: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            !leave_filters.contains(&filter_bytes(0xA1)),
            "a bound allocation on a halt-risk shard keeps the shield even as \
             the worst scorer; got {:?}",
            actions
        );
        assert!(
            leave_filters.contains(&filter_bytes(0xA3)),
            "an unbound allocation on a halt-risk shard provides no coverage \
             and is sheddable; got {:?}",
            actions
        );
    }

    /// Orphan filters reaching the decide window must auto-confirm
    /// regardless of shard score. Without this they cycle propose →
    /// reject forever because `decide_leaves` rejects when the shard
    /// scores ≥ 67% of best alternative, which leaves a healthy-shard
    /// orphan stuck.
    #[test]
    fn orphan_leaving_filter_auto_confirms_at_window() {
        use quil_types::consensus::ProverAllocationInfo;
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // One worker bound to 0xA1 (kept healthy). Filter 0xA2 is an
        // orphan that's already Leaving and has matured past the
        // confirm window.
        wm.add(allocated_worker(1, filter_bytes(0xA1)));

        let leaving_alloc = ProverAllocationInfo {
            status: ProverStatus::Leaving,
            confirmation_filter: filter_bytes(0xA2),
            rejection_filter: vec![],
            join_frame_number: 10,
            leave_frame_number: 90,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 11,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            epoch: 0,
            ring: 0,
            vertex_address: vec![],
        };
        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            leaving_alloc,
        ];
        reg.set_prover(prover(address.clone(), allocs));

        // Make 0xA2 look healthy — same summary as 0xA1 + an even
        // better unallocated alternative. Without the orphan exception,
        // score-driven decide_leaves would reject the leave (0xA2's
        // score ≥ 67% of the best).
        reg.set_summaries(vec![
            shard_summary(filter_bytes(0xA1), 1),
            shard_summary(filter_bytes(0xA2), 1),
            shard_summary(filter_bytes(0xB0), 1),
        ]);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(800);
        // Epoch-aligned: leave_frame=90 is epoch 0, so the leave confirms in
        // epoch 1 — evaluate at frame 800 (epoch 1).
        let actions = lifecycle.evaluate(800, 1, reg.as_ref(), wm.as_ref()).unwrap();

        let confirm_filters: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::ConfirmLeaves { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let reject_filters: Vec<Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                LifecycleAction::RejectLeaves { filters, .. } => Some(filters.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            confirm_filters.contains(&filter_bytes(0xA2)),
            "orphan leave must auto-confirm; got confirms={:?} rejects={:?}",
            confirm_filters,
            reject_filters
        );
        assert!(
            !reject_filters.contains(&filter_bytes(0xA2)),
            "orphan leave must NOT be rejected; got {:?}",
            actions
        );
    }

    // Every regular node sheds the same healthy shards to cover four
    // unstaffed children, then rejects its own leave on score, epoch after
    // epoch. With a halt-risk shard waiting, the leavers the
    // shard can spare confirm and the rest stay.
    #[test]
    fn a_halt_risk_swap_leave_confirms_for_the_leavers_a_shard_can_spare() {
        use quil_types::consensus::ProverAllocationInfo;
        let healthy = filter_bytes(0xA2);
        let waiting = filter_bytes(0xB0);
        let leavers: Vec<Vec<u8>> = (0x10u8..0x16).map(|b| vec![b; 32]).collect();
        let leaving = |address: &Vec<u8>| {
            let mut info = prover(address.clone(), vec![ProverAllocationInfo {
                status: ProverStatus::Leaving,
                confirmation_filter: healthy.clone(),
                rejection_filter: vec![],
                join_frame_number: 10,
                leave_frame_number: 90,
                pause_frame_number: 0,
                resume_frame_number: 0,
                kick_frame_number: 0,
                join_confirm_frame_number: 11,
                join_reject_frame_number: 0,
                leave_confirm_frame_number: 0,
                leave_reject_frame_number: 0,
                last_active_frame_number: 0,
                epoch: 0,
                ring: 0,
                vertex_address: vec![],
            }]);
            info.status = ProverStatus::Leaving;
            info
        };
        let decide = |me: &Vec<u8>, with_waiting_shard: bool, idle_slot_owed: Option<bool>| {
            let wm = Arc::new(ConfigurableWorkerManager::new());
            let reg = Arc::new(ConfigurableRegistry::new());
            wm.add(allocated_worker(1, healthy.clone()));
            reg.set_provers(leavers.iter().map(leaving).collect());
            let mut summaries = vec![shard_summary(healthy.clone(), 0)];
            if let Some(owed) = idle_slot_owed {
                wm.add(idle_worker(2));
                if owed {
                    let held = filter_bytes(0xA3);
                    let mut ours = leaving(me);
                    ours.allocations.push(alloc(held.clone(), ProverStatus::Active, 10));
                    reg.set_prover(ours);
                    summaries.push(shard_summary(held, 10));
                }
            }
            if with_waiting_shard {
                summaries.push(shard_summary(waiting.clone(), 0));
            }
            reg.set_summaries(summaries);
            let lifecycle = make_lifecycle(
                me.clone(),
                wm.clone() as Arc<dyn WorkerManager>,
                reg.clone() as Arc<dyn ProverRegistry>,
            );
            lifecycle.set_prover_root_verified_frame(800);
            let actions = lifecycle.evaluate(800, 1, reg.as_ref(), wm.as_ref()).unwrap();
            let named = |confirm: bool| actions.iter().any(|a| match a {
                LifecycleAction::ConfirmLeaves { filters, .. } if confirm => filters.contains(&healthy),
                LifecycleAction::RejectLeaves { filters, .. } if !confirm => filters.contains(&healthy),
                _ => false,
            });
            (named(true), named(false))
        };
        let chosen = leavers.iter().find(|a| proposer::chosen_to_depart(a, &healthy, 0, &leavers)).unwrap();
        let spared = leavers.iter().find(|a| !proposer::chosen_to_depart(a, &healthy, 0, &leavers)).unwrap();
        assert_eq!(decide(chosen, true, None), (true, false), "a leaver the shard can spare departs");
        assert_eq!(decide(spared, true, None), (false, true), "the others stay");
        assert_eq!(decide(chosen, false, None), (false, true), "no waiting shard, no swap");
        assert_eq!(decide(chosen, true, Some(false)), (false, true), "a free slot covers the waiting shard without a swap");
        assert_eq!(decide(chosen, true, Some(true)), (true, false), "an idle worker owed to a held allocation cannot cover swap demand");
    }

    /// The propose side of the same swap: of six members of a healthy shard,
    /// only the three it can spare propose to leave it for a waiting
    /// halt-risk shard; the others' leaves would be rejected at the window.
    #[test]
    fn only_the_members_a_shard_can_spare_propose_a_swap_leave() {
        let healthy = filter_bytes(0xA2);
        let waiting = filter_bytes(0xB0);
        let members: Vec<Vec<u8>> = (0x20u8..0x26).map(|b| vec![b; 32]).collect();
        let active = |address: &Vec<u8>| prover(address.clone(), vec![alloc(healthy.clone(), ProverStatus::Active, 10)]);
        let proposes_leave = |me: &Vec<u8>| {
            let wm = Arc::new(ConfigurableWorkerManager::new());
            let reg = Arc::new(ConfigurableRegistry::new());
            wm.add(allocated_worker(1, healthy.clone()));
            reg.set_provers(members.iter().map(active).collect());
            reg.set_prover(active(me));
            reg.set_summaries(vec![shard_summary(healthy.clone(), members.len() as u32), shard_summary(waiting.clone(), 0)]);
            let lifecycle = make_lifecycle(
                me.clone(),
                wm.clone() as Arc<dyn WorkerManager>,
                reg.clone() as Arc<dyn ProverRegistry>,
            );
            lifecycle.set_prover_root_verified_frame(800);
            let mut sizes = std::collections::HashMap::new();
            sizes.insert(healthy.clone(), 100_000_000u64);
            sizes.insert(waiting.clone(), 1_000_000u64);
            lifecycle.set_remote_shard_sizes(sizes);
            let actions = lifecycle.evaluate(800, 1, reg.as_ref(), wm.as_ref()).unwrap();
            actions.iter().any(|a| matches!(a, LifecycleAction::ProposeLeave { filters, .. } if filters.contains(&healthy)))
        };
        let (spared, kept): (Vec<&Vec<u8>>, Vec<&Vec<u8>>) =
            members.iter().partition(|m| proposer::releasable_member(m, &healthy, &members));
        assert_eq!(spared.len(), members.len() - (proposer::HALT_RISK_PROVER_COUNT as usize + 1));
        for member in spared {
            assert!(proposes_leave(member), "a member the shard can spare swaps out");
        }
        for member in kept {
            assert!(!proposes_leave(member), "the others stay without proposing");
        }
    }

    // The same run: the workers the swaps freed all joined one of the four
    // empty shards. Each node's lifecycle now spreads its halt-risk picks.
    #[test]
    fn regular_nodes_spread_their_joins_over_the_empty_shards() {
        let pick = |address: Vec<u8>| {
            let wm = Arc::new(ConfigurableWorkerManager::new());
            let reg = Arc::new(ConfigurableRegistry::new());
            wm.add(idle_worker(1));
            // Distinct sizes, so score order alone would send every node to
            // the largest.
            reg.set_summaries((0u8..4).map(|b| ProverShardSummary {
                total_size: 100_000 * (b as u64 + 1),
                ..shard_summary(filter_bytes(0x40 + b), 0)
            }).collect());
            reg.set_prover(prover(address.clone(), vec![]));
            let lifecycle = make_lifecycle(
                address,
                wm.clone() as Arc<dyn WorkerManager>,
                reg.clone() as Arc<dyn ProverRegistry>,
            );
            lifecycle.set_prover_root_verified_frame(100);
            proposed_join_filters(&lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap())
        };
        let picked: std::collections::HashSet<Vec<Vec<u8>>> = (0u8..12).map(|b| pick(vec![b; 32])).collect();
        assert!(picked.len() > 1, "twelve nodes do not all join the same empty shard: {picked:?}");
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

    /// A worker with an empty filter is not necessarily a free slot.
    ///
    /// After a restart every worker starts unbound while the registry
    /// still holds every allocation from before; the allocator installs
    /// the filters on its next reconcile. A join cycle that clears its
    /// readiness gates first used to see a fully idle fleet and propose
    /// a second full set of joins on top of the set already held.
    ///
    /// Mainnet 2026-09-09: `free_workers=15 total_workers=15` while
    /// holding 13 Active allocations → a 14-filter join → 35 orphans 14
    /// seconds later, 12 of which were shed at the next epoch boundary.
    #[test]
    fn join_budget_excludes_slots_owed_to_unbound_allocations() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // Post-restart shape: every worker idle, every allocation still
        // held. Three slots, three allocations already owed them.
        wm.add(idle_worker(1));
        wm.add(idle_worker(2));
        wm.add(idle_worker(3));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA3), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        let mut summaries = vec![
            shard_summary(filter_bytes(0xA1), 1),
            shard_summary(filter_bytes(0xA2), 1),
            shard_summary(filter_bytes(0xA3), 1),
        ];
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
            proposed, 0,
            "every idle worker is already owed to a held allocation, so the \
             join budget is zero; got {} in {:?}",
            proposed, actions
        );
    }

    /// The control for the test above: the budget is a subtraction, not
    /// a blanket "never join while an allocation is unbound." With two
    /// slots more than allocations owed, exactly two joins go out.
    #[test]
    fn join_budget_is_free_workers_minus_unbound_allocations() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        for core in 1..=5u32 {
            wm.add(idle_worker(core));
        }

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA3), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        let mut summaries = vec![
            shard_summary(filter_bytes(0xA1), 1),
            shard_summary(filter_bytes(0xA2), 1),
            shard_summary(filter_bytes(0xA3), 1),
        ];
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
            proposed, 2,
            "5 idle workers less 3 allocations already owed a slot = 2; got \
             {} in {:?}",
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

    /// Regression: TUI's manual-join window flips workers to
    /// `manually_managed=true` *before* the matching alloc lands.
    /// Those workers are idle (filter empty) so absent from
    /// `mm_filters`. Old code subtracted them from `auto_capacity`
    /// while still counting all actives, falsely concluding "more
    /// allocs than auto workers can host" and proposing leaves on
    /// allocations whose intended worker was the just-flagged
    /// manual one.
    #[test]
    fn manual_idle_workers_do_not_trigger_phantom_surplus_leaves() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // 8 workers, 2 of which the operator just marked manual
        // (still idle — no filter assigned yet because the join
        // hasn't materialized).
        for i in 1..=6u32 {
            let f = filter_bytes(0xA0 + i as u8);
            wm.add(allocated_worker(i, f));
        }
        for i in 7..=8u32 {
            let mut w = idle_worker(i);
            w.manually_managed = true;
            wm.add(w);
        }

        // 6 existing Active allocations matching the auto workers.
        let mut allocs = Vec::new();
        let mut summaries = Vec::new();
        for i in 1..=6u8 {
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
        assert_eq!(
            count_proposed_leaves(&actions),
            0,
            "marking idle workers manual must not trigger phantom-surplus leaves"
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
        let current_frame = crate::current_frame::CurrentFrame::new();
        current_frame.observe(1); // test-harness seed; see make_lifecycle
        let lifecycle = Arc::new(ProverLifecycle::new(
            address,
            allocator,
            halt,
            current_frame,
            Strategy::RewardGreedy,
        ));
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

        // Joined in epoch 0 (frame 10), never confirmed in epoch 1 → by epoch 2
        // (eval frame 1440) the join is implicitly expired/rejected.
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
        lifecycle.set_prover_root_verified_frame(1440);

        let actions = lifecycle.evaluate(1440, 1, reg.as_ref(), wm.as_ref()).unwrap();

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

    fn count_confirms(actions: &[LifecycleAction]) -> Vec<Vec<u8>> {
        actions
            .iter()
            .flat_map(|a| match a {
                LifecycleAction::ConfirmJoins { filters, .. } => filters.clone(),
                _ => Vec::new(),
            })
            .collect()
    }

    fn count_reject_filters(actions: &[LifecycleAction]) -> Vec<Vec<u8>> {
        actions
            .iter()
            .flat_map(|a| match a {
                LifecycleAction::RejectJoins { filters, .. } => filters.clone(),
                _ => Vec::new(),
            })
            .collect()
    }

    fn manual_worker(core_id: u32, filter: Vec<u8>) -> WorkerInfo {
        WorkerInfo {
            core_id,
            filter,
            available_storage: 0,
            total_storage: 0,
            manually_managed: true,
            pending_filter_frame: 0,
            allocated: false,
        }
    }

    /// Gate: with `shard_info_loaded == false`, the lifecycle must
    /// emit zero ProposeJoin / ProposeLeave actions regardless of how
    /// good the candidates look. Confirms still run when their window
    /// matures.
    #[test]
    fn no_propose_paths_fire_without_shard_info_refresh() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        wm.add(idle_worker(1));
        wm.add(idle_worker(2));

        let mut summaries = Vec::new();
        for i in 1..=3u8 {
            summaries.push(shard_summary(filter_bytes(0xA0 + i), 1));
        }
        reg.set_prover(prover(address.clone(), Vec::new()));
        reg.set_summaries(summaries);

        // NOTE: deliberately NOT using `make_lifecycle` because that
        // helper flips `shard_info_loaded`. Build the lifecycle bare
        // so the gate is still false.
        let allocator = Arc::new(WorkerAllocator::new(
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
            address.clone(),
        ));
        let halt = Arc::new(HaltState::new());
        let current_frame = crate::current_frame::CurrentFrame::new();
        current_frame.observe(1); // test-harness seed; see make_lifecycle
        let lifecycle = ProverLifecycle::new(
            address,
            allocator,
            halt,
            current_frame,
            Strategy::RewardGreedy,
        );
        lifecycle.set_confirm_window_frames(2);
        lifecycle.set_sync_complete();
        lifecycle.set_prover_root_verified_frame(100);
        // Even with local shard sizes, the GetAppShards gate is closed.
        lifecycle.set_local_shard_sizes({
            let mut m = HashMap::new();
            m.insert(filter_bytes(0xA1), 1_000_000);
            m
        });

        assert!(!lifecycle.shard_info_loaded(), "gate must default to closed");

        let actions = lifecycle
            .evaluate(100, 1, reg.as_ref(), wm.as_ref())
            .unwrap();

        assert_eq!(
            count_proposed_joins(&actions),
            0,
            "ProposeJoin must not fire while GetAppShards gate is closed; got {:?}",
            actions
        );
        assert_eq!(
            count_proposed_leaves(&actions),
            0,
            "ProposeLeave must not fire while GetAppShards gate is closed; got {:?}",
            actions
        );

        // After set_remote_shard_sizes, the gate opens. (We re-supply the
        // same map to keep the test minimal.)
        let mut sizes = HashMap::new();
        for i in 1..=3u8 {
            sizes.insert(filter_bytes(0xA0 + i), 1_000_000);
        }
        lifecycle.set_remote_shard_sizes(sizes);
        assert!(lifecycle.shard_info_loaded(), "gate opens after set_remote_shard_sizes");

        // Bump verified frame so `tree_synced` passes at frame 101.
        lifecycle.set_prover_root_verified_frame(101);
        let actions2 = lifecycle
            .evaluate(101, 1, reg.as_ref(), wm.as_ref())
            .unwrap();
        assert!(
            count_proposed_joins(&actions2) > 0,
            "ProposeJoin should fire once gate is open and free workers exist; got {:?}",
            actions2
        );
    }

    /// A pending join on a shard the grid has since split is rejected, not
    /// confirmed: the chain no longer confirms it, and it holds the worker.
    #[test]
    fn a_pending_join_on_a_split_away_shard_is_rejected() {
        use quil_types::store::{KvDb as _, ShardInfo, ShardsStore};
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());
        let app = [0x13u8; 32];
        let root = app.to_vec();
        wm.add(WorkerInfo {
            core_id: 1, filter: root.clone(), available_storage: 0, total_storage: 0,
            manually_managed: false, pending_filter_frame: 0, allocated: false,
        });
        reg.set_prover(prover(address.clone(), vec![alloc(root.clone(), ProverStatus::Joining, 50)]));
        let mut status_counts = HashMap::new();
        status_counts.insert(ProverStatus::Joining, 1);
        reg.set_summaries(vec![ProverShardSummary { filter: root.clone(), status_counts, total_size: 5 }]);
        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(800);

        let evaluate = || lifecycle.evaluate(800, 1, reg.as_ref(), wm.as_ref()).unwrap();
        assert!(count_confirms(&evaluate()).contains(&root), "a live root's join is confirmed");

        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let shards: Arc<dyn ShardsStore> = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
        let mut grid = quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3).to_vec();
        grid.extend_from_slice(&app);
        for bit in [false, true] {
            let txn = db.new_batch(false).unwrap();
            shards.put_app_shard(txn.as_ref(), &ShardInfo {
                shard_key: grid.clone(), prefix: quil_forest::bit_path_to_prefix(&[bit]),
                size: vec![], data_shards: 0, commitment: vec![],
            }).unwrap();
            txn.commit().unwrap();
        }
        lifecycle.set_shards_store(shards);
        let actions = evaluate();
        assert!(count_reject_filters(&actions).contains(&root), "{actions:?}");
        assert!(!count_confirms(&actions).contains(&root), "{actions:?}");
    }

    fn put_grid(
        app: &[u8; 32],
        paths: &[&[bool]],
        change: Option<(quil_types::store::ShardChangeKind, Vec<u8>, Vec<Vec<u8>>)>,
    ) -> Arc<dyn quil_types::store::ShardsStore> {
        use quil_types::store::{KvDb as _, PendingShardChange, ShardInfo, ShardsStore};
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let shards: Arc<dyn ShardsStore> = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
        let mut shard_key = quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3).to_vec();
        shard_key.extend_from_slice(app);
        let txn = db.new_batch(false).unwrap();
        for path in paths {
            shards.put_app_shard(txn.as_ref(), &ShardInfo {
                shard_key: shard_key.clone(), prefix: quil_forest::bit_path_to_prefix(path),
                size: vec![], data_shards: 0, commitment: vec![],
            }).unwrap();
        }
        if let Some((kind, parent, children)) = change {
            shards.put_pending_shard_change(txn.as_ref(), &PendingShardChange {
                kind, parent, children, effective_epoch: 8, proposed_frame: 185,
            }).unwrap();
        }
        txn.commit().unwrap();
        shards
    }

    /// After a legacy merge, the registry synced the merged parent's moved
    /// allocations at frame 241, the local grid flipped at 243, and the
    /// archive sizes still named the children. Every member proposed a
    /// leave off the merged parent at 242 as a split-away parent, and it
    /// never formed a committee.
    #[test]
    fn a_merged_parent_is_not_left_before_every_view_catches_up() {
        let address = vec![0xCDu8; 32];
        let app = [0x19u8; 32];
        let parent = quil_forest::encode_shard_bit_path(&app, &[false]);
        let children = [false, true].map(|bit| quil_forest::encode_shard_bit_path(&app, &[false, bit])).to_vec();
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());
        wm.add(allocated_worker(1, parent.clone()));
        reg.set_prover(prover(address.clone(), vec![alloc(parent.clone(), ProverStatus::Active, 4)]));
        let mut historic = HashMap::new();
        historic.insert(ProverStatus::Historic, 4u32);
        reg.set_summaries(vec![
            shard_summary(parent.clone(), 8),
            ProverShardSummary { filter: children[0].clone(), status_counts: historic.clone(), total_size: 0 },
            ProverShardSummary { filter: children[1].clone(), status_counts: historic, total_size: 0 },
        ]);
        let lifecycle = make_lifecycle(address, wm.clone() as Arc<dyn WorkerManager>, reg.clone() as Arc<dyn ProverRegistry>);
        lifecycle.set_prover_root_verified_frame(242);
        let stale_sizes: HashMap<Vec<u8>, u64> = children.iter().map(|c| (c.clone(), 734u64)).collect();
        let leaves = |shards: Arc<dyn quil_types::store::ShardsStore>, sizes: &HashMap<Vec<u8>, u64>| {
            lifecycle.set_shards_store(shards);
            lifecycle.set_remote_shard_sizes(sizes.clone());
            let actions = lifecycle.evaluate(242, 1, reg.as_ref(), wm.as_ref()).unwrap();
            actions.iter().filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            }).flatten().collect::<Vec<_>>()
        };

        let merge = (quil_types::store::ShardChangeKind::Merge, parent.clone(), children.clone());
        let recorded = put_grid(&app, &[&[false, false], &[false, true]], Some(merge));
        assert!(!leaves(recorded.clone(), &stale_sizes).contains(&parent), "the refresh it asked for is pending");
        assert!(!leaves(recorded, &stale_sizes).contains(&parent), "a lagging archive's refresh omits it; the recorded merge names it");
        let flipped = put_grid(&app, &[&[false]], None);
        assert!(!leaves(flipped, &stale_sizes).contains(&parent), "the local grid holds it");
        let refreshed: HashMap<Vec<u8>, u64> = [(parent.clone(), 1468u64)].into_iter().collect();
        let stale_grid = put_grid(&app, &[&[false, false], &[false, true]], None);
        assert!(!leaves(stale_grid.clone(), &refreshed).contains(&parent), "the archive sizes hold it");
        assert!(!leaves(stale_grid.clone(), &stale_sizes).contains(&parent), "the sizes lack a live shard: wait for the refresh");
        assert!(leaves(stale_grid, &stale_sizes).contains(&parent), "a parent every view shows split, after a refresh, is left");
    }

    /// Mainnet's merged parents: a legacy merge moves only committee
    /// members, so the retired children keep live Joining and expired
    /// allocations in the registry. Counted as shards, they made each merged
    /// parent a split-away parent that no regular would join.
    #[test]
    fn allocations_left_on_a_retired_child_do_not_hide_its_merged_parent() {
        let address = vec![0xCDu8; 32];
        let app = [0x1Au8; 32];
        let parent = quil_forest::encode_shard_bit_path(&app, &[true]);
        let retired = quil_forest::encode_shard_bit_path(&app, &[true, false]);
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());
        wm.add(idle_worker(1));
        reg.set_prover(prover(address.clone(), vec![]));
        let mut leftover = HashMap::new();
        leftover.insert(ProverStatus::Joining, 2u32);
        reg.set_summaries(vec![
            shard_summary(parent.clone(), 3),
            ProverShardSummary { filter: retired.clone(), status_counts: leftover, total_size: 0 },
        ]);
        let lifecycle = make_lifecycle(address, wm.clone() as Arc<dyn WorkerManager>, reg.clone() as Arc<dyn ProverRegistry>);
        lifecycle.set_prover_root_verified_frame(900);
        let sizes: HashMap<Vec<u8>, u64> = [(parent.clone(), 1_000_000u64)].into_iter().collect();
        lifecycle.set_remote_shard_sizes(sizes.clone());
        let joins = || {
            let actions = lifecycle.evaluate(900, 1, reg.as_ref(), wm.as_ref()).unwrap();
            actions.iter().filter_map(|a| match a {
                LifecycleAction::ProposeJoin { filters, .. } => Some(filters.clone()),
                _ => None,
            }).flatten().collect::<Vec<_>>()
        };

        assert!(!joins().contains(&parent), "until a refresh, the leftover allocations look like a live child");
        assert!(lifecycle.wants_shard_info_refresh(), "the unsized child asks for a refresh");
        lifecycle.set_remote_shard_sizes(sizes);
        assert!(joins().contains(&parent), "a refresh without the child retires it");
    }

    /// The provers holding those leftover allocations run a shard the chain
    /// no longer credits; each leaves it once every view agrees it retired.
    #[test]
    fn an_allocation_on_a_retired_child_is_left() {
        use quil_types::store::ShardChangeKind::Split;
        let address = vec![0xCDu8; 32];
        let app = [0x1Bu8; 32];
        let parent = quil_forest::encode_shard_bit_path(&app, &[true]);
        let retired = quil_forest::encode_shard_bit_path(&app, &[true, false]);
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());
        wm.add(allocated_worker(1, retired.clone()));
        reg.set_prover(prover(address.clone(), vec![alloc(retired.clone(), ProverStatus::Active, 4)]));
        reg.set_summaries(vec![shard_summary(parent.clone(), 3), shard_summary(retired.clone(), 2)]);
        let lifecycle = make_lifecycle(address, wm.clone() as Arc<dyn WorkerManager>, reg.clone() as Arc<dyn ProverRegistry>);
        lifecycle.set_prover_root_verified_frame(900);
        let sizes: HashMap<Vec<u8>, u64> = [(parent.clone(), 1_000_000u64)].into_iter().collect();
        let leaves = |shards: Arc<dyn quil_types::store::ShardsStore>| {
            lifecycle.set_shards_store(shards);
            lifecycle.set_remote_shard_sizes(sizes.clone());
            let actions = lifecycle.evaluate(900, 1, reg.as_ref(), wm.as_ref()).unwrap();
            actions.iter().filter_map(|a| match a {
                LifecycleAction::ProposeLeave { filters, .. } => Some(filters.clone()),
                _ => None,
            }).flatten().collect::<Vec<_>>()
        };

        let merged = put_grid(&app, &[&[true]], None);
        assert!(!leaves(merged.clone()).contains(&retired), "the refresh it asked for is pending");
        let splitting = put_grid(&app, &[&[true]], Some((Split, parent.clone(), vec![retired.clone()])));
        assert!(!leaves(splitting).contains(&retired), "a recorded split creates it");
        assert!(!leaves(put_grid(&app, &[&[true, false]], None)).contains(&retired), "the local grid lists it");
        assert!(leaves(merged).contains(&retired), "no view lists it");
    }

    /// Manual-bucket confirm: when a Joining alloc reaches confirm
    /// window AND its filter is bound to a manually_managed worker,
    /// the lifecycle confirms it unconditionally — no score-based
    /// reject even if a higher-scoring alternative exists.
    #[test]
    fn manual_bound_join_confirms_at_window_without_score_reject() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        let manual_filter = filter_bytes(0xA1);
        // Worker 1 is manually pinned to the alloc confirmed below.
        wm.add(manual_worker(1, manual_filter.clone()));

        // Alloc is Joining (proposed epoch 0, join_frame 50); confirms in epoch 1.
        let allocs = vec![alloc(manual_filter.clone(), ProverStatus::Joining, 50)];
        reg.set_prover(prover(address.clone(), allocs));

        // Add a competing summary with higher size — would normally
        // beat the manual filter on score-greedy reward ranking and
        // cause a reject in auto mode.
        let mut summaries = vec![ProverShardSummary {
            filter: manual_filter.clone(),
            status_counts: {
                let mut m = HashMap::new();
                m.insert(ProverStatus::Joining, 1);
                m
            },
            total_size: 1, // tiny — would lose score-greedy
        }];
        summaries.push(shard_summary(filter_bytes(0xB1), 5));
        reg.set_summaries(summaries);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(800);

        // Epoch 1 → the epoch-0 join is in its confirm slot.
        let actions = lifecycle
            .evaluate(800, 1, reg.as_ref(), wm.as_ref())
            .unwrap();

        let confirms = count_confirms(&actions);
        let rejects = count_reject_filters(&actions);

        assert!(
            confirms.contains(&manual_filter),
            "manual-bound alloc must be in confirm set regardless of score; got confirms={:?}, rejects={:?}",
            confirms, rejects
        );
        assert!(
            !rejects.contains(&manual_filter),
            "manual-bound alloc must NEVER be score-rejected; got rejects={:?}",
            rejects
        );
    }

    /// Per-message 100-filter cap is enforced even when the manual
    /// bucket alone exceeds it. The combined Confirm/Reject lists
    /// must not exceed `MAX_PROPOSALS_PER_CYCLE`. Truncated filters
    /// stay Joining and are re-evaluated next frame.
    #[test]
    fn bucketed_confirms_respect_100_filter_cap() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // 150 manual workers, each pinned to a unique filter. All
        // are unallocated, so available_workers = 150.
        let mut filters = Vec::with_capacity(150);
        for i in 0..150u32 {
            // Filter bytes: i serialized into a 4-byte head + zeros.
            let mut f = i.to_be_bytes().to_vec();
            f.resize(8, 0);
            filters.push(f.clone());
            wm.add(manual_worker(i + 1, f));
        }

        // 150 ready Joining allocs.
        let mut allocs = Vec::with_capacity(150);
        let mut summaries = Vec::with_capacity(150);
        for f in &filters {
            allocs.push(alloc(f.clone(), ProverStatus::Joining, 50));
            summaries.push(ProverShardSummary {
                filter: f.clone(),
                status_counts: {
                    let mut m = HashMap::new();
                    m.insert(ProverStatus::Joining, 1);
                    m
                },
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
        lifecycle.set_prover_root_verified_frame(800);

        // Epoch 1 → all 150 epoch-0 joins are in their confirm slot.
        let actions = lifecycle
            .evaluate(800, 1, reg.as_ref(), wm.as_ref())
            .unwrap();

        let confirms = count_confirms(&actions);
        assert!(
            confirms.len() <= MAX_PROPOSALS_PER_CYCLE,
            "ConfirmJoins must respect 100-filter cap, got {}",
            confirms.len()
        );
        let rejects = count_reject_filters(&actions);
        assert!(
            rejects.len() <= MAX_PROPOSALS_PER_CYCLE,
            "RejectJoins must respect 100-filter cap, got {}",
            rejects.len()
        );
    }

    /// Manual-bucket capacity overflow: more manual-bound Joining
    /// allocs than `available_workers` triggers a capacity-only
    /// reject of the lexicographically-latest excess (deterministic
    /// ordering for cross-node consistency).
    #[test]
    fn manual_bound_join_capacity_overflow_rejects_excess() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        let f1 = filter_bytes(0xA1);
        let f2 = filter_bytes(0xA2);
        let f3 = filter_bytes(0xA3);

        // Three manually-pinned workers but only 2 are not yet
        // allocated. available_workers = count(workers where
        // !allocated) so we deliberately mark one as allocated.
        let mut w1 = manual_worker(1, f1.clone());
        w1.allocated = true; // already serving — consumes capacity
        wm.add(w1);
        wm.add(manual_worker(2, f2.clone()));
        wm.add(manual_worker(3, f3.clone()));

        // Three Joining allocs, all manual-bound, all ready.
        let allocs = vec![
            alloc(f1.clone(), ProverStatus::Joining, 50),
            alloc(f2.clone(), ProverStatus::Joining, 50),
            alloc(f3.clone(), ProverStatus::Joining, 50),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        let mut summaries = Vec::new();
        for f in [&f1, &f2, &f3] {
            summaries.push(ProverShardSummary {
                filter: f.clone(),
                status_counts: {
                    let mut m = HashMap::new();
                    m.insert(ProverStatus::Joining, 1);
                    m
                },
                total_size: 1_000_000,
            });
        }
        reg.set_summaries(summaries);

        let lifecycle = make_lifecycle(
            address,
            wm.clone() as Arc<dyn WorkerManager>,
            reg.clone() as Arc<dyn ProverRegistry>,
        );
        lifecycle.set_prover_root_verified_frame(800);

        // Epoch 1 → the three epoch-0 joins are in their confirm slot.
        let actions = lifecycle
            .evaluate(800, 1, reg.as_ref(), wm.as_ref())
            .unwrap();

        let confirms = count_confirms(&actions);
        let rejects = count_reject_filters(&actions);

        // 2 available workers → confirm 2 (lexicographically first),
        // reject 1.
        assert_eq!(confirms.len(), 2, "expected 2 confirms, got {:?}", confirms);
        assert_eq!(rejects.len(), 1, "expected 1 reject, got {:?}", rejects);
        // Lexicographic order: f1, f2, f3 — so the LAST one (f3) is rejected.
        assert_eq!(rejects[0], f3, "expected lexicographically-last filter rejected");
    }
}

/// End-to-end halt-risk descriptor build path: synthesize
/// `ProverShardSummary` inputs that model the registry's live view
/// after live-status filtering, then run them through
/// `build_proposal_descriptors` and the proposer's halt-risk bucket.
///
/// Pins the upstream link in the user-reported bug: a shard with N
/// real provers but stale/expired allocations must NOT have those
/// dead allocations inflate `total_active_joining` past the halt-risk
/// threshold — that was the failure mode causing the proposer to
/// skip real halt-risk shards and pile onto healthy ones. With
/// `get_prover_shard_summaries` now applying the live-status filter,
/// the summaries reaching `build_proposal_descriptors` carry only
/// live counts, and the halt-risk bucket sees the right set.
#[cfg(test)]
mod halt_risk_descriptor_tests {
    use super::*;
    use std::collections::HashMap;
    use num_bigint::BigInt;
    use quil_types::consensus::{ProverShardSummary, ProverStatus};
    use crate::provers::proposer::{plan_and_allocate, Strategy, HALT_RISK_PROVER_COUNT};

    fn summary(filter: &[u8], counts: &[(ProverStatus, u32)]) -> ProverShardSummary {
        let mut status_counts = HashMap::new();
        for (status, n) in counts {
            status_counts.insert(*status, *n);
        }
        let total_size: u64 = status_counts.values().map(|&c| c as u64).sum();
        ProverShardSummary {
            filter: filter.to_vec(),
            status_counts,
            total_size,
        }
    }

    fn sizes(entries: &[(&[u8], u64)]) -> HashMap<Vec<u8>, u64> {
        entries.iter().map(|(f, s)| (f.to_vec(), *s)).collect()
    }

    /// A shard whose registry view shows 3 Active provers should
    /// arrive at `plan_and_allocate` with `total_active_joining = 3`
    /// — at-or-below the halt-risk threshold — and get picked ahead
    /// of a healthy 8-Active shard that has higher reward score.
    #[test]
    fn build_descriptors_surfaces_halt_risk_at_three_active() {
        let halt_filter: &[u8] = b"halt-shard\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let healthy_filter: &[u8] = b"healthy-shard\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let summaries = vec![
            summary(halt_filter, &[(ProverStatus::Active, 3)]),
            summary(healthy_filter, &[(ProverStatus::Active, 8)]),
        ];
        let shard_sizes = sizes(&[
            (halt_filter, 500_000),
            (healthy_filter, 10_000_000),
        ]);
        let our_filters: Vec<Vec<u8>> = Vec::new();
        let shards_store_filters: Vec<Vec<u8>> = Vec::new();

        let descriptors = super::build_proposal_descriptors(
            &summaries,
            &our_filters,
            &shard_sizes,
            &shards_store_filters,
        );
        assert_eq!(descriptors.len(), 2);

        let halt = descriptors.iter().find(|d| d.filter == halt_filter).unwrap();
        let healthy = descriptors.iter().find(|d| d.filter == healthy_filter).unwrap();
        assert_eq!(halt.total_active_joining, 3, "halt-risk shard prover count");
        assert_eq!(healthy.total_active_joining, 8, "healthy shard prover count");
        assert!(halt.total_active_joining <= HALT_RISK_PROVER_COUNT);
        assert!(healthy.total_active_joining > HALT_RISK_PROVER_COUNT);

        let proposals = plan_and_allocate(
            &descriptors,
            50_000,
            &BigInt::from(20_000_000u64),
            1_000_000,
            &[0],
            1,
            Strategy::RewardGreedy,
            None,
        );
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            proposals[0].filter, halt_filter,
            "halt-risk shard must be picked before the healthier reward shard"
        );
    }

    /// `total_active_joining` is the sum of Active + Joining only —
    /// Leaving and Paused do not delay halt-risk classification.
    /// Verifies the descriptor build path applies that arithmetic
    /// (since Leaving/Paused provers aren't producing or imminently
    /// going to produce, counting them would mask a real halt-risk).
    #[test]
    fn build_descriptors_excludes_leaving_and_paused_from_halt_count() {
        let filter: &[u8] = b"mixed-shard\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        // 3 Active + 5 Leaving + 5 Paused. Total live = 13, but
        // Active+Joining = 3 → still halt-risk.
        let summaries = vec![summary(
            filter,
            &[
                (ProverStatus::Active, 3),
                (ProverStatus::Leaving, 5),
                (ProverStatus::Paused, 5),
            ],
        )];
        let shard_sizes = sizes(&[(filter, 500_000)]);
        let our_filters: Vec<Vec<u8>> = Vec::new();
        let shards_store_filters: Vec<Vec<u8>> = Vec::new();

        let descriptors = super::build_proposal_descriptors(
            &summaries,
            &our_filters,
            &shard_sizes,
            &shards_store_filters,
        );
        assert_eq!(descriptors.len(), 1);
        assert_eq!(
            descriptors[0].total_active_joining, 3,
            "Leaving and Paused must not inflate the halt-risk count"
        );
        assert!(descriptors[0].total_active_joining <= HALT_RISK_PROVER_COUNT);
    }

    /// Joining counts toward the halt-risk denominator — pending
    /// joiners are imminent producers. 1 Active + 3 Joining = 4 is
    /// just past the threshold; the shard should NOT be classified
    /// as halt-risk.
    #[test]
    fn build_descriptors_joining_counts_toward_threshold() {
        let filter: &[u8] = b"joining-shard\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let summaries = vec![summary(
            filter,
            &[
                (ProverStatus::Active, 1),
                (ProverStatus::Joining, 3),
            ],
        )];
        let shard_sizes = sizes(&[(filter, 500_000)]);
        let our_filters: Vec<Vec<u8>> = Vec::new();
        let shards_store_filters: Vec<Vec<u8>> = Vec::new();

        let descriptors = super::build_proposal_descriptors(
            &summaries,
            &our_filters,
            &shard_sizes,
            &shards_store_filters,
        );
        assert_eq!(descriptors[0].total_active_joining, 4);
        assert!(
            descriptors[0].total_active_joining > HALT_RISK_PROVER_COUNT,
            "1 Active + 3 Joining = 4 is past the halt-risk threshold of {}",
            HALT_RISK_PROVER_COUNT
        );
    }

    /// Shards with no real byte-size data are dropped at descriptor
    /// build time even when the summary shows live provers. Without
    /// this, the proposer would chase shards whose archive doesn't
    /// yet have size info reported — wasted joins.
    #[test]
    fn build_descriptors_drops_zero_size_halt_risk_shards() {
        let filter_no_size: &[u8] = b"no-size-shard\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let filter_real: &[u8] = b"real-shard\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let summaries = vec![
            summary(filter_no_size, &[(ProverStatus::Active, 2)]),
            summary(filter_real, &[(ProverStatus::Active, 2)]),
        ];
        let shard_sizes = sizes(&[(filter_real, 500_000)]); // no entry for filter_no_size
        let our_filters: Vec<Vec<u8>> = Vec::new();
        let shards_store_filters: Vec<Vec<u8>> = Vec::new();

        let descriptors = super::build_proposal_descriptors(
            &summaries,
            &our_filters,
            &shard_sizes,
            &shards_store_filters,
        );
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].filter, filter_real);
    }
}

#[cfg(test)]
mod orphan_leave_tests {
    use super::*;
    use quil_types::consensus::{EffectiveStatus, ProverAllocationInfo, ProverStatus};

    fn set(filters: &[&[u8]]) -> std::collections::HashSet<Vec<u8>> {
        filters.iter().map(|f| f.to_vec()).collect()
    }

    fn none() -> std::collections::HashSet<Vec<u8>> {
        std::collections::HashSet::new()
    }

    /// An Active allocation held for `epoch`, i.e. one that reads ExpiredEpoch
    /// once the chain passes that epoch.
    fn active_alloc(filter: u8, epoch: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: vec![filter],
            rejection_filter: Vec::new(),
            join_frame_number: 0,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            epoch,
            ring: 0,
            vertex_address: Vec::new(),
        }
    }

    /// THE BUG THIS GUARDS. An orphan's own orphanhood is what expires it: no
    /// worker means no proofs, so it misses the per-epoch re-confirm and leaves
    /// the `active` bucket. Sweeping `active` alone gave the orphan sweep a
    /// single epoch of reach, after which the allocation was stuck forever —
    /// the state behind "35 allocations, 15 workers, 20 reading `re-confirm!`,
    /// no Leave ever proposed".
    #[test]
    fn an_orphan_that_outlived_its_epoch_is_still_proposed_for_leave() {
        let bound = vec![0x01u8];
        let orphan = vec![0x02u8];

        // Both allocations registered for epoch 5; the chain is now in epoch 6.
        let allocs = vec![active_alloc(0x01, 5), active_alloc(0x02, 5)];
        let frame = 6 * quil_types::consensus::EPOCH_LENGTH_FRAMES;
        let buckets = AllocationBuckets::from_allocations(&allocs, frame);

        // Precondition: expiry has emptied `active`, which is exactly why the
        // old `active`-only sweep saw nothing to shed.
        assert!(
            buckets.active.is_empty(),
            "an allocation past its registered epoch must not count for coverage",
        );
        assert_eq!(buckets.expired_epoch.len(), 2);

        let orphans = orphaned_allocation_filters(
            &buckets.active,
            &buckets.expired_epoch,
            &set(&[&bound]),
            &none(),
            &none(),
        );
        assert_eq!(orphans, vec![orphan], "only the unbound one is shed");
    }

    /// The sweep must not shed what is being worked. An ExpiredEpoch allocation
    /// WITH a worker is recoverable by re-confirming, so it is not an orphan.
    #[test]
    fn an_expired_allocation_with_a_worker_is_not_an_orphan() {
        let filter = vec![0x07u8];
        let orphans = orphaned_allocation_filters(
            &[],
            &[filter.clone()],
            &set(&[&filter]),
            &none(),
            &none(),
        );
        assert!(orphans.is_empty());
    }

    /// Operator pins and in-flight Leaves still win, on the expired path as
    /// much as the active one — otherwise widening the sweep would start
    /// re-publishing Leaves for allocations already on their way out.
    #[test]
    fn pinned_and_already_leaving_expired_allocations_are_left_alone() {
        let pinned = vec![0x03u8];
        let leaving = vec![0x04u8];
        let shed = vec![0x05u8];
        let expired = vec![pinned.clone(), leaving.clone(), shed.clone()];

        let orphans = orphaned_allocation_filters(
            &[],
            &expired,
            &none(),
            &set(&[&pinned]),
            &set(&[&leaving]),
        );
        assert_eq!(orphans, vec![shed]);
    }

    /// An allocation can be in both buckets across a boundary; it must be
    /// proposed once, not twice — a duplicated filter would inflate the
    /// per-cycle proposal budget and the orphan count in the log line.
    #[test]
    fn a_filter_in_both_buckets_is_proposed_once() {
        let f = vec![0x09u8];
        let orphans = orphaned_allocation_filters(
            &[f.clone()],
            &[f.clone()],
            &none(),
            &none(),
            &none(),
        );
        assert_eq!(orphans, vec![f]);
    }

    /// Sanity on the status mapping the sweep depends on: an unbound
    /// allocation stays on-chain Active, so a Leave is a valid thing to
    /// propose for it. It is only the DERIVED status that reads expired.
    #[test]
    fn an_expired_allocation_is_still_on_chain_active() {
        let a = active_alloc(0x01, 5);
        let frame = 6 * quil_types::consensus::EPOCH_LENGTH_FRAMES;
        assert_eq!(a.effective_status(frame), EffectiveStatus::ExpiredEpoch);
        assert_eq!(a.status, ProverStatus::Active);
    }
}
