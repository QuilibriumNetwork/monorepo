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

/// Allocations partitioned by their effective status at a given
/// frame. Lifecycle's `evaluate` collects these once and dispatches
/// each downstream subroutine against the appropriate slice. Pulling
/// the partitioning out of the inline match expression makes it
/// testable in isolation — important because mis-bucketing has been
/// a recurring source of regressions (bug #14, #15 in the v2.1.0.20
/// branch — `tree.Delete` was wrongly removing expired Joining
/// allocs that should have been bucketed as ExpiredJoining and left
/// alone).
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
        use quil_types::consensus::EffectiveStatus;
        let mut buckets = AllocationBuckets::default();
        for alloc in allocations {
            match alloc.effective_status(frame_number) {
                EffectiveStatus::Joining => {
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                    buckets
                        .joining
                        .push((alloc.confirmation_filter.clone(), alloc.join_frame_number));
                }
                EffectiveStatus::Active => {
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                    buckets.active.push(alloc.confirmation_filter.clone());
                }
                EffectiveStatus::Leaving => {
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                    buckets.leaving.push((
                        alloc.confirmation_filter.clone(),
                        alloc.leave_frame_number,
                    ));
                }
                EffectiveStatus::Paused => {
                    // We still own the alloc — keep it in `all_ours`
                    // so the proposer doesn't re-propose joining the
                    // same shard — but neither active (no
                    // surplus/leave pressure) nor joining/leaving
                    // (no decide-pending action).
                    buckets.all_ours.push(alloc.confirmation_filter.clone());
                }
                // Terminal / past-grace. Treat as "doesn't exist":
                // don't push anywhere, otherwise these would leak
                // into `allocated_descriptors` and `plan_leaves`
                // may emit a Leave for an allocation that's already
                // terminal on-chain.
                EffectiveStatus::ExpiredJoining
                | EffectiveStatus::ExpiredLeaving
                | EffectiveStatus::Rejected
                | EffectiveStatus::Kicked
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
    /// No coverage halt is currently active. While halted, the
    /// lifecycle defers all propose/confirm actions to avoid making
    /// allocation decisions on stale shard data.
    pub no_halt: bool,
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
    local_shard_sizes: RwLock<HashMap<Vec<u8>, u64>>,
    /// Per-shard byte sizes from the most recent successful
    /// `GetAppShards` archive fetch. Authoritative for shards we are
    /// NOT allocated to (the local cache would have 0 / missing
    /// entries for those). Refreshed every 60 frames or on first-
    /// success by the `shard_info_refresh` task; setting it flips the
    /// `shard_info_loaded` gate.
    remote_shard_sizes: RwLock<HashMap<Vec<u8>, u64>>,
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
            confirm_window_frames: AtomicU64::new(DEFAULT_CONFIRM_WINDOW_FRAMES),
            shards_store: RwLock::new(None),
            shard_info_loaded: AtomicBool::new(false),
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
        if let Ok(mut guard) = self.remote_shard_sizes.write() {
            *guard = sizes;
        }
        self.shard_info_loaded.store(true, Ordering::Relaxed);
    }

    /// Merged read of the two size caches. Remote entries form the
    /// base map (authoritative for shards we're not on); local
    /// entries override / fill in (authoritative for shards we
    /// hold). Cloned per call — typical map sizes are O(thousands)
    /// at most, called once per `evaluate` (~10 s cadence), so the
    /// alloc cost is negligible. Returned by value so callers
    /// don't hold either lock during proposal building.
    pub fn merged_shard_sizes(&self) -> HashMap<Vec<u8>, u64> {
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

        // Orphan active filters (no worker bound, not operator-pinned)
        // are always the right answer to shed capacity-pressure: no
        // worker does the work, so leaving them costs nothing. Pick
        // them first; only fall back to lowest-scoring auto-bound when
        // surplus exceeds the orphan count. This protects healthy
        // bound filters from being evicted ahead of a stale orphan.
        let mut picks: Vec<Vec<u8>> = active_filters
            .iter()
            .filter(|f| !bound_filters.contains(*f))
            .filter(|f| !mm_filters.contains(*f))
            .take(surplus)
            .cloned()
            .collect();

        if picks.len() < surplus {
            // Build the exclusion set: manually-managed pins + any
            // shard whose post-leave Active count would land at or
            // below the halt-risk threshold (`active_count <=
            // HALT_RISK_PROVER_COUNT + 1`, matching `plan_leaves` and
            // `decide_leaves`). Shedding a shard already at the
            // threshold OR one our departure would push into it
            // would immediately worsen the network's exposure.
            // Operators dealing with chronic capacity pressure
            // should reduce worker count or add manual pins, not
            // auto-shed halt-risk-adjacent shards.
            let mut excluded = mm_filters.clone();
            for d in allocated_descriptors {
                if d.size > 0 && d.active_count <= proposer::HALT_RISK_PROVER_COUNT + 1 {
                    excluded.insert(d.filter.clone());
                }
            }
            let ranked = proposer::rank_allocated_by_score_ascending(
                allocated_descriptors,
                difficulty,
                world_bytes,
                self.units,
                self.strategy,
                &excluded,
            );
            // Lowest-scoring `surplus - orphan_count` auto-bound. A
            // filter that's `Active` but absent from `allocated_descriptors`
            // is, in practice, a size-0 shard (build_decide_descriptors
            // skipped it). Mirroring Go's `worker_allocator.go:821-824` —
            // where `if size == 0 { continue }` lands BEFORE
            // `leaveProposalCandidates = append(...)` — we deliberately
            // do NOT pick those here. The empty-allocated path in the
            // main ProposeLeave block surfaces them.
            for (f, _) in ranked {
                if picks.len() == surplus {
                    break;
                }
                if picks.contains(&f) {
                    continue;
                }
                picks.push(f);
            }
        }
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
            no_halt: !self.halt_state.any_halted(),
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
        let shard_sizes_snapshot = self.merged_shard_sizes();
        let proposal_descriptors = build_proposal_descriptors(
            &summaries,
            &all_our_filters,
            &shard_sizes_snapshot,
            &shards_store_filters,
        );
        let decide_all_descriptors =
            build_decide_descriptors(&summaries, &shard_sizes_snapshot);
        let allocated_descriptors: Vec<ShardDescriptor> = decide_all_descriptors.iter()
            .filter(|d| active_filters.contains(&d.filter))
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
        let allow_proposals = !free_worker_ids.is_empty();

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
        if !shard_info_ready {
            tracing::debug!(
                frame = frame_number,
                "deferring auto-allocation: no remote GetAppShards data yet"
            );
        }

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
        //
        // Bucketed by mode: filters bound to manually_managed workers
        // are confirmed at window-maturity regardless of score; if
        // there are more manual-bound pending allocs than available
        // workers, the excess is rejected on capacity grounds only
        // (no score-based reject). Filters bound to auto workers or
        // currently unbound flow through the existing score-driven
        // `decide_joins` against the remaining capacity.
        let confirm_window = self.confirm_window_frames();
        let ready_join_filters: Vec<Vec<u8>> = joining_filters.iter()
            .filter(|(_, jf)| frame_number >= *jf + confirm_window)
            .map(|(f, _)| f.clone())
            .collect();

        if !ready_join_filters.is_empty() {
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

            // Tier-5 #5: cap confirmations at unallocated worker count
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

            let mut combined_reject = manual_reject;
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
        if shard_info_ready && can_propose && !join_proposed_this_cycle && !active_filters.is_empty()
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
            // allocation but nothing is doing the work.
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

            // Orphan filters: Active allocations with no worker bound.
            // Always propose leave regardless of shard score — there's
            // no useful work to retain. Fixes the "extra allocation
            // from earlier issues, shows as -1 in TUI" case where the
            // allocation lingers on a healthy shard and plan_leaves /
            // surplus-leave can't (or won't) pick it.
            let orphan_filters: Vec<Vec<u8>> = active_filters
                .iter()
                .filter(|f| !bound_filters.contains(*f))
                .filter(|f| !manually_managed_filters.contains(*f))
                .filter(|f| !pending_leave_filters.contains(*f))
                .cloned()
                .collect();

            // Score-driven candidates — only meaningful when there are
            // unallocated alternatives to compare against.
            let score_candidates: Vec<Vec<u8>> = if !proposal_descriptors.is_empty() {
                proposer::plan_leaves(
                    &allocated_descriptors,
                    &proposal_descriptors,
                    difficulty,
                    &world_bytes,
                    self.units,
                    self.strategy,
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
            for f in &orphan_filters {
                if !leave_candidates.contains(f) {
                    leave_candidates.push(f.clone());
                }
            }
            let orphan_count =
                leave_candidates.len() - score_driven_count - empty_shard_count;
            if leave_candidates.len() > MAX_PROPOSALS_PER_CYCLE {
                leave_candidates.truncate(MAX_PROPOSALS_PER_CYCLE);
            }

            if !leave_candidates.is_empty() {
                self.allocator.set_last_join_attempt(frame_number);
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
                    orphan = orphan_count,
                    ?leave_summary,
                    "proposing leaves (overcrowded + empty + orphan)"
                );
                actions.push(LifecycleAction::ProposeLeave {
                    filters: leave_candidates,
                    frame_number,
                });
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
        let ready_leave_filters: Vec<Vec<u8>> = leaving_filters.iter()
            .filter(|(_, lf)| frame_number >= *lf + confirm_window)
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
            // bound), and auto-bound. Manual + orphan always confirm;
            // auto-bound goes through score-driven decide.
            let mut manual_ready: Vec<Vec<u8>> = Vec::new();
            let mut orphan_ready: Vec<Vec<u8>> = Vec::new();
            let mut auto_ready: Vec<Vec<u8>> = Vec::new();
            for f in &ready_leave_filters {
                if manual_bound_filters.contains(f) {
                    manual_ready.push(f.clone());
                } else if !bound_filters.contains(f) {
                    orphan_ready.push(f.clone());
                } else {
                    auto_ready.push(f.clone());
                }
            }

            // Auto bucket: score-driven decide_leaves on auto-bound.
            let (mut auto_reject, auto_confirm) = proposer::decide_leaves(
                &decide_all_descriptors,
                &auto_ready,
                difficulty,
                &world_bytes,
                self.units,
                self.strategy,
            );

            // Manual + orphan: always confirm at window, no auto-reject.
            // Order: auto confirms, then orphans, then manuals — stable
            // per-frame ordering for the log.
            let mut combined_confirm = auto_confirm;
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
            ring: ri.joiner_ring,
            shards: 1,
            active_on_ring: ri.active_on_joiner_ring,
            total_active_joining: total as u64,
            active_count: active as u64,
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
/// Tier-5 #3: see `build_proposal_descriptors` doc.
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
            vertex_address: Vec::new(),
        }
    }

    #[test]
    fn buckets_partition_by_effective_status_at_frame() {
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

    #[test]
    fn expired_joining_and_leaving_are_excluded_from_all_ours() {
        // Joining at frame 1 — by frame 1 + GRACE + 1, it's expired.
        let allocations = vec![
            alloc(0x01, ProverStatus::Joining, 1, 0),
            // Leaving at frame 2 — by frame 2 + GRACE + 1, it's expired.
            alloc(0x02, ProverStatus::Leaving, 1, 2),
        ];
        let b = AllocationBuckets::from_allocations(
            &allocations,
            ALLOCATION_GRACE_FRAMES + 100,
        );
        assert!(b.joining.is_empty(), "expired joining excluded");
        assert!(b.leaving.is_empty(), "expired leaving excluded");
        assert!(b.all_ours.is_empty(), "expired allocs not in all_ours");
    }

    #[test]
    fn rejected_and_kicked_excluded() {
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

    /// User report: "extra allocation from earlier issues, in the TUI
    /// it shows as -1 for the worker id, never leaves successfully".
    /// An active allocation whose filter is not bound to any worker is
    /// an orphan. plan_leaves alone can't fix it because if the orphan's
    /// shard scores at-or-above 67% of the best alternative, plan_leaves
    /// emits nothing for it. The orphan path proposes leave
    /// unconditionally for unbound active filters.
    #[test]
    fn orphan_active_filter_gets_leave_proposed() {
        let address = vec![0xCDu8; 32];
        let wm = Arc::new(ConfigurableWorkerManager::new());
        let reg = Arc::new(ConfigurableRegistry::new());

        // One worker bound to 0xA1. Filter 0xA2 is an orphan — the
        // allocation exists but no worker is doing the work.
        wm.add(allocated_worker(1, filter_bytes(0xA1)));

        let allocs = vec![
            alloc(filter_bytes(0xA1), ProverStatus::Active, 10),
            alloc(filter_bytes(0xA2), ProverStatus::Active, 10),
        ];
        reg.set_prover(prover(address.clone(), allocs));

        // Both allocated filters score similarly; no plan_leaves trigger.
        // Unallocated alternatives present but not dominantly better.
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
            leave_filters.contains(&filter_bytes(0xA2)),
            "expected ProposeLeave for orphan 0xA2 (no worker bound); got {:?}",
            actions
        );
        assert!(
            !leave_filters.contains(&filter_bytes(0xA1)),
            "must NOT leave the worker-bound filter 0xA1; got {:?}",
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
        lifecycle.set_prover_root_verified_frame(100);
        // confirm_window is 2 in make_lifecycle. leave_frame=90, so
        // frame 100 is well past 90 + 2.
        let actions = lifecycle.evaluate(100, 1, reg.as_ref(), wm.as_ref()).unwrap();

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
        // Worker 1 is manually pinned to the alloc we'll confirm.
        wm.add(manual_worker(1, manual_filter.clone()));

        // Alloc is Joining, ready to confirm. Set join_frame to 50 so
        // at frame 100 the confirm-window (default 2 frames in tests)
        // has long passed.
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
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle
            .evaluate(100, 1, reg.as_ref(), wm.as_ref())
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
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle
            .evaluate(100, 1, reg.as_ref(), wm.as_ref())
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
        lifecycle.set_prover_root_verified_frame(100);

        let actions = lifecycle
            .evaluate(100, 1, reg.as_ref(), wm.as_ref())
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
/// after Phase 4 filtering, then run them through
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
