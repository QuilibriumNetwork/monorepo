//! Worker allocation logic. Port of
//! `node/consensus/global/worker_allocator.go`.
//!
//! Decides which shards this node's workers should handle. On each
//! new global frame, reconciles the prover registry's allocations
//! against the running worker threads and spawns/stops as needed.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use num_bigint::BigInt;
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
/// deliberately wants worker (i+1) left idle / auto-managed."
/// - Invalid hex is logged and counted as `invalid`. Decoding is
/// tolerant: leading `0x` (any case) is stripped first.
/// - If no worker exists at `core_id` (the operator declared more
/// filters than CPU cores), the entry is skipped with a warning.
/// - **Persisted state wins**: if a worker already has a non-empty
/// `filter` (restored from the worker store from a prior gRPC edit,
/// or already pinned by some earlier startup step), config does NOT
/// override it. This means an operator who flipped the assignment
/// via `NodeService::set_manually_managed` + `request_join` keeps
/// their runtime decision across restarts.
/// - Otherwise: pin the filter with `set_worker_filter(core_id,
/// filter, start_consensus=false)` and mark the worker
/// `manually_managed=true`. `start_consensus=false` because we
/// don't yet know whether a matching registry allocation exists —
/// the auto-allocator will start the consensus engine when it
/// observes the alloc transition to Active.
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
/// How long a published allocation-priority snapshot stays usable.
///
/// The snapshot is produced by `ProverLifecycle::evaluate` (the only
/// place that holds archive-sourced shard sizes) and consumed here on
/// every reconcile, including the ones driven by the archive poller and
/// the frame-receive path, which run independently of the lifecycle. If
/// the lifecycle has been quiet for longer than this — shard-info
/// refresh failing, node still syncing — the scores are treated as
/// unknown and both the priority ordering and the rebind path
/// short-circuit to the previous registry-order behavior rather than
/// acting on stale reward data.
pub const PRIORITY_SNAPSHOT_MAX_AGE_FRAMES: u64 = 60;

/// Minimum frames between two reconciles that perform a priority
/// rebind. Churn safeguard: a rebind stops a running app-shard
/// consensus engine, so bursts are spaced out even when the ranking
/// keeps recommending them.
pub const REBIND_COOLDOWN_FRAMES: u64 = 30;

/// Maximum number of rebinds performed in a single reconcile. Bounds
/// the blast radius of one bad snapshot while still letting a node that
/// just lost workers converge on its best shards in a few cycles rather
/// than a few hundred frames.
pub const MAX_REBINDS_PER_RECONCILE: usize = 4;

/// How often the rebind path repeats an unchanged outcome in the log.
/// Roughly ten minutes of frames — often enough that a fresh log window
/// always shows the current state, rare enough not to bury the log.
pub const REBIND_TELEMETRY_REPEAT_FRAMES: u64 = 75;

/// Hysteresis for a priority rebind within the same tier: the unbound
/// allocation must score at least this percent of the bound one before
/// it may take its worker. Prevents two near-equal shards from trading
/// the same worker back and forth as their scores drift — after a swap
/// the reverse swap needs the same margin, which the loser cannot meet.
pub const REBIND_MARGIN_PERCENT: u64 = 125;

/// Minimum frames between join attempts.
///
/// Single source of truth — ProverLifecycle consults
/// `WorkerAllocator::last_join_attempt()` and this constant via
/// `join_proposal_ready`, matching Go's per-allocator field at
/// `worker_allocator.go:1306`.
pub const JOIN_COOLDOWN_FRAMES: u64 = 4;

/// Ranking of one of this prover's allocations, as scored by the
/// lifecycle's proposer policy.
#[derive(Debug, Clone)]
pub struct AllocationPriorityEntry {
    /// The shard is data-bearing and at/below `HALT_RISK_PROVER_COUNT`
    /// active provers. Keeping a worker on it is worth more than any
    /// reward difference, so it forms a strictly higher tier.
    pub halt_risk: bool,
    /// Expected-reward score under the node's configured strategy.
    pub score: BigInt,
}

/// A whole-frame ranking of allocations, published by the lifecycle.
///
/// The allocator cannot compute this itself: scoring needs archive-
/// sourced shard sizes, the world-byte total and the current
/// difficulty, none of which the prover registry carries.
struct AllocationPriority {
    frame_number: u64,
    entries: HashMap<Vec<u8>, AllocationPriorityEntry>,
}

/// Sort key for one filter. Tier 2 = halt-risk, tier 1 = scored,
/// tier 0 = absent from the snapshot (a size-0 shard, or one the
/// lifecycle had no data for). Ordering is by tier then score, both
/// descending, with the filter bytes as a deterministic tie-break.
fn priority_key(
    priority: &HashMap<Vec<u8>, AllocationPriorityEntry>,
    filter: &[u8],
) -> (u8, BigInt) {
    match priority.get(filter) {
        Some(e) if e.halt_risk => (2, e.score.clone()),
        Some(e) => (1, e.score.clone()),
        None => (0, BigInt::from(0)),
    }
}

/// Whether `challenger` is worth taking a worker away from `holder`.
///
/// A tier upgrade always qualifies — covering a halt-risk shard beats
/// any reward gap. Within a tier the challenger must clear
/// `REBIND_MARGIN_PERCENT` of the holder's score, which is what stops
/// the swap from being reversible on the next drift of either score.
fn rebind_justified(challenger: &(u8, BigInt), holder: &(u8, BigInt)) -> bool {
    if challenger.0 != holder.0 {
        return challenger.0 > holder.0;
    }
    if challenger.1 <= holder.1 {
        return false;
    }
    &challenger.1 * BigInt::from(100u64) >= &holder.1 * BigInt::from(REBIND_MARGIN_PERCENT)
}

/// Whether the lifecycle's ranking can be acted on this reconcile.
enum PriorityState {
    /// The lifecycle has never published — it has not completed an
    /// evaluation with shard-info loaded since this node started.
    Missing,
    /// A ranking exists but predates `PRIORITY_SNAPSHOT_MAX_AGE_FRAMES`.
    Stale { published_at: u64, age: u64 },
    Fresh(HashMap<Vec<u8>, AllocationPriorityEntry>),
}

/// What the rebind path did, or why it did nothing. Logged so
/// "no rebinding happened" is diagnosable without a debug build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebindOutcome {
    /// Workers were moved onto better-ranked allocations.
    Rebound = 1,
    /// No ranking published yet: the lifecycle publishes from `evaluate`,
    /// which returns early while any readiness gate is closed — so this
    /// covers cold start, an unfinished prover-tree sync, an unverified
    /// tree, and shard-info never loading alike.
    NoRanking = 2,
    /// Ranking too old to act on.
    RankingStale = 3,
    /// Within `REBIND_COOLDOWN_FRAMES` of the last rebind.
    Cooldown = 4,
    /// No unbound allocation is eligible — all orphans are mid-transition
    /// (`Joining`/`Leaving`) or epoch-stale rather than steady `Active`.
    NoEligibleOrphan = 5,
    /// No bound worker may be taken: all are operator-pinned, mid-join,
    /// or themselves not steady `Active`.
    NoEvictableWorker = 6,
    /// Ranked and eligible, but the best orphan does not clear the tier
    /// or the `REBIND_MARGIN_PERCENT` margin over the worst holder.
    BelowMargin = 7,
}

impl RebindOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rebound => "rebound",
            Self::NoRanking => "no_ranking_published",
            Self::RankingStale => "ranking_stale",
            Self::Cooldown => "cooldown",
            Self::NoEligibleOrphan => "no_eligible_orphan",
            Self::NoEvictableWorker => "no_evictable_worker",
            Self::BelowMargin => "below_margin",
        }
    }
}

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
    /// Self-leave confirm window, kept in lockstep with
    /// `ProverLifecycle::confirm_window_frames` (default 360; testnet
    /// overrides to a shorter value). A Leaving allocation is still
    /// participating until its leave confirms at `leave_frame +
    /// confirm_window`, so on recovery (e.g. after a store wipe) we
    /// reestablish a worker for it while it is within this window, and
    /// stop past it (the lifecycle confirms the leave instead). Must
    /// match the lifecycle value or the bind/confirm handoff would gap.
    confirm_window_frames: std::sync::atomic::AtomicU64,
    /// Latest lifecycle-published allocation ranking, consulted when
    /// this node holds more allocations than it has worker slots.
    /// `None` until the first `publish_allocation_priority`.
    allocation_priority: RwLock<Option<AllocationPriority>>,
    /// Frame of the last reconcile that rebound a worker. Gates
    /// `REBIND_COOLDOWN_FRAMES`.
    last_rebind_frame: std::sync::atomic::AtomicU64,
    /// Last logged `RebindOutcome` (as its discriminant) and the frame
    /// it was logged at, for the rate limiter in `log_rebind_outcome`.
    last_rebind_outcome: std::sync::atomic::AtomicU64,
    last_rebind_outcome_frame: std::sync::atomic::AtomicU64,
    /// Once-guard for the prover-reset-v3 worker-filter reset (mainnet frame
    /// 747_000). Fires exactly at that frame in `on_new_frame`, clearing every
    /// AUTO-managed worker's persisted deep filter so re-join lands on the clean
    /// genesis grid (the local worker store is what survived the v2 tree wipe and
    /// re-fed the cascade). In-memory is sufficient: the gate is the exact frame
    /// (processed once, monotonic) and the clear is idempotent — unlike the
    /// prover-TREE reseed, re-clearing auto filters has no harmful effect.
    worker_reset_v3_done: std::sync::atomic::AtomicBool,
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
            confirm_window_frames: std::sync::atomic::AtomicU64::new(
                crate::provers::lifecycle::DEFAULT_CONFIRM_WINDOW_FRAMES,
            ),
            allocation_priority: RwLock::new(None),
            last_rebind_frame: std::sync::atomic::AtomicU64::new(0),
            last_rebind_outcome: std::sync::atomic::AtomicU64::new(0),
            last_rebind_outcome_frame: std::sync::atomic::AtomicU64::new(0),
            worker_reset_v3_done: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Override the self-leave confirm window. Call alongside
    /// `ProverLifecycle::set_confirm_window_frames` so the recovery
    /// reestablish cutoff matches when leaves actually confirm.
    pub fn set_confirm_window_frames(&self, frames: u64) {
        self.confirm_window_frames
            .store(frames, std::sync::atomic::Ordering::Relaxed);
    }

    fn confirm_window_frames(&self) -> u64 {
        self.confirm_window_frames
            .load(std::sync::atomic::Ordering::Relaxed)
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

    /// Publish the lifecycle's per-filter ranking for `frame_number`.
    ///
    /// Called once per lifecycle evaluation, after shard-info has
    /// loaded. `entries` may cover shards this prover does not hold —
    /// only the ones matching an allocation are ever read.
    pub fn publish_allocation_priority(
        &self,
        frame_number: u64,
        entries: Vec<(Vec<u8>, bool, BigInt)>,
    ) {
        let entries: HashMap<Vec<u8>, AllocationPriorityEntry> = entries
            .into_iter()
            .map(|(filter, halt_risk, score)| {
                (filter, AllocationPriorityEntry { halt_risk, score })
            })
            .collect();
        if let Ok(mut guard) = self.allocation_priority.write() {
            *guard = Some(AllocationPriority { frame_number, entries });
        }
    }

    /// The published ranking and why it is or isn't usable.
    ///
    /// Returns the state rather than an `Option` so the caller can say
    /// in the log which of "the lifecycle has never published",
    /// "the last publish is too old" and "ranked, but nothing cleared
    /// the bar" is happening — from the outside those are three very
    /// different problems that all look like "no rebinding."
    ///
    /// The age check is two-sided: reconciles are driven by three
    /// independent sources (lifecycle, archive poller, frame receive)
    /// whose frame numbers can be slightly out of order, so a snapshot
    /// stamped a few frames ahead is normal and still valid.
    fn allocation_priority_state(&self, frame_number: u64) -> PriorityState {
        let Ok(guard) = self.allocation_priority.read() else {
            return PriorityState::Missing;
        };
        let Some(snapshot) = guard.as_ref() else {
            return PriorityState::Missing;
        };
        let age = frame_number.abs_diff(snapshot.frame_number);
        if age > PRIORITY_SNAPSHOT_MAX_AGE_FRAMES {
            return PriorityState::Stale {
                published_at: snapshot.frame_number,
                age,
            };
        }
        PriorityState::Fresh(snapshot.entries.clone())
    }

    /// Emit a rebind-path telemetry line, rate-limited.
    ///
    /// A node under allocation surplus reconciles every frame, so an
    /// unconditional line here would be several thousand entries an
    /// hour. Log when the outcome *changes* — which is the interesting
    /// moment — and otherwise once per `REBIND_TELEMETRY_REPEAT_FRAMES`
    /// so a steady state is still visible to an operator reading a
    /// fresh window of the log. `info`, not `debug`: the node runs with
    /// debug filtered out, and the whole point is that this is legible
    /// on a live node.
    fn log_rebind_outcome(&self, frame_number: u64, outcome: RebindOutcome, detail: &str) {
        use std::sync::atomic::Ordering;
        let code = outcome as u64;
        let last_code = self.last_rebind_outcome.load(Ordering::Relaxed);
        let last_frame = self.last_rebind_outcome_frame.load(Ordering::Relaxed);
        let changed = last_code != code;
        let due = last_frame == 0
            || frame_number.abs_diff(last_frame) >= REBIND_TELEMETRY_REPEAT_FRAMES;
        if !changed && !due {
            return;
        }
        self.last_rebind_outcome.store(code, Ordering::Relaxed);
        self.last_rebind_outcome_frame
            .store(frame_number, Ordering::Relaxed);
        info!(
            frame_number,
            outcome = outcome.as_str(),
            detail,
            "worker rebind under allocation surplus"
        );
    }

    /// Called on each new global frame. Reconciles the prover registry's
    /// allocations against running worker threads.
    ///
    /// Key timing constants:
    /// - `PROPOSAL_TIMEOUT_FRAMES = 10`: proposal never landed → clear filter
    /// - `PENDING_FILTER_GRACE_FRAMES = 720`: pending join not confirmed → clear
    pub fn on_new_frame(&self, frame_number: u64) -> Result<()> {
        // Prover-reset v3 (mainnet 747_000): clear every AUTO-managed worker's
        // persisted filter so it re-joins onto the clean genesis grid instead of
        // the deep filter that survived the v2 tree wipe in the local worker store
        // and re-fed the overlap cascade. Manually-managed workers keep their pins
        // (operator intent). Exact-frame gated + a one-shot in-memory guard; the
        // clear is idempotent so no persisted marker is needed (unlike the
        // prover-tree reseed on the consensus path).
        if (frame_number
            == quil_execution::global_intrinsic::materialize::quil_prover_reset_v3_frame()
            || frame_number
                == quil_execution::global_intrinsic::materialize::quil_prover_reset_v4_frame())
            && !self
                .worker_reset_v3_done
                .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            let mut cleared = 0usize;
            if let Ok(workers) = self.worker_manager.range_workers() {
                for w in workers {
                    if !w.manually_managed && !w.filter.is_empty() {
                        if let Err(e) = self.worker_manager.deallocate_worker(w.core_id) {
                            warn!(core_id = w.core_id, error = %e, "prover-reset v3: worker filter clear FAILED");
                        } else {
                            cleared += 1;
                        }
                    }
                }
            }
            info!(frame = frame_number, cleared, "prover-reset v3: cleared auto-managed worker filters (re-join lands on genesis grid)");
        }

        // Get our prover info from the registry
        let prover_info = self
            .prover_registry
            .get_prover_info(&self.local_prover_address)?;

        // Do NOT early-return when unregistered. A worker carrying a
        // `pending_filter_frame` from a ProposeJoin that never landed must
        // still be swept below — otherwise `free_auto()` stays empty,
        // `allow_proposals` is false, and the lifecycle never retries the
        // join, leaving the node permanently unregistered with idle
        // workers (observed production wedge: a single failed join pins
        // every worker forever). Matches Go `OnNewFrame`, which proceeds
        // with `self == nil` and clears stale/pending filters regardless.
        // When unregistered, `alloc_by_filter` is empty → every
        // filter-pinned worker hits the `None` arm → the 10-frame
        // pending-timeout sweep frees it so the lifecycle can re-propose.
        let alloc_by_filter: HashMap<Vec<u8>, &quil_types::consensus::ProverAllocationInfo> =
            prover_info
                .as_ref()
                .map(|p| {
                    p.allocations
                        .iter()
                        .map(|a| (a.confirmation_filter.clone(), a))
                        .collect()
                })
                .unwrap_or_default();

        // Get current worker assignments
        let workers = self.worker_manager.range_workers()?;

        // FIX (split-parent rebind, local-only): after an epoch-aligned split
        // rekeys this prover's allocation from a parent filter onto a child
        // filter, a worker still pinned to the now-defunct parent can sit idle
        // — the parent no longer has a live (Active) allocation, yet the live
        // child allocation has no worker bound (the flapping/stale parent entry
        // keeps the worker pinned instead of freeing it). Detect that here:
        // there is an Active allocation on a filter NOT bound to any worker
        // (the orphaned child). If so, any worker pinned to a filter with no
        // resolvable (Active/Paused/Joining-in-grace/Leaving-in-grace)
        // allocation — and not still inside its own pending-join window — is
        // deallocated below so the fresh-assign path binds it to the child.
        // This only re-pins LOCAL workers; it changes no consensus-visible state.
        let bound_filters: std::collections::HashSet<Vec<u8>> = workers
            .iter()
            .filter(|w| !w.filter.is_empty())
            .map(|w| w.filter.clone())
            .collect();
        let unassigned_active_exists = prover_info
            .as_ref()
            .map(|p| p.allocations.as_slice())
            .unwrap_or(&[])
            .iter()
            .any(|a| {
                a.status == ProverStatus::Active
                    && !bound_filters.contains(&a.confirmation_filter)
            });

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

            // Split-parent rebind (see note above range_workers): free a worker
            // stranded on a defunct parent so the orphaned child alloc can bind.
            if unassigned_active_exists {
                use quil_types::consensus::EffectiveStatus;
                let f_resolvable = alloc_by_filter
                    .get(&worker.filter)
                    .map(|a| {
                        matches!(
                            a.effective_status(frame_number),
                            EffectiveStatus::Active
                                | EffectiveStatus::Paused
                                | EffectiveStatus::Joining
                                | EffectiveStatus::Leaving
                        )
                    })
                    .unwrap_or(false);
                // Protect a still-in-flight ProposeJoin (pending window not yet
                // elapsed) so we don't cancel a legitimately pending bind.
                let pending_in_flight = worker.pending_filter_frame > 0
                    && frame_number
                        <= worker.pending_filter_frame + PROPOSAL_TIMEOUT_FRAMES;
                if !f_resolvable && !pending_in_flight {
                    warn!(
                        core_id = worker.core_id,
                        stale_filter = hex::encode(&worker.filter),
                        "worker pinned to a filter with no active allocation while an \
                         active child allocation is unbound (likely split-parent) — \
                         deallocating so the child rebinds"
                    );
                    self.worker_manager.deallocate_worker(worker.core_id)?;
                    continue;
                }
            }

            match alloc_by_filter.get(&worker.filter) {
                Some(alloc) => {
                    // `Active` is a raw wire status. An allocation whose
                    // epoch is stale is effectively inactive until its
                    // re-confirmation lands, so it must not pin a scarce
                    // worker while a live allocation is unbound.
                    if alloc.effective_status(frame_number)
                        == quil_types::consensus::EffectiveStatus::ExpiredEpoch
                    {
                        info!(
                            core_id = worker.core_id,
                            filter = hex::encode(&worker.filter),
                            allocation_epoch = alloc.epoch,
                            current_epoch = quil_types::consensus::epoch_for_frame(frame_number),
                            "epoch-expired allocation released so a live shard can use the worker"
                        );
                        self.worker_manager.deallocate_worker(worker.core_id)?;
                        continue;
                    }

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
                        ProverStatus::Rejected
                        | ProverStatus::Kicked
                        | ProverStatus::Historic => {
                            // Allocation no longer lives on this filter — clear
                            // immediately so the worker returns to the free pool.
                            // `Rejected` = join was rejected; `Kicked` =
                            // leave-confirmed (alloc byte 5) OR evicted; `Historic`
                            // = vacated by a reassignment (the prover moved to
                            // another filter — the worker must follow, so free it to
                            // re-bind to the new active allocation rather than sit
                            // idle pinned to the vacated one; a merge-back that
                            // reactivates the slot re-binds a worker from the pool).
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
                                "allocation ended/reassigned, clearing worker"
                            );
                            self.worker_manager.deallocate_worker(worker.core_id)?;
                        }
                        ProverStatus::Leaving => {
                            // Live Leave (within 720-frame grace) →
                            // keep the worker bound until
                            // Confirm/Reject resolves. Expired Leave
                            // (no Confirm/Reject within grace) →
                            // protocol treats it as terminal; clear
                            // the worker so it becomes a free auto
                            // candidate again. Without this, an
                            // operator-submitted Leave that the
                            // network never confirmed would pin the
                            // worker to a shard the operator
                            // explicitly asked to leave, forever.
                            if alloc.effective_status(frame_number)
                                == quil_types::consensus::EffectiveStatus::ExpiredLeaving
                            {
                                desired_allocated = false;
                                info!(
                                    core_id = worker.core_id,
                                    filter = hex::encode(&worker.filter),
                                    leave_frame = alloc.leave_frame_number,
                                    "leave expired after 720 frames, clearing worker"
                                );
                                self.worker_manager.deallocate_worker(worker.core_id)?;
                            }
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
        // Sorted DESCENDING so `pop()` yields the LOWEST core id first.
        // The proposal path (`proposer::plan_and_allocate`) sorts
        // `free_worker_ids` ascending and hands shard k to
        // `sorted_workers[k]`, i.e. it always plans from the lowest free
        // core up. This fallback must agree: with ascending order + `pop()`
        // it bound from the top down, so whenever a planned worker's
        // pre-pin was lost the whole set shifted up by one and the lowest
        // core was left idle (production: joins planned on cores 1..14,
        // bindings landed on 2..15, core 1's join reported missing).
        idle_workers.sort();
        idle_workers.reverse();

        // Manually-managed-but-unbound workers — the operator picked
        // these via the TUI's worker-selector at join time. We
        // consume them first when binding new Joining/Active
        // allocations to filters, so the user's selection is
        // honored. Sorted descending so `pop()` gives the
        // lowest-numbered first (matches `idle_workers` ordering and the
        // proposal path; operators typically pick contiguous
        // low-numbered workers).
        let mut manual_pending: Vec<u32> = self
            .worker_manager
            .range_workers()?
            .iter()
            .filter(|w| w.filter.is_empty() && w.manually_managed)
            .map(|w| w.core_id)
            .collect();
        manual_pending.sort();
        manual_pending.reverse();

        // Track allocations that need a worker but couldn't get one
        // (idle pool empty + no manual-pending available). Without
        // surfacing this we have no signal that an alloc landed
        // without a worker binding — the symptom of the orphan-
        // Joining failure mode that requires the lifecycle-side
        // per-filter Join cooldown to prevent at the source.
        let mut orphan_filters: Vec<(Vec<u8>, ProverStatus)> = Vec::new();

        // Ranking for this frame, when the lifecycle has published a
        // recent one. Under an allocation surplus — more Active
        // allocations than worker slots, the normal state after a
        // reset or after losing workers to an incident — registry
        // iteration order decides which shards get the scarce workers
        // and which are orphaned. That order is incidental, so the
        // node can end up running its least valuable shards. Order the
        // bind candidates by the same policy the lifecycle uses to
        // pick which surplus allocations to shed, so the workers we
        // still have run the shards we would keep.
        let priority_state = self.allocation_priority_state(frame_number);
        let priority = match &priority_state {
            PriorityState::Fresh(entries) => Some(entries.clone()),
            _ => None,
        };

        let mut bind_candidates: Vec<&quil_types::consensus::ProverAllocationInfo> =
            Vec::new();
        for alloc in prover_info
            .as_ref()
            .map(|p| p.allocations.as_slice())
            .unwrap_or(&[])
        {
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
                EffectiveStatus::Leaving => {
                    // A Leaving allocation is still participating in its
                    // shard until the leave confirms (at `leave_frame +
                    // confirm_window`). On recovery (e.g. after a store
                    // wipe) the worker is idle, so reestablish it here so
                    // the shard keeps producing while the leave is still
                    // in flight. Once we're past the confirm window, the
                    // lifecycle's `ready_leave_filters` confirms the leave
                    // (ConfirmLeaves) — don't bind a worker we're about to
                    // release. (frame >= leave + window is guaranteed for
                    // EffectiveStatus::Leaving only when window < 720; the
                    // 720 grace fallback still applies via ExpiredLeaving.)
                    if frame_number
                        >= alloc
                            .leave_frame_number
                            .saturating_add(self.confirm_window_frames())
                    {
                        continue;
                    }
                }
                _ => continue,
            }
            if assigned_filters.contains(&alloc.confirmation_filter) {
                continue;
            }
            bind_candidates.push(alloc);
        }

        // Best-first when we have a ranking; registry order otherwise
        // (an unranked run must behave exactly as before).
        if let Some(priority) = priority.as_ref() {
            bind_candidates.sort_by(|a, b| {
                let ka = priority_key(priority, &a.confirmation_filter);
                let kb = priority_key(priority, &b.confirmation_filter);
                kb.0.cmp(&ka.0)
                    .then_with(|| kb.1.cmp(&ka.1))
                    .then_with(|| a.confirmation_filter.cmp(&b.confirmation_filter))
            });
        }

        for alloc in bind_candidates {
            // Prefer a manually-pending (user-picked) worker before
            // falling back to the auto-managed idle pool.
            let pick = manual_pending.pop().or_else(|| idle_workers.pop());
            if let Some(core_id) = pick {
                // Leaving counts as participating — the worker must run
                // the shard's consensus engine until the leave confirms.
                let start_consensus = matches!(
                    alloc.status,
                    ProverStatus::Active | ProverStatus::Paused | ProverStatus::Leaving
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
            } else {
                // No idle worker available — the alloc is on-chain
                // but has no local worker bound. This is a
                // worker-budget overflow, almost always caused by
                // overlapping ProposeJoin cycles materializing more
                // distinct filters than we have worker slots for.
                // The lifecycle's per-filter Join cooldown prevents
                // the upstream cause; this branch logs the symptom
                // so the operator (or a future regression) can spot
                // it. Collected and logged in aggregate below so a
                // batch of 9 orphans produces one log line, not 9.
                orphan_filters.push((alloc.confirmation_filter.clone(), alloc.status));
            }
        }

        if !orphan_filters.is_empty() {
            let count = orphan_filters.len();
            let sample: Vec<String> = orphan_filters
                .iter()
                .take(8)
                .map(|(f, s)| format!("{}:{:?}", hex::encode(f), s))
                .collect();
            warn!(
                orphan_count = count,
                frame_number,
                ?sample,
                "allocations with no worker bound — idle pool exhausted; \
                 likely overlapping ProposeJoin cycles produced more \
                 distinct Joining filters than worker slots. The orphan \
                 alloc stays in the registry until its 720-frame grace \
                 expires (Joining) or until the network confirms/rejects \
                 it. Lifecycle's `JOIN_FILTER_COOLDOWN_FRAMES` is the \
                 upstream guard against this."
            );

            // Orphans are not necessarily the least valuable
            // allocations: workers lost to an incident (crashed data
            // worker, reduced core count, an operator shrinking the
            // fleet) leave whatever they held bound and push the rest
            // out, and a reset can land a surplus in any order. Take
            // the workers back for the best allocations.
            match &priority_state {
                PriorityState::Fresh(entries) => {
                    self.rebind_surplus_by_priority(
                        frame_number,
                        &orphan_filters,
                        &alloc_by_filter,
                        entries,
                    )?;
                }
                PriorityState::Missing => self.log_rebind_outcome(
                    frame_number,
                    RebindOutcome::NoRanking,
                    "lifecycle has not published a ranking yet — it publishes \
                     from evaluate, which returns early while any of its \
                     readiness gates is closed (prover-tree sync, tree \
                     verification, shard-info load)",
                ),
                PriorityState::Stale { published_at, age } => self.log_rebind_outcome(
                    frame_number,
                    RebindOutcome::RankingStale,
                    &format!(
                        "last ranking published at frame {published_at} is {age} \
                         frames old (max {PRIORITY_SNAPSHOT_MAX_AGE_FRAMES})"
                    ),
                ),
            }
        }

        Ok(())
    }

    /// Move workers from lower-ranked bound allocations onto
    /// higher-ranked unbound ones.
    ///
    /// Only runs when this prover holds more allocations than it has
    /// workers; with slack, the bind pass above has already placed
    /// everything and `orphans` is empty. Confined to steady-state
    /// bindings: manually-managed workers are the operator's, an
    /// in-flight join has its own timeout, and a `Joining`/`Leaving`
    /// allocation is mid-transition and resolves on its own. An
    /// orphan must be `Active`/`Paused` to be promoted — taking a
    /// running shard's worker to give it to a shard we have not
    /// joined yet trades work for none.
    ///
    /// Rebinding does not touch consensus-visible state: the surplus
    /// allocations stay on-chain either way and the lifecycle's
    /// surplus-leave path sheds them, lowest-scoring first — the same
    /// order used here, so the shards left unbound are the ones it
    /// will propose leaving.
    fn rebind_surplus_by_priority(
        &self,
        frame_number: u64,
        orphans: &[(Vec<u8>, ProverStatus)],
        alloc_by_filter: &HashMap<Vec<u8>, &quil_types::consensus::ProverAllocationInfo>,
        priority: &HashMap<Vec<u8>, AllocationPriorityEntry>,
    ) -> Result<()> {
        use quil_types::consensus::EffectiveStatus;
        use std::sync::atomic::Ordering;

        let last_rebind = self.last_rebind_frame.load(Ordering::Relaxed);
        if last_rebind > 0 && frame_number.abs_diff(last_rebind) < REBIND_COOLDOWN_FRAMES {
            self.log_rebind_outcome(
                frame_number,
                RebindOutcome::Cooldown,
                &format!(
                    "last rebind at frame {last_rebind}, {} of                      {REBIND_COOLDOWN_FRAMES} cooldown frames elapsed",
                    frame_number.abs_diff(last_rebind)
                ),
            );
            return Ok(());
        }

        let steady = |filter: &[u8]| {
            alloc_by_filter
                .get(filter)
                .map(|a| {
                    matches!(
                        a.effective_status(frame_number),
                        EffectiveStatus::Active | EffectiveStatus::Paused
                    )
                })
                .unwrap_or(false)
        };

        // Best unbound first.
        let mut challengers: Vec<(u8, BigInt, Vec<u8>)> = orphans
            .iter()
            .filter(|(f, _)| steady(f))
            .map(|(f, _)| {
                let (tier, score) = priority_key(priority, f);
                (tier, score, f.clone())
            })
            .collect();
        challengers.sort_by(|a, b| {
            b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| a.2.cmp(&b.2))
        });
        if challengers.is_empty() {
            self.log_rebind_outcome(
                frame_number,
                RebindOutcome::NoEligibleOrphan,
                &format!(
                    "{} unbound allocation(s), none steady Active/Paused                      (mid-transition or epoch-stale)",
                    orphans.len()
                ),
            );
            return Ok(());
        }

        // Worst bound first.
        let mut holders: Vec<(u8, BigInt, u32, Vec<u8>)> = self
            .worker_manager
            .range_workers()?
            .into_iter()
            .filter(|w| {
                !w.filter.is_empty()
                    && !w.manually_managed
                    && w.pending_filter_frame == 0
                    && steady(&w.filter)
            })
            .map(|w| {
                let (tier, score) = priority_key(priority, &w.filter);
                (tier, score, w.core_id, w.filter)
            })
            .collect();
        holders.sort_by(|a, b| {
            a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)).then_with(|| a.3.cmp(&b.3))
        });
        if holders.is_empty() {
            self.log_rebind_outcome(
                frame_number,
                RebindOutcome::NoEvictableWorker,
                "every bound worker is operator-pinned, mid-join, or not                  steady Active/Paused",
            );
            return Ok(());
        }

        // Captured before the vectors are consumed, so the telemetry can
        // show the gap that was or wasn't cleared.
        let best_challenger = (challengers[0].0, challengers[0].1.clone());
        let worst_holder = (holders[0].0, holders[0].1.clone());
        let challenger_count = challengers.len();
        let holder_count = holders.len();

        let mut rebound = 0usize;
        for ((c_tier, c_score, c_filter), (h_tier, h_score, core_id, h_filter)) in
            challengers.into_iter().zip(holders.into_iter())
        {
            if rebound == MAX_REBINDS_PER_RECONCILE {
                break;
            }
            if !rebind_justified(&(c_tier, c_score.clone()), &(h_tier, h_score.clone())) {
                // Both lists are sorted, so once the best remaining
                // challenger cannot displace the worst remaining
                // holder, no later pair can either.
                break;
            }
            warn!(
                core_id,
                released_filter = hex::encode(&h_filter),
                released_tier = h_tier,
                released_score = %h_score,
                bound_filter = hex::encode(&c_filter),
                bound_tier = c_tier,
                bound_score = %c_score,
                frame_number,
                "rebinding worker to a higher-ranked allocation — this node holds \
                 more allocations than workers, so the scarce workers run the \
                 shards the lifecycle would keep. The released allocation stays \
                 on-chain until the surplus-leave path sheds it."
            );
            self.worker_manager.deallocate_worker(core_id)?;
            self.worker_manager.set_worker_filter(core_id, &c_filter, true)?;
            rebound += 1;
        }

        if rebound > 0 {
            self.last_rebind_frame.store(frame_number, Ordering::Relaxed);
            self.log_rebind_outcome(
                frame_number,
                RebindOutcome::Rebound,
                &format!(
                    "{rebound} worker(s) moved; {challenger_count} unbound                      candidate(s) against {holder_count} evictable worker(s)"
                ),
            );
        } else {
            self.log_rebind_outcome(
                frame_number,
                RebindOutcome::BelowMargin,
                &format!(
                    "best unbound (tier {}, score {}) does not clear                      {REBIND_MARGIN_PERCENT}% of worst bound (tier {}, score                      {}); {challenger_count} candidate(s), {holder_count}                      evictable worker(s)",
                    best_challenger.0,
                    best_challenger.1,
                    worst_holder.0,
                    worst_holder.1,
                ),
            );
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
            epoch: 0,
            ring: 0,
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
    fn clears_stuck_pending_join_when_unregistered() {
        // Regression (production wedge): a ProposeJoin whose submit never
        // landed leaves workers carrying a `pending_filter_frame` while the
        // prover is NOT in the registry (the join never confirmed). If
        // `on_new_frame` early-returns when unregistered, the marker never
        // clears → `free_auto()` stays empty → `allow_proposals = false` →
        // the lifecycle never re-proposes → the node sits permanently idle
        // with 0 allocations. The sweep must run regardless of registration.
        let wm = Arc::new(MockWorkerManager::new());
        // Idle worker (empty filter) carrying a stale pending-join marker.
        wm.add(crate::worker::WorkerInfo {
            core_id: 1,
            filter: Vec::new(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 100,
            allocated: false,
        });

        // Empty registry: our prover never registered (join never landed).
        let reg = Arc::new(TestProverRegistry::new());
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);

        // Well past the 10-frame proposal timeout.
        alloc
            .on_new_frame(100 + PROPOSAL_TIMEOUT_FRAMES + 1)
            .unwrap();

        let workers = wm.range_workers().unwrap();
        assert_eq!(workers.len(), 1, "worker must still exist");
        assert_eq!(
            workers[0].pending_filter_frame, 0,
            "stuck pending-join marker must be cleared so the worker is free \
             again and the lifecycle can re-propose"
        );
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

    fn prover_with(allocs: Vec<ProverAllocationInfo>) -> ProverInfo {
        ProverInfo {
            public_key: vec![0xBB; 585],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: allocs,
            available_storage: 0,
            seniority: 100,
            delegate_address: vec![],
        }
    }

    fn bound_cores(wm: &MockWorkerManager) -> Vec<u32> {
        let mut v: Vec<u32> = wm
            .range_workers()
            .unwrap()
            .iter()
            .filter(|w| !w.filter.is_empty())
            .map(|w| w.core_id)
            .collect();
        v.sort();
        v
    }

    #[test]
    fn fresh_assign_binds_lowest_core_ids_first() {
        // Regression (production, post-grid-reset): the lifecycle's
        // proposal path (`proposer::plan_and_allocate`) sorts the free
        // worker ids ascending and plans shard k onto `sorted_workers[k]`
        // — i.e. it always starts at the LOWEST free core. This fallback
        // assign pass used to sort ascending and `pop()`, taking the
        // HIGHEST core first, so the two disagreed: joins planned on
        // cores 1..14 landed as bindings on cores 2..15 and core 1 sat
        // idle with its join reported missing. With M > N idle workers,
        // N allocations must occupy the N lowest cores.
        let wm = Arc::new(MockWorkerManager::new());
        for c in 1..=6u32 {
            wm.allocate_worker(c, &[]).unwrap();
        }

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            make_alloc(vec![0x01; 32]),
            make_alloc(vec![0x02; 32]),
            make_alloc(vec![0x03; 32]),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.on_new_frame(101).unwrap();

        assert_eq!(
            bound_cores(&wm),
            vec![1, 2, 3],
            "3 allocations over 6 idle workers must bind the 3 lowest cores, \
             matching the order the proposal path pre-pins them in"
        );
    }

    #[test]
    fn manual_pending_consumed_before_auto_idle_pool() {
        // Precedence rule must survive the ordering fix: operator-picked
        // (`manually_managed`) unbound workers are consumed before the
        // auto idle pool, and each pool is drained lowest-core-first.
        let wm = Arc::new(MockWorkerManager::new());
        for c in 1..=3u32 {
            wm.allocate_worker(c, &[]).unwrap(); // auto idle pool
        }
        for c in [10u32, 11] {
            wm.add(crate::worker::WorkerInfo {
                core_id: c,
                filter: Vec::new(),
                available_storage: 0,
                total_storage: 0,
                manually_managed: true,
                pending_filter_frame: 0,
                allocated: false,
            });
        }

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            make_alloc(vec![0x01; 32]),
            make_alloc(vec![0x02; 32]),
            make_alloc(vec![0x03; 32]),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.on_new_frame(101).unwrap();

        assert_eq!(
            bound_cores(&wm),
            vec![1, 10, 11],
            "both operator-picked workers must be consumed before the auto \
             pool, and the single auto spillover must take the lowest free \
             core (1), not the highest (3)"
        );
    }

    #[test]
    fn recovery_reestablishes_active_and_leaving_within_window() {
        // Store-wipe recovery: workers are idle but the registry (synced
        // from the network) still holds our allocations. on_new_frame must
        // rebind a worker to each Active allocation AND each Leaving
        // allocation still within the confirm window (still participating),
        // but NOT a Leaving allocation past the window (the lifecycle
        // confirms that leave instead of us reassigning a doomed worker).
        let wm = Arc::new(MockWorkerManager::new());
        for c in 0..3u32 {
            wm.allocate_worker(c, &[]).unwrap(); // 3 idle workers
        }

        let window = crate::provers::lifecycle::DEFAULT_CONFIRM_WINDOW_FRAMES; // 360
        let frame = 10_000u64;

        let mut active = make_alloc(vec![0x01; 32]); // status Active, leave_frame 0
        // Confirmed for the current epoch so always-on epoch expiry keeps it
        // Active (eval frame 10_000 is well past the first epoch boundary).
        active.epoch = quil_types::consensus::epoch_for_frame(frame);

        let mut leaving_in = make_alloc(vec![0x02; 32]);
        leaving_in.status = ProverStatus::Leaving;
        leaving_in.leave_frame_number = frame - 10; // 10 frames in — within window

        let mut leaving_out = make_alloc(vec![0x03; 32]);
        leaving_out.status = ProverStatus::Leaving;
        leaving_out.leave_frame_number = frame - window - 5; // past confirm window

        let prover = ProverInfo {
            public_key: vec![0xBB; 585],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![active, leaving_in, leaving_out],
            available_storage: 0,
            seniority: 100,
            delegate_address: vec![],
        };

        let reg = Arc::new(TestProverRegistry::with_prover(prover));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.on_new_frame(frame).unwrap();

        let assigned: Vec<Vec<u8>> = wm
            .range_workers()
            .unwrap()
            .iter()
            .filter(|w| !w.filter.is_empty())
            .map(|w| w.filter.clone())
            .collect();
        assert!(
            assigned.contains(&vec![0x01; 32]),
            "Active allocation must be reestablished"
        );
        assert!(
            assigned.contains(&vec![0x02; 32]),
            "Leaving allocation within the confirm window must be reestablished"
        );
        assert!(
            !assigned.contains(&vec![0x03; 32]),
            "Leaving allocation past the confirm window must NOT be reestablished \
             (the lifecycle confirms the leave instead)"
        );
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

        // Worker should have been released but remain visible as idle, which
        // matches the production worker manager and lets it be reused.
        let workers = wm.range_workers().unwrap();
        assert_eq!(workers.len(), 1);
        assert!(workers[0].filter.is_empty());
        assert!(!workers[0].allocated);
    }

    #[test]
    fn releases_epoch_expired_binding_for_live_allocation() {
        let wm = Arc::new(MockWorkerManager::new());
        let stale_filter = vec![0x01; 32];
        let live_filter = vec![0x02; 32];
        wm.allocate_worker(1, &stale_filter).unwrap();

        let frame = 10_000;
        let mut stale = make_alloc(stale_filter);
        stale.epoch = 0;
        let mut live = make_alloc(live_filter.clone());
        live.epoch = quil_types::consensus::epoch_for_frame(frame);

        let prover = ProverInfo {
            public_key: vec![],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![stale, live],
            available_storage: 0,
            seniority: 0,
            delegate_address: vec![],
        };
        let reg = Arc::new(TestProverRegistry::with_prover(prover));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);

        alloc.on_new_frame(frame).unwrap();

        let workers = wm.range_workers().unwrap();
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].filter, live_filter,
            "the stale epoch binding must yield its only worker to the live allocation");
    }

    // -----------------------------------------------------------------
    // Allocation surplus: priority binding and rebinding
    // -----------------------------------------------------------------

    /// Build a prover holding `filters`, all Active for `frame`'s epoch.
    fn prover_with_active(filters: &[Vec<u8>], frame: u64) -> ProverInfo {
        ProverInfo {
            public_key: vec![0xBB; 585],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: filters
                .iter()
                .map(|f| {
                    let mut a = make_alloc(f.clone());
                    a.epoch = quil_types::consensus::epoch_for_frame(frame);
                    a
                })
                .collect(),
            available_storage: 0,
            seniority: 100,
            delegate_address: vec![],
        }
    }

    fn bound_filters(wm: &MockWorkerManager) -> Vec<Vec<u8>> {
        wm.range_workers()
            .unwrap()
            .iter()
            .filter(|w| !w.filter.is_empty())
            .map(|w| w.filter.clone())
            .collect()
    }

    #[test]
    fn surplus_binds_highest_ranked_allocations_first() {
        // Three Active allocations, one worker. Registry order is
        // worst-first, so binding in that order would run the least
        // valuable shard.
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let frame = 10_000u64;
        let filters = vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]];

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with_active(
            &filters, frame,
        )));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.publish_allocation_priority(
            frame,
            vec![
                (filters[0].clone(), false, BigInt::from(100)),
                (filters[1].clone(), false, BigInt::from(200)),
                (filters[2].clone(), false, BigInt::from(900)),
            ],
        );

        alloc.on_new_frame(frame).unwrap();

        assert_eq!(
            bound_filters(&wm),
            vec![filters[2].clone()],
            "the only worker must run the highest-scoring allocation"
        );
    }

    #[test]
    fn halt_risk_allocation_outranks_a_higher_reward_one() {
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let frame = 10_000u64;
        let filters = vec![vec![0x01; 32], vec![0x02; 32]];

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with_active(
            &filters, frame,
        )));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.publish_allocation_priority(
            frame,
            vec![
                (filters[0].clone(), true, BigInt::from(10)),
                (filters[1].clone(), false, BigInt::from(9_000)),
            ],
        );

        alloc.on_new_frame(frame).unwrap();

        assert_eq!(
            bound_filters(&wm),
            vec![filters[0].clone()],
            "covering a halt-risk shard outranks any reward gap"
        );
    }

    #[test]
    fn lost_workers_keep_the_most_profitable_allocations() {
        // Incident shape: the node had three workers, two died, and the
        // survivor happens to hold the worst allocation. The two better
        // allocations are orphaned. The survivor must be moved onto the
        // best of them.
        let wm = Arc::new(MockWorkerManager::new());
        let frame = 10_000u64;
        let filters = vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]];
        wm.allocate_worker(1, &filters[0]).unwrap();

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with_active(
            &filters, frame,
        )));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.publish_allocation_priority(
            frame,
            vec![
                (filters[0].clone(), false, BigInt::from(100)),
                (filters[1].clone(), false, BigInt::from(400)),
                (filters[2].clone(), false, BigInt::from(900)),
            ],
        );

        alloc.on_new_frame(frame).unwrap();

        assert_eq!(
            bound_filters(&wm),
            vec![filters[2].clone()],
            "the surviving worker must be moved onto the best allocation"
        );
    }

    #[test]
    fn rebind_needs_more_than_a_marginal_score_gain() {
        // 900 vs 800 is only 112% — below REBIND_MARGIN_PERCENT. Churning
        // a running consensus engine for that is not worth it.
        let wm = Arc::new(MockWorkerManager::new());
        let frame = 10_000u64;
        let filters = vec![vec![0x01; 32], vec![0x02; 32]];
        wm.allocate_worker(1, &filters[0]).unwrap();

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with_active(
            &filters, frame,
        )));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.publish_allocation_priority(
            frame,
            vec![
                (filters[0].clone(), false, BigInt::from(800)),
                (filters[1].clone(), false, BigInt::from(900)),
            ],
        );

        alloc.on_new_frame(frame).unwrap();

        assert_eq!(
            bound_filters(&wm),
            vec![filters[0].clone()],
            "a sub-margin gain must not move a running worker"
        );
    }

    #[test]
    fn rebind_leaves_manually_managed_workers_alone() {
        let wm = Arc::new(MockWorkerManager::new());
        let frame = 10_000u64;
        let filters = vec![vec![0x01; 32], vec![0x02; 32]];
        wm.allocate_worker(1, &filters[0]).unwrap();
        wm.set_manually_managed(1, true).unwrap();

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with_active(
            &filters, frame,
        )));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.publish_allocation_priority(
            frame,
            vec![
                (filters[0].clone(), false, BigInt::from(1)),
                (filters[1].clone(), false, BigInt::from(9_000)),
            ],
        );

        alloc.on_new_frame(frame).unwrap();

        assert_eq!(
            bound_filters(&wm),
            vec![filters[0].clone()],
            "an operator-pinned worker is never rebound automatically"
        );
    }

    #[test]
    fn stale_priority_snapshot_does_not_rebind() {
        let wm = Arc::new(MockWorkerManager::new());
        let frame = 10_000u64;
        let filters = vec![vec![0x01; 32], vec![0x02; 32]];
        wm.allocate_worker(1, &filters[0]).unwrap();

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with_active(
            &filters, frame,
        )));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.publish_allocation_priority(
            frame - PRIORITY_SNAPSHOT_MAX_AGE_FRAMES - 1,
            vec![
                (filters[0].clone(), false, BigInt::from(1)),
                (filters[1].clone(), false, BigInt::from(9_000)),
            ],
        );

        alloc.on_new_frame(frame).unwrap();

        assert_eq!(
            bound_filters(&wm),
            vec![filters[0].clone()],
            "an out-of-date ranking must not drive worker churn"
        );
    }

    #[test]
    fn priority_state_distinguishes_missing_from_stale() {
        let wm = Arc::new(MockWorkerManager::new());
        let reg = Arc::new(TestProverRegistry::new());
        let alloc = WorkerAllocator::new(wm, reg, vec![0xAAu8; 32]);
        let frame = 10_000u64;

        assert!(
            matches!(alloc.allocation_priority_state(frame), PriorityState::Missing),
            "a node whose lifecycle has never evaluated reports Missing, not Stale"
        );

        alloc.publish_allocation_priority(
            frame - PRIORITY_SNAPSHOT_MAX_AGE_FRAMES - 1,
            vec![(vec![0x01; 32], false, BigInt::from(5))],
        );
        match alloc.allocation_priority_state(frame) {
            PriorityState::Stale { published_at, age } => {
                assert_eq!(published_at, frame - PRIORITY_SNAPSHOT_MAX_AGE_FRAMES - 1);
                assert_eq!(age, PRIORITY_SNAPSHOT_MAX_AGE_FRAMES + 1);
            }
            _ => panic!("an out-of-date ranking must report Stale with its age"),
        }

        alloc.publish_allocation_priority(
            frame + 1,
            vec![(vec![0x01; 32], false, BigInt::from(5))],
        );
        assert!(
            matches!(alloc.allocation_priority_state(frame), PriorityState::Fresh(_)),
            "a ranking stamped a frame ahead is still fresh — reconciles run \
             from three sources whose frame numbers interleave"
        );
    }

    #[test]
    fn rebind_respects_its_cooldown() {
        let wm = Arc::new(MockWorkerManager::new());
        let frame = 10_000u64;
        let filters = vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]];
        wm.allocate_worker(1, &filters[0]).unwrap();

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with_active(
            &filters, frame,
        )));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        let publish = |f: u64| {
            alloc.publish_allocation_priority(
                f,
                vec![
                    (filters[0].clone(), false, BigInt::from(100)),
                    (filters[1].clone(), false, BigInt::from(400)),
                    (filters[2].clone(), false, BigInt::from(900)),
                ],
            )
        };

        publish(frame);
        alloc.on_new_frame(frame).unwrap();
        assert_eq!(bound_filters(&wm), vec![filters[2].clone()]);

        // Immediately after, pretend the best shard collapsed so the
        // ranking now prefers a different one. The cooldown must hold.
        alloc.publish_allocation_priority(
            frame + 1,
            vec![
                (filters[0].clone(), false, BigInt::from(100)),
                (filters[1].clone(), false, BigInt::from(4_000)),
                (filters[2].clone(), false, BigInt::from(1)),
            ],
        );
        alloc.on_new_frame(frame + 1).unwrap();
        assert_eq!(
            bound_filters(&wm),
            vec![filters[2].clone()],
            "a second rebind within REBIND_COOLDOWN_FRAMES must be deferred"
        );

        // Past the cooldown it takes effect.
        let later = frame + REBIND_COOLDOWN_FRAMES + 1;
        alloc.publish_allocation_priority(
            later,
            vec![
                (filters[0].clone(), false, BigInt::from(100)),
                (filters[1].clone(), false, BigInt::from(4_000)),
                (filters[2].clone(), false, BigInt::from(1)),
            ],
        );
        alloc.on_new_frame(later).unwrap();
        assert_eq!(bound_filters(&wm), vec![filters[1].clone()]);
    }

    #[test]
    fn without_a_snapshot_binding_keeps_registry_order() {
        // Unranked runs must behave exactly as before the fix.
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let frame = 10_000u64;
        let filters = vec![vec![0x01; 32], vec![0x02; 32]];

        let reg = Arc::new(TestProverRegistry::with_prover(prover_with_active(
            &filters, frame,
        )));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);

        alloc.on_new_frame(frame).unwrap();

        assert_eq!(bound_filters(&wm), vec![filters[0].clone()]);
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
