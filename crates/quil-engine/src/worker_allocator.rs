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

use crate::worker::{WorkerInfo, WorkerManager};

/// A binding must stay unchanged this long before its worker evicts payload
/// outside it: the previous engine's background tasks have finished by then.
pub(crate) const PAYLOAD_EVICTION_SETTLE: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);
/// Repeat interval for a settled binding. Requests are idempotent; repeats
/// retry refusals (pending mutations, an unfinished sync) and are cheap once
/// nothing remains outside the protected scopes.
const PAYLOAD_EVICTION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

pub type PendingShardChanges =
    Arc<dyn Fn() -> Result<Vec<quil_types::store::PendingShardChange>> + Send + Sync>;

struct EvictionTrack {
    filter: Vec<u8>,
    since: std::time::Instant,
    requested: Option<std::time::Instant>,
}

/// A rejected leave restores Active without renewing storage. Keep its worker
/// available to encode renewal until the end of the rejection epoch. This is
/// local recovery scheduling only: the allocation remains ExpiredEpoch for
/// committee membership and proof validation until registration lands.
pub(crate) fn rejected_leave_recovery_pending(
    allocation: &quil_types::consensus::ProverAllocationInfo,
    frame: u64,
) -> bool {
    use quil_types::consensus::{epoch_for_frame, EffectiveStatus};
    allocation.effective_status(frame) == EffectiveStatus::ExpiredEpoch
        && allocation.leave_reject_frame_number > allocation.leave_frame_number
        && allocation.leave_reject_frame_number > 0
        && frame >= allocation.leave_reject_frame_number
        && epoch_for_frame(frame) == epoch_for_frame(allocation.leave_reject_frame_number)
}

/// Why the allocator released a manual worker's seat, and whether a leave
/// ended it.
fn manual_release_reason(
    alloc: Option<&quil_types::consensus::ProverAllocationInfo>,
    frame_number: u64,
) -> (&'static str, bool) {
    use quil_types::consensus::EffectiveStatus;
    let Some(alloc) = alloc else {
        return ("join_never_landed", false);
    };
    match alloc.effective_status(frame_number) {
        EffectiveStatus::Kicked if alloc.leave_confirm_frame_number > 0 => {
            ("leave_confirmed", true)
        }
        EffectiveStatus::ExpiredLeaving => ("leave_departed", true),
        EffectiveStatus::Kicked => ("kicked", false),
        EffectiveStatus::Rejected => ("join_rejected", false),
        EffectiveStatus::ExpiredJoining => ("join_expired", false),
        EffectiveStatus::ExpiredEpoch => ("missed_epoch_renewal", false),
        EffectiveStatus::Historic => ("reassigned", false),
        // Still live: freed for an unbound allocation, a split child.
        _ => ("freed_for_split_child", false),
    }
}

/// Whether a GLOBAL head stamped `head_unix_ms` is current at `now_unix_ms`:
/// at most an epoch of ideal frame time old. An older stored head belongs to
/// a node returning from downtime, whose seats may have lapsed since.
pub fn stored_head_current(head_unix_ms: u64, now_unix_ms: u64) -> bool {
    let epoch_ms = quil_types::consensus::epoch_length_frames()
        .saturating_mul(crate::difficulty::IDEAL_FRAME_TIME.unsigned_abs());
    now_unix_ms.saturating_sub(head_unix_ms) <= epoch_ms
}

/// A recently expired storage registration gets one epoch to recover its
/// worker and publish renewal. This reserves local capacity only; it never
/// changes protocol membership, proof eligibility or the stored epoch.
/// Older abandoned allocations remain eligible for release and cleanup.
pub(crate) fn epoch_renewal_recovery_pending(
    allocation: &quil_types::consensus::ProverAllocationInfo,
    frame: u64,
) -> bool {
    use quil_types::consensus::{epoch_for_frame, EffectiveStatus};
    allocation.effective_status(frame) == EffectiveStatus::ExpiredEpoch
        && (allocation.epoch.checked_add(1) == Some(epoch_for_frame(frame))
            || rejected_leave_recovery_pending(allocation, frame))
}

/// Why this node gives up a data-shard seat it still holds
/// (`WorkerAllocator::gives_up`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GivenUp {
    /// Its storage registration lapsed past the recovery epoch, and no
    /// renewal of it runs or awaits the first renewal decision after this
    /// start: the allocator releases its worker and the lifecycle's orphan
    /// sweep leaves it.
    Lapsed,
    /// It is being left after its storage registration so lapsed, and the
    /// registry no longer seats it in its committee for its notice
    /// (`quil_execution::prover_registry::leaver_seated`, from the leaver
    /// currency frame on); a renewal naming a leaving seat is refused.
    LeftLapsed,
}

impl GivenUp {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Lapsed => {
                "its storage registration lapsed past its recovery epoch and no renewal of it runs"
            }
            Self::LeftLapsed => {
                "it is being left after its storage registration lapsed past its recovery epoch, \
                and its committee no longer seats it"
            }
        }
    }

    /// What the operator can do about it, and what ends it.
    pub fn action(self) -> &'static str {
        match self {
            Self::Lapsed => "none: unless a renewal of the seat starts, the allocator releases this worker and the \
                lifecycle leaves the seat",
            Self::LeftLapsed => "none: the allocator releases this worker and the seat departs at its leave boundary",
        }
    }
}

/// A seat this node gives up at GLOBAL `frame`, as the archive-recovery gate
/// reports it ([`WorkerAllocator::given_up_seat`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GivenUpSeat {
    pub cause: GivenUp,
    pub frame: u64,
    /// The epoch its storage was last registered for.
    pub allocation_epoch: u64,
    /// The epoch of `frame`.
    pub current_epoch: u64,
}

/// What a worker manager's workers ask before they recover a shard from an
/// archive: the GLOBAL frame it judges at, and the seat on that filter this
/// node gives up there, if it does ([`WorkerAllocator::install_recovery_gate`]).
pub type RecoveryGate = Arc<dyn Fn(&[u8]) -> (u64, Option<GivenUpSeat>) + Send + Sync>;

/// The registry's part of [`WorkerAllocator::gives_up`]: a seat lapsed past
/// its recovery epoch, or one left after it so lapsed that its committee no
/// longer seats. The planner leaves only seats lapsed past recovery as
/// unrecoverable orphans. A leaver the registry seats serves its notice,
/// whatever its epoch: until the leaver currency frame is set (it is not on
/// mainnet) that is every unexpired leaver; and a seat left while current,
/// or within its recovery epoch, is not given up either way.
fn lapsed_seat(
    allocation: &quil_types::consensus::ProverAllocationInfo,
    frame: u64,
) -> Option<GivenUp> {
    use quil_types::consensus::{epoch_for_frame, EffectiveStatus};
    match allocation.effective_status(frame) {
        EffectiveStatus::ExpiredEpoch if !epoch_renewal_recovery_pending(allocation, frame) => {
            Some(GivenUp::Lapsed)
        }
        EffectiveStatus::Leaving
            if !allocation.confirmation_filter.is_empty()
                && allocation.leave_frame_number > 0
                && allocation.epoch.saturating_add(1)
                    < epoch_for_frame(allocation.leave_frame_number)
                && !quil_execution::prover_registry::leaver_seated(allocation, frame) =>
        {
            Some(GivenUp::LeftLapsed)
        }
        _ => None,
    }
}

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
        if worker_manager.is_draining(core_id) {
            stats.skipped_missing_core += 1;
            warn!(
                index = i,
                core_id,
                "data_worker_filters: the worker is above the configured worker count and drains; skipping"
            );
            continue;
        }
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
/// Ceiling on holding a proposal's worker for a registry sync (see
/// `WorkerAllocator::hold_pending_joins_for_registry_sync`), so failing
/// syncs cannot pin it: about three five-minute syncs.
pub const PROPOSAL_SYNC_CEILING_FRAMES: u64 = 60;
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

/// Minimum frames between detailed reviews of a priority replacement that
/// cannot proceed while its source allocation still owns the worker.
pub const SURPLUS_REVIEW_INTERVAL_FRAMES: u64 = 30;

/// Bound the number of deferred replacement pairs reported in one review.
/// The complete candidate and holder inventories are logged once.
pub const MAX_DEFERRED_REPLACEMENTS_PER_REVIEW: usize = 4;

/// How often the rebind path repeats an unchanged outcome in the log.
/// Roughly ten minutes of frames — often enough that a fresh log window
/// always shows the current state, rare enough not to bury the log.
pub const REBIND_TELEMETRY_REPEAT_FRAMES: u64 = 75;

/// How often the orphan warning repeats while the same allocations stay
/// without a worker, about ten minutes of frames. A change of the orphan
/// set is logged at once.
pub const ORPHAN_WARNING_REPEAT_FRAMES: u64 = 75;

/// The allocations without a worker as of the last reconcile that found
/// some, for the bounded orphan warning ([`WorkerAllocator::watch_orphans`]).
struct OrphanWatch {
    /// Frame at which the current episode began.
    since_frame: u64,
    /// Frame of the last line logged for it.
    logged_frame: u64,
    /// The orphans as sorted `filter:Status` strings.
    set: Vec<String>,
}

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
    pub evidence: Option<AllocationPriorityEvidence>,
}

/// Inputs captured with a priority score, for explaining an actual worker move.
/// Counts describe effective statuses at `frame_number`, not peer liveness.
/// A stored ring may be a legacy decoder default; it is not proof of issuance.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AllocationPriorityEvidence {
    pub frame_number: u64,
    pub active: u32,
    pub joining: u32,
    pub paused: u32,
    pub leaving: u32,
    pub scoring_ring: u8,
    pub ring_source: &'static str,
    pub ring_member_count: Option<usize>,
    pub ring_target_frame: Option<u64>,
    pub size_bytes: u64,
    pub data_shards: u64,
    pub difficulty: u64,
    pub world_bytes_input: String,
    pub world_bytes_source: &'static str,
    pub allocation_epoch: Option<u64>,
    pub stored_ring: Option<u8>,
    pub allocation_status: Option<String>,
    pub allocation_raw_status: Option<String>,
    pub join_confirm_frame: Option<u64>,
    pub leave_frame: Option<u64>,
    pub leave_confirm_frame: Option<u64>,
    pub leave_reject_frame: Option<u64>,
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

/// Whether a priority gap warrants a diagnostic replacement review.
/// This never authorizes transferring a serving worker: a tier or score
/// improvement cannot change the source shard's committee membership.
fn replacement_priority_gap(challenger: &(u8, BigInt), holder: &(u8, BigInt)) -> bool {
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
    Stale {
        published_at: u64,
        age: u64,
    },
    Fresh(HashMap<Vec<u8>, AllocationPriorityEntry>),
}

/// What the rebind path did, or why it did nothing. Logged so
/// "no rebinding happened" is diagnosable without a debug build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebindOutcome {
    /// Better-ranked allocations exist, but serving workers are retained.
    ServiceRetained = 1,
    /// No ranking published yet: the lifecycle publishes from `evaluate`,
    /// which returns early while any readiness gate is closed — so this
    /// covers cold start, an unfinished prover-tree sync, an unverified
    /// tree, and shard-info never loading alike.
    NoRanking = 2,
    /// Ranking too old to act on.
    RankingStale = 3,
    /// Within `SURPLUS_REVIEW_INTERVAL_FRAMES` of the last rebind.
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
            Self::ServiceRetained => "service_retained",
            Self::NoRanking => "no_ranking_published",
            Self::RankingStale => "ranking_stale",
            Self::Cooldown => "cooldown",
            Self::NoEligibleOrphan => "no_eligible_orphan",
            Self::NoEvictableWorker => "no_evictable_worker",
            Self::BelowMargin => "below_margin",
        }
    }
}

/// How far a worker's held shard may trail the frame GLOBAL committed for
/// it and still be bound to that worker: an epoch's worth of frames. A
/// lineage further behind replays that many frames from archives, a cost
/// that outgrows the install a worker without it makes.
fn shard_data_trail() -> u64 {
    quil_types::consensus::epoch_length_frames()
}

/// For each of `filters` in turn, the worker among `eligible` whose store
/// holds that shard's data (`holders`, [`WorkerManager::shard_data`]): the
/// one with the highest materialized cursor, then the lowest core, among
/// those within [`shard_data_trail`] of the shard's committed tip (`tip`;
/// any holder when it is unknown). Each worker is chosen once; a filter no
/// eligible worker holds is absent.
fn data_holders<'a>(
    filters: impl Iterator<Item = &'a [u8]>,
    eligible: &[u32],
    holders: &HashMap<u32, Vec<(Vec<u8>, u64)>>,
    tip: impl Fn(&[u8]) -> Option<u64>,
) -> HashMap<Vec<u8>, u32> {
    let mut chosen: HashMap<Vec<u8>, u32> = HashMap::new();
    for filter in filters {
        let tip = tip(filter);
        let best = eligible
            .iter()
            .filter(|core| !chosen.values().any(|taken| taken == *core))
            .filter_map(|core| {
                let (_, cursor) = holders
                    .get(core)?
                    .iter()
                    .find(|(held, _)| held.as_slice() == filter)?;
                Some((*cursor, *core))
            })
            .filter(|(cursor, _)| {
                tip.is_none_or(|tip| cursor.saturating_add(shard_data_trail()) >= tip)
            })
            .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
        if let Some((_, core)) = best {
            chosen.entry(filter.to_vec()).or_insert(core);
        }
    }
    chosen
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
    /// Serialize frame-driven and registry-sync reconciliation so their
    /// release/bind passes cannot compete for the same idle worker.
    reconcile_lock: std::sync::Mutex<()>,
    /// Shard operations in progress, shared with the lifecycle that
    /// dispatches them.
    pub(crate) submission_attempts: Arc<crate::submission_attempts::SubmissionAttempts>,
    /// Seats a worker still served when this process started although their
    /// storage registration had lapsed past its recovery epoch: a renewal
    /// was running when the node stopped, or the node was down for an epoch.
    /// `None` until the first reconcile that finds this prover registered.
    interrupted_seats: std::sync::Mutex<Option<std::collections::HashSet<Vec<u8>>>>,
    /// The latest GLOBAL frame a reconcile ran at: the frame the registry it
    /// reads reflects, at which the recovery gate judges seats.
    reconciled_frame: std::sync::atomic::AtomicU64,
    /// The lifecycle has decided renewals since this process started.
    renewals_offered: std::sync::atomic::AtomicBool,
    /// Workers the lifecycle holds back from new seats for sending no vote
    /// ([`Self::set_held_back`]).
    held_back: std::sync::Mutex<std::collections::HashSet<u32>>,
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
    /// First epoch in which a seniority merge may be proposed again, set
    /// when none of this node's merge targets was creditable.
    seniority_merge_resume_epoch: std::sync::atomic::AtomicU64,
    /// Latest lifecycle-published allocation ranking, consulted when
    /// this node holds more allocations than it has worker slots.
    /// `None` until the first `publish_allocation_priority`.
    allocation_priority: RwLock<Option<AllocationPriority>>,
    /// Frame of the last detailed deferred-replacement review. Gates
    /// `SURPLUS_REVIEW_INTERVAL_FRAMES`.
    last_priority_review_frame: std::sync::atomic::AtomicU64,
    /// Last logged `RebindOutcome` (as its discriminant) and the frame
    /// it was logged at, for the rate limiter in `log_rebind_outcome`.
    last_rebind_outcome: std::sync::atomic::AtomicU64,
    last_rebind_outcome_frame: std::sync::atomic::AtomicU64,
    /// See `hold_pending_joins_for_registry_sync`.
    pending_joins_await_sync: std::sync::atomic::AtomicBool,
    /// Frame at which each running prover-tree sync began.
    registry_syncs_running: std::sync::Mutex<HashMap<u64, u64>>,
    /// Latest begin frame of a sync that has refreshed the registry.
    registry_synced_from_frame: std::sync::atomic::AtomicU64,
    /// Once-guard for the prover-reset-v3 worker-filter reset (mainnet frame
    /// 747_000). Fires exactly at that frame in `on_new_frame`, clearing every
    /// AUTO-managed worker's persisted deep filter so re-join lands on the clean
    /// genesis grid (the local worker store is what survived the v2 tree wipe and
    /// re-fed the cascade). In-memory is sufficient: the gate is the exact frame
    /// (processed once, monotonic) and the clear is idempotent — unlike the
    /// prover-TREE reseed, re-clearing auto filters has no harmful effect.
    worker_reset_v3_done: std::sync::atomic::AtomicBool,
    /// Authenticated GLOBAL state, for committee-session retention: a worker
    /// whose committee session is closing stays bound until its terminal seal
    /// is recorded, whatever the registry says about the allocation meanwhile.
    /// The closing committee needs its quorum to finalize that seal.
    session_authority: RwLock<Option<Arc<quil_hypergraph::HypergraphCrdt>>>,
    /// Staged splits and merges. A confirmation encodes their targets from the
    /// confirming worker's store, so they stay protected from eviction. Unset
    /// means unknown: no eviction is requested.
    pending_shard_changes: RwLock<Option<PendingShardChanges>>,
    payload_eviction: std::sync::Mutex<HashMap<u32, EvictionTrack>>,
    /// The running orphan episode, `None` while every seat has a worker.
    orphan_watch: std::sync::Mutex<Option<OrphanWatch>>,
}

impl WorkerAllocator {
    /// Whether a missed renewal may keep or recover its worker: within the
    /// recovery epoch, or for as long as this node's renewal of it is still
    /// running or awaiting its retry. A renewal stuck in preparation past the
    /// recovery epoch would otherwise lose its worker, and the orphan sweep
    /// then proposes leaving a registration the protocol still accepts.
    /// Only a confirm counts: a seat whose leave is in flight is not being
    /// renewed, and a confirm naming it once it is Leaving is refused.
    pub(crate) fn renewal_recovering(
        &self,
        allocation: &quil_types::consensus::ProverAllocationInfo,
        frame: u64,
    ) -> bool {
        epoch_renewal_recovery_pending(allocation, frame)
            || (allocation.effective_status(frame)
                == quil_types::consensus::EffectiveStatus::ExpiredEpoch
                && self
                    .submission_attempts
                    .confirming(&allocation.confirmation_filter, frame))
    }

    /// Whether a lapsed seat keeps its worker until the lifecycle first
    /// decides renewals after this process started. What keeps the worker of
    /// a running renewal past the recovery epoch ([`Self::renewal_recovering`])
    /// lives in memory, so after a restart the first reconcile, which runs
    /// before the first evaluation, released the worker: the seat then got
    /// no renewal, which renews bound seats only, and the orphan sweep
    /// proposed leaving it. Only seats a worker was bound to at startup are
    /// kept; a renewal dispatched for one keeps it from then on as before.
    fn awaits_renewal_offer(
        &self,
        allocation: &quil_types::consensus::ProverAllocationInfo,
        frame: u64,
    ) -> bool {
        !self
            .renewals_offered
            .load(std::sync::atomic::Ordering::Acquire)
            && allocation.effective_status(frame)
                == quil_types::consensus::EffectiveStatus::ExpiredEpoch
            && self
                .interrupted_seats
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|seats| seats.contains(&allocation.confirmation_filter))
    }

    /// The lifecycle has decided which seats renew; see
    /// [`Self::awaits_renewal_offer`].
    pub(crate) fn note_renewals_offered(&self) {
        self.renewals_offered
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether this node gives up `allocation` at GLOBAL `frame`, and why: a
    /// data-shard seat lapsed past its recovery epoch that no renewal of this
    /// node is running for or waits on ([`Self::renewal_recovering`],
    /// [`Self::awaits_renewal_offer`]), or one being left after it so lapsed
    /// that its committee no longer seats. Nothing renews such a seat. The
    /// reconcile releases its worker (unless its committee session retains
    /// it) and binds none to it, the lifecycle's orphan sweep leaves it, and
    /// workers recover none of its shard from archives
    /// ([`Self::install_recovery_gate`]): one rule, so they cannot disagree
    /// (an operator's node recovered 1.26M leaves per shard of nine seats
    /// lapsed 18 epochs, which its planner then left).
    pub(crate) fn gives_up(
        &self,
        allocation: &quil_types::consensus::ProverAllocationInfo,
        frame: u64,
    ) -> Option<GivenUp> {
        match lapsed_seat(allocation, frame)? {
            GivenUp::Lapsed
                if self.renewal_recovering(allocation, frame)
                    || self.awaits_renewal_offer(allocation, frame) =>
            {
                None
            }
            given_up => Some(given_up),
        }
    }

    /// The seat on `filter` this node gives up at GLOBAL `frame`
    /// ([`Self::gives_up`]), from the registry, for the recovery gate: `None`
    /// while the registry lists no such seat or one on `filter` it still
    /// serves, and fail-open in two cases where the reconcile keeps the
    /// worker too. Before the first reconcile finds this prover registered,
    /// the seats a worker served at this start, which keep it until renewals
    /// are decided ([`Self::awaits_renewal_offer`]), are not known yet: no
    /// lapsed seat is given up then, so a bootstrap a starting engine asks
    /// for once is not lost. And a worker its committee session retains
    /// still serves that session.
    pub fn given_up_seat(&self, filter: &[u8], frame: u64) -> Option<GivenUpSeat> {
        let prover = self
            .prover_registry
            .get_prover_info(&self.local_prover_address)
            .ok()
            .flatten()?;
        let seat = self.given_up_among(&prover.allocations, filter, frame)?;
        let reconciled = self
            .interrupted_seats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        if seat.cause == GivenUp::Lapsed && !reconciled {
            return None;
        }
        if self.session_retains(filter, &prover.public_key) {
            return None;
        }
        Some(seat)
    }

    /// Whether the committee session on `filter` retains this node's worker
    /// there, `member` being this prover's key: the reconcile's retention
    /// (`app_handoff::retains_worker`).
    fn session_retains(&self, filter: &[u8], member: &[u8]) -> bool {
        !filter.is_empty()
            && self
                .session_authority
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|global| crate::app_handoff::retains_worker(global, filter, member))
    }

    /// The seat on `filter` among this prover's `allocations` that this node
    /// gives up at GLOBAL `frame` ([`Self::gives_up`]): `None` when none is,
    /// or another, non-terminal allocation on `filter` is not given up (one
    /// still served, or Paused, Historic or Unknown).
    pub(crate) fn given_up_among(
        &self,
        allocations: &[quil_types::consensus::ProverAllocationInfo],
        filter: &[u8],
        frame: u64,
    ) -> Option<GivenUpSeat> {
        let mut given_up = None;
        for allocation in allocations
            .iter()
            .filter(|a| a.confirmation_filter == filter)
        {
            match self.gives_up(allocation, frame) {
                Some(cause) => {
                    given_up.get_or_insert(GivenUpSeat {
                        cause,
                        frame,
                        allocation_epoch: allocation.epoch,
                        current_epoch: quil_types::consensus::epoch_for_frame(frame),
                    });
                }
                None if !allocation.effective_status(frame).is_terminal() => return None,
                None => {}
            }
        }
        given_up
    }

    /// Have the workers ask [`Self::given_up_seat`] before they recover a
    /// shard from an archive, at the frame the latest reconcile ran at: the
    /// registry follows executed GLOBAL state, so judged at a gossip head
    /// beyond it, every seat of a node whose execution lags would read lapsed
    /// and lose its catch-up recovery while the reconcile keeps its worker.
    /// Until the registry has loaded, or a reconcile has run, it gives
    /// nothing up.
    pub fn install_recovery_gate(self: &Arc<Self>) {
        let allocator = Arc::downgrade(self);
        self.worker_manager
            .set_recovery_gate(Arc::new(move |filter: &[u8]| {
                let Some(allocator) = allocator.upgrade() else {
                    return (0, None);
                };
                let frame = allocator
                    .reconciled_frame
                    .load(std::sync::atomic::Ordering::Relaxed);
                (frame, allocator.given_up_seat(filter, frame))
            }));
    }

    /// Tell the operator about each manual worker this pass released and
    /// left idle. Releases are mode-agnostic: a seat that expired, was
    /// rejected or evicted, or was vacated for a split child frees a manual
    /// worker like any other. The lifecycle plans joins for auto workers
    /// only, so an idle manual worker serves nothing until the operator
    /// joins it to a shard, or until an allocation of this prover lands
    /// unbound, which the bind pass gives to manual workers first (the
    /// TUI's join relies on that). Logged once, on the transition; a leave
    /// the operator asked for idles it as intended, so that is info only.
    fn log_idled_manual_workers(
        &self,
        frame_number: u64,
        manual_seats: &[(u32, Vec<u8>)],
        alloc_by_filter: &HashMap<Vec<u8>, &quil_types::consensus::ProverAllocationInfo>,
    ) -> Result<()> {
        if manual_seats.is_empty() {
            return Ok(());
        }
        let workers = self.worker_manager.range_workers()?;
        for (core_id, filter) in manual_seats {
            if !workers
                .iter()
                .any(|w| w.core_id == *core_id && w.manually_managed && w.filter.is_empty())
            {
                continue;
            }
            let (reason, left) =
                manual_release_reason(alloc_by_filter.get(filter).copied(), frame_number);
            if left {
                info!(core_id, filter = %hex::encode(filter), frame = frame_number, reason,
                    "manual worker idle after leaving its shard; the lifecycle does not join manual \
                     workers: join it to a shard or switch it to auto");
            } else {
                warn!(core_id, filter = %hex::encode(filter), frame = frame_number, reason,
                    "manual worker lost its seat and is idle; the lifecycle does not join manual \
                     workers: join it to a shard or switch it to auto");
            }
        }
        Ok(())
    }

    /// Free a worker, unless its committee session is still closing or its
    /// seat still owes a storage epoch proof.
    fn release_worker(&self, worker: &WorkerInfo, retained: bool) -> Result<()> {
        if retained {
            debug!(core_id = worker.core_id, filter = hex::encode(&worker.filter),
                "committee session or storage settlement still needs this member; worker stays bound");
            return Ok(());
        }
        self.worker_manager.deallocate_worker(worker.core_id)
    }

    /// Whether this prover's seat on `filter` still owes GLOBAL an epoch proof
    /// for roots it committed: a sealed, open slot of the previous or current
    /// epoch with committed roots, whose settlement window has not closed.
    /// Only the shard's engine proves a seat, and GLOBAL kicks a member that
    /// committed roots and never proved them, so the worker stays bound (and
    /// its engine running) until the epoch settles or its window closes.
    fn owes_storage_settlement(&self, filter: &[u8], frame_number: u64) -> bool {
        use quil_types::consensus::{epoch_for_frame, hash_storage_proofs_at};
        let current = epoch_for_frame(frame_number);
        [current.saturating_sub(1), current].into_iter().any(|epoch| {
            hash_storage_proofs_at(epoch)
                && self.prover_registry.get_storage_seat_slot(&self.local_prover_address, filter, epoch).ok().flatten()
                    .is_some_and(|slot| {
                        slot.sealed_at.is_some() && slot.open && slot.frames > 0
                            && frame_number < quil_execution::global_intrinsic::storage_seat::settlement_window(epoch).1
                    })
        })
    }

    /// The frame GLOBAL committed for each of `filters` that has one
    /// ([`crate::app_handoff::committed_tips`]); none without authenticated
    /// GLOBAL state or when it is unreadable.
    fn committed_tips(&self, filters: &[Vec<u8>]) -> HashMap<Vec<u8>, u64> {
        let Some(global) = self
            .session_authority
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return HashMap::new();
        };
        match crate::app_handoff::committed_tips(&global, filters) {
            Ok(tips) => tips.into_iter().collect(),
            Err(error) => {
                debug!(%error, "committed shard tips unreadable; binding prefers any holder of a shard's data");
                HashMap::new()
            }
        }
    }

    pub fn set_session_authority(&self, global: Arc<quil_hypergraph::HypergraphCrdt>) {
        *self
            .session_authority
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(global);
    }

    /// Of `filters`, those whose current committee session counts `member`
    /// ([`crate::app_handoff::member_sessions`]). Empty without authenticated
    /// GLOBAL state or when it is unreadable: no seat is then held to
    /// hosting a session. `None` while a GLOBAL state sync withholds the
    /// committed view: membership is then unknown, not empty.
    pub(crate) fn session_member_filters(
        &self,
        filters: &[Vec<u8>],
        member: &[u8],
    ) -> Option<std::collections::HashSet<Vec<u8>>> {
        let Some(global) = self
            .session_authority
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return Some(Default::default());
        };
        match crate::app_handoff::member_sessions(&global, filters, member) {
            Ok(members) => Some(members),
            Err(error)
                if quil_execution::global_intrinsic::handoff::global_sync_in_progress(&error) =>
            {
                debug!(%error, "committee sessions withheld by a GLOBAL state sync; seat hosting is not observed");
                None
            }
            Err(error) => {
                debug!(%error, "committee sessions unreadable; no seat is held to hosting");
                Some(Default::default())
            }
        }
    }

    pub fn new(
        worker_manager: Arc<dyn WorkerManager>,
        prover_registry: Arc<dyn ProverRegistry>,
        local_prover_address: Vec<u8>,
    ) -> Self {
        Self {
            reconcile_lock: std::sync::Mutex::new(()),
            submission_attempts: Arc::new(crate::submission_attempts::SubmissionAttempts::default()),
            interrupted_seats: std::sync::Mutex::new(None),
            reconciled_frame: std::sync::atomic::AtomicU64::new(0),
            renewals_offered: std::sync::atomic::AtomicBool::new(false),
            held_back: Default::default(),
            worker_manager,
            prover_registry,
            local_prover_address,
            cooldowns: [
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
            ],
            config_seniority_estimate: std::sync::atomic::AtomicU64::new(u64::MAX),
            seniority_merge_resume_epoch: std::sync::atomic::AtomicU64::new(0),
            allocation_priority: RwLock::new(None),
            session_authority: RwLock::new(None),
            last_priority_review_frame: std::sync::atomic::AtomicU64::new(0),
            last_rebind_outcome: std::sync::atomic::AtomicU64::new(0),
            last_rebind_outcome_frame: std::sync::atomic::AtomicU64::new(0),
            pending_joins_await_sync: std::sync::atomic::AtomicBool::new(false),
            registry_syncs_running: std::sync::Mutex::new(HashMap::new()),
            registry_synced_from_frame: std::sync::atomic::AtomicU64::new(0),
            worker_reset_v3_done: std::sync::atomic::AtomicBool::new(false),
            pending_shard_changes: RwLock::new(None),
            payload_eviction: std::sync::Mutex::new(HashMap::new()),
            orphan_watch: std::sync::Mutex::new(None),
        }
    }

    /// Log the allocations left without a worker, once per episode and
    /// change of its set, then every `ORPHAN_WARNING_REPEAT_FRAMES` while it
    /// lasts, and its end when the set empties. A node under a lowered worker
    /// count reconciles every frame with the same orphans, so a line per
    /// pass would repeat one fact about a hundred times an hour. Returns the
    /// event logged, if any.
    fn watch_orphans(
        &self,
        frame_number: u64,
        orphans: &[(Vec<u8>, ProverStatus)],
        draining: usize,
    ) -> Option<&'static str> {
        let mut watch = self.orphan_watch.lock().unwrap_or_else(|e| e.into_inner());
        let capacity = self
            .worker_manager
            .allocation_capacity()
            .unwrap_or_default();
        let bound = self
            .worker_manager
            .range_workers()
            .map(|ws| ws.iter().filter(|w| !w.filter.is_empty()).count())
            .unwrap_or_default();
        if orphans.is_empty() {
            if let Some(ended) = watch.take() {
                info!(
                    frame_number,
                    since_frame = ended.since_frame,
                    orphaned_frames = frame_number.saturating_sub(ended.since_frame),
                    bound_workers = bound,
                    configured_workers = capacity,
                    "every allocation has a worker again; the allocations without one have left or been bound"
                );
                return Some("ended");
            }
            return None;
        }
        let mut set: Vec<String> = orphans
            .iter()
            .map(|(f, s)| format!("{}:{:?}", hex::encode(f), s))
            .collect();
        set.sort();
        let (event, since_frame) = match watch.as_ref() {
            None => ("started", frame_number),
            Some(w) if w.set != set => ("changed", w.since_frame),
            Some(w) if frame_number.abs_diff(w.logged_frame) >= ORPHAN_WARNING_REPEAT_FRAMES => {
                ("continues", w.since_frame)
            }
            Some(_) => return None,
        };
        *watch = Some(OrphanWatch {
            since_frame,
            logged_frame: frame_number,
            set,
        });
        let count_of = |status: ProverStatus| orphans.iter().filter(|(_, s)| *s == status).count();
        let sample: Vec<String> = orphans
            .iter()
            .take(8)
            .map(|(f, s)| format!("{}:{:?}", hex::encode(f), s))
            .collect();
        warn!(
            event,
            orphan_count = orphans.len(),
            joining = count_of(ProverStatus::Joining),
            active = count_of(ProverStatus::Active),
            leaving = count_of(ProverStatus::Leaving),
            bound_workers = bound,
            configured_workers = capacity,
            draining_workers = draining,
            frame_number,
            since_frame,
            orphaned_frames = frame_number.saturating_sub(since_frame),
            ?sample,
            "allocations without a worker: this node holds more seats than it has workers \
             (a lowered dataWorkerCount, lost workers or overlapping joins). An expected wait: \
             an unconfirmed Joining seat expires after its confirm epoch, a Leaving seat departs \
             at its confirmed boundary or expiry, an Active seat leaves through the surplus \
             leave or lapses when its reconfirm is missed. Report it only if it outlasts these"
        );
        Some(event)
    }

    /// The workers held back from new seats for sending no vote in their
    /// last one: the bind pass gives them an unbound seat only after every
    /// other idle worker.
    pub(crate) fn set_held_back(&self, cores: std::collections::HashSet<u32>) {
        *self.held_back.lock().unwrap_or_else(|e| e.into_inner()) = cores;
    }

    pub fn set_pending_shard_changes(&self, changes: PendingShardChanges) {
        *self
            .pending_shard_changes
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(changes);
    }

    /// Ask each settled, serving worker to drop payload its store keeps from
    /// shards it no longer serves. Protected: the binding (a closing session
    /// keeps it bound) and staged split/merge filters of the bound
    /// application.
    pub(crate) fn schedule_payload_eviction(&self, now: std::time::Instant) -> Result<()> {
        let _reconcile = self
            .reconcile_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(changes) = self
            .pending_shard_changes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return Ok(());
        };
        let workers = self.worker_manager.range_workers()?;
        let mut tracks = self
            .payload_eviction
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        tracks.retain(|core, _| workers.iter().any(|w| w.core_id == *core));
        let mut due = Vec::new();
        for worker in &workers {
            if worker.filter.is_empty() || !worker.allocated || worker.pending_filter_frame != 0 {
                tracks.remove(&worker.core_id);
                continue;
            }
            let track = tracks
                .entry(worker.core_id)
                .or_insert_with(|| EvictionTrack {
                    filter: worker.filter.clone(),
                    since: now,
                    requested: None,
                });
            if track.filter != worker.filter {
                *track = EvictionTrack {
                    filter: worker.filter.clone(),
                    since: now,
                    requested: None,
                };
            }
            let settled = now.saturating_duration_since(track.since) >= PAYLOAD_EVICTION_SETTLE;
            let repeat = track
                .requested
                .is_none_or(|at| now.saturating_duration_since(at) >= PAYLOAD_EVICTION_INTERVAL);
            if settled && repeat {
                due.push(worker.core_id);
            }
        }
        if due.is_empty() {
            return Ok(());
        }
        let staged = changes()?;
        // A regular node never consumes staged changes, so a change whose
        // shards are all gone would protect their payload forever. Retained
        // historic, rejected or kicked slots do not hold a shard.
        let held: std::collections::HashSet<Vec<u8>> = if staged.is_empty() {
            Default::default()
        } else {
            self.prover_registry
                .get_all_active_app_shard_provers()?
                .into_iter()
                .flat_map(|p| p.allocations)
                .filter(|a| {
                    matches!(
                        a.status,
                        ProverStatus::Joining
                            | ProverStatus::Active
                            | ProverStatus::Paused
                            | ProverStatus::Leaving
                    )
                })
                .map(|a| a.confirmation_filter)
                .chain(workers.iter().map(|w| w.filter.clone()))
                .filter(|f| !f.is_empty())
                .collect()
        };
        let staged: Vec<_> = staged
            .into_iter()
            .filter(|c| {
                std::iter::once(&c.parent)
                    .chain(c.children.iter())
                    .any(|f| held.contains(f))
            })
            .collect();
        for worker in workers.iter().filter(|w| due.contains(&w.core_id)) {
            let application = &worker.filter[..worker.filter.len().min(32)];
            let mut keep = vec![worker.filter.clone()];
            keep.extend(
                staged
                    .iter()
                    .flat_map(|c| std::iter::once(&c.parent).chain(c.children.iter()))
                    .filter(|f| f.len() >= 32 && f[..32] == *application)
                    .cloned(),
            );
            keep.sort();
            keep.dedup();
            match self.worker_manager.evict_payload(worker.core_id, keep) {
                Ok(()) => {
                    if let Some(track) = tracks.get_mut(&worker.core_id) {
                        track.requested = Some(now);
                    }
                }
                Err(error) => {
                    warn!(core_id = worker.core_id, %error, "worker payload eviction request failed")
                }
            }
        }
        Ok(())
    }

    /// Cached config-derived seniority estimate. Computed once at
    /// startup by the node binary (which has the config + local peer
    /// key available). 0 if not wired.
    pub fn config_seniority_estimate(&self) -> u64 {
        let v = self
            .config_seniority_estimate
            .load(std::sync::atomic::Ordering::Relaxed);
        if v == u64::MAX {
            0
        } else {
            v
        }
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
        self.cooldowns[kind as usize].fetch_max(frame_number, std::sync::atomic::Ordering::Relaxed);
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
    /// Hold seniority merges for the rest of `frame_number`'s epoch: GLOBAL
    /// already consumed every merge target. The next epoch checks again.
    pub fn hold_seniority_merge(&self, frame_number: u64) {
        let resume = quil_types::consensus::epoch_for_frame(frame_number) + 1;
        self.seniority_merge_resume_epoch
            .fetch_max(resume, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn seniority_merge_held(&self, frame_number: u64) -> bool {
        quil_types::consensus::epoch_for_frame(frame_number)
            < self
                .seniority_merge_resume_epoch
                .load(std::sync::atomic::Ordering::Relaxed)
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

    /// For a node whose registry shows a landed join only after the next
    /// prover-tree sync (every five minutes, about 20 frames on mainnet):
    /// keep a proposal's worker reserved past `PROPOSAL_TIMEOUT_FRAMES` until
    /// a sync begun after the join's inclusion has refreshed the registry.
    /// Freed earlier, the worker is proposed for a second shard while the
    /// first join is still on its way.
    pub fn hold_pending_joins_for_registry_sync(&self) {
        self.pending_joins_await_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// A prover-tree sync numbered `sync` began at `frame_number`.
    pub fn note_registry_sync_begun(&self, sync: u64, frame_number: u64) {
        if let Ok(mut running) = self.registry_syncs_running.lock() {
            running.insert(sync, frame_number);
        }
    }

    /// The registry now reflects the prover-tree sync numbered `sync`.
    pub fn note_registry_synced(&self, sync: u64) {
        let Ok(mut running) = self.registry_syncs_running.lock() else {
            return;
        };
        if let Some(frame) = running.remove(&sync) {
            self.registry_synced_from_frame
                .fetch_max(frame, std::sync::atomic::Ordering::SeqCst);
        }
        running.retain(|later, _| *later > sync);
    }

    /// Whether a join proposed at `pending_frame` (included at the next
    /// frame) may still appear with the next registry sync, holding its
    /// worker for at most `PROPOSAL_SYNC_CEILING_FRAMES`.
    fn join_awaits_registry_sync(&self, pending_frame: u64, frame_number: u64) -> bool {
        pending_frame > 0
            && frame_number <= pending_frame + PROPOSAL_SYNC_CEILING_FRAMES
            && self.registry_may_lack_join(pending_frame)
    }

    /// Whether the registry may still lack a join proposed at
    /// `proposed_frame` (included at the next frame): on a node whose
    /// registry shows a landed join only after a prover-tree sync, no sync
    /// begun after the inclusion has refreshed it yet. A sync anchors at the
    /// frame before its begin frame.
    pub(crate) fn registry_may_lack_join(&self, proposed_frame: u64) -> bool {
        self.pending_joins_await_sync
            .load(std::sync::atomic::Ordering::SeqCst)
            && self
                .registry_synced_from_frame
                .load(std::sync::atomic::Ordering::SeqCst)
                <= proposed_frame + 1
    }

    /// Clear the pending-join marker of a worker still idle after the bind
    /// pass once its join is past `PROPOSAL_TIMEOUT_FRAMES` (and any registry
    /// sync hold). `submit_join` sets the marker BEFORE the allocation lands
    /// in the registry, so the lifecycle's `free_auto()` won't re-pick the
    /// worker mid-flight; a marker that outlived a lost join would exclude
    /// the worker from `free_auto()` for good and wedge the lifecycle (no
    /// free workers, no new ProposeJoin).
    ///
    /// Runs after the bind pass: a join whose first registry sync arrives
    /// past the timeout binds its worker in the same pass and keeps the
    /// marker until it is confirmed. A worker left idle although the
    /// registry holds an allocation joined at or after its proposal frame
    /// lost the binding to another worker (or the join was decided
    /// already); its reservation is released without claiming the join was
    /// dropped.
    fn expire_unlanded_join_markers(
        &self,
        frame_number: u64,
        allocations: &[quil_types::consensus::ProverAllocationInfo],
    ) -> Result<()> {
        for worker in self.worker_manager.range_workers()? {
            let pending = worker.pending_filter_frame;
            if !worker.filter.is_empty()
                || pending == 0
                || frame_number <= pending + PROPOSAL_TIMEOUT_FRAMES
                || self.join_awaits_registry_sync(pending, frame_number)
            {
                continue;
            }
            let landed = allocations.iter().find(|a| a.join_frame_number >= pending);
            match landed {
                Some(alloc) => info!(
                    core_id = worker.core_id,
                    pending_since = pending,
                    join_frame = alloc.join_frame_number,
                    status = ?alloc.status,
                    filter = hex::encode(&alloc.confirmation_filter),
                    "join landed in the registry but not on this worker; releasing \
                     the worker's join reservation"
                ),
                // Warn, not info: submit_join returned Ok (no transport
                // error visible) but no allocation joined in the proposal
                // window reached the registry, which usually means an archive
                // accepted the bundle and then dropped it during
                // materialization (stale frame_number on archive-side
                // materialize, BLS / VDF rejection, prover-state gate). The
                // operator can spot a string of these before the lifecycle's
                // retry burns more attempts.
                None => warn!(
                    core_id = worker.core_id,
                    frame = frame_number,
                    pending_since = pending,
                    frames_elapsed = frame_number - pending,
                    "join submitted but no alloc landed in registry within 10 frames \
                     — archive likely dropped the bundle silently"
                ),
            }
            let _ = self
                .worker_manager
                .set_pending_filter_frame(worker.core_id, 0);
        }
        Ok(())
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
        self.publish_allocation_priority_with_evidence(frame_number, entries, HashMap::new());
    }

    /// Publish scores and their original inputs under the same lock. Reading
    /// counts again during reconcile could otherwise describe a different tree.
    pub fn publish_allocation_priority_with_evidence(
        &self,
        frame_number: u64,
        entries: Vec<(Vec<u8>, bool, BigInt)>,
        mut evidence: HashMap<Vec<u8>, AllocationPriorityEvidence>,
    ) {
        let entries = entries
            .into_iter()
            .map(|(filter, halt_risk, score)| {
                let evidence = evidence.remove(&filter);
                (
                    filter,
                    AllocationPriorityEntry {
                        halt_risk,
                        score,
                        evidence,
                    },
                )
            })
            .collect();
        if let Ok(mut guard) = self.allocation_priority.write() {
            *guard = Some(AllocationPriority {
                frame_number,
                entries,
            });
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
        let due =
            last_frame == 0 || frame_number.abs_diff(last_frame) >= REBIND_TELEMETRY_REPEAT_FRAMES;
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
    /// The startup reconcile, at the stored GLOBAL head `head` (stamped
    /// `head_unix_ms`) before any frame arrives from the network; run only
    /// when that head is current ([`stored_head_current`]). Judged at an
    /// older head, the seats of a node returning from downtime look as they
    /// were before it: workers were bound to, and recovered the shards of,
    /// seats lapsed since, which nothing renews (an operator's node back
    /// after 18 epochs installed 1.26M leaves per shard of nine), and the
    /// seats a worker served at this start were latched there
    /// ([`Self::awaits_renewal_offer`]). The node waits instead for its
    /// first reconcile at a current frame: the archive poller's after the
    /// startup state jump, the registry sync's at its authenticated cursor,
    /// or an executed frame's. Workers restored from the store start no
    /// engine before a reconcile. Returns whether it reconciled.
    pub fn startup_reconcile(
        &self,
        head: u64,
        head_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<bool> {
        if !stored_head_current(head_unix_ms, now_unix_ms) {
            return Ok(false);
        }
        self.on_new_frame(head)?;
        Ok(true)
    }

    pub fn on_new_frame(&self, frame_number: u64) -> Result<()> {
        let result = self.reconcile(frame_number);
        if let Err(error) = self.schedule_payload_eviction(std::time::Instant::now()) {
            warn!(%error, "worker payload eviction not scheduled");
        }
        result
    }

    fn reconcile(&self, frame_number: u64) -> Result<()> {
        let _reconcile = self
            .reconcile_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.reconciled_frame
            .fetch_max(frame_number, std::sync::atomic::Ordering::Relaxed);
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
                == quil_execution::global_intrinsic::materialize::quil_prover_reset_v4_frame()
            || frame_number
                == quil_execution::global_intrinsic::materialize::quil_prover_reset_v5_frame())
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

        // A node loads its prover registry in the background at startup.
        // Read before that load ends, it shows none of our allocations, and
        // every bound worker below would be released as orphaned.
        if !self.prover_registry.initial_load_complete() {
            info!(
                frame = frame_number,
                "worker reconcile deferred: the prover registry has not finished its first load from the store",
            );
            return Ok(());
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

        // The seats the first reconcile finds bound although lapsed past
        // recovery; see `awaits_renewal_offer`.
        if prover_info.is_some() {
            let mut seats = self
                .interrupted_seats
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if seats.is_none() {
                let found: std::collections::HashSet<Vec<u8>> = workers
                    .iter()
                    .filter(|w| !w.filter.is_empty())
                    .filter(|w| {
                        alloc_by_filter.get(&w.filter).is_some_and(|a| {
                            a.effective_status(frame_number)
                                == quil_types::consensus::EffectiveStatus::ExpiredEpoch
                                && !self.renewal_recovering(a, frame_number)
                        })
                    })
                    .map(|w| w.filter.clone())
                    .collect();
                if !found.is_empty() {
                    info!(frame = frame_number, seats = found.len(),
                        filters = ?found.iter().map(hex::encode).collect::<Vec<_>>(),
                        "seats lapsed past their recovery epoch keep their workers until the lifecycle \
                         decides renewals after this start");
                }
                *seats = Some(found);
            }
        }

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
                a.status == ProverStatus::Active && !bound_filters.contains(&a.confirmation_filter)
            });

        // Seats of manual workers at the start of this pass; see
        // `log_idled_manual_workers`.
        let manual_seats: Vec<(u32, Vec<u8>)> = workers
            .iter()
            .filter(|w| w.manually_managed && !w.filter.is_empty())
            .map(|w| (w.core_id, w.filter.clone()))
            .collect();

        let session_authority = self
            .session_authority
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let local_public_key = prover_info.as_ref().map(|p| p.public_key.clone());
        for worker in &workers {
            // Retention only withholds a RELEASE below. Everything else in this
            // pass (notably starting the engine once the allocation is Active)
            // must still run for a retained worker.
            let retained = match (session_authority.as_ref(), local_public_key.as_ref()) {
                (Some(global), Some(member)) if !worker.filter.is_empty() => {
                    crate::app_handoff::retains_worker(global, &worker.filter, member)
                }
                _ => false,
            } || (!worker.filter.is_empty()
                && self.owes_storage_settlement(&worker.filter, frame_number));
            if worker.filter.is_empty() {
                // Idle worker: an expired pending-join marker is swept after
                // the bind pass below (`expire_unlanded_join_markers`), so a
                // join the registry shows for the first time in this pass is
                // bound before its marker is judged.
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
                        ) || self.renewal_recovering(a, frame_number)
                            || self.awaits_renewal_offer(a, frame_number)
                    })
                    .unwrap_or(false);
                // Protect a still-in-flight ProposeJoin (pending window not yet
                // elapsed) so we don't cancel a legitimately pending bind.
                let pending_in_flight = self
                    .join_awaits_registry_sync(worker.pending_filter_frame, frame_number)
                    || worker.pending_filter_frame > 0
                        && frame_number <= worker.pending_filter_frame + PROPOSAL_TIMEOUT_FRAMES;
                // A retained worker is not stranded: its closing session still
                // counts its vote, and the pass below restarts its engine.
                if !f_resolvable && !pending_in_flight && !retained {
                    warn!(
                        core_id = worker.core_id,
                        stale_filter = hex::encode(&worker.filter),
                        "worker pinned to a filter with no active allocation while an \
                         active child allocation is unbound (likely split-parent) — \
                         deallocating so the child rebinds"
                    );
                    self.release_worker(worker, retained)?;
                    continue;
                }
            }

            match alloc_by_filter.get(&worker.filter) {
                Some(alloc) => {
                    // `Active` is a raw wire status. An allocation whose
                    // epoch is stale is effectively inactive until its
                    // re-confirmation lands, so it must not pin a scarce
                    // worker while a live allocation is unbound.
                    match self.gives_up(alloc, frame_number).filter(|_| !retained) {
                        Some(GivenUp::Lapsed) => {
                            info!(
                                core_id = worker.core_id,
                                filter = hex::encode(&worker.filter),
                                allocation_epoch = alloc.epoch,
                                current_epoch = quil_types::consensus::epoch_for_frame(frame_number),
                                "epoch-expired allocation released so a live shard can use the worker"
                            );
                            self.release_worker(worker, retained)?;
                            continue;
                        }
                        Some(GivenUp::LeftLapsed) => {
                            info!(
                                core_id = worker.core_id,
                                filter = hex::encode(&worker.filter),
                                frame = frame_number,
                                allocation_epoch = alloc.epoch,
                                leave_frame = alloc.leave_frame_number,
                                scope = "this node's worker",
                                "worker released from a seat left after its storage registration lapsed, which its \
                                 committee no longer seats: it owes no notice; the seat departs at its leave boundary"
                            );
                            self.release_worker(worker, retained)?;
                            continue;
                        }
                        None => {}
                    }

                    // Compute desired_allocated AFTER the
                    // expired-join/leave reset, mirroring Go's
                    // worker_allocator.go:421-422 + 781-816. Paused
                    // counts as "desired allocated" alongside Active —
                    // the registry maintains the filter binding while
                    // the worker pauses.
                    // A retained worker runs consensus whatever its allocation
                    // says: after a restart its engine must start again even
                    // though the allocation is Leaving or terminal.
                    let mut desired_allocated = retained
                        || matches!(
                            alloc.status,
                            ProverStatus::Active | ProverStatus::Paused | ProverStatus::Leaving
                        );

                    // The join has landed once its allocation is confirmed. The
                    // pending marker would otherwise exclude the worker from
                    // priority replacement for as long as it stays bound.
                    if worker.pending_filter_frame > 0
                        && matches!(
                            alloc.status,
                            ProverStatus::Active | ProverStatus::Paused | ProverStatus::Leaving
                        )
                    {
                        let _ = self
                            .worker_manager
                            .set_pending_filter_frame(worker.core_id, 0);
                    }

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
                                self.release_worker(worker, retained)?;
                            }
                        }
                        ProverStatus::Rejected | ProverStatus::Kicked | ProverStatus::Historic => {
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
                            self.release_worker(worker, retained)?;
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
                                && !retained
                            {
                                desired_allocated = false;
                                info!(
                                    core_id = worker.core_id,
                                    filter = hex::encode(&worker.filter),
                                    leave_frame = alloc.leave_frame_number,
                                    "leave expired after 720 frames, clearing worker"
                                );
                                self.release_worker(worker, retained)?;
                            }
                        }
                        _ => {}
                    }

                    let desired_allocated = desired_allocated || retained;
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
                            match alloc.join_wait(frame_number) {
                                // Confirmed, but the committee stays frozen
                                // until the next epoch boundary.
                                Some(wait) => info!(
                                    core_id = worker.core_id,
                                    filter = hex::encode(&worker.filter),
                                    activation_frame = wait.activation_frame(),
                                    "join confirmed — starting consensus engine; it waits for the \
                                     allocation to activate at activation_frame"
                                ),
                                None => info!(
                                    core_id = worker.core_id,
                                    filter = hex::encode(&worker.filter),
                                    "alloc transitioned to Active — starting consensus engine"
                                ),
                            }
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
                        && !self
                            .join_awaits_registry_sync(worker.pending_filter_frame, frame_number)
                    {
                        info!(
                            core_id = worker.core_id,
                            filter = hex::encode(&worker.filter),
                            pending_since = worker.pending_filter_frame,
                            "proposal timed out after 10 frames, clearing worker"
                        );
                        self.release_worker(worker, retained)?;
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
                        self.release_worker(worker, retained)?;
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

        // A worker above the configured count drains: it takes no new seat,
        // so neither idle list offers it (`WorkerManager::is_draining`).
        let draining = self.worker_manager.draining_workers();
        let mut idle_workers: Vec<u32> = self
            .worker_manager
            .range_workers()?
            .iter()
            .filter(|w| {
                w.filter.is_empty() && !w.manually_managed && !draining.contains(&w.core_id)
            })
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
        // A worker held back for sending no vote in its last seat is bound
        // last, so a healthy idle worker takes an unbound seat first
        // (`provers::session_hosting`).
        let held_back = self
            .held_back
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // So is a worker whose store stopped writing: it cannot serve a seat
        // until its store is reopened (`worker_execution::store_stopped`).
        idle_workers.sort_by_key(|core_id| {
            !held_back.contains(core_id) && !crate::worker_execution::store_stopped(*core_id)
        });

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
            .filter(|w| w.filter.is_empty() && w.manually_managed && !draining.contains(&w.core_id))
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

        let mut bind_candidates: Vec<&quil_types::consensus::ProverAllocationInfo> = Vec::new();
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
                EffectiveStatus::Active | EffectiveStatus::Paused | EffectiveStatus::Joining => {}
                EffectiveStatus::ExpiredEpoch if self.renewal_recovering(alloc, frame_number) => {}
                // Both proposed and confirmed leaves serve until their
                // protocol departure boundary; confirmation does not free
                // the worker or change the frozen committee mid-epoch. A seat
                // left after it lapsed that its committee no longer seats owes
                // no notice.
                EffectiveStatus::Leaving if self.gives_up(alloc, frame_number).is_none() => {}
                _ => continue,
            }
            if assigned_filters.contains(&alloc.confirmation_filter) {
                continue;
            }
            bind_candidates.push(alloc);
        }

        // Serving allocations take precedence over joins that have not
        // activated, and a confirmed join over an unconfirmed one. A
        // notice-period member must not lose its recovery slot to a pending
        // join merely because the latter scores higher; nor may a confirmed
        // join, a committee member from the next boundary whatever this node
        // does, lose the worker to a join that may never be confirmed.
        // A leave not yet confirmed comes after the seats the node keeps:
        // when workers are short (a lowered count, or a restart that binds
        // anew), it stays unbound, and its confirm then goes through as an
        // orphan's instead of being rejected for its score. A confirmed
        // leave serves its notice and keeps its place.
        bind_candidates.sort_by(|a, b| {
            use quil_types::consensus::AllocationPhase;
            let pending =
                |a: &quil_types::consensus::ProverAllocationInfo| match a.phase(frame_number) {
                    Some(AllocationPhase::Joining) => 3u8,
                    Some(AllocationPhase::Leaving) => 2,
                    Some(AllocationPhase::Activating) => 1,
                    _ => 0,
                };
            pending(a).cmp(&pending(b)).then_with(|| {
                if let Some(priority) = priority.as_ref() {
                    let ka = priority_key(priority, &a.confirmation_filter);
                    let kb = priority_key(priority, &b.confirmation_filter);
                    kb.0.cmp(&ka.0)
                        .then_with(|| kb.1.cmp(&ka.1))
                        .then_with(|| a.confirmation_filter.cmp(&b.confirmation_filter))
                } else {
                    std::cmp::Ordering::Equal
                }
            })
        });

        // The candidates the idle pool serves go first to the idle worker
        // whose own store holds their shard's data. A restart or release
        // that frees several workers at once rebinds them here, and a shard
        // given to a worker without its data installs all of it from an
        // archive (minutes and about a gigabyte for a large shard, through
        // the node's two archive recovery turns) while the worker holding it
        // installs another. Which candidates get a worker, and the manual
        // pool's precedence, stay as they were; a worker held back or whose
        // store stopped keeps its place at the end.
        let served = bind_candidates
            .len()
            .min(manual_pending.len() + idle_workers.len());
        let eligible: Vec<u32> = idle_workers
            .iter()
            .copied()
            .filter(|core| {
                !held_back.contains(core) && !crate::worker_execution::store_stopped(*core)
            })
            .collect();
        let from_idle: Vec<Vec<u8>> = bind_candidates[manual_pending.len().min(served)..served]
            .iter()
            .map(|a| a.confirmation_filter.clone())
            .collect();
        let holders = self.worker_manager.shard_data();
        let tips = if holders.values().any(|held| !held.is_empty()) {
            self.committed_tips(&from_idle)
        } else {
            HashMap::new()
        };
        let mut on_data = data_holders(
            from_idle.iter().map(Vec::as_slice),
            &eligible,
            &holders,
            |filter| tips.get(filter).copied(),
        );
        idle_workers.retain(|core| !on_data.values().any(|held| held == core));
        let mut bound_on_data: Vec<String> = Vec::new();

        // Unconfirmed joins bound in this pass, by the epoch their confirm is
        // due in: (count, first join frame, last join frame).
        let mut landed_joins: std::collections::BTreeMap<u64, (usize, u64, u64)> =
            Default::default();
        for alloc in bind_candidates {
            // Prefer a manually-pending (user-picked) worker before
            // falling back to the auto-managed idle pool.
            let holds_data =
                manual_pending.is_empty() && on_data.contains_key(&alloc.confirmation_filter);
            let pick = manual_pending
                .pop()
                .or_else(|| on_data.remove(&alloc.confirmation_filter))
                .or_else(|| idle_workers.pop());
            if let Some(core_id) = pick {
                if holds_data {
                    bound_on_data.push(format!(
                        "{core_id}:{}",
                        hex::encode(&alloc.confirmation_filter)
                    ));
                }
                if let Some(quil_types::consensus::JoinWait::Confirmation { epoch }) =
                    alloc.join_wait(frame_number)
                {
                    let join = alloc.join_frame_number;
                    let entry = landed_joins.entry(epoch).or_insert((0, join, join));
                    *entry = (entry.0 + 1, entry.1.min(join), entry.2.max(join));
                }
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
                    holds_data,
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
                // worker-budget overflow: a lowered worker count, lost
                // workers, or overlapping ProposeJoin cycles
                // materializing more distinct filters than we have
                // worker slots for (the lifecycle's per-filter Join
                // cooldown prevents the last). Collected and logged in
                // aggregate by `watch_orphans` below, so a batch of 9
                // orphans produces one line, not 9, and a steady state
                // one line per `ORPHAN_WARNING_REPEAT_FRAMES`.
                orphan_filters.push((alloc.confirmation_filter.clone(), alloc.status));
            }
        }

        if !bound_on_data.is_empty() {
            info!(frame = frame_number, bound = bound_on_data.len(),
                workers = ?bound_on_data.iter().take(8).collect::<Vec<_>>(),
                "bound shards to the idle workers whose stores hold their data");
        }

        self.log_idled_manual_workers(frame_number, &manual_seats, &alloc_by_filter)?;

        self.expire_unlanded_join_markers(
            frame_number,
            prover_info
                .as_ref()
                .map(|p| p.allocations.as_slice())
                .unwrap_or(&[]),
        )?;

        let _ = self.watch_orphans(frame_number, &orphan_filters, draining.len());

        if !orphan_filters.is_empty() {
            // Orphans are not necessarily the least valuable
            // allocations: workers lost to an incident (crashed data
            // worker, reduced core count, an operator shrinking the
            // fleet) leave whatever they held bound and push the rest
            // out, and a reset can land a surplus in any order. Take
            // the workers back for the best allocations.
            match &priority_state {
                PriorityState::Fresh(entries) => {
                    self.review_surplus_priority(
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

        for (epoch, (count, first_join, last_join)) in landed_joins {
            let window_start = quil_types::consensus::epoch_start_frame(epoch);
            let activation =
                quil_types::consensus::JoinWait::Confirmation { epoch }.activation_frame();
            let join_frames = if first_join == last_join {
                first_join.to_string()
            } else {
                format!("{first_join}..{last_join}")
            };
            let confirm_window = format!("{window_start}..{}", activation - 1);
            info!(
                frame = frame_number,
                allocations = count,
                join_frames = %join_frames,
                confirm_epoch = epoch,
                confirm_window = %confirm_window,
                activation_frame = activation,
                "joins landed in the registry: their workers are bound without consensus until this \
                 prover confirms them in confirm_window, then activate at activation_frame; an \
                 unconfirmed join expires after its confirm epoch and frees its worker"
            );
        }

        Ok(())
    }

    /// Explain a surplus priority gap without stopping a serving worker.
    /// Moving a worker does not remove its source allocation from the on-chain
    /// committee. The lifecycle must first arrange a protocol departure; only
    /// then may the ordinary free-worker binding pass select another holding.
    /// Paused allocations retain their worker too, so a resume can be served.
    fn review_surplus_priority(
        &self,
        frame_number: u64,
        orphans: &[(Vec<u8>, ProverStatus)],
        alloc_by_filter: &HashMap<Vec<u8>, &quil_types::consensus::ProverAllocationInfo>,
        priority: &HashMap<Vec<u8>, AllocationPriorityEntry>,
    ) -> Result<()> {
        use quil_types::consensus::EffectiveStatus;
        use std::sync::atomic::Ordering;

        let last_review = self.last_priority_review_frame.load(Ordering::Relaxed);
        if last_review > 0 && frame_number.abs_diff(last_review) < SURPLUS_REVIEW_INTERVAL_FRAMES {
            self.log_rebind_outcome(
                frame_number,
                RebindOutcome::Cooldown,
                &format!(
                    "last priority review at frame {last_review}, {} of                      {SURPLUS_REVIEW_INTERVAL_FRAMES} review interval frames elapsed",
                    frame_number.abs_diff(last_review)
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
            b.0.cmp(&a.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.cmp(&b.2))
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
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.3.cmp(&b.3))
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

        // Retain every eligible alternative so operators can explain why a
        // favorable holding was chosen instead of a lower displayed estimate.
        let include_inputs = tracing::enabled!(tracing::Level::INFO)
            && replacement_priority_gap(&best_challenger, &worst_holder);
        let candidate_inputs: Vec<_> = challengers.iter().filter(|_| include_inputs).map(|(tier, score, filter)|
            serde_json::json!({"filter": hex::encode(filter), "tier": tier,
                "score": score.to_string(), "ranking": priority.get(filter).and_then(|p| p.evidence.as_ref())})).collect();
        let holder_inputs: Vec<_> = holders
            .iter()
            .filter(|_| include_inputs)
            .map(|(tier, score, core_id, filter)| {
                serde_json::json!({"filter": hex::encode(filter), "worker": core_id,
                "tier": tier, "score": score.to_string(),
                "ranking": priority.get(filter).and_then(|p| p.evidence.as_ref())})
            })
            .collect();
        let mut deferred = 0usize;
        for ((c_tier, c_score, c_filter), (h_tier, h_score, core_id, h_filter)) in
            challengers.into_iter().zip(holders.into_iter())
        {
            if deferred == MAX_DEFERRED_REPLACEMENTS_PER_REVIEW {
                break;
            }
            if !replacement_priority_gap(&(c_tier, c_score.clone()), &(h_tier, h_score.clone())) {
                // Both lists are sorted, so once the best remaining
                // challenger cannot displace the worst remaining
                // holder, no later pair can either.
                break;
            }
            if deferred == 0 {
                info!(frame_number,
                    current_epoch = quil_types::consensus::epoch_for_frame(frame_number),
                    halt_risk_threshold = crate::provers::proposer::HALT_RISK_PROVER_COUNT,
                    candidates = %serde_json::json!(candidate_inputs),
                    holders = %serde_json::json!(holder_inputs),
                    "deferred worker replacement inputs; registry coverage is not peer liveness");
            }
            warn!(
                source_status = ?alloc_by_filter.get(&h_filter).map(|a| a.effective_status(frame_number)),
                source_epoch = ?alloc_by_filter.get(&h_filter).map(|a| a.epoch),
                destination_status = ?alloc_by_filter.get(&c_filter).map(|a| a.effective_status(frame_number)),
                destination_epoch = ?alloc_by_filter.get(&c_filter).map(|a| a.epoch),
                core_id,
                retained_filter = hex::encode(&h_filter),
                retained_tier = h_tier,
                retained_score = %h_score,
                candidate_filter = hex::encode(&c_filter),
                candidate_tier = c_tier,
                candidate_score = %c_score,
                frame_number,
                "priority replacement deferred: the source allocation retains its worker until effective departure"
            );
            deferred += 1;
        }

        if deferred > 0 {
            self.last_priority_review_frame
                .store(frame_number, Ordering::Relaxed);
            self.log_rebind_outcome(
                frame_number,
                RebindOutcome::ServiceRetained,
                &format!(
                    "{deferred} replacement(s) deferred; {challenger_count} unbound                      candidate(s) against {holder_count} serving worker(s)"
                ),
            );
        } else {
            self.log_rebind_outcome(
                frame_number,
                RebindOutcome::BelowMargin,
                &format!(
                    "best unbound (tier {}, score {}) does not clear                      {REBIND_MARGIN_PERCENT}% of worst bound (tier {}, score                      {}); {challenger_count} candidate(s), {holder_count}                      serving worker(s)",
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
                a.effective_status(frame_number) == quil_types::consensus::EffectiveStatus::Joining
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
            active, idle, "worker allocation status"
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
            last_signed_frame_number: 0,
            epoch: 0,
            ring: 0,
            vertex_address: vec![],
        }
    }

    /// A worker whose committee session is closing stays bound through a
    /// terminal allocation status, is released once the seal is recorded, and
    /// retention never suppresses the rest of the reconcile pass.
    #[test]
    fn closing_session_retains_only_the_release_of_its_worker() {
        use quil_cw_consensus::handoff::{Checkpoint, Seal, Session};
        use quil_execution::global_intrinsic::handoff::{
            self, CertificateSubmission, DesiredCommittee,
        };
        use quil_execution::hypergraph_state::HypergraphState;
        use quil_types::crypto::Signer as _;

        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        global.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let state = HypergraphState::new(global.clone());
        let commit = |frame: u64| {
            state.commit().unwrap();
            state.abort();
            global
                .commit_with_global_cursor(
                    frame,
                    &quil_store::encoding::global_materialized_cursor_key(),
                )
                .unwrap();
        };
        let signers: Vec<_> = (0..2)
            .map(|_| quil_crypto::FalconSigner::generate())
            .collect();
        let local_key = signers[0].public_key().to_vec();
        let mut members: Vec<Vec<u8>> = signers.iter().map(|s| s.public_key().to_vec()).collect();
        members.sort();
        let filter = vec![0x01; 32];
        let session = Session {
            chain_id: [7; 32],
            filter: filter.clone(),
            generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0,
            authorization: [0; 32],
            members: members.clone(),
        };

        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &filter).unwrap();
        let mut kicked = make_alloc(filter.clone());
        kicked.status = ProverStatus::Kicked;
        let prover = |allocation: ProverAllocationInfo| ProverInfo {
            public_key: local_key.clone(),
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![allocation],
            available_storage: 0,
            seniority: 100,
            delegate_address: vec![],
        };
        let bound = |wm: &MockWorkerManager| wm.range_workers().unwrap()[0].filter.clone();

        // No authenticated GLOBAL state at all: nothing can be closing here.
        let alloc = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_provers(vec![prover(
                kicked.clone(),
            )])),
            vec![0xAA; 32],
        );
        alloc.set_session_authority(global.clone());
        alloc.on_new_frame(100).unwrap();
        assert!(
            bound(&wm).is_empty(),
            "an unreadable cursor must not pin workers forever"
        );

        // The session, not the registry, says who runs consensus: a member of
        // an ACTIVE session keeps its worker through a terminal allocation.
        commit(1);
        handoff::initialize(&state, 2, &session).unwrap();
        commit(2);
        wm.set_worker_filter(1, &filter, true).unwrap();
        alloc.on_new_frame(101).unwrap();
        assert_eq!(bound(&wm), filter);

        // Closing: still bound…
        let request = handoff::schedule(
            &state,
            3,
            vec![filter.clone()],
            vec![DesiredCommittee {
                filter: filter.clone(),
                members: vec![signers[1].public_key().to_vec()],
            }],
        )
        .unwrap();
        commit(3);
        wm.set_worker_filter(1, &filter, true).unwrap();
        alloc.on_new_frame(102).unwrap();
        assert_eq!(bound(&wm), filter);
        // …and a retained worker still gets the rest of the pass: a fresh
        // allocator that sees the allocation Active marks it allocated.
        let active = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_provers(vec![prover(make_alloc(
                filter.clone(),
            ))])),
            vec![0xAA; 32],
        );
        active.set_session_authority(global.clone());
        let _ = wm.set_allocated(1, false);
        active.on_new_frame(102).unwrap();
        assert!(
            wm.range_workers().unwrap()[0].allocated,
            "retention must not skip the Active transition"
        );
        // …nor the engine restart of a member whose allocation already ended,
        // while another allocation waits for a worker.
        let restarted = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_provers(vec![ProverInfo {
                allocations: vec![kicked.clone(), make_alloc(vec![0x02; 32])],
                ..prover(kicked.clone())
            }])),
            vec![0xAA; 32],
        );
        restarted.set_session_authority(global.clone());
        wm.set_worker_filter(1, &filter, false).unwrap();
        restarted.on_new_frame(102).unwrap();
        let worker = wm.range_workers().unwrap()[0].clone();
        assert_eq!(worker.filter, filter);
        assert!(
            worker.allocated,
            "a closing member must restart its engine while another allocation waits"
        );
        // Nor does the recovery gate give up a lapsed seat the session
        // retains, whose worker the reconcile keeps.
        let e = epoch_length_frames();
        let lapsed_gate = || {
            let gate = WorkerAllocator::new(
                Arc::new(MockWorkerManager::new()),
                Arc::new(TestProverRegistry::with_provers(vec![prover(make_alloc(
                    filter.clone(),
                ))])),
                vec![0xAA; 32],
            );
            gate.set_session_authority(global.clone());
            gate.on_new_frame(3 * e).unwrap();
            gate.note_renewals_offered();
            gate.given_up_seat(&filter, 3 * e).map(|seat| seat.cause)
        };
        assert_eq!(lapsed_gate(), None, "retained by its closing session");

        // Once GLOBAL state records the seal, the worker is released.
        let seal = Seal {
            request: request.id().unwrap(),
            session: session.id().unwrap(),
            view: 3,
            checkpoint: Checkpoint {
                frame: 0,
                view: 0,
                digest: session.genesis,
                state_roots: [[0; 32]; 4],
                history_root: [9; 32],
            },
        };
        let certificate = crate::test_support::certify_seal(&session, &signers, &seal);
        handoff::record_session_tip(&state, 4, &seal.session, &seal.checkpoint).unwrap();
        assert!(
            handoff::apply_submission(&state, 4, &CertificateSubmission { seal, certificate })
                .unwrap()
        );
        commit(4);
        alloc.on_new_frame(103).unwrap();
        assert!(bound(&wm).is_empty());
        assert_eq!(
            lapsed_gate(),
            Some(GivenUp::Lapsed),
            "the seal recorded, nothing retains it"
        );
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

    /// Held for a registry sync, a stuck marker still clears at the ceiling,
    /// so failing syncs cannot pin the worker.
    #[test]
    fn a_marker_held_for_a_registry_sync_clears_at_the_ceiling() {
        let wm = Arc::new(MockWorkerManager::new());
        wm.add(crate::worker::WorkerInfo {
            core_id: 1,
            filter: Vec::new(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 100,
            allocated: false,
        });
        let alloc = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::new()),
            vec![0xAAu8; 32],
        );
        alloc.hold_pending_joins_for_registry_sync();
        let pending = |frame: u64| {
            alloc.on_new_frame(frame).unwrap();
            wm.range_workers().unwrap()[0].pending_filter_frame
        };
        assert_eq!(
            pending(100 + PROPOSAL_SYNC_CEILING_FRAMES),
            100,
            "no sync has refreshed the registry since"
        );
        assert_eq!(pending(100 + PROPOSAL_SYNC_CEILING_FRAMES + 1), 0);
    }

    /// A node loads its prover registry in the background at startup. A
    /// reconcile before that load ends must not release the workers the
    /// still-empty registry shows no allocation for.
    #[test]
    fn reconcile_waits_for_the_registry_first_load() {
        let filter = vec![0x01; 32];
        let wm = Arc::new(MockWorkerManager::new());
        wm.add(crate::worker::WorkerInfo {
            core_id: 1,
            filter: filter.clone(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: true,
        });
        let registry = Arc::new(quil_execution::SharedProverRegistry::new());
        let alloc = WorkerAllocator::new(wm.clone(), registry.clone(), vec![0xAAu8; 32]);
        let frame = PENDING_FILTER_GRACE_FRAMES + 100;
        alloc.on_new_frame(frame).unwrap();
        assert_eq!(
            wm.range_workers().unwrap()[0].filter,
            filter,
            "nothing is released before the load"
        );
        // Loaded and still without the allocation, the worker is orphaned.
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        registry
            .refresh_from_store(&quil_store::RocksHypergraphStore::new(db.inner()))
            .unwrap();
        alloc.on_new_frame(frame + 1).unwrap();
        assert!(
            wm.range_workers().unwrap()[0].filter.is_empty(),
            "the loaded registry decides"
        );
    }

    #[test]
    fn landed_join_clears_its_pending_marker() {
        let filter = vec![0x01; 32];
        let wm = Arc::new(MockWorkerManager::new());
        wm.add(crate::worker::WorkerInfo {
            core_id: 1,
            filter: filter.clone(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 100,
            allocated: true,
        });
        let alloc = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_prover(prover_with_active(
                &[filter.clone()],
                200,
            ))),
            vec![0xAAu8; 32],
        );
        alloc.on_new_frame(200).unwrap();
        let workers = wm.range_workers().unwrap();
        assert_eq!(workers[0].filter, filter);
        assert_eq!(
            workers[0].pending_filter_frame, 0,
            "a landed join must not stay pending"
        );
    }

    /// Runs one reconcile and returns what it logged.
    fn reconcile_logged(alloc: &WorkerAllocator, frame: u64) -> String {
        #[derive(Clone, Default)]
        struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || alloc.on_new_frame(frame).unwrap());
        let bytes = lines.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn idle_worker(core_id: u32, pending_filter_frame: u64) -> crate::worker::WorkerInfo {
        crate::worker::WorkerInfo {
            core_id,
            filter: Vec::new(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame,
            allocated: false,
        }
    }

    fn joining_alloc(filter: Vec<u8>, join_frame: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status: ProverStatus::Joining,
            join_frame_number: join_frame,
            join_confirm_frame_number: 0,
            ..make_alloc(filter)
        }
    }

    const DROPPED: &str = "join submitted but no alloc landed in registry";

    /// A join whose first registry sync arrives past the proposal timeout
    /// binds its worker in that pass, keeps the marker and is not reported
    /// as dropped (observed: every worker of a 27-shard join warned in the
    /// pass that bound it).
    #[test]
    fn a_join_first_seen_past_the_timeout_binds_without_a_dropped_warning() {
        let filter = vec![0x01; 32];
        let wm = Arc::new(MockWorkerManager::new());
        wm.add(idle_worker(1, 100));
        let alloc = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_prover(prover_with(vec![
                joining_alloc(filter.clone(), 102),
            ]))),
            vec![0xAAu8; 32],
        );
        let logged = reconcile_logged(&alloc, 129);
        assert!(!logged.contains(DROPPED), "{logged}");
        let worker = &wm.range_workers().unwrap()[0];
        assert_eq!(worker.filter, filter);
        assert_eq!(
            worker.pending_filter_frame, 100,
            "the landed join stays pending until confirmed"
        );
    }

    /// A join that landed on another worker releases this worker's
    /// reservation without reporting a dropped join; a join absent from the
    /// registry past the timeout still warns and frees its worker.
    #[test]
    fn an_expired_join_marker_warns_only_when_no_join_landed() {
        let filter = vec![0x01; 32];
        let wm = Arc::new(MockWorkerManager::new());
        wm.add(idle_worker(1, 0));
        wm.add(idle_worker(2, 100));
        let alloc = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_prover(prover_with(vec![
                joining_alloc(filter.clone(), 102),
            ]))),
            vec![0xAAu8; 32],
        );
        let logged = reconcile_logged(&alloc, 129);
        assert!(
            !logged.contains(DROPPED) && logged.contains("not on this worker"),
            "{logged}"
        );
        let workers = wm.range_workers().unwrap();
        assert_eq!(
            (workers[0].filter.clone(), workers[1].pending_filter_frame),
            (filter, 0)
        );

        let wm = Arc::new(MockWorkerManager::new());
        wm.add(idle_worker(1, 100));
        let alloc = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_prover(prover_with(Vec::new()))),
            vec![0xAAu8; 32],
        );
        let logged = reconcile_logged(&alloc, 100 + PROPOSAL_TIMEOUT_FRAMES);
        assert!(!logged.contains(DROPPED), "within the timeout: {logged}");
        let logged = reconcile_logged(&alloc, 129);
        assert!(logged.contains(DROPPED), "{logged}");
        let workers = wm.range_workers().unwrap();
        assert_eq!(workers[0].pending_filter_frame, 0);
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
            allocations: vec![make_alloc(vec![0x01; 32]), make_alloc(vec![0x02; 32])],
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

    /// A worker held back for sending no vote in its last seat is bound to
    /// an unbound seat only after every other idle worker; held back alone,
    /// it is still bound (binding is not a join).
    #[test]
    fn held_back_workers_are_bound_last() {
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        wm.allocate_worker(2, &[]).unwrap();
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            make_alloc(vec![0x01; 32]),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.set_held_back(std::collections::HashSet::from([1]));
        alloc.on_new_frame(101).unwrap();
        assert_eq!(
            bound_cores(&wm),
            vec![2],
            "the healthy idle worker takes the seat"
        );

        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            make_alloc(vec![0x01; 32]),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.set_held_back(std::collections::HashSet::from([1]));
        alloc.on_new_frame(101).unwrap();
        assert_eq!(
            bound_cores(&wm),
            vec![1],
            "with no other idle worker it is bound"
        );
    }

    /// A worker whose store stopped writing is bound to an unbound seat only
    /// after every other idle worker.
    #[test]
    fn workers_whose_store_stopped_are_bound_last() {
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        wm.allocate_worker(2, &[]).unwrap();
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            make_alloc(vec![0x01; 32]),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        quil_forest::storage_health::hold_store(quil_forest::StoreRole::Worker(1));
        let result = alloc.on_new_frame(101);
        quil_forest::storage_health::release_store(quil_forest::StoreRole::Worker(1));
        result.unwrap();
        assert_eq!(
            bound_cores(&wm),
            vec![2],
            "the worker with a working store takes the seat"
        );
    }

    fn bound_to(wm: &MockWorkerManager) -> Vec<(u32, Vec<u8>)> {
        wm.range_workers()
            .unwrap()
            .into_iter()
            .filter(|w| !w.filter.is_empty())
            .map(|w| (w.core_id, w.filter))
            .collect()
    }

    /// Workers a restart released together (an early reconcile against an
    /// unloaded registry clears every binding) are bound back to the shards
    /// their own stores hold, whatever order the shards are bound in: the
    /// worker with the highest cursor of a shard wins, and no worker is
    /// given to two shards.
    #[test]
    fn a_restart_rebinds_each_shard_to_the_worker_holding_its_data() {
        let f = |byte: u8| vec![byte; 32];
        let wm = Arc::new(MockWorkerManager::new());
        for (core, filter) in [(1, f(2)), (2, f(3)), (3, f(1)), (4, Vec::new())] {
            wm.add_with_filter(core, filter);
            wm.deallocate_worker(core).unwrap();
        }
        wm.set_shard_data(1, vec![(f(2), 70)]);
        wm.set_shard_data(2, vec![(f(3), 80), (f(1), 12)]);
        wm.set_shard_data(3, vec![(f(1), 90)]);
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            make_alloc(f(1)),
            make_alloc(f(2)),
            make_alloc(f(3)),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        let logged = reconcile_logged(&alloc, 101);
        assert_eq!(
            bound_to(&wm),
            vec![(1, f(2)), (2, f(3)), (3, f(1))],
            "each shard back on its data"
        );
        assert!(
            logged.contains("bound shards to the idle workers whose stores hold their data")
                && logged.contains("bound=3"),
            "{logged}"
        );
    }

    /// A holder trailing the shard's committed tip by more than an epoch's
    /// worth of frames is not preferred; one within it, or any holder of a
    /// shard whose tip is unknown, is, the highest cursor first.
    #[test]
    fn a_holder_far_behind_the_committed_tip_is_not_preferred() {
        let f = |byte: u8| vec![byte; 32];
        let trail = shard_data_trail();
        let holders = HashMap::from([
            (1, vec![(f(1), 10), (f(2), 10)]),
            (2, vec![(f(1), 5000 - trail)]),
        ]);
        let tips = HashMap::from([(f(1), 5000u64), (f(2), 5000)]);
        let pick = |filters: &[Vec<u8>], tips: &HashMap<Vec<u8>, u64>| {
            let mut chosen: Vec<_> = data_holders(
                filters.iter().map(Vec::as_slice),
                &[1, 2],
                &holders,
                |filter| tips.get(filter).copied(),
            )
            .into_iter()
            .collect();
            chosen.sort();
            chosen
        };
        assert_eq!(
            pick(&[f(1), f(2)], &tips),
            vec![(f(1), 2)],
            "core 1's lineages trail too far"
        );
        assert_eq!(
            pick(&[f(2)], &HashMap::new()),
            vec![(f(2), 1)],
            "an unknown tip bounds nothing"
        );
    }

    /// A shard no idle worker's store holds takes the lowest free core as
    /// before, and a worker held back from new seats is not preferred for
    /// the shard its store holds: it is still bound last.
    #[test]
    fn binding_by_shard_data_keeps_the_free_order_otherwise() {
        let f = |byte: u8| vec![byte; 32];
        let wm = Arc::new(MockWorkerManager::new());
        for core in 1..=4u32 {
            wm.allocate_worker(core, &[]).unwrap();
        }
        wm.set_shard_data(1, vec![(f(1), 50)]);
        wm.set_shard_data(4, vec![(f(3), 40)]);
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            make_alloc(f(1)),
            make_alloc(f(2)),
            make_alloc(f(3)),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.set_held_back(std::collections::HashSet::from([1]));
        alloc.on_new_frame(101).unwrap();
        assert_eq!(bound_to(&wm), vec![(2, f(1)), (3, f(2)), (4, f(3))]);
    }

    /// A worker above the configured count drains: an unbound allocation is
    /// bound to an idle worker within the count, or to none, but never to a
    /// draining one, manual or not.
    #[test]
    fn a_draining_worker_is_never_bound_to_a_seat() {
        let f = |byte: u8| vec![byte; 32];
        let wm = Arc::new(MockWorkerManager::new());
        for core in 1..=4u32 {
            wm.allocate_worker(core, &[]).unwrap();
        }
        wm.set_manually_managed(4, true).unwrap();
        wm.set_configured_count(2);
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            make_alloc(f(1)),
            make_alloc(f(2)),
            make_alloc(f(3)),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.on_new_frame(101).unwrap();
        assert_eq!(
            bound_cores(&wm),
            vec![1, 2],
            "cores 3 and 4 drain; the third seat stays unbound"
        );
    }

    /// With fewer idle workers than seats, a leave not yet confirmed waits
    /// behind the seats the node keeps, so it stays unbound; a confirmed
    /// leave serving its notice keeps its precedence.
    #[test]
    fn an_unconfirmed_leave_is_bound_after_the_seats_the_node_keeps() {
        let f = |byte: u8| vec![byte; 32];
        let e = epoch_length_frames();
        let wm = Arc::new(MockWorkerManager::new());
        for core in 1..=3u32 {
            wm.allocate_worker(core, &[]).unwrap();
        }
        let current = |filter: Vec<u8>| ProverAllocationInfo {
            epoch: u64::MAX,
            ..make_alloc(filter)
        };
        let mut leaving = current(f(1));
        leaving.status = ProverStatus::Leaving;
        leaving.leave_frame_number = e + 10;
        let mut departing = current(f(2));
        departing.status = ProverStatus::Leaving;
        departing.leave_frame_number = 10;
        departing.leave_confirm_frame_number = e + 5;
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            leaving,
            departing,
            current(f(3)),
            current(f(4)),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        alloc.on_new_frame(e + 101).unwrap();
        let mut bound: Vec<Vec<u8>> = bound_to(&wm)
            .into_iter()
            .map(|(_, filter)| filter)
            .collect();
        bound.sort();
        assert_eq!(
            bound,
            vec![f(2), f(3), f(4)],
            "the unconfirmed leave waits for a spare worker"
        );
    }

    /// Allocations without a worker are logged once per episode and change
    /// of their set, repeated once per interval while they last, and their
    /// end is logged: not a line per pass.
    #[test]
    fn orphan_warning_is_bounded_by_the_interval_and_the_set() {
        let f = |byte: u8| vec![byte; 32];
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let current = |filter: Vec<u8>| ProverAllocationInfo {
            epoch: u64::MAX,
            ..make_alloc(filter)
        };
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            current(f(1)),
            current(f(2)),
            current(f(3)),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAAu8; 32]);
        let two = vec![(f(2), ProverStatus::Active), (f(3), ProverStatus::Active)];
        let swapped = vec![(f(2), ProverStatus::Active), (f(3), ProverStatus::Leaving)];
        let base = 1_000u64;
        assert_eq!(alloc.watch_orphans(base, &two, 0), Some("started"));
        for pass in 1..ORPHAN_WARNING_REPEAT_FRAMES {
            assert_eq!(
                alloc.watch_orphans(base + pass, &two, 0),
                None,
                "frame +{pass} is inside the interval"
            );
        }
        assert_eq!(
            alloc.watch_orphans(base + ORPHAN_WARNING_REPEAT_FRAMES, &two, 0),
            Some("continues"),
            "the interval has elapsed"
        );
        assert_eq!(
            alloc.watch_orphans(base + ORPHAN_WARNING_REPEAT_FRAMES + 1, &two, 0),
            None
        );
        assert_eq!(
            alloc.watch_orphans(base + ORPHAN_WARNING_REPEAT_FRAMES + 2, &swapped, 0),
            Some("changed"),
            "a changed status is logged at once"
        );
        assert_eq!(
            alloc.watch_orphans(base + ORPHAN_WARNING_REPEAT_FRAMES + 3, &swapped[..1], 0),
            Some("changed")
        );
        assert_eq!(
            alloc.watch_orphans(base + ORPHAN_WARNING_REPEAT_FRAMES + 4, &swapped[..1], 0),
            None
        );
        assert_eq!(
            alloc.watch_orphans(base + ORPHAN_WARNING_REPEAT_FRAMES + 5, &[], 0),
            Some("ended")
        );
        assert_eq!(
            alloc.watch_orphans(base + ORPHAN_WARNING_REPEAT_FRAMES + 6, &[], 0),
            None,
            "the end is logged once"
        );
        assert_eq!(
            alloc.watch_orphans(base + ORPHAN_WARNING_REPEAT_FRAMES + 7, &two, 0),
            Some("started")
        );
    }

    /// The reconcile feeds the episode: two seats beyond the one worker are
    /// an episode that ends when a seat is gone.
    #[test]
    fn orphan_episode_follows_the_reconcile() {
        let f = |byte: u8| vec![byte; 32];
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let current = |filter: Vec<u8>| ProverAllocationInfo {
            epoch: u64::MAX,
            ..make_alloc(filter)
        };
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            current(f(1)),
            current(f(2)),
            current(f(3)),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg.clone(), vec![0xAAu8; 32]);
        alloc.on_new_frame(101).unwrap();
        let since = alloc
            .orphan_watch
            .lock()
            .unwrap()
            .as_ref()
            .map(|w| (w.since_frame, w.set.len()));
        assert_eq!(since, Some((101, 2)));
        alloc.on_new_frame(102).unwrap();
        assert_eq!(
            alloc
                .orphan_watch
                .lock()
                .unwrap()
                .as_ref()
                .map(|w| w.logged_frame),
            Some(101)
        );
        reg.set_prover(prover_with(vec![current(f(1))]));
        alloc.on_new_frame(103).unwrap();
        assert!(
            alloc.orphan_watch.lock().unwrap().is_none(),
            "the episode ended with its orphans"
        );
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
    fn leaving_workers_serve_until_protocol_departure() {
        let e = EPOCH_LENGTH_FRAMES;
        for confirmed in [false, true] {
            for recovered in [false, true] {
                let wm = Arc::new(MockWorkerManager::new());
                let filter = vec![0x02; 32];
                wm.allocate_worker(1, if recovered { &[] } else { &filter })
                    .unwrap();
                if !recovered {
                    wm.set_allocated(1, true).unwrap();
                }
                let mut leaving = make_alloc(filter.clone());
                leaving.status = ProverStatus::Leaving;
                leaving.leave_frame_number = e + 1;
                leaving.leave_confirm_frame_number = if confirmed { 2 * e + 10 } else { 0 };
                let prover = ProverInfo {
                    public_key: vec![0xBB; 585],
                    address: vec![0xAA; 32],
                    status: ProverStatus::Active,
                    kick_frame_number: 0,
                    allocations: vec![leaving],
                    available_storage: 0,
                    seniority: 100,
                    delegate_address: vec![],
                };
                let allocator = WorkerAllocator::new(
                    wm.clone(),
                    Arc::new(TestProverRegistry::with_prover(prover)),
                    vec![0xAA; 32],
                );
                for frame in [2 * e + 20, 3 * e - 1] {
                    allocator.on_new_frame(frame).unwrap();
                    let worker = wm.range_workers().unwrap().remove(0);
                    assert_eq!(
                        worker.filter, filter,
                        "confirmed={confirmed}, recovered={recovered}, frame={frame}"
                    );
                    assert!(worker.allocated, "notice-period worker must run consensus");
                }
                allocator.on_new_frame(3 * e).unwrap();
                let worker = wm.range_workers().unwrap().remove(0);
                assert!(worker.filter.is_empty(), "depart exactly at epoch boundary");
                assert!(!worker.allocated);
            }
        }
    }

    /// A departing member whose seat committed roots in its last epoch keeps
    /// its worker, engine running, until that epoch settles or its settlement
    /// window closes: only the engine proves the seat, and GLOBAL kicks a
    /// member that committed roots and never proved them.
    #[test]
    fn a_departing_worker_stays_bound_while_its_seat_owes_a_settlement() {
        let e = EPOCH_LENGTH_FRAMES;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(0));
        for open in [true, false] {
            let wm = Arc::new(MockWorkerManager::new());
            let filter = vec![0x02; 32];
            wm.allocate_worker(1, &filter).unwrap();
            wm.set_allocated(1, true).unwrap();
            let mut leaving = make_alloc(filter.clone());
            leaving.status = ProverStatus::Leaving;
            leaving.leave_frame_number = e + 1;
            leaving.leave_confirm_frame_number = 2 * e + 10;
            let prover = ProverInfo {
                public_key: vec![0xBB; 585],
                address: vec![0xAA; 32],
                status: ProverStatus::Active,
                kick_frame_number: 0,
                allocations: vec![leaving],
                available_storage: 0,
                seniority: 100,
                delegate_address: vec![],
            };
            let registry = TestProverRegistry::with_prover(prover);
            // The last epoch it served (2) committed roots; settling it is
            // owed until the end of epoch 3.
            registry.set_storage_seat_slot(
                &[0xAA; 32],
                &filter,
                quil_types::consensus::StorageSeatSlot {
                    epoch: 2,
                    leaves: vec![vec![0]],
                    registered_at: e + 20,
                    sealed_at: Some(e + 30),
                    frames: 3,
                    accumulator: [0; 32],
                    chained: Vec::new(),
                    open,
                },
            );
            let allocator = WorkerAllocator::new(wm.clone(), Arc::new(registry), vec![0xAA; 32]);
            allocator.on_new_frame(3 * e).unwrap();
            let worker = wm.range_workers().unwrap().remove(0);
            assert_eq!(
                worker.filter.is_empty(),
                !open,
                "open={open}: bound only while the settlement is owed"
            );
            assert_eq!(
                worker.allocated, open,
                "open={open}: the owed seat's engine keeps running"
            );
            allocator.on_new_frame(4 * e).unwrap();
            let worker = wm.range_workers().unwrap().remove(0);
            assert!(
                worker.filter.is_empty(),
                "open={open}: departs once the settlement window closes"
            );
        }
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    #[test]
    fn recovery_reserves_scarce_worker_for_notice_before_pending_join() {
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let e = EPOCH_LENGTH_FRAMES;
        let mut joining = make_alloc(vec![0x01; 32]);
        joining.status = ProverStatus::Joining;
        joining.join_frame_number = 2 * e + 1;
        let mut leaving = make_alloc(vec![0x02; 32]);
        leaving.status = ProverStatus::Leaving;
        leaving.leave_frame_number = e + 1;
        leaving.leave_confirm_frame_number = 2 * e + 10;
        let prover = ProverInfo {
            public_key: vec![0xBB; 585],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![joining, leaving.clone()],
            available_storage: 0,
            seniority: 100,
            delegate_address: vec![],
        };
        let allocator = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_prover(prover)),
            vec![0xAA; 32],
        );
        allocator.on_new_frame(2 * e + 20).unwrap();
        let worker = wm.range_workers().unwrap().remove(0);
        assert_eq!(worker.filter, leaving.confirmation_filter);
        assert!(worker.allocated);
    }

    /// A confirmed join becomes a committee member at the next boundary
    /// whatever this node does, so a scarce worker goes to it before a join
    /// still awaiting confirmation, even one on a halt-risk shard and first
    /// in registry order.
    #[test]
    fn a_confirmed_join_outranks_an_unconfirmed_one_for_a_scarce_worker() {
        let e = epoch_length_frames();
        let frame = 10 * e + 20;
        let mut activating = make_alloc(vec![0x01; 32]);
        activating.join_frame_number = 9 * e + 1;
        activating.join_confirm_frame_number = 10 * e + 5;
        activating.epoch = 11;
        let mut pending = make_alloc(vec![0x02; 32]);
        pending.status = ProverStatus::Joining;
        pending.join_frame_number = 10 * e + 1;
        pending.join_confirm_frame_number = 0;
        assert_eq!(activating.phase(frame), Some(AllocationPhase::Activating));
        assert_eq!(pending.phase(frame), Some(AllocationPhase::Joining));
        for ranked in [false, true] {
            let wm = Arc::new(MockWorkerManager::new());
            wm.allocate_worker(1, &[]).unwrap();
            let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
                pending.clone(),
                activating.clone(),
            ])));
            let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
            if ranked {
                allocator.publish_allocation_priority(
                    frame,
                    vec![
                        (pending.confirmation_filter.clone(), true, BigInt::from(10)),
                        (
                            activating.confirmation_filter.clone(),
                            false,
                            BigInt::from(9_000),
                        ),
                    ],
                );
            }
            allocator.on_new_frame(frame).unwrap();
            assert_eq!(
                bound_filters(&wm),
                vec![activating.confirmation_filter.clone()],
                "ranked={ranked}"
            );
        }
    }

    /// The production worker manager, counting consensus starts.
    struct CountingThreadWorkers {
        inner: crate::thread_worker::ThreadWorkerManager,
        starts: std::sync::atomic::AtomicUsize,
    }

    impl WorkerManager for CountingThreadWorkers {
        fn set_worker_filter(
            &self,
            core_id: u32,
            filter: &[u8],
            start_consensus: bool,
        ) -> Result<()> {
            if start_consensus && !filter.is_empty() {
                self.starts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner
                .set_worker_filter(core_id, filter, start_consensus)
        }
        fn deallocate_worker(&self, core_id: u32) -> Result<()> {
            self.inner.deallocate_worker(core_id)
        }
        fn check_workers_connected(&self) -> Result<Vec<u32>> {
            self.inner.check_workers_connected()
        }
        fn range_workers(&self) -> Result<Vec<crate::worker::WorkerInfo>> {
            self.inner.range_workers()
        }
        fn respawn_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
            self.inner.respawn_worker(core_id, filter)
        }
        fn set_pending_filter_frame(&self, core_id: u32, frame: u64) -> Result<()> {
            self.inner.set_pending_filter_frame(core_id, frame)
        }
        fn set_manually_managed(&self, core_id: u32, manual: bool) -> Result<()> {
            self.inner.set_manually_managed(core_id, manual)
        }
        fn set_allocated(&self, core_id: u32, allocated: bool) -> Result<()> {
            self.inner.set_allocated(core_id, allocated)
        }
    }

    /// An Active allocation bound to an idle worker must not have its engine
    /// restarted by the next pass, seconds after it started: a finalized frame
    /// the engine had queued would be lost with it.
    #[tokio::test]
    async fn an_active_allocation_bound_to_an_idle_worker_starts_its_engine_once() {
        let inner = crate::thread_worker::ThreadWorkerManager::new();
        let _master = inner.take_master_rx();
        inner.set_worker_filter(1, &[], true).unwrap();
        let wm = Arc::new(CountingThreadWorkers {
            inner,
            starts: Default::default(),
        });
        let filter = vec![0x01; 32];
        let prover = ProverInfo {
            public_key: vec![],
            address: vec![0xAA; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![make_alloc(filter.clone())],
            available_storage: 0,
            seniority: 0,
            delegate_address: vec![],
        };
        let alloc = WorkerAllocator::new(
            wm.clone(),
            Arc::new(TestProverRegistry::with_prover(prover)),
            vec![0xAAu8; 32],
        );
        alloc.on_new_frame(100).unwrap();
        assert_eq!(wm.range_workers().unwrap()[0].filter, filter);
        for frame in 101..104 {
            alloc.on_new_frame(frame).unwrap();
        }
        assert_eq!(wm.starts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(wm.range_workers().unwrap()[0].allocated);
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
    fn missed_renewal_retains_or_recovers_worker_for_one_epoch() {
        use quil_types::consensus::EffectiveStatus;
        let filter = vec![0x01; 32];
        for initially_bound in [false, true] {
            let wm = Arc::new(MockWorkerManager::new());
            wm.allocate_worker(1, if initially_bound { &filter } else { &[] })
                .unwrap();
            let mut recovering = make_alloc(filter.clone());
            recovering.epoch = 0;
            let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
                recovering.clone(),
            ])));
            let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
            for frame in [720, 725, 1439] {
                allocator.on_new_frame(frame).unwrap();
                assert_eq!(wm.range_workers().unwrap()[0].filter, filter);
                assert_eq!(
                    recovering.effective_status(frame),
                    EffectiveStatus::ExpiredEpoch,
                    "capacity recovery must not make stale proofs valid"
                );
            }
            allocator.on_new_frame(1440).unwrap();
            assert!(
                wm.range_workers().unwrap()[0].filter.is_empty(),
                "an unrenewed registration cannot reserve capacity indefinitely"
            );
        }
    }

    #[test]
    fn running_renewal_keeps_or_recovers_worker_past_the_recovery_epoch() {
        use quil_types::consensus::EffectiveStatus;
        let filter = vec![0x01; 32];
        for initially_bound in [false, true] {
            let wm = Arc::new(MockWorkerManager::new());
            wm.allocate_worker(1, if initially_bound { &filter } else { &[] })
                .unwrap();
            let mut renewing = make_alloc(filter.clone());
            renewing.epoch = 0;
            let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
                renewing.clone()
            ])));
            let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
            let renewal = allocator
                .submission_attempts
                .begin(
                    std::slice::from_ref(&filter),
                    1400,
                    crate::submission_attempts::OpKind::Confirm,
                )
                .unwrap();
            for frame in [1440, 2160, 2900] {
                allocator.on_new_frame(frame).unwrap();
                assert_eq!(
                    wm.range_workers().unwrap()[0].filter,
                    filter,
                    "a renewal still in preparation keeps its worker"
                );
                assert_eq!(
                    renewing.effective_status(frame),
                    EffectiveStatus::ExpiredEpoch
                );
            }
            drop(renewal);
            allocator.on_new_frame(2901).unwrap();
            assert!(
                wm.range_workers().unwrap()[0].filter.is_empty(),
                "a failed renewal no longer reserves the worker"
            );
        }
    }

    /// A seat lapsed past its recovery epoch whose leave is in flight is not
    /// being renewed: its worker is released, and an idle one is not bound
    /// to it, while a running confirm keeps or recovers it (2026-10-22: a
    /// worker was rebound to a seat being left, and the renewal planned for
    /// it was refused once the seat was Leaving).
    #[test]
    fn only_a_running_confirm_keeps_or_recovers_a_lapsed_seats_worker() {
        use crate::submission_attempts::OpKind;
        let filter = vec![0x01; 32];
        for (kind, kept) in [(OpKind::Confirm, true), (OpKind::Leave, false)] {
            for initially_bound in [false, true] {
                let wm = Arc::new(MockWorkerManager::new());
                wm.allocate_worker(1, if initially_bound { &filter } else { &[] })
                    .unwrap();
                let mut lapsed = make_alloc(filter.clone());
                lapsed.epoch = 0;
                let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![lapsed])));
                let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
                allocator.note_renewals_offered();
                let running = allocator
                    .submission_attempts
                    .begin(std::slice::from_ref(&filter), 1440, kind)
                    .unwrap();
                allocator.on_new_frame(1441).unwrap();
                assert_eq!(
                    wm.range_workers().unwrap()[0].filter == filter,
                    kept,
                    "{kind:?} in flight, initially_bound={initially_bound}"
                );
                drop(running);
            }
        }
    }

    /// After a restart, a worker still bound to a seat lapsed past its
    /// recovery epoch keeps it until the lifecycle first decides renewals:
    /// the record of the renewal that kept it was in memory. Decided without
    /// a renewal, the seat is released; with one running, it stays. A seat
    /// unbound at startup is not bound for it.
    #[test]
    fn a_restart_keeps_a_lapsed_seat_until_renewals_are_decided() {
        let filter = vec![0x01; 32];
        let e = epoch_length_frames();
        for renewing in [false, true] {
            let wm = Arc::new(MockWorkerManager::new());
            wm.allocate_worker(1, &filter).unwrap();
            let mut lapsed = make_alloc(filter.clone());
            lapsed.epoch = 0;
            let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![lapsed])));
            let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
            for frame in [3 * e, 3 * e + 1] {
                allocator.on_new_frame(frame).unwrap();
                assert_eq!(
                    wm.range_workers().unwrap()[0].filter,
                    filter,
                    "renewals not decided yet; renewing={renewing}"
                );
            }
            let renewal = renewing.then(|| {
                allocator
                    .submission_attempts
                    .begin(
                        std::slice::from_ref(&filter),
                        3 * e + 1,
                        crate::submission_attempts::OpKind::Confirm,
                    )
                    .unwrap()
            });
            allocator.note_renewals_offered();
            allocator.on_new_frame(3 * e + 2).unwrap();
            assert_eq!(
                wm.range_workers().unwrap()[0].filter.is_empty(),
                !renewing,
                "renewing={renewing}"
            );
            drop(renewal);
        }

        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let mut lapsed = make_alloc(filter.clone());
        lapsed.epoch = 0;
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![lapsed])));
        let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
        allocator.on_new_frame(3 * e).unwrap();
        assert!(
            wm.range_workers().unwrap()[0].filter.is_empty(),
            "an unbound lapsed seat is not bound"
        );
    }

    /// Sets this thread's leaver currency frame, and unsets it when dropped.
    struct LeaverCurrency;
    impl LeaverCurrency {
        fn at(frame: Option<u64>) -> Self {
            quil_execution::prover_registry::set_leaver_currency_frame_for_thread(frame);
            Self
        }
    }
    impl Drop for LeaverCurrency {
        fn drop(&mut self) {
            quil_execution::prover_registry::set_leaver_currency_frame_for_thread(None);
        }
    }

    /// A seat registered for `epoch` on filter `[byte; 32]`, and one left
    /// at `leave_frame`.
    fn lapsed(byte: u8, epoch: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            epoch,
            ..make_alloc(vec![byte; 32])
        }
    }
    fn left(byte: u8, epoch: u64, leave_frame: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status: ProverStatus::Leaving,
            leave_frame_number: leave_frame,
            ..lapsed(byte, epoch)
        }
    }

    /// The recovery gate withholds archive recovery from exactly the seats
    /// nothing renews, read from the registry before any lifecycle
    /// evaluation: one lapsed past its recovery epoch, and one being left
    /// after it so lapsed that its committee no longer seats (from the
    /// leaver currency frame). A current seat, one in its recovery epoch, one
    /// whose renewal runs, one a worker served at this start (until renewals
    /// are decided) and one left while current all keep recovering. An
    /// operator's node recovered 1.26M leaves per shard of nine seats lapsed
    /// 18 epochs, before and after its planner left them.
    #[test]
    fn the_recovery_gate_withholds_only_seats_nothing_renews() {
        let _currency = LeaverCurrency::at(Some(0));
        let e = epoch_length_frames();
        let frame = 20 * e + 5;
        let allocations = vec![
            lapsed(1, 20),
            lapsed(2, 19),
            lapsed(3, 2),
            lapsed(4, 2),
            lapsed(5, 2),
            left(6, 2, 20 * e + 1),
            left(7, 20, 20 * e + 1),
        ];
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[5; 32]).unwrap();
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(allocations)));
        let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
        let renewal = allocator
            .submission_attempts
            .begin(
                &[vec![4; 32]],
                frame,
                crate::submission_attempts::OpKind::Confirm,
            )
            .unwrap();
        allocator.on_new_frame(frame).unwrap();
        assert_eq!(
            wm.range_workers().unwrap()[0].filter,
            vec![5; 32],
            "kept until renewals are decided"
        );
        let gate = |byte: u8| {
            allocator
                .given_up_seat(&[byte; 32], frame)
                .map(|seat| seat.cause)
        };
        let expected = [
            (1, None),
            (2, None),
            (3, Some(GivenUp::Lapsed)),
            (4, None),
            (5, None),
            (6, Some(GivenUp::LeftLapsed)),
            (7, None),
            (8, None),
        ];
        for (byte, cause) in expected {
            assert_eq!(gate(byte), cause, "seat {byte}");
        }
        assert_eq!(
            allocator.given_up_seat(&[3; 32], frame),
            Some(GivenUpSeat {
                cause: GivenUp::Lapsed,
                frame,
                allocation_epoch: 2,
                current_epoch: 20
            })
        );
        allocator.note_renewals_offered();
        assert_eq!(
            gate(5),
            Some(GivenUp::Lapsed),
            "renewals decided without it"
        );
        drop(renewal);
    }

    /// A node back after 18 epochs judges no seat at its stored GLOBAL head:
    /// the startup reconcile waits, so no lapsed seat is bound, and no shard
    /// recovered, before a reconcile at a current frame, which binds none of
    /// them and gives them up. A head stored a minute ago is reconciled at once.
    #[test]
    fn a_node_back_after_18_epochs_binds_no_seat_before_its_global_view_is_current() {
        let e = epoch_length_frames();
        let (stored, current) = (1274 * e + 100, 1292 * e + 50);
        let now = 1_800_000_000_000;
        let epoch_ms = e * crate::difficulty::IDEAL_FRAME_TIME.unsigned_abs();
        let idle = |wm: &MockWorkerManager| wm.range_workers().unwrap()[0].filter.is_empty();
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![lapsed(
            3, 1274,
        )])));
        let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
        assert!(
            !allocator
                .startup_reconcile(stored, now - 18 * epoch_ms, now)
                .unwrap(),
            "the stored head is stale"
        );
        assert!(idle(&wm), "nothing is bound off the stored head");
        allocator.on_new_frame(current).unwrap();
        assert!(idle(&wm), "at a current frame the lapsed seat is not bound");
        assert_eq!(
            allocator
                .given_up_seat(&[3; 32], current)
                .map(|seat| seat.cause),
            Some(GivenUp::Lapsed)
        );

        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[]).unwrap();
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![lapsed(
            4, 1292,
        )])));
        let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
        assert!(
            allocator
                .startup_reconcile(current, now - 60_000, now)
                .unwrap(),
            "a current head is used at once"
        );
        assert_eq!(wm.range_workers().unwrap()[0].filter, vec![4; 32]);
        assert!(
            stored_head_current(now - epoch_ms, now)
                && !stored_head_current(now - epoch_ms - 1, now)
        );
    }

    /// The gate judges at the frame the latest reconcile ran at, which the
    /// registry reflects: a seat current there is not withheld however far
    /// a lagging node's gossip head runs past an epoch boundary, and is once
    /// a reconcile reaches the frame it lapsed at.
    #[test]
    fn the_recovery_gate_judges_at_the_reconciled_frame_not_the_head() {
        let e = epoch_length_frames();
        let wm = Arc::new(MockWorkerManager::new());
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![lapsed(
            3, 20,
        )])));
        let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
        let frame = |allocator: &WorkerAllocator| {
            allocator
                .reconciled_frame
                .load(std::sync::atomic::Ordering::Relaxed)
        };
        allocator.on_new_frame(20 * e + 5).unwrap();
        // Execution, and so the reconcile, stays in epoch 20 while the head
        // passes the boundaries of epochs 21 and 22.
        let head = 22 * e + 5;
        assert_eq!(
            allocator
                .given_up_seat(&[3; 32], head)
                .map(|seat| seat.cause),
            Some(GivenUp::Lapsed),
            "judged at the head, the seat would read lapsed"
        );
        assert_eq!(
            allocator.given_up_seat(&[3; 32], frame(&allocator)),
            None,
            "current at the reconciled frame"
        );
        allocator.on_new_frame(head).unwrap();
        assert_eq!(frame(&allocator), head);
        allocator.on_new_frame(21 * e).unwrap();
        assert_eq!(
            frame(&allocator),
            head,
            "an older reconcile frame does not move it back"
        );
        assert_eq!(
            allocator
                .given_up_seat(&[3; 32], frame(&allocator))
                .map(|seat| seat.cause),
            Some(GivenUp::Lapsed)
        );
    }

    /// Before the first reconcile finds this prover registered, the gate
    /// gives up no lapsed seat: which seats a worker served at this start,
    /// and keeps until renewals are decided, is not known yet, and an engine
    /// starting on one asks for some bootstraps only once. A leaver its
    /// committee no longer seats needs no such wait.
    #[test]
    fn the_recovery_gate_gives_up_no_lapsed_seat_before_the_first_reconcile() {
        let _currency = LeaverCurrency::at(Some(0));
        let e = epoch_length_frames();
        let frame = 20 * e + 5;
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &[3; 32]).unwrap();
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            lapsed(3, 2),
            lapsed(4, 2),
            left(6, 2, 20 * e + 1),
        ])));
        let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
        let gate = |byte: u8| {
            allocator
                .given_up_seat(&[byte; 32], frame)
                .map(|seat| seat.cause)
        };
        assert_eq!(
            (gate(3), gate(4), gate(6)),
            (None, None, Some(GivenUp::LeftLapsed))
        );
        allocator.on_new_frame(frame).unwrap();
        assert_eq!(
            (gate(3), gate(4)),
            (None, Some(GivenUp::Lapsed)),
            "the seat served at this start waits for the renewal decision; the other is given up"
        );
    }

    /// A seat left after its registration lapsed keeps its worker while its
    /// committee seats it for its notice: under an unset leaver currency
    /// frame (mainnet) every unexpired leaver is seated. From that frame, a
    /// seat left in its recovery epoch keeps it too, and one left an epoch
    /// later gets none, a bound one being released.
    #[test]
    fn a_seat_left_after_it_lapsed_keeps_its_worker_while_its_committee_seats_it() {
        let e = epoch_length_frames();
        let frame = 20 * e + 5;
        for (currency, epoch, keeps) in
            [(None, 18, true), (Some(0), 19, true), (Some(0), 18, false)]
        {
            let _currency = LeaverCurrency::at(currency);
            for initially_bound in [false, true] {
                let wm = Arc::new(MockWorkerManager::new());
                wm.allocate_worker(1, if initially_bound { &[6; 32] } else { &[] })
                    .unwrap();
                let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![left(
                    6,
                    epoch,
                    20 * e + 1,
                )])));
                let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
                allocator.on_new_frame(frame).unwrap();
                let worker = wm.range_workers().unwrap().remove(0);
                let case = format!(
                    "currency={currency:?}, epoch={epoch}, initially_bound={initially_bound}"
                );
                assert_eq!(worker.filter == [6; 32], keeps, "{case}");
                assert_eq!(worker.allocated, keeps, "{case}");
                assert_eq!(
                    allocator.given_up_seat(&[6; 32], frame).is_none(),
                    keeps,
                    "{case}"
                );
            }
        }
    }

    #[test]
    fn rejected_leave_keeps_or_rebinds_worker_until_recovery_epoch_ends() {
        use quil_types::consensus::EffectiveStatus;
        let filter = vec![0x01; 32];
        for initially_bound in [false, true] {
            let wm = Arc::new(MockWorkerManager::new());
            wm.allocate_worker(1, if initially_bound { &filter } else { &[] })
                .unwrap();
            let mut recovering = make_alloc(filter.clone());
            recovering.epoch = 0;
            recovering.leave_frame_number = 10;
            recovering.leave_reject_frame_number = 721;
            let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
                recovering.clone(),
            ])));
            let allocator = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
            for frame in [725, 1439] {
                allocator.on_new_frame(frame).unwrap();
                assert_eq!(
                    wm.range_workers().unwrap()[0].filter,
                    filter,
                    "renewal needs its worker even before registration lands"
                );
                assert_eq!(
                    recovering.effective_status(frame),
                    EffectiveStatus::ExpiredEpoch,
                    "worker recovery must not fake a valid storage epoch"
                );
            }
            allocator.on_new_frame(1440).unwrap();
            assert!(
                wm.range_workers().unwrap()[0].filter.is_empty(),
                "failed renewal cannot reserve the worker beyond the rejection epoch"
            );
        }
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
        // Renewals were decided since start; the restart case is
        // `a_restart_keeps_a_lapsed_seat_until_renewals_are_decided`.
        alloc.note_renewals_offered();

        alloc.on_new_frame(frame).unwrap();

        let workers = wm.range_workers().unwrap();
        assert_eq!(workers.len(), 1);
        assert_eq!(
            workers[0].filter, live_filter,
            "the stale epoch binding must yield its only worker to the live allocation"
        );
    }

    /// Releases are mode-agnostic, and the lifecycle joins auto workers
    /// only, so a manual worker whose seat lapsed sat idle with no signal.
    /// The pass that idles it says so once; one rebound in the same pass,
    /// or one whose leave departed, is not reported as a lost seat.
    #[test]
    fn a_manual_worker_idled_by_a_release_is_reported_once() {
        const LOST: &str = "manual worker lost its seat and is idle";
        const LEFT: &str = "manual worker idle after leaving its shard";
        let frame = 10_000;
        let stale_filter = vec![0x01; 32];
        let live_filter = vec![0x02; 32];
        let setup = |allocations: Vec<ProverAllocationInfo>| {
            let wm = Arc::new(MockWorkerManager::new());
            wm.allocate_worker(1, &stale_filter).unwrap();
            wm.set_manually_managed(1, true).unwrap();
            let reg = Arc::new(TestProverRegistry::with_prover(prover_with(allocations)));
            let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
            alloc.note_renewals_offered();
            (wm, alloc)
        };
        let mut stale = make_alloc(stale_filter.clone());
        stale.epoch = 0;

        let (wm, alloc) = setup(vec![stale.clone()]);
        let logged = reconcile_logged(&alloc, frame);
        assert!(
            wm.range_workers().unwrap()[0].filter.is_empty(),
            "the lapsed seat frees its worker"
        );
        assert_eq!(logged.matches(LOST).count(), 1, "{logged}");
        assert!(
            logged.contains("missed_epoch_renewal") && logged.contains("core_id=1"),
            "{logged}"
        );
        let logged = reconcile_logged(&alloc, frame + 1);
        assert!(
            !logged.contains(LOST),
            "an idle worker is reported on the transition only: {logged}"
        );

        let mut live = make_alloc(live_filter.clone());
        live.epoch = quil_types::consensus::epoch_for_frame(frame);
        let (wm, alloc) = setup(vec![stale.clone(), live]);
        let logged = reconcile_logged(&alloc, frame);
        assert_eq!(wm.range_workers().unwrap()[0].filter, live_filter);
        assert!(
            !logged.contains(LOST),
            "a worker rebound in the same pass is not idle: {logged}"
        );

        let mut departed = make_alloc(stale_filter.clone());
        departed.status = ProverStatus::Kicked;
        departed.leave_frame_number = 100;
        departed.leave_confirm_frame_number = 800;
        let (_, alloc) = setup(vec![departed]);
        let logged = reconcile_logged(&alloc, frame);
        assert!(
            !logged.contains(LOST) && logged.contains(LEFT) && logged.contains("leave_confirmed"),
            "{logged}"
        );
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
    fn worker_loss_does_not_interrupt_the_surviving_allocation() {
        // Losing two workers does not authorize stopping the survivor's
        // consensus participation, even if orphaned holdings score better.
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
            vec![filters[0].clone()],
            "a better score must not interrupt the surviving allocation"
        );
    }

    #[test]
    fn halt_risk_priority_never_preempts_serving_or_paused_allocations() {
        for status in [
            ProverStatus::Active,
            ProverStatus::Paused,
            ProverStatus::Leaving,
        ] {
            let frame = 10_000;
            let filters = vec![vec![0x01; 32], vec![0x02; 32]];
            let wm = Arc::new(MockWorkerManager::new());
            wm.allocate_worker(1, &filters[0]).unwrap();
            let mut prover = prover_with_active(&filters, frame);
            prover.allocations[0].status = status;
            prover.allocations[0].leave_frame_number = frame;
            let registry = Arc::new(TestProverRegistry::with_prover(prover));
            let allocator = WorkerAllocator::new(wm.clone(), registry, vec![0xAA; 32]);
            allocator.publish_allocation_priority(
                frame,
                vec![
                    (filters[0].clone(), false, 1.into()),
                    (filters[1].clone(), true, 9_000.into()),
                ],
            );
            allocator.on_new_frame(frame).unwrap();
            assert_eq!(bound_filters(&wm), vec![filters[0].clone()], "{status:?}");
        }
    }

    #[test]
    fn replacement_binds_after_the_notice_period_actually_ends() {
        let frame = 10_000;
        let filters = vec![vec![0x01; 32], vec![0x02; 32]];
        let wm = Arc::new(MockWorkerManager::new());
        wm.allocate_worker(1, &filters[0]).unwrap();
        let mut prover = prover_with_active(&filters, frame);
        prover.allocations[0].status = ProverStatus::Leaving;
        prover.allocations[0].leave_frame_number = frame - 720;
        prover.allocations[0].leave_confirm_frame_number = frame;
        prover.allocations[1].epoch = u64::MAX;
        let registry = Arc::new(TestProverRegistry::with_prover(prover));
        let allocator = WorkerAllocator::new(wm.clone(), registry, vec![0xAA; 32]);
        allocator.publish_allocation_priority(
            frame,
            vec![
                (filters[0].clone(), false, 1.into()),
                (filters[1].clone(), true, 9_000.into()),
            ],
        );
        allocator.on_new_frame(frame).unwrap();
        assert_eq!(bound_filters(&wm), vec![filters[0].clone()]);
        let departure = (quil_types::consensus::epoch_for_frame(frame) + 1)
            * quil_types::consensus::epoch_length_frames();
        allocator.on_new_frame(departure - 1).unwrap();
        assert_eq!(bound_filters(&wm), vec![filters[0].clone()]);
        allocator.on_new_frame(departure).unwrap();
        assert_eq!(bound_filters(&wm), vec![filters[1].clone()]);
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
    fn priority_evidence_retains_the_scoring_snapshot() {
        let wm = Arc::new(MockWorkerManager::new());
        let reg = Arc::new(TestProverRegistry::new());
        let allocator = WorkerAllocator::new(wm, reg, vec![0xAA; 32]);
        let filter = vec![0x01; 32];
        let frame = 720;
        let evidence = AllocationPriorityEvidence {
            frame_number: frame,
            active: 3,
            joining: 20,
            paused: 1,
            leaving: 7,
            scoring_ring: 0,
            ring_source: "current_committee",
            ring_member_count: Some(3),
            ring_target_frame: Some(frame),
            size_bytes: 1000,
            data_shards: 2,
            difficulty: 100,
            world_bytes_input: "123".into(),
            world_bytes_source: "registry_count_proxy",
            allocation_epoch: Some(1),
            stored_ring: Some(0),
            allocation_status: Some("Active".into()),
            allocation_raw_status: Some("Active".into()),
            join_confirm_frame: Some(1),
            leave_frame: Some(0),
            leave_confirm_frame: Some(0),
            leave_reject_frame: Some(0),
        };
        allocator.publish_allocation_priority_with_evidence(
            frame,
            vec![(filter.clone(), true, 10.into())],
            HashMap::from([(filter.clone(), evidence)]),
        );
        let PriorityState::Fresh(captured) = allocator.allocation_priority_state(frame + 1) else {
            panic!("expected usable snapshot");
        };
        allocator.publish_allocation_priority(frame + 1, vec![(filter.clone(), false, 20.into())]);
        let old = serde_json::to_value(captured[&filter].evidence.as_ref().unwrap()).unwrap();
        assert_eq!(old["frame_number"], frame);
        assert_eq!(old["active"], 3);
        assert_eq!(old["joining"], 20);
        assert_eq!(old["leaving"], 7);
        assert_eq!(old["stored_ring"], 0);
        assert!(captured[&filter].halt_risk);
        let PriorityState::Fresh(current) = allocator.allocation_priority_state(frame + 1) else {
            panic!("expected replacement snapshot");
        };
        assert!(!current[&filter].halt_risk);
        assert!(
            current[&filter].evidence.is_none(),
            "missing provenance must remain unknown"
        );
    }

    #[test]
    fn priority_state_distinguishes_missing_from_stale() {
        let wm = Arc::new(MockWorkerManager::new());
        let reg = Arc::new(TestProverRegistry::new());
        let alloc = WorkerAllocator::new(wm, reg, vec![0xAAu8; 32]);
        let frame = 10_000u64;

        assert!(
            matches!(
                alloc.allocation_priority_state(frame),
                PriorityState::Missing
            ),
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

        alloc
            .publish_allocation_priority(frame + 1, vec![(vec![0x01; 32], false, BigInt::from(5))]);
        assert!(
            matches!(
                alloc.allocation_priority_state(frame),
                PriorityState::Fresh(_)
            ),
            "a ranking stamped a frame ahead is still fresh — reconciles run \
             from three sources whose frame numbers interleave"
        );
    }

    #[test]
    fn deferred_replacement_review_respects_its_interval() {
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
        assert_eq!(bound_filters(&wm), vec![filters[0].clone()]);
        assert_eq!(
            alloc
                .last_priority_review_frame
                .load(std::sync::atomic::Ordering::Relaxed),
            frame
        );

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
            vec![filters[0].clone()],
            "a second rebind within SURPLUS_REVIEW_INTERVAL_FRAMES must be deferred"
        );

        assert_eq!(
            alloc
                .last_priority_review_frame
                .load(std::sync::atomic::Ordering::Relaxed),
            frame
        );

        // A later review still must not move the serving worker.
        let later = frame + SURPLUS_REVIEW_INTERVAL_FRAMES + 1;
        alloc.publish_allocation_priority(
            later,
            vec![
                (filters[0].clone(), false, BigInt::from(100)),
                (filters[1].clone(), false, BigInt::from(4_000)),
                (filters[2].clone(), false, BigInt::from(1)),
            ],
        );
        alloc.on_new_frame(later).unwrap();
        assert_eq!(bound_filters(&wm), vec![filters[0].clone()]);
        assert_eq!(
            alloc
                .last_priority_review_frame
                .load(std::sync::atomic::Ordering::Relaxed),
            later
        );
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
        let cfg = vec!["0xaabbccdd".into(), "11223344".into(), "".into()];

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

        let cfg = vec!["0xab".into(), "0XCD".into(), "ef".into()];
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

    /// Eviction waits for a settled binding, protects every scope the worker
    /// may still read (binding, staged changes of its own application),
    /// repeats on its interval and restarts its wait on rebind.
    #[test]
    fn payload_eviction_waits_for_settled_bindings_and_protects_live_scopes() {
        use quil_types::store::{PendingShardChange, ShardChangeKind};
        let minutes = |m: u64| std::time::Duration::from_secs(m * 60);
        let filter = |app: u8, tail: u8| {
            let mut f = vec![app; 32];
            f.extend([0, 1, tail]);
            f
        };
        let wm = Arc::new(MockWorkerManager::new());
        wm.add_with_filter(1, filter(7, 0x00));
        wm.add_with_filter(2, filter(7, 0x80));
        wm.add(WorkerInfo {
            pending_filter_frame: 5,
            ..find_worker(&wm, 2)
        });
        wm.add_with_filter(3, Vec::new());
        let reg = Arc::new(TestProverRegistry::new());
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
        let t0 = std::time::Instant::now();
        alloc.schedule_payload_eviction(t0 + minutes(120)).unwrap();
        assert!(
            wm.evictions().is_empty(),
            "unknown staged changes must not evict"
        );

        let staged = vec![
            PendingShardChange {
                kind: ShardChangeKind::Merge,
                parent: vec![7; 32],
                children: vec![filter(7, 0x00), filter(7, 0x80)],
                effective_epoch: 9,
                proposed_frame: 1,
            },
            PendingShardChange {
                kind: ShardChangeKind::Split,
                parent: filter(8, 0x00),
                children: vec![],
                effective_epoch: 9,
                proposed_frame: 1,
            },
        ];
        alloc.set_pending_shard_changes(Arc::new(move || Ok(staged.clone())));
        alloc.schedule_payload_eviction(t0).unwrap();
        alloc.schedule_payload_eviction(t0 + minutes(29)).unwrap();
        assert!(
            wm.evictions().is_empty(),
            "an unsettled binding must not evict"
        );
        alloc.schedule_payload_eviction(t0 + minutes(30)).unwrap();
        let mut expected = vec![filter(7, 0x00), filter(7, 0x80), vec![7; 32]];
        expected.sort();
        assert_eq!(
            wm.evictions(),
            vec![(1, expected)],
            "pending joins and idle workers never evict"
        );
        alloc.schedule_payload_eviction(t0 + minutes(89)).unwrap();
        assert_eq!(wm.evictions().len(), 1);
        alloc.schedule_payload_eviction(t0 + minutes(90)).unwrap();
        assert_eq!(
            wm.evictions().len(),
            2,
            "settled bindings repeat on their interval"
        );

        wm.add_with_filter(1, filter(7, 0xc0));
        alloc.schedule_payload_eviction(t0 + minutes(100)).unwrap();
        alloc.schedule_payload_eviction(t0 + minutes(129)).unwrap();
        assert_eq!(
            wm.evictions().len(),
            2,
            "a rebind restarts the settle period"
        );
        alloc.schedule_payload_eviction(t0 + minutes(130)).unwrap();
        assert_eq!(wm.evictions().len(), 3);
        assert!(wm.evictions()[2].1.contains(&filter(7, 0xc0)));
    }

    /// A staged change protects its shards only while a prover or worker holds
    /// one of them.
    #[test]
    fn payload_eviction_ignores_staged_changes_of_shards_nobody_holds() {
        use quil_types::store::{PendingShardChange, ShardChangeKind};
        let filter = |tail: u8| {
            let mut f = vec![7; 32];
            f.extend([0, 1, tail]);
            f
        };
        let wm = Arc::new(MockWorkerManager::new());
        wm.add_with_filter(1, filter(0x00));
        let mut prover = prover_with_active(&[filter(0x60), filter(0x40)], 100);
        prover.allocations[1].status = ProverStatus::Historic;
        let reg = Arc::new(TestProverRegistry::with_provers(vec![prover]));
        let alloc = WorkerAllocator::new(wm.clone(), reg, vec![0xAA; 32]);
        let split = |parent: u8| PendingShardChange {
            kind: ShardChangeKind::Split,
            parent: filter(parent),
            children: vec![filter(parent + 1), filter(parent + 2)],
            effective_epoch: 9,
            proposed_frame: 1,
        };
        let staged = vec![split(0x40), split(0x60)];
        alloc.set_pending_shard_changes(Arc::new(move || Ok(staged.clone())));
        let t0 = std::time::Instant::now();
        alloc.schedule_payload_eviction(t0).unwrap();
        alloc
            .schedule_payload_eviction(t0 + PAYLOAD_EVICTION_SETTLE)
            .unwrap();
        assert_eq!(
            wm.evictions(),
            vec![(
                1,
                vec![filter(0x00), filter(0x60), filter(0x61), filter(0x62)]
            )],
            "a change of shards nobody holds protects nothing"
        );
    }

    /// Joins that land are announced once per batch with the epoch their
    /// confirm is due in and the frame they activate at; a confirmed join
    /// starts its engine naming the frame it activates at.
    #[test]
    fn landed_joins_are_announced_once_with_their_confirm_window_and_activation() {
        fn reconcile_log(alloc: &WorkerAllocator, frame: u64) -> String {
            #[derive(Clone, Default)]
            struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for Lines {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().write(bytes)
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let lines = Lines::default();
            let writer = lines.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, || alloc.on_new_frame(frame).unwrap());
            let bytes = lines.0.lock().unwrap().clone();
            String::from_utf8(bytes).unwrap()
        }
        let e = quil_types::consensus::epoch_length_frames();
        let joining = |filter: u8, join_frame: u64| ProverAllocationInfo {
            status: ProverStatus::Joining,
            join_frame_number: join_frame,
            join_confirm_frame_number: 0,
            ..make_alloc(vec![filter; 32])
        };
        let wm = Arc::new(MockWorkerManager::new());
        for core in 1..=3u32 {
            wm.allocate_worker(core, &[]).unwrap();
        }
        let reg = Arc::new(TestProverRegistry::with_prover(prover_with(vec![
            joining(1, e + 2),
            joining(2, e + 3),
        ])));
        let alloc = WorkerAllocator::new(wm.clone(), reg.clone(), vec![0xAAu8; 32]);
        let logged = reconcile_log(&alloc, e + 29);
        assert_eq!(
            logged.matches("joins landed in the registry").count(),
            1,
            "{logged}"
        );
        for field in [
            "allocations=2".to_string(),
            format!("join_frames={}..{}", e + 2, e + 3),
            "confirm_epoch=2".to_string(),
            format!("confirm_window={}..{}", 2 * e, 3 * e - 1),
            format!("activation_frame={}", 3 * e),
        ] {
            assert!(logged.contains(&field), "{field}: {logged}");
        }
        assert_eq!(bound_cores(&wm), vec![1, 2]);
        assert!(
            !reconcile_log(&alloc, e + 30).contains("joins landed"),
            "announced once"
        );

        let mut confirmed = joining(1, e + 2);
        (
            confirmed.status,
            confirmed.join_confirm_frame_number,
            confirmed.epoch,
        ) = (ProverStatus::Active, 2 * e + 8, 3);
        reg.set_prover(prover_with(vec![confirmed, joining(2, e + 3)]));
        let logged = reconcile_log(&alloc, 2 * e + 9);
        assert_eq!(
            logged
                .matches("join confirmed — starting consensus engine")
                .count(),
            1,
            "{logged}"
        );
        assert!(
            logged.contains(&format!("activation_frame={}", 3 * e)),
            "{logged}"
        );
    }
}
