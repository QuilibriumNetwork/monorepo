//! Shard coverage tracking. Partial port of
//! `node/consensus/global/coverage_monitor.go`.
//!
//! Quilibrium uses a "coverage" signal on each shard — if the number
//! of active provers on a shard drops to or below a halt threshold,
//! eviction of inactive provers is suspended so the surviving provers
//! don't kick each other out in a cascading failure.
//!
//! This module ports the data-structure and halt-duration
//! computation parts of the Go `CoverageMonitor`:
//!
//! - [`CoverageStreak`] tracks how long a shard has been in a
//! low-coverage state.
//! - [`LowCoverageStreakTracker`] manages the per-shard streak map,
//! providing `bump`, `clear`, and snapshot methods.
//! - [`CoverageThresholds`] captures the mainnet vs testnet halt
//! parameters.
//! - [`compute_shard_halt_durations`] walks per-shard summaries +
//! the streak map and returns the eviction-suppression duration
//! map used by `evict_inactive_provers`.
//!
//! The event-distribution + async coverage-check-loop plumbing from
//! the Go side is left for a later port — it requires infrastructure
//! (event distributor, hypergraph iteration, async task supervision)
//! that isn't wired into quil-engine yet.

use std::collections::HashMap;
use std::sync::Mutex;

use quil_types::consensus::{ProverInfo, ProverShardSummary, ProverStatus};

/// Per-shard "has been in a low-coverage state for N frames" record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageStreak {
    /// Frame at which the streak began.
    pub start_frame: u64,
    /// Most-recent frame contributing to the streak.
    pub last_frame: u64,
    /// Number of frames in the streak. Incremented by
    /// `last_frame - prev_last_frame` on each bump, so forks within
    /// a single frame don't double-count.
    pub count: u64,
}

impl CoverageStreak {
    /// Construct a fresh streak covering a single frame.
    pub fn new(frame: u64) -> Self {
        Self {
            start_frame: frame,
            last_frame: frame,
            count: 1,
        }
    }
}

/// Halt threshold configuration for a coverage monitor.
#[derive(Debug, Clone, Copy)]
pub struct CoverageThresholds {
    /// Minimum active provers on a shard. If a shard drops to this
    /// count or below, eviction is suspended for that shard.
    pub halt_threshold: u64,
    /// Minimum total provers for normal operation (from config).
    pub min_provers: u64,
    /// Maximum provers before a split is considered (the split TRIGGER). A shard
    /// splits only when `active > max_provers` AND its leaves can divide further
    /// (§6.1 — the divisibility guard bounds depth to where data diverges, giving
    /// convergence; there is NO separate data-count threshold).
    pub max_provers: u64,
    /// Streak length at which an initial halt is confirmed.
    pub halt_grace_frames: u64,
}

/// Default halt grace window. Sized to cover a full migration cycle
/// PLUS a complete back-to-back retry if the first attempt fails:
///
/// ```text
///   720 first cycle  : ProposeLeave → ConfirmLeaves → ProposeJoin
///                        → ConfirmJoins (2 × CONFIRM_WINDOW)
///   720 second cycle : full retry if the first never landed an
/// alloc (archive silently drops a bundle,
/// lifecycle re-proposes after the 10-frame
/// PROPOSAL_TIMEOUT_FRAMES expires)
///   360 slack budget : evaluate cadence + 4-frame join cooldown
/// + archive sync skew + a single
/// ProposalTimeout detection window
/// ────
/// 1800
/// ```
///
/// Rationale: a transaction can create a new vertex at an address
/// that bloom-routes to a zero-coverage shard. Until provers migrate
/// to it, the shard sits below the halt threshold and the streak
/// tracker bumps each frame. With a 360-frame grace (one confirm
/// window), even an instantly-responding network barely has time for
/// *one* prover to leave a heavily-covered shard before the halt
/// fires. 1800 frames give the network a complete happy-path
/// migration AND a full back-to-back retry on top of it before
/// any halt fires — so a single dropped bundle or a one-off race
/// doesn't halt the shard.
pub const DEFAULT_HALT_GRACE_FRAMES: u64 = 1800;

impl CoverageThresholds {
    /// Mainnet defaults: 3-prover halt, 6-prover min, 32-prover max,
    /// `DEFAULT_HALT_GRACE_FRAMES` (1440) frame grace window.
    pub fn mainnet() -> Self {
        Self {
            halt_threshold: 3,
            min_provers: 6,
            max_provers: 32,
            halt_grace_frames: DEFAULT_HALT_GRACE_FRAMES,
        }
    }

    /// Testnet defaults: 0-prover halt (no halt unless `min_provers`
    /// > 1, in which case 1), `min_provers` from config, 32-prover
    /// max, `DEFAULT_HALT_GRACE_FRAMES` grace window.
    pub fn testnet(min_provers: u64) -> Self {
        let halt_threshold = if min_provers > 1 { 1 } else { 0 };
        Self {
            halt_threshold,
            min_provers,
            max_provers: 32,
            halt_grace_frames: DEFAULT_HALT_GRACE_FRAMES,
        }
    }
}

/// Thread-safe tracker for per-shard low-coverage streaks.
#[derive(Debug, Default)]
pub struct LowCoverageStreakTracker {
    streaks: Mutex<HashMap<Vec<u8>, CoverageStreak>>,
}

impl LowCoverageStreakTracker {
    pub fn new() -> Self {
        Self {
            streaks: Mutex::new(HashMap::new()),
        }
    }

    /// Bump the streak for `shard_key` at `frame`. If no streak
    /// exists, create a new one covering `frame`. Count advances by
    /// `frame - last_frame` to avoid double-counting under
    /// single-slot fork choice.
    pub fn bump(&self, shard_key: &[u8], frame: u64) -> CoverageStreak {
        let mut guard = self.streaks.lock().unwrap();
        match guard.get_mut(shard_key) {
            Some(s) => {
                if frame > s.last_frame {
                    s.count = s.count.saturating_add(frame - s.last_frame);
                    s.last_frame = frame;
                }
                *s
            }
            None => {
                let fresh = CoverageStreak::new(frame);
                guard.insert(shard_key.to_vec(), fresh);
                fresh
            }
        }
    }

    /// Clear the streak for `shard_key`. Called when a shard's
    /// coverage recovers above the halt threshold.
    pub fn clear(&self, shard_key: &[u8]) {
        let mut guard = self.streaks.lock().unwrap();
        guard.remove(shard_key);
    }

    /// Snapshot of current streak counts, keyed by shard key.
    pub fn snapshot(&self) -> HashMap<Vec<u8>, CoverageStreak> {
        self.streaks.lock().unwrap().clone()
    }

    /// Number of shards currently in a low-coverage streak.
    pub fn len(&self) -> usize {
        self.streaks.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.streaks.lock().unwrap().is_empty()
    }

    /// Get the current streak for a specific shard, if any.
    pub fn get(&self, shard_key: &[u8]) -> Option<CoverageStreak> {
        self.streaks.lock().unwrap().get(shard_key).copied()
    }

    /// Reconstruct streak data from each prover's allocations after
    /// a restart. On a fresh process the in-memory streak map is
    /// empty; without reconstruction an eviction pass run before any
    /// new frame would treat every stale allocation as freshly
    /// inactive and kick it. Computes per-shard
    /// `(active_count, max_last_active)` and seeds
    /// `count = current_frame - last_active` for shards below the
    /// halt threshold or with `staleness > 1`.
    ///
    /// Should normally be invoked once at startup before any
    /// frame-driven streak updates.
    pub fn reconstruct(
        &self,
        provers: &[ProverInfo],
        current_frame: u64,
        halt_threshold: u64,
    ) {
        let mut effective_coverage: HashMap<Vec<u8>, u64> = HashMap::new();
        let mut last_frame: HashMap<Vec<u8>, u64> = HashMap::new();

        for p in provers {
            for alloc in &p.allocations {
                let key = alloc.confirmation_filter.clone();
                if !effective_coverage.contains_key(&key) {
                    effective_coverage.insert(key.clone(), 0);
                    last_frame.insert(key.clone(), alloc.last_active_frame_number);
                }
                // Frame-aware, matching the LIVE coverage path
                // (`get_active_provers`): an epoch-EXPIRED allocation (raw
                // status still `Active`, `effective_status` = ExpiredEpoch) is
                // NOT effectively covering the shard, so it must not seed
                // coverage — otherwise a shard held only by expired provers looks
                // covered at startup and suppresses joins until the first live
                // update corrects it.
                if alloc.effective_status(current_frame)
                    == quil_types::consensus::EffectiveStatus::Active
                {
                    *effective_coverage.entry(key.clone()).or_insert(0) += 1;
                    let entry = last_frame.entry(key).or_insert(0);
                    if alloc.last_active_frame_number > *entry {
                        *entry = alloc.last_active_frame_number;
                    }
                }
            }
        }

        let mut guard = self.streaks.lock().unwrap();
        for (shard_key, coverage) in effective_coverage {
            let last = last_frame.get(&shard_key).copied().unwrap_or(0);
            let staleness = current_frame.saturating_sub(last);
            if coverage <= halt_threshold {
                // Currently halted — record full staleness as the streak.
                guard.insert(
                    shard_key,
                    CoverageStreak {
                        start_frame: last,
                        last_frame: current_frame,
                        count: staleness,
                    },
                );
            } else if staleness > 1 {
                // Recovered but stale — record gap so eviction subtracts it.
                guard.insert(
                    shard_key,
                    CoverageStreak {
                        start_frame: last,
                        last_frame: current_frame,
                        count: staleness,
                    },
                );
            }
        }
    }
}

/// Compute the eviction-suppression durations for each shard.
///
/// Semantics:
/// - Shards at or below `halt_threshold` → `u64::MAX` (eviction
/// fully suppressed).
/// - Shards with a non-empty streak but above the halt threshold →
/// their streak count, giving recently-recovered shards a grace
/// period proportional to how long they were halted.
/// - Shards with no streak and above the halt threshold → no entry
/// (normal eviction rules apply).
pub fn compute_shard_halt_durations(
    tracker: &LowCoverageStreakTracker,
    summaries: &[ProverShardSummary],
    thresholds: &CoverageThresholds,
) -> HashMap<Vec<u8>, u64> {
    let mut out = HashMap::new();

    // Step 1: snapshot live streaks into the output.
    for (shard_key, streak) in tracker.snapshot() {
        if streak.count > 0 {
            out.insert(shard_key, streak.count);
        }
    }

    // Step 2: override shards currently at/below the halt threshold
    // with `u64::MAX`. Uses `active_count` from the shard summary
    // (ProverStatus::Active count).
    for summary in summaries {
        // GUARD: a zero-size shard has no data to protect — never halt it,
        // mirroring the `check()` detection sweep's `entry.size == 0` skip and
        // the proposer's `raw_size == 0` continue. Without this, STALE OFF-GRID
        // filters (old-depth / ancestor prefixes left behind as the grid splits
        // deeper) with a few stranded provers each trip a PERMANENT `u64::MAX`
        // halt, inflating `halted_count` and wedging `any_halted()` true — which
        // suppresses `coverage_publish` (reward proofs) and blocks leave/swap
        // re-homing network-wide, even though every real data-bearing shard is
        // fully covered. Only real shards (size > 0) can hold a halt.
        if summary.total_size == 0 {
            continue;
        }
        let active_count = summary
            .status_counts
            .get(&ProverStatus::Active)
            .copied()
            .unwrap_or(0) as u64;
        if active_count <= thresholds.halt_threshold {
            out.insert(summary.filter.clone(), u64::MAX);
        }
    }

    out
}

// =====================================================================
// CoverageMonitor — async check loop
// =====================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use quil_types::consensus::{
    ControlEvent, ControlEventData, ControlEventType, EventDistributor, ProverRegistry,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// Coverage action constants.
const MAX_PROVERS_FOR_SPLIT: usize = 32;
const MIN_PROVERS_FOR_MERGE: usize = 2;
const STREAK_THRESHOLD: u64 = 10;

/// Frame at which the +720 grace-frame extension expires
/// (`FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END (262_340) + 360 (halt_grace_frames)`).
/// Before this frame, halt detection allows
/// `halt_grace_frames + 720` streak count before declaring a halt.
pub const EXTENDED_ENROLL_HALT_GRACE_END: u64 = 262_700;

/// Per-shard coverage action determined by [`CoverageMonitor::check_shard_coverage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageAction {
    /// Shard coverage is healthy — no action needed.
    Ok,
    /// Shard has fewer active provers than the halt threshold.
    NeedMoreProvers {
        filter: Vec<u8>,
        current: usize,
        needed: usize,
    },
    /// Shard has too many provers and should be split.
    ShouldSplit {
        filter: Vec<u8>,
        prover_count: usize,
    },
    /// Shard has too few provers and should be merged with its sibling.
    ShouldMerge {
        filter: Vec<u8>,
        sibling: Vec<u8>,
    },
    /// Coverage is critically low — halt eviction on this shard.
    Halt {
        filter: Vec<u8>,
        reason: String,
    },
}

/// Request sent over the mpsc channel to trigger a coverage check.
#[derive(Debug, Clone)]
pub struct CoverageCheckRequest {
    /// Frame number that triggered the check.
    pub frame_number: u64,
    /// Shard filters to check. If empty, all known shards are checked.
    pub filters: Vec<Vec<u8>>,
}

/// Coverage monitor that checks shard coverage on each new frame.
/// Subscribes to NewHead events and triggers coverage checks
/// asynchronously, updating the prover-only mode flag on the
/// message collector when coverage is degraded.
/// Per-shard data point the coverage monitor needs to make a halt
/// decision: shard size in bytes (skip if zero — no data to
/// protect) and current Active prover count. Sourced by the caller
/// from whichever data layer it has — the prover registry summary
/// (allocated-only view) on archive nodes, or the lifecycle's
/// `merged_shard_sizes` cache (archive-sync'd, ≤60 frames stale)
/// + registry summaries on non-archive nodes.
#[derive(Debug, Clone)]
pub struct ShardCoverageEntry {
    pub filter: Vec<u8>,
    pub size: u64,
    pub active_count: u64,
}

/// Caller-supplied closure that returns the universe of shards to
/// evaluate. The monitor stays storage-agnostic — non-archive nodes
/// wire this to `lifecycle.merged_shard_sizes()` keyed by filter,
/// archive nodes can wire it to a direct local-CRDT walk. When
/// unset, the monitor falls back to iterating
/// `prover_registry.get_prover_shard_summaries` — which sees only
/// shards with at least one allocation in `filter_cache` and
/// therefore can't observe zero-prover shards (the gap that
/// motivated this hook).
pub type ShardInventoryProvider =
    Arc<dyn Fn() -> Vec<ShardCoverageEntry> + Send + Sync>;

pub struct CoverageMonitor {
    prover_registry: Arc<dyn ProverRegistry>,
    event_distributor: Arc<dyn EventDistributor>,
    thresholds: CoverageThresholds,
    streaks: Arc<LowCoverageStreakTracker>,
    /// Shared flag: when true, the message collector rejects
    /// non-prover messages.
    prover_only_mode: Arc<AtomicBool>,
    /// Last frame where a coverage check ran (debounce).
    last_checked_frame: AtomicU64,
    /// Per-shard halt state we've already emitted to the event
    /// distributor. Used to detect transitions and emit Halt /
    /// Resume events only on the leading / trailing edge.
    emitted_halted: Mutex<std::collections::HashSet<Vec<u8>>>,
    /// Optional alternative source of the shard universe — see
    /// [`ShardInventoryProvider`]. When set, the per-frame `check`
    /// iterates the provider's output instead of relying on the
    /// allocated-only registry summary, which lets the monitor see
    /// zero-prover-but-non-zero-size shards (the address-creation
    /// failure mode).
    shard_inventory_provider: Option<ShardInventoryProvider>,
    /// Optional EMPTY-SPLIT GUARD (`UNIFIED_APP_TREE_DESIGN` §6.1): given a shard
    /// `(filter, factor)`, returns the leaf count of each of the `factor` proposed
    /// children under the unified app tree. A split is only proposed when ≥2 of
    /// those children are DATA-BEARING — otherwise the split would create an
    /// empty child (meaningless; on the legacy separate-tree model it also
    /// orphaned data). Wired by the node to
    /// `HypergraphCrdt::unified_subtree_leaf_count` (unified only); unset ⇒ no
    /// guard (legacy behavior). Interior-mutable because the monitor is
    /// `Arc`-wrapped before the CRDT exists.
    split_feasibility: std::sync::RwLock<Option<SplitFeasibilityProvider>>,
    /// Deep-bifurcation (§6.1 encoding rework) split PROPOSER. Given a shard
    /// filter, returns the child bit-path FILTERS of the shallowest real branch
    /// (`HypergraphCrdt::propose_split_children` → `first_split_bifurcation`),
    /// descending past any uniform run so BOTH children are data-bearing — or
    /// `None` (the empty-split guard, or an unsplittable single-leaf shard).
    /// Wired by the node ONLY under the unified app tree; unset ⇒ the legacy
    /// immediate-bit `compute_proposed_shards` byte-suffix children. Interior-
    /// mutable for the same reason as `split_feasibility`.
    split_proposer: std::sync::RwLock<Option<SplitProposalProvider>>,
    /// Deep-bifurcation: reports whether the unified app tree is active RIGHT NOW
    /// (the node wires `move || crdt.unified_tree()`, checked dynamically since it
    /// flips at the cutover frame — not at wiring time). Gates `propose_merge_
    /// rebalance`'s sibling identification: bit-path filters (`parent = drop the
    /// last BIT`) under unified, byte-suffix (`drop the last BYTE`, `0x00`/`0x80`)
    /// otherwise. Unset ⇒ legacy. Parity with the split proposer's dynamic check.
    unified_provider: std::sync::RwLock<Option<Arc<dyn Fn() -> bool + Send + Sync>>>,
    /// Per-shard frame of the last split/merge proposal we emitted, so a
    /// hot/cold shard isn't re-proposed every frame while the previous
    /// proposal is still working through consensus + materialize. Mirrors
    /// Go's `shard_rebalancer` cooldown.
    last_rebalance_frame: Mutex<std::collections::HashMap<Vec<u8>, u64>>,
    /// Reports the set of shard parents that ALREADY have a staged
    /// `PendingShardChange` (any effective epoch). The proposer skips these.
    /// Without it, a split/merge is re-emitted EVERY frame while the parent stays
    /// over/under-crowded — the pending change doesn't relieve the trigger until
    /// its E+2 apply, and the per-node cooldown is defeated by leader rotation. A
    /// re-proposal that crosses the epoch boundary then records a SECOND change at
    /// a LATER effective epoch (E+3), which conflicts with the E+2 one on apply
    /// (overlapping grid children). Consulting committed pending state makes
    /// emission idempotent. Unset ⇒ no suppression (legacy / no shards store).
    pending_change_provider:
        std::sync::RwLock<Option<PendingChangeProvider>>,
}

/// See [`CoverageMonitor::split_feasibility`]: `(filter, factor) →` per-child
/// leaf counts (length `factor`).
pub type SplitFeasibilityProvider = Arc<dyn Fn(&[u8], u8) -> Vec<u64> + Send + Sync>;

/// See [`CoverageMonitor::split_proposer`]: `filter →` the deep-bifurcation
/// child bit-path FILTERS (length 2), or `None` when the shard can't be split
/// into two data-bearing halves (the empty-split guard / single leaf).
pub type SplitProposalProvider = Arc<dyn Fn(&[u8]) -> Option<Vec<Vec<u8>>> + Send + Sync>;

/// See [`CoverageMonitor::pending_change_provider`]: `() →` the set of shard
/// parents (`ShardInfo`/filter bytes) that already have a staged pending change.
pub type PendingChangeProvider =
    Arc<dyn Fn() -> std::collections::HashSet<Vec<u8>> + Send + Sync>;

/// Frames to wait before re-proposing a split/merge for the same shard.
const REBALANCE_COOLDOWN_FRAMES: u64 = 30;

/// Assemble the per-shard inventory `propose_merge_rebalance` needs:
/// every current grid sub-shard with its reconstructed filter, committed
/// byte size, and Active prover count. Mirrors the proven filter +
/// size-byte reconstruction the archive poller uses to feed
/// `set_local_shard_sizes` (`bp = L2[32] ++ prefix-bytes`), so the filters
/// match what the rest of the system keys on.
///
/// Includes size-0 sub-shards (unlike the size-feeding path) so the
/// merge trigger can correctly count a parent's children and reject
/// partial-group (factor-4/8) merges.
pub fn build_shard_inventory(
    crdt: std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    shards_store: std::sync::Arc<dyn quil_types::store::ShardsStore>,
    prover_registry: &dyn ProverRegistry,
    frame_number: u64,
) -> Vec<ShardCoverageEntry> {
    let get_sizes = crate::shard_info::local_app_shard_get_sizes(crdt, shards_store.clone());
    let mut out: Vec<ShardCoverageEntry> = Vec::new();
    let Ok(shards) = shards_store.range_app_shards() else {
        return out;
    };
    // `range_app_shards` returns one row per sub-shard; `get_sizes` returns
    // every sub-shard under a shard_key, so dedupe to one call per key.
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for s in &shards {
        if !seen.insert(s.shard_key.clone()) {
            continue;
        }
        let Ok(sub_sizes) = get_sizes(&s.shard_key, s) else {
            continue;
        };
        for entry in sub_sizes {
            let mut bytes: u64 = 0;
            for &b in entry.size.iter() {
                bytes = bytes.saturating_mul(256).saturating_add(b as u64);
            }
            let l2 = if s.shard_key.len() >= 35 {
                &s.shard_key[3..35]
            } else if s.shard_key.len() > 3 {
                &s.shard_key[3..]
            } else {
                &s.shard_key[..]
            };
            // Canonical prefix → filter (sentinel-aware; see shard_prefix_to_filter).
            let filter = quil_forest::shard_prefix_to_filter(l2, &entry.prefix);
            let active = prover_registry
                .get_active_provers(&filter, frame_number)
                .map(|v| v.len() as u64)
                .unwrap_or(0);
            out.push(ShardCoverageEntry { filter, size: bytes, active_count: active });
        }
    }
    out
}

/// Maximum total size of the shard that results from a merge: 16 GiB. A
/// merge whose combined child size would exceed this is NOT proposed — the
/// resulting shard would be too large to replicate/attest efficiently.
///
/// This is a LEADER-side decision gate: the frame producer evaluates it
/// against its own (full-coverage) per-shard size view before proposing.
/// The `ShardMerge` op carries no size field, so peers validate it
/// structurally only — consistent with how split/merge proposals work
/// (no per-node size verify, which would fork under partial coverage).
pub const MERGE_MAX_SIZE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

impl CoverageMonitor {
    pub fn new(
        prover_registry: Arc<dyn ProverRegistry>,
        event_distributor: Arc<dyn EventDistributor>,
        thresholds: CoverageThresholds,
        prover_only_mode: Arc<AtomicBool>,
    ) -> Self {
        Self {
            prover_registry,
            event_distributor,
            thresholds,
            streaks: Arc::new(LowCoverageStreakTracker::new()),
            prover_only_mode,
            last_checked_frame: AtomicU64::new(0),
            emitted_halted: Mutex::new(std::collections::HashSet::new()),
            shard_inventory_provider: None,
            split_feasibility: std::sync::RwLock::new(None),
            split_proposer: std::sync::RwLock::new(None),
            unified_provider: std::sync::RwLock::new(None),
            last_rebalance_frame: Mutex::new(std::collections::HashMap::new()),
            pending_change_provider: std::sync::RwLock::new(None),
        }
    }

    /// Configured thresholds (halt threshold, min/max provers, grace frames).
    pub fn thresholds(&self) -> CoverageThresholds {
        self.thresholds
    }

    /// Install the §6.1 empty-split guard provider (see
    /// [`Self::split_feasibility`]). The node wires this to the unified app tree;
    /// without it, splits are proposed unconditionally (legacy). `&self` +
    /// interior mutability so it can be set through the `Arc` once the CRDT exists.
    pub fn set_split_feasibility_provider(&self, provider: SplitFeasibilityProvider) {
        *self.split_feasibility.write().unwrap() = Some(provider);
    }

    /// Install the deep-bifurcation split proposer (see [`Self::split_proposer`]).
    /// Wired by the node ONLY under the unified app tree; without it,
    /// `propose_split_rebalance` emits legacy immediate-bit byte-suffix children.
    pub fn set_split_proposer(&self, provider: SplitProposalProvider) {
        *self.split_proposer.write().unwrap() = Some(provider);
    }

    /// Install the pending-change provider (see [`Self::pending_change_provider`]).
    /// The node wires a closure over the shards store returning the set of parents
    /// with a staged `PendingShardChange`; the split/merge proposers skip those so
    /// a shard is proposed at most once until its change applies at E+2.
    pub fn set_pending_change_provider(&self, provider: PendingChangeProvider) {
        *self.pending_change_provider.write().unwrap() = Some(provider);
    }

    /// Install the unified-tree state provider (see [`Self::unified_provider`]).
    /// The node wires `move || crdt.unified_tree()`; `propose_merge_rebalance`
    /// calls it each frame to pick bit-path vs byte-suffix sibling identification.
    pub fn set_unified_provider(&self, provider: Arc<dyn Fn() -> bool + Send + Sync>) {
        *self.unified_provider.write().unwrap() = Some(provider);
    }

    /// Whether the unified app tree is active right now (deep-bifurcation mode).
    fn is_unified(&self) -> bool {
        self.unified_provider
            .read()
            .unwrap()
            .as_ref()
            .map(|p| p())
            .unwrap_or(false)
    }

    /// Install a [`ShardInventoryProvider`] so per-frame `check` sees
    /// the FULL shard universe — including shards with zero active
    /// provers but non-zero size (data landed via a transaction
    /// before any prover joined). Without a provider installed,
    /// `check` falls back to the prover registry's summary, which
    /// only sees shards already represented in `filter_cache` and
    /// can't observe the zero-coverage case.
    ///
    /// Non-archive nodes should wire this to a closure that reads
    /// `prover_lifecycle.merged_shard_sizes()` (archive-sourced
    /// shard sizes cached on a 60-frame cadence) joined with the
    /// registry's per-filter active counts. Archive nodes can wire
    /// a closure that pulls sizes directly from the local hypergraph
    /// CRDT and counts from the registry.
    pub fn set_shard_inventory_provider(&mut self, provider: ShardInventoryProvider) {
        self.shard_inventory_provider = Some(provider);
    }

    /// Seed the per-shard streak map from each prover's
    /// `last_active_frame_number`. Mirror of Go's `ensureStreakMap`.
    /// Should be called once at startup, before any frame-driven
    /// `check`/`check_shard_coverage` runs, so that an eviction pass on
    /// the first post-restart frame doesn't immediately kick provers
    /// that were already stale before the restart.
    pub fn reconstruct_streaks(&self, provers: &[ProverInfo], current_frame: u64) {
        self.streaks
            .reconstruct(provers, current_frame, self.thresholds.halt_threshold);
    }

    /// Run a coverage check for the given frame. Called by the event
    /// distributor when a new global head is finalized.
    ///
    /// Returns the per-shard halt durations for use by the eviction
    /// logic.
    pub fn check(&self, frame_number: u64) -> HashMap<Vec<u8>, u64> {
        let last = self.last_checked_frame.load(Ordering::Relaxed);
        if frame_number <= last {
            return HashMap::new();
        }
        self.last_checked_frame.store(frame_number, Ordering::Relaxed);

        // Get per-shard summaries from the prover registry.
        // Pass the current frame so expired Joining/Leaving allocs
        // are dropped from `status_counts` — without that, a shard
        // whose pending joiners all timed out still looks healthy.
        let summaries = self.prover_registry
            .get_prover_shard_summaries(frame_number)
            .unwrap_or_default();

        // Build the universe of shards to evaluate. Two sources:
        //
        // 1. The registry summary (always present). Sees only shards
        //    represented in `filter_cache` — i.e. shards with at
        //    least one allocation. Blind to zero-prover-but-data-
        //    present shards, which is the failure mode where a
        //    transaction creates a new vertex on a shard nobody has
        //    joined yet.
        //
        // 2. The inventory provider (optional). When set, returns
        //    the FULL shard universe with sizes — including shards
        //    nobody is on but where data has landed. Sourced by the
        //    caller from `lifecycle.merged_shard_sizes` (non-archive)
        //    or the local CRDT (archive). The provider's
        //    `active_count` may lag the registry summary by up to
        //    one archive-refresh interval (~60 frames), which is
        //    fine against the 1800-frame halt grace.
        //
        // When the provider is installed, we use it for the
        // detection sweep. When absent, we fall back to summaries
        // only (legacy behavior).
        let inventory: Vec<ShardCoverageEntry> = match &self.shard_inventory_provider {
            Some(provider) => provider(),
            None => summaries
                .iter()
                .map(|s| ShardCoverageEntry {
                    filter: s.filter.clone(),
                    // Size unknown from registry — pass `u64::MAX`
                    // so the size==0 skip below doesn't false-skip.
                    // This is the legacy behavior: every summary
                    // entry is evaluated for halt regardless of
                    // actual data size.
                    size: u64::MAX,
                    active_count: s.status_counts
                        .get(&ProverStatus::Active)
                        .copied()
                        .unwrap_or(0) as u64,
                })
                .collect(),
        };

        let mut any_halted = false;
        let mut currently_halted: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();

        for entry in &inventory {
            // Zero-size shards have no data to protect — no halt
            // needed even if zero provers are on them. Mirrors the
            // proposer's `if raw_size == 0 { continue }` gate.
            // Without this, every shard in the network with no
            // genesis allocation would bump a streak forever.
            if entry.size == 0 {
                if self.streaks.get(&entry.filter).is_some() {
                    // Recovery path: the shard had data before
                    // (which we were tracking) and now has none.
                    // Clear the streak so we don't carry it
                    // indefinitely.
                    self.streaks.clear(&entry.filter);
                }
                continue;
            }

            let active = entry.active_count;

            if active <= self.thresholds.halt_threshold {
                // Low coverage — bump streak
                let streak = self.streaks.bump(&entry.filter, frame_number);
                // Mainnet extended-enrollment window: before frame
                // 262_700 (FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END + 360),
                // grant an additional 720 grace frames before halting.
                let effective_grace = if frame_number
                    < EXTENDED_ENROLL_HALT_GRACE_END
                {
                    self.thresholds.halt_grace_frames + 720
                } else {
                    self.thresholds.halt_grace_frames
                };
                if streak.count >= effective_grace {
                    any_halted = true;
                    currently_halted.insert(entry.filter.clone());
                    tracing::debug!(
                        filter = hex::encode(&entry.filter),
                        active,
                        size = entry.size,
                        streak = streak.count,
                        "COVERAGE HALT — shard below threshold"
                    );
                }
            } else {
                // Recovered — clear streak
                if self.streaks.get(&entry.filter).is_some() {
                    tracing::info!(
                        filter = hex::encode(&entry.filter),
                        active,
                        "shard coverage recovered"
                    );
                    self.streaks.clear(&entry.filter);
                }
            }
        }

        // Emit edge-triggered CoverageHalt / CoverageResume events to the
        // distributor. The `halt_state` subscriber in the node binary
        // consumes these and broadcasts `set_halted(true|false)` to every
        // app shard engine. Without this emission, halts detected here
        // never propagate to workers and they keep producing frames.
        {
            let mut emitted = self.emitted_halted.lock().unwrap();
            // Newly-halted filters.
            for filter in &currently_halted {
                if !emitted.contains(filter) {
                    self.event_distributor.publish(ControlEvent {
                        event_type: ControlEventType::CoverageHalt,
                        data: ControlEventData::Coverage {
                            filter: filter.clone(),
                            duration: u64::MAX,
                        },
                    });
                    crate::metrics::inc_coverage_halts_entered();
                    emitted.insert(filter.clone());
                }
            }
            // Filters that were halted but no longer are.
            let cleared: Vec<Vec<u8>> = emitted
                .iter()
                .filter(|f| !currently_halted.contains(*f))
                .cloned()
                .collect();
            for filter in cleared {
                self.event_distributor.publish(ControlEvent {
                    event_type: ControlEventType::CoverageResume,
                    data: ControlEventData::Coverage {
                        filter: filter.clone(),
                        duration: 0,
                    },
                });
                crate::metrics::inc_coverage_resumes();
                emitted.remove(&filter);
            }
        }

        // Update prover-only mode
        let was_prover_only = self.prover_only_mode.load(Ordering::Relaxed);
        if any_halted && !was_prover_only {
            tracing::warn!("entering prover-only mode (degraded coverage)");
            self.prover_only_mode.store(true, Ordering::Relaxed);
        } else if !any_halted && was_prover_only {
            tracing::info!("exiting prover-only mode (coverage recovered)");
            self.prover_only_mode.store(false, Ordering::Relaxed);
        }

        compute_shard_halt_durations(&self.streaks, &summaries, &self.thresholds)
    }

    /// Get the current halt durations without running a check.
    /// `frame_number` is used to filter expired Joining/Leaving
    /// allocs from the per-shard counts — pass the latest received
    /// frame or `last_checked_frame` if you want point-in-time
    /// consistency with the last `check()` call.
    pub fn current_halt_durations(&self, frame_number: u64) -> HashMap<Vec<u8>, u64> {
        let summaries = self.prover_registry
            .get_prover_shard_summaries(frame_number)
            .unwrap_or_default();
        compute_shard_halt_durations(&self.streaks, &summaries, &self.thresholds)
    }

    /// Whether any shard is currently in a halt state.
    pub fn any_halted(&self) -> bool {
        self.prover_only_mode.load(Ordering::Relaxed)
    }

    /// Handle a verified `GlobalAlert`. This is a fire alarm — ALL
    /// consensus (global AND app-shard) must stop immediately. Sets
    /// prover-only mode and publishes a `Halt` event (NOT
    /// `CoverageHalt` — this is a hard stop, not a per-shard
    /// coverage issue) so every engine ceases producing frames.
    pub fn emit_alert(&self, message: &str) {
        self.prover_only_mode.store(true, Ordering::SeqCst);
        self.event_distributor.publish(ControlEvent {
            event_type: ControlEventType::Halt,
            data: ControlEventData::Alert {
                message: message.to_string(),
            },
        });
        tracing::error!(message, "GLOBAL ALERT — hard halt activated, all frame production stopped");
    }

    /// Check for shards that need splitting (too many provers) or
    /// merging (too few provers). Returns proposed actions.
    pub fn check_split_merge(&self, frame_number: u64) -> Vec<ShardAction> {
        let summaries = self.prover_registry
            .get_prover_shard_summaries(frame_number)
            .unwrap_or_default();

        let mut actions = Vec::new();

        for summary in &summaries {
            let active = summary.status_counts
                .get(&ProverStatus::Active)
                .copied()
                .unwrap_or(0) as u64;

            if active > self.thresholds.max_provers {
                actions.push(ShardAction::Split {
                    filter: summary.filter.clone(),
                    active_count: active,
                    frame_number,
                });
            } else if active < self.thresholds.min_provers && active > 0 {
                // Check if an adjacent shard also has low coverage
                // for a merge candidate. For now, just flag low coverage.
                actions.push(ShardAction::MergeCandidate {
                    filter: summary.filter.clone(),
                    active_count: active,
                    frame_number,
                });
            }
        }

        actions
    }

    /// Leader-gated per-frame rebalance trigger. The CALLER must gate on
    /// `local_prover == frame_producer` before calling (mirrors Go's
    /// `checkShardCoverage(frameNumber, frameProver)` — only the producer
    /// of the triggering frame emits, so we get exactly one proposer per
    /// frame instead of N duplicates).
    ///
    /// For every shard whose ACTIVE prover count exceeds `max_provers`,
    /// publishes a `ShardSplitEligible` event carrying the computed
    /// sub-shards. The already-wired shard-orchestrator loop
    /// (`master_node/mod.rs`) consumes the event and submits the
    /// `ShardSplit` op to the global mempool; it rides into a later frame,
    /// is finalized, and the materializer registers the sub-shards in the
    /// grid. Worker redistribution onto the new sub-shards is then
    /// emergent via the normal lifecycle (`decide_leaves` sheds the
    /// crowded parent, `decide_joins` fills the children) — matching Go,
    /// whose `ShardSplitOp.Materialize` is also grid-only.
    ///
    /// Auto-MERGE is intentionally NOT emitted here: the QUIL reshard
    /// deliberately widened coverage (4096→64) to escape an under-coverage
    /// halt, so auto-merging low shards would fight that and risk
    /// re-spiraling; merge is also the riskier inverse and rarely fires at
    /// the current thresholds. Split is wired now; merge can be enabled
    /// once split is validated in the field.
    pub fn propose_split_rebalance(&self, frame_number: u64) {
        let summaries = self
            .prover_registry
            .get_prover_shard_summaries(frame_number)
            .unwrap_or_default();
        let mut last = self.last_rebalance_frame.lock().unwrap();
        // Parents that already have a staged pending change (fetched ONCE). Skip
        // them: the pending split doesn't drop the parent's prover count until its
        // E+2 apply, so without this the shard is re-proposed every frame, and a
        // re-proposal crossing the epoch boundary stamps a conflicting later-epoch
        // change. Consulting committed pending state makes emission idempotent.
        let pending_parents = self
            .pending_change_provider
            .read()
            .unwrap()
            .clone()
            .map(|p| p())
            .unwrap_or_default();
        for summary in &summaries {
            let filter = &summary.filter;
            if filter.is_empty() {
                continue;
            }
            if pending_parents.contains(filter.as_slice()) {
                // Already staged for a topology change — don't re-propose.
                continue;
            }
            let active = summary
                .status_counts
                .get(&ProverStatus::Active)
                .copied()
                .unwrap_or(0) as u64;
            // Per-shard cooldown so we don't re-propose every frame while
            // the previous split works through consensus + materialize.
            if last
                .get(filter)
                .map_or(false, |&lf| frame_number < lf + REBALANCE_COOLDOWN_FRAMES)
            {
                continue;
            }
            // §6.1: a shard splits ONLY when BOTH hold — (1) it is OVER-CROWDED
            // (`active > max_provers`, the trigger), AND (2) its leaves CAN BE
            // DIVIDED FURTHER (≥2 non-empty children). Prover-count alone is not
            // enough: splitting a shard whose data can't divide (the skewed [7,0]
            // case) just makes an empty child and never reduces load. Divisibility
            // (2) is enforced below by the empty-split guard / the deep proposer
            // returning `None`, so it also BOUNDS the split depth to where the data
            // actually diverges → convergence even under surplus workers. The data
            // condition is "can it split", NOT "is it big" — there is no data-count
            // threshold.
            let provider = self.split_feasibility.read().unwrap().clone();
            if active <= self.thresholds.max_provers {
                continue; // (1) not over-crowded → no split
            }
            let factor = crate::shard_rebalancer::split_factor(active);
            // Per-child leaf counts for the divisibility / empty-split guard below.
            let counts = provider.as_ref().map(|p| p(filter, factor));
            tracing::debug!(
                filter = hex::encode(filter),
                active,
                factor,
                ?counts,
                "split-trigger check (over-crowded; divisibility guard next)",
            );
            // Deep-bifurcation (§6.1 encoding rework): under the unified app tree
            // the PROPOSER descends past any uniform bit run to the shallowest
            // REAL branch and emits variable-depth bit-path child FILTERS — so a
            // skewed shard (the localnet `[7,0]` case) splits at the branch where
            // the data actually diverges instead of cutting at the immediate bit
            // and orphaning a child. Its `None` IS the empty-split guard (no two
            // data-bearing halves / single leaf). Absent (legacy tree) ⇒ the
            // immediate-bit byte-suffix children + the counts-based guard below.
            let deep_proposer = self.split_proposer.read().unwrap().clone();
            let proposed = if let Some(propose) = deep_proposer.as_ref() {
                match propose(filter) {
                    Some(children) if children.len() >= 2 => children,
                    _ => {
                        tracing::debug!(
                            filter = hex::encode(filter),
                            "skipping split — no two data-bearing halves (deep-bifurcation guard)",
                        );
                        continue;
                    }
                }
            } else {
                let proposed = crate::shard_rebalancer::compute_proposed_shards(filter, factor);
                if proposed.len() < 2 {
                    continue;
                }
                // §6.1 EMPTY-SPLIT GUARD: only propose when the split actually
                // divides the data — ≥2 of the proposed children are data-bearing.
                // Skips the meaningless "one child gets everything, the sibling is
                // empty" split (which on the legacy tree also orphaned data). Only
                // active when the provider is wired; absent ⇒ propose unconditionally.
                if let Some(c) = counts.as_ref() {
                    if c.iter().filter(|&&x| x > 0).count() < 2 {
                        tracing::debug!(
                            filter = hex::encode(filter),
                            factor,
                            ?c,
                            "skipping split — data does not divide across children (empty-split guard)",
                        );
                        continue;
                    }
                }
                proposed
            };
            // Deep-bifurcation observability: log each proposed child filter so a
            // DEEP bit-path (app ‖ bit_len ‖ packed, depth > 1) is visible — proof
            // the proposer descended past uniform bits instead of cutting at the
            // immediate bit (which the legacy byte-suffix form could only ever do).
            let child_hex: Vec<String> = proposed.iter().map(hex::encode).collect();
            self.event_distributor.publish(ControlEvent {
                event_type: ControlEventType::ShardSplitEligible,
                data: ControlEventData::ShardSplit {
                    filter: filter.clone(),
                    proposed,
                },
            });
            last.insert(filter.clone(), frame_number);
            tracing::info!(
                filter = hex::encode(filter),
                active,
                factor,
                frame = frame_number,
                children = ?child_hex,
                "shard eligible for split — proposing"
            );
        }
    }

    /// Leader-gated per-frame MERGE rebalance trigger — the merge counterpart
    /// of [`Self::propose_split_rebalance`]. The CALLER must gate on
    /// `local_prover == frame_producer` before calling (exactly one proposer
    /// per frame, no duplicates).
    ///
    /// `inventory` is the universe of current sub-shards with per-filter
    /// `size` + `active_count` (assembled by the caller from the grid + the
    /// local per-shard sizes + registry counts). For each depth-1 factor-2
    /// sibling pair `{P‖0x00, P‖0x80}` (`P` = 32-byte parent) where BOTH
    /// halves are under-covered and the merge is safe, publishes a
    /// `ShardMergeEligible` event; the shard-orchestrator submits the
    /// `ShardMerge` op, which rides into a later frame and (epoch-aligned)
    /// flips at E+2.
    ///
    /// Three gates, all leader-side:
    /// - TRIGGER: each child's active count `< min_provers` (both starved →
    /// consolidation is warranted).
    /// - COVERAGE (decision #3): combined active `<= max_provers` — never
    /// merge into an over-crowded shard.
    /// - SIZE (decision #4, REQUIRED): combined size `<= MERGE_MAX_SIZE_BYTES`
    /// (16 GiB) — never merge into an over-large shard.
    ///
    /// v1 scope: only depth-1 factor-2 shards (33-byte filters, suffix
    /// `0x00`/`0x80`) collapsing to a 32-byte root — exactly what
    /// `materialize_shard_merge` supports (merge-to-root). Factor-4/8 and
    /// deeper groups are skipped: a partial-group merge would leave coverage
    /// holes, so a clean two-child `{0x00,0x80}` group is required.
    /// This shard's clean factor-2 merge group: `(parent_filter, low_child,
    /// high_child)`, or `None` when `f` isn't a mergeable factor-2 child (the
    /// root, wrong suffix, or the two clean siblings don't both exist in
    /// `by_filter`).
    ///
    /// - **Deep-bifurcation (unified):** `f` is a bit-path filter
    ///   (`app ‖ bit_len ‖ packed`). The parent is `bits` with the LAST bit
    ///   dropped; the siblings are `parent_bits‖0` / `parent_bits‖1` (re-encoded).
    ///   The parent filter is the BARE app address when `parent_bits` is empty
    ///   (merge-to-root), else the encoded parent — matching `verify_shard_merge` /
    ///   `materialize_shard_merge`'s `bit_path_mode`.
    /// - **Legacy (byte-suffix):** parent = drop the last BYTE; siblings
    ///   `parent‖0x00` / `parent‖0x80`; requires EXACTLY two children under the
    ///   parent (a `0x40`/`0xC0` ⇒ a factor-4/8 group we don't partial-merge).
    fn merge_sibling_group(
        &self,
        f: &[u8],
        by_filter: &std::collections::HashMap<&[u8], &ShardCoverageEntry>,
    ) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        if self.is_unified() {
            let (app, bits) = quil_forest::decode_shard_bit_path(f, 32)?;
            if bits.is_empty() {
                return None; // the root has no parent to merge into
            }
            // Merge the two immediate bit-siblings `B‖0`/`B‖1` back into the branch
            // `B` = drop-last-bit. Under Option A (prefix-free spine) `B` is a valid
            // leaf after merge — the retained spine keeps completeness around it —
            // and `materialize_shard_merge` re-registers `B`. (Bare app when the
            // branch is empty, i.e. a 1-bit split of the root.)
            let branch = &bits[..bits.len() - 1];
            let mut lo = branch.to_vec();
            lo.push(false);
            let mut hi = branch.to_vec();
            hi.push(true);
            let c0 = quil_forest::encode_shard_bit_path(&app, &lo);
            let c1 = quil_forest::encode_shard_bit_path(&app, &hi);
            if !by_filter.contains_key(c0.as_slice()) || !by_filter.contains_key(c1.as_slice()) {
                return None; // both clean siblings must exist
            }
            let parent = if branch.is_empty() {
                app // bare app = the root shard (empty bit-path)
            } else {
                quil_forest::encode_shard_bit_path(&app, branch)
            };
            Some((parent, c0, c1))
        } else {
            if f.len() < 33 || f.len() > 64 {
                return None;
            }
            let suffix = *f.last().unwrap();
            if suffix != 0x00 && suffix != 0x80 {
                return None;
            }
            let parent = f[..f.len() - 1].to_vec();
            let child_len = parent.len() + 1;
            let child_count = by_filter
                .keys()
                .filter(|k| k.len() == child_len && k.starts_with(parent.as_slice()))
                .count();
            if child_count != 2 {
                return None;
            }
            let mut c0 = parent.clone();
            c0.push(0x00);
            let mut c1 = parent.clone();
            c1.push(0x80);
            if !by_filter.contains_key(c0.as_slice()) || !by_filter.contains_key(c1.as_slice()) {
                return None;
            }
            Some((parent, c0, c1))
        }
    }

    pub fn propose_merge_rebalance(
        &self,
        frame_number: u64,
        inventory: &[ShardCoverageEntry],
    ) {
        use std::collections::{HashMap, HashSet};
        let by_filter: HashMap<&[u8], &ShardCoverageEntry> =
            inventory.iter().map(|e| (e.filter.as_slice(), e)).collect();
        let mut last = self.last_rebalance_frame.lock().unwrap();
        let mut emitted: HashSet<Vec<u8>> = HashSet::new();
        // Parents already staged for a topology change (fetched once) — skip, same
        // idempotency reason as `propose_split_rebalance`.
        let pending_parents = self
            .pending_change_provider
            .read()
            .unwrap()
            .clone()
            .map(|p| p())
            .unwrap_or_default();

        for entry in inventory {
            let f = &entry.filter;
            // Identify this shard's clean factor-2 merge group: the parent filter
            // and its two sibling children. Bit-path `parent = drop last BIT`
            // (unified) vs byte-suffix `drop last BYTE`, `{0x00,0x80}` (legacy).
            let Some((parent, c0, c1)) = self.merge_sibling_group(f, &by_filter) else {
                continue;
            };
            if emitted.contains(&parent) {
                continue;
            }
            if pending_parents.contains(parent.as_slice()) {
                continue;
            }
            let (Some(e0), Some(e1)) =
                (by_filter.get(c0.as_slice()), by_filter.get(c1.as_slice()))
            else {
                continue;
            };

            // Deep-bifurcation: two EMPTY siblings are latent prefix-free-spine
            // placeholders — leave them (don't churn a merge on shards with no data
            // to consolidate). Mirrors the halt-risk / split-proposer `size == 0`
            // exclusion: empty shards are not viable for proposal logic until data
            // lands. A pair with data on either side still merges under the gates.
            if e0.size == 0 && e1.size == 0 {
                continue;
            }
            // TRIGGER: both halves starved.
            if e0.active_count >= self.thresholds.min_provers
                || e1.active_count >= self.thresholds.min_provers
            {
                continue;
            }
            let combined_active = e0.active_count.saturating_add(e1.active_count);
            // COVERAGE gate (#3): never merge into an over-crowded shard.
            if combined_active > self.thresholds.max_provers {
                continue;
            }
            // SIZE gate (#4): never merge into an over-large shard.
            let combined_size = e0.size.saturating_add(e1.size);
            if combined_size > MERGE_MAX_SIZE_BYTES {
                tracing::info!(
                    parent = hex::encode(&parent),
                    combined_size,
                    "merge skipped — resulting shard would exceed the 16GiB gate"
                );
                continue;
            }
            // Per-shard cooldown.
            if last
                .get(&parent)
                .map_or(false, |&lf| frame_number < lf + REBALANCE_COOLDOWN_FRAMES)
            {
                continue;
            }

            self.event_distributor.publish(ControlEvent {
                event_type: ControlEventType::ShardMergeEligible,
                data: ControlEventData::ShardMerge {
                    filters: vec![c0.clone(), c1.clone()],
                    parent: parent.clone(),
                },
            });
            last.insert(c0, frame_number);
            last.insert(c1, frame_number);
            last.insert(parent.clone(), frame_number);
            emitted.insert(parent.clone());
            tracing::info!(
                parent = hex::encode(&parent),
                combined_active,
                combined_size,
                frame = frame_number,
                "shards eligible for merge — proposing"
            );
        }
    }

    /// Check coverage for a single shard and return the appropriate action.
    ///
    /// This is the per-shard decision function. It inspects the active
    /// prover count via the registry, updates the streak tracker, and
    /// returns a [`CoverageAction`] describing what (if anything) should
    /// happen.
    pub fn check_shard_coverage(
        &self,
        filter: &[u8],
        frame_number: u64,
    ) -> CoverageAction {
        let active = self
            .prover_registry
            .get_prover_count(filter)
            .unwrap_or(0);

        // --- Halt: critically low coverage ---
        // Network-aware: mainnet=3, testnet=0 or 1 depending on
        // `minimumProvers`.
        let halt_threshold = self.thresholds.halt_threshold as usize;
        if active <= halt_threshold {
            let streak = self.bump_streak(filter, frame_number);
            if streak.count >= STREAK_THRESHOLD {
                return CoverageAction::Halt {
                    filter: filter.to_vec(),
                    reason: format!(
                        "shard has {} active provers (<= halt threshold {}) \
                         for {} consecutive frames",
                        active, halt_threshold, streak.count,
                    ),
                };
            }
            return CoverageAction::NeedMoreProvers {
                filter: filter.to_vec(),
                current: active,
                needed: halt_threshold + 1,
            };
        }

        // Shard is above halt threshold — clear any outstanding streak.
        self.clear_streak(filter);

        // --- Split: too many provers ---
        if active > MAX_PROVERS_FOR_SPLIT {
            return CoverageAction::ShouldSplit {
                filter: filter.to_vec(),
                prover_count: active,
            };
        }

        // --- Merge: too few provers (but above halt) ---
        if active < MIN_PROVERS_FOR_MERGE {
            let sibling = compute_sibling_filter(filter).unwrap_or_default();
            return CoverageAction::ShouldMerge {
                filter: filter.to_vec(),
                sibling,
            };
        }

        CoverageAction::Ok
    }

    /// Convenience wrapper around `self.streaks.bump`.
    fn bump_streak(&self, filter: &[u8], frame: u64) -> CoverageStreak {
        self.streaks.bump(filter, frame)
    }

    /// Convenience wrapper around `self.streaks.clear`.
    fn clear_streak(&self, filter: &[u8]) {
        self.streaks.clear(filter);
    }

    /// Event-driven coverage check loop. Receives
    /// [`CoverageCheckRequest`]s from the frame materializer (or any
    /// other producer) and runs `check_shard_coverage` for every shard
    /// in the request. Emits [`ControlEvent`]s via the event
    /// distributor when coverage state changes.
    ///
    /// Runs until `cancel` is triggered or the `rx` channel closes.
    pub async fn run_coverage_loop(
        self,
        mut rx: mpsc::Receiver<CoverageCheckRequest>,
        cancel: CancellationToken,
    ) {
        tracing::info!("coverage monitor loop started");

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("coverage monitor loop shutting down");
                    break;
                }
                maybe_req = rx.recv() => {
                    let req = match maybe_req {
                        Some(r) => r,
                        None => {
                            tracing::info!(
                                "coverage check channel closed, exiting loop"
                            );
                            break;
                        }
                    };
                    self.handle_coverage_request(&req);
                }
            }
        }
    }

    /// Process a single [`CoverageCheckRequest`].
    fn handle_coverage_request(&self, req: &CoverageCheckRequest) {
        // Determine which filters to check: explicit list or all shards.
        let filters: Vec<Vec<u8>> = if req.filters.is_empty() {
            self.prover_registry
                .get_prover_shard_summaries(req.frame_number)
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.filter)
                .collect()
        } else {
            req.filters.clone()
        };

        let mut any_halted = false;

        for filter in &filters {
            let action = self.check_shard_coverage(filter, req.frame_number);

            match &action {
                CoverageAction::Ok => {}
                CoverageAction::NeedMoreProvers {
                    filter: f,
                    current,
                    needed,
                } => {
                    tracing::warn!(
                        filter = hex::encode(f),
                        current,
                        needed,
                        frame = req.frame_number,
                        "shard needs more provers"
                    );
                    self.event_distributor.publish(ControlEvent {
                        event_type: ControlEventType::CoverageWarn,
                        data: ControlEventData::Coverage {
                            filter: f.clone(),
                            duration: 0,
                        },
                    });
                }
                CoverageAction::Halt { filter: f, reason } => {
                    any_halted = true;
                    tracing::warn!(
                        filter = hex::encode(f),
                        reason,
                        frame = req.frame_number,
                        "COVERAGE HALT"
                    );
                    self.event_distributor.publish(ControlEvent {
                        event_type: ControlEventType::CoverageHalt,
                        data: ControlEventData::Coverage {
                            filter: f.clone(),
                            duration: u64::MAX,
                        },
                    });
                }
                CoverageAction::ShouldSplit {
                    filter: f,
                    prover_count,
                } => {
                    tracing::info!(
                        filter = hex::encode(f),
                        prover_count,
                        frame = req.frame_number,
                        "shard eligible for split"
                    );
                    self.event_distributor.publish(ControlEvent {
                        event_type: ControlEventType::ShardSplitEligible,
                        data: ControlEventData::ShardSplit {
                            filter: f.clone(),
                            proposed: vec![],
                        },
                    });
                }
                CoverageAction::ShouldMerge {
                    filter: f,
                    sibling,
                } => {
                    tracing::info!(
                        filter = hex::encode(f),
                        sibling = hex::encode(sibling),
                        frame = req.frame_number,
                        "shard eligible for merge"
                    );
                    self.event_distributor.publish(ControlEvent {
                        event_type: ControlEventType::ShardMergeEligible,
                        data: ControlEventData::ShardMerge {
                            filters: vec![f.clone(), sibling.clone()],
                            parent: compute_parent_filter(f),
                        },
                    });
                }
            }
        }

        // Update prover-only mode flag.
        let was_prover_only = self.prover_only_mode.load(Ordering::Relaxed);
        if any_halted && !was_prover_only {
            tracing::warn!("entering prover-only mode (degraded coverage)");
            self.prover_only_mode.store(true, Ordering::Relaxed);
        } else if !any_halted && was_prover_only {
            tracing::info!("exiting prover-only mode (coverage recovered)");
            self.prover_only_mode.store(false, Ordering::Relaxed);
            self.event_distributor.publish(ControlEvent {
                event_type: ControlEventType::CoverageResume,
                data: ControlEventData::None,
            });
        }
    }
}

/// Compute the sibling filter by flipping the last bit of the filter.
/// In the shard tree, two sibling shards differ only in the final bit
/// of their confirmation filter. Returns `None` when the filter is
/// empty (no sibling of an unsharded filter).
pub fn compute_sibling_filter(filter: &[u8]) -> Option<Vec<u8>> {
    if filter.is_empty() {
        return None;
    }
    let mut sibling = filter.to_vec();
    if let Some(last) = sibling.last_mut() {
        *last ^= 0x01;
    }
    Some(sibling)
}

/// Compute the parent filter by removing the last byte from the
/// filter. The parent shard's confirmation filter is one byte shorter.
fn compute_parent_filter(filter: &[u8]) -> Vec<u8> {
    if filter.len() > 1 {
        filter[..filter.len() - 1].to_vec()
    } else {
        vec![]
    }
}

/// Proposed shard management action from the coverage monitor.
#[derive(Debug, Clone)]
pub enum ShardAction {
    /// Shard has too many provers — propose a split.
    Split {
        filter: Vec<u8>,
        active_count: u64,
        frame_number: u64,
    },
    /// Shard has too few provers — candidate for merging with an
    /// adjacent shard.
    MergeCandidate {
        filter: Vec<u8>,
        active_count: u64,
        frame_number: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary_with_active(filter: &[u8], active: u32) -> ProverShardSummary {
        // A real, data-bearing shard (nonzero size) so the halt logic under
        // test actually applies; the zero-size guard is covered separately by
        // `zero_size_shard_below_threshold_is_not_halted`.
        summary_with_active_size(filter, active, 1000)
    }

    fn summary_with_active_size(filter: &[u8], active: u32, total_size: u64) -> ProverShardSummary {
        let mut status_counts = HashMap::new();
        status_counts.insert(ProverStatus::Active, active);
        ProverShardSummary {
            filter: filter.to_vec(),
            status_counts,
            total_size,
        }
    }

    #[test]
    fn zero_size_shard_below_threshold_is_not_halted() {
        // A zero-size shard (empty spine or STALE off-grid ancestor filter)
        // with a few stranded provers below the halt threshold must NOT get a
        // halt duration — only real data-bearing shards can halt. Regression
        // for the mass stale-filter halts that wedged `any_halted()` true.
        let t = LowCoverageStreakTracker::new();
        let thresholds = CoverageThresholds::mainnet(); // halt_threshold=3
        let summaries = vec![
            summary_with_active_size(b"stale-offgrid", 2, 0), // below threshold, NO data
            summary_with_active_size(b"real-data", 2, 5_000), // below threshold, HAS data
        ];
        let out = compute_shard_halt_durations(&t, &summaries, &thresholds);
        assert_eq!(out.get(&b"stale-offgrid".to_vec()), None, "zero-size shard must not halt");
        assert_eq!(out.get(&b"real-data".to_vec()), Some(&u64::MAX), "real shard still halts");
    }

    fn alloc(
        filter: &[u8],
        status: ProverStatus,
        last_active: u64,
    ) -> quil_types::consensus::ProverAllocationInfo {
        quil_types::consensus::ProverAllocationInfo {
            status,
            confirmation_filter: filter.to_vec(),
            rejection_filter: vec![],
            join_frame_number: 0,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: last_active,
            epoch: 0,
            ring: 0,
            vertex_address: vec![],
        }
    }

    fn prover_with(allocs: Vec<quil_types::consensus::ProverAllocationInfo>) -> ProverInfo {
        ProverInfo {
            public_key: vec![],
            address: vec![],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: allocs,
            available_storage: 0,
            seniority: 0,
            delegate_address: vec![],
        }
    }

    // =================================================================
    // CoverageStreak
    // =================================================================

    #[test]
    fn coverage_streak_new_starts_at_one() {
        let s = CoverageStreak::new(100);
        assert_eq!(s.start_frame, 100);
        assert_eq!(s.last_frame, 100);
        assert_eq!(s.count, 1);
    }

    // =================================================================
    // Thresholds
    // =================================================================

    #[test]
    fn mainnet_thresholds_match_go_defaults() {
        let t = CoverageThresholds::mainnet();
        assert_eq!(t.halt_threshold, 3);
        assert_eq!(t.min_provers, 6);
        assert_eq!(t.max_provers, 32);
        // 1800 = 2 × full migration cycle (720) + slack (360) —
        // covers a complete leave→confirm→join→confirm migration AND
        // a full back-to-back retry before a halt fires, so a single
        // dropped bundle on the first attempt doesn't halt a shard
        // that's actively being rescued.
        assert_eq!(t.halt_grace_frames, DEFAULT_HALT_GRACE_FRAMES);
        assert_eq!(t.halt_grace_frames, 1800);
    }

    /// Walks through the full lifecycle a prover takes to rescue a
    /// shard that has just gone uncovered (e.g. a transaction
    /// created a new vertex at an address that bloom-routes to a
    /// shard with zero active provers), and verifies the coverage
    /// monitor's grace window is wide enough for the rescue to
    /// complete before a CoverageHalt event fires.
    ///
    /// Timeline modeled (frame numbers relative to migration start):
    ///   T=0 shard X goes to active=0 (or stays at 0); coverage
    /// monitor begins bumping its streak each frame
    ///   T=0 prover lifecycle observes halt-risk + no free
    /// worker → `plan_leaves` bypass triggers ProposeLeave
    /// on a heavily-covered shard Y
    ///   T=CONFIRM DecideLeaves matures → ConfirmLeaves submitted →
    /// worker freed
    ///   T=CONFIRM+1 free worker observed → `plan_and_allocate` picks
    /// halt-risk shard X → ProposeJoin
    ///   T=2*CONFIRM DecideJoins matures → ConfirmJoins → alloc flips
    /// to Active → shard X now covered → streak clears
    ///
    /// Total cycle = 2 × CONFIRM_WINDOW = 720 frames. The grace must
    /// be wide enough to absorb BOTH a complete first-attempt
    /// migration AND a complete back-to-back retry if the first
    /// attempt's bundle was silently dropped — only then is a single
    /// transient archive hiccup recoverable without firing a halt
    /// event on a shard that's actively being rescued. Plus a
    /// confirm-window of slack for: lifecycle-evaluate cadence, the
    /// 4-frame join cooldown, archive registry-refresh skew, and the
    /// 10-frame ProposalTimeout detection window between attempts.
    #[test]
    fn halt_grace_covers_full_leave_confirm_join_confirm_cycle() {
        // Imported via path so this test stays a tripwire if
        // CONFIRM_WINDOW moves in the lifecycle crate.
        const CONFIRM_WINDOW: u64 =
            crate::provers::lifecycle::DEFAULT_CONFIRM_WINDOW_FRAMES;
        const MIGRATION_CYCLE_FRAMES: u64 = 2 * CONFIRM_WINDOW;
        // Headroom budget: a full second migration cycle (the retry)
        // plus one confirm window of slack for cadence/cooldown/sync
        // skew/ProposalTimeout detection.
        const RETRY_CYCLE_FRAMES: u64 = MIGRATION_CYCLE_FRAMES;
        const SLACK_HEADROOM: u64 = CONFIRM_WINDOW;

        // Static relationship: the grace must cover one full cycle
        // plus a full retry plus the slack budget. If either constant
        // drifts, this test fires before the coverage monitor starts
        // halting mid-rescue in production.
        assert!(
            DEFAULT_HALT_GRACE_FRAMES
                >= MIGRATION_CYCLE_FRAMES + RETRY_CYCLE_FRAMES + SLACK_HEADROOM,
            "halt grace ({}) must be ≥ first cycle ({}) + retry cycle ({}) + slack ({})",
            DEFAULT_HALT_GRACE_FRAMES,
            MIGRATION_CYCLE_FRAMES,
            RETRY_CYCLE_FRAMES,
            SLACK_HEADROOM,
        );

        // Simulate the per-frame bumping the coverage monitor would
        // do while the shard remains uncovered. The streak starts at
        // 1 on the first bump and increments by 1 per subsequent
        // frame.
        let tracker = LowCoverageStreakTracker::new();
        let shard_x = vec![0xAB; 32];
        let migration_start: u64 = 100_000;

        // Half-open range: bumping at frames 0..N produces a streak
        // count of N (1-indexed counter — the first bump establishes
        // count=1, each subsequent bump adds frame_delta=1). So a
        // 720-frame migration cycle = 720 bumps → streak count 720.
        for offset in 0..MIGRATION_CYCLE_FRAMES {
            let frame = migration_start + offset;
            let streak = tracker.bump(&shard_x, frame);
            assert!(
                streak.count < DEFAULT_HALT_GRACE_FRAMES,
                "streak {} reached halt grace {} at frame {} (offset {}) — \
                 coverage halt would fire mid-migration, before the join \
                 cycle could complete",
                streak.count, DEFAULT_HALT_GRACE_FRAMES, frame, offset,
            );
        }

        // Happy-path recovery check: at the end of the canonical
        // first cycle the streak still has enough headroom for a
        // full retry + slack. This is the property the 1800-frame
        // grace buys us — a dropped bundle on the first attempt
        // doesn't halt the shard.
        let final_streak = tracker
            .get(&shard_x)
            .expect("streak should still be tracked at migration end");
        let headroom = DEFAULT_HALT_GRACE_FRAMES - final_streak.count;
        assert!(
            headroom >= RETRY_CYCLE_FRAMES + SLACK_HEADROOM,
            "only {} frames of headroom after one migration cycle — too \
             tight to absorb a full retry ({} frames) + slack ({} frames) \
             if the first attempt's bundle gets dropped",
            headroom, RETRY_CYCLE_FRAMES, SLACK_HEADROOM,
        );

        // Continue simulating through the retry cycle. The streak
        // must still stay below the halt grace all the way through
        // the second attempt.
        for offset in MIGRATION_CYCLE_FRAMES
            ..(MIGRATION_CYCLE_FRAMES + RETRY_CYCLE_FRAMES)
        {
            let frame = migration_start + offset;
            let streak = tracker.bump(&shard_x, frame);
            assert!(
                streak.count < DEFAULT_HALT_GRACE_FRAMES,
                "streak {} reached halt grace {} during retry at frame {} \
                 (offset {}) — coverage halt would fire before the retry \
                 could complete",
                streak.count, DEFAULT_HALT_GRACE_FRAMES, frame, offset,
            );
        }

        // Recovery: prover join confirmed, active count rises above
        // halt_threshold, `CoverageMonitor::check` calls `clear` and
        // the streak goes away — no CoverageHalt event fires.
        tracker.clear(&shard_x);
        assert!(
            tracker.snapshot().is_empty(),
            "streak must clear once the shard recovers above halt_threshold",
        );
    }

    /// Stub registry that returns nothing — exercises the pure-
    /// inventory-provider code path. Coverage of all required
    /// `ProverRegistry` methods; behavior is "empty universe."
    struct EmptyRegistry;
    impl quil_types::consensus::ProverRegistry for EmptyRegistry {
        fn get_prover_info(
            &self,
            _: &[u8],
        ) -> quil_types::error::Result<
            Option<quil_types::consensus::ProverInfo>,
        > {
            Ok(None)
        }
        fn get_next_prover(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: u64,
        ) -> quil_types::error::Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn get_ordered_provers(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: u64,
        ) -> quil_types::error::Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }
        fn get_active_provers(
            &self,
            _: &[u8],
            _: u64,
        ) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn get_prover_count(&self, _: &[u8]) -> quil_types::error::Result<usize> {
            Ok(0)
        }
        fn get_provers(
            &self,
            _: &[u8],
        ) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn get_provers_by_status(
            &self,
            _: &[u8],
            _: quil_types::consensus::ProverStatus,
        ) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn get_prover_shard_summaries(
            &self,
            _: u64,
        ) -> quil_types::error::Result<Vec<quil_types::consensus::ProverShardSummary>> {
            Ok(Vec::new())
        }
    }

    /// Capturing distributor for test assertions. `subscribe` returns
    /// a Receiver from a fresh channel (sender dropped immediately,
    /// so recv yields None) — coverage monitor only uses `publish`
    /// in `check`.
    struct CapturingDistributor(
        std::sync::Mutex<Vec<quil_types::consensus::ControlEvent>>,
    );
    impl quil_types::consensus::EventDistributor for CapturingDistributor {
        fn subscribe(
            &self,
            _: &str,
        ) -> tokio::sync::mpsc::Receiver<quil_types::consensus::ControlEvent> {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            rx
        }
        fn publish(&self, event: quil_types::consensus::ControlEvent) {
            self.0.lock().unwrap().push(event);
        }
        fn unsubscribe(&self, _: &str) {}
    }

    fn build_monitor_with_inventory(
        provider: ShardInventoryProvider,
    ) -> (CoverageMonitor, Arc<CapturingDistributor>) {
        let registry: Arc<dyn quil_types::consensus::ProverRegistry> =
            Arc::new(EmptyRegistry);
        let dist =
            Arc::new(CapturingDistributor(std::sync::Mutex::new(Vec::new())));
        let dist_arc: Arc<dyn quil_types::consensus::EventDistributor> =
            dist.clone();
        let mut monitor = CoverageMonitor::new(
            registry,
            dist_arc,
            CoverageThresholds::mainnet(),
            Arc::new(AtomicBool::new(false)),
        );
        monitor.set_shard_inventory_provider(provider);
        (monitor, dist)
    }

    /// Stub registry exposing exactly one shard whose Active count we set,
    /// to drive `propose_split_rebalance`.
    struct HotShardRegistry {
        filter: Vec<u8>,
        active: u32,
    }
    impl quil_types::consensus::ProverRegistry for HotShardRegistry {
        fn get_prover_info(&self, _: &[u8]) -> quil_types::error::Result<Option<quil_types::consensus::ProverInfo>> { Ok(None) }
        fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> quil_types::error::Result<Vec<u8>> { Ok(Vec::new()) }
        fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8], _: u64) -> quil_types::error::Result<Vec<Vec<u8>>> { Ok(Vec::new()) }
        fn get_active_provers(&self, _: &[u8], _: u64) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> { Ok(Vec::new()) }
        fn get_prover_count(&self, _: &[u8]) -> quil_types::error::Result<usize> { Ok(0) }
        fn get_provers(&self, _: &[u8]) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> { Ok(Vec::new()) }
        fn get_provers_by_status(&self, _: &[u8], _: quil_types::consensus::ProverStatus) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> { Ok(Vec::new()) }
        fn get_prover_shard_summaries(&self, _: u64) -> quil_types::error::Result<Vec<quil_types::consensus::ProverShardSummary>> {
            let mut status_counts = std::collections::HashMap::new();
            status_counts.insert(quil_types::consensus::ProverStatus::Active, self.active);
            Ok(vec![quil_types::consensus::ProverShardSummary {
                filter: self.filter.clone(),
                status_counts,
                total_size: 0,
            }])
        }
    }

    #[test]
    fn propose_split_emits_above_threshold_then_cools_down() {
        // 33-byte depth-1 QUIL-style filter, 40 active provers (> mainnet max 32).
        let mut filter = vec![0x11u8; 32];
        filter.push(0x05);
        let registry: Arc<dyn quil_types::consensus::ProverRegistry> =
            Arc::new(HotShardRegistry { filter: filter.clone(), active: 40 });
        let dist = Arc::new(CapturingDistributor(std::sync::Mutex::new(Vec::new())));
        let dist_arc: Arc<dyn quil_types::consensus::EventDistributor> = dist.clone();
        let monitor = CoverageMonitor::new(
            registry,
            dist_arc,
            CoverageThresholds::mainnet(),
            Arc::new(AtomicBool::new(false)),
        );

        // First call: one ShardSplitEligible with valid child shards.
        monitor.propose_split_rebalance(1000);
        {
            let events = dist.0.lock().unwrap();
            assert_eq!(events.len(), 1, "expected one split event");
            assert!(matches!(
                events[0].event_type,
                quil_types::consensus::ControlEventType::ShardSplitEligible
            ));
            match &events[0].data {
                quil_types::consensus::ControlEventData::ShardSplit { filter: f, proposed } => {
                    assert_eq!(f, &filter);
                    assert!(proposed.len() >= 2, "must propose >= 2 children");
                    for child in proposed {
                        assert!(child.starts_with(&filter), "child must extend parent");
                        assert!(child.len() == filter.len() + 1 || child.len() == filter.len() + 2);
                    }
                }
                _ => panic!("wrong event data"),
            }
        }

        // Within cooldown: suppressed.
        monitor.propose_split_rebalance(1005);
        assert_eq!(dist.0.lock().unwrap().len(), 1, "cooldown must suppress re-emit");

        // After cooldown: emits again.
        monitor.propose_split_rebalance(1000 + REBALANCE_COOLDOWN_FRAMES + 1);
        assert_eq!(dist.0.lock().unwrap().len(), 2, "should re-emit after cooldown");
    }

    #[test]
    fn propose_split_suppressed_when_parent_already_has_a_pending_change() {
        // Over-crowded shard (40 > 32) — normally a proposal.
        let mut filter = vec![0x11u8; 32];
        filter.push(0x05);
        let registry: Arc<dyn quil_types::consensus::ProverRegistry> =
            Arc::new(HotShardRegistry { filter: filter.clone(), active: 40 });
        let dist = Arc::new(CapturingDistributor(std::sync::Mutex::new(Vec::new())));
        let dist_arc: Arc<dyn quil_types::consensus::EventDistributor> = dist.clone();
        let monitor = CoverageMonitor::new(
            registry,
            dist_arc,
            CoverageThresholds::mainnet(),
            Arc::new(AtomicBool::new(false)),
        );

        // A split is ALREADY staged for this parent (its pending change exists).
        let staged = filter.clone();
        monitor.set_pending_change_provider(Arc::new(move || {
            let mut s = std::collections::HashSet::new();
            s.insert(staged.clone());
            s
        }));

        // Idempotent emission: over threshold, but no new proposal while pending.
        monitor.propose_split_rebalance(1000);
        assert!(
            dist.0.lock().unwrap().is_empty(),
            "must NOT re-propose a split whose parent already has a pending change"
        );

        // Once the change is gone (applied at E+2), a still-crowded shard proposes.
        monitor.set_pending_change_provider(Arc::new(|| std::collections::HashSet::new()));
        monitor.propose_split_rebalance(2000);
        assert_eq!(
            dist.0.lock().unwrap().len(),
            1,
            "resumes proposing once no pending change is staged"
        );
    }

    /// §6.1 empty-split guard: a shard over the trigger is NOT split when the
    /// split would put all data on one child (the sibling empty); it IS split
    /// once the data divides across children.
    #[test]
    fn empty_split_guard_suppresses_one_sided_split() {
        let mut filter = vec![0x11u8; 32];
        filter.push(0x05);
        let registry: Arc<dyn quil_types::consensus::ProverRegistry> =
            Arc::new(HotShardRegistry { filter: filter.clone(), active: 40 });
        let dist = Arc::new(CapturingDistributor(std::sync::Mutex::new(Vec::new())));
        let dist_arc: Arc<dyn quil_types::consensus::EventDistributor> = dist.clone();
        let monitor = CoverageMonitor::new(
            registry,
            dist_arc,
            CoverageThresholds::mainnet(),
            Arc::new(AtomicBool::new(false)),
        );

        // One-sided: all data on child 0, sibling empty → guard suppresses.
        monitor.set_split_feasibility_provider(Arc::new(|_f: &[u8], factor: u8| {
            let mut v = vec![0u64; factor as usize];
            v[0] = 100;
            v
        }));
        monitor.propose_split_rebalance(1000);
        assert_eq!(
            dist.0.lock().unwrap().len(),
            0,
            "empty-split guard must suppress a one-sided split"
        );

        // Data divides across children → the split is proposed (no cooldown was
        // recorded, since the guard `continue`d before the cooldown insert).
        monitor.set_split_feasibility_provider(Arc::new(|_f: &[u8], factor: u8| {
            vec![50u64; factor as usize]
        }));
        monitor.propose_split_rebalance(2000);
        assert_eq!(
            dist.0.lock().unwrap().len(),
            1,
            "a data-dividing split IS proposed"
        );
    }

    /// §6.1 split fires ONLY when BOTH hold: (1) OVER-CROWDED (`active >
    /// max_provers`) AND (2) the leaves CAN DIVIDE (≥2 non-empty children). Not
    /// over-crowded ⇒ never splits (even if divisible); over-crowded but
    /// INDIVISIBLE (the skewed `[10,0]` case) ⇒ deferred by the empty-split guard.
    #[test]
    fn split_requires_both_overcrowded_and_divisible() {
        let filter = {
            let mut f = vec![0x11u8; 32];
            f.push(0x05);
            f
        };
        // (active provers, per-child leaf counts) → number of split events.
        let round = |active: u32, counts: Vec<u64>| -> usize {
            let registry: Arc<dyn quil_types::consensus::ProverRegistry> =
                Arc::new(HotShardRegistry { filter: filter.clone(), active });
            let dist = Arc::new(CapturingDistributor(std::sync::Mutex::new(Vec::new())));
            let dist_arc: Arc<dyn quil_types::consensus::EventDistributor> = dist.clone();
            let monitor = CoverageMonitor::new(
                registry,
                dist_arc,
                CoverageThresholds::mainnet(), // max_provers = 32
                Arc::new(AtomicBool::new(false)),
            );
            monitor.set_split_feasibility_provider(Arc::new(move |_f: &[u8], factor: u8| {
                let mut v = counts.clone();
                v.resize(factor as usize, 0); // pad/truncate to the split factor
                v
            }));
            monitor.propose_split_rebalance(1000);
            let n = dist.0.lock().unwrap().len();
            n
        };

        // (1) NOT over-crowded (20 ≤ 32), even though divisible → NO split.
        assert_eq!(round(20, vec![5, 5]), 0, "not over-crowded → no split even if divisible");
        // (2) Over-crowded (40 > 32) but INDIVISIBLE (all data on one side) → NO
        // split (the divisibility precondition fails; the guard defers).
        assert_eq!(round(40, vec![10, 0]), 0, "over-crowded but indivisible → deferred");
        // BOTH: over-crowded AND divisible → split.
        assert_eq!(round(40, vec![5, 5]), 1, "over-crowded AND divisible → split");
    }

    /// Deep-bifurcation (§6.1 encoding rework): when a `split_proposer` is wired
    /// (unified app tree) the proposal emits ITS variable-depth bit-path children
    /// verbatim — NOT `compute_proposed_shards`' immediate-bit byte-suffix ones —
    /// and the proposer's `None` supersedes the counts guard (suppresses).
    #[test]
    fn deep_bifurcation_proposer_children_and_none_guard() {
        use quil_types::consensus::ControlEventData;
        let mut filter = vec![0x11u8; 32];
        filter.push(0x05);
        let registry: Arc<dyn quil_types::consensus::ProverRegistry> =
            Arc::new(HotShardRegistry { filter: filter.clone(), active: 40 });
        let dist = Arc::new(CapturingDistributor(std::sync::Mutex::new(Vec::new())));
        let dist_arc: Arc<dyn quil_types::consensus::EventDistributor> = dist.clone();
        // Prover-count trigger (active 40 > mainnet max 32); no data trigger.
        let monitor = CoverageMonitor::new(
            registry,
            dist_arc,
            CoverageThresholds::mainnet(),
            Arc::new(AtomicBool::new(false)),
        );

        // Proposer returns two DEEP bit-path child filters (a byte-suffix cut
        // could never produce a 40- and 41-byte pair) → emitted verbatim.
        let c0 = vec![0xAAu8; 40];
        let c1 = vec![0xBBu8; 41];
        let (p0, p1) = (c0.clone(), c1.clone());
        monitor.set_split_proposer(Arc::new(move |_f: &[u8]| Some(vec![p0.clone(), p1.clone()])));
        monitor.propose_split_rebalance(1000);
        {
            let events = dist.0.lock().unwrap();
            assert_eq!(events.len(), 1, "proposer path emits the split");
            match &events[0].data {
                ControlEventData::ShardSplit { proposed, .. } => {
                    assert_eq!(
                        proposed,
                        &vec![c0.clone(), c1.clone()],
                        "emitted children are the proposer's bit-path filters, not byte-suffix",
                    );
                }
                _ => panic!("wrong event data"),
            }
        }

        // A fresh over-threshold shard whose proposer returns None (no two
        // data-bearing halves) → the split is suppressed by the guard.
        let mut filter2 = vec![0x22u8; 32];
        filter2.push(0x07);
        let registry2: Arc<dyn quil_types::consensus::ProverRegistry> =
            Arc::new(HotShardRegistry { filter: filter2.clone(), active: 40 });
        let dist2 = Arc::new(CapturingDistributor(std::sync::Mutex::new(Vec::new())));
        let dist2_arc: Arc<dyn quil_types::consensus::EventDistributor> = dist2.clone();
        let monitor2 = CoverageMonitor::new(
            registry2,
            dist2_arc,
            CoverageThresholds::mainnet(),
            Arc::new(AtomicBool::new(false)),
        );
        monitor2.set_split_proposer(Arc::new(|_f: &[u8]| None));
        monitor2.propose_split_rebalance(1000);
        assert_eq!(
            dist2.0.lock().unwrap().len(),
            0,
            "proposer None → deep-bifurcation guard suppresses the split",
        );
    }

    /// Verifies the inventory-provider path actually catches the
    /// "zero provers, non-zero size" case the registry-summary path
    /// misses. With registry summary empty, the only way the
    /// monitor sees this shard is via the inventory provider.
    #[test]
    fn inventory_provider_surfaces_zero_prover_data_shard() {
        let target_filter: Vec<u8> = vec![0xAB; 32];
        let target_for_provider = target_filter.clone();
        let provider: ShardInventoryProvider = Arc::new(move || {
            vec![ShardCoverageEntry {
                filter: target_for_provider.clone(),
                size: 1024, // 1 KB of data on this shard
                active_count: 0,
            }]
        });
        let (monitor, dist) = build_monitor_with_inventory(provider);

        // Bump for every frame in the grace window plus one. The
        // halt fires on the boundary frame.
        let start: u64 = 1_000_000;
        for offset in 0..=DEFAULT_HALT_GRACE_FRAMES {
            monitor.check(start + offset);
        }

        let events = dist.0.lock().unwrap();
        let target_halt = events.iter().any(|e| {
            matches!(
                (&e.event_type, &e.data),
                (
                    quil_types::consensus::ControlEventType::CoverageHalt,
                    quil_types::consensus::ControlEventData::Coverage { filter, .. }
                ) if filter == &target_filter
            )
        });
        assert!(target_halt, "no CoverageHalt fired for the zero-prover non-zero-size shard");
    }

    /// Symmetric to the above: a zero-size shard MUST NOT trigger a
    /// halt even if the provider reports `active_count = 0`. The
    /// "no data to protect" rule means we skip it entirely.
    #[test]
    fn inventory_provider_skips_zero_size_shards() {
        let target_filter: Vec<u8> = vec![0xCD; 32];
        let target_for_provider = target_filter.clone();
        let provider: ShardInventoryProvider = Arc::new(move || {
            vec![ShardCoverageEntry {
                filter: target_for_provider.clone(),
                size: 0, // no data — must skip
                active_count: 0,
            }]
        });
        let (monitor, dist) = build_monitor_with_inventory(provider);

        for offset in 0..=DEFAULT_HALT_GRACE_FRAMES {
            monitor.check(1_000_000 + offset);
        }
        let events = dist.0.lock().unwrap();
        let halts: usize = events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    quil_types::consensus::ControlEventType::CoverageHalt
                )
            })
            .count();
        assert_eq!(
            halts, 0,
            "expected zero CoverageHalt events for size-0 shard, got {}",
            halts,
        );
    }

    // =================================================================
    // Merge rebalance trigger + 16GiB gate (decision #4) + coverage gate (#3)
    // =================================================================

    /// Build a monitor with an empty registry + capturing distributor.
    /// `propose_merge_rebalance` takes its inventory as a parameter, so no
    /// inventory provider is needed.
    fn build_merge_monitor() -> (CoverageMonitor, Arc<CapturingDistributor>) {
        build_monitor_with_inventory(Arc::new(Vec::new))
    }

    fn entry(filter: Vec<u8>, size: u64, active: u64) -> ShardCoverageEntry {
        ShardCoverageEntry { filter, size, active_count: active }
    }

    fn child(parent: &[u8], suffix: u8) -> Vec<u8> {
        let mut c = parent.to_vec();
        c.push(suffix);
        c
    }

    fn merge_events(dist: &Arc<CapturingDistributor>) -> Vec<(Vec<Vec<u8>>, Vec<u8>)> {
        dist.0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match (&e.event_type, &e.data) {
                (
                    quil_types::consensus::ControlEventType::ShardMergeEligible,
                    quil_types::consensus::ControlEventData::ShardMerge { filters, parent },
                ) => Some((filters.clone(), parent.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn merge_emitted_for_starved_factor2_pair_under_gates() {
        let parent = vec![0xAAu8; 32];
        let inv = vec![
            entry(child(&parent, 0x00), 1 << 30, 2), // 1 GiB, 2 active
            entry(child(&parent, 0x80), 1 << 30, 3), // 1 GiB, 3 active
        ];
        let (monitor, dist) = build_merge_monitor();
        monitor.propose_merge_rebalance(100, &inv);

        let events = merge_events(&dist);
        assert_eq!(events.len(), 1, "exactly one merge proposed");
        let (filters, p) = &events[0];
        assert_eq!(p, &parent);
        assert_eq!(filters, &vec![child(&parent, 0x00), child(&parent, 0x80)]);
    }

    #[test]
    fn merge_emitted_for_deeper_quil_topology_pair() {
        // Genesis QUIL shards are 33-byte filters; their split children are
        // 34-byte and must merge back to the 33-byte parent (not just a
        // 32-byte root). This is the case that actually fires on mainnet.
        let mut parent = vec![0xAAu8; 32];
        parent.push(0x05); // 33-byte parent
        let inv = vec![
            entry(child(&parent, 0x00), 1 << 30, 2),
            entry(child(&parent, 0x80), 1 << 30, 3),
        ];
        let (monitor, dist) = build_merge_monitor();
        monitor.propose_merge_rebalance(100, &inv);

        let events = merge_events(&dist);
        assert_eq!(events.len(), 1, "deeper QUIL-topology merge must fire");
        let (filters, p) = &events[0];
        assert_eq!(p, &parent, "33-byte parent");
        assert_eq!(filters, &vec![child(&parent, 0x00), child(&parent, 0x80)]);
    }

    /// Deep-bifurcation merge proposer: under the unified provider, siblings are
    /// bit-path FILTERS and the parent is the BRANCH (drop the last bit) — under
    /// Option A the branch is a valid leaf after merge (the retained prefix-free
    /// spine keeps completeness around it) and `materialize_shard_merge` re-registers
    /// it. Two EMPTY siblings are latent spine placeholders → no merge; a lone
    /// sibling → no merge (both required).
    #[test]
    fn merge_bit_path_siblings_propose_parent_with_last_bit_dropped() {
        use quil_forest::encode_shard_bit_path;
        let app = [0xAAu8; 32];

        // Deep pair [0,0,0,0]/[0,0,0,1] → the branch [0,0,0] (drop last bit).
        let (monitor, dist) = build_merge_monitor();
        monitor.set_unified_provider(Arc::new(|| true));
        let c0 = encode_shard_bit_path(&app, &[false, false, false, false]);
        let c1 = encode_shard_bit_path(&app, &[false, false, false, true]);
        let inv = vec![entry(c0.clone(), 1 << 30, 2), entry(c1.clone(), 1 << 30, 3)];
        monitor.propose_merge_rebalance(100, &inv);
        let events = merge_events(&dist);
        assert_eq!(events.len(), 1, "deep bit-path merge fires");
        let (filters, parent) = &events[0];
        assert_eq!(parent, &encode_shard_bit_path(&app, &[false, false, false]), "parent = branch (drop last bit)");
        assert_eq!(filters, &vec![c0, c1]);

        // Two EMPTY siblings (size 0) are latent spine placeholders → NOT merged.
        let (monitor_e, dist_e) = build_merge_monitor();
        monitor_e.set_unified_provider(Arc::new(|| true));
        let e0 = encode_shard_bit_path(&app, &[false, false, false, false]);
        let e1 = encode_shard_bit_path(&app, &[false, false, false, true]);
        monitor_e.propose_merge_rebalance(100, &[entry(e0, 0, 0), entry(e1, 0, 0)]);
        assert_eq!(merge_events(&dist_e).len(), 0, "two empty siblings are not merged");

        // Merge-to-root: [0]/[1] → parent = the BARE app address (root shard).
        let (monitor2, dist2) = build_merge_monitor();
        monitor2.set_unified_provider(Arc::new(|| true));
        let r0 = encode_shard_bit_path(&app, &[false]);
        let r1 = encode_shard_bit_path(&app, &[true]);
        let inv2 = vec![entry(r0.clone(), 1 << 30, 2), entry(r1.clone(), 1 << 30, 3)];
        monitor2.propose_merge_rebalance(100, &inv2);
        let ev2 = merge_events(&dist2);
        assert_eq!(ev2.len(), 1, "merge-to-root fires");
        assert_eq!(ev2[0].1, app.to_vec(), "parent = bare app root");
        assert_eq!(ev2[0].0, vec![r0, r1]);

        // A lone deep sibling (no partner in the inventory) → no merge.
        let (monitor3, dist3) = build_merge_monitor();
        monitor3.set_unified_provider(Arc::new(|| true));
        let lone = encode_shard_bit_path(&app, &[false, false, false, false]);
        monitor3.propose_merge_rebalance(100, &[entry(lone, 1 << 30, 2)]);
        assert_eq!(merge_events(&dist3).len(), 0, "lone sibling does not merge");
    }

    #[test]
    fn merge_skipped_when_combined_size_exceeds_16gib() {
        let parent = vec![0xBBu8; 32];
        // 9 GiB + 9 GiB = 18 GiB > 16 GiB gate.
        let nine_gib = 9u64 * (1 << 30);
        let inv = vec![
            entry(child(&parent, 0x00), nine_gib, 1),
            entry(child(&parent, 0x80), nine_gib, 1),
        ];
        let (monitor, dist) = build_merge_monitor();
        monitor.propose_merge_rebalance(100, &inv);
        assert!(merge_events(&dist).is_empty(), "16GiB gate must block the merge");
    }

    #[test]
    fn merge_emitted_right_at_16gib_boundary() {
        let parent = vec![0xB1u8; 32];
        let half = MERGE_MAX_SIZE_BYTES / 2; // exactly 16 GiB combined
        let inv = vec![
            entry(child(&parent, 0x00), half, 1),
            entry(child(&parent, 0x80), half, 1),
        ];
        let (monitor, dist) = build_merge_monitor();
        monitor.propose_merge_rebalance(100, &inv);
        assert_eq!(merge_events(&dist).len(), 1, "exactly-16GiB merge is allowed");
    }

    #[test]
    fn merge_skipped_when_either_child_is_healthy() {
        let parent = vec![0xCCu8; 32];
        // c1 has 6 active == min_provers ⇒ not starved.
        let inv = vec![
            entry(child(&parent, 0x00), 1 << 20, 2),
            entry(child(&parent, 0x80), 1 << 20, 6),
        ];
        let (monitor, dist) = build_merge_monitor();
        monitor.propose_merge_rebalance(100, &inv);
        assert!(merge_events(&dist).is_empty(), "a healthy half must block the merge");
    }

    #[test]
    fn merge_skipped_for_factor4_group() {
        // Four children under P ⇒ factor-4 split, not a clean {0x00,0x80} pair.
        let parent = vec![0xDDu8; 32];
        let inv = vec![
            entry(child(&parent, 0x00), 1 << 20, 1),
            entry(child(&parent, 0x40), 1 << 20, 1),
            entry(child(&parent, 0x80), 1 << 20, 1),
            entry(child(&parent, 0xC0), 1 << 20, 1),
        ];
        let (monitor, dist) = build_merge_monitor();
        monitor.propose_merge_rebalance(100, &inv);
        assert!(merge_events(&dist).is_empty(), "factor-4 group must not partial-merge");
    }

    #[test]
    fn merge_cooldown_prevents_immediate_reproposal() {
        let parent = vec![0xEEu8; 32];
        let inv = vec![
            entry(child(&parent, 0x00), 1 << 20, 1),
            entry(child(&parent, 0x80), 1 << 20, 1),
        ];
        let (monitor, dist) = build_merge_monitor();
        monitor.propose_merge_rebalance(100, &inv);
        monitor.propose_merge_rebalance(100 + 5, &inv); // within cooldown window
        assert_eq!(merge_events(&dist).len(), 1, "cooldown blocks the second proposal");
        monitor.propose_merge_rebalance(100 + REBALANCE_COOLDOWN_FRAMES, &inv);
        assert_eq!(merge_events(&dist).len(), 2, "proposal allowed after cooldown");
    }

    #[test]
    fn testnet_thresholds_scale_with_min_provers() {
        // min_provers=1 → halt_threshold=0 (never halt)
        let t1 = CoverageThresholds::testnet(1);
        assert_eq!(t1.halt_threshold, 0);
        assert_eq!(t1.min_provers, 1);
        // min_provers>1 → halt_threshold=1
        let t2 = CoverageThresholds::testnet(4);
        assert_eq!(t2.halt_threshold, 1);
        assert_eq!(t2.min_provers, 4);
    }

    // =================================================================
    // Streak tracker
    // =================================================================

    #[test]
    fn bump_creates_fresh_streak_for_unknown_shard() {
        let t = LowCoverageStreakTracker::new();
        let s = t.bump(b"shard-a", 100);
        assert_eq!(s, CoverageStreak::new(100));
    }

    #[test]
    fn bump_increments_count_by_frame_delta() {
        let t = LowCoverageStreakTracker::new();
        t.bump(b"shard-a", 100); // count=1
        let s = t.bump(b"shard-a", 102); // count += 102-100 = 3
        assert_eq!(s.count, 3);
        assert_eq!(s.last_frame, 102);
        assert_eq!(s.start_frame, 100);
    }

    #[test]
    fn bump_same_frame_is_noop() {
        // Single-slot fork choice can produce multiple candidates at
        // the same frame; bump must not double-count.
        let t = LowCoverageStreakTracker::new();
        t.bump(b"shard-a", 100);
        let s1 = t.bump(b"shard-a", 100);
        let s2 = t.bump(b"shard-a", 100);
        assert_eq!(s1.count, 1);
        assert_eq!(s2.count, 1);
    }

    #[test]
    fn bump_earlier_frame_is_noop() {
        // Out-of-order frame arrivals must not decrement or rewrite.
        let t = LowCoverageStreakTracker::new();
        t.bump(b"shard-a", 100);
        t.bump(b"shard-a", 105);
        let s = t.bump(b"shard-a", 102); // earlier than last_frame
        assert_eq!(s.count, 6); // 1 + (105 - 100)
        assert_eq!(s.last_frame, 105);
    }

    #[test]
    fn clear_removes_streak() {
        let t = LowCoverageStreakTracker::new();
        t.bump(b"shard-a", 100);
        assert!(t.get(b"shard-a").is_some());
        t.clear(b"shard-a");
        assert!(t.get(b"shard-a").is_none());
    }

    #[test]
    fn clear_unknown_shard_is_noop() {
        let t = LowCoverageStreakTracker::new();
        t.clear(b"unknown"); // no panic
        assert!(t.is_empty());
    }

    #[test]
    fn reconstruct_seeds_streak_for_halted_shard() {
        // Shard with only 2 active provers (below halt_threshold=3) → seeded.
        let t = LowCoverageStreakTracker::new();
        let p1 = prover_with(vec![alloc(b"shard-a", ProverStatus::Active, 90)]);
        let p2 = prover_with(vec![alloc(b"shard-a", ProverStatus::Active, 95)]);
        t.reconstruct(&[p1, p2], 100, 3);
        let s = t.get(b"shard-a").expect("streak present");
        // staleness = 100 - 95 (max last_active) = 5
        assert_eq!(s.count, 5);
        assert_eq!(s.last_frame, 100);
    }

    #[test]
    fn reconstruct_seeds_streak_for_recovered_but_stale_shard() {
        // Shard recovered (4 active > halt_threshold=3) but max
        // last_active is far in the past (staleness > 1) → seeded.
        let t = LowCoverageStreakTracker::new();
        let provers: Vec<ProverInfo> = (0..4)
            .map(|i| {
                prover_with(vec![alloc(b"shard-r", ProverStatus::Active, 50 + i as u64)])
            })
            .collect();
        t.reconstruct(&provers, 200, 3);
        let s = t.get(b"shard-r").expect("streak present");
        // staleness = 200 - 53 = 147
        assert_eq!(s.count, 147);
    }

    #[test]
    fn reconstruct_no_seed_when_recovered_and_fresh() {
        // Shard recovered AND fresh (staleness <= 1) → no streak entry.
        let t = LowCoverageStreakTracker::new();
        let provers: Vec<ProverInfo> = (0..4)
            .map(|_| prover_with(vec![alloc(b"shard-ok", ProverStatus::Active, 100)]))
            .collect();
        t.reconstruct(&provers, 100, 3);
        assert!(t.get(b"shard-ok").is_none());
    }

    #[test]
    fn reconstruct_uses_max_last_active_per_shard() {
        // Two provers on same shard with different last_active. Streak
        // staleness should use the *latest* last_active.
        let t = LowCoverageStreakTracker::new();
        let p1 = prover_with(vec![alloc(b"shard-x", ProverStatus::Active, 30)]);
        let p2 = prover_with(vec![alloc(b"shard-x", ProverStatus::Active, 80)]);
        t.reconstruct(&[p1, p2], 100, 3);
        let s = t.get(b"shard-x").expect("streak present");
        // Below halt_threshold (2 active <= 3): staleness = 100 - 80 = 20
        assert_eq!(s.count, 20);
    }

    #[test]
    fn reconstruct_ignores_non_active_allocations_for_count() {
        // Joining/leaving allocations don't contribute to active
        // coverage but still contribute their last_active when a
        // record exists. Halt status driven by Active count only.
        let t = LowCoverageStreakTracker::new();
        let p_active1 = prover_with(vec![alloc(b"shard-y", ProverStatus::Active, 90)]);
        let p_active2 = prover_with(vec![alloc(b"shard-y", ProverStatus::Active, 91)]);
        let p_active3 = prover_with(vec![alloc(b"shard-y", ProverStatus::Active, 92)]);
        let p_active4 = prover_with(vec![alloc(b"shard-y", ProverStatus::Active, 93)]);
        let p_joining = prover_with(vec![alloc(b"shard-y", ProverStatus::Joining, 95)]);
        // 4 active → above halt_threshold=3, staleness = 100 - 93 = 7 → seed.
        t.reconstruct(
            &[p_active1, p_active2, p_active3, p_active4, p_joining],
            100,
            3,
        );
        let s = t.get(b"shard-y").expect("streak present");
        assert_eq!(s.count, 7);
    }

    #[test]
    fn tracker_is_per_shard_isolated() {
        let t = LowCoverageStreakTracker::new();
        t.bump(b"shard-a", 100);
        t.bump(b"shard-b", 200);
        assert_eq!(t.len(), 2);
        t.clear(b"shard-a");
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(b"shard-b").unwrap().start_frame, 200);
    }

    // =================================================================
    // compute_shard_halt_durations
    // =================================================================

    #[test]
    fn compute_halt_durations_empty_inputs_returns_empty() {
        let t = LowCoverageStreakTracker::new();
        let thresholds = CoverageThresholds::mainnet();
        let out = compute_shard_halt_durations(&t, &[], &thresholds);
        assert!(out.is_empty());
    }

    #[test]
    fn compute_halt_durations_active_below_threshold_is_max_u64() {
        let t = LowCoverageStreakTracker::new();
        let thresholds = CoverageThresholds::mainnet(); // halt_threshold=3
        let summaries = vec![
            summary_with_active(b"shard-a", 2), // below threshold
            summary_with_active(b"shard-b", 10), // above threshold
        ];
        let out = compute_shard_halt_durations(&t, &summaries, &thresholds);
        assert_eq!(out.get(&b"shard-a".to_vec()), Some(&u64::MAX));
        assert_eq!(out.get(&b"shard-b".to_vec()), None);
    }

    #[test]
    fn compute_halt_durations_exactly_at_threshold_is_halted() {
        // `active_count <= halt_threshold` should halt at equality too.
        let t = LowCoverageStreakTracker::new();
        let thresholds = CoverageThresholds::mainnet(); // halt_threshold=3
        let summaries = vec![summary_with_active(b"shard-a", 3)];
        let out = compute_shard_halt_durations(&t, &summaries, &thresholds);
        assert_eq!(out.get(&b"shard-a".to_vec()), Some(&u64::MAX));
    }

    #[test]
    fn compute_halt_durations_streak_without_active_halt_uses_count() {
        // A shard that was low-coverage earlier but has recovered:
        // above halt_threshold now, but streak still has count.
        // Expected: halt duration = streak count.
        let t = LowCoverageStreakTracker::new();
        t.bump(b"shard-a", 100);
        t.bump(b"shard-a", 110); // count = 11
        let thresholds = CoverageThresholds::mainnet();
        let summaries = vec![summary_with_active(b"shard-a", 10)]; // recovered
        let out = compute_shard_halt_durations(&t, &summaries, &thresholds);
        assert_eq!(out.get(&b"shard-a".to_vec()), Some(&11));
    }

    #[test]
    fn compute_halt_durations_current_halt_overrides_streak() {
        // Shard has a streak AND is currently at/below halt threshold.
        // The `u64::MAX` entry must override the streak-derived value.
        let t = LowCoverageStreakTracker::new();
        t.bump(b"shard-a", 100);
        t.bump(b"shard-a", 110);
        let thresholds = CoverageThresholds::mainnet();
        let summaries = vec![summary_with_active(b"shard-a", 2)]; // still halted
        let out = compute_shard_halt_durations(&t, &summaries, &thresholds);
        assert_eq!(out.get(&b"shard-a".to_vec()), Some(&u64::MAX));
    }

    #[test]
    fn compute_halt_durations_missing_from_summary_uses_streak() {
        // Streak exists but no summary entry for the shard. We fall
        // back to the streak count (no halt override).
        let t = LowCoverageStreakTracker::new();
        t.bump(b"shard-ghost", 50);
        let thresholds = CoverageThresholds::mainnet();
        let out = compute_shard_halt_durations(&t, &[], &thresholds);
        assert_eq!(out.get(&b"shard-ghost".to_vec()), Some(&1));
    }
}
