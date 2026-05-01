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
//!   low-coverage state.
//! - [`LowCoverageStreakTracker`] manages the per-shard streak map,
//!   providing `bump`, `clear`, and snapshot methods.
//! - [`CoverageThresholds`] captures the mainnet vs testnet halt
//!   parameters.
//! - [`compute_shard_halt_durations`] walks per-shard summaries +
//!   the streak map and returns the eviction-suppression duration
//!   map used by `evict_inactive_provers`.
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
    /// Maximum provers before split should be considered.
    pub max_provers: u64,
    /// Streak length at which an initial halt is confirmed.
    pub halt_grace_frames: u64,
}

impl CoverageThresholds {
    /// Mainnet defaults: 3-prover halt, 6-prover min, 32-prover max,
    /// 360-frame grace window.
    pub fn mainnet() -> Self {
        Self {
            halt_threshold: 3,
            min_provers: 6,
            max_provers: 32,
            halt_grace_frames: 360,
        }
    }

    /// Testnet defaults: 0-prover halt (no halt unless `min_provers`
    /// > 1, in which case 1), `min_provers` from config, 32-prover
    /// max, 360-frame grace window.
    pub fn testnet(min_provers: u64) -> Self {
        let halt_threshold = if min_provers > 1 { 1 } else { 0 };
        Self {
            halt_threshold,
            min_provers,
            max_provers: 32,
            halt_grace_frames: 360,
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
                if alloc.status == ProverStatus::Active {
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
///   fully suppressed).
/// - Shards with a non-empty streak but above the halt threshold →
///   their streak count, giving recently-recovered shards a grace
///   period proportional to how long they were halted.
/// - Shards with no streak and above the halt threshold → no entry
///   (normal eviction rules apply).
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
}

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
        }
    }

    /// Configured thresholds (halt threshold, min/max provers, grace frames).
    pub fn thresholds(&self) -> CoverageThresholds {
        self.thresholds
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

        // Get per-shard summaries from the prover registry
        let summaries = self.prover_registry
            .get_prover_shard_summaries()
            .unwrap_or_default();

        let mut any_halted = false;

        for summary in &summaries {
            let active = summary.status_counts
                .get(&ProverStatus::Active)
                .copied()
                .unwrap_or(0) as u64;

            if active <= self.thresholds.halt_threshold {
                // Low coverage — bump streak
                let streak = self.streaks.bump(&summary.filter, frame_number);
                // Mainnet extended-enrollment window: before frame
                // 262_700 (FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END + 360),
                // grant an additional 720 grace frames before halting.
                // Mirrors Go `coverage_monitor.go:222-226`.
                let effective_grace = if frame_number
                    < EXTENDED_ENROLL_HALT_GRACE_END
                {
                    self.thresholds.halt_grace_frames + 720
                } else {
                    self.thresholds.halt_grace_frames
                };
                if streak.count >= effective_grace {
                    any_halted = true;
                    tracing::debug!(
                        filter = hex::encode(&summary.filter),
                        active,
                        streak = streak.count,
                        "COVERAGE HALT — shard below threshold"
                    );
                }
            } else {
                // Recovered — clear streak
                if self.streaks.get(&summary.filter).is_some() {
                    tracing::info!(
                        filter = hex::encode(&summary.filter),
                        active,
                        "shard coverage recovered"
                    );
                    self.streaks.clear(&summary.filter);
                }
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
    pub fn current_halt_durations(&self) -> HashMap<Vec<u8>, u64> {
        let summaries = self.prover_registry
            .get_prover_shard_summaries()
            .unwrap_or_default();
        compute_shard_halt_durations(&self.streaks, &summaries, &self.thresholds)
    }

    /// Whether any shard is currently in a halt state.
    pub fn any_halted(&self) -> bool {
        self.prover_only_mode.load(Ordering::Relaxed)
    }

    /// Check for shards that need splitting (too many provers) or
    /// merging (too few provers). Returns proposed actions.
    pub fn check_split_merge(&self, frame_number: u64) -> Vec<ShardAction> {
        let summaries = self.prover_registry
            .get_prover_shard_summaries()
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
                .get_prover_shard_summaries()
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
        let mut status_counts = HashMap::new();
        status_counts.insert(ProverStatus::Active, active);
        ProverShardSummary {
            filter: filter.to_vec(),
            status_counts,
            total_size: 0,
        }
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
        assert_eq!(t.halt_grace_frames, 360);
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
