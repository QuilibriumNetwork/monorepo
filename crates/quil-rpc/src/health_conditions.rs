//! The health conditions this node detects, served in its health report.
//!
//! The node owns each condition: it detects it from its own observations,
//! gives it a severity, a scope (this node, a peer, the network), its
//! evidence and the operator's next check, logs it when it starts, at most
//! every [`REPEAT_INTERVAL_MS`] while it lasts and when it ends, and serves
//! the current ones in [`HealthConditions`]. Clients only render them, and
//! every condition served has its start and end line.
//!
//! A condition is served only while its last evaluation found it: one clear
//! is not served. It ends after [`CLEAR_HOLD_MS`] clear; one recurring
//! sooner is served again under its first start, without a line, and its
//! lasting and end lines count those clear spells and the seconds they
//! lasted, so the log can be matched against what a client showed.
//!
//! Missing or old observations establish no condition: a shard's clock
//! restarts after a gap of [`OBSERVATION_GAP_MS`], an unchanged span counts
//! only up to the latest observation, and a kind without fresh
//! observations reports nothing and ends what it reported.
//!
//! Evidence is safe to serve to an allowlisted peer: public shard filters,
//! worker core numbers, frames, counts and times, never addresses, keys,
//! paths or peer IDs.

use std::collections::{BTreeMap, HashMap, VecDeque};

use quil_engine::global_stall::GlobalReach;
use quil_types::proto::diagnostics::{
    AffectedShard, ConditionAction, ConditionKind, ConditionScope, ConditionSeverity,
    ConditionSource, ExpectedWait, GlobalProgress, HealthCondition, HealthConditions,
};
use quil_types::proto::node::{FrameCadence, FrameWindow, GlobalAppFrameHead};
use tracing::{error, info, warn};

/// The shortest window a stall is judged by.
pub const BASE_WINDOW_MS: u64 = 60_000;
/// A slower shard's window spans this many of its mean frame intervals, so
/// a healthy shard is not reported between two of its frames.
pub const CADENCE_INTERVALS: u64 = 3;
/// A committed head trailing the shard's app head by more frames is behind.
pub const GLOBAL_APP_LAG_FRAMES: u64 = 100;
/// A gap between two observations longer than this restarts a shard's
/// clock, and a shard not observed for this long is no longer tracked.
pub const OBSERVATION_GAP_MS: u64 = 150_000;
/// A worker observation older than this is stale (the worker view's
/// threshold).
pub const WORKER_STALE_MS: u64 = 30_000;
/// Affected shards a condition lists; the rest are counted.
pub const MAX_AFFECTED: usize = 64;
/// How often a lasting condition is logged again.
pub const REPEAT_INTERVAL_MS: u64 = 10 * 60_000;
/// A condition clear this long ends; one that recurs sooner continues.
pub const CLEAR_HOLD_MS: u64 = 60_000;
/// A cadence sampled longer ago than this is not fresh.
const CADENCE_FRESH_SECS: u64 = 90;
/// How long a GLOBAL state sync leaves committed GLOBAL state unreadable at
/// most when all is well (its installs take about 80 s); longer is a
/// warning.
pub const GLOBAL_SYNC_EXPECTED_MS: u64 = 10 * 60_000;
/// Frames a prover op takes to land at most: every node refuses one older.
pub const PROVER_OP_MARGIN_FRAMES: u64 =
    quil_execution::global_intrinsic::verify::PROVER_OP_FRESHNESS_WINDOW;
/// How long prover ops wait for the next epoch at most while GLOBAL
/// advances: the margin's frames many times over. Longer means GLOBAL is not
/// advancing, or this node is not following it.
pub const EPOCH_WAIT_EXPECTED_MS: u64 = 10 * 60_000;
/// GLOBAL's head unchanged this long is a stall: four leader timeouts and at
/// least this, so a few skipped leader turns and a frame are not one; a
/// GLOBAL prover's longer leader timeout widens it ([`GlobalReach`]).
pub const GLOBAL_STALL_MS: u64 = quil_engine::global_stall::MIN_STALL_AFTER.as_millis() as u64;
/// GLOBAL advancing fewer frames an hour is slow (10 s frames make 360).
pub const GLOBAL_MIN_FRAMES_PER_HOUR: u64 = 330;
/// GLOBAL's rate is judged over at most this window, once its samples span
/// [`GLOBAL_RATE_MIN_SPAN_MS`].
pub const GLOBAL_RATE_WINDOW_MS: u64 = 3_600_000;
pub const GLOBAL_RATE_MIN_SPAN_MS: u64 = 600_000;

/// Every kind this build judges.
pub const KINDS: [ConditionKind; 9] = [
    ConditionKind::LocalAppFramesUnchanged,
    ConditionKind::PeerAppFramesUnchanged,
    ConditionKind::GlobalAppFramesUnchanged,
    ConditionKind::GlobalAppFramesBehind,
    ConditionKind::GlobalHeadUnchanged,
    ConditionKind::GlobalFramesSlow,
    ConditionKind::GlobalStateSyncInstalling,
    ConditionKind::ProverOpsWaitForEpoch,
    ConditionKind::ShieldsNotAdmitted,
];

/// The expected waits: each names the event that ends it, and only a wait
/// past its expected time repeats in the log.
pub const WAIT_KINDS: [ConditionKind; 3] = [
    ConditionKind::GlobalStateSyncInstalling,
    ConditionKind::ProverOpsWaitForEpoch,
    ConditionKind::ShieldsNotAdmitted,
];

/// The frames left in the epoch when a prover op signed at `head` may land
/// after it, where every node refuses it: at most
/// [`PROVER_OP_MARGIN_FRAMES`], and at most half an epoch, so a short devnet
/// epoch keeps a time to sign. `None` with an unknown head or epoch length.
pub fn epoch_end_frames_left(head: u64, epoch_length: u64) -> Option<u64> {
    if head == 0 || epoch_length == 0 {
        return None;
    }
    let left = epoch_length - head % epoch_length;
    (left <= PROVER_OP_MARGIN_FRAMES.min(epoch_length / 2)).then_some(left)
}

/// This node's GLOBAL position and settings, as the expected waits judge
/// them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlobalObservation {
    /// The GLOBAL head this node serves (`last_global_head_frame`); 0
    /// before it knows one.
    pub head_frame: u64,
    pub epoch_length: u64,
    /// The GLOBAL frames from which admission takes shields of legacy coins
    /// (`token shield`, `token shield-all`); `None` when this build admits
    /// none, `u64::MAX` when the network sets no frame.
    pub shields_from: Option<(u64, u64)>,
    /// Whether a GLOBAL state sync has installed some of its chunks but not
    /// the last; `None` when that could not be read.
    pub sync_installing: Option<bool>,
}

/// A shard's stall window: [`BASE_WINDOW_MS`], widened to
/// [`CADENCE_INTERVALS`] of its mean frame interval on slower shards. The
/// shorter of the fresh 60m and 24h means counts, so an ongoing stall cannot
/// widen its own window past the 24h mean; without a fresh cadence the base
/// window applies.
pub fn stall_window_ms(cadence: Option<&FrameCadence>, now_secs: u64) -> u64 {
    let Some(cadence) = cadence else {
        return BASE_WINDOW_MS;
    };
    if now_secs < cadence.last_observed_unix_seconds
        || now_secs - cadence.last_observed_unix_seconds > CADENCE_FRESH_SECS
    {
        return BASE_WINDOW_MS;
    }
    let fresh = |w: &&FrameWindow| {
        w.observed_seconds >= 60 && w.observed_seconds <= w.window_seconds && w.advanced_frames > 0
    };
    [cadence.hour.as_ref(), cadence.day.as_ref()]
        .into_iter()
        .flatten()
        .filter(fresh)
        .map(|w| {
            w.observed_seconds
                .saturating_mul(CADENCE_INTERVALS)
                .saturating_mul(1000)
                / w.advanced_frames
        })
        .min()
        .map_or(BASE_WINDOW_MS, |ms| ms.max(BASE_WINDOW_MS))
}

/// One worker as the master's worker view and prover registry show it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkerObservation {
    pub core_id: u32,
    pub filter: Vec<u8>,
    /// Its allocation is active or leaving in this node's prover registry.
    pub earning: bool,
    pub state: String,
    pub blocker: String,
    pub observed_unix_ms: u64,
    pub materialized_frame: Option<u64>,
    /// When the materialized frame last advanced; 0 when it has not since
    /// the engine started.
    pub last_advance_unix_ms: u64,
}

impl WorkerObservation {
    fn fresh(&self, now_ms: u64) -> bool {
        self.observed_unix_ms != 0
            && now_ms.saturating_sub(self.observed_unix_ms) <= WORKER_STALE_MS
    }

    /// A fresh observation of an earning worker in a phase that advances
    /// frames: sync, close, handoff, activation and other waits are
    /// expected lifecycle waits, not stalls.
    fn judged(&self, now_ms: u64) -> bool {
        // Older workers classified the handoff wait as a blocker.
        let handoff = self.state == "blocked" && self.blocker == "awaiting successor";
        self.fresh(now_ms)
            && self.earning
            && !self.filter.is_empty()
            && self.materialized_frame.is_some()
            && !handoff
            && matches!(
                self.state.as_str(),
                "starting" | "running" | "serving" | "blocked" | "stopped"
            )
    }
}

/// One shard row of served shard info: the head peers report for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerObservation {
    pub filter: Vec<u8>,
    pub latest_frame: u64,
    pub materialized_frame: u64,
    pub active_provers: u32,
    /// The generation of the shard's committed session, if known.
    pub generation: Option<u64>,
}

#[derive(Debug, Clone)]
struct PeerTrack {
    frame: u64,
    generation: Option<u64>,
    since_ms: u64,
    seen_ms: u64,
}

#[derive(Debug, Clone)]
struct CommittedTrack {
    frame: u64,
    generation: u64,
    /// The GLOBAL frame and the app head when the committed head last
    /// changed (the app head: when first known since).
    global_frame_at_change: u64,
    head_at_change: u64,
    global_frame: u64,
    since_ms: u64,
    seen_ms: u64,
}

/// The GLOBAL head this node knows, as the health task samples it.
#[derive(Debug, Clone, Default)]
struct GlobalTrack {
    head: u64,
    since_ms: u64,
    seen_ms: u64,
    /// `(time, head)` over the rate window.
    samples: VecDeque<(u64, u64)>,
    reach: Option<GlobalReach>,
}

#[derive(Debug, Clone)]
struct Current {
    since_ms: u64,
    last_logged_ms: u64,
    clear_since_ms: Option<u64>,
    /// The clear spells it recurred from, and their total length.
    clear_spells: u32,
    unserved_ms: u64,
    /// An expected wait that lasted past its expected time.
    overran: bool,
    condition: HealthCondition,
    log_evidence: Option<String>,
}

/// A change of a condition, to be logged.
#[derive(Debug, Clone, PartialEq)]
pub enum Transition {
    Started {
        condition: HealthCondition,
        /// Evidence for this node's log that is not served, such as the
        /// labels of unreachable GLOBAL provers.
        log_evidence: Option<String>,
    },
    Lasting {
        condition: HealthCondition,
        duration_ms: u64,
        /// The clear spells it recurred from so far, and their total
        /// length, during which it was not served.
        clear_spells: u32,
        unserved_ms: u64,
        log_evidence: Option<String>,
    },
    /// An expected wait lasted past its expected time: from now on a
    /// warning.
    Overran {
        condition: HealthCondition,
        duration_ms: u64,
    },
    Ended {
        kind: ConditionKind,
        /// From its start to this end.
        duration_ms: u64,
        /// How long it was clear, and so not served, before it ended.
        clear_ms: u64,
        /// Its clear spells from start to end, this last one included, and
        /// their total length, during which it was not served.
        clear_spells: u32,
        unserved_ms: u64,
        /// Its inputs went stale rather than the progress resuming.
        unobserved: bool,
    },
}

/// The node's conditions, fed by its observations and judged on a timer.
#[derive(Debug, Default)]
pub struct HealthRegistry {
    peers: HashMap<Vec<u8>, PeerTrack>,
    committed: HashMap<Vec<u8>, CommittedTrack>,
    workers: Vec<WorkerObservation>,
    workers_seen_ms: u64,
    peers_seen_ms: u64,
    committed_seen_ms: u64,
    global: GlobalObservation,
    global_seen_ms: u64,
    global_head: Option<GlobalTrack>,
    /// When each judged worker without an advance was first judged.
    worker_first_seen: HashMap<(u32, Vec<u8>), u64>,
    current: BTreeMap<i32, Current>,
    sources: Vec<ConditionSource>,
}

/// A kind's severity; an expected wait past its expected time is a
/// warning.
fn severity_of(kind: ConditionKind, overran: bool) -> ConditionSeverity {
    if WAIT_KINDS.contains(&kind) && !overran {
        ConditionSeverity::Info
    } else if kind == ConditionKind::GlobalHeadUnchanged {
        ConditionSeverity::Error
    } else {
        ConditionSeverity::Warning
    }
}

fn scope_of(kind: ConditionKind) -> ConditionScope {
    match kind {
        ConditionKind::LocalAppFramesUnchanged | ConditionKind::GlobalStateSyncInstalling => {
            ConditionScope::ThisNode
        }
        ConditionKind::PeerAppFramesUnchanged => ConditionScope::Peer,
        _ => ConditionScope::Network,
    }
}

fn action_of(kind: ConditionKind) -> ConditionAction {
    match kind {
        ConditionKind::LocalAppFramesUnchanged => ConditionAction::CheckWorkerLogs,
        ConditionKind::PeerAppFramesUnchanged => ConditionAction::ComparePeerWithExplorer,
        ConditionKind::GlobalStateSyncInstalling => ConditionAction::WaitForGlobalSync,
        ConditionKind::ProverOpsWaitForEpoch => ConditionAction::WaitForNextEpoch,
        ConditionKind::ShieldsNotAdmitted => ConditionAction::WaitForShieldAdmission,
        ConditionKind::GlobalHeadUnchanged => ConditionAction::CheckGlobalHead,
        ConditionKind::GlobalFramesSlow => ConditionAction::CheckGlobalRate,
        _ => ConditionAction::CheckGlobalInclusion,
    }
}

/// How long an expected wait lasts at most when all is well; `None` for a
/// wait only its frame bounds, and for the other kinds.
fn expected_ms(kind: ConditionKind) -> Option<u64> {
    match kind {
        ConditionKind::GlobalStateSyncInstalling => Some(GLOBAL_SYNC_EXPECTED_MS),
        ConditionKind::ProverOpsWaitForEpoch => Some(EPOCH_WAIT_EXPECTED_MS),
        _ => None,
    }
}

/// Whether `frames` over `span_ms` reach [`GLOBAL_MIN_FRAMES_PER_HOUR`].
fn global_rate_ok(frames: u64, span_ms: u64) -> bool {
    u128::from(frames) * 3_600_000 >= u128::from(GLOBAL_MIN_FRAMES_PER_HOUR) * u128::from(span_ms)
}

/// One kind's judgement in an evaluation.
struct Judged {
    kind: ConditionKind,
    shards: Vec<AffectedShard>,
    tracked: u32,
    observed_unix_ms: u64,
    threshold: u64,
    /// For an expected wait: what ends it, when it is current.
    wait: Option<ExpectedWait>,
    global: Option<GlobalProgress>,
    log_evidence: Option<String>,
}

/// GLOBAL's progress judged at one evaluation.
#[derive(Default)]
struct GlobalJudged {
    unchanged: Option<(AffectedShard, GlobalProgress)>,
    slow: Option<(AffectedShard, GlobalProgress)>,
    tracked: u32,
    window_ms: u64,
    unreachable: Option<String>,
}

impl HealthRegistry {
    /// Record the heads peers report, from one served shard info.
    pub fn observe_peers(&mut self, rows: &[PeerObservation], now_ms: u64) {
        for row in rows {
            // Empty or unknown peer metadata and unstaffed shards cannot
            // establish a stall.
            if row.active_provers == 0 || (row.latest_frame == 0 && row.materialized_frame == 0) {
                continue;
            }
            let fresh = PeerTrack {
                frame: row.latest_frame,
                generation: row.generation,
                since_ms: now_ms,
                seen_ms: now_ms,
            };
            let track = self
                .peers
                .entry(row.filter.clone())
                .or_insert_with(|| fresh.clone());
            if track.frame != row.latest_frame
                || track.generation != row.generation
                || now_ms.saturating_sub(track.seen_ms) > OBSERVATION_GAP_MS
            {
                *track = fresh;
            }
            track.seen_ms = now_ms;
        }
        self.peers_seen_ms = now_ms;
    }

    /// The app head of `filter`: the highest of its fresh peer-reported
    /// head and this node's workers' materialized frames on it; 0 unknown.
    fn app_head(&self, filter: &[u8], now_ms: u64) -> u64 {
        let peer = self
            .peers
            .get(filter)
            .filter(|t| now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS)
            .map_or(0, |t| t.frame);
        let local = self
            .workers
            .iter()
            .filter(|w| w.filter == filter && w.fresh(now_ms))
            .filter_map(|w| w.materialized_frame)
            .max()
            .unwrap_or(0);
        peer.max(local)
    }

    /// Record shards' heads in this node's committed GLOBAL state.
    pub fn observe_committed(&mut self, heads: &[(Vec<u8>, GlobalAppFrameHead)], now_ms: u64) {
        for (filter, committed) in heads {
            let head = self.app_head(filter, now_ms);
            let fresh = CommittedTrack {
                frame: committed.frame,
                generation: committed.generation,
                global_frame_at_change: committed.global_frame,
                head_at_change: head,
                global_frame: committed.global_frame,
                since_ms: now_ms,
                seen_ms: now_ms,
            };
            let track = self
                .committed
                .entry(filter.clone())
                .or_insert_with(|| fresh.clone());
            if track.frame != committed.frame
                || track.generation != committed.generation
                || now_ms.saturating_sub(track.seen_ms) > OBSERVATION_GAP_MS
            {
                *track = fresh;
            }
            if track.head_at_change == 0 {
                track.head_at_change = head;
            }
            track.global_frame = track.global_frame.max(committed.global_frame);
            track.seen_ms = now_ms;
        }
        self.committed_seen_ms = now_ms;
    }

    /// Record this node's GLOBAL position and settings.
    pub fn observe_global(&mut self, global: GlobalObservation, now_ms: u64) {
        self.global = global;
        self.global_seen_ms = now_ms;
    }

    /// The expected waits as of the latest GLOBAL observation: each current
    /// one with what ends it. Without a fresh observation, or the inputs a
    /// kind needs, it tracks nothing and reports nothing.
    fn judge_waits(&self, now_ms: u64) -> [Judged; 3] {
        let fresh = self.global_seen_ms != 0
            && now_ms.saturating_sub(self.global_seen_ms) <= OBSERVATION_GAP_MS;
        let g = self.global;
        let observed = |known: bool| {
            if fresh && known {
                self.global_seen_ms
            } else {
                0
            }
        };
        let wait = |until_frame, batch_from_frame, kind| ExpectedWait {
            head_frame: g.head_frame,
            until_frame,
            batch_from_frame,
            expected_secs: expected_ms(kind).unwrap_or(0) / 1000,
        };
        let judged =
            |kind, observed_unix_ms: u64, tracked: bool, threshold, wait: Option<_>| Judged {
                kind,
                shards: Vec::new(),
                tracked: u32::from(observed_unix_ms != 0 && tracked),
                observed_unix_ms,
                threshold,
                wait: wait.filter(|_| observed_unix_ms != 0 && tracked),
                global: None,
                log_evidence: None,
            };

        let kind = ConditionKind::GlobalStateSyncInstalling;
        let installing = g.sync_installing == Some(true);
        let sync = judged(
            kind,
            observed(g.sync_installing.is_some()),
            true,
            0,
            installing.then(|| wait(0, 0, kind)),
        );

        let kind = ConditionKind::ProverOpsWaitForEpoch;
        let left = epoch_end_frames_left(g.head_frame, g.epoch_length);
        let epoch = judged(
            kind,
            observed(g.head_frame != 0 && g.epoch_length != 0),
            true,
            PROVER_OP_MARGIN_FRAMES.min(g.epoch_length / 2),
            left.map(|left| wait(g.head_frame + left, 0, kind)),
        );

        // A network that sets no admission frame has no wait to track.
        let kind = ConditionKind::ShieldsNotAdmitted;
        let frames = g
            .shields_from
            .filter(|(single, batch)| *single != u64::MAX && *batch != u64::MAX);
        let shields = judged(
            kind,
            observed(g.head_frame != 0),
            frames.is_some(),
            0,
            frames
                .filter(|(single, batch)| g.head_frame < (*single).max(*batch))
                .map(|(single, batch)| wait(single, single.max(batch), kind)),
        );
        [sync, epoch, shields]
    }

    /// Judge the expected waits at once on `global`, as a report is served:
    /// a client deciding when to sign reads the head it signs at. The
    /// transitions to log.
    pub fn refresh_waits(&mut self, global: GlobalObservation, now_ms: u64) -> Vec<Transition> {
        self.observe_global(global, now_ms);
        self.sources
            .retain(|s| !WAIT_KINDS.iter().any(|k| *k as i32 == s.kind));
        let mut transitions = Vec::new();
        for judged in self.judge_waits(now_ms) {
            self.sources.push(ConditionSource {
                kind: judged.kind as i32,
                observed_unix_ms: judged.observed_unix_ms,
                tracked: judged.tracked,
            });
            if let Some(t) = self.update(judged, now_ms) {
                transitions.push(t);
            }
        }
        transitions
    }

    /// Record the GLOBAL head this node knows (0: unknown) and, on a GLOBAL
    /// prover, the GLOBAL provers it hears.
    pub fn observe_global_head(&mut self, head: u64, reach: Option<GlobalReach>, now_ms: u64) {
        if head == 0 {
            return;
        }
        let mut track = match self.global_head.take() {
            Some(t) if now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS => t,
            _ => GlobalTrack {
                head,
                since_ms: now_ms,
                ..Default::default()
            },
        };
        if track.head != head {
            track.head = head;
            track.since_ms = now_ms;
        }
        track.seen_ms = now_ms;
        track.samples.push_back((now_ms, head));
        while track
            .samples
            .front()
            .is_some_and(|(t, _)| t + GLOBAL_RATE_WINDOW_MS < now_ms)
        {
            track.samples.pop_front();
        }
        track.reach = reach;
        self.global_head = Some(track);
    }

    /// Record the worker view.
    pub fn observe_workers(&mut self, workers: Vec<WorkerObservation>, now_ms: u64) {
        self.workers = workers;
        self.workers_seen_ms = now_ms;
    }

    fn judge_local(
        &mut self,
        now_ms: u64,
        window: &dyn Fn(&[u8]) -> u64,
    ) -> (Vec<AffectedShard>, u32) {
        let mut affected = Vec::new();
        let mut tracked = 0;
        let mut judged_keys = Vec::new();
        let stale = now_ms.saturating_sub(self.workers_seen_ms) > OBSERVATION_GAP_MS;
        for w in self.workers.iter().filter(|w| !stale && w.judged(now_ms)) {
            tracked += 1;
            let key = (w.core_id, w.filter.clone());
            let since = if w.last_advance_unix_ms != 0 {
                w.last_advance_unix_ms
            } else {
                *self.worker_first_seen.entry(key.clone()).or_insert(now_ms)
            };
            judged_keys.push(key);
            let window_ms = window(&w.filter);
            if now_ms.saturating_sub(since) >= window_ms {
                affected.push(AffectedShard {
                    filter: w.filter.clone(),
                    core_id: w.core_id,
                    frame: w.materialized_frame.unwrap_or(0),
                    unchanged_since_unix_ms: since,
                    window_secs: window_ms / 1000,
                    lag_frames: 0,
                });
            }
        }
        self.worker_first_seen
            .retain(|key, _| judged_keys.contains(key));
        (affected, tracked)
    }

    fn judge_peers(
        &mut self,
        now_ms: u64,
        window: &dyn Fn(&[u8]) -> u64,
    ) -> (Vec<AffectedShard>, u32) {
        self.peers
            .retain(|_, t| now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS);
        let mut affected = Vec::new();
        for (filter, t) in &self.peers {
            let window_ms = window(filter);
            // Unchanged only as far as it was observed.
            if t.seen_ms.saturating_sub(t.since_ms) >= window_ms {
                affected.push(AffectedShard {
                    filter: filter.clone(),
                    frame: t.frame,
                    unchanged_since_unix_ms: t.since_ms,
                    window_secs: window_ms / 1000,
                    ..Default::default()
                });
            }
        }
        (affected, self.peers.len() as u32)
    }

    fn judge_committed(
        &mut self,
        now_ms: u64,
        window: &dyn Fn(&[u8]) -> u64,
    ) -> (Vec<AffectedShard>, Vec<AffectedShard>, u32) {
        self.committed
            .retain(|_, t| now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS);
        let (mut unchanged, mut behind, mut tracked) = (Vec::new(), Vec::new(), 0);
        for (filter, t) in &self.committed {
            // A shard without a known app head cannot establish a stall or
            // a lag.
            let head = self.app_head(filter, now_ms);
            if head == 0 {
                continue;
            }
            tracked += 1;
            let window_ms = window(filter);
            if t.seen_ms.saturating_sub(t.since_ms) >= window_ms
                && t.global_frame > t.global_frame_at_change
                && t.head_at_change != 0
                && head > t.head_at_change
            {
                unchanged.push(AffectedShard {
                    filter: filter.clone(),
                    frame: t.frame,
                    unchanged_since_unix_ms: t.since_ms,
                    window_secs: window_ms / 1000,
                    ..Default::default()
                });
            }
            let lag = head.saturating_sub(t.frame);
            if lag > GLOBAL_APP_LAG_FRAMES {
                behind.push(AffectedShard {
                    filter: filter.clone(),
                    frame: t.frame,
                    lag_frames: lag,
                    ..Default::default()
                });
            }
        }
        (unchanged, behind, tracked)
    }

    /// GLOBAL's head unchanged for its window, else its rate below
    /// [`GLOBAL_MIN_FRAMES_PER_HOUR`] once the samples span
    /// [`GLOBAL_RATE_MIN_SPAN_MS`]: a stall is one condition while it lasts
    /// and shows in the rate after it, until the hour has made it up, so a
    /// stall shorter than a reader's gap between reads still shows.
    /// Nothing without a fresh observation.
    fn judge_global(&mut self, now_ms: u64) -> GlobalJudged {
        if self
            .global_head
            .as_ref()
            .is_some_and(|t| now_ms.saturating_sub(t.seen_ms) > OBSERVATION_GAP_MS)
        {
            self.global_head = None;
        }
        let Some(t) = self.global_head.as_ref() else {
            return GlobalJudged {
                window_ms: GLOBAL_STALL_MS,
                ..Default::default()
            };
        };
        let window_ms = global_window_ms(t.reach.as_ref());
        let progress = |advanced_frames, span_ms: u64| {
            let (provers, reachable, quorum) = t
                .reach
                .as_ref()
                .map_or((0, 0, 0), |r| (r.provers, r.reachable, r.quorum));
            GlobalProgress {
                head: t.head,
                advanced_frames,
                span_secs: span_ms / 1000,
                provers: provers as u32,
                reachable: reachable as u32,
                quorum: quorum as u32,
            }
        };
        let mut judged = GlobalJudged {
            tracked: 1,
            window_ms,
            unreachable: t
                .reach
                .as_ref()
                .filter(|r| !r.unreachable.is_empty())
                .map(|r| r.unreachable.join(", ")),
            ..Default::default()
        };
        // Unchanged only as far as it was observed.
        let unchanged_ms = t.seen_ms.saturating_sub(t.since_ms);
        if unchanged_ms >= window_ms {
            let row = AffectedShard {
                frame: t.head,
                unchanged_since_unix_ms: t.since_ms,
                window_secs: window_ms / 1000,
                ..Default::default()
            };
            judged.unchanged = Some((row, progress(0, unchanged_ms)));
        } else if let Some(&(first_ms, first_head)) = t.samples.front() {
            let span_ms = t.seen_ms.saturating_sub(first_ms);
            let frames = t.head.saturating_sub(first_head);
            if span_ms >= GLOBAL_RATE_MIN_SPAN_MS && !global_rate_ok(frames, span_ms) {
                let row = AffectedShard {
                    frame: t.head,
                    window_secs: span_ms / 1000,
                    ..Default::default()
                };
                judged.slow = Some((row, progress(frames, span_ms)));
            }
        }
        judged
    }

    /// Judge every kind at `now_ms`, each shard by its window from
    /// `cadence`; the transitions to log.
    pub fn evaluate(
        &mut self,
        now_ms: u64,
        cadence: &dyn Fn(&[u8]) -> Option<FrameCadence>,
    ) -> Vec<Transition> {
        let now_secs = now_ms / 1000;
        let window = |filter: &[u8]| stall_window_ms(cadence(filter).as_ref(), now_secs);
        let (local, local_tracked) = self.judge_local(now_ms, &window);
        let (peer, peer_tracked) = self.judge_peers(now_ms, &window);
        let (unchanged, behind, committed_tracked) = self.judge_committed(now_ms, &window);
        let global = self.judge_global(now_ms);
        let global_seen = self.global_head.as_ref().map_or(0, |t| t.seen_ms);
        let fresh = |seen: u64| {
            if seen != 0 && now_ms.saturating_sub(seen) <= OBSERVATION_GAP_MS {
                seen
            } else {
                0
            }
        };
        let base_secs = BASE_WINDOW_MS / 1000;
        let judged = [
            Judged {
                kind: ConditionKind::LocalAppFramesUnchanged,
                shards: local,
                tracked: local_tracked,
                observed_unix_ms: fresh(self.workers_seen_ms),
                threshold: base_secs,
                wait: None,
                global: None,
                log_evidence: None,
            },
            Judged {
                kind: ConditionKind::PeerAppFramesUnchanged,
                shards: peer,
                tracked: peer_tracked,
                observed_unix_ms: fresh(self.peers_seen_ms),
                threshold: base_secs,
                wait: None,
                global: None,
                log_evidence: None,
            },
            Judged {
                kind: ConditionKind::GlobalAppFramesUnchanged,
                shards: unchanged,
                tracked: committed_tracked,
                observed_unix_ms: fresh(self.committed_seen_ms),
                threshold: base_secs,
                wait: None,
                global: None,
                log_evidence: None,
            },
            Judged {
                kind: ConditionKind::GlobalAppFramesBehind,
                shards: behind,
                tracked: committed_tracked,
                observed_unix_ms: fresh(self.committed_seen_ms),
                threshold: GLOBAL_APP_LAG_FRAMES,
                wait: None,
                global: None,
                log_evidence: None,
            },
            Judged {
                kind: ConditionKind::GlobalHeadUnchanged,
                shards: global
                    .unchanged
                    .iter()
                    .map(|(row, _)| row.clone())
                    .collect(),
                tracked: global.tracked,
                observed_unix_ms: fresh(global_seen),
                threshold: global.window_ms / 1000,
                wait: None,
                global: global.unchanged.map(|(_, progress)| progress),
                log_evidence: global.unreachable,
            },
            Judged {
                kind: ConditionKind::GlobalFramesSlow,
                shards: global.slow.iter().map(|(row, _)| row.clone()).collect(),
                tracked: global.tracked,
                observed_unix_ms: fresh(global_seen),
                threshold: GLOBAL_MIN_FRAMES_PER_HOUR,
                wait: None,
                global: global.slow.map(|(_, progress)| progress),
                log_evidence: None,
            },
        ];
        self.sources.clear();
        let mut transitions = Vec::new();
        for mut judged in judged.into_iter().chain(self.judge_waits(now_ms)) {
            self.sources.push(ConditionSource {
                kind: judged.kind as i32,
                observed_unix_ms: judged.observed_unix_ms,
                tracked: judged.tracked,
            });
            judged
                .shards
                .sort_by(|a, b| a.filter.cmp(&b.filter).then(a.core_id.cmp(&b.core_id)));
            if let Some(t) = self.update(judged, now_ms) {
                transitions.push(t);
            }
        }
        transitions
    }

    fn update(&mut self, judged: Judged, now_ms: u64) -> Option<Transition> {
        let Judged {
            kind,
            mut shards,
            tracked,
            threshold,
            wait,
            global,
            log_evidence,
            ..
        } = judged;
        let key = kind as i32;
        // A current wait is one condition of this node; the others count
        // their shards.
        let affected = if wait.is_some() {
            1
        } else {
            shards.len() as u32
        };
        if affected == 0 {
            let current = self.current.get_mut(&key)?;
            let clear_since = *current.clear_since_ms.get_or_insert(now_ms);
            // Without fresh observations nothing holds it open.
            if tracked > 0 && now_ms.saturating_sub(clear_since) < CLEAR_HOLD_MS {
                return None;
            }
            let current = self.current.remove(&key)?;
            let clear_ms = now_ms.saturating_sub(clear_since);
            return Some(Transition::Ended {
                kind,
                duration_ms: now_ms.saturating_sub(current.since_ms),
                clear_ms,
                clear_spells: current.clear_spells + u32::from(clear_ms > 0),
                unserved_ms: current.unserved_ms + clear_ms,
                unobserved: tracked == 0,
            });
        }
        let omitted_shards = shards.len().saturating_sub(MAX_AFFECTED) as u32;
        shards.truncate(MAX_AFFECTED);
        let condition = |since_unix_ms, overran| HealthCondition {
            kind: key,
            severity: severity_of(kind, overran) as i32,
            scope: scope_of(kind) as i32,
            action: action_of(kind) as i32,
            since_unix_ms,
            affected,
            tracked,
            threshold,
            shards,
            omitted_shards,
            wait,
            global,
        };
        if let Some(current) = self.current.get_mut(&key) {
            // It recurred within its clear hold: count the spell.
            if let Some(clear_since) = current.clear_since_ms.take() {
                current.clear_spells += 1;
                current.unserved_ms += now_ms.saturating_sub(clear_since);
            }
            let duration_ms = now_ms.saturating_sub(current.since_ms);
            let overran = expected_ms(kind).is_some_and(|expected| duration_ms >= expected);
            current.condition = condition(current.since_ms, overran);
            current.log_evidence = log_evidence;
            if overran && !current.overran {
                // An anomaly now: a warning from here on.
                current.overran = true;
                current.last_logged_ms = now_ms;
                return Some(Transition::Overran {
                    condition: current.condition.clone(),
                    duration_ms,
                });
            }
            // An expected wait repeats only once it overran.
            let repeats = !WAIT_KINDS.contains(&kind) || current.overran;
            if repeats && now_ms.saturating_sub(current.last_logged_ms) >= REPEAT_INTERVAL_MS {
                current.last_logged_ms = now_ms;
                return Some(Transition::Lasting {
                    condition: current.condition.clone(),
                    duration_ms: now_ms.saturating_sub(current.since_ms),
                    clear_spells: current.clear_spells,
                    unserved_ms: current.unserved_ms,
                    log_evidence: current.log_evidence.clone(),
                });
            }
            return None;
        }
        let current = Current {
            since_ms: now_ms,
            last_logged_ms: now_ms,
            clear_since_ms: None,
            clear_spells: 0,
            unserved_ms: 0,
            overran: false,
            condition: condition(now_ms, false),
            log_evidence: log_evidence.clone(),
        };
        let started = current.condition.clone();
        self.current.insert(key, current);
        Some(Transition::Started {
            condition: started,
            log_evidence,
        })
    }

    /// The conditions found at the last evaluation, worst first (a clear
    /// one is not served), and every kind's source.
    pub fn snapshot(&self) -> HealthConditions {
        let mut conditions: Vec<HealthCondition> = self
            .current
            .values()
            .filter(|c| c.clear_since_ms.is_none())
            .map(|c| c.condition.clone())
            .collect();
        conditions.sort_by_key(|c| (std::cmp::Reverse(c.severity), c.kind));
        HealthConditions {
            conditions,
            sources: self.sources.clone(),
        }
    }
}

/// The stall window GLOBAL's head is judged by.
fn global_window_ms(reach: Option<&GlobalReach>) -> u64 {
    reach.map_or(GLOBAL_STALL_MS, |r| {
        (r.stall_after.as_millis() as u64).max(GLOBAL_STALL_MS)
    })
}

/// The condition's notice, as the node logs it and clients show it.
pub fn notice_text(c: &HealthCondition) -> String {
    let (affected, tracked, threshold) = (c.affected, c.tracked, c.threshold);
    match ConditionKind::try_from(c.kind).unwrap_or(ConditionKind::Unspecified) {
        ConditionKind::LocalAppFramesUnchanged => {
            format!("Local app frames unchanged >{threshold}s: {affected}/{tracked} allocations.")
        }
        ConditionKind::PeerAppFramesUnchanged => {
            format!("Peer app frames unchanged >{threshold}s: {affected}/{tracked} tracked shards.")
        }
        ConditionKind::GlobalAppFramesUnchanged => format!(
            "Global app frames unchanged >{threshold}s: {affected}/{tracked} tracked shards."
        ),
        ConditionKind::GlobalAppFramesBehind => format!(
            "Global app frames >{threshold} behind app heads: {affected}/{tracked} tracked shards."
        ),
        ConditionKind::GlobalStateSyncInstalling => {
            let expected = c.wait.as_ref().map_or(0, |w| w.expected_secs / 60);
            if c.severity == ConditionSeverity::Warning as i32 {
                format!(
                    "GLOBAL state sync installing >{expected}m: committed GLOBAL state stays \
                     unreadable until its last chunk is in."
                )
            } else {
                "GLOBAL state sync installing: committed shard heads show again once its last \
                 chunk is in."
                    .into()
            }
        }
        ConditionKind::ProverOpsWaitForEpoch => {
            let w = c.wait.unwrap_or_default();
            if c.severity == ConditionSeverity::Warning as i32 {
                format!(
                    "Prover ops waited >{}m for the next epoch at frame {}; the GLOBAL head \
                     stays at {}.",
                    w.expected_secs / 60,
                    w.until_frame,
                    w.head_frame
                )
            } else {
                format!(
                    "Prover ops wait for the next epoch: it starts at frame {} ({} frames).",
                    w.until_frame,
                    w.until_frame.saturating_sub(w.head_frame)
                )
            }
        }
        ConditionKind::ShieldsNotAdmitted => {
            let w = c.wait.unwrap_or_default();
            let to_go = w.batch_from_frame.saturating_sub(w.head_frame);
            if w.until_frame == w.batch_from_frame {
                format!(
                    "Legacy coin shields admitted from GLOBAL frame {}: {to_go} frames to go.",
                    w.until_frame
                )
            } else {
                format!(
                    "Legacy coin shields admitted from GLOBAL frame {}, batches from {}: \
                     {to_go} frames to go.",
                    w.until_frame, w.batch_from_frame
                )
            }
        }
        ConditionKind::GlobalHeadUnchanged => {
            let reach = c.global.as_ref().filter(|g| g.provers > 0);
            match reach {
                Some(g) if g.reachable < g.quorum => format!(
                    "Global head unchanged >{threshold}s: {} of {} GLOBAL provers reachable, {} \
                     needed.",
                    g.reachable, g.provers, g.quorum
                ),
                Some(g) => format!(
                    "Global head unchanged >{threshold}s although {} of {} GLOBAL provers are \
                     reachable ({} needed).",
                    g.reachable, g.provers, g.quorum
                ),
                None => format!("Global head unchanged >{threshold}s."),
            }
        }
        ConditionKind::GlobalFramesSlow => {
            let g = c.global.unwrap_or_default();
            let rate = (g.advanced_frames * 3_600)
                .checked_div(g.span_secs)
                .unwrap_or(0);
            format!(
                "Global frames slow: {} in {} min (~{rate}/h, below {threshold}/h).",
                g.advanced_frames,
                g.span_secs / 60
            )
        }
        ConditionKind::Unspecified => format!(
            "Health condition {} ({}, {}): {affected}/{tracked}; see this node's log.",
            c.kind,
            severity_label(c.severity),
            scope_label(c.scope)
        ),
    }
}

/// The notice of the worst current GLOBAL progress condition, if any, as a
/// clause without its final stop: what a paced shield pauses for.
pub fn global_progress_notice(health: &HealthConditions) -> Option<String> {
    health
        .conditions
        .iter()
        .find(|c| {
            matches!(
                ConditionKind::try_from(c.kind),
                Ok(ConditionKind::GlobalHeadUnchanged | ConditionKind::GlobalFramesSlow)
            )
        })
        .map(|c| notice_text(c).trim_end_matches('.').to_string())
}

/// What the operator checks next.
pub fn action_text(action: i32) -> &'static str {
    match ConditionAction::try_from(action).unwrap_or(ConditionAction::Unspecified) {
        ConditionAction::CheckWorkerLogs => {
            "check the affected workers' logs: sync, close, handoff and activation waits are \
             excluded, so a stop there is an engine or consensus failure"
        }
        ConditionAction::ComparePeerWithExplorer => {
            "compare the shards on the explorer: advancing there means the reporting peer \
             trails, stopped there means the shard halted"
        }
        ConditionAction::CheckGlobalInclusion => {
            "check GLOBAL's inclusion of the shards on the explorer: advancing there means \
             this node's GLOBAL view trails, else GLOBAL is not including them"
        }
        ConditionAction::WaitForGlobalSync => {
            "nothing: committed GLOBAL state reads again once the sync's last chunk is in; past \
             10 min, check the node's `sync phase` and prover tree sync lines"
        }
        ConditionAction::WaitForNextEpoch => {
            "nothing: prover ops are signed once the next epoch starts; past 10 min, check that \
             this node follows GLOBAL"
        }
        ConditionAction::WaitForShieldAdmission => {
            "nothing: shield once GLOBAL reaches the admission frame"
        }
        ConditionAction::CheckGlobalHead => {
            "compare GLOBAL's head on the explorer: stopped there means GLOBAL halted \
             network-wide (a GLOBAL prover's log names the unreachable provers to bring back; \
             with a quorum reachable, look for provers on builds with other activation \
             constants), advancing there means this node stopped following GLOBAL: check its \
             peers and sync"
        }
        ConditionAction::CheckGlobalRate => {
            "compare GLOBAL's frame rate on the explorer: slow there means GLOBAL provers vote \
             late or skip leader turns (their logs count skipped turns), normal there means \
             this node receives GLOBAL frames late: check its peers"
        }
        ConditionAction::Unspecified => "see this node's log",
    }
}

pub fn severity_label(severity: i32) -> &'static str {
    match ConditionSeverity::try_from(severity).unwrap_or(ConditionSeverity::Unspecified) {
        ConditionSeverity::Error => "error",
        ConditionSeverity::Warning => "warning",
        ConditionSeverity::Info => "info",
        ConditionSeverity::Unspecified => "unknown severity",
    }
}

pub fn scope_label(scope: i32) -> &'static str {
    match ConditionScope::try_from(scope).unwrap_or(ConditionScope::Unspecified) {
        ConditionScope::ThisNode => "this node",
        ConditionScope::Peer => "peer reports",
        ConditionScope::Network => "the network",
        ConditionScope::Unspecified => "unknown scope",
    }
}

/// The kind's name in log lines.
pub fn kind_label(kind: i32) -> &'static str {
    match ConditionKind::try_from(kind).unwrap_or(ConditionKind::Unspecified) {
        ConditionKind::LocalAppFramesUnchanged => "local_app_frames_unchanged",
        ConditionKind::PeerAppFramesUnchanged => "peer_app_frames_unchanged",
        ConditionKind::GlobalAppFramesUnchanged => "global_app_frames_unchanged",
        ConditionKind::GlobalAppFramesBehind => "global_app_frames_behind",
        ConditionKind::GlobalStateSyncInstalling => "global_state_sync_installing",
        ConditionKind::ProverOpsWaitForEpoch => "prover_ops_wait_for_epoch",
        ConditionKind::ShieldsNotAdmitted => "shields_not_admitted",
        ConditionKind::GlobalHeadUnchanged => "global_head_unchanged",
        ConditionKind::GlobalFramesSlow => "global_frames_slow",
        ConditionKind::Unspecified => "unknown",
    }
}

/// The first affected shards' filter ends, for a log line: filters on one
/// app share their leading bytes, so only the end tells shards apart.
fn shard_names(c: &HealthCondition) -> String {
    let mut text = c
        .shards
        .iter()
        .take(3)
        .map(|s| match s.filter.as_slice() {
            [] => "global".to_string(),
            filter => hex::encode(&filter[filter.len().saturating_sub(6)..]),
        })
        .collect::<Vec<_>>()
        .join(",");
    let more = c.affected.saturating_sub(3);
    if more > 0 {
        text += &format!(",+{more}");
    }
    text
}

/// The longest window the affected shards were judged by.
fn widest_window(c: &HealthCondition) -> u64 {
    c.shards.iter().map(|s| s.window_secs).max().unwrap_or(0)
}

/// Why a condition of `kind` ended while still observed.
fn ended_reason(kind: ConditionKind) -> &'static str {
    match kind {
        ConditionKind::GlobalStateSyncInstalling => "GLOBAL state installed",
        ConditionKind::ProverOpsWaitForEpoch => "next epoch started",
        ConditionKind::ShieldsNotAdmitted => "admission frame reached",
        _ => "progress resumed",
    }
}

/// Emit `$($line)*` at the level of `$severity`.
macro_rules! at_severity {
    ($severity:expr, $($line:tt)*) => {
        match ConditionSeverity::try_from($severity) {
            Ok(ConditionSeverity::Error) => error!($($line)*),
            Ok(ConditionSeverity::Info) => info!($($line)*),
            _ => warn!($($line)*),
        }
    };
}

/// Log one transition as one structured line, at the condition's severity:
/// an expected wait starts as info, and warns once it overruns.
pub fn log_transition(transition: &Transition) {
    match transition {
        Transition::Started {
            condition: c,
            log_evidence,
        } => {
            at_severity!(c.severity, condition = kind_label(c.kind), scope = scope_label(c.scope),
                affected = c.affected, tracked = c.tracked, shards = %shard_names(c),
                widest_window_secs = widest_window(c), evidence = log_evidence.as_deref(),
                action = action_text(c.action),
                text = %notice_text(c), "health condition started");
        }
        Transition::Lasting {
            condition: c,
            duration_ms,
            clear_spells,
            unserved_ms,
            log_evidence,
        } => {
            at_severity!(c.severity, condition = kind_label(c.kind), scope = scope_label(c.scope),
                affected = c.affected, tracked = c.tracked, shards = %shard_names(c),
                widest_window_secs = widest_window(c), duration_secs = duration_ms / 1000,
                clear_spells, unserved_secs = unserved_ms / 1000,
                evidence = log_evidence.as_deref(),
                action = action_text(c.action), text = %notice_text(c),
                "health condition lasting");
        }
        Transition::Overran {
            condition: c,
            duration_ms,
        } => {
            warn!(condition = kind_label(c.kind), scope = scope_label(c.scope),
                duration_secs = duration_ms / 1000,
                expected_secs = c.wait.as_ref().map_or(0, |w| w.expected_secs),
                action = action_text(c.action), text = %notice_text(c),
                "health condition overran its expected wait");
        }
        Transition::Ended {
            kind,
            duration_ms,
            clear_ms,
            clear_spells,
            unserved_ms,
            unobserved,
        } => {
            info!(
                condition = kind_label(*kind as i32),
                duration_secs = duration_ms / 1000,
                clear_secs = clear_ms / 1000,
                clear_spells,
                unserved_secs = unserved_ms / 1000,
                reason = if *unobserved {
                    "no fresh observations"
                } else {
                    ended_reason(*kind)
                },
                "health condition ended"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000_000;

    fn cadence(now_ms: u64, hour: Option<(u64, u64)>, day: Option<(u64, u64)>) -> FrameCadence {
        let window = |seconds, (observed_seconds, advanced_frames)| FrameWindow {
            window_seconds: seconds,
            observed_seconds,
            advanced_frames,
        };
        FrameCadence {
            last_observed_unix_seconds: now_ms / 1000,
            hour: hour.map(|h| window(3600, h)),
            day: day.map(|d| window(86_400, d)),
        }
    }

    fn peer(filter: u8, frame: u64) -> PeerObservation {
        PeerObservation {
            filter: vec![filter],
            latest_frame: frame,
            active_provers: 3,
            generation: Some(1),
            ..Default::default()
        }
    }

    fn worker(core_id: u32, filter: u8, now_ms: u64, last_advance: u64) -> WorkerObservation {
        WorkerObservation {
            core_id,
            filter: vec![filter],
            earning: true,
            state: "serving".into(),
            observed_unix_ms: now_ms,
            materialized_frame: Some(500),
            last_advance_unix_ms: last_advance,
            ..Default::default()
        }
    }

    fn affected(reg: &HealthRegistry, kind: ConditionKind) -> Option<(u32, u32)> {
        reg.snapshot()
            .conditions
            .iter()
            .find(|c| c.kind == kind as i32)
            .map(|c| (c.affected, c.tracked))
    }

    /// Three of the shard's mean frame intervals, never under the base
    /// window; without a fresh cadence the base window.
    #[test]
    fn stall_window_scales_with_the_shard_cadence() {
        let now = T0 / 1000;
        // 150 s mean: 450 s.
        let slow = cadence(T0, Some((3000, 20)), None);
        assert_eq!(stall_window_ms(Some(&slow), now), 450_000);
        // 10 s mean: the base window.
        let fast = cadence(T0, Some((600, 60)), None);
        assert_eq!(stall_window_ms(Some(&fast), now), BASE_WINDOW_MS);
        assert_eq!(stall_window_ms(None, now), BASE_WINDOW_MS);
        // Sampled over 90 s ago: not fresh.
        assert_eq!(stall_window_ms(Some(&slow), now + 91), BASE_WINDOW_MS);
        // No advance in the hour: the day's mean alone.
        let halted = cadence(T0, Some((3600, 0)), Some((86_400, 576)));
        assert_eq!(stall_window_ms(Some(&halted), now), 450_000);
    }

    /// The shorter fresh mean counts, so a stall that inflates the 60m mean
    /// is bounded by the 24h one.
    #[test]
    fn stall_window_uses_the_shorter_fresh_mean() {
        let now = T0 / 1000;
        // 60m: 600 s mean (1800 s window); 24h: 150 s mean (450 s window).
        let c = cadence(T0, Some((3600, 6)), Some((86_400, 576)));
        assert_eq!(stall_window_ms(Some(&c), now), 450_000);
    }

    /// A 150 s shard is not stalled between frames; a fast shard and one
    /// without a cadence are after 60 s.
    #[test]
    fn peer_stall_is_judged_by_each_shard_window() {
        let mut reg = HealthRegistry::default();
        let slow = cadence(T0, Some((3000, 20)), None);
        let cad = move |f: &[u8]| (f == [1]).then_some(slow);
        let rows = [peer(1, 10), peer(2, 20)];
        for secs in (0..=100).step_by(20) {
            let now = T0 + secs * 1000;
            reg.observe_peers(&rows, now);
            // The test's cadence is pinned to T0: keep it fresh.
            let c = cad;
            let cadence = move |f: &[u8]| {
                c(f).map(|mut x| {
                    x.last_observed_unix_seconds = now / 1000;
                    x
                })
            };
            reg.evaluate(now, &cadence);
        }
        assert_eq!(
            affected(&reg, ConditionKind::PeerAppFramesUnchanged),
            Some((1, 2))
        );
        let c = reg.snapshot();
        let peer_condition = c
            .conditions
            .iter()
            .find(|c| c.kind == ConditionKind::PeerAppFramesUnchanged as i32)
            .unwrap();
        assert_eq!(peer_condition.shards[0].filter, vec![2]);
        assert_eq!(peer_condition.shards[0].window_secs, 60);
        for secs in (120..=480).step_by(20) {
            let now = T0 + secs * 1000;
            reg.observe_peers(&rows, now);
            let c = cad;
            let cadence = move |f: &[u8]| {
                c(f).map(|mut x| {
                    x.last_observed_unix_seconds = now / 1000;
                    x
                })
            };
            reg.evaluate(now, &cadence);
            let slow_flagged =
                affected(&reg, ConditionKind::PeerAppFramesUnchanged) == Some((2, 2));
            assert_eq!(slow_flagged, secs >= 460, "at {secs}s");
        }
    }

    /// A gap longer than the observation gap restarts the clock, and an
    /// unchanged span counts only to the latest observation.
    #[test]
    fn peer_stall_needs_continuous_observations() {
        let mut reg = HealthRegistry::default();
        let none = |_: &[u8]| None;
        reg.observe_peers(&[peer(1, 10)], T0);
        reg.evaluate(T0 + 59_000, &none);
        assert_eq!(affected(&reg, ConditionKind::PeerAppFramesUnchanged), None);
        reg.observe_peers(&[peer(1, 10)], T0 + 59_000);
        // Observed 59 s unchanged, judged at 100 s: not yet.
        reg.evaluate(T0 + 100_000, &none);
        assert_eq!(affected(&reg, ConditionKind::PeerAppFramesUnchanged), None);
        // After a 160 s gap the clock restarts.
        reg.observe_peers(&[peer(1, 10)], T0 + 219_000);
        reg.evaluate(T0 + 219_000, &none);
        assert_eq!(affected(&reg, ConditionKind::PeerAppFramesUnchanged), None);
        reg.observe_peers(&[peer(1, 10)], T0 + 279_000);
        reg.evaluate(T0 + 279_000, &none);
        assert_eq!(
            affected(&reg, ConditionKind::PeerAppFramesUnchanged),
            Some((1, 1))
        );
    }

    /// Only fresh, earning workers in frame-advancing phases count; each
    /// is judged by its shard's window.
    #[test]
    fn local_stall_judges_earning_workers_by_their_shard_window() {
        let mut reg = HealthRegistry::default();
        let now = T0 + 300_000;
        let slow = cadence(now, Some((3000, 20)), None);
        let cad = move |f: &[u8]| (f == [1]).then_some(slow);
        let mut syncing = worker(3, 3, now, T0);
        syncing.state = "syncing".into();
        let mut idle = worker(4, 4, now, T0);
        idle.earning = false;
        let stale = worker(5, 5, now - 31_000, T0);
        let mut handoff = worker(6, 6, now, T0);
        handoff.state = "blocked".into();
        handoff.blocker = "awaiting successor".into();
        reg.observe_workers(
            vec![
                // 300 s without an advance on a 450 s shard: not stalled.
                worker(1, 1, now, T0),
                // 300 s on a shard without a cadence: stalled.
                worker(2, 2, now, T0),
                syncing,
                idle,
                stale,
                handoff,
            ],
            now,
        );
        reg.evaluate(now, &cad);
        assert_eq!(
            affected(&reg, ConditionKind::LocalAppFramesUnchanged),
            Some((1, 2))
        );
        let snapshot = reg.snapshot();
        let c = &snapshot.conditions[0];
        assert_eq!(c.shards[0].core_id, 2);
        assert_eq!(c.scope, ConditionScope::ThisNode as i32);
        assert_eq!(
            notice_text(c),
            "Local app frames unchanged >60s: 1/2 allocations."
        );
    }

    /// A worker that never advanced is judged from when it was first seen.
    #[test]
    fn local_stall_without_an_advance_counts_from_the_first_sighting() {
        let mut reg = HealthRegistry::default();
        let none = |_: &[u8]| None;
        reg.observe_workers(vec![worker(1, 1, T0, 0)], T0);
        reg.evaluate(T0, &none);
        reg.observe_workers(vec![worker(1, 1, T0 + 59_000, 0)], T0 + 59_000);
        reg.evaluate(T0 + 59_000, &none);
        assert_eq!(affected(&reg, ConditionKind::LocalAppFramesUnchanged), None);
        reg.observe_workers(vec![worker(1, 1, T0 + 60_000, 0)], T0 + 60_000);
        reg.evaluate(T0 + 60_000, &none);
        assert_eq!(
            affected(&reg, ConditionKind::LocalAppFramesUnchanged),
            Some((1, 1))
        );
    }

    fn committed(frame: u64, global_frame: u64) -> GlobalAppFrameHead {
        GlobalAppFrameHead {
            frame,
            global_frame,
            generation: 1,
        }
    }

    /// The committed head is unchanged only while GLOBAL and the shard's
    /// app frames both advance; a halted shard is not GLOBAL's lag.
    #[test]
    fn global_stall_needs_global_and_app_progress() {
        let none = |_: &[u8]| None;
        // App frames advance, GLOBAL advances, committed head stays.
        let mut reg = HealthRegistry::default();
        for (i, secs) in [0u64, 30, 60].into_iter().enumerate() {
            let now = T0 + secs * 1000;
            reg.observe_peers(&[peer(1, 100 + i as u64)], now);
            reg.observe_committed(&[(vec![1], committed(90, 1000 + i as u64))], now);
            reg.evaluate(now, &none);
        }
        assert_eq!(
            affected(&reg, ConditionKind::GlobalAppFramesUnchanged),
            Some((1, 1))
        );
        // The shard's app head stays too: no GLOBAL claim.
        let mut halted = HealthRegistry::default();
        for (i, secs) in [0u64, 30, 60].into_iter().enumerate() {
            let now = T0 + secs * 1000;
            halted.observe_peers(&[peer(1, 100)], now);
            halted.observe_committed(&[(vec![1], committed(90, 1000 + i as u64))], now);
            halted.evaluate(now, &none);
        }
        assert_eq!(
            affected(&halted, ConditionKind::GlobalAppFramesUnchanged),
            None
        );
        // GLOBAL stays: no inclusion claim.
        let mut stopped = HealthRegistry::default();
        for (i, secs) in [0u64, 30, 60].into_iter().enumerate() {
            let now = T0 + secs * 1000;
            stopped.observe_peers(&[peer(1, 100 + i as u64)], now);
            stopped.observe_committed(&[(vec![1], committed(90, 1000))], now);
            stopped.evaluate(now, &none);
        }
        assert_eq!(
            affected(&stopped, ConditionKind::GlobalAppFramesUnchanged),
            None
        );
    }

    /// Behind: the committed head trails the app head by over 100 frames.
    #[test]
    fn global_behind_counts_lag_over_the_threshold() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        reg.observe_peers(&[peer(1, 200), peer(2, 201)], T0);
        reg.observe_committed(
            &[
                (vec![1], committed(100, 1000)),
                (vec![2], committed(100, 1000)),
            ],
            T0,
        );
        reg.evaluate(T0, &none);
        let snapshot = reg.snapshot();
        let c = snapshot
            .conditions
            .iter()
            .find(|c| c.kind == ConditionKind::GlobalAppFramesBehind as i32)
            .unwrap();
        assert_eq!((c.affected, c.tracked), (1, 2));
        assert_eq!(c.shards[0].lag_frames, 101);
        assert_eq!(
            notice_text(c),
            "Global app frames >100 behind app heads: 1/2 tracked shards."
        );
    }

    /// A condition logs its start once, lasts through a short clear spell
    /// with its first start time, repeats at most every 10 minutes and ends
    /// after a clear minute; a restart is logged however soon it comes;
    /// stale inputs end it at once.
    #[test]
    fn conditions_start_last_and_end_with_bounded_lines() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        let step = |reg: &mut HealthRegistry, secs: u64, frame: u64| {
            let now = T0 + secs * 1000;
            reg.observe_peers(&[peer(1, frame)], now);
            reg.evaluate(now, &none)
        };
        assert!(step(&mut reg, 0, 10).is_empty());
        let started = step(&mut reg, 60, 10);
        assert!(matches!(started.as_slice(), [Transition::Started { .. }]));
        let since = reg.snapshot().conditions[0].since_unix_ms;
        // It advances once, then stalls again within the clear hold.
        assert!(step(&mut reg, 75, 11).is_empty());
        assert!(
            reg.snapshot().conditions.is_empty(),
            "clear while it advances"
        );
        assert!(step(&mut reg, 135, 11).is_empty());
        assert_eq!(reg.snapshot().conditions[0].since_unix_ms, since);
        // Lasting lines at most every 10 minutes.
        let mut lasting = 0;
        for secs in (150..=1300).step_by(15) {
            for t in step(&mut reg, secs, 11) {
                assert!(matches!(t, Transition::Lasting { .. }), "{t:?}");
                lasting += 1;
            }
        }
        assert_eq!(lasting, 2);
        // Progress resumes: it ends after a clear minute.
        assert!(step(&mut reg, 1315, 12).is_empty());
        assert!(step(&mut reg, 1330, 13).is_empty());
        let ended = step(&mut reg, 1375, 14);
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: false,
                    ..
                }]
            ),
            "{ended:?}"
        );
        // A start: logged.
        let again = step(&mut reg, 1500, 14);
        assert!(
            matches!(again.as_slice(), [Transition::Started { .. }]),
            "{again:?}"
        );
        assert!(step(&mut reg, 1515, 15).is_empty());
        let ended = step(&mut reg, 1575, 16);
        assert!(
            matches!(ended.as_slice(), [Transition::Ended { .. }]),
            "{ended:?}"
        );
        // A restart within 10 minutes of the last start line: logged too.
        let restart = step(&mut reg, 1650, 16);
        assert!(
            matches!(restart.as_slice(), [Transition::Started { .. }]),
            "a restart is logged: {restart:?}"
        );
        // Inputs go stale: it ends at once, unobserved, never clear first.
        let stale = reg.evaluate(T0 + 1850 * 1000, &none);
        assert!(
            matches!(
                stale.as_slice(),
                [Transition::Ended {
                    unobserved: true,
                    clear_ms: 0,
                    ..
                }]
            ),
            "{stale:?}"
        );
        assert!(reg.snapshot().conditions.is_empty());
        let source = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == ConditionKind::PeerAppFramesUnchanged as i32)
            .unwrap();
        assert_eq!((source.observed_unix_ms, source.tracked), (0, 0));
    }

    /// Every condition served has its start and end line, however soon it
    /// recurs, so a client shows only what the log records. A manager that
    /// polls 90 s of every 5 min feeds the peer heads: each poll window
    /// starts a condition and each gap ends it.
    #[test]
    fn every_served_condition_has_a_start_and_an_end_line() {
        let none = |_: &[u8]| None;
        let kind = ConditionKind::PeerAppFramesUnchanged;
        let mut reg = HealthRegistry::default();
        let (mut open, mut starts, mut ends) = (false, 0, 0);
        for secs in (0..3600u64).step_by(15) {
            let now = T0 + secs * 1000;
            if secs % 300 < 90 {
                reg.observe_peers(&[peer(1, 10)], now);
            }
            for t in reg.evaluate(now, &none) {
                match t {
                    Transition::Started { condition, .. } if condition.kind == kind as i32 => {
                        assert!(!open, "a second start line at {secs}s");
                        open = true;
                        starts += 1;
                    }
                    Transition::Ended { kind: k, .. } if k == kind => {
                        assert!(open, "an end line without a start at {secs}s");
                        open = false;
                        ends += 1;
                    }
                    _ => {}
                }
            }
            let served = affected(&reg, kind).is_some();
            assert!(!served || open, "served without a start line at {secs}s");
        }
        assert_eq!(
            (starts, ends),
            (12, 12),
            "one start and end per poll window"
        );
    }

    /// An end line's duration runs from its start line to it, and it names
    /// how long the condition was clear, and so not served, before it ended.
    #[test]
    fn an_end_line_spans_from_its_start_and_names_its_clear_spell() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        let mut lines = Vec::new();
        for secs in (0..=165u64).step_by(15) {
            let now = T0 + secs * 1000;
            // Unchanged to 75 s (a start at 60 s), then advancing from 90 s.
            let frame = if secs < 90 { 10 } else { secs };
            reg.observe_peers(&[peer(1, frame)], now);
            lines.extend(reg.evaluate(now, &none));
        }
        let ended: Vec<_> = lines
            .iter()
            .filter_map(|t| match t {
                Transition::Ended {
                    duration_ms,
                    clear_ms,
                    ..
                } => Some((*duration_ms, *clear_ms)),
                _ => None,
            })
            .collect();
        // Started at 60 s, clear from 90 s, ended at 150 s.
        assert_eq!(
            ended,
            vec![(90_000, 60_000)],
            "the end line's duration from its start and its clear spell"
        );
    }

    /// A condition is not served while clear. One that recurs within its
    /// clear hold continues under its first start without a line, and its
    /// lasting and end lines count those clear spells and their length, so
    /// the log accounts for each time a client showed nothing.
    #[test]
    fn an_end_line_counts_the_clear_spells_a_condition_was_not_served() {
        let none = |_: &[u8]| None;
        let kind = ConditionKind::LocalAppFramesUnchanged;
        let mut reg = HealthRegistry::default();
        let mut step = |secs: u64, advanced: u64| {
            let now = T0 + secs * 1000;
            reg.observe_workers(vec![worker(1, 1, now, T0 + advanced * 1000)], now);
            let lines = reg.evaluate(now, &none);
            (lines, reg.snapshot())
        };
        let served = |s: &HealthConditions| {
            s.conditions
                .iter()
                .find(|c| c.kind == kind as i32)
                .map(|c| c.since_unix_ms)
        };
        let (lines, _) = step(45, 0);
        assert!(lines.is_empty(), "{lines:?}");
        let (lines, s) = step(60, 0);
        assert!(matches!(lines.as_slice(), [Transition::Started { .. }]));
        let since = served(&s).unwrap();
        // An advance at 30 s, first reported at 75 s: clear for 15 s.
        let (lines, s) = step(75, 30);
        assert!(lines.is_empty(), "{lines:?}");
        assert_eq!(served(&s), None, "not served while clear at 75s");
        // Unchanged 60 s at 90 s: served again under its first start.
        let (lines, s) = step(90, 30);
        assert!(lines.is_empty(), "a recurrence adds no line: {lines:?}");
        assert_eq!(served(&s), Some(since), "served under its first start");
        let mut lasting = Vec::new();
        for secs in (105..=690).step_by(15) {
            let (lines, s) = step(secs, 30);
            assert_eq!(served(&s), Some(since), "served at {secs}s");
            lasting.extend(lines.into_iter().filter_map(|t| match t {
                Transition::Lasting {
                    clear_spells,
                    unserved_ms,
                    ..
                } => Some((clear_spells, unserved_ms)),
                _ => None,
            }));
        }
        assert_eq!(
            lasting,
            vec![(1, 15_000)],
            "the lasting line counts the unserved spell so far"
        );
        // Progress resumes at 705 s: clear, and ended after 60 s clear.
        for secs in (705..=750).step_by(15) {
            let (lines, s) = step(secs, secs);
            assert!(lines.is_empty(), "{lines:?}");
            assert_eq!(served(&s), None, "not served while clear at {secs}s");
        }
        let (lines, s) = step(765, 765);
        assert_eq!(served(&s), None);
        let ended: Vec<_> = lines
            .iter()
            .filter_map(|t| match t {
                Transition::Ended {
                    duration_ms,
                    clear_ms,
                    clear_spells,
                    unserved_ms,
                    ..
                } => Some((*duration_ms, *clear_ms, *clear_spells, *unserved_ms)),
                _ => None,
            })
            .collect();
        // Started at 60 s, clear 75-90 s and 705-765 s, ended at 765 s.
        assert_eq!(
            ended,
            vec![(705_000, 60_000, 2, 75_000)],
            "the end line counts each unserved clear spell and their length"
        );
    }

    /// Every kind reports its source, observed or not, and a condition
    /// lists at most 64 shards.
    #[test]
    fn snapshot_reports_every_source_and_bounds_shards() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        let rows: Vec<_> = (0..100u8).map(|f| peer(f, 10)).collect();
        reg.observe_peers(&rows, T0);
        reg.observe_peers(&rows, T0 + 60_000);
        reg.evaluate(T0 + 60_000, &none);
        let snapshot = reg.snapshot();
        assert_eq!(snapshot.sources.len(), KINDS.len());
        let c = &snapshot.conditions[0];
        assert_eq!((c.affected, c.tracked), (100, 100));
        assert_eq!((c.shards.len(), c.omitted_shards), (64, 36));
    }

    /// Filters on one app differ only at their end, so a log line naming
    /// shards by their first bytes would name every shard alike.
    #[test]
    fn a_log_line_tells_shards_of_one_app_apart() {
        let filter = |end: u8| {
            let mut f = vec![0x11; 32];
            f.extend([0x90, end]);
            f
        };
        let condition = HealthCondition {
            affected: 4,
            shards: [0x01, 0x02, 0x03, 0x04]
                .iter()
                .map(|end| AffectedShard {
                    filter: filter(*end),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            shard_names(&condition),
            "111111119001,111111119002,111111119003,+1"
        );
    }

    /// A node on a 720-frame epoch at `head`: no shields, its sync state
    /// unread.
    fn at_head(head: u64) -> GlobalObservation {
        GlobalObservation {
            head_frame: head,
            epoch_length: 720,
            shields_from: None,
            sync_installing: None,
        }
    }

    /// `kind`'s current condition.
    fn current(reg: &HealthRegistry, kind: ConditionKind) -> Option<HealthCondition> {
        reg.snapshot()
            .conditions
            .into_iter()
            .find(|c| c.kind == kind as i32)
    }

    /// `kind`'s source: when it was observed and what it tracks.
    fn source_of(reg: &HealthRegistry, kind: ConditionKind) -> (u64, u32) {
        let s = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == kind as i32)
            .expect("every kind reports its source");
        (s.observed_unix_ms, s.tracked)
    }

    /// Only an epoch's last frames hold prover ops, where one may land in
    /// the next epoch: the freshness window on a mainnet epoch, half of a
    /// short devnet one; nothing without a head or an epoch length.
    #[test]
    fn only_the_end_of_an_epoch_holds_prover_ops() {
        assert_eq!(PROVER_OP_MARGIN_FRAMES, 10);
        assert_eq!(epoch_end_frames_left(720 - 11, 720), None);
        assert_eq!(epoch_end_frames_left(720 - 10, 720), Some(10));
        assert_eq!(epoch_end_frames_left(719, 720), Some(1));
        assert_eq!(epoch_end_frames_left(720, 720), None);
        assert_eq!(epoch_end_frames_left(89, 30), Some(1));
        assert_eq!(epoch_end_frames_left(79, 30), None);
        assert_eq!(epoch_end_frames_left(80, 30), Some(10));
        assert_eq!(epoch_end_frames_left(4, 10), None);
        assert_eq!(epoch_end_frames_left(5, 10), Some(5));
        assert_eq!(epoch_end_frames_left(0, 720), None);
        assert_eq!(epoch_end_frames_left(719, 0), None);
    }

    /// The epoch-end wait is an info condition naming the frame that ends
    /// it, judged on the head as a report is served, and it ends with the
    /// epoch; a frame-bound wait within its expected time never repeats.
    #[test]
    fn prover_ops_wait_for_the_next_epoch_as_an_expected_wait() {
        let kind = ConditionKind::ProverOpsWaitForEpoch;
        let mut reg = HealthRegistry::default();
        assert!(reg.refresh_waits(at_head(709), T0).is_empty());
        assert!(current(&reg, kind).is_none());
        assert_eq!(source_of(&reg, kind), (T0, 1));
        let started = reg.refresh_waits(at_head(712), T0 + 1_000);
        assert!(
            matches!(started.as_slice(), [Transition::Started { .. }]),
            "{started:?}"
        );
        let c = current(&reg, kind).expect("ops wait");
        assert_eq!(c.severity, ConditionSeverity::Info as i32);
        assert_eq!(c.scope, ConditionScope::Network as i32);
        assert_eq!(c.action, ConditionAction::WaitForNextEpoch as i32);
        assert_eq!((c.affected, c.tracked, c.threshold), (1, 1, 10));
        assert_eq!(
            c.wait,
            Some(ExpectedWait {
                head_frame: 712,
                until_frame: 720,
                batch_from_frame: 0,
                expected_secs: 600,
            })
        );
        assert_eq!(
            notice_text(&c),
            "Prover ops wait for the next epoch: it starts at frame 720 (8 frames)."
        );
        // Judged on the tick too, with no lines while it lasts as expected.
        for secs in [15, 30, 45, 60, 75] {
            let now = T0 + secs * 1000;
            reg.observe_global(at_head(712 + secs / 15), now);
            assert!(reg.evaluate(now, &|_: &[u8]| None).is_empty());
        }
        // The next epoch: gone from the report at once, ended after the
        // clear hold with its reason.
        assert!(reg.refresh_waits(at_head(720), T0 + 90_000).is_empty());
        assert!(current(&reg, kind).is_none());
        let ended = reg.refresh_waits(at_head(726), T0 + 150_000);
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: false,
                    ..
                }]
            ),
            "{ended:?}"
        );
        assert_eq!(ended_reason(kind), "next epoch started");
        // Without a head nothing is judged.
        let mut unknown = HealthRegistry::default();
        unknown.refresh_waits(at_head(0), T0);
        assert_eq!(source_of(&unknown, kind), (0, 0));
    }

    /// Observe a GLOBAL state sync `installing` at `secs` and judge; the
    /// transitions to log.
    fn sync_at(reg: &mut HealthRegistry, secs: u64, installing: bool) -> Vec<Transition> {
        let now = T0 + secs * 1000;
        reg.observe_global(
            GlobalObservation {
                sync_installing: Some(installing),
                ..at_head(700)
            },
            now,
        );
        reg.evaluate(now, &|_: &[u8]| None)
    }

    /// A GLOBAL state sync's install is an info condition of this node that
    /// names the event ending it, and ends after the clear hold once the
    /// last chunk is in. An unreadable sync state establishes nothing.
    #[test]
    fn a_global_state_sync_install_is_an_expected_wait() {
        let kind = ConditionKind::GlobalStateSyncInstalling;
        let mut reg = HealthRegistry::default();
        assert!(sync_at(&mut reg, 0, false).is_empty());
        assert_eq!(source_of(&reg, kind), (T0, 1));
        let started = sync_at(&mut reg, 15, true);
        assert!(
            matches!(started.as_slice(), [Transition::Started { .. }]),
            "{started:?}"
        );
        let c = current(&reg, kind).expect("installing");
        assert_eq!(c.severity, ConditionSeverity::Info as i32);
        assert_eq!(c.scope, ConditionScope::ThisNode as i32);
        assert_eq!(c.action, ConditionAction::WaitForGlobalSync as i32);
        assert_eq!(c.wait.map(|w| w.expected_secs), Some(600));
        assert_eq!(
            notice_text(&c),
            "GLOBAL state sync installing: committed shard heads show again once its last \
             chunk is in."
        );
        for secs in [30, 45, 60, 75, 90] {
            assert!(sync_at(&mut reg, secs, true).is_empty());
        }
        // The last chunk is in: gone from the report, ended after the hold.
        assert!(sync_at(&mut reg, 105, false).is_empty());
        assert!(current(&reg, kind).is_none());
        let mut ended = Vec::new();
        for secs in [120, 135, 150, 165] {
            ended.extend(sync_at(&mut reg, secs, false));
        }
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: false,
                    ..
                }]
            ),
            "{ended:?}"
        );
        assert_eq!(ended_reason(kind), "GLOBAL state installed");
        let mut unread = HealthRegistry::default();
        unread.refresh_waits(at_head(700), T0);
        assert!(current(&unread, kind).is_none());
        assert_eq!(source_of(&unread, kind), (0, 0));
    }

    /// An expected wait lasting past its expected time warns once, then
    /// repeats every 10 minutes; before that it logs nothing while it
    /// lasts.
    #[test]
    fn an_expected_wait_warns_once_it_overruns() {
        let mut reg = HealthRegistry::default();
        let mut shape = Vec::new();
        for secs in (0..=1800).step_by(15) {
            for t in sync_at(&mut reg, secs, true) {
                let name = match t {
                    Transition::Started { .. } => "started",
                    Transition::Overran { .. } => "overran",
                    Transition::Lasting { .. } => "lasting",
                    Transition::Ended { .. } => "ended",
                };
                shape.push((secs, name));
            }
        }
        assert_eq!(
            shape,
            [
                (0, "started"),
                (600, "overran"),
                (1200, "lasting"),
                (1800, "lasting")
            ]
        );
        let c = current(&reg, ConditionKind::GlobalStateSyncInstalling).unwrap();
        assert_eq!(c.since_unix_ms, T0);
    }

    /// A wait past its expected time is a warning and says so; it started
    /// as info.
    #[test]
    fn an_overrun_wait_is_a_warning() {
        let kind = ConditionKind::GlobalStateSyncInstalling;
        let mut reg = HealthRegistry::default();
        sync_at(&mut reg, 0, true);
        assert_eq!(
            current(&reg, kind).map(|c| c.severity),
            Some(ConditionSeverity::Info as i32)
        );
        for secs in (15..=1500).step_by(15) {
            sync_at(&mut reg, secs, true);
        }
        let c = current(&reg, kind).expect("still installing");
        assert_eq!(c.severity, ConditionSeverity::Warning as i32);
        assert_eq!(
            notice_text(&c),
            "GLOBAL state sync installing >10m: committed GLOBAL state stays unreadable until \
             its last chunk is in."
        );
    }

    /// Shields wait for their admission frame, batches for the later one,
    /// with no overrun and no repeat however long; stale inputs end it at
    /// once.
    #[test]
    fn shields_wait_for_their_admission_frame() {
        let kind = ConditionKind::ShieldsNotAdmitted;
        let shields = |head, from| GlobalObservation {
            shields_from: from,
            ..at_head(head)
        };
        let mut reg = HealthRegistry::default();
        let started = reg.refresh_waits(shields(950, Some((900, 1000))), T0);
        assert!(matches!(started.as_slice(), [Transition::Started { .. }]));
        let c = current(&reg, kind).expect("not admitted");
        assert_eq!(c.severity, ConditionSeverity::Info as i32);
        assert_eq!(c.scope, ConditionScope::Network as i32);
        assert_eq!(c.action, ConditionAction::WaitForShieldAdmission as i32);
        assert_eq!(
            c.wait,
            Some(ExpectedWait {
                head_frame: 950,
                until_frame: 900,
                batch_from_frame: 1000,
                expected_secs: 0,
            })
        );
        assert_eq!(
            notice_text(&c),
            "Legacy coin shields admitted from GLOBAL frame 900, batches from 1000: 50 frames to \
             go."
        );
        for hour in 1..=24 {
            let lines = reg.refresh_waits(shields(990, Some((900, 1000))), T0 + hour * 3_600_000);
            assert!(lines.is_empty(), "{lines:?}");
        }
        assert_eq!(
            current(&reg, kind).map(|c| c.severity),
            Some(ConditionSeverity::Info as i32)
        );
        let now = T0 + 25 * 3_600_000;
        reg.refresh_waits(shields(1000, Some((900, 1000))), now);
        assert!(current(&reg, kind).is_none(), "admitted at the batch frame");
        let mut one = HealthRegistry::default();
        one.refresh_waits(shields(10, Some((50, 50))), T0);
        assert_eq!(
            current(&one, kind).map(|c| notice_text(&c)).as_deref(),
            Some("Legacy coin shields admitted from GLOBAL frame 50: 40 frames to go.")
        );
        let ended = one.evaluate(T0 + OBSERVATION_GAP_MS + 1, &|_: &[u8]| None);
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: true,
                    ..
                }]
            ),
            "{ended:?}"
        );
    }

    /// A network that sets no admission frame for either shield, or a
    /// build that admits none, has no wait to track.
    #[test]
    fn shields_track_nothing_without_admission_frames() {
        let kind = ConditionKind::ShieldsNotAdmitted;
        for from in [None, Some((u64::MAX, u64::MAX)), Some((50, u64::MAX))] {
            let mut reg = HealthRegistry::default();
            reg.refresh_waits(
                GlobalObservation {
                    shields_from: from,
                    ..at_head(10)
                },
                T0,
            );
            assert!(current(&reg, kind).is_none(), "{from:?}");
            assert_eq!(source_of(&reg, kind), (T0, 0), "{from:?}");
        }
    }

    fn reach(reachable: usize, stall_secs: u64) -> GlobalReach {
        GlobalReach {
            provers: 4,
            reachable,
            quorum: 3,
            unreachable: (reachable..4).map(|m| format!("…member{m}")).collect(),
            stall_after: std::time::Duration::from_secs(stall_secs),
        }
    }

    /// GLOBAL's head unchanged for 120 s, as far as it was observed, is an
    /// error of the network; an advance clears it.
    #[test]
    fn global_head_unchanged_starts_after_its_window() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        for secs in (0..=105).step_by(15) {
            let now = T0 + secs * 1000;
            reg.observe_global_head(5_000, None, now);
            assert!(reg.evaluate(now, &none).is_empty(), "at {secs}s");
        }
        let now = T0 + 120_000;
        reg.observe_global_head(5_000, None, now);
        let started = reg.evaluate(now, &none);
        assert!(
            matches!(
                started.as_slice(),
                [Transition::Started {
                    log_evidence: None,
                    ..
                }]
            ),
            "{started:?}"
        );
        let snapshot = reg.snapshot();
        let c = &snapshot.conditions[0];
        assert_eq!(
            (c.kind, c.severity, c.scope, c.action, c.threshold),
            (
                ConditionKind::GlobalHeadUnchanged as i32,
                ConditionSeverity::Error as i32,
                ConditionScope::Network as i32,
                ConditionAction::CheckGlobalHead as i32,
                120
            )
        );
        assert_eq!(c.shards[0].unchanged_since_unix_ms, T0);
        assert_eq!(
            c.global.as_ref().map(|g| (g.head, g.span_secs, g.provers)),
            Some((5_000, 120, 0))
        );
        assert_eq!(notice_text(c), "Global head unchanged >120s.");
        assert_eq!(shard_names(c), "global");
        reg.observe_global_head(5_001, None, now + 15_000);
        reg.evaluate(now + 15_000, &none);
        assert!(reg.snapshot().conditions.is_empty());
    }

    /// On a GLOBAL prover the window is four of its leader timeouts, the
    /// notice counts the provers it hears against the quorum, and only the
    /// log names the silent ones.
    #[test]
    fn a_global_prover_judges_by_its_leader_timeout_and_counts_the_provers_heard() {
        let none = |_: &[u8]| None;
        let run = |reachable: usize| {
            let mut reg = HealthRegistry::default();
            let mut transitions = Vec::new();
            for secs in (0..=255).step_by(15) {
                let now = T0 + secs * 1000;
                reg.observe_global_head(5_000, Some(reach(reachable, 240)), now);
                let changes = reg.evaluate(now, &none);
                assert!(secs >= 240 || changes.is_empty(), "at {secs}s: {changes:?}");
                transitions.extend(changes);
            }
            (reg.snapshot().conditions, transitions)
        };
        let (conditions, transitions) = run(2);
        assert_eq!(
            notice_text(&conditions[0]),
            "Global head unchanged >240s: 2 of 4 GLOBAL provers reachable, 3 needed."
        );
        assert!(
            matches!(
                transitions.as_slice(),
                [Transition::Started { log_evidence: Some(names), .. }]
                    if names == "…member2, …member3"
            ),
            "{transitions:?}"
        );
        let (conditions, _) = run(3);
        assert_eq!(
            notice_text(&conditions[0]),
            "Global head unchanged >240s although 3 of 4 GLOBAL provers are reachable (3 needed)."
        );
    }

    /// Under 330 frames an hour is slow once 10 minutes are observed; 330
    /// is not.
    #[test]
    fn global_frames_slow_needs_ten_minutes_under_330_an_hour() {
        let none = |_: &[u8]| None;
        // `frames` every 120 s: 11 make 330 an hour, 10 make 300.
        let run = |frames: u64, until: u64| {
            let mut reg = HealthRegistry::default();
            for step in 0..=until / 120 {
                let now = T0 + step * 120_000;
                reg.observe_global_head(1_000 + step * frames, None, now);
                reg.evaluate(now, &none);
            }
            reg.snapshot().conditions
        };
        assert!(run(10, 480).is_empty(), "judged before 10 minutes");
        assert!(run(11, 3_600).is_empty(), "330 an hour is not slow");
        let slow = run(10, 600);
        assert_eq!(slow.len(), 1);
        assert_eq!(
            (slow[0].kind, slow[0].severity, slow[0].threshold),
            (
                ConditionKind::GlobalFramesSlow as i32,
                ConditionSeverity::Warning as i32,
                GLOBAL_MIN_FRAMES_PER_HOUR
            )
        );
        assert_eq!(
            notice_text(&slow[0]),
            "Global frames slow: 50 in 10 min (~300/h, below 330/h)."
        );
    }

    /// A stall is one condition while it lasts; after it the hour's rate
    /// shows it, so a stall between two of a reader's reads still shows.
    #[test]
    fn a_global_stall_then_shows_in_the_hourly_rate() {
        let none = |_: &[u8]| None;
        // One frame per 10 s for 20 min, standing still for 5 min, then on.
        let head = |secs: u64| {
            1_000
                + match secs {
                    s if s < 1_200 => s / 10,
                    s if s < 1_500 => 120,
                    s => 120 + (s - 1_500) / 10,
                }
        };
        let mut reg = HealthRegistry::default();
        let mut kinds = HashMap::new();
        for secs in (0..=1_530).step_by(15) {
            let now = T0 + secs * 1000;
            reg.observe_global_head(head(secs), None, now);
            reg.evaluate(now, &none);
            let current: Vec<i32> = reg.snapshot().conditions.iter().map(|c| c.kind).collect();
            kinds.insert(secs, current);
        }
        assert_eq!(kinds[&1_185], Vec::<i32>::new());
        assert_eq!(kinds[&1_485], [ConditionKind::GlobalHeadUnchanged as i32]);
        assert_eq!(kinds[&1_515], [ConditionKind::GlobalFramesSlow as i32]);
    }

    /// A paced shield pauses for the worst GLOBAL progress condition and for
    /// no other kind.
    #[test]
    fn the_global_progress_notice_is_the_worst_global_condition() {
        let condition = |kind: ConditionKind, severity: ConditionSeverity| HealthCondition {
            kind: kind as i32,
            severity: severity as i32,
            threshold: 120,
            global: Some(GlobalProgress {
                advanced_frames: 50,
                span_secs: 600,
                ..Default::default()
            }),
            ..Default::default()
        };
        let local = condition(
            ConditionKind::LocalAppFramesUnchanged,
            ConditionSeverity::Warning,
        );
        let mut health = HealthConditions {
            conditions: vec![
                condition(ConditionKind::GlobalHeadUnchanged, ConditionSeverity::Error),
                local.clone(),
                condition(ConditionKind::GlobalFramesSlow, ConditionSeverity::Warning),
            ],
            sources: Vec::new(),
        };
        assert_eq!(
            global_progress_notice(&health).as_deref(),
            Some("Global head unchanged >120s")
        );
        health.conditions = vec![local];
        assert_eq!(global_progress_notice(&health), None);
    }

    /// Without a fresh GLOBAL observation the GLOBAL kinds end, unobserved.
    #[test]
    fn global_conditions_end_without_fresh_observations() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        for secs in (0..=135).step_by(15) {
            let now = T0 + secs * 1000;
            reg.observe_global_head(5_000, None, now);
            reg.evaluate(now, &none);
        }
        assert!(affected(&reg, ConditionKind::GlobalHeadUnchanged).is_some());
        let ended = reg.evaluate(T0 + 295_000, &none);
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: true,
                    ..
                }]
            ),
            "{ended:?}"
        );
        let source = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == ConditionKind::GlobalHeadUnchanged as i32)
            .unwrap();
        assert_eq!((source.observed_unix_ms, source.tracked), (0, 0));
    }
}
