//! The health conditions this node detects, served in its health report.
//!
//! The node owns each condition: it detects it from its own observations,
//! gives it a severity, a scope (this node, a peer, the network), its
//! evidence and the operator's next check, logs it when it starts, at most
//! every [`REPEAT_INTERVAL_MS`] while it lasts and when it ends, and serves
//! the current ones in [`HealthConditions`]. Clients only render them.
//!
//! Missing or old observations establish no condition: a shard's clock
//! restarts after a gap of [`OBSERVATION_GAP_MS`], an unchanged span counts
//! only up to the latest observation, and a kind without fresh
//! observations reports nothing and ends what it reported.
//!
//! Evidence is safe to serve to an allowlisted peer: public shard filters,
//! worker core numbers, frames, counts and times, never addresses, keys,
//! paths or peer IDs.

use std::collections::{BTreeMap, HashMap};

use quil_types::proto::diagnostics::{
    AffectedShard, ConditionAction, ConditionKind, ConditionScope, ConditionSeverity,
    ConditionSource, HealthCondition, HealthConditions,
};
use quil_types::proto::node::{FrameCadence, FrameWindow, GlobalAppFrameHead};
use tracing::{info, warn};

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
/// How often a lasting condition is logged again, and the shortest spacing
/// of two start lines of one kind.
pub const REPEAT_INTERVAL_MS: u64 = 10 * 60_000;
/// A condition clear this long ends; one that recurs sooner continues.
pub const CLEAR_HOLD_MS: u64 = 60_000;
/// A cadence sampled longer ago than this is not fresh.
const CADENCE_FRESH_SECS: u64 = 90;

/// Every kind this build judges.
pub const KINDS: [ConditionKind; 4] = [
    ConditionKind::LocalAppFramesUnchanged,
    ConditionKind::PeerAppFramesUnchanged,
    ConditionKind::GlobalAppFramesUnchanged,
    ConditionKind::GlobalAppFramesBehind,
];

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

#[derive(Debug, Clone)]
struct Current {
    since_ms: u64,
    last_logged_ms: u64,
    clear_since_ms: Option<u64>,
    /// Whether its start was logged: a start within the repeat interval of
    /// the kind's last start line is counted instead, and so is its end.
    logged: bool,
    condition: HealthCondition,
}

/// A change of a condition, to be logged.
#[derive(Debug, Clone, PartialEq)]
pub enum Transition {
    Started {
        condition: HealthCondition,
        /// Starts and ends of this kind not logged since its last line.
        unlogged: u32,
    },
    Lasting {
        condition: HealthCondition,
        duration_ms: u64,
        unlogged: u32,
    },
    Ended {
        kind: ConditionKind,
        duration_ms: u64,
        /// Its inputs went stale rather than the progress resuming.
        unobserved: bool,
        unlogged: u32,
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
    /// When each judged worker without an advance was first judged.
    worker_first_seen: HashMap<(u32, Vec<u8>), u64>,
    current: BTreeMap<i32, Current>,
    last_start_logged_ms: HashMap<i32, u64>,
    unlogged: HashMap<i32, u32>,
    sources: Vec<ConditionSource>,
}

fn severity_of(_kind: ConditionKind) -> ConditionSeverity {
    ConditionSeverity::Warning
}

fn scope_of(kind: ConditionKind) -> ConditionScope {
    match kind {
        ConditionKind::LocalAppFramesUnchanged => ConditionScope::ThisNode,
        ConditionKind::PeerAppFramesUnchanged => ConditionScope::Peer,
        _ => ConditionScope::Network,
    }
}

fn action_of(kind: ConditionKind) -> ConditionAction {
    match kind {
        ConditionKind::LocalAppFramesUnchanged => ConditionAction::CheckWorkerLogs,
        ConditionKind::PeerAppFramesUnchanged => ConditionAction::ComparePeerWithExplorer,
        _ => ConditionAction::CheckGlobalInclusion,
    }
}

/// One kind's judgement in an evaluation.
struct Judged {
    kind: ConditionKind,
    shards: Vec<AffectedShard>,
    tracked: u32,
    observed_unix_ms: u64,
    threshold: u64,
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
            },
            Judged {
                kind: ConditionKind::PeerAppFramesUnchanged,
                shards: peer,
                tracked: peer_tracked,
                observed_unix_ms: fresh(self.peers_seen_ms),
                threshold: base_secs,
            },
            Judged {
                kind: ConditionKind::GlobalAppFramesUnchanged,
                shards: unchanged,
                tracked: committed_tracked,
                observed_unix_ms: fresh(self.committed_seen_ms),
                threshold: base_secs,
            },
            Judged {
                kind: ConditionKind::GlobalAppFramesBehind,
                shards: behind,
                tracked: committed_tracked,
                observed_unix_ms: fresh(self.committed_seen_ms),
                threshold: GLOBAL_APP_LAG_FRAMES,
            },
        ];
        self.sources.clear();
        let mut transitions = Vec::new();
        for mut judged in judged {
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
            ..
        } = judged;
        let key = kind as i32;
        let affected = shards.len() as u32;
        if affected == 0 {
            let current = self.current.get_mut(&key)?;
            let clear_since = *current.clear_since_ms.get_or_insert(now_ms);
            // Without fresh observations nothing holds it open.
            if tracked > 0 && now_ms.saturating_sub(clear_since) < CLEAR_HOLD_MS {
                return None;
            }
            let current = self.current.remove(&key)?;
            let duration_ms = clear_since.saturating_sub(current.since_ms);
            if !current.logged {
                *self.unlogged.entry(key).or_default() += 1;
                return None;
            }
            return Some(Transition::Ended {
                kind,
                duration_ms,
                unobserved: tracked == 0,
                unlogged: self.unlogged.remove(&key).unwrap_or(0),
            });
        }
        let omitted_shards = shards.len().saturating_sub(MAX_AFFECTED) as u32;
        shards.truncate(MAX_AFFECTED);
        let condition = |since_unix_ms| HealthCondition {
            kind: key,
            severity: severity_of(kind) as i32,
            scope: scope_of(kind) as i32,
            action: action_of(kind) as i32,
            since_unix_ms,
            affected,
            tracked,
            threshold,
            shards,
            omitted_shards,
        };
        if let Some(current) = self.current.get_mut(&key) {
            current.clear_since_ms = None;
            current.condition = condition(current.since_ms);
            if current.logged && now_ms.saturating_sub(current.last_logged_ms) >= REPEAT_INTERVAL_MS
            {
                current.last_logged_ms = now_ms;
                return Some(Transition::Lasting {
                    condition: current.condition.clone(),
                    duration_ms: now_ms.saturating_sub(current.since_ms),
                    unlogged: self.unlogged.remove(&key).unwrap_or(0),
                });
            }
            return None;
        }
        let logged = self
            .last_start_logged_ms
            .get(&key)
            .is_none_or(|at| now_ms.saturating_sub(*at) >= REPEAT_INTERVAL_MS);
        let current = Current {
            since_ms: now_ms,
            last_logged_ms: now_ms,
            clear_since_ms: None,
            logged,
            condition: condition(now_ms),
        };
        let started = current.condition.clone();
        self.current.insert(key, current);
        if !logged {
            *self.unlogged.entry(key).or_default() += 1;
            return None;
        }
        self.last_start_logged_ms.insert(key, now_ms);
        Some(Transition::Started {
            condition: started,
            unlogged: self.unlogged.remove(&key).unwrap_or(0),
        })
    }

    /// The current conditions, worst first, and every kind's source.
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
        ConditionKind::Unspecified => format!(
            "Health condition {} ({}, {}): {affected}/{tracked}; see this node's log.",
            c.kind,
            severity_label(c.severity),
            scope_label(c.scope)
        ),
    }
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
        .map(|s| hex::encode(&s.filter[s.filter.len().saturating_sub(6)..]))
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

/// Log one transition as one structured line.
pub fn log_transition(transition: &Transition) {
    match transition {
        Transition::Started {
            condition: c,
            unlogged,
        } => {
            warn!(condition = kind_label(c.kind), scope = scope_label(c.scope),
                affected = c.affected, tracked = c.tracked, shards = %shard_names(c),
                widest_window_secs = widest_window(c), unlogged_transitions = unlogged,
                action = action_text(c.action), text = %notice_text(c),
                "health condition started");
        }
        Transition::Lasting {
            condition: c,
            duration_ms,
            unlogged,
        } => {
            warn!(condition = kind_label(c.kind), scope = scope_label(c.scope),
                affected = c.affected, tracked = c.tracked, shards = %shard_names(c),
                widest_window_secs = widest_window(c), duration_secs = duration_ms / 1000,
                unlogged_transitions = unlogged, action = action_text(c.action),
                text = %notice_text(c), "health condition lasting");
        }
        Transition::Ended {
            kind,
            duration_ms,
            unobserved,
            unlogged,
        } => {
            info!(
                condition = kind_label(*kind as i32),
                duration_secs = duration_ms / 1000,
                reason = if *unobserved {
                    "no fresh observations"
                } else {
                    "progress resumed"
                },
                unlogged_transitions = unlogged,
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
    /// after a clear minute; stale inputs end it at once.
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
        // Over 10 minutes after the last start line: logged.
        let again = step(&mut reg, 1500, 14);
        assert!(matches!(
            again.as_slice(),
            [Transition::Started { unlogged: 0, .. }]
        ));
        assert!(step(&mut reg, 1515, 15).is_empty());
        let ended = step(&mut reg, 1575, 16);
        assert!(
            matches!(ended.as_slice(), [Transition::Ended { .. }]),
            "{ended:?}"
        );
        // A restart within 10 minutes of the last start line is counted,
        // not logged, and so is its end.
        assert!(step(&mut reg, 1650, 16).is_empty());
        assert!(!reg.snapshot().conditions.is_empty());
        // Inputs go stale: it ends at once, unobserved.
        reg.evaluate(T0 + 1850 * 1000, &none);
        assert!(reg.snapshot().conditions.is_empty());
        let source = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == ConditionKind::PeerAppFramesUnchanged as i32)
            .unwrap();
        assert_eq!((source.observed_unix_ms, source.tracked), (0, 0));
        // The next logged line carries the two unlogged transitions.
        let mut reg2 = reg;
        let start = |reg: &mut HealthRegistry, secs: u64| {
            let now = T0 + secs * 1000;
            reg.observe_peers(&[peer(1, 99)], now);
            reg.evaluate(now, &none)
        };
        start(&mut reg2, 2400);
        let again = start(&mut reg2, 2460);
        assert!(
            matches!(again.as_slice(), [Transition::Started { unlogged: 2, .. }]),
            "{again:?}"
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
}
