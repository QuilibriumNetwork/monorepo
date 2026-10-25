//! Local engine observations, with no allocation or reward inference.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use quil_types::proto::node::{SessionSeal, ShardRecovery, WorkerExecution};

use crate::prover_tree_syncer::{ReplayTurn, ShardRecoveryProgress};
use crate::recovery_turns::{RecoveryKind, MAX_TURN_HOLD};

tokio::task_local! {
    /// The record of the worker whose archive recovery runs on this task.
    static RECOVERING: SharedWorkerExecution;
}

/// Every phase a worker execution record names (`WorkerExecution.state`).
/// Readers outside the engine map these literals, so add a new one here.
pub const STATES: [&str; 9] =
    ["starting", "waiting", "syncing", "serving", "closing", "handoff", "blocked", "stopped", "unknown"];

/// Every reason a record gives for its phase (`WorkerExecution.blocker`),
/// besides none.
pub const BLOCKERS: [&str; 14] = [
    "waiting for transport",
    "restarting consensus host",
    "engine exited",
    "awaiting successor",
    "staging shard data",
    "awaiting closing certificate",
    "awaiting allocation activation",
    "checkpoint mismatch",
    "state unavailable",
    "committee admission unavailable",
    "consensus startup unavailable",
    "session identity unavailable",
    "session state unavailable",
    STORAGE_WRITE_FAILED,
];

/// The blocker of a worker whose own store stopped writing: after a failed
/// write, or below the free-space floor ([`with_store_state`]).
pub const STORAGE_WRITE_FAILED: &str = "storage writes stopped";

/// Every archive recovery phase (`ShardRecovery.phase`).
pub const RECOVERY_PHASES: [&str; 6] = [
    "idle",
    "waiting_for_permit",
    "replaying_frames",
    "fetching_checkpoint",
    "installing_leaves",
    "installing_checkpoint",
];

/// Every class [`failure_class`] gives a failed recovery attempt.
pub const FAILURE_CLASSES: [&str; 6] =
    [NO_ARCHIVE, "connect", "archive_request", "archive_state", "replay_mismatch", "other"];

/// A worker's execution report with its store's state: a worker whose own
/// store refuses writes after a failed write reads as blocked by it, also
/// while it runs no engine, since it cannot progress until the store is
/// reopened, and as stopped by it while the node holds it stopped to reopen
/// the store. `execution` is what its engine reports, if it runs one.
pub fn with_store_state(core_id: u32, execution: Option<WorkerExecution>) -> Option<WorkerExecution> {
    let role = quil_forest::StoreRole::Worker(core_id);
    let state = if quil_forest::storage_health::store_held(role) {
        "stopped"
    } else if quil_forest::storage_health::store_latched(role) {
        "blocked"
    } else {
        return execution;
    };
    let mut execution = execution.unwrap_or_default();
    execution.state = state.into();
    execution.blocker = STORAGE_WRITE_FAILED.into();
    execution.observed_unix_ms = now_ms();
    Some(execution)
}

/// Whether worker `core_id`'s own store has stopped writing: latched after
/// a failed write or below the free-space floor, or held stopped while the
/// node reopens it. Its shard cannot be prepared and it hosts no new seat.
pub fn store_stopped(core_id: u32) -> bool {
    let role = quil_forest::StoreRole::Worker(core_id);
    quil_forest::storage_health::store_held(role) || quil_forest::storage_health::store_latched(role)
}

/// The report of a worker the node holds stopped to reopen its store, for
/// the lifecycle: it cannot host its seat's session, so a long stop lets
/// the seat lapse instead of renewing it for a worker that does not vote.
pub fn held_store_execution(core_id: u32) -> Option<WorkerExecution> {
    quil_forest::storage_health::store_held(quil_forest::StoreRole::Worker(core_id))
        .then(|| with_store_state(core_id, None))
        .flatten()
}

/// `executions` with a report for each bound worker `(core, filter)` the
/// node holds stopped to reopen its store and that reports nothing itself,
/// for the lifecycle's seat renewal ([`held_store_execution`]).
pub fn with_held_stores(
    mut executions: Vec<(u32, Vec<u8>, WorkerExecution)>,
    bound: &[(u32, Vec<u8>)],
) -> Vec<(u32, Vec<u8>, WorkerExecution)> {
    for (core_id, filter) in bound {
        if executions.iter().any(|(id, reported, _)| id == core_id && reported == filter) {
            continue;
        }
        if let Some(held) = held_store_execution(*core_id) {
            executions.push((*core_id, filter.clone(), held));
        }
    }
    executions
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_millis() as u64
}

#[derive(Clone, Debug, Default)]
pub struct SharedWorkerExecution {
    record: Arc<Mutex<WorkerExecution>>,
    /// This worker's successor session waits on the archive recovery of its
    /// predecessor's state.
    successor_blocked: Arc<AtomicBool>,
    /// Failed recovery attempts by shard.
    streaks: Arc<Mutex<HashMap<Vec<u8>, FailureStreak>>>,
    /// This worker's shard owes a re-anchor whose requested attempt no
    /// shard sync has taken yet.
    reanchor_armed: Arc<AtomicBool>,
    /// An attempt of the owed re-anchor handed its turn back, and the
    /// engine has not yet requested the attempt again.
    reanchor_yield: Arc<AtomicBool>,
    /// The archive recovery turn this worker's recovery holds.
    turn: Arc<Mutex<TurnHold>>,
    /// This worker is a voting member of its shard's running committee
    /// session whose materialized frame trails the session's committed tip.
    lagging_voter: Arc<AtomicBool>,
    /// The queue place of this worker's last replay, kept while it ended
    /// behind its target: `(filter, ticket)`.
    replay_ticket: Arc<Mutex<Option<(Vec<u8>, u64)>>>,
}

/// An archive recovery turn as its holder's recovery sees it
/// ([`crate::recovery_turns`]).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TurnHold {
    /// When it was granted; `None` while none is held.
    pub(crate) since: Option<tokio::time::Instant>,
    pub(crate) kind: RecoveryKind,
    /// Its hold limit passed: the recovery hands it back at its next chunk
    /// boundary ([`recovery_turn_spent`]).
    pub(crate) yielding: bool,
}

/// What a tree sync returns when its recovery hands its turn back at the
/// hold limit ([`recovery_turn_spent`]).
pub const RECOVERY_TURN_SPENT: &str =
    "archive recovery turn reached its hold limit; the installed leaves stay and the next turn resumes from them";

/// The error a tree sync returns when its recovery hands its turn back.
pub fn turn_spent_error() -> quil_types::error::QuilError {
    quil_types::error::QuilError::ExecutionUnavailable(RECOVERY_TURN_SPENT.into())
}

/// Whether `error` is a turn handed back ([`turn_spent_error`]), not a failure.
pub fn turn_spent(error: &quil_types::error::QuilError) -> bool {
    matches!(error, quil_types::error::QuilError::ExecutionUnavailable(m) if m == RECOVERY_TURN_SPENT)
}

impl SharedWorkerExecution {
    /// Whether this worker's successor session cannot start until archive
    /// recovery brings its predecessor's state through the seal. Such a
    /// worker takes the next recovery turn before others.
    pub fn set_successor_blocked(&self, blocked: bool) {
        self.successor_blocked.store(blocked, Ordering::Relaxed);
    }

    /// The flag behind [`Self::set_successor_blocked`], read by the recovery
    /// turn queue each time it grants a turn.
    pub(crate) fn successor_blocked_flag(&self) -> Arc<AtomicBool> { self.successor_blocked.clone() }

    /// Whether this worker's shard owes a re-anchor whose requested attempt
    /// waits for a shard sync to take it. That sync takes the next recovery
    /// turn before others.
    pub fn set_reanchor_armed(&self, armed: bool) {
        self.reanchor_armed.store(armed, Ordering::Relaxed);
    }

    /// The flag behind [`Self::set_reanchor_armed`], read by the recovery
    /// turn queue each time it grants a turn.
    pub(crate) fn reanchor_armed_flag(&self) -> Arc<AtomicBool> { self.reanchor_armed.clone() }

    /// An attempt of the owed re-anchor handed its turn back at the hold
    /// limit: its recovery queues again first, and the engine requests the
    /// attempt again when it next looks ([`Self::take_reanchor_yield`]). A
    /// flag rather than a message, which a full mailbox would drop.
    pub(crate) fn reanchor_yielded(&self) {
        self.reanchor_yield.store(true, Ordering::Relaxed);
        self.reanchor_armed.store(true, Ordering::Relaxed);
    }

    /// Whether a re-anchor attempt handed its turn back since the engine
    /// last looked; clears it.
    pub(crate) fn take_reanchor_yield(&self) -> bool {
        self.reanchor_yield.swap(false, Ordering::Relaxed)
    }

    /// Whether a re-anchor attempt handed its turn back and the engine has
    /// not looked since.
    pub(crate) fn reanchor_yield_pending(&self) -> bool {
        self.reanchor_yield.load(Ordering::Relaxed)
    }

    /// Whether this worker votes in its shard's running committee session
    /// while its materialized frame trails the session's committed tip. Its
    /// replays take the next recovery turn before others, and keep it for
    /// further batches, as a blocked successor's do.
    pub fn set_lagging_voter(&self, lagging: bool) {
        self.lagging_voter.store(lagging, Ordering::Relaxed);
    }

    /// The flag behind [`Self::set_lagging_voter`], read by the recovery
    /// turn queue each time it grants a turn.
    pub(crate) fn lagging_voter_flag(&self) -> Arc<AtomicBool> { self.lagging_voter.clone() }

    /// A replay of `filter` ended its turn behind its target: its next
    /// recovery of the shard queues again at `ticket`, its place, rather
    /// than behind every waiter.
    pub(crate) fn keep_replay_ticket(&self, filter: &[u8], ticket: u64) {
        *self.replay_ticket.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some((filter.to_vec(), ticket));
    }

    /// The place [`Self::keep_replay_ticket`] kept for `filter`; clears it.
    pub(crate) fn take_replay_ticket(&self, filter: &[u8]) -> Option<u64> {
        self.replay_ticket.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
            .filter(|(kept, _)| kept == filter).map(|(_, ticket)| ticket)
    }

    /// This worker's recovery holds a turn from `since`, to do `kind`.
    pub(crate) fn hold_turn(&self, kind: RecoveryKind, since: tokio::time::Instant) {
        *self.turn.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            TurnHold { since: Some(since), kind, yielding: false };
    }

    /// The turn this worker's recovery holds, if any.
    pub(crate) fn turn(&self) -> TurnHold {
        *self.turn.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The turn was released: how it was held.
    pub(crate) fn end_turn(&self) -> TurnHold {
        std::mem::take(&mut *self.turn.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    pub fn snapshot(&self) -> WorkerExecution { self.record.lock().unwrap().clone() }

    pub fn state(&self, state: &str, blocker: &str) {
        let mut s = self.record.lock().unwrap();
        s.state = state.into();
        s.blocker = blocker.into();
        s.awaited_frame = None;
        s.observed_unix_ms = now_ms();
    }

    /// A wait for `blocker` that committed GLOBAL state ends by `frame`.
    pub fn waiting_until(&self, blocker: &str, frame: u64) {
        let mut s = self.record.lock().unwrap();
        s.state = "waiting".into();
        s.blocker = blocker.into();
        s.awaited_frame = Some(frame);
        s.observed_unix_ms = now_ms();
    }

    /// Observed host phase, independent of frame progress or voting health.
    /// A retained seal belongs only to its own session, not its successor.
    pub fn consensus_phase(&self, ready: bool, closing: bool, session: Option<[u8; 32]>, sealed: Option<[u8; 32]>) {
        let (state, reason) = if session.is_some() && session == sealed {
            ("handoff", "awaiting successor")
        } else if !ready {
            ("syncing", "staging shard data")
        } else if closing {
            ("closing", "awaiting closing certificate")
        } else {
            ("serving", "")
        };
        self.state(state, reason);
    }

    pub fn restored(&self, height: u64) {
        let mut s = self.record.lock().unwrap();
        s.materialized_frame = Some(height);
        s.last_advance_unix_ms = 0;
        s.observed_unix_ms = now_ms();
    }

    pub fn materialized(&self, height: u64) {
        let mut s = self.record.lock().unwrap();
        let now = now_ms();
        // Restoring the initial cursor is an observation, not an advance.
        if s.materialized_frame.is_some_and(|old| height > old) {
            s.last_advance_unix_ms = now;
        }
        s.materialized_frame = Some(height);
        s.observed_unix_ms = now;
    }

    pub fn observe(&self) { self.record.lock().unwrap().observed_unix_ms = now_ms(); }

    /// The votes of the running session host (`WorkerExecution.own_votes`
    /// and its companions).
    pub(crate) fn votes(&self, votes: crate::own_votes::VotesReport) {
        let mut s = self.record.lock().unwrap();
        s.own_votes = votes.own;
        s.peer_votes = votes.peer;
        s.last_peer_vote_unix_ms = votes.last_peer_vote_unix_ms;
        s.host_started_unix_ms = votes.host_started_unix_ms;
        s.silent_ms = votes.silent_ms;
    }

    /// The engine this record belongs to started now
    /// (`WorkerExecution.engine_started_unix_ms`).
    pub fn engine_started(&self) { self.record.lock().unwrap().engine_started_unix_ms = now_ms(); }

    /// This member saw its session's terminal seal finalized.
    pub fn sealed(&self, generation: u64, checkpoint: u64, view: u64) {
        let mut s = self.record.lock().unwrap();
        let now = now_ms();
        s.seal = Some(SessionSeal { generation, checkpoint, view, finalized_unix_ms: now, ..Default::default() });
        s.observed_unix_ms = now;
    }

    /// The seal was submitted, carrying `drain` (`app_handoff::DrainedSeal::reason`).
    pub fn seal_submitted(&self, global_executed: u64, drain: &str, drain_headers: usize) {
        let mut s = self.record.lock().unwrap();
        let now = now_ms();
        if let Some(seal) = s.seal.as_mut() {
            seal.global_executed = global_executed;
            seal.drain = drain.into();
            seal.drain_headers = drain_headers as u32;
            seal.last_submitted_unix_ms = now;
            seal.submissions += 1;
        }
        s.observed_unix_ms = now;
    }

    /// A successor session runs: the last seal is history.
    pub fn clear_seal(&self) {
        let mut s = self.record.lock().unwrap();
        s.seal = None;
        s.observed_unix_ms = now_ms();
    }

    /// GLOBAL recorded the seal, in this node's view of it.
    pub fn seal_recorded(&self) {
        let mut s = self.record.lock().unwrap();
        let now = now_ms();
        if let Some(seal) = s.seal.as_mut().filter(|seal| seal.recorded_unix_ms == 0) {
            seal.recorded_unix_ms = now;
        }
        s.observed_unix_ms = now;
    }

    fn recovery(&self, update: impl FnOnce(&mut ShardRecovery, u64)) {
        let mut s = self.record.lock().unwrap();
        let now = now_ms();
        update(s.recovery.get_or_insert_with(Default::default), now);
        s.observed_unix_ms = now;
    }

    /// Run one recovery attempt of `filter`, attributing the phases, source
    /// and leaf progress reported on this task to this worker, then record
    /// and log how it ended. A recovery that found nothing usable is an
    /// error, not an outcome; one that handed its turn back at the hold limit
    /// (`ShardRecoveryProgress::Yielded`) installed leaves, an outcome. A deferred one (`ShardRecoveryProgress::Deferred`)
    /// attempted nothing: the record is left as it was, and neither the
    /// shard's failure streak nor the node's archive state hears of it.
    pub(crate) async fn recovering(
        &self,
        filter: &[u8],
        attempt: impl std::future::Future<Output = quil_types::error::Result<ShardRecoveryProgress>>,
    ) -> quil_types::error::Result<ShardRecoveryProgress> {
        let before = self.record.lock().unwrap().recovery.clone();
        self.recovery(|r, now| {
            r.attempt_started_unix_ms = now;
            r.permit_wait_ms = 0;
            r.attempt_ms = 0;
            r.attempt_installed_leaves = 0;
            r.source.clear();
        });
        let result = RECOVERING.scope(self.clone(), attempt).await;
        if let Ok(ShardRecoveryProgress::Deferred(reason)) = &result {
            self.record.lock().unwrap().recovery = before;
            tracing::debug!(filter = %hex::encode(filter), reason, "archive recovery deferred");
            return result;
        }
        let failure = match &result {
            Ok(ShardRecoveryProgress::NotReady(reason)) => Some((*reason).to_string()),
            Ok(_) => None,
            Err(error) => Some(error.to_string()),
        };
        let mut ended = ShardRecovery::default();
        self.recovery(|r, now| {
            match (&failure, &result) {
                (Some(failure), _) => {
                    r.last_error = failure.clone();
                    r.last_error_unix_ms = now;
                    r.consecutive_failures += 1;
                    let count = r.failures_by_class.entry(failure_class(failure).into()).or_default();
                    *count = count.saturating_add(1);
                }
                (None, progress) => {
                    r.last_outcome = progress.as_ref().map(ToString::to_string).unwrap_or_default();
                    r.last_outcome_unix_ms = now;
                    r.consecutive_failures = 0;
                }
            }
            enter(r, "idle", now);
            r.attempts += 1;
            r.attempt_ms = now.saturating_sub(r.attempt_started_unix_ms).saturating_sub(r.permit_wait_ms);
            ended = r.clone();
        });
        let now = Instant::now();
        let source = if ended.source.is_empty() { "none" } else { ended.source.as_str() };
        let class = failure.as_deref().map(failure_class);
        let (logged, classes, failed_before, first_failure) = {
            let mut streaks = self.streaks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let streak = streaks.entry(filter.to_vec()).or_default();
            // The failures a success ends, warned about or not: one or two
            // failures between successes never reach the warning.
            let failed_before = match streak.failures {
                0 => (0, "none".to_string()),
                failures => (failures, streak.classes()),
            };
            // A node without any archive is one condition, summarized below
            // for all its workers.
            let logged = match class {
                None => streak.succeeded(now),
                Some(class) => streak.failed(class, now, if class == NO_ARCHIVE { u64::MAX } else { STREAK_WARN_AFTER }),
            };
            let first_failure = logged.is_none()
                && class.is_some_and(|class| class != NO_ARCHIVE)
                && streak.first_failure_due(now);
            (logged, streak.classes(), failed_before, first_failure)
        };
        note_archive_known(filter, class != Some(NO_ARCHIVE), failure.as_deref(), now);
        let filter = hex::encode(filter);
        match failure {
            None => {
                let turn = match &result {
                    Ok(ShardRecoveryProgress::Replayed { turn, .. }) => *turn,
                    _ => ReplayTurn::default(),
                };
                tracing::info!(%filter, outcome = %ended.last_outcome, source,
                    attempt_secs = ended.attempt_ms / 1000, permit_wait_secs = ended.permit_wait_ms / 1000,
                    installed_leaves = ended.attempt_installed_leaves, frames = turn.frames, batches = turn.batches,
                    fetch_ms = turn.fetch_ms, replay_ms = turn.replay_ms, failed_attempts = failed_before.0,
                    failed_classes = %failed_before.1, "archive recovery batch complete");
                if let Some(StreakLog::Ended { failures, duration }) = logged {
                    tracing::info!(%filter, failures, failing_secs = duration.as_secs(), source,
                        "archive recovery succeeded after a failure streak");
                }
            }
            Some(error) => {
                tracing::debug!(%filter, %error, source,
                    attempt_secs = ended.attempt_ms / 1000, permit_wait_secs = ended.permit_wait_ms / 1000,
                    installed_leaves = ended.attempt_installed_leaves, consecutive_failures = ended.consecutive_failures,
                    "archive recovery attempt failed");
                if let (true, Some(class)) = (first_failure, class) {
                    let (scope, _) = failure_guidance(class);
                    tracing::info!(%filter, %error, class, source,
                        attempt_secs = ended.attempt_ms / 1000, permit_wait_secs = ended.permit_wait_ms / 1000,
                        installed_leaves = ended.attempt_installed_leaves, warn_after = STREAK_WARN_AFTER, scope,
                        "archive recovery attempt failed; it retries (installed leaves are kept) and warns if it \
                        keeps failing");
                }
                if let (Some(StreakLog::Failing { failures, duration }), Some(class)) = (logged, class) {
                    let (scope, action) = failure_guidance(class);
                    tracing::warn!(%filter, consecutive_failures = failures, failing_secs = duration.as_secs(),
                        classes = %classes, last_class = class, last_error = %error, last_source = source,
                        longest_permit_wait_secs = ended.longest_permit_wait_ms / 1000,
                        scope, action, "archive recovery failing; it retries (installed leaves are kept)");
                }
            }
        }
        result
    }
}

/// Consecutive failed attempts of one shard before they are warned about:
/// a failure between successes is retried, not yet an anomaly.
const STREAK_WARN_AFTER: u64 = 3;

/// How often failing recoveries of one shard, or of the node as a whole,
/// warn again; across streaks too, so a flapping recovery stays bounded.
const STREAK_REPEAT: Duration = Duration::from_secs(10 * 60);

/// The class of a failure that found no archive at all.
pub(crate) const NO_ARCHIVE: &str = "no_archive_known";

/// A run of failed archive recovery attempts, from the first failure to the
/// first success.
#[derive(Debug, Default)]
pub(crate) struct FailureStreak {
    since: Option<Instant>,
    /// When it, or an earlier streak, was last warned about.
    warned: Option<Instant>,
    /// This streak was warned about.
    reported: bool,
    failures: u64,
    classes: BTreeMap<&'static str, u64>,
    /// When a streak's first failure was last noted at info.
    noted: Option<Instant>,
}

/// What a [`FailureStreak`] change logs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StreakLog {
    /// Once `warn_after` failures in a row, then at most every
    /// [`STREAK_REPEAT`] while it lasts.
    Failing { failures: u64, duration: Duration },
    /// The success that ended a warned streak.
    Ended { failures: u64, duration: Duration },
}

impl FailureStreak {
    const fn new() -> Self {
        Self { since: None, warned: None, reported: false, failures: 0, classes: BTreeMap::new(), noted: None }
    }

    /// An attempt failed with `class` at `now`.
    pub(crate) fn failed(&mut self, class: &'static str, now: Instant, warn_after: u64) -> Option<StreakLog> {
        let since = *self.since.get_or_insert(now);
        self.failures += 1;
        *self.classes.entry(class).or_default() += 1;
        if self.failures < warn_after
            || self.warned.is_some_and(|at| now.saturating_duration_since(at) < STREAK_REPEAT)
        {
            return None;
        }
        self.warned = Some(now);
        self.reported = true;
        Some(StreakLog::Failing { failures: self.failures, duration: now.saturating_duration_since(since) })
    }

    /// Whether the failure just counted, a streak's first, is noted at info
    /// at `now`: at most once per [`STREAK_REPEAT`], so a flapping recovery
    /// stays bounded.
    pub(crate) fn first_failure_due(&mut self, now: Instant) -> bool {
        if self.failures != 1 || self.noted.is_some_and(|at| now.saturating_duration_since(at) < STREAK_REPEAT) {
            return false;
        }
        self.noted = Some(now);
        true
    }

    /// An attempt succeeded at `now`: the end of the streak, named if it
    /// was warned about.
    pub(crate) fn succeeded(&mut self, now: Instant) -> Option<StreakLog> {
        let since = self.since.take()?;
        let failures = std::mem::take(&mut self.failures);
        self.classes.clear();
        std::mem::take(&mut self.reported)
            .then(|| StreakLog::Ended { failures, duration: now.saturating_duration_since(since) })
    }

    /// The streak's failures by class, as `class=count` pairs.
    pub(crate) fn classes(&self) -> String {
        self.classes.iter().map(|(class, n)| format!("{class}={n}")).collect::<Vec<_>>().join(",")
    }
}

/// This node's recoveries finding no archive at all, across its workers.
#[derive(Debug)]
pub(crate) struct NoArchive {
    streak: FailureStreak,
    shards: BTreeSet<Vec<u8>>,
}

impl NoArchive {
    const fn new() -> Self {
        Self { streak: FailureStreak::new(), shards: BTreeSet::new() }
    }

    /// A recovery of `filter` found no archive at `now`: warned at once,
    /// then at most every [`STREAK_REPEAT`], with the shards affected.
    pub(crate) fn failed(&mut self, filter: &[u8], now: Instant) -> Option<(StreakLog, usize)> {
        self.shards.insert(filter.to_vec());
        Some((self.streak.failed(NO_ARCHIVE, now, 1)?, self.shards.len()))
    }

    /// A recovery reached an archive at `now`, failing or not.
    pub(crate) fn resolved(&mut self, now: Instant) -> Option<(StreakLog, usize)> {
        let shards = std::mem::take(&mut self.shards).len();
        Some((self.streak.succeeded(now)?, shards))
    }
}

static NO_ARCHIVE_KNOWN: Mutex<NoArchive> = Mutex::new(NoArchive::new());

/// Log the node-wide condition of recoveries finding no archive: a recovery
/// of `filter` at `now` that did (`reached`) or did not reach one.
fn note_archive_known(filter: &[u8], reached: bool, error: Option<&str>, now: Instant) {
    let logged = {
        let mut state = NO_ARCHIVE_KNOWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if reached { state.resolved(now) } else { state.failed(filter, now) }
    };
    match logged {
        Some((StreakLog::Failing { failures, duration }, shards)) => {
            let (scope, action) = failure_guidance(NO_ARCHIVE);
            tracing::warn!(failures, shards, failing_secs = duration.as_secs(), last_error = error.unwrap_or("none"),
                scope, action, "archive recovery finds no archive; recoveries retry");
        }
        Some((StreakLog::Ended { failures, duration }, shards)) => tracing::info!(failures, shards,
            failing_secs = duration.as_secs(), "archive recovery reaches an archive again"),
        None => {}
    }
}

/// The class of a failed recovery attempt, from its error or not-ready
/// text: one of [`FAILURE_CLASSES`].
pub fn failure_class(error: &str) -> &'static str {
    if error.contains("no archive known") || error.contains("discovered an archive") || error.contains("archive discovery") {
        NO_ARCHIVE
    } else if error.contains("archive connect") {
        "connect"
    } else if error.contains("get app-shard frame") || error.contains("get_forest_head") || error.contains("resolve shard subtree") {
        "archive_request"
    } else if error.contains("is missing") || error.contains("the archive") {
        "archive_state"
    } else if error.contains("replay") {
        "replay_mismatch"
    } else {
        "other"
    }
}

/// Whose problem a failure of `class` is, and what the operator can check.
pub(crate) fn failure_guidance(class: &str) -> (&'static str, &'static str) {
    match class {
        NO_ARCHIVE => ("this node", "this node's master knows no reachable archive yet; \
            check its 'archive endpoint added' lines and outbound connectivity; it retries"),
        "connect" => ("archive", "the archive refused or timed out the connection; \
            check this node's outbound connectivity to it; the next attempt tries another archive"),
        "archive_request" => ("archive", "the archive failed a read; the next attempt tries another archive; \
            report it with this line if it persists"),
        "replay_mismatch" => ("this node", "the archive's certified shard frames do not replay onto this worker's \
            local state; once one frame has failed so 10 times over 30 minutes, while the shard runs no consensus and \
            its current session continues this shard's chain, this worker re-anchors it at the frame GLOBAL \
            committed above its head; report it with this line if it persists"),
        "archive_state" => ("archive", "no archive supplied the shard state this worker needs; \
            it retries; report it with this line if it persists"),
        _ => ("this node", "report it with this line if it persists"),
    }
}

fn enter(r: &mut ShardRecovery, phase: &str, now: u64) {
    if r.phase != phase {
        if r.phase == "waiting_for_permit" {
            r.permit_wait_ms = now.saturating_sub(r.phase_since_unix_ms);
            r.longest_permit_wait_ms = r.longest_permit_wait_ms.max(r.permit_wait_ms);
        }
        r.phase = phase.into();
        r.phase_since_unix_ms = now;
    }
}

/// The archive the recovery on this task reads from now; elsewhere, or
/// for an empty address, nothing.
pub fn recovery_source(source: &str) {
    if source.is_empty() {
        return;
    }
    let _ = RECOVERING.try_with(|s| s.recovery(|r, _| {
        if r.source != source { r.source = source.into(); }
    }));
}

/// `leaves` more leaves installed durably by the recovery on this task;
/// elsewhere nothing.
pub fn recovery_installed(leaves: u64) {
    let _ = RECOVERING.try_with(|s| s.recovery(|r, _| r.attempt_installed_leaves += leaves));
}

/// Enter `phase` of the recovery running on this task; elsewhere nothing.
pub fn recovery_phase(phase: &'static str) {
    let _ = RECOVERING.try_with(|s| s.recovery(|r, now| enter(r, phase, now)));
}

/// What the recovery on this task does with its turn, once it knows: a
/// sync that takes an owed re-anchor's attempt re-anchors. Elsewhere
/// nothing.
pub(crate) fn recovery_kind(kind: RecoveryKind) {
    let _ = RECOVERING.try_with(|s| s.turn.lock().unwrap_or_else(std::sync::PoisonError::into_inner).kind = kind);
}

/// Whether the recovery on this task hands its archive recovery turn back
/// now, at a chunk or phase boundary of its tree sync: it has held the turn
/// for [`MAX_TURN_HOLD`] and installed leaves in it, so every turn makes
/// progress and the next resumes from it. Elsewhere, or without a turn,
/// false.
pub fn recovery_turn_spent() -> bool {
    RECOVERING.try_with(|s| {
        let installed = s.record.lock().unwrap().recovery.as_ref().is_some_and(|r| r.attempt_installed_leaves > 0);
        let mut turn = s.turn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let spent = installed && turn.since.is_some_and(|since| since.elapsed() >= MAX_TURN_HOLD);
        turn.yielding |= spent;
        spent
    }).unwrap_or(false)
}

/// Run `attempt` as the recovery of `execution`'s worker holding a turn
/// granted `held` ago, with no leaves installed in it yet: a test of a tree
/// sync in another crate sees [`recovery_turn_spent`] as a recovery would.
#[doc(hidden)]
pub async fn with_recovery_turn<T>(
    execution: &SharedWorkerExecution,
    held: Duration,
    attempt: impl std::future::Future<Output = T>,
) -> T {
    let now = tokio::time::Instant::now();
    execution.hold_turn(RecoveryKind::Install, now.checked_sub(held).unwrap_or(now));
    execution.recovery(|r, _| r.attempt_installed_leaves = 0);
    let result = RECOVERING.scope(execution.clone(), attempt).await;
    execution.end_turn();
    result
}

/// `installed` of the `planned` leaves of forest phase `tree_phase`, in the
/// tree the recovery on this task is installing; elsewhere (prover-tree and
/// archive syncs) nothing.
pub fn recovery_leaves(tree_phase: u32, installed: u64, planned: u64) {
    let _ = RECOVERING.try_with(|s| s.recovery(|r, now| {
        r.tree_phase = tree_phase;
        r.installed_leaves = installed;
        r.planned_leaves = planned;
        r.leaves_observed_unix_ms = now;
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A worker whose store latched reads as blocked by it, with or without
    /// an engine; others keep their engine's report.
    #[test]
    fn a_worker_whose_store_refuses_writes_reads_as_blocked_by_it() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let core = 9_401;
        assert!(db.inner().register_store(quil_forest::StoreRole::Worker(core)));
        let serving = WorkerExecution { state: "serving".into(), observed_unix_ms: 1, ..Default::default() };
        assert_eq!(with_store_state(core, Some(serving.clone())), Some(serving.clone()));
        assert_eq!(with_store_state(core, None), None);
        assert!(!store_stopped(core));
        db.inner().refuse_writes("IO error: No space left on device");
        assert!(store_stopped(core), "a latched store has stopped writing");
        for execution in [Some(serving.clone()), None] {
            let reported = with_store_state(core, execution).expect("a latched store is reported");
            assert_eq!((reported.state.as_str(), reported.blocker.as_str()), ("blocked", STORAGE_WRITE_FAILED));
            assert!(reported.observed_unix_ms > 1);
        }
        assert_eq!(with_store_state(core + 1, Some(serving.clone())), Some(serving.clone()));
        assert_eq!(held_store_execution(core + 1), None);
        quil_forest::storage_health::hold_store(quil_forest::StoreRole::Worker(core + 1));
        let held = with_store_state(core + 1, Some(serving)).expect("a held store is reported");
        assert_eq!((held.state.as_str(), held.blocker.as_str()), ("stopped", STORAGE_WRITE_FAILED));
        let for_lifecycle = held_store_execution(core + 1).expect("the lifecycle sees it too");
        assert_eq!(for_lifecycle.state, "stopped");
        let bound = [(core, vec![1]), (core + 1, vec![2])];
        let running = vec![(core, vec![1], WorkerExecution { state: "serving".into(), ..Default::default() })];
        let seen = with_held_stores(running.clone(), &bound);
        assert_eq!(seen.len(), 2, "the held worker reads as unable to host: {seen:?}");
        assert_eq!((seen[1].0, seen[1].1.clone(), seen[1].2.state.as_str()), (core + 1, vec![2], "stopped"));
        assert_eq!(with_held_stores(running.clone(), &bound[..1]), running, "an unbound worker adds nothing");
        quil_forest::storage_health::release_store(quil_forest::StoreRole::Worker(core + 1));
    }

    #[test]
    fn restoration_rewind_and_state_are_independent() {
        let s = SharedWorkerExecution::default();
        assert_eq!(s.snapshot().materialized_frame, None);
        s.restored(42);
        assert_eq!(s.snapshot().last_advance_unix_ms, 0);
        s.state("blocked", "checkpoint mismatch");
        s.materialized(43);
        assert!(s.snapshot().last_advance_unix_ms > 0);
        assert_eq!(s.snapshot().state, "blocked");
        s.materialized(40);
        assert_eq!(s.snapshot().materialized_frame, Some(40));
        s.state("running", "");
        assert!(s.snapshot().blocker.is_empty());
        assert!(s.snapshot().observed_unix_ms > 0);
        s.waiting_until("committee admission unavailable", 919_440);
        assert_eq!((s.snapshot().state.as_str(), s.snapshot().awaited_frame), ("waiting", Some(919_440)));
        s.state("serving", "");
        assert_eq!(s.snapshot().awaited_frame, None, "a later state ends the wait");
    }

    #[test]
    fn consensus_phases_follow_readiness_and_the_current_session_seal() {
        let execution = SharedWorkerExecution::default();
        execution.restored(0);
        execution.consensus_phase(false, false, Some([1; 32]), None);
        assert_eq!(execution.snapshot().state, "syncing");
        execution.consensus_phase(true, false, Some([1; 32]), None);
        assert_eq!(execution.snapshot().state, "serving");
        assert_eq!(execution.snapshot().last_advance_unix_ms, 0, "serving is not a progress claim");
        execution.consensus_phase(true, true, Some([1; 32]), None);
        assert_eq!(execution.snapshot().state, "closing");
        execution.consensus_phase(false, true, Some([1; 32]), Some([1; 32]));
        assert_eq!(execution.snapshot().state, "handoff");
        execution.consensus_phase(true, false, Some([2; 32]), Some([1; 32]));
        assert_eq!(execution.snapshot().state, "serving", "an old seal must not label a successor as waiting");
        assert!(execution.snapshot().blocker.is_empty());
        execution.consensus_phase(true, false, None, None);
        assert_eq!(execution.snapshot().state, "serving", "legacy hosts have no session seal");
    }

    /// A recovery hands its turn back only once it has held it for the
    /// limit and installed leaves in it; elsewhere nothing is spent.
    #[tokio::test(start_paused = true)]
    async fn a_turn_is_spent_after_the_hold_limit_and_an_installed_chunk() {
        assert!(!recovery_turn_spent(), "no recovery runs on this task");
        let worker = SharedWorkerExecution::default();
        let result = worker.recovering(&[7; 32], async {
            assert!(!recovery_turn_spent(), "no turn is held");
            worker.hold_turn(RecoveryKind::Install, tokio::time::Instant::now());
            tokio::time::advance(MAX_TURN_HOLD).await;
            assert!(!recovery_turn_spent(), "nothing installed in this turn yet");
            assert!(!worker.turn().yielding);
            recovery_installed(1_024);
            assert!(recovery_turn_spent());
            assert!(worker.turn().yielding);
            recovery_kind(RecoveryKind::Reanchor);
            assert_eq!(worker.turn().kind, RecoveryKind::Reanchor);
            Ok(ShardRecoveryProgress::Yielded)
        }).await;
        assert_eq!(result.unwrap(), ShardRecoveryProgress::Yielded);
        let r = worker.snapshot().recovery.unwrap();
        assert_eq!((r.consecutive_failures, r.last_outcome.as_str()), (0, RECOVERY_TURN_SPENT), "a handed-back turn is progress");
        assert!(turn_spent(&turn_spent_error()));
        assert!(!turn_spent(&quil_types::error::QuilError::ExecutionUnavailable("archive connect: refused".into())));
        assert!(worker.end_turn().yielding);
        assert!(worker.turn().since.is_none());
    }

    #[tokio::test]
    async fn recovery_is_reported_beside_the_execution_state_for_its_own_worker() {
        let (worker, other) = (SharedWorkerExecution::default(), SharedWorkerExecution::default());
        recovery_phase("installing_leaves");
        recovery_leaves(0, 1, 2);
        assert!(worker.snapshot().recovery.is_none(), "no recovery runs on this task");
        worker.state("blocked", "state unavailable");
        let installed = worker.recovering(&[7; 32], async {
            recovery_phase("waiting_for_permit");
            assert_eq!(worker.snapshot().recovery.unwrap().phase, "waiting_for_permit");
            recovery_phase("installing_leaves");
            recovery_source("198.51.100.7:8340");
            recovery_source("");
            recovery_leaves(2, 262_144, 2_517_449);
            recovery_installed(1_024);
            recovery_installed(1_024);
            let r = worker.snapshot().recovery.unwrap();
            assert_eq!((r.phase.as_str(), r.tree_phase, r.installed_leaves, r.planned_leaves),
                ("installing_leaves", 2, 262_144, 2_517_449));
            assert!(r.phase_since_unix_ms > 0 && r.leaves_observed_unix_ms > 0);
            Ok(ShardRecoveryProgress::Anchored { frame: 7 })
        }).await;
        assert!(installed.is_ok());
        assert!(other.snapshot().recovery.is_none());
        let s = worker.snapshot();
        assert_eq!((s.state.as_str(), s.blocker.as_str()), ("blocked", "state unavailable"));
        let r = s.recovery.unwrap();
        assert_eq!(r.phase, "idle");
        assert!(r.last_outcome.contains("frame 7") && r.last_outcome_unix_ms > 0);
        assert!(r.last_error.is_empty());
        assert_eq!(r.installed_leaves, 262_144, "the last leaf counts stay visible");
        assert_eq!((r.source.as_str(), r.attempt_installed_leaves), ("198.51.100.7:8340", 2_048));
        assert_eq!((r.attempts, r.consecutive_failures), (1, 0));
        assert!(r.attempt_started_unix_ms > 0);

        let _ = worker.recovering(&[7; 32], async { Ok(ShardRecoveryProgress::NotReady("the archive checkpoint failed validation")) }).await;
        let r = worker.snapshot().recovery.unwrap();
        assert_eq!(r.last_error, "the archive checkpoint failed validation");
        assert!(r.last_outcome.contains("frame 7"), "an error keeps the last outcome");
        assert_eq!((r.attempts, r.consecutive_failures, r.attempt_installed_leaves), (2, 1, 0));
        assert!(r.source.is_empty(), "each attempt names its own source");
        let _ = worker.recovering(&[7; 32], async {
            Err(quil_types::error::QuilError::ExecutionUnavailable("archive discovery timed out".into()))
        }).await;
        let r = worker.snapshot().recovery.unwrap();
        assert!(r.last_error.contains("archive discovery timed out"));
        assert_eq!(r.consecutive_failures, 2);
        let classes: BTreeMap<String, u32> = r.failures_by_class.into_iter().collect();
        assert_eq!(classes, BTreeMap::from([("archive_state".into(), 1), ("no_archive_known".into(), 1)]),
            "failures are counted by class since the engine started");
    }

    const MINUTE: Duration = Duration::from_secs(60);

    /// A failure streak warns once it reaches the threshold, then only
    /// every repeat interval with its count and duration, and its end is
    /// named once.
    #[test]
    fn a_failure_streak_warns_after_the_threshold_and_then_at_a_bounded_rate() {
        let start = Instant::now();
        let mut streak = FailureStreak::default();
        assert_eq!(streak.succeeded(start), None, "no streak, no end");
        assert_eq!(streak.failed("connect", start, 3), None);
        assert_eq!(streak.failed("connect", start, 3), None);
        assert_eq!(streak.failed("no_archive_known", start + MINUTE, 3),
            Some(StreakLog::Failing { failures: 3, duration: MINUTE }));
        for minute in 2..11 {
            assert_eq!(streak.failed("no_archive_known", start + MINUTE * minute, 3), None);
        }
        assert_eq!(streak.failed("connect", start + MINUTE * 11, 3),
            Some(StreakLog::Failing { failures: 13, duration: MINUTE * 11 }));
        assert_eq!(streak.classes(), "connect=3,no_archive_known=10");
        assert_eq!(streak.succeeded(start + MINUTE * 20),
            Some(StreakLog::Ended { failures: 13, duration: MINUTE * 20 }));
        assert_eq!(streak.succeeded(start + MINUTE * 21), None);
        assert_eq!(streak.classes(), "");
    }

    /// Failures between successes do not warn, and a flapping recovery
    /// warns at most once per repeat interval; an unwarned streak's end is
    /// not named.
    #[test]
    fn a_flapping_recovery_warns_at_most_once_per_interval() {
        let start = Instant::now();
        let mut streak = FailureStreak::default();
        let mut warnings = 0;
        for minute in 0..20 {
            let at = start + MINUTE * minute;
            if minute % 4 == 3 {
                streak.succeeded(at);
                continue;
            }
            warnings += usize::from(streak.failed("connect", at, 3).is_some());
        }
        assert_eq!(warnings, 2, "minutes 2 and 14");
        for minute in 20..30 {
            let at = start + MINUTE * minute;
            assert_eq!(streak.failed("connect", at, 3), None);
            assert_eq!(streak.succeeded(at), None);
        }
    }

    /// A streak's first failure is noted at most once per repeat interval,
    /// so failures between successes show without flooding.
    #[test]
    fn a_streaks_first_failure_is_noted_at_most_once_per_interval() {
        let start = Instant::now();
        let mut streak = FailureStreak::default();
        streak.failed("connect", start, 3);
        assert!(streak.first_failure_due(start));
        streak.succeeded(start + MINUTE);
        streak.failed("connect", start + MINUTE * 2, 3);
        assert!(!streak.first_failure_due(start + MINUTE * 2), "within the interval");
        streak.failed("connect", start + MINUTE * 3, 3);
        assert!(!streak.first_failure_due(start + MINUTE * 3), "not a first failure");
        streak.succeeded(start + MINUTE * 4);
        streak.failed("connect", start + MINUTE * 12, 3);
        assert!(streak.first_failure_due(start + MINUTE * 12));
    }

    /// Recoveries finding no archive warn once for the node, with the
    /// shards affected, and end when any recovery reaches an archive.
    #[test]
    fn a_node_without_archives_warns_once_for_all_its_workers() {
        let start = Instant::now();
        let mut node = NoArchive::new();
        assert_eq!(node.resolved(start), None);
        assert_eq!(node.failed(&[1; 32], start), Some((StreakLog::Failing { failures: 1, duration: Duration::ZERO }, 1)));
        for worker in 2..100u8 {
            assert_eq!(node.failed(&[worker; 32], start + MINUTE), None);
        }
        assert_eq!(node.failed(&[1; 32], start + MINUTE * 10),
            Some((StreakLog::Failing { failures: 100, duration: MINUTE * 10 }, 99)));
        assert_eq!(node.resolved(start + MINUTE * 11),
            Some((StreakLog::Ended { failures: 100, duration: MINUTE * 11 }, 99)));
    }

    /// A deferred sync attempted nothing: the record, the shard's streak
    /// and its failure classes are as before it.
    #[tokio::test]
    async fn a_deferred_recovery_changes_no_record_or_streak() {
        let worker = SharedWorkerExecution::default();
        let _ = worker.recovering(&[4; 32], async {
            Err(quil_types::error::QuilError::Internal("archive connect: refused".into()))
        }).await;
        let before = worker.snapshot().recovery.unwrap();
        for _ in 0..5 {
            let result = worker.recovering(&[4; 32], async {
                recovery_phase("waiting_for_permit");
                Ok(ShardRecoveryProgress::Deferred("a re-anchor at the session fence is owed and has its own attempt"))
            }).await;
            assert!(matches!(result, Ok(ShardRecoveryProgress::Deferred(_))));
        }
        assert_eq!(worker.snapshot().recovery.unwrap(), before);
        let streaks = worker.streaks.lock().unwrap();
        assert_eq!((streaks[&vec![4; 32]].failures, streaks[&vec![4; 32]].reported), (1, false));
    }

    /// Each shard keeps its own streak: another shard's success does not
    /// end it, and a node without archives leaves the worker's own warning
    /// to the node's.
    #[tokio::test]
    async fn streaks_are_kept_per_shard() {
        let worker = SharedWorkerExecution::default();
        let fail = || async { Err(quil_types::error::QuilError::Internal("archive connect: refused".into())) };
        for _ in 0..2 {
            let _ = worker.recovering(&[1; 32], fail()).await;
        }
        let _ = worker.recovering(&[2; 32], async { Ok(ShardRecoveryProgress::Anchored { frame: 3 }) }).await;
        let _ = worker.recovering(&[1; 32], fail()).await;
        let streaks = worker.streaks.lock().unwrap();
        assert_eq!(streaks[&vec![1; 32]].failures, 3, "the other shard's success must not reset it");
        assert!(streaks[&vec![1; 32]].reported);
        assert_eq!(streaks[&vec![2; 32]].failures, 0);
    }

    #[test]
    fn failures_are_classed_by_whose_problem_they_are() {
        for (error, class) in [
            ("execution unavailable: no archive known yet", "no_archive_known"),
            ("internal error: archive connect: invalid endpoint: invalid URI", "connect"),
            ("internal error: get app-shard frame: status: Unavailable", "archive_request"),
            ("invalid argument: wrong-shard archive replay tip", "replay_mismatch"),
            ("execution unavailable: archive replay pre-state mismatch at phase 0", "replay_mismatch"),
            ("the archive checkpoint failed validation", "archive_state"),
            ("execution unavailable: archive replay is missing shard frame 9", "archive_state"),
            ("actor rejected checkpoint", "other"),
        ] {
            assert_eq!(failure_class(error), class, "{error}");
        }
        assert_eq!(failure_guidance("no_archive_known").0, "this node");
        assert_eq!(failure_guidance("connect").0, "archive");
    }

    #[tokio::test]
    async fn permit_wait_is_measured_apart_from_the_attempt() {
        let worker = SharedWorkerExecution::default();
        let _ = worker.recovering(&[7; 32], async {
            recovery_phase("waiting_for_permit");
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            recovery_phase("fetching_checkpoint");
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            Ok(ShardRecoveryProgress::Anchored { frame: 1 })
        }).await;
        let r = worker.snapshot().recovery.unwrap();
        assert!(r.permit_wait_ms >= 60, "{}", r.permit_wait_ms);
        assert!(r.attempt_ms >= 30 && r.attempt_ms < r.permit_wait_ms + 30, "{} after {}", r.attempt_ms, r.permit_wait_ms);
        let longest = r.longest_permit_wait_ms;
        assert_eq!(longest, r.permit_wait_ms);
        let _ = worker.recovering(&[7; 32], async {
            recovery_phase("waiting_for_permit");
            recovery_phase("fetching_checkpoint");
            Ok(ShardRecoveryProgress::Anchored { frame: 2 })
        }).await;
        let r = worker.snapshot().recovery.unwrap();
        assert!(r.permit_wait_ms < longest);
        assert_eq!(r.longest_permit_wait_ms, longest, "the longest wait outlasts a shorter one");
    }

    /// The text between `start` and the next `end` after it in `source`.
    fn region<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let from = source.find(start).unwrap_or_else(|| panic!("{start} not found"));
        let rest = &source[from + start.len()..];
        &rest[..rest.find(end).unwrap_or_else(|| panic!("{end} not found after {start}"))]
    }

    /// The string literals of each `open` … `close` in `source` that starts
    /// with a literal, e.g. each `state("…", "…")` call. Whitespace after
    /// `open` is skipped, so a line break inserted by rustfmt hides nothing.
    fn literals<'a>(source: &'a str, open: &str, close: char) -> Vec<Vec<&'a str>> {
        source.match_indices(open).filter_map(|(at, _)| {
            let rest = source[at + open.len()..].trim_start();
            rest.starts_with('"').then(|| rest[..rest.find(close).unwrap()].split('"').skip(1).step_by(2).collect())
        }).collect()
    }

    /// Every phase and reason the engine writes is listed in [`STATES`] and
    /// [`BLOCKERS`], every recovery phase in [`RECOVERY_PHASES`], and every
    /// listed one is written: readers outside the engine map the lists.
    #[test]
    fn the_lists_hold_every_literal_the_engine_writes() {
        let engine = include_str!("app_engine.rs");
        let thread = include_str!("thread_worker.rs");
        let syncer = include_str!("prover_tree_syncer.rs");
        let own = include_str!("worker_execution.rs");
        let own = &own[..own.find("#[cfg(test)]
mod tests").unwrap()];
        let phase = region(own, "pub fn consensus_phase", "self.state(state, reason)");
        let chain = region(engine, "let blocker = ", ";");
        let mut written: Vec<Vec<&str>> = [engine, thread].iter().flat_map(|s| literals(s, "state(", ')')).collect();
        assert!(written.len() >= 10, "{written:?}");
        written.extend(literals(phase, "(", ')'));
        let chained = literals(chain, "{", '}');
        assert_eq!(chained.len(), 4, "{chain}");
        written.extend(chained.into_iter().map(|blocker| vec!["blocked", blocker[0]]));
        // A store's state, which no engine writes (`with_store_state`).
        written.push(vec!["blocked", STORAGE_WRITE_FAILED]);
        let states: BTreeSet<&str> = written.iter().map(|args| args[0]).collect();
        let blockers: BTreeSet<&str> = written.iter().filter_map(|args| args.get(1).copied()).filter(|b| !b.is_empty()).collect();
        assert_eq!(states, STATES.into_iter().collect::<BTreeSet<_>>());
        assert_eq!(blockers, BLOCKERS.into_iter().collect::<BTreeSet<_>>());
        let phases: BTreeSet<&str> = [thread, syncer].iter().flat_map(|s| literals(s, "recovery_phase(", ')'))
            .chain(literals(own, "enter(r, ", ','))
            .map(|args| args[0]).collect();
        assert_eq!(phases, RECOVERY_PHASES.into_iter().collect::<BTreeSet<_>>());
    }

}
