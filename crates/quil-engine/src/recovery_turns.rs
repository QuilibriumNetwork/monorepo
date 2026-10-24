//! Archive shard recovery turns: the few recoveries a node's workers run at
//! once. A node's workers share its archive identity and so its per-peer
//! read slots; a few recover at a time rather than all failing busy
//! together. Turns go in arrival order, except that a worker replaying frames
//! onto those it holds goes before checkpoint installs, and a worker whose
//! successor session cannot start until its recovery lands, whose shard
//! owes a re-anchor, or that votes in its running session while it trails
//! the session's committed tip (a lagging voter), goes first: these reorder
//! the queue and add no concurrent recovery. A blocked successor or lagging
//! voter also keeps its turn for further replay batches, for at most
//! [`BLOCKED_TURN_BUDGET`]. A replay whose turn ends behind its target
//! queues again in its first place. No recovery keeps a turn
//! much past [`MAX_TURN_HOLD`]: a tree install hands it back at its next
//! chunk boundary and queues again in its first place, resuming from the
//! leaves it installed, and the engine's own installation of a checkpoint
//! runs after the turn is released. A recovery that handed its turn back
//! takes at most every other turn while others wait ([`TurnQueue::next`]).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::worker_execution::SharedWorkerExecution;

/// Archive shard recoveries this process runs at once.
pub(crate) const RECOVERY_TURNS: usize = 2;

/// Turns in a row that may go past the longest waiter to replays and
/// blocked successors, so other recoveries still progress meanwhile.
const PRIORITY_RUN: usize = 2;

/// How long a blocked successor keeps its turn, replaying batch after batch
/// while it stays blocked. Its session cannot start until the replay reaches
/// the predecessor's seal; handing the turn back after each batch re-queued
/// it behind every waiter, and with 90 to 180 waiting a turn came round every
/// 1.5 to 3 hours for 32 frames while its shard advanced 30 to 50 an hour.
/// Holding the turn adds no concurrent archive reads; it delays the waiters
/// by at most this, plus the batch running when it runs out.
pub(crate) const BLOCKED_TURN_BUDGET: Duration = Duration::from_secs(5 * 60);

/// How long a recovery holds its turn before it hands it back at its next
/// chunk boundary, having installed at least one chunk in it. Two checkpoint
/// installs of 157,076 and 23,348 leaves, at about 7.5 minutes per
/// 1,024-leaf chunk, held both turns for hours while 89 to 143 workers
/// waited, the first for 7.5 hours, and blocked successor sessions never
/// started. A handed-back turn goes to the next waiter: archive reads stay
/// at [`RECOVERY_TURNS`] at once.
pub(crate) const MAX_TURN_HOLD: Duration = Duration::from_secs(10 * 60);

/// How long a worker waits for a turn before the queue counts as saturated.
const SATURATED_AFTER: Duration = Duration::from_secs(60);

/// How often saturated turns warn again.
const SATURATED_REPEAT: Duration = Duration::from_secs(10 * 60);

/// How often a waiting worker re-evaluates saturation while no turn moves.
const SATURATION_TICK: Duration = Duration::from_secs(60);

pub(crate) static SHARD_RECOVERY_TURNS: RecoveryTurns = RecoveryTurns::new(RECOVERY_TURNS);

/// Whether a turn held for `held` replays another batch: only while one of
/// the holder's `flags` is set (its successor-blocked or lagging-voter flag;
/// none for a recovery holding no turn), and within [`BLOCKED_TURN_BUDGET`].
pub(crate) fn holds_turn(flags: &[&AtomicBool], held: Duration) -> bool {
    held < BLOCKED_TURN_BUDGET && flags.iter().any(|flag| flag.load(Ordering::Relaxed))
}

/// What a recovery does with its turn.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum RecoveryKind {
    /// Installs an archive checkpoint's shard state.
    #[default]
    Install,
    /// Replays archive frames onto those the worker holds.
    Replay,
    /// Re-anchors the shard at its session fence: an install pinned to the
    /// frame GLOBAL committed.
    Reanchor,
}

impl RecoveryKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Replay => "replay",
            Self::Reanchor => "re-anchor",
        }
    }
}

/// A worker asking for a turn.
pub(crate) struct Claim {
    pub(crate) core: u32,
    /// The shard it recovers.
    pub(crate) filter: Vec<u8>,
    /// What it expects to do: a worker holding frames of its shard replays.
    pub(crate) kind: RecoveryKind,
    /// Its execution record: the flags its rank reads, and the phase and
    /// leaf progress its turn is named with.
    pub(crate) execution: SharedWorkerExecution,
    /// Its place in the queue: `None` for a new arrival; a recovery that
    /// handed its turn back passes its first arrival's [`Turn::ticket`] and
    /// keeps that place.
    pub(crate) ticket: Option<u64>,
}

/// What orders a waiter, read when a turn frees up rather than when it
/// queued.
#[derive(Debug, Clone, Default)]
struct Priority {
    /// Its successor session cannot start until this recovery lands
    /// (`SharedWorkerExecution::set_successor_blocked`).
    blocked: Arc<AtomicBool>,
    /// Its shard owes a re-anchor whose requested attempt this recovery
    /// makes (`SharedWorkerExecution::set_reanchor_armed`).
    reanchor: Arc<AtomicBool>,
    /// It votes in its running session while it trails the session's
    /// committed tip (`SharedWorkerExecution::set_lagging_voter`): it goes
    /// as a blocked successor does.
    lagging: Arc<AtomicBool>,
    /// It holds frames of its shard, so its turn replays at most a few
    /// batches onto them (or re-anchors at a fence) rather than installing a
    /// checkpoint, about half an hour per million leaves.
    replay: bool,
}

/// A queued worker.
#[derive(Debug)]
struct Waiter<T> {
    id: u64,
    /// Its place: waiters stand in ticket order.
    ticket: u64,
    /// It handed its last turn back and queued again ([`Claim::ticket`]).
    resumed: bool,
    priority: Priority,
    core: u32,
    /// When it queued this time.
    since: Instant,
    grant: T,
}

impl<T> Waiter<T> {
    /// Turn order past the longest waiter, lowest first: an owed re-anchor
    /// or a blocked successor's or lagging voter's replay, a replay, a
    /// blocked successor's or lagging voter's install, an install.
    fn rank(&self) -> u8 {
        if self.priority.reanchor.load(Ordering::Relaxed) {
            return 0;
        }
        let first = self.priority.blocked.load(Ordering::Relaxed) || self.priority.lagging.load(Ordering::Relaxed);
        match (self.priority.replay, first) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        }
    }
}

/// The waiting workers in ticket order: arrival order, except that a
/// recovery queued again after handing its turn back keeps its first place.
#[derive(Debug)]
struct TurnQueue<T> {
    free: usize,
    next_id: u64,
    next_ticket: u64,
    /// Turns granted in a row past the longest waiter.
    bypassed: usize,
    /// The last turn went to a resumed waiter.
    after_resumed: bool,
    waiters: VecDeque<Waiter<T>>,
}

impl<T> TurnQueue<T> {
    const fn new(turns: usize) -> Self {
        Self { free: turns, next_id: 0, next_ticket: 0, bypassed: 0, after_resumed: false, waiters: VecDeque::new() }
    }

    /// A new arrival: [`Self::take_or_requeue`] without a ticket.
    #[cfg(test)]
    fn take_or_queue(&mut self, priority: Priority, core: u32, now: Instant, grant: T) -> Result<(), u64> {
        self.take_or_requeue(priority, core, None, now, grant).1
    }

    /// Take a free turn when nobody waits; otherwise queue `grant`, at the
    /// place of `ticket` when it has one, and return its id. Also returns
    /// its ticket: `ticket`, or a new one after every other.
    fn take_or_requeue(
        &mut self, priority: Priority, core: u32, ticket: Option<u64>, now: Instant, grant: T,
    ) -> (u64, Result<(), u64>) {
        let resumed = ticket.is_some();
        let ticket = ticket.unwrap_or_else(|| {
            self.next_ticket += 1;
            self.next_ticket - 1
        });
        if self.free > 0 && self.waiters.is_empty() {
            self.free -= 1;
            return (ticket, Ok(()));
        }
        let id = self.next_id;
        self.next_id += 1;
        let at = self.waiters.iter().position(|w| w.ticket > ticket).unwrap_or(self.waiters.len());
        self.waiters.insert(at, Waiter { id, ticket, resumed, priority, core, since: now, grant });
        (ticket, Err(id))
    }

    /// A turn ended: the waiter it goes to, or none (the turn is free). The
    /// first waiter of the lowest [`Waiter::rank`] goes first, unless
    /// [`PRIORITY_RUN`] turns in a row already went past the longest waiter.
    ///
    /// A resumed waiter keeps its place, so a long install that handed its
    /// turn back is soon granted another, but after a turn went to a resumed
    /// waiter the next goes to one that is not, while any waits. Among equal
    /// ranks the first waiter always wins, so without this two long
    /// installs at the front would alternate on both turns until done; with
    /// it they take at most every other turn and the waiters behind them
    /// the rest. Requeued last instead, a 157,076-leaf install would wait
    /// behind every waiter for each of its about 77 turns.
    fn next(&mut self) -> Option<T> {
        if self.waiters.is_empty() {
            self.free += 1;
            return None;
        }
        let skip_resumed = self.after_resumed && self.waiters.iter().any(|w| !w.resumed);
        let eligible = |w: &Waiter<T>| !(skip_resumed && w.resumed);
        let first = self.waiters.iter().position(eligible).unwrap_or(0);
        let pick = if self.bypassed < PRIORITY_RUN {
            self.waiters.iter().enumerate().filter(|(_, w)| eligible(*w))
                .min_by_key(|(_, w)| w.rank()).map_or(first, |(at, _)| at)
        } else {
            first
        };
        self.bypassed = if pick == first { 0 } else { self.bypassed + 1 };
        let waiter = self.waiters.remove(pick)?;
        self.after_resumed = waiter.resumed;
        Some(waiter.grant)
    }

    /// Withdraw waiter `id`; false when it already got its turn.
    fn withdraw(&mut self, id: u64) -> bool {
        let Some(at) = self.waiters.iter().position(|w| w.id == id) else { return false };
        self.waiters.remove(at);
        true
    }

    /// Waiting workers, of them blocked successors and replays, the longest
    /// wait and whose it is.
    fn load(&self, now: Instant) -> QueueLoad {
        QueueLoad {
            waiting: self.waiters.len(),
            blocked_successors: self.waiters.iter().filter(|w| w.priority.blocked.load(Ordering::Relaxed)).count(),
            replays: self.waiters.iter().filter(|w| w.priority.replay).count(),
            longest_wait: self.waiters.iter().map(|w| now.saturating_duration_since(w.since)).max().unwrap_or_default(),
            front_core: self.waiters.front().map(|w| w.core),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueueLoad {
    waiting: usize,
    blocked_successors: usize,
    replays: usize,
    longest_wait: Duration,
    /// The core of the longest waiter.
    front_core: Option<u32>,
}

/// What a [`Saturation`] change logs.
#[derive(Debug, PartialEq, Eq)]
enum SaturationLog {
    /// Saturated for `duration`: at the first wait past [`SATURATED_AFTER`],
    /// then at most every [`SATURATED_REPEAT`].
    Saturated { duration: Duration },
    /// The queue drained after a warned saturation of `duration`.
    Cleared { duration: Duration },
}

/// A period with workers waiting for a recovery turn, from the first
/// queued worker to the queue's drain.
#[derive(Debug)]
struct Saturation {
    since: Option<Instant>,
    /// When it was last warned about.
    warned: Option<Instant>,
}

impl Saturation {
    const fn new() -> Self {
        Self { since: None, warned: None }
    }

    fn observe(&mut self, now: Instant, load: QueueLoad) -> Option<SaturationLog> {
        if load.waiting == 0 {
            let since = self.since.take();
            return self.warned.take().map(|_| SaturationLog::Cleared {
                duration: since.map_or(Duration::ZERO, |since| now.saturating_duration_since(since)),
            });
        }
        let since = *self.since.get_or_insert_with(|| now.checked_sub(load.longest_wait).unwrap_or(now));
        if load.longest_wait < SATURATED_AFTER
            || self.warned.is_some_and(|at| now.saturating_duration_since(at) < SATURATED_REPEAT)
        {
            return None;
        }
        self.warned = Some(now);
        Some(SaturationLog::Saturated { duration: now.saturating_duration_since(since) })
    }
}

/// How long a holder of a turn for `kind` runs before it counts as held
/// past its limit: a replay ends its turn within [`BLOCKED_TURN_BUDGET`]
/// and a batch, so at [`MAX_TURN_HOLD`]; a tree install hands its turn back
/// at its first chunk boundary past the limit, about a chunk later, so only
/// at twice the limit (a chunk slower than the limit itself, or a repair of
/// legacy state, which keeps its turn until done).
fn overdue_after(kind: RecoveryKind) -> Duration {
    match kind {
        RecoveryKind::Replay => MAX_TURN_HOLD,
        RecoveryKind::Install | RecoveryKind::Reanchor => MAX_TURN_HOLD * 2,
    }
}

/// A worker holding a turn.
struct Holder {
    id: u64,
    core: u32,
    filter: Vec<u8>,
    execution: SharedWorkerExecution,
    since: Instant,
    /// It was warned about for holding its turn past [`overdue_after`].
    warned: bool,
}

impl Holder {
    fn view(&self, now: Instant) -> HolderView {
        let recovery = self.execution.snapshot().recovery.unwrap_or_default();
        HolderView {
            core: self.core,
            filter: hex::encode(&self.filter),
            kind: self.execution.turn().kind,
            phase: if recovery.phase.is_empty() { "none".into() } else { recovery.phase },
            held: now.saturating_duration_since(self.since),
            installed: recovery.installed_leaves,
            planned: recovery.planned_leaves,
        }
    }
}

/// What a turn's holder is doing, as logged: its tree install's progress is
/// that of the current tree phase.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HolderView {
    core: u32,
    filter: String,
    kind: RecoveryKind,
    phase: String,
    held: Duration,
    installed: u64,
    planned: u64,
}

impl std::fmt::Display for HolderView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "core {} {} {} held {}s leaves {}/{} filter {}", self.core, self.kind.as_str(), self.phase,
            self.held.as_secs(), self.installed, self.planned, self.filter)
    }
}

/// What a queue change logs.
#[derive(Debug, Default)]
struct Logged {
    saturation: Option<(SaturationLog, QueueLoad, Vec<HolderView>)>,
    /// Holders that just passed [`overdue_after`] while workers wait.
    overruns: Vec<(HolderView, usize)>,
}

struct State {
    queue: TurnQueue<oneshot::Sender<()>>,
    saturation: Saturation,
    holders: Vec<Holder>,
    next_holder: u64,
}

impl State {
    /// Re-evaluate saturation and the holders after a queue change or a tick
    /// at `now`. A turn held past [`overdue_after`] is warned about once,
    /// while workers wait for it.
    fn observe(&mut self, now: Instant) -> Logged {
        let load = self.queue.load(now);
        let mut overruns = Vec::new();
        if load.waiting > 0 {
            for holder in self.holders.iter_mut().filter(|holder| !holder.warned
                && now.saturating_duration_since(holder.since) >= overdue_after(holder.execution.turn().kind))
            {
                holder.warned = true;
                overruns.push((holder.view(now), load.waiting));
            }
        }
        let saturation = self.saturation.observe(now, load)
            .map(|logged| (logged, load, self.holders.iter().map(|holder| holder.view(now)).collect()));
        Logged { saturation, overruns }
    }
}

/// A fixed number of turns, granted in [`TurnQueue`] order.
pub(crate) struct RecoveryTurns {
    turns: usize,
    state: Mutex<State>,
}

/// A held turn; dropping it hands it to the next waiter.
pub(crate) struct Turn<'a> {
    turns: &'a RecoveryTurns,
    id: u64,
    ticket: u64,
}

impl Turn<'_> {
    /// Its holder's place in the queue, kept if it queues again after
    /// handing the turn back ([`Claim::ticket`]).
    pub(crate) fn ticket(&self) -> u64 {
        self.ticket
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let holder = {
            let mut state = self.turns.lock();
            state.holders.iter().position(|holder| holder.id == self.id).map(|at| state.holders.swap_remove(at))
        };
        if let Some(holder) = holder {
            let view = holder.view(Instant::now());
            let hold = holder.execution.end_turn();
            if hold.yielding {
                tracing::info!(core = view.core, filter = %view.filter, kind = view.kind.as_str(), phase = %view.phase,
                    held_secs = view.held.as_secs(), installed_leaves = view.installed, planned_leaves = view.planned,
                    limit_secs = MAX_TURN_HOLD.as_secs(),
                    "archive recovery turn handed back at its hold limit; the installed leaves stay and the recovery \
                    queues again to resume from them");
            } else if holder.warned {
                tracing::info!(core = view.core, filter = %view.filter, kind = view.kind.as_str(), phase = %view.phase,
                    held_secs = view.held.as_secs(), installed_leaves = view.installed, planned_leaves = view.planned,
                    "archive recovery turn held past its limit is released");
            }
        }
        self.turns.release();
    }
}

/// A queued request for a turn; dropped unanswered, it leaves the queue,
/// and dropped answered, it passes the turn on.
struct Queued<'a> {
    turns: &'a RecoveryTurns,
    id: u64,
    granted: oneshot::Receiver<()>,
    /// The turn was received and is now held by a [`Turn`].
    taken: bool,
}

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        if self.taken {
            return;
        }
        let (withdrawn, logged) = {
            let mut state = self.turns.lock();
            let withdrawn = state.queue.withdraw(self.id);
            (withdrawn, state.observe(Instant::now()))
        };
        self.turns.log(logged);
        if !withdrawn && self.granted.try_recv().is_ok() {
            self.turns.release();
        }
    }
}

impl RecoveryTurns {
    pub(crate) const fn new(turns: usize) -> Self {
        Self {
            turns,
            state: Mutex::new(State {
                queue: TurnQueue::new(turns), saturation: Saturation::new(), holders: Vec::new(), next_holder: 0,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Workers waiting for a turn.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.lock().queue.waiters.len()
    }

    /// Wait for a turn. Replays go before checkpoint installs, and a worker
    /// whose successor-blocked, re-anchor or lagging-voter flag is set when
    /// a turn frees up before others of its kind ([`Waiter::rank`]).
    pub(crate) async fn acquire(&self, claim: Claim) -> Turn<'_> {
        let priority = Priority {
            blocked: claim.execution.successor_blocked_flag(),
            reanchor: claim.execution.reanchor_armed_flag(),
            lagging: claim.execution.lagging_voter_flag(),
            replay: claim.kind == RecoveryKind::Replay,
        };
        let (grant, granted) = oneshot::channel();
        let (mut queued, logged, ticket) = {
            let mut state = self.lock();
            let now = Instant::now();
            match state.queue.take_or_requeue(priority, claim.core, claim.ticket, now, grant) {
                (ticket, Ok(())) => return self.hold(&mut state, claim, ticket, now),
                (ticket, Err(id)) => (Queued { turns: self, id, granted, taken: false }, state.observe(now), ticket),
            }
        };
        self.log(logged);
        // The sender is dropped only after it granted the turn.
        while tokio::time::timeout(SATURATION_TICK, &mut queued.granted).await.is_err() {
            let logged = self.lock().observe(Instant::now());
            self.log(logged);
        }
        queued.taken = true;
        let mut state = self.lock();
        self.hold(&mut state, claim, ticket, Instant::now())
    }

    /// Record `claim`'s worker as a holder from `now`.
    fn hold(&self, state: &mut State, claim: Claim, ticket: u64, now: Instant) -> Turn<'_> {
        let Claim { core, filter, kind, execution, .. } = claim;
        execution.hold_turn(kind, now);
        let id = state.next_holder;
        state.next_holder += 1;
        state.holders.push(Holder { id, core, filter, execution, since: now, warned: false });
        Turn { turns: self, id, ticket }
    }

    fn release(&self) {
        let logged = {
            let mut state = self.lock();
            while let Some(grant) = state.queue.next() {
                if grant.send(()).is_ok() {
                    break;
                }
            }
            state.observe(Instant::now())
        };
        self.log(logged);
    }

    fn log(&self, logged: Logged) {
        for (holder, waiting) in logged.overruns {
            tracing::warn!(core = holder.core, filter = %holder.filter, kind = holder.kind.as_str(),
                phase = %holder.phase, held_secs = holder.held.as_secs(), limit_secs = MAX_TURN_HOLD.as_secs(),
                installed_leaves = holder.installed, planned_leaves = holder.planned, waiting_workers = waiting,
                scope = "this node",
                action = "a replay ends its turn within 5 minutes and a batch, and a tree install hands its turn back \
                    at its first chunk boundary past the limit; held this long, a replay batch or an install chunk \
                    is slower than the limit (a slow archive, named by this worker's 'archive recovery' lines), or \
                    a repair of legacy shard state keeps its turn until it completes; report it with this line if \
                    one worker's turns keep running this long",
                "archive recovery turn held past its limit while workers wait");
        }
        match logged.saturation {
            Some((SaturationLog::Saturated { duration }, load, holders)) => tracing::warn!(
                waiting_workers = load.waiting, blocked_successors_waiting = load.blocked_successors,
                replays_waiting = load.replays,
                longest_wait_secs = load.longest_wait.as_secs(),
                longest_waiting_core = %load.front_core.map_or_else(|| "none".to_string(), |core| core.to_string()),
                permits = self.turns, saturated_secs = duration.as_secs(),
                holders = %holders.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "),
                scope = "this node",
                action = "this node recovers at most this many shards from archives at once to bound their load; \
                    workers wait their turn, frame replays before checkpoint installs and owed re-anchors, blocked \
                    successor sessions and voting members trailing their committee first, and no recovery holds a \
                    turn much past 10 minutes; holders names what the turns do now; with 'archive recovery \
                    failing' warnings check those first, otherwise it ends as the queue drains",
                "archive recovery turns saturated"),
            Some((SaturationLog::Cleared { duration }, _, _)) => tracing::info!(
                permits = self.turns, saturated_secs = duration.as_secs(),
                "archive recovery turns no longer saturated"),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn waiter(blocked: bool, replay: bool) -> Priority {
        Priority { blocked: Arc::new(AtomicBool::new(blocked)), reanchor: Arc::default(), lagging: Arc::default(), replay }
    }

    /// A lagging voter's replay.
    fn lagging() -> Priority {
        Priority { lagging: Arc::new(AtomicBool::new(true)), ..waiter(false, true) }
    }

    fn claim(core: u32, blocked: bool) -> Claim {
        let execution = SharedWorkerExecution::default();
        execution.set_successor_blocked(blocked);
        Claim { core, filter: vec![core as u8; 32], kind: RecoveryKind::Install, execution, ticket: None }
    }

    /// A worker's replay claim; `lagging` sets its lagging-voter flag.
    fn replay_claim(core: u32, lagging: bool) -> Claim {
        let execution = SharedWorkerExecution::default();
        execution.set_lagging_voter(lagging);
        Claim { core, filter: vec![core as u8; 32], kind: RecoveryKind::Replay, execution, ticket: None }
    }

    /// A worker's lagging-voter flag, read when a turn frees up, takes it
    /// the next turn before a replay that queued earlier.
    #[tokio::test]
    async fn turns_go_to_lagging_voters_first() {
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let held = turns.acquire(claim(1, false)).await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let run = |name: &'static str, core: u32, lagging: bool| {
            let order = order.clone();
            tokio::spawn(async move {
                let _turn = turns.acquire(replay_claim(core, lagging)).await;
                order.lock().unwrap().push(name);
            })
        };
        let replay = run("replay", 2, false);
        tokio::task::yield_now().await;
        let voter = run("lagging voter", 3, true);
        tokio::task::yield_now().await;
        assert_eq!(turns.lock().queue.waiters.len(), 2);
        drop(held);
        replay.await.unwrap();
        voter.await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["lagging voter", "replay"]);
    }

    /// Free turns are taken in arrival order; a blocked successor takes the
    /// next turn, judged when the turn frees up, not when it queued.
    #[test]
    fn a_successor_blocked_after_it_queued_takes_the_next_turn() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(2);
        assert_eq!(queue.take_or_queue(waiter(false, false), 1, now, "a"), Ok(()));
        assert_eq!(queue.take_or_queue(waiter(false, false), 2, now, "b"), Ok(()));
        let later = waiter(false, false);
        queue.take_or_queue(waiter(false, false), 3, now, "c").unwrap_err();
        queue.take_or_queue(later.clone(), 4, now, "blocked later").unwrap_err();
        queue.take_or_queue(waiter(true, false), 5, now, "blocked").unwrap_err();
        assert_eq!(queue.load(now).blocked_successors, 1);
        later.blocked.store(true, Ordering::Relaxed);
        assert_eq!(queue.load(now).blocked_successors, 2);
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["blocked later", "blocked", "c"]);
        // Once nobody waits, a released turn is free again.
        assert_eq!(queue.free, 1);
        assert_eq!(queue.take_or_queue(waiter(true, false), 6, now, "e"), Ok(()));
        queue.take_or_queue(waiter(true, false), 7, now, "f").unwrap_err();
    }

    /// Blocked successors take at most [`PRIORITY_RUN`] turns in a row past
    /// the longest waiter, so it is not starved.
    #[test]
    fn blocked_successors_do_not_starve_the_longest_waiter() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue.take_or_queue(waiter(false, false), 1, now, "regular").unwrap_err();
        for name in ["b1", "b2", "b3", "b4"] {
            queue.take_or_queue(waiter(true, false), 2, now, name).unwrap_err();
        }
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["b1", "b2", "regular", "b3", "b4"]);
    }

    /// A replay, a few batches at most, goes before checkpoint installs that
    /// queued earlier, a blocked successor's first; the longest waiter still
    /// gets a turn after [`PRIORITY_RUN`] in a row went past it.
    #[test]
    fn replays_go_before_checkpoint_installs() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue.take_or_queue(waiter(true, false), 1, now, "blocked install").unwrap_err();
        queue.take_or_queue(waiter(false, false), 2, now, "install").unwrap_err();
        queue.take_or_queue(waiter(false, true), 3, now, "replay").unwrap_err();
        queue.take_or_queue(waiter(true, true), 4, now, "blocked replay").unwrap_err();
        queue.take_or_queue(waiter(false, true), 5, now, "replay 2").unwrap_err();
        assert_eq!(queue.load(now).replays, 3);
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["blocked replay", "replay", "blocked install", "replay 2", "install"]);
    }

    /// A worker whose shard owes a re-anchor goes first, as a blocked
    /// successor's replay does, though its successor is no longer blocked:
    /// its sync makes the requested attempt (an operator's node:
    /// one queued at replay rank behind about 77 waiters, and the attempt
    /// went untaken).
    #[test]
    fn an_owed_reanchor_keeps_the_first_rank() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue.take_or_queue(waiter(false, true), 1, now, "replay").unwrap_err();
        queue.take_or_queue(waiter(true, false), 2, now, "blocked install").unwrap_err();
        let reanchor = waiter(false, true);
        reanchor.reanchor.store(true, Ordering::Relaxed);
        queue.take_or_queue(reanchor, 3, now, "re-anchor").unwrap_err();
        assert_eq!(queue.next(), Some("re-anchor"));
        assert_eq!(queue.next(), Some("replay"));
    }

    /// A recovery that handed its turn back keeps its place at the front,
    /// but takes at most every other turn while others wait: two long
    /// installs and the waiters behind them all progress.
    #[test]
    fn resumed_recoveries_keep_their_place_but_take_every_other_turn() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(2);
        let (long1, taken) = queue.take_or_requeue(waiter(false, false), 1, None, now, "long 1");
        assert_eq!(taken, Ok(()));
        let (long2, taken) = queue.take_or_requeue(waiter(false, false), 2, None, now, "long 2");
        assert_eq!(taken, Ok(()));
        for (core, name) in [(3, "s1"), (4, "s2"), (5, "s3"), (6, "s4")] {
            queue.take_or_queue(waiter(false, false), core, now, name).unwrap_err();
        }
        // Long 1 hands its turn back, then queues again in its first place.
        assert_eq!(queue.next(), Some("s1"));
        let (ticket, _) = queue.take_or_requeue(waiter(false, false), 1, Some(long1), now, "long 1 again");
        assert_eq!(ticket, long1);
        assert_eq!(queue.waiters.front().map(|w| w.core), Some(1), "it keeps its place");
        assert_eq!(queue.next(), Some("long 1 again"));
        queue.take_or_requeue(waiter(false, false), 2, Some(long2), now, "long 2 again").1.unwrap_err();
        assert_eq!(queue.next(), Some("s2"), "after a resumed recovery's turn another waiter's");
        assert_eq!(queue.next(), Some("long 2 again"));
        queue.take_or_requeue(waiter(false, false), 1, Some(long1), now, "long 1 third").1.unwrap_err();
        assert_eq!(queue.next(), Some("s3"));
        assert_eq!(queue.next(), Some("long 1 third"));
        assert_eq!(queue.next(), Some("s4"));
        assert_eq!(queue.next(), None);
    }

    /// A blocked successor replays further batches in its turn until the
    /// budget runs out or it is no longer blocked; others hand it back.
    #[test]
    fn only_a_blocked_successor_holds_its_turn_and_only_within_the_budget() {
        let blocked = Arc::new(AtomicBool::new(true));
        assert!(holds_turn(&[&*blocked], Duration::ZERO));
        assert!(holds_turn(&[&*blocked], BLOCKED_TURN_BUDGET - Duration::from_millis(1)));
        assert!(!holds_turn(&[&*blocked], BLOCKED_TURN_BUDGET));
        blocked.store(false, Ordering::Relaxed);
        assert!(!holds_turn(&[&*blocked], Duration::ZERO));
        assert!(!holds_turn(&[], Duration::ZERO));
    }

    /// A seated voter trailing its committee's committed tip goes first, as
    /// a blocked successor's replay does: before replays and installs that
    /// queued earlier (an operator's node: such a member waited up to 5
    /// hours per turn at replay rank, behind everyone each time).
    #[test]
    fn a_lagging_voter_goes_before_replays_and_installs() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue.take_or_queue(waiter(false, false), 1, now, "install").unwrap_err();
        queue.take_or_queue(waiter(false, true), 2, now, "replay").unwrap_err();
        queue.take_or_queue(waiter(true, false), 3, now, "blocked install").unwrap_err();
        queue.take_or_queue(lagging(), 4, now, "lagging voter").unwrap_err();
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["lagging voter", "replay", "install", "blocked install"]);
        // Once it caught up it is a replay like any other.
        let mut queue = TurnQueue::new(0);
        let caught_up = lagging();
        caught_up.lagging.store(false, Ordering::Relaxed);
        queue.take_or_queue(waiter(false, true), 5, now, "replay 2").unwrap_err();
        queue.take_or_queue(caught_up, 6, now, "caught up").unwrap_err();
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["replay 2", "caught up"]);
    }

    /// Lagging voters take at most [`PRIORITY_RUN`] turns in a row past the
    /// longest waiter, a replay queued before them.
    #[test]
    fn lagging_voters_do_not_starve_the_longest_waiter() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue.take_or_queue(waiter(false, true), 1, now, "replay").unwrap_err();
        for (core, name) in [(2, "l1"), (3, "l2"), (4, "l3"), (5, "l4")] {
            queue.take_or_queue(lagging(), core, now, name).unwrap_err();
        }
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["l1", "l2", "replay", "l3", "l4"]);
    }

    /// Two lagging voters queued again in their first places take at most
    /// every other turn while others wait, so they do not hold both turns.
    #[test]
    fn resumed_lagging_voters_take_every_other_turn() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(2);
        let (l1, _) = queue.take_or_requeue(lagging(), 1, None, now, "l1");
        let (l2, _) = queue.take_or_requeue(lagging(), 2, None, now, "l2");
        for (core, name) in [(3, "s1"), (4, "s2")] {
            queue.take_or_queue(waiter(false, false), core, now, name).unwrap_err();
        }
        queue.take_or_requeue(lagging(), 1, Some(l1), now, "l1 again").1.unwrap_err();
        queue.take_or_requeue(lagging(), 2, Some(l2), now, "l2 again").1.unwrap_err();
        assert_eq!(queue.next(), Some("l1 again"));
        assert_eq!(queue.next(), Some("s1"), "after a resumed recovery's turn another waiter's");
        assert_eq!(queue.next(), Some("l2 again"));
        assert_eq!(queue.next(), Some("s2"));
        assert_eq!(queue.next(), None);
    }

    #[test]
    fn a_withdrawn_waiter_leaves_the_queue() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(1);
        queue.take_or_queue(waiter(false, false), 1, now, 1).unwrap();
        let id = queue.take_or_queue(waiter(false, false), 2, now, 2).unwrap_err();
        queue.take_or_queue(waiter(true, false), 3, now + MINUTE, 3).unwrap_err();
        assert_eq!(queue.load(now + MINUTE * 2), QueueLoad {
            waiting: 2, blocked_successors: 1, replays: 0, longest_wait: MINUTE * 2, front_core: Some(2),
        });
        assert!(queue.withdraw(id));
        assert!(!queue.withdraw(id));
        assert_eq!(queue.next(), Some(3));
    }

    /// Saturation warns once a worker waited the threshold, then at most
    /// every repeat interval, and its end only after a warning.
    #[test]
    fn saturation_warns_at_a_bounded_rate_and_names_its_end() {
        let start = Instant::now();
        let load = |waiting, longest_wait| QueueLoad { waiting, blocked_successors: 0, replays: 0, longest_wait, front_core: None };
        let mut saturation = Saturation::new();
        assert_eq!(saturation.observe(start, load(1, Duration::ZERO)), None);
        assert_eq!(saturation.observe(start + MINUTE / 2, load(0, Duration::ZERO)), None, "brief waits are not named");
        assert_eq!(saturation.observe(start + MINUTE, load(3, Duration::ZERO)), None);
        assert_eq!(saturation.observe(start + MINUTE * 2, load(3, MINUTE)),
            Some(SaturationLog::Saturated { duration: MINUTE }));
        assert_eq!(saturation.observe(start + MINUTE * 11, load(9, MINUTE * 10)), None);
        assert_eq!(saturation.observe(start + MINUTE * 12, load(9, MINUTE * 11)),
            Some(SaturationLog::Saturated { duration: MINUTE * 11 }));
        assert_eq!(saturation.observe(start + MINUTE * 13, load(0, Duration::ZERO)),
            Some(SaturationLog::Cleared { duration: MINUTE * 12 }));
        assert_eq!(saturation.observe(start + MINUTE * 14, load(0, Duration::ZERO)), None);
        assert_eq!(saturation.observe(start + MINUTE * 15, load(1, MINUTE)),
            Some(SaturationLog::Saturated { duration: MINUTE }), "a later saturation warns afresh");
    }

    /// With every turn taken, a blocked successor that queued last runs
    /// next; a waiter dropped while queued neither holds nor loses a turn,
    /// and the drained queue ends the saturation period.
    #[tokio::test]
    async fn turns_go_to_blocked_successors_first() {
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let held = turns.acquire(claim(1, false)).await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let run = |name: &'static str, core: u32, blocked: bool| {
            let order = order.clone();
            tokio::spawn(async move {
                let _turn = turns.acquire(claim(core, blocked)).await;
                order.lock().unwrap().push(name);
            })
        };
        let dropped = run("dropped", 2, false);
        tokio::task::yield_now().await;
        let regular = run("regular", 3, false);
        tokio::task::yield_now().await;
        let blocked = run("blocked", 4, true);
        tokio::task::yield_now().await;
        assert_eq!(turns.lock().queue.waiters.len(), 3);
        dropped.abort();
        assert!(dropped.await.unwrap_err().is_cancelled());
        assert_eq!(turns.lock().queue.waiters.len(), 2);
        drop(held);
        regular.await.unwrap();
        blocked.await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["blocked", "regular"]);
        let state = turns.lock();
        assert_eq!((state.queue.free, state.queue.waiters.len(), state.holders.len()), (1, 0, 0));
        assert!(state.saturation.since.is_none(), "the drained queue ends the period");
    }

    /// A waiter dropped after its turn was granted, before it ran, passes
    /// the turn on rather than losing it.
    #[tokio::test]
    async fn a_turn_granted_to_a_dropped_waiter_passes_on() {
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let held = turns.acquire(claim(1, false)).await;
        let ran = Arc::new(Mutex::new(Vec::new()));
        let run = |name: &'static str, core: u32| {
            let ran = ran.clone();
            tokio::spawn(async move {
                let _turn = turns.acquire(claim(core, false)).await;
                ran.lock().unwrap().push(name);
            })
        };
        let first = run("first", 2);
        tokio::task::yield_now().await;
        let second = run("second", 3);
        tokio::task::yield_now().await;
        // Grants the turn to `first`, which is dropped before it runs.
        drop(held);
        assert_eq!(turns.lock().queue.waiters.len(), 1);
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), second).await.expect("the turn passed on").unwrap();
        assert_eq!(*ran.lock().unwrap(), ["second"]);
        let state = turns.lock();
        assert_eq!((state.queue.free, state.queue.waiters.len()), (1, 0));
    }

    /// A turn held past its overdue time while workers wait is warned about once,
    /// named by its holder's core, shard, kind, phase and leaves, as are the
    /// holders and the longest waiter in the saturation warning; its record
    /// shows the turn until it is released.
    #[tokio::test(start_paused = true)]
    async fn holders_are_named_and_an_overrun_is_warned_once() {
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let holder = claim(7, false);
        let execution = holder.execution.clone();
        let held = turns.acquire(holder).await;
        assert!(execution.turn().since.is_some());
        let waiting = tokio::spawn(async move { drop(turns.acquire(claim(9, false)).await) });
        tokio::task::yield_now().await;
        let start = Instant::now();
        let logged = turns.lock().observe(start + SATURATED_AFTER);
        let (log, load, holders) = logged.saturation.expect("saturated");
        assert!(matches!(log, SaturationLog::Saturated { .. }));
        assert_eq!((load.waiting, load.front_core), (1, Some(9)));
        assert_eq!(holders.len(), 1);
        assert_eq!((holders[0].core, holders[0].kind, holders[0].filter.as_str()), (7, RecoveryKind::Install, hex::encode([7u8; 32]).as_str()));
        assert!(holders[0].to_string().starts_with("core 7 install none held 60s leaves 0/0 filter 0707"), "{}", holders[0]);
        assert!(logged.overruns.is_empty());
        assert!(turns.lock().observe(start + MAX_TURN_HOLD).overruns.is_empty(),
            "an install hands its turn back at its next chunk boundary past the limit");
        let late = start + MAX_TURN_HOLD * 2;
        let overruns = turns.lock().observe(late).overruns;
        assert_eq!(overruns.len(), 1, "warned at twice the limit");
        assert_eq!((overruns[0].0.core, overruns[0].0.held, overruns[0].1), (7, MAX_TURN_HOLD * 2, 1));
        assert!(turns.lock().observe(late + MINUTE).overruns.is_empty(), "warned once per turn");
        drop(held);
        assert!(execution.turn().since.is_none(), "a released turn is no longer held");
        waiting.await.unwrap();
        assert!(turns.lock().holders.is_empty());
    }
}
