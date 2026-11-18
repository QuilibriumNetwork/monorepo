//! Archive shard recovery turns: the few recoveries a node's workers run at
//! once. A node's workers share its archive identity and so its per-peer
//! read slots; a few recover at a time rather than all failing busy
//! together. Turns go in arrival order, except that a worker replaying frames
//! onto those it holds goes before checkpoint installs, and a worker whose
//! successor session cannot start until its recovery lands, whose shard
//! owes a re-anchor, or that votes in its running session while it trails
//! the session's committed tip (a lagging voter), goes first: these reorder
//! the queue and add no concurrent recovery. A worker whose seat departs
//! (GLOBAL confirmed its leave) waits while any seat the node keeps waits,
//! unless it fills a short gap ([`DEPARTING_GAP_FILL_FRAMES`]). A blocked
//! successor or lagging voter also keeps its turn for further replay
//! batches, for at most [`BLOCKED_TURN_BUDGET`]. A replay whose turn ends
//! behind its target queues again in its first place. No recovery keeps a turn
//! much past [`MAX_TURN_HOLD`]: a tree install hands it back at its next
//! chunk boundary and queues again in its first place, resuming from the
//! leaves it installed, and the engine's own installation of a checkpoint
//! runs after the turn is released. A recovery that handed its turn back
//! takes at most every other turn while others wait ([`TurnQueue::next`]).
//! While a replay, a re-anchor or a blocked successor's replay waits,
//! checkpoint installs hold at most all but one turn: a node activating
//! several seats at once otherwise fills every turn with installs of up to
//! [`MAX_TURN_HOLD`] each, and its replays and successors wait for hours. An
//! install it passes over takes the first turn it may, so installs still
//! finish, one at a time.
//! A claim withdrawn while it waits because its worker's engine stopped
//! leaves its place to the same core's next claim of the same shard, which
//! queues there rather than behind every claim that arrived meanwhile: an
//! engine restarts on its seat at its activation, around a GLOBAL sync or
//! at an operator's action. The place serves one claim, and lapses
//! [`place_kept_for`] after its first withdrawal since its last turn.
//!
//! A turn bounds archive reads; a replay spends much of its turn on none, in
//! its own engine or waiting out this node's GLOBAL state sync. While it does
//! it lends the turn to the queue ([`lent_during`]) and takes the next one
//! that ends to fetch its next frame: archive reads stay at [`RECOVERY_TURNS`]
//! at once and at most [`MAX_LENT_TURNS`] more workers replay beside them. With
//! both turns kept through local work, 47 to 52 waiters on a node waited 10
//! to 80 minutes for batches taking 25 to 58 s (2026-11-03), 61 to 85% of it
//! local.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::worker_execution::SharedWorkerExecution;

/// Archive shard recoveries this process runs at once.
pub(crate) const RECOVERY_TURNS: usize = 2;

/// Turns lent out at once ([`lent_during`]): how many more workers than
/// [`RECOVERY_TURNS`] may be in a replay. Each replays on its own worker
/// thread and store, on the node's disk. Past this a replay keeps its turn
/// through its local work, as before lending existed.
pub(crate) const MAX_LENT_TURNS: usize = 6;

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

/// The most frames a worker whose seat departs may trail its known
/// committed tip by and still queue as the seats the node keeps do
/// (`SharedWorkerExecution::set_departing`): about one replay batch,
/// cheap, and it keeps the seat's vote alive until it departs, which its
/// committee's quorum may need. A longer catch-up or a checkpoint install
/// waits while any kept seat waits: on an operator's node every turn for
/// 2.5 hours went to departing seats installing 0.2 to 2.5 million leaves
/// while the one seat it kept waited. A thread worker holding no frame of
/// a departing seat's shard installs none of it
/// (`WorkerAllocator::departing_install`).
pub(crate) const DEPARTING_GAP_FILL_FRAMES: u64 = 32;

/// How long a worker waits for a turn before the queue counts as saturated.
const SATURATED_AFTER: Duration = Duration::from_secs(60);

/// How often saturated turns warn again.
const SATURATED_REPEAT: Duration = Duration::from_secs(10 * 60);

/// How often a waiting worker re-evaluates saturation while no turn moves.
const SATURATION_TICK: Duration = Duration::from_secs(60);

/// How long a withdrawn claim's place waits for its worker's next claim of
/// the shard ([`State::keep_place`]): an epoch of wall time from its first
/// withdrawal since the place last got a turn, at the GLOBAL frame interval
/// of this process's latest GLOBAL frame. An engine restarts within
/// seconds to minutes; on an operator's node the engine of a seat it kept
/// restarted seven times in 81 minutes while its recovery waited.
fn place_kept_for() -> Duration {
    Duration::from_millis(
        quil_types::consensus::epoch_length_frames()
            .saturating_mul(quil_types::consensus::ideal_frame_time_ms()),
    )
}

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
    /// Its seat departs and its recovery is more than a gap fill
    /// (`SharedWorkerExecution::set_departing`): it waits while any seat
    /// the node keeps waits.
    departing: Arc<AtomicBool>,
    /// It holds frames of its shard, so its turn replays at most a few
    /// batches onto them (or re-anchors at a fence) rather than installing a
    /// checkpoint, about half an hour per million leaves.
    replay: bool,
}

impl Priority {
    /// Turn order past the longest waiter, lowest first: an owed re-anchor
    /// or a blocked successor's or lagging voter's replay, a replay, a
    /// blocked successor's or lagging voter's install, an install.
    fn rank(&self) -> u8 {
        if self.reanchor.load(Ordering::Relaxed) {
            return 0;
        }
        let first = self.blocked.load(Ordering::Relaxed) || self.lagging.load(Ordering::Relaxed);
        match (self.replay, first) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        }
    }

    /// Its turn installs a checkpoint and may hold for [`MAX_TURN_HOLD`]: a
    /// blocked successor's install counts, an owed re-anchor does not.
    fn installs(&self) -> bool {
        self.rank() >= 2
    }
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
    /// Its [`Priority::rank`], read now.
    fn rank(&self) -> u8 {
        self.priority.rank()
    }

    /// Its turn would install a checkpoint ([`Priority::installs`]).
    fn installs(&self) -> bool {
        self.priority.installs()
    }

    /// Its seat departs and it needs more than a gap fill
    /// ([`DEPARTING_GAP_FILL_FRAMES`]): it waits while any other waits.
    fn departing(&self) -> bool {
        self.priority.departing.load(Ordering::Relaxed)
    }
}

/// The waiting workers in ticket order: arrival order, except that a
/// recovery queued again after handing its turn back keeps its first place.
#[derive(Debug)]
struct TurnQueue<T> {
    /// Turns in all.
    turns: usize,
    free: usize,
    /// Turns held by checkpoint installs ([`Priority::installs`], as judged
    /// when granted).
    installs: usize,
    next_id: u64,
    next_ticket: u64,
    /// Turns granted in a row past the longest waiter.
    bypassed: usize,
    /// The last turn went to a resumed waiter.
    after_resumed: bool,
    waiters: VecDeque<Waiter<T>>,
    /// Holders whose turn is lent out ([`lent_during`]), in local work.
    lent: usize,
    /// Holders back from local work waiting for a turn, by id: each goes
    /// before every waiter, or the workers lent to would keep their fetches
    /// from those already part way through a batch.
    returning: VecDeque<(u64, T)>,
}

impl<T> TurnQueue<T> {
    const fn new(turns: usize) -> Self {
        Self {
            turns,
            free: turns,
            installs: 0,
            next_id: 0,
            next_ticket: 0,
            bypassed: 0,
            after_resumed: false,
            waiters: VecDeque::new(),
            lent: 0,
            returning: VecDeque::new(),
        }
    }

    /// Whether a holder may lend its turn now: someone could use it, and
    /// fewer than [`MAX_LENT_TURNS`] are out.
    fn may_lend(&self) -> bool {
        self.lent < MAX_LENT_TURNS && !(self.waiters.is_empty() && self.returning.is_empty())
    }

    /// A holder back from local work asks for a turn: taken if one is free,
    /// else queued as `grant` under the returned id.
    fn take_back(&mut self, grant: T) -> Option<u64> {
        self.lent = self.lent.saturating_sub(1);
        if self.free > 0 {
            self.free -= 1;
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.returning.push_back((id, grant));
        Some(id)
    }

    /// Withdraw a returning holder; false when it already got its turn.
    fn withdraw_returning(&mut self, id: u64) -> bool {
        let Some(at) = self.returning.iter().position(|(held, _)| *held == id) else {
            return false;
        };
        self.returning.remove(at);
        true
    }

    /// A new arrival: [`Self::take_or_requeue`] without a ticket.
    #[cfg(test)]
    fn take_or_queue(
        &mut self,
        priority: Priority,
        core: u32,
        now: Instant,
        grant: T,
    ) -> Result<(), u64> {
        self.take_or_requeue(priority, core, None, now, grant)
            .1
            .map(|_install| ())
    }

    /// A turn that installs nothing ended: [`Self::next`]'s waiter.
    #[cfg(test)]
    fn pass(&mut self) -> Option<T> {
        self.next(false).map(|(grant, _install)| grant)
    }

    /// Take a free turn when nobody waits, and return whether it installs;
    /// otherwise queue `grant`, at the place of `ticket` when it has one, and
    /// return its id. Also returns its ticket: `ticket`, or a new one after
    /// every other.
    fn take_or_requeue(
        &mut self,
        priority: Priority,
        core: u32,
        ticket: Option<u64>,
        now: Instant,
        grant: T,
    ) -> (u64, Result<bool, u64>) {
        let resumed = ticket.is_some();
        let ticket = ticket.unwrap_or_else(|| {
            self.next_ticket += 1;
            self.next_ticket - 1
        });
        if self.free > 0 && self.waiters.is_empty() {
            self.free -= 1;
            let install = priority.installs();
            self.installs += usize::from(install);
            return (ticket, Ok(install));
        }
        let id = self.next_id;
        self.next_id += 1;
        let at = self
            .waiters
            .iter()
            .position(|w| w.ticket > ticket)
            .unwrap_or(self.waiters.len());
        self.waiters.insert(
            at,
            Waiter {
                id,
                ticket,
                resumed,
                priority,
                core,
                since: now,
                grant,
            },
        );
        (ticket, Err(id))
    }

    /// A turn ended: the waiter it goes to, or none (the turn is free). The
    /// first waiter of the lowest [`Waiter::rank`] goes first, unless
    /// [`PRIORITY_RUN`] turns in a row already went past the longest waiter.
    /// A departing seat's waiter ([`Waiter::departing`]) goes only once no
    /// other waits, whatever its rank, and the longest waiter is that of
    /// the seats the node keeps: a departing seat still votes until it
    /// departs, but a full install of its shard serves no seat the node
    /// keeps, and starves those that need one.
    ///
    /// A resumed waiter keeps its place, so a long install that handed its
    /// turn back is soon granted another, but after a turn went to a resumed
    /// waiter the next goes to one that is not, while any waits. Among equal
    /// ranks the first waiter always wins, so without this two long
    /// installs at the front would alternate on both turns until done; with
    /// it they take at most every other turn and the waiters behind them
    /// the rest. Requeued last instead, a 157,076-leaf install would wait
    /// behind every waiter for each of its about 77 turns.
    ///
    /// While any other waiter a turn may go to would not install, installs
    /// hold at most all but one turn: of two turns filled with installs, the
    /// first to hand back goes to a replay, and eight seats activating at
    /// once left an operator's replays waiting 20 to 90 minutes with
    /// installs on about 88% of the turn time. A longest waiter passed over
    /// this way stays counted, so once no install holds the last turn it may
    /// take it takes it at once. A queue of one turn reserves nothing: its
    /// installs would never run.
    ///
    /// `ended_install`: the turn that ended was an install's. Returns the
    /// waiter's grant and whether its turn installs.
    fn next(&mut self, ended_install: bool) -> Option<(T, bool)> {
        self.installs = self.installs.saturating_sub(usize::from(ended_install));
        if let Some((_, grant)) = self.returning.pop_front() {
            return Some((grant, false));
        }
        if self.waiters.is_empty() {
            self.free += 1;
            return None;
        }
        let keeps = self.waiters.iter().any(|w| !w.departing());
        let candidate = |w: &Waiter<T>| !(keeps && w.departing());
        let reserve = self.turns >= 2
            && self.installs + 1 >= self.turns
            && self.waiters.iter().any(|w| candidate(w) && !w.installs());
        let open = |w: &Waiter<T>| candidate(w) && !(reserve && w.installs());
        let skip_resumed = self.after_resumed && self.waiters.iter().any(|w| open(w) && !w.resumed);
        let eligible = |w: &Waiter<T>| open(w) && !(skip_resumed && w.resumed);
        let longest = self
            .waiters
            .iter()
            .position(|w| candidate(w) && !(skip_resumed && w.resumed));
        let first = self.waiters.iter().position(eligible).unwrap_or(0);
        let pick = if self.bypassed < PRIORITY_RUN {
            self.waiters
                .iter()
                .enumerate()
                .filter(|(_, w)| eligible(*w))
                .min_by_key(|(_, w)| w.rank())
                .map_or(first, |(at, _)| at)
        } else {
            first
        };
        self.bypassed = if Some(pick) == longest {
            0
        } else {
            self.bypassed.saturating_add(1)
        };
        let waiter = self.waiters.remove(pick)?;
        self.after_resumed = waiter.resumed;
        let install = waiter.installs();
        self.installs += usize::from(install);
        Some((waiter.grant, install))
    }

    /// Withdraw waiter `id`; false when it already got its turn.
    fn withdraw(&mut self, id: u64) -> bool {
        let Some(at) = self.waiters.iter().position(|w| w.id == id) else {
            return false;
        };
        self.waiters.remove(at);
        true
    }

    /// Waiting workers, of them blocked successors, replays and departing
    /// seats, the longest wait and whose it is, the turns installs hold and
    /// the longest wait of a waiter that would not install.
    fn load(&self, now: Instant) -> QueueLoad {
        QueueLoad {
            waiting: self.waiters.len(),
            blocked_successors: self
                .waiters
                .iter()
                .filter(|w| w.priority.blocked.load(Ordering::Relaxed))
                .count(),
            replays: self.waiters.iter().filter(|w| w.priority.replay).count(),
            departing: self.waiters.iter().filter(|w| w.departing()).count(),
            longest_wait: self
                .waiters
                .iter()
                .map(|w| now.saturating_duration_since(w.since))
                .max()
                .unwrap_or_default(),
            front_core: self.waiters.front().map(|w| w.core),
            install_turns: self.installs,
            lent_turns: self.lent,
            longest_replay_wait: self
                .waiters
                .iter()
                .filter(|w| !w.installs())
                .map(|w| now.saturating_duration_since(w.since))
                .max()
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueueLoad {
    waiting: usize,
    blocked_successors: usize,
    replays: usize,
    /// Waiters whose seat departs ([`Waiter::departing`]).
    departing: usize,
    longest_wait: Duration,
    /// The core of the longest waiter.
    front_core: Option<u32>,
    /// Turns held by checkpoint installs.
    install_turns: usize,
    /// Holders in local work, their turns lent out.
    lent_turns: usize,
    /// The longest wait of a waiter that would not install.
    longest_replay_wait: Duration,
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
        Self {
            since: None,
            warned: None,
        }
    }

    fn observe(&mut self, now: Instant, load: QueueLoad) -> Option<SaturationLog> {
        if load.waiting == 0 {
            let since = self.since.take();
            return self.warned.take().map(|_| SaturationLog::Cleared {
                duration: since
                    .map_or(Duration::ZERO, |since| now.saturating_duration_since(since)),
            });
        }
        let since = *self
            .since
            .get_or_insert_with(|| now.checked_sub(load.longest_wait).unwrap_or(now));
        if load.longest_wait < SATURATED_AFTER
            || self
                .warned
                .is_some_and(|at| now.saturating_duration_since(at) < SATURATED_REPEAT)
        {
            return None;
        }
        self.warned = Some(now);
        Some(SaturationLog::Saturated {
            duration: now.saturating_duration_since(since),
        })
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
            phase: if recovery.phase.is_empty() {
                "none".into()
            } else {
                recovery.phase
            },
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
        write!(
            f,
            "core {} {} {} held {}s leaves {}/{} filter {}",
            self.core,
            self.kind.as_str(),
            self.phase,
            self.held.as_secs(),
            self.installed,
            self.planned,
            self.filter
        )
    }
}

/// What a queue change logs.
#[derive(Debug, Default)]
struct Logged {
    saturation: Option<(SaturationLog, QueueLoad, Vec<HolderView>)>,
    /// Holders that just passed [`overdue_after`] while workers wait.
    overruns: Vec<(HolderView, usize)>,
}

/// The place of a claim withdrawn while it waited ([`Queued`]), kept for
/// its core's next claim of the shard.
#[derive(Debug)]
struct KeptPlace {
    core: u32,
    filter: Vec<u8>,
    ticket: u64,
    /// Its first withdrawal since it last got a turn.
    since: Instant,
}

struct State {
    queue: TurnQueue<oneshot::Sender<bool>>,
    saturation: Saturation,
    holders: Vec<Holder>,
    next_holder: u64,
    /// Places of withdrawn claims, at most one per core and shard.
    kept: Vec<KeptPlace>,
}

impl State {
    /// Keep `ticket`, the place of `core`'s withdrawn claim of `filter`,
    /// first withdrawn at `since`, for the core's next claim of the shard
    /// ([`Self::take_place`]), unless [`place_kept_for`] has passed since
    /// then. Of two places of one core and shard, the earlier stays.
    fn keep_place(&mut self, core: u32, filter: &[u8], ticket: u64, since: Instant, now: Instant) {
        let lasts = place_kept_for();
        self.kept
            .retain(|kept| now.saturating_duration_since(kept.since) < lasts);
        if now.saturating_duration_since(since) >= lasts {
            return;
        }
        match self
            .kept
            .iter_mut()
            .find(|kept| kept.core == core && kept.filter == filter)
        {
            Some(kept) => {
                kept.ticket = kept.ticket.min(ticket);
                kept.since = kept.since.min(since);
            }
            None => self.kept.push(KeptPlace {
                core,
                filter: filter.to_vec(),
                ticket,
                since,
            }),
        }
    }

    /// The place kept for `core`'s claim of `filter`, with its first
    /// withdrawal; it serves this claim only. A place the core kept for
    /// another shard lapses: its worker serves this one now.
    fn take_place(&mut self, core: u32, filter: &[u8], now: Instant) -> Option<(u64, Instant)> {
        let lasts = place_kept_for();
        let mut taken = None;
        self.kept.retain(|kept| {
            let current = now.saturating_duration_since(kept.since) < lasts;
            if kept.core != core {
                return current;
            }
            if current && kept.filter == filter {
                taken = Some((kept.ticket, kept.since));
            }
            false
        });
        taken
    }

    /// Re-evaluate saturation and the holders after a queue change or a tick
    /// at `now`. A turn held past [`overdue_after`] is warned about once,
    /// while workers wait for it.
    fn observe(&mut self, now: Instant) -> Logged {
        let load = self.queue.load(now);
        let mut overruns = Vec::new();
        if load.waiting > 0 {
            for holder in self.holders.iter_mut().filter(|holder| {
                !holder.warned
                    && now.saturating_duration_since(holder.since)
                        >= overdue_after(holder.execution.turn().kind)
            }) {
                holder.warned = true;
                overruns.push((holder.view(now), load.waiting));
            }
        }
        let saturation = self.saturation.observe(now, load).map(|logged| {
            (
                logged,
                load,
                self.holders.iter().map(|holder| holder.view(now)).collect(),
            )
        });
        Logged {
            saturation,
            overruns,
        }
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
    /// It counts as an install's turn ([`TurnQueue::installs`]).
    install: bool,
    /// Where its turn is: held, lent out, or being taken back.
    lending: AtomicU8,
}

/// [`Turn::lending`]: the holder has its turn.
const TURN_HELD: u8 = 0;
/// Lent out; counted in [`TurnQueue::lent`].
const TURN_LENT: u8 = 1;
/// Asked for back; no longer counted lent, and not yet held.
const TURN_RETURNING: u8 = 2;

/// Run `work`, which reads no archive, with `turn` lent to the queue, and
/// take a turn back after it, before the holder's next archive read. Without
/// a turn, with nobody waiting, or with [`MAX_LENT_TURNS`] out, the holder
/// just does the work holding it. Also returns how long taking it back took.
///
/// A lent turn cannot strand its queue: it goes on at once, and a holder back
/// from local work waits only for the next turn to end, before any waiter. A
/// turn ends within a replay's archive read, or at an install's hold limit.
/// Holders only leave while returning holders take every ended turn, so the
/// waiters are served again once those are through.
pub(crate) async fn lent_during<R>(
    turn: Option<&Turn<'_>>,
    work: impl std::future::Future<Output = R>,
) -> (R, Duration) {
    let Some(turn) = turn.filter(|turn| turn.lend()) else {
        return (work.await, Duration::ZERO);
    };
    let done = work.await;
    let asked = Instant::now();
    turn.take_back().await;
    (done, asked.elapsed())
}

/// The queue as a replay starts ([`Turn::replay_load`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayLoad {
    /// Workers in a replay's turn, this one and those lent out included.
    pub(crate) parallel_replays: u32,
    /// Of all turns, those lent out to local work now.
    pub(crate) lent_turns: u32,
    /// Workers waiting for a turn.
    pub(crate) queue_len: u32,
}

impl Turn<'_> {
    /// The queue now. A lent turn's holder stays a holder, so holders count
    /// each replay once.
    pub(crate) fn replay_load(&self) -> ReplayLoad {
        let state = self.turns.lock();
        let replaying = state
            .holders
            .iter()
            .filter(|holder| holder.execution.turn().kind == RecoveryKind::Replay)
            .count();
        ReplayLoad {
            parallel_replays: replaying as u32,
            lent_turns: state.queue.lent as u32,
            queue_len: state.queue.waiters.len() as u32,
        }
    }

    /// Lend this turn out, if it may be: an install's never is, since it
    /// holds its archive reads across its local work.
    fn lend(&self) -> bool {
        if self.install || self.lending.load(Ordering::Relaxed) != TURN_HELD {
            return false;
        }
        {
            let mut state = self.turns.lock();
            if !state.queue.may_lend() {
                return false;
            }
            state.queue.lent += 1;
        }
        self.lending.store(TURN_LENT, Ordering::Relaxed);
        self.turns.release(false);
        true
    }

    /// Hold a turn again. Dropped while it waits, the request leaves the
    /// queue, and a turn granted meanwhile passes on.
    async fn take_back(&self) {
        let (grant, granted) = oneshot::channel();
        self.lending.store(TURN_RETURNING, Ordering::Relaxed);
        let id = self.turns.lock().queue.take_back(grant);
        if let Some(id) = id {
            let mut returning = Returning {
                turns: self.turns,
                id,
                granted,
                taken: false,
            };
            // The sender is dropped only after it granted the turn.
            let _ = (&mut returning.granted).await;
            returning.taken = true;
        }
        self.lending.store(TURN_HELD, Ordering::Relaxed);
    }
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
            state
                .holders
                .iter()
                .position(|holder| holder.id == self.id)
                .map(|at| state.holders.swap_remove(at))
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
        match self.lending.load(Ordering::Relaxed) {
            TURN_HELD => self.turns.release(self.install),
            TURN_LENT => {
                let mut state = self.turns.lock();
                state.queue.lent = state.queue.lent.saturating_sub(1);
            }
            // [`Returning`] settled it as it dropped, before this.
            _ => {}
        }
    }
}

/// A lent turn's holder asking for one back. Dropped unanswered, it leaves
/// the queue; dropped answered, it passes the turn on.
struct Returning<'a> {
    turns: &'a RecoveryTurns,
    id: u64,
    granted: oneshot::Receiver<bool>,
    /// The turn was received.
    taken: bool,
}

impl Drop for Returning<'_> {
    fn drop(&mut self) {
        if self.taken {
            return;
        }
        let withdrawn = self.turns.lock().queue.withdraw_returning(self.id);
        if !withdrawn && self.granted.try_recv().is_ok() {
            self.turns.release(false);
        }
    }
}

/// A queued request for a turn; dropped unanswered, it leaves the queue,
/// its place kept for its core's next claim of the shard, and dropped
/// answered, it passes the turn on.
struct Queued<'a> {
    turns: &'a RecoveryTurns,
    id: u64,
    /// Answered with whether the granted turn installs.
    granted: oneshot::Receiver<bool>,
    /// The turn was received and is now held by a [`Turn`].
    taken: bool,
    core: u32,
    filter: Vec<u8>,
    ticket: u64,
    /// The first withdrawal of the place it took back, if it did
    /// ([`State::take_place`]).
    kept_since: Option<Instant>,
}

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        if self.taken {
            return;
        }
        let (withdrawn, logged) = {
            let mut state = self.turns.lock();
            let now = Instant::now();
            let withdrawn = state.queue.withdraw(self.id);
            if withdrawn {
                let since = self.kept_since.unwrap_or(now);
                state.keep_place(self.core, &self.filter, self.ticket, since, now);
            }
            (withdrawn, state.observe(now))
        };
        self.turns.log(logged);
        if !withdrawn {
            if let Ok(install) = self.granted.try_recv() {
                self.turns.release(install);
            }
        }
    }
}

impl RecoveryTurns {
    pub(crate) const fn new(turns: usize) -> Self {
        Self {
            turns,
            state: Mutex::new(State {
                queue: TurnQueue::new(turns),
                saturation: Saturation::new(),
                holders: Vec::new(),
                next_holder: 0,
                kept: Vec::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How long the longest waiter has waited for a turn.
    pub(crate) fn longest_wait(&self) -> Duration {
        self.lock().queue.load(Instant::now()).longest_wait
    }

    /// Workers waiting for a turn.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.lock().queue.waiters.len()
    }

    /// Wait for a turn. Replays go before checkpoint installs, and a worker
    /// whose successor-blocked, re-anchor or lagging-voter flag is set when
    /// a turn frees up before others of its kind ([`Waiter::rank`]). A new
    /// arrival takes the place its core's withdrawn claim of the shard left,
    /// if one is kept ([`State::take_place`]).
    pub(crate) async fn acquire(&self, claim: Claim) -> Turn<'_> {
        let priority = Priority {
            blocked: claim.execution.successor_blocked_flag(),
            reanchor: claim.execution.reanchor_armed_flag(),
            lagging: claim.execution.lagging_voter_flag(),
            departing: claim.execution.departing_flag(),
            replay: claim.kind == RecoveryKind::Replay,
        };
        let (grant, granted) = oneshot::channel();
        let (core, filter) = (claim.core, claim.filter.clone());
        let (mut queued, logged, ticket, kept) = {
            let mut state = self.lock();
            let now = Instant::now();
            let kept = match claim.ticket {
                Some(_) => None,
                None => state.take_place(core, &filter, now),
            };
            let place = claim.ticket.or(kept.map(|(ticket, _)| ticket));
            match state
                .queue
                .take_or_requeue(priority, core, place, now, grant)
            {
                (ticket, Ok(install)) => {
                    let turn = self.hold(&mut state, claim, ticket, install, now);
                    drop(state);
                    log_kept_place(core, &filter, kept);
                    return turn;
                }
                (ticket, Err(id)) => (
                    Queued {
                        turns: self,
                        id,
                        granted,
                        taken: false,
                        core,
                        filter: filter.clone(),
                        ticket,
                        kept_since: kept.map(|(_, since)| since),
                    },
                    state.observe(now),
                    ticket,
                    kept,
                ),
            }
        };
        log_kept_place(core, &filter, kept);
        self.log(logged);
        // The sender is dropped only after it granted the turn.
        let install = loop {
            match tokio::time::timeout(SATURATION_TICK, &mut queued.granted).await {
                Ok(granted) => break granted.unwrap_or_default(),
                Err(_) => {
                    let logged = self.lock().observe(Instant::now());
                    self.log(logged);
                }
            }
        };
        queued.taken = true;
        let mut state = self.lock();
        self.hold(&mut state, claim, ticket, install, Instant::now())
    }

    /// Record `claim`'s worker as a holder from `now`.
    fn hold(
        &self,
        state: &mut State,
        claim: Claim,
        ticket: u64,
        install: bool,
        now: Instant,
    ) -> Turn<'_> {
        let Claim {
            core,
            filter,
            kind,
            execution,
            ..
        } = claim;
        execution.hold_turn(kind, now);
        let id = state.next_holder;
        state.next_holder += 1;
        state.holders.push(Holder {
            id,
            core,
            filter,
            execution,
            since: now,
            warned: false,
        });
        Turn {
            turns: self,
            id,
            ticket,
            install,
            lending: AtomicU8::new(TURN_HELD),
        }
    }

    /// Keep `ticket`, the place of `core`'s recovery of `filter` that handed
    /// its turn back and whose engine then stopped, for the core's next claim
    /// of the shard, as a withdrawn claim's is ([`State::keep_place`]).
    pub(crate) fn keep_place(&self, core: u32, filter: &[u8], ticket: u64) {
        let now = Instant::now();
        self.lock().keep_place(core, filter, ticket, now, now);
    }

    /// A turn ended; `install`: it was an install's. A grant whose waiter
    /// has gone ends a turn of the class it was granted as.
    fn release(&self, install: bool) {
        let logged = {
            let mut state = self.lock();
            let mut ended = install;
            while let Some((grant, granted)) = state.queue.next(ended) {
                if grant.send(granted).is_ok() {
                    break;
                }
                ended = granted;
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
                replays_waiting = load.replays, departing_waiting = load.departing,
                longest_wait_secs = load.longest_wait.as_secs(),
                install_turns = load.install_turns, lent_turns = load.lent_turns,
                longest_replay_wait_secs = load.longest_replay_wait.as_secs(),
                longest_waiting_core = %load.front_core.map_or_else(|| "none".to_string(), |core| core.to_string()),
                permits = self.turns, saturated_secs = duration.as_secs(),
                holders = %holders.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "),
                scope = "this node",
                action = "this node reads for at most this many shard recoveries from archives at once to bound their load, \
                    and lent_turns more replay meanwhile on this node's own engines; \
                    workers wait their turn, frame replays before checkpoint installs and owed re-anchors, blocked \
                    successor sessions and voting members trailing their committee first, seats whose leave GLOBAL \
                    confirmed after every other unless they fill a gap of at most 32 frames, and no recovery holds a \
                    turn much past 10 minutes; with replays waiting, installs hold at most permits-1 turns once one \
                    hands back, so if install_turns equals permits and longest_replay_wait_secs is past 1200, installs \
                    are crowding out replays: report it; holders names what the turns do now; with 'archive recovery \
                    failing' warnings check those first, otherwise it ends as the queue drains",
                "archive recovery turns saturated"),
            Some((SaturationLog::Cleared { duration }, _, _)) => tracing::info!(
                permits = self.turns,
                saturated_secs = duration.as_secs(),
                "archive recovery turns no longer saturated"
            ),
            None => {}
        }
    }
}

/// Name a claim that took back the place its core's withdrawn claim of the
/// shard left ([`State::take_place`]), with that place's first withdrawal.
fn log_kept_place(core: u32, filter: &[u8], kept: Option<(u64, Instant)>) {
    if let Some((_, since)) = kept {
        tracing::info!(core, filter = %hex::encode(filter),
            withdrawn_secs = since.elapsed().as_secs(), scope = "this node's worker",
            "archive recovery queues again in the place its stopped engine's request held: \
            the shard engine restarted on this core");
    }
}

#[cfg(test)]
mod lending_tests {
    use super::*;

    fn replay(core: u32) -> Claim {
        Claim {
            core,
            filter: vec![core as u8; 32],
            kind: RecoveryKind::Replay,
            execution: SharedWorkerExecution::default(),
            ticket: None,
        }
    }

    fn install(core: u32) -> Claim {
        Claim {
            kind: RecoveryKind::Install,
            ..replay(core)
        }
    }

    fn leaked(turns: usize) -> &'static RecoveryTurns {
        Box::leak(Box::new(RecoveryTurns::new(turns)))
    }

    /// A worker that takes a turn, tells `got`, and holds it until `end`.
    fn taking(
        turns: &'static RecoveryTurns,
        core: u32,
    ) -> (
        tokio::task::JoinHandle<()>,
        oneshot::Receiver<()>,
        oneshot::Sender<()>,
    ) {
        let (got_tx, got) = oneshot::channel();
        let (end, end_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _turn = turns.acquire(replay(core)).await;
            got_tx.send(()).unwrap();
            let _ = end_rx.await;
        });
        (task, got, end)
    }

    async fn settles<T>(wait: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .expect("it never came")
    }

    /// The lent turn reaches a waiter while its holder works; back from the
    /// work the holder waits for it, then goes before every other waiter.
    #[tokio::test]
    async fn a_lent_turn_serves_a_waiter_and_its_holder_goes_first_after() {
        let turns = leaked(1);
        let held = turns.acquire(replay(1)).await;
        let (second, got_second, end_second) = taking(turns, 2);
        tokio::task::yield_now().await;
        let (third, mut got_third, end_third) = taking(turns, 3);
        tokio::task::yield_now().await;
        let (worked, work) = oneshot::channel::<()>();
        let lending = lent_during(Some(&held), async {
            settles(got_second).await.unwrap();
            let _ = worked.send(());
        });
        let mut lending = Box::pin(lending);
        // The work ended; the holder cannot read yet: the second has the turn.
        let waiting = tokio::time::timeout(Duration::from_millis(200), &mut lending).await;
        assert!(waiting.is_err(), "the holder waits for a turn to end");
        settles(work).await.unwrap();
        end_second.send(()).unwrap();
        settles(&mut lending).await;
        assert!(
            got_third.try_recv().is_err(),
            "the holder went before the third"
        );
        assert_eq!(turns.lock().queue.lent, 0);
        drop(lending);
        drop(held);
        settles(got_third).await.unwrap();
        end_third.send(()).unwrap();
        settles(second).await.unwrap();
        settles(third).await.unwrap();
        settles(turns.acquire(replay(9))).await;
    }

    /// Holders in a replay count once, lent out or not; an install's turn
    /// and a waiter are no replay running.
    #[tokio::test]
    async fn a_replays_load_counts_replays_in_their_turns_and_the_queue() {
        let turns = leaked(2);
        let first = turns.acquire(replay(1)).await;
        let installing = turns.acquire(install(2)).await;
        let load = |parallel_replays, lent_turns, queue_len| ReplayLoad {
            parallel_replays,
            lent_turns,
            queue_len,
        };
        assert_eq!(first.replay_load(), load(1, 0, 0));
        let (second, got_second, end_second) = taking(turns, 3);
        tokio::task::yield_now().await;
        let (third, got_third, end_third) = taking(turns, 4);
        tokio::task::yield_now().await;
        assert_eq!(first.replay_load(), load(1, 0, 2));
        lent_during(Some(&first), async {
            settles(got_second).await.unwrap();
            assert_eq!(first.replay_load(), load(2, 1, 1));
            drop(installing);
            settles(got_third).await.unwrap();
            assert_eq!(first.replay_load(), load(3, 1, 0));
            end_second.send(()).unwrap();
            settles(second).await.unwrap();
        })
        .await;
        assert_eq!(first.replay_load(), load(2, 0, 0));
        end_third.send(()).unwrap();
        settles(third).await.unwrap();
    }

    /// With nobody waiting there is nothing to lend for.
    #[tokio::test]
    async fn a_turn_nobody_waits_for_is_not_lent() {
        let turns = leaked(1);
        let held = turns.acquire(replay(1)).await;
        let (_, took) = lent_during(Some(&held), async {
            assert_eq!(turns.lock().queue.lent, 0);
        })
        .await;
        assert_eq!(took, Duration::ZERO);
        assert_eq!(held.lending.load(Ordering::Relaxed), TURN_HELD);
    }

    /// An install reads the archive across its work: its turn stays.
    #[tokio::test]
    async fn an_install_keeps_its_turn() {
        let turns = leaked(1);
        let held = turns.acquire(install(1)).await;
        assert!(held.install);
        let (_second, _got, _end) = taking(turns, 2);
        tokio::task::yield_now().await;
        lent_during(Some(&held), async {
            assert_eq!(turns.lock().queue.lent, 0, "not lent");
        })
        .await;
    }

    /// At most [`MAX_LENT_TURNS`] are out: the next holder keeps its turn
    /// through its work, so the waiters behind it wait.
    #[tokio::test]
    async fn no_more_than_the_limit_are_lent() {
        let turns = leaked(1);
        let gate = turns.acquire(replay(1000)).await;
        let (hold, mut in_work) = (Arc::new(tokio::sync::Notify::new()), Vec::new());
        // Queued behind the gate: each takes its turn in order and lends it,
        // staying in its work.
        for core in 0..=MAX_LENT_TURNS as u32 + 1 {
            let (hold, (tx, rx)) = (hold.clone(), oneshot::channel());
            tokio::spawn(async move {
                let turn = turns.acquire(replay(core)).await;
                lent_during(Some(&turn), async {
                    tx.send(()).unwrap();
                    hold.notified().await;
                })
                .await;
            });
            tokio::task::yield_now().await;
            in_work.push(rx);
        }
        let (_last, mut got_last, _end) = taking(turns, 99);
        tokio::task::yield_now().await;
        drop(gate);
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let working = in_work
            .iter_mut()
            .filter_map(|rx| rx.try_recv().ok())
            .count();
        assert_eq!(turns.lock().queue.lent, MAX_LENT_TURNS);
        assert_eq!(
            working,
            MAX_LENT_TURNS + 1,
            "the limit's holders and the one keeping its turn"
        );
        assert!(
            got_last.try_recv().is_err(),
            "the turn was not lent past the limit"
        );
    }

    /// Past the limit a waiter is served within a bounded number of ended
    /// turns, even while every holder comes back from its local work at once
    /// and queues again for another batch. Holders back from local work take
    /// every ended turn before any waiter, but none joins them meanwhile,
    /// and each ends its turn after its batch: once no more hold, lend or
    /// wait to take one back than there are turns, the next ended turn
    /// reaches a waiter, and of two in a row at most one goes to a holder
    /// queued again in its first place ([`TurnQueue::next`]). So at most
    /// [`MAX_LENT_TURNS`] + 2 turns end before it is served: its wait is
    /// bounded by the holders' batches.
    #[tokio::test]
    async fn a_waiter_past_the_lending_limit_is_served_once_the_holders_batches_end() {
        use std::sync::atomic::AtomicUsize;
        // Frames per batch, each an archive read and a lent replay.
        const FRAMES: usize = 3;
        let turns = leaked(RECOVERY_TURNS);
        let mut gates = Vec::new();
        for core in 0..RECOVERY_TURNS as u32 {
            gates.push(turns.acquire(replay(1000 + core)).await);
        }
        let (hold, ended, served) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicBool::new(false)),
        );
        let (mut holders, mut in_work) = (Vec::new(), Vec::new());
        // Queued behind the gates: each takes its turn in order and lends it,
        // up to the limit, in its first frame's work, which lasts until every
        // holder is in one; later work ends at once, so each comes back while
        // another's turn is lent.
        for core in 0..(RECOVERY_TURNS + MAX_LENT_TURNS) as u32 {
            let (hold, ended, served) = (hold.clone(), ended.clone(), served.clone());
            let (tx, rx) = oneshot::channel();
            let mut first = Some(tx);
            holders.push(tokio::spawn(async move {
                let mut ticket = None;
                while !served.load(Ordering::Relaxed) {
                    let turn = turns
                        .acquire(Claim {
                            ticket,
                            ..replay(core)
                        })
                        .await;
                    for _ in 0..FRAMES {
                        tokio::task::yield_now().await;
                        let (first, hold) = (first.take(), &hold);
                        lent_during(Some(&turn), async move {
                            if let Some(tx) = first {
                                tx.send(()).unwrap();
                                hold.notified().await;
                            }
                            tokio::task::yield_now().await;
                        })
                        .await;
                    }
                    ticket = Some(turn.ticket());
                    // Counted while the waiter (core 99) still queues.
                    let waits = turns.lock().queue.waiters.iter().any(|w| w.core == 99);
                    ended.fetch_add(usize::from(waits), Ordering::Relaxed);
                    drop(turn);
                }
            }));
            tokio::task::yield_now().await;
            in_work.push(rx);
        }
        let (waiter, got, end) = taking(turns, 99);
        tokio::task::yield_now().await;
        drop(gates);
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let working = in_work
            .iter_mut()
            .filter_map(|rx| rx.try_recv().ok())
            .count();
        assert_eq!(turns.lock().queue.lent, MAX_LENT_TURNS);
        assert_eq!(working, RECOVERY_TURNS + MAX_LENT_TURNS);
        assert_eq!(turns.waiting(), 1, "only the waiter queues");
        hold.notify_waiters();
        settles(got).await.unwrap();
        served.store(true, Ordering::Relaxed);
        let ended_before = ended.load(Ordering::Relaxed);
        assert!(
            ended_before <= MAX_LENT_TURNS + 2,
            "the waiter was served after {ended_before} turns ended"
        );
        end.send(()).unwrap();
        settles(waiter).await.unwrap();
        for holder in holders {
            settles(holder).await.unwrap();
        }
        assert_eq!(turns.lock().queue.lent, 0);
    }

    /// A holder stopped in its local work owns no turn: none is released
    /// twice, and the count of lent turns comes back.
    #[tokio::test]
    async fn a_holder_stopped_while_its_turn_is_lent_releases_nothing() {
        let turns = leaked(1);
        let held = turns.acquire(replay(1)).await;
        let (second, got, end) = taking(turns, 2);
        tokio::task::yield_now().await;
        {
            let lending = lent_during(Some(&held), std::future::pending::<()>());
            let mut lending = Box::pin(lending);
            assert!(futures_poll_once(&mut lending).await.is_none());
        }
        drop(held);
        settles(got).await.unwrap();
        assert_eq!(turns.lock().queue.lent, 0);
        // The second holds the only turn: a third must wait for it.
        let (third, mut got_third, end_third) = taking(turns, 3);
        tokio::task::yield_now().await;
        assert!(got_third.try_recv().is_err(), "one turn, not two");
        end.send(()).unwrap();
        settles(second).await.unwrap();
        settles(got_third).await.unwrap();
        end_third.send(()).unwrap();
        settles(third).await.unwrap();
    }

    /// A holder stopped while it waits to take a turn back leaves that wait:
    /// the turn goes on to the next waiter.
    #[tokio::test]
    async fn a_holder_stopped_taking_its_turn_back_leaves_the_queue() {
        let turns = leaked(1);
        let held = turns.acquire(replay(1)).await;
        let (second, got, end) = taking(turns, 2);
        tokio::task::yield_now().await;
        {
            let lending = lent_during(Some(&held), std::future::ready(()));
            let mut lending = Box::pin(lending);
            assert!(futures_poll_once(&mut lending).await.is_none());
            settles(got).await.unwrap();
            assert_eq!(turns.lock().queue.returning.len(), 1);
        }
        assert_eq!(turns.lock().queue.returning.len(), 0);
        drop(held);
        end.send(()).unwrap();
        settles(second).await.unwrap();
        settles(turns.acquire(replay(9))).await;
    }

    /// One poll of `future`.
    async fn futures_poll_once<F: std::future::Future + Unpin>(
        future: &mut F,
    ) -> Option<F::Output> {
        tokio::time::timeout(Duration::from_millis(50), future)
            .await
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn waiter(blocked: bool, replay: bool) -> Priority {
        Priority {
            blocked: Arc::new(AtomicBool::new(blocked)),
            reanchor: Arc::default(),
            lagging: Arc::default(),
            departing: Arc::default(),
            replay,
        }
    }

    /// A lagging voter's replay.
    fn lagging() -> Priority {
        Priority {
            lagging: Arc::new(AtomicBool::new(true)),
            ..waiter(false, true)
        }
    }

    fn claim(core: u32, blocked: bool) -> Claim {
        let execution = SharedWorkerExecution::default();
        execution.set_successor_blocked(blocked);
        Claim {
            core,
            filter: vec![core as u8; 32],
            kind: RecoveryKind::Install,
            execution,
            ticket: None,
        }
    }

    /// A worker's replay claim; `lagging` sets its lagging-voter flag.
    fn replay_claim(core: u32, lagging: bool) -> Claim {
        let execution = SharedWorkerExecution::default();
        execution.set_lagging_voter(lagging);
        Claim {
            core,
            filter: vec![core as u8; 32],
            kind: RecoveryKind::Replay,
            execution,
            ticket: None,
        }
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
        assert_eq!(
            queue.take_or_queue(waiter(false, false), 1, now, "a"),
            Ok(())
        );
        assert_eq!(
            queue.take_or_queue(waiter(false, false), 2, now, "b"),
            Ok(())
        );
        let later = waiter(false, false);
        queue
            .take_or_queue(waiter(false, false), 3, now, "c")
            .unwrap_err();
        queue
            .take_or_queue(later.clone(), 4, now, "blocked later")
            .unwrap_err();
        queue
            .take_or_queue(waiter(true, false), 5, now, "blocked")
            .unwrap_err();
        assert_eq!(queue.load(now).blocked_successors, 1);
        later.blocked.store(true, Ordering::Relaxed);
        assert_eq!(queue.load(now).blocked_successors, 2);
        let order: Vec<_> = std::iter::from_fn(|| queue.pass()).collect();
        assert_eq!(order, ["blocked later", "blocked", "c"]);
        // Once nobody waits, a released turn is free again.
        assert_eq!(queue.free, 1);
        assert_eq!(
            queue.take_or_queue(waiter(true, false), 6, now, "e"),
            Ok(())
        );
        queue
            .take_or_queue(waiter(true, false), 7, now, "f")
            .unwrap_err();
    }

    /// Blocked successors take at most [`PRIORITY_RUN`] turns in a row past
    /// the longest waiter, so it is not starved.
    #[test]
    fn blocked_successors_do_not_starve_the_longest_waiter() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue
            .take_or_queue(waiter(false, false), 1, now, "regular")
            .unwrap_err();
        for name in ["b1", "b2", "b3", "b4"] {
            queue
                .take_or_queue(waiter(true, false), 2, now, name)
                .unwrap_err();
        }
        let order: Vec<_> = std::iter::from_fn(|| queue.pass()).collect();
        assert_eq!(order, ["b1", "b2", "regular", "b3", "b4"]);
    }

    /// A replay, a few batches at most, goes before checkpoint installs that
    /// queued earlier, a blocked successor's first; the longest waiter still
    /// gets a turn after [`PRIORITY_RUN`] in a row went past it.
    #[test]
    fn replays_go_before_checkpoint_installs() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue
            .take_or_queue(waiter(true, false), 1, now, "blocked install")
            .unwrap_err();
        queue
            .take_or_queue(waiter(false, false), 2, now, "install")
            .unwrap_err();
        queue
            .take_or_queue(waiter(false, true), 3, now, "replay")
            .unwrap_err();
        queue
            .take_or_queue(waiter(true, true), 4, now, "blocked replay")
            .unwrap_err();
        queue
            .take_or_queue(waiter(false, true), 5, now, "replay 2")
            .unwrap_err();
        assert_eq!(queue.load(now).replays, 3);
        let order: Vec<_> = std::iter::from_fn(|| queue.pass()).collect();
        assert_eq!(
            order,
            [
                "blocked replay",
                "replay",
                "blocked install",
                "replay 2",
                "install"
            ]
        );
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
        queue
            .take_or_queue(waiter(false, true), 1, now, "replay")
            .unwrap_err();
        queue
            .take_or_queue(waiter(true, false), 2, now, "blocked install")
            .unwrap_err();
        let reanchor = waiter(false, true);
        reanchor.reanchor.store(true, Ordering::Relaxed);
        queue
            .take_or_queue(reanchor, 3, now, "re-anchor")
            .unwrap_err();
        assert_eq!(queue.pass(), Some("re-anchor"));
        assert_eq!(queue.pass(), Some("replay"));
    }

    /// A recovery that handed its turn back keeps its place at the front,
    /// but takes at most every other turn while others wait: two long
    /// installs and the waiters behind them all progress.
    #[test]
    fn resumed_recoveries_keep_their_place_but_take_every_other_turn() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(2);
        let (long1, taken) = queue.take_or_requeue(waiter(false, false), 1, None, now, "long 1");
        assert_eq!(taken, Ok(true));
        let (long2, taken) = queue.take_or_requeue(waiter(false, false), 2, None, now, "long 2");
        assert_eq!(taken, Ok(true));
        for (core, name) in [(3, "s1"), (4, "s2"), (5, "s3"), (6, "s4")] {
            queue
                .take_or_queue(waiter(false, false), core, now, name)
                .unwrap_err();
        }
        // Long 1 hands its turn back, then queues again in its first place.
        assert_eq!(queue.pass(), Some("s1"));
        let (ticket, _) =
            queue.take_or_requeue(waiter(false, false), 1, Some(long1), now, "long 1 again");
        assert_eq!(ticket, long1);
        assert_eq!(
            queue.waiters.front().map(|w| w.core),
            Some(1),
            "it keeps its place"
        );
        assert_eq!(queue.pass(), Some("long 1 again"));
        queue
            .take_or_requeue(waiter(false, false), 2, Some(long2), now, "long 2 again")
            .1
            .unwrap_err();
        assert_eq!(
            queue.pass(),
            Some("s2"),
            "after a resumed recovery's turn another waiter's"
        );
        assert_eq!(queue.pass(), Some("long 2 again"));
        queue
            .take_or_requeue(waiter(false, false), 1, Some(long1), now, "long 1 third")
            .1
            .unwrap_err();
        assert_eq!(queue.pass(), Some("s3"));
        assert_eq!(queue.pass(), Some("long 1 third"));
        assert_eq!(queue.pass(), Some("s4"));
        assert_eq!(queue.pass(), None);
    }

    /// With a replay waiting, installs hold at most all but one turn once
    /// one hands back; the longest waiter, an install passed over meanwhile,
    /// takes the next install turn the moment one frees.
    #[test]
    fn installs_leave_a_turn_to_waiting_replays() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(2);
        for (core, name) in [(1, "i1"), (2, "i2")] {
            assert_eq!(
                queue
                    .take_or_requeue(waiter(false, false), core, None, now, name)
                    .1,
                Ok(true)
            );
        }
        queue
            .take_or_queue(waiter(false, false), 3, now, "i3")
            .unwrap_err();
        for (core, name) in [(4, "r1"), (5, "r2"), (6, "r3")] {
            queue
                .take_or_queue(waiter(false, true), core, now, name)
                .unwrap_err();
        }
        let load = queue.load(now + MINUTE);
        assert_eq!(
            (load.install_turns, load.longest_replay_wait),
            (2, MINUTE),
            "the warning names both"
        );
        assert_eq!(
            queue.next(true),
            Some(("r1", false)),
            "install 1 handed back"
        );
        assert_eq!(queue.next(false), Some(("r2", false)));
        assert_eq!(
            queue.next(false),
            Some(("r3", false)),
            "the longest waiter's run is due, but install 2 holds the only turn installs may"
        );
        for (core, name) in [(7, "r4"), (8, "r5")] {
            queue
                .take_or_queue(waiter(false, true), core, now, name)
                .unwrap_err();
        }
        assert_eq!(
            queue.next(true),
            Some(("i3", true)),
            "install 2 handed back: the install passed over goes at once"
        );
        assert_eq!(queue.next(false), Some(("r4", false)));
        assert_eq!(queue.next(false), Some(("r5", false)));
        assert_eq!(queue.installs, 1);
        assert_eq!(queue.next(true), None);
        assert_eq!((queue.installs, queue.free), (0, 1));
    }

    /// Two installs of 4 turns each, with a replay arriving as every turn
    /// ends: from the first hand-back on, installs never hold both turns
    /// while a replay waits, and both still finish, one at a time.
    #[test]
    fn an_install_still_finishes_while_replays_keep_arriving() {
        const INSTALL_TURN: Duration = Duration::from_secs(600);
        const REPLAY_TURN: Duration = Duration::from_secs(40);
        #[derive(Clone, Copy)]
        enum Held {
            /// Which of the two installs.
            Install(usize),
            Replay,
        }
        let start = Instant::now();
        let mut queue = TurnQueue::new(2);
        let mut left = [4u32, 4];
        let mut tickets = [0u64; 2];
        let mut ends: Vec<(Instant, Held)> = Vec::new();
        for at in 0..2 {
            let (ticket, taken) = queue.take_or_requeue(
                waiter(false, false),
                at as u32,
                None,
                start,
                Held::Install(at),
            );
            assert_eq!(taken, Ok(true));
            tickets[at] = ticket;
            ends.push((start + INSTALL_TURN, Held::Install(at)));
        }
        let deadline = start + Duration::from_secs(8 * 700);
        let mut core = 2;
        while left != [0, 0] {
            let soonest = (0..ends.len())
                .min_by_key(|&at| ends[at].0)
                .expect("a turn is always held");
            let (now, ended) = ends.remove(soonest);
            assert!(now <= deadline, "installs left past the deadline: {left:?}");
            // A replay arrives, then the turn passes on, then an install
            // that handed back queues again in its first place.
            core += 1;
            queue
                .take_or_queue(waiter(false, true), core, now, Held::Replay)
                .unwrap_err();
            let ended_install = matches!(ended, Held::Install(_));
            let (granted, _) = queue.next(ended_install).expect("a replay waits");
            ends.push((
                now + match granted {
                    Held::Install(_) => INSTALL_TURN,
                    Held::Replay => REPLAY_TURN,
                },
                granted,
            ));
            if let Held::Install(at) = ended {
                left[at] -= 1;
                if left[at] > 0 {
                    queue
                        .take_or_requeue(
                            waiter(false, false),
                            at as u32,
                            Some(tickets[at]),
                            now,
                            Held::Install(at),
                        )
                        .1
                        .unwrap_err();
                }
            }
            assert!(
                queue.installs < 2 || !queue.waiters.iter().any(|w| !w.installs()),
                "installs hold both turns while a replay waits at {:?}",
                now - start
            );
        }
    }

    /// Through the turns themselves: a dropped install's turn goes to a
    /// replay while the other install holds a turn, and the install waiting
    /// takes the next one as that install hands back.
    #[tokio::test]
    async fn installs_leave_a_turn_to_replays_until_one_hands_back() {
        async fn next_grant(
            grants: &mut tokio::sync::mpsc::UnboundedReceiver<&'static str>,
        ) -> &'static str {
            tokio::time::timeout(Duration::from_secs(60), grants.recv())
                .await
                .expect("a turn was granted")
                .expect("a waiter is left")
        }
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(2)));
        let install_1 = turns.acquire(claim(1, false)).await;
        let install_2 = turns.acquire(claim(2, false)).await;
        let (granted, mut grants) = tokio::sync::mpsc::unbounded_channel();
        let mut ends = std::collections::HashMap::new();
        let mut tasks = Vec::new();
        let waiters = [
            ("install 3", claim(3, false)),
            ("replay 4", replay_claim(4, false)),
            ("replay 5", replay_claim(5, false)),
            ("replay 6", replay_claim(6, false)),
            ("replay 7", replay_claim(7, false)),
        ];
        for (name, seat) in waiters {
            let (end, ended) = oneshot::channel::<()>();
            ends.insert(name, end);
            let granted = granted.clone();
            tasks.push(tokio::spawn(async move {
                let turn = turns.acquire(seat).await;
                granted.send(name).unwrap();
                let _ = ended.await;
                drop(turn);
            }));
            tokio::task::yield_now().await;
        }
        assert_eq!(turns.waiting(), 5);
        drop(install_1);
        assert_eq!(next_grant(&mut grants).await, "replay 4");
        ends.remove("replay 4").unwrap().send(()).unwrap();
        assert_eq!(next_grant(&mut grants).await, "replay 5");
        ends.remove("replay 5").unwrap().send(()).unwrap();
        assert_eq!(next_grant(&mut grants).await, "replay 6");
        drop(install_2);
        assert_eq!(next_grant(&mut grants).await, "install 3");
        ends.remove("replay 6").unwrap().send(()).unwrap();
        assert_eq!(next_grant(&mut grants).await, "replay 7");
        ends.remove("replay 7").unwrap().send(()).unwrap();
        ends.remove("install 3").unwrap().send(()).unwrap();
        for task in tasks {
            task.await.unwrap();
        }
        let state = turns.lock();
        assert_eq!(
            (
                state.queue.free,
                state.queue.installs,
                state.queue.waiters.len(),
                state.holders.len()
            ),
            (2, 0, 0, 0)
        );
    }

    /// A blocked successor replays further batches in its turn until the
    /// budget runs out or it is no longer blocked; others hand it back.
    #[test]
    fn only_a_blocked_successor_holds_its_turn_and_only_within_the_budget() {
        let blocked = Arc::new(AtomicBool::new(true));
        assert!(holds_turn(&[&*blocked], Duration::ZERO));
        assert!(holds_turn(
            &[&*blocked],
            BLOCKED_TURN_BUDGET - Duration::from_millis(1)
        ));
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
        queue
            .take_or_queue(waiter(false, false), 1, now, "install")
            .unwrap_err();
        queue
            .take_or_queue(waiter(false, true), 2, now, "replay")
            .unwrap_err();
        queue
            .take_or_queue(waiter(true, false), 3, now, "blocked install")
            .unwrap_err();
        queue
            .take_or_queue(lagging(), 4, now, "lagging voter")
            .unwrap_err();
        let order: Vec<_> = std::iter::from_fn(|| queue.pass()).collect();
        assert_eq!(
            order,
            ["lagging voter", "replay", "install", "blocked install"]
        );
        // Once it caught up it is a replay like any other.
        let mut queue = TurnQueue::new(0);
        let caught_up = lagging();
        caught_up.lagging.store(false, Ordering::Relaxed);
        queue
            .take_or_queue(waiter(false, true), 5, now, "replay 2")
            .unwrap_err();
        queue
            .take_or_queue(caught_up, 6, now, "caught up")
            .unwrap_err();
        let order: Vec<_> = std::iter::from_fn(|| queue.pass()).collect();
        assert_eq!(order, ["replay 2", "caught up"]);
    }

    /// Lagging voters take at most [`PRIORITY_RUN`] turns in a row past the
    /// longest waiter, a replay queued before them.
    #[test]
    fn lagging_voters_do_not_starve_the_longest_waiter() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue
            .take_or_queue(waiter(false, true), 1, now, "replay")
            .unwrap_err();
        for (core, name) in [(2, "l1"), (3, "l2"), (4, "l3"), (5, "l4")] {
            queue.take_or_queue(lagging(), core, now, name).unwrap_err();
        }
        let order: Vec<_> = std::iter::from_fn(|| queue.pass()).collect();
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
            queue
                .take_or_queue(waiter(false, false), core, now, name)
                .unwrap_err();
        }
        queue
            .take_or_requeue(lagging(), 1, Some(l1), now, "l1 again")
            .1
            .unwrap_err();
        queue
            .take_or_requeue(lagging(), 2, Some(l2), now, "l2 again")
            .1
            .unwrap_err();
        assert_eq!(queue.pass(), Some("l1 again"));
        assert_eq!(
            queue.pass(),
            Some("s1"),
            "after a resumed recovery's turn another waiter's"
        );
        assert_eq!(queue.pass(), Some("l2 again"));
        assert_eq!(queue.pass(), Some("s2"));
        assert_eq!(queue.pass(), None);
    }

    /// A worker whose seat departs waits while any seat the node keeps
    /// waits, whatever its rank and however long it waited: every third
    /// turn goes to the longest waiting kept seat. Once none waits, the
    /// departing seats take turns in their usual order.
    #[test]
    fn departing_seats_wait_for_every_kept_seat() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        let departing = |blocked, replay| Priority {
            departing: Arc::new(AtomicBool::new(true)),
            ..waiter(blocked, replay)
        };
        queue
            .take_or_queue(departing(true, true), 1, now, "departing blocked replay")
            .unwrap_err();
        queue
            .take_or_queue(departing(false, false), 2, now, "departing install")
            .unwrap_err();
        for (core, name) in [(3, "install 1"), (4, "install 2"), (5, "install 3")] {
            queue
                .take_or_queue(waiter(false, false), core, now, name)
                .unwrap_err();
        }
        queue
            .take_or_queue(waiter(false, true), 6, now, "replay")
            .unwrap_err();
        assert_eq!(queue.load(now).departing, 2);
        let order: Vec<_> = std::iter::from_fn(|| queue.pass()).collect();
        assert_eq!(
            order,
            [
                "replay",
                "install 1",
                "install 2",
                "install 3",
                "departing blocked replay",
                "departing install"
            ]
        );
    }

    #[test]
    fn a_withdrawn_waiter_leaves_the_queue() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(1);
        queue
            .take_or_queue(waiter(false, false), 1, now, 1)
            .unwrap();
        let id = queue
            .take_or_queue(waiter(false, false), 2, now, 2)
            .unwrap_err();
        queue
            .take_or_queue(waiter(true, false), 3, now + MINUTE, 3)
            .unwrap_err();
        assert_eq!(
            queue.load(now + MINUTE * 2),
            QueueLoad {
                waiting: 2,
                blocked_successors: 1,
                replays: 0,
                departing: 0,
                longest_wait: MINUTE * 2,
                front_core: Some(2),
                install_turns: 1,
                longest_replay_wait: Duration::ZERO,
                lent_turns: 0,
            }
        );
        assert!(queue.withdraw(id));
        assert!(!queue.withdraw(id));
        assert_eq!(queue.pass(), Some(3));
    }

    /// Saturation warns once a worker waited the threshold, then at most
    /// every repeat interval, and its end only after a warning.
    #[test]
    fn saturation_warns_at_a_bounded_rate_and_names_its_end() {
        let start = Instant::now();
        let load = |waiting, longest_wait| QueueLoad {
            waiting,
            blocked_successors: 0,
            replays: 0,
            departing: 0,
            longest_wait,
            front_core: None,
            install_turns: 0,
            longest_replay_wait: Duration::ZERO,
            lent_turns: 0,
        };
        let mut saturation = Saturation::new();
        assert_eq!(saturation.observe(start, load(1, Duration::ZERO)), None);
        assert_eq!(
            saturation.observe(start + MINUTE / 2, load(0, Duration::ZERO)),
            None,
            "brief waits are not named"
        );
        assert_eq!(
            saturation.observe(start + MINUTE, load(3, Duration::ZERO)),
            None
        );
        assert_eq!(
            saturation.observe(start + MINUTE * 2, load(3, MINUTE)),
            Some(SaturationLog::Saturated { duration: MINUTE })
        );
        assert_eq!(
            saturation.observe(start + MINUTE * 11, load(9, MINUTE * 10)),
            None
        );
        assert_eq!(
            saturation.observe(start + MINUTE * 12, load(9, MINUTE * 11)),
            Some(SaturationLog::Saturated {
                duration: MINUTE * 11
            })
        );
        assert_eq!(
            saturation.observe(start + MINUTE * 13, load(0, Duration::ZERO)),
            Some(SaturationLog::Cleared {
                duration: MINUTE * 12
            })
        );
        assert_eq!(
            saturation.observe(start + MINUTE * 14, load(0, Duration::ZERO)),
            None
        );
        assert_eq!(
            saturation.observe(start + MINUTE * 15, load(1, MINUTE)),
            Some(SaturationLog::Saturated { duration: MINUTE }),
            "a later saturation warns afresh"
        );
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
        assert_eq!(
            (
                state.queue.free,
                state.queue.waiters.len(),
                state.holders.len()
            ),
            (1, 0, 0)
        );
        assert!(
            state.saturation.since.is_none(),
            "the drained queue ends the period"
        );
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
        tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .expect("the turn passed on")
            .unwrap();
        assert_eq!(*ran.lock().unwrap(), ["second"]);
        let state = turns.lock();
        assert_eq!((state.queue.free, state.queue.waiters.len()), (1, 0));
        assert_eq!(
            state.queue.installs, 0,
            "the dropped waiter's install turn ended with it"
        );
    }

    /// A claim withdrawn as its worker's engine stopped leaves its place to
    /// the same core's next claim of the same shard, once, and to no other
    /// core's or shard's claim; the place lapses an epoch of wall time after
    /// its first withdrawal, though the claims that took it were withdrawn
    /// in turn, and once the core claims another shard.
    #[tokio::test(start_paused = true)]
    async fn a_withdrawn_place_serves_its_own_seat_once_within_an_epoch() {
        let lasts = place_kept_for();
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let _held = turns.acquire(claim(9, false)).await;
        let queue = |core: u32, shard: u8| {
            let mut seat = claim(core, false);
            seat.filter = vec![shard; 32];
            tokio::spawn(async move { drop(turns.acquire(seat).await) })
        };
        let places = || -> Vec<(u32, u64)> {
            let state = turns.lock();
            let waiters = state.queue.waiters.iter();
            waiters.map(|w| (w.core, w.ticket)).collect()
        };
        let withdraw = |task: tokio::task::JoinHandle<()>| async move {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        };
        let first = queue(1, 1);
        tokio::task::yield_now().await;
        assert_eq!(places(), [(1, 1)]);
        withdraw(first).await;
        let _other_core = queue(2, 1);
        tokio::task::yield_now().await;
        let again = queue(1, 1);
        tokio::task::yield_now().await;
        let twice = queue(1, 1);
        tokio::task::yield_now().await;
        assert_eq!(
            places(),
            [(1, 1), (2, 2), (1, 3)],
            "taken back once, by its own seat"
        );
        // Withdrawn again half an epoch on, it keeps its first withdrawal.
        tokio::time::advance(lasts / 2).await;
        withdraw(twice).await;
        withdraw(again).await;
        let third = queue(1, 1);
        tokio::task::yield_now().await;
        assert_eq!(places(), [(1, 1), (2, 2)]);
        tokio::time::advance(lasts / 2).await;
        withdraw(third).await;
        let fourth = queue(1, 1);
        tokio::task::yield_now().await;
        assert_eq!(
            places(),
            [(2, 2), (1, 4)],
            "lapsed an epoch after its first withdrawal"
        );
        // The core claims another shard: the place it kept lapses.
        withdraw(fourth).await;
        let moved = queue(1, 2);
        tokio::task::yield_now().await;
        withdraw(moved).await;
        let _back = queue(1, 1);
        tokio::task::yield_now().await;
        assert_eq!(places(), [(2, 2), (1, 6)]);
        assert!(turns.lock().kept.is_empty());
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
        assert_eq!(
            (holders[0].core, holders[0].kind, holders[0].filter.as_str()),
            (7, RecoveryKind::Install, hex::encode([7u8; 32]).as_str())
        );
        assert!(
            holders[0]
                .to_string()
                .starts_with("core 7 install none held 60s leaves 0/0 filter 0707"),
            "{}",
            holders[0]
        );
        assert!(logged.overruns.is_empty());
        assert!(
            turns
                .lock()
                .observe(start + MAX_TURN_HOLD)
                .overruns
                .is_empty(),
            "an install hands its turn back at its next chunk boundary past the limit"
        );
        let late = start + MAX_TURN_HOLD * 2;
        let overruns = turns.lock().observe(late).overruns;
        assert_eq!(overruns.len(), 1, "warned at twice the limit");
        assert_eq!(
            (overruns[0].0.core, overruns[0].0.held, overruns[0].1),
            (7, MAX_TURN_HOLD * 2, 1)
        );
        assert!(
            turns.lock().observe(late + MINUTE).overruns.is_empty(),
            "warned once per turn"
        );
        drop(held);
        assert!(
            execution.turn().since.is_none(),
            "a released turn is no longer held"
        );
        waiting.await.unwrap();
        assert!(turns.lock().holders.is_empty());
    }
}
