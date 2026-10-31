//! Marks what a worker thread or a master task is running, so that a
//! watchdog on another thread can name what blocks it.
//!
//! Each worker thread runs a current-thread runtime: one synchronous call
//! that does not return stalls every task on it, among them consensus
//! messages and votes. A worker thread installs a [`ThreadProbe`]; its
//! heartbeat task [`ThreadProbe::beat`]s it, [`probed`] marks the task
//! being polled, [`step`] the step a task is in, and [`section`] guards
//! mark synchronous sections. A master task, which moves between the
//! threads of a multi-thread runtime, carries its own probe instead
//! ([`task_probed`]) and [`beat`]s it each time its loop comes round.
//! Every mark is a few atomic stores, and on threads without a probe
//! (tests, untracked tasks) a no-op. A [`detail`] names what a section
//! works on (a frame, a shard): it takes the probe's uncontended detail
//! lock twice, so it marks units of work, not loop iterations.
use std::cell::RefCell;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;

macro_rules! sections {
    ($($name:ident => $label:literal,)*) => {
        /// A named task, task step or synchronous section of a worker thread.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum Section {
            None = 0,
            $($name,)*
        }

        impl Section {
            const ALL: &'static [Section] = &[Section::None, $(Section::$name,)*];

            pub fn label(self) -> &'static str {
                match self {
                    Section::None => "none",
                    $(Section::$name => $label,)*
                }
            }
        }
    };
}

sections! {
    // Tasks a worker thread polls.
    WorkerLoop => "worker command loop",
    AppEngine => "app engine",
    EngineEvents => "app engine event forwarding",
    ArchiveRecovery => "archive recovery",
    PayloadEviction => "payload eviction",
    // Steps of the app engine's loop.
    EngineMessage => "inbound message",
    EngineFrameMessage => "inbound app frame",
    EngineReplayArchiveFrame => "archive frame replay",
    EngineSyncAnchor => "archive sync anchor validation",
    EngineSyncCompleted => "shard sync checkpoint",
    EngineBootstrapCompleted => "archive bootstrap install",
    EngineFinalizedFrame => "finalized frame",
    EngineTransportReady => "consensus start on transport readiness",
    EngineCleanupTimer => "cleanup timer",
    EngineDeliveryTimer => "delivery source timer",
    EngineRetryTimer => "consensus retry timer",
    EngineUpkeep => "loop upkeep",
    // Synchronous sections.
    CommitLockWait => "CRDT commit lock wait",
    GlobalViewCapture => "GLOBAL committed view capture",
    FinalizedRecordsScan => "finalized records scan",
    FenceRewind => "fence rewind check",
    SessionResolve => "committee session resolve",
    PredecessorHistorySources => "predecessor history sources",
    SuccessorStateCheck => "successor state check",
    SessionGenesis => "session genesis output",
    CommitteeBuild => "committee build",
    SeatRead => "seat read",
    SuccessorPriority => "successor priority read",
    PredecessorBlockReport => "successor block report",
    CommitteeMembers => "committee members read",
    SessionLiveness => "session liveness report",
    PresenceReport => "presence report",
    OwnVotes => "own vote tracking",
    ConsensusPhase => "consensus phase read",
    StagedDataCheck => "staged data check",
    FrameStoreCleanup => "frame store cleanup",
    PreStateHeal => "pre-state heal check",
    GenesisSupersededCheck => "adopted genesis check",
    LegacyHistoryCheck => "legacy history discard check",
    EvictedLineageCheck => "evicted lineage check",
    StorageEpochProofCheck => "storage epoch proof check",
    HeldFrameCheck => "held frame re-check",
    LaggingVoterCheck => "lagging voter check",
    SessionStatusCheck => "committee session status check",
    // Master tasks.
    MessageLoop => "message loop",
    ArchivePoller => "archive frame poller",
    ArchiveIngest => "archive application frame ingest",
    GlobalMaterializer => "GLOBAL frame materializer",
    // Steps of the archive application frame ingest.
    IngestFrame => "gossiped application frame",
    IngestRetry => "ingest retry pass",
    // Steps of the master's message loop.
    LoopRemoteDirect => "remote worker topic tick",
    LoopCommitteePeers => "committee peer tick",
    LoopStatus => "status tick",
    LoopMessage => "inbound message",
    LoopPeerInfo => "inbound peer info",
    LoopGlobalFrame => "inbound GLOBAL frame",
    // Steps of the archive frame poller.
    PollerGossipFollow => "gossip-carried frame follow",
    PollerConnect => "archive connect",
    PollerHeadFetch => "archive head fetch",
    PollerHeadFrame => "archive head frame processing",
    PollerFillFetch => "archive catch-up fetch",
    PollerFillFrame => "archive catch-up frame processing",
    PollerReconnect => "archive reconnect",
    PollerRefetch => "archive fetch on a fresh connection",
    // Steps of the GLOBAL materializer.
    MaterializerFinalization => "GLOBAL finalization step",
    MaterializerIngest => "application-frame ingest before GLOBAL execution",
    MaterializerAtomic => "canonical GLOBAL frame atomic execution",
    MaterializerExecute => "GLOBAL frame execution in place",
    // Synchronous sections of master tasks.
    LatestGlobalFrameRead => "latest GLOBAL frame read",
    ProverInfoRead => "own prover info read",
    GlobalFrameValidation => "GLOBAL frame validation",
    GlobalFrameRequestsRoot => "GLOBAL frame requests root check",
    GlobalFrameStore => "GLOBAL frame store",
    GlobalFrameExecution => "GLOBAL frame execution",
    SequencedIngest => "application frames a GLOBAL frame sequences",
    PollerFrameCallback => "poller frame callback",
    ProverRegistryRefresh => "prover registry refresh",
    AllocationReconcile => "worker allocation reconcile",
    ShardSizeRead => "local shard size read",
    LifecycleEvaluate => "prover lifecycle evaluation",
    // Archive application-frame ingest.
    ArchiveIngestLockWait => "archive ingest lock wait",
    SequencedPreverify => "sequenced proof pre-verification (does not hold the ingest lock)",
    AppFramePreverify => "app-shard frame proof pre-verification",
    AppFramePricing => "app-shard frame bundle pricing",
    AppFrameProcess => "app-shard frame bundle execution",
    AppFrameCommit => "app-shard frame commit",
    // Clock store lock waits, marked only when the lock is contended.
    ClockCacheWait => "GLOBAL frame cache lock wait",
    ClockWriterWait => "GLOBAL frame writer lock wait",
    ClockLoadWait => "GLOBAL frame load lock wait",
}

impl Section {
    fn from_id(id: u8) -> Section {
        Section::ALL
            .get(id as usize)
            .copied()
            .unwrap_or(Section::None)
    }
}

const MS_BITS: u32 = 56;
const MS_MASK: u64 = (1 << MS_BITS) - 1;
/// The beat of a task waiting with no deadline ([`ThreadProbe::idle`]).
const IDLE: u64 = u64::MAX;

fn pack(section: Section, at_ms: u64) -> u64 {
    if section == Section::None {
        return 0;
    }
    ((section as u64) << MS_BITS) | (at_ms & MS_MASK)
}

fn unpack(value: u64) -> Option<Mark> {
    let section = Section::from_id((value >> MS_BITS) as u8);
    (section != Section::None).then_some(Mark {
        section,
        since_ms: value & MS_MASK,
    })
}

/// Milliseconds since this process first asked; the probe's clock.
pub fn now_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// A marked task, step or section and when it began ([`now_ms`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    pub section: Section,
    pub since_ms: u64,
}

/// What one worker thread or master task was last seen doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// When it last beat ([`now_ms`]); see [`Snapshot::idle`].
    pub last_beat_ms: u64,
    /// The task being polled.
    pub task: Option<Mark>,
    /// The step the app engine's task last entered.
    pub step: Option<Mark>,
    /// The innermost synchronous section.
    pub section: Option<Mark>,
    /// The outermost synchronous section.
    pub outer: Option<Mark>,
}

impl Snapshot {
    /// It waits with no deadline (an empty endpoint pool, a state jump)
    /// since it last beat: not blocked until it beats again.
    pub fn idle(&self) -> bool {
        self.last_beat_ms == IDLE
    }
}

/// One worker thread's or master task's marks, written by that thread or
/// task and read by a watchdog.
pub struct ThreadProbe {
    beat: AtomicU64,
    task: AtomicU64,
    step: AtomicU64,
    section: AtomicU64,
    outer: AtomicU64,
    filter: Mutex<Vec<u8>>,
    detail: Mutex<String>,
}

impl ThreadProbe {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            beat: AtomicU64::new(now_ms()),
            task: AtomicU64::new(0),
            step: AtomicU64::new(0),
            section: AtomicU64::new(0),
            outer: AtomicU64::new(0),
            filter: Mutex::new(Vec::new()),
            detail: Mutex::new(String::new()),
        })
    }

    /// The thread ran its heartbeat task: it is not blocked.
    pub fn beat(&self) {
        self.beat_at(now_ms());
    }

    /// A beat at `at_ms` on the probe's clock ([`now_ms`]).
    pub fn beat_at(&self, at_ms: u64) {
        self.beat.store(at_ms, Ordering::Relaxed);
    }

    /// The task now waits with no deadline; its next beat ends the wait.
    pub fn idle(&self) {
        self.beat.store(IDLE, Ordering::Relaxed);
    }

    /// The shard this thread's worker is bound to (empty: none).
    pub fn set_filter(&self, filter: &[u8]) {
        let mut held = self.filter.lock().unwrap_or_else(|e| e.into_inner());
        held.clear();
        held.extend_from_slice(filter);
    }

    pub fn filter(&self) -> Vec<u8> {
        self.filter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// What the marked work is about ([`detail`]), empty when unnamed.
    pub fn detail(&self) -> String {
        self.detail
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            last_beat_ms: self.beat.load(Ordering::Relaxed),
            task: unpack(self.task.load(Ordering::Relaxed)),
            step: unpack(self.step.load(Ordering::Relaxed)),
            section: unpack(self.section.load(Ordering::Relaxed)),
            outer: unpack(self.outer.load(Ordering::Relaxed)),
        }
    }
}

std::thread_local! {
    static CURRENT: RefCell<Option<Arc<ThreadProbe>>> = const { RefCell::new(None) };
}

fn current() -> Option<Arc<ThreadProbe>> {
    CURRENT
        .try_with(|current| current.borrow().clone())
        .ok()
        .flatten()
}

fn with_current(mark: impl FnOnce(&ThreadProbe)) {
    let _ = CURRENT.try_with(|current| {
        if let Some(probe) = current.borrow().as_deref() {
            mark(probe);
        }
    });
}

/// The probe installed on this thread until [`Installed`] drops.
pub fn install(probe: Arc<ThreadProbe>) -> Installed {
    let previous = CURRENT.with(|current| current.replace(Some(probe)));
    Installed {
        previous,
        _thread: PhantomData,
    }
}

/// Uninstalls its probe, restoring the one it replaced, when dropped.
pub struct Installed {
    previous: Option<Arc<ThreadProbe>>,
    _thread: PhantomData<*const ()>,
}

impl Drop for Installed {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let _ = CURRENT.try_with(|current| current.replace(previous));
    }
}

/// Mark a synchronous section until the guard drops. Not `Send`: a guard
/// held across an `.await` would mark the section while other tasks run.
pub fn section(section: Section) -> SectionGuard {
    let Some(probe) = current() else {
        return SectionGuard {
            entered: None,
            _thread: PhantomData,
        };
    };
    let previous = probe.section.load(Ordering::Relaxed);
    let mark = pack(section, now_ms());
    if previous == 0 {
        probe.outer.store(mark, Ordering::Relaxed);
    }
    probe.section.store(mark, Ordering::Relaxed);
    SectionGuard {
        entered: Some((probe, previous)),
        _thread: PhantomData,
    }
}

pub struct SectionGuard {
    entered: Option<(Arc<ThreadProbe>, u64)>,
    _thread: PhantomData<*const ()>,
}

impl Drop for SectionGuard {
    fn drop(&mut self) {
        if let Some((probe, previous)) = self.entered.take() {
            probe.section.store(previous, Ordering::Relaxed);
            if previous == 0 {
                probe.outer.store(0, Ordering::Relaxed);
            }
        }
    }
}

/// Name what the current work is about (a frame, a shard) until the guard
/// drops; nested details are joined with `: `. Formatted only when a probe
/// is installed. Not `Send`, as [`section`].
pub fn detail(args: std::fmt::Arguments<'_>) -> DetailGuard {
    let Some(probe) = current() else {
        return DetailGuard {
            entered: None,
            _thread: PhantomData,
        };
    };
    let mut held = probe.detail.lock().unwrap_or_else(|e| e.into_inner());
    let previous = held.len();
    if previous > 0 {
        held.push_str(": ");
    }
    let _ = std::fmt::Write::write_fmt(&mut *held, args);
    drop(held);
    DetailGuard {
        entered: Some((probe, previous)),
        _thread: PhantomData,
    }
}

pub struct DetailGuard {
    entered: Option<(Arc<ThreadProbe>, usize)>,
    _thread: PhantomData<*const ()>,
}

impl Drop for DetailGuard {
    fn drop(&mut self) {
        if let Some((probe, previous)) = self.entered.take() {
            probe
                .detail
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .truncate(previous);
        }
    }
}

/// Mark the step the app engine's task entered; it stays until the next.
pub fn step(step: Section) {
    if let Some(probe) = current() {
        probe.step.store(pack(step, now_ms()), Ordering::Relaxed);
    }
}

/// A master task's loop came round: beat the probe of the task being polled
/// ([`task_probed`]) and clear its step.
pub fn beat() {
    with_current(|probe| {
        probe.beat();
        probe.step.store(0, Ordering::Relaxed);
    });
}

/// The master task being polled now waits with no deadline, as for an
/// archive endpoint or a state jump: not blocked until its next [`beat`].
pub fn idle() {
    with_current(|probe| {
        probe.idle();
        probe.step.store(0, Ordering::Relaxed);
    });
}

/// Install `probe` on the thread that polls `future`, during each poll: a
/// master task moves between the threads of a multi-thread runtime, so its
/// marks follow the task rather than a thread.
pub fn task_probed<F: Future>(probe: Arc<ThreadProbe>, future: F) -> TaskProbed<F> {
    TaskProbed {
        probe,
        future: Box::pin(future),
    }
}

pub struct TaskProbed<F> {
    probe: Arc<ThreadProbe>,
    future: Pin<Box<F>>,
}

impl<F: Future> Future for TaskProbed<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // Uninstalled when the poll returns or panics.
        let _installed = install(self.probe.clone());
        self.future.as_mut().poll(cx)
    }
}

/// Mark `task` as the task being polled during each of its polls.
pub fn probed<F: Future>(task: Section, future: F) -> Probed<F> {
    Probed {
        task,
        future: Box::pin(future),
    }
}

pub struct Probed<F> {
    task: Section,
    future: Pin<Box<F>>,
}

impl<F: Future> Future for Probed<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let Some(probe) = current() else {
            return self.future.as_mut().poll(cx);
        };
        let previous = probe
            .task
            .swap(pack(self.task, now_ms()), Ordering::Relaxed);
        // Restored even when the poll panics: the runtime catches a task's
        // panic and the thread lives on.
        let _restore = RestoreTask { probe, previous };
        self.future.as_mut().poll(cx)
    }
}

struct RestoreTask {
    probe: Arc<ThreadProbe>,
    previous: u64,
}

impl Drop for RestoreTask {
    fn drop(&mut self) {
        self.probe.task.store(self.previous, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_nest_and_restore_and_cost_nothing_without_a_probe() {
        drop(section(Section::SuccessorStateCheck));
        let probe = ThreadProbe::new();
        let installed = install(probe.clone());
        {
            let _outer = section(Section::SuccessorStateCheck);
            {
                let _inner = section(Section::CommitLockWait);
                let seen = probe.snapshot();
                assert_eq!(
                    seen.section.map(|m| m.section),
                    Some(Section::CommitLockWait)
                );
                assert_eq!(
                    seen.outer.map(|m| m.section),
                    Some(Section::SuccessorStateCheck)
                );
            }
            let seen = probe.snapshot();
            assert_eq!(
                seen.section.map(|m| m.section),
                Some(Section::SuccessorStateCheck)
            );
            assert_eq!(
                seen.outer.map(|m| m.section),
                Some(Section::SuccessorStateCheck)
            );
        }
        let seen = probe.snapshot();
        assert_eq!((seen.section, seen.outer), (None, None));
        drop(installed);
        drop(section(Section::CommitLockWait));
        assert_eq!(probe.snapshot().section, None);
    }

    #[test]
    fn a_panicking_poll_restores_the_task_mark_and_leaves_no_section() {
        fn explode() {
            panic!("the task panics, as a spawned task may");
        }
        let probe = ThreadProbe::new();
        let _installed = install(probe.clone());
        let mut task = probed(Section::AppEngine, async {
            let _held = section(Section::CommitLockWait);
            explode()
        });
        let mut cx = Context::from_waker(std::task::Waker::noop());
        // The mark the poll replaced, as when a task polls another.
        probe
            .task
            .store(pack(Section::WorkerLoop, now_ms()), Ordering::Relaxed);
        let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Pin::new(&mut task).poll(&mut cx);
        }));
        assert!(polled.is_err());
        let seen = probe.snapshot();
        assert_eq!(seen.task.map(|m| m.section), Some(Section::WorkerLoop));
        assert_eq!((seen.section, seen.outer), (None, None));
    }

    #[test]
    fn a_task_probe_marks_only_while_its_task_is_polled() {
        let probe = ThreadProbe::new();
        probe.idle();
        let mut task = task_probed(probe.clone(), async {
            beat();
            step(Section::PollerHeadFetch);
            std::future::pending::<()>().await
        });
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(Pin::new(&mut task).poll(&mut cx).is_pending());
        let seen = probe.snapshot();
        assert!(!seen.idle());
        assert_eq!(seen.step.map(|m| m.section), Some(Section::PollerHeadFetch));
        // Between polls the thread carries no probe: other tasks mark nothing.
        let _other = section(Section::CommitLockWait);
        step(Section::LoopStatus);
        idle();
        let seen = probe.snapshot();
        assert_eq!(seen.section, None);
        assert_eq!(seen.step.map(|m| m.section), Some(Section::PollerHeadFetch));
        assert!(!seen.idle());
    }

    #[test]
    fn details_nest_restore_and_cost_nothing_without_a_probe() {
        drop(detail(format_args!("unprobed")));
        let probe = ThreadProbe::new();
        let installed = install(probe.clone());
        {
            let _global = detail(format_args!("GLOBAL frame {}", 945_000));
            {
                let _shard = detail(format_args!("shard {} frame {}", "ab01", 16_210));
                assert_eq!(
                    probe.detail(),
                    "GLOBAL frame 945000: shard ab01 frame 16210"
                );
            }
            assert_eq!(probe.detail(), "GLOBAL frame 945000");
        }
        assert_eq!(probe.detail(), "");
        drop(installed);
        drop(detail(format_args!("unprobed")));
        assert_eq!(probe.detail(), "");
    }

    #[test]
    fn every_section_id_round_trips() {
        for (id, section) in Section::ALL.iter().enumerate() {
            assert_eq!(Section::from_id(id as u8), *section);
            assert_eq!(
                unpack(pack(*section, 1234)).map(|m| m.section),
                (*section != Section::None).then_some(*section)
            );
        }
    }
}
