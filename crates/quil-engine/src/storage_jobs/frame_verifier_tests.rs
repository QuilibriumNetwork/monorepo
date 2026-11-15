//! A verification a finalized frame waits on, under strict (macOS)
//! admission ([`Admission::reserve_verifier`]): it runs alone on the host
//! when it does not fit unless the kernel's memory pressure is critical,
//! and, verified by the admission queue, keeps its place past its caller's
//! short deadline.

use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::mpsc;

const GIB: u64 = 1 << 30;

fn warning() -> Option<u32> {
    Some(2)
}

fn critical() -> Option<u32> {
    Some(4)
}

fn running() -> bool {
    false
}

static STOP: AtomicBool = AtomicBool::new(false);

fn stop_asked() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// A frame's check whose test ends before its place's wait: long enough
/// that no scheduling delay under parallel load ends it first.
const PLACE: Duration = Duration::from_secs(30);

/// A frame's check whose test asserts it returns at once: a wait in its
/// place would show as seconds.
const PROMPT_PLACE: Duration = Duration::from_secs(10);

/// What "at once" means under parallel load, well short of
/// [`PROMPT_PLACE`].
const PROMPT: Duration = Duration::from_secs(3);

/// A strict admission with `available` bytes at kernel pressure `pressure`,
/// stopping as `stopping` says; frames' checks wait `place` in their place.
fn strict(
    available: u64,
    pressure: fn() -> Option<u32>,
    stopping: fn() -> bool,
    place: Duration,
) -> Admission {
    let mut admission = Admission::new(6, Box::new(move || Some(available)));
    admission.strict_due = true;
    admission.pressure = pressure;
    admission.stopping = stopping;
    admission.frame_verifier_wait = place;
    admission
}

impl Admission {
    /// A strict (macOS) admission for the node's tests, with no memory
    /// available at warning pressure, for the process.
    pub(crate) fn strict_at_no_headroom_for_tests() -> &'static Admission {
        Box::leak(Box::new(strict(
            0,
            warning,
            running,
            Duration::from_millis(800),
        )))
    }
}

/// [`Admission::reserve_verifier`] of a 3 GiB check on a thread of its own,
/// its caller's deadline now; what it returns comes on the receiver.
fn check(admission: &'static Admission, frame: FrameCheck) -> mpsc::Receiver<Option<Reservation>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(admission.reserve_verifier(3 * GIB, Instant::now(), frame));
    });
    receiver
}

/// The Oumlaut stall: at warning pressure strict admission sees nothing
/// available, and nothing holds memory. A frame's check runs alone.
#[test]
fn a_frames_check_runs_alone_when_nothing_holds_memory_and_none_is_available() {
    let admission: &'static Admission = Box::leak(Box::new(strict(
        0,
        warning,
        running,
        Duration::from_millis(800),
    )));
    assert_eq!(admission.held_bytes(), 0, "setup: nothing holds memory");
    let granted = check(admission, FrameCheck::Queued)
        .recv_timeout(Duration::from_secs(5))
        .expect("the check returns within its place's wait");
    assert!(
        granted.is_some(),
        "frame_check_refused_alone_at_no_headroom: a finalized frame would never execute"
    );
    assert_eq!(admission.held_bytes(), 3 * GIB);
}

/// A check no frame waits on keeps the share and its caller's short
/// deadline: it never runs alone beyond the share, nor keeps a place.
#[test]
fn a_check_no_frame_waits_on_neither_runs_alone_nor_keeps_a_place() {
    let admission: &'static Admission =
        Box::leak(Box::new(strict(0, warning, running, PROMPT_PLACE)));
    let started = Instant::now();
    // Past a wait in its place, so a check that kept one fails on its
    // elapsed time below, not here.
    let granted = check(admission, FrameCheck::No)
        .recv_timeout(PROMPT_PLACE + Duration::from_secs(5))
        .expect("the check returns");
    assert!(
        granted.is_none(),
        "check_no_frame_waits_on_ran_alone beyond the memory share"
    );
    assert!(
        started.elapsed() < PROMPT,
        "check_no_frame_waits_on_kept_a_place past its deadline: {:?}",
        started.elapsed()
    );
}

/// At critical pressure a frame's check does not start alone; it gives up
/// once its place's wait ends, and is retried as before.
#[test]
fn a_frames_check_does_not_start_alone_at_critical_pressure() {
    let admission: &'static Admission = Box::leak(Box::new(strict(
        0,
        critical,
        running,
        Duration::from_millis(800),
    )));
    let granted = check(admission, FrameCheck::Queued)
        .recv_timeout(Duration::from_secs(5))
        .expect("frame_check_wait_unbounded: it must end with its place's wait");
    assert!(
        granted.is_none(),
        "frame_check_ran_alone_at_critical_pressure"
    );
}

/// While another process of the node holds memory, a frame's check waits
/// in its place past its caller's deadline, not beside it; it runs alone
/// once that memory is given back.
#[test]
fn a_frames_check_keeps_its_place_while_another_process_holds_memory() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Admission::new(6, Box::new(|| Some(8 * GIB)));
    storage.strict_due = true;
    assert!(storage.use_ledger(HostLedger::open_as(dir.path(), "storage").unwrap()));
    let storage: &'static Admission = Box::leak(Box::new(storage));
    let verifier = strict(0, warning, running, PLACE);
    assert!(verifier.use_ledger(HostLedger::open_as(dir.path(), "verifier").unwrap()));
    let verifier: &'static Admission = Box::leak(Box::new(verifier));
    let held = storage.reserve(GIB);
    assert_eq!(
        storage.ledger.get().unwrap().others().bytes,
        0,
        "setup: the verifier's process holds nothing"
    );
    let receiver = check(verifier, FrameCheck::Queued);
    match receiver.recv_timeout(Duration::from_millis(300)) {
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        Ok(Some(_)) => panic!("frame_check_ran_beside_a_holder in another process"),
        Ok(None) => panic!("frame_check_left_its_place at its caller's deadline"),
        Err(error) => panic!("setup: the check's thread ended: {error}"),
    }
    drop(held);
    // Its place's wait ends well before HANG: a check still refused
    // returns None then and fails on the tag below.
    let granted = receiver
        .recv_timeout(HANG)
        .expect("the check returns by its place's wait");
    assert!(
        granted.is_some(),
        "frame_check_did_not_run_alone once the memory was given back"
    );
}

/// The node stopping ends a frame's check waiting in its place.
#[test]
fn stopping_ends_a_frames_check_waiting_in_its_place() {
    let admission: &'static Admission = Box::leak(Box::new(strict(0, critical, stop_asked, PLACE)));
    let receiver = check(admission, FrameCheck::Queued);
    assert!(
        matches!(
            receiver.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "setup: the check waits in its place"
    );
    STOP.store(true, Ordering::SeqCst);
    let ended = receiver.recv_timeout(Duration::from_secs(5));
    assert!(
        matches!(ended, Ok(None)),
        "frame_check_ignored_stopping: {:?}",
        ended.map(|granted| granted.is_some())
    );
}

/// A check on the engine's thread, or the lanes it waits on, keeps its
/// caller's short deadline, though a frame waits on it: refused at
/// critical pressure, it returns at once, so the engine's thread never
/// blocks for memory, and the frame retries.
#[test]
fn a_frames_check_on_the_engines_thread_keeps_its_callers_deadline() {
    let admission: &'static Admission =
        Box::leak(Box::new(strict(0, critical, running, PROMPT_PLACE)));
    let started = Instant::now();
    // Past a wait in its place, so a check that kept one fails on its
    // elapsed time below, not here.
    let granted = check(admission, FrameCheck::Inline)
        .recv_timeout(PROMPT_PLACE + Duration::from_secs(5))
        .expect("the check returns");
    assert!(granted.is_none(), "setup: refused at critical pressure");
    assert!(
        started.elapsed() < PROMPT,
        "inline_frame_check_kept_a_place past its caller's deadline: {:?}",
        started.elapsed()
    );
}

static PRESSURE: AtomicU32 = AtomicU32::new(PRESSURE_CRITICAL);

fn flipping() -> Option<u32> {
    Some(PRESSURE.load(Ordering::SeqCst))
}

/// Refused at critical pressure, a frame's check waiting in its place runs
/// alone once the pressure drops: the refusal ends with its cause.
#[test]
fn a_frames_check_refused_at_critical_pressure_runs_once_it_drops() {
    let admission: &'static Admission = Box::leak(Box::new(strict(0, flipping, running, PLACE)));
    let receiver = check(admission, FrameCheck::Queued);
    assert!(
        matches!(
            receiver.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "frame_check_gave_up_at_critical_pressure: it must wait in its place"
    );
    PRESSURE.store(2, Ordering::SeqCst);
    // Its place's wait ends well before HANG: a check still refused
    // returns None then and fails on the tag below.
    let granted = receiver
        .recv_timeout(HANG)
        .expect("the check returns by its place's wait");
    assert!(
        granted.is_some(),
        "frame_check_refused_after_pressure_dropped: the frame would wait for nothing"
    );
}

const MIB: u64 = 1 << 20;

/// A bound only a test whose awaited progress never comes reaches: tests
/// below wait on a pass, a record or a thread's result, never on time.
const HANG: Duration = Duration::from_secs(120);

/// A frame's check whose test waits for it to leave at the end of its
/// place's wait: long beside the few milliseconds its setup takes.
const DEADLINE_PLACE: Duration = Duration::from_secs(10);

/// Waits until `done` holds, looked at every 5 ms; panics with `what` if
/// it has not by [`HANG`].
fn until(what: &str, done: impl Fn() -> bool) {
    let hang = Instant::now() + HANG;
    while !done() {
        assert!(Instant::now() < hang, "{what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// What a reservation on a thread of its own returned.
fn returned(receiver: &mpsc::Receiver<Option<Reservation>>, what: &str) -> Option<Reservation> {
    receiver
        .recv_timeout(HANG)
        .unwrap_or_else(|error| panic!("{what}: {error}"))
}

/// Whether the frame's check of [`check`] waits in this process.
fn frame_waits(admission: &Admission) -> bool {
    admission
        .state()
        .waiting
        .iter()
        .any(|waiting| waiting.bytes == 3 * GIB)
}

/// A reservation for `bytes` of work due now on a thread of its own, given
/// up after [`HANG`]; what it returns comes on the receiver.
fn due(admission: &'static Admission, bytes: u64) -> mpsc::Receiver<Option<Reservation>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let until = Instant::now() + HANG;
        let expired = move || Instant::now() >= until;
        let _ = sender.send(admission.reserve_until(bytes, Urgency::Due, &expired));
    });
    receiver
}

/// Returns once a pass of `admission` found the work due now on `receiver`
/// waiting and left it waiting; panics with `passed` if it was granted.
fn held(admission: &Admission, receiver: &mpsc::Receiver<Option<Reservation>>, passed: &str) {
    let hang = Instant::now() + HANG;
    loop {
        match receiver.try_recv() {
            Ok(Some(_)) => panic!("{passed}"),
            Ok(None) => panic!("setup: the work due now gave up"),
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("setup: the work due now's thread ended")
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let state = admission.state();
        if state
            .waiting
            .iter()
            .any(|waiting| waiting.urgency == Urgency::Due && waiting.ticket < state.passed_below)
        {
            return;
        }
        drop(state);
        assert!(
            Instant::now() < hang,
            "setup: no pass found the work due now waiting"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// What the work due now on `receiver` returned, granted by a pass of
/// `admission` after this call; panics with `kept` once such a pass left
/// it waiting.
fn started(
    admission: &Admission,
    receiver: &mpsc::Receiver<Option<Reservation>>,
    kept: &str,
) -> Option<Reservation> {
    let after = admission.state().passes;
    let hang = Instant::now() + HANG;
    loop {
        match receiver.try_recv() {
            Ok(started) => return started,
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("setup: the work due now's thread ended")
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let state = admission.state();
        let waits = state
            .waiting
            .iter()
            .any(|waiting| waiting.urgency == Urgency::Due);
        if waits && state.passes > after {
            panic!("{kept}");
        }
        drop(state);
        assert!(Instant::now() < hang, "setup: no pass ran: {kept}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// While a frame's check waits in its place for the memory a job due now
/// holds, no further job due now starts beside that one: the jobs holding
/// memory drain, and the check runs alone. The later job starts once the
/// check no longer waits.
#[test]
fn work_due_now_waits_while_a_frames_check_waits_for_memory() {
    let admission: &'static Admission =
        Box::leak(Box::new(strict(2 * GIB, warning, running, PLACE)));
    let first = admission
        .reserve_until(MIB, Urgency::Due, &|| false)
        .expect("setup: work due now fits the share");
    let frame = check(admission, FrameCheck::Queued);
    until(
        "setup: the frame's check waits in its place beside the job holding memory",
        || frame_waits(admission),
    );
    let second = due(admission, MIB);
    held(
        admission,
        &second,
        "due_passed_a_waiting_frame_check: work due now started beside a job holding \
         memory while a frame's check waited for that memory",
    );
    assert!(
        matches!(frame.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "setup: the frame's check still waits"
    );
    drop(first);
    let checked = returned(&frame, "the check returns");
    assert!(
        checked.is_some(),
        "frame_check_not_run_once_the_holder_ended"
    );
    drop(checked);
    assert!(
        returned(&second, "the work due now returns").is_some(),
        "due_never_started_once_the_frame_check_ended"
    );
}

/// A storage process and a verifier process of the node on one host
/// ledger in `dir`: the storage process holds a job due now, and the
/// verifier's frame check waits for that memory in its place.
fn elsewhere(
    dir: &tempfile::TempDir,
    pressure: fn() -> Option<u32>,
    stopping: fn() -> bool,
    place: Duration,
) -> (
    &'static Admission,
    Reservation,
    mpsc::Receiver<Option<Reservation>>,
) {
    let mut storage = Admission::new(6, Box::new(|| Some(8 * GIB)));
    storage.strict_due = true;
    assert!(storage.use_ledger(HostLedger::open_as(dir.path(), "storage").unwrap()));
    let storage: &'static Admission = Box::leak(Box::new(storage));
    let verifier = strict(0, pressure, stopping, place);
    assert!(verifier.use_ledger(HostLedger::open_as(dir.path(), "verifier").unwrap()));
    let verifier: &'static Admission = Box::leak(Box::new(verifier));
    let first = storage.reserve(MIB);
    let frame = check(verifier, FrameCheck::Queued);
    until(
        "setup: the frame's check waits in the verifier's process, and its record says so",
        || storage.ledger.get().unwrap().others().due_waiting,
    );
    (storage, first, frame)
}

/// A frame's check waiting in one process of the node holds back work due
/// now in the host's others: their jobs holding memory drain, and the check
/// runs alone. Their work starts once the check no longer waits.
#[test]
fn work_due_now_elsewhere_waits_while_a_frames_check_waits_for_memory() {
    let dir = tempfile::tempdir().unwrap();
    let (storage, first, frame) = elsewhere(&dir, warning, running, PLACE);
    let second = due(storage, MIB);
    held(
        storage,
        &second,
        "due_passed_a_frame_check_waiting_elsewhere: work due now started beside a job \
         holding memory while another process's frame check waited for that memory",
    );
    assert!(
        matches!(frame.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "setup: the frame's check still waits"
    );
    drop(first);
    let checked = returned(&frame, "the check returns");
    assert!(
        checked.is_some(),
        "frame_check_not_run_once_the_holder_ended"
    );
    assert!(
        returned(&second, "the work due now returns").is_some(),
        "due_never_started_once_the_frame_check_stopped_waiting"
    );
}

/// How a frame's check held up by a job due now ends without running.
#[derive(Clone, Copy)]
enum End {
    /// Its place's wait ends: at critical pressure it never runs alone.
    Deadline,
    /// The node stops.
    Stop,
}

/// A frame's check held up by work due now ends without running, the
/// first job still holding its memory: the later job due now it held back
/// in `admission` starts beside the first, at once.
fn ends(
    admission: &'static Admission,
    frame: mpsc::Receiver<Option<Reservation>>,
    end: End,
    kept: &str,
) {
    let second = due(admission, MIB);
    held(
        admission,
        &second,
        "setup: work due now waits while the frame's check waits",
    );
    assert!(
        matches!(frame.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "setup: the frame's check still waits"
    );
    if let End::Stop = end {
        STOP.store(true, Ordering::SeqCst);
    }
    assert!(
        returned(&frame, "the check returns").is_none(),
        "setup: the frame's check ends without running"
    );
    assert!(started(admission, &second, kept).is_some(), "{kept}");
}

/// At critical pressure a frame's check never runs alone: its place's
/// wait ending is the only end of the hold while a job holds memory.
#[test]
fn work_due_now_starts_once_a_frames_check_leaves_at_its_deadline() {
    let admission: &'static Admission =
        Box::leak(Box::new(strict(2 * GIB, critical, running, DEADLINE_PLACE)));
    let _first = admission
        .reserve_until(MIB, Urgency::Due, &|| false)
        .expect("setup: work due now fits the share");
    let frame = check(admission, FrameCheck::Queued);
    until("setup: the frame's check waits in its place", || {
        frame_waits(admission)
    });
    ends(
        admission,
        frame,
        End::Deadline,
        "due_held_after_the_frame_check_left: work due now still waited once the \
         frame's check left at its deadline",
    );
}

/// The node stopping ends a frame's check, and with it the hold.
#[test]
fn work_due_now_starts_once_stopping_ends_a_frames_check() {
    let admission: &'static Admission =
        Box::leak(Box::new(strict(2 * GIB, critical, stop_asked, PLACE)));
    let _first = admission
        .reserve_until(MIB, Urgency::Due, &|| false)
        .expect("setup: work due now fits the share");
    let frame = check(admission, FrameCheck::Queued);
    until("setup: the frame's check waits in its place", || {
        frame_waits(admission)
    });
    ends(
        admission,
        frame,
        End::Stop,
        "due_held_after_stopping_ended_the_frame_check: work due now still waited \
         once stopping ended the frame's check",
    );
}

/// A frame's check leaving another process at its deadline ends the hold
/// on work due now here: its process's record says it no longer waits.
#[test]
fn work_due_now_elsewhere_starts_once_a_frames_check_leaves_at_its_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let (storage, _first, frame) = elsewhere(&dir, critical, running, DEADLINE_PLACE);
    ends(
        storage,
        frame,
        End::Deadline,
        "due_held_after_the_frame_check_left_elsewhere: work due now still waited once \
         another process's frame check left at its deadline",
    );
}

/// Stopping a frame's check in another process ends the hold here.
#[test]
fn work_due_now_elsewhere_starts_once_stopping_ends_a_frames_check() {
    let dir = tempfile::tempdir().unwrap();
    let (storage, _first, frame) = elsewhere(&dir, critical, stop_asked, PLACE);
    ends(
        storage,
        frame,
        End::Stop,
        "due_held_after_stopping_ended_the_frame_check_elsewhere: work due now still \
         waited once stopping ended another process's frame check",
    );
}

/// A frame's check waiting only for a job slot, its memory fitting, waits
/// for no memory: its process's record holds back no work due now in the
/// host's others, which would drain their memory for nothing.
#[test]
fn a_frames_check_waiting_for_a_job_slot_holds_back_nothing_elsewhere() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Admission::new(6, Box::new(|| Some(8 * GIB)));
    storage.strict_due = true;
    assert!(storage.use_ledger(HostLedger::open_as(dir.path(), "storage").unwrap()));
    let storage: &'static Admission = Box::leak(Box::new(storage));
    let mut verifier = Admission::new(1, Box::new(|| Some(8 * GIB)));
    verifier.strict_due = true;
    verifier.pressure = warning;
    verifier.stopping = running;
    verifier.frame_verifier_wait = PLACE;
    assert!(verifier.use_ledger(HostLedger::open_as(dir.path(), "verifier").unwrap()));
    let verifier: &'static Admission = Box::leak(Box::new(verifier));
    let slot = verifier
        .reserve_until(MIB, Urgency::Due, &|| false)
        .expect("setup: the verifier's one job slot is free");
    let frame = check(verifier, FrameCheck::Queued);
    until(
        "setup: a pass found the frame's check waiting for the one job slot",
        || {
            let state = verifier.state();
            state.holders == 1
                && state
                    .waiting
                    .iter()
                    .any(|waiting| waiting.bytes == 3 * GIB && waiting.ticket < state.passed_below)
        },
    );
    assert!(
        !storage.ledger.get().unwrap().others().frame_waiting,
        "frame_waiting_published_for_a_job_slot: a frame's check waiting only for a job \
         slot held back the host's other processes' work due now"
    );
    drop(slot);
    assert!(
        returned(&frame, "the check returns").is_some(),
        "setup: the frame's check fits once the job slot is free"
    );
}

/// Which of a frame's check and the work due now on their receivers a pass
/// granted first: `true` for the work due now.
fn first_granted(
    check: &mpsc::Receiver<Option<Reservation>>,
    due: &mpsc::Receiver<Option<Reservation>>,
) -> (bool, Option<Reservation>) {
    let hang = Instant::now() + HANG;
    loop {
        if let Ok(granted) = due.try_recv() {
            return (true, granted);
        }
        if let Ok(granted) = check.try_recv() {
            return (false, granted);
        }
        assert!(Instant::now() < hang, "setup: neither was granted");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Frames' checks one after another, each waiting while the one before
/// runs, hold work due now back for [`PASS_LIMIT`] of them granted, no
/// more: then it takes its place, starts once the check running ends, and
/// the next check waits for it. Work due now larger than a check, so the
/// checks come first in line.
#[test]
fn work_due_now_held_back_by_a_stream_of_frames_checks_starts_at_the_bound() {
    let admission: &'static Admission =
        Box::leak(Box::new(strict(7 * GIB, warning, running, PLACE)));
    let share = {
        let mut state = admission.state();
        admission.share(&mut state).expect("setup: memory is known")
    };
    assert!(
        (4 * GIB..6 * GIB).contains(&share),
        "setup: a check or the work due now fits the share alone, not two beside each other"
    );
    let mut running = returned(&check(admission, FrameCheck::Queued), "the first check")
        .expect("setup: the first check fits the share");
    let mut next = check(admission, FrameCheck::Queued);
    until("setup: the next check waits for memory", || {
        frame_waits(admission)
    });
    let due = due(admission, 4 * GIB);
    held(
        admission,
        &due,
        "setup: the work due now started beside a check",
    );
    assert_eq!(
        admission.state().frame_held.len(),
        1,
        "setup: the waiting check held the work due now back"
    );
    for granted in 1..=PASS_LIMIT + 1 {
        drop(running);
        let (due_first, reservation) = first_granted(&next, &due);
        let reservation = reservation.expect("setup: granted, not given up");
        if granted <= PASS_LIMIT {
            assert!(
                !due_first,
                "due_started_before_the_bound: work due now passed check {granted}"
            );
        } else {
            assert!(
                due_first,
                "frame_hold_unbounded: check {granted} passed work due now held back past \
                 {PASS_LIMIT} checks granted"
            );
            assert!(frame_waits(admission), "setup: the next check still waits");
            drop(reservation);
            assert!(
                returned(&next, "the next check returns").is_some(),
                "frame_check_not_run_once_the_work_due_now_ended"
            );
            return;
        }
        running = reservation;
        next = check(admission, FrameCheck::Queued);
        until("setup: the next check waits for memory", || {
            frame_waits(admission)
        });
    }
}

/// Another process's work due now held back past its bound, as its record
/// says, keeps this process's frames' checks from starting, alone or
/// within the share; they start once it no longer waits.
#[test]
fn a_frames_check_waits_while_work_due_now_elsewhere_takes_its_place() {
    let admission: &'static Admission = Box::leak(Box::new(strict(
        0,
        warning,
        running,
        Duration::from_millis(200),
    )));
    admission.state().others.due_overdue = true;
    assert!(
        returned(&check(admission, FrameCheck::Queued), "the check returns").is_none(),
        "frame_check_passed_due_overdue_elsewhere: a frame's check started while another \
         process's work due now held back past its bound waited"
    );
    admission.state().others.due_overdue = false;
    assert!(
        returned(&check(admission, FrameCheck::Queued), "the check returns").is_some(),
        "setup: the check runs alone once nothing waits elsewhere"
    );
}

/// What the verifier's process of
/// [`work_due_now_elsewhere_held_back_past_its_window_takes_its_place`]
/// has available: none until the test lets its frame's check fit.
static VERIFIER_AVAILABLE: AtomicU64 = AtomicU64::new(0);

/// [`VERIFIER_AVAILABLE`] of
/// [`a_frames_check_starts_once_the_only_work_due_now_past_its_window_gives_up`].
static GIVEN_UP_AVAILABLE: AtomicU64 = AtomicU64::new(0);

/// Whether the work due now of
/// [`a_frames_check_starts_once_the_only_work_due_now_past_its_window_gives_up`]
/// is of no use any more.
static GIVE_UP: AtomicBool = AtomicBool::new(false);

/// The window a test's work due now is held back for by frames' checks
/// ([`PASS_WINDOW`]): short, so a window never checked shows in seconds.
const HOLD_WINDOW: Duration = Duration::from_secs(1);

/// How long a test waits for what [`HOLD_WINDOW`] ends: work due now
/// waiting looks again every [`RECHECK`], late under parallel load.
const HOLD_ENDS: Duration = Duration::from_secs(30);

/// Panics with `what` unless `done` holds within `limit`.
fn within(limit: Duration, what: &str, done: impl Fn() -> bool) {
    let until = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < until, "{what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Work due now in the storage process held back only by a frame's check
/// waiting in the verifier's: no frame's check is granted in the storage
/// process, so only [`PASS_WINDOW`] ends the hold. At the window, work
/// that fits beside the jobs holding memory starts. Work that does not
/// takes its place: the storage process's record says so, the verifier's
/// check waits though it fits, and starts once that work has started and
/// the record no longer says so.
#[test]
fn work_due_now_elsewhere_held_back_past_its_window_takes_its_place() {
    let (_dir, storage, verifier) = two_processes(&VERIFIER_AVAILABLE);
    let share = 8 * GIB * MEMORY_SHARE_PERCENT / 100;
    let first = storage.reserve(MIB);
    let frame = check(verifier, FrameCheck::Queued);
    let second = past_the_window(&second_due(storage, share));
    // Fits only once the second job ends, and would fit alone.
    let third = due(storage, share / 2 + 2 * MIB);
    within(
        HOLD_ENDS,
        "due_overdue_unpublished: the verifier's process never read that work due now \
         elsewhere waited past its window",
        || verifier.ledger.get().unwrap().others().due_overdue,
    );
    VERIFIER_AVAILABLE.store(64 * GIB, Ordering::SeqCst);
    let after = verifier.state().passes;
    until(
        "setup: the verifier's process passed over its check",
        || verifier.state().passes > after + 2,
    );
    assert!(
        matches!(frame.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "frame_check_passed_due_overdue_published: a frame's check that fits started while \
         another process's record said its work due now waited past its window"
    );
    drop(second);
    let third = returned(&third, "the work due now returns");
    assert!(
        third.is_some(),
        "due_overdue_never_started: work due now past its window did not start once it fit"
    );
    within(
        HOLD_ENDS,
        "due_overdue_sticky: the storage process's record still said its work due now \
         waited past its window once it started",
        || !verifier.ledger.get().unwrap().others().due_overdue,
    );
    assert!(
        returned(&frame, "the check returns").is_some(),
        "frame_check_not_run_once_due_started: a frame's check that fits waited once the \
         work due now it waited for started"
    );
    drop((first, third));
}

/// Work due now past its window that gives up while it waits, the only
/// such work in the storage process, no longer holds back frames'
/// checks: its process runs no pass after (nothing else waits there), so
/// the record it writes as it leaves must say so, or the verifier's
/// check, which fits, would wait until that process's next reservation.
#[test]
fn a_frames_check_starts_once_the_only_work_due_now_past_its_window_gives_up() {
    let (_dir, storage, verifier) = two_processes(&GIVEN_UP_AVAILABLE);
    let share = 8 * GIB * MEMORY_SHARE_PERCENT / 100;
    let first = storage.reserve(MIB);
    let frame = check(verifier, FrameCheck::Queued);
    let second = past_the_window(&second_due(storage, share));
    // Fits only once the second job ends, and would fit alone.
    let (sender, third) = mpsc::channel();
    std::thread::spawn(move || {
        let expired = || GIVE_UP.load(Ordering::SeqCst);
        let _ = sender.send(storage.reserve_until(share / 2 + 2 * MIB, Urgency::Due, &expired));
    });
    within(
        HOLD_ENDS,
        "setup: the verifier's process never read that work due now elsewhere waited past \
         its window",
        || verifier.ledger.get().unwrap().others().due_overdue,
    );
    GIVEN_UP_AVAILABLE.store(64 * GIB, Ordering::SeqCst);
    let after = verifier.state().passes;
    until(
        "setup: the verifier's process passed over its check",
        || verifier.state().passes > after + 2,
    );
    assert!(
        matches!(frame.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "setup: a frame's check started while work due now elsewhere waited past its window"
    );
    GIVE_UP.store(true, Ordering::SeqCst);
    assert!(
        returned(&third, "the work due now returns").is_none(),
        "setup: the work due now past its window started instead of giving up"
    );
    assert!(
        storage.state().waiting.is_empty(),
        "setup: work still waits in the storage process"
    );
    let frame = frame.recv_timeout(HOLD_ENDS).unwrap_or_else(|error| {
        panic!(
            "due_overdue_stale_on_leave: a frame's check that fits still waited after the \
             only work due now elsewhere past its window gave up: {error}"
        )
    });
    assert!(frame.is_some(), "setup: the frame's check gave up");
    drop((first, second, frame));
}

/// A storage process and a verifier's process on one host, sharing a
/// ledger in the returned directory: the storage process's work due now
/// is held back by frames' checks for [`HOLD_WINDOW`]; the verifier's has
/// `available` and runs its frames' checks at warning pressure.
fn two_processes(
    available: &'static AtomicU64,
) -> (tempfile::TempDir, &'static Admission, &'static Admission) {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Admission::new(6, Box::new(|| Some(8 * GIB)));
    storage.strict_due = true;
    storage.pass_window = HOLD_WINDOW;
    assert!(storage.use_ledger(HostLedger::open_as(dir.path(), "storage").unwrap()));
    let storage: &'static Admission = Box::leak(Box::new(storage));
    let mut verifier = Admission::new(6, Box::new(move || Some(available.load(Ordering::SeqCst))));
    verifier.strict_due = true;
    verifier.pressure = warning;
    verifier.stopping = running;
    verifier.frame_verifier_wait = HANG;
    assert!(verifier.use_ledger(HostLedger::open_as(dir.path(), "verifier").unwrap()));
    let verifier: &'static Admission = Box::leak(Box::new(verifier));
    (dir, storage, verifier)
}

/// Work due now of half the storage process's `share` there, once the
/// verifier's frame's check waits and its record says so: it fits beside
/// a small job, so only that check holds it back.
fn second_due(storage: &'static Admission, share: u64) -> mpsc::Receiver<Option<Reservation>> {
    until(
        "setup: the frame's check waits in the verifier's process, and its record says so",
        || storage.ledger.get().unwrap().others().frame_waiting,
    );
    let second = due(storage, share / 2);
    held(
        storage,
        &second,
        "setup: work due now started while another process's frame check waited",
    );
    second
}

/// The work due now on `second`, held back only by another process's
/// frame's check, once [`HOLD_WINDOW`] ends the hold.
fn past_the_window(second: &mpsc::Receiver<Option<Reservation>>) -> Reservation {
    second
        .recv_timeout(HOLD_ENDS)
        .unwrap_or_else(|error| {
            panic!(
                "due_held_past_its_window_elsewhere: work due now held back only by another \
                 process's frame check still waited past the window: {error}"
            )
        })
        .expect("setup: the work due now started")
}

/// Work due now held back past its bound that does not fit even once no
/// job holds memory does not take its place: frames' checks waiting for
/// it would never run, and no frame would execute. The next check runs
/// alone once the one running ends.
#[test]
fn a_frames_check_runs_past_held_back_work_that_would_never_fit() {
    let admission: &'static Admission = Box::leak(Box::new(strict(0, warning, running, PLACE)));
    let first = returned(&check(admission, FrameCheck::Queued), "the first check")
        .expect("setup: the first check runs alone");
    let next = check(admission, FrameCheck::Queued);
    until("setup: the next check waits for memory", || {
        frame_waits(admission)
    });
    let due = due(admission, MIB);
    held(
        admission,
        &due,
        "setup: the work due now started beside a check",
    );
    {
        let mut state = admission.state();
        assert!(
            admission.share(&mut state).is_some_and(|share| share < MIB),
            "setup: the work due now does not fit the share"
        );
        assert_eq!(
            state.frame_held.len(),
            1,
            "setup: the waiting check held the work due now back"
        );
        for held in state.frame_held.values_mut() {
            held.grants = PASS_LIMIT;
        }
    }
    drop(first);
    assert!(
        returned(&next, "the next check returns").is_some(),
        "frame_check_kept_behind_work_that_never_fits: a frame's check waited for held \
         back work due now that does not fit with no job holding memory"
    );
    assert!(
        matches!(due.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "setup: the work due now still waits"
    );
}
