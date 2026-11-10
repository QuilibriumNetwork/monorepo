//! The storage epoch proof check, off the consensus thread.
//!
//! An app engine asks for its seat's storage epoch proof check at each
//! GLOBAL frame, materialized frame and retry tick. The check reads the
//! registry, the replica store and GLOBAL frames; on a disk an epoch
//! boundary's storage work saturated, it took 35-72 s on every worker's
//! consensus thread at once, so votes waited and proposals were refused
//! after (mainnet, 2026-11-10). It runs on a blocking thread instead, one
//! run per engine at a time: what is asked while one runs is checked once
//! after it, at the newest GLOBAL frame asked. Every check repeats its
//! decisions from the stores, and its proving runs in storage jobs, so a
//! check that ends in an error or a panic is simply the next one's to
//! redo.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tracing::{info, warn};

/// A check running this long is reported: well past the few seconds it
/// takes on a disk that keeps up, and below the 35 s seen on one that did
/// not.
pub const OVERRUN: Duration = Duration::from_secs(10);

/// How often a check still running is reported again.
pub const OVERRUN_REPEAT: Duration = Duration::from_secs(10 * 60);

/// The GLOBAL frame a check is asked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    /// This GLOBAL frame.
    Frame(u64),
    /// The newest GLOBAL frame stored when the check runs.
    Head,
}

/// What one check runs at: the newest GLOBAL frame asked, and whether the
/// stored head was asked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Asked {
    pub frame: Option<u64>,
    pub head: bool,
}

impl Asked {
    fn add(&mut self, ask: Ask) {
        match ask {
            Ask::Frame(frame) => self.frame = self.frame.max(Some(frame)),
            Ask::Head => self.head = true,
        }
    }

    /// The GLOBAL frame to check at: the newest asked, the stored head
    /// (read by `head` only when it was asked) included. `None`: no frame
    /// is known.
    pub fn frame(self, head: impl FnOnce() -> Option<u64>) -> Option<u64> {
        let head = if self.head { head() } else { None };
        self.frame.max(head)
    }
}

/// One engine's checks: at most one runs at a time.
#[derive(Default)]
pub struct Checks {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// What was asked since the running check began.
    asked: Option<Asked>,
    run: Option<Run>,
    runs: u64,
}

struct Run {
    id: u64,
    /// Whether a check runs, or the run waits to start one.
    checking: bool,
    /// When the check running now began, or the run was asked for.
    since: Instant,
    /// When its overrun was last reported.
    reported: Option<Instant>,
    /// Asks since it began.
    asks: u64,
}

/// What [`Checks::ask`] leaves the caller to do.
pub enum Asking {
    /// No check runs: start one, which holds the engine's run until it
    /// ends or is dropped ([`Running::run`]).
    Start(Running),
    /// A check runs; this ask is checked after it. `Some`: it has run this
    /// long, reported now.
    Queued(Option<Duration>),
}

/// The engine's one running check, freed when dropped (a run never
/// started, as by a runtime shutting down, included).
pub struct Running {
    checks: Arc<Checks>,
    id: u64,
}

impl Checks {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ask for a check at `ask`, `now`. A check running past [`OVERRUN`] is
    /// due a report at the first ask past it, then every [`OVERRUN_REPEAT`]
    /// while it runs ([`Asking::Queued`]).
    pub fn ask(self: &Arc<Self>, ask: Ask, now: Instant) -> Asking {
        let mut state = self.lock();
        state.asked.get_or_insert_with(Asked::default).add(ask);
        if let Some(run) = state.run.as_mut() {
            run.asks += 1;
            let ran = now.saturating_duration_since(run.since);
            let due = ran >= OVERRUN
                && run
                    .reported
                    .is_none_or(|at| now.saturating_duration_since(at) >= OVERRUN_REPEAT);
            if !due {
                return Asking::Queued(None);
            }
            run.reported = Some(now);
            return Asking::Queued(Some(ran));
        }
        let id = state.runs + 1;
        state.runs = id;
        state.run = Some(Run {
            id,
            checking: false,
            since: now,
            reported: None,
            asks: 0,
        });
        Asking::Start(Running {
            checks: self.clone(),
            id,
        })
    }

    /// Run `id`'s check ended at `now`, or the run starts: what to check
    /// next, asked meanwhile, else `None`, and the run ends. Logs the end
    /// of a check that ran past [`OVERRUN`], and returns how long it ran.
    fn next(&self, id: u64, now: Instant, filter: &[u8]) -> (Option<Asked>, Option<Duration>) {
        let mut guard = self.lock();
        let state = &mut *guard;
        let Some(run) = state.run.as_mut().filter(|run| run.id == id) else {
            return (None, None);
        };
        let ran = now.saturating_duration_since(run.since);
        let overran = (run.checking && (run.reported.is_some() || ran >= OVERRUN)).then_some(ran);
        if let Some(ran) = overran {
            info!(filter = %hex::encode(filter), seconds = ran.as_secs_f64(), asked_since = run.asks,
                "storage epoch proof check ended after running long; the frames asked meanwhile are checked now");
        }
        match state.asked.take() {
            Some(asked) => {
                *run = Run {
                    id,
                    checking: true,
                    since: now,
                    reported: None,
                    asks: 0,
                };
                (Some(asked), overran)
            }
            None => {
                state.run = None;
                (None, overran)
            }
        }
    }

    /// Free run `id` if it still holds the engine's run.
    fn release(&self, id: u64) {
        let mut state = self.lock();
        if state.run.as_ref().is_some_and(|run| run.id == id) {
            state.run = None;
        }
    }
}

impl Running {
    /// Run checks until nothing more is asked: `check` at what each asks.
    /// A check that panics is reported and the next one runs.
    pub fn run(self, filter: &[u8], mut check: impl FnMut(Asked)) {
        loop {
            let (asked, _) = self.checks.next(self.id, Instant::now(), filter);
            let Some(asked) = asked else {
                return;
            };
            let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(asked)));
            if checked.is_err() {
                warn!(filter = %hex::encode(filter), scope = "this node", action = "report this line with the panic above it",
                    "storage epoch proof check panicked; the next GLOBAL frame checks again");
            }
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.checks.release(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started(asking: Asking) -> Running {
        match asking {
            Asking::Start(running) => running,
            Asking::Queued(_) => panic!("SLOT-HELD: no check ran, yet the ask was queued"),
        }
    }

    fn queued(asking: Asking) -> Option<Duration> {
        match asking {
            Asking::Queued(reported) => reported,
            Asking::Start(_) => panic!("TWO-IN-FLIGHT: a second check started while one ran"),
        }
    }

    /// One check runs at a time; what is asked while it runs is checked
    /// once after it, at the newest GLOBAL frame asked, and the stored head
    /// if asked.
    #[test]
    fn asks_during_a_check_run_once_after_it_at_the_newest_frame() {
        let checks = Arc::new(Checks::default());
        let running = started(checks.ask(Ask::Frame(10), Instant::now()));
        let (mut seen, mut queued_asks) = (Vec::new(), Vec::new());
        running.run(b"s", |asked| {
            if seen.is_empty() {
                for ask in [Ask::Frame(12), Ask::Frame(11), Ask::Head] {
                    let asking = checks.ask(ask, Instant::now());
                    queued_asks.push(matches!(asking, Asking::Queued(None)));
                }
            }
            seen.push(asked);
        });
        assert_eq!(
            queued_asks, [true; 3],
            "TWO-IN-FLIGHT: a second check started while one ran"
        );
        assert!(
            seen.len() > 1,
            "FOLLOW-UP-LOST: the frames asked during a check were never checked"
        );
        assert_eq!(
            seen[1],
            Asked {
                frame: Some(12),
                head: true
            },
            "NOT-NEWEST: the check after it ran at another frame than the newest asked"
        );
        assert_eq!(
            seen,
            [
                Asked {
                    frame: Some(10),
                    head: false
                },
                Asked {
                    frame: Some(12),
                    head: true
                }
            ]
        );
        drop(started(checks.ask(Ask::Frame(13), Instant::now())));
    }

    /// The frame a check runs at reads the stored head only when asked.
    #[test]
    fn a_check_reads_the_stored_head_only_when_asked() {
        let at = |asked: Asked| {
            let mut read = false;
            let frame = asked.frame(|| {
                read = true;
                Some(20)
            });
            (frame, read)
        };
        assert_eq!(
            at(Asked {
                frame: Some(30),
                head: false
            }),
            (Some(30), false),
            "HEAD-READ: the stored head was read though not asked"
        );
        assert_eq!(
            at(Asked {
                frame: Some(10),
                head: true
            }),
            (Some(20), true)
        );
        assert_eq!(
            at(Asked {
                frame: None,
                head: false
            }),
            (None, false)
        );
    }

    /// A run never started, as by a runtime shutting down, frees the
    /// engine's run: else no check would run again.
    #[test]
    fn a_run_never_started_frees_its_slot() {
        let checks = Arc::new(Checks::default());
        drop(started(checks.ask(Ask::Frame(1), Instant::now())));
        let running = started(checks.ask(Ask::Frame(2), Instant::now()));
        let mut seen = Vec::new();
        running.run(b"s", |asked| seen.push(asked.frame));
        assert_eq!(seen, [Some(2)], "what was asked before is checked once");
    }

    /// A check that panics is reported, and the next one is asked anew:
    /// the panic neither escapes the run nor holds the engine's run.
    #[test]
    fn a_panicking_check_ends_its_run_and_frees_the_slot() {
        let checks = Arc::new(Checks::default());
        let running = started(checks.ask(Ask::Frame(1), Instant::now()));
        let escaped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            running.run(b"s", |_| panic!("a check that panics"))
        }))
        .is_err();
        assert!(
            !escaped,
            "PANIC-ESCAPED: a panicking check ended the run's thread"
        );
        drop(started(checks.ask(Ask::Frame(2), Instant::now())));
    }

    /// A check past its bound is reported once, again only after the
    /// repeat interval, and its end with how long it ran.
    #[test]
    fn a_check_past_its_bound_is_reported_once_then_at_the_repeat_and_at_its_end() {
        let checks = Arc::new(Checks::default());
        let start = Instant::now();
        let running = started(checks.ask(Ask::Frame(1), start));
        assert_eq!(
            checks.next(running.id, start, b"s").0.map(|a| a.frame),
            Some(Some(1))
        );
        let ask = |after: Duration| queued(checks.ask(Ask::Frame(2), start + after));
        assert_eq!(
            ask(OVERRUN / 2),
            None,
            "a check within its bound is not reported"
        );
        assert_eq!(
            ask(OVERRUN),
            Some(OVERRUN),
            "OVERRUN-SILENT: a check past its bound was not reported"
        );
        assert_eq!(
            ask(OVERRUN * 2),
            None,
            "REPEAT-UNBOUNDED: a check still running was reported again before the repeat interval"
        );
        assert_eq!(
            ask(OVERRUN + OVERRUN_REPEAT),
            Some(OVERRUN + OVERRUN_REPEAT),
            "a check still running is reported again at the repeat interval"
        );
        let end = start + OVERRUN_REPEAT * 2;
        let (asked, ran) = checks.next(running.id, end, b"s");
        assert_eq!(
            ran,
            Some(OVERRUN_REPEAT * 2),
            "its end is reported with how long it ran"
        );
        assert_eq!(asked.map(|a| a.frame), Some(Some(2)));
        assert_eq!(checks.next(running.id, end, b"s"), (None, None));
        drop(running);
        drop(started(checks.ask(Ask::Frame(3), end)));
    }
}
