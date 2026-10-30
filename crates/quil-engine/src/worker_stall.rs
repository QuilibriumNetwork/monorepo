//! Names what blocks a worker thread. Each worker thread runs a
//! current-thread runtime, so one synchronous call that does not return
//! stalls every task on it: consensus messages, votes and archive work
//! wait until it returns.
//!
//! A heartbeat task on each worker thread beats its
//! [`ThreadProbe`]; one watchdog thread, shared by all workers, warns when
//! a heartbeat is overdue, naming the task, engine step and synchronous
//! section the thread is in ([`quil_types::thread_probe`]), repeats while
//! it lasts, and logs its end with the sections seen.
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use quil_types::thread_probe::{now_ms, Mark, Section, Snapshot, ThreadProbe};
use tracing::{info, warn};

/// How often a worker thread beats.
pub const HEARTBEAT: Duration = Duration::from_secs(1);
/// A heartbeat older than this is a blocked thread.
pub const STALL_AFTER: Duration = Duration::from_secs(6);
/// How often a continuing stall warns again.
pub const STALL_REPEAT: Duration = Duration::from_secs(30);
/// How often the watchdog looks.
const WATCH_EVERY: Duration = Duration::from_millis(500);
/// Distinct places recorded per stall.
const MAX_SEEN: usize = 8;

/// Where a blocked thread was seen: its task, the engine step (only while
/// the engine's task is polled) and its synchronous sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub task: Option<Mark>,
    pub step: Option<Mark>,
    pub section: Option<Mark>,
    pub outer: Option<Mark>,
}

impl Place {
    fn of(snapshot: &Snapshot) -> Self {
        let engine = snapshot
            .task
            .is_some_and(|task| task.section == Section::AppEngine);
        Place {
            task: snapshot.task,
            step: snapshot.step.filter(|_| engine),
            section: snapshot.section,
            outer: snapshot
                .outer
                .filter(|outer| Some(outer.section) != snapshot.section.map(|s| s.section)),
        }
    }

    fn labels(&self) -> (Section, Section, Section, Section) {
        let label = |mark: Option<Mark>| mark.map_or(Section::None, |mark| mark.section);
        (
            label(self.task),
            label(self.step),
            label(self.section),
            label(self.outer),
        )
    }

    /// `task / step / section (within outer)`, naming only what is marked.
    pub fn describe(&self) -> String {
        let (task, step, section, outer) = self.labels();
        let mut text = if task == Section::None {
            "an unmarked task".to_string()
        } else {
            task.label().to_string()
        };
        if step != Section::None {
            text.push_str(" / ");
            text.push_str(step.label());
        }
        if section != Section::None {
            text.push_str(" / ");
            text.push_str(section.label());
        }
        if outer != Section::None {
            text.push_str(" within ");
            text.push_str(outer.label());
        }
        text
    }
}

/// What the watchdog logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StallReport {
    /// A heartbeat became overdue (`continues: false`) or is still overdue.
    Blocked {
        core_id: u32,
        filter: Vec<u8>,
        blocked: Duration,
        place: Place,
        at_ms: u64,
        continues: bool,
    },
    /// The heartbeat resumed, or the thread ended.
    Ended {
        core_id: u32,
        filter: Vec<u8>,
        blocked: Duration,
        seen: Vec<String>,
        exited: bool,
    },
}

struct Stall {
    last_beat_ms: u64,
    /// The worker's shard when the stall began.
    filter: Vec<u8>,
    reported_ms: u64,
    seen: Vec<(Section, Section, Section, Section)>,
    described: Vec<String>,
}

impl Stall {
    fn see(&mut self, place: &Place) {
        let labels = place.labels();
        if self.seen.len() < MAX_SEEN && !self.seen.contains(&labels) {
            self.seen.push(labels);
            self.described.push(place.describe());
        }
    }
}

struct Watched {
    core_id: u32,
    probe: Weak<ThreadProbe>,
    stall: Option<Stall>,
}

/// The watchdog's state: the threads it watches and their stalls.
pub struct StallWatch {
    stall_after: Duration,
    repeat: Duration,
    watched: Vec<Watched>,
}

impl StallWatch {
    pub fn new(stall_after: Duration, repeat: Duration) -> Self {
        Self {
            stall_after,
            repeat,
            watched: Vec::new(),
        }
    }

    /// Watch a worker thread's probe until it is dropped.
    pub fn add(&mut self, core_id: u32, probe: &Arc<ThreadProbe>) {
        self.watched
            .retain(|w| w.core_id != core_id || w.probe.strong_count() > 0);
        self.watched.push(Watched {
            core_id,
            probe: Arc::downgrade(probe),
            stall: None,
        });
    }

    /// Look at every watched thread at `now_ms`.
    pub fn poll(&mut self, now_ms: u64) -> Vec<StallReport> {
        let stall_after = self.stall_after.as_millis() as u64;
        let repeat = self.repeat.as_millis() as u64;
        let mut reports = Vec::new();
        self.watched.retain_mut(|watched| {
            let Some(probe) = watched.probe.upgrade() else {
                if let Some(stall) = watched.stall.take() {
                    reports.push(StallReport::Ended {
                        core_id: watched.core_id,
                        filter: stall.filter,
                        blocked: Duration::from_millis(now_ms.saturating_sub(stall.last_beat_ms)),
                        seen: stall.described,
                        exited: true,
                    });
                }
                return false;
            };
            let snapshot = probe.snapshot();
            let age = now_ms.saturating_sub(snapshot.last_beat_ms);
            let resumed = watched
                .stall
                .as_ref()
                .is_some_and(|stall| stall.last_beat_ms != snapshot.last_beat_ms);
            if resumed {
                let stall = watched.stall.take().expect("a resumed thread was stalled");
                reports.push(StallReport::Ended {
                    core_id: watched.core_id,
                    filter: stall.filter,
                    blocked: Duration::from_millis(
                        snapshot.last_beat_ms.saturating_sub(stall.last_beat_ms),
                    ),
                    seen: stall.described,
                    exited: false,
                });
            } else if let Some(stall) = watched.stall.as_mut() {
                let place = Place::of(&snapshot);
                stall.see(&place);
                if now_ms.saturating_sub(stall.reported_ms) >= repeat {
                    stall.reported_ms = now_ms;
                    reports.push(StallReport::Blocked {
                        core_id: watched.core_id,
                        filter: stall.filter.clone(),
                        blocked: Duration::from_millis(age),
                        place,
                        at_ms: now_ms,
                        continues: true,
                    });
                }
            } else if age > stall_after {
                let place = Place::of(&snapshot);
                let mut stall = Stall {
                    last_beat_ms: snapshot.last_beat_ms,
                    filter: probe.filter(),
                    reported_ms: now_ms,
                    seen: Vec::new(),
                    described: Vec::new(),
                };
                stall.see(&place);
                let filter = stall.filter.clone();
                watched.stall = Some(stall);
                reports.push(StallReport::Blocked {
                    core_id: watched.core_id,
                    filter,
                    blocked: Duration::from_millis(age),
                    place,
                    at_ms: now_ms,
                    continues: false,
                });
            }
            true
        });
        reports
    }
}

/// Beat `probe` every `period` while it lives; spawn on the worker thread's
/// runtime, so that the beat stops while anything blocks the thread.
pub async fn heartbeat(probe: Weak<ThreadProbe>, period: Duration) {
    let mut ticks = tokio::time::interval(period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticks.tick().await;
        match probe.upgrade() {
            Some(probe) => probe.beat(),
            None => return,
        }
    }
}

type LogRoute = fn(Option<u32>);
static LOG_ROUTE: OnceLock<LogRoute> = OnceLock::new();

/// Route the watchdog's lines for a worker to that worker's log, through
/// the node's per-thread log tag (`None` restores the watchdog's own).
pub fn route_logs_with(route: LogRoute) {
    let _ = LOG_ROUTE.set(route);
}

fn watchdog() -> &'static Mutex<StallWatch> {
    static WATCH: OnceLock<Mutex<StallWatch>> = OnceLock::new();
    WATCH.get_or_init(|| {
        let spawned = std::thread::Builder::new().name("worker-watchdog".into()).spawn(|| loop {
            std::thread::sleep(WATCH_EVERY);
            let reports = watchdog().lock().unwrap_or_else(|e| e.into_inner()).poll(now_ms());
            for report in reports {
                log(&report);
            }
        });
        if let Err(error) = spawned {
            warn!(%error, "worker thread watchdog could not start; blocked worker threads go unreported");
        }
        Mutex::new(StallWatch::new(STALL_AFTER, STALL_REPEAT))
    })
}

/// Watch a worker thread's probe from the shared watchdog thread.
pub fn watch(core_id: u32, probe: &Arc<ThreadProbe>) {
    watchdog()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .add(core_id, probe);
}

const BLOCKED_ACTION: &str =
    "a defect in this node's worker thread (blocked over 6 s): votes and other work on it wait \
    while it lasts; report this line and its 'worker thread unblocked' line to the maintainer";

fn log(report: &StallReport) {
    let route = LOG_ROUTE.get();
    let core = match report {
        StallReport::Blocked { core_id, .. } | StallReport::Ended { core_id, .. } => *core_id,
    };
    if let Some(route) = route {
        route(Some(core));
    }
    let filter_text = |filter: &[u8]| {
        if filter.is_empty() {
            "none".to_string()
        } else {
            hex::encode(filter)
        }
    };
    let secs = |mark: Option<Mark>, now: u64| {
        mark.map_or(0, |mark| now.saturating_sub(mark.since_ms) / 1000)
    };
    let label = |mark: Option<Mark>| mark.map_or("none", |mark| mark.section.label());
    match report {
        StallReport::Blocked {
            core_id,
            filter,
            blocked,
            place,
            at_ms,
            continues,
        } => {
            let message = if *continues {
                "worker thread still blocked"
            } else {
                "worker thread blocked"
            };
            warn!(core_id, filter = %filter_text(filter), blocked_secs = blocked.as_secs(),
                task = label(place.task), poll_secs = secs(place.task, *at_ms),
                engine_step = label(place.step), step_secs = secs(place.step, *at_ms),
                section = label(place.section), section_secs = secs(place.section, *at_ms),
                within = label(place.outer), within_secs = secs(place.outer, *at_ms),
                place = %place.describe(), scope = "this node's worker thread",
                action = BLOCKED_ACTION, "{message}");
        }
        StallReport::Ended {
            core_id,
            filter,
            blocked,
            seen,
            exited,
        } => {
            info!(core_id, filter = %filter_text(filter), blocked_secs = blocked.as_secs(),
                seen = %seen.join("; "), exited, scope = "this node's worker thread",
                "worker thread unblocked after {}s", blocked.as_secs());
        }
    }
    if let Some(route) = route {
        route(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::thread_probe::{install, probed, section, step};

    /// Poll `watch` every 20 ms until `found` picks a report, for at most 5 s.
    fn await_report(
        watch: &mut StallWatch,
        found: impl Fn(&StallReport) -> bool,
    ) -> Option<StallReport> {
        for _ in 0..250 {
            if let Some(report) = watch.poll(now_ms()).into_iter().find(|r| found(r)) {
                return Some(report);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    #[test]
    fn a_blocked_worker_thread_is_reported_with_its_section_until_it_returns() {
        let probe = ThreadProbe::new();
        probe.set_filter(&[0xab; 35]);
        let mut watch = StallWatch::new(Duration::from_millis(1000), Duration::from_millis(300));
        watch.add(7, &probe);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        // The worker thread holds the only reference, as in a node.
        let worker_probe = probe;
        let worker = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let installed = install(worker_probe.clone());
            rt.spawn(heartbeat(
                Arc::downgrade(&worker_probe),
                Duration::from_millis(50),
            ));
            drop(worker_probe);
            rt.block_on(async move {
                // Longer than the threshold: a missing heartbeat would be reported.
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let engine = tokio::spawn(probed(Section::AppEngine, async move {
                    step(Section::EngineRetryTimer);
                    tokio::task::yield_now().await;
                    let _check = section(Section::SuccessorStateCheck);
                    let _wait = section(Section::CommitLockWait);
                    entered_tx.send(()).unwrap();
                    // Blocks the worker thread, as a synchronous call would.
                    release_rx.recv().unwrap();
                }));
                engine.await.unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
            });
            drop(installed);
        });
        // Healthy beats before the block raise nothing.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while entered_rx.recv_timeout(Duration::from_millis(20)).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "the worker never blocked"
            );
            assert_eq!(watch.poll(now_ms()), Vec::new());
        }

        let started = await_report(&mut watch, |r| {
            matches!(
                r,
                StallReport::Blocked {
                    continues: false,
                    ..
                }
            )
        })
        .expect("the watchdog reports the blocked worker thread");
        let StallReport::Blocked {
            core_id,
            filter,
            blocked,
            place,
            ..
        } = started
        else {
            unreachable!()
        };
        assert_eq!((core_id, filter), (7, vec![0xab; 35]));
        assert!(blocked > Duration::from_millis(1000));
        assert_eq!(place.task.map(|m| m.section), Some(Section::AppEngine));
        assert_eq!(
            place.step.map(|m| m.section),
            Some(Section::EngineRetryTimer)
        );
        assert_eq!(
            place.section.map(|m| m.section),
            Some(Section::CommitLockWait)
        );
        assert_eq!(
            place.outer.map(|m| m.section),
            Some(Section::SuccessorStateCheck)
        );
        assert_eq!(place.describe(),
            "app engine / consensus retry timer / CRDT commit lock wait within successor state check");

        // It repeats while the thread stays blocked.
        assert!(await_report(&mut watch, |r| matches!(
            r,
            StallReport::Blocked {
                continues: true,
                ..
            }
        ))
        .is_some());

        release_tx.send(()).unwrap();
        let ended = await_report(&mut watch, |r| matches!(r, StallReport::Ended { .. }))
            .expect("the watchdog reports the end of the stall");
        let StallReport::Ended {
            core_id,
            blocked,
            seen,
            exited,
            ..
        } = ended
        else {
            unreachable!()
        };
        assert_eq!((core_id, exited), (7, false));
        assert!(blocked > Duration::from_millis(1000));
        // The first sighting is the blocked place. The closure then drops its
        // sections before the next heartbeat, so a poll under load may also see
        // the unwound place: the same task and step, shorter.
        let blocked_place = "app engine / consensus retry timer / CRDT commit lock wait within successor state check";
        let unwound_prefix = "app engine / consensus retry timer";
        assert_eq!(
            seen.first().map(String::as_str),
            Some(blocked_place),
            "{seen:?}"
        );
        assert!(seen[1..].iter().all(|later| later.starts_with(unwound_prefix) && later.len() < blocked_place.len()),
            "{seen:?}");
        worker.join().unwrap();
        // The thread's probe is gone; the watchdog drops it without a report.
        assert!(watch.poll(now_ms()).is_empty());
        assert!(watch.watched.is_empty());
    }

    #[test]
    fn a_beating_worker_thread_is_not_reported() {
        let probe = ThreadProbe::new();
        // Well above the heartbeat, for parallel test load; the worker beats
        // for twice as long, so a missing heartbeat would be reported.
        let mut watch = StallWatch::new(Duration::from_millis(1500), Duration::from_millis(300));
        watch.add(3, &probe);
        let worker_probe = probe;
        let worker = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _installed = install(worker_probe.clone());
            rt.spawn(heartbeat(
                Arc::downgrade(&worker_probe),
                Duration::from_millis(50),
            ));
            rt.block_on(async { tokio::time::sleep(Duration::from_millis(3500)).await });
        });
        let mut reports = Vec::new();
        for _ in 0..150 {
            reports.extend(watch.poll(now_ms()));
            std::thread::sleep(Duration::from_millis(20));
        }
        worker.join().unwrap();
        assert!(reports.is_empty(), "{reports:?}");
    }

    #[test]
    fn a_thread_that_exits_blocked_ends_its_stall_with_its_shard() {
        let probe = ThreadProbe::new();
        probe.set_filter(&[0xcd; 35]);
        let mut watch = StallWatch::new(Duration::from_millis(400), Duration::from_millis(300));
        watch.add(4, &probe);
        let beat = probe.snapshot().last_beat_ms;
        let reports = watch.poll(beat + 500);
        assert!(
            matches!(
                reports.as_slice(),
                [StallReport::Blocked {
                    core_id: 4,
                    continues: false,
                    ..
                }]
            ),
            "{reports:?}"
        );
        drop(probe);
        let reports = watch.poll(beat + 700);
        let [StallReport::Ended {
            core_id,
            filter,
            blocked,
            exited,
            ..
        }] = reports.as_slice()
        else {
            panic!("{reports:?}");
        };
        assert_eq!(
            (*core_id, filter.as_slice(), *blocked, *exited),
            (4, &[0xcd; 35][..], Duration::from_millis(700), true)
        );
        assert!(watch.watched.is_empty());
    }
}
