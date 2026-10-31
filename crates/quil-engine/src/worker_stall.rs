//! Names what blocks a worker thread. Each worker thread runs a
//! current-thread runtime, so one synchronous call that does not return
//! stalls every task on it: consensus messages, votes and archive work
//! wait until it returns.
//!
//! A heartbeat task on each worker thread beats its
//! [`ThreadProbe`]; one watchdog thread, shared by all workers, warns when
//! a heartbeat is overdue, naming the task, engine step and synchronous
//! section the thread is in ([`quil_types::thread_probe`]) and where the
//! stall's time went since its last beat, repeats while it lasts, and logs
//! its end with the sections seen. Further stalls of the same worker within
//! [`STALL_SUMMARY_EVERY`] of a warned one are counted into one summary.
use std::collections::VecDeque;
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
/// After a warned stall, how long further stalls of that worker are counted
/// into one summary instead of warned one by one.
pub const STALL_SUMMARY_EVERY: Duration = Duration::from_secs(10 * 60);
/// How often the watchdog looks.
const WATCH_EVERY: Duration = Duration::from_millis(500);
/// Distinct places recorded per stall, and per summary.
const MAX_SEEN: usize = 8;
/// Places sampled before a stall is found: enough for [`STALL_AFTER`] at
/// [`WATCH_EVERY`], so a stall's time is accounted from its last beat.
const SAMPLES: usize = 16;

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

/// Time a stall, or a summary's stalls, spent in each place, in the order
/// first seen; places past [`MAX_SEEN`] are counted as "other places".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlaceTimes(Vec<(String, u64)>);

impl PlaceTimes {
    fn add(&mut self, place: String, ms: u64) {
        if let Some(entry) = self.0.iter_mut().find(|(seen, _)| *seen == place) {
            entry.1 += ms;
        } else if self.0.len() < MAX_SEEN {
            self.0.push((place, ms));
        } else {
            self.add_other(ms);
        }
    }

    fn add_other(&mut self, ms: u64) {
        const OTHER: &str = "other places";
        match self.0.iter_mut().find(|(seen, _)| seen == OTHER) {
            Some(entry) => entry.1 += ms,
            None => self.0.push((OTHER.to_string(), ms)),
        }
    }

    fn merge(&mut self, other: &PlaceTimes) {
        for (place, ms) in &other.0 {
            self.add(place.clone(), *ms);
        }
    }

    /// The place with the most time, and that time.
    pub fn most(&self) -> Option<(&str, Duration)> {
        self.0
            .iter()
            .max_by_key(|(_, ms)| *ms)
            .map(|(place, ms)| (place.as_str(), Duration::from_millis(*ms)))
    }

    /// `place 3.5s; place 1.0s`, most time first.
    pub fn describe(&self) -> String {
        let mut sorted: Vec<&(String, u64)> = self.0.iter().collect();
        sorted.sort_by_key(|(_, ms)| std::cmp::Reverse(*ms));
        sorted
            .iter()
            .map(|(place, ms)| format!("{place} {:.1}s", *ms as f64 / 1000.0))
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub fn entries(&self) -> &[(String, u64)] {
        &self.0
    }
}

/// What the watchdog logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StallReport {
    /// A heartbeat became overdue (`continues: false`) or is still overdue.
    /// `times`: where the stall's time went since the thread's last beat.
    Blocked {
        core_id: u32,
        filter: Vec<u8>,
        blocked: Duration,
        place: Place,
        times: PlaceTimes,
        at_ms: u64,
        continues: bool,
    },
    /// The heartbeat resumed, or the thread ended.
    Ended {
        core_id: u32,
        filter: Vec<u8>,
        blocked: Duration,
        seen: Vec<String>,
        times: PlaceTimes,
        exited: bool,
    },
    /// The stalls of one worker counted after a warned one, over `interval`
    /// from that warned stall's report: how many (the warned one included),
    /// the longest and where its time went most, and their time by place.
    /// `ongoing`: how long one still lasting has blocked so far; it is
    /// warned on its own from here.
    Summary {
        core_id: u32,
        filter: Vec<u8>,
        interval: Duration,
        stalls: u32,
        longest: Duration,
        longest_place: String,
        total: Duration,
        times: PlaceTimes,
        ongoing: Option<Duration>,
    },
}

struct Stall {
    last_beat_ms: u64,
    /// The worker's shard when the stall began.
    filter: Vec<u8>,
    reported_ms: u64,
    seen: Vec<(Section, Section, Section, Section)>,
    described: Vec<String>,
    /// Where its time went, accounted to `accounted_ms`.
    times: PlaceTimes,
    accounted_ms: u64,
    /// Counted into the worker's summary rather than warned on its own.
    quiet: bool,
}

impl Stall {
    fn see(&mut self, place: &Place) {
        let labels = place.labels();
        if self.seen.len() < MAX_SEEN && !self.seen.contains(&labels) {
            self.seen.push(labels);
            self.described.push(place.describe());
        }
    }

    /// Account the time since the last sample to `place`, seen at `at_ms`.
    fn account(&mut self, place: &Place, at_ms: u64) {
        let ms = at_ms.saturating_sub(self.accounted_ms);
        if ms > 0 {
            self.times.add(place.describe(), ms);
            self.accounted_ms = at_ms;
        }
    }
}

/// A worker's stalls since its last warned one: the summary's counts.
#[derive(Default)]
struct Summary {
    /// When the warned stall that opened it was reported; none while closed.
    opened_ms: Option<u64>,
    filter: Vec<u8>,
    stalls: u32,
    quiet: u32,
    longest_ms: u64,
    longest_place: String,
    total_ms: u64,
    times: PlaceTimes,
}

impl Summary {
    fn open(&mut self, at_ms: u64) {
        *self = Summary {
            opened_ms: Some(at_ms),
            ..Summary::default()
        };
    }

    /// A stall of `blocked_ms` ended; `quiet` when it was not warned.
    fn count(&mut self, filter: &[u8], blocked_ms: u64, times: &PlaceTimes, quiet: bool) {
        self.stalls += 1;
        self.quiet += u32::from(quiet);
        self.total_ms += blocked_ms;
        self.times.merge(times);
        if blocked_ms >= self.longest_ms {
            self.longest_ms = blocked_ms;
            self.longest_place = times
                .most()
                .map_or_else(|| "none".to_string(), |(place, _)| place.to_string());
        }
        filter.clone_into(&mut self.filter);
    }
}

struct Watched {
    core_id: u32,
    probe: Weak<ThreadProbe>,
    stall: Option<Stall>,
    /// Recent places, sampled each poll: `(at_ms, place)`.
    samples: VecDeque<(u64, Place)>,
    summary: Summary,
}

impl Watched {
    /// The summary of the stalls counted since the warned one, when any
    /// were counted silently or `ongoing` still lasts; it closes either way.
    fn close_summary(
        &mut self,
        now_ms: u64,
        ongoing: Option<(u64, Vec<u8>)>,
    ) -> Option<StallReport> {
        let opened = self.summary.opened_ms?;
        let mut summary = std::mem::take(&mut self.summary);
        let ongoing = ongoing.map(|(blocked, filter)| {
            summary.filter = filter;
            blocked
        });
        (summary.quiet > 0 || ongoing.is_some()).then(|| StallReport::Summary {
            core_id: self.core_id,
            filter: summary.filter,
            interval: Duration::from_millis(now_ms.saturating_sub(opened)),
            stalls: summary.stalls + u32::from(ongoing.is_some()),
            longest: Duration::from_millis(summary.longest_ms.max(ongoing.unwrap_or(0))),
            longest_place: summary.longest_place,
            total: Duration::from_millis(summary.total_ms + ongoing.unwrap_or(0)),
            times: summary.times,
            ongoing: ongoing.map(Duration::from_millis),
        })
    }
}

/// The watchdog's state: the threads it watches and their stalls.
pub struct StallWatch {
    stall_after: Duration,
    repeat: Duration,
    summary_every: Duration,
    watched: Vec<Watched>,
}

impl StallWatch {
    pub fn new(stall_after: Duration, repeat: Duration) -> Self {
        Self::with_summary(stall_after, repeat, STALL_SUMMARY_EVERY)
    }

    /// [`Self::new`], counting a worker's stalls into one summary for
    /// `summary_every` after each warned one.
    pub fn with_summary(stall_after: Duration, repeat: Duration, summary_every: Duration) -> Self {
        Self {
            stall_after,
            repeat,
            summary_every,
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
            samples: VecDeque::with_capacity(SAMPLES),
            summary: Summary::default(),
        });
    }

    /// Look at every watched thread at `now_ms`.
    pub fn poll(&mut self, now_ms: u64) -> Vec<StallReport> {
        let stall_after = self.stall_after.as_millis() as u64;
        let repeat = self.repeat.as_millis() as u64;
        let summary_every = self.summary_every.as_millis() as u64;
        let mut reports = Vec::new();
        self.watched.retain_mut(|watched| {
            let Some(probe) = watched.probe.upgrade() else {
                if let Some(mut stall) = watched.stall.take() {
                    let blocked = now_ms.saturating_sub(stall.last_beat_ms);
                    if let Some(&(_, last)) = watched.samples.back() {
                        stall.account(&last, now_ms);
                    }
                    watched
                        .summary
                        .count(&stall.filter, blocked, &stall.times, stall.quiet);
                    if !stall.quiet {
                        reports.push(StallReport::Ended {
                            core_id: watched.core_id,
                            filter: stall.filter,
                            blocked: Duration::from_millis(blocked),
                            seen: stall.described,
                            times: stall.times,
                            exited: true,
                        });
                    }
                }
                reports.extend(watched.close_summary(now_ms, None));
                return false;
            };
            let snapshot = probe.snapshot();
            let place = Place::of(&snapshot);
            if watched.samples.len() == SAMPLES {
                watched.samples.pop_front();
            }
            watched.samples.push_back((now_ms, place));
            let age = now_ms.saturating_sub(snapshot.last_beat_ms);
            let resumed = watched
                .stall
                .as_ref()
                .is_some_and(|stall| stall.last_beat_ms != snapshot.last_beat_ms);
            if resumed {
                let mut stall = watched.stall.take().expect("a resumed thread was stalled");
                let blocked = snapshot.last_beat_ms.saturating_sub(stall.last_beat_ms);
                // The place the thread was last seen blocked in held it until
                // the beat.
                let last = watched
                    .samples
                    .iter()
                    .rev()
                    .nth(1)
                    .map_or(place, |&(_, last)| last);
                stall.account(&last, snapshot.last_beat_ms.min(now_ms));
                watched
                    .summary
                    .count(&stall.filter, blocked, &stall.times, stall.quiet);
                if !stall.quiet {
                    reports.push(StallReport::Ended {
                        core_id: watched.core_id,
                        filter: stall.filter,
                        blocked: Duration::from_millis(blocked),
                        seen: stall.described,
                        times: stall.times,
                        exited: false,
                    });
                }
            } else if let Some(stall) = watched.stall.as_mut() {
                stall.see(&place);
                stall.account(&place, now_ms);
                if !stall.quiet && now_ms.saturating_sub(stall.reported_ms) >= repeat {
                    stall.reported_ms = now_ms;
                    reports.push(StallReport::Blocked {
                        core_id: watched.core_id,
                        filter: stall.filter.clone(),
                        blocked: Duration::from_millis(age),
                        place,
                        times: stall.times.clone(),
                        at_ms: now_ms,
                        continues: true,
                    });
                }
            } else if age > stall_after {
                let quiet = watched.summary.opened_ms.is_some();
                let mut stall = Stall {
                    last_beat_ms: snapshot.last_beat_ms,
                    filter: probe.filter(),
                    reported_ms: now_ms,
                    seen: Vec::new(),
                    described: Vec::new(),
                    times: PlaceTimes::default(),
                    accounted_ms: snapshot.last_beat_ms,
                    quiet,
                };
                // Where the time since the last beat went, from the places
                // sampled meanwhile.
                for (at, sampled) in watched.samples.iter() {
                    if *at > snapshot.last_beat_ms {
                        stall.account(sampled, *at);
                    }
                }
                stall.see(&place);
                if !quiet {
                    watched.summary.open(now_ms);
                    reports.push(StallReport::Blocked {
                        core_id: watched.core_id,
                        filter: stall.filter.clone(),
                        blocked: Duration::from_millis(age),
                        place,
                        times: stall.times.clone(),
                        at_ms: now_ms,
                        continues: false,
                    });
                }
                watched.stall = Some(stall);
            }
            let summary_due = watched
                .summary
                .opened_ms
                .is_some_and(|opened| now_ms.saturating_sub(opened) >= summary_every);
            if summary_due {
                // A quiet stall still lasting is warned on its own from here,
                // and opens the next summary.
                let ongoing = watched
                    .stall
                    .as_ref()
                    .filter(|stall| stall.quiet)
                    .map(|stall| {
                        (
                            now_ms.saturating_sub(stall.last_beat_ms),
                            stall.filter.clone(),
                        )
                    });
                reports.extend(watched.close_summary(now_ms, ongoing));
                if let Some(stall) = watched.stall.as_mut().filter(|stall| stall.quiet) {
                    stall.quiet = false;
                    stall.reported_ms = now_ms;
                    watched.summary.open(now_ms);
                    reports.push(StallReport::Blocked {
                        core_id: watched.core_id,
                        filter: stall.filter.clone(),
                        blocked: Duration::from_millis(age),
                        place,
                        times: stall.times.clone(),
                        at_ms: now_ms,
                        continues: true,
                    });
                }
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
    while it lasts; 'time_by_place' names where its time went; further stalls of this worker in the \
    next 10 minutes are counted into one 'worker thread blocked repeatedly' line; report this line \
    and its 'worker thread unblocked' line to the maintainer";

const REPEATED_ACTION: &str =
    "a defect in this node's worker thread: it kept blocking after the warned stall; votes and other \
    work on it waited meanwhile; report this line with the place that took the most time";

fn log(report: &StallReport) {
    let route = LOG_ROUTE.get();
    let core = match report {
        StallReport::Blocked { core_id, .. }
        | StallReport::Ended { core_id, .. }
        | StallReport::Summary { core_id, .. } => *core_id,
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
            times,
            at_ms,
            continues,
        } => {
            let message = if *continues {
                "worker thread still blocked"
            } else {
                "worker thread blocked"
            };
            let (most_place, most) = times.most().unwrap_or(("none", Duration::ZERO));
            warn!(core_id, filter = %filter_text(filter), blocked_secs = blocked.as_secs(),
                task = label(place.task), poll_secs = secs(place.task, *at_ms),
                engine_step = label(place.step), step_secs = secs(place.step, *at_ms),
                section = label(place.section), section_secs = secs(place.section, *at_ms),
                within = label(place.outer), within_secs = secs(place.outer, *at_ms),
                place = %place.describe(), most_time_in = most_place, most_time_secs = most.as_secs(),
                time_by_place = %times.describe(), scope = "this node's worker thread",
                action = BLOCKED_ACTION, "{message}");
        }
        StallReport::Ended {
            core_id,
            filter,
            blocked,
            seen,
            times,
            exited,
        } => {
            info!(core_id, filter = %filter_text(filter), blocked_secs = blocked.as_secs(),
                seen = %seen.join("; "), time_by_place = %times.describe(), exited,
                scope = "this node's worker thread",
                "worker thread unblocked after {}s", blocked.as_secs());
        }
        StallReport::Summary {
            core_id,
            filter,
            interval,
            stalls,
            longest,
            longest_place,
            total,
            times,
            ongoing,
        } => {
            warn!(core_id, filter = %filter_text(filter), interval_secs = interval.as_secs(), stalls,
                longest_secs = longest.as_secs(), longest_place = %longest_place,
                total_blocked_secs = total.as_secs(), time_by_place = %times.describe(),
                ongoing_secs = ongoing.map_or(0, |d| d.as_secs()), scope = "this node's worker thread",
                action = REPEATED_ACTION,
                "worker thread blocked repeatedly: {stalls} stalls in {}s, longest {}s",
                interval.as_secs(), longest.as_secs());
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

    /// A stall names where its time went from the thread's last beat, not
    /// only the place it is found in: a retry tick that read the store for
    /// seconds before reaching its fence rewind check was named after that
    /// check alone (2026-10-31).
    #[test]
    fn a_stall_names_where_its_time_went_since_its_last_beat() {
        let probe = ThreadProbe::new();
        let _installed = install(probe.clone());
        let mut watch = StallWatch::new(Duration::from_millis(1000), Duration::from_secs(60));
        watch.add(5, &probe);
        let beat = probe.snapshot().last_beat_ms;
        {
            let _scan = section(Section::FinalizedRecordsScan);
            assert_eq!(watch.poll(beat + 600), Vec::new());
        }
        let rewind = section(Section::FenceRewind);
        let reports = watch.poll(beat + 1100);
        let [StallReport::Blocked {
            place,
            times,
            continues: false,
            ..
        }] = reports.as_slice()
        else {
            panic!("{reports:?}");
        };
        assert_eq!(place.section.map(|m| m.section), Some(Section::FenceRewind));
        let scan = "an unmarked task / finalized records scan".to_string();
        let check = "an unmarked task / fence rewind check".to_string();
        assert_eq!(
            times.entries(),
            &[(scan.clone(), 600), (check.clone(), 500)][..]
        );
        assert_eq!(
            times.most(),
            Some((scan.as_str(), Duration::from_millis(600)))
        );
        drop(rewind);
        probe.beat_at(beat + 3000);
        let reports = watch.poll(beat + 3100);
        let [StallReport::Ended { seen, times, .. }] = reports.as_slice() else {
            panic!("{reports:?}");
        };
        assert_eq!(seen, &[check.clone()]);
        assert_eq!(times.entries(), &[(scan, 600), (check, 2400)][..]);
        assert_eq!(
            times.describe(),
            "an unmarked task / fence rewind check 2.4s; an unmarked task / finalized records scan 0.6s"
        );
    }

    /// After a warned stall, a worker's further stalls within the summary
    /// interval are counted into one summary with the longest, instead of a
    /// warning and an end line each (74 of each in 18 minutes on one worker,
    /// 2026-10-31); the next stall after it is warned again. A counted stall
    /// still lasting when the summary closes is warned on its own.
    #[test]
    fn stalls_after_a_warned_one_are_summarized_with_the_longest() {
        let probe = ThreadProbe::new();
        probe.set_filter(&[0xee; 35]);
        let mut watch = StallWatch::with_summary(
            Duration::from_millis(400),
            Duration::from_secs(60),
            Duration::from_secs(10),
        );
        watch.add(9, &probe);
        let t0 = probe.snapshot().last_beat_ms;
        let stall = |watch: &mut StallWatch, beat: u64, found: u64, ended: u64| {
            probe.beat_at(t0 + beat);
            let found = watch.poll(t0 + found);
            probe.beat_at(t0 + ended);
            let ended = watch.poll(t0 + ended);
            (found, ended)
        };
        assert!(matches!(
            watch.poll(t0 + 500).as_slice(),
            [StallReport::Blocked {
                continues: false,
                ..
            }]
        ));
        probe.beat_at(t0 + 1_000);
        assert!(matches!(
            watch.poll(t0 + 1_000).as_slice(),
            [StallReport::Ended { .. }]
        ));
        assert_eq!(stall(&mut watch, 1_000, 1_500, 1_800), (vec![], vec![]));
        assert_eq!(stall(&mut watch, 1_800, 2_500, 4_000), (vec![], vec![]));
        probe.beat_at(t0 + 10_400);
        let reports = watch.poll(t0 + 10_500);
        let [StallReport::Summary {
            core_id,
            filter,
            interval,
            stalls,
            longest,
            total,
            ongoing,
            ..
        }] = reports.as_slice()
        else {
            panic!("{reports:?}");
        };
        assert_eq!(
            (*core_id, filter.as_slice(), *stalls, *ongoing),
            (9, &[0xee; 35][..], 3, None)
        );
        assert_eq!(*interval, Duration::from_secs(10));
        assert_eq!(*longest, Duration::from_millis(2_200));
        assert_eq!(*total, Duration::from_millis(1_000 + 800 + 2_200));

        // The next stall is warned again and opens the next summary; one
        // counted into it that outlasts it is warned when it closes.
        assert!(matches!(
            watch.poll(t0 + 11_000).as_slice(),
            [StallReport::Blocked {
                continues: false,
                ..
            }]
        ));
        probe.beat_at(t0 + 11_500);
        assert!(matches!(
            watch.poll(t0 + 11_500).as_slice(),
            [StallReport::Ended { .. }]
        ));
        assert_eq!(watch.poll(t0 + 12_000), Vec::new());
        let reports = watch.poll(t0 + 21_000);
        assert!(
            matches!(
                reports.as_slice(),
                [
                    StallReport::Summary {
                        stalls: 2,
                        ongoing: Some(ongoing),
                        ..
                    },
                    StallReport::Blocked {
                        continues: true,
                        ..
                    }
                ] if *ongoing == Duration::from_millis(9_500)
            ),
            "{reports:?}"
        );
        probe.beat_at(t0 + 22_000);
        assert!(matches!(
            watch.poll(t0 + 22_000).as_slice(),
            [StallReport::Ended { .. }]
        ));
    }
}
