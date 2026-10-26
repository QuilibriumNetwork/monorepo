//! Names what blocks a master task. The message loop and the archive frame
//! poller each run as one task: a call in either that does not return holds
//! every message or GLOBAL frame behind it, and nothing else logs it.
//!
//! Each watched task runs under
//! [`task_probed`](quil_types::thread_probe::task_probed) with its own
//! [`ThreadProbe`] and beats it each time its loop comes round; the steps
//! and synchronous sections it enters mark where it is. One watchdog
//! thread, outside the async runtime so that it runs while the runtime is
//! wedged, warns when a task has not beaten within its threshold, naming
//! the task, step and section, repeats while the block lasts, and logs its
//! end.
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use quil_types::thread_probe::{now_ms, Mark, Section, Snapshot, ThreadProbe};
use tracing::{info, warn};

/// Its timers bring the message loop round at least every five seconds,
/// but an epoch step on it (a full prover registry refresh, epoch-boundary
/// execution) takes up to about 30 s on a regular node.
pub(crate) const MESSAGE_LOOP_STALL_AFTER: Duration = Duration::from_secs(60);
/// A poller fetch times out after 30 s and is retried once on a fresh
/// connection; a pass longer than that is blocked.
pub(crate) const POLLER_STALL_AFTER: Duration = Duration::from_secs(90);
/// How often a continuing block warns again.
const REPEAT: Duration = Duration::from_secs(60);
/// How often the watchdog looks.
const WATCH_EVERY: Duration = Duration::from_secs(5);
/// Distinct places recorded per block.
const MAX_SEEN: usize = 8;

pub(crate) const MESSAGE_LOOP_IMPACT: &str =
    "inbound gossip (GLOBAL frames, peer info, consensus messages) waits and 'node status' lines stop while it lasts";
pub(crate) const POLLER_IMPACT: &str = "this node fetches and executes no GLOBAL frame from archives while it lasts";

/// Where a blocked task was seen: the step it last entered and its
/// innermost and outermost synchronous sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Place {
    pub step: Option<Mark>,
    pub section: Option<Mark>,
    pub outer: Option<Mark>,
}

impl Place {
    fn of(snapshot: &Snapshot) -> Self {
        Place {
            step: snapshot.step,
            section: snapshot.section,
            outer: snapshot.outer.filter(|outer| Some(outer.section) != snapshot.section.map(|s| s.section)),
        }
    }

    /// `step / section within outer`, naming only what is marked.
    pub(crate) fn describe(&self) -> String {
        let mut parts = Vec::with_capacity(2);
        if let Some(step) = self.step {
            parts.push(step.section.label());
        }
        if let Some(section) = self.section {
            parts.push(section.section.label());
        }
        if parts.is_empty() {
            // Between beats every await is marked by a step: an unmarked
            // block is a task the runtime has not polled.
            parts.push("awaiting its next event");
        }
        let mut text = parts.join(" / ");
        if let Some(outer) = self.outer {
            text.push_str(" within ");
            text.push_str(outer.section.label());
        }
        text
    }
}

/// What the watchdog logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StallReport {
    /// The task's beat became overdue (`repeat: false`) or is still overdue.
    Blocked { task: Section, impact: &'static str, blocked: Duration, place: Place, at_ms: u64, repeat: bool },
    /// The task beat again, or ended.
    Unblocked { task: Section, blocked: Duration, seen: Vec<String>, exited: bool },
}

struct Stall {
    last_beat_ms: u64,
    reported_ms: u64,
    seen: Vec<String>,
}

impl Stall {
    fn see(&mut self, place: &Place) {
        let described = place.describe();
        if self.seen.len() < MAX_SEEN && !self.seen.contains(&described) {
            self.seen.push(described);
        }
    }
}

struct Watched {
    task: Section,
    impact: &'static str,
    stall_after_ms: u64,
    probe: Weak<ThreadProbe>,
    stall: Option<Stall>,
}

/// The watchdog's state: the tasks it watches and their blocks.
pub(crate) struct StallWatch {
    repeat_ms: u64,
    watched: Vec<Watched>,
}

impl StallWatch {
    pub(crate) fn new(repeat: Duration) -> Self {
        Self { repeat_ms: repeat.as_millis() as u64, watched: Vec::new() }
    }

    /// Watch `task`'s probe until it is dropped.
    pub(crate) fn add(&mut self, task: Section, impact: &'static str, stall_after: Duration, probe: &Arc<ThreadProbe>) {
        self.watched.push(Watched {
            task,
            impact,
            stall_after_ms: stall_after.as_millis() as u64,
            probe: Arc::downgrade(probe),
            stall: None,
        });
    }

    /// Look at every watched task at `now_ms` on the probe clock.
    pub(crate) fn poll(&mut self, now_ms: u64) -> Vec<StallReport> {
        let repeat_ms = self.repeat_ms;
        let mut reports = Vec::new();
        self.watched.retain_mut(|watched| {
            let Some(probe) = watched.probe.upgrade() else {
                if let Some(stall) = watched.stall.take() {
                    reports.push(StallReport::Unblocked {
                        task: watched.task,
                        blocked: Duration::from_millis(now_ms.saturating_sub(stall.last_beat_ms)),
                        seen: stall.seen,
                        exited: true,
                    });
                }
                return false;
            };
            let snapshot = probe.snapshot();
            if let Some(stall) = watched.stall.as_mut() {
                if snapshot.last_beat_ms != stall.last_beat_ms {
                    // It beat, or moved on to a wait without a deadline.
                    let resumed_ms = if snapshot.idle() { now_ms } else { snapshot.last_beat_ms };
                    let stall = watched.stall.take().expect("a resumed task was blocked");
                    reports.push(StallReport::Unblocked {
                        task: watched.task,
                        blocked: Duration::from_millis(resumed_ms.saturating_sub(stall.last_beat_ms)),
                        seen: stall.seen,
                        exited: false,
                    });
                } else {
                    let place = Place::of(&snapshot);
                    stall.see(&place);
                    if now_ms.saturating_sub(stall.reported_ms) >= repeat_ms {
                        stall.reported_ms = now_ms;
                        reports.push(StallReport::Blocked {
                            task: watched.task,
                            impact: watched.impact,
                            blocked: Duration::from_millis(now_ms.saturating_sub(stall.last_beat_ms)),
                            place,
                            at_ms: now_ms,
                            repeat: true,
                        });
                    }
                }
            } else if !snapshot.idle() && now_ms.saturating_sub(snapshot.last_beat_ms) >= watched.stall_after_ms {
                let place = Place::of(&snapshot);
                let mut stall = Stall { last_beat_ms: snapshot.last_beat_ms, reported_ms: now_ms, seen: Vec::new() };
                stall.see(&place);
                watched.stall = Some(stall);
                reports.push(StallReport::Blocked {
                    task: watched.task,
                    impact: watched.impact,
                    blocked: Duration::from_millis(now_ms.saturating_sub(snapshot.last_beat_ms)),
                    place,
                    at_ms: now_ms,
                    repeat: false,
                });
            }
            true
        });
        reports
    }
}

fn watchdog() -> &'static Mutex<StallWatch> {
    static WATCH: OnceLock<Mutex<StallWatch>> = OnceLock::new();
    WATCH.get_or_init(|| {
        let spawned = std::thread::Builder::new().name("master-watchdog".into()).spawn(|| loop {
            std::thread::sleep(WATCH_EVERY);
            let reports = watchdog().lock().unwrap_or_else(|e| e.into_inner()).poll(now_ms());
            for report in reports {
                log(&report);
            }
        });
        if let Err(error) = spawned {
            warn!(%error, "master task watchdog could not start; blocked master tasks go unreported");
        }
        Mutex::new(StallWatch::new(REPEAT))
    })
}

/// A probe for `task`, watched from the watchdog thread until it is
/// dropped; run the task under
/// [`task_probed`](quil_types::thread_probe::task_probed) with it.
pub(crate) fn watch(task: Section, impact: &'static str, stall_after: Duration) -> Arc<ThreadProbe> {
    let probe = ThreadProbe::new();
    watchdog().lock().unwrap_or_else(|e| e.into_inner()).add(task, impact, stall_after, &probe);
    probe
}

fn log(report: &StallReport) {
    let secs = |mark: Option<Mark>, now: u64| mark.map_or(0, |mark| now.saturating_sub(mark.since_ms) / 1000);
    let label = |mark: Option<Mark>| mark.map_or("none", |mark| mark.section.label());
    let pid = std::process::id();
    match report {
        StallReport::Blocked { task, impact, blocked, place, at_ms, repeat } => {
            let message = if *repeat { "master task still blocked" } else { "master task blocked" };
            let action = format!(
                "this node's master process, not the network: {impact}. One warning after a slow epoch step \
                 (prover registry refresh, epoch-boundary execution) is expected; if this warning repeats, \
                 take a thread dump before restarting (gdb -p {pid} -batch -ex 'thread apply all bt', or \
                 eu-stack -p {pid}) and report it with these lines; a dump can contain file paths, so share \
                 it privately"
            );
            warn!(task = task.label(), blocked_secs = blocked.as_secs(),
                step = label(place.step), step_secs = secs(place.step, *at_ms),
                section = label(place.section), section_secs = secs(place.section, *at_ms),
                within = label(place.outer), within_secs = secs(place.outer, *at_ms),
                pid, scope = "this node's master process", action = %action,
                "{message}: {} / {} has not returned for {}s", task.label(), place.describe(), blocked.as_secs());
        }
        StallReport::Unblocked { task, blocked, seen, exited } => {
            info!(task = task.label(), blocked_secs = blocked.as_secs(), seen = %seen.join("; "), exited,
                scope = "this node's master process",
                "master task unblocked after {}s: {}", blocked.as_secs(), task.label());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::thread_probe::{install, section, step};

    fn blocked(reports: &[StallReport]) -> Vec<(Section, u64, String, bool)> {
        reports
            .iter()
            .filter_map(|report| match report {
                StallReport::Blocked { task, blocked, place, repeat, .. } =>
                    Some((*task, blocked.as_secs(), place.describe(), *repeat)),
                StallReport::Unblocked { .. } => None,
            })
            .collect()
    }

    #[test]
    fn a_blocked_task_warns_once_repeats_after_the_interval_and_logs_its_end() {
        let probe = ThreadProbe::new();
        let t0 = now_ms();
        probe.beat_at(t0);
        let mut watch = StallWatch::new(REPEAT);
        watch.add(Section::MessageLoop, MESSAGE_LOOP_IMPACT, MESSAGE_LOOP_STALL_AFTER, &probe);
        let place = "inbound GLOBAL frame / GLOBAL frame cache lock wait within GLOBAL frame execution";
        {
            let _installed = install(probe.clone());
            step(Section::LoopGlobalFrame);
            let _execute = section(Section::GlobalFrameExecution);
            let _wait = section(Section::ClockCacheWait);
            assert_eq!(watch.poll(t0 + 59_999), Vec::new());
            let reports = watch.poll(t0 + 60_000);
            assert_eq!(blocked(&reports), vec![(Section::MessageLoop, 60, place.to_string(), false)]);
            // Every five seconds the watchdog looks again; it warns again
            // only after the repeat interval.
            for later in (65_000..120_000).step_by(5_000) {
                assert_eq!(watch.poll(t0 + later), Vec::new(), "{later}");
            }
            let reports = watch.poll(t0 + 120_000);
            assert_eq!(blocked(&reports), vec![(Section::MessageLoop, 120, place.to_string(), true)]);
        }
        // The call returned and the loop came round.
        probe.beat_at(t0 + 125_000);
        let reports = watch.poll(t0 + 126_000);
        assert_eq!(reports, vec![StallReport::Unblocked {
            task: Section::MessageLoop,
            blocked: Duration::from_secs(125),
            seen: vec![place.to_string()],
            exited: false,
        }]);
        assert_eq!(watch.poll(t0 + 184_000), Vec::new());
    }

    #[test]
    fn each_task_has_its_own_threshold_and_an_ended_task_ends_its_block() {
        let (message_loop, poller) = (ThreadProbe::new(), ThreadProbe::new());
        let t0 = now_ms();
        message_loop.beat_at(t0);
        poller.beat_at(t0);
        let mut watch = StallWatch::new(REPEAT);
        watch.add(Section::MessageLoop, MESSAGE_LOOP_IMPACT, MESSAGE_LOOP_STALL_AFTER, &message_loop);
        watch.add(Section::ArchivePoller, POLLER_IMPACT, POLLER_STALL_AFTER, &poller);
        {
            let _installed = install(poller.clone());
            step(Section::PollerConnect);
        }
        assert_eq!(watch.poll(t0 + 59_999), Vec::new());
        let reports = watch.poll(t0 + 60_000);
        assert_eq!(blocked(&reports), vec![(Section::MessageLoop, 60, "awaiting its next event".to_string(), false)]);
        let reports = watch.poll(t0 + 90_000);
        assert_eq!(blocked(&reports), vec![(Section::ArchivePoller, 90, "archive connect".to_string(), false)]);
        let reports = watch.poll(t0 + 120_000);
        assert_eq!(blocked(&reports), vec![(Section::MessageLoop, 120, "awaiting its next event".to_string(), true)]);
        drop(poller);
        let reports = watch.poll(t0 + 125_000);
        assert_eq!(reports, vec![StallReport::Unblocked {
            task: Section::ArchivePoller,
            blocked: Duration::from_secs(125),
            seen: vec!["archive connect".to_string()],
            exited: true,
        }]);
        assert_eq!(watch.watched.len(), 1);
    }

    #[test]
    fn a_task_waiting_without_a_deadline_is_not_blocked() {
        let probe = ThreadProbe::new();
        let t0 = now_ms();
        probe.idle();
        let mut watch = StallWatch::new(REPEAT);
        watch.add(Section::ArchivePoller, POLLER_IMPACT, POLLER_STALL_AFTER, &probe);
        assert_eq!(watch.poll(t0 + 3_600_000), Vec::new());
        // Its next beat starts the clock again.
        probe.beat_at(t0 + 3_600_000);
        assert_eq!(watch.poll(t0 + 3_689_999), Vec::new());
        assert_eq!(blocked(&watch.poll(t0 + 3_690_000)).len(), 1);
    }
}
