//! The start, bounded repeats and end of a node duty that keeps failing.
//!
//! A duty that fails on every attempt (a sync, an evaluation, a read) should
//! show in the log as one outage: a warning when it begins, a repeat at most
//! every [`OUTAGE_LOG_EVERY`] with its duration and failure count, and a line
//! when it ends. One line per attempt floods the log; none at all hides a
//! degraded node from its operator. A duty retried every few seconds can
//! begin its outage only after several consecutive failures, so a single
//! failed attempt between successes stays quiet.
//!
//! Each warning names its scope and the operator's action in two fields:
//! `scope` is `local` (this node), `peer` (a remote peer) or `network` (the
//! network as a whole), and `action` is `check` (something the operator can
//! inspect or fix), `wait` (an expected condition; the line names what ends
//! it) or `report` (a defect to report with the line's identifiers).

use std::time::{Duration, Instant};

/// How often a continuing outage is logged again.
pub const OUTAGE_LOG_EVERY: Duration = Duration::from_secs(600);

/// A transition of an [`Outage`] worth logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutageEvent {
    /// The failure that made the streak an outage.
    Began,
    /// Still failing, `secs` after it began, with `failures` failed attempts.
    Continues { secs: u64, failures: u64 },
    /// Succeeded again after `secs` and `failures` failed attempts.
    Ended { secs: u64, failures: u64 },
}

#[derive(Debug)]
struct Failing {
    since: Instant,
    logged: Instant,
    failures: u64,
    began: bool,
}

/// Tracks whether a repeated duty is failing; see the module docs.
#[derive(Debug)]
pub struct Outage {
    begin_after: u64,
    log_every: Duration,
    failing: Option<Failing>,
}

impl Default for Outage {
    /// An outage that begins at the first failure.
    fn default() -> Self {
        Self::begin_after(1)
    }
}

impl Outage {
    /// An outage that begins after `failures` consecutive failed attempts.
    pub fn begin_after(failures: u64) -> Self {
        Self::begin_after_repeating(failures, OUTAGE_LOG_EVERY)
    }

    /// An outage that begins after `failures` consecutive failed attempts and
    /// repeats every `every` instead of [`OUTAGE_LOG_EVERY`].
    pub fn begin_after_repeating(failures: u64, every: Duration) -> Self {
        Self {
            begin_after: failures.max(1),
            log_every: every,
            failing: None,
        }
    }

    /// Record one attempt's outcome at `now`; returns the transition to log.
    pub fn observe(&mut self, now: Instant, ok: bool) -> Option<OutageEvent> {
        if ok {
            let f = self.failing.take()?;
            return f.began.then(|| OutageEvent::Ended {
                secs: now.duration_since(f.since).as_secs(),
                failures: f.failures,
            });
        }
        let f = self.failing.get_or_insert(Failing {
            since: now,
            logged: now,
            failures: 0,
            began: false,
        });
        f.failures += 1;
        match f.began {
            false if f.failures >= self.begin_after => {
                f.began = true;
                f.logged = now;
                Some(OutageEvent::Began)
            }
            false => None,
            true => {
                if now.duration_since(f.logged) < self.log_every {
                    return None;
                }
                f.logged = now;
                Some(OutageEvent::Continues {
                    secs: now.duration_since(f.since).as_secs(),
                    failures: f.failures,
                })
            }
        }
    }
}

/// Captures a test's log lines, to check what an operator would see.
#[cfg(test)]
pub(crate) mod test_logs {
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub(crate) struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLogs {
        /// Install a subscriber that writes this thread's info and above here.
        pub(crate) fn install(&self) -> tracing::subscriber::DefaultGuard {
            let logs = self.clone();
            tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::INFO)
                    .with_ansi(false)
                    .with_writer(move || logs.clone())
                    .finish(),
            )
        }

        /// The captured lines that contain `text`.
        pub(crate) fn lines_with(&self, text: &str) -> Vec<String> {
            String::from_utf8_lossy(&self.0.lock().unwrap())
                .lines()
                .filter(|line| line.contains(text))
                .map(str::to_owned)
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An outage logs its start, then at most once per interval with its
    /// duration and failure count, then its end.
    #[test]
    fn an_outage_logs_its_transitions_with_bounded_repeats() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut outage = Outage::default();
        assert_eq!(outage.observe(at(0), true), None);
        assert_eq!(outage.observe(at(10), false), Some(OutageEvent::Began));
        assert_eq!(outage.observe(at(20), false), None);
        assert_eq!(outage.observe(at(609), false), None);
        assert_eq!(
            outage.observe(at(610), false),
            Some(OutageEvent::Continues {
                secs: 600,
                failures: 4
            })
        );
        assert_eq!(outage.observe(at(900), false), None);
        assert_eq!(
            outage.observe(at(905), true),
            Some(OutageEvent::Ended {
                secs: 895,
                failures: 5
            })
        );
        assert_eq!(outage.observe(at(915), true), None);
        assert_eq!(outage.observe(at(920), false), Some(OutageEvent::Began));
    }

    /// With a threshold, a shorter failure streak logs nothing, not even an
    /// end; the outage begins at the threshold and its duration counts from
    /// the streak's first failure.
    #[test]
    fn an_outage_with_a_threshold_ignores_shorter_streaks() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut outage = Outage::begin_after(3);
        assert_eq!(outage.observe(at(0), false), None);
        assert_eq!(outage.observe(at(10), false), None);
        assert_eq!(outage.observe(at(20), true), None);
        assert_eq!(outage.observe(at(30), false), None);
        assert_eq!(outage.observe(at(40), false), None);
        assert_eq!(outage.observe(at(50), false), Some(OutageEvent::Began));
        assert_eq!(outage.observe(at(649), false), None);
        assert_eq!(
            outage.observe(at(650), false),
            Some(OutageEvent::Continues {
                secs: 620,
                failures: 5
            })
        );
        assert_eq!(
            outage.observe(at(660), true),
            Some(OutageEvent::Ended {
                secs: 630,
                failures: 5
            })
        );
    }
}
