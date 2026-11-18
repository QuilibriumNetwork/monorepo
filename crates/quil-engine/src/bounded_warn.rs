//! Bounded warnings for a duty that is retried until it succeeds: one line
//! when a condition starts, a repeat at most every [`WARN_REPEAT`] while it
//! continues, and one line when it ends. Without it a per-retry warning
//! fires at the retry rate for as long as the condition lasts.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How often a continuing condition warns again.
pub(crate) const WARN_REPEAT: Duration = Duration::from_secs(10 * 60);

/// Conditions tracked at once; the least recently failing one is dropped
/// beyond it, so the map cannot grow without bound.
const MAX_STREAMS: usize = 256;

/// What a change of a [`WarnLimiter`] logs.
#[derive(Debug, PartialEq, Eq)]
pub enum Report {
    /// The condition started, or continues: `attempts` failures since the
    /// previous line (the first line counts one), `duration` since onset.
    Failing { attempts: u64, duration: Duration },
    /// The next success after a warned condition: all its failures and
    /// its total duration.
    Recovered { attempts: u64, duration: Duration },
}

#[derive(Debug)]
struct Stream {
    since: Instant,
    last_failure: Instant,
    warned: Instant,
    unreported: u64,
    attempts: u64,
    /// The highest position (a frame number) that failed.
    position: u64,
}

/// Ongoing failure conditions by key.
#[derive(Debug)]
pub(crate) struct WarnLimiter<K> {
    streams: BTreeMap<K, Stream>,
}

impl<K: Ord + Clone> WarnLimiter<K> {
    pub(crate) const fn new() -> Self {
        Self {
            streams: BTreeMap::new(),
        }
    }

    /// An attempt for `key` failed at `now`.
    #[cfg(test)]
    pub(crate) fn failed(&mut self, key: &K, now: Instant) -> Option<Report> {
        self.failed_at(key, 0, now)
    }

    /// An attempt for `key` failed at `position`, such as a frame number,
    /// at `now`.
    pub(crate) fn failed_at(&mut self, key: &K, position: u64, now: Instant) -> Option<Report> {
        if let Some(stream) = self.streams.get_mut(key) {
            stream.position = stream.position.max(position);
            stream.attempts += 1;
            stream.unreported += 1;
            stream.last_failure = now;
            if now.saturating_duration_since(stream.warned) < WARN_REPEAT {
                return None;
            }
            stream.warned = now;
            return Some(Report::Failing {
                attempts: std::mem::take(&mut stream.unreported),
                duration: now.saturating_duration_since(stream.since),
            });
        }
        if self.streams.len() >= MAX_STREAMS {
            let oldest = self
                .streams
                .iter()
                .min_by_key(|(_, s)| s.last_failure)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                self.streams.remove(&oldest);
            }
        }
        self.streams.insert(
            key.clone(),
            Stream {
                since: now,
                last_failure: now,
                warned: now,
                unreported: 0,
                attempts: 1,
                position,
            },
        );
        Some(Report::Failing {
            attempts: 1,
            duration: Duration::ZERO,
        })
    }

    /// An attempt for `key` succeeded at `now`: the end of its condition.
    #[cfg(test)]
    pub(crate) fn succeeded(&mut self, key: &K, now: Instant) -> Option<Report> {
        self.succeeded_at(key, 0, now)
    }

    /// An attempt for `key` succeeded at `position` at `now`: the end of its
    /// condition, unless a later position failed. A batch that interleaves
    /// failing and passing frames is one ongoing condition until it passes
    /// the highest failing one.
    pub(crate) fn succeeded_at(&mut self, key: &K, position: u64, now: Instant) -> Option<Report> {
        if self.streams.get(key)?.position > position {
            return None;
        }
        let stream = self.streams.remove(key)?;
        Some(Report::Recovered {
            attempts: stream.attempts,
            duration: now.saturating_duration_since(stream.since),
        })
    }

    /// The failures of `key`'s ongoing condition.
    fn attempts(&self, key: &K) -> Option<u64> {
        self.streams.get(key).map(|stream| stream.attempts)
    }
}

/// Which retried duty a condition belongs to, its shard filter and two
/// generations (zero where the duty has none).
pub type Key = (&'static str, Vec<u8>, u64, u64);

static CONDITIONS: Mutex<WarnLimiter<Key>> = Mutex::new(WarnLimiter::new());

/// [`WarnLimiter::failed_at`] on the process-wide conditions, at the current time.
pub fn failed(key: &Key, position: u64) -> Option<Report> {
    CONDITIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .failed_at(key, position, Instant::now())
}

/// [`WarnLimiter::succeeded_at`] on the process-wide conditions, at the current time.
pub fn succeeded(key: &Key, position: u64) -> Option<Report> {
    CONDITIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .succeeded_at(key, position, Instant::now())
}

/// [`note_retry_at`] at the current time.
pub fn note_retry<E: std::fmt::Display + ?Sized>(
    duty: &'static str,
    frame: u64,
    error: Option<&E>,
) {
    note_retry_at(duty, frame, error, Instant::now());
}

/// Log the outcome of one attempt of `duty` (a store write retried by the
/// next frame or retry) for `frame` at `now`. A store that refuses writes
/// fails every attempt: an operator sees one line at the first failure, one
/// per [`WARN_REPEAT`] with the failures since, and one at the next attempt
/// that succeeds at or above the highest failed frame. Without a success
/// the condition ends with the process (a latched store exits or stays
/// refused until it is reopened).
pub fn note_retry_at<E: std::fmt::Display + ?Sized>(
    duty: &'static str,
    frame: u64,
    error: Option<&E>,
    now: Instant,
) {
    let key: Key = (duty, Vec::new(), 0, 0);
    let report = {
        let mut conditions = CONDITIONS.lock().unwrap_or_else(|e| e.into_inner());
        match error {
            Some(_) => conditions.failed_at(&key, frame, now),
            None => conditions.succeeded_at(&key, frame, now),
        }
    };
    match (report, error) {
        (Some(Report::Failing { attempts, duration }), Some(error)) if duration.is_zero() => {
            tracing::warn!(
                frame,
                attempts,
                %error,
                scope = "this node",
                until = "an attempt succeeds; a store that refuses writes needs the node restarted \
                         (see its \"store write failed\" line)",
                repeat_every_s = WARN_REPEAT.as_secs(),
                "{duty} failed; retrying"
            );
        }
        (Some(Report::Failing { attempts, duration }), Some(error)) => {
            tracing::warn!(
                frame,
                attempts,
                duration_s = duration.as_secs(),
                %error,
                scope = "this node",
                "{duty} still failing; retrying"
            );
        }
        (Some(Report::Recovered { attempts, duration }), _) => {
            tracing::info!(
                frame,
                attempts,
                duration_s = duration.as_secs(),
                "{duty} succeeded after failures"
            );
        }
        _ => {}
    }
}

/// The failures of `duty` since its condition started, or None when none
/// is ongoing: what tests of a duty's callers in other crates check.
#[doc(hidden)]
pub fn failing_attempts(duty: &'static str) -> Option<u64> {
    CONDITIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .attempts(&(duty, Vec::new(), 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn onset_warns_once_and_repeats_are_suppressed() {
        let t0 = Instant::now();
        let mut limiter = WarnLimiter::new();
        assert_eq!(
            limiter.failed(&"a", t0),
            Some(Report::Failing {
                attempts: 1,
                duration: Duration::ZERO
            })
        );
        for i in 1..60 {
            assert_eq!(limiter.failed(&"a", t0 + 10 * S * i), None, "retry {i}");
        }
    }

    #[test]
    fn repeat_after_the_interval_counts_failures_since_the_last_line() {
        let t0 = Instant::now();
        let mut limiter = WarnLimiter::new();
        limiter.failed(&"a", t0);
        for i in 1..=59 {
            limiter.failed(&"a", t0 + 10 * S * i);
        }
        assert_eq!(
            limiter.failed(&"a", t0 + WARN_REPEAT),
            Some(Report::Failing {
                attempts: 60,
                duration: WARN_REPEAT
            }),
        );
        assert_eq!(limiter.failed(&"a", t0 + WARN_REPEAT + 10 * S), None);
        assert_eq!(
            limiter.failed(&"a", t0 + 2 * WARN_REPEAT),
            Some(Report::Failing {
                attempts: 2,
                duration: 2 * WARN_REPEAT
            }),
        );
    }

    #[test]
    fn success_ends_a_condition_once_and_a_new_failure_is_a_new_onset() {
        let t0 = Instant::now();
        let mut limiter = WarnLimiter::new();
        assert_eq!(limiter.succeeded(&"a", t0), None);
        limiter.failed(&"a", t0);
        limiter.failed(&"a", t0 + 30 * S);
        assert_eq!(
            limiter.succeeded(&"a", t0 + 90 * S),
            Some(Report::Recovered {
                attempts: 2,
                duration: 90 * S
            }),
        );
        assert_eq!(limiter.succeeded(&"a", t0 + 100 * S), None);
        assert_eq!(
            limiter.failed(&"a", t0 + 110 * S),
            Some(Report::Failing {
                attempts: 1,
                duration: Duration::ZERO
            }),
        );
    }

    #[test]
    fn distinct_keys_are_independent() {
        let t0 = Instant::now();
        let mut limiter = WarnLimiter::new();
        limiter.failed(&"a", t0);
        assert_eq!(
            limiter.failed(&"b", t0 + S),
            Some(Report::Failing {
                attempts: 1,
                duration: Duration::ZERO
            })
        );
        assert_eq!(limiter.failed(&"a", t0 + 2 * S), None);
        assert_eq!(
            limiter.succeeded(&"b", t0 + 3 * S),
            Some(Report::Recovered {
                attempts: 1,
                duration: 2 * S
            })
        );
        assert_eq!(
            limiter.failed(&"a", t0 + WARN_REPEAT),
            Some(Report::Failing {
                attempts: 2,
                duration: WARN_REPEAT
            })
        );
    }

    #[test]
    fn a_pass_below_the_highest_failure_does_not_end_the_condition() {
        let t0 = Instant::now();
        let mut limiter = WarnLimiter::new();
        assert_eq!(
            limiter.failed_at(&"a", 10, t0),
            Some(Report::Failing {
                attempts: 1,
                duration: Duration::ZERO
            })
        );
        assert_eq!(limiter.succeeded_at(&"a", 9, t0 + S), None);
        assert_eq!(limiter.failed_at(&"a", 11, t0 + 2 * S), None);
        assert_eq!(limiter.succeeded_at(&"a", 10, t0 + 3 * S), None);
        assert_eq!(
            limiter.succeeded_at(&"a", 12, t0 + 4 * S),
            Some(Report::Recovered {
                attempts: 2,
                duration: 4 * S
            }),
        );
        assert_eq!(limiter.succeeded_at(&"a", 13, t0 + 5 * S), None);
    }

    #[test]
    fn tracked_conditions_are_bounded() {
        let t0 = Instant::now();
        let mut limiter = WarnLimiter::new();
        for i in 0..(MAX_STREAMS as u64 * 2) {
            limiter.failed(&i, t0 + S * u32::try_from(i).unwrap());
        }
        assert_eq!(limiter.streams.len(), MAX_STREAMS);
        assert!(!limiter.streams.contains_key(&0));
        assert!(limiter.streams.contains_key(&(MAX_STREAMS as u64 * 2 - 1)));
    }
}
