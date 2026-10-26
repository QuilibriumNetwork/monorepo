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
pub(crate) enum Report {
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
}

/// Which retried duty a condition belongs to, its shard filter and two
/// generations (zero where the duty has none).
pub(crate) type Key = (&'static str, Vec<u8>, u64, u64);

static CONDITIONS: Mutex<WarnLimiter<Key>> = Mutex::new(WarnLimiter::new());

/// [`WarnLimiter::failed_at`] on the process-wide conditions, at the current time.
pub(crate) fn failed(key: &Key, position: u64) -> Option<Report> {
    CONDITIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .failed_at(key, position, Instant::now())
}

/// [`WarnLimiter::succeeded_at`] on the process-wide conditions, at the current time.
pub(crate) fn succeeded(key: &Key, position: u64) -> Option<Report> {
    CONDITIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .succeeded_at(key, position, Instant::now())
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
