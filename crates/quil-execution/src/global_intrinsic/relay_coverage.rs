//! Spend relay coverage of the shard headers GLOBAL executes.
//!
//! Header `N` relays the spends of source frames `N-8 ..= N-1`
//! ([`spend_relay::relay_window`]), and GLOBAL commits spends only from the
//! headers it executes. When the header GLOBAL executes for a shard lies more
//! than [`RELAY_WINDOW_FRAMES`] frames above the one it executed before, no
//! executed header relays the source frames between: their spends do not
//! commit unless the shard's members execute them again, and a shield is never
//! routed to another shard. Nothing else reports it, so each such gap gets one
//! warning. Logging only: no state is written.
//!
//! A gap seen again (the same headers executed on a tentative branch and then
//! for real, or replayed) is not logged again. Further gaps of a shard within
//! [`SHARD_QUIET`] of its last warning are counted into its next warning, and
//! one summary per [`SUMMARY_INTERVAL`] counts every gap of the interval.

use crate::token_intrinsic::spend_relay::{self, RELAY_WINDOW_FRAMES};
use std::collections::{BTreeMap, HashMap};
use std::ops::RangeInclusive;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// How long after a shard's warning its further gaps are only counted.
pub const SHARD_QUIET: Duration = Duration::from_secs(60);

/// How often the gaps of an interval are summarized while they occur.
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);

/// Shards a summary names, those with the most uncovered frames first.
const LISTED_SHARDS: usize = 8;

/// Shards remembered for repeat detection and quieting; past this, those
/// with nothing pending are forgotten first.
const MAX_SHARDS: usize = 4096;

/// The source frames no executed header relays between the shard's previously
/// executed header `previous` and header `frame`: a header relays only the
/// frames below it, so `previous` itself is left to later headers. `None`
/// when the window leaves no gap; frame 0 is never relayed or reported.
pub fn uncovered(previous: u64, frame: u64) -> Option<RangeInclusive<u64>> {
    let first = previous.max(1);
    let window_start = *spend_relay::relay_window(frame).start();
    (window_start > first).then(|| first..=window_start - 1)
}

/// What a newly seen gap logs.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Warn, with the shard's gaps counted since its last warning.
    Warn {
        suppressed_gaps: u64,
        suppressed_frames: u64,
    },
    /// Counted into the shard's next warning and the summary.
    Quiet,
    /// The same gap as the shard's last: nothing.
    Repeat,
}

#[derive(Debug)]
struct ShardGaps {
    last: (u64, u64),
    warned_at: Instant,
    suppressed_gaps: u64,
    suppressed_frames: u64,
}

#[derive(Debug, Default)]
struct IntervalShard {
    gaps: u64,
    frames: u64,
    widest: u64,
    last: (u64, u64),
}

/// Gaps per shard: repeat detection, quieting and the interval summary.
#[derive(Debug, Default)]
pub struct Tracker {
    shards: HashMap<Vec<u8>, ShardGaps>,
    since: Option<Instant>,
    interval: BTreeMap<Vec<u8>, IntervalShard>,
    suppressed: u64,
}

/// One interval's gaps, as logged.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub interval_secs: u64,
    pub gaps: u64,
    pub shards: usize,
    pub uncovered_frames: u64,
    pub widest_gap: u64,
    /// Gaps counted without a warning line of their own.
    pub suppressed_gaps: u64,
    /// `<filter> <gaps> gaps, <frames> frames (last <first>..=<last>)` for the
    /// shards with the most uncovered frames.
    pub by_shard: String,
    pub unlisted_shards: usize,
}

impl Tracker {
    /// Count the gap `uncovered` of shard `filter`, left between its
    /// previously executed header `previous` and header `frame`.
    pub fn record(
        &mut self,
        now: Instant,
        filter: &[u8],
        previous: u64,
        frame: u64,
        uncovered: &RangeInclusive<u64>,
    ) -> Verdict {
        let key = (previous, frame);
        let count = uncovered.end() - uncovered.start() + 1;
        if self
            .shards
            .get(filter)
            .is_some_and(|shard| shard.last == key)
        {
            return Verdict::Repeat;
        }
        if self.shards.len() >= MAX_SHARDS && !self.shards.contains_key(filter) {
            self.shards.retain(|_, shard| {
                shard.suppressed_gaps > 0 && now.duration_since(shard.warned_at) < SHARD_QUIET
            });
            if self.shards.len() >= MAX_SHARDS {
                self.shards.clear();
            }
        }
        self.since.get_or_insert(now);
        let interval = self.interval.entry(filter.to_vec()).or_default();
        interval.gaps += 1;
        interval.frames += count;
        interval.widest = interval.widest.max(count);
        interval.last = (*uncovered.start(), *uncovered.end());
        let verdict = match self.shards.get_mut(filter) {
            Some(shard) if now.duration_since(shard.warned_at) < SHARD_QUIET => {
                shard.last = key;
                shard.suppressed_gaps += 1;
                shard.suppressed_frames += count;
                Verdict::Quiet
            }
            Some(shard) => {
                let verdict = Verdict::Warn {
                    suppressed_gaps: shard.suppressed_gaps,
                    suppressed_frames: shard.suppressed_frames,
                };
                *shard = ShardGaps {
                    last: key,
                    warned_at: now,
                    suppressed_gaps: 0,
                    suppressed_frames: 0,
                };
                verdict
            }
            None => {
                self.shards.insert(
                    filter.to_vec(),
                    ShardGaps {
                        last: key,
                        warned_at: now,
                        suppressed_gaps: 0,
                        suppressed_frames: 0,
                    },
                );
                Verdict::Warn {
                    suppressed_gaps: 0,
                    suppressed_frames: 0,
                }
            }
        };
        if verdict == Verdict::Quiet {
            self.suppressed += 1;
        }
        verdict
    }

    /// The interval's report once it has lasted [`SUMMARY_INTERVAL`], and a
    /// fresh interval; `None` before, or when it counted nothing.
    pub fn take_due(&mut self, now: Instant) -> Option<Report> {
        let since = self.since?;
        let elapsed = now.saturating_duration_since(since);
        if elapsed < SUMMARY_INTERVAL {
            return None;
        }
        let shards = std::mem::take(&mut self.interval);
        let suppressed_gaps = std::mem::take(&mut self.suppressed);
        self.since = None;
        let mut ranked: Vec<_> = shards.iter().collect();
        ranked.sort_by(|a, b| b.1.frames.cmp(&a.1.frames).then_with(|| a.0.cmp(b.0)));
        let by_shard = ranked
            .iter()
            .take(LISTED_SHARDS)
            .map(|(filter, shard)| {
                format!(
                    "{} {} gaps, {} frames (last {}..={})",
                    hex::encode(filter),
                    shard.gaps,
                    shard.frames,
                    shard.last.0,
                    shard.last.1
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(Report {
            interval_secs: elapsed.as_secs(),
            gaps: shards.values().map(|shard| shard.gaps).sum(),
            shards: shards.len(),
            uncovered_frames: shards.values().map(|shard| shard.frames).sum(),
            widest_gap: shards.values().map(|shard| shard.widest).max().unwrap_or(0),
            suppressed_gaps,
            by_shard,
            unlisted_shards: shards.len().saturating_sub(LISTED_SHARDS),
        })
    }
}

static TRACKER: LazyLock<Mutex<Tracker>> = LazyLock::new(|| Mutex::new(Tracker::default()));

/// GLOBAL frame `frame` executes shard `filter`'s header `shard_frame`
/// (anchored at GLOBAL frame `anchor`) after its header `previous`: warn when
/// the relay windows leave source frames between them uncovered.
pub fn check(frame: u64, filter: &[u8], anchor: u64, previous: u64, shard_frame: u64) {
    let Some(gap) = uncovered(previous, shard_frame) else {
        return;
    };
    let now = Instant::now();
    let (verdict, report) = {
        let Ok(mut tracker) = TRACKER.lock() else {
            return;
        };
        let verdict = tracker.record(now, filter, previous, shard_frame, &gap);
        (verdict, tracker.take_due(now))
    };
    if let Verdict::Warn {
        suppressed_gaps,
        suppressed_frames,
    } = verdict
    {
        tracing::warn!(
            frame,
            shard = %hex::encode(filter),
            shard_frame,
            previous_shard_frame = previous,
            anchor,
            uncovered_first = *gap.start(),
            uncovered_last = *gap.end(),
            uncovered_frames = gap.end() - gap.start() + 1,
            relay_window_frames = RELAY_WINDOW_FRAMES,
            earlier_gaps_quieted = suppressed_gaps,
            earlier_frames_quieted = suppressed_frames,
            scope = "network: GLOBAL leaders carried no header of this shard for the uncovered \
                frames; not this node",
            action = "spends of the shard's uncovered frames commit only if its members offer \
                them again, within a bound; shields there are not re-routed, so past that their \
                senders must resubmit; check the GLOBAL leaders' carry of \
                this shard (budget deferrals, body holdbacks, refused tips) around these frames, \
                and report it to the maintainers if it repeats",
            "spend relay coverage skipped: GLOBAL executed a shard header more than the relay \
             window past the shard's previous executed header",
        );
    }
    log(frame, report);
}

/// Write the summary if its interval has passed, so the last gaps are
/// reported without waiting for the next one. Called once per GLOBAL frame.
pub fn flush_due(frame: u64) {
    let report = match TRACKER.lock() {
        Ok(mut tracker) => tracker.take_due(Instant::now()),
        Err(_) => return,
    };
    log(frame, report);
}

fn log(frame: u64, report: Option<Report>) {
    let Some(report) = report else {
        return;
    };
    tracing::warn!(
        frame,
        interval_secs = report.interval_secs,
        gaps = report.gaps,
        shards = report.shards,
        uncovered_frames = report.uncovered_frames,
        widest_gap = report.widest_gap,
        quieted_gaps = report.suppressed_gaps,
        by_shard = %report.by_shard,
        unlisted_shards = report.unlisted_shards,
        scope = "network: GLOBAL leaders' carry of shard headers, not this node",
        action = "spends of the uncovered shard frames commit only if the shards' members offer \
            them again, within a bound; past that their senders must resubmit; check the GLOBAL \
            leaders' carry of these shards",
        "spend relay coverage: shard frames no executed header relayed",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header N relays N-8..=N-1, not N: a successor up to 8 frames above the
    /// previous header leaves nothing uncovered, one 9 frames above leaves the
    /// previous header's own frame, and a re-carried or lower header leaves
    /// none.
    #[test]
    fn uncovered_frames_are_those_below_the_relay_window_after_the_previous_header() {
        for next in 0..=18 {
            assert_eq!(uncovered(10, next), None, "next {next}");
        }
        assert_eq!(uncovered(10, 19), Some(10..=10));
        assert_eq!(uncovered(10, 20), Some(10..=11));
        assert_eq!(uncovered(10, 30), Some(10..=21));
        assert_eq!(uncovered(0, 9), None, "frame 0 is never relayed");
        assert_eq!(uncovered(0, 10), Some(1..=1));
        assert_eq!(uncovered(u64::MAX, u64::MAX), None);
    }

    /// Every advance a contiguous carry makes, up to the window, logs
    /// nothing; the next advance leaves the previous header's frame.
    #[test]
    fn contiguous_carries_leave_no_gap() {
        for previous in [1, 7, 8, 978_129] {
            for advance in 0..=RELAY_WINDOW_FRAMES {
                assert_eq!(
                    uncovered(previous, previous + advance),
                    None,
                    "previous {previous}, advance {advance}"
                );
            }
            assert_eq!(
                uncovered(previous, previous + RELAY_WINDOW_FRAMES + 1),
                Some(previous..=previous),
                "previous {previous}"
            );
        }
    }

    /// One warning per gap and shard; the same gap again is a repeat; a
    /// shard's further gaps within the quiet period are counted into its
    /// next warning; other shards warn independently.
    #[test]
    fn a_shard_warns_once_per_gap_and_counts_gaps_within_its_quiet_period() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        let (a, b) = (vec![0xa1; 33], vec![0xb2; 33]);
        let warn = |gaps, frames| Verdict::Warn {
            suppressed_gaps: gaps,
            suppressed_frames: frames,
        };
        assert_eq!(tracker.record(t0, &a, 10, 30, &(11..=21)), warn(0, 0));
        assert_eq!(
            tracker.record(t0 + Duration::from_secs(1), &a, 10, 30, &(11..=21)),
            Verdict::Repeat
        );
        assert_eq!(
            tracker.record(t0 + Duration::from_secs(2), &b, 5, 20, &(6..=11)),
            warn(0, 0),
            "another shard"
        );
        assert_eq!(
            tracker.record(t0 + Duration::from_secs(10), &a, 30, 45, &(31..=36)),
            Verdict::Quiet
        );
        assert_eq!(
            tracker.record(t0 + Duration::from_secs(11), &a, 30, 45, &(31..=36)),
            Verdict::Repeat
        );
        assert_eq!(
            tracker.record(t0 + Duration::from_secs(20), &a, 45, 60, &(46..=51)),
            Verdict::Quiet
        );
        assert_eq!(
            tracker.record(t0 + SHARD_QUIET, &a, 60, 80, &(61..=71)),
            warn(2, 12),
            "the quiet period ends with a warning counting its gaps"
        );
        assert_eq!(
            tracker.record(t0 + SHARD_QUIET * 3, &a, 80, 100, &(81..=91)),
            warn(0, 0)
        );
    }

    /// One summary per interval counting every gap, warned or quieted,
    /// repeats excluded; nothing before the interval ends or when nothing was
    /// counted.
    #[test]
    fn gaps_are_summarized_once_per_interval() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        assert_eq!(tracker.take_due(t0 + SUMMARY_INTERVAL * 2), None);
        let (a, b) = (vec![0xa1; 33], vec![0xb2; 33]);
        tracker.record(t0, &a, 10, 30, &(11..=21));
        tracker.record(t0, &a, 10, 30, &(11..=21));
        tracker.record(t0 + Duration::from_secs(5), &a, 30, 45, &(31..=36));
        tracker.record(t0 + Duration::from_secs(6), &b, 5, 20, &(6..=11));
        assert_eq!(
            tracker.take_due(t0 + SUMMARY_INTERVAL - Duration::from_secs(1)),
            None
        );
        assert_eq!(
            tracker.take_due(t0 + SUMMARY_INTERVAL),
            Some(Report {
                interval_secs: SUMMARY_INTERVAL.as_secs(),
                gaps: 3,
                shards: 2,
                uncovered_frames: 23,
                widest_gap: 11,
                suppressed_gaps: 1,
                by_shard: format!(
                    "{} 2 gaps, 17 frames (last 31..=36); {} 1 gaps, 6 frames (last 6..=11)",
                    hex::encode(&a),
                    hex::encode(&b)
                ),
                unlisted_shards: 0,
            })
        );
        assert_eq!(
            tracker.take_due(t0 + SUMMARY_INTERVAL * 3),
            None,
            "a fresh interval"
        );
    }

    /// The shards remembered stay bounded.
    #[test]
    fn remembered_shards_are_bounded() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        for shard in 0..(MAX_SHARDS as u32 + 10) {
            tracker.record(t0, &shard.to_be_bytes(), 10, 30, &(11..=21));
            assert!(tracker.shards.len() <= MAX_SHARDS);
        }
    }
}
