//! Superseded copies of partial seal drains (#699).
//!
//! Every member of a closing committee submits its seal, each copy carrying
//! the next drain headers from the member's own committed view of GLOBAL.
//! GLOBAL executes one copy of a part; the copies built from a view before
//! it carry only headers GLOBAL has executed since, and are refused as "a
//! partial drain's headers are already executed". That is a stale copy
//! losing a race the next copy continues, not a defect: one line per
//! [`SUMMARY_INTERVAL`] counts them per shard instead of one line per seal
//! every five minutes, which read as hundreds of refusals an hour on an
//! archive while sealed sessions drained.

use quil_types::error::QuilError;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// The refusal of a partial drain whose every header GLOBAL has executed
/// (`seal drain: ` precedes it in the error).
pub const PARTIAL_DRAIN_EXECUTED: &str = "a partial drain's headers are already executed";

/// How often superseded copies are summarized while they occur.
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);

/// Shards a summary names, those with the most superseded copies first.
const LISTED_SHARDS: usize = 8;

/// Whether `error` refused a stale copy of a partial drain.
pub fn is_superseded_copy(error: &QuilError) -> bool {
    matches!(error, QuilError::InvalidArgument(message) if message.ends_with(PARTIAL_DRAIN_EXECUTED))
}

#[derive(Debug, Default)]
struct ShardCopies {
    copies: u64,
    /// The drain parts the copies were stale for: (session, executed tip).
    parts: BTreeSet<([u8; 32], u64)>,
    /// GLOBAL's executed tip and the copy's last header, at the latest copy.
    executed: u64,
    through: u64,
}

/// Superseded copies counted per shard over one interval.
#[derive(Debug, Default)]
pub struct Summary {
    since: Option<Instant>,
    shards: BTreeMap<Vec<u8>, ShardCopies>,
}

/// One interval's superseded copies, as logged.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub interval_secs: u64,
    pub copies: u64,
    /// Drain parts the copies were stale for, across shards.
    pub parts: usize,
    pub shards: usize,
    /// `<filter> <copies> copies of <parts> parts (executed <tip>, copy
    /// through <frame>)` for the shards with the most copies.
    pub by_shard: String,
    pub unlisted_shards: usize,
}

impl Summary {
    /// Count a superseded copy of `session`'s seal for shard `filter`:
    /// GLOBAL had executed through `executed`, the copy's headers ran
    /// through `through`.
    pub fn record(
        &mut self,
        now: Instant,
        filter: &[u8],
        session: [u8; 32],
        executed: u64,
        through: u64,
    ) {
        self.since.get_or_insert(now);
        let shard = self.shards.entry(filter.to_vec()).or_default();
        shard.copies += 1;
        shard.parts.insert((session, executed));
        shard.executed = executed;
        shard.through = through;
    }

    /// The interval's report once it has lasted [`SUMMARY_INTERVAL`], and a
    /// fresh interval; `None` before, or when it counted nothing.
    pub fn take_due(&mut self, now: Instant) -> Option<Report> {
        let since = self.since?;
        let interval = now.saturating_duration_since(since);
        if interval < SUMMARY_INTERVAL {
            return None;
        }
        let shards = std::mem::take(&mut self.shards);
        self.since = None;
        let mut ranked: Vec<_> = shards.iter().collect();
        ranked.sort_by(|a, b| b.1.copies.cmp(&a.1.copies).then_with(|| a.0.cmp(b.0)));
        let by_shard = ranked
            .iter()
            .take(LISTED_SHARDS)
            .map(|(filter, shard)| {
                format!(
                    "{} {} copies of {} parts (executed {}, copy through {})",
                    hex::encode(filter),
                    shard.copies,
                    shard.parts.len(),
                    shard.executed,
                    shard.through
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(Report {
            interval_secs: interval.as_secs(),
            copies: shards.values().map(|shard| shard.copies).sum(),
            parts: shards.values().map(|shard| shard.parts.len()).sum(),
            shards: shards.len(),
            by_shard,
            unlisted_shards: shards.len().saturating_sub(LISTED_SHARDS),
        })
    }
}

static SUMMARY: std::sync::LazyLock<std::sync::Mutex<Summary>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Summary::default()));

/// Count a superseded copy (see [`is_superseded_copy`]) GLOBAL refused at
/// `frame`, and write the summary when due.
pub fn note(frame: u64, filter: &[u8], session: [u8; 32], executed: u64, through: u64) {
    let now = Instant::now();
    let report = {
        let Ok(mut summary) = SUMMARY.lock() else {
            return;
        };
        summary.record(now, filter, session, executed, through);
        summary.take_due(now)
    };
    log(frame, report);
}

/// Write the summary if its interval has passed, so the last copies of a
/// drain are reported without waiting for the next one. Called for every
/// seal submission validated and once per GLOBAL frame executed.
pub fn flush_due(frame: u64) {
    let report = match SUMMARY.lock() {
        Ok(mut summary) => summary.take_due(Instant::now()),
        Err(_) => return,
    };
    log(frame, report);
}

fn log(frame: u64, report: Option<Report>) {
    let Some(report) = report else {
        return;
    };
    tracing::info!(
        frame,
        interval_secs = report.interval_secs,
        copies = report.copies,
        parts = report.parts,
        shards = report.shards,
        by_shard = %report.by_shard,
        unlisted_shards = report.unlisted_shards,
        scope = "none",
        action = "none: expected while closing committees drain sealed sessions in parts; each member \
            resubmits from its own view of GLOBAL, and a copy built before GLOBAL executed another \
            member's copy of the same part carries only executed headers; the next copy carries the \
            following headers; it ends when the drains reach their checkpoints",
        "committee handoff: stale seal drain copies superseded by executed ones",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_fully_executed_partial_drain_is_a_superseded_copy() {
        let refused = |message: &str| QuilError::InvalidArgument(format!("seal drain: {message}"));
        assert!(is_superseded_copy(&refused(PARTIAL_DRAIN_EXECUTED)));
        for other in [
            "headers leave a gap after the executed tip",
            "a partial drain carries exactly the most headers a submission may",
            "headers do not end at the sealed checkpoint",
        ] {
            assert!(!is_superseded_copy(&refused(other)), "{other}");
        }
        assert!(!is_superseded_copy(&QuilError::ExecutionUnavailable(
            PARTIAL_DRAIN_EXECUTED.into()
        )));
    }

    /// One report per interval, with copies counted per shard against the
    /// drain parts they were stale for, the busiest shards named; nothing
    /// before the interval ends or when nothing was counted.
    #[test]
    fn superseded_copies_are_reported_once_per_interval_per_shard() {
        let t0 = Instant::now();
        let mut summary = Summary::default();
        assert_eq!(
            summary.take_due(t0 + SUMMARY_INTERVAL * 2),
            None,
            "nothing counted"
        );
        let (a, b) = (vec![0xa1; 32], vec![0xb2; 32]);
        // Shard a: three copies stale for its part at 26941, two for 26949.
        for (secs, executed) in [
            (0, 26_941),
            (1, 26_941),
            (2, 26_941),
            (30, 26_949),
            (31, 26_949),
        ] {
            summary.record(
                t0 + Duration::from_secs(secs),
                &a,
                [1; 32],
                executed,
                executed,
            );
        }
        summary.record(t0 + Duration::from_secs(40), &b, [2; 32], 700, 696);
        assert_eq!(
            summary.take_due(t0 + SUMMARY_INTERVAL - Duration::from_secs(1)),
            None
        );
        let report = summary.take_due(t0 + SUMMARY_INTERVAL).unwrap();
        assert_eq!(
            report,
            Report {
                interval_secs: SUMMARY_INTERVAL.as_secs(),
                copies: 6,
                parts: 3,
                shards: 2,
                by_shard: format!(
                    "{} 5 copies of 2 parts (executed 26949, copy through 26949); \
                     {} 1 copies of 1 parts (executed 700, copy through 696)",
                    hex::encode(&a),
                    hex::encode(&b)
                ),
                unlisted_shards: 0,
            }
        );
        assert_eq!(
            summary.take_due(t0 + SUMMARY_INTERVAL * 3),
            None,
            "a fresh interval"
        );
        // The next interval starts at its first copy.
        let t1 = t0 + SUMMARY_INTERVAL * 4;
        for shard in 0..(LISTED_SHARDS as u8 + 3) {
            summary.record(t1, &[shard; 32], [shard; 32], 8, 8);
        }
        assert_eq!(summary.take_due(t1 + SUMMARY_INTERVAL / 2), None);
        let report = summary.take_due(t1 + SUMMARY_INTERVAL).unwrap();
        assert_eq!(
            (report.copies, report.shards, report.unlisted_shards),
            (11, 11, 3)
        );
        assert_eq!(report.by_shard.matches("copies of").count(), LISTED_SHARDS);
    }
}
