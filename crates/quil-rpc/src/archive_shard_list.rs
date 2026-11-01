//! Cross-archive check of the reported shard list.
//!
//! Each shard-info refresh asks one archive ([`crate::shard_info_refresh`])
//! and the node takes that archive's list. The shard grid is not part of the
//! GLOBAL commitment, so nothing else notices an archive that keeps an
//! outdated grid (e.g. one still listing a split parent instead of its two
//! children): the node silently alternates between the archives' views.
//! [`ArchiveShardListTracker`] remembers the latest list of every endpoint in
//! the pool and compares each refresh with the lists reported within
//! [`RECENT_REPORT_WINDOW`]. It only logs; it never changes which list the
//! node uses.
//!
//! A split or merge applied between two refreshes changes the list once, so a
//! newer list differing from an older one is not by itself a disagreement.
//! Archives disagree when, in report order, a list comes back after another
//! list was reported in between (A, B, A), by another endpoint or by the same
//! one repeating its list; the tracker starts a disagreement on that
//! alternation, and ends it once every recent list agrees again.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::shard_info_refresh::ArchiveShardInfo;

/// Reports older than this are not compared (and are forgotten). The pool
/// holds about six archives and a refresh asks one of them every 10-15
/// minutes, so each archive reports about once per 60-90 minutes: a shorter
/// window would forget a stale archive's report before its next turn, and the
/// warning and the agreement line would alternate.
pub const RECENT_REPORT_WINDOW: Duration = Duration::from_secs(6 * 60 * 60);
/// A disagreement is warned about at most this often, a new one included.
pub const DISAGREEMENT_REPEAT_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// At most this many filters per side are named in one log line; the counts
/// give the totals.
pub const MAX_LOGGED_FILTERS: usize = 16;

/// The shards one archive lists: every filter it reports, and the subset a
/// pending split or merge has frozen.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShardList {
    pub filters: BTreeSet<Vec<u8>>,
    pub frozen: BTreeSet<Vec<u8>>,
}

impl ShardList {
    pub fn from_info(info: &ArchiveShardInfo) -> Self {
        Self {
            filters: info.sizes.keys().cloned().collect(),
            frozen: info.frozen.iter().cloned().collect(),
        }
    }

    /// The list of a refresh in which every shard key answered: a refresh
    /// with per-shard failures lists only part of the grid, and comparing it
    /// would report a spurious disagreement.
    pub fn from_complete(info: &ArchiveShardInfo) -> Option<Self> {
        (info.failed_shard_keys == 0).then(|| Self::from_info(info))
    }

    /// Short digest of the sorted filter list (first 8 hex digits of SHA-256
    /// over each filter, length-prefixed): equal digests mean equal lists, so
    /// log lines can be matched by eye.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        for filter in &self.filters {
            hasher.update((filter.len() as u32).to_be_bytes());
            hasher.update(filter);
        }
        hex::encode(&hasher.finalize()[..4])
    }

    /// Filters `self` lists that `other` does not, in order.
    pub fn only_in(&self, other: &ShardList) -> Vec<Vec<u8>> {
        self.filters.difference(&other.filters).cloned().collect()
    }
}

/// Comma-separated full hex filters, at most [`MAX_LOGGED_FILTERS`] of them.
pub fn hex_filters(filters: &[Vec<u8>]) -> String {
    filters
        .iter()
        .take(MAX_LOGGED_FILTERS)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(",")
}

/// Two endpoints whose recent lists differ: the one just refreshed, and the
/// most recent other report that lists different shards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    pub endpoint: String,
    pub shards: usize,
    pub frozen: usize,
    pub digest: String,
    /// Recent endpoints whose list equals `endpoint`'s (itself included).
    pub endpoint_agreeing: usize,
    pub other_endpoint: String,
    pub other_shards: usize,
    pub other_frozen: usize,
    pub other_digest: String,
    /// Recent endpoints whose list equals `other_endpoint`'s.
    pub other_agreeing: usize,
    /// How long before this refresh the other endpoint reported.
    pub other_age: Duration,
    /// Filters only `endpoint` lists.
    pub endpoint_only: Vec<Vec<u8>>,
    /// Filters only `other_endpoint` lists.
    pub other_only: Vec<Vec<u8>>,
    /// Endpoints with a recent report, and how many distinct lists they hold.
    pub recent_endpoints: usize,
    pub distinct_lists: usize,
}

/// Why a disagreement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndCause {
    /// The differing endpoints reported the agreeing list.
    Agreement,
    /// A differing report aged out of [`RECENT_REPORT_WINDOW`] (or its
    /// endpoint left the pool) before its endpoint reported again.
    Expired,
}

impl EndCause {
    pub fn as_str(self) -> &'static str {
        match self {
            EndCause::Agreement => "agreement",
            EndCause::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardListEvent {
    /// A new disagreement.
    Started(Disagreement),
    /// Still disagreeing, `duration` after it started.
    Persisting {
        disagreement: Disagreement,
        duration: Duration,
    },
    /// Every recent list agrees again, `duration` after the disagreement
    /// started.
    Ended {
        duration: Duration,
        cause: EndCause,
        digest: String,
        recent_endpoints: usize,
        shards: usize,
    },
}

impl ShardListEvent {
    /// Log the event: a warning while archives disagree (`duration_secs` 0
    /// when it starts), info once their recent lists agree.
    pub fn log(&self, frame: u64) {
        let (d, duration) = match self {
            ShardListEvent::Started(d) => (d, Duration::ZERO),
            ShardListEvent::Persisting {
                disagreement,
                duration,
            } => (disagreement, *duration),
            ShardListEvent::Ended {
                duration,
                cause,
                digest,
                recent_endpoints,
                shards,
            } => {
                info!(
                    frame,
                    duration_secs = duration.as_secs(),
                    ended_by = cause.as_str(),
                    %digest,
                    recent_endpoints,
                    shards,
                    "archives' recent shard lists agree again"
                );
                return;
            }
        };
        warn!(
            frame,
            duration_secs = duration.as_secs(),
            endpoint = %d.endpoint,
            shards = d.shards,
            frozen = d.frozen,
            digest = %d.digest,
            endpoint_agreeing = d.endpoint_agreeing,
            other_endpoint = %d.other_endpoint,
            other_shards = d.other_shards,
            other_frozen = d.other_frozen,
            other_digest = %d.other_digest,
            other_agreeing = d.other_agreeing,
            other_reported_secs_ago = d.other_age.as_secs(),
            endpoint_only_count = d.endpoint_only.len(),
            endpoint_only_filters = %hex_filters(&d.endpoint_only),
            other_only_count = d.other_only.len(),
            other_only_filters = %hex_filters(&d.other_only),
            recent_endpoints = d.recent_endpoints,
            distinct_lists = d.distinct_lists,
            "archives disagree on the shard list: archive-side, this node cannot fix it; \
             report endpoint, other_endpoint and their *_only_filters to the archive operators; \
             `qclient node archive shards` shows each archive's list"
        );
    }
}

#[derive(Debug)]
struct Report {
    list: ShardList,
    at: Instant,
}

/// Each pool endpoint's latest shard list, and the disagreement state.
/// Memory is bounded by the pool: reports of endpoints no longer in it, and
/// reports older than [`RECENT_REPORT_WINDOW`], are dropped.
#[derive(Debug, Default)]
pub struct ArchiveShardListTracker {
    reports: HashMap<String, Report>,
    /// When the open disagreement started.
    disagreeing_since: Option<Instant>,
    /// Whether the open disagreement has been warned about.
    warned: bool,
    /// Whether a differing report expired during the open disagreement.
    expired: bool,
    /// The last warning, of this disagreement or an earlier one.
    last_warned: Option<Instant>,
}

impl ArchiveShardListTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `endpoint`'s list as of `now` and return the event to log, if
    /// any. `pool` is the pool's current endpoints.
    pub fn observe(
        &mut self,
        endpoint: &str,
        list: ShardList,
        now: Instant,
        pool: &[String],
    ) -> Option<ShardListEvent> {
        let open = self.disagreeing_since.is_some();
        let mut expired = false;
        self.reports.retain(|known, report| {
            let keep = pool.iter().any(|p| p == known)
                && now.saturating_duration_since(report.at) <= RECENT_REPORT_WINDOW;
            expired |= !keep && open && report.list.filters != list.filters;
            keep
        });
        self.expired |= expired;
        // The endpoint repeats its previous list although another endpoint
        // reported a different one since: A, B, A with one endpoint saying A.
        let repeated = self.reports.get(endpoint).is_some_and(|previous| {
            previous.list.filters == list.filters
                && self.reports.iter().any(|(other, r)| {
                    other != endpoint && r.at > previous.at && r.list.filters != list.filters
                })
        });
        self.reports
            .insert(endpoint.to_string(), Report { list, at: now });
        let current = &self.reports[endpoint].list;

        let mut recent: Vec<(&String, &Report)> = self.reports.iter().collect();
        // Report order; ties by endpoint, so the result is deterministic.
        recent.sort_by(|a, b| a.1.at.cmp(&b.1.at).then_with(|| a.0.cmp(b.0)));

        if recent
            .iter()
            .all(|(_, r)| r.list.filters == current.filters)
        {
            let since = self.disagreeing_since.take()?;
            let (warned, expired) = (self.warned, self.expired);
            self.warned = false;
            self.expired = false;
            // A disagreement that started within the repeat interval of an
            // earlier warning was never logged: neither is its end.
            return warned.then(|| ShardListEvent::Ended {
                duration: now.saturating_duration_since(since),
                cause: if expired {
                    EndCause::Expired
                } else {
                    EndCause::Agreement
                },
                digest: current.digest(),
                recent_endpoints: recent.len(),
                shards: current.filters.len(),
            });
        }

        // Most recent other report listing different shards: one exists,
        // since not every recent list equals the current one.
        let (other_endpoint, other) = recent
            .iter()
            .rev()
            .find(|(_, r)| r.list.filters != current.filters)
            .copied()?;
        let agreeing = |filters: &BTreeSet<Vec<u8>>| {
            recent
                .iter()
                .filter(|(_, r)| &r.list.filters == filters)
                .count()
        };
        let mut distinct: Vec<&BTreeSet<Vec<u8>>> = Vec::new();
        for (_, r) in &recent {
            if !distinct.contains(&&r.list.filters) {
                distinct.push(&r.list.filters);
            }
        }
        let disagreement = Disagreement {
            endpoint: endpoint.to_string(),
            shards: current.filters.len(),
            frozen: current.frozen.len(),
            digest: current.digest(),
            endpoint_agreeing: agreeing(&current.filters),
            other_endpoint: other_endpoint.clone(),
            other_shards: other.list.filters.len(),
            other_frozen: other.list.frozen.len(),
            other_digest: other.list.digest(),
            other_agreeing: agreeing(&other.list.filters),
            other_age: now.saturating_duration_since(other.at),
            endpoint_only: current.only_in(&other.list),
            other_only: other.list.only_in(current),
            recent_endpoints: recent.len(),
            distinct_lists: distinct.len(),
        };

        let since = match self.disagreeing_since {
            Some(since) => since,
            None => {
                if !repeated && !alternates(&recent) {
                    // A newer list replaced an older one, as a split or
                    // merge applied between two refreshes does.
                    return None;
                }
                self.disagreeing_since = Some(now);
                self.expired = false;
                now
            }
        };
        if self
            .last_warned
            .is_some_and(|at| now.saturating_duration_since(at) < DISAGREEMENT_REPEAT_INTERVAL)
        {
            return None;
        }
        self.last_warned = Some(now);
        if !std::mem::replace(&mut self.warned, true) {
            return Some(ShardListEvent::Started(disagreement));
        }
        Some(ShardListEvent::Persisting {
            disagreement,
            duration: now.saturating_duration_since(since),
        })
    }
}

/// Whether some list comes back after a different list was reported in
/// between, in report order (`reports` sorted by time).
fn alternates(reports: &[(&String, &Report)]) -> bool {
    let mut runs: Vec<&BTreeSet<Vec<u8>>> = Vec::new();
    for (_, r) in reports {
        if runs.last() != Some(&&r.list.filters) {
            runs.push(&r.list.filters);
        }
    }
    runs.iter()
        .enumerate()
        .any(|(i, list)| runs[..i].contains(list))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(60 * 60);

    fn list(filters: &[u8]) -> ShardList {
        ShardList {
            filters: filters.iter().map(|&f| vec![f; 3]).collect(),
            frozen: BTreeSet::new(),
        }
    }

    fn pool() -> Vec<String> {
        ["a:8340", "b:8340", "c:8340"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// The parent `1` split into `2` and `3`; a stale archive still lists `1`.
    fn split() -> ShardList {
        list(&[2, 3, 9])
    }
    fn stale() -> ShardList {
        list(&[1, 9])
    }

    #[test]
    fn a_list_coming_back_starts_a_disagreement_naming_the_differing_filters() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        assert_eq!(t.observe("a:8340", split(), t0, &pool()), None);
        assert_eq!(
            t.observe("b:8340", stale(), t0 + 10 * MIN, &pool()),
            None,
            "a newer list alone is not a disagreement"
        );
        let Some(ShardListEvent::Started(d)) = t.observe("c:8340", split(), t0 + 20 * MIN, &pool())
        else {
            panic!("the split list came back after the stale one");
        };
        assert_eq!(
            (d.endpoint.as_str(), d.shards, d.endpoint_agreeing),
            ("c:8340", 3, 2)
        );
        assert_eq!(
            (d.other_endpoint.as_str(), d.other_shards, d.other_agreeing),
            ("b:8340", 2, 1)
        );
        assert_eq!(d.endpoint_only, vec![vec![2; 3], vec![3; 3]]);
        assert_eq!(d.other_only, vec![vec![1; 3]]);
        assert_eq!(d.other_age, 10 * MIN);
        assert_eq!((d.recent_endpoints, d.distinct_lists), (3, 2));
        assert_eq!(d.digest, split().digest());
        assert_ne!(d.digest, d.other_digest);
    }

    #[test]
    fn two_endpoints_alternating_start_a_disagreement() {
        let two: Vec<String> = vec!["a:8340".into(), "b:8340".into()];
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        assert_eq!(t.observe("a:8340", stale(), t0, &two), None);
        assert_eq!(t.observe("b:8340", split(), t0 + 10 * MIN, &two), None);
        let Some(ShardListEvent::Started(d)) = t.observe("a:8340", stale(), t0 + 20 * MIN, &two)
        else {
            panic!("a repeated its list after b reported another");
        };
        assert_eq!(
            (
                d.other_endpoint.as_str(),
                d.endpoint_agreeing,
                d.other_agreeing
            ),
            ("b:8340", 1, 1)
        );
    }

    #[test]
    fn three_distinct_lists_name_the_most_recent_other_one() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        let third = list(&[4, 9]);
        t.observe("a:8340", split(), t0, &pool());
        t.observe("b:8340", stale(), t0 + 10 * MIN, &pool());
        assert_eq!(
            t.observe("c:8340", third.clone(), t0 + 20 * MIN, &pool()),
            None,
            "each list once is no alternation"
        );
        let Some(ShardListEvent::Started(d)) = t.observe("a:8340", split(), t0 + 30 * MIN, &pool())
        else {
            panic!("a repeated its list after two others");
        };
        assert_eq!(
            (d.other_endpoint.as_str(), d.other_digest.clone()),
            ("c:8340", third.digest())
        );
        assert_eq!(
            (d.distinct_lists, d.endpoint_agreeing, d.other_agreeing),
            (3, 1, 1)
        );
        assert_eq!(d.other_only, vec![vec![4; 3]]);
    }

    #[test]
    fn a_split_applied_between_refreshes_is_not_a_disagreement() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        assert_eq!(t.observe("a:8340", stale(), t0, &pool()), None);
        assert_eq!(t.observe("b:8340", stale(), t0 + 10 * MIN, &pool()), None);
        assert_eq!(t.observe("c:8340", split(), t0 + 20 * MIN, &pool()), None);
        assert_eq!(t.observe("a:8340", split(), t0 + 30 * MIN, &pool()), None);
        assert_eq!(t.observe("b:8340", split(), t0 + 40 * MIN, &pool()), None);
    }

    #[test]
    fn a_persisting_disagreement_repeats_at_most_hourly_then_ends_once() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        t.observe("a:8340", split(), t0, &pool());
        t.observe("b:8340", stale(), t0 + 10 * MIN, &pool());
        assert!(matches!(
            t.observe("c:8340", split(), t0 + 20 * MIN, &pool()),
            Some(ShardListEvent::Started(_))
        ));
        assert_eq!(
            t.observe("a:8340", split(), t0 + 30 * MIN, &pool()),
            None,
            "repeat suppressed within the hour"
        );
        assert_eq!(
            t.observe("b:8340", stale(), t0 + 50 * MIN, &pool()),
            None,
            "repeat suppressed within the hour"
        );
        let Some(ShardListEvent::Persisting {
            disagreement,
            duration,
        }) = t.observe("c:8340", split(), t0 + 80 * MIN, &pool())
        else {
            panic!("an hour after the warning it repeats");
        };
        assert_eq!(duration, 60 * MIN);
        assert_eq!(disagreement.other_endpoint, "b:8340");
        assert_eq!(
            t.observe("a:8340", split(), t0 + 90 * MIN, &pool()),
            None,
            "b's stale list is still recent"
        );
        assert_eq!(
            t.observe("b:8340", split(), t0 + 100 * MIN, &pool()),
            Some(ShardListEvent::Ended {
                duration: 80 * MIN,
                cause: EndCause::Agreement,
                digest: split().digest(),
                recent_endpoints: 3,
                shards: 3,
            })
        );
        assert_eq!(
            t.observe("c:8340", split(), t0 + 110 * MIN, &pool()),
            None,
            "the end is logged once"
        );
    }

    #[test]
    fn a_new_disagreement_within_the_hour_of_a_warning_is_not_warned_yet() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        t.observe("a:8340", split(), t0, &pool());
        t.observe("b:8340", stale(), t0 + 10 * MIN, &pool());
        assert!(matches!(
            t.observe("c:8340", split(), t0 + 20 * MIN, &pool()),
            Some(ShardListEvent::Started(_))
        ));
        assert!(matches!(
            t.observe("b:8340", split(), t0 + 30 * MIN, &pool()),
            Some(ShardListEvent::Ended { .. })
        ));
        // b flips back: a new disagreement, 20 minutes after the warning.
        assert_eq!(t.observe("b:8340", stale(), t0 + 40 * MIN, &pool()), None);
        assert_eq!(
            t.observe("a:8340", split(), t0 + 50 * MIN, &pool()),
            None,
            "started, not warned within the hour"
        );
        let Some(ShardListEvent::Started(d)) = t.observe("c:8340", split(), t0 + 80 * MIN, &pool())
        else {
            panic!("an hour after the last warning the new disagreement is warned");
        };
        assert_eq!(d.other_endpoint, "b:8340");
        // Its end and a further silent start/end log nothing new.
        assert!(matches!(
            t.observe("b:8340", split(), t0 + 90 * MIN, &pool()),
            Some(ShardListEvent::Ended { .. })
        ));
        assert_eq!(t.observe("b:8340", stale(), t0 + 100 * MIN, &pool()), None);
        assert_eq!(t.observe("a:8340", split(), t0 + 110 * MIN, &pool()), None);
        assert_eq!(
            t.observe("b:8340", split(), t0 + 120 * MIN, &pool()),
            None,
            "an unwarned disagreement ends silently"
        );
    }

    #[test]
    fn a_report_five_hours_old_still_counts() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        assert_eq!(t.observe("a:8340", split(), t0, &pool()), None);
        assert_eq!(t.observe("b:8340", stale(), t0 + HOUR, &pool()), None);
        let Some(ShardListEvent::Started(d)) = t.observe("c:8340", split(), t0 + 5 * HOUR, &pool())
        else {
            panic!("a's five-hour-old list came back after b's");
        };
        assert_eq!(
            (d.other_endpoint.as_str(), d.other_age),
            ("b:8340", 4 * HOUR)
        );
        assert_eq!(d.recent_endpoints, 3);
    }

    #[test]
    fn a_report_seven_hours_old_is_ignored() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        assert_eq!(t.observe("a:8340", split(), t0, &pool()), None);
        assert_eq!(t.observe("b:8340", stale(), t0 + 2 * HOUR, &pool()), None);
        // a's list is seven hours old, so only b's (five hours) and c's
        // remain, and nothing alternates.
        assert_eq!(t.observe("c:8340", split(), t0 + 7 * HOUR, &pool()), None);
        assert_eq!(t.reports.len(), 2);
    }

    #[test]
    fn no_agreement_while_a_differing_report_is_within_six_hours() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        t.observe("a:8340", split(), t0, &pool());
        t.observe("b:8340", stale(), t0 + 10 * MIN, &pool());
        assert!(matches!(
            t.observe("c:8340", split(), t0 + 20 * MIN, &pool()),
            Some(ShardListEvent::Started(_))
        ));
        // a and c take turns hourly while b's stale list stays recent: the
        // warning repeats hourly and no agreement is logged.
        for (hours, endpoint) in [
            (1, "a:8340"),
            (2, "c:8340"),
            (3, "a:8340"),
            (4, "c:8340"),
            (5, "a:8340"),
        ] {
            let event = t.observe(endpoint, split(), t0 + 20 * MIN + hours * HOUR, &pool());
            assert!(
                matches!(&event, Some(ShardListEvent::Persisting { disagreement, .. }) if disagreement.other_endpoint == "b:8340"),
                "{hours} h after the start: {event:?}"
            );
        }
        // b's report is now 6 h 10 min old and forgotten: the end says so.
        assert_eq!(
            t.observe("c:8340", split(), t0 + 20 * MIN + 6 * HOUR, &pool()),
            Some(ShardListEvent::Ended {
                duration: 6 * HOUR,
                cause: EndCause::Expired,
                digest: split().digest(),
                recent_endpoints: 2,
                shards: 3,
            })
        );
    }

    #[test]
    fn endpoints_that_left_the_pool_are_forgotten() {
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        t.observe("a:8340", split(), t0, &pool());
        t.observe("b:8340", stale(), t0 + MIN, &pool());
        let only_a_c: Vec<String> = vec!["a:8340".into(), "c:8340".into()];
        assert_eq!(t.observe("c:8340", split(), t0 + 2 * MIN, &only_a_c), None);
        assert_eq!(t.reports.len(), 2);
    }

    #[test]
    fn an_endpoint_outside_the_pool_counts_once_then_is_forgotten() {
        let a_b: Vec<String> = vec!["a:8340".into(), "b:8340".into()];
        let mut t = ArchiveShardListTracker::new();
        let t0 = Instant::now();
        t.observe("a:8340", split(), t0, &a_b);
        t.observe("b:8340", stale(), t0 + MIN, &a_b);
        assert!(
            matches!(
                t.observe("x:8340", split(), t0 + 2 * MIN, &a_b),
                Some(ShardListEvent::Started(_))
            ),
            "the refreshed endpoint's own report is compared"
        );
        t.observe("a:8340", split(), t0 + 3 * MIN, &a_b);
        assert!(!t.reports.contains_key("x:8340"));
        assert_eq!(t.reports.len(), 2);
    }

    #[test]
    fn a_partial_refresh_is_not_compared() {
        let mut info = ArchiveShardInfo::default();
        info.sizes.insert(vec![2; 3], 1);
        assert_eq!(
            ShardList::from_complete(&info).map(|l| l.filters.len()),
            Some(1)
        );
        info.failed_shard_keys = 1;
        assert_eq!(ShardList::from_complete(&info), None);
    }

    #[test]
    fn logged_filter_lists_are_capped() {
        let filters: Vec<Vec<u8>> = (0..40u8).map(|f| vec![f]).collect();
        let logged = hex_filters(&filters);
        assert_eq!(logged.split(',').count(), MAX_LOGGED_FILTERS);
        assert!(
            logged.starts_with("00,01,") && logged.ends_with(",0f"),
            "{logged}"
        );
    }

    #[test]
    fn the_digest_depends_on_the_filters_only() {
        let mut frozen = split();
        frozen.frozen.insert(vec![2; 3]);
        assert_eq!(frozen.digest(), split().digest());
        assert_ne!(stale().digest(), split().digest());
        assert_eq!(split().digest().len(), 8);
        // Without length prefixes both lists would hash the bytes 1, 1, 2.
        let a = ShardList {
            filters: [vec![1u8, 1], vec![2u8]].into_iter().collect(),
            ..Default::default()
        };
        let b = ShardList {
            filters: [vec![1u8], vec![1u8, 2]].into_iter().collect(),
            ..Default::default()
        };
        assert_ne!(a.digest(), b.digest());
    }
}
