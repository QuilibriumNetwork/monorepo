//! QUILIBRIUM: one bounded line per interval on where this member's finalize
//! vote stood in each view it voted in.
//!
//! A shard frame credits only the signers of its finalization certificate,
//! and every certificate holds exactly a quorum of them, so a member that
//! votes on time can still go unsigned when more members vote than the
//! quorum needs. Three causes remain after the member's worker shows no
//! lag: its vote left late, it reached the peers late, or it arrived and
//! lost to the copy that landed. This counts, per view with this member's
//! finalize vote, its place in the order the votes reached this batcher and
//! whose certificate finished the view: the rank above the quorum says the
//! quorum was already here when this vote was added (late here, or the
//! peers were faster); a rank within the quorum with a peer's certificate
//! finishing the view says the vote was early here and lost on the wire or
//! to another copy. One line per [`SUMMARY_EVERY`], no peer identities.

use std::time::{Duration, SystemTime};

/// How often the counts are logged.
pub(super) const SUMMARY_EVERY: Duration = Duration::from_secs(600);

/// Ranks kept per interval for the percentiles; the counts stay exact.
const SAMPLES: usize = 2_048;

/// How a view this member voted finalize in ended, as seen here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// This batcher assembled the certificate; `own_in` says whether this
    /// member's vote is among its signers.
    Assembled { own_in: bool },
    /// A certificate assembled elsewhere finished the view first.
    PeerCopy,
}

/// One view's reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Sample {
    /// This vote's place in the order the finalize votes were held here
    /// (1 = the first).
    pub rank: u32,
    pub quorum: u32,
    pub outcome: Outcome,
}

impl Sample {
    /// `held_before` votes of others were held when this member's vote was
    /// added.
    pub(super) const fn new(held_before: u32, quorum: u32, outcome: Outcome) -> Self {
        Self {
            rank: held_before.saturating_add(1),
            quorum,
            outcome,
        }
    }

    /// The quorum was already held when this vote was added.
    pub(super) const fn late_here(&self) -> bool {
        self.rank > self.quorum
    }
}

/// What the views of one interval showed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Summary {
    /// Seconds since the previous line (0 for the first).
    pub secs: u64,
    /// Views this member voted finalize in.
    pub views: u64,
    pub rank_p50: u32,
    pub rank_p90: u32,
    /// The quorum of the latest view.
    pub quorum: u32,
    /// Views whose quorum was held before this vote was added.
    pub quorum_before_own: u64,
    /// Views assembled here with this member's vote among the signers.
    pub assembled_with_own: u64,
    /// Views assembled here without it.
    pub assembled_without_own: u64,
    /// Views a peer's certificate finished, this vote within the quorum
    /// here.
    pub peer_copy_own_early: u64,
    /// Views a peer's certificate finished, the quorum held here first.
    pub peer_copy_own_late: u64,
}

/// The readings of the current interval.
#[derive(Debug, Default)]
pub(super) struct Races {
    /// The engine's journal partition, naming the session in the line.
    pub(super) partition: String,
    logged: Option<SystemTime>,
    ranks: Vec<u32>,
    pending: Summary,
}

impl Races {
    /// Record `sample` at `now`; returns the summary to log once
    /// [`SUMMARY_EVERY`] has passed since the interval began.
    pub(super) fn record(&mut self, now: SystemTime, sample: Sample) -> Option<Summary> {
        let p = &mut self.pending;
        p.views += 1;
        p.quorum = sample.quorum;
        if sample.late_here() {
            p.quorum_before_own += 1;
        }
        match sample.outcome {
            Outcome::Assembled { own_in: true } => p.assembled_with_own += 1,
            Outcome::Assembled { own_in: false } => p.assembled_without_own += 1,
            Outcome::PeerCopy if sample.late_here() => p.peer_copy_own_late += 1,
            Outcome::PeerCopy => p.peer_copy_own_early += 1,
        }
        if self.ranks.len() < SAMPLES {
            self.ranks.push(sample.rank);
        }
        let Some(began) = self.logged else {
            self.logged = Some(now);
            return None;
        };
        let since = now.duration_since(began).unwrap_or_default();
        if since < SUMMARY_EVERY {
            return None;
        }
        self.logged = Some(now);
        let mut summary = std::mem::take(&mut self.pending);
        let mut ranks = std::mem::take(&mut self.ranks);
        ranks.sort_unstable();
        summary.secs = since.as_secs();
        summary.rank_p50 = percentile(&ranks, 50);
        summary.rank_p90 = percentile(&ranks, 90);
        Some(summary)
    }
}

/// The `pct`th percentile (nearest rank) of sorted `ranks`; 0 when empty.
fn percentile(ranks: &[u32], pct: usize) -> u32 {
    match (ranks.len() * pct).div_ceil(100) {
        0 => 0,
        n => ranks[n - 1],
    }
}

impl Summary {
    /// Log the summary for a member in epoch `ours` of the engine journaling
    /// to `partition`.
    pub(super) fn log(&self, partition: &str, ours: u64) {
        tracing::info!(
            scope = "this node's finalize votes in this session",
            partition,
            epoch = ours,
            secs = self.secs,
            views = self.views,
            own_rank_p50 = self.rank_p50,
            own_rank_p90 = self.rank_p90,
            quorum = self.quorum,
            quorum_before_own = self.quorum_before_own,
            assembled_with_own = self.assembled_with_own,
            assembled_without_own = self.assembled_without_own,
            peer_copy_own_early = self.peer_copy_own_early,
            peer_copy_own_late = self.peer_copy_own_late,
            action = "no action needed; reading: quorum_before_own high means the quorum of other votes \
                      was held before this node's vote was added (its worker is late, or the peers \
                      are faster); peer_copy_own_early high means the vote was early here but a \
                      certificate assembled elsewhere finished the view (path or copy race: report \
                      with the partition and times)",
            "finalize vote race: where this node's finalize vote ranked among the votes held and whose certificate finished the view"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000 + secs)
    }

    #[test]
    fn a_sample_ranks_after_the_votes_held_and_is_late_past_the_quorum() {
        let early = Sample::new(2, 3, Outcome::PeerCopy);
        assert_eq!(
            (early.rank, early.late_here()),
            (3, false),
            "the third of a quorum of 3"
        );
        let late = Sample::new(3, 3, Outcome::PeerCopy);
        assert_eq!(
            (late.rank, late.late_here()),
            (4, true),
            "the quorum was held first"
        );
    }

    /// The views test holds one early and one late peer copy, so swapping the
    /// two counts passes it; this one tells them apart.
    #[test]
    fn a_peer_copy_counts_late_only_past_the_quorum() {
        let mut r = Races::default();
        assert_eq!(r.record(at(0), Sample::new(3, 3, Outcome::PeerCopy)), None);
        let summary = r
            .record(at(600), Sample::new(3, 3, Outcome::PeerCopy))
            .expect("one summary per interval");
        assert_eq!(
            (summary.peer_copy_own_early, summary.peer_copy_own_late),
            (0, 2)
        );
    }

    #[test]
    fn views_are_classified_and_summarized_once_per_interval() {
        let mut r = Races::default();
        // Rank 1..=4 against a quorum of 3, one outcome each way.
        let samples = [
            Sample::new(0, 3, Outcome::Assembled { own_in: true }),
            Sample::new(1, 3, Outcome::Assembled { own_in: false }),
            Sample::new(2, 3, Outcome::PeerCopy),
            Sample::new(3, 3, Outcome::PeerCopy),
        ];
        assert_eq!(r.record(at(0), samples[0]), None, "the interval begins");
        assert_eq!(r.record(at(100), samples[1]), None);
        assert_eq!(r.record(at(200), samples[2]), None);
        assert_eq!(r.record(at(599), samples[3]), None);
        let summary = r
            .record(
                at(600),
                Sample::new(0, 3, Outcome::Assembled { own_in: true }),
            )
            .expect("one summary per interval");
        assert_eq!(
            summary,
            Summary {
                secs: 600,
                views: 5,
                rank_p50: 2,
                rank_p90: 4,
                quorum: 3,
                quorum_before_own: 1,
                assembled_with_own: 2,
                assembled_without_own: 1,
                peer_copy_own_early: 1,
                peer_copy_own_late: 1,
            }
        );
        assert_eq!(
            r.record(at(601), samples[0]),
            None,
            "the next interval is empty again"
        );
        let next = r
            .record(at(1_200), samples[0])
            .expect("one summary per interval");
        assert_eq!((next.views, next.rank_p90), (2, 1));
    }

    #[test]
    fn the_ranks_kept_are_bounded_and_the_counts_stay_exact() {
        let mut r = Races::default();
        for n in 0..(SAMPLES as u64 + 500) {
            assert_eq!(
                r.record(at(n / 100), Sample::new(1, 3, Outcome::PeerCopy)),
                None
            );
        }
        assert_eq!(r.ranks.len(), SAMPLES);
        let summary = r
            .record(at(600), Sample::new(1, 3, Outcome::PeerCopy))
            .expect("summary");
        assert_eq!(summary.views, SAMPLES as u64 + 501);
        assert_eq!(summary.peer_copy_own_early, SAMPLES as u64 + 501);
    }

    #[test]
    fn percentiles_use_the_nearest_rank() {
        assert_eq!(percentile(&[], 90), 0);
        let ranks: Vec<u32> = (1..=10).collect();
        assert_eq!(
            (
                percentile(&ranks, 50),
                percentile(&ranks, 90),
                percentile(&ranks, 100)
            ),
            (5, 9, 10)
        );
        // Between ranks, the percentile rounds up to the next one held.
        assert_eq!(
            (percentile(&[1, 2, 3], 50), percentile(&[1, 2, 3], 90)),
            (2, 3)
        );
    }
}
