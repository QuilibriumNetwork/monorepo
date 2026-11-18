//! QUILIBRIUM: one bounded summary per signer of the repeated and conflicting
//! votes the batcher ignores.
//!
//! Upstream logs a warning per message (`block!`) when a member sends a
//! second vote in a view it already voted in: "invalid signature" for the
//! same proposal signed again with different bytes, "conflicting notarize",
//! "conflicting finalize" and "conflicting nullify", and "nullify after
//! finalize" or "finalize after nullify". One remote signer that kept
//! re-signing its votes produced about 1,650 such warnings an hour for a day
//! and a half on a regular node, 85% of its warnings, and "invalid
//! signature" suggested a verification failure that never happened. The
//! sender is still blocked and the evidence still reported as before; this
//! logs the first repeat of a signer at once, then a summary of that signer
//! at most once per [`SUMMARY_EVERY`], and an end line once it has sent none
//! for that long.

use crate::types::Participant;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

/// How often a signer's continuing repeats are summarized again, and how
/// long a signer must stay quiet before its episode ends.
pub(super) const SUMMARY_EVERY: Duration = Duration::from_secs(600);

/// Why a member's further vote in a view was ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repeat {
    /// The same vote signed again with different bytes (upstream's
    /// "invalid signature" and "conflicting nullify").
    Resigned,
    /// A notarize or finalize for another proposal than the signer's first
    /// ("conflicting notarize"/"conflicting finalize"); equivocation.
    Conflicting,
    /// Both a nullify and a finalize ("nullify after finalize"/"finalize
    /// after nullify"); equivocation.
    NullifyFinalize,
}

impl Repeat {
    const fn name(self) -> &'static str {
        match self {
            Self::Resigned => "same vote, other signature bytes",
            Self::Conflicting => "votes for two proposals",
            Self::NullifyFinalize => "nullify and finalize",
        }
    }
}

/// Repeats counted by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Counts {
    pub resigned: u64,
    pub conflicting: u64,
    pub nullify_finalize: u64,
}

impl Counts {
    fn add(&mut self, kind: Repeat) {
        match kind {
            Repeat::Resigned => self.resigned += 1,
            Repeat::Conflicting => self.conflicting += 1,
            Repeat::NullifyFinalize => self.nullify_finalize += 1,
        }
    }

    fn merge(&mut self, other: Self) {
        self.resigned += other.resigned;
        self.conflicting += other.conflicting;
        self.nullify_finalize += other.nullify_finalize;
    }
}

/// A line to log about one signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Line<P> {
    /// The signer's first repeat (of a new episode).
    First { signer: P, index: Participant, kind: Repeat, view: u64 },
    /// Repeats since the signer's previous line; `secs` since its first.
    Summary { signer: P, index: Participant, counts: Counts, secs: u64, last_view: u64 },
    /// The signer sent none for [`SUMMARY_EVERY`]: totals of the episode,
    /// `secs` from its first repeat to its last.
    End { signer: P, index: Participant, totals: Counts, secs: u64, last_view: u64 },
}

/// One signer's current episode of repeats.
#[derive(Debug)]
struct Episode<P> {
    signer: P,
    first: SystemTime,
    logged: SystemTime,
    last: SystemTime,
    last_view: u64,
    /// Not yet in a line.
    pending: Counts,
    /// Already in a line.
    logged_counts: Counts,
}

impl<P: Clone> Episode<P> {
    fn end(self, index: Participant) -> Line<P> {
        let mut totals = self.logged_counts;
        totals.merge(self.pending);
        Line::End {
            signer: self.signer,
            index,
            totals,
            secs: secs(self.last, self.first),
            last_view: self.last_view,
        }
    }
}

fn secs(later: SystemTime, earlier: SystemTime) -> u64 {
    later.duration_since(earlier).unwrap_or_default().as_secs()
}

/// Repeated and conflicting votes per signer, summarized at most once per
/// interval. Keyed by participant index, so it holds at most one episode
/// per member of the batcher's (one epoch's) participant set.
#[derive(Debug)]
pub(super) struct Repeats<P> {
    /// The engine's journal partition, naming the session in each line
    /// (`app-<shard filter>` on app shards).
    pub(super) partition: String,
    episodes: BTreeMap<Participant, Episode<P>>,
    /// No episode can end before this time.
    due: Option<SystemTime>,
}

impl<P> Default for Repeats<P> {
    fn default() -> Self {
        Self { partition: String::new(), episodes: BTreeMap::new(), due: None }
    }
}

impl<P: Clone> Repeats<P> {
    /// A further vote of `signer` (participant `index`) in `view`, ignored
    /// for `kind`; returns the lines to log.
    pub(super) fn record(&mut self, now: SystemTime, signer: &P, index: Participant, kind: Repeat, view: u64) -> Vec<Line<P>> {
        let mut lines = Vec::new();
        // A repeat after a quiet spell starts a new episode.
        if self.episodes.get(&index).is_some_and(|e| secs(now, e.last) >= SUMMARY_EVERY.as_secs()) {
            lines.push(self.episodes.remove(&index).expect("present").end(index));
        }
        if self.due.is_none() {
            self.due = Some(now + SUMMARY_EVERY);
        }
        let Some(episode) = self.episodes.get_mut(&index) else {
            let mut logged_counts = Counts::default();
            logged_counts.add(kind);
            self.episodes.insert(
                index,
                Episode { signer: signer.clone(), first: now, logged: now, last: now, last_view: view, pending: Counts::default(), logged_counts },
            );
            lines.push(Line::First { signer: signer.clone(), index, kind, view });
            return lines;
        };
        episode.last = now;
        episode.last_view = episode.last_view.max(view);
        episode.pending.add(kind);
        if secs(now, episode.logged) >= SUMMARY_EVERY.as_secs() {
            episode.logged = now;
            let counts = std::mem::take(&mut episode.pending);
            episode.logged_counts.merge(counts);
            lines.push(Line::Summary {
                signer: episode.signer.clone(),
                index,
                counts,
                secs: secs(now, episode.first),
                last_view: episode.last_view,
            });
        }
        lines
    }

    /// End the episodes of signers quiet for [`SUMMARY_EVERY`]; returns their
    /// end lines. Cheap until the earliest episode can end.
    pub(super) fn expire(&mut self, now: SystemTime) -> Vec<Line<P>> {
        if self.due.is_none_or(|due| now < due) {
            return Vec::new();
        }
        let quiet: Vec<Participant> = self
            .episodes
            .iter()
            .filter(|(_, e)| secs(now, e.last) >= SUMMARY_EVERY.as_secs())
            .map(|(index, _)| *index)
            .collect();
        let lines = quiet.into_iter().filter_map(|index| self.episodes.remove(&index).map(|e| e.end(index))).collect();
        self.due = self.episodes.values().map(|e| e.last + SUMMARY_EVERY).min();
        lines
    }
}

/// What this node's operator does about a remote prover's repeated votes.
const ACTION: &str = "no action needed on this node: ignored votes cost nothing, and only that \
    prover's operator can fix it (a duplicate instance, or a restart without its vote journal); \
    repeats are summarized every 10 min at info";

impl<P: std::fmt::Debug> Line<P> {
    /// Log the line for a member in epoch `epoch` of the engine journaling to
    /// `partition`. A signer's first equivocation (votes for two proposals,
    /// or a nullify and a finalize, in one view) logs a warning: the
    /// evidence is reported and a maintainer may want it. Its summaries log
    /// at info, as does a re-signed duplicate: they change no outcome (the
    /// vote counts once) and this operator cannot act on them.
    pub(super) fn log(&self, partition: &str, epoch: u64) {
        match self {
            Self::First { signer, index, kind, view } => {
                let resigned = *kind == Repeat::Resigned;
                let kind = kind.name();
                if resigned {
                    tracing::info!(
                        scope = "peer",
                        partition,
                        epoch,
                        view,
                        signer = ?signer,
                        index = %index,
                        kind,
                        action = ACTION,
                        "a remote prover sent the same vote twice with other signature bytes; the copy is ignored"
                    );
                } else {
                    tracing::warn!(
                        scope = "peer",
                        partition,
                        epoch,
                        view,
                        signer = ?signer,
                        index = %index,
                        kind,
                        action = ACTION,
                        "a remote prover is signing conflicting votes; its extra votes are ignored and the equivocation is reported"
                    );
                }
            }
            // The first line said it all: repeats are counts at info.
            Self::Summary { signer, index, counts, secs, last_view } => {
                tracing::info!(
                    scope = "peer",
                    partition,
                    epoch,
                    signer = ?signer,
                    index = %index,
                    resigned = counts.resigned,
                    conflicting = counts.conflicting,
                    nullify_finalize = counts.nullify_finalize,
                    secs,
                    last_view,
                    action = ACTION,
                    "a remote prover still sends repeated or conflicting votes, all ignored; counts since the previous line"
                );
            }
            Self::End { signer, index, totals, secs, last_view } => {
                tracing::info!(
                    scope = "peer",
                    partition,
                    epoch,
                    signer = ?signer,
                    index = %index,
                    resigned = totals.resigned,
                    conflicting = totals.conflicting,
                    nullify_finalize = totals.nullify_finalize,
                    secs,
                    last_view,
                    "a remote prover's repeated or conflicting votes stopped: none for 10 min; totals of the episode"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000 + secs)
    }

    fn p(index: u32) -> Participant {
        Participant::new(index)
    }

    #[test]
    fn a_signer_logs_its_first_repeat_then_one_summary_per_interval() {
        let mut r = Repeats::<u8>::default();
        assert_eq!(r.record(at(0), &7, p(3), Repeat::Resigned, 40), vec![Line::First { signer: 7, index: p(3), kind: Repeat::Resigned, view: 40 }]);
        // About 1,650 repeats an hour, as observed: none logs before the interval.
        for n in 1..=274u64 {
            let kind = match n % 10 {
                0 => Repeat::Conflicting,
                1 | 2 => Repeat::NullifyFinalize,
                _ => Repeat::Resigned,
            };
            assert_eq!(r.record(at(n * 2), &7, p(3), kind, 40 + n), vec![], "repeat {n}");
        }
        let summary = r.record(at(600), &7, p(3), Repeat::Resigned, 300);
        assert_eq!(
            summary,
            vec![Line::Summary {
                signer: 7,
                index: p(3),
                counts: Counts { resigned: 192, conflicting: 27, nullify_finalize: 56 },
                secs: 600,
                last_view: 314,
            }]
        );
        assert_eq!(r.record(at(1_199), &7, p(3), Repeat::Resigned, 400), vec![]);
        // Quiet for ten minutes after its last repeat: the episode ends with totals.
        assert_eq!(r.expire(at(1_798)), vec![]);
        assert_eq!(
            r.expire(at(1_799)),
            vec![Line::End {
                signer: 7,
                index: p(3),
                totals: Counts { resigned: 194, conflicting: 27, nullify_finalize: 56 },
                secs: 1_199,
                last_view: 400,
            }]
        );
        assert_eq!(r.expire(at(5_000)), vec![]);
    }

    #[test]
    fn signers_are_summarized_apart() {
        let mut r = Repeats::<u8>::default();
        assert_eq!(r.record(at(0), &1, p(0), Repeat::Conflicting, 5).len(), 1);
        assert_eq!(r.record(at(1), &2, p(1), Repeat::Resigned, 5).len(), 1, "another signer's first repeat logs at once");
        assert_eq!(r.record(at(2), &1, p(0), Repeat::Resigned, 6), vec![]);
        assert_eq!(r.record(at(400), &2, p(1), Repeat::Resigned, 9), vec![]);
        // Signer 0 went quiet; signer 1 did not.
        assert_eq!(
            r.expire(at(602)),
            vec![Line::End { signer: 1, index: p(0), totals: Counts { resigned: 1, conflicting: 1, nullify_finalize: 0 }, secs: 2, last_view: 6 }]
        );
        assert_eq!(r.expire(at(999)), vec![]);
        assert_eq!(r.expire(at(1_000)).len(), 1);
    }

    #[test]
    fn a_repeat_after_a_quiet_spell_ends_the_episode_and_logs_at_once() {
        let mut r = Repeats::<u8>::default();
        assert_eq!(r.record(at(0), &1, p(0), Repeat::Resigned, 5).len(), 1);
        assert_eq!(
            r.record(at(3_000), &1, p(0), Repeat::NullifyFinalize, 90),
            vec![
                Line::End { signer: 1, index: p(0), totals: Counts { resigned: 1, ..Counts::default() }, secs: 0, last_view: 5 },
                Line::First { signer: 1, index: p(0), kind: Repeat::NullifyFinalize, view: 90 },
            ]
        );
    }

    #[test]
    fn each_line_names_the_session_partition_and_its_level() {
        use std::{
            io,
            sync::{Arc, Mutex},
        };

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
        let mut r = Repeats::<u8>::default();
        r.partition = "app-00a2080".into();
        tracing::subscriber::with_default(subscriber, || {
            let mut lines = r.record(at(0), &1, p(0), Repeat::Resigned, 5);
            for n in 1..=100 {
                lines.extend(r.record(at(n), &1, p(0), Repeat::Resigned, 5 + n));
            }
            lines.extend(r.record(at(600), &1, p(0), Repeat::Conflicting, 200));
            lines.extend(r.expire(at(1_200)));
            for line in lines {
                line.log(&r.partition, 18);
            }
        });
        let out = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out.lines().count(), 3, "first, one summary and the end, not 102 lines: {out}");
        assert_eq!(out.matches("partition=\"app-00a2080\"").count(), 3, "{out}");
        assert_eq!(out.matches(" INFO ").count(), 3, "the re-signed first repeat, the summary and the end: {out}");
        assert_eq!(out.matches(" WARN ").count(), 0, "a summary with a conflicting vote is counts at info: {out}");
        assert!(out.contains("resigned=100 conflicting=1"), "{out}");
        assert!(!out.contains("invalid signature"), "{out}");
    }
}
