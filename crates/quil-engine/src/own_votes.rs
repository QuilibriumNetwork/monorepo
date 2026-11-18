//! Whether this member's own engine votes in its committee session.
//!
//! A member that hosts its session but never sends a vote counts against the
//! session's quorum like an absent one: provers whose workers reported
//! serving were silent in nearly every below-quorum session of a regular
//! node, connected and subscribed to each shard's topic, while their seats
//! renewed every epoch (2026-10-21). Only the member's own node can see that
//! its engine sends nothing, so it counts the votes the session host hands
//! to the node for publishing and those it receives from the other members,
//! and measures how long it has sent none while the others vote. It reports
//! both (`WorkerExecution.own_votes`, `silent_ms`) and warns while the
//! silence lasts. The node lets the seat lapse once that has lasted an epoch
//! ([`crate::provers::session_hosting`]).
//!
//! A vote counts when the host hands it to the node to publish on the
//! shard's topic, not when the network carries it: the publish happens in
//! the master (for a standalone worker, after a hop over its stream) and
//! reports no outcome to the engine. A node whose publishing fails thus
//! counts as voting.
//!
//! A present member always votes: each view that times out without a
//! certificate gets this member's nullify vote, and simplex sends it again
//! every retry period while the view lasts, so a stalled session does not
//! make its present members silent.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Simplex's vote channel (`cw_app_seams` routes channels 0/1/2 as
/// vote/certificate/resolver).
pub(crate) const VOTE_CHANNEL: u64 = 0;

/// Other members vote while one of their votes arrived this recently. Present
/// members send a nullify vote again every retry period (15 s) while a view
/// lasts. Silence is counted only while they vote, and in steps no longer
/// than this.
pub(crate) const PEERS_VOTING: Duration = Duration::from_secs(2 * 60);

/// How long this member may send nothing while the others vote before the
/// operator is warned: well past the first view timeout (30 s) of a new host.
pub(crate) const WARN_AFTER: Duration = Duration::from_secs(10 * 60);

/// How often a continuing silence is warned about again.
pub(crate) const WARN_REPEAT: Duration = Duration::from_secs(30 * 60);

/// The votes one session host handed to the node to publish, counted by the
/// transport on the consensus thread.
#[derive(Clone, Debug, Default)]
pub struct SentVotes(Arc<AtomicU64>);

impl SentVotes {
    pub(crate) fn note(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// What [`OwnVotes`] has to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnVotesLog {
    /// This member has sent nothing for `silent` while the others vote.
    Silent { silent: Duration, repeat: bool },
    /// A silence that was warned about ended after `silent`, `how`; this
    /// member was at index `member` of that host's session.
    Ended {
        silent: Duration,
        how: &'static str,
        member: Option<usize>,
    },
}

/// The report fields of [`OwnVotes::report`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct VotesReport {
    /// Votes sent; `None` while no session host runs.
    pub own: Option<u64>,
    pub peer: u64,
    pub last_peer_vote_unix_ms: u64,
    /// When the running host started, on this machine's clock: it names the
    /// host.
    pub host_started_unix_ms: u64,
    /// How long the running host has sent nothing while the others voted.
    pub silent_ms: u64,
}

/// This member's votes in its running session host, against the other
/// members'.
#[derive(Debug, Default)]
pub(crate) struct OwnVotes {
    /// The running host's count; `None` while no session host runs.
    sent: Option<SentVotes>,
    me: Option<usize>,
    host_started_unix_ms: u64,
    peer_votes: u64,
    last_peer_vote: Option<(Instant, u64)>,
    /// How long this host has sent nothing while the others voted: it
    /// pauses while they are silent too.
    silent: Duration,
    /// The previous [`Self::check`].
    checked: Option<Instant>,
    /// When the silence was last warned about.
    warned: Option<Instant>,
}

impl OwnVotes {
    /// A session host started at `now` (`now_ms` on the wall clock),
    /// counting its votes in `sent`, with this member at index `me`. Ends the
    /// previous host's silence.
    pub fn restart(
        &mut self,
        sent: SentVotes,
        me: Option<usize>,
        now: Instant,
        now_ms: u64,
    ) -> Option<OwnVotesLog> {
        let ended = self.stop("its consensus host restarted");
        *self = Self {
            sent: Some(sent),
            me,
            host_started_unix_ms: now_ms,
            checked: Some(now),
            ..Self::default()
        };
        ended
    }

    /// No session host runs any more.
    pub fn stop(&mut self, how: &'static str) -> Option<OwnVotesLog> {
        let ended = self.warned.take().map(|_| OwnVotesLog::Ended {
            silent: self.silent,
            how,
            member: self.me,
        });
        *self = Self::default();
        ended
    }

    /// A message on `channel` from session member `member` arrived at `now`
    /// (`now_ms` on the wall clock).
    pub fn received(&mut self, member: usize, channel: u64, now: Instant, now_ms: u64) {
        if self.sent.is_none() || channel != VOTE_CHANNEL || Some(member) == self.me {
            return;
        }
        self.peer_votes += 1;
        self.last_peer_vote = Some((now, now_ms));
    }

    /// This member's index in the running host's session.
    pub fn member(&self) -> Option<usize> {
        self.me
    }

    /// The report fields. A host this member is not seated in casts no
    /// votes, so its count says nothing: `own` is `None` then.
    pub fn report(&self) -> VotesReport {
        VotesReport {
            own: self
                .sent
                .as_ref()
                .filter(|_| self.me.is_some())
                .map(SentVotes::get),
            peer: self.peer_votes,
            last_peer_vote_unix_ms: self.last_peer_vote.map_or(0, |(_, ms)| ms),
            host_started_unix_ms: if self.sent.is_some() {
                self.host_started_unix_ms
            } else {
                0
            },
            silent_ms: self.silent.as_millis() as u64,
        }
    }

    /// Count the silence up to `now` and say what to log: the silence once it
    /// lasted [`WARN_AFTER`] while the others vote, again every
    /// [`WARN_REPEAT`] while they still do, and its end once this member
    /// sends a vote. Time while nobody's votes arrive is not counted.
    pub fn check(&mut self, now: Instant) -> Option<OwnVotesLog> {
        self.me?;
        let sent = self.sent.as_ref()?.get();
        let previous = self.checked.replace(now);
        if sent > 0 {
            let silent = std::mem::take(&mut self.silent);
            return self.warned.take().map(|_| OwnVotesLog::Ended {
                silent,
                how: "it sent a vote",
                member: self.me,
            });
        }
        let peers_voting = self
            .last_peer_vote
            .is_some_and(|(at, _)| now.saturating_duration_since(at) <= PEERS_VOTING);
        if !peers_voting {
            return None;
        }
        if let Some(previous) = previous {
            self.silent += now.saturating_duration_since(previous).min(PEERS_VOTING);
        }
        let due = match self.warned {
            None => self.silent >= WARN_AFTER,
            Some(at) => now.saturating_duration_since(at) >= WARN_REPEAT,
        };
        if !due {
            return None;
        }
        let repeat = self.warned.replace(now).is_some();
        Some(OwnVotesLog::Silent {
            silent: self.silent,
            repeat,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn running(start: Instant) -> (OwnVotes, SentVotes) {
        let sent = SentVotes::default();
        let mut votes = OwnVotes::default();
        assert!(votes.restart(sent.clone(), Some(0), start, 5_000).is_none());
        (votes, sent)
    }

    /// Each minute from `from` (in minutes after `start`) through `to`: the
    /// other members vote (when `others` is set) and the silence is checked;
    /// what was logged, at which minute.
    fn minutes(
        votes: &mut OwnVotes,
        start: Instant,
        from: u32,
        to: u32,
        others: bool,
    ) -> Vec<(u32, OwnVotesLog)> {
        let mut logged = Vec::new();
        for minute in from..=to {
            let now = start + MINUTE * minute;
            if others {
                votes.received(1, VOTE_CHANNEL, now, 1);
            }
            if let Some(log) = votes.check(now) {
                logged.push((minute, log));
            }
        }
        logged
    }

    /// Silence while the others vote is warned about after ten minutes, then
    /// every thirty while they still vote, and its end once this member
    /// votes; the report carries the counts and the host.
    #[test]
    fn silence_while_others_vote_is_warned_with_a_bounded_repeat_and_its_end() {
        let start = Instant::now();
        let (mut votes, sent) = running(start);
        assert_eq!(
            votes.report(),
            VotesReport {
                own: Some(0),
                host_started_unix_ms: 5_000,
                ..Default::default()
            }
        );
        let silent = |minutes, repeat| OwnVotesLog::Silent {
            silent: MINUTE * minutes,
            repeat,
        };
        let logged = minutes(&mut votes, start, 1, 75, true);
        assert_eq!(
            logged,
            vec![
                (10, silent(10, false)),
                (40, silent(40, true)),
                (70, silent(70, true))
            ]
        );
        let report = votes.report();
        assert_eq!(
            (
                report.own,
                report.peer,
                report.last_peer_vote_unix_ms,
                report.silent_ms
            ),
            (Some(0), 75, 1, 75 * 60_000)
        );

        sent.note();
        let ended = OwnVotesLog::Ended {
            silent: MINUTE * 75,
            how: "it sent a vote",
            member: Some(0),
        };
        assert_eq!(votes.check(start + MINUTE * 76), Some(ended));
        assert_eq!(votes.check(start + MINUTE * 200), None, "logged once");
        assert_eq!(votes.report().own, Some(1));
        assert_eq!(votes.report().silent_ms, 0);
    }

    /// While nobody's votes arrive the silence clock pauses and no repeat
    /// is logged; it resumes when the others vote again.
    #[test]
    fn an_outage_pauses_the_silence_and_its_repeats() {
        let start = Instant::now();
        let (mut votes, _sent) = running(start);
        assert_eq!(minutes(&mut votes, start, 1, 10, true).len(), 1);
        // The others' last vote stays within the window for two minutes.
        assert!(
            minutes(&mut votes, start, 11, 100, false).is_empty(),
            "no repeat while the others are silent"
        );
        assert_eq!(votes.report().silent_ms, 12 * 60_000);
        let logged = minutes(&mut votes, start, 101, 102, true);
        assert_eq!(
            logged,
            vec![(
                101,
                OwnVotesLog::Silent {
                    silent: MINUTE * 13,
                    repeat: true
                }
            )],
            "the repeat is due; the gap was not counted beyond the vote window"
        );
    }

    /// A member that votes, a silence nobody else breaks (an outage), this
    /// member's own messages and other channels are not warned about.
    #[test]
    fn voting_members_and_outages_are_not_warned_about() {
        let start = Instant::now();
        let (mut votes, _sent) = running(start);
        votes.received(0, VOTE_CHANNEL, start, 1);
        votes.received(1, 1, start, 1);
        assert_eq!(
            votes.report().peer,
            0,
            "own and certificate messages are not votes received"
        );
        assert!(
            minutes(&mut votes, start, 1, 60, false).is_empty(),
            "nobody votes"
        );
        assert_eq!(votes.report().silent_ms, 0);

        let (mut votes, sent) = running(start);
        sent.note();
        assert!(
            minutes(&mut votes, start, 1, 60, true).is_empty(),
            "a member that voted once, as a nullify in a stalled view"
        );
        assert_eq!(votes.report().silent_ms, 0);
    }

    /// A new host or the end of hosting ends a warned silence; without a host
    /// nothing is counted or reported.
    #[test]
    fn a_restart_or_stop_ends_a_warned_silence() {
        let start = Instant::now();
        let mut unseated = OwnVotes::default();
        unseated.restart(SentVotes::default(), None, start, 5_000);
        assert_eq!(
            unseated.report().own,
            None,
            "a host that does not seat this member reports no votes"
        );
        assert!(
            minutes(&mut unseated, start, 1, 30, true).is_empty(),
            "nor is it warned about"
        );

        let (mut votes, _) = running(start);
        assert_eq!(minutes(&mut votes, start, 1, 11, true).len(), 1);
        let ended = votes.restart(SentVotes::default(), Some(0), start + MINUTE * 12, 9_000);
        let restarted = OwnVotesLog::Ended {
            silent: MINUTE * 11,
            how: "its consensus host restarted",
            member: Some(0),
        };
        assert_eq!(ended, Some(restarted));
        assert_eq!(
            votes.report(),
            VotesReport {
                own: Some(0),
                host_started_unix_ms: 9_000,
                ..Default::default()
            }
        );

        assert_eq!(minutes(&mut votes, start, 13, 23, true).len(), 1);
        assert!(matches!(
            votes.stop("stopped"),
            Some(OwnVotesLog::Ended { .. })
        ));
        votes.received(1, VOTE_CHANNEL, start + MINUTE * 25, 1);
        assert_eq!(votes.report(), VotesReport::default());
        assert!(votes.check(start + MINUTE * 60).is_none());
        assert!(
            votes.stop("stopped").is_none(),
            "nothing warned, nothing ended"
        );
    }
}
