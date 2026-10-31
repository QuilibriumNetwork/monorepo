//! Whether this node's workers host the committee sessions their seats sit in.
//!
//! A seat is renewed only while its worker takes part in the shard's
//! consensus (decided 2026-10-18). A worker bound to a seat whose current
//! session counts it as a member, but that cannot host that session (its
//! start is refused, its data is not staged, its engine stopped), sends
//! nothing: its committee carries a member that never votes, and enough of
//! them keep the committee below quorum (2026-10-18, regular-node workers
//! refused their predecessors' state for hours while their seats renewed).
//! Once such a seat has gone an epoch without its worker hosting, it is not
//! renewed: it lapses to `ExpiredEpoch`, which removes it from committee
//! eligibility, so the shard's next session is drawn without it.
//!
//! Lapsing takes the seat out of its session, which owes it no hosting, so
//! the withheld renewal stays withheld through it (2026-10-21: a lapsed seat
//! renewed three frames after it lapsed, its worker still failing recovery).
//! Outside its session the worker cannot host; it is able to once its start
//! passes every check of the shard's state and is refused only because no
//! session seats it. Until then the seat stays lapsed: the allocator
//! releases its worker after the recovery epoch and the orphan sweep leaves
//! it.
//!
//! The record is in memory, and a restart cannot tell for how long a worker
//! has not hosted (2026-10-21: three such seats renewed 55 s after a
//! restart). A member or lapsed seat whose worker is seen unable to host
//! within a settle period after the start waits; if the worker still cannot
//! host when the period ends, its renewal is withheld as above. Only the
//! worker's current state lifts it, so a restart that fixed the worker
//! renews the seat. A seat not yet seated owes no hosting and renews.
//!
//! Only this node's own observations count, and only against its own seats.
//! A standalone worker that does not answer its report request, or that the
//! node holds no connection to, hosts nothing (2026-10-21: provers silent in
//! every committee that seated them reconfirmed all their seats each epoch,
//! while a worker that does not answer gave no report, and no report held no
//! seat back). A worker that cannot report (a build without the call) or
//! whose report is stale is not observed and never held against its seat.
//!
//! Hosting is not voting (decided 2026-10-22): provers whose workers
//! reported serving were silent in nearly every below-quorum session of a
//! regular node, connected and subscribed to each shard's topic, while their
//! seats renewed every epoch. A worker reports the votes its session host
//! sent and received ([`crate::own_votes`]). A seat whose worker serves or
//! closes the session that counts it, and has sent no vote since its host
//! started while the other members' votes reach it, is silent. Its
//! renewal is withheld as above once one host of the worker has been silent
//! for an epoch: by the worker's own clock, which pauses while nobody's
//! votes arrive, so a network outage lapses no one, and by observed GLOBAL
//! frames, credited at most a settle period per observation, so a GLOBAL
//! catch-up after a restart does not stand in for time. A new engine or host
//! starts the run over and lifts a withheld renewal, so an operator who
//! fixes and restarts the worker keeps the seat; so does a vote. An
//! observation where the worker does not serve or the seat is outside its
//! session neither adds to the run nor ends it. A present member sends a
//! nullify vote whenever a view times out, so members of a stalled committee
//! are not silent. A build that does not report its votes is never silent.
//!
//! A seat withheld for silence lapses, the allocator releases its worker and
//! the orphan sweep leaves the seat. That worker is then held back from new
//! seats: otherwise a broken engine would join, sit silent, lapse and leave
//! again every few epochs, each time adding chain traffic and a pending join
//! to every other prover's planning. It is released when it is seen voting,
//! when its engine or host on the withheld seat restarts while still bound
//! to it, after [`HELD_BACK_EPOCHS`] epochs, or when this node restarts. A
//! released worker that is still broken may join once more and must again
//! be silent for an epoch, so it costs at most one leave in about five epochs. A
//! worker released by the allocator reports nothing (an idle worker runs no
//! engine), so restarting it shows only once the hold expires or it votes
//! after binding to another seat; the allocator binds held-back workers last.
//!
//! Only silence from a host's start counts: a host that voted once and then
//! wedged is not silent here.

use std::collections::{HashMap, HashSet};

use quil_types::proto::node::WorkerExecution;

/// A report older than this says nothing about the worker now. Engines
/// refresh their report on every state change and start attempt, and a
/// standalone worker's report is fetched every few seconds.
const FRESH_MS: u64 = 2 * 60 * 1000;

/// The blocker a worker reports once its start passed every check of the
/// shard's state and only the committee refused its key
/// (`worker_execution::BLOCKERS`): seated, it would host.
const REFUSED_FOR_SEAT_ONLY: &str = "committee admission unavailable";

/// The other members vote while one of their votes reached the worker this
/// recently ([`crate::own_votes::PEERS_VOTING`]).
const PEERS_VOTING_MS: u64 = crate::own_votes::PEERS_VOTING.as_millis() as u64;

/// Epochs a worker stays held back from new seats after its seat was
/// withheld for silence, unless it votes or restarts first.
pub(crate) const HELD_BACK_EPOCHS: u64 = 4;

/// The wall-clock time `epoch_frames` take at the ideal GLOBAL frame time:
/// the interval at this process's latest GLOBAL frame throughout
/// ([`quil_types::consensus::ideal_frame_time_ms`]).
pub(crate) fn epoch_ms(epoch_frames: u64) -> u64 {
    epoch_frames.saturating_mul(quil_types::consensus::ideal_frame_time_ms())
}

/// How long after a start a worker seen unable to host may still be
/// starting: a twelfth of an epoch, 60 frames on mainnet.
pub(crate) fn settle_frames(epoch_frames: u64) -> u64 {
    (epoch_frames / 12).max(1)
}

/// What one report says about the worker hosting its session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Hosting {
    /// It hosts the session (`serving` or `closing`), or saw it sealed and
    /// awaits its successor (`handoff`), and its votes are not observed: an
    /// older build, a sealed session, or no other member's votes arrive.
    Hosting,
    /// It hosts the session and has sent a vote since its host started.
    Voting,
    /// It hosts the session and has sent no vote since its host started,
    /// while the other members' votes reach it (`peer_votes` so far), for
    /// `silent_ms` by its own clock.
    Silent { peer_votes: u64, silent_ms: u64 },
    /// It does not: startup refused or stopped, or the host is up but gated
    /// on unstaged data, so it neither proposes nor votes.
    Absent { state: String, blocker: String },
    /// No usable report.
    Unknown,
}

/// Classify the latest `execution` report of a worker at `now_ms`.
pub(crate) fn classify(execution: Option<&WorkerExecution>, now_ms: u64) -> Hosting {
    let Some(execution) = execution else {
        return Hosting::Unknown;
    };
    if execution.observed_unix_ms == 0
        || now_ms.saturating_sub(execution.observed_unix_ms) > FRESH_MS
    {
        return Hosting::Unknown;
    }
    match execution.state.as_str() {
        "serving" | "closing" => match execution.own_votes {
            Some(0)
                if execution.last_peer_vote_unix_ms != 0
                    && now_ms.saturating_sub(execution.last_peer_vote_unix_ms)
                        <= PEERS_VOTING_MS =>
            {
                Hosting::Silent {
                    peer_votes: execution.peer_votes,
                    silent_ms: execution.silent_ms,
                }
            }
            Some(own) if own > 0 => Hosting::Voting,
            _ => Hosting::Hosting,
        },
        // "running" is the name builds before the lifecycle phases reported.
        "handoff" | "running" => Hosting::Hosting,
        "" | "unknown" => Hosting::Unknown,
        state => Hosting::Absent {
            state: state.to_string(),
            blocker: execution.blocker.clone(),
        },
    }
}

impl Hosting {
    /// Whether the worker can host the session of a seat standing at `seat`:
    /// it hosts, or, outside the session, its start passed every check of
    /// the shard's state and only the committee refused its key. A worker
    /// still syncing or recovering the shard has not passed those checks.
    pub(crate) fn able(&self, seat: Seat) -> bool {
        match self {
            Hosting::Hosting | Hosting::Voting | Hosting::Silent { .. } => true,
            Hosting::Absent { blocker, .. } => {
                seat != Seat::Member && blocker == REFUSED_FOR_SEAT_ONLY
            }
            Hosting::Unknown => false,
        }
    }

    /// Whether the report shows the worker unable to host at `seat`. An
    /// unknown report is never held against its seat.
    pub(crate) fn seen_unable(&self, seat: Seat) -> bool {
        matches!(self, Hosting::Absent { .. }) && !self.able(seat)
    }
}

/// Which engine and consensus host of a worker a report comes from: when
/// each started, on the worker's own clock (0: not reported).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Instance {
    pub engine: u64,
    pub host: u64,
}

impl Instance {
    pub fn of(execution: Option<&WorkerExecution>) -> Self {
        execution.map_or_else(Self::default, |execution| Self {
            engine: execution.engine_started_unix_ms,
            host: execution.host_started_unix_ms,
        })
    }

    /// How `self` differs from `before`, if it names another engine or
    /// host: a restart.
    fn restarted_since(&self, before: &Self) -> Option<&'static str> {
        let differs = |now: u64, then: u64| now != 0 && then != 0 && now != then;
        if differs(self.engine, before.engine) {
            Some("its engine restarted")
        } else if differs(self.host, before.host) {
            Some("its consensus host restarted")
        } else {
            None
        }
    }
}

/// A standalone worker that did not answer its report request for `reason`.
pub(crate) fn unanswered(reason: &str) -> Hosting {
    Hosting::Absent {
        state: "unreachable".into(),
        blocker: reason.into(),
    }
}

/// Where a seat stands with its shard's current committee session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seat {
    /// The session counts this prover.
    Member,
    /// It does not, and the seat missed its epoch renewal (`ExpiredEpoch`).
    Lapsed,
    /// It does not, and the seat is current: not yet seated, or its
    /// session is closed.
    Outside,
}

/// Since when a seat's worker has failed to host the session that counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unhosted {
    pub core_id: u32,
    /// The GLOBAL frame of the first observation in this run.
    pub since: u64,
    /// The latest observation.
    pub state: String,
    pub blocker: String,
    /// First seen within the settle period after this process started: the
    /// run may have begun before the start.
    pub from_start: bool,
    /// Whether this run has withheld its seat's renewal.
    withheld: bool,
}

/// Since when one host of a seat's worker has hosted the session that
/// counts it without sending a vote while the other members vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unvoted {
    pub core_id: u32,
    /// The worker's engine and host this run observed.
    pub instance: Instance,
    /// The GLOBAL frame of the first silent observation in this run.
    pub since: u64,
    /// GLOBAL frames between consecutive silent observations, each step
    /// credited at most a settle period, summed.
    pub silent_frames: u64,
    /// How long the host has been silent by the worker's clock, at the
    /// latest silent observation.
    pub silent_ms: u64,
    /// Votes the worker had received from the other members at the latest
    /// silent observation.
    pub peer_votes: u64,
    /// The frame of the previous observation, when it was silent.
    last: Option<u64>,
    /// Whether this run has withheld its seat's renewal.
    withheld: bool,
}

/// A worker whose seat was withheld for silence: it takes no new seats
/// until it votes, restarts on that seat or the hold expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldBack {
    /// The seat withheld, and the GLOBAL frame it was withheld at.
    pub filter: Vec<u8>,
    pub since: u64,
    instance: Instance,
}

/// What [`SessionHosting::observe_votes`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VoteEvent {
    /// A renewal withheld for silence is no longer withheld, `how`.
    Lifted { run: Unvoted, how: &'static str },
    /// Worker `core_id` takes new seats again, `how`.
    Released {
        core_id: u32,
        held: HeldBack,
        how: &'static str,
    },
}

/// Per seat (by filter), how long its bound worker has not hosted the
/// session that counts this prover, or has hosted it without voting; and
/// the workers held back from new seats for silence. In memory: after a
/// restart, see [`settle_frames`]; silence is counted afresh and no worker
/// is held back.
#[derive(Debug, Default)]
pub(crate) struct SessionHosting {
    unhosted: HashMap<Vec<u8>, Unhosted>,
    unvoted: HashMap<Vec<u8>, Unvoted>,
    held_back: HashMap<u32, HeldBack>,
    /// The GLOBAL frame of this process's first observation.
    started: Option<u64>,
    /// Whether renewals waiting for the settle period have been reported.
    settling_reported: bool,
}

impl SessionHosting {
    /// Record the observation at GLOBAL `frame` of the worker `core_id`
    /// bound to `filter`, whose seat stands at `seat`. A seat outside its
    /// session owes no hosting, unless the run already withheld its renewal
    /// or began within the settle period; a worker able to host ends the
    /// run; an unknown report leaves it as it is. Returns the run it ends
    /// when that run had withheld the renewal.
    pub fn observe(
        &mut self,
        frame: u64,
        epoch_frames: u64,
        filter: &[u8],
        core_id: u32,
        seat: Seat,
        hosting: Hosting,
    ) -> Option<Unhosted> {
        let started = *self.started.get_or_insert(frame);
        // Another worker took the seat: its run starts over.
        if self
            .unhosted
            .get(filter)
            .is_some_and(|run| run.core_id != core_id)
        {
            self.unhosted.remove(filter);
        }
        if hosting.able(seat) {
            return self.unhosted.remove(filter).filter(|run| run.withheld);
        }
        if seat != Seat::Member
            && self
                .unhosted
                .get(filter)
                .is_some_and(|run| !run.withheld && !run.from_start)
        {
            self.unhosted.remove(filter);
        }
        let Hosting::Absent { state, blocker } = hosting else {
            return None;
        };
        let from_start = frame < started.saturating_add(settle_frames(epoch_frames));
        match self.unhosted.get_mut(filter) {
            Some(run) => {
                run.state = state;
                run.blocker = blocker;
            }
            None if seat == Seat::Member || (from_start && seat == Seat::Lapsed) => {
                self.unhosted.insert(
                    filter.to_vec(),
                    Unhosted {
                        core_id,
                        since: frame,
                        state,
                        blocker,
                        from_start,
                        withheld: false,
                    },
                );
            }
            None => {}
        }
        None
    }

    /// Record whether the worker `core_id` bound to `filter`, whose seat
    /// stands at `seat`, votes in the session it hosts, as observed at GLOBAL
    /// `frame` from the report of its engine and host `instance`. A silent
    /// observation of a member seat adds the frames since the previous one,
    /// if that was silent too, at most a settle period. A vote or a new
    /// engine or host ends the run, and lifts a renewal it withheld; a vote
    /// of a held-back worker anywhere, or its restart on the seat it was held
    /// back for, releases it; a new engine on another seat (the allocator
    /// bound it there) does not. Any other observation leaves the run as it
    /// is.
    pub fn observe_votes(
        &mut self,
        frame: u64,
        epoch_frames: u64,
        filter: &[u8],
        core_id: u32,
        seat: Seat,
        hosting: &Hosting,
        instance: Instance,
    ) -> Vec<VoteEvent> {
        let mut events = Vec::new();
        let release = self.held_back.get(&core_id).and_then(|held| {
            if *hosting == Hosting::Voting {
                Some("it votes")
            } else if held.filter == filter {
                instance.restarted_since(&held.instance)
            } else {
                None
            }
        });
        if let Some(how) = release {
            if let Some(held) = self.held_back.remove(&core_id) {
                events.push(VoteEvent::Released { core_id, held, how });
            }
        }
        // Another worker took the seat: its run starts over.
        if self
            .unvoted
            .get(filter)
            .is_some_and(|run| run.core_id != core_id)
        {
            self.unvoted.remove(filter);
        }
        let ended = match hosting {
            Hosting::Voting => Some("it votes"),
            _ => self
                .unvoted
                .get(filter)
                .and_then(|run| instance.restarted_since(&run.instance)),
        };
        if let Some(how) = ended {
            if let Some(run) = self.unvoted.remove(filter).filter(|run| run.withheld) {
                events.push(VoteEvent::Lifted { run, how });
            }
        }
        match hosting {
            Hosting::Silent {
                peer_votes,
                silent_ms,
            } if seat == Seat::Member => {
                let run = self
                    .unvoted
                    .entry(filter.to_vec())
                    .or_insert_with(|| Unvoted {
                        core_id,
                        instance,
                        since: frame,
                        silent_frames: 0,
                        silent_ms: 0,
                        peer_votes: 0,
                        last: None,
                        withheld: false,
                    });
                if let Some(last) = run.last {
                    let step = frame.saturating_sub(last).min(settle_frames(epoch_frames));
                    run.silent_frames = run.silent_frames.saturating_add(step);
                }
                run.last = Some(frame);
                run.silent_ms = *silent_ms;
                run.peer_votes = *peer_votes;
            }
            _ => {
                if let Some(run) = self.unvoted.get_mut(filter) {
                    run.last = None;
                }
            }
        }
        events
    }

    /// The workers held back from new seats for silence.
    pub fn held_back(&self) -> HashSet<u32> {
        self.held_back.keys().copied().collect()
    }

    /// Release the workers held back for [`HELD_BACK_EPOCHS`] epochs by
    /// GLOBAL `frame`.
    pub fn expire_held_back(&mut self, frame: u64, epoch_frames: u64) -> Vec<(u32, HeldBack)> {
        let span = epoch_frames.saturating_mul(HELD_BACK_EPOCHS);
        let expired: Vec<u32> = self
            .held_back
            .iter()
            .filter(|(_, held)| frame.saturating_sub(held.since) >= span)
            .map(|(core_id, _)| *core_id)
            .collect();
        expired
            .into_iter()
            .filter_map(|core_id| self.held_back.remove(&core_id).map(|held| (core_id, held)))
            .collect()
    }

    /// Forget seats no worker is bound to any more.
    pub fn retain_bound(&mut self, bound: &HashSet<Vec<u8>>) {
        self.unhosted.retain(|filter, _| bound.contains(filter));
        self.unvoted.retain(|filter, _| bound.contains(filter));
    }

    /// Whether `filter`'s renewal is held back at GLOBAL `frame`: withheld
    /// once its worker's run without hosting has lasted `epoch_frames`, or,
    /// for a run from this process's start, the settle period, which it
    /// waits out first; or once its worker's host was observed silent for
    /// `epoch_frames` and [`epoch_ms`]. A withheld run stays withheld until
    /// [`Self::observe`] or [`Self::observe_votes`] ends it; a run withheld
    /// for silence holds its worker back from new seats.
    pub fn withhold(&mut self, filter: &[u8], frame: u64, epoch_frames: u64) -> Option<Hold> {
        let settled = self
            .started
            .get_or_insert(frame)
            .saturating_add(settle_frames(epoch_frames));
        if let Some(run) = self.unhosted.get_mut(filter) {
            let due = if run.from_start {
                frame >= settled
            } else {
                frame.saturating_sub(run.since) >= epoch_frames
            };
            if run.withheld || due {
                let first = !run.withheld;
                run.withheld = true;
                return Some(Hold::Withheld(Withheld {
                    run: run.clone(),
                    first,
                }));
            }
            if run.from_start {
                return Some(Hold::Settling { until: settled });
            }
        }
        let run = self.unvoted.get_mut(filter)?;
        let due = run.silent_frames >= epoch_frames && run.silent_ms >= epoch_ms(epoch_frames);
        if !run.withheld && !due {
            return None;
        }
        let first = !run.withheld;
        run.withheld = true;
        if first {
            self.held_back
                .entry(run.core_id)
                .or_insert_with(|| HeldBack {
                    filter: filter.to_vec(),
                    since: frame,
                    instance: run.instance,
                });
        }
        Some(Hold::Unvoted(UnvotedHold {
            run: run.clone(),
            first,
        }))
    }

    /// True the first time renewals wait for the settle period, for the
    /// caller to report it once.
    pub fn report_settling(&mut self) -> bool {
        !std::mem::replace(&mut self.settling_reported, true)
    }
}

/// A renewal [`SessionHosting::withhold`] holds back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Hold {
    /// Its worker was seen unable to host within the settle period after
    /// this process started, which lasts until GLOBAL frame `until`.
    Settling {
        until: u64,
    },
    Withheld(Withheld),
    /// Its worker hosts the session but has been silent for an epoch; the
    /// worker is held back from new seats.
    Unvoted(UnvotedHold),
}

/// A renewal withheld because its seat's worker cannot host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Withheld {
    pub run: Unhosted,
    /// The first time this run withholds a renewal.
    pub first: bool,
}

/// A renewal withheld because its seat's worker hosts its session without
/// voting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnvotedHold {
    pub run: Unvoted,
    /// The first time this run withholds a renewal.
    pub first: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u64 = 720;

    fn report(state: &str, observed_unix_ms: u64) -> WorkerExecution {
        WorkerExecution {
            state: state.into(),
            blocker: "predecessor state".into(),
            observed_unix_ms,
            ..Default::default()
        }
    }

    /// Serving, closing and handoff host the session; a refused start, a
    /// host gated on unstaged data and a stopped engine do not; a missing or
    /// stale report says nothing.
    #[test]
    fn reports_classify_by_phase_and_age() {
        let now = 10 * FRESH_MS;
        for state in ["serving", "closing", "handoff", "running"] {
            assert_eq!(
                classify(Some(&report(state, now)), now),
                Hosting::Hosting,
                "{state}"
            );
        }
        for state in ["blocked", "syncing", "starting", "stopped", "waiting"] {
            assert!(
                matches!(
                    classify(Some(&report(state, now)), now),
                    Hosting::Absent { .. }
                ),
                "{state}"
            );
        }
        assert_eq!(classify(None, now), Hosting::Unknown);
        assert_eq!(
            classify(Some(&report("blocked", now - FRESH_MS - 1)), now),
            Hosting::Unknown
        );
        assert_eq!(classify(Some(&report("blocked", 0)), now), Hosting::Unknown);
        assert_eq!(
            classify(Some(&report("unknown", now)), now),
            Hosting::Unknown
        );
    }

    /// A worker is able to host when it hosts, whether seen voting, silent
    /// or unobserved, or, outside its session, is refused only for its
    /// seat; only a report of another blocker shows it unable, and an
    /// unknown one shows nothing.
    #[test]
    fn a_worker_refused_only_for_its_seat_is_able_outside_its_session() {
        for seat in [Seat::Member, Seat::Lapsed, Seat::Outside] {
            for hosts in [
                Hosting::Hosting,
                Hosting::Voting,
                Hosting::Silent {
                    peer_votes: 40,
                    silent_ms: 9_000,
                },
            ] {
                assert!(
                    hosts.able(seat) && !hosts.seen_unable(seat),
                    "{hosts:?} {seat:?}"
                );
            }
            assert!(
                !absent().able(seat) && absent().seen_unable(seat),
                "{seat:?}"
            );
            assert!(
                !Hosting::Unknown.able(seat) && !Hosting::Unknown.seen_unable(seat),
                "{seat:?}"
            );
            let outside = seat != Seat::Member;
            assert_eq!(
                (
                    refused_for_seat_only().able(seat),
                    refused_for_seat_only().seen_unable(seat)
                ),
                (outside, !outside),
                "{seat:?}"
            );
        }
    }

    fn voted(
        state: &str,
        own: Option<u64>,
        last_peer_vote_unix_ms: u64,
        now: u64,
    ) -> WorkerExecution {
        WorkerExecution {
            own_votes: own,
            peer_votes: 40,
            last_peer_vote_unix_ms,
            silent_ms: 9_000,
            ..report(state, now)
        }
    }

    /// A serving or closing worker that has sent no vote while the other
    /// members' votes reach it is silent; one that sent any vote votes; one
    /// whose build does not report votes, that hears no other member (an
    /// outage) or whose session is sealed hosts as before.
    #[test]
    fn hosting_reports_classify_by_own_votes_against_the_others() {
        let now = 10 * FRESH_MS;
        let silent = Hosting::Silent {
            peer_votes: 40,
            silent_ms: 9_000,
        };
        for state in ["serving", "closing"] {
            assert_eq!(
                classify(Some(&voted(state, Some(0), now - 1_000, now)), now),
                silent
            );
            assert_eq!(
                classify(Some(&voted(state, Some(1), now - 1_000, now)), now),
                Hosting::Voting,
                "a single nullify"
            );
            assert_eq!(
                classify(Some(&voted(state, None, now - 1_000, now)), now),
                Hosting::Hosting,
                "an older build"
            );
            assert_eq!(
                classify(Some(&voted(state, Some(0), 0, now)), now),
                Hosting::Hosting,
                "no other member heard"
            );
            assert_eq!(
                classify(
                    Some(&voted(state, Some(0), now - PEERS_VOTING_MS - 1, now)),
                    now
                ),
                Hosting::Hosting,
                "the others stopped voting"
            );
        }
        assert_eq!(
            classify(Some(&voted("handoff", Some(0), now, now)), now),
            Hosting::Hosting,
            "sealed"
        );
        assert!(matches!(
            classify(Some(&voted("syncing", Some(0), now, now)), now),
            Hosting::Absent { .. }
        ));
    }

    const HOST: Instance = Instance {
        engine: 1_000,
        host: 2_000,
    };

    /// A silent observation at GLOBAL `frame` of a host silent since `from`
    /// (frame), on the ideal frame clock.
    fn silent_since(from: u64, frame: u64) -> Hosting {
        Hosting::Silent {
            peer_votes: 7,
            silent_ms: frame.saturating_sub(from) * epoch_ms(1),
        }
    }

    fn unvoted(hold: Option<Hold>) -> Option<UnvotedHold> {
        match hold {
            Some(Hold::Unvoted(hold)) => Some(hold),
            _ => None,
        }
    }

    /// Observe `filter`'s worker 1 at each frame of `frames` as `observed`
    /// from `instance`; the events.
    fn observe_each(
        hosting: &mut SessionHosting,
        filter: &[u8],
        frames: impl IntoIterator<Item = u64>,
        seat: Seat,
        observed: impl Fn(u64) -> Hosting,
        instance: Instance,
    ) -> Vec<VoteEvent> {
        let mut events = Vec::new();
        for frame in frames {
            let observation = observed(frame);
            hosting.observe(frame, EPOCH, filter, 1, seat, observation.clone());
            events.extend(hosting.observe_votes(
                frame,
                EPOCH,
                filter,
                1,
                seat,
                &observation,
                instance,
            ));
        }
        events
    }

    /// One host silent for an epoch of frames and of its own time withholds
    /// a member seat's renewal and holds its worker back; frames observed in
    /// an outage, without hosting or outside the session add nothing and end
    /// nothing; a vote ends the run and releases the worker; a rebound or
    /// unbound seat starts over, while the worker stays held back.
    #[test]
    fn a_member_seat_silent_for_an_epoch_is_withheld_until_it_votes() {
        let filter = vec![1; 32];
        let mut hosting = running();
        let silent = |frame| silent_since(100, frame);
        assert!(observe_each(
            &mut hosting,
            &filter,
            (100..=500).step_by(10),
            Seat::Member,
            silent,
            HOST
        )
        .is_empty());
        // An outage, a host gated on unstaged data and a seat outside its
        // session: frames that do not count.
        for (frame, seat, observed) in [
            (600, Seat::Member, Hosting::Hosting),
            (700, Seat::Member, absent()),
            (800, Seat::Outside, silent(800)),
            (900, Seat::Member, Hosting::Unknown),
        ] {
            assert!(observe_each(
                &mut hosting,
                &filter,
                [frame],
                seat,
                |_| observed.clone(),
                HOST
            )
            .is_empty());
            assert!(hosting.withhold(&filter, frame, EPOCH).is_none(), "{frame}");
        }
        observe_each(
            &mut hosting,
            &filter,
            (1_000..=1_310).step_by(10),
            Seat::Member,
            silent,
            HOST,
        );
        assert!(
            hosting.withhold(&filter, 1_310, EPOCH).is_none(),
            "710 silent frames"
        );
        observe_each(&mut hosting, &filter, [1_320], Seat::Member, silent, HOST);
        let first = unvoted(hosting.withhold(&filter, 1_320, EPOCH)).expect("an epoch silent");
        assert!(
            first.first
                && first.run.since == 100
                && first.run.silent_frames == 720
                && first.run.peer_votes == 7
        );
        assert!(
            !unvoted(hosting.withhold(&filter, 1_330, EPOCH))
                .unwrap()
                .first,
            "reported once per run"
        );
        assert_eq!(
            hosting.held_back(),
            HashSet::from([1]),
            "its worker takes no new seats"
        );
        for (frame, seat, observed) in [
            (1_440, Seat::Lapsed, absent()),
            (1_450, Seat::Lapsed, Hosting::Hosting),
        ] {
            observe_each(
                &mut hosting,
                &filter,
                [frame],
                seat,
                |_| observed.clone(),
                HOST,
            );
            assert!(
                unvoted(hosting.withhold(&filter, frame, EPOCH)).is_some(),
                "lapsing lifts nothing"
            );
        }
        let events = observe_each(
            &mut hosting,
            &filter,
            [1_460],
            Seat::Member,
            |_| Hosting::Voting,
            HOST,
        );
        assert!(
            matches!(&events[..], [VoteEvent::Released { core_id: 1, how: "it votes", .. },
            VoteEvent::Lifted { run, how: "it votes" }] if run.since == 100),
            "{events:?}"
        );
        assert!(hosting.withhold(&filter, 1_460, EPOCH).is_none());
        assert!(hosting.held_back().is_empty());

        observe_each(
            &mut hosting,
            &filter,
            (2_000..=2_720).step_by(20),
            Seat::Member,
            |f| silent_since(2_000, f),
            HOST,
        );
        assert!(unvoted(hosting.withhold(&filter, 2_720, EPOCH)).is_some());
        hosting.observe(2_730, EPOCH, &filter, 2, Seat::Member, silent(2_730));
        hosting.observe_votes(2_730, EPOCH, &filter, 2, Seat::Member, &silent(2_730), HOST);
        assert!(
            hosting.withhold(&filter, 2_730, EPOCH).is_none(),
            "a rebound seat starts over"
        );
        hosting.retain_bound(&HashSet::new());
        assert!(hosting.unvoted.is_empty(), "an unbound seat is forgotten");
        assert_eq!(hosting.held_back(), HashSet::from([1]), "its worker is not");
    }

    /// GLOBAL frames passing faster than the host's own time, as in a
    /// catch-up after a restart, withhold nothing: two observations an epoch
    /// apart credit a settle period, and many of them minutes apart do not
    /// reach the host's epoch of silence.
    #[test]
    fn a_frame_jump_with_little_silent_time_withholds_nothing() {
        let filter = vec![1; 32];
        let mut hosting = running();
        let minutes = |minutes: u64| {
            move |_: u64| Hosting::Silent {
                peer_votes: 7,
                silent_ms: minutes * 60_000,
            }
        };
        observe_each(
            &mut hosting,
            &filter,
            [5, 725],
            Seat::Member,
            minutes(10),
            HOST,
        );
        assert!(
            hosting.withhold(&filter, 725, EPOCH).is_none(),
            "an epoch apart: one settle period credited"
        );
        observe_each(
            &mut hosting,
            &filter,
            (730..=1_500).step_by(10),
            Seat::Member,
            minutes(15),
            HOST,
        );
        assert!(
            hosting.withhold(&filter, 1_500, EPOCH).is_none(),
            "an epoch of frames in fifteen minutes"
        );
        observe_each(
            &mut hosting,
            &filter,
            [1_510],
            Seat::Member,
            minutes(120),
            HOST,
        );
        assert!(
            hosting.withhold(&filter, 1_510, EPOCH).is_some(),
            "both an epoch of frames and of time"
        );
    }

    /// A new engine or host starts the run over: silence spanning a restart
    /// withholds nothing, and a restart lifts a withheld renewal and
    /// releases the worker, also once the seat lapsed out of its session.
    #[test]
    fn a_restart_starts_the_run_over_and_lifts_a_withheld_renewal() {
        let filter = vec![1; 32];
        let mut hosting = running();
        let restarted_host = Instance {
            host: 3_000,
            ..HOST
        };
        observe_each(
            &mut hosting,
            &filter,
            (100..=500).step_by(10),
            Seat::Member,
            |f| silent_since(100, f),
            HOST,
        );
        observe_each(
            &mut hosting,
            &filter,
            (510..=900).step_by(10),
            Seat::Member,
            |f| silent_since(100, f),
            restarted_host,
        );
        assert!(
            hosting.withhold(&filter, 900, EPOCH).is_none(),
            "the new host's run is 390 frames old"
        );
        observe_each(
            &mut hosting,
            &filter,
            (910..=1_230).step_by(10),
            Seat::Member,
            |f| silent_since(100, f),
            restarted_host,
        );
        assert!(
            unvoted(hosting.withhold(&filter, 1_230, EPOCH)).is_some(),
            "an epoch of the new host"
        );

        // The seat lapsed out of its session: no host runs, the engine is
        // the same until the operator restarts the worker.
        let no_host = Instance {
            host: 0,
            ..restarted_host
        };
        assert!(observe_each(
            &mut hosting,
            &filter,
            [1_500],
            Seat::Lapsed,
            |_| absent(),
            no_host
        )
        .is_empty());
        assert!(unvoted(hosting.withhold(&filter, 1_500, EPOCH)).is_some());
        let restarted = Instance {
            engine: 4_000,
            host: 0,
        };
        let events = observe_each(
            &mut hosting,
            &filter,
            [1_510],
            Seat::Lapsed,
            |_| absent(),
            restarted,
        );
        assert!(
            matches!(
                &events[..],
                [
                    VoteEvent::Released {
                        how: "its engine restarted",
                        ..
                    },
                    VoteEvent::Lifted {
                        how: "its engine restarted",
                        ..
                    }
                ]
            ),
            "{events:?}"
        );
        assert!(
            hosting.withhold(&filter, 1_510, EPOCH).is_none() && hosting.held_back().is_empty()
        );
    }

    /// The step cap alone: a host silent for an epoch by its own clock,
    /// observed twice an epoch of GLOBAL frames apart, is credited one settle
    /// period, not the epoch.
    #[test]
    fn the_frame_step_cap_alone_keeps_a_frame_jump_from_withholding() {
        let filter = vec![1; 32];
        let mut hosting = running();
        let epoch_silent = |_: u64| Hosting::Silent {
            peer_votes: 7,
            silent_ms: epoch_ms(EPOCH),
        };
        observe_each(
            &mut hosting,
            &filter,
            [5, 725],
            Seat::Member,
            epoch_silent,
            HOST,
        );
        assert!(
            hosting.withhold(&filter, 725, EPOCH).is_none(),
            "one settle period credited"
        );
        observe_each(
            &mut hosting,
            &filter,
            (785..=1_385).step_by(60),
            Seat::Member,
            epoch_silent,
            HOST,
        );
        assert!(
            hosting.withhold(&filter, 1_385, EPOCH).is_some(),
            "an epoch credited in settle periods"
        );
    }

    /// Hold `filter`'s worker 1 back: one host silent for an epoch from
    /// frame 0, withheld at `EPOCH`.
    fn held_back(hosting: &mut SessionHosting, filter: &[u8]) {
        observe_each(
            hosting,
            filter,
            (0..=EPOCH).step_by(60),
            Seat::Member,
            |f| silent_since(0, f),
            HOST,
        );
        assert!(unvoted(hosting.withhold(filter, EPOCH, EPOCH)).is_some_and(|hold| hold.first));
        assert_eq!(hosting.held_back(), HashSet::from([1]));
    }

    /// A held-back worker that is never observed again (the allocator
    /// released it once its seat lapsed) is released after four epochs.
    #[test]
    fn a_held_back_worker_is_released_after_four_epochs() {
        let mut hosting = running();
        held_back(&mut hosting, &[1; 32]);
        hosting.retain_bound(&HashSet::new());
        let expires = EPOCH + HELD_BACK_EPOCHS * EPOCH;
        assert!(hosting.expire_held_back(expires - 1, EPOCH).is_empty());
        assert_eq!(hosting.held_back(), HashSet::from([1]));
        let released = hosting.expire_held_back(expires, EPOCH);
        assert!(
            matches!(&released[..], [(1, held)] if held.filter == vec![1; 32] && held.since == EPOCH)
        );
        assert!(hosting.held_back().is_empty());
    }

    /// A held-back worker the allocator binds to another seat runs a new
    /// engine there, which is no restart of the worker that was withheld:
    /// it stays held back until it votes, or restarts on its own seat.
    #[test]
    fn a_rebound_held_back_worker_stays_held_back_until_it_votes() {
        let (own, other) = (vec![1; 32], vec![2; 32]);
        let rebound = Instance {
            engine: 9_000,
            host: 9_500,
        };
        let mut hosting = running();
        held_back(&mut hosting, &own);
        for observed in [Hosting::Hosting, absent(), silent_since(0, 800)] {
            assert!(observe_each(
                &mut hosting,
                &other,
                [800],
                Seat::Member,
                |_| observed.clone(),
                rebound
            )
            .is_empty());
            assert_eq!(hosting.held_back(), HashSet::from([1]), "{observed:?}");
        }
        let events = observe_each(
            &mut hosting,
            &other,
            [810],
            Seat::Member,
            |_| Hosting::Voting,
            rebound,
        );
        assert!(
            matches!(
                &events[..],
                [VoteEvent::Released {
                    core_id: 1,
                    how: "it votes",
                    ..
                }]
            ),
            "{events:?}"
        );

        let mut hosting = running();
        held_back(&mut hosting, &own);
        let events = observe_each(
            &mut hosting,
            &own,
            [800],
            Seat::Lapsed,
            |_| absent(),
            rebound,
        );
        assert!(
            matches!(
                &events[..],
                [
                    VoteEvent::Released {
                        how: "its engine restarted",
                        ..
                    },
                    VoteEvent::Lifted { .. }
                ]
            ),
            "restarted on its own seat: {events:?}"
        );
    }

    /// A worker that votes, even once in a session that stalls, is never
    /// silent; nor is one in an outage, or of a build that does not report.
    #[test]
    fn voting_members_outages_and_older_builds_renew() {
        let now = 10 * FRESH_MS;
        let mut hosting = running();
        let cases = [
            (
                "a member that nullified once",
                voted("serving", Some(1), now, now),
            ),
            ("an outage", voted("serving", Some(0), 0, now)),
            ("an older build", voted("serving", None, now, now)),
        ];
        for (filter, (case, report)) in cases.iter().enumerate() {
            let filter = vec![filter as u8 + 2; 32];
            for frame in (0..=2 * EPOCH).step_by(10) {
                let observed = classify(Some(report), now);
                hosting.observe(frame, EPOCH, &filter, 1, Seat::Member, observed.clone());
                hosting.observe_votes(
                    frame,
                    EPOCH,
                    &filter,
                    1,
                    Seat::Member,
                    &observed,
                    Instance::of(Some(report)),
                );
                assert!(
                    hosting.withhold(&filter, frame, EPOCH).is_none(),
                    "{case} at {frame}"
                );
            }
        }
        assert!(hosting.held_back().is_empty());
    }

    /// Engines report the seat-only refusal under this name.
    #[test]
    fn the_seat_only_refusal_is_a_reported_blocker() {
        assert!(crate::worker_execution::BLOCKERS.contains(&REFUSED_FOR_SEAT_ONLY));
    }

    fn absent() -> Hosting {
        Hosting::Absent {
            state: "blocked".into(),
            blocker: "predecessor state".into(),
        }
    }

    fn refused_for_seat_only() -> Hosting {
        Hosting::Absent {
            state: "blocked".into(),
            blocker: REFUSED_FOR_SEAT_ONLY.into(),
        }
    }

    /// Hosting that started long before the frames observed below.
    fn running() -> SessionHosting {
        let mut hosting = SessionHosting::default();
        hosting.observe(0, EPOCH, &[0; 32], 0, Seat::Member, Hosting::Hosting);
        hosting
    }

    fn withheld(hold: Option<Hold>) -> Option<Withheld> {
        match hold {
            Some(Hold::Withheld(withheld)) => Some(withheld),
            _ => None,
        }
    }

    /// A member seat is withheld only after a full epoch without its worker
    /// hosting; hosting, leaving the session before that, rebinding or
    /// unbinding resets it, and an unknown report neither starts nor ends
    /// the run.
    #[test]
    fn a_member_seat_is_withheld_after_an_epoch_unhosted() {
        let filter = vec![1; 32];
        let mut hosting = running();
        hosting.observe(100, EPOCH, &filter, 1, Seat::Member, Hosting::Unknown);
        assert!(
            hosting.withhold(&filter, 2_000, EPOCH).is_none(),
            "unknown starts nothing"
        );
        hosting.observe(100, EPOCH, &filter, 1, Seat::Member, absent());
        hosting.observe(500, EPOCH, &filter, 1, Seat::Member, Hosting::Unknown);
        assert!(hosting.withhold(&filter, 819, EPOCH).is_none());
        let first = withheld(hosting.withhold(&filter, 820, EPOCH)).expect("an epoch unhosted");
        assert_eq!(
            (first.run.core_id, first.run.since, first.run.state.as_str()),
            (1, 100, "blocked")
        );
        assert!(first.first && !first.run.from_start);
        assert!(
            !withheld(hosting.withhold(&filter, 821, EPOCH))
                .unwrap()
                .first,
            "reported once per run"
        );

        let ended = hosting.observe(830, EPOCH, &filter, 1, Seat::Member, Hosting::Hosting);
        assert_eq!(
            ended.map(|run| run.since),
            Some(100),
            "the withheld run is returned as it ends"
        );
        assert!(
            hosting.withhold(&filter, 5_000, EPOCH).is_none(),
            "hosting ends the run"
        );

        hosting.observe(900, EPOCH, &filter, 1, Seat::Member, absent());
        hosting.observe(1_000, EPOCH, &filter, 2, Seat::Member, absent());
        assert!(
            hosting.withhold(&filter, 1_700, EPOCH).is_none(),
            "a rebound seat starts over"
        );
        assert!(hosting.withhold(&filter, 1_720, EPOCH).is_some());

        hosting.observe(1_800, EPOCH, &filter, 3, Seat::Member, absent());
        hosting.observe(1_900, EPOCH, &filter, 3, Seat::Outside, absent());
        hosting.observe(1_900, EPOCH, &filter, 3, Seat::Lapsed, absent());
        assert!(
            hosting.withhold(&filter, 5_000, EPOCH).is_none(),
            "a seat that leaves its session before its renewal is withheld owes no hosting"
        );

        hosting.observe(2_000, EPOCH, &filter, 3, Seat::Member, absent());
        hosting.retain_bound(&HashSet::new());
        assert!(
            hosting.withhold(&filter, 5_000, EPOCH).is_none(),
            "an unbound seat is forgotten"
        );
    }

    /// A withheld renewal stays withheld when the seat lapses and leaves its
    /// session, until the worker passes its state checks and is refused only
    /// for its seat; another worker bound to the seat starts over.
    #[test]
    fn a_withheld_seat_stays_withheld_after_it_lapses() {
        let filter = vec![1; 32];
        let mut hosting = running();
        hosting.observe(100, EPOCH, &filter, 1, Seat::Member, absent());
        assert!(
            withheld(hosting.withhold(&filter, 820, EPOCH))
                .unwrap()
                .first
        );
        for (frame, seat, observed) in [
            (1_440, Seat::Lapsed, absent()),
            (1_450, Seat::Lapsed, Hosting::Unknown),
            (1_460, Seat::Outside, absent()),
            (1_470, Seat::Member, refused_for_seat_only()),
        ] {
            assert!(hosting
                .observe(frame, EPOCH, &filter, 1, seat, observed)
                .is_none());
            let still = withheld(hosting.withhold(&filter, frame, EPOCH)).expect("still withheld");
            assert!(!still.first && still.run.since == 100, "{frame}");
        }
        let ended = hosting.observe(
            1_480,
            EPOCH,
            &filter,
            1,
            Seat::Lapsed,
            refused_for_seat_only(),
        );
        assert_eq!(
            ended.map(|run| run.since),
            Some(100),
            "refused only for its seat, it can host again"
        );
        assert!(hosting.withhold(&filter, 1_480, EPOCH).is_none());

        hosting.observe(1_500, EPOCH, &filter, 1, Seat::Member, absent());
        assert!(hosting.withhold(&filter, 2_220, EPOCH).is_some());
        hosting.observe(2_400, EPOCH, &filter, 1, Seat::Lapsed, absent());
        hosting.observe(2_410, EPOCH, &filter, 2, Seat::Lapsed, absent());
        assert!(
            hosting.withhold(&filter, 2_410, EPOCH).is_none(),
            "a newly bound worker starts over"
        );
    }

    /// A start refused only for the seat is reported as a wait for the
    /// boundary that seats the worker; with the same blocker it shows a
    /// worker able to host, as the refusal did.
    #[test]
    fn a_seat_only_wait_shows_a_worker_able_to_host() {
        let now = 10 * FRESH_MS;
        let wait = WorkerExecution {
            state: "waiting".into(),
            blocker: REFUSED_FOR_SEAT_ONLY.into(),
            observed_unix_ms: now,
            awaited_frame: Some(919_440),
            ..Default::default()
        };
        let filter = vec![1; 32];
        let mut hosting = running();
        hosting.observe(100, EPOCH, &filter, 1, Seat::Member, absent());
        assert!(withheld(hosting.withhold(&filter, 820, EPOCH)).is_some());
        let ended = hosting.observe(
            1_440,
            EPOCH,
            &filter,
            1,
            Seat::Lapsed,
            classify(Some(&wait), now),
        );
        assert_eq!(ended.map(|run| run.since), Some(100));
    }

    /// After a start, a member or lapsed seat whose worker is seen unable to
    /// host waits out the settle period and is then withheld until the
    /// worker can host; a seat not yet seated, an unobservable worker, one
    /// that hosts and a seat first seen after the period renew as before.
    #[test]
    fn after_a_start_a_seat_whose_worker_cannot_host_waits_then_is_withheld() {
        let settled = 1_000 + settle_frames(EPOCH);
        let [member, lapsed, outside, unknown, hosts, late] =
            [1u8, 2, 3, 4, 5, 6].map(|b| vec![b; 32]);
        let mut hosting = SessionHosting::default();
        hosting.observe(1_000, EPOCH, &member, 1, Seat::Member, absent());
        hosting.observe(1_000, EPOCH, &lapsed, 2, Seat::Lapsed, absent());
        hosting.observe(1_000, EPOCH, &outside, 3, Seat::Outside, absent());
        hosting.observe(1_000, EPOCH, &unknown, 4, Seat::Lapsed, Hosting::Unknown);
        hosting.observe(1_000, EPOCH, &hosts, 5, Seat::Member, Hosting::Hosting);
        for frame in [1_000, settled - 1] {
            for filter in [&member, &lapsed] {
                assert_eq!(
                    hosting.withhold(filter, frame, EPOCH),
                    Some(Hold::Settling { until: settled })
                );
            }
            for filter in [&outside, &unknown, &hosts] {
                assert!(hosting.withhold(filter, frame, EPOCH).is_none());
            }
        }
        assert!(
            hosting.report_settling() && !hosting.report_settling(),
            "reported once"
        );
        for filter in [&member, &lapsed] {
            let first =
                withheld(hosting.withhold(filter, settled, EPOCH)).expect("withheld once settled");
            assert!(first.first && first.run.from_start && first.run.since == 1_000);
        }
        assert!(hosting
            .observe(settled, EPOCH, &member, 1, Seat::Member, Hosting::Hosting)
            .is_some());
        assert!(hosting
            .observe(
                settled,
                EPOCH,
                &lapsed,
                2,
                Seat::Lapsed,
                refused_for_seat_only()
            )
            .is_some());
        for filter in [&member, &lapsed] {
            assert!(
                hosting.withhold(filter, settled, EPOCH).is_none(),
                "the worker's current state lifts it"
            );
        }

        hosting.observe(settled, EPOCH, &late, 6, Seat::Lapsed, absent());
        assert!(
            hosting.withhold(&late, settled, EPOCH).is_none(),
            "first seen after the settle period"
        );
        hosting.observe(settled, EPOCH, &late, 6, Seat::Member, absent());
        assert!(hosting
            .withhold(&late, settled + EPOCH - 1, EPOCH)
            .is_none());
        assert!(hosting.withhold(&late, settled + EPOCH, EPOCH).is_some());
    }
}
