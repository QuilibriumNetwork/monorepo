//! What the GLOBAL mempool held when this archive copied it for its own
//! proposal, and what reached it since the copy before.
//!
//! One archive's proposals carried about 10 shard headers where the others'
//! carried about 95 (2026-11-04), and no line said whether the headers never
//! arrived, were refused, waited unverified, or arrived after the copy: the
//! cause took a log join across four archives. The proposal line
//! ("proving next global state") now carries this summary.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Why a submit reached the collector and what became of it, counted for
/// [`PoolIntake`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Intake {
    /// A shard frame was filed.
    Accepted,
    /// A shard frame was filed unverified: committed state cannot judge it
    /// yet (its anchor or session is not executed here).
    HeldUnverifiable,
    /// A shard frame was filed unverified: every verification slot was busy,
    /// or another copy's verdict was slow.
    HeldVerifierBusy,
    /// Refused: the rank's count or byte cap is reached.
    RefusedRankFull,
    /// Refused: it waits for GLOBAL execution and no place is left for it.
    RefusedAwaitingExecution,
    /// Refused: verification failed or the encoding is not canonical.
    RefusedInvalid,
    /// Refused: its address is not in this node's committed shard set.
    RefusedUnknownShard,
}

const KINDS: usize = 7;

impl Intake {
    fn index(self) -> usize {
        self as usize
    }
}

/// Submits counted since the last proposal copy, with when the last shard
/// frame was accepted and the last finalized frame published.
pub(crate) struct PoolIntake {
    counts: [AtomicU64; KINDS],
    last_accepted: Mutex<Option<Instant>>,
    published: Mutex<Option<Instant>>,
    /// The verification gate's drops when the last copy was taken.
    gate_dropped_at_copy: AtomicU64,
}

impl Default for PoolIntake {
    fn default() -> Self {
        Self {
            counts: Default::default(),
            last_accepted: Mutex::new(None),
            published: Mutex::new(None),
            gate_dropped_at_copy: AtomicU64::new(0),
        }
    }
}

impl PoolIntake {
    pub(crate) fn note(&self, intake: Intake, now: Instant) {
        self.counts[intake.index()].fetch_add(1, Ordering::Relaxed);
        if intake == Intake::Accepted {
            if let Ok(mut last) = self.last_accepted.lock() {
                *last = Some(now);
            }
        }
    }

    /// A finalized frame published here.
    pub(crate) fn note_published(&self, now: Instant) {
        if let Ok(mut published) = self.published.lock() {
            *published = Some(now);
        }
    }

    /// The counts since the previous call, cleared, with the ages of the last
    /// accepted shard frame and the last publication at `now`, and the gate's
    /// drops since the previous call given its total `gate_dropped`.
    pub(crate) fn take(&self, now: Instant, gate_dropped: u64) -> IntakeWindow {
        let count = |intake: Intake| self.counts[intake.index()].swap(0, Ordering::Relaxed);
        let age = |at: &Mutex<Option<Instant>>| {
            at.lock()
                .ok()
                .and_then(|at| *at)
                .map(|at| now.saturating_duration_since(at))
        };
        let previous = self
            .gate_dropped_at_copy
            .swap(gate_dropped, Ordering::Relaxed);
        IntakeWindow {
            accepted: count(Intake::Accepted),
            held_unverifiable: count(Intake::HeldUnverifiable),
            held_verifier_busy: count(Intake::HeldVerifierBusy),
            refused_rank_full: count(Intake::RefusedRankFull),
            refused_awaiting_execution: count(Intake::RefusedAwaitingExecution),
            refused_invalid: count(Intake::RefusedInvalid),
            refused_unknown_shard: count(Intake::RefusedUnknownShard),
            gate_dropped: gate_dropped.saturating_sub(previous),
            since_accepted_ms: age(&self.last_accepted).map(|d| d.as_millis() as u64),
            since_published_ms: age(&self.published).map(|d| d.as_millis() as u64),
        }
    }
}

/// [`PoolIntake::take`]: shard-frame submits since the previous proposal copy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IntakeWindow {
    pub accepted: u64,
    pub held_unverifiable: u64,
    pub held_verifier_busy: u64,
    pub refused_rank_full: u64,
    pub refused_awaiting_execution: u64,
    pub refused_invalid: u64,
    pub refused_unknown_shard: u64,
    /// Shard-frame submits the verification gate refused before the
    /// collector saw them (the sender retries).
    pub gate_dropped: u64,
    /// Since the last shard frame was accepted; `None` if none was.
    pub since_accepted_ms: Option<u64>,
    /// Since this node last published a finalized frame; `None` if it has
    /// not since it started.
    pub since_published_ms: Option<u64>,
}

/// The mempool's shard proofs when a GLOBAL proposal copied it, by anchor
/// and verification, with the intake since the previous copy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProposalPool {
    /// Shards with a proof the proposed frame can carry.
    pub shards: usize,
    /// Single-shard proofs anchored to the proposal's parent.
    pub anchored_parent: usize,
    /// Single-shard proofs anchored to an earlier frame within the lockstep
    /// window.
    pub anchored_earlier: usize,
    /// Proofs the proposed frame cannot carry (anchor outside the window).
    pub out_of_window: usize,
    /// Carriable single-shard proofs held verified, and unverified.
    pub verified: usize,
    pub unverified: usize,
    /// Shard-frame verifications running in the collector, and verification
    /// tasks admitted by the node's gate (running or waiting for a slot).
    pub verifying: usize,
    pub gate_in_flight: usize,
    pub intake: IntakeWindow,
}

/// `Some(ms)` as the number, `None` as -1, for a log field.
pub(crate) fn ms_field(ms: Option<u64>) -> i64 {
    ms.map_or(-1, |ms| i64::try_from(ms).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_window_counts_since_the_previous_copy_and_clears() {
        let intake = PoolIntake::default();
        let start = Instant::now();
        let none = intake.take(start, 0);
        assert_eq!(
            none,
            IntakeWindow::default(),
            "nothing accepted or published yet"
        );
        intake.note(Intake::Accepted, start);
        intake.note(Intake::HeldUnverifiable, start);
        intake.note(Intake::HeldUnverifiable, start);
        intake.note(Intake::RefusedRankFull, start);
        intake.note_published(start + Duration::from_millis(500));
        let window = intake.take(start + Duration::from_secs(2), 7);
        assert_eq!(
            window,
            IntakeWindow {
                accepted: 1,
                held_unverifiable: 2,
                refused_rank_full: 1,
                gate_dropped: 7,
                since_accepted_ms: Some(2_000),
                since_published_ms: Some(1_500),
                ..Default::default()
            }
        );
        let next = intake.take(start + Duration::from_secs(3), 9);
        assert_eq!(
            next.accepted + next.held_unverifiable + next.refused_rank_full,
            0
        );
        assert_eq!(next.gate_dropped, 2, "drops since the previous copy only");
        assert_eq!(
            next.since_accepted_ms,
            Some(3_000),
            "the last accept is kept"
        );
        assert_eq!(ms_field(None), -1);
    }
}
