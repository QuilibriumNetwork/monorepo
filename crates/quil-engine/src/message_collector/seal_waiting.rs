//! The refused storage epoch proof the next room freed in its share goes to
//! ([`SealWaiting`]).

use super::{share_label, CollectedMessage, Share};
use std::time::{Duration, Instant};

/// How long a waiting proof keeps its room after its last refusal: its
/// sender resends it within about a minute while its window is open (a
/// room refusal rests it 40-60 seconds, any other retry at most 60), and
/// stops once another archive accepts it. Three times that minute, so one
/// late resend keeps it waiting and a sender that stopped frees the room.
pub(super) const SEAL_WAIT_STALE: Duration = Duration::from_secs(180);

/// Refusals of one proof before its share keeps room for it: the second
/// shows its sender still resends it.
const SEAL_WAIT_REFUSALS: u32 = 2;

/// A refused proof the next room freed goes to.
#[derive(Clone, Copy, Debug)]
struct Waiting {
    hash: [u8; 32],
    /// Its window end ([`CollectedMessage::window_end`]).
    end: u64,
    len: usize,
    refusals: u32,
    first: Instant,
    last: Instant,
}

impl Waiting {
    /// Its share keeps room for it.
    fn active(&self) -> bool {
        self.refusals >= SEAL_WAIT_REFUSALS
    }
}

/// Where a waiting proof stands outside its wait, read under the buffers'
/// lock when its share is next consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Found {
    /// Neither held here nor carried by a finalized frame.
    Absent,
    /// Held here at some rank, in the active provers' share if `prover`.
    Held { prover: bool },
    /// A finalized frame carried it: no frame carries it again.
    Included,
}

impl Found {
    /// The proof waiting in the `prover` share needs no more room. A copy
    /// in the provers' share ends either wait; another sender's copy ends
    /// only the other senders' wait, as an active prover's copy still
    /// needs room in the provers' share to promote it.
    fn ends(self, prover: bool) -> bool {
        match self {
            Found::Absent => false,
            Found::Held { prover: held } => held || !prover,
            Found::Included => true,
        }
    }
}

/// Why a proof stopped waiting, for its line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// It was held here, or a finalized frame carried it ([`Found::ends`]).
    Held,
    /// Its sender did not send it again within [`SEAL_WAIT_STALE`].
    Stale,
    /// Its window ended.
    Closed,
    /// A refused proof due sooner, or a larger one due with it, waits
    /// instead.
    Superseded,
}

impl Ended {
    fn as_str(self) -> &'static str {
        match self {
            Ended::Held => "held",
            Ended::Stale => "stale",
            Ended::Closed => "window_ended",
            Ended::Superseded => "superseded",
        }
    }
}

/// For each share of held storage epoch proofs, the refused proof whose
/// window ends soonest: once its sender sends it again, the share keeps its
/// bytes free of every proof due no sooner, so the room frames free gathers
/// for it. Without it, proofs of about 1 MB took each megabyte a frame
/// freed, and a 4 MB proof due with them was refused on all 22 sends over
/// 15 minutes until its window ended; the free room never passed 1.39 MB
/// (2026-11-25). Of two proofs due together the larger waits: room for it
/// fits the smaller, and a proof as small as the room a frame frees needs no
/// wait. Taken under the buffers' lock only.
///
/// A wait ends however its proof is held or carried: each consult reads
/// where both shares' waiting proofs stand ([`Found`]) before it keeps any
/// room, so no hold or carry path has to report it. Until 2026-11-25 only a
/// plain submit's hold in its own share ended it, and a proof promoted,
/// carried by another archive's frame or re-filed kept its room for up to
/// [`SEAL_WAIT_STALE`].
#[derive(Default)]
pub(super) struct SealWaiting {
    prover: Option<Waiting>,
    other: Option<Waiting>,
}

impl SealWaiting {
    fn slot(&mut self, prover: bool) -> &mut Option<Waiting> {
        if prover {
            &mut self.prover
        } else {
            &mut self.other
        }
    }

    /// The bytes `message`, a submitted proof, must leave free in its share
    /// held with it: the waiting proof's, unless `message` is that proof or
    /// due sooner. `frame` is the next GLOBAL frame to finalize, 0 unknown;
    /// `found` tells where a proof with a given hash stands.
    pub(super) fn keep(
        &mut self,
        message: &CollectedMessage,
        frame: u64,
        now: Instant,
        found: impl Fn(&[u8; 32]) -> Found,
    ) -> usize {
        if !message.held_seal() {
            return 0;
        }
        self.settle(frame, now, found);
        match self.slot(message.prover) {
            Some(waiting)
                if waiting.active()
                    && waiting.hash != message.hash
                    && message.window_end.is_none_or(|end| end >= waiting.end) =>
            {
                waiting.len
            }
            _ => 0,
        }
    }

    /// `message` was refused for its full share: it waits if its window
    /// ends sooner than the waiting proof's, or with it and it is larger,
    /// or none waits.
    pub(super) fn refused(
        &mut self,
        message: &CollectedMessage,
        frame: u64,
        now: Instant,
        found: impl Fn(&[u8; 32]) -> Found,
    ) {
        let Some(end) = message
            .window_end
            .filter(|end| message.held_seal() && (frame == 0 || *end > frame))
        else {
            return;
        };
        self.settle(frame, now, found);
        let prover = message.prover;
        let slot = self.slot(prover);
        match slot {
            Some(waiting) if waiting.hash == message.hash => {
                waiting.refusals = waiting.refusals.saturating_add(1);
                waiting.last = now;
                waiting.len = message.data.len();
                if waiting.refusals == SEAL_WAIT_REFUSALS {
                    tracing::info!(
                        scope = "network",
                        action = "wait",
                        share = share_label(share(prover)),
                        bytes = waiting.len,
                        window_end = waiting.end,
                        refusals = waiting.refusals,
                        stale_secs = SEAL_WAIT_STALE.as_secs(),
                        "message collector: keeping room in a full storage epoch proof share for the refused proof due soonest; proofs due no later are refused until it is held, so frames that free room free it for this proof; ends when it is held, its window ends, or its sender sends it no more for stale_secs"
                    );
                }
            }
            Some(waiting)
                if (end, std::cmp::Reverse(message.data.len()))
                    >= (waiting.end, std::cmp::Reverse(waiting.len)) => {}
            _ => {
                if let Some(old) = slot.take() {
                    end_line(old, prover, Ended::Superseded, now);
                }
                *slot = Some(Waiting {
                    hash: message.hash,
                    end,
                    len: message.data.len(),
                    refusals: 1,
                    first: now,
                    last: now,
                });
            }
        }
    }

    /// End each share's wait that is over: its proof held or carried
    /// ([`Found::ends`]), its window ended at `frame`, or its sender
    /// stopped. Called on every consult, and right after a hold so its line
    /// times the wait.
    pub(super) fn settle(&mut self, frame: u64, now: Instant, found: impl Fn(&[u8; 32]) -> Found) {
        for prover in [true, false] {
            expire(self.slot(prover), prover, frame, now, &found);
        }
    }

    /// The proof waiting in the `prover` share, as (bytes, window end, keeping
    /// room for it), for tests.
    #[cfg(test)]
    pub(super) fn waiting(&self, prover: bool) -> Option<(usize, u64, bool)> {
        let slot = if prover { &self.prover } else { &self.other };
        slot.map(|waiting| (waiting.len, waiting.end, waiting.active()))
    }
}

/// The share of held proofs `prover` names.
fn share(prover: bool) -> Share {
    if prover {
        Share::Seals
    } else {
        Share::OtherSeals
    }
}

/// End the proof waiting in `slot`, of the `prover` share, if `found` finds
/// it held or carried, its window has ended at `frame`, or its sender
/// stopped sending it.
fn expire(
    slot: &mut Option<Waiting>,
    prover: bool,
    frame: u64,
    now: Instant,
    found: &impl Fn(&[u8; 32]) -> Found,
) {
    let Some(waiting) = *slot else {
        return;
    };
    let why = if found(&waiting.hash).ends(prover) {
        Ended::Held
    } else if frame != 0 && waiting.end <= frame {
        Ended::Closed
    } else if now.saturating_duration_since(waiting.last) > SEAL_WAIT_STALE {
        Ended::Stale
    } else {
        return;
    };
    *slot = None;
    end_line(waiting, prover, why, now);
}

/// Log the end of `waiting`'s wait, if its share kept room for it.
fn end_line(waiting: Waiting, prover: bool, why: Ended, now: Instant) {
    if !waiting.active() {
        return;
    }
    tracing::info!(
        scope = "network",
        share = share_label(share(prover)),
        outcome = why.as_str(),
        bytes = waiting.len,
        window_end = waiting.end,
        refusals = waiting.refusals,
        waited_secs = now.saturating_duration_since(waiting.first).as_secs(),
        "message collector: stopped keeping room for a refused storage epoch proof; held: it was held here or a finalized frame carried it, by waited_secs after its first refusal; window_ended or stale: its window ended or its sender sent it no more, and the room is free again; superseded: a refused proof due sooner, or a larger one due with it, waits instead"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(hash: u8, end: u64, len: usize) -> CollectedMessage {
        let mut message = CollectedMessage::new(Vec::new());
        message.hash = [hash; 32];
        message.seal = true;
        message.window_end = Some(end);
        message.data = vec![0; len];
        message
    }

    fn absent(_: &[u8; 32]) -> Found {
        Found::Absent
    }

    /// Where `hash` stands if `copy` is held, in the provers' share if
    /// `prover`.
    fn held(hash: &[u8; 32], copy: &CollectedMessage, prover: bool) -> Found {
        if *hash == copy.hash {
            Found::Held { prover }
        } else {
            Found::Absent
        }
    }

    /// A waiting proof keeps room only once sent again, for proofs due no
    /// sooner than it, and frees it once held, past its window, or no
    /// longer sent.
    #[test]
    fn a_waiting_proof_keeps_room_until_held_closed_or_stale() {
        let now = Instant::now();
        let big = proof(1, 100, 4_000_000);
        let small = proof(2, 100, 1_000_000);
        let sooner = proof(3, 90, 1_000_000);
        let mut waiting = SealWaiting::default();
        waiting.refused(&big, 10, now, absent);
        assert_eq!(
            waiting.keep(&small, 10, now, absent),
            0,
            "one refusal keeps no room"
        );
        waiting.refused(&big, 10, now, absent);
        let kept = waiting.keep(&small, 10, now, absent);
        eprintln!("REACH seal-waiting kept={kept}");
        assert_eq!(
            kept, 4_000_000,
            "SEAL-WAITING: a waiting proof kept no room"
        );
        assert_eq!(
            waiting.keep(&big, 10, now, absent),
            0,
            "nothing kept from itself"
        );
        assert_eq!(
            waiting.keep(&sooner, 10, now, absent),
            0,
            "a proof due sooner rides first"
        );
        waiting.refused(&small, 10, now, absent);
        assert_eq!(
            waiting.waiting(true),
            Some((4_000_000, 100, true)),
            "a smaller one waits after"
        );

        waiting.settle(10, now, |hash| held(hash, &big, true));
        assert_eq!(waiting.waiting(true), None);

        waiting.refused(&big, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        assert_eq!(
            waiting.keep(&small, 100, now, absent),
            0,
            "its window ended"
        );
        assert_eq!(waiting.waiting(true), None);

        waiting.refused(&big, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        let later = now + SEAL_WAIT_STALE + Duration::from_secs(1);
        assert_eq!(
            waiting.keep(&small, 10, later, absent),
            0,
            "its sender stopped"
        );
        assert_eq!(waiting.waiting(true), None);

        waiting.refused(&small, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        assert_eq!(
            waiting.waiting(true),
            Some((4_000_000, 100, false)),
            "a larger one waits"
        );
        waiting.refused(&sooner, 10, now, absent);
        assert_eq!(
            waiting.waiting(true),
            Some((1_000_000, 90, false)),
            "a sooner one waits"
        );
        let other = CollectedMessage {
            prover: false,
            ..proof(4, 100, 1_000_000)
        };
        assert_eq!(
            waiting.keep(&other, 10, now, absent),
            0,
            "the other share keeps its own"
        );
    }

    /// A waiting proof keeps its room until more than [`SEAL_WAIT_STALE`]
    /// passed since its last refusal: a resend at exactly that much keeps
    /// it waiting.
    #[test]
    fn a_waiting_proof_keeps_room_at_exactly_its_stale_time() {
        let now = Instant::now();
        let big = proof(1, 100, 4_000_000);
        let small = proof(2, 100, 1_000_000);
        let mut waiting = SealWaiting::default();
        waiting.refused(&big, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        let kept = waiting.keep(&small, 10, now + SEAL_WAIT_STALE, absent);
        eprintln!("REACH seal-stale kept={kept}");
        assert_eq!(
            kept,
            4_000_000,
            "SEAL-STALE-EDGE: a proof refused exactly {}s ago kept no room",
            SEAL_WAIT_STALE.as_secs()
        );
        let later = now + SEAL_WAIT_STALE + Duration::from_millis(1);
        assert_eq!(waiting.keep(&small, 10, later, absent), 0);
    }

    /// A wait ends once its proof is held in its own share or the provers',
    /// or carried by a finalized frame, read on the share's next consult; an
    /// active prover's proof whose other sender's copy is held still waits.
    #[test]
    fn a_wait_ends_once_its_proof_is_held_or_carried() {
        let now = Instant::now();
        let big = proof(1, 100, 4_000_000);
        let other_big = CollectedMessage {
            prover: false,
            ..proof(1, 100, 4_000_000)
        };
        let small = proof(2, 100, 1_000_000);
        let other_small = CollectedMessage {
            prover: false,
            ..proof(2, 100, 1_000_000)
        };
        let wait = |message: &CollectedMessage| {
            let mut waiting = SealWaiting::default();
            waiting.refused(message, 10, now, absent);
            waiting.refused(message, 10, now, absent);
            waiting
        };

        let mut waiting = wait(&big);
        let kept = waiting.keep(&small, 10, now, |hash| held(hash, &big, false));
        eprintln!("REACH seal-wait-end other-copy kept={kept}");
        assert_eq!(
            kept, 4_000_000,
            "SEAL-END-SHARE: another sender's copy held ended a prover's wait"
        );

        let mut waiting = wait(&other_big);
        let kept = waiting.keep(&small, 10, now, |hash| held(hash, &big, true));
        assert_eq!(
            waiting.waiting(false),
            None,
            "SEAL-END-PROVER: a prover's copy held left the other senders' wait"
        );
        assert_eq!(kept, 0);
        assert_eq!(
            waiting.keep(&other_small, 10, now, absent),
            0,
            "SEAL-END-PROVER: room kept after the prover's copy was held"
        );

        for prover in [true, false] {
            let waiter = if prover { &big } else { &other_big };
            let consult = if prover { &small } else { &other_small };
            let mut waiting = wait(waiter);
            let kept = waiting.keep(consult, 10, now, |hash| {
                if *hash == big.hash {
                    Found::Included
                } else {
                    Found::Absent
                }
            });
            eprintln!("REACH seal-wait-end included prover={prover} kept={kept}");
            assert_eq!(
                (kept, waiting.waiting(prover)),
                (0, None),
                "SEAL-END-INCLUDED: a proof a frame carried kept its wait (prover share {prover})"
            );
        }
    }
}
