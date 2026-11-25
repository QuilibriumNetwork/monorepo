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

/// Why a proof stopped waiting, for its line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// It was held.
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
    /// due sooner. `frame` is the next GLOBAL frame to finalize, 0 unknown.
    pub(super) fn keep(&mut self, message: &CollectedMessage, frame: u64, now: Instant) -> usize {
        if !message.held_seal() {
            return 0;
        }
        let slot = self.slot(message.prover);
        expire(slot, message.prover, frame, now);
        match slot {
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
    pub(super) fn refused(&mut self, message: &CollectedMessage, frame: u64, now: Instant) {
        let Some(end) = message
            .window_end
            .filter(|end| message.held_seal() && (frame == 0 || *end > frame))
        else {
            return;
        };
        let prover = message.prover;
        let slot = self.slot(prover);
        expire(slot, prover, frame, now);
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

    /// The proof with `hash`, of the `prover` share, was held.
    pub(super) fn held(&mut self, prover: bool, hash: &[u8; 32], now: Instant) {
        let slot = self.slot(prover);
        if slot.is_some_and(|waiting| waiting.hash == *hash) {
            if let Some(waiting) = slot.take() {
                end_line(waiting, prover, Ended::Held, now);
            }
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

/// End the proof waiting in `slot` if its window has ended at `frame` or its
/// sender stopped sending it.
fn expire(slot: &mut Option<Waiting>, prover: bool, frame: u64, now: Instant) {
    let Some(waiting) = *slot else {
        return;
    };
    let why = if frame != 0 && waiting.end <= frame {
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
        "message collector: stopped keeping room for a refused storage epoch proof; held: it was admitted waited_secs after its first refusal; window_ended or stale: its window ended or its sender sent it no more, and the room is free again; superseded: a refused proof due sooner, or a larger one due with it, waits instead"
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
        waiting.refused(&big, 10, now);
        assert_eq!(
            waiting.keep(&small, 10, now),
            0,
            "one refusal keeps no room"
        );
        waiting.refused(&big, 10, now);
        let kept = waiting.keep(&small, 10, now);
        eprintln!("REACH seal-waiting kept={kept}");
        assert_eq!(
            kept, 4_000_000,
            "SEAL-WAITING: a waiting proof kept no room"
        );
        assert_eq!(waiting.keep(&big, 10, now), 0, "nothing kept from itself");
        assert_eq!(
            waiting.keep(&sooner, 10, now),
            0,
            "a proof due sooner rides first"
        );
        waiting.refused(&small, 10, now);
        assert_eq!(
            waiting.waiting(true),
            Some((4_000_000, 100, true)),
            "a smaller one waits after"
        );

        waiting.held(true, &big.hash, now);
        assert_eq!(waiting.waiting(true), None);

        waiting.refused(&big, 10, now);
        waiting.refused(&big, 10, now);
        assert_eq!(waiting.keep(&small, 100, now), 0, "its window ended");
        assert_eq!(waiting.waiting(true), None);

        waiting.refused(&big, 10, now);
        waiting.refused(&big, 10, now);
        let later = now + SEAL_WAIT_STALE + Duration::from_secs(1);
        assert_eq!(waiting.keep(&small, 10, later), 0, "its sender stopped");
        assert_eq!(waiting.waiting(true), None);

        waiting.refused(&small, 10, now);
        waiting.refused(&big, 10, now);
        assert_eq!(
            waiting.waiting(true),
            Some((4_000_000, 100, false)),
            "a larger one waits"
        );
        waiting.refused(&sooner, 10, now);
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
            waiting.keep(&other, 10, now),
            0,
            "the other share keeps its own"
        );
    }
}
