//! The refused storage epoch proof the next room freed in its share goes to
//! ([`SealWaiting`]).

use super::{share_label, CollectedMessage, Share};
use sha3::{Digest, Sha3_256};
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

/// This node's proposals, each of its own frame, that pass over a waiting
/// proof not yet held before its wait ends ([`SealWaiting::passed`]): as
/// many as pass over a held proof before it yields its room
/// ([`super::SEAL_PASSES_TO_YIELD`]), about 29 minutes. A held proof rides
/// only this node's proposals, so the room a wait gathers frees as their
/// frames finalize: one pass would end a wait at the proposal whose frame
/// frees its room, before its sender sends it again, and a few would when
/// this node leads consecutive frames. A proof whose wait they ended waits
/// no more before its window ends ([`SealWaiting::passed_over`]).
const SEAL_WAIT_PASSES: u32 = super::SEAL_PASSES_TO_YIELD;

/// A refused proof the next room freed goes to.
#[derive(Clone, Copy, Debug)]
struct Waiting {
    hash: [u8; 32],
    /// What identifies it ([`proof_key`]).
    key: [u8; 32],
    /// Its window end ([`CollectedMessage::window_end`]).
    end: u64,
    len: usize,
    refusals: u32,
    /// This node's proposals that passed over it, each frame's once, and
    /// the last one's frame.
    passes: u32,
    passed: u64,
    first: Instant,
    last: Instant,
}

impl Waiting {
    /// Its share keeps room for it.
    fn active(&self) -> bool {
        self.refusals >= SEAL_WAIT_REFUSALS
    }
}

/// Where the waiting proof stands outside its wait, read under the
/// buffers' lock when its share is next consulted.
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
    /// The waiting proof needs no more room: a copy is held in the
    /// provers' share, or a frame carried it. Another sender's copy held
    /// does not end it: promoting that copy still needs room in the
    /// provers' share.
    fn ends(self) -> bool {
        match self {
            Found::Absent => false,
            Found::Held { prover } => prover,
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
    /// [`SEAL_WAIT_PASSES`] of this node's proposals passed over it: it
    /// waits no more before its window ends.
    PassedOver,
    /// Its window ended.
    Closed,
    /// A refused proof due sooner, or a larger one due with it, waits
    /// instead.
    Superseded,
}

impl Ended {
    /// Every way a wait ends, as both its lines list them ([`ends_text`]).
    const ALL: [Ended; 5] = [
        Ended::Held,
        Ended::Closed,
        Ended::Stale,
        Ended::PassedOver,
        Ended::Superseded,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Ended::Held => "held",
            Ended::Stale => "stale",
            Ended::PassedOver => "passed_over",
            Ended::Closed => "window_ended",
            Ended::Superseded => "superseded",
        }
    }

    /// What it means, for the lines.
    fn meaning(self) -> &'static str {
        match self {
            Ended::Held => "it was held here or a finalized frame carried it",
            Ended::Stale => "its sender sent it no more for stale_secs",
            Ended::PassedOver => {
                "passes of this node's proposals passed over it while it was not held; it waits no more before its window ends"
            }
            Ended::Closed => "its window ended",
            Ended::Superseded => "a refused proof due sooner, or a larger one due with it, waits instead",
        }
    }
}

/// Each way a wait ends and what it means ([`Ended::ALL`]): the wait's
/// start and end lines both carry it.
fn ends_text() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        Ended::ALL
            .iter()
            .map(|ended| format!("{}: {}", ended.as_str(), ended.meaning()))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

/// The refused storage epoch proof whose window ends soonest, of those
/// that may wait ([`CollectedMessage::may_wait`]: only the active
/// provers' share holds them, [`Share::waits`]) and that are due within an
/// epoch ([`within_reach`]): once its sender sends it again, the provers'
/// share keeps its bytes free of every proof due no sooner, so the room
/// frames free gathers for it. Without it, proofs of about 1 MB took each
/// megabyte a frame freed, and a 4 MB proof due with them was refused on
/// all 22 sends over 15 minutes until its window ended; the free room never
/// passed 1.39 MB (2026-11-25). Of two proofs due together the larger
/// waits: room for it fits the smaller, and a proof as small as the room a
/// frame frees needs no wait. Taken under the buffers' lock only.
///
/// A wait ends however its proof is held or carried: each consult reads
/// where the waiting proof stands ([`Found`]) before it keeps any room, so
/// no hold or carry path has to report it. Until 2026-11-25 only a plain
/// submit's hold in its own share ended it, and a proof promoted, carried
/// by another archive's frame or re-filed kept its room for up to
/// [`SEAL_WAIT_STALE`].
///
/// A wait also ends once [`SEAL_WAIT_PASSES`] of this node's proposals
/// passed over its proof while it was not held, however often it is sent
/// again, and that proof waits no more before its window ends. Any other
/// proof neither starts nor refreshes a wait: it is held or refused as the
/// room left allows.
#[derive(Default)]
pub(super) struct SealWaiting {
    waiting: Option<Waiting>,
    /// The proofs whose wait [`SEAL_WAIT_PASSES`] ended, by [`proof_key`],
    /// with their window ends: none waits again before its window ends, when
    /// it leaves. One joins each [`SEAL_WAIT_PASSES`] proposals of this node
    /// at most, and each leaves within an epoch ([`within_reach`]).
    passed_over: Vec<([u8; 32], u64)>,
}

impl SealWaiting {
    /// The bytes `message`, a submitted proof, must leave free in its share
    /// held with it: the waiting proof's if `message` is held in the
    /// provers' share, unless it is that proof or due sooner. `frame` is the
    /// next GLOBAL frame to finalize, 0 unknown; `found` tells where a proof
    /// with a given hash stands.
    pub(super) fn keep(
        &mut self,
        message: &CollectedMessage,
        frame: u64,
        now: Instant,
        found: impl Fn(&[u8; 32]) -> Found,
    ) -> usize {
        if !message.held_seal() || !message.prover {
            return 0;
        }
        self.settle(frame, now, found);
        match &self.waiting {
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

    /// `message` was refused for its full share: if it may wait
    /// ([`CollectedMessage::may_wait`]), is due within reach of `frame`
    /// ([`within_reach`]) and no wait for it ended by passes
    /// ([`SealWaiting::passed_over`]), it waits if its window ends sooner
    /// than the waiting proof's, or with it and it is larger, or none waits.
    pub(super) fn refused(
        &mut self,
        message: &CollectedMessage,
        frame: u64,
        now: Instant,
        found: impl Fn(&[u8; 32]) -> Found,
    ) {
        let Some(end) = message
            .window_end
            .filter(|&end| message.may_wait() && within_reach(end, frame))
        else {
            return;
        };
        self.settle(frame, now, found);
        let key = proof_key(message);
        if self.passed_over.iter().any(|&(passed, _)| passed == key) {
            return;
        }
        match &mut self.waiting {
            Some(waiting) if waiting.hash == message.hash => {
                waiting.refusals = waiting.refusals.saturating_add(1);
                waiting.last = now;
                waiting.len = message.data.len();
                if waiting.refusals == SEAL_WAIT_REFUSALS {
                    tracing::info!(
                        scope = "network",
                        action = "wait",
                        share = share_label(Share::Seals),
                        bytes = waiting.len,
                        window_end = waiting.end,
                        refusals = waiting.refusals,
                        stale_secs = SEAL_WAIT_STALE.as_secs(),
                        passes = SEAL_WAIT_PASSES,
                        ends = ends_text(),
                        "message collector: keeping room in a full storage epoch proof share for the refused proof due soonest; proofs due no later are refused until it is held, so frames that free room free it for this proof; the wait ends as one of ends"
                    );
                }
            }
            Some(waiting)
                if (end, std::cmp::Reverse(message.data.len()))
                    >= (waiting.end, std::cmp::Reverse(waiting.len)) => {}
            slot => {
                if let Some(old) = slot.take() {
                    end_line(old, Ended::Superseded, now);
                }
                *slot = Some(Waiting {
                    hash: message.hash,
                    key,
                    end,
                    len: message.data.len(),
                    refusals: 1,
                    passes: 0,
                    passed: 0,
                    first: now,
                    last: now,
                });
            }
        }
    }

    /// End the wait if it is over: its proof held or carried
    /// ([`Found::ends`]), its window ended at `frame`, or its sender
    /// stopped; and forget each passed-over proof whose window ended.
    /// Called on every consult, and right after a hold so its line times
    /// the wait.
    pub(super) fn settle(&mut self, frame: u64, now: Instant, found: impl Fn(&[u8; 32]) -> Found) {
        if frame != 0 {
            self.passed_over.retain(|&(_, end)| end > frame);
        }
        let Some(waiting) = self.waiting else {
            return;
        };
        let why = if found(&waiting.hash).ends() {
            Ended::Held
        } else if frame != 0 && waiting.end <= frame {
            Ended::Closed
        } else if now.saturating_duration_since(waiting.last) > SEAL_WAIT_STALE {
            Ended::Stale
        } else {
            return;
        };
        self.waiting = None;
        end_line(waiting, why, now);
    }

    /// A proposal of this node for frame `proposal` was taken: a wait still
    /// not over ([`Self::settle`]) counts it, a frame's proposals once, and
    /// ends at [`SEAL_WAIT_PASSES`]; its proof then waits no more before its
    /// window ends. Under the buffers' lock.
    pub(super) fn passed(
        &mut self,
        proposal: u64,
        frame: u64,
        now: Instant,
        found: impl Fn(&[u8; 32]) -> Found,
    ) {
        self.settle(frame, now, &found);
        let Some(waiting) = self.waiting.as_mut() else {
            return;
        };
        if waiting.passes > 0 && waiting.passed == proposal {
            return;
        }
        waiting.passes = waiting.passes.saturating_add(1);
        waiting.passed = proposal;
        if waiting.passes >= SEAL_WAIT_PASSES {
            let waiting = *waiting;
            self.waiting = None;
            self.passed_over.push((waiting.key, waiting.end));
            end_line(waiting, Ended::PassedOver, now);
        }
    }

    /// The waiting proof, as (bytes, window end, keeping room for it), for
    /// tests.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> Option<(usize, u64, bool)> {
        self.waiting
            .map(|waiting| (waiting.len, waiting.end, waiting.active()))
    }

    /// The passed-over proofs no wait may start for, for tests.
    #[cfg(test)]
    fn passed_over_count(&self) -> usize {
        self.passed_over.len()
    }
}

/// A wait may keep room for a proof due at `end` while `frame` is the next
/// GLOBAL frame to finalize: after it, and at most an epoch past it. Every
/// window ends at an epoch boundary, its proofs sent within it
/// (`settlement_window`; a seal's ends with its settlement's), so a proof
/// due further off has no need to wait yet. While `frame` is unknown (0)
/// none waits.
fn within_reach(end: u64, frame: u64) -> bool {
    frame != 0 && end > frame && end - frame <= quil_types::consensus::epoch_length_frames()
}

/// What identifies a storage epoch proof for its wait: the seat parts it
/// proves ([`CollectedMessage::seat_keys`]), in any order, so a copy encoded
/// again is the same proof; its hash if it names none.
fn proof_key(message: &CollectedMessage) -> [u8; 32] {
    if message.seat_keys.is_empty() {
        return message.hash;
    }
    let mut seats = message.seat_keys.clone();
    seats.sort_unstable();
    seats.dedup();
    let mut h = Sha3_256::new();
    h.update(b"quil/collector/seal-wait-proof/v1");
    for seat in &seats {
        h.update(seat);
    }
    h.finalize().into()
}

/// Log the end of `waiting`'s wait, if its share kept room for it.
fn end_line(waiting: Waiting, why: Ended, now: Instant) {
    if !waiting.active() {
        return;
    }
    tracing::info!(
        scope = "network",
        share = share_label(Share::Seals),
        outcome = why.as_str(),
        bytes = waiting.len,
        window_end = waiting.end,
        refusals = waiting.refusals,
        passes = waiting.passes,
        waited_secs = now.saturating_duration_since(waiting.first).as_secs(),
        stale_secs = SEAL_WAIT_STALE.as_secs(),
        ends = ends_text(),
        "message collector: stopped keeping room for a refused storage epoch proof, waited_secs after its first refusal; outcome is one of ends; unless held, the room is free again"
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
            waiting.waiting(),
            Some((4_000_000, 100, true)),
            "a smaller one waits after"
        );

        waiting.settle(10, now, |hash| held(hash, &big, true));
        assert_eq!(waiting.waiting(), None);

        waiting.refused(&big, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        assert_eq!(
            waiting.keep(&small, 100, now, absent),
            0,
            "its window ended"
        );
        assert_eq!(waiting.waiting(), None);

        waiting.refused(&big, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        let later = now + SEAL_WAIT_STALE + Duration::from_secs(1);
        assert_eq!(
            waiting.keep(&small, 10, later, absent),
            0,
            "its sender stopped"
        );
        assert_eq!(waiting.waiting(), None);

        waiting.refused(&small, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        assert_eq!(
            waiting.waiting(),
            Some((4_000_000, 100, false)),
            "a larger one waits"
        );
        waiting.refused(&sooner, 10, now, absent);
        assert_eq!(
            waiting.waiting(),
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

    /// A wait ends once a copy of its proof is held in the provers' share,
    /// or a finalized frame carried it, read on the share's next consult;
    /// another sender's copy held leaves it waiting.
    #[test]
    fn a_wait_ends_once_its_proof_is_held_or_carried() {
        let now = Instant::now();
        let big = proof(1, 100, 4_000_000);
        let small = proof(2, 100, 1_000_000);
        let wait = || {
            let mut waiting = SealWaiting::default();
            waiting.refused(&big, 10, now, absent);
            waiting.refused(&big, 10, now, absent);
            waiting
        };

        let mut waiting = wait();
        let kept = waiting.keep(&small, 10, now, |hash| held(hash, &big, false));
        eprintln!("REACH seal-wait-end other-copy kept={kept}");
        assert_eq!(
            kept, 4_000_000,
            "SEAL-END-SHARE: another sender's copy held ended a prover's wait"
        );

        let mut waiting = wait();
        let kept = waiting.keep(&small, 10, now, |hash| held(hash, &big, true));
        assert_eq!(
            (kept, waiting.waiting()),
            (0, None),
            "SEAL-END-PROVER: a prover's copy held left its wait"
        );

        let mut waiting = wait();
        let kept = waiting.keep(&small, 10, now, |hash| {
            if *hash == big.hash {
                Found::Included
            } else {
                Found::Absent
            }
        });
        eprintln!("REACH seal-wait-end included kept={kept}");
        assert_eq!(
            (kept, waiting.waiting()),
            (0, None),
            "SEAL-END-INCLUDED: a proof a frame carried kept its wait"
        );
    }

    /// Only a proof held in the active provers' share waits: one outside it,
    /// even this node's own, keeps no room and takes none.
    #[test]
    fn only_a_proof_of_the_provers_share_waits() {
        let now = Instant::now();
        let other = CollectedMessage {
            prover: false,
            ..proof(1, 100, 4_000_000)
        };
        let mut waiting = SealWaiting::default();
        waiting.refused(&other, 10, now, absent);
        waiting.refused(&other, 10, now, absent);
        let waits = waiting.waiting();
        eprintln!("REACH seal-waiting share waiting={waits:?}");
        assert_eq!(
            waits, None,
            "SEAL-WAIT-SHARE: a proof outside the provers' share waits"
        );
    }

    /// A proof due exactly an epoch past the next frame to finalize waits;
    /// one due a frame later keeps no room ([`within_reach`]).
    #[test]
    fn a_proof_due_an_epoch_away_waits_and_one_frame_later_does_not() {
        let now = Instant::now();
        let epoch = quil_types::consensus::epoch_length_frames();
        let frame = 10;
        let wait = |message: &CollectedMessage| {
            let mut waiting = SealWaiting::default();
            waiting.refused(message, frame, now, absent);
            waiting.refused(message, frame, now, absent);
            waiting.waiting()
        };
        let edge = wait(&proof(1, frame + epoch, 4_000_000));
        let past = wait(&proof(2, frame + epoch + 1, 4_000_000));
        eprintln!("REACH seal-waiting reach epoch={epoch} edge={edge:?} past={past:?}");
        assert_eq!(
            edge,
            Some((4_000_000, frame + epoch, true)),
            "SEAL-REACH-EDGE: a proof due exactly an epoch ({epoch} frames) on kept no room"
        );
        assert_eq!(
            past, None,
            "SEAL-REACH-PAST: a proof due an epoch and a frame on kept room"
        );
    }

    /// The tracing lines `act` logs at info, as text.
    fn lines(act: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Lines(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, act);
        let bytes = lines.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    /// A wait's start line and its end line name every way it ends, from
    /// one list ([`Ended::ALL`]).
    #[test]
    fn a_waits_start_and_end_lines_name_every_way_it_ends() {
        let now = Instant::now();
        let big = proof(1, 100, 4_000_000);
        let mut waiting = SealWaiting::default();
        let text = lines(|| {
            waiting.refused(&big, 10, now, absent);
            waiting.refused(&big, 10, now, absent);
            waiting.settle(10, now, |hash| held(hash, &big, true));
        });
        let start: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("keeping room in a full"))
            .collect();
        let end: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("stopped keeping room"))
            .collect();
        eprintln!(
            "REACH seal-waiting lines start={} end={}",
            start.len(),
            end.len()
        );
        assert_eq!(
            (start.len(), end.len()),
            (1, 1),
            "premise: one start and one end line: {text:?}"
        );
        for name in ["held", "window_ended", "stale", "passed_over", "superseded"] {
            let named = format!("{name}: ");
            assert!(
                start[0].contains(&named),
                "SEAL-ENDS-START: the start line omits {name}: {}",
                start[0]
            );
            assert!(
                end[0].contains(&named),
                "SEAL-ENDS-END: the end line omits {name}: {}",
                end[0]
            );
        }
    }

    /// A proof whose wait this node's proposals ended by passing over it
    /// waits no more, sent again or encoded again with the same seats,
    /// until its window ends; another proof still may.
    #[test]
    fn a_proof_passed_over_waits_no_more_before_its_window_ends() {
        let now = Instant::now();
        let big = CollectedMessage {
            seat_keys: vec![[7; 32], [8; 32]],
            ..proof(1, 100, 4_000_000)
        };
        let mut waiting = SealWaiting::default();
        waiting.refused(&big, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        for proposal in 1..=u64::from(SEAL_WAIT_PASSES) {
            waiting.passed(proposal, 10, now, absent);
        }
        assert_eq!(
            (waiting.waiting(), waiting.passed_over_count()),
            (None, 1),
            "premise: the passes ended its wait"
        );

        waiting.refused(&big, 10, now, absent);
        waiting.refused(&big, 10, now, absent);
        let again = waiting.waiting();
        let encoded = CollectedMessage {
            seat_keys: vec![[8; 32], [7; 32]],
            ..proof(9, 100, 4_000_000)
        };
        waiting.refused(&encoded, 10, now, absent);
        waiting.refused(&encoded, 10, now, absent);
        let re_encoded = waiting.waiting();
        eprintln!("REACH seal-waiting passed-over again={again:?} encoded={re_encoded:?}");
        assert_eq!(
            again, None,
            "SEAL-PASSED-REARM: a passed-over proof sent again waited"
        );
        assert_eq!(
            re_encoded, None,
            "SEAL-PASSED-KEY: a passed-over proof encoded again waited"
        );

        let other = CollectedMessage {
            seat_keys: vec![[5; 32]],
            ..proof(2, 100, 4_000_000)
        };
        waiting.refused(&other, 10, now, absent);
        waiting.refused(&other, 10, now, absent);
        assert_eq!(
            waiting.waiting(),
            Some((4_000_000, 100, true)),
            "premise: another proof still waits"
        );

        waiting.settle(99, now, |hash| held(hash, &other, true));
        assert_eq!(
            waiting.passed_over_count(),
            1,
            "SEAL-PASSED-KEPT: a passed-over proof was forgotten before its window ended"
        );
        waiting.refused(&big, 99, now, absent);
        waiting.refused(&big, 99, now, absent);
        assert_eq!(
            waiting.waiting(),
            None,
            "SEAL-PASSED-KEPT: a passed-over proof waited a frame before its window ended"
        );
        waiting.settle(100, now, absent);
        let left = waiting.passed_over_count();
        eprintln!("REACH seal-waiting passed-over left={left}");
        assert_eq!(
            left, 0,
            "SEAL-PASSED-END: a passed-over proof was kept past its window end"
        );
    }
}
