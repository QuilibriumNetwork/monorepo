//! What became of the seats storage epoch proofs carried to this collector,
//! by the frame their windows end at: an epoch's settlements and the seals
//! due with them. One line per window end gives the distinct seats held
//! here at least once and, of those no finalized frame carried, each in
//! one state: only ever refused for room, or held and then dropped for
//! room, gone before the window's end, or held at it. Archives' lines
//! compare network-wide. Only the GLOBAL collector reads seats.

use std::collections::{BTreeMap, HashMap};

use quil_execution::global_intrinsic::storage_epoch_proof::{StorageEpochProof, MAX_SEATS};
use sha3::{Digest, Sha3_256};

/// Distinct seats from active provers a window's tally keeps, and as many
/// again first seen in a finalized frame; past either the window only says
/// it overflowed.
const SEATS_PER_WINDOW: usize = 1 << 16;

/// Distinct seats no active prover's proof carried that a window counts,
/// apart from active provers' seats; past it they are no longer counted.
const UNREGISTERED_SEATS_PER_WINDOW: usize = 1 << 12;

/// Window ends tallied at once; past it the latest goes first.
const WINDOWS_KEPT: usize = 4;

/// A seat's window end and its id: 64 bits of a digest ([`seat_ids`]).
pub(super) type SeatId = (u64, u64);

/// The seats of a message's storage epoch proofs ([`seat_ids`]).
#[derive(Clone, Debug, Default)]
pub(super) struct Seats {
    pub(super) ids: Vec<SeatId>,
    /// It carries more seats than [`seat_ids_cap`]: those were not read.
    pub(super) past_cap: bool,
}

impl Seats {
    pub(super) fn is_empty(&self) -> bool {
        self.ids.is_empty() && !self.past_cap
    }

    pub(super) fn extend(&mut self, other: &Seats) {
        self.ids.extend_from_slice(&other.ids);
        self.past_cap |= other.past_cap;
    }
}

/// Most seat ids a message of `len` bytes keeps: those of one full proof
/// (each of its at most `MAX_SEATS` seats a seal and a settlement), and no
/// more than take half its bytes, which its share is charged.
pub(super) fn seat_ids_cap(len: usize) -> usize {
    (2 * MAX_SEATS as usize).min(len / (2 * std::mem::size_of::<SeatId>()))
}

/// What happened to a storage epoch proof's seats here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SeatEvent {
    /// Held.
    Admitted,
    /// Refused for room.
    Refused,
    /// Held, then dropped to make room for a proof due sooner.
    Evicted,
    /// Held, then dropped before its window ended: its rank aged out, or
    /// its proof's window for an earlier seat ended.
    AgedOut,
    /// Held when its window ended.
    Closed,
    /// In a finalized frame.
    Carried,
}

impl SeatEvent {
    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A seat's bit: a proof of it came from this node or an active prover.
const PROVER: u8 = 1 << 7;

/// A seat's bits if it was held here: noted held, or dropped.
const HELD: u8 = SeatEvent::Admitted.bit()
    | SeatEvent::Evicted.bit()
    | SeatEvent::AgedOut.bit()
    | SeatEvent::Closed.bit();

/// What a seat with `bits` that no finalized frame carried counts as when
/// its window ends: the last state it can have reached, held at the end
/// ([`SeatEvent::Closed`]), else aged out, else dropped for room, else
/// gone from the buffers some other way while held (counted aged out),
/// else refused for room. `None` for a carried seat.
fn lost_as(bits: u8) -> Option<SeatEvent> {
    use SeatEvent::*;
    if bits & Carried.bit() != 0 {
        return None;
    }
    [Closed, AgedOut, Evicted]
        .into_iter()
        .find(|event| bits & event.bit() != 0)
        .or_else(|| (bits & HELD != 0).then_some(AgedOut))
        .or_else(|| (bits & Refused.bit() != 0).then_some(Refused))
}

/// A held proof's seats as it leaves the buffers, and why.
pub(super) struct Dropped {
    pub(super) event: SeatEvent,
    /// It came from this node or an active prover.
    pub(super) prover: bool,
    pub(super) seats: Seats,
}

/// How far past the next frame to finalize a window end may be for its
/// window to open: two epochs. `storage_epoch_proof::check` accepts a proof
/// only in the epoch before its window ends (a settlement from the lockstep
/// window into it, a seal after its registration in it), so the next frame
/// can carry only proofs whose window ends within an epoch of it; the
/// second epoch keeps the proofs sent for the window after, which a share
/// holds and drops first ([`super::evict_later_seals`]).
fn horizon() -> u64 {
    quil_types::consensus::epoch_length_frames().saturating_mul(2)
}

/// Add the seats `proof` carries to `into`, unless it is a capacity
/// message, while `into` holds fewer than `cap` ([`seat_ids_cap`]): each
/// seat's seal and its settlement apart, by the frame its window ends at,
/// as a digest of member, shard, epoch and half. `into` grows by exactly
/// the ids it keeps.
pub(super) fn seat_ids(proof: &StorageEpochProof, cap: usize, into: &mut Seats) {
    use quil_execution::global_intrinsic::persistent_storage::capacity_message;
    use quil_execution::global_intrinsic::storage_seat::settlement_window;
    #[cfg(test)]
    tests::PROOFS_READ.with(|read| read.set(read.get() + 1));
    if capacity_message(proof) {
        return;
    }
    let halves: usize = proof
        .seats
        .iter()
        .map(|seat| usize::from(seat.settles) + usize::from(seat.seals))
        .sum();
    into.ids
        .reserve_exact(halves.min(cap.saturating_sub(into.ids.len())));
    for seat in &proof.seats {
        let halves = [
            seat.settles.then(|| (settlement_window(seat.epoch).1, 0u8)),
            seat.seals.then(|| {
                let end = quil_types::consensus::epoch_start_frame(seat.seal_epoch());
                (end, 1u8)
            }),
        ];
        for (end, half) in halves.into_iter().flatten() {
            if into.ids.len() >= cap {
                into.past_cap = true;
                return;
            }
            let mut h = Sha3_256::new();
            h.update(b"quil/collector/window-seat/v2");
            h.update(proof.member);
            h.update((seat.shard_filter.len() as u64).to_be_bytes());
            h.update(&seat.shard_filter);
            h.update(seat.epoch.to_be_bytes());
            h.update([half]);
            let digest = h.finalize();
            let mut id = [0u8; 8];
            id.copy_from_slice(&digest[..8]);
            into.ids.push((end, u64::from_be_bytes(id)));
        }
    }
}

/// One window end's seats, each with the bits of what happened to it
/// ([`SeatEvent::bit`], [`PROVER`]).
#[derive(Default)]
struct Tally {
    /// Seats a proof from this node or an active prover carried here, and
    /// seats first seen in a finalized frame.
    seats: HashMap<u64, u8>,
    /// The entries of `seats` an active prover's proof opened.
    from_provers: usize,
    /// The entries of `seats` a finalized frame opened.
    from_frames: usize,
    /// Seats no active prover's proof carried here, up to
    /// [`UNREGISTERED_SEATS_PER_WINDOW`]; an active prover's proof of one
    /// moves it to `seats`.
    unregistered: HashMap<u64, u8>,
    overflowed: bool,
}

impl Tally {
    fn note(&mut self, id: u64, event: SeatEvent, prover: bool) {
        let bits = event.bit() | if prover { PROVER } else { 0 };
        if let Some(held) = self.seats.get_mut(&id) {
            *held |= bits;
        } else if prover {
            if self.from_provers < SEATS_PER_WINDOW {
                let earlier = self.unregistered.remove(&id).unwrap_or(0);
                self.seats.insert(id, bits | earlier);
                self.from_provers += 1;
            } else {
                self.overflowed = true;
            }
        } else if let Some(held) = self.unregistered.get_mut(&id) {
            *held |= bits;
        } else if event == SeatEvent::Carried {
            if self.from_frames < SEATS_PER_WINDOW {
                self.seats.insert(id, bits);
                self.from_frames += 1;
            } else {
                self.overflowed = true;
            }
        } else if self.unregistered.len() < UNREGISTERED_SEATS_PER_WINDOW {
            self.unregistered.insert(id, bits);
        }
    }

    /// Its counts as the window ending at `window_end` ends.
    fn counts(&self, window_end: u64) -> WindowCounts {
        let mut counts = WindowCounts {
            window_end,
            overflowed: self.overflowed,
            ..Default::default()
        };
        for &bits in self.unregistered.values().chain(self.seats.values()) {
            if bits & PROVER == 0 {
                // Noted for another sender, not only seen in a frame.
                let noted = bits & !SeatEvent::Carried.bit() != 0;
                counts.unregistered_seats += usize::from(noted);
                continue;
            }
            counts.admitted += usize::from(bits & HELD != 0);
            match lost_as(bits) {
                Some(SeatEvent::Refused) => counts.refused_only += 1,
                Some(SeatEvent::Evicted) => counts.evicted += 1,
                Some(SeatEvent::AgedOut) => counts.aged_out += 1,
                Some(SeatEvent::Closed) => counts.closed += 1,
                _ => {}
            }
        }
        counts
    }
}

/// What became of one window end's seats ([`WindowSeats::ended`]), each a
/// count of distinct seats. All but `unregistered_seats` count only seats
/// a proof from this node or an active prover carried here; each of those
/// no finalized frame carried counts in exactly one of `refused_only`,
/// `evicted`, `aged_out` and `closed` ([`lost_as`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct WindowCounts {
    pub(super) window_end: u64,
    /// Held here at least once, carried or not.
    pub(super) admitted: usize,
    /// Refused for room, never held here.
    pub(super) refused_only: usize,
    /// Held, dropped for a proof due sooner, never aged out after or held
    /// when the window ended.
    pub(super) evicted: usize,
    /// Held, gone before the window ended, and either aged out (its rank,
    /// or its proof's window for an earlier seat) or never dropped for
    /// room.
    pub(super) aged_out: usize,
    /// Held when the window ended.
    pub(super) closed: usize,
    /// No active prover's proof carried them here; counted up to
    /// [`UNREGISTERED_SEATS_PER_WINDOW`].
    pub(super) unregistered_seats: usize,
    /// The tally reached [`SEATS_PER_WINDOW`], or an active prover's or a
    /// finalized frame's message carried more seats than [`seat_ids_cap`]:
    /// the counts are inexact.
    pub(super) overflowed: bool,
}

impl WindowCounts {
    /// Seats no finalized frame carried: settlements and seals missed.
    pub(super) fn lost(&self) -> usize {
        self.refused_only + self.evicted + self.aged_out + self.closed
    }
}

/// The seats of each window end not ended yet.
#[derive(Default)]
pub(super) struct WindowSeats {
    windows: BTreeMap<u64, Tally>,
    /// The frame the last lines were logged through: no window ending by it
    /// opens again.
    ended_through: u64,
    /// The next frame to finalize when the tally began ([`Self::begin`]); 0
    /// before.
    since: u64,
}

impl WindowSeats {
    /// Begin the tally at `frame`, the next frame to finalize, unless it
    /// began. Proofs for a window come within [`horizon`] of its end, so a
    /// window ending by `frame` plus the horizon may have had proofs before
    /// it: those windows never open, and none logs a part of its seats.
    pub(super) fn begin(&mut self, frame: u64) {
        if self.since == 0 {
            self.since = frame;
        }
    }

    /// Note `event` for `seats` ([`seat_ids`]); `prover` if their proof came
    /// from this node or an active prover, `frame` the next frame to
    /// finalize. A window opens only for an end some frame can still meet
    /// and the tally saw whole: after `frame`, within [`horizon`] of it,
    /// and past the horizon of the frame the tally began at
    /// ([`Self::begin`]); one already ended opens no more. A seat of a
    /// closed proof whose own window ends later was dropped before it: aged
    /// out. A message past its cap, an active prover's or a finalized
    /// frame's, marks every open window overflowed.
    pub(super) fn note(&mut self, event: SeatEvent, prover: bool, seats: &Seats, frame: u64) {
        for &(end, id) in &seats.ids {
            if end <= self.ended_through {
                continue;
            }
            if !self.windows.contains_key(&end) {
                if frame == 0
                    || self.since == 0
                    || end <= frame
                    || end - frame > horizon()
                    || end <= self.since.saturating_add(horizon())
                {
                    continue;
                }
                if self.windows.len() >= WINDOWS_KEPT {
                    match self.windows.last_key_value() {
                        Some((&last, _)) if last > end => {
                            self.windows.pop_last();
                        }
                        _ => continue,
                    }
                }
                self.windows.insert(end, Tally::default());
            }
            let Some(tally) = self.windows.get_mut(&end) else {
                continue;
            };
            let event = if event == SeatEvent::Closed && end > frame {
                SeatEvent::AgedOut
            } else {
                event
            };
            tally.note(id, event, prover);
        }
        if seats.past_cap && (prover || event == SeatEvent::Carried) {
            for tally in self.windows.values_mut() {
                tally.overflowed = true;
            }
        }
    }

    /// The counts of each window that ended by `frame`, the next frame to
    /// finalize: no frame from it on carries their proofs. Each once.
    pub(super) fn ended(&mut self, frame: u64) -> Vec<WindowCounts> {
        let open = self.windows.split_off(&frame.saturating_add(1));
        let ended = std::mem::replace(&mut self.windows, open);
        self.ended_through = self.ended_through.max(frame);
        ended
            .into_iter()
            .map(|(window_end, tally)| tally.counts(window_end))
            .collect()
    }
}

/// Log what became of each window's seats ([`WindowCounts`]), one line
/// each: a warning if any seat was lost, else at info.
pub(super) fn log_ended(ended: &[WindowCounts]) {
    for counts in ended {
        // A window ending at the start of epoch E + 2 settles epoch E.
        let epoch = (counts.window_end / quil_types::consensus::epoch_length_frames().max(1))
            .saturating_sub(2);
        macro_rules! window_line {
            ($level:ident, $text:literal) => {
                tracing::$level!(
                    scope = "network",
                    epoch,
                    window_end = counts.window_end,
                    admitted = counts.admitted,
                    refused_only = counts.refused_only,
                    evicted = counts.evicted,
                    aged_out = counts.aged_out,
                    closed = counts.closed,
                    unregistered_seats = counts.unregistered_seats,
                    overflowed = counts.overflowed,
                    $text
                )
            };
        }
        if counts.lost() > 0 {
            window_line!(
                warn,
                "message collector: an ended window's storage epoch proof seats from active provers \
                 were lost, unsettled or unsealed: no finalized frame carried them. Each counts once, \
                 by its last state: refused_only refused for room, never held; evicted dropped for a \
                 proof due sooner; aged_out gone before the window end; closed held at it. Check this \
                 archive's share-full, dropped and aged-out lines, and other archives' lines for \
                 window_end"
            );
        } else {
            window_line!(
                info,
                "message collector: an ended window's storage epoch proof seats from active provers: \
                 none lost; admitted were held here, unregistered_seats came from no active prover"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// Storage epoch proofs whose seats this thread read ([`seat_ids`]).
        pub(super) static PROOFS_READ: Cell<usize> = const { Cell::new(0) };
    }

    fn seats(end: u64, ids: &[u8]) -> Seats {
        Seats {
            ids: ids.iter().map(|&id| (end, u64::from(id))).collect(),
            past_cap: false,
        }
    }

    /// `n` seats of the window ending at `end`, ids from `first` on.
    fn many(end: u64, first: u64, n: usize) -> Seats {
        Seats {
            ids: (first..first + n as u64).map(|id| (end, id)).collect(),
            past_cap: false,
        }
    }

    /// The frame the unit tests' tally begins at.
    const START: u64 = 1;

    /// A tally begun at [`START`].
    fn tally() -> WindowSeats {
        let mut tally = WindowSeats::default();
        tally.begin(START);
        tally
    }

    /// The frame the unit tests note at: windows ending up to a horizon
    /// past it open, and the tally saw them whole.
    fn now() -> u64 {
        START + horizon()
    }

    /// Each window's seats are counted once each by what became of them,
    /// a seat any finalized frame carried losing none, an unregistered one
    /// counting apart, and a window ends once, when the next frame to
    /// finalize reaches it.
    #[test]
    fn a_windows_seats_are_counted_once_each_when_it_ends() {
        use SeatEvent::*;
        let (a, b) = (now() + 50, now() + 150);
        let mut tally = tally();
        let events: [(SeatEvent, bool, u64, &[u8]); 13] = [
            // Seat 1 is held and gone with no drop noted: aged out.
            (Admitted, true, a, &[1, 2, 3, 4, 8, 9]),
            (Admitted, true, a, &[1]),
            (Refused, true, a, &[1, 5, 6, 7]),
            (Evicted, true, a, &[8, 9]),
            (AgedOut, true, a, &[2, 3]),
            (Closed, true, a, &[4]),
            (Carried, false, a, &[3, 7, 9]),
            (Admitted, false, a, &[11]),
            (AgedOut, false, a, &[11]),
            // Carried before anything here: refused afterwards, it lost
            // nothing.
            (Carried, false, b, &[10]),
            (Refused, true, b, &[10]),
            (Admitted, true, b, &[12]),
            (Carried, false, b, &[12]),
        ];
        for (event, prover, end, ids) in events {
            // A proof closes once the next frame reaches its window's end.
            let frame = if event == Closed { end } else { now() };
            tally.note(event, prover, &seats(end, ids), frame);
        }
        assert_eq!(
            tally.ended(a - 1),
            Vec::new(),
            "window_early: a window ended before its end"
        );
        let ended = tally.ended(a);
        eprintln!("REACH window-seats counts {ended:?}");
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: a,
                admitted: 6,
                refused_only: 2,
                evicted: 1,
                aged_out: 2,
                closed: 1,
                unregistered_seats: 1,
                overflowed: false,
            }],
            "window_counts: a window's seats were miscounted"
        );
        assert_eq!(
            tally.ended(a + 50),
            Vec::new(),
            "window_twice: a window ended twice"
        );
        assert_eq!(
            tally.ended(b),
            vec![WindowCounts {
                window_end: b,
                admitted: 1,
                ..Default::default()
            }],
            "window_counts: a seat carried before it was refused here counted as refused"
        );
    }

    /// A seat no finalized frame carried counts in one state only, its
    /// last: held at the window's end, else aged out, else dropped for
    /// room, else gone from the buffers otherwise (aged out); a seat held
    /// only before its window opened counts held, never refused only.
    #[test]
    fn a_lost_seat_counts_once_by_its_last_state() {
        use SeatEvent::*;
        let a = now() + 50;
        let mut tally = tally();
        let events: [(SeatEvent, bool, &[u8]); 10] = [
            (Admitted, true, &[1, 2, 3, 5, 6]),
            (Evicted, true, &[1, 2, 6]),
            (AgedOut, true, &[3]),
            // Held again, from a copy sent again.
            (Admitted, true, &[1, 2, 3]),
            (Closed, true, &[1]),
            (AgedOut, true, &[2]),
            (Evicted, true, &[3]),
            // Held while its window was not open yet: noted only as its
            // proof was dropped.
            (Refused, true, &[4]),
            (Evicted, true, &[4]),
            (Carried, false, &[6]),
        ];
        for (event, prover, ids) in events {
            let frame = if event == Closed { a } else { now() };
            tally.note(event, prover, &seats(a, ids), frame);
        }
        let ended = tally.ended(a);
        eprintln!("REACH window-seats lost-once {ended:?}");
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: a,
                admitted: 6,
                evicted: 1,
                aged_out: 3,
                closed: 1,
                ..Default::default()
            }],
            "lost_twice: a lost seat counted in more or fewer than one state"
        );
    }

    /// A window opens only for an end a frame can still meet: none for an
    /// end past the horizon, at or before the next frame to finalize, or
    /// while that frame is unknown.
    #[test]
    fn a_window_opens_only_for_an_end_a_frame_can_meet() {
        let mut tally = tally();
        for event in [SeatEvent::Admitted, SeatEvent::Refused, SeatEvent::Carried] {
            tally.note(event, true, &seats(now() + horizon() + 1, &[1]), now());
            tally.note(event, true, &seats(now(), &[2]), now());
            tally.note(event, true, &seats(now() + 1, &[3]), 0);
        }
        eprintln!("REACH window-seats horizon {:?}", tally.windows.keys());
        assert!(
            tally.windows.is_empty(),
            "window_horizon: windows opened for {:?}",
            tally.windows.keys().collect::<Vec<_>>()
        );
        let at_horizon = seats(now() + horizon(), &[4]);
        tally.note(SeatEvent::Admitted, true, &at_horizon, now());
        assert_eq!(
            tally.ended(u64::MAX).len(),
            1,
            "window_horizon: the window at the horizon did not open"
        );
    }

    /// A window opens only if the tally saw its whole horizon: none before
    /// the tally began, and none ending within the horizon of the frame it
    /// began at, whose proofs may have come before.
    #[test]
    fn a_window_opens_only_if_the_tally_saw_its_whole_horizon() {
        let mut unbegun = WindowSeats::default();
        unbegun.note(SeatEvent::Admitted, true, &seats(now() + 1, &[1]), now());
        let mut tally = tally();
        let frame = START + 1;
        tally.note(
            SeatEvent::Admitted,
            true,
            &seats(START + horizon(), &[2]),
            frame,
        );
        let whole = START + horizon() + 1;
        tally.note(SeatEvent::Admitted, true, &seats(whole, &[3]), frame);
        let opened: Vec<u64> = unbegun
            .windows
            .keys()
            .chain(tally.windows.keys())
            .copied()
            .collect();
        eprintln!("REACH window-seats began {opened:?}");
        assert_eq!(
            opened,
            vec![whole],
            "window_partial: a window opened that the tally saw only in part"
        );
    }

    /// A window that ended logs no second line, whatever arrives for it
    /// after, even noted with a frame read before it ended.
    #[test]
    fn a_window_ends_once_whatever_arrives_after() {
        let a = now() + 50;
        let mut tally = tally();
        tally.note(SeatEvent::Admitted, true, &seats(a, &[1]), now());
        assert_eq!(tally.ended(a).len(), 1);
        tally.note(SeatEvent::Refused, true, &seats(a, &[1, 2]), now());
        tally.note(SeatEvent::Admitted, true, &seats(a, &[3]), now());
        tally.note(SeatEvent::Carried, false, &seats(a, &[4]), now());
        let again = tally.ended(a + 1);
        eprintln!("REACH window-seats once {again:?}");
        assert_eq!(again, Vec::new(), "window_twice: a window ended twice");
    }

    /// A finalized frame's message past its cap leaves seats it carried
    /// unread, which would count lost: the window says it overflowed.
    #[test]
    fn a_frames_message_past_its_cap_marks_the_window_overflowed() {
        let a = now() + 50;
        let mut tally = tally();
        tally.note(SeatEvent::Admitted, true, &seats(a, &[1]), now());
        let unread = Seats {
            ids: Vec::new(),
            past_cap: true,
        };
        tally.note(SeatEvent::Carried, false, &unread, now());
        let ended = tally.ended(a);
        eprintln!("REACH window-seats carried-cap {ended:?}");
        assert!(
            ended.iter().all(|counts| counts.overflowed) && ended.len() == 1,
            "carried_cap_unmarked: a frame's message past its cap left the window exact: {ended:?}"
        );
    }

    /// Member `id`'s proof of `n` seats of [`EPOCH`], each sealing and
    /// settling.
    fn sealing(id: u8, n: u8) -> StorageEpochProof {
        use quil_execution::global_intrinsic::storage_epoch_proof::SeatProof;
        StorageEpochProof {
            member: [id; 32],
            seats: (0..n)
                .map(|shard| SeatProof {
                    shard_filter: vec![shard],
                    epoch: EPOCH,
                    seals: true,
                    settles: true,
                    ..Default::default()
                })
                .collect(),
            proof: Vec::new(),
        }
    }

    /// A message's seat ids take the room of the ids kept, no more: a
    /// vector doubling as it grows could take twice the bytes its cap
    /// allows.
    #[test]
    fn a_messages_seat_ids_take_only_the_room_they_need() {
        let cap = 5;
        let mut read = Seats::default();
        seat_ids(&sealing(1, 1), cap, &mut read);
        seat_ids(&sealing(2, 2), cap, &mut read);
        eprintln!(
            "REACH window-seats room len={} capacity={}",
            read.ids.len(),
            read.ids.capacity()
        );
        assert!(read.past_cap && read.ids.len() == cap);
        assert!(
            read.ids.capacity() <= cap,
            "ids_overgrown: {} seat ids took room for {}",
            read.ids.len(),
            read.ids.capacity()
        );
    }

    /// The line `log_ended` writes for `counts`, with its level.
    fn logged(counts: WindowCounts) -> String {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Lines(Arc<Mutex<Vec<u8>>>);
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
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || log_ended(&[counts]));
        let bytes = lines.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    /// A window that lost any seat logs a warning saying what to check;
    /// one that lost none logs at info.
    #[test]
    fn a_window_that_lost_seats_warns_and_says_what_to_check() {
        let held = WindowCounts {
            window_end: now(),
            admitted: 3,
            ..Default::default()
        };
        let losses = [
            WindowCounts {
                refused_only: 1,
                ..held
            },
            WindowCounts { evicted: 1, ..held },
            WindowCounts {
                aged_out: 1,
                ..held
            },
            WindowCounts { closed: 1, ..held },
        ];
        for counts in losses {
            let line = logged(counts);
            eprintln!("REACH window-seats warn {line}");
            assert!(
                line.contains("WARN") && line.contains("Check this archive's"),
                "loss_not_warned: a window that lost seats logged {line}"
            );
        }
        let line = logged(held);
        assert!(
            line.contains("INFO") && !line.contains("WARN"),
            "quiet_warned: a window that lost no seat logged {line}"
        );
    }

    /// Member `id`'s settlement of one seat of `epoch`, of mainnet's size.
    fn settlement(id: u32, epoch: u64) -> Vec<u8> {
        use quil_execution::global_intrinsic::storage_epoch_proof::SeatProof;
        let mut member = [0u8; 32];
        member[..4].copy_from_slice(&id.to_be_bytes());
        let mut bytes = vec![0u8; 650_000];
        bytes[..4].copy_from_slice(&id.to_be_bytes());
        let proof = StorageEpochProof {
            member,
            seats: vec![SeatProof {
                shard_filter: member.to_vec(),
                epoch,
                settles: true,
                ..Default::default()
            }],
            proof: bytes,
        };
        envelope(vec![proof])
    }

    /// `proofs` in one bundle.
    fn envelope(proofs: Vec<StorageEpochProof>) -> Vec<u8> {
        use quil_execution::global_intrinsic::storage_epoch_proof::TYPE_STORAGE_EPOCH_PROOF;
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        CanonicalMessageBundle {
            requests: proofs
                .iter()
                .map(|proof| {
                    Some(CanonicalMessageRequest {
                        inner_type_prefix: TYPE_STORAGE_EPOCH_PROOF,
                        inner_bytes: proof.to_canonical_bytes(),
                    })
                })
                .collect(),
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    /// Member `id`'s bundle of one proof per entry of `proofs`, each seat
    /// `(epoch, seals)` settling on a shard of its own, the first proof
    /// `pad` bytes long.
    fn bundle(id: u32, proofs: &[Vec<(u64, bool)>], pad: usize) -> Vec<u8> {
        use quil_execution::global_intrinsic::storage_epoch_proof::SeatProof;
        let mut member = [0u8; 32];
        member[..4].copy_from_slice(&id.to_be_bytes());
        let mut shard = 0u32;
        let mut built = Vec::new();
        for (i, seats) in proofs.iter().enumerate() {
            let mut proof = StorageEpochProof {
                member,
                seats: Vec::new(),
                proof: vec![0; if i == 0 { pad } else { 0 }],
            };
            for &(epoch, seals) in seats {
                shard += 1;
                proof.seats.push(SeatProof {
                    shard_filter: shard.to_be_bytes().to_vec(),
                    epoch,
                    seals,
                    settles: true,
                    ..Default::default()
                });
            }
            built.push(proof);
        }
        envelope(built)
    }

    /// A full proof's seats of `epoch`, each sealing and settling.
    fn full(epoch: u64) -> Vec<(u64, bool)> {
        vec![(epoch, true); MAX_SEATS as usize]
    }

    /// The settled epoch of the collector tests.
    const EPOCH: u64 = 1478;

    /// A GLOBAL collector that saw frame `finalized` finalized, its tally
    /// begun two horizons before: the windows the tests use are whole.
    fn collector(finalized: u64) -> super::super::MessageCollector {
        let mc = super::super::MessageCollector::new();
        mc.set_class_shares();
        mc.note_finalized_frame(finalized - 2 * horizon());
        mc.note_finalized_frame(finalized);
        mc
    }

    /// Fill the provers' share at rank 1 with settlements of `epoch`, member
    /// ids from `first` on: the proofs held, and the first refused.
    fn fill(
        mc: &super::super::MessageCollector,
        first: u32,
        epoch: u64,
    ) -> (Vec<Vec<u8>>, Vec<u8>) {
        use super::super::{Refusal, SubmitOutcome};
        let mut held = Vec::new();
        loop {
            let bytes = settlement(first + held.len() as u32, epoch);
            match mc.add_message_outcome(1, bytes.clone()) {
                SubmitOutcome::Accepted => held.push(bytes),
                SubmitOutcome::Filtered(Refusal::RankFull) => return (held, bytes),
                other => panic!("{other:?}"),
            }
            assert!(held.len() < 40, "40 proofs did not fill the share");
        }
    }

    /// Finalize up to `frame - 1` and age out every rank held at 1.
    fn age_out(mc: &super::super::MessageCollector, frame: u64) {
        mc.note_finalized_frame(frame - 1);
        for rank in 2..=super::super::RETENTION_WINDOW + 2 {
            mc.prune_after_finalization(rank);
        }
    }

    /// The window lines `mc` logged.
    fn lines(mc: &super::super::MessageCollector) -> Vec<WindowCounts> {
        mc.windows_ended.lock().unwrap().clone()
    }

    /// The GLOBAL collector logs one line for a settlement window once the
    /// next frame to finalize reaches its end: the seats it held, those it
    /// only refused for room, and those that aged out, a seat any
    /// finalized frame carried counting as neither and an unregistered one
    /// apart (mainnet, 2026-11-13: archives refused seats for room to each
    /// window's end, and nothing counted the seats lost).
    #[test]
    fn the_global_collector_logs_each_windows_seats_once_it_ends() {
        use super::super::{Provenance, Refusal, SubmitOutcome};
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let mc = collector(from);
        assert_eq!(
            mc.add_message_outcome_from(1, settlement(500, EPOCH), Provenance::Other),
            SubmitOutcome::Accepted
        );
        let (held, refused) = fill(&mc, 1, EPOCH);
        // Sent again and refused again: one seat.
        assert_eq!(
            mc.add_message_outcome(1, refused),
            SubmitOutcome::Filtered(Refusal::RankFull)
        );
        // Refused here, and carried by a frame another archive proposed.
        let carried = settlement(held.len() as u32 + 2, EPOCH);
        assert_eq!(
            mc.add_message_outcome(1, carried.clone()),
            SubmitOutcome::Filtered(Refusal::RankFull)
        );
        mc.mark_finalized(&[held[0].clone(), carried]);
        age_out(&mc, end);
        let ended = lines(&mc);
        eprintln!("REACH window-seats collector held={} {ended:?}", held.len());
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: end,
                admitted: held.len(),
                refused_only: 1,
                aged_out: held.len() - 1,
                unregistered_seats: 1,
                ..Default::default()
            }],
            "window_line: the collector's window line miscounted its seats"
        );
    }

    /// The first windows after the tally begins, whose proofs may have come
    /// before, log no line; the first it saw whole does.
    #[test]
    fn the_first_windows_after_a_start_log_no_line() {
        use super::super::SubmitOutcome;
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let mc = super::super::MessageCollector::new();
        mc.set_class_shares();
        // The first frame seen finalized.
        mc.note_finalized_frame(from);
        assert_eq!(
            mc.add_message_outcome(1, settlement(1, EPOCH)),
            SubmitOutcome::Accepted
        );
        age_out(&mc, end);
        let (from, whole) = settlement_window(EPOCH + 2);
        mc.note_finalized_frame(from);
        let rank = 20;
        assert_eq!(
            mc.add_message_outcome(rank, settlement(2, EPOCH + 2)),
            SubmitOutcome::Accepted
        );
        // Held when its window ends.
        mc.note_finalized_frame(whole - 1);
        mc.prune_after_finalization(rank + 1);
        let ended = lines(&mc);
        eprintln!("REACH window-seats partial {ended:?}");
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: whole,
                admitted: 1,
                closed: 1,
                ..Default::default()
            }],
            "window_partial: a window the tally saw only in part logged a line, or a whole one none"
        );
    }

    /// A held proof dropped to make room for one due sooner counts as
    /// evicted in its window's line.
    #[test]
    fn the_global_collector_counts_seats_dropped_for_room() {
        use super::super::SubmitOutcome;
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let later = settlement_window(EPOCH + 1).1;
        let mc = collector(from);
        let (held, _) = fill(&mc, 1, EPOCH + 1);
        // Due sooner: one held proof of the later window leaves for it.
        assert_eq!(
            mc.add_message_outcome(1, settlement(1_000, EPOCH)),
            SubmitOutcome::Accepted
        );
        age_out(&mc, later);
        let ended = lines(&mc);
        eprintln!("REACH window-seats evicted held={} {ended:?}", held.len());
        assert_eq!(
            ended,
            vec![
                WindowCounts {
                    window_end: end,
                    admitted: 1,
                    aged_out: 1,
                    ..Default::default()
                },
                WindowCounts {
                    window_end: later,
                    admitted: held.len(),
                    refused_only: 1,
                    evicted: 1,
                    aged_out: held.len() - 1,
                    ..Default::default()
                },
            ],
            "window_evicted: the line miscounted seats dropped for room"
        );
    }

    /// A held proof no frame carried by its window's end counts as closed.
    #[test]
    fn the_global_collector_counts_seats_held_when_their_window_ends() {
        use super::super::{SubmitOutcome, RETENTION_WINDOW};
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let mc = collector(from);
        let carried = settlement(2, EPOCH);
        for bytes in [settlement(1, EPOCH), carried.clone()] {
            assert_eq!(mc.add_message_outcome(50, bytes), SubmitOutcome::Accepted);
        }
        mc.mark_finalized(&[carried]);
        // Rank 50 outlives these prunes: its proof is held when the window ends.
        mc.note_finalized_frame(end - 1);
        for rank in 1..=RETENTION_WINDOW + 1 {
            mc.prune_after_finalization(rank);
        }
        let ended = lines(&mc);
        eprintln!("REACH window-seats closed {ended:?}");
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: end,
                admitted: 2,
                closed: 1,
                ..Default::default()
            }],
            "window_closed: the line miscounted seats held when their window ended"
        );
    }

    /// A held proof that leaves the buffers before its window ends with no
    /// drop noted (taken out at a proposal) counts lost, as aged out.
    #[test]
    fn the_global_collector_counts_a_held_seat_that_left_otherwise() {
        use super::super::{SubmitOutcome, RETENTION_WINDOW};
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let mc = collector(from);
        let bytes = settlement(1, EPOCH);
        assert_eq!(
            mc.add_message_outcome(50, bytes.clone()),
            SubmitOutcome::Accepted
        );
        mc.remove(&[bytes]);
        mc.note_finalized_frame(end - 1);
        for rank in 1..=RETENTION_WINDOW + 1 {
            mc.prune_after_finalization(rank);
        }
        let ended = lines(&mc);
        eprintln!("REACH window-seats left {ended:?}");
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: end,
                admitted: 1,
                aged_out: 1,
                ..Default::default()
            }],
            "left_uncounted: a held seat no frame carried counted in no state"
        );
    }

    /// Unregistered seats fill a bound of their own: past it they are no
    /// longer counted, and active provers' seats are still counted
    /// exactly.
    #[test]
    fn a_windows_prover_seats_have_room_of_their_own() {
        use super::super::{Provenance, Refusal, SubmitOutcome};
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let mc = collector(from);
        // More seats than a window keeps, a full proof per message.
        let others = SEATS_PER_WINDOW / (2 * MAX_SEATS as usize) + 2;
        for id in 0..others as u32 {
            let bytes = bundle(10_000 + id, &[full(EPOCH)], 1 << 14);
            let outcome = mc.add_message_outcome_from(1, bytes, Provenance::Other);
            assert!(
                matches!(
                    outcome,
                    SubmitOutcome::Accepted | SubmitOutcome::Filtered(Refusal::RankFull)
                ),
                "{outcome:?}"
            );
        }
        assert_eq!(
            mc.add_message_outcome(1, settlement(1, EPOCH)),
            SubmitOutcome::Accepted
        );
        age_out(&mc, end);
        let ended = lines(&mc);
        eprintln!("REACH window-seats crowd {ended:?}");
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: end,
                admitted: 1,
                aged_out: 1,
                unregistered_seats: UNREGISTERED_SEATS_PER_WINDOW,
                ..Default::default()
            }],
            "unregistered_crowd: unregistered seats changed the counts of active provers' seats"
        );
    }

    /// A collector without class shares (a shard's, or any regular node's)
    /// reads no seats, whatever it collects or sees finalized.
    #[test]
    fn a_collector_without_shares_reads_no_seats() {
        use super::super::SubmitOutcome;
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, _) = settlement_window(EPOCH);
        let mc = super::super::MessageCollector::new();
        mc.note_finalized_frame(from);
        let bytes = settlement(1, EPOCH);
        assert_eq!(
            mc.add_message_outcome(1, bytes.clone()),
            SubmitOutcome::Accepted
        );
        mc.mark_finalized(&[bytes]);
        let read = PROOFS_READ.with(Cell::get);
        eprintln!("REACH window-seats unshared read={read}");
        assert_eq!(
            read, 0,
            "seats_read: a collector without class shares read seats"
        );
    }

    /// A message keeps at most a full proof's seats, and no more than take
    /// half its bytes (16-byte ids); one past either marks the window
    /// overflowed.
    #[test]
    fn a_messages_seats_are_capped() {
        use super::super::SubmitOutcome;
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let mc = collector(from);
        let two = bundle(1, &[full(EPOCH), full(EPOCH)], 1 << 15);
        let dense = bundle(2, &[full(EPOCH)], 0);
        let cap = 2 * MAX_SEATS as usize;
        let kept = cap + (dense.len() / 32).min(cap);
        for bytes in [two, dense] {
            assert_eq!(mc.add_message_outcome(1, bytes), SubmitOutcome::Accepted);
        }
        age_out(&mc, end);
        let ended = lines(&mc);
        eprintln!("REACH window-seats capped kept={kept} {ended:?}");
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: end,
                admitted: kept,
                aged_out: kept,
                overflowed: true,
                ..Default::default()
            }],
            "message_uncapped: a message kept seats past its cap, or the window did not say so"
        );
    }

    /// A proof dropped as its earliest seat's window ends holds its later
    /// seats no longer: their window's line counts them aged out, not held
    /// when it ended.
    #[test]
    fn a_proofs_later_seats_are_not_closed_with_its_earliest_window() {
        use super::super::{SubmitOutcome, RETENTION_WINDOW};
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let later = settlement_window(EPOCH + 1).1;
        let mc = collector(from);
        let both = bundle(1, &[vec![(EPOCH, false), (EPOCH + 1, false)]], 0);
        assert_eq!(mc.add_message_outcome(50, both), SubmitOutcome::Accepted);
        // Rank 50 outlives these prunes: the proof is held when the first
        // window ends.
        mc.note_finalized_frame(end - 1);
        for rank in 1..=RETENTION_WINDOW + 1 {
            mc.prune_after_finalization(rank);
        }
        mc.note_finalized_frame(later - 1);
        mc.prune_after_finalization(RETENTION_WINDOW + 2);
        let ended = lines(&mc);
        eprintln!("REACH window-seats later {ended:?}");
        assert_eq!(
            ended,
            vec![
                WindowCounts {
                    window_end: end,
                    admitted: 1,
                    closed: 1,
                    ..Default::default()
                },
                WindowCounts {
                    window_end: later,
                    admitted: 1,
                    aged_out: 1,
                    ..Default::default()
                },
            ],
            "later_closed: a proof's later seat counted as held when its window ended"
        );
    }

    /// A frame carrying a held proof counts its seats carried from the
    /// held copy, reading the proof no second time.
    #[test]
    fn the_global_collector_reads_a_held_proofs_seats_once() {
        use super::super::SubmitOutcome;
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let mc = collector(from);
        let bytes = settlement(1, EPOCH);
        assert_eq!(
            mc.add_message_outcome(1, bytes.clone()),
            SubmitOutcome::Accepted
        );
        let read = PROOFS_READ.with(Cell::get);
        mc.mark_finalized(&[bytes]);
        let again = PROOFS_READ.with(Cell::get) - read;
        age_out(&mc, end);
        let ended = lines(&mc);
        eprintln!("REACH window-seats read-once again={again} {ended:?}");
        assert_eq!(
            again, 0,
            "seats_read_twice: a held proof's seats were read again when a frame carried it"
        );
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: end,
                admitted: 1,
                ..Default::default()
            }],
            "window_line: a carried proof's seats were counted lost"
        );
    }

    /// A copy of a held or finalized proof reads no seats: the held copy's,
    /// read when it was filed, count for an active prover's copy that
    /// promotes it.
    #[test]
    fn a_copy_of_a_held_or_finalized_proof_reads_no_seats() {
        use super::super::{Provenance, SubmitOutcome};
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let (from, end) = settlement_window(EPOCH);
        let mc = collector(from);
        let bytes = settlement(1, EPOCH);
        assert_eq!(
            mc.add_message_outcome_from(1, bytes.clone(), Provenance::Other),
            SubmitOutcome::Accepted
        );
        let read = PROOFS_READ.with(Cell::get);
        // The active prover's copy promotes the held one; then copies.
        for _ in 0..2 {
            assert_eq!(
                mc.add_message_outcome(1, bytes.clone()),
                SubmitOutcome::Duplicate
            );
        }
        mc.mark_finalized(std::slice::from_ref(&bytes));
        assert_eq!(mc.add_message_outcome(1, bytes), SubmitOutcome::Duplicate);
        let again = PROOFS_READ.with(Cell::get) - read;
        age_out(&mc, end);
        let ended = lines(&mc);
        eprintln!("REACH window-seats copies again={again} {ended:?}");
        assert_eq!(
            again, 0,
            "seats_reread: copies of a held or finalized proof read its seats"
        );
        assert_eq!(
            ended,
            vec![WindowCounts {
                window_end: end,
                admitted: 1,
                ..Default::default()
            }],
            "copy_line: a promoted proof's seats were not counted as an active prover's"
        );
    }

    /// A window's tally is bounded: past [`SEATS_PER_WINDOW`] seats from
    /// active provers, or as many first seen in a finalized frame, it keeps
    /// no more and says so; past [`UNREGISTERED_SEATS_PER_WINDOW`] unregistered
    /// seats it counts no more; and past [`WINDOWS_KEPT`] window
    /// ends the latest goes, keeping those due first.
    #[test]
    fn a_windows_tally_is_bounded() {
        let first = now() + 1;
        let mut tally = tally();
        tally.note(
            SeatEvent::Admitted,
            true,
            &many(first, 0, SEATS_PER_WINDOW + 1),
            now(),
        );
        tally.note(SeatEvent::Refused, true, &many(first, 1 << 40, 1), now());
        let t = &tally.windows[&first];
        assert!(
            t.overflowed && t.seats.len() == SEATS_PER_WINDOW,
            "seats_unbounded: a window kept {} seats from active provers, overflowed {}",
            t.seats.len(),
            t.overflowed
        );
        let mut frames = self::tally();
        frames.note(
            SeatEvent::Carried,
            false,
            &many(first, 0, SEATS_PER_WINDOW + 1),
            now(),
        );
        let t = &frames.windows[&first];
        assert!(
            t.overflowed && t.seats.len() == SEATS_PER_WINDOW,
            "frame_seats_unbounded: a window kept {} seats first seen in frames, overflowed {}",
            t.seats.len(),
            t.overflowed
        );
        let mut others = self::tally();
        others.note(
            SeatEvent::Refused,
            false,
            &many(first, 0, UNREGISTERED_SEATS_PER_WINDOW + 1),
            now(),
        );
        let t = &others.windows[&first];
        assert!(
            t.unregistered.len() == UNREGISTERED_SEATS_PER_WINDOW && !t.overflowed,
            "unregistered_unbounded: a window kept {} unregistered seats",
            t.unregistered.len()
        );
        assert!(WINDOWS_KEPT as u64 + 2 <= horizon());
        // Latest first: each earlier end takes the place of the latest.
        for end in (first + 1..=first + WINDOWS_KEPT as u64 + 1).rev() {
            tally.note(SeatEvent::Refused, true, &seats(end, &[1]), now());
        }
        assert!(
            tally.windows.len() <= WINDOWS_KEPT,
            "windows_unbounded: {} window ends kept",
            tally.windows.len()
        );
        let kept: Vec<u64> = tally.windows.keys().copied().collect();
        eprintln!("REACH window-seats bound {kept:?}");
        assert_eq!(
            kept,
            (first..first + WINDOWS_KEPT as u64).collect::<Vec<_>>(),
            "window_kept: the window ends due first did not stay"
        );
    }
}
