//! One line per seat and seal epoch: whether this node sealed the seat's
//! registration before the epoch began and, when not, why and what the
//! operator should check. Without it a node logged hundreds of "no sealed
//! storage registration" lines across its cores and never said why a slot
//! did not seal (2026-11-16).
//!
//! The seal's job notes what refused it or that it sent the seal part
//! ([`note_refusal`], [`note_published`]), the label store what disk it
//! lacked ([`note_disk_short`]); the engines note the GLOBAL frames that
//! show this process is live ([`note_live`], [`note_head`]) and the
//! seat's engine concludes the epoch once ([`due`], [`conclude`]): at
//! once for a sealed registration, else [`CONCLUDE_HOLD`] after this
//! process first checked a frame past the epoch's first, re-reading the
//! slot on each frame checked, as a seal sent late in the window reaches
//! this node's view only with a later registry pull. Notes live in the
//! process: one started after the seal's send window opened says so
//! instead of guessing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use tracing::{info, warn};

/// Why a registration did not seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    DiskShort,
    CertificationPending,
    SlotsOccupied,
    LabelNotRetained,
    NotRegistered,
    /// The seal's job started after the window it is sent in closed.
    WindowClosed,
    SealedLate,
    Undelivered,
    Restarted,
    Other,
}

impl Reason {
    /// The reason a seal job's error names, read by the texts its emitters
    /// share, never a copy. No seal error names disk: a disk floor leaves a
    /// sector's labels unkept, so disk short is only a registration's
    /// ([`Notes::note_disk_short`]).
    pub fn classify(error: &str) -> Self {
        use crate::storage_snapshot::{INITIALIZING, SLOTS_OCCUPIED, UNCERTIFIED};
        if error.contains(UNCERTIFIED) {
            Reason::CertificationPending
        } else if error.contains(SLOTS_OCCUPIED)
            || error.contains(INITIALIZING)
            || error.contains(crate::storage_labels::BUSY)
        {
            Reason::SlotsOccupied
        } else if crate::storage_epoch_batch::names_window_closed(error) {
            Reason::WindowClosed
        } else if crate::storage_epoch_batch::seal_failed_for_good(error) {
            Reason::LabelNotRetained
        } else {
            Reason::Other
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Reason::DiskShort => "disk short",
            Reason::CertificationPending => "certification pending",
            Reason::SlotsOccupied => "slots occupied",
            Reason::LabelNotRetained => "label not retained",
            Reason::NotRegistered => "not registered",
            Reason::WindowClosed => "queued past its window",
            Reason::SealedLate => "sealed after the epoch began",
            Reason::Undelivered => "undelivered",
            Reason::Restarted => "node restarted since the send",
            Reason::Other => "other",
        }
    }

    /// What the operator should check.
    pub fn check(self) -> &'static str {
        match self {
            Reason::DiskShort => {
                "free disk space on the filesystem holding the node's store: a sector's labels \
                 need needed_bytes free"
            }
            Reason::CertificationPending => {
                "nothing: the sector's certification lands first and the seal is tried again; \
                 if it repeats every epoch, check the storage snapshot job's failure warnings"
            }
            Reason::SlotsOccupied => {
                "nothing if it clears: other sectors hold this host's initialization slots; if \
                 it repeats every epoch, check the host's cores and memory for storage jobs"
            }
            Reason::LabelNotRetained => {
                "nothing: the registration was labelled by another build (the 'storage seal \
                 cannot be proved' warning); the next registration, labelled by this build, seals"
            }
            Reason::NotRegistered => {
                "the storage snapshot job's failure warnings and free disk space: no \
                 registration for this epoch reached GLOBAL"
            }
            Reason::WindowClosed => {
                "the 'storage seal part not proved' warnings and this shard's storage job backlog: \
                 the seal's job waited behind the shard's other storage work until its window \
                 closed, so GLOBAL would refuse it"
            }
            Reason::SealedLate => {
                "the 'storage seal part' and 'storage epoch proof' lines: the seal landed \
                 after the epoch began"
            }
            Reason::Undelivered => {
                "the master's 'storage epoch proof undelivered' errors and its window summary's \
                 refused count: archives refused the proof carrying the seal (as 'rank buffer \
                 full') until its window ended; or its 'so the part is not sent' lines: the part \
                 reached its batch after its window closed"
            }
            Reason::Restarted => {
                "the previous run's 'storage epoch proof part prepared' lines and the master's \
                 'storage epoch proof undelivered' errors: this run began after the seal's send \
                 window opened, so it cannot tell whether the seal was sent"
            }
            Reason::Other => "the 'storage seal part not prepared' warnings for the error",
        }
    }
}

/// What the operator checks for a registration this process watched the
/// whole send window of and never tried to seal: no refusal to point at.
const UNTRIED_CHECK: &str = "the 'storage epoch proof check still running' warnings: this run \
                             watched the whole send window, and no seal attempt was refused or \
                             sent";

/// How the seal of a seat's registration for an epoch ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Sealed,
    NotAttempted,
    Refused,
    /// Sent to the master, never sealed.
    Sent,
    /// This process did not see the whole send window.
    Unknown,
}

impl Outcome {
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Sealed => "sealed",
            Outcome::NotAttempted => "not attempted",
            Outcome::Refused => "refused",
            Outcome::Sent => "sent",
            Outcome::Unknown => "unknown",
        }
    }
}

/// GLOBAL's slot for the seat and epoch, as this node sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotView {
    pub sealed_at: Option<u64>,
    pub has_leaves: bool,
    /// The frame the seat registered at. A seal is sent only past the
    /// next, so a run watching from the next saw every send.
    pub registered_at: u64,
}

impl SlotView {
    fn sealed(slot: Option<&Self>) -> bool {
        slot.is_some_and(|slot| slot.has_leaves && slot.sealed_at.is_some())
    }
}

/// How long a registration not sealed in this node's view waits before
/// it is concluded, from this process's first check of a frame past the
/// epoch's first. The view is the prover tree pulled from an archive
/// every 300 s, and a pull begins only once the epoch's first frame has
/// a successor: a seal GLOBAL took in the window's last frames shows only
/// that late (up to 23 frames measured, 435 s at 18.9 s a frame). Time,
/// not frames: frames checked from a backlog come faster than the view
/// is pulled. 600 s is 32 frames at 18.9 s, 1.4 times the worst lag
/// measured. A run begun later holds from its own first check, as it may
/// hold a view pulled before the epoch. A first check in an epoch's last
/// 600 s never concludes that epoch, as the engines ask only the current
/// epoch, so no line is written for it.
pub const CONCLUDE_HOLD: Duration = Duration::from_secs(600);

/// The most of a refusal's error a line carries.
const ERROR_CHARS: usize = 200;

/// One seat's seal for one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealLine {
    pub epoch: u64,
    pub filter: Vec<u8>,
    pub outcome: Outcome,
    pub reason: Option<Reason>,
    /// Seal attempts refused this epoch, and the error naming their cause
    /// ([`Notes::note_refusal`]).
    pub refusals: u32,
    pub error: Option<String>,
    /// Bytes a sector's labels needed and those free, when the label store
    /// refused them room for an epoch whose registration is missing.
    pub needed_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub sealed_at: Option<u64>,
    /// This member holds the seat: unsealed, it forgoes the epoch's
    /// storage reward.
    pub held: bool,
    /// This process's first live GLOBAL frame ([`Notes::note_live`]).
    pub watching_from: Option<u64>,
    /// Seconds since this process first checked a frame past the epoch's
    /// first ([`CONCLUDE_HOLD`]); 0 when none was.
    pub held_secs: u64,
}

impl SealLine {
    /// A held seat ending its epoch unsealed or sealed late.
    pub fn warns(&self) -> bool {
        self.held && self.reason.is_some()
    }

    /// Chosen by outcome and reason: a seal never tried has no refusal's
    /// warning to point at.
    pub fn check(&self) -> &'static str {
        match (self.outcome, self.reason) {
            (Outcome::NotAttempted, Some(Reason::Other)) => UNTRIED_CHECK,
            (_, reason) => reason.map_or("nothing", Reason::check),
        }
    }
}

impl fmt::Display for SealLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "epoch={} filter={} outcome={} held={}",
            self.epoch,
            hex::encode(&self.filter),
            self.outcome.name(),
            self.held
        )?;
        match self.watching_from {
            Some(from) => write!(f, " watching_from={from}")?,
            None => write!(f, " watching_from=none")?,
        }
        write!(f, " held_secs={}", self.held_secs)?;
        if let Some(at) = self.sealed_at {
            write!(f, " sealed_at={at}")?;
        }
        if let Some(reason) = self.reason {
            write!(f, " reason=\"{}\"", reason.name())?;
        }
        if let Some(needed) = self.needed_bytes {
            write!(f, " needed_bytes={needed}")?;
        }
        if self.needed_bytes.is_some() {
            match self.free_bytes {
                Some(free) => write!(f, " free_bytes={free}")?,
                None => write!(f, " free_bytes=unknown")?,
            }
        }
        if self.refusals > 0 {
            write!(f, " refusals={}", self.refusals)?;
        }
        if let Some(error) = &self.error {
            write!(f, " error=\"{error}\"")?;
        }
        write!(f, " check=\"{}\"", self.check())
    }
}

/// What this process saw refuse or send seals, by seat and epoch, which
/// seats and epochs it concluded, when it first checked a frame past each
/// epoch's first, the first stored GLOBAL head it read and its first live
/// GLOBAL frame. Kept for the last [`KEPT_EPOCHS`] epochs.
#[derive(Default)]
pub struct Notes {
    refusals: BTreeMap<(Vec<u8>, u64), (u32, Reason, String)>,
    disk: BTreeMap<u64, (u64, Option<u64>)>,
    published: BTreeSet<(Vec<u8>, u64)>,
    concluded: BTreeSet<(Vec<u8>, u64)>,
    /// By epoch, this process's first check of a frame past the epoch's
    /// first, on any path ([`Self::due`]).
    past_end: BTreeMap<u64, Instant>,
    first_head: Option<u64>,
    watching_from: Option<u64>,
}

const KEPT_EPOCHS: u64 = 4;

impl Notes {
    /// Classified on the whole error; kept to [`ERROR_CHARS`] characters.
    /// A retry queued past its window follows from an earlier attempt's
    /// refusal, so it only counts: the earlier reason and error stay.
    pub fn note_refusal(&mut self, filter: &[u8], epoch: u64, error: &str) {
        let kept = error
            .char_indices()
            .nth(ERROR_CHARS)
            .map_or(error, |(at, _)| &error[..at]);
        let entry = self.refusals.entry((filter.to_vec(), epoch)).or_insert((
            0,
            Reason::Other,
            String::new(),
        ));
        let noted = entry.0 > 0;
        entry.0 = entry.0.saturating_add(1);
        let reason = Reason::classify(error);
        if noted && reason == Reason::WindowClosed {
            return;
        }
        entry.1 = reason;
        entry.2 = kept.to_string();
    }

    /// Keyed by the epoch the labels register for, as a seal line is: the
    /// label store is asked for the epoch its snapshot, labelling ahead or
    /// sector warmup serves (`storage_labels::LabelStore::admit`).
    pub fn note_disk_short(&mut self, epoch: u64, needed: u64, free: Option<u64>) {
        self.disk.insert(epoch, (needed, free));
    }

    pub fn note_published(&mut self, filter: &[u8], epoch: u64) {
        self.published.insert((filter.to_vec(), epoch));
    }

    /// A GLOBAL frame received as GLOBAL produced it. The first bounds
    /// which seal sends this process's notes can show (a run following
    /// the first send frame is restarted). A frame only checked (a
    /// catch-up frame's anchor) may lag the network by any amount, in
    /// ascending order too, so it is never noted. The hold does not read
    /// it ([`Self::due`]).
    pub fn note_live(&mut self, frame: u64) {
        self.watching_from.get_or_insert(frame);
    }

    /// The stored GLOBAL head, read. The first may lag the network by any
    /// amount (the head stored before a start); one above it was stored
    /// while this process ran, so it is live ([`Self::note_live`]).
    pub fn note_head(&mut self, frame: u64) {
        match self.first_head {
            None => self.first_head = Some(frame),
            Some(first) if frame > first => self.note_live(frame),
            Some(_) => {}
        }
    }

    /// Whether `filter`'s seat in `epoch` concludes at GLOBAL `frame`,
    /// checked at `now`: not yet concluded, and its registration `slot`
    /// sealed in this node's view or the hold over: [`CONCLUDE_HOLD`]
    /// since this process first checked a frame past `window_end`, the
    /// epoch's first frame, on any path. That first check is noted here;
    /// a frame at or before `window_end` starts no hold.
    pub fn due(
        &mut self,
        filter: &[u8],
        epoch: u64,
        window_end: u64,
        frame: u64,
        slot: Option<&SlotView>,
        now: Instant,
    ) -> bool {
        if frame > window_end {
            self.past_end.entry(epoch).or_insert(now);
            let newest = self.past_end.last_key_value().map_or(epoch, |(e, _)| *e);
            let floor = newest.saturating_sub(KEPT_EPOCHS);
            self.past_end.retain(|e, _| *e >= floor);
        }
        let held_out = self
            .past_end
            .get(&epoch)
            .is_some_and(|since| now.saturating_duration_since(*since) >= CONCLUDE_HOLD);
        !self.concluded.contains(&(filter.to_vec(), epoch)) && (SlotView::sealed(slot) || held_out)
    }

    /// The line for `filter`'s seat in `epoch`, once, when [`Self::due`] at
    /// GLOBAL `frame` and `now`; `slot` is GLOBAL's registration, `window`
    /// the frames the seal is sent in (it ends at the epoch's first
    /// frame), `unprovable` whether this process found the registration
    /// cannot be sealed. Not due, the notes are kept for a later frame.
    #[allow(clippy::too_many_arguments)] // each a distinct input of the one line
    pub fn conclude(
        &mut self,
        filter: &[u8],
        epoch: u64,
        window: std::ops::Range<u64>,
        frame: u64,
        slot: Option<SlotView>,
        held: bool,
        unprovable: bool,
        now: Instant,
    ) -> Option<SealLine> {
        if !self.due(filter, epoch, window.end, frame, slot.as_ref(), now) {
            return None;
        }
        let held_secs = self
            .past_end
            .get(&epoch)
            .map_or(0, |since| now.saturating_duration_since(*since).as_secs());
        self.concluded.insert((filter.to_vec(), epoch));
        let floor = epoch.saturating_sub(KEPT_EPOCHS);
        self.concluded.retain(|(_, e)| *e >= floor);
        self.disk.retain(|e, _| *e >= floor);
        let refused = self.refusals.remove(&(filter.to_vec(), epoch));
        self.refusals.retain(|(_, e), _| *e >= floor);
        let published = self.published.remove(&(filter.to_vec(), epoch));
        self.published.retain(|(_, e)| *e >= floor);
        let registered = slot.filter(|slot| slot.has_leaves);
        // Begun after the first frame a seal could be sent in, this process
        // may have missed a send by the one before it.
        let first_send = registered.map_or(window.start, |slot| {
            window.start.max(slot.registered_at.saturating_add(1))
        });
        let restarted = self.watching_from.is_none_or(|from| from > first_send);
        let disk = self.disk.get(&epoch).copied();
        let sealed_at = registered.and_then(|slot| slot.sealed_at);
        let (outcome, reason) = match (registered, sealed_at, &refused) {
            (Some(_), Some(at), _) if at < window.end => (Outcome::Sealed, None),
            (Some(_), Some(_), _) => (Outcome::Sealed, Some(Reason::SealedLate)),
            (Some(_), None, _) if published => (Outcome::Sent, Some(Reason::Undelivered)),
            (_, _, Some((_, reason, _))) => (Outcome::Refused, Some(*reason)),
            (Some(_), None, None) if unprovable => {
                (Outcome::NotAttempted, Some(Reason::LabelNotRetained))
            }
            (Some(_), None, None) if restarted => (Outcome::Unknown, Some(Reason::Restarted)),
            (None, _, None) if disk.is_some() => (Outcome::NotAttempted, Some(Reason::DiskShort)),
            (None, _, None) => (Outcome::NotAttempted, Some(Reason::NotRegistered)),
            (Some(_), None, None) => (Outcome::NotAttempted, Some(Reason::Other)),
        };
        let disk = disk.filter(|_| reason == Some(Reason::DiskShort));
        Some(SealLine {
            epoch,
            filter: filter.to_vec(),
            outcome,
            reason,
            refusals: refused.as_ref().map_or(0, |(n, _, _)| *n),
            error: refused.map(|(_, _, error)| error),
            needed_bytes: disk.map(|(needed, _)| needed),
            free_bytes: disk.and_then(|(_, free)| free),
            sealed_at,
            held: held || registered.is_some(),
            watching_from: self.watching_from,
            held_secs,
        })
    }
}

fn notes() -> std::sync::MutexGuard<'static, Notes> {
    static NOTES: Mutex<Notes> = Mutex::new(Notes {
        refusals: BTreeMap::new(),
        disk: BTreeMap::new(),
        published: BTreeSet::new(),
        concluded: BTreeSet::new(),
        past_end: BTreeMap::new(),
        first_head: None,
        watching_from: None,
    });
    NOTES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A seal job for `filter`'s registration of `epoch` failed with `error`.
pub fn note_refusal(filter: &[u8], epoch: u64, error: &str) {
    notes().note_refusal(filter, epoch, error);
}

/// The label store refused room for labels registering for `epoch`:
/// `needed` bytes, `free`.
pub fn note_disk_short(epoch: u64, needed: u64, free: Option<u64>) {
    notes().note_disk_short(epoch, needed, free);
}

/// The seal part for `filter`'s registration of `epoch` went to the master.
pub fn note_published(filter: &[u8], epoch: u64) {
    notes().note_published(filter, epoch);
}

/// An engine received GLOBAL `frame` as GLOBAL produced it
/// ([`Notes::note_live`]).
pub fn note_live(frame: u64) {
    notes().note_live(frame);
}

/// An engine read GLOBAL `frame` as the stored head ([`Notes::note_head`]).
pub fn note_head(frame: u64) {
    notes().note_head(frame);
}

/// Whether `filter`'s seat concludes its seal for `epoch` at GLOBAL
/// `frame`, checked at `now` ([`Notes::due`]); checked before the work
/// [`conclude`] needs.
pub fn due(filter: &[u8], epoch: u64, frame: u64, slot: Option<&SlotView>, now: Instant) -> bool {
    let window_end = quil_types::consensus::epoch_start_frame(epoch);
    notes().due(filter, epoch, window_end, frame, slot, skewed(now))
}

#[cfg(test)]
thread_local! {
    /// Added to the engines' `now` in tests, which do not wait out the
    /// hold.
    pub(crate) static SKEW: std::cell::Cell<Duration> =
        const { std::cell::Cell::new(Duration::ZERO) };
}

#[cfg(not(test))]
fn skewed(now: Instant) -> Instant {
    now
}

#[cfg(test)]
fn skewed(now: Instant) -> Instant {
    now + SKEW.with(std::cell::Cell::get)
}

/// Log, once per seat and epoch, how the seat's seal for `epoch` ended,
/// when due at GLOBAL `frame` and `now`. A seal for `epoch` is sent while
/// its previous epoch runs.
pub fn conclude(
    filter: &[u8],
    epoch: u64,
    frame: u64,
    slot: Option<SlotView>,
    held: bool,
    unprovable: bool,
    now: Instant,
) {
    use quil_types::consensus::epoch_start_frame;
    let window = epoch_start_frame(epoch.saturating_sub(1))..epoch_start_frame(epoch);
    let now = skewed(now);
    let Some(line) = notes().conclude(filter, epoch, window, frame, slot, held, unprovable, now)
    else {
        return;
    };
    let (outcome, reason) = (
        line.outcome.name(),
        line.reason.map_or("none", Reason::name),
    );
    if line.warns() {
        warn!(epoch, outcome, reason, seal = %line,
            "storage seal: a held seat begins its epoch without a timely sealed registration, so its frames \
             commit no openings root and it forgoes the epoch's storage reward; check what the line names");
    } else {
        info!(epoch, outcome, reason, seal = %line, "storage seal for the epoch concluded");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame past epoch 7's first (its window 600..700).
    const PAST: u64 = 701;

    const MS: Duration = Duration::from_millis(1);

    /// When a test's run first checks a frame past epoch 7's first.
    fn t0() -> Instant {
        static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        *T0.get_or_init(Instant::now)
    }

    /// The first time an unsealed seat of epoch 7 is concluded at.
    fn hold_end() -> Instant {
        t0() + CONCLUDE_HOLD
    }

    impl Notes {
        /// [`Self::conclude`] for epoch 7 (window 600..700) at [`hold_end`].
        fn ended(&mut self, filter: &[u8], slot: Option<SlotView>, held: bool) -> Option<SealLine> {
            self.conclude(filter, 7, 600..700, PAST, slot, held, false, hold_end())
        }
    }

    /// The notes of a run whose first live frame is `from` and which
    /// first checked a frame past epoch 7's first at [`t0`].
    fn watching(from: u64) -> Notes {
        let mut notes = Notes::default();
        notes.note_live(from);
        notes.due(&[], 7, 700, from.max(PAST), None, t0());
        notes
    }

    /// The one way a line says disk short: a held seat with no registration
    /// in an epoch whose labels the label store refused room
    /// ([`Notes::note_disk_short`]), read by the line's own epoch.
    #[test]
    fn a_held_seat_not_registered_while_disk_was_short_renders_free_and_needed_and_warns() {
        let mut notes = watching(550);
        notes.note_disk_short(7, 33_100, Some(30_000));
        let line = notes.ended(&[0xab], None, true).unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::NotAttempted, Some(Reason::DiskShort))
        );
        assert!(line.warns());
        assert_eq!(
            line.to_string(),
            format!(
                "epoch=7 filter=ab outcome=not attempted held=true watching_from=550 \
                 held_secs=600 reason=\"disk short\" needed_bytes=33100 free_bytes=30000 \
                 check=\"{}\"",
                Reason::DiskShort.check()
            )
        );
        assert_eq!(notes.ended(&[0xab], None, true), None, "once");
        println!("seal-report reached: {line}");
        let mut other_epoch = watching(550);
        other_epoch.note_disk_short(8, 33_100, Some(30_000));
        let line = other_epoch.ended(&[0xab], None, true).unwrap();
        assert_eq!(
            (line.reason, line.needed_bytes),
            (Some(Reason::NotRegistered), None),
            "disk short in another epoch: {line}"
        );
    }

    /// The refusals as their emitters build them, through the texts they
    /// share with [`Reason::classify`].
    fn uncertified() -> String {
        quil_types::error::QuilError::StorageWaiting(crate::storage_snapshot::UNCERTIFIED.into())
            .to_string()
    }

    fn window_closed(epoch: u64) -> String {
        quil_types::error::QuilError::ExecutionUnavailable(
            crate::storage_epoch_batch::window_closed_error(epoch),
        )
        .to_string()
    }

    /// A retry queued past its window keeps the earlier attempt's cause
    /// and counts; a refusal after a window-closed one names its own.
    #[test]
    fn a_window_closed_retry_keeps_the_earlier_refusal() {
        let (uncertified, closed) = (uncertified(), window_closed(5));
        let mut notes = watching(550);
        notes.note_refusal(&[0xab], 7, &uncertified);
        notes.note_refusal(&[0xab], 7, &closed);
        notes.note_refusal(&[0xcd], 7, &closed);
        notes.note_refusal(&[0xcd], 7, &uncertified);
        let slot = SlotView {
            sealed_at: None,
            has_leaves: true,
            registered_at: 0,
        };
        for filter in [[0xab], [0xcd]] {
            let line = notes.ended(&filter, Some(slot), true).unwrap();
            assert_eq!(
                (
                    line.outcome,
                    line.reason,
                    line.refusals,
                    line.error.as_deref()
                ),
                (
                    Outcome::Refused,
                    Some(Reason::CertificationPending),
                    2,
                    Some(uncertified.as_str()),
                ),
                "window_closed_kept_cause: {line}"
            );
            println!("seal-report reached: {line}");
        }
    }

    #[test]
    fn each_refusal_names_its_reason() {
        use crate::storage_snapshot::{INITIALIZING, SLOTS_OCCUPIED};
        use quil_types::error::QuilError;
        // A seal that fails for good, as its prepare error reads.
        let for_good = format!(
            "invalid argument: {}",
            quil_crypto::storage_proof::COLUMNS_NOT_REGISTERED
        );
        let busy = format!(
            "waiting: a new sector's labels not admitted to certify it: {} by 1234",
            crate::storage_labels::BUSY
        );
        for (error, reason) in [
            (uncertified(), Reason::CertificationPending),
            (
                QuilError::StorageWaiting(SLOTS_OCCUPIED.into()).to_string(),
                Reason::SlotsOccupied,
            ),
            (
                QuilError::ExecutionUnavailable(INITIALIZING.into()).to_string(),
                Reason::SlotsOccupied,
            ),
            (busy, Reason::SlotsOccupied),
            (for_good, Reason::LabelNotRetained),
            (
                "execution unavailable: the epoch 5 snapshot of ab is not retained here".into(),
                Reason::Other,
            ),
            (window_closed(7), Reason::WindowClosed),
            (
                "the window of epoch 7 has not closed yet".into(),
                Reason::Other,
            ),
            (
                "no stored replica of leaf 00 for epoch 3".into(),
                Reason::Other,
            ),
        ] {
            assert_eq!(Reason::classify(&error), reason, "{error}");
        }
        println!("seal-report reached: every refusal classified");
    }

    #[test]
    fn a_timely_seal_is_info_and_an_unregistered_unheld_seat_does_not_warn() {
        let mut notes = watching(550);
        let sealed = SlotView {
            sealed_at: Some(699),
            has_leaves: true,
            registered_at: 0,
        };
        let line = notes.ended(&[1], Some(sealed), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.warns()),
            (Outcome::Sealed, None, false)
        );
        assert_eq!(line.check(), "nothing");
        let late = SlotView {
            sealed_at: Some(700),
            ..sealed
        };
        let line = notes.ended(&[2], Some(late), true).unwrap();
        assert_eq!(
            (line.reason, line.warns()),
            (Some(Reason::SealedLate), true)
        );
        let line = notes.ended(&[3], None, false).unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.warns()),
            (Outcome::NotAttempted, Some(Reason::NotRegistered), false)
        );
        let line = notes.ended(&[4], None, true).unwrap();
        assert!(line.warns(), "a held seat with no registration warns");
        println!("seal-report reached: {line}");
    }

    const UNSEALED: SlotView = SlotView {
        sealed_at: None,
        has_leaves: true,
        registered_at: 0,
    };

    #[test]
    fn a_published_seal_unsealed_concludes_undelivered() {
        let mut notes = watching(550);
        notes.note_published(&[0xab], 7);
        let line = notes.ended(&[0xab], Some(UNSEALED), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::Sent, Some(Reason::Undelivered)),
            "a sent seal never sealed concludes sent, undelivered"
        );
        assert!(line.warns());
        assert_eq!(
            line.to_string(),
            format!(
                "epoch=7 filter=ab outcome=sent held=true watching_from=550 held_secs=600 \
                 reason=\"undelivered\" check=\"{}\"",
                Reason::Undelivered.check()
            )
        );
        assert!(line.check().contains("'storage epoch proof undelivered'"));
        // Refused once, then sent: the send is what failed, the refusal
        // still counted.
        notes.note_refusal(&[0xcd], 7, crate::storage_snapshot::SLOTS_OCCUPIED);
        notes.note_published(&[0xcd], 7);
        let line = notes.ended(&[0xcd], Some(UNSEALED), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.refusals),
            (Outcome::Sent, Some(Reason::Undelivered), 1)
        );
        // Watched from before the window opened and never sent.
        let line = notes.ended(&[0xef], Some(UNSEALED), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::NotAttempted, Some(Reason::Other))
        );
        println!("seal-report reached: {line}");
    }

    /// The check text follows the outcome too: a seal this run never tried
    /// points at no refusal's warning, a refused one at its warning.
    #[test]
    fn a_seal_never_tried_names_no_refusal_warning() {
        const REFUSAL_WARNING: &str = "'storage seal part not prepared'";
        let mut notes = watching(550);
        let line = notes.ended(&[0xab], Some(UNSEALED), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.refusals),
            (Outcome::NotAttempted, Some(Reason::Other), 0)
        );
        assert!(
            !line.check().contains(REFUSAL_WARNING),
            "a seal never tried names no refusal's warning: {}",
            line.check()
        );
        assert!(line
            .to_string()
            .contains("'storage epoch proof check still running'"));
        notes.note_refusal(&[0xcd], 7, "no stored replica of leaf 00 for epoch 3");
        let line = notes.ended(&[0xcd], Some(UNSEALED), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.refusals),
            (Outcome::Refused, Some(Reason::Other), 1)
        );
        assert!(line.check().contains(REFUSAL_WARNING));
        println!("seal-report reached: {line}");
    }

    #[test]
    fn a_run_begun_after_the_send_window_opened_concludes_unknown() {
        // Begun after the epoch began, as at a restart 67 frames in.
        let after = 799;
        let mut restarted = watching(767);
        let line = restarted
            .conclude(
                &[0xab],
                7,
                600..700,
                after,
                Some(UNSEALED),
                true,
                false,
                hold_end(),
            )
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::Unknown, Some(Reason::Restarted)),
            "a run that missed the send window cannot tell whether it was sent"
        );
        assert!(line.warns());
        assert_eq!(
            line.to_string(),
            format!(
                "epoch=7 filter=ab outcome=unknown held=true watching_from=767 held_secs=600 \
                 reason=\"node restarted since the send\" check=\"{}\"",
                Reason::Restarted.check()
            )
        );
        // Begun inside the window: still blind to the earlier sends.
        let mut midway = watching(650);
        let line = midway.ended(&[0xab], Some(UNSEALED), true).unwrap();
        assert_eq!(line.outcome, Outcome::Unknown);
        // What this run itself saw still names its reason.
        restarted.note_refusal(&[0xcd], 7, crate::storage_snapshot::SLOTS_OCCUPIED);
        let line = restarted
            .conclude(
                &[0xcd],
                7,
                600..700,
                after,
                Some(UNSEALED),
                true,
                false,
                hold_end(),
            )
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::Refused, Some(Reason::SlotsOccupied))
        );
        // Begun at the window's first frame: it saw every send.
        let mut whole = watching(600);
        let line = whole.ended(&[0xab], Some(UNSEALED), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::NotAttempted, Some(Reason::Other))
        );
        println!("seal-report reached: {line}");
    }

    /// A seal GLOBAL took in the window's last frames reaches this node's
    /// view a registry pull later: the seat is not concluded unsealed
    /// before the hold ends, and a seal seen meanwhile concludes it sealed.
    #[test]
    fn an_unsealed_seat_is_not_concluded_before_the_hold_ends() {
        let mut notes = watching(550);
        notes.note_published(&[0xab], 7);
        for (frame, now) in [(700, t0()), (PAST + 400, hold_end() - MS)] {
            assert_eq!(
                notes.conclude(
                    &[0xab],
                    7,
                    600..700,
                    frame,
                    Some(UNSEALED),
                    true,
                    false,
                    now
                ),
                None,
                "an unsealed seat is not concluded before the view can reach the epoch"
            );
        }
        let sealed = SlotView {
            sealed_at: Some(699),
            ..UNSEALED
        };
        assert!(notes.due(&[0xab], 7, 700, 705, Some(&sealed), t0()));
        let line = notes
            .conclude(&[0xab], 7, 600..700, 705, Some(sealed), true, false, t0())
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.warns()),
            (Outcome::Sealed, None, false)
        );
        assert!(
            !notes.due(&[0xab], 7, 700, PAST, Some(&sealed), hold_end()),
            "once"
        );
        println!("seal-report reached: {line}");
    }

    /// A run begun past the hold, as at a restart across the epoch's
    /// first frame, may hold a view pulled before the epoch: its unsealed
    /// seat is held from its own first check, however many frames past
    /// the epoch's first, and not by an earlier run's; a sealed one not.
    #[test]
    fn a_run_begun_past_the_hold_holds_from_its_first_frame() {
        let mut earlier = watching(550);
        let begun = PAST + 400;
        let t1 = t0() + Duration::from_secs(500);
        let mut notes = Notes::default();
        notes.note_live(begun);
        for now in [t1, hold_end(), t1 + CONCLUDE_HOLD - MS] {
            assert_eq!(
                notes.conclude(
                    &[0xab],
                    7,
                    600..700,
                    begun,
                    Some(UNSEALED),
                    true,
                    false,
                    now
                ),
                None,
                "a run begun past the hold waits for its view to reach the epoch"
            );
        }
        assert!(
            earlier.due(&[0xab], 7, 700, begun, Some(&UNSEALED), hold_end()),
            "the earlier run holds from its own first check"
        );
        let sealed = SlotView {
            sealed_at: Some(699),
            ..UNSEALED
        };
        assert!(notes.due(&[0xab], 7, 700, begun, Some(&sealed), t1));
        let end = t1 + CONCLUDE_HOLD;
        let line = notes.conclude(
            &[0xab],
            7,
            600..700,
            begun + 1,
            Some(UNSEALED),
            true,
            false,
            end,
        );
        assert!(
            line.is_some(),
            "a run begun past the hold concludes once held from its first check"
        );
        let line = line.unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.held_secs),
            (Outcome::Unknown, Some(Reason::Restarted), 600)
        );
        println!("seal-report reached: {line}");
    }

    /// The hold is time, not frames: a backlog of frames past the epoch's
    /// first, checked at once, ends no hold, which ends [`CONCLUDE_HOLD`]
    /// after the first of them, once.
    #[test]
    fn a_backlog_of_frames_does_not_end_the_hold() {
        let mut notes = Notes::default();
        notes.note_live(550);
        let slot = Some(UNSEALED);
        for frame in PAST..PAST + 400 {
            assert_eq!(
                notes.conclude(&[0xab], 7, 600..700, frame, slot, true, false, t0()),
                None,
                "frame {frame}, checked at once with the epoch's first frames, ends no hold"
            );
        }
        let last = PAST + 400;
        let line = notes.conclude(
            &[0xab],
            7,
            600..700,
            last,
            slot,
            true,
            false,
            hold_end() - MS,
        );
        assert_eq!(
            line, None,
            "held until {CONCLUDE_HOLD:?} after the first check"
        );
        let line = notes.conclude(&[0xab], 7, 600..700, last, slot, true, false, hold_end());
        assert!(
            line.is_some(),
            "the hold ends {CONCLUDE_HOLD:?} after the first check"
        );
        let line = line.unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.held_secs),
            (Outcome::NotAttempted, Some(Reason::Other), 600)
        );
        let again = notes.conclude(
            &[0xab],
            7,
            600..700,
            last,
            slot,
            true,
            false,
            hold_end() + MS,
        );
        assert_eq!(again, None, "once");
        println!("seal-report reached: {line}");
    }

    /// Only a frame past the epoch's first starts its hold: one at or
    /// before it, checked however late, starts none.
    #[test]
    fn a_frame_at_or_before_the_epochs_first_starts_no_hold() {
        let mut notes = Notes::default();
        notes.note_live(550);
        let slot = Some(UNSEALED);
        let late = hold_end() + CONCLUDE_HOLD;
        for (frame, now) in [(699, t0()), (700, t0()), (700, hold_end()), (699, late)] {
            assert_eq!(
                notes.conclude(&[0xab], 7, 600..700, frame, slot, true, false, now),
                None,
                "frame {frame} is not past the epoch's first: no hold began"
            );
        }
        assert!(notes.past_end.is_empty(), "{:?}", notes.past_end);
        let line = notes.conclude(&[0xab], 7, 600..700, PAST, slot, true, false, late);
        assert_eq!(
            line, None,
            "the first frame past the epoch's first starts the hold"
        );
        let line = notes.conclude(
            &[0xab],
            7,
            600..700,
            PAST,
            slot,
            true,
            false,
            late + CONCLUDE_HOLD,
        );
        assert!(
            line.is_some(),
            "held from the first frame past the epoch's first"
        );
        println!("seal-report reached: {}", line.unwrap());
    }

    /// Each epoch holds from its own first check past its first frame, and
    /// a sealed registration concludes at that check.
    #[test]
    fn each_epoch_holds_from_its_own_first_check() {
        let mut notes = watching(550);
        let t1 = t0() + Duration::from_secs(300);
        let slot = Some(UNSEALED);
        let line = notes.conclude(&[0xab], 8, 700..800, 801, slot, true, false, t1);
        assert_eq!(line, None, "epoch 8's hold begins at its own first check");
        let sealed = SlotView {
            sealed_at: Some(799),
            ..UNSEALED
        };
        let line = notes
            .conclude(&[0xcd], 8, 700..800, 801, Some(sealed), true, false, t1)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.held_secs),
            (Outcome::Sealed, None, 0),
            "a sealed registration concludes at the first check"
        );
        let line = notes.conclude(&[0xab], 7, 600..700, 802, slot, true, false, hold_end());
        assert!(line.is_some(), "epoch 7 holds from its first check");
        let line = notes.conclude(&[0xab], 8, 700..800, 802, slot, true, false, hold_end());
        assert_eq!(
            line, None,
            "epoch 8 holds from its own first check, not epoch 7's"
        );
        let line = notes.conclude(
            &[0xab],
            8,
            700..800,
            803,
            slot,
            true,
            false,
            t1 + CONCLUDE_HOLD,
        );
        assert!(
            line.is_some(),
            "epoch 8's hold ends {CONCLUDE_HOLD:?} after its first check"
        );
        println!("seal-report reached: {}", line.unwrap());
    }

    /// The first checks are kept for the last [`KEPT_EPOCHS`] epochs.
    #[test]
    fn first_checks_are_kept_for_the_last_epochs() {
        let mut notes = Notes::default();
        for epoch in 1..=20u64 {
            let window_end = epoch * 100;
            notes.due(&[0xab], epoch, window_end, window_end + 1, None, t0());
            assert!(
                notes.past_end.len() as u64 <= KEPT_EPOCHS + 1
                    && notes.past_end.contains_key(&epoch),
                "epoch {epoch}: {:?}",
                notes.past_end.keys()
            );
        }
        notes.due(&[0xab], 3, 300, 301, None, t0());
        let kept: Vec<u64> = notes.past_end.keys().copied().collect();
        assert_eq!(
            kept,
            vec![16, 17, 18, 19, 20],
            "an epoch older than those kept is not"
        );
        println!("seal-report reached: {kept:?}");
    }

    /// The hold ends: a seat still unsealed is concluded with what this
    /// process noted during it, once.
    #[test]
    fn an_unsealed_seat_concludes_when_the_hold_ends() {
        let mut notes = watching(550);
        notes.note_refusal(&[0xab], 7, crate::storage_snapshot::SLOTS_OCCUPIED);
        notes.note_published(&[0xab], 7);
        let slot = Some(UNSEALED);
        let line = notes.conclude(
            &[0xab],
            7,
            600..700,
            PAST,
            slot,
            true,
            false,
            hold_end() - MS,
        );
        assert_eq!(line, None);
        let line = notes.ended(&[0xab], slot, true);
        assert!(
            line.is_some(),
            "a seat still unsealed when the hold ends is concluded"
        );
        let line = line.unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.refusals, line.held_secs),
            (Outcome::Sent, Some(Reason::Undelivered), 1, 600)
        );
        assert!(line.warns());
        let again = notes.conclude(
            &[0xab],
            7,
            600..700,
            PAST,
            slot,
            true,
            false,
            hold_end() + MS,
        );
        assert_eq!(again, None, "once");
        println!("seal-report reached: {line}");
    }

    /// No seal is sent before the frame after the seat registered: a run
    /// begun by then saw every send.
    #[test]
    fn a_run_begun_by_the_first_send_frame_saw_every_send() {
        let slot = SlotView {
            registered_at: 640,
            ..UNSEALED
        };
        let mut first = watching(641);
        let line = first.ended(&[0xab], Some(slot), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::NotAttempted, Some(Reason::Other)),
            "a run begun at the first send frame saw every send"
        );
        let mut later = watching(642);
        let line = later.ended(&[0xab], Some(slot), true).unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::Unknown, Some(Reason::Restarted))
        );
        println!("seal-report reached: {line}");
    }

    /// Only a frame received live or a stored head above the first one
    /// read makes a run live: the head stored before a start, and heads at
    /// or below it, do not.
    #[test]
    fn only_a_received_frame_or_an_advanced_head_is_live() {
        let mut notes = Notes::default();
        notes.note_head(550);
        notes.note_head(550);
        notes.note_head(540);
        assert_eq!(
            notes.watching_from, None,
            "a stale stored head, read first, is not live"
        );
        notes.note_head(551);
        assert_eq!(
            notes.watching_from,
            Some(551),
            "a head stored while the run ran is live"
        );
        let mut received = Notes::default();
        received.note_live(552);
        received.note_head(560);
        received.note_head(561);
        assert_eq!(
            received.watching_from,
            Some(552),
            "the first live frame stays"
        );
        println!("seal-report reached: {:?}", notes.watching_from);
    }

    /// A refusal's error is kept to a bounded length, cut on a character
    /// boundary, and classified on the whole text.
    #[test]
    fn a_long_refusal_error_is_cut_and_still_classified() {
        let long = format!("{}: {}", "\u{e9}".repeat(5_000), uncertified());
        let mut notes = watching(550);
        notes.note_refusal(&[0xab], 7, &long);
        let line = notes.ended(&[0xab], Some(UNSEALED), true).unwrap();
        assert_eq!(line.reason, Some(Reason::CertificationPending));
        let error = line.error.clone().unwrap();
        assert!(
            error.chars().count() <= ERROR_CHARS && line.to_string().len() < 1_000,
            "a refusal's error is kept to {ERROR_CHARS} characters: {} kept",
            error.chars().count()
        );
        assert!(error.chars().all(|c| c == '\u{e9}'));
        println!("seal-report reached: {} chars kept", error.chars().count());
    }
}
