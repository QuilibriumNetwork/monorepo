//! One line per seat and seal epoch: whether this node sealed the seat's
//! registration before the epoch began and, when not, why and what the
//! operator should check. Without it a node logged hundreds of "no sealed
//! storage registration" lines across its cores and never said why a slot
//! did not seal (2026-11-16).
//!
//! The seal's job notes what refused it or that it sent the seal part
//! ([`note_refusal`], [`note_published`]), the label store what disk it
//! lacked ([`note_disk_short`]); the seat's engine notes each GLOBAL
//! frame it checks ([`note_frame`]) and concludes the epoch once, at its
//! first frame ([`conclude`]). Notes live in the process: one started
//! after the seal's send window opened says so instead of guessing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Mutex, PoisonError};

use tracing::{info, warn};

/// Why a registration did not seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    DiskShort,
    CertificationPending,
    SlotsOccupied,
    LabelNotRetained,
    NotRegistered,
    SealedLate,
    Undelivered,
    Restarted,
    Other,
}

impl Reason {
    /// The reason a seal job's error names.
    pub fn classify(error: &str) -> Self {
        if error.contains("disk space") {
            Reason::DiskShort
        } else if error.contains("certification must finish") {
            Reason::CertificationPending
        } else if error.contains("slots are occupied") || error.contains("already runs") {
            Reason::SlotsOccupied
        } else if error.contains("not be retained")
            || error.contains("not retained")
            || error.contains("cannot be sealed")
        {
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
                "nothing: the registration was labelled by another build or its labels were \
                 dropped; the next registration, labelled by this build, seals"
            }
            Reason::NotRegistered => {
                "the storage snapshot job's failure warnings and free disk space: no \
                 registration for this epoch reached GLOBAL"
            }
            Reason::SealedLate => {
                "the 'storage seal part' and 'storage epoch proof' lines: the seal landed \
                 after the epoch began"
            }
            Reason::Undelivered => {
                "the master's 'storage epoch proof undelivered' errors and its window summary's \
                 refused count: archives refused the proof carrying the seal (as 'rank buffer \
                 full') until its window ended"
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
}

/// One seat's seal for one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealLine {
    pub epoch: u64,
    pub filter: Vec<u8>,
    pub outcome: Outcome,
    pub reason: Option<Reason>,
    /// Seal attempts refused this epoch, and the last one's error.
    pub refusals: u32,
    pub error: Option<String>,
    /// Bytes a sector's labels needed and those free, when disk refused.
    pub needed_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub sealed_at: Option<u64>,
    /// This member holds the seat: unsealed, it forgoes the epoch's
    /// storage reward.
    pub held: bool,
}

impl SealLine {
    /// A held seat ending its epoch unsealed or sealed late.
    pub fn warns(&self) -> bool {
        self.held && self.reason.is_some()
    }

    pub fn check(&self) -> &'static str {
        self.reason.map_or("nothing", Reason::check)
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
/// seats and epochs it concluded, and the first GLOBAL frame it checked.
/// Kept for the last [`KEPT_EPOCHS`] epochs.
#[derive(Default)]
pub struct Notes {
    refusals: BTreeMap<(Vec<u8>, u64), (u32, String)>,
    disk: BTreeMap<u64, (u64, Option<u64>)>,
    published: BTreeSet<(Vec<u8>, u64)>,
    concluded: BTreeSet<(Vec<u8>, u64)>,
    watching_from: Option<u64>,
}

const KEPT_EPOCHS: u64 = 4;

impl Notes {
    pub fn note_refusal(&mut self, filter: &[u8], epoch: u64, error: &str) {
        let entry = self.refusals.entry((filter.to_vec(), epoch)).or_default();
        entry.0 = entry.0.saturating_add(1);
        entry.1 = error.to_string();
    }

    pub fn note_disk_short(&mut self, epoch: u64, needed: u64, free: Option<u64>) {
        self.disk.insert(epoch, (needed, free));
    }

    pub fn note_published(&mut self, filter: &[u8], epoch: u64) {
        self.published.insert((filter.to_vec(), epoch));
    }

    /// A GLOBAL frame this process checked; the first one bounds what its
    /// notes can show.
    pub fn note_frame(&mut self, frame: u64) {
        self.watching_from.get_or_insert(frame);
    }

    /// The line for `filter`'s seat in `epoch`, once; `slot` is GLOBAL's
    /// registration, `window` the frames the seal is sent in (it ends at
    /// the epoch's first frame), `unprovable` whether this process found
    /// the registration cannot be sealed.
    pub fn conclude(
        &mut self,
        filter: &[u8],
        epoch: u64,
        window: std::ops::Range<u64>,
        slot: Option<SlotView>,
        held: bool,
        unprovable: bool,
    ) -> Option<SealLine> {
        if !self.concluded.insert((filter.to_vec(), epoch)) {
            return None;
        }
        let floor = epoch.saturating_sub(KEPT_EPOCHS);
        self.concluded.retain(|(_, e)| *e >= floor);
        self.disk.retain(|e, _| *e >= floor);
        let refused = self.refusals.remove(&(filter.to_vec(), epoch));
        self.refusals.retain(|(_, e), _| *e >= floor);
        let published = self.published.remove(&(filter.to_vec(), epoch));
        self.published.retain(|(_, e)| *e >= floor);
        // Begun after the window opened, this process may have missed a
        // send by the one before it.
        let restarted = self.watching_from.is_none_or(|from| from > window.start);
        let disk = self.disk.get(&epoch).copied();
        let registered = slot.filter(|slot| slot.has_leaves);
        let sealed_at = registered.and_then(|slot| slot.sealed_at);
        let (outcome, reason) = match (registered, sealed_at, &refused) {
            (Some(_), Some(at), _) if at < window.end => (Outcome::Sealed, None),
            (Some(_), Some(_), _) => (Outcome::Sealed, Some(Reason::SealedLate)),
            (Some(_), None, _) if published => (Outcome::Sent, Some(Reason::Undelivered)),
            (_, _, Some((_, error))) => (Outcome::Refused, Some(Reason::classify(error))),
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
            refusals: refused.as_ref().map_or(0, |(n, _)| *n),
            error: refused.map(|(_, error)| error),
            needed_bytes: disk.map(|(needed, _)| needed),
            free_bytes: disk.and_then(|(_, free)| free),
            sealed_at,
            held: held || registered.is_some(),
        })
    }
}

fn notes() -> std::sync::MutexGuard<'static, Notes> {
    static NOTES: Mutex<Notes> = Mutex::new(Notes {
        refusals: BTreeMap::new(),
        disk: BTreeMap::new(),
        published: BTreeSet::new(),
        concluded: BTreeSet::new(),
        watching_from: None,
    });
    NOTES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A seal job for `filter`'s registration of `epoch` failed with `error`.
pub fn note_refusal(filter: &[u8], epoch: u64, error: &str) {
    notes().note_refusal(filter, epoch, error);
}

/// The label store refused a sector of `epoch`: `needed` bytes, `free`.
pub fn note_disk_short(epoch: u64, needed: u64, free: Option<u64>) {
    notes().note_disk_short(epoch, needed, free);
}

/// The seal part for `filter`'s registration of `epoch` went to the master.
pub fn note_published(filter: &[u8], epoch: u64) {
    notes().note_published(filter, epoch);
}

/// A seat's engine checks GLOBAL `frame` for its seals and settlements.
pub fn note_frame(frame: u64) {
    notes().note_frame(frame);
}

/// Log, once per seat and epoch, how the seat's seal for `epoch` ended.
/// A seal for `epoch` is sent while its previous epoch runs.
pub fn conclude(filter: &[u8], epoch: u64, slot: Option<SlotView>, held: bool, unprovable: bool) {
    use quil_types::consensus::epoch_start_frame;
    let window = epoch_start_frame(epoch.saturating_sub(1))..epoch_start_frame(epoch);
    let Some(line) = notes().conclude(filter, epoch, window, slot, held, unprovable) else {
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

    const DISK: &str = "persistent sector: a new sector's labels not admitted to certify it: too \
                        little free disk space, or the sector labelled already by another task";

    #[test]
    fn a_held_seat_refused_for_disk_renders_free_and_needed_and_warns() {
        let mut notes = Notes::default();
        notes.note_disk_short(7, 33_100, Some(30_000));
        notes.note_refusal(&[0xab], 7, DISK);
        notes.note_refusal(&[0xab], 7, DISK);
        let slot = SlotView {
            sealed_at: None,
            has_leaves: true,
        };
        let line = notes
            .conclude(&[0xab], 7, 600..700, Some(slot), true, false)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::Refused, Some(Reason::DiskShort))
        );
        assert!(line.warns());
        assert_eq!(
            line.to_string(),
            format!(
                "epoch=7 filter=ab outcome=refused held=true reason=\"disk short\" \
                 needed_bytes=33100 free_bytes=30000 refusals=2 error=\"{DISK}\" check=\"{}\"",
                Reason::DiskShort.check()
            )
        );
        assert_eq!(
            notes.conclude(&[0xab], 7, 600..700, Some(slot), true, false),
            None,
            "once"
        );
        println!("seal-report reached: {line}");
    }

    #[test]
    fn each_refusal_names_its_reason() {
        for (error, reason) in [
            (DISK, Reason::DiskShort),
            (
                "sector certification must finish before data registration",
                Reason::CertificationPending,
            ),
            (
                "sector initialization slots are occupied",
                Reason::SlotsOccupied,
            ),
            ("sector initialization already runs", Reason::SlotsOccupied),
            (
                "initial sector labelling could not be retained",
                Reason::LabelNotRetained,
            ),
            (
                "the registration cannot be sealed",
                Reason::LabelNotRetained,
            ),
            ("no stored replica of leaf 00 for epoch 3", Reason::Other),
        ] {
            assert_eq!(Reason::classify(error), reason, "{error}");
        }
        println!("seal-report reached: every refusal classified");
    }

    #[test]
    fn a_timely_seal_is_info_and_an_unregistered_unheld_seat_does_not_warn() {
        let mut notes = Notes::default();
        let sealed = SlotView {
            sealed_at: Some(699),
            has_leaves: true,
        };
        let line = notes
            .conclude(&[1], 7, 600..700, Some(sealed), true, false)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.warns()),
            (Outcome::Sealed, None, false)
        );
        assert_eq!(line.check(), "nothing");
        let late = SlotView {
            sealed_at: Some(700),
            ..sealed
        };
        let line = notes
            .conclude(&[2], 7, 600..700, Some(late), true, false)
            .unwrap();
        assert_eq!(
            (line.reason, line.warns()),
            (Some(Reason::SealedLate), true)
        );
        let line = notes
            .conclude(&[3], 7, 600..700, None, false, false)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.warns()),
            (Outcome::NotAttempted, Some(Reason::NotRegistered), false)
        );
        let line = notes
            .conclude(&[4], 7, 600..700, None, true, false)
            .unwrap();
        assert!(line.warns(), "a held seat with no registration warns");
        println!("seal-report reached: {line}");
    }

    const UNSEALED: SlotView = SlotView {
        sealed_at: None,
        has_leaves: true,
    };

    #[test]
    fn a_published_seal_unsealed_concludes_undelivered() {
        let mut notes = Notes::default();
        notes.note_frame(550);
        notes.note_published(&[0xab], 7);
        let line = notes
            .conclude(&[0xab], 7, 600..700, Some(UNSEALED), true, false)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::Sent, Some(Reason::Undelivered)),
            "a sent seal never sealed concludes sent, undelivered"
        );
        assert!(line.warns());
        assert_eq!(
            line.to_string(),
            format!(
                "epoch=7 filter=ab outcome=sent held=true reason=\"undelivered\" check=\"{}\"",
                Reason::Undelivered.check()
            )
        );
        assert!(line.check().contains("'storage epoch proof undelivered'"));
        // Refused once, then sent: the send is what failed, the refusal
        // still counted.
        notes.note_refusal(&[0xcd], 7, "sector initialization slots are occupied");
        notes.note_published(&[0xcd], 7);
        let line = notes
            .conclude(&[0xcd], 7, 600..700, Some(UNSEALED), true, false)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason, line.refusals),
            (Outcome::Sent, Some(Reason::Undelivered), 1)
        );
        // Watched from before the window opened and never sent.
        let line = notes
            .conclude(&[0xef], 7, 600..700, Some(UNSEALED), true, false)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::NotAttempted, Some(Reason::Other))
        );
        println!("seal-report reached: {line}");
    }

    #[test]
    fn a_run_begun_after_the_send_window_opened_concludes_unknown() {
        // Begun after the epoch began, as at a restart 367 frames in.
        let mut restarted = Notes::default();
        restarted.note_frame(767);
        let line = restarted
            .conclude(&[0xab], 7, 600..700, Some(UNSEALED), true, false)
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
                "epoch=7 filter=ab outcome=unknown held=true reason=\"node restarted since the \
                 send\" check=\"{}\"",
                Reason::Restarted.check()
            )
        );
        // Begun inside the window: still blind to the earlier sends.
        let mut midway = Notes::default();
        midway.note_frame(650);
        let line = midway
            .conclude(&[0xab], 7, 600..700, Some(UNSEALED), true, false)
            .unwrap();
        assert_eq!(line.outcome, Outcome::Unknown);
        // What this run itself saw still names its reason.
        restarted.note_refusal(&[0xcd], 7, "sector initialization slots are occupied");
        let line = restarted
            .conclude(&[0xcd], 7, 600..700, Some(UNSEALED), true, false)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::Refused, Some(Reason::SlotsOccupied))
        );
        // Begun at the window's first frame: it saw every send.
        let mut whole = Notes::default();
        whole.note_frame(600);
        let line = whole
            .conclude(&[0xab], 7, 600..700, Some(UNSEALED), true, false)
            .unwrap();
        assert_eq!(
            (line.outcome, line.reason),
            (Outcome::NotAttempted, Some(Reason::Other))
        );
        println!("seal-report reached: {line}");
    }
}
