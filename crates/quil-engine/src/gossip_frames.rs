//! Admission of full app-shard frames received on a shard's frame topic.
//!
//! Any peer may publish on that topic, so nothing it sends may make the
//! engine loop wait on the network, hold memory without bound, or displace
//! a body this worker already holds. The engine checks a frame against its
//! own state first (address, cursor, held bodies), validates it with local
//! data only, and fetches what validation lacks off the loop, paced here.
//! Frames without a certificate of their own wait in a small buffer, keyed
//! by their output digest, until a certified child that names them is
//! committed.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quil_types::proto::global::AppShardFrame;

/// Frame numbers above the materialized frame whose uncertified bodies
/// are held.
pub(crate) const UNCERTIFIED_WINDOW: u64 = 16;
/// Uncertified bodies held per shard.
pub(crate) const UNCERTIFIED_CAP: usize = 16;
/// Uncertified bodies held per frame number.
pub(crate) const UNCERTIFIED_PER_FRAME: usize = 2;
/// Encoded bytes of the uncertified bodies held per shard.
pub(crate) const UNCERTIFIED_BYTES: usize = 32 * 1024 * 1024;

/// Why an uncertified body is not held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotHeld {
    /// At or below the materialized frame, or too far above it.
    OutsideWindow,
    /// This body is held already.
    Duplicate,
    /// The frame number or the shard has no room left.
    Full,
}

/// Uncertified bodies received from peers, keyed by frame number and
/// output digest, which the certified child names as its parent.
#[derive(Debug, Default)]
pub(crate) struct UncertifiedFrames {
    frames: BTreeMap<(u64, [u8; 32]), (AppShardFrame, usize)>,
    bytes: usize,
}

impl UncertifiedFrames {
    /// Whether a body of `bytes` for frame `number` with output `digest`
    /// would be held while the materialized frame is `cursor`. Checked
    /// before the frame is validated, and again when it is held.
    pub(crate) fn admits(
        &self,
        cursor: u64,
        number: u64,
        digest: &[u8; 32],
        bytes: usize,
    ) -> Result<(), NotHeld> {
        if number <= cursor || number - cursor > UNCERTIFIED_WINDOW {
            return Err(NotHeld::OutsideWindow);
        }
        if self.frames.contains_key(&(number, *digest)) {
            return Err(NotHeld::Duplicate);
        }
        let at_number = self
            .frames
            .range((number, [0; 32])..=(number, [0xff; 32]))
            .count();
        if at_number >= UNCERTIFIED_PER_FRAME
            || self.frames.len() >= UNCERTIFIED_CAP
            || self.bytes.saturating_add(bytes) > UNCERTIFIED_BYTES
        {
            return Err(NotHeld::Full);
        }
        Ok(())
    }

    /// Hold `frame` (frame `number`, output `digest`, `bytes` encoded) when
    /// [`Self::admits`] allows it. A held body is never replaced.
    pub(crate) fn insert(
        &mut self,
        cursor: u64,
        number: u64,
        digest: [u8; 32],
        bytes: usize,
        frame: AppShardFrame,
    ) -> Result<(), NotHeld> {
        self.admits(cursor, number, &digest, bytes)?;
        self.frames.insert((number, digest), (frame, bytes));
        self.bytes += bytes;
        Ok(())
    }

    /// Remove and return the body of frame `number` whose output digest is
    /// `selector`, the parent selector of its certified child.
    pub(crate) fn take(&mut self, number: u64, selector: &[u8]) -> Option<AppShardFrame> {
        let digest = <[u8; 32]>::try_from(selector).ok()?;
        let (frame, bytes) = self.frames.remove(&(number, digest))?;
        self.bytes -= bytes;
        Some(frame)
    }

    /// Drop the bodies at or below the materialized frame `cursor`.
    pub(crate) fn retain_above(&mut self, cursor: u64) {
        let kept = self.frames.split_off(&(cursor.saturating_add(1), [0; 32]));
        let dropped: usize = self.frames.values().map(|(_, bytes)| bytes).sum();
        self.bytes -= dropped;
        self.frames = kept;
    }

    pub(crate) fn clear(&mut self) {
        self.frames.clear();
        self.bytes = 0;
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }
}

/// Least time between two preparations started for one shard.
pub(crate) const PREP_INTERVAL: Duration = Duration::from_secs(5);
/// How long a frame whose preparation started is not prepared again.
pub(crate) const PREP_FORGET: Duration = Duration::from_secs(10 * 60);
/// Frame digests remembered as prepared.
const PREP_REMEMBERED: usize = 256;

/// Why a preparation does not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrepRefused {
    /// This frame was prepared within [`PREP_FORGET`].
    Tried,
    /// A preparation of this shard is running.
    Busy,
    /// One started within [`PREP_INTERVAL`].
    Paced,
}

/// Pacing of the off-loop preparation (GLOBAL anchor, storage history) of
/// certified frames received from peers: one at a time per shard, at most
/// one start per [`PREP_INTERVAL`], each frame once per [`PREP_FORGET`].
#[derive(Debug)]
pub(crate) struct PrepBudget {
    busy: Arc<AtomicBool>,
    last_start: Option<Instant>,
    tried: HashMap<[u8; 32], Instant>,
}

impl Default for PrepBudget {
    fn default() -> Self {
        Self {
            busy: Arc::new(AtomicBool::new(false)),
            last_start: None,
            tried: HashMap::new(),
        }
    }
}

impl PrepBudget {
    /// Start the preparation of the frame with output `digest` at `now`,
    /// when allowed. The returned flag is the running mark: the
    /// preparation clears it when it ends.
    pub(crate) fn start(
        &mut self,
        digest: [u8; 32],
        now: Instant,
    ) -> Result<Arc<AtomicBool>, PrepRefused> {
        self.tried
            .retain(|_, at| now.saturating_duration_since(*at) < PREP_FORGET);
        if self.tried.contains_key(&digest) {
            return Err(PrepRefused::Tried);
        }
        if self.busy.load(Ordering::Acquire) {
            return Err(PrepRefused::Busy);
        }
        if self
            .last_start
            .is_some_and(|last| now.saturating_duration_since(last) < PREP_INTERVAL)
        {
            return Err(PrepRefused::Paced);
        }
        if self.tried.len() >= PREP_REMEMBERED {
            let oldest = self
                .tried
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(digest, _)| *digest);
            if let Some(oldest) = oldest {
                self.tried.remove(&oldest);
            }
        }
        self.tried.insert(digest, now);
        self.last_start = Some(now);
        self.busy.store(true, Ordering::Release);
        Ok(self.busy.clone())
    }
}

/// How long the topic must send no refused frame before the condition
/// ends.
pub(crate) const REFUSAL_QUIET: Duration = Duration::from_secs(10 * 60);

/// What a change of [`Refusals`] logs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RefusalReport {
    /// The first refused frame of a condition.
    Started,
    /// The condition continues: `refused` frames since the previous line,
    /// by reason, `ongoing` since its start.
    Continuing {
        refused: u64,
        reasons: String,
        ongoing: Duration,
    },
    /// No frame was refused for [`REFUSAL_QUIET`]: all its `refused`
    /// frames, and how long it `lasted` until the last one.
    Ended { refused: u64, lasted: Duration },
}

/// Frames refused from the topic, for one warning when refusals start, a
/// repeat at most every [`crate::bounded_warn::WARN_REPEAT`] while they
/// continue, and one line once they stop.
#[derive(Debug, Default)]
pub(crate) struct Refusals {
    since: Option<Instant>,
    last: Option<Instant>,
    warned: Option<Instant>,
    total: u64,
    unreported: BTreeMap<&'static str, u64>,
}

impl Refusals {
    /// A frame was refused for `reason` at `now`.
    pub(crate) fn refused(&mut self, reason: &'static str, now: Instant) -> Option<RefusalReport> {
        self.total += 1;
        self.last = Some(now);
        let Some(since) = self.since else {
            self.since = Some(now);
            self.warned = Some(now);
            return Some(RefusalReport::Started);
        };
        *self.unreported.entry(reason).or_default() += 1;
        if self.warned.is_some_and(|warned| {
            now.saturating_duration_since(warned) < crate::bounded_warn::WARN_REPEAT
        }) {
            return None;
        }
        self.warned = Some(now);
        let unreported = std::mem::take(&mut self.unreported);
        Some(RefusalReport::Continuing {
            refused: unreported.values().sum(),
            reasons: unreported
                .iter()
                .map(|(reason, count)| format!("{reason}: {count}"))
                .collect::<Vec<_>>()
                .join(", "),
            ongoing: now.saturating_duration_since(since),
        })
    }

    /// The end of the condition, once nothing was refused for
    /// [`REFUSAL_QUIET`] before `now`.
    pub(crate) fn quiet(&mut self, now: Instant) -> Option<RefusalReport> {
        let (since, last) = (self.since?, self.last?);
        if now.saturating_duration_since(last) < REFUSAL_QUIET {
            return None;
        }
        let report = RefusalReport::Ended {
            refused: self.total,
            lasted: last.saturating_duration_since(since),
        };
        *self = Self::default();
        Some(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(number: u64, size: usize) -> AppShardFrame {
        AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                frame_number: number,
                output: vec![0; size],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Uncertified bodies are held only just above the cursor, a bounded
    /// number per frame and per shard, never replacing one held, and are
    /// taken only by the digest a certified child names.
    #[test]
    fn uncertified_bodies_are_bounded_and_never_replaced() {
        let mut held = UncertifiedFrames::default();
        let cursor = 100;
        assert_eq!(
            held.insert(cursor, cursor, [1; 32], 1, body(cursor, 1)),
            Err(NotHeld::OutsideWindow)
        );
        assert_eq!(
            held.insert(
                cursor,
                cursor + UNCERTIFIED_WINDOW + 1,
                [1; 32],
                1,
                body(0, 1)
            ),
            Err(NotHeld::OutsideWindow)
        );
        held.insert(cursor, 101, [1; 32], 1, body(101, 1)).unwrap();
        assert_eq!(
            held.insert(cursor, 101, [1; 32], 1, body(101, 2)),
            Err(NotHeld::Duplicate),
            "a held body is not replaced"
        );
        held.insert(cursor, 101, [2; 32], 1, body(101, 1)).unwrap();
        assert_eq!(
            held.insert(cursor, 101, [3; 32], 1, body(101, 1)),
            Err(NotHeld::Full),
            "per frame"
        );
        for number in 102..=115 {
            held.insert(cursor, number, [1; 32], 1, body(number, 1))
                .unwrap();
        }
        assert_eq!(held.len(), UNCERTIFIED_CAP);
        assert_eq!(
            held.insert(cursor, 116, [1; 32], 1, body(116, 1)),
            Err(NotHeld::Full),
            "per shard"
        );
        assert_eq!(held.take(101, &[9; 32]), None, "another digest");
        assert_eq!(held.take(101, &[1; 31]), None, "not a digest");
        let taken = held.take(101, &[1; 32]).unwrap();
        assert_eq!(taken.header.unwrap().output.len(), 1, "the first held");
        held.retain_above(110);
        assert_eq!(held.len(), 5);
        assert_eq!(held.bytes, 5);
        held.clear();
        assert_eq!((held.len(), held.bytes), (0, 0));

        let mut held = UncertifiedFrames::default();
        held.insert(cursor, 101, [1; 32], UNCERTIFIED_BYTES, body(101, 1))
            .unwrap();
        assert_eq!(
            held.insert(cursor, 102, [1; 32], 1, body(102, 1)),
            Err(NotHeld::Full),
            "per shard bytes"
        );
    }

    /// One preparation at a time, paced, each frame once.
    #[test]
    fn preparations_are_paced_and_never_repeated() {
        let t0 = Instant::now();
        let mut budget = PrepBudget::default();
        let running = budget.start([1; 32], t0).unwrap();
        assert_eq!(
            budget.start([2; 32], t0 + PREP_INTERVAL).err(),
            Some(PrepRefused::Busy)
        );
        running.store(false, Ordering::Release);
        assert_eq!(
            budget.start([2; 32], t0 + Duration::from_secs(1)).err(),
            Some(PrepRefused::Paced)
        );
        assert_eq!(
            budget.start([1; 32], t0 + PREP_INTERVAL).err(),
            Some(PrepRefused::Tried)
        );
        budget
            .start([2; 32], t0 + PREP_INTERVAL)
            .unwrap()
            .store(false, Ordering::Release);
        budget
            .start([1; 32], t0 + PREP_FORGET)
            .unwrap()
            .store(false, Ordering::Release);
        let mut later = t0 + PREP_FORGET;
        for n in 0..(PREP_REMEMBERED as u32 + 8) {
            later += PREP_INTERVAL;
            let mut digest = [0; 32];
            digest[..4].copy_from_slice(&n.to_le_bytes());
            digest[31] = 7;
            budget
                .start(digest, later)
                .unwrap()
                .store(false, Ordering::Release);
        }
        assert!(budget.tried.len() <= PREP_REMEMBERED);
    }

    /// Refusals warn once, repeat with their count at the bounded
    /// interval, and end once the topic stays quiet.
    #[test]
    fn refusals_warn_once_repeat_bounded_and_end_when_quiet() {
        let t0 = Instant::now();
        let second = Duration::from_secs(1);
        let mut refusals = Refusals::default();
        assert_eq!(refusals.quiet(t0), None);
        assert_eq!(
            refusals.refused("failed validation", t0),
            Some(RefusalReport::Started)
        );
        for i in 1..1000u32 {
            assert_eq!(
                refusals.refused("failed validation", t0 + second * i / 10),
                None
            );
        }
        assert_eq!(refusals.quiet(t0 + second * 200), None);
        refusals.refused("buffer full", t0 + second * 300);
        assert_eq!(
            refusals.refused("failed validation", t0 + crate::bounded_warn::WARN_REPEAT),
            Some(RefusalReport::Continuing {
                refused: 1001,
                reasons: "buffer full: 1, failed validation: 1000".into(),
                ongoing: crate::bounded_warn::WARN_REPEAT,
            })
        );
        let last = t0 + crate::bounded_warn::WARN_REPEAT;
        assert_eq!(refusals.quiet(last + REFUSAL_QUIET - second), None);
        assert_eq!(
            refusals.quiet(last + REFUSAL_QUIET),
            Some(RefusalReport::Ended {
                refused: 1002,
                lasted: crate::bounded_warn::WARN_REPEAT,
            })
        );
        assert_eq!(refusals.quiet(last + 2 * REFUSAL_QUIET), None);
        assert_eq!(
            refusals.refused("failed validation", last + 3 * REFUSAL_QUIET),
            Some(RefusalReport::Started),
            "a new condition"
        );
    }
}
