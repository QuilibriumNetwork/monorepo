//! Confidential bundles whose spend relay GLOBAL skipped.
//!
//! Header `N` relays the spends of source frames `N-8 ..= N-1`, and GLOBAL
//! commits spends only from the headers it executes. When it executes a
//! shard's headers more than 8 frames apart, the relay window, no executed
//! header relays the frames between: their operations consumed nothing and
//! never commit, while the executing shard holds them as consumed. Another
//! shard takes a hash-routed bundle past the routing fallback, but a shield
//! goes only to the shard holding its source coin, so only its sender could
//! still commit it.
//!
//! So each member of a committee watches GLOBAL's executed tip of its shard,
//! and puts a bundle back in its own mempool once the tip has passed every
//! header relaying it and GLOBAL has not decided it. Any leader then carries
//! it through the usual routing and proof-verification budget, a new frame
//! executes it, and later headers relay it from that frame. This is proposal
//! input only: voters and archives replay the frame as they replay any body,
//! and the global commit decides an operation once whatever carries it, so a
//! relay thought lost that still lands costs a verification and nothing else.
//!
//! Bounds: frames at most [`REOFFER_HORIZON_FRAMES`] below the tip, at most
//! [`FRAMES_PER_TICK`] examined per tick, at most [`MAX_REOFFERS`] of a bundle
//! per process, and another only after GLOBAL skips its new source frame too.
//! A bundle past them stays uncommitted, and consumed nothing: its sender
//! submits it again, as before.

use quil_execution::message_envelope::CanonicalMessageBundle;
use quil_execution::token_intrinsic::global_commit::{self, SpendEntry};
use quil_execution::token_intrinsic::spend_relay;
use quil_types::error::Result;
use quil_types::store::ClockStore;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::RangeInclusive;
use std::sync::Arc;

/// How far below GLOBAL's executed tip a skipped frame is still re-offered:
/// the 30 minutes a wallet waits for inclusion at one shard frame per
/// 10-second GLOBAL frame. A sender may by then submit again; the commit's
/// consume-once markers settle what both copies race for.
pub(crate) const REOFFER_HORIZON_FRAMES: u64 = 180;

/// Re-offers of one bundle per process. Each one costs every archive the
/// operation's verification, and needs GLOBAL to skip the bundle's new source
/// frame as well.
pub(crate) const MAX_REOFFERS: u32 = 3;

/// Frames examined per tick, one store read each at the least: a start's pass
/// over the horizon spreads over a minute instead of holding the engine.
pub(crate) const FRAMES_PER_TICK: usize = 32;

/// Bundles whose re-offers are counted; past this the oldest is forgotten.
const BUNDLES_REMEMBERED: usize = 1024;

/// The source frames neither the header at `previous` nor the one at `tip`
/// relays when none between them executed. A header relays only the frames
/// below it, so `previous` itself is left to later headers. Frame 0 is never
/// relayed. `None` when the window leaves no gap.
pub(crate) fn unrelayed_frames(previous: u64, tip: u64) -> Option<RangeInclusive<u64>> {
    let first = previous.max(1);
    let window_start = *spend_relay::relay_window(tip).start();
    (window_start > first).then(|| first..=window_start - 1)
}

/// What a member of a committee tracks of its shard's relays.
#[derive(Debug, Default)]
pub(crate) struct RelayWatch {
    /// GLOBAL's executed tip when last read.
    tip: Option<u64>,
    /// Source frames to examine, oldest first.
    queued: BTreeSet<u64>,
    reoffers: HashMap<[u8; 32], u32>,
    remembered: VecDeque<[u8; 32]>,
}

impl RelayWatch {
    /// GLOBAL's executed tip now reads `tip`: queue the frames no executed
    /// header can have relayed since the last read. The first read, after a
    /// start, knows no earlier tip and looks back over the whole horizon.
    /// Ticks that miss a header only widen the range; a frame it relayed is
    /// decided, and is not offered. Returns the frames that left the horizon
    /// without being examined.
    pub(crate) fn observe_tip(&mut self, tip: u64) -> u64 {
        let floor = tip.saturating_sub(REOFFER_HORIZON_FRAMES).max(1);
        let previous = self.tip.replace(tip).unwrap_or(floor);
        let mut expired = 0;
        if let Some(range) = unrelayed_frames(previous, tip) {
            let (first, last) = range.into_inner();
            expired += floor.saturating_sub(first).min(last - first + 1);
            self.queued.extend(first.max(floor)..=last);
        }
        let held = self.queued.len();
        self.queued.retain(|frame| *frame >= floor);
        expired + (held - self.queued.len()) as u64
    }

    /// The frames to examine this tick. Each stays queued until
    /// [`Self::examined`].
    pub(crate) fn due(&self) -> Vec<u64> {
        self.queued.iter().take(FRAMES_PER_TICK).copied().collect()
    }

    pub(crate) fn examined(&mut self, frame: u64) {
        self.queued.remove(&frame);
    }

    /// Whether `bundle` may be offered again.
    pub(crate) fn may_reoffer(&self, bundle: &[u8; 32]) -> bool {
        self.reoffers.get(bundle).copied().unwrap_or(0) < MAX_REOFFERS
    }

    /// `bundle` was offered again; returns which time this was.
    pub(crate) fn note_reoffered(&mut self, bundle: [u8; 32]) -> u32 {
        if !self.reoffers.contains_key(&bundle) {
            if self.remembered.len() >= BUNDLES_REMEMBERED {
                if let Some(oldest) = self.remembered.pop_front() {
                    self.reoffers.remove(&oldest);
                }
            }
            self.remembered.push_back(bundle);
        }
        let count = self.reoffers.entry(bundle).or_insert(0);
        *count += 1;
        *count
    }

    /// `bundle` is at its cap and GLOBAL skipped it again; whether that is
    /// news, for one warning per bundle.
    pub(crate) fn note_given_up(&mut self, bundle: &[u8; 32]) -> bool {
        match self.reoffers.get_mut(bundle) {
            Some(count) if *count == MAX_REOFFERS => {
                *count += 1;
                true
            }
            _ => false,
        }
    }
}

/// The bundles of `frame` to offer again, in canonical encoding: every
/// operation of the bundle took effect in that frame, GLOBAL has not decided
/// at least one, and no frame through `head` executed that one since. A bundle
/// with an operation that commits on the shard itself is left alone: executing
/// it again would apply that operation twice. So is one the frame skipped,
/// which has no entries. `Err` when the frame cannot be read here, which a
/// member that reached it by sync may not.
pub(crate) fn unrelayed_bundles(
    clock: &dyn ClockStore,
    global: &Arc<quil_hypergraph::HypergraphCrdt>,
    application: &[u8; 32],
    filter: &[u8],
    frame: u64,
    head: u64,
) -> Result<Vec<Vec<u8>>> {
    let executed = frame_tx_ids(clock, filter, frame)?;
    if executed.is_empty() {
        return Ok(Vec::new());
    }
    let state = quil_execution::hypergraph_state::HypergraphState::new(global.clone());
    let mut undecided = HashSet::new();
    for tx in &executed {
        if !global_commit::is_decided(&state, application, tx)? {
            undecided.insert(*tx);
        }
    }
    let last = head.min(frame.saturating_add(REOFFER_HORIZON_FRAMES));
    for later in frame.saturating_add(1)..=last {
        if undecided.is_empty() {
            break;
        }
        for tx in frame_tx_ids(clock, filter, later)? {
            undecided.remove(&tx);
        }
    }
    if undecided.is_empty() {
        return Ok(Vec::new());
    }
    let body = clock.get_shard_clock_frame(filter, frame, false)?;
    let mut bundles = Vec::new();
    for bundle in &body.requests {
        let Ok(canonical) = crate::consensus_wire::app_bundle_to_canonical_bytes(bundle) else {
            continue;
        };
        let Ok(parsed) = CanonicalMessageBundle::from_canonical_bytes(&canonical) else {
            continue;
        };
        let ids: Vec<[u8; 32]> = parsed
            .requests
            .iter()
            .flatten()
            .map(|request| global_commit::tx_id(&request.inner_bytes))
            .collect();
        if !ids.is_empty()
            && ids.iter().all(|id| executed.contains(id))
            && ids.iter().any(|id| undecided.contains(id))
        {
            bundles.push(canonical);
        }
    }
    Ok(bundles)
}

/// The operations the shard's frame `frame` took into its spend relay.
fn frame_tx_ids(clock: &dyn ClockStore, filter: &[u8], frame: u64) -> Result<HashSet<[u8; 32]>> {
    let Some(bytes) = clock.get_shard_frame_spends(filter, frame)? else {
        return Ok(HashSet::new());
    };
    Ok(spend_relay::decode_frame_entries(&bytes)?
        .iter()
        // Read under the widest bounds: a frame's bounds decide what the
        // commit accepts, not what the frame recorded.
        .filter_map(|entry| SpendEntry::decode_at(entry, u64::MAX).ok())
        .map(|entry| entry.tx_id)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::spend_relay::RELAY_WINDOW_FRAMES;
    use super::*;

    /// Header N relays N-8..=N-1, not N: an advance of up to the window leaves
    /// nothing, the next leaves the previous header's own frame.
    #[test]
    fn unrelayed_frames_start_at_the_previous_headers_own_frame() {
        for advance in 0..=RELAY_WINDOW_FRAMES {
            assert_eq!(unrelayed_frames(100, 100 + advance), None, "{advance}");
        }
        assert_eq!(unrelayed_frames(100, 109), Some(100..=100));
        assert_eq!(unrelayed_frames(100, 110), Some(100..=101));
        assert_eq!(unrelayed_frames(100, 90), None, "a lower tip adds nothing");
        assert_eq!(unrelayed_frames(0, 8), None, "frame 0 is never relayed");
        assert_eq!(unrelayed_frames(0, 9), None, "header 9 relays 1..=8");
        assert_eq!(unrelayed_frames(0, 10), Some(1..=1));
    }

    /// A tip that moves within the window queues nothing, whatever the tick
    /// spacing; one past it queues the frames between.
    #[test]
    fn a_tip_past_the_window_queues_the_frames_no_header_relayed() {
        let mut watch = RelayWatch::default();
        assert_eq!(watch.observe_tip(5), 0);
        assert!(watch.due().is_empty(), "the first read of a low tip");
        for tip in [6, 13, 21] {
            assert_eq!(watch.observe_tip(tip), 0);
            assert!(watch.due().is_empty(), "tip {tip}");
        }
        watch.observe_tip(31);
        assert_eq!(watch.due(), vec![21, 22]);
        watch.examined(21);
        assert_eq!(watch.due(), vec![22]);
        watch.examined(22);
        watch.observe_tip(20);
        assert!(watch.due().is_empty(), "a lower tip queues nothing");
    }

    /// The horizon bounds what a jump queues and how long a frame stays
    /// queued; each frame past it is counted once, and newer ones go on.
    #[test]
    fn frames_past_the_horizon_are_counted_and_not_queued() {
        let mut watch = RelayWatch::default();
        assert_eq!(watch.observe_tip(1000), 0, "a start only looks back");
        assert_eq!(
            watch.queued.len() as u64,
            REOFFER_HORIZON_FRAMES - RELAY_WINDOW_FRAMES
        );
        assert_eq!(*watch.queued.first().unwrap(), 820);
        assert_eq!(watch.observe_tip(1100), 100, "820..=919 left the horizon");
        assert_eq!(*watch.queued.first().unwrap(), 920);
        // Queued: 920..=991 and 1000..=1091, 164 frames. The jump's own
        // 1100..=4819, 3720 frames, are below the new floor.
        assert_eq!(watch.observe_tip(5000), 164 + 3720);
        assert_eq!(*watch.queued.first().unwrap(), 4820);
        assert_eq!(*watch.queued.last().unwrap(), 4991);
    }

    #[test]
    fn a_tick_examines_a_bounded_number_of_frames() {
        let mut watch = RelayWatch::default();
        watch.observe_tip(1000);
        let mut ticks = 0;
        while !watch.due().is_empty() {
            let due = watch.due();
            assert!(due.len() <= FRAMES_PER_TICK);
            due.into_iter().for_each(|frame| watch.examined(frame));
            ticks += 1;
        }
        assert_eq!(ticks, 6, "172 frames at 32 a tick");
    }

    /// A bundle may be offered up to its cap, and giving up is news once.
    #[test]
    fn reoffers_stop_at_the_cap() {
        let mut watch = RelayWatch::default();
        let bundle = [1; 32];
        assert!(!watch.note_given_up(&bundle), "never offered");
        for attempt in 1..=MAX_REOFFERS {
            assert!(watch.may_reoffer(&bundle));
            assert_eq!(watch.note_reoffered(bundle), attempt);
        }
        assert!(!watch.may_reoffer(&bundle));
        assert!(watch.note_given_up(&bundle));
        assert!(!watch.note_given_up(&bundle));
        assert!(!watch.may_reoffer(&bundle), "stays given up");
    }

    #[test]
    fn counted_bundles_are_bounded() {
        let mut watch = RelayWatch::default();
        let bundle = |n: usize| {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&(n as u64).to_be_bytes());
            key
        };
        for n in 0..BUNDLES_REMEMBERED + 10 {
            watch.note_reoffered(bundle(n));
        }
        assert_eq!(watch.reoffers.len(), BUNDLES_REMEMBERED);
        assert_eq!(watch.remembered.len(), BUNDLES_REMEMBERED);
        assert!(!watch.reoffers.contains_key(&bundle(0)));
        assert!(watch.reoffers.contains_key(&bundle(BUNDLES_REMEMBERED + 9)));
    }
}
