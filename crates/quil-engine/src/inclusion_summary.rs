//! One periodic operator line on application shard inclusion by this
//! archive's GLOBAL proposals, and on what holds it up, in place of a line per
//! proposal, execution lease and frame gap.
//!
//! Those per-event lines ran to hundreds an hour on every archive
//! (2026-10-27) and still did not say how many proposals carried shard
//! headers. The summary counts them per interval; transitions (inclusion
//! stalling and resuming) keep lines of their own.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::leader_provider::HeldShard;

/// How often the summary is logged: at the first event after this long.
const INTERVAL: Duration = Duration::from_secs(600);
/// Proposals offering shard headers carried none for this long: inclusion
/// stalled on this archive.
const STALL_AFTER: Duration = Duration::from_secs(300);
/// How often a stall is logged again while it lasts.
const STALL_REPEAT: Duration = Duration::from_secs(600);
/// Execution lease holds kept per interval for the median.
const MAX_LEASE_SAMPLES: usize = 4096;
/// Shards tracked per map.
const MAX_SHARDS: usize = 4096;
/// The scope every line names.
const SCOPE: &str = "this archive's GLOBAL proposals";

#[derive(Default)]
struct Window {
    proposals: u64,
    offering: u64,
    with_headers: u64,
    carried: u64,
    held_back: u64,
    deferred: u64,
    largest_deferred: u64,
    unavailable: u64,
    first_held_back: Option<(Vec<u8>, u64)>,
    recovered: u64,
    first_recovered: Option<(Vec<u8>, u64)>,
    lease_ms: Vec<u64>,
    lease_holds: u64,
    lease_slow: u64,
    lease_max_ms: u64,
    gaps: HashMap<Vec<u8>, u64>,
    gap_requests: u64,
    relief_carries: u64,
    relief_most_behind: u64,
    relief_longest_wait: u64,
}

struct Stall {
    since: Instant,
    proposals: u64,
    held_back: u64,
    warned: Option<Instant>,
}

/// Proposals the application frame budget deferred shard headers in, each
/// carrying the shard furthest behind of those it did not fit.
struct Relief {
    since: Instant,
    since_frame: u64,
    proposals: u64,
    most_behind: u64,
    longest_wait: u64,
    warned: Option<Instant>,
}

/// GLOBAL frames each shard waited at its cursor, as this archive's proposals
/// saw it: from the first proposal offering its header at that cursor.
#[derive(Default)]
struct Waits(HashMap<Vec<u8>, (u64, u64)>);

impl Waits {
    /// A proposal at `frame` offered headers of `shards`; those it did not
    /// offer are forgotten.
    fn observe(&mut self, frame: u64, shards: &[HeldShard]) {
        let offered: HashSet<&[u8]> = shards
            .iter()
            .map(|shard| shard.address.as_slice())
            .collect();
        self.0
            .retain(|address, _| offered.contains(address.as_slice()));
        for shard in shards {
            let tracked = self.0.len();
            match self.0.get_mut(&shard.address) {
                Some((cursor, _)) if *cursor == shard.cursor => {}
                Some(entry) => *entry = (shard.cursor, frame),
                None if tracked < MAX_SHARDS => {
                    self.0.insert(shard.address.clone(), (shard.cursor, frame));
                }
                None => {}
            }
        }
    }

    fn waited(&self, shard: &[u8], frame: u64) -> u64 {
        self.0
            .get(shard)
            .map_or(0, |&(_, since)| frame.saturating_sub(since))
    }
}

struct State {
    since: Instant,
    window: Window,
    /// Shards whose header was refused while further behind than the frame
    /// buffer, and how far.
    behind: HashMap<Vec<u8>, u64>,
    stall: Option<Stall>,
    waits: Waits,
    relief: Option<Relief>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with_state(record: impl FnOnce(&mut State)) {
    let mut guard = STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = guard.get_or_insert_with(|| State {
        since: Instant::now(),
        window: Window::default(),
        behind: HashMap::new(),
        stall: None,
        waits: Waits::default(),
        relief: None,
    });
    record(state);
    if state.since.elapsed() >= INTERVAL {
        state.log();
        state.since = Instant::now();
        state.window = Window::default();
    }
}

/// A GLOBAL proposal this archive led: `offered` shard tips whose certificates
/// verified, of which `carried` ride, `held_back` stay back because this
/// archive lacks bodies executing them needs (the first shard and frame
/// lacking one in `first_held_back`), and `deferred` wait for a later
/// proposal by the application frame budget, the furthest behind
/// `largest_deferred` frames.
pub fn note_proposal(
    frame: u64,
    offered: usize,
    carried: usize,
    held_back: usize,
    first_held_back: Option<(&[u8], u64)>,
    deferred: usize,
    largest_deferred: u64,
) {
    with_state(|state| {
        let window = &mut state.window;
        window.proposals += 1;
        window.carried += carried as u64;
        window.held_back += held_back as u64;
        window.deferred += deferred as u64;
        window.largest_deferred = window.largest_deferred.max(largest_deferred);
        if window.first_held_back.is_none() {
            window.first_held_back = first_held_back.map(|(shard, frame)| (shard.to_vec(), frame));
        }
        if offered == 0 {
            return;
        }
        window.offering += 1;
        if carried > 0 {
            window.with_headers += 1;
            if let Some(stall) = state.stall.take().filter(|stall| stall.warned.is_some()) {
                info!(scope = SCOPE, frame, stalled_secs = stall.since.elapsed().as_secs(),
                    proposals = stall.proposals, held_back_tips = stall.held_back,
                    "application shard inclusion resumed: this archive's GLOBAL proposal carries shard headers again");
            }
            return;
        }
        let now = Instant::now();
        let stall = state.stall.get_or_insert(Stall {
            since: now,
            proposals: 0,
            held_back: 0,
            warned: None,
        });
        stall.proposals += 1;
        stall.held_back += held_back as u64;
        if stall.since.elapsed() >= STALL_AFTER
            && stall.warned.is_none_or(|at| at.elapsed() >= STALL_REPEAT)
        {
            stall.warned = Some(now);
            let (shard, shard_frame) = first_held_back
                .map_or((String::new(), 0), |(shard, frame)| {
                    (hex::encode(shard), frame)
                });
            warn!(scope = SCOPE, frame, stalled_secs = stall.since.elapsed().as_secs(),
                proposals = stall.proposals, held_back_tips = stall.held_back,
                first_held_back_shard = %shard, first_held_back_frame = shard_frame,
                "application shard inclusion stalled: this archive's GLOBAL proposals offered shard headers but \
                 carried none, so shard state and rewards are not applied from them; the inclusion summary line \
                 counts why. Repeated while it lasts; a line follows when a proposal carries headers again");
        }
    });
}

/// A GLOBAL proposal this archive led at `frame` offered headers of `shards`
/// whose bodies it holds; the application frame `budget` deferred `deferred`
/// of them and carried `furthest`, the one furthest behind of those it did
/// not fit, anyway.
///
/// Lines: one when the budget starts deferring headers, naming the shard
/// carried furthest behind; one when it stops; a warning, every
/// [`STALL_REPEAT`] while it lasts, when a deferred shard waited longer than
/// the bound, as many GLOBAL frames as shards offered.
pub(crate) fn note_budget(
    frame: u64,
    budget: u64,
    shards: &[HeldShard],
    furthest: Option<&HeldShard>,
    deferred: usize,
) {
    with_state(|state| {
        state.waits.observe(frame, shards);
        let waits = &state.waits;
        let Some(furthest) = furthest.filter(|_| deferred > 0) else {
            if let Some(relief) = state.relief.take() {
                info!(scope = SCOPE, frame, budget, lasted_secs = relief.since.elapsed().as_secs(),
                    global_frames = frame.saturating_sub(relief.since_frame), proposals = relief.proposals,
                    most_frames_behind_carried = relief.most_behind,
                    longest_wait_global_frames = relief.longest_wait,
                    "application frame budget no longer defers shard headers: this archive's GLOBAL proposals \
                     carry every shard header whose bodies it holds again");
            }
            return;
        };
        let bound = shards.len() as u64;
        let waited = waits.waited(&furthest.address, frame);
        let window = &mut state.window;
        window.relief_carries += 1;
        window.relief_most_behind = window.relief_most_behind.max(furthest.frames);
        window.relief_longest_wait = window.relief_longest_wait.max(waited);
        let relief = state.relief.get_or_insert_with(|| {
            info!(scope = SCOPE, frame, budget, deferred_tips = deferred,
                furthest_shard = %hex::encode(&furthest.address), furthest_frames_behind = furthest.frames,
                furthest_waited_global_frames = waited, bound_global_frames = bound,
                "application frame budget defers shard headers: more application frames wait than one GLOBAL \
                 proposal carries, so this archive's proposals carry the smallest gaps that fit and the shard \
                 furthest behind, and each shard rides within the bound. Expected while GLOBAL frames run slow \
                 or after shard headers were held back; a line follows when the budget no longer defers any");
            Relief {
                since: Instant::now(),
                since_frame: frame,
                proposals: 0,
                most_behind: 0,
                longest_wait: 0,
                warned: None,
            }
        });
        relief.proposals += 1;
        relief.most_behind = relief.most_behind.max(furthest.frames);
        relief.longest_wait = relief.longest_wait.max(waited);
        let overdue = || {
            shards
                .iter()
                .filter(|shard| !shard.rides)
                .map(|shard| (waits.waited(&shard.address, frame), shard))
                .filter(|&(waited, _)| waited > bound)
        };
        let Some((waited, shard)) = overdue().max_by_key(|&(waited, _)| waited) else {
            return;
        };
        if relief.warned.is_none_or(|at| at.elapsed() >= STALL_REPEAT) {
            relief.warned = Some(Instant::now());
            warn!(scope = SCOPE, frame, budget, shard = %hex::encode(&shard.address),
                frames_behind = shard.frames, waited_global_frames = waited, bound_global_frames = bound,
                overdue_shards = overdue().count(),
                "shard header waited longer than the application frame budget's bound: this archive's GLOBAL \
                 proposals carry the shard furthest behind every frame, so each should ride within as many GLOBAL \
                 frames as shards wait. Expected only while other GLOBAL leaders run a build that carries the \
                 smallest gaps only, or the shard produces far slower than the rest; otherwise a defect to \
                 report. Repeated every 10 minutes while it lasts");
        }
    });
}

/// A proposal could not check which bodies this archive holds, so its
/// `needs` shard headers stay back.
pub fn note_gate_unavailable(needs: usize) {
    with_state(|state| state.window.unavailable += needs as u64);
}

/// A GLOBAL execution lease held for `held`.
pub fn note_lease(held: Duration) {
    with_state(|state| {
        let window = &mut state.window;
        let ms = held.as_millis() as u64;
        window.lease_holds += 1;
        if held >= crate::stage_clock::SLOW_EXECUTION {
            window.lease_slow += 1;
        }
        window.lease_max_ms = window.lease_max_ms.max(ms);
        if window.lease_ms.len() < MAX_LEASE_SAMPLES {
            window.lease_ms.push(ms);
        }
    });
}

/// The ingest asked for `requested` frames of `shard` from `missing_from`,
/// the first it lacks while a GLOBAL frame or frames buffered above it wait.
pub fn note_gap(shard: &[u8], missing_from: u64, requested: usize) {
    with_state(|state| {
        let window = &mut state.window;
        window.gap_requests += requested as u64;
        if window.gaps.len() < MAX_SHARDS || window.gaps.contains_key(shard) {
            window.gaps.insert(shard.to_vec(), missing_from);
        }
    });
}

/// A header of `shard`, `gap` frames above its cursor and so past the frame
/// buffer, could not be proposed: not every body below it is held.
pub fn note_behind(shard: &[u8], gap: u64) {
    with_state(|state| {
        if state.behind.len() < MAX_SHARDS || state.behind.contains_key(shard) {
            state.behind.insert(shard.to_vec(), gap);
        }
    });
}

/// A header of `shard` can be proposed again, `gap` frames above its cursor,
/// after one further behind than the frame buffer could not.
pub fn note_caught_up(shard: &[u8], gap: u64) {
    with_state(|state| {
        state.behind.remove(shard);
        let window = &mut state.window;
        window.recovered += 1;
        if window.first_recovered.is_none() {
            window.first_recovered = Some((shard.to_vec(), gap));
        }
    });
}

impl State {
    fn log(&self) {
        let w = &self.window;
        if w.proposals == 0 && w.lease_holds == 0 && w.gaps.is_empty() && self.behind.is_empty() {
            return;
        }
        let mut lease = w.lease_ms.clone();
        lease.sort_unstable();
        let lease_p50_ms = lease.get(lease.len() / 2).copied().unwrap_or(0);
        let largest_gap = self.behind.values().max().copied().unwrap_or(0);
        let named = |shard: &Option<(Vec<u8>, u64)>| {
            shard
                .as_ref()
                .map_or((String::new(), 0), |(shard, n)| (hex::encode(shard), *n))
        };
        let (held_back_shard, held_back_frame) = named(&w.first_held_back);
        let (recovered_shard, recovered_gap) = named(&w.first_recovered);
        let (gap_shard, gap_missing_from) = w
            .gaps
            .iter()
            .next()
            .map_or((String::new(), 0), |(shard, n)| (hex::encode(shard), *n));
        let interval_secs = self.since.elapsed().as_secs();
        let shards_behind_buffer = self.behind.len();
        // Most proposals that offered shard headers carried none.
        let unhealthy = w.offering > 0 && w.with_headers * 2 < w.offering;
        macro_rules! summary {
            ($level:ident) => {
                tracing::$level!(
                    scope = SCOPE,
                    interval_secs,
                    proposals = w.proposals,
                    proposals_offering_headers = w.offering,
                    proposals_carrying_headers = w.with_headers,
                    tips_carried = w.carried,
                    tips_held_back = w.held_back,
                    first_held_back_shard = %held_back_shard,
                    first_held_back_frame = held_back_frame,
                    tips_deferred_by_budget = w.deferred,
                    largest_deferred_gap = w.largest_deferred,
                    budget_furthest_carried = w.relief_carries,
                    budget_furthest_most_frames_behind = w.relief_most_behind,
                    budget_furthest_longest_wait = w.relief_longest_wait,
                    headers_body_check_unavailable = w.unavailable,
                    shards_behind_buffer,
                    largest_gap,
                    shards_caught_up = w.recovered,
                    first_caught_up_shard = %recovered_shard,
                    first_caught_up_gap = recovered_gap,
                    lease_holds = w.lease_holds,
                    lease_holds_slow = w.lease_slow,
                    lease_p50_ms,
                    lease_max_ms = w.lease_max_ms,
                    gap_shards = w.gaps.len(),
                    gap_frames_requested = w.gap_requests,
                    gap_shard_example = %gap_shard,
                    gap_example_missing_from = gap_missing_from,
                    "application shard inclusion summary: shard tips (headers) this archive's GLOBAL proposals \
                     carried, held back because this archive lacks application frame bodies executing them needs, \
                     or deferred by the application frame budget, and the shards furthest behind carried beyond \
                     it; shards whose headers wait further behind than \
                     the frame buffer; GLOBAL execution lease holds; shards with frame gaps the ingest asked for. \
                     A warning when most proposals offering shard headers carried none: shard state and rewards \
                     then lag on every archive"
                )
            };
        }
        if unhealthy {
            summary!(warn);
        } else {
            summary!(info);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard(address: u8, cursor: u64) -> HeldShard {
        HeldShard {
            address: vec![address; 32],
            cursor,
            frames: 1,
            rides: false,
        }
    }

    /// A shard waits from the first proposal offering its header at a cursor
    /// until its cursor moves; a shard no proposal offers is forgotten.
    #[test]
    fn shard_waits_count_from_the_first_proposal_at_its_cursor() {
        let mut waits = Waits::default();
        waits.observe(10, &[shard(1, 5), shard(2, 7)]);
        waits.observe(14, &[shard(1, 5), shard(2, 9)]);
        assert_eq!(waits.waited(&[1; 32], 14), 4);
        assert_eq!(waits.waited(&[2; 32], 14), 0, "its cursor moved");
        waits.observe(15, &[shard(2, 9)]);
        waits.observe(20, &[shard(1, 5), shard(2, 9)]);
        assert_eq!(waits.waited(&[1; 32], 20), 0, "forgotten while not offered");
        assert_eq!(waits.waited(&[2; 32], 20), 6);
    }
}
