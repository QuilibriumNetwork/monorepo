//! One periodic operator line on application shard inclusion by this
//! archive's GLOBAL proposals, and on what holds it up, in place of a line per
//! proposal, execution lease and frame gap.
//!
//! Those per-event lines ran to hundreds an hour on every archive
//! (2026-10-27) and still did not say how many proposals carried shard
//! headers. The summary counts them per interval; transitions (inclusion
//! stalling and resuming) keep lines of their own, as does a fall in the shard
//! headers the proposals' pool holds.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::leader_provider::HeldShard;
use crate::proposal_pool::ProposalPool;

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
/// Pool sizes kept for the median: about 20 minutes of one archive's turns.
const POOL_SAMPLES: usize = 32;
/// Fewer pool sizes, or a smaller median, call no dip: a node just started,
/// or a network of a few shards.
const POOL_MIN_SAMPLES: usize = 8;
const POOL_MIN_MEDIAN: usize = 8;
/// After a dip ends, a further one is logged only once this long has passed.
const POOL_REARM: Duration = Duration::from_secs(300);
/// A shard whose last header is older than this many GLOBAL frames before the
/// dip began did not fall out in it: it is counted, not named.
const POOL_RECENT_FRAMES: u64 = 64;
/// Shards a dip line names, and the bytes of each address it shows: all of an
/// application's shards share their first 32 bytes.
const POOL_NAMED: usize = 5;
const POOL_NAMED_BYTES: usize = 4;

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

/// A pool at its lowest in a dip, and what this archive last knows of the
/// shards absent from it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PoolReading {
    frame: u64,
    shards: usize,
    known: usize,
    /// Absent, with no header since [`POOL_RECENT_FRAMES`] before the dip.
    absent_long: usize,
    /// The others absent, by what this archive knows of each: a held header
    /// too old to carry, past the frame buffer, frames the ingest asked for, or
    /// no header arrived.
    late: usize,
    behind_buffer: usize,
    gap: usize,
    no_header: usize,
    /// The first of those to fall out, each as `suffix:frames since its last
    /// header:reason`.
    named: String,
}

struct PoolDip {
    since: Instant,
    since_frame: u64,
    median: usize,
    proposals: u64,
    lowest: PoolReading,
    logged: Instant,
}

/// One line of a dip in the pool.
#[derive(Debug, PartialEq, Eq)]
struct PoolLine {
    phase: &'static str,
    frame: u64,
    pool_shards: usize,
    median: usize,
    proposals: u64,
    lasted_secs: u64,
    global_frames: u64,
    lowest: PoolReading,
}

/// Each own proposal's pool size against the recent median: a dip is a pool
/// under half of it, logged when it starts, every [`STALL_REPEAT`] and when it
/// ends. Samples in a dip stay out of the median.
#[derive(Default)]
struct PoolWatch {
    samples: VecDeque<usize>,
    /// The frame of the last proposal holding a header, by shard.
    last_seen: HashMap<Vec<u8>, u64>,
    dip: Option<PoolDip>,
    ended: Option<Instant>,
}

impl PoolWatch {
    fn observe(
        &mut self,
        frame: u64,
        pool: &ProposalPool,
        behind: &HashMap<Vec<u8>, u64>,
        gaps: &HashMap<Vec<u8>, u64>,
        now: Instant,
    ) -> Option<PoolLine> {
        if !pool.known.is_empty() {
            self.last_seen.retain(|shard, _| pool.known.contains(shard));
        }
        for shard in &pool.tips {
            let tracked = self.last_seen.len();
            match self.last_seen.get_mut(shard) {
                Some(seen) => *seen = frame,
                None if tracked < MAX_SHARDS => {
                    self.last_seen.insert(shard.clone(), frame);
                }
                None => {}
            }
        }
        let Some(mut dip) = self.dip.take() else {
            let mut sorted: Vec<usize> = self.samples.iter().copied().collect();
            sorted.sort_unstable();
            let median = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
            if sorted.len() < POOL_MIN_SAMPLES
                || median < POOL_MIN_MEDIAN
                || pool.shards * 2 >= median
            {
                self.sample(pool.shards);
                return None;
            }
            if self
                .ended
                .is_some_and(|ended| now.saturating_duration_since(ended) < POOL_REARM)
            {
                return None;
            }
            let dip = PoolDip {
                since: now,
                since_frame: frame,
                median,
                proposals: 1,
                lowest: self.read(frame, frame, pool, behind, gaps),
                logged: now,
            };
            let line = dip.line("start", frame, pool.shards, now);
            self.dip = Some(dip);
            return Some(line);
        };
        if pool.shards * 2 >= dip.median {
            self.ended = Some(now);
            self.sample(pool.shards);
            return Some(dip.line("end", frame, pool.shards, now));
        }
        dip.proposals += 1;
        if pool.shards < dip.lowest.shards {
            dip.lowest = self.read(frame, dip.since_frame, pool, behind, gaps);
        }
        let line = (now.saturating_duration_since(dip.logged) >= STALL_REPEAT).then(|| {
            dip.logged = now;
            dip.line("repeat", frame, pool.shards, now)
        });
        self.dip = Some(dip);
        line
    }

    fn sample(&mut self, shards: usize) {
        if self.samples.len() == POOL_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(shards);
    }

    fn read(
        &self,
        frame: u64,
        since_frame: u64,
        pool: &ProposalPool,
        behind: &HashMap<Vec<u8>, u64>,
        gaps: &HashMap<Vec<u8>, u64>,
    ) -> PoolReading {
        let recent_from = since_frame.saturating_sub(POOL_RECENT_FRAMES);
        let mut reading = PoolReading {
            frame,
            shards: pool.shards,
            known: pool.known.len(),
            ..Default::default()
        };
        let mut fell_out = Vec::new();
        for shard in pool
            .known
            .iter()
            .filter(|shard| !pool.tips.contains(*shard))
        {
            let Some(&seen) = self
                .last_seen
                .get(shard)
                .filter(|&&seen| seen >= recent_from)
            else {
                reading.absent_long += 1;
                continue;
            };
            let reason = if pool.late.contains(shard) {
                reading.late += 1;
                "late"
            } else if behind.contains_key(shard) {
                reading.behind_buffer += 1;
                "behind_buffer"
            } else if gaps.contains_key(shard) {
                reading.gap += 1;
                "gap"
            } else {
                reading.no_header += 1;
                "no_header"
            };
            fell_out.push((seen, shard, reason));
        }
        fell_out.sort_unstable();
        reading.named = fell_out
            .iter()
            .take(POOL_NAMED)
            .map(|(seen, shard, reason)| {
                let suffix = &shard[shard.len().saturating_sub(POOL_NAMED_BYTES)..];
                format!(
                    "{}:{}:{}",
                    hex::encode(suffix),
                    frame.saturating_sub(*seen),
                    reason
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        reading
    }
}

impl PoolDip {
    fn line(&self, phase: &'static str, frame: u64, pool_shards: usize, now: Instant) -> PoolLine {
        PoolLine {
            phase,
            frame,
            pool_shards,
            median: self.median,
            proposals: self.proposals,
            lasted_secs: now.saturating_duration_since(self.since).as_secs(),
            global_frames: frame.saturating_sub(self.since_frame),
            lowest: self.lowest.clone(),
        }
    }
}

impl PoolLine {
    fn log(&self) {
        let lowest = &self.lowest;
        info!(
            scope = SCOPE,
            phase = self.phase,
            frame = self.frame,
            epoch_offset_frames = self.frame % quil_types::consensus::EPOCH_LENGTH_FRAMES,
            pool_shards = self.pool_shards,
            median_shards = self.median,
            proposals = self.proposals,
            lasted_secs = self.lasted_secs,
            global_frames = self.global_frames,
            lowest_frame = lowest.frame,
            lowest_shards = lowest.shards,
            shards_known = lowest.known,
            absent_long = lowest.absent_long,
            late = lowest.late,
            behind_buffer = lowest.behind_buffer,
            gap = lowest.gap,
            no_header = lowest.no_header,
            first_absent = %lowest.named,
            "GLOBAL proposal pool dip: this archive's proposals hold shard headers from under half the shards \
             of their recent median. One line at the start, every 10 minutes and at the end; the absent shards \
             are as at the lowest pool, each named suffix:frames since its last header:reason. late: headers \
             arrive too old to carry; behind_buffer or gap: this archive misses their frames; no_header: none \
             arrived. Compare epoch_offset_frames across epochs and archives, and the named shards on the \
             explorer"
        );
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
    pool: PoolWatch,
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
        pool: PoolWatch::default(),
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

/// A GLOBAL proposal this archive led at `frame` copied `pool`.
pub(crate) fn note_pool(frame: u64, pool: &ProposalPool) {
    with_state(|state| {
        let line = state.pool.observe(
            frame,
            pool,
            &state.behind,
            &state.window.gaps,
            Instant::now(),
        );
        if let Some(line) = line {
            line.log();
        }
    });
}

/// `sizes` as the recent proposals' pool sizes.
#[cfg(test)]
pub(crate) fn seed_pool_samples(sizes: &[usize]) {
    with_state(|state| state.pool.samples = sizes.iter().copied().collect());
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

    fn address(n: usize) -> Vec<u8> {
        let mut address = vec![0xaa; 32];
        address.extend([0, (n >> 8) as u8, n as u8]);
        address
    }

    fn addresses(shards: impl IntoIterator<Item = usize>) -> HashSet<Vec<u8>> {
        shards.into_iter().map(address).collect()
    }

    /// One archive's turns, 4 GLOBAL frames and 41 s apart.
    struct Turns {
        watch: PoolWatch,
        frame: u64,
        now: Instant,
        known: HashSet<Vec<u8>>,
        late: HashSet<Vec<u8>>,
        behind: HashMap<Vec<u8>, u64>,
        gaps: HashMap<Vec<u8>, u64>,
    }

    impl Turns {
        fn new(known: usize) -> Self {
            Self {
                watch: PoolWatch::default(),
                frame: 1000,
                now: Instant::now(),
                known: addresses(0..known),
                late: HashSet::new(),
                behind: HashMap::new(),
                gaps: HashMap::new(),
            }
        }

        fn turn(&mut self, tips: impl IntoIterator<Item = usize>) -> Option<PoolLine> {
            let tips = addresses(tips);
            let pool = ProposalPool {
                shards: tips.len(),
                tips,
                late: self.late.clone(),
                known: self.known.clone(),
                ..Default::default()
            };
            let line = self
                .watch
                .observe(self.frame, &pool, &self.behind, &self.gaps, self.now);
            self.frame += 4;
            self.now += Duration::from_secs(41);
            line
        }

        /// `turns` proposals holding `shards` shards.
        fn turns(&mut self, turns: usize, shards: usize) -> Vec<PoolLine> {
            (0..turns).filter_map(|_| self.turn(0..shards)).collect()
        }
    }

    /// The fall this line is for: the first line says where the pool fell from
    /// and who left, by what this archive knows of each.
    #[test]
    fn a_pool_drop_starts_a_line_naming_who_left() {
        let mut turns = Turns::new(109);
        assert!(turns.turns(14, 97).is_empty());
        // Two shards leave before the rest.
        assert_eq!(turns.turn((0..97).filter(|shard| *shard != 11)), None);
        assert_eq!(
            turns.turn((0..97).filter(|shard| !(11..=12).contains(shard))),
            None
        );
        let at = |shards: HashSet<Vec<u8>>| shards.into_iter().map(|a| (a, 9)).collect();
        turns.late = addresses([13, 30, 31, 32, 33, 34, 35]);
        turns.behind = at(addresses([14, 21]));
        turns.gaps = at(addresses([15, 21, 22, 23]));
        let line = turns.turn(0..11).expect("the start line");
        assert_eq!(
            (line.phase, line.frame, line.pool_shards, line.median),
            ("start", 1064, 11, 97)
        );
        assert_eq!(
            line.lowest,
            PoolReading {
                frame: 1064,
                shards: 11,
                known: 109,
                absent_long: 12,
                late: 7,
                behind_buffer: 2,
                gap: 3,
                no_header: 74,
                named: "aa00000b:12:no_header,aa00000c:8:no_header,aa00000d:4:late,\
                        aa00000e:4:behind_buffer,aa00000f:4:gap"
                    .into(),
            }
        );
    }

    /// A dip lasts until the pool is back at half the median it fell from.
    #[test]
    fn a_dip_ends_at_half_its_median() {
        let mut turns = Turns::new(109);
        turns.turns(16, 97);
        assert_eq!(turns.turn(0..10).map(|line| line.phase), Some("start"));
        assert_eq!(turns.turn(0..48), None, "48 of 97 is under half");
        assert_eq!(turns.turn(0..49).map(|line| line.phase), Some("end"));
    }

    /// The last line says how long the dip lasted.
    #[test]
    fn an_end_line_has_the_dips_duration() {
        let mut turns = Turns::new(109);
        turns.turns(16, 97);
        turns.turns(4, 10);
        let line = turns.turn(0..97).expect("the end line");
        assert_eq!(line.phase, "end");
        assert_eq!((line.frame, line.pool_shards, line.median), (1080, 97, 97));
        assert_eq!(
            (line.proposals, line.lasted_secs, line.global_frames),
            (4, 164, 16)
        );
    }

    /// The last line's absent shards are those at the lowest pool, not the
    /// last or the first.
    #[test]
    fn an_end_line_reads_the_lowest_pool() {
        let mut turns = Turns::new(109);
        turns.turns(16, 97);
        turns.turn(0..11);
        turns.turn(0..7);
        turns.turn(0..9);
        let lowest = turns.turn(0..97).expect("the end line").lowest;
        assert_eq!((lowest.frame, lowest.shards), (1068, 7));
        assert_eq!((lowest.absent_long, lowest.no_header), (12, 90));
    }

    /// A dip of hours writes a line per [`STALL_REPEAT`].
    #[test]
    fn a_long_dip_is_bounded() {
        let mut turns = Turns::new(109);
        turns.turns(16, 97);
        let dip = turns.turns(1000, 10);
        let phases: Vec<&str> = dip.iter().map(|line| line.phase).collect();
        assert_eq!(phases[0], "start");
        // 1000 turns of 41 s, a repeat every 15 of them.
        assert_eq!(phases.len(), 67, "{phases:?}");
        assert!(phases[1..].iter().all(|phase| *phase == "repeat"));
    }

    /// A dip's low pools do not lower the median the next dip is judged by.
    #[test]
    fn a_dips_low_pools_stay_out_of_the_median() {
        let mut turns = Turns::new(109);
        turns.turns(16, 97);
        turns.turns(POOL_SAMPLES, 10);
        assert_eq!(turns.turn(0..97).map(|line| line.phase), Some("end"));
        turns.turns(8, 97);
        let next = turns.turn(0..10).expect("the next dip's start");
        assert_eq!((next.phase, next.median), ("start", 97));
    }

    /// A pool swinging across the line every turn writes one start and one end
    /// per [`POOL_REARM`] at most.
    #[test]
    fn a_flapping_pool_is_bounded_by_the_rearm() {
        let mut turns = Turns::new(109);
        turns.turns(16, 97);
        let mut lines = Vec::new();
        for _ in 0..500 {
            lines.extend(turns.turn(0..10));
            lines.extend(turns.turn(0..97));
        }
        // Over 41,000 s a low turn comes every 82 s. A start, its end 41 s
        // later, and the first low turn 300 s past that end is 410 s after the
        // start: 100 of them.
        assert_eq!(lines.len(), 200);
        let starts = lines.iter().filter(|line| line.phase == "start").count();
        assert_eq!(starts, 100);
    }

    /// Exactly half the median is no dip.
    #[test]
    fn a_pool_at_half_its_median_is_no_dip() {
        let mut half = Turns::new(109);
        half.turns(16, 96);
        assert_eq!(half.turn(0..48), None, "exactly half");
        let line = half.turn(0..47).expect("under half");
        assert_eq!((line.phase, line.median), ("start", 96));
    }

    /// A node with few samples yet calls no dip.
    #[test]
    fn a_node_just_started_calls_no_dip() {
        let mut started = Turns::new(109);
        assert!(started.turns(POOL_MIN_SAMPLES - 1, 97).is_empty());
        assert_eq!(started.turn(0..10), None, "too few samples");
    }

    /// A network of a few shards calls no dip.
    #[test]
    fn a_small_network_calls_no_dip() {
        let mut small = Turns::new(10);
        assert!(small.turns(16, POOL_MIN_MEDIAN - 1).is_empty());
        assert_eq!(small.turn(0..0), None, "median under the minimum");
    }

    /// A shard absent since well before the dip is counted and not named; one
    /// never seen is too.
    #[test]
    fn a_shard_long_absent_is_counted_and_not_named() {
        let mut turns = Turns::new(30);
        turns.frame = 900;
        assert_eq!(turns.turn(0..22), None);
        assert!(turns.turns(25, 20).is_empty());
        let line = turns.turn(0..3).expect("the dip");
        // Shards 22-29 never had a header, and 20 and 21 last had one at frame
        // 900, more than 64 frames before the dip's frame 1004.
        assert_eq!(line.frame, 1004);
        assert_eq!(line.lowest.absent_long, 10);
        assert_eq!(line.lowest.no_header, 17);
        assert_eq!(
            line.lowest.named,
            "aa000003:4:no_header,aa000004:4:no_header,aa000005:4:no_header,\
             aa000006:4:no_header,aa000007:4:no_header"
        );
    }

    /// Shards are tracked up to [`MAX_SHARDS`].
    #[test]
    fn the_shards_tracked_stay_bounded() {
        let mut turns = Turns::new(0);
        turns.turn(0..MAX_SHARDS + 100);
        assert_eq!(turns.watch.last_seen.len(), MAX_SHARDS);
    }

    /// A shard no longer known is forgotten.
    #[test]
    fn a_shard_no_longer_known_is_forgotten() {
        let mut turns = Turns::new(0);
        turns.turn(0..50);
        turns.known = addresses(0..5);
        turns.turn(0..5);
        assert_eq!(turns.watch.last_seen.len(), 5);
    }

    /// Every field of the line, each with its own value.
    #[test]
    fn a_dip_line_logs_every_field() {
        let logs = crate::outage::test_logs::CapturedLogs::default();
        let _logs = logs.install();
        PoolLine {
            phase: "end",
            frame: 1_011_684,
            pool_shards: 2,
            median: 3,
            proposals: 4,
            lasted_secs: 5,
            global_frames: 6,
            lowest: PoolReading {
                frame: 7,
                shards: 8,
                known: 9,
                absent_long: 10,
                late: 11,
                behind_buffer: 12,
                gap: 13,
                no_header: 14,
                named: "aa00000b:15:gap".into(),
            },
        }
        .log();
        let lines = logs.lines_with("GLOBAL proposal pool dip");
        assert_eq!(lines.len(), 1, "{lines:?}");
        for field in [
            "phase=\"end\"",
            "frame=1011684",
            "epoch_offset_frames=84",
            "pool_shards=2",
            "median_shards=3",
            "proposals=4",
            "lasted_secs=5",
            "global_frames=6",
            "lowest_frame=7",
            "lowest_shards=8",
            "shards_known=9",
            "absent_long=10",
            "late=11",
            "behind_buffer=12",
            "gap=13",
            "no_header=14",
            "first_absent=aa00000b:15:gap",
        ] {
            assert!(lines[0].contains(field), "{field}: {}", lines[0]);
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
