//! Where the outputs GLOBAL commits are routed, and whether the shard owning
//! them can take delivery.
//!
//! A committed output or escrow is queued in a block, and only the committee
//! of the registered shard owning that block delivers it
//! ([`global_commit::committed_to_shard`]). A split registers latent spine
//! shards with no provers, so an output routed into one waits with no
//! committee to deliver it, and nothing else says so. Each executed header
//! that commits outputs logs one line counting them per owning shard with that
//! shard's active provers. An owning shard with none gets a warning when
//! outputs are first committed to it, a reminder at most every
//! [`REPEAT_INTERVAL`] while it stays so, and an info line once provers join
//! it or it leaves the grid. A staffed owning shard that executes no header
//! at GLOBAL in [`SILENT_FRAMES`] frames after outputs were committed to it
//! gets the same warning, reminder and end line: its committee delivers only
//! in its own frames. Logging only: no state is written.
//!
//! [`global_commit::committed_to_shard`]: crate::token_intrinsic::global_commit::committed_to_shard

use crate::token_intrinsic::global_commit::RelayCommit;
use crate::token_intrinsic::{accumulator_header, coin_blocks};
use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// How often a shard still holding committed outputs without provers is
/// warned about again.
pub const REPEAT_INTERVAL: Duration = Duration::from_secs(600);

/// How often the shards awaiting provers have their staffing read again.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// GLOBAL frames a staffed shard holding committed outputs may execute no
/// header of its own before it is reported silent: the accumulator
/// heartbeat, by which a producing shard's header reaches GLOBAL even with
/// nothing changed.
pub const SILENT_FRAMES: u64 = accumulator_header::HEARTBEAT_FRAMES;

/// Destinations a commit line names, the most outputs first.
const LISTED_SHARDS: usize = 8;

/// Unstaffed shards remembered; past this the longest-waiting is forgotten.
const MAX_SHARDS: usize = 1024;

/// A registered shard of the application: its bit path and filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GridShard {
    pub path: Vec<bool>,
    pub filter: Vec<u8>,
}

/// Outputs and escrows one relay committed to one destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    /// The owning shard's filter or, when no registered shard owns the block
    /// whole or the grid was not read, the block's own filter.
    pub filter: Vec<u8>,
    /// Whether `filter` is a registered shard's.
    pub owned: bool,
    pub outputs: u64,
    pub escrows: u64,
    /// The owning shard's active provers at the frame; `None` when unknown.
    pub active_provers: Option<usize>,
}

/// The registered shard owning `block` whole: the deepest whose path begins
/// the block's path. `None` when every shard covering it is deeper than the
/// block (it then awaits re-placement as an orphan).
pub fn owner(grid: &[GridShard], block: u64) -> Option<&GridShard> {
    grid.iter()
        .filter(|shard| coin_blocks::shard_owns_block(&shard.path, block))
        .max_by_key(|shard| shard.path.len())
}

/// `placed` grouped by owning shard (from `grid`, when read), in filter order.
pub fn destinations(
    application: &[u8; 32],
    grid: Option<&[GridShard]>,
    placed: &BTreeMap<u64, (u64, u64)>,
) -> Vec<Destination> {
    let mut by_filter: BTreeMap<Vec<u8>, Destination> = BTreeMap::new();
    for (block, (outputs, escrows)) in placed {
        let (filter, owned) = match grid.and_then(|grid| owner(grid, *block)) {
            Some(shard) => (shard.filter.clone(), true),
            None => (
                quil_forest::encode_shard_bit_path(application, &coin_blocks::block_path(*block)),
                false,
            ),
        };
        let destination = by_filter
            .entry(filter.clone())
            .or_insert_with(|| Destination {
                filter,
                owned,
                outputs: 0,
                escrows: 0,
                active_provers: None,
            });
        destination.outputs += outputs;
        destination.escrows += escrows;
    }
    by_filter.into_values().collect()
}

/// `<filter> <n> outputs, <m> escrows, <k> active provers` for the
/// destinations with the most outputs and escrows, and how many are unlisted.
pub fn describe(destinations: &[Destination]) -> (String, usize) {
    let mut ranked: Vec<&Destination> = destinations.iter().collect();
    ranked.sort_by(|a, b| {
        (b.outputs + b.escrows)
            .cmp(&(a.outputs + a.escrows))
            .then_with(|| a.filter.cmp(&b.filter))
    });
    let listed = ranked
        .iter()
        .take(LISTED_SHARDS)
        .map(|destination| {
            let provers = match (destination.owned, destination.active_provers) {
                (false, _) => "no registered shard owns the block whole".to_owned(),
                (true, Some(count)) => format!("{count} active provers"),
                (true, None) => "active provers unknown".to_owned(),
            };
            format!(
                "{} {} outputs, {} escrows, {provers}",
                hex::encode(&destination.filter),
                destination.outputs,
                destination.escrows
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    (listed, destinations.len().saturating_sub(LISTED_SHARDS))
}

/// A registered shard's staffing as read at a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Staffing {
    /// No active provers.
    Unstaffed,
    /// This many active provers.
    Staffed(usize),
    /// No longer a registered shard.
    LeftGrid,
}

/// One unstaffed shard's wait so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Episode {
    /// The GLOBAL frame that first committed outputs to it unstaffed.
    pub first_frame: u64,
    pub waited_secs: u64,
    /// Outputs and escrows committed to it since then.
    pub outputs: u64,
    pub escrows: u64,
    /// Commits to it since its last warning.
    pub quieted_commits: u64,
}

/// What a commit or a staffing check logs for a shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// Outputs were committed to the shard with no active provers.
    Start,
    /// Still none, [`REPEAT_INTERVAL`] after the last warning.
    Repeat(Episode),
    /// Provers joined it, or it left the grid.
    End(Episode, Staffing),
    /// The staffed shard executed no header in [`SILENT_FRAMES`] GLOBAL
    /// frames since the episode's first commit.
    SilentStart(Episode),
    /// Still silent, [`REPEAT_INTERVAL`] after the last warning.
    SilentRepeat(Episode),
    /// A silent shard executed a header again (`true`) or left the grid.
    SilentEnd(Episode, bool),
}

#[derive(Debug)]
struct Waiting {
    first_frame: u64,
    since: Instant,
    warned_at: Instant,
    outputs: u64,
    escrows: u64,
    quieted_commits: u64,
}

impl Waiting {
    fn episode(&self, now: Instant) -> Episode {
        Episode {
            first_frame: self.first_frame,
            waited_secs: now.saturating_duration_since(self.since).as_secs(),
            outputs: self.outputs,
            escrows: self.escrows,
            quieted_commits: self.quieted_commits,
        }
    }
}

/// Outputs committed to a staffed shard since its last executed header.
#[derive(Debug)]
struct Silent {
    /// The shard's filter as the grid names it.
    filter: Vec<u8>,
    /// The episode; its `since` and `warned_at` start at the first warning.
    waiting: Waiting,
    warned: bool,
}

/// `filter` in one form for a grid row and a header naming the same shard
/// (a legacy byte suffix decodes to its bit path).
fn shard_key(filter: &[u8]) -> Vec<u8> {
    quil_forest::decode_shard_filter_or_root(filter, 32).map_or_else(
        || filter.to_vec(),
        |(application, path)| quil_forest::encode_shard_bit_path(&application, &path),
    )
}

/// The shards holding committed outputs without active provers, and the
/// staffed ones holding outputs committed since their last header.
#[derive(Debug, Default)]
pub struct Tracker {
    shards: HashMap<Vec<u8>, Waiting>,
    silent: HashMap<Vec<u8>, Silent>,
    checked_at: Option<Instant>,
}

impl Tracker {
    /// GLOBAL frame `frame` committed `outputs` and `escrows` to registered
    /// shard `filter`, read as `staffing`.
    pub fn committed(
        &mut self,
        now: Instant,
        frame: u64,
        filter: &[u8],
        outputs: u64,
        escrows: u64,
        staffing: Staffing,
    ) -> Option<Notice> {
        if staffing != Staffing::Unstaffed {
            self.await_header(now, frame, filter, outputs, escrows);
            return self.resolve(now, filter, staffing);
        }
        if let Some(waiting) = self.shards.get_mut(filter) {
            waiting.outputs += outputs;
            waiting.escrows += escrows;
            waiting.quieted_commits += 1;
            return self.repeat_due(now, filter);
        }
        if self.shards.len() >= MAX_SHARDS {
            let oldest = self
                .shards
                .iter()
                .min_by_key(|(_, waiting)| waiting.since)
                .map(|(filter, _)| filter.clone());
            if let Some(oldest) = oldest {
                self.shards.remove(&oldest);
            }
        }
        self.shards.insert(
            filter.to_vec(),
            Waiting {
                first_frame: frame,
                since: now,
                warned_at: now,
                outputs,
                escrows,
                quieted_commits: 0,
            },
        );
        Some(Notice::Start)
    }

    /// Outputs committed at `frame` to staffed shard `filter`: remembered
    /// until a later header of the shard executes.
    fn await_header(
        &mut self,
        now: Instant,
        frame: u64,
        filter: &[u8],
        outputs: u64,
        escrows: u64,
    ) {
        let key = shard_key(filter);
        if let Some(silent) = self.silent.get_mut(&key) {
            silent.waiting.outputs += outputs;
            silent.waiting.escrows += escrows;
            silent.waiting.quieted_commits += u64::from(silent.warned);
            return;
        }
        if self.silent.len() >= MAX_SHARDS {
            let oldest = self
                .silent
                .iter()
                .min_by_key(|(_, silent)| silent.waiting.first_frame)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.silent.remove(&oldest);
            }
        }
        self.silent.insert(
            key,
            Silent {
                filter: filter.to_vec(),
                waiting: Waiting {
                    first_frame: frame,
                    since: now,
                    warned_at: now,
                    outputs,
                    escrows,
                    quieted_commits: 0,
                },
                warned: false,
            },
        );
    }

    /// GLOBAL frame `frame` executed a header of shard `filter`: outputs
    /// committed to it in earlier frames no longer wait on a silent shard.
    pub fn header(&mut self, now: Instant, frame: u64, filter: &[u8]) -> Option<(Vec<u8>, Notice)> {
        if self.silent.is_empty() {
            return None;
        }
        let key = shard_key(filter);
        if self.silent.get(&key)?.waiting.first_frame >= frame {
            return None;
        }
        let silent = self.silent.remove(&key)?;
        silent.warned.then(|| {
            (
                silent.filter,
                Notice::SilentEnd(silent.waiting.episode(now), true),
            )
        })
    }

    /// The staffed shards silent [`SILENT_FRAMES`] GLOBAL frames after their
    /// first commit, and the reminders due, in filter order. A shard
    /// awaiting provers is warned about as unstaffed instead.
    pub fn silent_due(&mut self, now: Instant, frame: u64) -> Vec<(Vec<u8>, Notice)> {
        let mut due = Vec::new();
        for silent in self.silent.values_mut() {
            if self.shards.contains_key(&silent.filter) {
                continue;
            }
            let waiting = &mut silent.waiting;
            if !silent.warned {
                if frame.saturating_sub(waiting.first_frame) < SILENT_FRAMES {
                    continue;
                }
                silent.warned = true;
                waiting.since = now;
                waiting.warned_at = now;
                due.push((
                    silent.filter.clone(),
                    Notice::SilentStart(waiting.episode(now)),
                ));
            } else if now.saturating_duration_since(waiting.warned_at) >= REPEAT_INTERVAL {
                due.push((
                    silent.filter.clone(),
                    Notice::SilentRepeat(waiting.episode(now)),
                ));
                waiting.warned_at = now;
                waiting.quieted_commits = 0;
            }
        }
        due.sort_by(|a, b| a.0.cmp(&b.0));
        due
    }

    /// The waiting shards, unstaffed or warned silent, to read the staffing
    /// of, sorted; none within [`CHECK_INTERVAL`] of the last check.
    pub fn due_checks(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let warned_silent = self.silent.values().any(|silent| silent.warned);
        if (self.shards.is_empty() && !warned_silent)
            || self
                .checked_at
                .is_some_and(|at| now.saturating_duration_since(at) < CHECK_INTERVAL)
        {
            return Vec::new();
        }
        self.checked_at = Some(now);
        let mut due: Vec<Vec<u8>> = self.shards.keys().cloned().collect();
        due.extend(
            self.silent
                .values()
                .filter(|silent| silent.warned)
                .map(|silent| silent.filter.clone()),
        );
        due.sort();
        due.dedup();
        due
    }

    /// A warned silent shard `filter` left the grid: it never executes a
    /// header again, and the shards replacing it take its blocks.
    pub fn silent_left(&mut self, now: Instant, filter: &[u8]) -> Option<Notice> {
        let key = shard_key(filter);
        if !self.silent.get(&key)?.warned {
            return None;
        }
        let silent = self.silent.remove(&key)?;
        Some(Notice::SilentEnd(silent.waiting.episode(now), false))
    }

    /// Waiting shard `filter`'s staffing as read at a check.
    pub fn resolve(&mut self, now: Instant, filter: &[u8], staffing: Staffing) -> Option<Notice> {
        if staffing == Staffing::Unstaffed {
            return self.repeat_due(now, filter);
        }
        let waiting = self.shards.remove(filter)?;
        Some(Notice::End(waiting.episode(now), staffing))
    }

    fn repeat_due(&mut self, now: Instant, filter: &[u8]) -> Option<Notice> {
        let waiting = self.shards.get_mut(filter)?;
        if now.saturating_duration_since(waiting.warned_at) < REPEAT_INTERVAL {
            return None;
        }
        let episode = waiting.episode(now);
        waiting.warned_at = now;
        waiting.quieted_commits = 0;
        Some(Notice::Repeat(episode))
    }
}

static TRACKER: LazyLock<Mutex<Tracker>> = LazyLock::new(|| Mutex::new(Tracker::default()));

/// Log where the relay of shard `source` committed at GLOBAL frame `frame`
/// sent its outputs: `grid` is `application`'s registered shards (`None`
/// when unread), `active` an owning shard's active provers at `frame`
/// (`None` when unknown).
pub fn log_commit(
    frame: u64,
    source: &[u8],
    application: &[u8; 32],
    grid: Option<&[GridShard]>,
    commit: &RelayCommit,
    active: impl Fn(&[u8]) -> Option<usize>,
) {
    if commit.placed.is_empty() {
        return;
    }
    let mut destinations = destinations(application, grid, &commit.placed);
    for destination in destinations.iter_mut().filter(|d| d.owned) {
        destination.active_provers = active(&destination.filter);
    }
    let (by_shard, unlisted_shards) = describe(&destinations);
    tracing::info!(
        frame,
        application = %hex::encode(&application[..8]),
        source_shard = %hex::encode(source),
        outputs = destinations.iter().map(|d| d.outputs).sum::<u64>(),
        escrows = destinations.iter().map(|d| d.escrows).sum::<u64>(),
        shards = destinations.len(),
        unstaffed = destinations.iter().filter(|d| d.active_provers == Some(0)).count(),
        grid_read = grid.is_some(),
        destinations = %by_shard,
        unlisted_shards,
        "committed outputs queued for delivery by the shards owning their blocks",
    );
    let now = Instant::now();
    let notices: Vec<(Vec<u8>, Notice)> = {
        let Ok(mut tracker) = TRACKER.lock() else {
            return;
        };
        destinations
            .iter()
            .filter(|d| d.owned)
            .filter_map(|d| {
                let staffing = match d.active_provers? {
                    0 => Staffing::Unstaffed,
                    count => Staffing::Staffed(count),
                };
                let notice =
                    tracker.committed(now, frame, &d.filter, d.outputs, d.escrows, staffing)?;
                Some((d.filter.clone(), notice))
            })
            .collect()
    };
    for (filter, notice) in notices {
        let committed = destinations
            .iter()
            .find(|d| d.filter == filter)
            .map_or((0, 0), |d| (d.outputs, d.escrows));
        log_notice(frame, &filter, Some(committed), &notice, None);
    }
}

/// The shards awaiting provers whose staffing is due to be read again
/// (at most once per [`CHECK_INTERVAL`]); empty while none waits.
pub fn due_checks() -> Vec<Vec<u8>> {
    TRACKER.lock().map_or_else(
        |_| Vec::new(),
        |mut tracker| tracker.due_checks(Instant::now()),
    )
}

/// Waiting shard `filter`'s staffing, read at GLOBAL frame `frame`.
pub fn resolve(frame: u64, filter: &[u8], staffing: Staffing) {
    let notices = match TRACKER.lock() {
        Ok(mut tracker) => {
            let now = Instant::now();
            let left = if staffing == Staffing::LeftGrid {
                tracker.silent_left(now, filter)
            } else {
                None
            };
            [tracker.resolve(now, filter, staffing), left]
        }
        Err(_) => return,
    };
    for notice in notices.iter().flatten() {
        log_notice(frame, filter, None, notice, None);
    }
}

/// GLOBAL frame `frame` executed a header of shard `filter`.
pub fn header_executed(frame: u64, filter: &[u8]) {
    let ended = match TRACKER.lock() {
        Ok(mut tracker) => tracker.header(Instant::now(), frame, filter),
        Err(_) => return,
    };
    if let Some((filter, notice)) = ended {
        log_notice(frame, &filter, None, &notice, None);
    }
}

/// Warn, at GLOBAL frame `frame`, about the staffed shards holding committed
/// outputs that executed no header in [`SILENT_FRAMES`] frames; `active`
/// reads a shard's active provers, only for a warning due.
pub fn check_silent(frame: u64, active: impl Fn(&[u8]) -> Option<usize>) {
    let due = match TRACKER.lock() {
        Ok(mut tracker) => tracker.silent_due(Instant::now(), frame),
        Err(_) => return,
    };
    for (filter, notice) in due {
        log_notice(frame, &filter, None, &notice, active(&filter));
    }
}

/// `active_provers` is read for the silent-shard warnings only.
fn log_notice(
    frame: u64,
    filter: &[u8],
    committed: Option<(u64, u64)>,
    notice: &Notice,
    active_provers: Option<usize>,
) {
    let shard = hex::encode(filter);
    match notice {
        Notice::Start => {
            let (outputs, escrows) = committed.unwrap_or_default();
            tracing::warn!(
                frame,
                shard = %shard,
                outputs,
                escrows,
                active_provers = 0,
                scope = "network: the shard owning these outputs has no active provers, so no \
                    committee can deliver them; not this node",
                action = "the outputs stay committed and wait until provers join the shard; \
                    check its active prover count in the shard list or the explorer, and report \
                    it to the maintainers if it stays unstaffed",
                "committed outputs routed to a shard with no active provers: delivery waits \
                 until the shard is staffed",
            );
        }
        Notice::Repeat(episode) => tracing::warn!(
            frame,
            shard = %shard,
            first_frame = episode.first_frame,
            waiting_secs = episode.waited_secs,
            outputs = episode.outputs,
            escrows = episode.escrows,
            commits_since_last_warning = episode.quieted_commits,
            active_provers = 0,
            scope = "network: the shard owning these outputs has no active provers; not this node",
            action = "the outputs wait until provers join the shard; report it to the \
                maintainers with the shard filter",
            "committed outputs still wait for a shard with no active provers",
        ),
        Notice::End(episode, Staffing::Staffed(active_provers)) => tracing::info!(
            frame,
            shard = %shard,
            first_frame = episode.first_frame,
            waited_secs = episode.waited_secs,
            outputs = episode.outputs,
            escrows = episode.escrows,
            active_provers,
            "a shard holding committed outputs is staffed: its committee can deliver them",
        ),
        Notice::End(episode, _) => tracing::info!(
            frame,
            shard = %shard,
            first_frame = episode.first_frame,
            waited_secs = episode.waited_secs,
            outputs = episode.outputs,
            escrows = episode.escrows,
            "a shard holding committed outputs left the grid before it was staffed: the shards \
             replacing it own its blocks, and a block none owns whole is re-placed as an orphan",
        ),
        Notice::SilentStart(episode) => tracing::warn!(
            frame,
            shard = %shard,
            first_frame = episode.first_frame,
            waited_frames = frame.saturating_sub(episode.first_frame),
            outputs = episode.outputs,
            escrows = episode.escrows,
            active_provers = ?active_provers,
            scope = "network: the shard owning these outputs executed no header at GLOBAL since \
                they were committed, so its committee is not delivering them; not this node",
            action = "the outputs wait until the shard produces frames again; check its frames \
                in the explorer and its members' logs, and report it to the maintainers with the \
                shard filter if it stays silent",
            "committed outputs wait for a shard that executed no header in 32 GLOBAL frames: \
             delivery waits until it produces",
        ),
        Notice::SilentRepeat(episode) => tracing::warn!(
            frame,
            shard = %shard,
            first_frame = episode.first_frame,
            waited_frames = frame.saturating_sub(episode.first_frame),
            waiting_secs = episode.waited_secs,
            outputs = episode.outputs,
            escrows = episode.escrows,
            commits_since_last_warning = episode.quieted_commits,
            active_provers = ?active_provers,
            scope = "network: the shard owning these outputs still executes no header; not this \
                node",
            action = "the outputs wait until the shard produces frames again; report it to the \
                maintainers with the shard filter",
            "committed outputs still wait for a shard that executes no header",
        ),
        Notice::SilentEnd(episode, true) => tracing::info!(
            frame,
            shard = %shard,
            first_frame = episode.first_frame,
            waited_secs = episode.waited_secs,
            outputs = episode.outputs,
            escrows = episode.escrows,
            "a silent shard holding committed outputs executed a header: its committee can \
             deliver them",
        ),
        Notice::SilentEnd(episode, false) => tracing::info!(
            frame,
            shard = %shard,
            first_frame = episode.first_frame,
            waited_secs = episode.waited_secs,
            outputs = episode.outputs,
            escrows = episode.escrows,
            "a silent shard holding committed outputs left the grid: the shards replacing it own \
             its blocks, and a block none owns whole is re-placed as an orphan",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: [u8; 32] = [7; 32];

    fn bits(pattern: &str) -> Vec<bool> {
        pattern.chars().map(|c| c == '1').collect()
    }

    fn shard(pattern: &str) -> GridShard {
        let path = bits(pattern);
        GridShard {
            filter: quil_forest::encode_shard_bit_path(&APP, &path),
            path,
        }
    }

    fn block(pattern: &str) -> u64 {
        let path = bits(pattern);
        let value = path
            .iter()
            .fold(0u64, |acc, bit| (acc << 1) | u64::from(*bit));
        coin_blocks::block_id(path.len() as u8, value).unwrap()
    }

    /// A grid split three bits deep: three latent spine shards beside four
    /// live depth-five shards.
    fn spine_grid() -> Vec<GridShard> {
        ["1", "01", "001", "00000", "00001", "00010", "00011"]
            .into_iter()
            .map(shard)
            .collect()
    }

    /// Each block goes to the registered shard whose path begins it; a block
    /// narrower than every shard covering it has no whole owner.
    #[test]
    fn commit_destinations_resolve_each_block_to_its_owning_shard() {
        let grid = spine_grid();
        assert_eq!(owner(&grid, block("100000")), Some(&grid[0]));
        assert_eq!(owner(&grid, block("011111")), Some(&grid[1]));
        assert_eq!(owner(&grid, block("000110")), Some(&grid[6]));
        let deep = [shard("0000000"), shard("0000001")];
        assert_eq!(owner(&deep, block("000000")), None);
        // Nested shards (a parent still registered beside its children): the
        // deepest prefix wins.
        let nested = [shard("0"), shard("00"), shard("000")];
        assert_eq!(owner(&nested, block("000110")), Some(&nested[2]));
        assert_eq!(owner(&nested, block("001110")), Some(&nested[1]));
        assert_eq!(owner(&nested, block("011110")), Some(&nested[0]));

        let placed: BTreeMap<u64, (u64, u64)> = [
            (block("100000"), (1, 0)),
            (block("110101"), (2, 1)),
            (block("000110"), (3, 0)),
        ]
        .into_iter()
        .collect();
        let found = destinations(&APP, Some(&grid), &placed);
        let summary: Vec<(Vec<u8>, bool, u64, u64)> = found
            .iter()
            .map(|d| (d.filter.clone(), d.owned, d.outputs, d.escrows))
            .collect();
        let mut expected = vec![
            (grid[0].filter.clone(), true, 3, 1),
            (grid[6].filter.clone(), true, 3, 0),
        ];
        expected.sort();
        assert_eq!(summary, expected, "two blocks of one spine shard merge");

        let unread = destinations(&APP, None, &placed);
        assert_eq!(unread.len(), 3, "without the grid each block stands alone");
        assert!(unread.iter().all(|d| !d.owned));
        assert_eq!(
            unread[0].filter,
            quil_forest::encode_shard_bit_path(&APP, &bits("000110"))
        );
    }

    /// The line lists the destinations with the most outputs first, each
    /// with its prover count, and counts those past the listed few.
    #[test]
    fn commit_destinations_describe_the_largest_first_and_bound_the_list() {
        let destination = |n: u8, outputs, owned, active_provers| Destination {
            filter: vec![n; 3],
            owned,
            outputs,
            escrows: 1,
            active_provers,
        };
        let (line, unlisted) = describe(&[
            destination(1, 1, true, Some(4)),
            destination(2, 5, true, Some(0)),
            destination(3, 2, true, None),
            destination(4, 2, false, None),
        ]);
        assert_eq!(
            line,
            "020202 5 outputs, 1 escrows, 0 active provers; \
             030303 2 outputs, 1 escrows, active provers unknown; \
             040404 2 outputs, 1 escrows, no registered shard owns the block whole; \
             010101 1 outputs, 1 escrows, 4 active provers"
        );
        assert_eq!(unlisted, 0);
        let many: Vec<Destination> = (0..LISTED_SHARDS as u8 + 3)
            .map(|n| destination(n, u64::from(n), true, Some(1)))
            .collect();
        let (line, unlisted) = describe(&many);
        assert_eq!(unlisted, 3);
        assert_eq!(line.matches("; ").count(), LISTED_SHARDS - 1);
        assert!(line.starts_with(&hex::encode([LISTED_SHARDS as u8 + 2; 3])));
    }

    /// An unstaffed shard warns at its first commit, counts later commits
    /// quietly, warns again once per interval, and ends when staffed.
    #[test]
    fn commit_destinations_warn_once_per_interval_until_the_shard_is_staffed() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        let (a, b) = (vec![0xa1; 35], vec![0xb2; 35]);
        let u = Staffing::Unstaffed;
        assert_eq!(tracker.committed(t0, 757, &a, 1, 0, u), Some(Notice::Start));
        assert_eq!(
            tracker.committed(t0, 757, &b, 2, 0, Staffing::Staffed(4)),
            None,
            "a staffed shard is not tracked"
        );
        assert_eq!(
            tracker.committed(t0 + Duration::from_secs(5), 758, &a, 2, 1, u),
            None
        );
        assert_eq!(
            tracker.resolve(t0 + Duration::from_secs(30), &a, u),
            None,
            "no reminder within the interval"
        );
        assert_eq!(
            tracker.resolve(t0 + REPEAT_INTERVAL, &a, u),
            Some(Notice::Repeat(Episode {
                first_frame: 757,
                waited_secs: REPEAT_INTERVAL.as_secs(),
                outputs: 3,
                escrows: 1,
                quieted_commits: 1,
            }))
        );
        assert_eq!(
            tracker.committed(
                t0 + REPEAT_INTERVAL + Duration::from_secs(1),
                800,
                &a,
                1,
                0,
                u
            ),
            None
        );
        assert_eq!(
            tracker.committed(
                t0 + REPEAT_INTERVAL * 2,
                900,
                &a,
                1,
                0,
                Staffing::Staffed(3)
            ),
            Some(Notice::End(
                Episode {
                    first_frame: 757,
                    waited_secs: (REPEAT_INTERVAL * 2).as_secs(),
                    outputs: 4,
                    escrows: 1,
                    quieted_commits: 1,
                },
                Staffing::Staffed(3)
            ))
        );
        assert_eq!(
            tracker.resolve(t0 + REPEAT_INTERVAL * 3, &a, Staffing::Staffed(3)),
            None,
            "ended once"
        );
        assert_eq!(
            tracker.committed(t0 + REPEAT_INTERVAL * 3, 950, &a, 1, 0, u),
            Some(Notice::Start),
            "a new wait starts afresh"
        );
        assert!(matches!(
            tracker.resolve(t0 + REPEAT_INTERVAL * 3, &a, Staffing::LeftGrid),
            Some(Notice::End(_, Staffing::LeftGrid))
        ));
    }

    /// Staffing is read again at most once per check interval, and only
    /// while a shard waits.
    #[test]
    fn commit_destinations_checks_are_spaced_and_only_while_a_shard_waits() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        assert!(tracker.due_checks(t0).is_empty());
        let (a, b) = (vec![0xa1; 35], vec![0x01; 35]);
        tracker.committed(t0, 1, &a, 1, 0, Staffing::Unstaffed);
        tracker.committed(t0, 1, &b, 1, 0, Staffing::Unstaffed);
        assert_eq!(tracker.due_checks(t0), vec![b, a]);
        assert!(tracker
            .due_checks(t0 + CHECK_INTERVAL - Duration::from_secs(1))
            .is_empty());
        assert_eq!(tracker.due_checks(t0 + CHECK_INTERVAL).len(), 2);
    }

    /// The shards remembered stay bounded, forgetting the longest wait.
    #[test]
    fn commit_destinations_remembered_shards_are_bounded() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        for n in 0..(MAX_SHARDS as u32 + 10) {
            let at = t0 + Duration::from_millis(u64::from(n));
            tracker.committed(at, 1, &n.to_be_bytes(), 1, 0, Staffing::Unstaffed);
            assert!(tracker.shards.len() <= MAX_SHARDS);
        }
        assert!(!tracker.shards.contains_key(&0u32.to_be_bytes()[..]));
        assert!(tracker
            .shards
            .contains_key(&(MAX_SHARDS as u32 + 9).to_be_bytes()[..]));
    }

    /// A staffed shard that executes no header in [`SILENT_FRAMES`] GLOBAL
    /// frames after outputs were committed to it warns once, counts later
    /// commits, reminds once per interval and ends at its next header.
    #[test]
    fn commit_destinations_warn_once_per_interval_while_a_staffed_shard_executes_no_header() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        let silent = shard("00001");
        let s4 = Staffing::Staffed(4);
        assert_eq!(tracker.committed(t0, 100, &silent.filter, 2, 1, s4), None);
        assert!(tracker.silent_due(t0, 100 + SILENT_FRAMES - 1).is_empty());
        let start = Episode {
            first_frame: 100,
            waited_secs: 0,
            outputs: 2,
            escrows: 1,
            quieted_commits: 0,
        };
        assert_eq!(
            tracker.silent_due(t0, 100 + SILENT_FRAMES),
            vec![(silent.filter.clone(), Notice::SilentStart(start))]
        );
        assert!(
            tracker
                .silent_due(t0 + Duration::from_secs(30), 140)
                .is_empty(),
            "no reminder within the interval"
        );
        assert_eq!(
            tracker.committed(t0 + Duration::from_secs(31), 141, &silent.filter, 1, 0, s4),
            None
        );
        assert_eq!(
            tracker.silent_due(t0 + REPEAT_INTERVAL, 150),
            vec![(
                silent.filter.clone(),
                Notice::SilentRepeat(Episode {
                    first_frame: 100,
                    waited_secs: REPEAT_INTERVAL.as_secs(),
                    outputs: 3,
                    escrows: 1,
                    quieted_commits: 1,
                })
            )]
        );
        assert_eq!(
            tracker.header(t0 + REPEAT_INTERVAL * 2, 160, &silent.filter),
            Some((
                silent.filter.clone(),
                Notice::SilentEnd(
                    Episode {
                        first_frame: 100,
                        waited_secs: (REPEAT_INTERVAL * 2).as_secs(),
                        outputs: 3,
                        escrows: 1,
                        quieted_commits: 0,
                    },
                    true
                )
            ))
        );
        assert!(
            tracker.silent_due(t0 + REPEAT_INTERVAL * 3, 400).is_empty(),
            "ended once"
        );
    }

    /// Only a header executed after the commit's frame shows the shard
    /// producing: one in the same frame leaves the wait to be reported.
    #[test]
    fn commit_destinations_a_header_in_the_commits_own_frame_ends_no_silent_wait() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        let (same, later) = (shard("00001"), shard("00010"));
        tracker.committed(t0, 100, &same.filter, 1, 0, Staffing::Staffed(2));
        tracker.committed(t0, 100, &later.filter, 1, 0, Staffing::Staffed(2));
        assert_eq!(tracker.header(t0, 100, &same.filter), None);
        assert_eq!(
            tracker.header(t0, 101, &later.filter),
            None,
            "an unwarned wait ends quietly"
        );
        let due: Vec<Vec<u8>> = tracker
            .silent_due(t0, 200)
            .into_iter()
            .map(|(filter, _)| filter)
            .collect();
        assert_eq!(due, vec![same.filter.clone()]);
    }

    /// A header in a legacy byte-suffix filter ends the wait of the same
    /// shard's bit path; a warned silent shard is due a staffing check, and
    /// its wait ends when it leaves the grid.
    #[test]
    fn commit_destinations_a_silent_wait_ends_by_a_legacy_header_or_leaving_the_grid() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        let (legacy, left) = (shard("000011"), shard("000100"));
        tracker.committed(t0, 100, &legacy.filter, 1, 0, Staffing::Staffed(4));
        tracker.committed(t0, 100, &left.filter, 1, 0, Staffing::Staffed(4));
        assert_eq!(tracker.silent_due(t0, 200).len(), 2);
        let header = [APP.as_slice(), &[3]].concat();
        assert!(matches!(
            tracker.header(t0, 201, &header),
            Some((filter, Notice::SilentEnd(_, true))) if filter == legacy.filter
        ));
        assert_eq!(tracker.due_checks(t0), vec![left.filter.clone()]);
        assert!(matches!(
            tracker.silent_left(t0, &left.filter),
            Some(Notice::SilentEnd(_, false))
        ));
        assert!(tracker.silent_due(t0 + REPEAT_INTERVAL, 300).is_empty());
    }

    /// A shard holding outputs that loses its provers is warned about as
    /// unstaffed, not also as silent.
    #[test]
    fn commit_destinations_an_unstaffed_shard_is_not_also_reported_silent() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        let lost = shard("01");
        tracker.committed(t0, 100, &lost.filter, 1, 0, Staffing::Staffed(1));
        assert_eq!(
            tracker.committed(t0, 105, &lost.filter, 1, 0, Staffing::Unstaffed),
            Some(Notice::Start)
        );
        assert!(tracker.silent_due(t0, 200).is_empty());
    }

    /// The staffed shards awaiting a header stay bounded, forgetting the
    /// oldest commit.
    #[test]
    fn commit_destinations_silent_shards_remembered_are_bounded() {
        let t0 = Instant::now();
        let mut tracker = Tracker::default();
        for n in 0..(MAX_SHARDS as u64 + 10) {
            tracker.committed(t0, n, &n.to_be_bytes(), 1, 0, Staffing::Staffed(1));
            assert!(tracker.silent.len() <= MAX_SHARDS);
        }
        assert!(!tracker.silent.contains_key(&0u64.to_be_bytes()[..]));
        assert!(tracker
            .silent
            .contains_key(&(MAX_SHARDS as u64 + 9).to_be_bytes()[..]));
    }
}
