//! Background pruning of superseded tree versions, blob versions and index
//! entries, so a node's store stops growing with every commit. On by default
//! on nodes that do not serve history (`QUIL_PRUNE_RETAINED_VERSIONS=0` turns
//! it off, `=1` turns it on for an archive): which trees are prunable is decided by
//! [`HypergraphCrdt::prune_retaining`], which keeps every root syncing peers
//! may still request and leaves any tree whose history it cannot read alone.
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::HypergraphCrdt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Frames of each tree's own history kept resolvable and readable.
    pub retain_frames: u64,
    pub interval: Duration,
    /// Blob versions deleted per pass; the next pass continues.
    pub max_blob_deletes: usize,
    /// Superseded JMT leaf values deleted per pass, or `None` to keep them.
    /// On whenever retained-version pruning is (`QUIL_PRUNE_JMT_VALUES=0`
    /// keeps them).
    pub max_value_deletes: Option<usize>,
}

/// What one retention pass reclaimed, read and held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionPass {
    /// Trees whose superseded nodes were all reclaimed.
    pub trees: usize,
    pub nodes: usize,
    pub values: usize,
    /// Superseded blob versions deleted.
    pub blobs: usize,
    /// Root-version index entries deleted.
    pub roots: usize,
    /// Index entries, blob-version keys and leaf-value records read without
    /// the commit lock.
    pub scanned: usize,
    /// Holds of the store's commit lock.
    pub holds: usize,
    /// The longest hold, and all of them together.
    pub max_hold: Duration,
    pub held: Duration,
    /// Holds of [`LONG_HOLD`] or longer.
    pub long_holds: usize,
    /// How long the scans without the lock took.
    pub scan: Duration,
    /// Live replans of a scope's index under the lock, and the longest.
    pub replans: usize,
    pub max_replan: Duration,
    /// Trees refused and warned about because their watermark lay above
    /// their head.
    pub refused_trees: usize,
    /// A tree was wiped or its head dropped during the pass, which ended it;
    /// the next pass plans afresh.
    pub abandoned: bool,
}

impl RetentionPass {
    /// Whether the pass deleted nothing.
    fn reclaimed_nothing(&self) -> bool {
        self.trees == 0 && self.nodes == 0 && self.values == 0 && self.blobs == 0 && self.roots == 0
    }

    /// Whether the pass is worth its own log lines: it deleted something,
    /// its scans were slow, a hold was long, or it ended early.
    fn notable(&self) -> bool {
        self.nodes + self.values + self.blobs + self.roots > 0
            || self.scan >= SLOW_SCAN
            || self.long_holds > 0
            || self.abandoned
    }
}

/// How a retention pass sizes its holds of the commit lock. The default is
/// the production pacing; tests shrink it to cover work resumed across holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPacing {
    /// A hold ends once it has lasted this long, after at least one chunk.
    pub hold: Duration,
    /// The pause between two holds.
    pub pause: Duration,
    /// Vertices or leaf keys per store call inside a hold.
    pub chunk: usize,
    /// Stale node records per write batch inside a hold.
    pub node_batch: usize,
}

impl Default for RetentionPacing {
    fn default() -> Self {
        Self {
            hold: HOLD_BUDGET,
            pause: HOLD_PAUSE,
            chunk: 64,
            node_batch: 4096,
        }
    }
}

/// A step of a retention pass, as
/// [`HypergraphCrdt::prune_retaining_paced`] reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionStep {
    /// The index is read: at most `trees` trees and `keyspaces` blob
    /// keyspaces are pruned. Their scans, without the commit lock, follow.
    Planned {
        trees: usize,
        keyspaces: usize,
        index_entries: usize,
    },
    /// The scans are done: `blob_vertices` vertices and `value_keys` leaf
    /// keys hold superseded versions, `scanned` keys were read in `scan`.
    /// The deletions follow, in short holds of the commit lock.
    Scanned {
        blob_vertices: usize,
        value_keys: usize,
        scanned: usize,
        scan: Duration,
    },
    /// One hold of the commit lock ended after `hold`.
    Held { hold: Duration },
}

/// The longest a retention pass holds a store's commit lock at once, give or
/// take one chunk of work: a commit or a read waits at most about this long
/// for it.
pub const HOLD_BUDGET: Duration = Duration::from_millis(100);
/// The pause between two holds, so commits and reads queued meanwhile get in.
pub const HOLD_PAUSE: Duration = Duration::from_millis(5);
/// A hold this long is a defect: every commit and execution-record read of
/// the store waited for it.
pub const LONG_HOLD: Duration = Duration::from_secs(5);
/// Scans this long get the pass its own log lines even if it deletes
/// nothing: they read the store's whole versioned keyspace.
pub const SLOW_SCAN: Duration = Duration::from_secs(5);

impl RetentionPolicy {
    /// Everything a peer may still sync from ([`crate::SNAPSHOT_MAX_GENERATIONS`])
    /// plus an epoch of margin.
    pub const DEFAULT_RETAIN_FRAMES: u64 =
        crate::SNAPSHOT_MAX_GENERATIONS as u64 + quil_types::consensus::EPOCH_LENGTH_FRAMES;

    /// The policy for a store, or `None` when pruning is off: see
    /// [`pruning_enabled`]. `QUIL_PRUNE_RETAIN_FRAMES` and
    /// `QUIL_PRUNE_INTERVAL_SECS` override the defaults. A retention below
    /// the sync window is refused.
    pub fn from_env(serves_history: bool) -> Option<Self> {
        if !pruning_enabled(
            std::env::var("QUIL_PRUNE_RETAINED_VERSIONS")
                .ok()
                .as_deref(),
            serves_history,
        ) {
            return None;
        }
        let number = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
        Some(Self {
            retain_frames: number("QUIL_PRUNE_RETAIN_FRAMES")
                .unwrap_or(Self::DEFAULT_RETAIN_FRAMES)
                .max(crate::SNAPSHOT_MAX_GENERATIONS as u64),
            interval: Duration::from_secs(
                number("QUIL_PRUNE_INTERVAL_SECS").unwrap_or(600).max(10),
            ),
            max_blob_deletes: 100_000,
            max_value_deletes: (std::env::var("QUIL_PRUNE_JMT_VALUES").ok().as_deref()
                != Some("0"))
            .then_some(100_000),
        })
    }
}

/// Whether retained-version pruning runs for a `QUIL_PRUNE_RETAINED_VERSIONS`
/// setting: `0` turns it off and `1` on; unset (or anything else) leaves it on
/// unless the store serves history, as an archive's master store does.
pub fn pruning_enabled(setting: Option<&str>, serves_history: bool) -> bool {
    match setting.map(str::trim) {
        Some("0") => false,
        Some("1") => true,
        _ => !serves_history,
    }
}

/// `QUIL_SNAPSHOT_PINNED_MAX`: how many of the newest published generations
/// keep a store snapshot (see [`snapshot_pin_limit`]).
pub fn snapshot_pin_limit_from_env() -> Option<usize> {
    snapshot_pin_limit(std::env::var("QUIL_SNAPSHOT_PINNED_MAX").ok().as_deref())
}

/// The pin cap for a `QUIL_SNAPSHOT_PINNED_MAX` setting: unset (or
/// unparseable) is [`DEFAULT_PINNED_GENERATIONS`]; `0` or `off` keeps every
/// retained generation pinned (`None`); any other value is raised to at least
/// [`MIN_PINNED_GENERATIONS`], so a wallet scan has minutes to page through one.
/// Only wallet scans read a generation's snapshot, and each held snapshot keeps
/// every later overwrite and deletion on disk.
pub fn snapshot_pin_limit(setting: Option<&str>) -> Option<usize> {
    match setting.map(str::trim) {
        Some("0") | Some("off") => None,
        Some(value) => Some(
            value
                .parse::<usize>()
                .map_or(DEFAULT_PINNED_GENERATIONS, |limit| {
                    limit.max(MIN_PINNED_GENERATIONS)
                }),
        ),
        None => Some(DEFAULT_PINNED_GENERATIONS),
    }
}

/// About ten minutes of generations at one per 10 s frame.
pub const DEFAULT_PINNED_GENERATIONS: usize = 64;
/// About two and a half minutes of generations at one per 10 s frame.
pub const MIN_PINNED_GENERATIONS: usize = 16;

/// How often a store's pruner summarizes its passes, empty ones included.
const PASS_SUMMARY_INTERVAL: Duration = Duration::from_secs(3600);

/// The passes of one store's pruner since its last summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PassTally {
    passes: u64,
    empty: u64,
    failed: u64,
    trees: usize,
    nodes: usize,
    values: usize,
    blobs: usize,
    roots: usize,
    max_hold: Duration,
}

/// Tallies a pruner's passes and releases them at most once per
/// [`PASS_SUMMARY_INTERVAL`], so a store whose passes find nothing still
/// shows that its pruner runs.
#[derive(Debug)]
struct PassSummary {
    since: std::time::Instant,
    tally: PassTally,
}

impl PassSummary {
    fn new(now: std::time::Instant) -> Self {
        Self {
            since: now,
            tally: PassTally::default(),
        }
    }

    /// Count one pass (`None`: it failed). Returns the tally and its window
    /// once the interval has elapsed, and starts the next window.
    fn record(
        &mut self,
        pass: Option<RetentionPass>,
        now: std::time::Instant,
    ) -> Option<(PassTally, Duration)> {
        let tally = &mut self.tally;
        tally.passes += 1;
        match pass {
            Some(pass) => {
                if pass.reclaimed_nothing() {
                    tally.empty += 1;
                }
                tally.trees += pass.trees;
                tally.nodes += pass.nodes;
                tally.values += pass.values;
                tally.blobs += pass.blobs;
                tally.roots += pass.roots;
                tally.max_hold = tally.max_hold.max(pass.max_hold);
            }
            None => tally.failed += 1,
        }
        let window = now.saturating_duration_since(self.since);
        if window < PASS_SUMMARY_INTERVAL {
            return None;
        }
        self.since = now;
        Some((std::mem::take(&mut self.tally), window))
    }
}

/// The wait before a store's first pass: half an interval plus a random
/// share of one. A node opens all its stores at once, and passes that start
/// together read all their keyspaces at once.
fn first_wait(interval: Duration, label: &str) -> Duration {
    use std::hash::BuildHasher;
    let seed = std::collections::hash_map::RandomState::new().hash_one((
        label,
        std::process::id(),
        std::time::SystemTime::now(),
    ));
    let interval_ms = interval.as_millis().max(1) as u64;
    Duration::from_millis(interval_ms / 2 + seed % interval_ms)
}

/// Prune `crdt` every `policy.interval`, the first time after
/// [`first_wait`], until it is dropped.
pub fn spawn_retention_pruner(crdt: &Arc<HypergraphCrdt>, policy: RetentionPolicy, label: String) {
    let crdt: Weak<HypergraphCrdt> = Arc::downgrade(crdt);
    let mut summary = PassSummary::new(std::time::Instant::now());
    let mut wait = first_wait(policy.interval, &label);
    let spawned = std::thread::Builder::new().name(format!("prune-{label}")).spawn(move || loop {
        std::thread::sleep(wait);
        wait = policy.interval;
        let Some(crdt) = crdt.upgrade() else { return };
        let started = std::time::Instant::now();
        let mut announced = false;
        let outcome = crdt.prune_retaining_observed(
            policy.retain_frames,
            policy.max_blob_deletes,
            policy.max_value_deletes,
            &mut |step| {
                // Announced once the scans show deletions to make, or were
                // slow; a pass finding nothing quickly only counts in the
                // summary.
                if let RetentionStep::Scanned { blob_vertices, value_keys, scanned, scan } = step {
                    if blob_vertices > 0 || value_keys > 0 || scan >= SLOW_SCAN {
                        announced = true;
                        tracing::info!(store = %label, blob_vertices, value_keys, scanned,
                            scan_ms = scan.as_millis() as u64,
                            "retained-version prune scanned without the store's commit lock; deleting in short holds of it");
                    }
                }
            },
        );
        let pass = match outcome {
            Ok(pass) => {
                let ms = started.elapsed().as_millis() as u64;
                let max_hold_ms = pass.max_hold.as_millis() as u64;
                if announced || pass.notable() {
                    let RetentionPass { trees, nodes, values, blobs, roots, scanned, holds, long_holds, abandoned,
                        replans, .. } = pass;
                    tracing::info!(store = %label, trees, nodes, values, blobs, roots, scanned, holds, max_hold_ms,
                        long_holds, held_ms = pass.held.as_millis() as u64, replans, max_replan_ms = pass.max_replan.as_millis() as u64,
                        scan_ms = pass.scan.as_millis() as u64, abandoned, ms, "pruned retained versions");
                }
                if pass.long_holds > 0 {
                    tracing::warn!(store = %label, max_hold_ms, long_holds = pass.long_holds, holds = pass.holds, ms,
                        scope = "local", action = "report",
                        "retained-version pruning held this store's commit lock for seconds at once; this store's \
                         commits and execution-record reads waited for it; a slow disk lengthens it, otherwise \
                         report this line");
                }
                Some(pass)
            }
            Err(error) => {
                tracing::warn!(store = %label, %error, "retained-version prune failed; retrying next pass");
                None
            }
        };
        if let Some((tally, window)) = summary.record(pass, std::time::Instant::now()) {
            let PassTally { passes, empty, failed, trees, nodes, values, blobs, roots, max_hold } = tally;
            tracing::info!(
                store = %label, window_s = window.as_secs(), passes, empty, failed, trees, nodes, values, blobs,
                roots, max_hold_ms = max_hold.as_millis() as u64, "retained-version pruning summary",
            );
        }
    });
    if let Err(error) = spawned {
        tracing::warn!(%error, "retained-version pruner not started");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pruning is on by default except where history is served, and the
    /// setting overrides either default.
    #[test]
    fn retained_version_pruning_defaults_on_unless_history_is_served() {
        assert!(pruning_enabled(None, false));
        assert!(!pruning_enabled(None, true));
        assert!(pruning_enabled(Some("not a switch"), false));
        assert!(!pruning_enabled(Some("not a switch"), true));
        assert!(!pruning_enabled(Some("0"), false));
        assert!(pruning_enabled(Some(" 1 "), true));
    }

    /// Passes are summarized once the interval has elapsed, empty and failed
    /// passes included, and each summary starts a new window.
    #[test]
    fn pass_summaries_count_every_pass_at_most_once_an_interval() {
        let start = std::time::Instant::now();
        let at = |minutes: u64| start + Duration::from_secs(minutes * 60);
        let mut summary = PassSummary::new(start);
        let found = RetentionPass {
            trees: 1,
            nodes: 2,
            values: 3,
            blobs: 4,
            roots: 5,
            max_hold: Duration::from_millis(7),
            ..RetentionPass::default()
        };
        assert_eq!(summary.record(Some(RetentionPass::default()), at(10)), None);
        assert_eq!(summary.record(None, at(20)), None);
        assert_eq!(summary.record(Some(found), at(50)), None);
        assert_eq!(
            summary.record(Some(RetentionPass::default()), at(60)),
            Some((
                PassTally {
                    passes: 4,
                    empty: 2,
                    failed: 1,
                    trees: 1,
                    nodes: 2,
                    values: 3,
                    blobs: 4,
                    roots: 5,
                    max_hold: Duration::from_millis(7),
                },
                PASS_SUMMARY_INTERVAL
            )),
        );
        assert_eq!(summary.record(Some(RetentionPass::default()), at(70)), None);
        assert_eq!(
            summary.record(Some(RetentionPass::default()), at(125)),
            Some((
                PassTally {
                    passes: 2,
                    empty: 2,
                    ..PassTally::default()
                },
                Duration::from_secs(65 * 60)
            )),
        );
    }

    /// Stores opened together start their passes spread over an interval,
    /// never before half of one.
    #[test]
    fn first_passes_start_spread_over_an_interval() {
        let interval = Duration::from_secs(600);
        let waits: Vec<Duration> = (0..32)
            .map(|store| first_wait(interval, &format!("store-{store}")))
            .collect();
        assert!(waits
            .iter()
            .all(|wait| *wait >= interval / 2 && *wait < interval * 3 / 2));
        let distinct: std::collections::HashSet<_> = waits.iter().collect();
        assert!(distinct.len() > 16, "waits must differ: {waits:?}");
    }

    /// The pin cap defaults to [`DEFAULT_PINNED_GENERATIONS`], can be switched
    /// off, and is never below [`MIN_PINNED_GENERATIONS`].
    #[test]
    fn the_snapshot_pin_cap_defaults_on_and_respects_its_floor() {
        assert_eq!(snapshot_pin_limit(None), Some(DEFAULT_PINNED_GENERATIONS));
        assert_eq!(
            snapshot_pin_limit(Some("not a number")),
            Some(DEFAULT_PINNED_GENERATIONS)
        );
        assert_eq!(snapshot_pin_limit(Some("0")), None);
        assert_eq!(snapshot_pin_limit(Some("off")), None);
        assert_eq!(snapshot_pin_limit(Some("4")), Some(MIN_PINNED_GENERATIONS));
        assert_eq!(snapshot_pin_limit(Some("200")), Some(200));
    }
}
