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

/// What one retention pass reclaimed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionPass {
    pub trees: usize,
    pub nodes: usize,
    pub values: usize,
}

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
            Some(RetentionPass {
                trees,
                nodes,
                values,
            }) => {
                if trees == 0 && nodes == 0 && values == 0 {
                    tally.empty += 1;
                }
                tally.trees += trees;
                tally.nodes += nodes;
                tally.values += values;
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

/// Prune `crdt` every `policy.interval` until it is dropped.
pub fn spawn_retention_pruner(crdt: &Arc<HypergraphCrdt>, policy: RetentionPolicy, label: String) {
    let crdt: Weak<HypergraphCrdt> = Arc::downgrade(crdt);
    let mut summary = PassSummary::new(std::time::Instant::now());
    let spawned = std::thread::Builder::new().name(format!("prune-{label}")).spawn(move || loop {
        std::thread::sleep(policy.interval);
        let Some(crdt) = crdt.upgrade() else { return };
        let started = std::time::Instant::now();
        let pass = match crdt.prune_retaining_with(policy.retain_frames, policy.max_blob_deletes, policy.max_value_deletes) {
            Ok(pass @ RetentionPass { trees, nodes, values }) => {
                if trees > 0 || nodes > 0 || values > 0 {
                    let ms = started.elapsed().as_millis() as u64;
                    tracing::info!(store = %label, trees, nodes, values, ms, "pruned retained versions");
                }
                Some(pass)
            }
            Err(error) => {
                tracing::warn!(store = %label, %error, "retained-version prune failed; retrying next pass");
                None
            }
        };
        if let Some((tally, window)) = summary.record(pass, std::time::Instant::now()) {
            let PassTally { passes, empty, failed, trees, nodes, values } = tally;
            tracing::info!(
                store = %label, window_s = window.as_secs(), passes, empty, failed, trees, nodes, values,
                "retained-version pruning summary",
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
                    values: 3
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
