//! Background pruning of superseded tree versions, blob versions and index
//! entries, so a node's store stops growing with every commit. Off unless
//! `QUIL_PRUNE_RETAINED_VERSIONS=1`: which trees are prunable is decided by
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

    /// `QUIL_PRUNE_RETAINED_VERSIONS=1` enables it; `QUIL_PRUNE_RETAIN_FRAMES`
    /// and `QUIL_PRUNE_INTERVAL_SECS` override the defaults. A retention below
    /// the sync window is refused.
    pub fn from_env() -> Option<Self> {
        if std::env::var("QUIL_PRUNE_RETAINED_VERSIONS").ok().as_deref() != Some("1") {
            return None;
        }
        let number = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
        Some(Self {
            retain_frames: number("QUIL_PRUNE_RETAIN_FRAMES")
                .unwrap_or(Self::DEFAULT_RETAIN_FRAMES)
                .max(crate::SNAPSHOT_MAX_GENERATIONS as u64),
            interval: Duration::from_secs(number("QUIL_PRUNE_INTERVAL_SECS").unwrap_or(600).max(10)),
            max_blob_deletes: 100_000,
            max_value_deletes: (std::env::var("QUIL_PRUNE_JMT_VALUES").ok().as_deref() != Some("0"))
                .then_some(100_000),
        })
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
            value.parse::<usize>().map_or(DEFAULT_PINNED_GENERATIONS, |limit| limit.max(MIN_PINNED_GENERATIONS)),
        ),
        None => Some(DEFAULT_PINNED_GENERATIONS),
    }
}

/// About ten minutes of generations at one per 10 s frame.
pub const DEFAULT_PINNED_GENERATIONS: usize = 64;
/// About two and a half minutes of generations at one per 10 s frame.
pub const MIN_PINNED_GENERATIONS: usize = 16;

/// Prune `crdt` every `policy.interval` until it is dropped.
pub fn spawn_retention_pruner(crdt: &Arc<HypergraphCrdt>, policy: RetentionPolicy, label: String) {
    let crdt: Weak<HypergraphCrdt> = Arc::downgrade(crdt);
    let spawned = std::thread::Builder::new().name(format!("prune-{label}")).spawn(move || loop {
        std::thread::sleep(policy.interval);
        let Some(crdt) = crdt.upgrade() else { return };
        match crdt.prune_retaining_with(policy.retain_frames, policy.max_blob_deletes, policy.max_value_deletes) {
            Ok(RetentionPass { trees, nodes, values }) if trees > 0 || nodes > 0 || values > 0 => {
                tracing::info!(store = %label, trees, nodes, values, "pruned retained versions");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(store = %label, %error, "retained-version prune failed; retrying next pass"),
        }
    });
    if let Err(error) = spawned {
        tracing::warn!(%error, "retained-version pruner not started");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin cap defaults to [`DEFAULT_PINNED_GENERATIONS`], can be switched
    /// off, and is never below [`MIN_PINNED_GENERATIONS`].
    #[test]
    fn the_snapshot_pin_cap_defaults_on_and_respects_its_floor() {
        assert_eq!(snapshot_pin_limit(None), Some(DEFAULT_PINNED_GENERATIONS));
        assert_eq!(snapshot_pin_limit(Some("not a number")), Some(DEFAULT_PINNED_GENERATIONS));
        assert_eq!(snapshot_pin_limit(Some("0")), None);
        assert_eq!(snapshot_pin_limit(Some("off")), None);
        assert_eq!(snapshot_pin_limit(Some("4")), Some(MIN_PINNED_GENERATIONS));
        assert_eq!(snapshot_pin_limit(Some("200")), Some(200));
    }
}
