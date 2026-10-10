//! Background cleanup of a node store's clock records and pinned snapshots.
//! Each piece is on by default and is switched off by setting it to `0`:
//!
//! - `QUIL_PRUNE_STAGED_SHARD_FRAMES`: once at startup, delete staged
//!   application frames whose canonical copy is identical (stores written
//!   before a commit dropped its staged copy hold each frame twice).
//! - `QUIL_PRUNE_GLOBAL_CANDIDATES`: every `QUIL_PRUNE_INTERVAL_SECS`
//!   (default 600), delete GLOBAL candidates `QUIL_PRUNE_CANDIDATE_MARGIN`
//!   (default two epochs) or more below both the canonical head and the
//!   executed cursor, at heights holding a canonical record.
//! - `QUIL_SNAPSHOT_PINNED_MAX=<n>`: keep store snapshots only on the newest
//!   `n` (default 64, at least 16; `off` also disables it) published
//!   generations.
use std::sync::{Arc, Weak};
use std::time::Duration;

use tracing::{info, warn};

/// Staged keys examined per step of the startup cleanup.
const STAGED_STEP: usize = 10_000;
/// Candidate headers examined per step of a candidate pass.
const CANDIDATE_STEP: usize = 5_000;
/// Never closer to the head than this, whatever is configured.
const MIN_CANDIDATE_MARGIN: u64 = 64;

fn setting(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn enabled(name: &str) -> bool {
    default_on(std::env::var(name).ok().as_deref())
}

/// A default-on switch: anything but `0` leaves it on.
fn default_on(setting: Option<&str>) -> bool {
    setting.map(str::trim) != Some("0")
}

/// Apply the `QUIL_SNAPSHOT_PINNED_MAX` pin cap to `crdt`, unless it is off.
pub(crate) fn apply_snapshot_pin_limit(crdt: &quil_hypergraph::HypergraphCrdt, label: &str) {
    if let Some(limit) = quil_hypergraph::snapshot_pin_limit_from_env() {
        info!(store = label, limit, "keeping store snapshots only on the newest published generations");
        crdt.set_snapshot_pinned_limit(limit);
    }
}

/// `QUIL_PRUNE_STAGED_SHARD_FRAMES` (default on): one bounded pass over `clock`'s staged
/// application frames, in the background. It holds the store until done.
pub(crate) fn spawn_staged_cleanup(clock: Arc<quil_store::RocksClockStore>, label: String) {
    if !enabled("QUIL_PRUNE_STAGED_SHARD_FRAMES") {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name(format!("staged-prune-{label}"))
        .spawn(move || prune_staged(&clock, &label));
    if let Err(error) = spawned {
        warn!(%error, "staged shard frame cleanup not started");
    }
}

/// `QUIL_PRUNE_GLOBAL_CANDIDATES` (default on): prune `clock`'s GLOBAL candidates every
/// interval until the store is dropped. Only a store that executes GLOBAL
/// frames (a master) holds candidates.
pub(crate) fn spawn_candidate_pruner(clock: &Arc<quil_store::RocksClockStore>, label: String) {
    if !enabled("QUIL_PRUNE_GLOBAL_CANDIDATES") {
        return;
    }
    let clock: Weak<quil_store::RocksClockStore> = Arc::downgrade(clock);
    let margin = setting("QUIL_PRUNE_CANDIDATE_MARGIN")
        .unwrap_or(2 * quil_types::consensus::EPOCH_LENGTH_FRAMES)
        .max(MIN_CANDIDATE_MARGIN);
    let interval = Duration::from_secs(setting("QUIL_PRUNE_INTERVAL_SECS").unwrap_or(600).max(10));
    let spawned = std::thread::Builder::new().name(format!("candidate-prune-{label}")).spawn(move || {
        info!(store = %label, margin, "GLOBAL candidate pruning enabled");
        loop {
            std::thread::sleep(interval);
            let Some(store) = clock.upgrade() else { return };
            prune_candidates(&store, margin, &label);
        }
    });
    if let Err(error) = spawned {
        warn!(%error, "GLOBAL candidate pruning not started");
    }
}

fn prune_staged(store: &quil_store::RocksClockStore, label: &str) {
    let mut after: Option<Vec<u8>> = None;
    let (mut scanned, mut deleted, mut bytes, mut kept) = (0u64, 0u64, 0u64, 0u64);
    loop {
        match store.prune_committed_staged_shard_frames(after.as_deref(), STAGED_STEP, false) {
            Ok(pass) => {
                scanned += pass.scanned;
                deleted += pass.deleted;
                bytes += pass.deleted_bytes;
                kept += pass.differing + pass.uncommitted + pass.malformed;
                after = pass.next;
            }
            Err(error) => {
                warn!(store = %label, %error, "staged shard frame cleanup stopped; a restart resumes it");
                return;
            }
        }
        if after.is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    info!(store = %label, scanned, deleted, bytes, kept, "staged shard frame cleanup complete");
}

fn prune_candidates(store: &quil_store::RocksClockStore, margin: u64, label: &str) {
    let (mut from, mut pruned, mut bytes) = (0u64, 0u64, 0u64);
    loop {
        match store.prune_global_candidates(margin, from, CANDIDATE_STEP, false) {
            Ok(pass) => {
                pruned += pass.pruned;
                bytes += pass.pruned_bytes;
                match pass.next_from {
                    Some(next) => from = next,
                    None => break,
                }
            }
            Err(error) => {
                warn!(store = %label, %error, "GLOBAL candidate prune failed; retrying next pass");
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if pruned > 0 {
        info!(store = %label, pruned, bytes, "pruned GLOBAL candidates");
    }
}

#[cfg(test)]
mod tests {
    use super::default_on;

    /// Every cleanup is on unless its setting is `0`.
    #[test]
    fn cleanups_are_on_unless_switched_off() {
        assert!(default_on(None));
        assert!(default_on(Some("1")));
        assert!(default_on(Some("yes")));
        assert!(!default_on(Some("0")));
        assert!(!default_on(Some(" 0 ")));
    }
}
