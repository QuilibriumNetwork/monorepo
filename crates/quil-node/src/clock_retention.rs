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
//! - `QUIL_PRUNE_GLOBAL_REQUESTS`: on a regular (non-archive) node and on
//!   every standalone worker, every `QUIL_PRUNE_INTERVAL_SECS`, delete the
//!   request bodies of global frames more than
//!   `QUIL_PRUNE_GLOBAL_REQUESTS_KEEP` (default and minimum two days of
//!   frames) below the head. Headers are kept. A pass compacts the pruned
//!   range only once table files of pruned bodies reach
//!   `RocksClockStore::REQUEST_RECLAIM_BYTES`. A worker's first pass waits
//!   an extra minute per core (repeating after an hour of cores).
//! - `QUIL_PRUNE_UNSERVED_SHARD_FRAMES`: on a regular master, every
//!   `QUIL_PRUNE_INTERVAL_SECS` (first after an hour), delete the stored
//!   frames of shards no worker or engine of the node serves whose latest
//!   frame is older than `QUIL_PRUNE_UNSERVED_SHARD_FRAMES_IDLE_SECS`
//!   (default two days, at least one), keeping each shard's latest frame.
//! - `QUIL_SNAPSHOT_PINNED_MAX=<n>`: keep store snapshots only on the newest
//!   `n` (default 64, at least 16; `off` also disables it) published
//!   generations.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tracing::{info, warn};

/// Staged keys examined per step of the startup cleanup.
const STAGED_STEP: usize = 10_000;
/// The startup cleanup waits this long first, like the periodic pruners, so
/// a store closed soon after opening (a failed start, a test) is not scanned.
const STAGED_START_DELAY: Duration = Duration::from_secs(60);
/// Candidate headers examined per step of a candidate pass.
const CANDIDATE_STEP: usize = 5_000;
/// Never closer to the head than this, whatever is configured.
const MIN_CANDIDATE_MARGIN: u64 = 64;
/// Request bodies a regular node keeps: its gap backfill window
/// (two days of frames), which also covers the frame cache and gossip drain.
const MIN_REQUEST_KEEP: u64 = 2 * 1440;
/// Workers' first request prunes start this far apart, by core id: the first
/// pass of a store that kept every body deletes and compacts gigabytes, and a
/// host runs dozens of workers on the same disks.
const WORKER_FIRST_PRUNE_STEP: Duration = Duration::from_secs(60);
/// Core slots before the first-pass offsets repeat (an hour of steps).
const WORKER_FIRST_PRUNE_SLOTS: u32 = 60;

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
        info!(
            store = label,
            limit, "keeping store snapshots only on the newest published generations"
        );
        crdt.set_snapshot_pinned_limit(limit);
    }
}

/// `QUIL_PRUNE_STAGED_SHARD_FRAMES` (default on): one bounded pass over the staged
/// application frames in `db`, in the background, starting after
/// [`STAGED_START_DELAY`]. It holds the store only for one step at a time and
/// stops once the store is dropped, so it never keeps the database open past
/// its owners (an open RocksDB at process exit aborts).
pub(crate) fn spawn_staged_cleanup(db: &quil_forest::CoordinatedDb, label: String) {
    if !enabled("QUIL_PRUNE_STAGED_SHARD_FRAMES") {
        return;
    }
    let db = db.downgrade();
    let spawned = std::thread::Builder::new()
        .name(format!("staged-prune-{label}"))
        .spawn(move || {
            std::thread::sleep(STAGED_START_DELAY);
            prune_staged(&db, &label)
        });
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
    let spawned = std::thread::Builder::new()
        .name(format!("candidate-prune-{label}"))
        .spawn(move || {
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

/// `QUIL_PRUNE_GLOBAL_REQUESTS` (default on): on a node that neither executes
/// GLOBAL frames nor serves their history, prune old request bodies every
/// interval until the store is dropped. The caller decides that role.
pub(crate) fn spawn_request_pruner(clock: &Arc<quil_store::RocksClockStore>, label: String) {
    spawn_request_pruner_for_core(clock, label, 0);
}

/// When the first request prune of core `core_id`'s store runs: one interval
/// after start for the master (core 0), and a slot of
/// [`WORKER_FIRST_PRUNE_STEP`] later per worker core, so the workers of one
/// host do not all delete and compact their backlog at once.
fn first_request_prune(interval: Duration, core_id: u32) -> Duration {
    interval + WORKER_FIRST_PRUNE_STEP * (core_id % WORKER_FIRST_PRUNE_SLOTS)
}

/// [`spawn_request_pruner`] for the store of core `core_id`, whose first pass
/// waits for [`first_request_prune`].
pub(crate) fn spawn_request_pruner_for_core(
    clock: &Arc<quil_store::RocksClockStore>,
    label: String,
    core_id: u32,
) {
    if !enabled("QUIL_PRUNE_GLOBAL_REQUESTS") {
        return;
    }
    let clock: Weak<quil_store::RocksClockStore> = Arc::downgrade(clock);
    let keep = setting("QUIL_PRUNE_GLOBAL_REQUESTS_KEEP")
        .unwrap_or(MIN_REQUEST_KEEP)
        .max(MIN_REQUEST_KEEP);
    let interval = Duration::from_secs(setting("QUIL_PRUNE_INTERVAL_SECS").unwrap_or(600).max(10));
    let first = first_request_prune(interval, core_id);
    let spawned = std::thread::Builder::new().name(format!("request-prune-{label}")).spawn(move || {
        info!(store = %label, keep, first_pass_secs = first.as_secs(),
            "GLOBAL request body pruning enabled");
        let mut wait = first;
        loop {
            std::thread::sleep(wait);
            wait = interval;
            let Some(store) = clock.upgrade() else { return };
            let started = std::time::Instant::now();
            match store.prune_global_frame_requests(keep) {
                // `deferred`: RocksDB's own compaction reclaims the space.
                Ok(pass) if pass.frames > 0 => info!(store = %label, frames = pass.frames,
                    retained_from = pass.retained_from, dead_mib = pass.dead_bytes >> 20,
                    reclaim = if pass.compacted { "compacted" } else { "deferred" },
                    reclaim_at_mib = quil_store::RocksClockStore::REQUEST_RECLAIM_BYTES >> 20,
                    secs = started.elapsed().as_secs(), "pruned GLOBAL request bodies"),
                Ok(_) => {}
                Err(error) => warn!(store = %label, %error, "GLOBAL request prune failed; retrying next pass"),
            }
        }
    });
    if let Err(error) = spawned {
        warn!(%error, "GLOBAL request pruning not started");
    }
}

/// Frame keys examined per step of an unserved-shard frame pass.
const UNSERVED_STEP: usize = 10_000;
/// Frame keys one unserved-shard pass examines at most; the next pass goes on
/// from there.
const UNSERVED_PASS_MAX: u64 = 1_000_000;
/// A pass still running after this logs one overrun warning.
const UNSERVED_PASS_OVERRUN: Duration = Duration::from_secs(600);
/// The first unserved-shard pass waits this long, so the workers that serve
/// shards again after a restart are listed before any shard counts as left.
const UNSERVED_FIRST_PASS: Duration = Duration::from_secs(3600);
/// How long a shard's frames are kept after its latest frame, by default:
/// two days, the regular node's gap backfill window and four epochs, past a
/// leave's confirmation and the epoch its rewards settle in.
const UNSERVED_IDLE_DEFAULT_SECS: u64 = 2 * 86_400;
/// Never less than two epochs, whatever is configured.
const UNSERVED_IDLE_MIN_SECS: u64 = 86_400;

/// The shard filters a node serves, or `None` when it cannot tell (then no
/// frame is deleted).
pub(crate) type ServedShards = Arc<dyn Fn() -> Option<HashSet<Vec<u8>>> + Send + Sync>;

/// The filters of every worker bound to a shard (confirmed or pending) and
/// of every running application engine. `None` once either has gone (the
/// node is stopping) or the workers cannot be listed.
pub(crate) fn served_shards(
    workers: Weak<dyn quil_engine::worker::WorkerManager>,
    engines: Weak<
        parking_lot::RwLock<
            std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
        >,
    >,
) -> ServedShards {
    Arc::new(move || {
        let listed = workers.upgrade()?.range_workers().ok()?;
        let engines = engines.upgrade()?;
        let mut served: HashSet<Vec<u8>> = listed
            .into_iter()
            .map(|worker| worker.filter)
            .filter(|filter| !filter.is_empty())
            .collect();
        served.extend(engines.read().keys().cloned());
        Some(served)
    })
}

/// `QUIL_PRUNE_UNSERVED_SHARD_FRAMES` (default on): on a regular master,
/// every `QUIL_PRUNE_INTERVAL_SECS`, delete the stored frames of shards no
/// worker or engine of this node serves and whose latest frame is older
/// than `QUIL_PRUNE_UNSERVED_SHARD_FRAMES_IDLE_SECS` (default two days, at
/// least one), keeping each shard's latest frame. Engines read their worker's
/// own store, so only the master's copy, read by RPC and the explorer, goes.
pub(crate) fn spawn_unserved_frame_pruner(
    clock: &Arc<quil_store::RocksClockStore>,
    served: ServedShards,
    label: String,
) {
    if !enabled("QUIL_PRUNE_UNSERVED_SHARD_FRAMES") {
        return;
    }
    let clock: Weak<quil_store::RocksClockStore> = Arc::downgrade(clock);
    let idle = Duration::from_secs(unserved_idle_secs(setting(
        "QUIL_PRUNE_UNSERVED_SHARD_FRAMES_IDLE_SECS",
    )));
    let interval = Duration::from_secs(setting("QUIL_PRUNE_INTERVAL_SECS").unwrap_or(600).max(10));
    let spawned = std::thread::Builder::new()
        .name(format!("unserved-prune-{label}"))
        .spawn(move || {
            info!(store = %label, idle_secs = idle.as_secs(),
                first_pass_secs = UNSERVED_FIRST_PASS.as_secs(),
                "pruning frames of shards this node no longer serves enabled");
            let mut wait = UNSERVED_FIRST_PASS.max(interval);
            let mut resume = None;
            loop {
                std::thread::sleep(wait);
                wait = interval;
                let Some(store) = clock.upgrade() else { return };
                let pass = UnservedPass {
                    idle,
                    step: UNSERVED_STEP,
                    max: UNSERVED_PASS_MAX,
                    overrun: UNSERVED_PASS_OVERRUN,
                    pause: Duration::from_millis(50),
                };
                prune_unserved(&store, served.as_ref(), &pass, &mut resume, &label);
            }
        });
    if let Err(error) = spawned {
        warn!(%error, "unserved shard frame pruning not started");
    }
}

/// The configured idle bound in seconds, defaulted and floored.
fn unserved_idle_secs(configured: Option<u64>) -> u64 {
    configured
        .unwrap_or(UNSERVED_IDLE_DEFAULT_SECS)
        .max(UNSERVED_IDLE_MIN_SECS)
}

/// Bounds of one [`prune_unserved`] pass.
struct UnservedPass {
    idle: Duration,
    step: usize,
    max: u64,
    overrun: Duration,
    pause: Duration,
}

/// What one [`prune_unserved`] pass did, each shard counted once: in
/// `pruned` when any of its frames went, else under the reason the last step
/// that reached it kept it for.
#[derive(Debug, Default, PartialEq, Eq)]
struct UnservedTotals {
    /// Shards with a latest-frame index the pass examined.
    shards: u64,
    /// Shards whose old frames were deleted.
    pruned: u64,
    frames: u64,
    bytes: u64,
    compacted: u64,
    /// Kept whole: a worker or engine of this node serves them.
    served: u64,
    /// Kept whole: the latest frame is within the idle bound.
    recent: u64,
    /// Kept whole: the index or the latest frame does not decode.
    unreadable: u64,
    /// Unserved and idle with only the latest frame left: pruned before.
    latest_only: u64,
}

impl UnservedTotals {
    fn count(
        &mut self,
        pruned: &HashMap<Vec<u8>, (u64, u64)>,
        kept: &HashMap<Vec<u8>, quil_store::KeptShard>,
    ) {
        use quil_store::KeptShard;
        self.pruned = pruned.len() as u64;
        for (filter, why) in kept {
            if pruned.contains_key(filter) {
                continue;
            }
            match why {
                KeptShard::Served => self.served += 1,
                KeptShard::Recent => self.recent += 1,
                KeptShard::Unreadable => self.unreadable += 1,
                KeptShard::LatestOnly => self.latest_only += 1,
            }
        }
        self.shards = self.pruned + self.served + self.recent + self.unreadable + self.latest_only;
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as i64)
}

/// One bounded pass from `resume`, which it leaves where the next pass goes
/// on. The served set is read again for every step; when it cannot be read
/// the pass stops. Every pass that reads it ends with one summary line: what
/// went and why each other shard from `resume` on stayed.
fn prune_unserved(
    store: &quil_store::RocksClockStore,
    served: &(dyn Fn() -> Option<HashSet<Vec<u8>>> + Send + Sync),
    pass: &UnservedPass,
    resume: &mut Option<Vec<u8>>,
    label: &str,
) -> UnservedTotals {
    let started = std::time::Instant::now();
    let idle_before_ms = now_ms().saturating_sub(pass.idle.as_millis() as i64);
    let mut totals = UnservedTotals::default();
    let mut shards: HashMap<Vec<u8>, (u64, u64)> = HashMap::new();
    let mut kept: HashMap<Vec<u8>, quil_store::KeptShard> = HashMap::new();
    let (mut examined, mut announced, mut overran, mut listed) = (0u64, false, false, false);
    loop {
        let Some(set) = served() else {
            info!(store = %label, "unserved shard frame pass skipped: the served shards cannot be listed");
            break;
        };
        listed = true;
        let is_served = |filter: &[u8]| set.contains(filter);
        let step = pass
            .step
            .min(pass.max.saturating_sub(examined) as usize)
            .max(1);
        // A dry first step tells whether there is anything to do, so an idle
        // store logs nothing. Nothing left past the resume point: the next
        // pass starts over from the first shard.
        if !announced {
            match store.prune_unserved_shard_frames(
                &is_served,
                idle_before_ms,
                resume.as_deref(),
                step,
                true,
            ) {
                Ok(dry) if dry.pruned.is_empty() && dry.next.is_none() => {
                    kept.extend(dry.kept);
                    *resume = None;
                    break;
                }
                Ok(dry) => info!(store = %label, served = set.len(), shards = dry.shards,
                    idle_secs = pass.idle.as_secs(), max_frames = pass.max,
                    "pruning frames of shards this node no longer serves"),
                Err(error) => {
                    warn!(store = %label, %error, "unserved shard frame prune failed; retrying next pass");
                    break;
                }
            }
            announced = true;
        }
        let step = match store.prune_unserved_shard_frames(
            &is_served,
            idle_before_ms,
            resume.as_deref(),
            step,
            false,
        ) {
            Ok(step) => step,
            Err(error) => {
                warn!(store = %label, %error, "unserved shard frame prune failed; retrying next pass");
                break;
            }
        };
        examined += step.examined.max(1);
        kept.extend(step.kept);
        for shard in &step.pruned {
            let entry = shards.entry(shard.filter.clone()).or_default();
            entry.0 = entry.0.max(shard.below);
            entry.1 += shard.bytes;
            totals.frames += shard.frames;
            totals.bytes += shard.bytes;
        }
        *resume = step.next;
        if !overran && started.elapsed() >= pass.overrun {
            overran = true;
            warn!(store = %label, secs = started.elapsed().as_secs(), frames = totals.frames,
                mib = totals.bytes >> 20, "unserved shard frame pass is running long; it goes on");
        }
        if resume.is_none() || examined >= pass.max {
            break;
        }
        std::thread::sleep(pass.pause);
    }
    totals.count(&shards, &kept);
    for (filter, (below, bytes)) in &shards {
        if *bytes >= quil_store::RocksClockStore::SHARD_FRAME_RECLAIM_BYTES {
            store.compact_pruned_shard_frames(filter, *below);
            totals.compacted += 1;
        }
    }
    if listed {
        info!(store = %label, shards = totals.shards, pruned = totals.pruned,
            frames = totals.frames, bytes = totals.bytes, compacted = totals.compacted,
            kept_served = totals.served, kept_recent = totals.recent,
            kept_unreadable = totals.unreadable, kept_latest_only = totals.latest_only,
            idle_secs = pass.idle.as_secs(), done = resume.is_none(),
            millis = started.elapsed().as_millis() as u64,
            "unserved shard frame pass finished");
    }
    totals
}

fn prune_staged(db: &quil_forest::WeakCoordinatedDb, label: &str) {
    let mut after: Option<Vec<u8>> = None;
    let (mut scanned, mut deleted, mut bytes, mut kept) = (0u64, 0u64, 0u64, 0u64);
    loop {
        let Some(db) = db.upgrade() else {
            info!(store = %label, scanned, deleted, "staged shard frame cleanup stopped: the store closed; a restart resumes it");
            return;
        };
        let store = quil_store::RocksClockStore::new(db);
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
        drop(store);
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
    use super::{default_on, first_request_prune};
    use std::collections::BTreeSet;
    use std::time::Duration;

    /// The master's first request prune keeps its one-interval wait; the
    /// workers of a host start theirs a minute apart, each in its own slot.
    #[test]
    fn worker_first_request_prunes_are_staggered_by_core() {
        let interval = Duration::from_secs(600);
        let first = |core: u32| first_request_prune(interval, core).as_secs();
        assert_eq!(first(0), 600, "the master");
        assert_eq!(first(1), 660);
        assert_eq!(first(32), 600 + 32 * 60);
        assert_eq!(first(60), 600, "slots repeat after an hour");
        let starts: BTreeSet<u64> = (1..=32).map(first).collect();
        assert_eq!(starts.len(), 32, "a minute of its own per worker");
        assert!(starts.iter().all(|&start| start < 600 + 3600));
        assert_eq!(
            first_request_prune(Duration::from_secs(10), 3).as_secs(),
            190,
            "a slot does not shrink with the interval"
        );
    }

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

#[cfg(test)]
mod unserved_tests {
    use super::*;
    use quil_types::proto::global;
    use quil_types::store::ClockStore;

    fn open(dir: &std::path::Path) -> (quil_store::RocksDb, quil_store::RocksClockStore) {
        let db = quil_store::RocksDb::open(dir).unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        (db, clock)
    }

    /// Frames `1..=head` of `filter`, all `age` old.
    fn serve(s: &quil_store::RocksClockStore, filter: &[u8], head: u64, age: Duration) {
        let stamp = now_ms() - age.as_millis() as i64;
        for n in 1..=head {
            let frame = global::AppShardFrame {
                header: Some(global::FrameHeader {
                    address: filter.to_vec(),
                    frame_number: n,
                    timestamp: stamp,
                    output: vec![n as u8; 64],
                    ..Default::default()
                }),
                ..Default::default()
            };
            s.store_shard_clock_frame_for_serving(&[n as u8; 32], &frame)
                .unwrap();
        }
    }

    fn frames(s: &quil_store::RocksClockStore, filter: &[u8], head: u64) -> u64 {
        (1..=head)
            .filter(|&n| s.get_shard_clock_frame(filter, n, false).is_ok())
            .count() as u64
    }

    fn pass(max: u64) -> UnservedPass {
        UnservedPass {
            idle: Duration::from_secs(UNSERVED_IDLE_DEFAULT_SECS),
            step: 4,
            max,
            overrun: Duration::ZERO,
            pause: Duration::ZERO,
        }
    }

    const DAY: Duration = Duration::from_secs(86_400);

    /// A pass deletes the old frames of shards left more than the bound ago
    /// and keeps a served shard and one left within the bound whole.
    #[test]
    fn a_pass_prunes_only_shards_left_longer_than_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let (_db, s) = open(dir.path());
        let (left, served, recent) = (vec![1u8; 35], vec![2u8; 35], vec![3u8; 35]);
        serve(&s, &left, 12, 3 * DAY);
        serve(&s, &served, 12, 3 * DAY);
        serve(&s, &recent, 12, DAY);
        let set: HashSet<Vec<u8>> = [served.clone()].into();
        let listed = move || Some(set.clone());
        let mut resume = None;

        let totals = prune_unserved(&s, &listed, &pass(1_000), &mut resume, "test");

        assert_eq!(
            frames(&s, &left, 12),
            1,
            "a shard left more than the bound ago keeps only its latest frame"
        );
        assert_eq!(
            frames(&s, &served, 12),
            12,
            "a served shard keeps every frame"
        );
        assert_eq!(
            frames(&s, &recent, 12),
            12,
            "a recently left shard keeps every frame"
        );
        assert_eq!((totals.pruned, totals.frames, totals.compacted), (1, 11, 0));
        assert_eq!(resume, None);
    }

    /// A pass's summary counts each shard once, whatever number of steps
    /// reached it: pruned, or kept as served, recent or already pruned; a
    /// pass with nothing to delete still counts every shard it kept.
    #[test]
    fn a_pass_summary_counts_each_shard_once_by_why_it_stayed() {
        let dir = tempfile::tempdir().unwrap();
        let (_db, s) = open(dir.path());
        let (left, served, recent, done) =
            (vec![1u8; 35], vec![2u8; 35], vec![3u8; 35], vec![4u8; 35]);
        serve(&s, &left, 12, 3 * DAY);
        serve(&s, &served, 12, 3 * DAY);
        serve(&s, &recent, 12, DAY);
        serve(&s, &done, 1, 3 * DAY);
        let set: HashSet<Vec<u8>> = [served.clone()].into();
        let listed = move || Some(set.clone());
        let mut resume = None;

        // Steps of 4 frame keys: the first shard takes several steps.
        let first = prune_unserved(&s, &listed, &pass(1_000), &mut resume, "test");
        let counts = |t: &UnservedTotals| {
            (
                t.shards,
                t.pruned,
                t.served,
                t.recent,
                t.unreadable,
                t.latest_only,
            )
        };
        assert_eq!(
            counts(&first),
            (4, 1, 1, 1, 0, 1),
            "first_pass_counts: (shards, pruned, served, recent, unreadable, latest only)"
        );
        assert_eq!((first.frames, first.bytes > 0), (11, true));

        let second = prune_unserved(&s, &listed, &pass(1_000), &mut resume, "test");
        assert_eq!(
            counts(&second),
            (4, 0, 1, 1, 0, 2),
            "idle_pass_counts: a pass with nothing to delete counts what it kept"
        );
        assert_eq!((second.frames, second.bytes), (0, 0));
        assert_eq!(resume, None);
    }

    /// A shard taken up after a step of the pass deleted some of its frames
    /// counts as pruned, not as served.
    #[test]
    fn a_shard_taken_up_mid_pass_counts_as_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let (_db, s) = open(dir.path());
        let left = vec![1u8; 35];
        serve(&s, &left, 12, 3 * DAY);
        let calls = std::sync::atomic::AtomicU64::new(0);
        // Listed once per step: the third step finds the shard served.
        let listed = || {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(if call < 2 {
                HashSet::new()
            } else {
                HashSet::from([left.clone()])
            })
        };
        let mut resume = None;

        let totals = prune_unserved(&s, &listed, &pass(1_000), &mut resume, "test");
        assert_eq!(frames(&s, &left, 12), 4, "two steps deleted 8 frames");
        assert_eq!(
            (totals.shards, totals.pruned, totals.served, totals.frames),
            (1, 1, 0, 8),
            "taken_up_counts: (shards, pruned, served, frames)"
        );
    }

    /// Without the served shards, a pass deletes nothing.
    #[test]
    fn no_frame_is_deleted_when_the_served_shards_cannot_be_listed() {
        let dir = tempfile::tempdir().unwrap();
        let (_db, s) = open(dir.path());
        let left = vec![1u8; 35];
        serve(&s, &left, 12, 3 * DAY);
        let unlisted = || None;
        let mut resume = None;

        let totals = prune_unserved(&s, &unlisted, &pass(1_000), &mut resume, "test");
        assert_eq!(frames(&s, &left, 12), 12, "nothing is deleted unlisted");
        assert_eq!(totals, UnservedTotals::default());
    }

    /// A pass stops at its frame budget and the next goes on from there.
    #[test]
    fn a_pass_stops_at_its_budget_and_the_next_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let (_db, s) = open(dir.path());
        let (a, b) = (vec![1u8; 35], vec![2u8; 35]);
        serve(&s, &a, 12, 3 * DAY);
        serve(&s, &b, 12, 3 * DAY);
        let none = || Some(HashSet::new());
        let mut resume = None;

        let first = prune_unserved(&s, &none, &pass(8), &mut resume, "test");
        assert_eq!(first.frames, 8, "a pass stops at its budget");
        assert!(resume.is_some(), "and says where the next goes on");
        let second = prune_unserved(&s, &none, &pass(1_000), &mut resume, "test");
        assert_eq!(first.frames + second.frames, 22);
        assert_eq!((frames(&s, &a, 12), frames(&s, &b, 12)), (1, 1));
        assert_eq!(resume, None);
    }

    /// A pass that finds nothing left past where the last one stopped starts
    /// the next from the first shard, so shards before that point are not
    /// skipped for good.
    #[test]
    fn a_pass_with_nothing_past_its_resume_point_starts_over() {
        let dir = tempfile::tempdir().unwrap();
        let (_db, s) = open(dir.path());
        let (a, b) = (vec![1u8; 35], vec![2u8; 35]);
        serve(&s, &a, 12, 3 * DAY);
        serve(&s, &b, 12, 3 * DAY);
        let only_a = || Some(HashSet::from([a.clone()]));
        let only_b = || Some(HashSet::from([b.clone()]));
        let mut resume = None;

        prune_unserved(&s, &only_a, &pass(4), &mut resume, "test");
        assert!(
            resume.is_some(),
            "the first pass stops inside the second shard"
        );
        // The second shard is taken up and the first left.
        prune_unserved(&s, &only_b, &pass(1_000), &mut resume, "test");
        prune_unserved(&s, &only_b, &pass(1_000), &mut resume, "test");
        assert_eq!(
            frames(&s, &a, 12),
            1,
            "a pass with nothing past its resume point starts over"
        );
        assert_eq!(resume, None);
    }

    /// Served: every worker bound to a shard, confirmed or still joining;
    /// unknown once the workers are gone.
    #[test]
    fn served_shards_are_every_bound_workers_filter() {
        let workers = Arc::new(quil_engine::test_support::TestWorkerManager::new());
        workers.add_with_filter(1, vec![1; 35]);
        workers.add(quil_engine::worker::WorkerInfo {
            core_id: 2,
            filter: vec![2; 35],
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 7,
            allocated: false,
        });
        workers.add_with_filter(3, Vec::new());
        let engines = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
        let as_manager: Arc<dyn quil_engine::worker::WorkerManager> = workers.clone();
        let served = served_shards(Arc::downgrade(&as_manager), Arc::downgrade(&engines));

        let expected: HashSet<Vec<u8>> = [vec![1; 35], vec![2; 35]].into();
        assert_eq!(
            served(),
            Some(expected),
            "a joining worker's shard is served"
        );
        drop((as_manager, workers));
        assert_eq!(served(), None, "unknown once the workers are gone");
    }

    /// `(read_bytes, write_bytes)` of this process from `/proc/self/io`.
    fn process_io() -> (u64, u64) {
        let text = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0)
        };
        (field("read_bytes:"), field("write_bytes:"))
    }

    /// Full-scale cost of the pruner on a writable copy of a node's master
    /// store (`QUIL_PRUNE_MEASURE_STORE`; never a live store): a dry run,
    /// then the node's own passes until every shard is done, with its step,
    /// budget and compaction threshold. `QUIL_PRUNE_MEASURE_SERVED` lists the
    /// served filters in hex, comma-separated; with none, only the idle bound
    /// keeps the shards the copied node still served.
    #[test]
    #[ignore = "measurement on a store copy"]
    fn measure_unserved_frame_prune() {
        let Ok(path) = std::env::var("QUIL_PRUNE_MEASURE_STORE") else {
            return;
        };
        let served: HashSet<Vec<u8>> = std::env::var("QUIL_PRUNE_MEASURE_SERVED")
            .unwrap_or_default()
            .split(',')
            .filter(|hex| !hex.is_empty())
            .map(|filter| hex::decode(filter.trim()).unwrap())
            .collect();
        let (db, s) = open(std::path::Path::new(&path));
        let tables = || -> u64 {
            db.inner()
                .live_files()
                .unwrap()
                .iter()
                .map(|f| f.size as u64)
                .sum()
        };
        let idle = Duration::from_secs(unserved_idle_secs(setting(
            "QUIL_PRUNE_UNSERVED_SHARD_FRAMES_IDLE_SECS",
        )));
        let idle_before_ms = now_ms() - idle.as_millis() as i64;
        let is_served = |filter: &[u8]| served.contains(filter);
        println!(
            "store {path}: {} table bytes, {} served filters, idle {}s",
            tables(),
            served.len(),
            idle.as_secs()
        );

        let (io, started) = (process_io(), std::time::Instant::now());
        let (mut next, mut dry) = (None::<Vec<u8>>, (0u64, 0u64, 0u64, 0u64, 0u64));
        loop {
            let step = s
                .prune_unserved_shard_frames(
                    &is_served,
                    idle_before_ms,
                    next.as_deref(),
                    UNSERVED_STEP,
                    true,
                )
                .unwrap();
            if next.is_none() {
                dry.0 = step.shards;
                dry.1 = step.kept(quil_store::KeptShard::Served);
                dry.2 = step.kept(quil_store::KeptShard::Recent);
            }
            dry.3 += step.frames();
            dry.4 += step.bytes();
            next = step.next;
            if next.is_none() {
                break;
            }
        }
        let after = process_io();
        println!(
            "dry run: shards {} (served {}, recent {}), deletable {} frames, {} bytes; {:.1}s, read {} B, written {} B",
            dry.0, dry.1, dry.2, dry.3, dry.4,
            started.elapsed().as_secs_f64(), after.0 - io.0, after.1 - io.1
        );

        let listed = move || Some(served.clone());
        let mut resume = None;
        let (mut passes, mut totals) = (0u64, UnservedTotals::default());
        let (io, started, before) = (process_io(), std::time::Instant::now(), tables());
        loop {
            let pass = UnservedPass {
                idle,
                step: UNSERVED_STEP,
                max: UNSERVED_PASS_MAX,
                overrun: UNSERVED_PASS_OVERRUN,
                pause: Duration::from_millis(50),
            };
            let t = std::time::Instant::now();
            let done = prune_unserved(&s, &listed, &pass, &mut resume, "measure");
            passes += 1;
            println!(
                "pass {passes}: shards {}, frames {}, bytes {}, compacted {}, {:.1}s",
                done.shards,
                done.frames,
                done.bytes,
                done.compacted,
                t.elapsed().as_secs_f64()
            );
            totals.frames += done.frames;
            totals.bytes += done.bytes;
            totals.compacted += done.compacted;
            if resume.is_none() {
                break;
            }
        }
        let after = process_io();
        println!(
            "prune: {passes} passes, {} frames, {} bytes, {} shards compacted; {:.1}s, read {} B, written {} B; table bytes {before} -> {}",
            totals.frames, totals.bytes, totals.compacted, started.elapsed().as_secs_f64(),
            after.0 - io.0, after.1 - io.1, tables()
        );
        assert_eq!(
            totals.frames, dry.3,
            "the passes delete what the dry run counted"
        );
    }

    /// The idle bound defaults to two days and never goes below one.
    #[test]
    fn the_idle_bound_defaults_to_two_days_and_is_at_least_one() {
        assert_eq!(unserved_idle_secs(None), 2 * 86_400);
        assert_eq!(unserved_idle_secs(Some(600)), 86_400, "never below one day");
        assert_eq!(unserved_idle_secs(Some(7 * 86_400)), 7 * 86_400);
    }
}
