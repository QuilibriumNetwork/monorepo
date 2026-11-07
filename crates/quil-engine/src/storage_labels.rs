//! Hash storage proof labels computed ahead (decided 2026-10-26).
//!
//! A leaf's labels depend on its key and node count, never on its data.
//! Keys bind the member and leaf; before the stable replica key epoch (mainnet: 1429) they also bind the epoch. So a member labels the leaves it will
//! register for an epoch during the epoch before ([`precompute`]), at a count
//! the data may still change around
//! (`quil_crypto::storage_proof::precompute_nodes`), and keeps every layer on
//! disk. At the snapshot only the data's part is left
//! (`storage_snapshot::encode_member`), and the seal opens the kept layers
//! rather than labelling the leaf again (`storage_snapshot::prepare_member_seat`).
//! Labelling takes about an hour per GiB of a leaf on one core, which the
//! renewal's grace after the snapshot could not hold for a large shard.
//!
//! A leaf's eleven label layers plus column digests take twelve times its
//! replica on disk. Before that epoch they expire at their epoch; afterwards
//! used counts persist across seals and epochs, and only unused counts expire.
//! So a leaf is labelled and kept only while the labels' filesystem has room
//! for them (decided 2026-10-27): [`DISK_MARGIN`] times their bytes above a
//! floor ([`disk_floor`]), beside what the leaves being labelled have still
//! to write, checked before a leaf starts and before each of its writes. A
//! leaf refused room is labelled where it is needed instead, as by a process
//! that keeps no labels, and leaves nothing on disk.
//!
//! Labels kept are a cache: the node's stores and logs on the filesystem
//! must not starve for them (2026-11-03: a regular node's labels held 175
//! of its 207 GB used and every store failed its writes once the stores'
//! growth ate the floor). Once free space falls below the floor, labels not
//! in use are released until it is back [`release_band`] above it, latest
//! needed first ([`LabelStore::keep_floor`], checked every
//! [`FLOOR_CHECK_EVERY`]), and labelling ahead waits until free space is
//! back at [`resume_free`]; their snapshots and seals label those leaves at
//! need.
//!
//! Labelling ahead gives its memory back while more urgent work waits for
//! memory it holds (`crate::storage_jobs::Reservation::yield_requested`): the
//! whole layers it labelled stay on disk, marked for the next attempt at the
//! leaf's count (`<n>.kept`), which reads them back and goes on from the next
//! as soon as its memory fits again, unless its snapshot has labelled the
//! leaf meanwhile. Labelling a leaf of 32 million nodes takes most of the
//! window labelling ahead has, so labelling it again from its start after
//! each yield never ended (2026-11-01). The leaves wait for memory in an
//! order (`crate::storage_jobs::AheadOrder`): those its snapshot could not
//! label within half the renewal's grace first ([`ahead_orders`]). Only so
//! many are labelled at once (`crate::storage_jobs::ahead_jobs_for`: three
//! on a 16-thread node of 31 GiB, more with more cores and memory; sectors
//! of epochs where persistent storage holds run beside them on the other
//! slots, `crate::storage_jobs::ahead_in_parallel`), and while a renewal's
//! leaf is labelled now only half of them go on beside it; the others pause,
//! keeping their memory and layers, until that labelling ends
//! (`crate::storage_jobs::Reservation::wait_while_paused`).
//!
//! Labelling ahead for an epoch gives up once GLOBAL reaches the epoch's
//! snapshot frame ([`expired`]): the snapshot labels what is left itself,
//! going on from the whole layers labelled ahead, and past the renewal's
//! grace its seat renews without it.
//!
//! Whatever labels a leaf, ahead or at its snapshot, keeps each whole layer
//! on disk as it ends, synced, with a manifest of the labels it belongs to
//! and each layer's SHA-256 (`<n>.kept`, [`Manifest`]): a restart, a crash,
//! a yield or the snapshot frame costs at most the layer in progress
//! (2026-11-01: a restart while a seat's leaf was labelled at its snapshot
//! labelled it again from its first layer, past the renewal's grace, and
//! labelling ahead dropped its layers at the snapshot frame). The next
//! attempt at the leaf's count checks each kept layer against its digest
//! before going on from them ([`LabelStore::admit`]): from a layer cut
//! short or changed, the leaf is labelled again.
//!
//! From the stable replica key epoch
//! (`quil_types::consensus::stable_replica_keys_at`) the key no longer
//! depends on the epoch, so labels made for one epoch serve every later one
//! while the leaf's data stays registrable at their count (issue #749). They
//! are kept in one directory for all those epochs ([`STABLE_DIR`]), each
//! count with the latest epoch a registration, a seal or labelling ahead
//! looked for it, and a count goes at the first sweep of a later epoch
//! ([`LabelStore::sweep`]), never when one registration is sealed
//! ([`LabelStore::forget`]). A leaf is then labelled again only when its node
//! count leaves its padding band or its id changes.
//! Labelling ahead, a snapshot and a seal may then work in one leaf's
//! directory at once: one labelling writes a count at a time
//! ([`LabelStore::admit`]), `ready` last, so nothing finds it before it is
//! complete, and removing a count's files and opening its labels hold the
//! leaf's lock ([`leaf_lock`]). The whole layers kept of a count serve those
//! epochs too: labelling given up for one epoch goes on for a later one, and
//! only the sweep removes them ([`LabelStore::discard`]).
//!
//! Every worker process of a node keeps its labels in the one directory, so
//! the labelling of a count may be another process's: a labelling holds the
//! count's writer lock (`<n>.writer`, [`claim`]) from its admission to its
//! end, and a count another process labels is left to it, as one this
//! process labels is: two writers of a count leave a layers file of its
//! length whose labels are not the leaf's. A snapshot checks the labels kept
//! for a leaf before it encodes from them ([`Kept::verified_last_layer`]):
//! labels that do not match their column commitment are removed and the
//! leaf labelled again, rather than registered from them, which its seal
//! could never open.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use quil_crypto::sdr::SdrParams;
use quil_crypto::storage_hash::{self as hash, Digest};
use quil_crypto::storage_proof::{LabelSource, Node, NODE_BYTES};
use quil_forest::storage_health::FsUsage;
use quil_hypergraph::HypergraphCrdt;
use quil_types::error::{QuilError, Result};
use sha2::{Digest as _, Sha256};
use tracing::{info, warn};

use crate::storage_ledger::HostLedger;

/// Percent of the labels' filesystem that labels leave free, unless
/// [`DISK_FLOOR_MIN_BYTES`] is more. The stores sharing the filesystem stop
/// writing far below it (`quil_forest::storage_health::FLOOR_FREE_BYTES`).
pub const DISK_FLOOR_PERCENT: u64 = 10;

/// The least free space labels leave on their filesystem, however small it is.
pub const DISK_FLOOR_MIN_BYTES: u64 = 8 << 30;

/// A leaf is labelled and kept only with this many times its labels' bytes
/// free above the floor: room for whatever else writes to the filesystem
/// meanwhile, the stores and the logs among them. What they take of the
/// floor later, labels give back ([`LabelStore::keep_floor`]).
pub const DISK_MARGIN: u64 = 2;

/// How long a leaf's admission waits for the host's turn
/// ([`HostLedger::labels_turn`]) before it admits as if alone. A turn lasts
/// a look at the free space and a record written; one held longer is a
/// stopped process's, which must not stop the host's labels.
const LABELS_TURN_WAIT: Duration = Duration::from_secs(2);

/// How long a shard whose leaves were refused room waits before it is
/// labelled ahead again: the labels of the epoch before free their room once
/// their registration is sealed.
const REFUSED_RETRY: Duration = Duration::from_secs(30 * 60);

/// How often a process that keeps labels checks their filesystem for free
/// space below the floor ([`LabelStore::keep_floor`]): the stores and logs
/// beside them grow by gigabytes an hour at most.
pub const FLOOR_CHECK_EVERY: Duration = Duration::from_secs(60);

/// How often a release of labels that goes on is logged again.
const SHORT_LOGGED_EVERY: Duration = Duration::from_secs(60 * 60);

/// The file under the labels' directory marking that labels were released
/// for free space and labelling ahead waits ([`LabelStore::keep_floor`]),
/// shared by every process keeping labels there.
const SHORT_MARKER: &str = "short-of-space";

/// Free space a release of labels restores above a `floor`
/// ([`disk_floor`]): a quarter of it, so the stores beside them grow a while
/// before the next.
pub fn release_band(floor: u64) -> u64 {
    floor / 4
}

/// Free space on a filesystem of `total_bytes` from which labelling ahead
/// resumes after labels were released ([`LabelStore::keep_floor`]): the
/// floor and twice [`release_band`], so labels just released are not
/// labelled again for the next release to take.
pub fn resume_free(total_bytes: u64) -> u64 {
    let floor = disk_floor(total_bytes);
    floor.saturating_add(release_band(floor).saturating_mul(2))
}

/// The free space labels leave on a filesystem of `total_bytes`.
pub fn disk_floor(total_bytes: u64) -> u64 {
    (total_bytes / 100 * DISK_FLOOR_PERCENT).max(DISK_FLOOR_MIN_BYTES)
}

/// Bytes of a leaf's labels written to disk at a time ([`ChunkedWriter`]),
/// the buffer they are written through: each chunk is pushed to the disk
/// and waited for before the next is written, holding one of
/// [`FLUSH_PERMITS`], so a store's synced commit on the same disk waits
/// behind at most one chunk a permit (about 40 ms at 400 MB/s), not behind
/// whole layers. Written whole, then synced, a layer put up to a gigabyte
/// in the page cache at once, and leaves labelled together end their layers
/// together: a regular node labelling 37 leaves at its snapshot synced about
/// 13 GB in each round of layers, and its stores' commits waited up to 2.7 s
/// for their fsyncs behind them, past the store latency probe's fsync bound
/// (2026-11-05).
const FLUSH_CHUNK_BYTES: usize = 16 << 20;

/// Chunks of labels written to disk at once in this process, however many
/// leaves are labelled ([`FlushGate`]): two keep a fast disk's queue busy
/// while one waits for its chunk, and bound what a slow one holds ahead of
/// the stores' commits.
const FLUSH_PERMITS: usize = 2;

/// How long the labels written to disk at once may take there
/// ([`Pace`]): a store's synced commit waits behind them, and a frame's
/// votes wait on about 8 such commits in turn within its 10 s, so 50 ms
/// keeps labels to half of the 100 ms a store fsync is warned at, and to
/// 0.4 s of a frame. Chunks are cut to what this node's disk flushes in
/// it, so a fast disk keeps [`FLUSH_CHUNK_BYTES`] chunks (2026-11-07: a
/// node whose store fsyncs took about 1 s signed about half its
/// certificates).
const FLUSH_TARGET: Duration = Duration::from_millis(50);

/// The smallest chunk labels are cut to ([`Pace::chunk`]): below it a
/// push's own cost outweighs its bytes. A disk slower than this a
/// [`FLUSH_TARGET`] (20 MB/s) is paced by time instead ([`Pace::overran`]).
const FLUSH_MIN_CHUNK_BYTES: usize = 1 << 20;

/// Chunks are cut to a multiple of this, so a page is written once.
const FLUSH_CHUNK_ALIGN: usize = 64 << 10;

/// Pushes of labels a disk's speed is taken from ([`Pace`]): their median
/// ignores up to three slow ones, as behind a store's compaction.
const PACE_WINDOW: usize = 8;

/// Bytes of a kept layer read back at once, to resume a leaf's labelling
/// ([`Admitted::label_ahead`]).
const READ_CHUNK_BYTES: usize = 1 << 20;

/// How long writing a leaf's labels and building its column tree after its
/// last layer may take before it is logged ([`Admitted::label_until`]):
/// seconds on an idle node; a leaf of 32 million nodes wrote its column
/// digests and no commitment for over three minutes (2026-11-01).
const FINISH_LOGGED_FROM: Duration = Duration::from_secs(60);

/// Percent [`label_ahead_bytes`] adds to what labelling holds, for the
/// allocator: jemalloc rounds a large allocation up to its size class (it
/// counted 157.8 bytes a node allocated for 152.2 resident, 2026-11-01), and
/// keeps freed pages a while before it returns them, so a leaf labelled
/// again soon after it gave its memory back may still find them held.
const LABEL_AHEAD_MARGIN_PERCENT: u64 = 10;

/// Bytes labelling a leaf ahead reserves: bounded graph and column scratch,
/// the worker's layer buffers, allocator margin and the layer write buffer
/// ([`FLUSH_CHUNK_BYTES`]).
pub(crate) fn label_ahead_bytes(n: u64) -> u64 {
    let peak = quil_crypto::storage_proof::label_leaf_peak_bytes(n, &SdrParams::default());
    peak.saturating_add(peak / 100 * LABEL_AHEAD_MARGIN_PERCENT)
        .saturating_add(FLUSH_CHUNK_BYTES as u64)
}

/// Bytes a leaf's labels at `n` nodes take on disk: every layer, and a
/// column digest per node.
pub fn label_bytes(n: u64) -> u64 {
    n.saturating_mul(((SdrParams::default().layers + 1) * NODE_BYTES) as u64)
}

/// Reads the size and free space of the filesystem holding a path:
/// `statvfs` (`quil_forest::storage_health::fs_usage`), or a test's own.
pub type SpaceSource = Box<dyn Fn(&Path) -> Option<FsUsage> + Send + Sync>;

static STORE: OnceLock<LabelStore> = OnceLock::new();

/// The directory of the host ledger ([`crate::storage_jobs::install_host_ledger`])
/// of the node processes that keep labels in `labels_dir`: beside it, so a
/// process that keeps none (a cluster's master) can join it from the same
/// path.
pub fn host_ledger_dir(labels_dir: &Path) -> PathBuf {
    labels_dir.with_file_name("storage-admission")
}

/// Keep this process's labels under `dir`, checking their filesystem's free
/// space every [`FLOOR_CHECK_EVERY`] ([`LabelStore::keep_floor`]), and admit
/// its storage jobs with the node's other processes that label there
/// ([`crate::storage_jobs::install_host_ledger`], beside `dir`). The first
/// call decides; a process that never calls it labels nothing ahead and
/// relabels for its seals.
pub fn install(dir: PathBuf) {
    let scratch = dir.join("scratch");
    let ledger = host_ledger_dir(&dir);
    if STORE.set(LabelStore::new(dir)).is_err() {
        return;
    }
    quil_crypto::storage_proof::set_label_scratch_directory(scratch);
    crate::storage_jobs::install_host_ledger(&ledger);
    if let (Some(store), Some(ledger)) = (installed(), crate::storage_jobs::host_ledger()) {
        store.use_ledger(ledger);
    }
    let spawned = std::thread::Builder::new()
        .name("storage-labels-floor".into())
        .spawn(|| loop {
            if let Some(store) = installed() {
                store.keep_floor();
            }
            std::thread::sleep(FLOOR_CHECK_EVERY);
        });
    if let Err(error) = spawned {
        warn!(%error, scope = "local",
            "storage labels' free space check not started: labels kept are not released when \
             this node's disk runs short; a defect to report");
    }
}

/// [`install`], reading free space from `space`.
#[cfg(test)]
pub(crate) fn install_with_space(dir: PathBuf, space: SpaceSource) {
    let _ = STORE.set(LabelStore::with_space(dir, space));
}

/// A filesystem of 1 PiB, all of it free.
#[cfg(test)]
pub(crate) fn ample_space() -> SpaceSource {
    Box::new(|_| {
        Some(FsUsage {
            total_bytes: 1 << 50,
            free_bytes: 1 << 50,
            ..FsUsage::default()
        })
    })
}

/// The regular files under `dir`, at any depth.
#[cfg(test)]
pub(crate) fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

/// This process's label store, once installed.
pub fn installed() -> Option<&'static LabelStore> {
    STORE.get()
}

/// A failed read or write of the labels: a local disk error
/// (`QuilError::Io`), whose job is tried again less and less often while it
/// lasts (`crate::storage_snapshot::request`).
fn io(what: &str, path: &Path, error: std::io::Error) -> QuilError {
    QuilError::Io(std::io::Error::new(
        error.kind(),
        format!("storage labels: {what} {}: {error}", path.display()),
    ))
}

/// The directory under which the labels of every epoch from the stable
/// replica key epoch on are kept, in place of one per epoch.
pub const STABLE_DIR: &str = "stable";

/// The directory `epoch`'s labels are kept under: the epoch's own before the
/// stable replica key epoch, whose keys differ every epoch; [`STABLE_DIR`]
/// from it.
fn epoch_dir(epoch: u64) -> String {
    if quil_types::consensus::stable_replica_keys_at(epoch) {
        STABLE_DIR.to_string()
    } else {
        epoch.to_string()
    }
}

/// The lock of the leaf directory `dir`: held while a count's files are
/// removed and while its labels are opened.
fn leaf_lock(dir: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(dir.to_path_buf())
        .or_default()
        .clone()
}

/// A name part no other writer in this or another process uses.
fn unique_tag() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// The file of count `n` in a leaf's directory under [`STABLE_DIR`] naming
/// the latest epoch it was looked for or labelled for (`u64`, big-endian).
fn used_path(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("{n}.used"))
}

/// The epoch count `n` under `dir` was last used for.
fn used_epoch(dir: &Path, n: u64) -> Option<u64> {
    let bytes: [u8; 8] = fs::read(used_path(dir, n)).ok()?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Record that count `n` under `dir` was used for `epoch`. The caller holds
/// the leaf's lock.
fn write_used(dir: &Path, n: u64, epoch: u64) {
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let staged = dir.join(format!("{n}.used.{}.tmp", unique_tag()));
    if fs::write(&staged, epoch.to_be_bytes()).is_ok()
        && fs::rename(&staged, used_path(dir, n)).is_err()
    {
        let _ = fs::remove_file(staged);
    }
}

/// Note that count `n` under `dir` serves `epoch`, when `epoch` keeps its
/// labels under [`STABLE_DIR`] and no later epoch was noted. The caller
/// holds the leaf's lock.
fn note_used(dir: &Path, n: u64, epoch: u64) {
    if quil_types::consensus::stable_replica_keys_at(epoch)
        && used_epoch(dir, n).is_none_or(|used| used < epoch)
    {
        write_used(dir, n, epoch);
    }
}

/// Whether `file` is the file at `path` now: a release removes a count's
/// files under their lock ([`LabelStore::keep_floor`]), so a lock taken
/// after it is on a file gone from the directory.
#[cfg(unix)]
fn is_at(file: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), fs::metadata(path)) {
        (Ok(held), Ok(there)) => held.dev() == there.dev() && held.ino() == there.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn is_at(_file: &File, path: &Path) -> bool {
    path.exists()
}

/// A shared lock on the layers file at `path`, made first when `create`:
/// while it is held, by this process or another, a release passes the
/// count's labels by ([`LabelStore::keep_floor`]). Labelling a count and
/// opening its labels hold one. `None` when there is no such file and not
/// `create`, or when it cannot be locked.
fn hold_layers(path: &Path, create: bool) -> Option<File> {
    // A release between the open and the lock removed the file: made again.
    for _ in 0..8 {
        let file = if create {
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
        } else {
            File::open(path)
        }
        .ok()?;
        file.lock_shared().ok()?;
        if is_at(&file, path) {
            return Some(file);
        }
        if !create {
            return None;
        }
    }
    None
}

/// The file of count `n` in the leaf directory `dir` whose lock the
/// count's one labelling holds ([`claim`]).
fn writer_path(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("{n}.writer"))
}

/// Claim count `n` in the leaf directory `dir` for one labelling: an
/// exclusive lock on its writer file ([`writer_path`]), made first, held
/// until the file returned goes ([`end_claim`]). The node's worker processes
/// share the directory, and a lock is held by a file description, so a
/// second labelling of the count, in this process or another, finds it
/// held: `Ok(None)` then. An error when the directory cannot hold the file,
/// or it cannot be locked.
fn claim(dir: &Path, n: u64) -> std::io::Result<Option<File>> {
    let path = writer_path(dir, n);
    // A labelling that ended between the open and the lock removed the
    // file: made again.
    for _ in 0..8 {
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
        if is_at(&file, &path) {
            return Ok(Some(file));
        }
    }
    Ok(None)
}

/// Let go of the claim `writer` on count `n` in `dir` ([`claim`]), its
/// writer file removed first: nothing is left of it.
fn end_claim(dir: &Path, n: u64, writer: File) {
    let _ = fs::remove_file(writer_path(dir, n));
    drop(writer);
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// A release of labels for free space, from its first release until free
/// space is back at [`resume_free`] ([`LabelStore::keep_floor`]), kept in
/// [`SHORT_MARKER`] so that every process keeping labels in the directory
/// sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Shortage {
    /// When it began and was last logged, in Unix seconds.
    since: u64,
    logged: u64,
    /// Releases, the bytes and counts they released, and the epochs those
    /// labels were for.
    releases: u64,
    bytes: u64,
    counts: u64,
    epochs: Vec<u64>,
}

impl Shortage {
    fn epochs_text(&self) -> String {
        let epochs: Vec<String> = self.epochs.iter().map(u64::to_string).collect();
        epochs.join(",")
    }

    fn text(&self) -> String {
        format!(
            "since={} logged={} releases={} bytes={} counts={} epochs={}\n",
            self.since,
            self.logged,
            self.releases,
            self.bytes,
            self.counts,
            self.epochs_text()
        )
    }

    /// A marker that does not parse, cut short say, still marks a release.
    fn parse(text: &str) -> Self {
        let mut shortage = Self::default();
        for (key, value) in text
            .split_whitespace()
            .filter_map(|pair| pair.split_once('='))
        {
            let number = || value.parse::<u64>().unwrap_or(0);
            match key {
                "since" => shortage.since = number(),
                "logged" => shortage.logged = number(),
                "releases" => shortage.releases = number(),
                "bytes" => shortage.bytes = number(),
                "counts" => shortage.counts = number(),
                "epochs" => {
                    shortage.epochs = value.split(',').filter_map(|e| e.parse().ok()).collect()
                }
                _ => {}
            }
        }
        shortage
    }
}

/// A count's labels a release may take ([`LabelStore::keep_floor`]).
struct Candidate {
    dir: PathBuf,
    n: u64,
    /// The epoch they are needed for: their directory's, or under
    /// [`STABLE_DIR`] the latest one that looked for them (0 when none
    /// did).
    epoch: u64,
    /// Before the epoch of the last sweep ([`LabelStore::sweep`]): no seal
    /// needs them.
    stale: bool,
    bytes: u64,
}

/// What one check of the labels' free space released
/// ([`LabelStore::keep_floor`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Released {
    pub bytes: u64,
    pub counts: u64,
    /// Counts passed by because they are being labelled or read.
    pub in_use: u64,
    pub epochs: Vec<u64>,
}

/// Leaves' labels on disk: `<dir>/<epoch>/<leaf>/<n>.{layers,columns,ready}`
/// (`<dir>/stable/…` from the stable replica key epoch, [`epoch_dir`]),
/// `<leaf>` naming the member and the leaf. `layers` holds every layer in
/// order, `columns` every node's column digest, and `ready`, written last,
/// the column commitment. `kept`, beside the `layers` of a labelling not
/// ended, is the manifest of its whole layers ([`Manifest`]), rewritten
/// after each layer is synced.
#[derive(Clone)]
pub struct LabelStore {
    params: SdrParams,
    dir: PathBuf,
    space: Arc<dyn Fn(&Path) -> Option<FsUsage> + Send + Sync>,
    disk_floor: fn(u64) -> u64,
    /// Bytes the leaves being labelled have still to write.
    pending: Arc<Mutex<u64>>,
    /// The host's record of the node's processes ([`Self::use_ledger`]):
    /// what the others' labels have still to write is no room for these.
    ledger: Arc<OnceLock<&'static HostLedger>>,
    /// Whether a failure to use [`Self::ledger`] was logged.
    ledger_warned: Arc<AtomicBool>,
    /// Leaves' counts admitted and being labelled ([`Self::admit`]): no
    /// other labelling writes them, and nothing removes them meanwhile.
    busy: Arc<Mutex<HashSet<(PathBuf, u64)>>>,
    /// Leaves admitted with layers kept on disk, and from how many, for
    /// tests.
    #[cfg(test)]
    resumed: Arc<Mutex<Vec<(Vec<u8>, u64, usize)>>>,
    /// Leaves refused room, by epoch and stage, each logged once.
    refused: Arc<Mutex<HashSet<(u64, PathBuf, Stage)>>>,
    /// The epoch before which labels were last removed ([`Self::sweep`]).
    swept: Arc<AtomicU64>,
    /// The release of labels for free space this process last saw
    /// ([`Self::keep_floor`]).
    seen: Arc<Mutex<Option<Shortage>>>,
}

/// Room a leaf's labels were refused: the free bytes they needed, beside
/// the leaves being labelled and above the floor, and the free bytes there
/// were, if known.
#[derive(Debug, Clone, Copy)]
struct Shortfall {
    needed: u64,
    free: Option<u64>,
}

impl LabelStore {
    pub(crate) fn directory(&self) -> &Path {
        &self.dir
    }

    /// A GLOBAL-certified final-layer commitment no longer needs the temporary
    /// eleven-layer cache. Never remove files another proof is still reading.
    pub(crate) fn release_certified_sector(&self, epoch: u64, member: &[u8], sector: &[u8]) {
        let dir = self.leaf_dir(epoch, member, sector);
        let lock = leaf_lock(&dir);
        let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if self.busy().iter().any(|(path, _)| path == &dir) {
            return;
        }
        let mut guards = Vec::new();
        for n in counts_with(&dir, ".layers") {
            let Ok(file) = File::open(paths(&dir, n)[0].clone()) else {
                continue;
            };
            if file.try_lock().is_err() {
                return;
            }
            guards.push(file);
        }
        let _ = fs::remove_dir_all(dir);
    }
    pub fn new(dir: PathBuf) -> Self {
        Self::with_space(dir, Box::new(quil_forest::storage_health::fs_usage))
    }

    /// A store reading its filesystem's free space from `space`.
    pub fn with_space(dir: PathBuf, space: SpaceSource) -> Self {
        Self {
            dir,
            params: SdrParams::default(),
            space: Arc::from(space),
            disk_floor,
            pending: Arc::new(Mutex::new(0)),
            ledger: Arc::new(OnceLock::new()),
            ledger_warned: Arc::new(AtomicBool::new(false)),
            busy: Arc::new(Mutex::new(HashSet::new())),
            #[cfg(test)]
            resumed: Arc::new(Mutex::new(Vec::new())),
            refused: Arc::new(Mutex::new(HashSet::new())),
            swept: Arc::new(AtomicU64::new(0)),
            seen: Arc::new(Mutex::new(None)),
        }
    }

    /// Override this store's local free-space policy, for an isolated benchmark.
    /// Normal node stores use the production floor from [`Self::new`].
    pub fn with_disk_floor(mut self, floor: fn(u64) -> u64) -> Self {
        self.disk_floor = floor;
        self
    }

    /// Suite-specific view sharing disk reservations, busy locks and cache
    /// eviction state with the parent. Suites have disjoint parameter-bound
    /// label directories; switching a view cannot reinterpret stored labels.
    pub fn for_profile(&self, profile: quil_types::consensus::StorageSealProfile) -> Self {
        let mut view = self.clone();
        view.params = SdrParams::for_profile(profile);
        view
    }
    pub fn params(&self) -> &SdrParams {
        &self.params
    }
    fn label_bytes(&self, n: u64) -> u64 {
        n.saturating_mul(((self.params.layers + 1) * NODE_BYTES) as u64)
    }

    fn resume_free(&self, total_bytes: u64) -> u64 {
        let floor = (self.disk_floor)(total_bytes);
        floor.saturating_add(release_band(floor).saturating_mul(2))
    }

    /// Whether [`Self::admit`] could admit `member`'s leaf `leaf_id` for
    /// `epoch` at `least` nodes or more: false when its filesystem has no
    /// room for the labels of `least` nodes, logged as [`Self::admit`] logs a
    /// refusal. Checked before the leaf's data is read for its exact count,
    /// so a leaf refused room holds no memory for its read.
    pub fn may_admit(
        &self,
        epoch: u64,
        member: &[u8],
        leaf_id: &[u8],
        least: u64,
        stage: Stage,
    ) -> bool {
        let pending = self.pending();
        match self.admission(
            *pending,
            self.label_bytes(least).saturating_mul(DISK_MARGIN),
            stage,
        ) {
            Ok(()) => true,
            Err(shortfall) => {
                drop(pending);
                let dir = self.leaf_dir(epoch, member, leaf_id);
                self.refuse(epoch, &dir, leaf_id, least, stage, shortfall);
                false
            }
        }
    }

    fn pending(&self) -> MutexGuard<'_, u64> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count the labels still to write of the node's other processes on
    /// this host against this store's room, and this store's in their room
    /// (`crate::storage_ledger`): each process counting only its own, two
    /// could each admit a leaf the disk has room for above the floor, and
    /// write both. False when a ledger was in use already.
    pub(crate) fn use_ledger(&self, ledger: &'static HostLedger) -> bool {
        self.ledger.set(ledger).is_ok()
    }

    /// The bytes the node's other processes' labels have still to write
    /// ([`Self::use_ledger`]); none without a ledger.
    fn others_pending(&self) -> u64 {
        self.ledger
            .get()
            .map_or(0, |ledger| ledger.others_labels_pending())
    }

    /// Say in the host's record that this store's labels have `pending`
    /// bytes still to write ([`Self::use_ledger`]).
    fn publish_pending(&self, pending: u64) {
        let Some(ledger) = self.ledger.get() else {
            return;
        };
        if let Err(error) = ledger.publish_labels_pending(pending) {
            self.warn_ledger(ledger, &error.to_string());
        }
    }

    /// The host's turn to admit a leaf's labels ([`HostLedger::labels_turn`]),
    /// kept until this store's record counts it, so two processes never
    /// admit on the same free space; `None` without a ledger, or past
    /// [`LABELS_TURN_WAIT`] (another process stopped holding it), when this
    /// store admits as if alone.
    fn labels_turn(&self) -> Option<fs::File> {
        let ledger = self.ledger.get()?;
        match ledger.labels_turn(LABELS_TURN_WAIT) {
            Ok(Some(turn)) => Some(turn),
            Ok(None) => {
                self.warn_ledger(
                    ledger,
                    "another process of the node kept the turn past the bound",
                );
                None
            }
            Err(error) => {
                self.warn_ledger(ledger, &error.to_string());
                None
            }
        }
    }

    fn warn_ledger(&self, ledger: &HostLedger, error: &str) {
        if !self.ledger_warned.swap(true, Ordering::Relaxed) {
            warn!(dir = %ledger.dir().display(), error, scope = "this node",
                action = "check the free space and permissions of this directory, and for a stopped \
                          process of the node",
                "storage labels admitted without the node's other processes on this host: their \
                 leaves and this one's may together write past the disk floor; logged once");
        }
    }

    fn busy(&self) -> MutexGuard<'_, HashSet<(PathBuf, u64)>> {
        self.busy.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Leaves admitted with layers kept on disk ([`Self::admit`]): the leaf,
    /// its count and the layers resumed from.
    #[cfg(test)]
    pub(crate) fn resumed(&self) -> Vec<(Vec<u8>, u64, usize)> {
        self.resumed.lock().unwrap().clone()
    }

    /// Whether the labels' filesystem has room for `bytes` beside the
    /// `pending` bytes the leaves being labelled have still to write, above
    /// the floor. Free space that cannot be read leaves no room.
    fn room(&self, pending: u64, bytes: u64) -> std::result::Result<(), Shortfall> {
        self.room_from(pending, bytes, false)
    }

    /// [`Self::room`] for a leaf labelled at `stage`: labelling ahead also
    /// waits, while labels are released for free space, until it is back at
    /// [`resume_free`] ([`Self::keep_floor`]).
    fn admission(
        &self,
        pending: u64,
        bytes: u64,
        stage: Stage,
    ) -> std::result::Result<(), Shortfall> {
        let waits = stage == Stage::Ahead && self.shortage().is_some();
        self.room_from(pending, bytes, waits)
    }

    /// The size and free space of the labels' filesystem.
    fn usage(&self) -> Option<FsUsage> {
        // The directory is made at the first label: until then its nearest
        // existing parent is on the filesystem it will be on.
        self.dir.ancestors().find_map(|dir| (self.space)(dir))
    }

    /// [`Self::room`], and when `resuming` no less than [`resume_free`].
    fn room_from(
        &self,
        pending: u64,
        bytes: u64,
        resuming: bool,
    ) -> std::result::Result<(), Shortfall> {
        let usage = self.usage();
        let needed = pending
            .saturating_add(self.others_pending())
            .saturating_add(bytes);
        match usage {
            Some(usage) => {
                let mut needed = needed.saturating_add((self.disk_floor)(usage.total_bytes));
                if resuming {
                    needed = needed.max(self.resume_free(usage.total_bytes));
                }
                if usage.free_bytes >= needed {
                    Ok(())
                } else {
                    Err(Shortfall {
                        needed,
                        free: Some(usage.free_bytes),
                    })
                }
            }
            None => Err(Shortfall { needed, free: None }),
        }
    }

    /// Admit `member`'s leaf `leaf_id` for `epoch` at `n` nodes to be
    /// labelled and kept ([`Admitted::label_kept`]) when its filesystem has
    /// room: [`DISK_MARGIN`] times the [`label_bytes`] it has still to write.
    /// The whole layers an earlier attempt at that count kept, in this
    /// process or one before it, stay for this one to resume from
    /// ([`Admitted::resumes_from`]) as far as each matches its digest
    /// ([`verify_kept_with_params`]); whatever else an attempt left is removed first.
    /// `None` when refused, leaving none of its files, logged once a leaf,
    /// epoch and stage: the leaf is then labelled where it is needed, as by
    /// a process that keeps no labels. `None` too while that count is being
    /// labelled: silently in this process, with a line when in another
    /// ([`claim`]).
    pub fn admit(
        &self,
        epoch: u64,
        member: &[u8],
        leaf_id: &[u8],
        n: u64,
        stage: Stage,
    ) -> Option<Admitted<'_>> {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        if !self.busy().insert((dir.clone(), n)) {
            return None;
        }
        // Held to the labelling's end. A directory that cannot hold the
        // writer file fails the labelling as a disk error
        // ([`Admitted::label_kept`]).
        let _ = fs::create_dir_all(&dir);
        let writer = match claim(&dir, n) {
            Ok(Some(writer)) => Some(writer),
            Ok(None) => {
                self.busy().remove(&(dir.clone(), n));
                info!(epoch, leaf = %hex::encode(leaf_id), nodes = n, stage = stage.name(),
                    scope = "local",
                    "storage labels not computed here: another worker process of this node is \
                     labelling the leaf at that count; its labels serve this node once complete, \
                     and meanwhile the leaf is labelled where it is needed, as without labels \
                     kept");
                return None;
            }
            Err(_) => None,
        };
        let key = quil_crypto::sdr::replica_key(member, leaf_id, epoch);
        let [layers, columns, ready] = paths(&dir, n);
        // Held until the leaf is labelled or dropped: a release in another
        // process passes its layers by ([`Self::keep_floor`]). One that
        // removed them first leaves none to resume from.
        let mut in_use = hold_layers(&layers, false);
        // Not under the leaf's lock: checking a large leaf's layers takes a
        // while, and being busy keeps every removal off them. What a sweep
        // that looked before this count was busy removes is seen below.
        let mut verified = verify_kept_with_params(&dir, n, &key, &self.params);
        if in_use.is_none() {
            verified.layers.clear();
        }
        let lock = leaf_lock(&dir);
        let held = lock.lock().unwrap_or_else(PoisonError::into_inner);
        for path in [
            columns,
            ready,
            staged(&dir, n),
            manifest_staged(&dir, n),
            dir.join(format!("{n}.cap")),
        ] {
            let _ = fs::remove_file(path);
        }
        let whole = verified.layers.len() as u64 * layer_bytes(n);
        let cut = whole > 0
            && fs::OpenOptions::new()
                .write(true)
                .open(&layers)
                .and_then(|file| file.set_len(whole))
                .is_ok();
        if !cut {
            verified.layers.clear();
            let _ = fs::remove_file(&layers);
            let _ = fs::remove_file(kept_path(&dir, n));
            // Made again when the leaf is written.
            in_use = None;
        }
        log_verified(epoch, leaf_id, n, stage, &verified);
        let kept = verified.layers.len();
        #[cfg(test)]
        {
            if kept > 0 {
                self.resumed
                    .lock()
                    .unwrap()
                    .push((leaf_id.to_vec(), n, kept));
            }
        }
        let bytes = self
            .label_bytes(n)
            .saturating_sub(kept as u64 * layer_bytes(n));
        // Held until this store's record counts the leaf; taken first, so
        // this process's labels being written need not wait for it.
        let turn = self.labels_turn();
        let mut pending = self.pending();
        match self.admission(*pending, bytes.saturating_mul(DISK_MARGIN), stage) {
            Ok(()) => {
                *pending = pending.saturating_add(bytes);
                self.publish_pending(*pending);
                drop(turn);
                note_used(&dir, n, epoch);
                drop(held);
                Some(Admitted {
                    store: self,
                    dir,
                    epoch,
                    member: member.to_vec(),
                    leaf_id: leaf_id.to_vec(),
                    n,
                    stage,
                    kept,
                    resumed: (kept > 0).then(|| Resumed {
                        layers: kept,
                        bytes: verified.bytes,
                        took: verified.took,
                        kept_by: verified.kept_by.unwrap_or(stage),
                    }),
                    digests: verified.layers,
                    remaining: bytes,
                    in_use,
                    writer,
                })
            }
            Err(shortfall) => {
                drop((turn, pending));
                let _ = fs::remove_file(&layers);
                let _ = fs::remove_file(kept_path(&dir, n));
                if let Some(writer) = writer {
                    end_claim(&dir, n, writer);
                }
                self.busy().remove(&(dir.clone(), n));
                self.refuse(epoch, &dir, leaf_id, n, stage, shortfall);
                None
            }
        }
    }

    /// The count at which `member`'s leaf `leaf_id` for `epoch` has the most
    /// whole layers kept on disk, among those `accept` takes, and how many
    /// its manifest lists ([`Self::admit`] checks them); none when no such
    /// count has any. A count whose labels are complete ([`Self::find`]) or
    /// being labelled is not one.
    pub fn resumable(
        &self,
        epoch: u64,
        member: &[u8],
        leaf_id: &[u8],
        accept: impl Fn(u64) -> bool,
    ) -> Option<(u64, usize)> {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        let counts = counts_with(&dir, ".kept");
        let busy = self.busy();
        counts
            .into_iter()
            .filter(|&n| accept(n) && !busy.contains(&(dir.clone(), n)))
            .filter(|&n| !paths(&dir, n)[2].exists())
            .filter_map(|n| {
                let text = fs::read_to_string(kept_path(&dir, n)).ok()?;
                let layers = Manifest::parse(&text)?.layers.len();
                (layers > 0).then_some((n, layers))
            })
            .max_by_key(|&(n, layers)| (layers, std::cmp::Reverse(n)))
    }

    /// Remove what an attempt at labelling `member`'s leaf `leaf_id` for
    /// `epoch` at `n` nodes left, kept layers included: nothing goes on from
    /// them. Labels complete at that count, or being labelled, in this
    /// process or another ([`claim`]), stay. Nothing
    /// from the stable replica key epoch on, where a later epoch goes on from
    /// them: only [`Self::sweep`] removes those.
    pub fn discard(&self, epoch: u64, member: &[u8], leaf_id: &[u8], n: u64) {
        if quil_types::consensus::stable_replica_keys_at(epoch) {
            return;
        }
        let dir = self.leaf_dir(epoch, member, leaf_id);
        let lock = leaf_lock(&dir);
        let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let busy = self.busy();
        if busy.contains(&(dir.clone(), n)) || paths(&dir, n)[2].exists() {
            return;
        }
        let writer = match claim(&dir, n) {
            Ok(None) => return,
            Ok(Some(writer)) => Some(writer),
            Err(_) => None,
        };
        for path in paths(&dir, n).into_iter().chain([
            staged(&dir, n),
            kept_path(&dir, n),
            manifest_staged(&dir, n),
            dir.join(format!("{n}.cap")),
        ]) {
            let _ = fs::remove_file(path);
        }
        if let Some(writer) = writer {
            end_claim(&dir, n, writer);
        }
    }

    /// [`Self::discard`] the layers kept for `member`'s leaf `leaf_id` for
    /// `epoch` at every count but `n`, which its snapshot encoded it at.
    pub fn discard_others(&self, epoch: u64, member: &[u8], leaf_id: &[u8], n: u64) {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        for count in counts_with(&dir, ".layers") {
            if count != n {
                self.discard(epoch, member, leaf_id, count);
            }
        }
    }

    /// Remove the labels kept for `member`'s leaf `leaf_id` for `epoch` at
    /// `n` nodes that do not match their column commitment
    /// ([`Kept::verified_last_layer`]), complete or not, and from the stable
    /// replica key epoch on too: no epoch registers from them, nor seals
    /// from them. Left while the count is being labelled, in this process or
    /// another ([`claim`]): its labelling removes them first.
    pub fn discard_damaged(&self, epoch: u64, member: &[u8], leaf_id: &[u8], n: u64) {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        let lock = leaf_lock(&dir);
        let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
        // Held throughout, as by a discard: this process admits no labelling
        // of the count meanwhile.
        let busy = self.busy();
        if busy.contains(&(dir.clone(), n)) {
            return;
        }
        let writer = match claim(&dir, n) {
            Ok(None) => return,
            Ok(Some(writer)) => Some(writer),
            Err(_) => None,
        };
        let [layers, columns, ready] = paths(&dir, n);
        // `ready` first: nothing finds the count once it is gone.
        for path in [ready, layers, columns, kept_path(&dir, n)] {
            let _ = fs::remove_file(path);
        }
        if let Some(writer) = writer {
            end_claim(&dir, n, writer);
        }
    }

    /// Log, once a leaf, epoch and stage, that this node keeps no labels for
    /// it.
    fn refuse(
        &self,
        epoch: u64,
        dir: &Path,
        leaf_id: &[u8],
        n: u64,
        stage: Stage,
        shortfall: Shortfall,
    ) {
        let first = self
            .refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((epoch, dir.to_path_buf(), stage));
        if !first {
            return;
        }
        let (leaf, bytes) = (hex::encode(leaf_id), self.label_bytes(n));
        let free = shortfall
            .free
            .map_or_else(|| "unknown".to_string(), |free| free.to_string());
        match stage {
            Stage::Ahead => info!(epoch, leaf = %leaf, label_bytes = bytes,
                needed_bytes = shortfall.needed, free_bytes = %free,
                "storage labels not computed ahead: too little free disk space on this node; \
                 the leaf's snapshot labels it instead (about an hour per GiB on a core), and a \
                 snapshot not encoded within the renewal's grace renews without a registration, \
                 so the seat's frames that epoch forgo their storage reward"),
            Stage::Snapshot => info!(epoch, leaf = %leaf, label_bytes = bytes,
                needed_bytes = shortfall.needed, free_bytes = %free,
                "storage labels not kept at the snapshot: too little free disk space on this \
                 node; the leaf's seal labels it again, as without labels kept"),
        }
    }

    /// The directory of `member`'s leaf `leaf_id` for `epoch`. Under
    /// [`STABLE_DIR`] its name also hashes the leaf's replica key and the
    /// labelling's parameters, so labels a later key or parameters would
    /// not reproduce are never found.
    fn leaf_dir(&self, epoch: u64, member: &[u8], leaf_id: &[u8]) -> PathBuf {
        use sha3::Digest as _;
        let mut h = sha3::Sha3_256::new();
        h.update((member.len() as u32).to_be_bytes());
        h.update(member);
        h.update(leaf_id);
        if quil_types::consensus::stable_replica_keys_at(epoch) {
            let params = &self.params;
            h.update(quil_crypto::sdr::replica_key(member, leaf_id, epoch));
            for value in [
                params.layers,
                params.drg_degree,
                params.expander_degree,
                params.node_bytes,
            ] {
                h.update((value as u32).to_be_bytes());
            }
        }
        self.dir
            .join(epoch_dir(epoch))
            .join(hex::encode(h.finalize()))
    }

    /// Whether `member`'s leaf `leaf_id` has labels of any count kept for
    /// `epoch`. Unlike [`Self::find`], it notes no use.
    pub fn holds(&self, epoch: u64, member: &[u8], leaf_id: &[u8]) -> bool {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_suffix(".ready"))
                    .is_some_and(|n| n.parse::<u64>().is_ok())
            })
    }

    /// The labels kept for `member`'s leaf `leaf_id` for `epoch` at a node
    /// count `accept` takes, if any, noting that count's use for `epoch`.
    /// Its files are opened here, so labels removed after it are still read.
    pub fn find(
        &self,
        epoch: u64,
        member: &[u8],
        leaf_id: &[u8],
        accept: impl Fn(u64) -> bool,
    ) -> Option<Kept> {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        let lock = leaf_lock(&dir);
        let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut counts: Vec<u64> = fs::read_dir(&dir)
            .ok()?
            .filter_map(|entry| {
                let name = entry.ok()?.file_name().into_string().ok()?;
                name.strip_suffix(".ready")?.parse().ok()
            })
            .filter(|&n| accept(n))
            .collect();
        counts.sort_unstable();
        let n = *counts.first()?;
        let [layers, columns, ready] = paths(&dir, n);
        let comm_c: Node = fs::read(ready).ok()?.try_into().ok()?;
        let layers_file = File::open(&layers).ok()?;
        // Held while they are read: a release passes them by.
        layers_file.lock_shared().ok()?;
        if !is_at(&layers_file, &layers) {
            return None;
        }
        let expected = n * (self.params.layers * NODE_BYTES) as u64;
        if layers_file.metadata().ok()?.len() != expected {
            return None;
        }
        let columns_file = File::open(&columns).ok()?;
        if columns_file.metadata().ok()?.len() != n * NODE_BYTES as u64 {
            return None;
        }
        note_used(&dir, n, epoch);
        Some(Kept {
            n,
            comm_c,
            layers: Mutex::new(layers_file),
            columns: Mutex::new(columns_file),
            column_cap: fs::read(dir.join(format!("{n}.cap")))
                .ok()
                .and_then(|bytes| quil_crypto::storage_proof::MerkleCap::from_bytes(&bytes)),
            replica: None,
            depth: self.params.layers,
        })
    }

    /// Remove the labels kept for `member`'s leaf `leaf_id` for `epoch`: its
    /// registration is sealed, and nothing opens them again. Nothing from
    /// the stable replica key epoch on, where the same labels serve the
    /// later epochs: only [`Self::sweep`] removes those.
    pub fn forget(&self, epoch: u64, member: &[u8], leaf_id: &[u8]) {
        if quil_types::consensus::stable_replica_keys_at(epoch) {
            return;
        }
        let dir = self.leaf_dir(epoch, member, leaf_id);
        let lock = leaf_lock(&dir);
        let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if dir.exists() {
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// Remove the labels of epochs before `current`, once an epoch: their
    /// registrations were sealed before they began. Labels a crash, a
    /// restart or a lost seat left behind go with them. Under
    /// [`STABLE_DIR`], each count goes once nothing looked for it or
    /// labelled it for `current` or a later epoch ([`Self::sweep_stable`]).
    pub fn sweep(&self, current: u64) {
        if self.swept.fetch_max(current, Ordering::Relaxed) < current {
            self.evict_before(current);
            self.sweep_stable(current);
        }
    }

    /// The part of [`Self::sweep`] under [`STABLE_DIR`]: each count whose
    /// latest use is an epoch before `current` goes, every file of it (its
    /// registrations were sealed before `current` began), unless this process
    /// is labelling it. A count with no record of use, which a crash may
    /// leave, is kept for one more epoch. A leaf left with no file goes too.
    fn sweep_stable(&self, current: u64) {
        let Ok(leaves) = fs::read_dir(self.dir.join(STABLE_DIR)) else {
            return;
        };
        let (mut counts_removed, mut leaves_removed) = (0u64, 0u64);
        for leaf in leaves.flatten() {
            let dir = leaf.path();
            if !dir.is_dir() {
                continue;
            }
            let lock = leaf_lock(&dir);
            let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
            let mut files: HashMap<u64, Vec<PathBuf>> = HashMap::new();
            for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
                let count = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.split('.').next()?.parse::<u64>().ok());
                if let Some(n) = count {
                    files.entry(n).or_default().push(entry.path());
                }
            }
            for (n, paths) in files {
                if self.busy().contains(&(dir.clone(), n)) {
                    continue;
                }
                match used_epoch(&dir, n) {
                    None => write_used(&dir, n, current),
                    Some(used) if used < current => {
                        for path in paths {
                            let _ = fs::remove_file(path);
                        }
                        counts_removed += 1;
                    }
                    Some(_) => {}
                }
            }
            if fs::read_dir(&dir).is_ok_and(|mut entries| entries.next().is_none())
                && fs::remove_dir(&dir).is_ok()
            {
                leaves_removed += 1;
            }
        }
        if counts_removed > 0 {
            info!(
                epoch = current,
                counts_removed,
                leaves_removed,
                "storage labels kept across epochs removed: no registration, seal or labelling \
                 ahead looked for them this epoch or later; an expected cleanup"
            );
        }
    }

    /// Release labels kept while free space on their filesystem is below
    /// the floor ([`disk_floor`]): they are a cache, and the node's stores
    /// and logs beside them must not fail for them. Every count no
    /// labelling or seal of this process or another holds ([`hold_layers`])
    /// may go, until free space is [`release_band`] above the floor: those
    /// of epochs already swept first, then the latest needed, the smallest
    /// first within an epoch. A seal opens its labels within the hour after
    /// its snapshot, too soon to label a large leaf again, while labels for
    /// a later epoch may be labelled ahead again before their snapshot; and
    /// small leaves are labelled again at their snapshot within the
    /// renewal's grace, where large ones may not be. From the first release
    /// until free space is back at [`resume_free`], labelling ahead waits
    /// ([`Self::admit`]) and the episode is logged once, again every
    /// [`SHORT_LOGGED_EVERY`] while it goes on, and at its end, after which
    /// the shards whose labels went are labelled ahead again. One process
    /// releases at a time. What a check released; `None` when free space is
    /// above the floor or unknown, or another process is releasing.
    pub fn keep_floor(&self) -> Option<Released> {
        let usage = self.usage()?;
        let floor = (self.disk_floor)(usage.total_bytes);
        let marked = self.shortage();
        self.saw(marked.as_ref());
        if usage.free_bytes >= floor {
            if marked.is_some() && usage.free_bytes >= self.resume_free(usage.total_bytes) {
                self.end_shortage();
            } else if marked.is_some_and(|marked| {
                unix_now().saturating_sub(marked.logged) >= SHORT_LOGGED_EVERY.as_secs()
            }) {
                self.log_waiting(&usage);
            }
            return None;
        }
        let dir = File::open(&self.dir).ok()?;
        dir.try_lock().ok()?;
        // What another process released meanwhile counts.
        let usage = self.usage()?;
        if usage.free_bytes >= floor {
            return None;
        }
        let target = floor.saturating_add(release_band(floor));
        let released = self.release(usage.free_bytes, target);
        let now = unix_now();
        let marked = self.shortage();
        let first = marked.is_none();
        let mut shortage = marked.unwrap_or(Shortage {
            since: now,
            ..Shortage::default()
        });
        if released.counts > 0 {
            shortage.releases += 1;
        }
        shortage.bytes = shortage.bytes.saturating_add(released.bytes);
        shortage.counts = shortage.counts.saturating_add(released.counts);
        shortage.epochs.extend(&released.epochs);
        shortage.epochs.sort_unstable();
        shortage.epochs.dedup();
        let log = first || now.saturating_sub(shortage.logged) >= SHORT_LOGGED_EVERY.as_secs();
        if log {
            shortage.logged = now;
        }
        self.mark_shortage(&shortage);
        self.saw(Some(&shortage));
        drop(dir);
        if !log {
            return Some(released);
        }
        let free_after = self
            .usage()
            .map_or(usage.free_bytes, |usage| usage.free_bytes);
        let resume = self.resume_free(usage.total_bytes);
        if first {
            warn!(free_bytes = usage.free_bytes, floor_bytes = floor, free_after_bytes = free_after,
                released_bytes = released.bytes, released_counts = released.counts,
                in_use_counts = released.in_use, epochs = %shortage.epochs_text(),
                resume_bytes = resume, scope = "local",
                "storage labels kept ahead released: free disk space on this node fell below the \
                 labels' floor, and the node's stores and logs come first; the snapshots and seals \
                 of those leaves label them again when needed (about an hour per GiB on a core; a \
                 leaf not labelled in time leaves its seat without that epoch's registration), and \
                 labelling ahead waits until free space is back at resume_bytes; check what fills \
                 this node's disk (worker stores, logs, other files)");
        } else {
            log_still(&usage, free_after, &released, &shortage, now, floor);
        }
        Some(released)
    }

    /// Log again, once [`SHORT_LOGGED_EVERY`] passed, a release of labels
    /// for free space that goes on with free space above the floor and below
    /// [`resume_free`]: labelling ahead still waits.
    fn log_waiting(&self, usage: &FsUsage) {
        let Ok(dir) = File::open(&self.dir) else {
            return;
        };
        if dir.try_lock().is_err() {
            return;
        }
        let now = unix_now();
        let Some(mut shortage) = self.shortage() else {
            return;
        };
        if now.saturating_sub(shortage.logged) < SHORT_LOGGED_EVERY.as_secs() {
            return;
        }
        shortage.logged = now;
        self.mark_shortage(&shortage);
        drop(dir);
        log_still(
            usage,
            usage.free_bytes,
            &Released::default(),
            &shortage,
            now,
            (self.disk_floor)(usage.total_bytes),
        );
    }

    /// Release the counts [`Self::keep_floor`] may take, in its order, until
    /// `free` and what they held reach `target`.
    fn release(&self, free: u64, target: u64) -> Released {
        let mut released = Released::default();
        let mut free = free;
        for candidate in self.candidates() {
            if free >= target {
                break;
            }
            let lock = leaf_lock(&candidate.dir);
            let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
            if self.busy().contains(&(candidate.dir.clone(), candidate.n)) {
                released.in_use += 1;
                continue;
            }
            let layers = paths(&candidate.dir, candidate.n)[0].clone();
            // Locked against the labellings and seals that hold them, in this
            // process or another, while they go.
            let _exclusive = match File::open(&layers) {
                Ok(file) => match file.try_lock() {
                    Ok(()) if is_at(&file, &layers) => Some(file),
                    _ => {
                        released.in_use += 1;
                        continue;
                    }
                },
                Err(_) => None,
            };
            let mut bytes = 0u64;
            for path in count_files(&candidate.dir, candidate.n) {
                let len = fs::metadata(&path).map_or(0, |meta| meta.len());
                if fs::remove_file(&path).is_ok() {
                    bytes = bytes.saturating_add(len);
                }
            }
            free = free.saturating_add(bytes);
            released.bytes = released.bytes.saturating_add(bytes);
            released.counts += 1;
            if !released.epochs.contains(&candidate.epoch) {
                released.epochs.push(candidate.epoch);
            }
        }
        released.epochs.sort_unstable();
        released
    }

    /// Every count with labels on disk, in the order [`Self::keep_floor`]
    /// releases them.
    fn candidates(&self) -> Vec<Candidate> {
        let swept = self.swept.load(Ordering::Relaxed);
        let mut candidates = Vec::new();
        for entry in fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let epoch = match name.parse::<u64>() {
                Ok(epoch) => Some(epoch),
                Err(_) if name == STABLE_DIR => None,
                Err(_) => continue,
            };
            for leaf in fs::read_dir(entry.path()).into_iter().flatten().flatten() {
                let dir = leaf.path();
                if !dir.is_dir() {
                    continue;
                }
                let mut counts: HashMap<u64, (u64, bool)> = HashMap::new();
                for file in fs::read_dir(&dir).into_iter().flatten().flatten() {
                    let name = file.file_name();
                    let Some(name) = name.to_str() else {
                        continue;
                    };
                    let Some(n) = name.split('.').next().and_then(|n| n.parse::<u64>().ok()) else {
                        continue;
                    };
                    let count = counts.entry(n).or_default();
                    count.0 = count
                        .0
                        .saturating_add(file.metadata().map_or(0, |meta| meta.len()));
                    count.1 |= name.ends_with(".layers") || name.ends_with(".columns");
                }
                for (n, (bytes, labels)) in counts {
                    if !labels {
                        continue;
                    }
                    let epoch = epoch.unwrap_or_else(|| used_epoch(&dir, n).unwrap_or(0));
                    candidates.push(Candidate {
                        dir: dir.clone(),
                        n,
                        epoch,
                        stale: epoch < swept,
                        bytes,
                    });
                }
            }
        }
        candidates.sort_by(|a, b| {
            b.stale
                .cmp(&a.stale)
                .then(b.epoch.cmp(&a.epoch))
                .then(a.bytes.cmp(&b.bytes))
                .then(a.dir.cmp(&b.dir))
                .then(a.n.cmp(&b.n))
        });
        candidates
    }

    /// The release of labels for free space going on, if any
    /// ([`SHORT_MARKER`]).
    fn shortage(&self) -> Option<Shortage> {
        let text = fs::read_to_string(self.dir.join(SHORT_MARKER)).ok()?;
        Some(Shortage::parse(&text))
    }

    fn mark_shortage(&self, shortage: &Shortage) {
        let staged = self
            .dir
            .join(format!("{SHORT_MARKER}.{}.tmp", unique_tag()));
        if fs::write(&staged, shortage.text()).is_err()
            || fs::rename(&staged, self.dir.join(SHORT_MARKER)).is_err()
        {
            let _ = fs::remove_file(staged);
        }
    }

    /// End the release of labels for free space: free space is back at
    /// [`resume_free`].
    fn end_shortage(&self) {
        let Ok(dir) = File::open(&self.dir) else {
            return;
        };
        if dir.try_lock().is_err() {
            return;
        }
        let Some(shortage) = self.shortage() else {
            return;
        };
        if fs::remove_file(self.dir.join(SHORT_MARKER)).is_err() {
            return;
        }
        drop(dir);
        let usage = self.usage().unwrap_or_default();
        info!(free_bytes = usage.free_bytes, resume_bytes = self.resume_free(usage.total_bytes),
            released_bytes = shortage.bytes, released_counts = shortage.counts,
            releases = shortage.releases, epochs = %shortage.epochs_text(),
            episode_seconds = unix_now().saturating_sub(shortage.since), scope = "local",
            "storage labels released for free disk space no more: free space on this node is \
             back at resume_bytes; labelling ahead resumes, and the shards whose labels were \
             released are labelled ahead again while their snapshot is still to come");
        self.saw(Some(&shortage));
        self.saw(None);
    }

    /// Note the release of labels for free space this check saw: once one
    /// this process saw has ended, the shards it labelled ahead for its
    /// epochs are labelled ahead again ([`precomputed`]).
    fn saw(&self, shortage: Option<&Shortage>) {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        match shortage {
            Some(shortage) => *seen = Some(shortage.clone()),
            None => {
                if let Some(ended) = seen.take() {
                    precomputed_set().retain(|(_, _, epoch), _| !ended.epochs.contains(epoch));
                }
            }
        }
    }

    /// Remove the labels of every epoch before `epoch`.
    pub fn evict_before(&self, epoch: u64) {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(e, _, _)| *e >= epoch);
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let older = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u64>().ok())
                .is_some_and(|e| e < epoch);
            if older {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

/// When a leaf is labelled: ahead of its snapshot, or at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Ahead,
    Snapshot,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ahead => "ahead",
            Self::Snapshot => "snapshot",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [Self::Ahead, Self::Snapshot]
            .into_iter()
            .find(|stage| stage.name() == name)
    }
}

/// The whole layers kept on disk a leaf's labelling goes on from
/// ([`Admitted::resumed`]).
#[derive(Debug, Clone, Copy)]
pub struct Resumed {
    pub layers: usize,
    /// Bytes read to check them against their digests, and how long it
    /// took.
    pub bytes: u64,
    pub took: Duration,
    /// When they were labelled.
    pub kept_by: Stage,
}

/// A leaf admitted to be labelled and kept ([`LabelStore::admit`]): what it
/// has still to write counts against its filesystem's room until it is
/// labelled or dropped.
pub struct Admitted<'a> {
    store: &'a LabelStore,
    dir: PathBuf,
    epoch: u64,
    member: Vec<u8>,
    leaf_id: Vec<u8>,
    n: u64,
    stage: Stage,
    /// Whole layers an earlier attempt kept, resumed from.
    kept: usize,
    /// Those layers' digests.
    digests: Vec<[u8; 32]>,
    resumed: Option<Resumed>,
    remaining: u64,
    /// The shared lock on the leaf's layers file ([`hold_layers`]), once it
    /// exists.
    in_use: Option<File>,
    /// The lock of the count's one labelling ([`claim`]), once taken.
    writer: Option<File>,
}

/// How labelling an admitted leaf ahead ended ([`Admitted::label_ahead`]).
pub enum Labelling {
    /// To its end.
    Labelled(Labelled),
    /// Given up when told to, keeping its first `layers` whole layers on
    /// disk (none when it labelled none, or ran out of room) for the next
    /// attempt at its count to resume from, in this process or the next,
    /// unless its caller discards them ([`LabelStore::discard`]).
    Stopped { layers: usize },
    /// Labelling ahead ran out of room before its last layer: stopped at
    /// the layer the room ran out after, none of its files kept, the refusal
    /// logged as [`LabelStore::admit`] logs one. Its labels would not be
    /// kept, and the snapshot labels the leaf again.
    Refused,
}

/// A labelled leaf ([`Admitted::label`]): its column commitment and last
/// layer, and whether its layers are kept for its seal.
pub struct Labelled {
    pub comm_c: Node,
    pub last: Vec<Digest>,
    pub kept: bool,
}

impl Admitted<'_> {
    /// Whether the filesystem still has room for what this leaf and the
    /// others being labelled have still to write.
    fn room(&self) -> std::result::Result<(), Shortfall> {
        let pending = self.store.pending();
        self.store.room(*pending, 0)
    }

    /// `bytes` of this leaf's are written: they count as free space no more.
    fn wrote(&mut self, bytes: u64) {
        let bytes = bytes.min(self.remaining);
        self.remaining -= bytes;
        let mut pending = self.store.pending();
        *pending = pending.saturating_sub(bytes);
        self.store.publish_pending(*pending);
    }

    /// [`Self::label_until`], never given up.
    #[cfg(test)]
    pub(crate) fn label(self, params: &SdrParams) -> Result<Labelled> {
        self.label_until(params, &|| false)?
            .ok_or_else(|| QuilError::Internal("labelling that never stops stopped".into()))
    }

    /// Whole layers an earlier attempt at the leaf's count kept, which its
    /// labelling resumes from ([`LabelStore::admit`]).
    pub fn resumes_from(&self) -> usize {
        self.kept
    }

    /// The whole layers kept on disk the labelling goes on from, if any,
    /// and what checking them took.
    pub fn resumed(&self) -> Option<Resumed> {
        self.resumed
    }

    /// [`Self::label_kept`], `None` when given up.
    #[cfg(test)]
    pub(crate) fn label_until(
        self,
        params: &SdrParams,
        stop: &dyn Fn() -> bool,
    ) -> Result<Option<Labelled>> {
        Ok(match self.label_kept(params, stop, &|_| {})? {
            Labelling::Labelled(labelled) => Some(labelled),
            Labelling::Stopped { .. } | Labelling::Refused => None,
        })
    }

    /// Label the leaf at its count, going on from the whole layers an
    /// earlier attempt kept ([`Self::resumes_from`]), and keep its layers
    /// while the filesystem has room for them, checked before each layer and
    /// the columns are written: each whole layer is synced and listed in the
    /// leaf's manifest as it ends. A leaf that runs out of room is not kept:
    /// its files are removed and the refusal logged as [`LabelStore::admit`]
    /// logs one. Labelled at its snapshot, it is labelled to the end, for its
    /// caller to encode from; labelled ahead, it stops there
    /// ([`Labelling::Refused`]): no layer after it is of use. A write that
    /// fails stops the labelling at its layer, a disk error
    /// (`QuilError::Io`): no layer after it is of use. Given up once `stop`
    /// says so (`quil_crypto::storage_proof::label_leaf_until`), it keeps its
    /// whole layers for the next attempt at its count, unless it ran out of
    /// room.
    /// `layers` hears each layer's end with the layers labelled so far.
    pub fn label_kept(
        mut self,
        params: &SdrParams,
        stop: &dyn Fn() -> bool,
        layers: &dyn Fn(usize),
    ) -> Result<Labelling> {
        let paths = paths(&self.dir, self.n);
        let tally = FlushTally::default();
        let result = quil_crypto::storage_proof::with_label_memory_budget(
            quil_crypto::storage_proof::label_scratch_memory_bytes(self.n, params),
            || self.write(params, &paths, stop, layers, &tally),
        );
        tally.log(self.epoch, &self.leaf_id, self.n, self.stage);
        let keep = match &result {
            Ok(Labelling::Labelled(labelled)) => labelled.kept,
            Ok(Labelling::Stopped { layers }) => *layers > 0,
            Ok(Labelling::Refused) | Err(_) => false,
        };
        // Only under the count's claim: without it, they may be another
        // labelling's.
        if !keep && self.writer.is_some() {
            let [layers, columns, _] = &paths;
            let _ = fs::remove_file(layers);
            let _ = fs::remove_file(columns);
            let _ = fs::remove_file(staged(&self.dir, self.n));
            let _ = fs::remove_file(kept_path(&self.dir, self.n));
            let _ = fs::remove_file(manifest_staged(&self.dir, self.n));
            let _ = fs::remove_file(self.dir.join(format!("{}.cap", self.n)));
        }
        result
    }

    fn write(
        &mut self,
        params: &SdrParams,
        paths: &[PathBuf; 3],
        stop: &dyn Fn() -> bool,
        on_layers: &dyn Fn(usize),
        tally: &FlushTally,
    ) -> Result<Labelling> {
        let [layers_path, columns_path, ready_path] = paths;
        fs::create_dir_all(&self.dir).map_err(|e| io("create", &self.dir, e))?;
        if self.writer.is_none() {
            let path = writer_path(&self.dir, self.n);
            match claim(&self.dir, self.n) {
                Ok(Some(writer)) => self.writer = Some(writer),
                Ok(None) => {
                    return Err(QuilError::Internal(format!(
                        "storage labels: {} is held by another labelling",
                        path.display()
                    )))
                }
                Err(error) => return Err(io("lock", &path, error)),
            }
        }
        let (kept, layer_size) = (self.kept, layer_bytes(self.n));
        let key = quil_crypto::sdr::replica_key(&self.member, &self.leaf_id, self.epoch);
        let mut manifest = Manifest {
            n: self.n,
            params: params_text(params),
            key: hex::encode(key),
            stage: self.stage,
            layers: std::mem::take(&mut self.digests),
        };
        // The kept layers were checked against this store view's suite.
        if kept > 0 && manifest.params != params_text(params) {
            return Err(QuilError::Internal(
                "storage labels: layers kept for other labelling parameters".into(),
            ));
        }
        let (dir, n) = (self.dir.clone(), self.n);
        if self.in_use.is_none() {
            self.in_use = Some(hold_layers(layers_path, true).ok_or_else(|| {
                QuilError::Internal(format!(
                    "storage labels: could not lock {}",
                    layers_path.display()
                ))
            })?);
        }
        let file = if kept > 0 {
            fs::OpenOptions::new().append(true).open(layers_path)
        } else {
            File::create(layers_path)
        }
        .map_err(|e| io("open", layers_path, e))?;
        // Past the kept layers ([`LabelStore::admit`] cut the file there).
        let offset = file
            .metadata()
            .map_err(|e| io("open", layers_path, e))?
            .len();
        let mut reader = match kept {
            0 => None,
            _ => Some(File::open(layers_path).map_err(|e| io("open", layers_path, e))?),
        };
        let mut writer = Some(ChunkedWriter::new(
            file,
            offset,
            chunk_bytes(),
            flush_gate(),
            tally,
        ));
        let (mut failure, mut shortfall, mut unread) = (None, None, None);
        // Whole layers on disk.
        let mut whole = kept;
        // Labelling ahead out of room stops: its labels would not be kept.
        let refused = std::cell::Cell::new(false);
        // A write that failed stops the labelling: no layer after it is of
        // use.
        let halt = std::cell::Cell::new(false);
        let labelled = quil_crypto::storage_proof::label_leaf_resume(
            self.n,
            &key,
            params,
            kept,
            &mut |index, into| {
                let read = reader
                    .as_mut()
                    .map(|file| read_layer(file, index as u64 * layer_size, into));
                match read {
                    Some(Ok(true)) => true,
                    Some(Ok(false)) => {
                        unread = Some(std::io::Error::other("a kept label is not a digest"));
                        false
                    }
                    Some(Err(error)) => {
                        unread = Some(error);
                        false
                    }
                    None => false,
                }
            },
            &mut |index, layer| {
                on_layers(index + 1);
                if writer.is_none() {
                    return;
                }
                if let Err(short) = self.room() {
                    // Out of room: the rest is labelled, not written, when
                    // the snapshot needs the labels.
                    shortfall = Some(short);
                    writer = None;
                    refused.set(self.stage == Stage::Ahead);
                    return;
                }
                // Synced, then listed: a listed layer is whole on disk. Its
                // chunks went to disk as they were written; the sync takes
                // the rest and its size.
                let written = writer.as_mut().map(|writer| {
                    let digest = write_layer(writer, layer)?;
                    writer.sync(false)?;
                    Ok::<_, std::io::Error>(digest)
                });
                match written {
                    Some(Ok(digest)) => {
                        self.wrote((layer.len() * NODE_BYTES) as u64);
                        manifest.layers.truncate(index);
                        manifest.layers.push(digest);
                        let listed = {
                            let gate = flush_gate();
                            let _permit = gate.map(|gate| gate.take(tally));
                            let started = Instant::now();
                            let listed = write_manifest(&dir, n, &manifest);
                            if let Some(gate) = gate {
                                gate.synced(started.elapsed(), tally);
                            }
                            listed
                        };
                        match listed {
                            Ok(()) => whole = index + 1,
                            Err(error) => {
                                failure = Some(error);
                                writer = None;
                                halt.set(true);
                            }
                        }
                    }
                    Some(Err(error)) => {
                        failure = Some(error);
                        writer = None;
                        halt.set(true);
                    }
                    None => {}
                }
            },
            &|| refused.get() || halt.get() || stop(),
        );
        drop(reader);
        if let Some(error) = failure {
            return Err(io("write", layers_path, error));
        }
        if let Some(error) = unread {
            return Err(io("read back", layers_path, error));
        }
        if refused.get() {
            if let Some(shortfall) = shortfall {
                let (epoch, n, stage) = (self.epoch, self.n, self.stage);
                self.store
                    .refuse(epoch, &self.dir, &self.leaf_id, n, stage, shortfall);
            }
            return Ok(Labelling::Refused);
        }
        let Some((last, columns)) = labelled else {
            // Each whole layer was synced and listed as it ended; out of
            // room, none is kept.
            let layers = if writer.is_some() { whole } else { 0 };
            return Ok(Labelling::Stopped { layers });
        };
        let commitment = |columns: Vec<Digest>| {
            quil_crypto::storage_proof::MerkleCap::from_digests(
                &columns,
                quil_crypto::storage_proof::CAP_HEIGHT,
            )
            .commitment(quil_crypto::storage_proof::Tree::Column)
        };
        // Past its last layer the leaf is not given up: what is left is
        // written in moments, unless disk or the parallel pool its column
        // tree is built on is slow, which this then logs.
        let finishing = Instant::now();
        if let Some(writer) = writer {
            writer.finish().map_err(|e| io("write", layers_path, e))?;
            shortfall = self.room().err();
        }
        if let Some(shortfall) = shortfall {
            let (epoch, n, stage) = (self.epoch, self.n, self.stage);
            self.store
                .refuse(epoch, &self.dir, &self.leaf_id, n, stage, shortfall);
            return Ok(Labelling::Labelled(Labelled {
                comm_c: commitment(columns),
                last,
                kept: false,
            }));
        }
        let mut writer = ChunkedWriter::new(
            File::create(columns_path).map_err(|e| io("create", columns_path, e))?,
            0,
            chunk_bytes(),
            flush_gate(),
            tally,
        );
        write_digests(&mut writer, &columns).map_err(|e| io("write", columns_path, e))?;
        writer.finish().map_err(|e| io("write", columns_path, e))?;
        self.wrote((columns.len() * NODE_BYTES) as u64);
        let written = finishing.elapsed();
        let cap = quil_crypto::storage_proof::MerkleCap::from_digests(
            &columns,
            quil_crypto::storage_proof::seal_cap_height(self.n),
        );
        let comm_c = cap.commitment(quil_crypto::storage_proof::Tree::Column);
        let cap_path = self.dir.join(format!("{}.cap", self.n));
        fs::write(&cap_path, cap.to_bytes()).map_err(|e| io("write", &cap_path, e))?;
        let staged = staged(&self.dir, self.n);
        fs::write(&staged, comm_c).map_err(|e| io("write", &staged, e))?;
        fs::rename(&staged, ready_path).map_err(|e| io("rename", ready_path, e))?;
        // Complete: `ready` stands for the layers from now on.
        let _ = fs::remove_file(kept_path(&self.dir, self.n));
        let finished = finishing.elapsed();
        if finished >= FINISH_LOGGED_FROM {
            info!(epoch = self.epoch, leaf = %hex::encode(&self.leaf_id), nodes = self.n,
                seconds = finished.as_secs_f64(), writing_seconds = written.as_secs_f64(),
                commitment_seconds = finished.saturating_sub(written).as_secs_f64(),
                scope = "local",
                "storage labels took long to finish after their last layer: writing the layers \
                 and column digests to disk, then building the column tree on the shared \
                 parallel pool; check this node's disk and CPU load if this recurs");
        }
        Ok(Labelling::Labelled(Labelled {
            comm_c,
            last,
            kept: true,
        }))
    }
}

impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        let remaining = std::mem::take(&mut self.remaining);
        {
            let mut pending = self.store.pending();
            *pending = pending.saturating_sub(remaining);
            self.store.publish_pending(*pending);
        }
        if let Some(writer) = self.writer.take() {
            end_claim(&self.dir, self.n, writer);
        }
        self.store.busy().remove(&(self.dir.clone(), self.n));
    }
}

fn paths(dir: &Path, n: u64) -> [PathBuf; 3] {
    ["layers", "columns", "ready"].map(|kind| dir.join(format!("{n}.{kind}")))
}

/// Where the column commitment is written before it is renamed `ready`.
fn staged(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("{n}.ready.tmp"))
}

/// The manifest of the whole layers a labelling not ended kept
/// ([`Manifest`]).
fn kept_path(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("{n}.kept"))
}

/// Where a manifest is written before it is renamed `kept`.
fn manifest_staged(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("{n}.kept.tmp"))
}

/// Log a release of labels for free space that goes on ([`LabelStore::keep_floor`]):
/// `released` by this check, from `usage` to `free_after` free bytes.
fn log_still(
    usage: &FsUsage,
    free_after: u64,
    released: &Released,
    shortage: &Shortage,
    now: u64,
    floor: u64,
) {
    warn!(free_bytes = usage.free_bytes, floor_bytes = floor,
        free_after_bytes = free_after, released_bytes = released.bytes,
        released_counts = released.counts, in_use_counts = released.in_use,
        total_released_bytes = shortage.bytes, total_released_counts = shortage.counts,
        releases = shortage.releases, epochs = %shortage.epochs_text(),
        episode_seconds = now.saturating_sub(shortage.since),
        resume_bytes = floor.saturating_add(release_band(floor).saturating_mul(2)), scope = "local",
        "storage labels kept ahead still released: free disk space on this node stays below \
         resume_bytes, and labelling ahead waits; check what fills this node's disk (worker \
         stores, logs, other files)");
}

/// The files of count `n` in `dir`: every one named `<n>.<kind>`.
fn count_files(dir: &Path, n: u64) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.split('.').next())
                .and_then(|count| count.parse::<u64>().ok())
                == Some(n)
        })
        .map(|entry| entry.path())
        .collect()
}

/// The counts of the files in `dir` named `<n><suffix>`.
fn counts_with(dir: &Path, suffix: &str) -> Vec<u64> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(suffix)?.parse().ok()
        })
        .collect()
}

/// Bytes one layer of a leaf of `n` nodes takes.
fn layer_bytes(n: u64) -> u64 {
    n.saturating_mul(NODE_BYTES as u64)
}

/// The first line of a manifest ([`Manifest`]).
const MANIFEST_FORMAT: &str = "quil storage labels kept v1";

/// What the whole layers a labelling not ended kept on disk label, and each
/// one's SHA-256, in order (`<n>.kept`): its node count, labelling
/// parameters and replica key, which a labelling resumed from them must
/// share, and the stage that labelled them. Rewritten after each layer is
/// synced, through a synced file renamed over it.
struct Manifest {
    n: u64,
    params: String,
    key: String,
    stage: Stage,
    layers: Vec<[u8; 32]>,
}

impl Manifest {
    fn text(&self) -> String {
        let mut text = format!(
            "{MANIFEST_FORMAT}\nn {}\nparams {}\nkey {}\nstage {}\n",
            self.n,
            self.params,
            self.key,
            self.stage.name()
        );
        for layer in &self.layers {
            text.push_str("layer ");
            text.push_str(&hex::encode(layer));
            text.push('\n');
        }
        text
    }

    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != MANIFEST_FORMAT {
            return None;
        }
        let mut field = |name: &str| Some(lines.next()?.strip_prefix(name)?.to_string());
        let n = field("n ")?.parse().ok()?;
        let params = field("params ")?;
        let key = field("key ")?;
        let stage = Stage::from_name(&field("stage ")?)?;
        let layers = lines
            .map(|line| {
                hex::decode(line.strip_prefix("layer ")?)
                    .ok()?
                    .try_into()
                    .ok()
            })
            .collect::<Option<Vec<[u8; 32]>>>()?;
        Some(Self {
            n,
            params,
            key,
            stage,
            layers,
        })
    }
}

/// The labelling parameters, as a manifest names them.
fn params_text(params: &SdrParams) -> String {
    format!(
        "{} {} {} {}",
        params.drg_degree, params.expander_degree, params.layers, params.node_bytes
    )
}

/// Write `manifest` as the one of the leaf's layers at `n` nodes in `dir`:
/// to a file synced, then renamed over the last, the directory synced.
fn write_manifest(dir: &Path, n: u64, manifest: &Manifest) -> std::io::Result<()> {
    let staged = manifest_staged(dir, n);
    let mut file = File::create(&staged)?;
    file.write_all(manifest.text().as_bytes())?;
    file.sync_all()?;
    fs::rename(&staged, kept_path(dir, n))?;
    File::open(dir)?.sync_all()
}

/// The whole layers kept on disk a labelling at a leaf's count may go on
/// from ([`verify_kept_with_params`]).
#[derive(Default)]
struct Verified {
    /// The digests of the layers that matched, from the first.
    layers: Vec<[u8; 32]>,
    kept_by: Option<Stage>,
    /// Bytes read, and how long reading and hashing them took.
    bytes: u64,
    took: Duration,
    /// The first layer listed that did not match, and how.
    failed: Option<(usize, &'static str)>,
    /// Why no layer listed was looked at: they label something else.
    unusable: Option<&'static str>,
}

/// Check the whole layers its manifest lists for the leaf at `n` nodes in
/// `dir`, keyed `key`, against their digests, from the first: those before
/// the first one cut short or changed may be resumed from. None when there
/// is no manifest, or it is not one for these labels (another format, node
/// count, parameters or key). Reads each layer once, a chunk at a time.
fn verify_kept_with_params(dir: &Path, n: u64, key: &[u8; 32], params: &SdrParams) -> Verified {
    let started = Instant::now();
    let mut verified = Verified::default();
    let Ok(text) = fs::read_to_string(kept_path(dir, n)) else {
        return verified;
    };
    let Some(manifest) = Manifest::parse(&text) else {
        verified.unusable = Some("its manifest is of an unknown format, from another build");
        return verified;
    };
    if manifest.n != n
        || manifest.params != params_text(&params)
        || manifest.key != hex::encode(key)
        || manifest.layers.len() > params.layers
    {
        verified.unusable =
            Some("its manifest names another node count, labelling parameters or key");
        return verified;
    }
    verified.kept_by = Some(manifest.stage);
    let [layers, _, _] = paths(dir, n);
    let Ok(mut file) = File::open(&layers) else {
        verified.failed = Some((0, "its layers file cannot be read"));
        return verified;
    };
    let size = layer_bytes(n);
    let mut chunk = vec![0u8; READ_CHUNK_BYTES];
    for (index, digest) in manifest.layers.iter().enumerate() {
        let mut hasher = Sha256::new();
        let mut left = size;
        while left > 0 {
            let len = left.min(chunk.len() as u64) as usize;
            if file.read_exact(&mut chunk[..len]).is_err() {
                break;
            }
            hasher.update(&chunk[..len]);
            verified.bytes += len as u64;
            left -= len as u64;
        }
        if left > 0 {
            verified.failed = Some((index, "cut short"));
            break;
        }
        if hasher.finalize().as_slice() != digest {
            verified.failed = Some((index, "its digest differs"));
            break;
        }
        verified.layers.push(*digest);
    }
    verified.took = started.elapsed();
    verified
}

/// Log a kept leaf's layers not reused ([`verify_kept_with_params`]): written for other
/// labels (info), or a layer that did not match its digest (warn).
fn log_verified(epoch: u64, leaf_id: &[u8], n: u64, stage: Stage, verified: &Verified) {
    let leaf = hex::encode(leaf_id);
    if let Some(reason) = verified.unusable {
        info!(epoch, leaf = %leaf, nodes = n, stage = stage.name(), reason, scope = "local",
            "storage labels kept on disk not reused: they label something else, as after an \
             upgrade; the leaf is labelled from its first layer");
    }
    if let Some((layer, reason)) = verified.failed {
        warn!(epoch, leaf = %leaf, nodes = n, stage = stage.name(), layer, reason,
            layers_reused = verified.layers.len(), scope = "local",
            action = "check this node's disk and its kernel log for I/O errors if this recurs: \
                      a layer is synced before it is listed, so a crash or restart leaves only \
                      the layer it was labelling unlisted",
            "storage labels kept on disk failed their check: the leaf is labelled again from \
             that layer");
    }
}

/// Read the layer at byte `offset` of a leaf's `layers` back into `into`:
/// false when a label read is not a digest.
fn read_layer(file: &mut File, offset: u64, into: &mut [Digest]) -> std::io::Result<bool> {
    file.seek(SeekFrom::Start(offset))?;
    let mut chunk = vec![0u8; READ_CHUNK_BYTES.min(into.len() * NODE_BYTES)];
    for labels in into.chunks_mut(chunk.len() / NODE_BYTES) {
        let bytes = &mut chunk[..labels.len() * NODE_BYTES];
        file.read_exact(bytes)?;
        for (label, node) in labels.iter_mut().zip(bytes.chunks_exact(NODE_BYTES)) {
            match hash::from_bytes(node) {
                Some(digest) => *label = digest,
                None => return Ok(false),
            }
        }
    }
    Ok(true)
}

/// Counts the chunks of labels being written to disk in this process
/// ([`FLUSH_PERMITS`]): a writer takes a permit before it writes a chunk
/// and gives it back once the chunk is on disk ([`ChunkedWriter`]). It
/// paces them by what they took ([`Pace`]).
struct FlushGate {
    permits: usize,
    pace: Mutex<Pace>,
    freed: Condvar,
}

/// The gate every leaf's labels are written through, on Linux: elsewhere a
/// layer is written through the buffer, then synced whole, as before
/// (2026-11-05).
static FLUSH_GATE: FlushGate = FlushGate::new(FLUSH_PERMITS);

fn flush_gate() -> Option<&'static FlushGate> {
    cfg!(target_os = "linux").then_some(&FLUSH_GATE)
}

/// What a [`FlushGate`] holds: the permits held, the disk's speed over the
/// latest pushes, and until when an overrun holds the permits back.
///
/// Labels written at once take the disk for their bytes over its speed,
/// and a store's synced commit on the same disk waits behind them. Each
/// push is timed, waits for the others in flight included, so a chunk cut
/// to what one took [`FLUSH_TARGET`] for keeps all the labels in flight,
/// this process's and any other's on the disk, near that long ahead of a
/// commit ([`Self::chunk`]). A disk too slow for even the smallest chunk
/// is given time between them ([`Self::overran`]).
struct Pace {
    held: usize,
    /// Seconds a byte of the latest [`PACE_WINDOW`] pushes, the oldest
    /// replaced first.
    recent: [f64; PACE_WINDOW],
    /// Pushes timed in all.
    timed: usize,
    /// No permit is given before this.
    resume: Option<Instant>,
}

impl Pace {
    const fn new() -> Self {
        Self {
            held: 0,
            recent: [0.0; PACE_WINDOW],
            timed: 0,
            resume: None,
        }
    }

    /// Bytes of the next chunk: what the disk took [`FLUSH_TARGET`] to
    /// push at the median of the latest pushes, whole
    /// [`FLUSH_CHUNK_ALIGN`]s from [`FLUSH_MIN_CHUNK_BYTES`] to
    /// [`FLUSH_CHUNK_BYTES`], the most until a push is timed.
    fn chunk(&self) -> usize {
        let timed = self.timed.min(PACE_WINDOW);
        let mut recent = self.recent;
        let recent = &mut recent[..timed];
        recent.sort_unstable_by(f64::total_cmp);
        let Some(&per_byte) = recent.get(timed / 2) else {
            return FLUSH_CHUNK_BYTES;
        };
        let bytes = FLUSH_TARGET.as_secs_f64() / per_byte;
        if bytes >= FLUSH_CHUNK_BYTES as f64 {
            return FLUSH_CHUNK_BYTES;
        }
        (bytes as usize / FLUSH_CHUNK_ALIGN * FLUSH_CHUNK_ALIGN)
            .clamp(FLUSH_MIN_CHUNK_BYTES, FLUSH_CHUNK_BYTES)
    }

    /// Time a push of `bytes` that `took`: a chunk's, not a layer's
    /// smaller end, whose push costs more than its bytes.
    fn pushed(&mut self, bytes: u64, took: Duration, now: Instant) -> Duration {
        if bytes >= FLUSH_MIN_CHUNK_BYTES as u64 {
            self.recent[self.timed % PACE_WINDOW] = took.as_secs_f64() / bytes as f64;
            self.timed += 1;
        }
        self.overran(took, now)
    }

    /// A push or sync that took past [`FLUSH_TARGET`] holds the permits
    /// back as long as it overran: labels then take at most about half of
    /// a disk too slow for the smallest chunk, and the stores' commits get
    /// the rest. Returns the overrun.
    fn overran(&mut self, took: Duration, now: Instant) -> Duration {
        let over = took.saturating_sub(FLUSH_TARGET);
        if !over.is_zero() {
            let until = now + over;
            self.resume = Some(self.resume.map_or(until, |resume| resume.max(until)));
        }
        over
    }
}

impl FlushGate {
    const fn new(permits: usize) -> Self {
        Self {
            permits,
            pace: Mutex::new(Pace::new()),
            freed: Condvar::new(),
        }
    }

    fn pace(&self) -> MutexGuard<'_, Pace> {
        self.pace.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A permit, once fewer than `permits` are held and no overrun holds
    /// them back: a wait for it is counted in `tally`.
    fn take(&self, tally: &FlushTally) -> FlushPermit<'_> {
        let started = Instant::now();
        let mut pace = self.pace();
        let mut waits = false;
        loop {
            if pace.held >= self.permits {
                waits = true;
                pace = self
                    .freed
                    .wait(pace)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let now = Instant::now();
            match pace.resume {
                Some(resume) if resume > now => {
                    waits = true;
                    pace = self
                        .freed
                        .wait_timeout(pace, resume - now)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
                _ => break,
            }
        }
        pace.held += 1;
        drop(pace);
        if waits {
            tally.waited(started.elapsed());
        }
        FlushPermit(self)
    }

    /// Bytes of the next chunk ([`Pace::chunk`]).
    fn chunk(&self) -> usize {
        self.pace().chunk()
    }

    /// A push of `bytes` that `took`, made holding a permit: returns the
    /// bytes of the next chunk.
    fn pushed(&self, bytes: u64, took: Duration, tally: &FlushTally) -> usize {
        let mut pace = self.pace();
        let over = pace.pushed(bytes, took, Instant::now());
        let chunk = pace.chunk();
        drop(pace);
        tally.overran(over);
        chunk
    }

    /// A sync that `took`, made holding a permit ([`Pace::overran`]).
    fn synced(&self, took: Duration, tally: &FlushTally) {
        let over = self.pace().overran(took, Instant::now());
        tally.overran(over);
    }
}

/// A permit of a [`FlushGate`], given back when dropped.
struct FlushPermit<'a>(&'a FlushGate);

impl Drop for FlushPermit<'_> {
    fn drop(&mut self) {
        let mut pace = self.0.pace();
        pace.held = pace.held.saturating_sub(1);
        drop(pace);
        self.0.freed.notify_all();
    }
}

/// What writing a leaf's labels waited for and took ([`ChunkedWriter`]),
/// logged once its labelling ends ([`Self::log`]).
#[derive(Default)]
struct FlushTally {
    /// Chunks written and pushed to disk, and their bytes.
    chunks: Cell<u64>,
    bytes: Cell<u64>,
    /// Waits for a permit ([`FlushGate::take`]), how long they took in all,
    /// and the longest.
    waits: Cell<u64>,
    waited: Cell<Duration>,
    longest: Cell<Duration>,
    /// Time writing, pushing and syncing, holding a permit.
    disk: Cell<Duration>,
    /// Pushes and syncs past [`FLUSH_TARGET`], and how long they held the
    /// permits back in all ([`Pace::overran`]).
    overruns: Cell<u64>,
    overran: Cell<Duration>,
}

impl FlushTally {
    fn waited(&self, took: Duration) {
        self.waits.set(self.waits.get() + 1);
        self.waited.set(self.waited.get() + took);
        self.longest.set(self.longest.get().max(took));
    }

    fn pushed(&self, bytes: u64, took: Duration) {
        self.chunks.set(self.chunks.get() + 1);
        self.bytes.set(self.bytes.get() + bytes);
        self.disk.set(self.disk.get() + took);
    }

    fn synced(&self, took: Duration) {
        self.disk.set(self.disk.get() + took);
    }

    fn overran(&self, over: Duration) {
        if !over.is_zero() {
            self.overruns.set(self.overruns.get() + 1);
            self.overran.set(self.overran.get() + over);
        }
    }

    /// One line for a labelling that wrote labels, as it ends.
    fn log(&self, epoch: u64, leaf_id: &[u8], n: u64, stage: Stage) {
        if self.chunks.get() == 0 {
            return;
        }
        info!(epoch, leaf = %hex::encode(leaf_id), nodes = n, stage = stage.name(),
            bytes = self.bytes.get(), chunks = self.chunks.get(),
            permit_waits = self.waits.get(),
            permit_wait_seconds = self.waited.get().as_secs_f64(),
            longest_permit_wait_seconds = self.longest.get().as_secs_f64(),
            disk_seconds = self.disk.get().as_secs_f64(),
            overruns = self.overruns.get(),
            overrun_seconds = self.overran.get().as_secs_f64(),
            permits = FLUSH_PERMITS, chunk_bytes = FLUSH_CHUNK_BYTES,
            target_ms = FLUSH_TARGET.as_millis() as u64, scope = "local",
            "storage labels written to disk a chunk at a time, at most `permits` chunks at \
             once in this process, each cut to what this node's disk writes in `target_ms`, \
             so the stores' synced commits wait behind no more; `overruns` are writes past \
             it, after which labels wait as long, giving the stores the disk. Permit waits \
             well above `disk_seconds` mean labelling outpaces this node's disk, which slows \
             labelling, not the stores: check the disk's write speed if leaves miss their \
             renewal's grace");
    }
}

/// Where a leaf's labels are written a chunk at a time ([`ChunkedWriter`]):
/// a file, or a test's own.
trait ChunkSink: Write {
    /// Write the `len` bytes written last, from byte `start`, to the disk
    /// and wait until they are, without their metadata ([`Self::sync`]).
    fn push(&mut self, start: u64, len: u64) -> std::io::Result<()>;

    /// `sync_all` when `all`, else `sync_data`.
    fn sync(&mut self, all: bool) -> std::io::Result<()>;
}

impl ChunkSink for File {
    #[cfg(target_os = "linux")]
    fn push(&mut self, start: u64, len: u64) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        let range = |bytes: u64| {
            libc::off64_t::try_from(bytes).map_err(|_| std::io::Error::other("past a file's end"))
        };
        let flags = libc::SYNC_FILE_RANGE_WAIT_BEFORE
            | libc::SYNC_FILE_RANGE_WRITE
            | libc::SYNC_FILE_RANGE_WAIT_AFTER;
        // SAFETY: the descriptor is this file's, open while it is borrowed;
        // the call reads and writes no memory of the process.
        let pushed =
            unsafe { libc::sync_file_range(self.as_raw_fd(), range(start)?, range(len)?, flags) };
        if pushed == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Left to the final sync, as before (2026-11-05).
    #[cfg(not(target_os = "linux"))]
    fn push(&mut self, _start: u64, _len: u64) -> std::io::Result<()> {
        Ok(())
    }

    fn sync(&mut self, all: bool) -> std::io::Result<()> {
        if all {
            self.sync_all()
        } else {
            self.sync_data()
        }
    }
}

/// The bytes of a chunk for this thread's label writers:
/// [`FLUSH_CHUNK_BYTES`], unless a test sets fewer.
fn chunk_bytes() -> usize {
    #[cfg(test)]
    if let Some(bytes) = tests::TEST_CHUNK_BYTES.with(Cell::get) {
        return bytes;
    }
    FLUSH_CHUNK_BYTES
}

/// Set this thread's label writers' chunk bytes ([`chunk_bytes`]).
#[cfg(test)]
pub(crate) fn set_chunk_bytes_for_test(bytes: Option<usize>) {
    tests::TEST_CHUNK_BYTES.with(|chunk| chunk.set(bytes));
}

/// The chunks this thread's writers pushed through a flush gate since the
/// last call, and their bytes.
#[cfg(test)]
pub(crate) fn take_gated_pushes() -> (u64, u64) {
    tests::GATED_PUSHES.with(|pushes| pushes.replace((0, 0)))
}

/// Writes a leaf's labels to `inner` a chunk at a time: each chunk is
/// written and pushed to disk ([`ChunkSink::push`]) holding a permit of its
/// gate, before the next is written, so labels written and not yet on disk
/// are at most a chunk a permit in the process ([`FLUSH_CHUNK_BYTES`]),
/// fewer bytes on a disk slower than its gate's pace ([`Pace::chunk`]).
/// Syncing ([`Self::sync`]) holds one too. Without a gate (elsewhere than
/// Linux) it is a buffered writer.
struct ChunkedWriter<'a, W: ChunkSink> {
    inner: W,
    buffer: Vec<u8>,
    /// The most bytes of a chunk, and those of the next.
    chunk: usize,
    next: usize,
    /// Where in `inner` the next chunk goes.
    offset: u64,
    gate: Option<&'a FlushGate>,
    tally: &'a FlushTally,
}

impl<'a, W: ChunkSink> ChunkedWriter<'a, W> {
    /// Writing to `inner` from byte `offset`, its end, in chunks of at most
    /// `chunk` bytes.
    fn new(
        inner: W,
        offset: u64,
        chunk: usize,
        gate: Option<&'a FlushGate>,
        tally: &'a FlushTally,
    ) -> Self {
        let chunk = chunk.max(1);
        let next = gate.map_or(chunk, |gate| gate.chunk().min(chunk));
        Self {
            inner,
            buffer: Vec::with_capacity(next),
            chunk,
            next,
            offset,
            gate,
            tally,
        }
    }

    /// Write the buffer to `inner` and push it to disk, holding a permit.
    fn push(&mut self) -> std::io::Result<()> {
        #[cfg(test)]
        tests::crash_before_push();
        let len = self.buffer.len() as u64;
        let _permit = self.gate.map(|gate| gate.take(self.tally));
        let started = Instant::now();
        self.inner.write_all(&self.buffer)?;
        self.inner.push(self.offset, len)?;
        let took = started.elapsed();
        #[cfg(test)]
        tests::gated_push(self.gate.is_some(), len);
        self.tally.pushed(len, took);
        if let Some(gate) = self.gate {
            self.next = gate.pushed(len, took, self.tally).min(self.chunk);
        }
        self.offset += len;
        self.buffer.clear();
        Ok(())
    }

    /// Push what is buffered, then sync `inner` holding a permit:
    /// `sync_all` when `all`, else `sync_data`, cheap once its chunks are
    /// on disk.
    fn sync(&mut self, all: bool) -> std::io::Result<()> {
        self.flush()?;
        let _permit = self.gate.map(|gate| gate.take(self.tally));
        let started = Instant::now();
        self.inner.sync(all)?;
        let took = started.elapsed();
        self.tally.synced(took);
        if let Some(gate) = self.gate {
            gate.synced(took, self.tally);
        }
        Ok(())
    }

    /// [`Self::sync`] all of `inner`, its metadata too.
    fn finish(mut self) -> std::io::Result<()> {
        self.sync(true)
    }
}

impl<W: ChunkSink> Write for ChunkedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.buffer.len() >= self.next {
            self.push()?;
        }
        let len = bytes.len().min(self.next - self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..len]);
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            self.push()?;
        }
        self.inner.flush()
    }
}

/// Write `digests` to a new file at `path`, as a leaf's labels are written:
/// a chunk at a time through the flush gate, paced, then synced whole
/// ([`ChunkedWriter`]). A sector's last layer, up to 2 GiB, written at
/// once and then synced held the stores' synced commits behind all of it
/// (2026-11-07).
pub(crate) fn write_digests_paced(path: &Path, digests: &[Digest]) -> std::io::Result<()> {
    let tally = FlushTally::default();
    let mut writer =
        ChunkedWriter::new(File::create(path)?, 0, chunk_bytes(), flush_gate(), &tally);
    for digests in digests.chunks(1024) {
        writer.write_all(&hash::digests_to_bytes(digests))?;
    }
    writer.finish()
}

fn write_digests(writer: &mut impl Write, digests: &[Digest]) -> std::io::Result<()> {
    for digest in digests {
        writer.write_all(&hash::to_bytes(digest))?;
    }
    Ok(())
}

/// [`write_digests`] for a layer: its SHA-256, as its manifest lists it.
fn write_layer(writer: &mut impl Write, layer: &[Digest]) -> std::io::Result<[u8; 32]> {
    const LABELS: usize = 64;
    let mut hasher = Sha256::new();
    let mut chunk = [0u8; LABELS * NODE_BYTES];
    for labels in layer.chunks(LABELS) {
        let bytes = &mut chunk[..labels.len() * NODE_BYTES];
        for (label, node) in labels.iter().zip(bytes.chunks_exact_mut(NODE_BYTES)) {
            node.copy_from_slice(&hash::to_bytes(label));
        }
        hasher.update(&*bytes);
        writer.write_all(bytes)?;
    }
    Ok(hasher.finalize().into())
}

/// Nodes at which [`Kept::verified_last_layer`] checks the kept layers
/// against the column digests, spread evenly over the leaf.
const VERIFIED_NODES: u64 = 256;

/// One leaf's kept labels.
pub struct Kept {
    pub n: u64,
    pub comm_c: Node,
    layers: Mutex<File>,
    columns: Mutex<File>,
    column_cap: Option<quil_crypto::storage_proof::MerkleCap>,
    replica: Option<CachedReplica>,
    depth: usize,
}

struct CachedReplica {
    store: quil_store::replica_store::ReplicaStore,
    epoch: u64,
    leaf_id: Vec<u8>,
    leaf: Arc<quil_store::replica_store::HashLeaf>,
    data_cap: quil_crypto::storage_proof::MerkleCap,
}

impl Kept {
    /// Attach the replica only when all sparse caches bind to its exact
    /// registration. Old stores take the dense, compatible preparation path.
    pub fn with_replica(
        mut self,
        store: &quil_store::replica_store::ReplicaStore,
        epoch: u64,
        leaf_id: &[u8],
    ) -> Option<Self> {
        use quil_crypto::storage_proof::{parse_registration_root, Tree};
        let leaf = store.get_hash_leaf(epoch, leaf_id).ok()??;
        let data_cap = store.get_data_cap(epoch, leaf_id).ok()??;
        let registered = parse_registration_root(&leaf.registration_root)?;
        let column = self.column_cap.as_ref()?;
        if self.n != leaf.n
            || data_cap.n != leaf.n
            || column.n != leaf.n
            || data_cap.commitment(Tree::Data) != registered.comm_d
            || column.commitment(Tree::Column) != registered.comm_c
            || leaf.cap.commitment(Tree::Replica) != registered.comm_r
        {
            return None;
        }
        self.replica = Some(CachedReplica {
            store: store.clone(),
            epoch,
            leaf_id: leaf_id.to_vec(),
            leaf,
            data_cap,
        });
        Some(self)
    }

    /// The last layer, if these labels are whole: their column digests
    /// commit to the column commitment kept with them, and at
    /// [`VERIFIED_NODES`] nodes spread evenly over the leaf (from a random
    /// start) and its last node, the node's labels on every layer, the last
    /// layer's as returned, chain to its column digest. A layers or columns
    /// file torn or damaged over more than a 256th of the leaf fails it.
    /// `None` otherwise: the leaf is labelled again rather than registered
    /// from these, which its seal could not open.
    pub fn verified_last_layer(&self) -> Option<Vec<Digest>> {
        use quil_crypto::storage_proof::{column_digest, MerkleTree, Tree};
        let n = self.n;
        let columns = self.columns()?;
        let last = self.last_layer().filter(|last| last.len() as u64 == n)?;
        let count = VERIFIED_NODES.min(n);
        if count == 0 {
            return None;
        }
        let start = rand::random::<u64>() % n.div_ceil(count);
        let nodes = (0..count)
            .map(|i| {
                ((u128::from(i) * u128::from(n) / u128::from(count)) as u64 + start).min(n - 1)
            })
            .chain([n - 1]);
        for v in nodes {
            let mut labels = (0..self.depth - 1)
                .map(|layer| self.label(layer, v))
                .collect::<Option<Vec<Node>>>()?;
            labels.push(hash::to_bytes(&last[v as usize]));
            if column_digest(&labels)? != hash::to_bytes(&columns[v as usize]) {
                return None;
            }
        }
        (MerkleTree::from_digests(columns).commitment(Tree::Column) == self.comm_c).then_some(last)
    }

    fn read(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let mut file = self.layers.lock().ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes).ok()?;
        Some(bytes)
    }
}

impl LabelSource for Kept {
    fn cap(
        &self,
        tree: quil_crypto::storage_proof::Tree,
    ) -> Option<quil_crypto::storage_proof::MerkleCap> {
        use quil_crypto::storage_proof::Tree;
        let replica = self.replica.as_ref()?;
        Some(match tree {
            Tree::Data => replica.data_cap.clone(),
            Tree::Column => self.column_cap.clone()?,
            Tree::Replica => replica.leaf.cap.clone(),
        })
    }

    fn nodes(
        &self,
        tree: quil_crypto::storage_proof::Tree,
        range: std::ops::Range<u64>,
    ) -> Option<Vec<u8>> {
        use quil_crypto::storage_proof::Tree;
        if range.start > range.end || range.end > self.n {
            return None;
        }
        let replica = self.replica.as_ref()?;
        if tree == Tree::Column {
            let mut file = self.columns.lock().ok()?;
            file.seek(SeekFrom::Start(range.start * NODE_BYTES as u64))
                .ok()?;
            let mut bytes = vec![0; (range.end - range.start) as usize * NODE_BYTES];
            file.read_exact(&mut bytes).ok()?;
            return Some(bytes);
        }
        let bytes = replica
            .store
            .read_nodes(
                replica.epoch,
                &replica.leaf_id,
                &replica.leaf,
                range.clone(),
            )
            .ok()?;
        if tree == Tree::Replica {
            return Some(bytes);
        }
        let offset = ((self.depth - 1) as u64 * self.n + range.start) * NODE_BYTES as u64;
        let last = hash::digests_from_bytes(&self.read(offset, bytes.len())?)?;
        let mut data = hash::digests_from_bytes(&bytes)?;
        for (node, label) in data.iter_mut().zip(last) {
            *node = hash::sub(node, &label);
        }
        Some(hash::digests_to_bytes(&data))
    }

    fn label(&self, layer: usize, v: u64) -> Option<Node> {
        if layer >= self.depth || v >= self.n {
            return None;
        }
        let at = (layer as u64 * self.n + v) * NODE_BYTES as u64;
        let node: Node = self.read(at, NODE_BYTES)?.try_into().ok()?;
        hash::from_bytes(&node).map(|_| node)
    }

    fn columns(&self) -> Option<Vec<Digest>> {
        let mut file = self.columns.lock().ok()?;
        file.seek(SeekFrom::Start(0)).ok()?;
        let mut out = Vec::with_capacity(self.n as usize);
        for at in (0..self.n).step_by(1024) {
            let mut bytes = vec![0; (self.n - at).min(1024) as usize * NODE_BYTES];
            file.read_exact(&mut bytes).ok()?;
            out.extend(hash::digests_from_bytes(&bytes)?);
        }
        Some(out)
    }

    fn last_layer(&self) -> Option<Vec<Digest>> {
        let size = self.n as usize * NODE_BYTES;
        hash::digests_from_bytes(&self.read((self.depth - 1) as u64 * size as u64, size)?)
    }
}

/// Shards labelled ahead, by member, shard and epoch, with when for one
/// whose leaves were refused room.
type Precomputed = HashMap<(Vec<u8>, Vec<u8>, u64), Option<Instant>>;

fn precomputed_set() -> MutexGuard<'static, Precomputed> {
    static DONE: OnceLock<Mutex<Precomputed>> = OnceLock::new();
    DONE.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Whether this process labelled `member`'s leaves of `filter` for `epoch`
/// ahead ([`precompute`]), so it need not again. A shard whose leaves were
/// refused room is labelled ahead again after [`REFUSED_RETRY`].
pub fn precomputed(member: &[u8], filter: &[u8], epoch: u64) -> bool {
    precomputed_set()
        .get(&(member.to_vec(), filter.to_vec(), epoch))
        .is_some_and(|refused| refused.is_none_or(|at| at.elapsed() < REFUSED_RETRY))
}

/// The epoch whose leaves a member labels ahead at GLOBAL frame `frame`
/// ([`precompute`]): normally the epoch after next, from the first frame of the
/// current one, an epoch and 16 frames before its snapshot frame
/// (`quil_types::consensus::storage_snapshot_frame`). In an epoch's first 16
/// frames the next epoch's snapshot frame is too close to label a leaf of any
/// size by, and labelling ahead gives up at it ([`expired`]). During the eight
/// epochs before mandatory sealing, warm the first stable epoch instead.
pub fn ahead_epoch(frame: u64) -> u64 {
    let current = quil_types::consensus::epoch_for_frame(frame);
    let first = quil_types::consensus::sealed_storage_epoch();
    // Persistent labels are data-independent. Warm the first mandatory epoch
    // over eight epochs instead of imposing a two-hour initial setup deadline.
    if first != u64::MAX && current < first && current.saturating_add(8) >= first {
        first.max(current.saturating_add(2))
    } else {
        current.saturating_add(2)
    }
}

/// Whether labelling ahead for `epoch` is of no use any more: GLOBAL reached
/// the epoch's snapshot frame (`crate::storage_snapshot::note_global_frame`),
/// from which the snapshot labels its leaves itself.
fn expired(epoch: u64) -> bool {
    crate::storage_snapshot::global_frame()
        .is_some_and(|frame| frame >= quil_types::consensus::storage_snapshot_frame(epoch))
}

/// Log that labelling `leaf_id` of shard `filter` ahead for `epoch` gave up
/// `at` a step of its work: GLOBAL reached the epoch's snapshot frame
/// ([`expired`]).
fn log_expired(epoch: u64, filter: &[u8], leaf_id: &[u8], at: &'static str) {
    info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), at,
        snapshot_frame = quil_types::consensus::storage_snapshot_frame(epoch),
        global_frame = crate::storage_snapshot::global_frame().unwrap_or(0), scope = "local",
        "storage labels computed ahead given up: GLOBAL reached the epoch's snapshot frame, from \
         which the snapshot labels this leaf itself, going on from the whole layers labelled \
         ahead; an expected skip");
}

/// Where each of a seat's leaves of `sizes` (`Captured::leaf_size`, bytes)
/// waits for memory to be labelled ahead for `epoch`
/// (`crate::storage_jobs::AheadOrder`), the seat having place `seat`: a leaf
/// whose snapshot could not label it within half the renewal's grace even
/// at the fewest nodes its values take
/// (`crate::storage_snapshot::labels_within_grace`) goes before every leaf
/// that it could, with the other such leaves of its seat, a seat with fewer
/// of them first: such leaves register only, or most surely, from labels
/// computed ahead, and a seat registers only once all of its leaves do.
pub(crate) fn ahead_orders(
    epoch: u64,
    seat: u64,
    sizes: &[u128],
) -> Vec<crate::storage_jobs::AheadOrder> {
    use quil_crypto::storage_proof::data_node_count;
    let deferrable: Vec<bool> = sizes
        .iter()
        .map(|&size| {
            let least = data_node_count(u64::try_from(size).unwrap_or(u64::MAX));
            crate::storage_snapshot::labels_within_grace(epoch, least)
        })
        .collect();
    let seat_leaves = deferrable.iter().filter(|&&deferrable| !deferrable).count();
    deferrable
        .into_iter()
        .enumerate()
        .map(|(leaf, deferrable)| crate::storage_jobs::AheadOrder {
            deferrable,
            seat_leaves: u32::try_from(seat_leaves).unwrap_or(u32::MAX),
            seat,
            leaf: leaf as u64,
        })
        .collect()
}

/// Label ahead the leaves `member` will register for `epoch` on shard
/// `filter`: the leaves of the shard's data in `crdt` now, each at
/// `precompute_nodes` of its node count, or at a count its data allows
/// with whole layers kept ([`label_leaf_ahead`]), side by side
/// (`storage_jobs::for_each_parallel`), each waiting for memory in its order
/// ([`ahead_orders`]). A leaf already labelled at a count its data allows is
/// left, and one its filesystem has no room for is not labelled
/// ([`LabelStore::admit`]). A leaf whose memory more urgent work waits for
/// gives it back, keeping its whole layers, and goes on from them once its
/// memory fits again ([`label_leaf_ahead`]). Nothing is labelled once GLOBAL
/// reached the epoch's snapshot frame ([`expired`]). Removes the labels of
/// epochs that have begun.
pub fn precompute(
    store: &LabelStore,
    crdt: &Arc<HypergraphCrdt>,
    member: &[u8],
    filter: &[u8],
    epoch: u64,
) -> Result<()> {
    use quil_crypto::storage_proof::{data_node_count, padded_nodes_allowed, precompute_nodes};
    let current = crate::storage_snapshot::global_frame()
        .map(quil_types::consensus::epoch_for_frame)
        .unwrap_or(epoch.saturating_sub(2));
    // A far-future warmup must not discard nearer registrations' labels.
    store.evict_before(epoch.saturating_sub(1).min(current.saturating_add(1)));
    if expired(epoch) {
        info!(epoch, filter = %hex::encode(filter),
            snapshot_frame = quil_types::consensus::storage_snapshot_frame(epoch),
            global_frame = crate::storage_snapshot::global_frame().unwrap_or(0), scope = "local",
            "storage labels not computed ahead: GLOBAL already reached the epoch's snapshot \
             frame, from which the snapshot labels the leaves itself; an expected skip");
        return Ok(());
    }
    let source = crate::storage_snapshot::current_source(crdt, filter, epoch);
    let captured = crate::storage_snapshot::capture_at(crdt, filter, epoch, &[source])?;
    if quil_types::consensus::persistent_storage_at(epoch) {
        return crate::storage_snapshot::prewarm_sectors(&captured, store, member);
    }
    let params = SdrParams::default();
    let started = std::time::Instant::now();
    let sizes = captured
        .prefixes
        .iter()
        .map(|prefix| captured.leaf_size(prefix))
        .collect::<Result<Vec<u128>>>()?;
    let orders = ahead_orders(epoch, crate::storage_jobs::ahead_place(), &sizes);
    let leaves: Vec<usize> = (0..captured.prefixes.len()).collect();
    let labelled = crate::storage_jobs::for_each_parallel(&leaves, |&index| {
        let (prefix, size, order) = (&captured.prefixes[index], sizes[index], orders[index]);
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(filter, prefix);
        // Past the epoch's snapshot frame, leaves not started yet are skipped.
        if expired(epoch) {
            return Ok(Some(0));
        }
        // A leaf's data is at least its values (`leaf_size`): one whose
        // labels at that count have no room is refused before its read,
        // which would hold memory the epoch's snapshots wait for.
        let least = precompute_nodes(data_node_count(u64::try_from(size).unwrap_or(u64::MAX)));
        if !store.holds(epoch, member, &leaf_id)
            && !store.may_admit(epoch, member, &leaf_id, least, Stage::Ahead)
        {
            return Ok(None);
        }
        let exact = captured.node_count(prefix)?;
        if store
            .find(epoch, member, &leaf_id, |n| padded_nodes_allowed(exact, n))
            .is_some()
        {
            return Ok(Some(0));
        }
        let leaf = Leaf {
            member,
            filter,
            leaf_id: &leaf_id,
            epoch,
        };
        label_leaf_ahead(store, &leaf, exact, order, &params)
    })?;
    let refused = labelled.iter().filter(|n| n.is_none()).count();
    let outcome = if expired(epoch) {
        "stopped at the epoch's snapshot frame: its snapshot labels the leaves not labelled by then"
    } else {
        "completed"
    };
    {
        let mut done = precomputed_set();
        done.retain(|(_, _, e), _| e.saturating_add(2) >= epoch);
        done.insert(
            (member.to_vec(), filter.to_vec(), epoch),
            (refused > 0 || quil_types::consensus::sealed_storage_required(epoch))
                .then(Instant::now),
        );
    }
    info!(epoch, filter = %hex::encode(filter), leaves = labelled.len(),
        labelled = labelled.iter().filter(|n| n.is_some_and(|n| n > 0)).count(), refused,
        nodes = labelled.iter().flatten().sum::<u64>(), seconds = started.elapsed().as_secs_f64(),
        outcome, "storage labels computed ahead of the epoch's snapshot");
    Ok(())
}

/// A member's leaf of a shard, labelled ahead for an epoch.
struct Leaf<'a> {
    member: &'a [u8],
    filter: &'a [u8],
    leaf_id: &'a [u8],
    epoch: u64,
}

/// Label `leaf`, whose data takes `exact` nodes, ahead ([`precompute`]),
/// waiting for its memory in `order`: `Some` of the count it was labelled
/// and kept at (0 when it was labelled meanwhile, or given up), `None` when
/// refused room. Asked to give its memory back to more urgent work
/// (`crate::storage_jobs::Reservation::yield_requested`), the labelling
/// keeps the whole layers it labelled ([`Admitted::label_ahead`]), asks for
/// the memory again at once, in its place
/// (`crate::storage_jobs::reserve_ahead`), and goes on from them once it
/// fits, unless the epoch's snapshot of the shard labelled the leaf
/// meanwhile. Once GLOBAL reaches the epoch's snapshot frame ([`expired`]),
/// looked at while the leaf waits for its memory and once it has it, and
/// while it is labelled, the leaf is given up, its whole layers kept for its
/// snapshot to go on from.
fn label_leaf_ahead(
    store: &LabelStore,
    leaf: &Leaf<'_>,
    exact: u64,
    order: crate::storage_jobs::AheadOrder,
    params: &SdrParams,
) -> Result<Option<u64>> {
    use crate::storage_snapshot::LeafOutcome;
    use quil_crypto::storage_proof::{padded_nodes_allowed, precompute_nodes};
    let Leaf {
        member,
        filter,
        leaf_id,
        epoch,
    } = *leaf;
    let stopping = || QuilError::ExecutionUnavailable("the node is stopping".into());
    // At the count its data may register with the most whole layers kept,
    // as its snapshot picks (`crate::storage_snapshot`), else at one with
    // room for the data to change by the snapshot: from the stable replica
    // key epoch, a leaf whose data changed within its band since an earlier
    // epoch's attempt goes on from its layers rather than from the first.
    let n = store
        .resumable(epoch, member, leaf_id, |count| {
            padded_nodes_allowed(exact, count)
        })
        .map_or_else(|| precompute_nodes(exact), |(count, _)| count);
    let layers = params.layers;
    // When the leaf last gave its memory back, with the layers it kept.
    let mut yielded: Option<(Instant, usize)> = None;
    loop {
        let bytes = label_ahead_bytes(n);
        let gone = || expired(epoch) || crate::storage_jobs::stopping();
        let memory =
            crate::storage_jobs::reserve_ahead(bytes, order, epoch, &gone).filter(|_| !gone());
        let Some(memory) = memory else {
            if crate::storage_jobs::stopping() {
                return Err(stopping());
            }
            // What it kept stays for the snapshot to go on from.
            log_expired(
                epoch,
                filter,
                leaf_id,
                "waiting for memory to label the leaf",
            );
            return Ok(Some(0));
        };
        let resumed = yielded.take();
        if resumed.is_some()
            && (store
                .find(epoch, member, leaf_id, |n| padded_nodes_allowed(exact, n))
                .is_some()
                || crate::storage_snapshot::snapshot_encoded(filter, epoch))
        {
            info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes = n,
                scope = "local",
                "storage labels computed ahead not resumed: the leaf was labelled meanwhile");
            store.discard(epoch, member, leaf_id, n);
            return Ok(Some(0));
        }
        let Some(admitted) = store.admit(epoch, member, leaf_id, n, Stage::Ahead) else {
            return Ok(None);
        };
        let from = admitted.resumes_from();
        if let Some((at, kept)) = resumed {
            info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes = n,
                waited_seconds = at.elapsed().as_secs(), layers_kept = kept, from_layer = from,
                layers, scope = "local",
                "storage labels computed ahead resume: their memory fits again; the leaf goes on \
                 from the whole layers it kept");
        } else if let Some(kept) = admitted.resumed() {
            info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes = n,
                layers_reused = kept.layers, layers, verified_bytes = kept.bytes,
                verify_seconds = kept.took.as_secs_f64(), kept_by = kept.kept_by.name(),
                scope = "local",
                "storage labels computed ahead go on from the whole layers kept on disk before, \
                 as after a restart, each checked against its digest");
        }
        memory.progress(from as u64, layers as u64);
        let progress = crate::storage_snapshot::leaf_started(
            epoch,
            filter,
            leaf_id,
            n,
            crate::storage_snapshot::LeafWork::LabellingAhead,
        );
        progress.layers(from, layers);
        let started = Instant::now();
        // Beside a renewal's leaf labelled now it may pause, keeping its
        // memory and layers (`crate::storage_jobs::ahead_beside_due`).
        let pause = || {
            if !memory.paused() {
                return;
            }
            info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes = n,
                from_layer = from, layers, scope = "local",
                "storage labels computed ahead pause while a renewal's leaf is labelled now: they \
                 keep their memory and the layers labelled and go on once that labelling ends, \
                 which has this node's cores meanwhile: an expected wait");
            let paused = memory.wait_while_paused(&gone);
            progress.paused(paused);
            let then = if memory.yield_requested() {
                "giving their memory back to more urgent work"
            } else if gone() {
                "stopping"
            } else {
                "going on"
            };
            info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes = n,
                paused_seconds = paused.as_secs(), then, scope = "local",
                "storage labels computed ahead pause ends");
        };
        let labelled = admitted.label_kept(
            params,
            &|| {
                pause();
                memory.yield_requested() || gone()
            },
            &|done| {
                memory.progress(done as u64, layers as u64);
                progress.layers(done, layers);
            },
        )?;
        let kept = match labelled {
            Labelling::Labelled(labelled) => {
                if expired(epoch) {
                    // Past its last layer it was not given up: kept, the
                    // seal opens it, and the snapshot of a leaf not started
                    // yet encodes from it.
                    info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id),
                        nodes = n, kept = labelled.kept,
                        snapshot_frame = quil_types::consensus::storage_snapshot_frame(epoch),
                        global_frame = crate::storage_snapshot::global_frame().unwrap_or(0),
                        scope = "local",
                        "storage labels computed ahead ended after GLOBAL reached the epoch's \
                         snapshot frame: their last layer was labelled before it");
                }
                progress.end(LeafOutcome::Completed);
                return Ok(labelled.kept.then_some(n));
            }
            Labelling::Refused => {
                progress.end(LeafOutcome::Refused);
                return Ok(None);
            }
            Labelling::Stopped { layers } => layers,
        };
        drop(memory);
        if crate::storage_jobs::stopping() {
            progress.end(LeafOutcome::Stopping);
            return Err(stopping());
        }
        if expired(epoch) {
            // What it kept stays for the snapshot to go on from.
            log_expired(epoch, filter, leaf_id, "labelling the leaf");
            progress.end(LeafOutcome::Expired);
            return Ok(Some(0));
        }
        info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes = n,
            seconds = started.elapsed().as_secs(), from_layer = from, layers_kept = kept, layers,
            scope = "local",
            "storage labels computed ahead give their memory back to more urgent work waiting \
             for it (a renewal's snapshot, an epoch proof, or a leaf only labelling ahead can \
             register); the whole layers labelled stay on disk and the leaf goes on from them \
             once its memory fits again, unless GLOBAL reaches the epoch's snapshot frame first: \
             an expected wait");
        progress.end(LeafOutcome::Yielded);
        yielded = Some((Instant::now(), kept));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test filesystem's size: its floor is 10 GiB.
    const TOTAL: u64 = 100 << 30;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("quil-labels-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// A filesystem of [`TOTAL`] bytes with `free` of them free.
    fn space(free: &Arc<AtomicU64>) -> SpaceSource {
        let free = free.clone();
        Box::new(move |_| {
            Some(FsUsage {
                total_bytes: TOTAL,
                free_bytes: free.load(Ordering::SeqCst),
                ..FsUsage::default()
            })
        })
    }

    fn keep(store: &LabelStore, epoch: u64, member: &[u8], leaf: &[u8], n: u64) -> Labelled {
        let admitted = store.admit(epoch, member, leaf, n, Stage::Ahead).unwrap();
        let labelled = admitted.label(&SdrParams::default()).unwrap();
        assert!(labelled.kept);
        labelled
    }

    /// Labelling a leaf ahead holds no more than it reserves
    /// ([`label_ahead_bytes`]), and reserves no more than its margin above
    /// it ([`LABEL_AHEAD_MARGIN_PERCENT`]): reserving the snapshot's encode
    /// instead (`crate::storage_snapshot::encoding_bytes`) labelled two large
    /// leaves ahead at a time where the memory allowed three (2026-11-01).
    #[test]
    fn labelling_ahead_reserves_what_it_holds() {
        let dir = temp_dir("peak");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let n = 20_000u64;
        let admitted = store
            .admit(9, &[8u8; 32], b"peak", n, Stage::Ahead)
            .unwrap();
        let (labelled, peak) = crate::test_alloc::peak_by(|| admitted.label(&SdrParams::default()));
        assert!(labelled.unwrap().kept);
        // Fresh workers allocate on other threads, so this counter only
        // bounds the caller. Resumed labelling below runs on this thread.
        let (peak, reserved) = (peak as u64, label_ahead_bytes(n));
        assert!(
            peak <= reserved,
            "labelling {n} nodes ahead held {peak} bytes at its peak and reserves {reserved}"
        );
        // Resumed from kept layers, read back into the buffers labelling
        // fills, it holds no more.
        let stopped = stop_after(&store, b"resumed", n, 9);
        assert!(matches!(stopped, Labelling::Stopped { layers: 9 }));
        let admitted = store
            .admit(9, &[8u8; 32], b"resumed", n, Stage::Ahead)
            .unwrap();
        assert_eq!(admitted.resumes_from(), 9);
        let (labelled, resumed_peak) =
            crate::test_alloc::peak_by(|| admitted.label(&SdrParams::default()));
        assert!(labelled.unwrap().kept);
        assert!(
            resumed_peak as u64 <= reserved,
            "labelling {n} nodes resumed held {resumed_peak} bytes at its peak and reserves {reserved}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Label `[8; 32]`'s leaf `leaf` of `n` nodes ahead for epoch 9 into
    /// `store`, told to stop once `layers` layers are labelled.
    fn stop_after(store: &LabelStore, leaf: &[u8], n: u64, layers: usize) -> Labelling {
        let admitted = store.admit(9, &[8u8; 32], leaf, n, Stage::Ahead).unwrap();
        let done = AtomicU64::new(0);
        admitted
            .label_kept(
                &SdrParams::default(),
                &|| done.load(Ordering::SeqCst) >= layers as u64,
                &|labelled| done.store(labelled as u64, Ordering::SeqCst),
            )
            .unwrap()
    }

    /// Labelling ahead told to stop keeps its whole layers, synced and
    /// listed, and the next attempt at the leaf's count goes on from them:
    /// its labels, column digests and column commitment are the leaf
    /// labelled at once (2026-11-01: labelling a leaf of 32 million nodes
    /// again from its start after each yield never ended). What the next
    /// attempt cannot resume from is removed, and labelling at the snapshot
    /// keeps its whole layers too until they are discarded.
    #[test]
    fn labelling_ahead_given_up_resumes_from_its_whole_layers() {
        let dir = temp_dir("resume");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let params = SdrParams::default();
        let (member, leaf, n) = ([8u8; 32], b"leaf".as_slice(), 3_000u64);
        let stopped = stop_after(&store, leaf, n, 4);
        assert!(matches!(stopped, Labelling::Stopped { layers: 4 }));
        let leaf_dir = store.leaf_dir(9, &member, leaf);
        let layers_path = leaf_dir.join(format!("{n}.layers"));
        let layer = n * NODE_BYTES as u64;
        assert_eq!(fs::metadata(&layers_path).unwrap().len(), 4 * layer);
        let manifest = |leaf_dir: &Path| {
            Manifest::parse(&fs::read_to_string(leaf_dir.join(format!("{n}.kept"))).unwrap())
                .unwrap()
        };
        assert_eq!(manifest(&leaf_dir).layers.len(), 4);
        assert_eq!(
            *store.pending(),
            0,
            "what it wrote is on disk, the rest no more pending"
        );
        assert!(
            store.find(9, &member, leaf, |_| true).is_none(),
            "not labelled yet"
        );
        // A crash midway through the next layer left part of it.
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&layers_path)
            .unwrap();
        file.write_all(&[0xFF; 100]).unwrap();
        drop(file);

        let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
        assert_eq!(admitted.resumes_from(), 4);
        assert_eq!(
            *store.pending(),
            label_bytes(n) - 4 * layer,
            "only the rest to write"
        );
        assert_eq!(
            manifest(&leaf_dir).layers.len(),
            4,
            "listed until the next layer is"
        );
        let handed = Mutex::new(Vec::new());
        let labelled = admitted
            .label_kept(&params, &|| false, &|done| {
                handed.lock().unwrap().push(done)
            })
            .unwrap();
        let Labelling::Labelled(Labelled { comm_c, last, kept }) = labelled else {
            panic!("labelled to its end");
        };
        assert!(kept);
        assert_eq!(
            *handed.lock().unwrap(),
            (5..=params.layers).collect::<Vec<_>>()
        );
        let mut layers = Vec::new();
        let key = quil_crypto::sdr::replica_key(&member, leaf, 9);
        let (expected_last, columns) =
            quil_crypto::storage_proof::label_leaf(n, &key, &params, &mut |_, layer| {
                layers.push(layer.to_vec())
            });
        let expected_comm_c = quil_crypto::storage_proof::MerkleTree::from_digests(columns.clone())
            .commitment(quil_crypto::storage_proof::Tree::Column);
        assert_eq!((last, comm_c), (expected_last.clone(), expected_comm_c));
        let found = store.find(9, &member, leaf, |count| count == n).unwrap();
        assert_eq!(found.comm_c, expected_comm_c);
        assert_eq!(found.columns().unwrap(), columns);
        assert_eq!(found.last_layer().unwrap(), expected_last);
        for (layer, v) in [(0usize, 0u64), (3, 2_999), (4, 0), (7, 1_234), (10, n - 1)] {
            assert_eq!(
                found.label(layer, v),
                Some(hash::to_bytes(&layers[layer][v as usize])),
                "layer {layer} node {v}"
            );
        }
        assert_eq!(*store.pending(), 0);

        assert!(
            !leaf_dir.join(format!("{n}.kept")).exists(),
            "complete, `ready` stands for the layers"
        );
        // A manifest listing more layers than were written resumes from
        // those written; one of an earlier build's format, from none.
        let other = b"other".as_slice();
        assert!(matches!(
            stop_after(&store, other, n, 2),
            Labelling::Stopped { layers: 2 }
        ));
        let other_dir = store.leaf_dir(9, &member, other);
        let mut listed = manifest(&other_dir);
        listed.layers.push([7u8; 32]);
        write_manifest(&other_dir, n, &listed).unwrap();
        let admitted = store.admit(9, &member, other, n, Stage::Ahead).unwrap();
        assert_eq!(admitted.resumes_from(), 2);
        drop(admitted);
        fs::write(other_dir.join(format!("{n}.kept")), "2").unwrap();
        let admitted = store.admit(9, &member, other, n, Stage::Ahead).unwrap();
        assert_eq!(admitted.resumes_from(), 0);
        drop(admitted);
        // Given up for good, nothing stays.
        assert!(matches!(
            stop_after(&store, other, n, 1),
            Labelling::Stopped { layers: 1 }
        ));
        store.discard(9, &member, other, n);
        assert_eq!(files_under(&other_dir), Vec::<PathBuf>::new());
        // At the snapshot, a stopped labelling keeps its whole layers too,
        // until discarded.
        let admitted = store.admit(9, &member, other, n, Stage::Snapshot).unwrap();
        let done = AtomicU64::new(0);
        let stopped = admitted
            .label_kept(&params, &|| done.load(Ordering::SeqCst) >= 2, &|labelled| {
                done.store(labelled as u64, Ordering::SeqCst)
            })
            .unwrap();
        assert!(matches!(stopped, Labelling::Stopped { layers: 2 }));
        assert_eq!(manifest(&other_dir).stage, Stage::Snapshot);
        store.discard(9, &member, other, n);
        assert_eq!(files_under(&other_dir), Vec::<PathBuf>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    thread_local! {
        /// Bytes of a chunk for this thread's label writers, instead of
        /// [`FLUSH_CHUNK_BYTES`] ([`chunk_bytes`]).
        pub(super) static TEST_CHUNK_BYTES: Cell<Option<usize>> = const { Cell::new(None) };
        /// Chunks this thread's label writers push before the next push
        /// panics, before it writes, as a process stopped between chunks.
        static PUSHES_BEFORE_CRASH: Cell<Option<u32>> = const { Cell::new(None) };
        /// Chunks this thread's writers pushed through a flush gate, and
        /// their bytes ([`take_gated_pushes`]).
        pub(super) static GATED_PUSHES: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
    }

    pub(super) fn gated_push(gated: bool, len: u64) {
        if gated {
            GATED_PUSHES.with(|pushes| {
                let (chunks, bytes) = pushes.get();
                pushes.set((chunks + 1, bytes + len));
            });
        }
    }

    pub(super) fn crash_before_push() {
        PUSHES_BEFORE_CRASH.with(|left| match left.get() {
            Some(0) => {
                left.set(None);
                panic!("stopped between two chunks of labels");
            }
            Some(pushes) => left.set(Some(pushes - 1)),
            None => {}
        });
    }

    /// Writes nowhere, counting the chunk writers between their write and
    /// the end of its push, and the bytes they wrote not yet pushed, as a
    /// page cache's dirty pages: each and the most at once.
    #[derive(Default)]
    struct Gauge {
        writing: AtomicU64,
        most_writing: AtomicU64,
        unpushed: AtomicU64,
        most_unpushed: AtomicU64,
    }

    struct Probe(Arc<Gauge>);

    impl Write for Probe {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let gauge = &self.0;
            let writing = gauge.writing.fetch_add(1, Ordering::SeqCst) + 1;
            gauge.most_writing.fetch_max(writing, Ordering::SeqCst);
            let len = bytes.len() as u64;
            let unpushed = gauge.unpushed.fetch_add(len, Ordering::SeqCst) + len;
            gauge.most_unpushed.fetch_max(unpushed, Ordering::SeqCst);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ChunkSink for Probe {
        fn push(&mut self, _start: u64, len: u64) -> std::io::Result<()> {
            // A disk taking its time.
            std::thread::sleep(Duration::from_millis(2));
            self.0.unpushed.fetch_sub(len, Ordering::SeqCst);
            self.0.writing.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }

        fn sync(&mut self, _all: bool) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// However many leaves write labels at once, no more than
    /// [`FLUSH_PERMITS`] chunks of them are being written to disk at a time,
    /// so labels written and not yet on disk stay below a chunk a permit,
    /// and as many as that are, keeping a disk's queue busy (2026-11-05:
    /// leaves ending their layers together synced about 13 GB at once, and
    /// the stores' commits waited seconds for their fsyncs behind them).
    #[test]
    fn label_writers_push_at_most_their_permits_of_chunks_at_once() {
        const WRITERS: usize = 16;
        const CHUNK: usize = 4096;
        let gate = FlushGate::new(FLUSH_PERMITS);
        let gauge = Arc::new(Gauge::default());
        let start = std::sync::Barrier::new(WRITERS);
        let waits = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for writer in 0..WRITERS {
                let (gate, gauge, start, waits) = (&gate, gauge.clone(), &start, &waits);
                scope.spawn(move || {
                    let tally = FlushTally::default();
                    let mut chunked =
                        ChunkedWriter::new(Probe(gauge), 0, CHUNK, Some(gate), &tally);
                    start.wait();
                    // Eight chunks and part of one, in a layer's pieces.
                    let bytes = vec![writer as u8; 8 * CHUNK + 1_000];
                    for piece in bytes.chunks(1_000) {
                        chunked.write_all(piece).unwrap();
                    }
                    chunked.sync(false).unwrap();
                    waits.fetch_add(tally.waits.get(), Ordering::SeqCst);
                });
            }
        });
        let most = gauge.most_writing.load(Ordering::SeqCst);
        let unpushed = gauge.most_unpushed.load(Ordering::SeqCst);
        assert!(
            most <= FLUSH_PERMITS as u64 && unpushed <= (FLUSH_PERMITS * CHUNK) as u64,
            "{WRITERS} label writers: {most} chunks written at once, {unpushed} bytes not on \
             disk at once, past {FLUSH_PERMITS} permits of {CHUNK} bytes"
        );
        assert_eq!(
            most, FLUSH_PERMITS as u64,
            "as many chunks written at once as permits"
        );
        assert!(
            waits.load(Ordering::SeqCst) > 0,
            "writers past the permits waited, counted for the log"
        );
        assert_eq!(gauge.unpushed.load(Ordering::SeqCst), 0, "all pushed");
    }

    /// A store's synced commit waits behind the label chunks in flight, so
    /// a slow disk gets chunks it writes within [`FLUSH_TARGET`]: two 16
    /// MiB chunks took a disk writing 80 MB/s 419 ms, and a frame's votes
    /// wait on about 8 commits in turn (2026-11-07). Each push is timed
    /// with the others in flight, as on a disk.
    #[test]
    fn label_chunks_are_cut_to_what_a_slow_disk_writes_within_the_target() {
        let now = Instant::now();
        for mb_s in [80.0, 150.0, 400.0] {
            let rate = mb_s * 1e6;
            let mut pace = Pace::new();
            let mut chunk = pace.chunk();
            assert_eq!(chunk, FLUSH_CHUNK_BYTES, "the most until a push is timed");
            for _ in 0..2 * PACE_WINDOW {
                let took = Duration::from_secs_f64((FLUSH_PERMITS * chunk) as f64 / rate);
                pace.pushed(chunk as u64, took, now);
                chunk = pace.chunk();
            }
            let behind = Duration::from_secs_f64((FLUSH_PERMITS * chunk) as f64 / rate);
            assert!(
                behind <= FLUSH_TARGET,
                "PACE-LABELS-CUT: at {mb_s} MB/s a store's commit waits {behind:?} behind \
                 {FLUSH_PERMITS} chunks of {chunk} bytes of labels, past {FLUSH_TARGET:?}"
            );
            assert!(
                behind >= FLUSH_TARGET / 2,
                "PACE-LABELS-CUT: at {mb_s} MB/s chunks of {chunk} bytes take {behind:?}, \
                 well under {FLUSH_TARGET:?}: labelling is slowed for nothing"
            );
        }
    }

    /// A disk too slow even for the smallest chunk in [`FLUSH_TARGET`]
    /// gets as long as a push or sync overran it between them, so the
    /// stores' commits get about half of it; labels still get the rest.
    #[test]
    fn a_disk_too_slow_for_the_smallest_chunk_gets_time_between_chunks() {
        let gate = FlushGate::new(FLUSH_PERMITS);
        let tally = FlushTally::default();
        let over = Duration::from_millis(100);
        let pushed = Instant::now();
        let chunk = gate.pushed(FLUSH_MIN_CHUNK_BYTES as u64, FLUSH_TARGET + over, &tally);
        drop(gate.take(&tally));
        let waited = pushed.elapsed();
        assert!(
            chunk == FLUSH_MIN_CHUNK_BYTES && waited >= over,
            "PACE-LABELS-OVERRUN: a push of {FLUSH_MIN_CHUNK_BYTES} bytes overran \
             {FLUSH_TARGET:?} by {over:?}: the next chunk is {chunk} bytes, its permit \
             came {waited:?} after"
        );
        let synced = Instant::now();
        gate.synced(FLUSH_TARGET + over, &tally);
        drop(gate.take(&tally));
        let waited = synced.elapsed();
        assert!(
            waited >= over,
            "PACE-LABELS-OVERRUN: a sync overran {FLUSH_TARGET:?} by {over:?}: the next \
             permit came {waited:?} after"
        );
        assert_eq!(
            tally.overruns.get(),
            2,
            "each overrun is counted for the log"
        );
        assert!(tally.overran.get() >= 2 * over);
    }

    /// A disk writing a whole chunk well within [`FLUSH_TARGET`] keeps
    /// whole chunks and no waits between them: labelling is not slowed
    /// there. A layer's small end, which costs more than its bytes, does
    /// not count as the disk's speed.
    #[test]
    fn a_fast_disk_keeps_whole_chunks_and_no_waits() {
        let gate = FlushGate::new(FLUSH_PERMITS);
        let tally = FlushTally::default();
        for _ in 0..2 * PACE_WINDOW {
            // 1.7 GB/s.
            let chunk = gate.pushed(FLUSH_CHUNK_BYTES as u64, Duration::from_millis(10), &tally);
            assert_eq!(
                chunk, FLUSH_CHUNK_BYTES,
                "PACE-LABELS-FAST: a fast disk's chunks are cut"
            );
        }
        gate.synced(FLUSH_TARGET, &tally);
        for _ in 0..PACE_WINDOW {
            let chunk = gate.pushed(4096, Duration::from_millis(5), &tally);
            assert_eq!(
                chunk, FLUSH_CHUNK_BYTES,
                "PACE-LABELS-FAST: a layer's small ends cut the chunks"
            );
        }
        assert!(
            gate.pace().resume.is_none() && tally.overruns.get() == 0,
            "PACE-LABELS-FAST: a fast disk's labels wait between chunks"
        );
    }

    /// Writes nowhere, taking as long to push as a disk writing `rate`
    /// bytes a second, and lists each push's bytes.
    struct SlowDisk {
        rate: f64,
        pushes: Vec<u64>,
    }

    impl Write for SlowDisk {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ChunkSink for SlowDisk {
        fn push(&mut self, _start: u64, len: u64) -> std::io::Result<()> {
            std::thread::sleep(Duration::from_secs_f64(len as f64 / self.rate));
            self.pushes.push(len);
            Ok(())
        }

        fn sync(&mut self, _all: bool) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A label writer on a slow disk cuts its chunks once it has timed one:
    /// each takes the disk no longer than [`FLUSH_TARGET`]. A busier disk
    /// only makes them smaller.
    #[test]
    fn a_label_writer_on_a_slow_disk_cuts_its_chunks_after_the_first() {
        // 32 MiB/s: the first 16 MiB chunk takes it 500 ms.
        let rate = (32u64 << 20) as f64;
        let gate = FlushGate::new(FLUSH_PERMITS);
        let tally = FlushTally::default();
        let disk = SlowDisk {
            rate,
            pushes: Vec::new(),
        };
        let mut writer = ChunkedWriter::new(disk, 0, FLUSH_CHUNK_BYTES, Some(&gate), &tally);
        let labels = vec![7u8; FLUSH_CHUNK_BYTES + (8 << 20)];
        for piece in labels.chunks(64 << 10) {
            writer.write_all(piece).unwrap();
        }
        writer.flush().unwrap();
        let pushes = std::mem::take(&mut writer.inner.pushes);
        assert_eq!(pushes.iter().sum::<u64>(), labels.len() as u64);
        assert_eq!(
            pushes[0], FLUSH_CHUNK_BYTES as u64,
            "the first chunk is whole"
        );
        let longest = pushes[1..].iter().copied().max().unwrap_or(0);
        let took = Duration::from_secs_f64(longest as f64 / rate);
        assert!(
            pushes.len() > 2 && took <= FLUSH_TARGET,
            "PACE-LABELS-WIRED: after a chunk took the disk 500 ms, {} more chunks, the \
             largest {longest} bytes taking it {took:?}, past {FLUSH_TARGET:?}",
            pushes.len() - 1
        );
    }

    /// A labelling stopped between two chunks of a layer, as by a crash or
    /// a kill, leaves every layer it listed whole on disk, and the next
    /// attempt at the leaf's count goes on from them: a layer's chunks are
    /// pushed as they are written, its last part with its sync, and only
    /// then is it listed (2026-11-05). Stopped right after a layer is
    /// listed, nothing of the next is on disk; stopped after the next
    /// layer's first chunk, the next attempt cuts that chunk off. Either way
    /// the leaf's labels end as the leaf labelled at once.
    #[test]
    fn a_labelling_stopped_between_chunks_keeps_its_listed_layers_whole() {
        let dir = temp_dir("chunks");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let params = SdrParams::default();
        let (member, n) = ([8u8; 32], 3_000u64);
        let layer = n * NODE_BYTES as u64;
        // A layer of 96,000 bytes spans 23 chunks and part of one, so three
        // layers end within a chunk too.
        const CHUNK: u64 = 4096;
        TEST_CHUNK_BYTES.with(|chunk| chunk.set(Some(CHUNK as usize)));
        for (leaf, pushed) in [(b"listed".as_slice(), 0u32), (b"chunked".as_slice(), 1)] {
            let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
            let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                admitted.label_kept(&params, &|| false, &|done| {
                    // Layer 3 is labelled, layers 0 to 2 listed.
                    if done == 4 {
                        PUSHES_BEFORE_CRASH.with(|left| left.set(Some(pushed)));
                    }
                })
            }));
            assert!(stopped.is_err(), "{leaf:?}: stopped between chunks");
            let leaf_dir = store.leaf_dir(9, &member, leaf);
            let layers_path = leaf_dir.join(format!("{n}.layers"));
            assert_eq!(
                fs::metadata(&layers_path).unwrap().len(),
                3 * layer + u64::from(pushed) * CHUNK,
                "{leaf:?}: the listed layers and the chunks pushed since are on disk"
            );
            let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
            assert_eq!(
                admitted.resumes_from(),
                3,
                "{leaf:?}: each listed layer is whole"
            );
            let Labelling::Labelled(labelled) =
                admitted.label_kept(&params, &|| false, &|_| {}).unwrap()
            else {
                panic!("{leaf:?}: labelled to its end");
            };
            assert!(labelled.kept);
            assert_eq!(
                fs::metadata(&layers_path).unwrap().len(),
                params.layers as u64 * layer,
                "{leaf:?}: what the stop left of the next layer is cut off"
            );
            let mut layers = Vec::new();
            let key = quil_crypto::sdr::replica_key(&member, leaf, 9);
            let (last, columns) =
                quil_crypto::storage_proof::label_leaf(n, &key, &params, &mut |_, layer| {
                    layers.push(layer.to_vec())
                });
            let comm_c = quil_crypto::storage_proof::MerkleTree::from_digests(columns)
                .commitment(quil_crypto::storage_proof::Tree::Column);
            assert_eq!((labelled.last, labelled.comm_c), (last, comm_c), "{leaf:?}");
            let found = store.find(9, &member, leaf, |count| count == n).unwrap();
            for (layer, v) in [(2usize, n - 1), (3, 0), (3, 1_234), (10, n - 1)] {
                assert_eq!(
                    found.label(layer, v),
                    Some(hash::to_bytes(&layers[layer][v as usize])),
                    "{leaf:?}: layer {layer} node {v}"
                );
            }
        }
        TEST_CHUNK_BYTES.with(|chunk| chunk.set(None));
        assert_eq!(*store.pending(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A seat's leaves its snapshot could not label within the renewal's
    /// grace wait for memory before every leaf it could, a seat's together,
    /// seats with fewer of them first.
    #[test]
    fn leaves_only_labelling_ahead_registers_wait_first() {
        use quil_crypto::storage_proof::data_node_count;
        // At 10 s frames, half the grace of 320 frames labels about 10.7
        // million nodes.
        let epoch = 1317;
        let bytes = |nodes: u64| u128::from(nodes) * 30;
        assert_eq!(data_node_count(bytes(10_000_000) as u64), 10_000_000);
        let (small, large) = (bytes(10_000_000), bytes(30_000_000));
        let mut orders = ahead_orders(epoch, 10, &[small, large]);
        let pair = ahead_orders(epoch, 5, &[large, large]);
        assert_eq!(
            orders
                .iter()
                .map(|order| (order.deferrable, order.seat_leaves))
                .collect::<Vec<_>>(),
            vec![(true, 1), (false, 1)]
        );
        orders.extend(pair);
        orders.sort();
        assert_eq!(
            orders
                .iter()
                .map(|order| (order.deferrable, order.seat, order.leaf))
                .collect::<Vec<_>>(),
            vec![(false, 10, 1), (false, 5, 0), (false, 5, 1), (true, 10, 0)],
            "the one-leaf seat's large leaf, then the pair's, then the small one"
        );
    }

    #[test]
    fn kept_labels_are_the_leaf_labelling_and_go_when_their_epoch_has() {
        let dir = temp_dir("test");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let params = SdrParams::default();
        let (member, leaf) = ([7u8; 32], b"leaf".as_slice());
        let n = 3_000u64;
        let Labelled { comm_c, last, .. } = keep(&store, 9, &member, leaf, n);
        let mut layers = Vec::new();
        let key = quil_crypto::sdr::replica_key(&member, leaf, 9);
        let (expected_last, columns) =
            quil_crypto::storage_proof::label_leaf(n, &key, &params, &mut |_, layer| {
                layers.push(layer.to_vec())
            });
        assert_eq!(last, expected_last);
        let kept = store.find(9, &member, leaf, |count| count == n).unwrap();
        assert_eq!((kept.n, kept.comm_c), (n, comm_c));
        assert_eq!(kept.columns().unwrap(), columns);
        assert_eq!(kept.last_layer().unwrap(), expected_last);
        for (layer, v) in [(0usize, 0u64), (4, 1_234), (10, n - 1)] {
            assert_eq!(
                kept.label(layer, v),
                Some(hash::to_bytes(&layers[layer][v as usize]))
            );
        }
        assert!(kept.label(11, 0).is_none() && kept.label(0, n).is_none());
        assert!(store.find(9, &member, leaf, |count| count != n).is_none());
        assert!(store.find(9, &[8u8; 32], leaf, |_| true).is_none());
        assert!(store.find(10, &member, leaf, |_| true).is_none());
        store.evict_before(9);
        assert!(store.find(9, &member, leaf, |_| true).is_some());
        keep(&store, 9, &member, b"other", 64);
        store.forget(9, &member, leaf);
        assert!(store.find(9, &member, leaf, |_| true).is_none());
        assert!(store.find(9, &member, b"other", |_| true).is_some());
        store.evict_before(10);
        assert!(store.find(9, &member, leaf, |_| true).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A leaf is labelled and kept only with [`DISK_MARGIN`] times its
    /// labels free above the floor, beside what the leaves being labelled
    /// have still to write; a refused leaf leaves no files, not even those an
    /// earlier attempt left.
    #[test]
    fn benchmark_floor_applies_to_admission_and_retention_without_changing_node_defaults() {
        let dir = temp_dir("benchmark-floor");
        let free = Arc::new(AtomicU64::new(1 << 30));
        let production = LabelStore::with_space(dir.join("production"), space(&free));
        let benchmark = LabelStore::with_space(dir.join("benchmark"), space(&free))
            .with_disk_floor(crate::storage_readiness::disk_floor);
        assert!(production
            .admit(9, &[7; 32], b"leaf", 4, Stage::Ahead)
            .is_none());
        keep(&benchmark, 9, &[7; 32], b"leaf", 4);
        assert!(
            benchmark.keep_floor().is_none(),
            "benchmark labels survive below the production floor"
        );
        assert!(benchmark.find(9, &[7; 32], b"leaf", |_| true).is_some());
        let needed = crate::storage_readiness::disk_floor(TOTAL) + DISK_MARGIN * label_bytes(4);
        free.store(needed - 1, Ordering::SeqCst);
        assert!(benchmark
            .admit(9, &[7; 32], b"next", 4, Stage::Ahead)
            .is_none());
        free.store(needed, Ordering::SeqCst);
        assert!(benchmark
            .admit(9, &[7; 32], b"next", 4, Stage::Ahead)
            .is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_leaf_is_kept_only_with_room_for_its_labels_above_the_floor() {
        assert_eq!(disk_floor(TOTAL), 10 << 30);
        assert_eq!(disk_floor(20 << 30), DISK_FLOOR_MIN_BYTES);
        let dir = temp_dir("room");
        let free = Arc::new(AtomicU64::new(0));
        let store = LabelStore::with_space(dir.clone(), space(&free));
        let (member, n) = ([7u8; 32], 3_000u64);
        let bytes = label_bytes(n);
        assert_eq!(bytes, n * 12 * NODE_BYTES as u64);
        let enough = disk_floor(TOTAL) + DISK_MARGIN * bytes;
        // What a crash left of an attempt at the count.
        let leaf_dir = store.leaf_dir(9, &member, b"leaf");
        fs::create_dir_all(&leaf_dir).unwrap();
        fs::write(leaf_dir.join(format!("{n}.layers")), [1u8; 64]).unwrap();

        free.store(enough - 1, Ordering::SeqCst);
        assert!(store.admit(9, &member, b"leaf", n, Stage::Ahead).is_none());
        assert_eq!(
            files_under(&dir),
            Vec::<PathBuf>::new(),
            "a refused leaf leaves no files"
        );
        assert!(store.admit(9, &member, b"leaf", n, Stage::Ahead).is_none());
        assert_eq!(
            store.refused.lock().unwrap().len(),
            1,
            "logged once a leaf, epoch and stage"
        );

        free.store(enough, Ordering::SeqCst);
        let admitted = store
            .admit(9, &member, b"leaf", n, Stage::Ahead)
            .expect("room");
        assert!(
            store.admit(9, &member, b"other", n, Stage::Ahead).is_none(),
            "what the first has still to write is not room"
        );
        free.store(enough + bytes, Ordering::SeqCst);
        drop(
            store
                .admit(9, &member, b"other", n, Stage::Ahead)
                .expect("room for both"),
        );
        assert_eq!(
            *store.pending(),
            bytes,
            "a dropped admission frees its room"
        );
        assert!(admitted.label(&SdrParams::default()).unwrap().kept);
        assert_eq!(*store.pending(), 0);
        assert!(store
            .find(9, &member, b"leaf", |count| count == n)
            .is_some());

        let unknown = LabelStore::with_space(dir.clone(), Box::new(|_| None));
        assert!(
            unknown
                .admit(9, &member, b"third", n, Stage::Snapshot)
                .is_none(),
            "free space unknown"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Two processes of a node on one host keep labels on one filesystem
    /// ([`LabelStore::use_ledger`]): what one's leaves have still to write
    /// is no room for the other's, and is room again as it is written or
    /// given up. Each counting only its own, both leaves were admitted.
    #[test]
    fn another_processs_labels_still_to_write_are_no_room() {
        let base = temp_dir("host-pending");
        let (a_dir, b_dir) = (base.join("a"), base.join("b"));
        let ledger = host_ledger_dir(&a_dir);
        assert_eq!(ledger, host_ledger_dir(&b_dir), "one ledger beside both");
        let free = Arc::new(AtomicU64::new(0));
        let store = |dir: &Path, id: &str| {
            let store = LabelStore::with_space(dir.to_path_buf(), space(&free));
            let record: &'static HostLedger =
                Box::leak(Box::new(HostLedger::open_as(&ledger, id).unwrap()));
            assert!(store.use_ledger(record));
            (store, record)
        };
        let ((a, _), (b, b_record)) = (store(&a_dir, "a"), store(&b_dir, "b"));
        let (member, n) = ([7u8; 32], 3_000u64);
        let bytes = label_bytes(n);
        let enough = disk_floor(TOTAL) + DISK_MARGIN * bytes;

        free.store(enough, Ordering::SeqCst);
        let admitted = a.admit(9, &member, b"leaf", n, Stage::Ahead).expect("room");
        assert_eq!(b_record.others_labels_pending(), bytes);
        assert!(
            b.admit(9, &member, b"other", n, Stage::Snapshot).is_none(),
            "another process's labels still to write are no room"
        );
        free.store(enough + bytes, Ordering::SeqCst);
        drop(
            b.admit(9, &member, b"other", n, Stage::Snapshot)
                .expect("room for both"),
        );
        assert_eq!(
            a.others_pending(),
            0,
            "another process's dropped admission frees its room"
        );

        free.store(enough, Ordering::SeqCst);
        assert!(admitted.label(&SdrParams::default()).unwrap().kept);
        assert!(
            b.admit(9, &member, b"third", n, Stage::Snapshot).is_some(),
            "room again once another process's labels are written"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// A leaf that runs out of room while it is labelled is labelled to the
    /// end, for its caller to encode from, but not kept: none of its files
    /// remain.
    #[test]
    fn a_leaf_out_of_room_midway_is_labelled_but_leaves_no_files() {
        let dir = temp_dir("midway");
        let reads = Arc::new(AtomicU64::new(0));
        // Room for the admission and the first three layers, then none.
        let space: SpaceSource = {
            let reads = reads.clone();
            Box::new(move |_| {
                let read = reads.fetch_add(1, Ordering::SeqCst);
                Some(FsUsage {
                    total_bytes: TOTAL,
                    free_bytes: if read < 4 { TOTAL } else { 0 },
                    ..FsUsage::default()
                })
            })
        };
        let store = LabelStore::with_space(dir.clone(), space);
        let params = SdrParams::default();
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 3_000u64);
        let admitted = store.admit(9, &member, leaf, n, Stage::Snapshot).unwrap();
        let labelled = admitted.label(&params).unwrap();
        assert!(!labelled.kept);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            5,
            "no writes once out of room"
        );
        let key = quil_crypto::sdr::replica_key(&member, leaf, 9);
        let (last, columns) =
            quil_crypto::storage_proof::label_leaf(n, &key, &params, &mut |_, _| {});
        assert_eq!(labelled.last, last);
        assert_eq!(
            labelled.comm_c,
            quil_crypto::storage_proof::MerkleTree::from_digests(columns)
                .commitment(quil_crypto::storage_proof::Tree::Column)
        );
        assert_eq!(files_under(&dir), Vec::<PathBuf>::new());
        assert!(store.find(9, &member, leaf, |_| true).is_none());
        assert_eq!(*store.pending(), 0);
        assert_eq!(store.refused.lock().unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A leaf labelled ahead that runs out of room midway stops at the layer
    /// the room ran out after, instead of labelling its other layers for
    /// labels it would not keep: it leaves no files, logs its refusal and
    /// frees its room. Once room returns the leaf is admitted again and
    /// labelled and kept to its end.
    #[test]
    fn a_leaf_labelled_ahead_out_of_room_midway_stops_there() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        let dir = temp_dir("ahead-midway");
        let reads = Arc::new(AtomicU64::new(0));
        let full = Arc::new(AtomicBool::new(false));
        // Room for the admission and the first three layers, then none until
        // the filesystem is no longer full.
        let space: SpaceSource = {
            let (reads, full) = (reads.clone(), full.clone());
            Box::new(move |_| {
                let read = reads.fetch_add(1, Ordering::SeqCst);
                if read == 4 {
                    full.store(true, Ordering::SeqCst);
                }
                Some(FsUsage {
                    total_bytes: TOTAL,
                    free_bytes: if full.load(Ordering::SeqCst) {
                        0
                    } else {
                        TOTAL
                    },
                    ..FsUsage::default()
                })
            })
        };
        let store = LabelStore::with_space(dir.clone(), space);
        let params = SdrParams::default();
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 3_000u64);
        let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
        let labelled = AtomicUsize::new(0);
        let ended = admitted
            .label_kept(&params, &|| false, &|done| {
                labelled.fetch_max(done, Ordering::SeqCst);
            })
            .unwrap();
        assert_eq!(
            labelled.load(Ordering::SeqCst),
            4,
            "labelled past the layer the room ran out after, of {}",
            params.layers
        );
        assert!(matches!(ended, Labelling::Refused));
        assert_eq!(files_under(&dir), Vec::<PathBuf>::new());
        assert!(store.find(9, &member, leaf, |_| true).is_none());
        assert_eq!(*store.pending(), 0, "its room is freed");
        assert_eq!(
            store.refused.lock().unwrap().len(),
            1,
            "the refusal is logged"
        );

        // Room again: admitted, labelled and kept to its end.
        full.store(false, Ordering::SeqCst);
        let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
        let labelled = AtomicUsize::new(0);
        let ended = admitted
            .label_kept(&params, &|| false, &|done| {
                labelled.fetch_max(done, Ordering::SeqCst);
            })
            .unwrap();
        let Labelling::Labelled(Labelled { kept, .. }) = ended else {
            panic!("the leaf was not labelled once room returned");
        };
        assert!(kept);
        assert_eq!(labelled.load(Ordering::SeqCst), params.layers);
        assert!(store.find(9, &member, leaf, |count| count == n).is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A leaf whose labelling is given up midway keeps only its whole
    /// layers and their manifest, what it had still to write counts against
    /// the room no more, and a discard leaves none of its files.
    #[test]
    fn a_leaf_given_up_midway_keeps_only_its_whole_layers() {
        let dir = temp_dir("given-up");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 1_500u64);
        let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
        let done = AtomicU64::new(0);
        let stopped = admitted
            .label_kept(
                &SdrParams::default(),
                &|| done.load(Ordering::SeqCst) >= 1,
                &|layers| done.store(layers as u64, Ordering::SeqCst),
            )
            .unwrap();
        assert!(matches!(stopped, Labelling::Stopped { layers: 1 }));
        let leaf_dir = store.leaf_dir(9, &member, leaf);
        let mut files = files_under(&dir);
        files.sort();
        assert_eq!(
            files,
            vec![
                leaf_dir.join(format!("{n}.kept")),
                leaf_dir.join(format!("{n}.layers"))
            ]
        );
        assert_eq!(
            fs::metadata(leaf_dir.join(format!("{n}.layers")))
                .unwrap()
                .len(),
            layer_bytes(n),
            "the first layer, whole"
        );
        assert_eq!(*store.pending(), 0);
        assert!(store.find(9, &member, leaf, |_| true).is_none());
        assert_eq!(store.resumable(9, &member, leaf, |_| true), Some((n, 1)));
        store.discard(9, &member, leaf, n);
        assert_eq!(files_under(&dir), Vec::<PathBuf>::new());
        assert!(
            keep(&store, 9, &member, leaf, n).kept,
            "labelled again from its start"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The leaf labelled at once at `n` nodes, keyed for `[8; 32]`'s `leaf`
    /// in epoch 9: its last layer and column commitment.
    fn labelled_at_once(leaf: &[u8], n: u64) -> (Vec<Digest>, Node) {
        let key = quil_crypto::sdr::replica_key(&[8u8; 32], leaf, 9);
        let (last, columns) =
            quil_crypto::storage_proof::label_leaf(n, &key, &SdrParams::default(), &mut |_, _| {});
        let comm_c = quil_crypto::storage_proof::MerkleTree::from_digests(columns)
            .commitment(quil_crypto::storage_proof::Tree::Column);
        (last, comm_c)
    }

    /// Kept layers are reused only as far as each matches the digest its
    /// manifest lists, and only for the labels the manifest names: a layer
    /// changed or cut short on disk (a crash, a torn write) is labelled
    /// again from there, and layers of another node count, parameters or
    /// key from none. Whatever was reused, the leaf's labels are those
    /// labelled at once.
    #[test]
    fn kept_layers_are_checked_against_their_digests_before_reuse() {
        let dir = temp_dir("checked");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let member = [8u8; 32];
        let n = 1_000u64;
        let layer = layer_bytes(n);
        let label_rest = |leaf: &[u8], from: usize| {
            let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
            assert_eq!(admitted.resumes_from(), from, "{leaf:?}");
            assert_eq!(admitted.resumed().map_or(0, |r| r.layers), from);
            let labelled = admitted.label(&SdrParams::default()).unwrap();
            assert!(labelled.kept);
            assert_eq!((labelled.last, labelled.comm_c), labelled_at_once(leaf, n));
            let found = store.find(9, &member, leaf, |count| count == n).unwrap();
            assert_eq!(found.comm_c, labelled_at_once(leaf, n).1);
        };

        // A byte changed in the third layer: the first two are reused.
        assert!(matches!(
            stop_after(&store, b"changed", n, 6),
            Labelling::Stopped { layers: 6 }
        ));
        assert_eq!(
            store.resumable(9, &member, b"changed", |_| true),
            Some((n, 6))
        );
        let layers_path = store
            .leaf_dir(9, &member, b"changed")
            .join(format!("{n}.layers"));
        let mut bytes = fs::read(&layers_path).unwrap();
        bytes[(2 * layer + 100) as usize] ^= 1;
        fs::write(&layers_path, bytes).unwrap();
        label_rest(b"changed", 2);

        // Cut short midway through the fifth layer: the first four are.
        assert!(matches!(
            stop_after(&store, b"cut", n, 6),
            Labelling::Stopped { layers: 6 }
        ));
        let cut_dir = store.leaf_dir(9, &member, b"cut");
        fs::OpenOptions::new()
            .write(true)
            .open(cut_dir.join(format!("{n}.layers")))
            .unwrap()
            .set_len(4 * layer + layer / 2)
            .unwrap();
        label_rest(b"cut", 4);

        // Labels of other parameters, another key or another count: none.
        for (leaf, change) in [
            (b"params".as_slice(), 0usize),
            (b"key".as_slice(), 1),
            (b"count".as_slice(), 2),
        ] {
            assert!(matches!(
                stop_after(&store, leaf, n, 3),
                Labelling::Stopped { layers: 3 }
            ));
            let leaf_dir = store.leaf_dir(9, &member, leaf);
            let path = leaf_dir.join(format!("{n}.kept"));
            let mut manifest = Manifest::parse(&fs::read_to_string(&path).unwrap()).unwrap();
            match change {
                0 => manifest.params = "6 8 12 32".into(),
                1 => manifest.key = hex::encode([9u8; 32]),
                _ => manifest.n = n + 1,
            }
            write_manifest(&leaf_dir, n, &manifest).unwrap();
            label_rest(leaf, 0);
        }
        assert_eq!(
            store
                .resumed()
                .into_iter()
                .map(|(leaf, _, from)| (leaf, from))
                .collect::<Vec<_>>(),
            vec![(b"changed".to_vec(), 2), (b"cut".to_vec(), 4)]
        );
        assert_eq!(*store.pending(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Labelling ahead targets the epoch after next from an epoch's first
    /// frame: in its first 16 frames, the next epoch's snapshot frame is at
    /// most 16 frames away, too close to label a leaf by.
    #[test]
    fn labelling_ahead_targets_the_epoch_after_next() {
        use quil_types::consensus::{storage_snapshot_frame, STORAGE_SNAPSHOT_OFFSET};
        // Mainnet epoch 1315 begins at frame 946,800, and its frame 16
        // snapshots the leaves registered for epoch 1316.
        assert_eq!(storage_snapshot_frame(1316), 946_816);
        for frame in 946_800..=946_815 {
            assert_eq!(ahead_epoch(frame), 1317, "frame {frame}");
        }
        assert_eq!(ahead_epoch(946_816), 1317, "the snapshot frame");
        assert_eq!(ahead_epoch(946_799), 1316, "the epoch before's last frame");
        for frame in 946_080..948_240 {
            let lead = storage_snapshot_frame(ahead_epoch(frame)) - frame;
            assert!(
                lead > STORAGE_SNAPSHOT_OFFSET,
                "frame {frame}: labelling ahead {lead} frames before the snapshot frame"
            );
        }
    }

    /// Before the stable replica key epoch (mainnet: 1429) a leaf's labels
    /// are kept under their epoch's directory, byte for byte as before it
    /// existed, and serve that epoch alone.
    #[test]
    fn labels_before_the_stable_key_epoch_keep_their_epochs_layout() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(10));
        let dir = temp_dir("epoch-layout");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 64u64);
        keep(&store, 9, &member, leaf, n);
        let leaf_dir = store.leaf_dir(9, &member, leaf);
        assert_eq!(leaf_dir.parent().unwrap(), dir.join("9"));
        let mut files = files_under(&dir);
        files.sort();
        assert_eq!(
            files,
            ["cap", "columns", "layers", "ready"].map(|kind| leaf_dir.join(format!("{n}.{kind}")))
        );
        assert!(store.find(9, &member, leaf, |_| true).is_some());
        assert!(store.find(10, &member, leaf, |_| true).is_none());
        assert_eq!(files_under(&dir).len(), 4, "looking marks nothing");
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// From the stable replica key epoch a leaf's labels serve every later
    /// epoch: kept apart from an earlier epoch's, swept with neither the
    /// epochs before nor while each epoch looks for them, and removed at the
    /// first sweep of an epoch nothing looked for them for.
    #[test]
    fn stable_labels_serve_later_epochs_and_go_once_unused() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(9));
        let dir = temp_dir("stable");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 64u64);
        let early = keep(&store, 8, &member, leaf, n);
        let stable = keep(&store, 9, &member, leaf, n);
        assert_ne!(early.comm_c, stable.comm_c, "another key");
        assert_eq!(
            store.leaf_dir(12, &member, leaf).parent().unwrap(),
            dir.join(STABLE_DIR)
        );
        let found = store.find(10, &member, leaf, |count| count == n).unwrap();
        assert_eq!(found.comm_c, stable.comm_c, "labelled for 9, found for 10");
        assert_eq!(
            store.find(8, &member, leaf, |_| true).unwrap().comm_c,
            early.comm_c
        );
        store.sweep(9);
        assert!(store.find(8, &member, leaf, |_| true).is_none());
        store.sweep(10);
        assert!(
            store
                .leaf_dir(10, &member, leaf)
                .join(format!("{n}.ready"))
                .exists(),
            "looked for for the epoch the sweep begins"
        );
        assert!(store.find(11, &member, leaf, |_| true).is_some());
        store.sweep(11);
        assert!(store.leaf_dir(11, &member, leaf).exists());
        store.sweep(12);
        assert!(
            !store.leaf_dir(12, &member, leaf).exists(),
            "nothing looked for them for 12"
        );
        assert!(store.find(12, &member, leaf, |_| true).is_none());
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Each count under the stable directory goes at the first sweep of an
    /// epoch after the latest one it was looked for or labelled for: an
    /// older count still looked for outlives a newer one labelled after it,
    /// a count with no record of use (a crash) is kept one more epoch, and
    /// every file of a count goes with it, staged ones too.
    #[test]
    fn each_stable_count_goes_once_nothing_looks_for_it() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(9));
        let dir = temp_dir("per-count");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let member = [7u8; 32];
        let leaf = b"leaf".as_slice();
        keep(&store, 9, &member, leaf, 64);
        assert!(store.find(10, &member, leaf, |n| n == 64).is_some());
        keep(&store, 10, &member, leaf, 96);
        keep(&store, 10, &member, b"other", 64);
        let leaf_dir = store.leaf_dir(10, &member, leaf);
        fs::write(leaf_dir.join("64.kept.tmp"), [0u8; 32]).unwrap();
        fs::write(leaf_dir.join("128.layers"), [1u8; 64]).unwrap();
        let names = || {
            let mut names: Vec<String> = fs::read_dir(&leaf_dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };
        store.sweep(10);
        assert_eq!(
            names(),
            [
                "128.layers",
                "128.used",
                "64.cap",
                "64.columns",
                "64.kept.tmp",
                "64.layers",
                "64.ready",
                "64.used",
                "96.cap",
                "96.columns",
                "96.layers",
                "96.ready",
                "96.used"
            ],
            "the older count still looked for stays, and the unrecorded one"
        );
        assert!(store.find(11, &member, leaf, |n| n == 96).is_some());
        store.sweep(11);
        assert_eq!(
            names(),
            ["96.cap", "96.columns", "96.layers", "96.ready", "96.used"]
        );
        assert!(
            store.find(11, &member, b"other", |_| true).is_none(),
            "another leaf nothing looked for since 10"
        );
        assert!(!store.leaf_dir(11, &member, b"other").exists());
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A sealed registration's labels are forgotten before the stable key
    /// epoch, and not from it, where they serve the epochs after.
    #[test]
    fn forgetting_a_sealed_epoch_keeps_stable_labels() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(9));
        let dir = temp_dir("forget");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 64u64);
        keep(&store, 8, &member, leaf, n);
        store.forget(8, &member, leaf);
        assert!(store.find(8, &member, leaf, |_| true).is_none());
        keep(&store, 9, &member, leaf, n);
        assert!(store.find(10, &member, leaf, |_| true).is_some());
        store.forget(9, &member, leaf);
        store.forget(10, &member, leaf);
        assert!(
            store.find(10, &member, leaf, |count| count == n).is_some(),
            "the labels for 10 and later stay"
        );
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// From the stable replica key epoch, labelling ahead for a leaf whose
    /// data changed within its padding band since an earlier epoch's attempt
    /// goes on from the whole layers that attempt kept, at their count, as
    /// the leaf's snapshot would; at a count picked from the data again it
    /// started from its first layer.
    #[test]
    fn labelling_ahead_goes_on_from_layers_kept_at_a_count_its_data_still_allows() {
        use quil_crypto::storage_proof::{padded_nodes_allowed, precompute_nodes};
        let stable = quil_types::consensus::MAINNET_STABLE_REPLICA_KEY_EPOCH
            .expect("mainnet has a stable replica key epoch");
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(stable));
        let epoch = stable + 1;
        let dir = temp_dir("ahead-moved-count");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf) = ([8u8; 32], b"leaf".as_slice());
        // Labelled ahead for the epoch before, given up after 3 layers.
        let n = precompute_nodes(3_000);
        let admitted = store.admit(stable, &member, leaf, n, Stage::Ahead).unwrap();
        let done = AtomicU64::new(0);
        let stopped = admitted
            .label_kept(
                &SdrParams::default(),
                &|| done.load(Ordering::SeqCst) >= 3,
                &|labelled| done.store(labelled as u64, Ordering::SeqCst),
            )
            .unwrap();
        assert!(matches!(stopped, Labelling::Stopped { layers: 3 }));
        // Its data grew by a node: still registrable at that count, which
        // a count picked from the data again is not.
        let exact = 3_001;
        assert!(padded_nodes_allowed(exact, n));
        assert_ne!(precompute_nodes(exact), n);
        let ahead = Leaf {
            member: &member,
            filter: &[0x5Au8; 32],
            leaf_id: leaf,
            epoch,
        };
        let order = crate::storage_jobs::AheadOrder {
            deferrable: false,
            seat_leaves: 1,
            seat: 0,
            leaf: 0,
        };
        let labelled = label_leaf_ahead(&store, &ahead, exact, order, &SdrParams::default());
        assert_eq!(
            labelled.unwrap(),
            Some(n),
            "ahead misjudged: labelled at a count of its own"
        );
        assert_eq!(
            store.resumed(),
            vec![(leaf.to_vec(), n, 3)],
            "ahead misjudged: not from its kept layers"
        );
        assert!(store
            .find(epoch, &member, leaf, |count| count == n)
            .is_some());
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// While a count is labelled, a later epoch, which looks in the same
    /// directory from the stable replica key epoch, neither finds it nor
    /// labels it again: it finds it once complete.
    #[test]
    fn a_count_is_found_only_once_complete() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(9));
        let dir = temp_dir("complete");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 1_500u64);
        let leaf_dir = store.leaf_dir(9, &member, leaf);
        let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
        let seen = std::cell::Cell::new(None);
        let labelled = admitted
            .label_kept(&SdrParams::default(), &|| false, &|layers| {
                if layers == 3 {
                    let [_, columns, ready] = paths(&leaf_dir, n);
                    seen.set(Some((
                        columns.exists() || ready.exists(),
                        store.find(10, &member, leaf, |_| true).is_some(),
                        store.admit(10, &member, leaf, n, Stage::Snapshot).is_some(),
                    )));
                }
            })
            .unwrap();
        let Labelling::Labelled(labelled) = labelled else {
            panic!("labelling never stops");
        };
        assert!(labelled.kept);
        assert_eq!(
            seen.get(),
            Some((false, false, false)),
            "mid-labelling: final files, found, admitted again"
        );
        let mut files = files_under(&dir);
        files.sort();
        let mut expected = paths(&leaf_dir, n).to_vec();
        expected.push(used_path(&leaf_dir, n));
        expected.push(leaf_dir.join(format!("{n}.cap")));
        expected.sort();
        assert_eq!(files, expected);
        let kept = store.find(10, &member, leaf, |count| count == n).unwrap();
        assert_eq!(kept.comm_c, labelled.comm_c);
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A count admitted for an epoch is not swept while it is labelled, by
    /// the sweeps of the epochs before it or after: it lands whole and is
    /// found.
    #[test]
    fn a_count_being_labelled_survives_the_sweeps_meanwhile() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(9));
        let dir = temp_dir("mid-sweep");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 1_500u64);
        let admitted = store.admit(12, &member, leaf, n, Stage::Ahead).unwrap();
        let labelled = admitted
            .label_kept(&SdrParams::default(), &|| false, &|layers| {
                if layers == 3 {
                    store.sweep(10);
                    store.sweep(11);
                    store.sweep(13);
                }
            })
            .unwrap();
        let Labelling::Labelled(labelled) = labelled else {
            panic!("labelling never stops");
        };
        assert!(labelled.kept);
        let kept = store.find(12, &member, leaf, |count| count == n).unwrap();
        assert_eq!(kept.comm_c, labelled.comm_c);
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// From the stable replica key epoch the whole layers kept for one epoch
    /// serve a later one, whose labelling goes on from them to the labels
    /// labelling at once makes.
    #[test]
    fn stable_kept_layers_resume_for_a_later_epoch() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(9));
        let dir = temp_dir("stable-resume");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([8u8; 32], b"leaf".as_slice(), 1_500u64);
        assert!(matches!(
            stop_after(&store, leaf, n, 3),
            Labelling::Stopped { layers: 3 }
        ));
        assert_eq!(store.resumable(11, &member, leaf, |_| true), Some((n, 3)));
        let admitted = store.admit(11, &member, leaf, n, Stage::Snapshot).unwrap();
        assert_eq!(admitted.resumes_from(), 3);
        let labelled = admitted.label(&SdrParams::default()).unwrap();
        let (last, comm_c) = labelled_at_once(leaf, n);
        assert!(labelled.kept);
        assert_eq!(labelled.comm_c, comm_c);
        assert_eq!(labelled.last, last);
        assert_eq!(
            store
                .find(12, &member, leaf, |count| count == n)
                .unwrap()
                .comm_c,
            comm_c
        );
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Before the stable replica key epoch (mainnet: 1429) the whole layers
    /// kept for an epoch are kept as with no such epoch: under the epoch's
    /// directory with nothing beside them, resumed for that epoch alone,
    /// removed when discarded and with their epoch.
    #[test]
    fn kept_layers_before_the_stable_key_epoch_serve_their_epoch_alone() {
        for stable in [None, Some(10)] {
            quil_types::consensus::set_stable_replica_key_epoch_for_thread(stable);
            let dir = temp_dir("epoch-kept");
            let store = LabelStore::with_space(dir.clone(), ample_space());
            let (member, leaf, n) = ([8u8; 32], b"leaf".as_slice(), 1_500u64);
            assert!(matches!(
                stop_after(&store, leaf, n, 3),
                Labelling::Stopped { layers: 3 }
            ));
            let leaf_dir = store.leaf_dir(9, &member, leaf);
            assert_eq!(leaf_dir.parent().unwrap(), dir.join("9"));
            let kept = || {
                let mut files = files_under(&leaf_dir);
                files.sort();
                files
            };
            let layers = vec![
                leaf_dir.join(format!("{n}.kept")),
                leaf_dir.join(format!("{n}.layers")),
            ];
            assert_eq!(kept(), layers);
            assert_eq!(store.resumable(9, &member, leaf, |_| true), Some((n, 3)));
            assert_eq!(store.resumable(10, &member, leaf, |_| true), None);
            let later = store.admit(10, &member, leaf, n, Stage::Ahead).unwrap();
            assert_eq!(later.resumes_from(), 0, "another epoch's key");
            drop(later);
            let again = store.admit(9, &member, leaf, n, Stage::Snapshot).unwrap();
            assert_eq!(again.resumes_from(), 3);
            drop(again);
            assert_eq!(kept(), layers);
            store.discard(9, &member, leaf, n);
            assert_eq!(kept(), Vec::<PathBuf>::new());
            assert!(matches!(
                stop_after(&store, leaf, n, 3),
                Labelling::Stopped { layers: 3 }
            ));
            assert_eq!(kept(), layers);
            store.sweep(10);
            assert!(!dir.join("9").exists(), "gone with their epoch");
            quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// From the stable replica key epoch only the sweep removes whole layers
    /// kept: a snapshot given up on or encoded at another count discards
    /// them for its epoch, and a later one goes on from them. They go at the
    /// first sweep after the epoch they were admitted for.
    #[test]
    fn stable_kept_layers_go_only_at_the_sweep() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(9));
        let dir = temp_dir("stable-discard");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([8u8; 32], b"leaf".as_slice(), 1_500u64);
        let done = AtomicU64::new(0);
        let stopped = store
            .admit(12, &member, leaf, n, Stage::Ahead)
            .unwrap()
            .label_kept(
                &SdrParams::default(),
                &|| done.load(Ordering::SeqCst) >= 3,
                &|labelled| done.store(labelled as u64, Ordering::SeqCst),
            )
            .unwrap();
        assert!(matches!(stopped, Labelling::Stopped { layers: 3 }));
        store.discard(12, &member, leaf, n);
        store.discard_others(12, &member, leaf, n + 1);
        assert_eq!(store.resumable(13, &member, leaf, |_| true), Some((n, 3)));
        for epoch in [10, 11, 12] {
            store.sweep(epoch);
            assert_eq!(
                store.resumable(13, &member, leaf, |_| true),
                Some((n, 3)),
                "admitted for 12, swept for {epoch}"
            );
        }
        store.sweep(13);
        assert_eq!(store.resumable(13, &member, leaf, |_| true), None);
        assert!(!store.leaf_dir(13, &member, leaf).exists());
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Labels found stay readable when their files are removed after: a
    /// seal reading them while the sweep or an admission at the count
    /// removes them reads them whole.
    #[test]
    fn found_labels_stay_readable_when_their_files_go() {
        let dir = temp_dir("open");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 64u64);
        keep(&store, 9, &member, leaf, n);
        let kept = store.find(9, &member, leaf, |count| count == n).unwrap();
        let (columns, last) = (kept.columns().unwrap(), kept.last_layer().unwrap());
        drop(store.admit(9, &member, leaf, n, Stage::Snapshot));
        assert!(!paths(&store.leaf_dir(9, &member, leaf), n)[1].exists());
        assert_eq!(kept.columns(), Some(columns));
        assert_eq!(kept.last_layer(), Some(last));
        let _ = fs::remove_dir_all(&dir);
    }

    /// The labels of epochs before the current one go at its first sweep,
    /// with what a crash left of them, and only then.
    #[test]
    fn a_sweep_removes_earlier_epochs_labels_once_an_epoch() {
        let dir = temp_dir("sweep");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let member = [7u8; 32];
        for epoch in [7, 8, 9] {
            keep(&store, epoch, &member, b"leaf", 64);
        }
        let crashed = store.leaf_dir(7, &member, b"crashed");
        fs::create_dir_all(&crashed).unwrap();
        fs::write(crashed.join("64.layers"), [1u8; 64]).unwrap();
        store.sweep(8);
        assert!(!crashed.exists());
        assert!(store.find(7, &member, b"leaf", |_| true).is_none());
        assert!(store.find(8, &member, b"leaf", |_| true).is_some());
        keep(&store, 7, &member, b"leaf", 64);
        store.sweep(8);
        assert!(
            store.find(7, &member, b"leaf", |_| true).is_some(),
            "once an epoch"
        );
        store.sweep(9);
        assert!(store.find(7, &member, b"leaf", |_| true).is_none());
        assert!(store.find(8, &member, b"leaf", |_| true).is_none());
        assert!(store.find(9, &member, b"leaf", |_| true).is_some());
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn stable_labels_survive_seals_and_expire_only_when_unused() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(1393));
        let dir = temp_dir("stable-lifetime");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let member = [7; 32];
        let leaf = b"stable-leaf";
        keep(&store, 1393, &member, leaf, 73);
        assert!(store.find(1392, &member, leaf, |_| true).is_none());
        let kept = store.find(1394, &member, leaf, |n| n == 73).unwrap();
        store.forget(1393, &member, leaf);
        store.sweep(1394);
        assert!(store.find(1394, &member, leaf, |_| true).is_some());
        assert!(store.find(1394, &[8; 32], leaf, |_| true).is_none());
        store.sweep(1395);
        assert!(store.find(1395, &member, leaf, |_| true).is_none());
        // Open files stay usable even after the unused cache is evicted.
        assert_eq!(kept.last_layer().unwrap().len(), 73);
        assert_eq!(kept.columns().unwrap().len(), 73);
        let _ = fs::remove_dir_all(&dir);
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
    }

    #[test]
    fn concurrent_writers_do_not_replace_an_in_progress_label_file() {
        let dir = temp_dir("busy");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let member = [7; 32];
        let first = store.admit(9, &member, b"leaf", 73, Stage::Ahead).unwrap();
        assert!(store
            .admit(9, &member, b"leaf", 73, Stage::Snapshot)
            .is_none());
        first.label(&SdrParams::default()).unwrap();
        assert!(store.find(9, &member, b"leaf", |_| true).is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sparse_seal_uses_persisted_caps_across_stable_epochs() {
        use quil_crypto::storage_proof::{self, LabelSource, SealStatement};
        quil_types::consensus::set_sealed_storage_epoch_for_thread(Some(1393));
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(1393));
        let dir = temp_dir("sparse-seal");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let member = [9; 32];
        let leaf = b"leaf-A";
        let n = 1025;
        let labels = keep(&store, 1393, &member, leaf, n);
        let raw = vec![31; n as usize * 30];
        let encoded =
            storage_proof::encode_with_labels(&raw, n, &labels.last, labels.comm_c).unwrap();
        let replicas = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let mut prior = None;
        for epoch in [1393, 1394] {
            replicas
                .put_hash(
                    epoch,
                    leaf,
                    &encoded.replica,
                    &encoded.replica_cap.to_bytes(),
                    &encoded.registration_root(),
                )
                .unwrap();
            assert!(store
                .find(epoch, &member, leaf, |_| true)
                .unwrap()
                .with_replica(&replicas, epoch, leaf)
                .is_none());
            replicas
                .put_data_cap(epoch, leaf, &encoded.data_cap)
                .unwrap();
            let kept = store
                .find(epoch, &member, leaf, |_| true)
                .unwrap()
                .with_replica(&replicas, epoch, leaf)
                .unwrap();
            let statement = SealStatement {
                member: &member,
                leaf_id: leaf,
                epoch,
                n,
                registered: storage_proof::parse_registration_root(&encoded.registration_root())
                    .unwrap(),
                beacon: b"fresh",
            };
            if let Some(old) = prior.as_ref() {
                assert!(
                    storage_proof::verify_seal(&statement, old, &SdrParams::default(), 8).is_err()
                );
            }
            let proof = storage_proof::prove_seal_with_labels(
                &[],
                &statement,
                &SdrParams::default(),
                8,
                &kept,
            )
            .unwrap();
            storage_proof::verify_seal(&statement, &proof, &SdrParams::default(), 8).unwrap();
            assert_eq!(
                kept.cap(storage_proof::Tree::Data).unwrap(),
                encoded.data_cap
            );
            prior = Some(proof);
        }
        replicas.evict_below_epoch(1394).unwrap();
        assert!(replicas.get_data_cap(1393, leaf).unwrap().is_none());
        assert!(replicas.get_data_cap(1394, leaf).unwrap().is_some());
        let _ = fs::remove_dir_all(dir);
        quil_types::consensus::set_sealed_storage_epoch_for_thread(None);
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
    }
    #[test]
    fn stable_key_warmup_has_eight_epochs_without_changing_the_cutover() {
        quil_types::consensus::set_sealed_storage_epoch_for_thread(Some(1393));
        let start = quil_types::consensus::epoch_start_frame;
        assert_eq!(ahead_epoch(start(1384)), 1386);
        assert_eq!(ahead_epoch(start(1385)), 1393);
        assert_eq!(ahead_epoch(start(1391)), 1393);
        assert_eq!(ahead_epoch(start(1392)), 1394);
        assert_eq!(ahead_epoch(start(1393)), 1395);
        assert!(!quil_types::consensus::sealed_storage_required_at(
            start(1393) - 1
        ));
        assert!(quil_types::consensus::sealed_storage_required_at(start(
            1393
        )));
        quil_types::consensus::set_sealed_storage_epoch_for_thread(None);
    }

    /// Bytes of the files under `dir`, by their length.
    fn bytes_under(dir: &Path) -> u64 {
        files_under(dir)
            .iter()
            .map(|file| fs::metadata(file).map_or(0, |meta| meta.len()))
            .sum()
    }

    /// A filesystem of [`TOTAL`] bytes whose free space is `base` less what
    /// the files under `dir` take: what a release removes comes back.
    fn space_less_files(base: &Arc<AtomicU64>, dir: &Path) -> SpaceSource {
        let (base, dir) = (base.clone(), dir.to_path_buf());
        Box::new(move |_| {
            Some(FsUsage {
                total_bytes: TOTAL,
                free_bytes: base
                    .load(Ordering::SeqCst)
                    .saturating_sub(bytes_under(&dir)),
                ..FsUsage::default()
            })
        })
    }

    /// Labels of `n` nodes kept for `member`'s `leaf` for `epoch`, their
    /// files sparse at their full size: what a release weighs.
    fn kept_sparse(store: &LabelStore, epoch: u64, member: &[u8], leaf: &[u8], n: u64) -> PathBuf {
        let dir = store.leaf_dir(epoch, member, leaf);
        fs::create_dir_all(&dir).unwrap();
        let [layers, columns, ready] = paths(&dir, n);
        let depth = SdrParams::default().layers as u64;
        File::create(layers)
            .unwrap()
            .set_len(n * depth * NODE_BYTES as u64)
            .unwrap();
        File::create(columns)
            .unwrap()
            .set_len(n * NODE_BYTES as u64)
            .unwrap();
        fs::write(ready, [0u8; 32]).unwrap();
        assert!(store
            .find(epoch, member, leaf, |count| count == n)
            .is_some());
        dir
    }

    const GIB: u64 = 1 << 30;

    /// Nodes whose labels take 3/8 GiB on disk ([`label_bytes`]).
    const EIGHTH_NODES: u64 = 1 << 20;

    /// Labels kept are a cache: once free space falls below the floor, the
    /// counts no labelling or seal holds go until free space is
    /// [`release_band`] above it, those of epochs already swept first, then
    /// the latest needed, the smallest first, and those needed soonest last
    /// (2026-11-03: labels held 175 of a node's 207 GB used, and every store
    /// failed its writes). Labelling ahead then waits until free space is
    /// back at [`resume_free`], where the release ends.
    #[test]
    fn kept_labels_go_latest_needed_first_while_free_space_is_below_the_floor() {
        let dir = temp_dir("floor");
        let base = Arc::new(AtomicU64::new(1 << 50));
        let store = LabelStore::with_space(dir.clone(), space_less_files(&base, &dir));
        let floor = disk_floor(TOTAL);
        assert_eq!(
            (floor, release_band(floor), resume_free(TOTAL)),
            (10 * GIB, 10 * GIB / 4, 15 * GIB)
        );
        let member = [7u8; 32];
        store.sweep(9);
        let stale = kept_sparse(&store, 8, &member, b"stale", EIGHTH_NODES);
        // The optimized seal cache goes with the count's labels.
        let cap = [0u8; 32];
        fs::write(stale.join(format!("{EIGHTH_NODES}.cap")), cap).unwrap();
        let soonest = kept_sparse(&store, 9, &member, b"soonest", 4 * EIGHTH_NODES);
        let small = kept_sparse(&store, 10, &member, b"small", 2 * EIGHTH_NODES);
        let large = kept_sparse(&store, 10, &member, b"large", 8 * EIGHTH_NODES);
        assert_eq!(label_bytes(EIGHTH_NODES), 3 * GIB / 8);
        let held = bytes_under(&dir);

        base.store(floor + held, Ordering::SeqCst);
        assert_eq!(store.keep_floor(), None, "at the floor, nothing goes");
        assert_eq!(bytes_under(&dir), held);

        base.store(floor - 1 + held, Ordering::SeqCst);
        let released = store.keep_floor().expect("below the floor");
        assert_eq!(released.counts, 3, "{released:?}");
        assert_eq!(released.in_use, 0);
        assert_eq!(released.epochs, vec![8, 10]);
        assert_eq!(
            released.bytes,
            label_bytes(EIGHTH_NODES) + label_bytes(10 * EIGHTH_NODES) + 3 * 32 + cap.len() as u64
        );
        for gone in [&stale, &small, &large] {
            assert_eq!(files_under(gone), Vec::<PathBuf>::new(), "{gone:?}");
        }
        assert_eq!(files_under(&soonest).len(), 3, "needed soonest, kept");
        assert!(store.find(9, &member, b"soonest", |_| true).is_some());
        let free = store.usage().unwrap().free_bytes;
        assert!(free >= floor + release_band(floor) && free < resume_free(TOTAL));

        // Labelling ahead waits until free space is back at `resume_free`;
        // a snapshot keeps its labels as before.
        let n = 3_000u64;
        assert!(!store.may_admit(11, &member, b"next", n, Stage::Ahead));
        assert!(store.admit(11, &member, b"next", n, Stage::Ahead).is_none());
        drop(
            store
                .admit(11, &member, b"now", n, Stage::Snapshot)
                .expect("room for a snapshot's labels"),
        );
        assert_eq!(store.keep_floor(), None);
        assert!(store.shortage().is_some(), "short of resume_free");
        assert!(store.admit(11, &member, b"next", n, Stage::Ahead).is_none());

        base.fetch_add(resume_free(TOTAL) - free, Ordering::SeqCst);
        assert_eq!(store.keep_floor(), None);
        assert!(store.shortage().is_none(), "ended at resume_free");
        assert!(store.may_admit(11, &member, b"next", n, Stage::Ahead));
        drop(
            store
                .admit(11, &member, b"next", n, Stage::Ahead)
                .expect("labelling ahead resumes"),
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A release passes by the labels in use: a count being labelled, one
    /// a seal has open, and one another process holds; each goes at a
    /// later check once let go.
    #[test]
    fn labels_in_use_are_not_released() {
        let dir = temp_dir("in-use");
        let base = Arc::new(AtomicU64::new(1 << 50));
        let store = LabelStore::with_space(dir.clone(), space_less_files(&base, &dir));
        let floor = disk_floor(TOTAL);
        let member = [8u8; 32];
        // Labelled ahead for epoch 9, given up after two layers and resumed.
        let n = 3_000u64;
        assert!(matches!(
            stop_after(&store, b"labelling", n, 2),
            Labelling::Stopped { layers: 2 }
        ));
        let labelling = store
            .admit(9, &member, b"labelling", n, Stage::Ahead)
            .expect("resumed");
        assert_eq!(labelling.resumes_from(), 2);
        let open = kept_sparse(&store, 10, &member, b"open", EIGHTH_NODES);
        let seal = store.find(10, &member, b"open", |_| true).unwrap();
        let elsewhere = kept_sparse(&store, 10, &member, b"elsewhere", EIGHTH_NODES);
        // Another process's lock: one on a file description of its own.
        let other = File::open(paths(&elsewhere, EIGHTH_NODES)[0].clone()).unwrap();
        other.lock_shared().unwrap();
        let free = kept_sparse(&store, 10, &member, b"free", EIGHTH_NODES);
        let labelling_dir = store.leaf_dir(9, &member, b"labelling");
        let labelling_files = files_under(&labelling_dir).len();

        base.store(floor - 1 + bytes_under(&dir), Ordering::SeqCst);
        let released = store.keep_floor().expect("below the floor");
        assert_eq!((released.counts, released.in_use), (1, 3), "{released:?}");
        assert_eq!(files_under(&free), Vec::<PathBuf>::new());
        assert_eq!(files_under(&open).len(), 3);
        assert_eq!(files_under(&elsewhere).len(), 3);
        assert_eq!(files_under(&labelling_dir).len(), labelling_files);

        drop((labelling, seal, other));
        base.store(floor - 1 + bytes_under(&dir), Ordering::SeqCst);
        let released = store.keep_floor().expect("below the floor");
        assert_eq!((released.counts, released.in_use), (3, 0), "{released:?}");
        assert_eq!(released.epochs, vec![9, 10]);
        for gone in [&open, &elsewhere, &labelling_dir] {
            assert_eq!(files_under(gone), Vec::<PathBuf>::new(), "{gone:?}");
        }
        // Nothing left to release: labelling ahead still waits.
        base.store(floor - 1 + bytes_under(&dir), Ordering::SeqCst);
        assert_eq!(store.keep_floor().map(|released| released.counts), Some(0));
        assert!(store.admit(11, &member, b"next", n, Stage::Ahead).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A release that goes on is logged again once [`SHORT_LOGGED_EVERY`]
    /// passed, not at each check, and once it ends the shards whose labels
    /// went are labelled ahead again ([`precomputed`]).
    #[test]
    fn a_release_is_logged_again_hourly_and_its_shards_labelled_ahead_after() {
        let dir = temp_dir("episode");
        let base = Arc::new(AtomicU64::new(1 << 50));
        let store = LabelStore::with_space(dir.clone(), space_less_files(&base, &dir));
        let floor = disk_floor(TOTAL);
        let (member, filter, other) = ([91u8; 32], b"released".as_slice(), b"kept".as_slice());
        for (filter, epoch) in [(filter, 12u64), (other, 13)] {
            precomputed_set().insert((member.to_vec(), filter.to_vec(), epoch), None);
        }
        assert!(precomputed(&member, filter, 12));
        let now = unix_now();
        kept_sparse(&store, 12, &member, b"first", EIGHTH_NODES);
        store.mark_shortage(&Shortage {
            since: now - 7_200,
            logged: now - SHORT_LOGGED_EVERY.as_secs() - 1,
            releases: 1,
            ..Shortage::default()
        });

        base.store(floor - 1 + bytes_under(&dir), Ordering::SeqCst);
        assert_eq!(store.keep_floor().unwrap().counts, 1);
        let logged = store.shortage().unwrap();
        assert!(logged.logged >= now, "logged again past the hour");
        assert_eq!((logged.since, logged.releases), (now - 7_200, 2));
        assert_eq!(logged.epochs, vec![12]);

        kept_sparse(&store, 12, &member, b"second", EIGHTH_NODES);
        base.store(floor - 1 + bytes_under(&dir), Ordering::SeqCst);
        assert_eq!(store.keep_floor().unwrap().counts, 1);
        let again = store.shortage().unwrap();
        assert_eq!(again.logged, logged.logged, "not again within the hour");
        assert_eq!(again.releases, 3);
        assert_eq!(again.bytes, 2 * (label_bytes(EIGHTH_NODES) + 32));
        assert!(precomputed(&member, filter, 12), "not while it goes on");

        // Above the floor, short of `resume_free`: labelling ahead still
        // waits, logged again once the hour passed.
        base.store(floor + bytes_under(&dir), Ordering::SeqCst);
        assert_eq!(store.keep_floor(), None);
        assert_eq!(store.shortage().unwrap().logged, logged.logged);
        store.mark_shortage(&Shortage {
            logged: now - SHORT_LOGGED_EVERY.as_secs() - 1,
            ..again.clone()
        });
        assert_eq!(store.keep_floor(), None);
        let waiting = store.shortage().unwrap();
        assert!(waiting.logged >= now);
        assert_eq!(waiting.releases, again.releases, "nothing released");

        base.store(resume_free(TOTAL) + bytes_under(&dir), Ordering::SeqCst);
        assert_eq!(store.keep_floor(), None);
        assert!(store.shortage().is_none());
        assert!(
            !precomputed(&member, filter, 12),
            "labelled ahead again once it ended"
        );
        assert!(precomputed(&member, other, 13), "no labels of it went");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Kept labels are verified whole, and fail the check when their last
    /// layer is torn or their column digests are not the ones committed to;
    /// labels that failed it go ([`LabelStore::discard_damaged`]), from the
    /// stable replica key epoch on too.
    #[test]
    fn kept_labels_torn_or_damaged_fail_their_check() {
        use std::os::unix::fs::FileExt;
        for stable in [None, Some(9)] {
            quil_types::consensus::set_stable_replica_key_epoch_for_thread(stable);
            let dir = temp_dir("check");
            let store = LabelStore::with_space(dir.clone(), ample_space());
            let params = SdrParams::default();
            let (member, n) = ([7u8; 32], 3_000u64);
            let Labelled { last, .. } = keep(&store, 9, &member, b"leaf", n);
            let kept = store.find(9, &member, b"leaf", |_| true).unwrap();
            assert_eq!(kept.verified_last_layer(), Some(last));
            drop(kept);
            let leaf_dir = store.leaf_dir(9, &member, b"leaf");
            let [layers, columns, _] = paths(&leaf_dir, n);
            // The second half of the last layer zeroed, its length unchanged.
            let file = fs::OpenOptions::new().write(true).open(&layers).unwrap();
            let half = n / 2;
            let last_layer = (params.layers as u64 - 1) * n;
            file.write_all_at(
                &vec![0u8; ((n - half) * NODE_BYTES as u64) as usize],
                (last_layer + half) * NODE_BYTES as u64,
            )
            .unwrap();
            drop(file);
            let torn = store.find(9, &member, b"leaf", |_| true).unwrap();
            assert!(torn.last_layer().is_some(), "read as a layer");
            assert_eq!(torn.verified_last_layer(), None);
            drop(torn);
            store.discard_damaged(9, &member, b"leaf", n);
            assert!(
                store.find(9, &member, b"leaf", |_| true).is_none(),
                "labels that failed their check are found again ({stable:?})"
            );

            keep(&store, 9, &member, b"leaf", n);
            // Another labelling's column digests: canonical, not the committed.
            let other = quil_crypto::sdr::replica_key(&[8u8; 32], b"leaf", 9);
            let (_, others) =
                quil_crypto::storage_proof::label_leaf(n, &other, &params, &mut |_, _| {});
            let mut bytes = Vec::new();
            write_digests(&mut bytes, &others).unwrap();
            fs::write(&columns, bytes).unwrap();
            let kept = store.find(9, &member, b"leaf", |_| true).unwrap();
            assert_eq!(kept.verified_last_layer(), None);
            drop(kept);
            let _ = fs::remove_dir_all(&dir);
        }
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
    }

    /// Kept labels whose column commitment is not their column digests'
    /// fail their check, though every node's labels chain to its column
    /// digest.
    #[test]
    fn kept_labels_under_another_column_commitment_fail_their_check() {
        let dir = temp_dir("commitment");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, n) = ([7u8; 32], 64u64);
        let Labelled { comm_c, last, .. } = keep(&store, 9, &member, b"leaf", n);
        let kept = store.find(9, &member, b"leaf", |_| true).unwrap();
        assert_eq!(kept.verified_last_layer(), Some(last));
        let [_, _, ready] = paths(&store.leaf_dir(9, &member, b"leaf"), n);
        let mut other = comm_c;
        other[0] ^= 1;
        fs::write(&ready, other).unwrap();
        let kept = store.find(9, &member, b"leaf", |_| true).unwrap();
        assert_eq!(kept.comm_c, other);
        assert_eq!(
            kept.verified_last_layer(),
            None,
            "labels passed their check under a column commitment they do not make"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A count another process labels is left to it: while another file
    /// description holds the count's writer lock, as a labelling in another
    /// worker process sharing the directory does, the count is not admitted
    /// and its files stay as they are; once let go, it is, and its writer
    /// file goes with its labelling.
    #[test]
    fn a_leaf_has_one_writer_at_a_time() {
        let dir = temp_dir("writer");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, n) = ([7u8; 32], 64u64);
        let Labelled { last, .. } = keep(&store, 9, &member, b"leaf", n);
        let leaf_dir = store.leaf_dir(9, &member, b"leaf");
        let other = claim(&leaf_dir, n)
            .unwrap()
            .expect("no labelling holds the count");
        assert!(claim(&leaf_dir, n).unwrap().is_none(), "claimed twice");
        assert!(
            store
                .admit(9, &member, b"leaf", n, Stage::Snapshot)
                .is_none(),
            "admitted while another process labels the count"
        );
        let kept = store
            .find(9, &member, b"leaf", |_| true)
            .expect("its labels untouched");
        assert_eq!(kept.verified_last_layer(), Some(last));
        drop((kept, other));
        let admitted = store
            .admit(9, &member, b"leaf", n, Stage::Snapshot)
            .expect("let go");
        assert!(
            claim(&leaf_dir, n).unwrap().is_none(),
            "the admission does not hold the count"
        );
        drop(admitted);
        assert_eq!(files_under(&dir), Vec::<PathBuf>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A discard leaves the whole layers of a count another process labels
    /// to it, and removes them once let go.
    #[test]
    fn a_discard_is_left_to_another_processs_labelling() {
        let dir = temp_dir("discard-other");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([8u8; 32], b"leaf".as_slice(), 1_500u64);
        assert!(matches!(
            stop_after(&store, leaf, n, 2),
            Labelling::Stopped { layers: 2 }
        ));
        let leaf_dir = store.leaf_dir(9, &member, leaf);
        let other = claim(&leaf_dir, n)
            .unwrap()
            .expect("no labelling holds the count");
        store.discard(9, &member, leaf, n);
        assert_eq!(
            store.resumable(9, &member, leaf, |_| true),
            Some((n, 2)),
            "discarded under another process's labelling"
        );
        drop(other);
        store.discard(9, &member, leaf, n);
        assert_eq!(store.resumable(9, &member, leaf, |_| true), None);
        assert_eq!(files_under(&dir), Vec::<PathBuf>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A label write that fails on the disk is a disk error
    /// (`QuilError::Io`), whose job is retried less and less often while it
    /// lasts (`crate::storage_snapshot::request`).
    #[test]
    fn a_failed_label_write_is_a_disk_error() {
        let dir = temp_dir("io");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let member = [7u8; 32];
        // The leaf's directory path is taken by a file.
        let leaf_dir = store.leaf_dir(9, &member, b"leaf");
        fs::create_dir_all(leaf_dir.parent().unwrap()).unwrap();
        fs::write(&leaf_dir, b"").unwrap();
        let admitted = store.admit(9, &member, b"leaf", 64, Stage::Ahead).unwrap();
        let Err(error) = admitted.label(&SdrParams::default()) else {
            panic!("labelled into a file's path");
        };
        assert!(
            matches!(error, QuilError::Io(_)),
            "not a disk error: {error}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A label write that fails stops the labelling at its layer (here the
    /// manifest listing the first layer cannot be written): no layer after
    /// it is labelled, about an hour per GiB of leaf on a core for nothing,
    /// and the labelling fails as a disk error.
    #[test]
    fn a_failed_label_write_stops_the_labelling_at_its_layer() {
        let dir = temp_dir("write-fails");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, n) = ([7u8; 32], 64u64);
        let leaf_dir = store.leaf_dir(9, &member, b"leaf");
        // The manifest's staged path is taken by a directory.
        fs::create_dir_all(manifest_staged(&leaf_dir, n)).unwrap();
        let admitted = store.admit(9, &member, b"leaf", n, Stage::Ahead).unwrap();
        let heard = Mutex::new(Vec::new());
        let labelling = admitted.label_kept(&SdrParams::default(), &|| false, &|done| {
            heard.lock().unwrap().push(done)
        });
        let Err(error) = labelling else {
            panic!("the manifest was written into a directory's path");
        };
        assert_eq!(
            *heard.lock().unwrap(),
            [1],
            "layers were labelled after the one whose write failed"
        );
        assert!(
            matches!(error, QuilError::Io(_)),
            "not a disk error: {error}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The node's worker processes share the labels' directory, each with
    /// its own store: a count one labels is not admitted by another, which
    /// would write the same layers file beside it (here two stores on one
    /// directory, as two worker processes have).
    #[test]
    fn a_count_one_process_labels_is_not_admitted_by_another() {
        let dir = temp_dir("two-processes");
        let first = LabelStore::with_space(dir.clone(), ample_space());
        let second = LabelStore::with_space(dir.clone(), ample_space());
        let (member, n) = ([7u8; 32], 64u64);
        let labelling = first
            .admit(9, &member, b"leaf", n, Stage::Ahead)
            .expect("room");
        let beside = second.admit(9, &member, b"leaf", n, Stage::Snapshot);
        assert!(
            beside.is_none(),
            "a second worker process admitted a count another is labelling: both write \
             its layers file, which can then hold the leaf's length but not its labels"
        );
        drop(beside);
        let Labelled { last, .. } = labelling.label(&SdrParams::default()).unwrap();
        let kept = second
            .find(9, &member, b"leaf", |count| count == n)
            .expect("labelled by the first");
        assert_eq!(kept.last_layer(), Some(last));
        drop(kept);
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use quil_types::consensus::StorageSealProfile;
    #[test]
    fn profile_views_share_host_ledger_and_publish_combined_reservations() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_dir = dir.path().join("ledger");
        let store = LabelStore::with_space(dir.path().join("labels"), ample_space());
        let two = store.for_profile(StorageSealProfile::Two);
        let three = store.for_profile(StorageSealProfile::Three);
        let record = Box::leak(Box::new(
            HostLedger::open_as(&ledger_dir, "profiles").unwrap(),
        ));
        let observer = HostLedger::open_as(&ledger_dir, "observer").unwrap();
        // Installing through an existing view also installs it for every other view.
        assert!(two.use_ledger(record));
        assert!(!store.use_ledger(record));
        assert!(!three.use_ledger(record));
        let member = [8; 32];
        let first = two
            .admit(1500, &member, b"two", 64, Stage::Snapshot)
            .unwrap();
        let second = three
            .admit(1500, &member, b"three", 64, Stage::Snapshot)
            .unwrap();
        assert_eq!(observer.others_labels_pending(), 64 * 32 * (3 + 4));
        drop(first);
        assert_eq!(observer.others_labels_pending(), 64 * 32 * 4);
        drop(second);
        assert_eq!(observer.others_labels_pending(), 0);
    }

    #[test]
    fn profile_views_share_disk_reservations_and_never_reinterpret_labels() {
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(1393));
        let dir = tempfile::tempdir().unwrap();
        let store = LabelStore::with_space(dir.path().to_owned(), ample_space());
        let two = store.for_profile(StorageSealProfile::Two);
        let three = store.for_profile(StorageSealProfile::Three);
        let member = [8; 32];
        let admitted = three
            .admit(1500, &member, b"same-sector", 64, Stage::Snapshot)
            .unwrap();
        assert_eq!(*store.pending(), 64 * 32 * 4);
        let pending = *store.pending();
        assert_eq!(*two.pending(), pending);
        let done = AtomicU64::new(0);
        let stopped = admitted
            .label_kept(
                three.params(),
                &|| done.load(Ordering::Relaxed) >= 1,
                &|n| done.store(n as u64, Ordering::Relaxed),
            )
            .unwrap();
        assert!(matches!(stopped, Labelling::Stopped { layers: 1 }));
        assert_eq!(*store.pending(), 0);
        let resumed = three
            .admit(1500, &member, b"same-sector", 64, Stage::Snapshot)
            .unwrap();
        assert_eq!(resumed.resumes_from(), 1);
        assert!(matches!(
            resumed
                .label_kept(three.params(), &|| false, &|_| {})
                .unwrap(),
            Labelling::Labelled(_)
        ));
        assert!(three
            .find(1500, &member, b"same-sector", |_| true)
            .is_some());
        assert!(two.find(1500, &member, b"same-sector", |_| true).is_none());
        assert!(store
            .find(1500, &member, b"same-sector", |_| true)
            .is_none());
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
    }
}
