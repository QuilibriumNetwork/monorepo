//! Hash storage proof labels computed ahead (decided 2026-10-26).
//!
//! A leaf's labels depend on its key (the member, the leaf and the epoch) and
//! its node count, never on its data. So a member labels the leaves it will
//! register for an epoch during the epoch before ([`precompute`]), at a count
//! the data may still change around
//! (`quil_crypto::storage_proof::precompute_nodes`), and keeps every layer on
//! disk. At the snapshot only the data's part is left
//! (`storage_snapshot::encode_member`), and the seal opens the kept layers
//! rather than labelling the leaf again (`storage_snapshot::prepare_member_seat`).
//! Labelling takes about an hour per GiB of a leaf on one core, which the
//! renewal's grace after the snapshot could not hold for a large shard.
//!
//! A leaf's labels take eleven times its replica on disk, plus its column
//! digests, until its epoch begins: a registration is sealed before then.
//! So a leaf is labelled and kept only while the labels' filesystem has room
//! for them (decided 2026-10-27): [`DISK_MARGIN`] times their bytes above a
//! floor ([`disk_floor`]), beside what the leaves being labelled have still
//! to write, checked before a leaf starts and before each of its writes. A
//! leaf refused room is labelled where it is needed instead, as by a process
//! that keeps no labels, and leaves nothing on disk.
//!
//! Labelling ahead gives its memory back while work due now waits for memory
//! (`crate::storage_jobs::Reservation::yield_requested`): the leaf being
//! labelled is given up, and labelled again from its start as soon as its
//! memory fits beside that work, unless its snapshot has labelled it
//! meanwhile.
//!
//! Labelling ahead for an epoch gives up once GLOBAL reaches the epoch's
//! snapshot frame ([`expired`]): the snapshot labels what is left itself, and
//! past the renewal's grace its seat renews without it.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use quil_crypto::sdr::SdrParams;
use quil_crypto::storage_hash::{self as hash, Digest};
use quil_crypto::storage_proof::{LabelSource, Node, NODE_BYTES};
use quil_forest::storage_health::FsUsage;
use quil_hypergraph::HypergraphCrdt;
use quil_types::error::{QuilError, Result};
use tracing::info;

/// Percent of the labels' filesystem that labels leave free, unless
/// [`DISK_FLOOR_MIN_BYTES`] is more. The stores sharing the filesystem stop
/// writing far below it (`quil_forest::storage_health::FLOOR_FREE_BYTES`).
pub const DISK_FLOOR_PERCENT: u64 = 10;

/// The least free space labels leave on their filesystem, however small it is.
pub const DISK_FLOOR_MIN_BYTES: u64 = 8 << 30;

/// A leaf is labelled and kept only with this many times its labels' bytes
/// free above the floor: room for whatever else writes to the filesystem
/// meanwhile, the stores and the logs among them.
pub const DISK_MARGIN: u64 = 2;

/// How long a shard whose leaves were refused room waits before it is
/// labelled ahead again: the labels of the epoch before free their room once
/// their registration is sealed.
const REFUSED_RETRY: Duration = Duration::from_secs(30 * 60);

/// The free space labels leave on a filesystem of `total_bytes`.
pub fn disk_floor(total_bytes: u64) -> u64 {
    (total_bytes / 100 * DISK_FLOOR_PERCENT).max(DISK_FLOOR_MIN_BYTES)
}

/// Bytes of the buffer a leaf's layers are written through.
const WRITE_BUFFER_BYTES: usize = 1 << 22;

/// Percent [`label_ahead_bytes`] adds to what labelling holds, for the
/// allocator: jemalloc rounds a large allocation up to its size class (it
/// counted 157.8 bytes a node allocated for 152.2 resident, 2026-11-01), and
/// keeps freed pages a while before it returns them, so a leaf labelled
/// again soon after it gave its memory back may still find them held.
const LABEL_AHEAD_MARGIN_PERCENT: u64 = 10;

/// Bytes labelling a leaf of `n` nodes ahead reserves
/// (`crate::storage_jobs::reserve_ahead`): what the labelling holds at its
/// peak (`quil_crypto::storage_proof::label_leaf_peak_bytes`, 152 bytes a
/// node) and [`LABEL_AHEAD_MARGIN_PERCENT`] more, and its write buffer.
/// Measured on 2026-11-01 through this path under the node's allocator, a
/// synthetic leaf of 32,339,852 nodes held 4,920,782,848 bytes resident
/// above the process's baseline at its peak (152.2 a node); this reserves
/// 5,411,417,558 for it. The snapshot's reservation
/// (`crate::storage_snapshot::encoding_bytes`, 248 bytes a node, 8.0 GB
/// there) also holds the leaf's data, replica and trees, which labelling
/// ahead does not: with it, a node sharing 19.8 GB labelled two leaves of 32
/// million nodes at a time, not three.
pub(crate) fn label_ahead_bytes(n: u64) -> u64 {
    let peak = quil_crypto::storage_proof::label_leaf_peak_bytes(n, &SdrParams::default());
    peak.saturating_add(peak / 100 * LABEL_AHEAD_MARGIN_PERCENT)
        .saturating_add(WRITE_BUFFER_BYTES as u64)
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

/// Keep this process's labels under `dir`. The first call decides; a process
/// that never calls it labels nothing ahead and relabels for its seals.
pub fn install(dir: PathBuf) {
    let _ = STORE.set(LabelStore::new(dir));
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

fn io(what: &str, path: &Path, error: std::io::Error) -> QuilError {
    QuilError::Internal(format!(
        "storage labels: {what} {}: {error}",
        path.display()
    ))
}

/// Leaves' labels on disk: `<dir>/<epoch>/<leaf>/<n>.{layers,columns,ready}`,
/// `<leaf>` naming the member and the leaf. `layers` holds every layer in
/// order, `columns` every node's column digest, and `ready`, written last,
/// the column commitment.
pub struct LabelStore {
    dir: PathBuf,
    space: SpaceSource,
    /// Bytes the leaves being labelled have still to write.
    pending: Mutex<u64>,
    /// Leaves refused room, by epoch and stage, each logged once.
    refused: Mutex<HashSet<(u64, PathBuf, Stage)>>,
    /// The epoch before which labels were last removed ([`Self::sweep`]).
    swept: AtomicU64,
    /// Leaves whose data [`precompute`] read, for tests.
    #[cfg(test)]
    leaves_read: AtomicU64,
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
    pub fn new(dir: PathBuf) -> Self {
        Self::with_space(dir, Box::new(quil_forest::storage_health::fs_usage))
    }

    /// A store reading its filesystem's free space from `space`.
    pub fn with_space(dir: PathBuf, space: SpaceSource) -> Self {
        Self {
            dir,
            space,
            pending: Mutex::new(0),
            refused: Mutex::new(HashSet::new()),
            swept: AtomicU64::new(0),
            #[cfg(test)]
            leaves_read: AtomicU64::new(0),
        }
    }

    /// Leaves whose data [`precompute`] read with this store.
    #[cfg(test)]
    pub(crate) fn leaves_read(&self) -> u64 {
        self.leaves_read.load(Ordering::SeqCst)
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
        match self.room(*pending, label_bytes(least).saturating_mul(DISK_MARGIN)) {
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

    /// Whether the labels' filesystem has room for `bytes` beside the
    /// `pending` bytes the leaves being labelled have still to write, above
    /// the floor. Free space that cannot be read leaves no room.
    fn room(&self, pending: u64, bytes: u64) -> std::result::Result<(), Shortfall> {
        // The directory is made at the first label: until then its nearest
        // existing parent is on the filesystem it will be on.
        let usage = self.dir.ancestors().find_map(|dir| (self.space)(dir));
        let needed = pending.saturating_add(bytes);
        match usage {
            Some(usage) => {
                let needed = needed.saturating_add(disk_floor(usage.total_bytes));
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
    /// labelled and kept ([`Admitted::label`]) when its filesystem has room:
    /// [`DISK_MARGIN`] times its [`label_bytes`]. What an earlier attempt at
    /// that count left is removed first. `None` when refused, logged once a
    /// leaf, epoch and stage: the leaf is then labelled where it is needed, as by a
    /// process that keeps no labels.
    pub fn admit(
        &self,
        epoch: u64,
        member: &[u8],
        leaf_id: &[u8],
        n: u64,
        stage: Stage,
    ) -> Option<Admitted<'_>> {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        for path in paths(&dir, n) {
            let _ = fs::remove_file(path);
        }
        let bytes = label_bytes(n);
        let mut pending = self.pending();
        match self.room(*pending, bytes.saturating_mul(DISK_MARGIN)) {
            Ok(()) => {
                *pending = pending.saturating_add(bytes);
                Some(Admitted {
                    store: self,
                    dir,
                    epoch,
                    member: member.to_vec(),
                    leaf_id: leaf_id.to_vec(),
                    n,
                    stage,
                    remaining: bytes,
                })
            }
            Err(shortfall) => {
                drop(pending);
                self.refuse(epoch, &dir, leaf_id, n, stage, shortfall);
                None
            }
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
        let (leaf, bytes) = (hex::encode(leaf_id), label_bytes(n));
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

    fn leaf_dir(&self, epoch: u64, member: &[u8], leaf_id: &[u8]) -> PathBuf {
        use sha3::Digest as _;
        let mut h = sha3::Sha3_256::new();
        h.update((member.len() as u32).to_be_bytes());
        h.update(member);
        h.update(leaf_id);
        self.dir
            .join(epoch.to_string())
            .join(hex::encode(h.finalize()))
    }

    /// The labels kept for `member`'s leaf `leaf_id` for `epoch` at a node
    /// count `accept` takes, if any.
    pub fn find(
        &self,
        epoch: u64,
        member: &[u8],
        leaf_id: &[u8],
        accept: impl Fn(u64) -> bool,
    ) -> Option<Kept> {
        let dir = self.leaf_dir(epoch, member, leaf_id);
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
        let expected = n * (SdrParams::default().layers * NODE_BYTES) as u64;
        if layers_file.metadata().ok()?.len() != expected {
            return None;
        }
        Some(Kept {
            n,
            comm_c,
            layers: Mutex::new(layers_file),
            columns,
            depth: SdrParams::default().layers,
        })
    }

    /// Remove the labels kept for `member`'s leaf `leaf_id` for `epoch`: its
    /// registration is sealed, and nothing opens them again.
    pub fn forget(&self, epoch: u64, member: &[u8], leaf_id: &[u8]) {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        if dir.exists() {
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// Remove the labels of epochs before `current`, once an epoch: their
    /// registrations were sealed before they began. Labels a crash, a
    /// restart or a lost seat left behind go with them.
    pub fn sweep(&self, current: u64) {
        if self.swept.fetch_max(current, Ordering::Relaxed) < current {
            self.evict_before(current);
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
    remaining: u64,
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
    }

    /// [`Self::label_until`], never given up.
    #[cfg(test)]
    pub(crate) fn label(self, params: &SdrParams) -> Result<Labelled> {
        self.label_until(params, &|| false)?
            .ok_or_else(|| QuilError::Internal("labelling that never stops stopped".into()))
    }

    /// Label the leaf at its count and keep its layers while the filesystem
    /// has room for them, checked before each layer and the columns are
    /// written. A leaf that runs out of room is labelled to the end but not
    /// kept: its files are removed and the refusal logged as
    /// [`LabelStore::admit`] logs one. Given up once `stop` says so
    /// (`quil_crypto::storage_proof::label_leaf_until`): `None`, and none of
    /// its files remain.
    pub fn label_until(
        mut self,
        params: &SdrParams,
        stop: &dyn Fn() -> bool,
    ) -> Result<Option<Labelled>> {
        let paths = paths(&self.dir, self.n);
        let result = self.write(params, &paths, stop);
        if !matches!(result, Ok(Some(Labelled { kept: true, .. }))) {
            let [layers, columns, _] = &paths;
            let _ = fs::remove_file(layers);
            let _ = fs::remove_file(columns);
            let _ = fs::remove_file(self.dir.join(format!("{}.ready.tmp", self.n)));
        }
        result
    }

    fn write(
        &mut self,
        params: &SdrParams,
        paths: &[PathBuf; 3],
        stop: &dyn Fn() -> bool,
    ) -> Result<Option<Labelled>> {
        let [layers_path, columns_path, ready_path] = paths;
        fs::create_dir_all(&self.dir).map_err(|e| io("create", &self.dir, e))?;
        let file = File::create(layers_path).map_err(|e| io("create", layers_path, e))?;
        let mut writer = Some(BufWriter::with_capacity(WRITE_BUFFER_BYTES, file));
        let (mut failure, mut shortfall) = (None, None);
        let key = quil_crypto::sdr::replica_key(&self.member, &self.leaf_id, self.epoch);
        let labelled = quil_crypto::storage_proof::label_leaf_until(
            self.n,
            &key,
            params,
            &mut |_, layer| {
                if writer.is_none() {
                    return;
                }
                if let Err(short) = self.room() {
                    // Out of room: the rest is labelled, not written.
                    shortfall = Some(short);
                    writer = None;
                    return;
                }
                match writer.as_mut().map(|writer| write_digests(writer, layer)) {
                    Some(Ok(())) => self.wrote((layer.len() * NODE_BYTES) as u64),
                    Some(Err(error)) => {
                        failure = Some(error);
                        writer = None;
                    }
                    None => {}
                }
            },
            stop,
        );
        if let Some(error) = failure {
            return Err(io("write", layers_path, error));
        }
        let Some((last, columns)) = labelled else {
            return Ok(None);
        };
        let commitment = |columns: Vec<Digest>| {
            quil_crypto::storage_proof::MerkleTree::from_digests(columns)
                .commitment(quil_crypto::storage_proof::Tree::Column)
        };
        if let Some(writer) = writer {
            writer
                .into_inner()
                .map_err(|e| io("write", layers_path, e.into_error()))?
                .sync_all()
                .map_err(|e| io("sync", layers_path, e))?;
            shortfall = self.room().err();
        }
        if let Some(shortfall) = shortfall {
            let (epoch, n, stage) = (self.epoch, self.n, self.stage);
            self.store
                .refuse(epoch, &self.dir, &self.leaf_id, n, stage, shortfall);
            return Ok(Some(Labelled {
                comm_c: commitment(columns),
                last,
                kept: false,
            }));
        }
        let mut writer = BufWriter::with_capacity(
            WRITE_BUFFER_BYTES,
            File::create(columns_path).map_err(|e| io("create", columns_path, e))?,
        );
        write_digests(&mut writer, &columns).map_err(|e| io("write", columns_path, e))?;
        writer
            .into_inner()
            .map_err(|e| io("write", columns_path, e.into_error()))?
            .sync_all()
            .map_err(|e| io("sync", columns_path, e))?;
        self.wrote((columns.len() * NODE_BYTES) as u64);
        let comm_c = commitment(columns);
        let staged = self.dir.join(format!("{}.ready.tmp", self.n));
        fs::write(&staged, comm_c).map_err(|e| io("write", &staged, e))?;
        fs::rename(&staged, ready_path).map_err(|e| io("rename", ready_path, e))?;
        Ok(Some(Labelled {
            comm_c,
            last,
            kept: true,
        }))
    }
}

impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        let remaining = std::mem::take(&mut self.remaining);
        let mut pending = self.store.pending();
        *pending = pending.saturating_sub(remaining);
    }
}

fn paths(dir: &Path, n: u64) -> [PathBuf; 3] {
    ["layers", "columns", "ready"].map(|kind| dir.join(format!("{n}.{kind}")))
}

fn write_digests(writer: &mut impl Write, digests: &[Digest]) -> std::io::Result<()> {
    for digest in digests {
        writer.write_all(&hash::to_bytes(digest))?;
    }
    Ok(())
}

/// One leaf's kept labels.
pub struct Kept {
    pub n: u64,
    pub comm_c: Node,
    layers: Mutex<File>,
    columns: PathBuf,
    depth: usize,
}

impl Kept {
    fn read(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let mut file = self.layers.lock().ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes).ok()?;
        Some(bytes)
    }
}

impl LabelSource for Kept {
    fn label(&self, layer: usize, v: u64) -> Option<Node> {
        if layer >= self.depth || v >= self.n {
            return None;
        }
        let at = (layer as u64 * self.n + v) * NODE_BYTES as u64;
        let node: Node = self.read(at, NODE_BYTES)?.try_into().ok()?;
        hash::from_bytes(&node).map(|_| node)
    }

    fn columns(&self) -> Option<Vec<Digest>> {
        hash::digests_from_bytes(&fs::read(&self.columns).ok()?)
            .filter(|columns| columns.len() as u64 == self.n)
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
/// ([`precompute`]): the epoch after next, from the first frame of the
/// current one, an epoch and 16 frames before its snapshot frame
/// (`quil_types::consensus::storage_snapshot_frame`). In an epoch's first 16
/// frames the next epoch's snapshot frame is too close to label a leaf of any
/// size by, and labelling ahead gives up at it ([`expired`]).
pub fn ahead_epoch(frame: u64) -> u64 {
    quil_types::consensus::epoch_for_frame(frame) + 2
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
         which the snapshot labels this leaf itself; an expected skip");
}

/// Label ahead the leaves `member` will register for `epoch` on shard
/// `filter`: the leaves of the shard's data in `crdt` now, each at
/// `precompute_nodes` of its node count, side by side
/// (`storage_jobs::for_each_parallel`). A leaf already labelled at a count
/// its data allows is left, and one its filesystem has no room for is not
/// labelled ([`LabelStore::admit`]). A leaf whose memory work due now waits
/// for is given up and labelled again once its memory fits beside that work
/// ([`label_leaf_ahead`]). Nothing is labelled once GLOBAL reached the
/// epoch's snapshot frame ([`expired`]). Removes the labels of epochs that
/// have begun.
pub fn precompute(
    store: &LabelStore,
    crdt: &Arc<HypergraphCrdt>,
    member: &[u8],
    filter: &[u8],
    epoch: u64,
) -> Result<()> {
    use quil_crypto::storage_proof::{data_node_count, padded_nodes_allowed, precompute_nodes};
    store.evict_before(epoch.saturating_sub(1));
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
    let params = SdrParams::default();
    let started = std::time::Instant::now();
    let labelled = crate::storage_jobs::for_each_parallel(&captured.prefixes, |prefix| {
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(filter, prefix);
        // Past the epoch's snapshot frame, leaves not started yet are skipped.
        if expired(epoch) {
            return Ok(Some(0));
        }
        let size = captured.leaf_size(prefix)?;
        // A leaf's data is at least its values (`leaf_size`): one whose
        // labels at that count have no room is refused before its read,
        // which would hold memory the epoch's snapshots wait for.
        let least = precompute_nodes(data_node_count(u64::try_from(size).unwrap_or(u64::MAX)));
        if store.find(epoch, member, &leaf_id, |_| true).is_none()
            && !store.may_admit(epoch, member, &leaf_id, least, Stage::Ahead)
        {
            return Ok(None);
        }
        let exact = {
            let memory = crate::storage_jobs::reserve_ahead(
                crate::storage_snapshot::leaf_read_bytes(size),
                &|| expired(epoch),
            );
            if memory.is_none() || expired(epoch) {
                log_expired(
                    epoch,
                    filter,
                    &leaf_id,
                    "waiting for memory to read the leaf",
                );
                return Ok(Some(0));
            }
            #[cfg(test)]
            store.leaves_read.fetch_add(1, Ordering::SeqCst);
            data_node_count(captured.leaf_data(prefix)?.len() as u64)
        };
        if store
            .find(epoch, member, &leaf_id, |n| padded_nodes_allowed(exact, n))
            .is_some()
        {
            return Ok(Some(0));
        }
        label_leaf_ahead(store, member, filter, &leaf_id, epoch, exact, &params)
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
            (refused > 0).then(Instant::now),
        );
    }
    info!(epoch, filter = %hex::encode(filter), leaves = labelled.len(),
        labelled = labelled.iter().filter(|n| n.is_some_and(|n| n > 0)).count(), refused,
        nodes = labelled.iter().flatten().sum::<u64>(), seconds = started.elapsed().as_secs_f64(),
        outcome, "storage labels computed ahead of the epoch's snapshot");
    Ok(())
}

/// Label `member`'s leaf `leaf_id` of shard `filter`, whose data takes
/// `exact` nodes, ahead for `epoch` ([`precompute`]): `Some` of the count it
/// was labelled and kept at (0 when it was labelled meanwhile, or given up),
/// `None` when refused room. While work due now waits for memory
/// (`crate::storage_jobs::Reservation::yield_requested`) the labelling gives
/// up the leaf and its memory, asks for the memory again at once, behind
/// that work (`crate::storage_jobs::reserve_ahead`), and labels the leaf
/// again from its start once it fits, unless the epoch's snapshot of the
/// shard labelled it meanwhile. Once GLOBAL reaches the epoch's snapshot
/// frame ([`expired`]), looked at while the leaf waits for its memory and
/// once it has it, and while it is labelled, the leaf is given up.
fn label_leaf_ahead(
    store: &LabelStore,
    member: &[u8],
    filter: &[u8],
    leaf_id: &[u8],
    epoch: u64,
    exact: u64,
    params: &SdrParams,
) -> Result<Option<u64>> {
    use crate::storage_snapshot::LeafOutcome;
    use quil_crypto::storage_proof::{padded_nodes_allowed, precompute_nodes};
    let stopping = || QuilError::ExecutionUnavailable("the node is stopping".into());
    let n = precompute_nodes(exact);
    // When the leaf last gave its memory back to work due now.
    let mut yielded: Option<Instant> = None;
    loop {
        let bytes = label_ahead_bytes(n);
        let gone = || expired(epoch) || crate::storage_jobs::stopping();
        let memory = crate::storage_jobs::reserve_ahead(bytes, &gone).filter(|_| !gone());
        let Some(memory) = memory else {
            if crate::storage_jobs::stopping() {
                return Err(stopping());
            }
            log_expired(
                epoch,
                filter,
                leaf_id,
                "waiting for memory to label the leaf",
            );
            return Ok(Some(0));
        };
        if let Some(at) = yielded.take() {
            let done = store
                .find(epoch, member, leaf_id, |n| padded_nodes_allowed(exact, n))
                .is_some()
                || crate::storage_snapshot::snapshot_encoded(filter, epoch);
            info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes = n,
                waited_seconds = at.elapsed().as_secs(), labelled_meanwhile = done,
                scope = "local",
                "storage labels computed ahead resume: their memory fits beside the work due now");
            if done {
                return Ok(Some(0));
            }
        }
        let Some(admitted) = store.admit(epoch, member, leaf_id, n, Stage::Ahead) else {
            return Ok(None);
        };
        let progress = crate::storage_snapshot::leaf_started(
            epoch,
            filter,
            leaf_id,
            n,
            crate::storage_snapshot::LeafWork::LabellingAhead,
        );
        let started = Instant::now();
        let labelled = admitted.label_until(params, &|| {
            memory.yield_requested() || crate::storage_jobs::stopping() || expired(epoch)
        })?;
        if let Some(labelled) = labelled {
            progress.end(LeafOutcome::Completed);
            return Ok(labelled.kept.then_some(n));
        }
        drop(memory);
        if crate::storage_jobs::stopping() {
            progress.end(LeafOutcome::Stopping);
            return Err(stopping());
        }
        if expired(epoch) {
            log_expired(epoch, filter, leaf_id, "labelling the leaf");
            progress.end(LeafOutcome::Expired);
            return Ok(Some(0));
        }
        info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes = n,
            seconds = started.elapsed().as_secs(), scope = "local",
            "storage labels computed ahead give their memory back to work due now (a renewal's \
             snapshot or an epoch proof) waiting for it; this leaf is labelled ahead again from its \
             start once its memory fits beside that work, unless GLOBAL reaches the epoch's \
             snapshot frame first: an expected wait");
        progress.end(LeafOutcome::Yielded);
        yielded = Some(Instant::now());
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
        let (peak, reserved) = (peak as u64, label_ahead_bytes(n));
        assert!(
            peak <= reserved && reserved <= peak + peak / 100 * LABEL_AHEAD_MARGIN_PERCENT,
            "labelling {n} nodes ahead held {peak} bytes at its peak and reserves {reserved}"
        );
        let _ = fs::remove_dir_all(&dir);
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

    /// A leaf whose labelling is given up midway leaves none of its files,
    /// and what it had still to write counts against the room no more.
    #[test]
    fn a_leaf_given_up_midway_leaves_no_files() {
        use std::sync::atomic::AtomicUsize;
        let dir = temp_dir("given-up");
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let (member, leaf, n) = ([7u8; 32], b"leaf".as_slice(), 1_500u64);
        let admitted = store.admit(9, &member, leaf, n, Stage::Ahead).unwrap();
        let looks = AtomicUsize::new(0);
        // Past the first layer, written to disk, then stopped.
        let per_layer = (n as usize).div_ceil(quil_crypto::storage_proof::STOP_CHECK_NODES);
        let stopped = admitted
            .label_until(&SdrParams::default(), &|| {
                looks.fetch_add(1, Ordering::SeqCst) > per_layer
            })
            .unwrap();
        assert!(stopped.is_none());
        assert_eq!(files_under(&dir), Vec::<PathBuf>::new());
        assert_eq!(*store.pending(), 0);
        assert!(store.find(9, &member, leaf, |_| true).is_none());
        assert!(
            keep(&store, 9, &member, leaf, n).kept,
            "labelled again from its start"
        );
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
}
