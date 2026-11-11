//! Persistent store for per-member SDR storage replicas (proof-of-storage).
//!
//! An honest prover must KEEP its leaf replicas to answer the per-frame storage
//! challenges — regenerating a ≤1 GB replica is sequential-memory-latency-bound
//! (tens of seconds), far slower than the frame interval. Replicas are keyed
//! `(epoch, leaf_id)` with the epoch FIRST, so dropping a stale epoch after the
//! per-epoch re-encode is a single `delete_range`.
//!
//! `leaf_id` is `leaf_id_bytes(shard_filter, prefix)` — the same id the
//! registration, the storage openings, and the registry cache key on.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use quil_crypto::storage_proof::{MerkleCap, NODE_BYTES};
use quil_types::error::{QuilError, Result};
use quil_types::store::KvDb;

use crate::encoding::STORAGE_REPLICA;

/// Key: `[STORAGE_REPLICA][epoch:u64 BE][leaf_id]`.
fn replica_key(epoch: u64, leaf_id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8 + leaf_id.len());
    k.push(STORAGE_REPLICA);
    k.extend_from_slice(&epoch.to_be_bytes());
    k.extend_from_slice(leaf_id);
    k
}

/// The lower/upper bound of the keyspace for a whole epoch (`[lo, hi)`).
fn epoch_bounds(epoch: u64) -> (Vec<u8>, Vec<u8>) {
    let mut lo = Vec::with_capacity(9);
    lo.push(STORAGE_REPLICA);
    lo.extend_from_slice(&epoch.to_be_bytes());
    let mut hi = Vec::with_capacity(9);
    hi.push(STORAGE_REPLICA);
    hi.extend_from_slice(&(epoch + 1).to_be_bytes());
    (lo, hi)
}

/// Records beside the replicas, keyed `[STORAGE_REPLICA][0xFF][kind][epoch BE][id]`:
/// a replica key's epoch never has `0xFF` as its top byte, so neither keyspace
/// reaches into the other.
const META: u8 = 0xFF;
/// A member's leaf partition of one shard at an epoch's snapshot, by filter.
const PARTITION: u8 = 0x01;
/// A member's snapshot sources of one shard for an epoch, by filter: what it
/// read its registration's data from, to read it again for the seal.
const SNAPSHOT_SOURCES: u8 = 0x03;
/// The node count of each leaf of a member's partition, by filter: what its
/// replicas take in memory, known before they are read.
const LEAF_NODES: u8 = 0x04;
/// A hash-proof epoch's leaf without its nodes, by leaf id
/// ([`ReplicaStore::put_hash`]): node count, chunk size, Merkle cap and
/// registration root.
const HASH_LEAF: u8 = 0x05;
/// A hash-proof epoch's leaf nodes in chunks of [`CHUNK_NODES`], by
/// length-prefixed leaf id and chunk index, so opening a node reads one chunk
/// instead of the whole replica.
const HASH_NODES: u8 = 0x06;
/// Optional snapshot-data cap for sparse seal preparation.
const DATA_CAP: u8 = 0x07;
/// Latest immutable snapshot fingerprint and its epoch, by logical leaf.
const SNAPSHOT_REUSE: u8 = 0x08;
/// What a member's snapshot encoded a hash-proof epoch's leaf from, by leaf
/// id ([`ReplicaStore::put_hash_source`]): written once the leaf and what is
/// stored beside it are whole, and removed before it is written again,
/// aliased or deleted.
const HASH_LEAF_SOURCE: u8 = 0x09;
/// A hash-proof epoch's leaf whose chunks lie in runs over several epochs
/// ([`HASH_LEAF_RUNS`]), by leaf id, in place of its [`HASH_LEAF`] record:
/// builds before runs read no such record, so to them the leaf is not
/// stored and is encoded again.
const LEAF_RUNS: u8 = 0x0A;
/// The chunk index, under an epoch's [`HASH_NODES`] keys of a leaf, of an
/// empty value showing that a [`LEAF_RUNS`] record of a later epoch reads
/// that epoch's chunks of the leaf. Past every chunk, but within the range
/// builds before runs keep for an alias, so their eviction drops it
/// exactly when it drops the chunks.
const RUNS_WITNESS: u32 = u32::MAX - 1;

/// Nodes per stored chunk: one subtree below the cap, all a member reads of a
/// replica to open one node of it (`MerkleCap::subtree`).
pub const CHUNK_NODES: u64 = 1 << quil_crypto::storage_proof::CAP_HEIGHT;
/// Chunks written per batch: bounds what writing a replica copies at once.
/// The most a batch holds: fewer on a disk slower than [`WalPace`] allows.
const CHUNKS_PER_BATCH: usize = 512;
/// The fewest chunks a batch is cut to ([`WalPace::batch_chunks`]), 1 MiB:
/// below it a sync's own cost outweighs its bytes. A disk slower than this
/// a [`REPLICA_SYNC_TARGET`] (20 MB/s) is paced by time instead.
const MIN_CHUNKS_PER_BATCH: usize = 32;
/// How long a batch of replica nodes may take the disk to sync
/// ([`WalPace`]): the store's synced commits sync its write-ahead log, and
/// every write made before them with it, and a frame's votes wait on about
/// 8 of them in turn within its 10 s. 50 ms keeps a replica's share to
/// half of the 100 ms a store fsync is warned at.
const REPLICA_SYNC_TARGET: Duration = Duration::from_millis(50);
/// Batch syncs a disk's speed is taken from: their median ignores up to
/// three slow ones, as behind a compaction.
const PACE_WINDOW: usize = 8;
/// Chunks read per range scan when a whole replica is loaded.
const CHUNKS_PER_SCAN: u64 = 256;
/// A table file at least this large under replica keys holds a whole
/// replica as one data block ([`reclaim`]): table
/// files are cut at 64 MB, but no value is split across blocks or files.
const WHOLE_REPLICA_FILE_BYTES: u64 = 128 << 20;
/// Longest a compaction of evicted replicas runs before it warns
/// ([`compact_evicted`]): an epoch evicts once per store, and its compaction
/// reads about one epoch of a store's replicas.
const EVICTED_COMPACTION_BUDGET: std::time::Duration = std::time::Duration::from_secs(600);
/// What the cached leaf records ([`ReplicaStore::get_hash_leaf`]) may hold:
/// a 1 GiB replica's cap is about 2 MiB.
const LEAF_CACHE_BYTES: usize = 128 << 20;

fn meta_key(kind: u8, epoch: u64, id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(11 + id.len());
    k.extend_from_slice(&[STORAGE_REPLICA, META, kind]);
    k.extend_from_slice(&epoch.to_be_bytes());
    k.extend_from_slice(id);
    k
}

/// Leads a hash-proof epoch's leaf as builds before the chunked layout stored
/// it, whole, under its replica key; read only to convert it.
const LEGACY_HASH_REPLICA_TAG: u8 = 0xA5;
/// Leads a [`HASH_LEAF`] record whose chunks are all its own epoch's.
const HASH_LEAF_VERSION: u8 = 1;
/// Leads a [`HASH_LEAF`] record whose chunks are all one earlier epoch's
/// ([`ReplicaStore::alias_hash`]).
const HASH_LEAF_ALIAS: u8 = 2;
/// Leads a [`LEAF_RUNS`] record: a leaf whose chunks lie in runs, each its
/// own epoch's or an earlier one's ([`ReplicaStore::put_hash`]).
const HASH_LEAF_RUNS: u8 = 3;

/// A stored hash-proof epoch's leaf as [`ReplicaStore::stored_from`] found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredFrom {
    /// None, or one stored without its source: cut short before it was
    /// recorded, or stored another way.
    Unrecorded,
    /// One stored from another source.
    Other,
    /// One from this source whose nodes do not hash up to its registered
    /// replica commitment: why.
    Damaged(String),
    /// One from this source, every node checked: its node count.
    Whole(u64),
    /// Not checked through: `stop` said so.
    Stopped,
}

/// A hash-proof epoch's stored leaf, nodes and all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashReplica {
    pub replica: LoadedReplica,
    pub cap: Vec<u8>,
    pub registration_root: Vec<u8>,
}

/// A whole replica read from the store, counted while held
/// ([`replica_load_bytes`]): what per-frame work must never hold.
#[derive(PartialEq, Eq)]
pub struct LoadedReplica(Vec<u8>);

static LOADED_BYTES: AtomicU64 = AtomicU64::new(0);
static LOADED_PEAK: AtomicU64 = AtomicU64::new(0);

fn note_loaded(bytes: u64) {
    let held = LOADED_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    LOADED_PEAK.fetch_max(held, Ordering::Relaxed);
}

impl LoadedReplica {
    pub fn new(nodes: Vec<u8>) -> Self {
        note_loaded(nodes.len() as u64);
        Self(nodes)
    }
}

impl From<Vec<u8>> for LoadedReplica {
    fn from(nodes: Vec<u8>) -> Self {
        Self::new(nodes)
    }
}

impl Clone for LoadedReplica {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl Drop for LoadedReplica {
    fn drop(&mut self) {
        LOADED_BYTES.fetch_sub(self.0.len() as u64, Ordering::Relaxed);
    }
}

impl std::ops::Deref for LoadedReplica {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for LoadedReplica {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LoadedReplica({} bytes)", self.0.len())
    }
}

/// Replica bytes this process put into its stores: whole replicas
/// ([`ReplicaStore::put`]) and the chunks of hash-proof leaves it wrote
/// ([`ReplicaStore::put_hash`]), before the stores' own write-ahead log,
/// flushes and compactions write them again.
static WRITTEN_BYTES: AtomicU64 = AtomicU64::new(0);

/// Replica bytes this process put into its stores since it started
/// ([`WRITTEN_BYTES`]).
pub fn replica_bytes_written() -> u64 {
    WRITTEN_BYTES.load(Ordering::Relaxed)
}

/// Whole replicas this process holds now, read from its stores (one being
/// converted to the chunked layout included), and the most it held at once
/// since the previous call: `(held, peak)` bytes.
pub fn replica_load_bytes() -> (u64, u64) {
    let held = LOADED_BYTES.load(Ordering::Relaxed);
    let peak = LOADED_PEAK.swap(held, Ordering::Relaxed);
    (held, peak.max(held))
}

/// A hash-proof epoch's stored leaf without its nodes: what opening some of
/// them takes besides the nodes ([`ReplicaStore::read_nodes`]).
#[derive(Debug, PartialEq, Eq)]
pub struct HashLeaf {
    /// Nodes in the replica.
    pub n: u64,
    pub cap: MerkleCap,
    pub registration_root: Vec<u8>,
    chunk_nodes: u64,
    /// Where the chunks lie when not all under the record's own epoch:
    /// runs `(first chunk, epoch)` from chunk 0 on, each up to the next,
    /// under the record's own epoch or an earlier one whose immutable
    /// chunks it reads. A run names the epoch that wrote its chunks, never
    /// another reference to them.
    sources: Vec<(u32, u64)>,
}

impl HashLeaf {
    fn encode(n: u64, cap: &[u8], registration_root: &[u8]) -> Vec<u8> {
        let mut value = Vec::with_capacity(21 + cap.len() + registration_root.len());
        value.push(HASH_LEAF_VERSION);
        value.extend_from_slice(&n.to_be_bytes());
        value.extend_from_slice(&(CHUNK_NODES as u32).to_be_bytes());
        value.extend_from_slice(&(cap.len() as u32).to_be_bytes());
        value.extend_from_slice(cap);
        value.extend_from_slice(&(registration_root.len() as u32).to_be_bytes());
        value.extend_from_slice(registration_root);
        value
    }

    /// The record of a leaf stored under `epoch` whose chunks lie where
    /// `runs` (`(first chunk, epoch)` from chunk 0 on) put them, `body`
    /// what [`Self::encode`] writes after its version. Runs of one epoch
    /// are merged, so a leaf whose chunks are all its own epoch's, or all
    /// one earlier epoch's, is recorded as builds before runs recorded it.
    fn encode_runs(epoch: u64, runs: &[(u32, u64)], body: &[u8]) -> Vec<u8> {
        let mut merged: Vec<(u32, u64)> = Vec::with_capacity(runs.len());
        for &(first, source) in runs {
            if merged.last().is_none_or(|&(_, last)| last != source) {
                merged.push((first, source));
            }
        }
        let mut value = Vec::with_capacity(5 + merged.len() * 12 + body.len());
        match merged[..] {
            [] => value.push(HASH_LEAF_VERSION),
            [(0, source)] if source == epoch => value.push(HASH_LEAF_VERSION),
            [(0, source)] => {
                value.push(HASH_LEAF_ALIAS);
                value.extend_from_slice(&source.to_be_bytes());
            }
            _ => {
                value.push(HASH_LEAF_RUNS);
                value.extend_from_slice(&(merged.len() as u32).to_be_bytes());
                for (first, source) in merged {
                    value.extend_from_slice(&first.to_be_bytes());
                    value.extend_from_slice(&source.to_be_bytes());
                }
            }
        }
        value.extend_from_slice(body);
        value
    }

    /// A stored record without its version and runs: what
    /// [`Self::encode`] writes after its version.
    fn body(value: &[u8]) -> Option<&[u8]> {
        match *value.first()? {
            HASH_LEAF_VERSION => value.get(1..),
            HASH_LEAF_ALIAS => value.get(9..),
            HASH_LEAF_RUNS => {
                let runs = u32::from_be_bytes(value.get(1..5)?.try_into().ok()?) as usize;
                value.get(runs.checked_mul(12)?.checked_add(5)?..)
            }
            _ => None,
        }
    }

    fn decode(value: &[u8]) -> Result<Self> {
        let layout = Self::layout(value)?;
        let cap = MerkleCap::from_bytes(layout.cap).ok_or_else(|| {
            QuilError::InvalidArgument("a stored replica's cap does not decode".into())
        })?;
        Ok(Self {
            n: layout.n,
            cap,
            registration_root: layout.registration_root.to_vec(),
            chunk_nodes: layout.chunk_nodes,
            sources: layout.sources,
        })
    }

    /// A stored record's fields, its cap not decoded: what finding the
    /// chunks it reads takes, without checking a cap.
    fn layout(value: &[u8]) -> Result<LeafLayout<'_>> {
        let corrupt = || QuilError::Store("a stored replica's leaf record does not decode".into());
        let (&version, rest) = value.split_first().ok_or_else(corrupt)?;
        let sources: Vec<(u32, u64)> = match version {
            HASH_LEAF_VERSION => Vec::new(),
            HASH_LEAF_ALIAS => {
                let epoch = rest.get(..8).ok_or_else(corrupt)?;
                vec![(0, u64::from_be_bytes(epoch.try_into().expect("8 bytes")))]
            }
            HASH_LEAF_RUNS => {
                let count = rest.get(..4).ok_or_else(corrupt)?;
                let count = u32::from_be_bytes(count.try_into().expect("4 bytes")) as usize;
                let runs = count
                    .checked_mul(12)
                    .and_then(|len| rest.get(4..len.checked_add(4)?))
                    .ok_or_else(corrupt)?;
                runs.chunks_exact(12)
                    .map(|run| {
                        let first = u32::from_be_bytes(run[..4].try_into().expect("4 bytes"));
                        (
                            first,
                            u64::from_be_bytes(run[4..].try_into().expect("8 bytes")),
                        )
                    })
                    .collect()
            }
            _ => return Err(corrupt()),
        };
        let rest = HashLeaf::body(value).ok_or_else(corrupt)?;
        if rest.len() < 12 {
            return Err(corrupt());
        }
        let n = u64::from_be_bytes(rest[..8].try_into().expect("8 bytes"));
        let chunk_nodes = u32::from_be_bytes(rest[8..12].try_into().expect("4 bytes")) as u64;
        let (cap, rest) = take(&rest[12..]).ok_or_else(corrupt)?;
        let (registration_root, rest) = take(rest).ok_or_else(corrupt)?;
        if chunk_nodes == 0 || !rest.is_empty() {
            return Err(corrupt());
        }
        // Runs from chunk 0 on, each past the last and within the leaf.
        let chunks = n.div_ceil(chunk_nodes);
        if version == HASH_LEAF_RUNS
            && (sources.first().map(|&(first, _)| first) != Some(0)
                || sources.windows(2).any(|pair| pair[0].0 >= pair[1].0)
                || sources
                    .last()
                    .is_some_and(|&(first, _)| u64::from(first) >= chunks))
        {
            return Err(corrupt());
        }
        Ok(LeafLayout {
            n,
            chunk_nodes,
            cap,
            registration_root,
            sources,
        })
    }

    /// Bytes this record holds in memory.
    fn bytes(&self) -> usize {
        let cap: usize = self.cap.levels.iter().map(Vec::len).sum();
        cap * NODE_BYTES + self.registration_root.len() + self.sources.len() * 12
    }

    /// Where the chunks of this record, stored under `epoch`, lie: runs
    /// `(first chunk, epoch whose keys hold it)` from chunk 0 on.
    fn runs(&self, epoch: u64) -> Vec<(u32, u64)> {
        if self.sources.is_empty() {
            vec![(0, epoch)]
        } else {
            self.sources.clone()
        }
    }

    /// The epoch whose keys hold chunk `chunk` of this record, stored
    /// under `epoch`, and the first chunk after it that lies elsewhere
    /// (`u64::MAX` when none does).
    fn chunk_source(&self, epoch: u64, chunk: u64) -> (u64, u64) {
        let at = self
            .sources
            .partition_point(|&(first, _)| u64::from(first) <= chunk);
        let source = at.checked_sub(1).map_or(epoch, |run| self.sources[run].1);
        let end = self
            .sources
            .get(at)
            .map_or(u64::MAX, |&(first, _)| u64::from(first));
        (source, end)
    }
}

/// Compact the replica keys `[lo, hi)`, one range at a time in this process,
/// when a table file there holds a whole replica (`what` the deleted replicas
/// were). A replica stored whole is one data block of up to 1 GB: until a
/// compaction drops it, every lookup of a key the block's index range covers
/// (consensus records sort beside replica keys) reads all of it, and leveled
/// compaction may leave a bottommost file holding one for days. A compaction
/// reads the block once: about a replica in memory, for seconds.
fn reclaim(db: &Arc<dyn KvDb>, lo: &[u8], hi: &[u8], what: &'static str) {
    let _one = RECLAIMING.lock().unwrap_or_else(PoisonError::into_inner);
    let started = std::time::Instant::now();
    match db.compact_reclaiming(&lo, &hi, WHOLE_REPLICA_FILE_BYTES) {
        Ok(false) => {}
        Ok(true) => tracing::info!(
            replicas = what,
            ms = started.elapsed().as_millis() as u64,
            "storage replicas stored whole compacted away: lookups beside them no longer read \
             them"
        ),
        Err(error) => tracing::warn!(replicas = what, %error, scope = "this node",
            action = "check this node's disk and store health; the next conversion or eviction \
                      compacts again",
            "compacting storage replicas stored whole failed: lookups beside them keep reading \
             them"),
    }
}

/// One compaction of replica keys at a time in this process ([`reclaim`],
/// [`compact_evicted`]): each reads all it covers, up to an epoch of a
/// store's replicas.
static RECLAIMING: Mutex<()> = Mutex::new(());

/// Compact the evicted chunks `[lo, hi)` of the replicas below `keep_from`
/// in `store`, logging its start and end, and a warning once it runs past
/// [`EVICTED_COMPACTION_BUDGET`]. The lines give the bytes of the table
/// files overlapping the range (`range_mb`: files bordering it count whole)
/// and of the whole store (which the next epoch's encoding may be filling
/// meanwhile): a range still as large after its compaction is held by a
/// snapshot or iterator older than the eviction.
fn compact_evicted(db: &Arc<dyn KvDb>, lo: &[u8], hi: &[u8], keep_from: u64, store: &str) {
    let _one = RECLAIMING.lock().unwrap_or_else(PoisonError::into_inner);
    let failed = |error: &QuilError, ms: u64| {
        tracing::warn!(store, below_epoch = keep_from, ms, %error, scope = "this node",
            action = "check this node's disk and store health; the next epoch's eviction \
                      compacts again",
            "compacting evicted storage replicas failed: their disk space stays taken until \
             RocksDB compacts there")
    };
    let measure = || -> Result<(u64, u64)> {
        Ok((
            db.live_file_bytes(Some((lo, hi)))?,
            db.live_file_bytes(None)?,
        ))
    };
    let (in_range, before) = match measure() {
        Ok((0, _)) => return,
        Ok(bytes) => bytes,
        Err(error) => return failed(&error, 0),
    };
    tracing::info!(
        store,
        below_epoch = keep_from,
        range_mb = in_range >> 20,
        store_mb = before >> 20,
        budget_s = EVICTED_COMPACTION_BUDGET.as_secs(),
        "compacting evicted storage replicas: their disk space returns when it ends"
    );
    let started = std::time::Instant::now();
    let (finished, finishing) = std::sync::mpsc::channel::<()>();
    let compacted = std::thread::scope(|scope| {
        // Only a warning: a compaction cannot be cut short.
        let _ = std::thread::Builder::new()
            .name("replica-reclaim-watch".into())
            .spawn_scoped(scope, move || {
                if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                    finishing.recv_timeout(EVICTED_COMPACTION_BUDGET)
                {
                    tracing::warn!(
                        store,
                        below_epoch = keep_from,
                        budget_s = EVICTED_COMPACTION_BUDGET.as_secs(),
                        scope = "this node",
                        action = "check this node's disk load; it keeps running and logs its \
                                  end",
                        "compacting evicted storage replicas is running past its budget: \
                         their disk space returns when it ends"
                    );
                }
            });
        let compacted = db.compact_reclaiming(lo, hi, 0);
        drop(finished);
        compacted
    });
    let ms = started.elapsed().as_millis() as u64;
    let (in_range_after, after) = match compacted.and_then(|_| measure()) {
        Ok(bytes) => bytes,
        Err(error) => return failed(&error, ms),
    };
    tracing::info!(
        store,
        below_epoch = keep_from,
        range_mb_before = in_range >> 20,
        range_mb_after = in_range_after >> 20,
        store_mb_before = before >> 20,
        store_mb_after = after >> 20,
        ms,
        "compacted evicted storage replicas"
    );
}

/// Threads of this module's still running ([`wait_for_background_work`]).
static BACKGROUND: (Mutex<usize>, std::sync::Condvar) = (Mutex::new(0), std::sync::Condvar::new());

/// One thread of this module's, counted from before it is spawned until it
/// ends, so a wait started meanwhile sees it. A process ending through
/// `exit` waits for it too.
struct Background {
    _exit: quil_forest::ExitHold,
}

impl Background {
    fn start() -> Self {
        let exit = quil_forest::ExitHold::start();
        *BACKGROUND.0.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        Self { _exit: exit }
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        let mut running = BACKGROUND.0.lock().unwrap_or_else(PoisonError::into_inner);
        *running -= 1;
        BACKGROUND.1.notify_all();
    }
}

/// Wait up to `timeout` for the conversions and compactions this module runs
/// on threads of their own; how many still run. A process must not exit
/// under one: RocksDB's static teardown would abort it ("pthread lock:
/// Invalid argument").
pub fn wait_for_background_work(timeout: std::time::Duration) -> usize {
    let deadline = std::time::Instant::now() + timeout;
    let mut running = BACKGROUND.0.lock().unwrap_or_else(PoisonError::into_inner);
    while *running > 0 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break;
        }
        running = BACKGROUND
            .1
            .wait_timeout(running, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
    *running
}

/// A length-prefixed field (`u32` BE length) and what follows it.
fn take(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let field = bytes.get(4..4 + len)?;
    Some((field, &bytes[4 + len..]))
}

/// A stored [`HASH_LEAF`] record's fields ([`HashLeaf::layout`]), its cap
/// not decoded.
struct LeafLayout<'a> {
    n: u64,
    chunk_nodes: u64,
    cap: &'a [u8],
    registration_root: &'a [u8],
    /// As [`HashLeaf`]'s.
    sources: Vec<(u32, u64)>,
}

impl LeafLayout<'_> {
    /// Chunks the leaf's nodes take.
    fn chunks(&self) -> u64 {
        self.n.div_ceil(self.chunk_nodes)
    }
}

/// A leaf as builds before the chunked layout stored it, borrowed from the
/// stored value.
struct LegacyHashReplica<'a> {
    replica: &'a [u8],
    cap: &'a [u8],
    registration_root: &'a [u8],
}

impl<'a> LegacyHashReplica<'a> {
    fn decode(value: &'a [u8]) -> Option<Self> {
        let (&tag, rest) = value.split_first()?;
        if tag != LEGACY_HASH_REPLICA_TAG {
            return None;
        }
        let (cap, rest) = take(rest)?;
        let (registration_root, replica) = take(rest)?;
        Some(Self {
            replica,
            cap,
            registration_root,
        })
    }
}

fn leaf_key(epoch: u64, leaf_id: &[u8]) -> Vec<u8> {
    meta_key(HASH_LEAF, epoch, leaf_id)
}

fn runs_key(epoch: u64, leaf_id: &[u8]) -> Vec<u8> {
    meta_key(LEAF_RUNS, epoch, leaf_id)
}

/// The earlier epochs, below `epoch`, whose chunks a record read.
fn earlier_sources(sources: &[(u32, u64)], epoch: u64) -> std::collections::BTreeSet<u64> {
    sources
        .iter()
        .map(|&(_, source)| source)
        .filter(|&source| source < epoch)
        .collect()
}

/// Runs records found reading chunks an earlier build evicted, by epoch
/// and leaf id, warned of once each.
type StaleRuns = std::collections::HashSet<(u64, Vec<u8>)>;

fn stale_runs() -> std::sync::MutexGuard<'static, StaleRuns> {
    static STALE: OnceLock<Mutex<StaleRuns>> = OnceLock::new();
    STALE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Key of chunk `chunk` of a leaf's nodes: the leaf id is length-prefixed so
/// no leaf's chunks fall among another's.
fn chunk_key(epoch: u64, leaf_id: &[u8], chunk: u32) -> Vec<u8> {
    let mut id = Vec::with_capacity(8 + leaf_id.len());
    id.extend_from_slice(&(leaf_id.len() as u32).to_be_bytes());
    id.extend_from_slice(leaf_id);
    id.extend_from_slice(&chunk.to_be_bytes());
    meta_key(HASH_NODES, epoch, &id)
}

/// Serializes writes of hash leaves and conversions of legacy ones in this
/// process, so no write interleaves another's chunks and at most one legacy
/// replica is read whole at a time.
fn hash_writes() -> &'static Mutex<()> {
    static WRITES: Mutex<()> = Mutex::new(());
    &WRITES
}

/// How a replica's nodes go into the store, which the consensus commits
/// share: each batch is synced on its own before the next is written, so
/// a synced commit of the store's waits behind at most one batch, not
/// behind every node written since the last (an epoch's replicas are
/// 1-1.7 GB a seat, written at once). Each sync is timed and the next
/// batch cut to what the disk synced in [`REPLICA_SYNC_TARGET`] at the
/// median of the latest; a sync past it is followed by as long a wait,
/// leaving the disk to the store's commits. A fast disk keeps
/// [`CHUNKS_PER_BATCH`] and never waits.
struct WalPace {
    /// Seconds a byte of the latest [`PACE_WINDOW`] syncs, the oldest
    /// replaced first.
    recent: [f64; PACE_WINDOW],
    /// Syncs timed in all.
    timed: usize,
}

impl WalPace {
    const fn new() -> Self {
        Self {
            recent: [0.0; PACE_WINDOW],
            timed: 0,
        }
    }

    /// Chunks of the next batch: what the disk synced in
    /// [`REPLICA_SYNC_TARGET`] at the median of the latest syncs, from
    /// [`MIN_CHUNKS_PER_BATCH`] to [`CHUNKS_PER_BATCH`], the most until a
    /// sync is timed.
    fn batch_chunks(&self) -> usize {
        let timed = self.timed.min(PACE_WINDOW);
        let mut recent = self.recent;
        let recent = &mut recent[..timed];
        recent.sort_unstable_by(f64::total_cmp);
        let Some(&per_byte) = recent.get(timed / 2) else {
            return CHUNKS_PER_BATCH;
        };
        let chunk_bytes = (CHUNK_NODES as usize * NODE_BYTES) as f64;
        let chunks = REPLICA_SYNC_TARGET.as_secs_f64() / per_byte / chunk_bytes;
        if chunks >= CHUNKS_PER_BATCH as f64 {
            return CHUNKS_PER_BATCH;
        }
        (chunks as usize).clamp(MIN_CHUNKS_PER_BATCH, CHUNKS_PER_BATCH)
    }

    /// Time a sync of a batch of `bytes` that `took` (a batch of at least
    /// [`MIN_CHUNKS_PER_BATCH`]: a replica's smaller end costs more than
    /// its bytes): returns how long to wait before the next batch, what it
    /// took past [`REPLICA_SYNC_TARGET`].
    fn synced(&mut self, bytes: u64, took: Duration) -> Duration {
        let batch = (MIN_CHUNKS_PER_BATCH * CHUNK_NODES as usize * NODE_BYTES) as u64;
        if bytes >= batch {
            self.recent[self.timed % PACE_WINDOW] = took.as_secs_f64() / bytes as f64;
            self.timed += 1;
        }
        took.saturating_sub(REPLICA_SYNC_TARGET)
    }
}

/// This process's [`WalPace`]: replica writes take turns ([`hash_writes`]).
fn wal_pace() -> std::sync::MutexGuard<'static, WalPace> {
    static PACE: Mutex<WalPace> = Mutex::new(WalPace::new());
    PACE.lock().unwrap_or_else(PoisonError::into_inner)
}

type LeafCacheKey = (usize, u64, Vec<u8>);

/// Chunks of a leaf stored under an epoch that another epoch's record
/// reads: `(epoch, leaf id, first chunk, end)`.
type ChunkRun = (u64, Vec<u8>, u64, u64);

/// Leaf records read recently, by store, epoch and leaf id: every frame a
/// seat proposes opens the same leaves, whose caps it would otherwise read
/// and check again. Each holds its store weakly: no other store can take the
/// address it is keyed by, and one closed is never answered for.
#[derive(Default)]
struct LeafCache {
    entries: HashMap<LeafCacheKey, (std::sync::Weak<dyn KvDb>, Arc<HashLeaf>)>,
    bytes: usize,
}

fn leaf_cache() -> std::sync::MutexGuard<'static, LeafCache> {
    static CACHE: OnceLock<Mutex<LeafCache>> = OnceLock::new();
    CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

impl LeafCache {
    fn get(&mut self, key: &LeafCacheKey) -> Option<Arc<HashLeaf>> {
        let (store, leaf) = self.entries.get(key)?;
        if store.strong_count() > 0 {
            return Some(leaf.clone());
        }
        self.remove(key);
        None
    }

    fn insert(&mut self, key: LeafCacheKey, store: &Arc<dyn KvDb>, leaf: Arc<HashLeaf>) {
        let bytes = leaf.bytes();
        if bytes > LEAF_CACHE_BYTES {
            return;
        }
        self.remove(&key);
        self.forget_closed();
        // The oldest epochs go first: frames open the newest.
        while self.bytes + bytes > LEAF_CACHE_BYTES {
            let Some(oldest) = self.entries.keys().min_by_key(|key| key.1).cloned() else {
                break;
            };
            self.remove(&oldest);
        }
        self.entries.insert(key, (Arc::downgrade(store), leaf));
        self.bytes += bytes;
    }

    fn remove(&mut self, key: &LeafCacheKey) {
        if let Some((_, old)) = self.entries.remove(key) {
            self.bytes -= old.bytes();
        }
    }

    /// Drop the records of stores no longer open.
    fn forget_closed(&mut self) {
        let keys: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, (store, _))| store.strong_count() == 0)
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            self.remove(&key);
        }
    }

    /// Drop every store's records of the leaves `stale` names.
    fn forget(&mut self, stale: &dyn Fn(u64, &[u8]) -> bool) {
        let keys: Vec<_> = self
            .entries
            .keys()
            .filter(|key| stale(key.1, &key.2))
            .cloned()
            .collect();
        for key in keys {
            self.remove(&key);
        }
    }
}

fn forget_leaves(stale: impl Fn(u64, &[u8]) -> bool) {
    leaf_cache().forget(&stale);
    legacy_lookups().retain(|key, _| !stale(key.1, &key.2));
}

/// A proposal-path lookup of a leaf not stored chunked
/// ([`ReplicaStore::try_get_hash_leaf`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegacyLookup {
    /// Queued or running on its own thread.
    Pending,
    /// No leaf stored, chunked or whole: until one is written.
    Absent,
}

type LegacyLookups = HashMap<LeafCacheKey, (std::sync::Weak<dyn KvDb>, LegacyLookup)>;

fn legacy_lookups() -> std::sync::MutexGuard<'static, LegacyLookups> {
    static LOOKUPS: OnceLock<Mutex<LegacyLookups>> = OnceLock::new();
    LOOKUPS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

type EvictedBelow = HashMap<usize, (std::sync::Weak<dyn KvDb>, u64)>;

/// The epoch each open store was last evicted below in this process
/// ([`ReplicaStore::evict_below_epoch_once`]), by store. Each holds its
/// store weakly, as [`LeafCache`] does.
fn evicted_below() -> std::sync::MutexGuard<'static, EvictedBelow> {
    static EVICTED: OnceLock<Mutex<EvictedBelow>> = OnceLock::new();
    EVICTED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Bytes the cached leaf records hold in this process.
pub fn leaf_cache_bytes() -> usize {
    leaf_cache().bytes
}

/// A `KvDb`-backed replica store. Cheap to clone (shares the `Arc<dyn KvDb>`).
#[derive(Clone)]
pub struct ReplicaStore {
    db: Arc<dyn KvDb>,
}

impl ReplicaStore {
    pub fn new(db: Arc<dyn KvDb>) -> Self {
        Self { db }
    }

    /// Persist `replica` for `(epoch, leaf_id)`, replacing any prior value.
    pub fn put(&self, epoch: u64, leaf_id: &[u8], replica: &[u8]) -> Result<()> {
        self.db.set(&replica_key(epoch, leaf_id), replica)?;
        WRITTEN_BYTES.fetch_add(replica.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Fetch the replica for `(epoch, leaf_id)`, or `None`.
    pub fn get(&self, epoch: u64, leaf_id: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(&replica_key(epoch, leaf_id))
    }

    /// Persist a hash-proof epoch's leaf: the replica with the Merkle cap that,
    /// with it, opens any node (`quil_crypto::storage_proof::MerkleCap`), and
    /// the registration root it was registered with. The nodes go in chunks
    /// of [`CHUNK_NODES`], written before the leaf record that makes them
    /// readable, so an interrupted write leaves no leaf. A chunk whose bytes
    /// the leaf's latest earlier epoch ([`Self::note_snapshot`]) stored
    /// alike is not written again: the record reads it where it lies.
    pub fn put_hash(
        &self,
        epoch: u64,
        leaf_id: &[u8],
        replica: &[u8],
        cap: &[u8],
        registration_root: &[u8],
    ) -> Result<()> {
        let _writing = hash_writes().lock().unwrap_or_else(PoisonError::into_inner);
        self.write_hash(epoch, leaf_id, replica, cap, registration_root)
    }

    /// Record the `source` the leaf stored at `(epoch, leaf_id)` was encoded
    /// from, by [`Self::put_hash`] or [`Self::alias_hash`], for
    /// [`Self::stored_from`]: last, once the leaf and what is stored beside
    /// it are whole. Writing the leaf again, aliasing it or deleting it drops
    /// the record. A leaf in chunk runs ([`LEAF_RUNS`]) counts as stored.
    pub fn put_hash_source(&self, epoch: u64, leaf_id: &[u8], source: &[u8]) -> Result<()> {
        let _writing = hash_writes().lock().unwrap_or_else(PoisonError::into_inner);
        if self.leaf_value(epoch, leaf_id)?.is_none() {
            return Err(QuilError::Store(
                "no stored leaf to record the source of".into(),
            ));
        }
        self.db
            .set(&meta_key(HASH_LEAF_SOURCE, epoch, leaf_id), source)
    }

    /// Whether `(epoch, leaf_id)` holds a leaf [`Self::put_hash_source`]
    /// recorded as stored from `source`, each of its nodes read back and
    /// hashed up to its cap, and the cap to the replica commitment its
    /// registration root carries. Holds one scan window of nodes at a time,
    /// and looks at `stop` before each.
    pub fn stored_from(
        &self,
        epoch: u64,
        leaf_id: &[u8],
        source: &[u8],
        stop: &dyn Fn() -> bool,
    ) -> Result<StoredFrom> {
        use quil_crypto::storage_proof::{parse_registration_root, Tree, CAP_HEIGHT};
        match self.db.get(&meta_key(HASH_LEAF_SOURCE, epoch, leaf_id))? {
            None => return Ok(StoredFrom::Unrecorded),
            Some(stored) if stored != source => return Ok(StoredFrom::Other),
            Some(_) => {}
        }
        let damaged = |why: String| Ok(StoredFrom::Damaged(why));
        let leaf = match self.get_hash_leaf(epoch, leaf_id) {
            Ok(Some(leaf)) => leaf,
            Ok(None) => return Ok(StoredFrom::Unrecorded),
            Err(error) => return damaged(error.to_string()),
        };
        let comm_r = parse_registration_root(&leaf.registration_root).map(|root| root.comm_r);
        if comm_r != Some(leaf.cap.commitment(Tree::Replica))
            || leaf.cap.n != leaf.n
            || leaf.cap.height > CAP_HEIGHT
        {
            return damaged("its cap is not the registered replica's".into());
        }
        // The cap's subtrees: a tree shallower than the cap's height is one,
        // under its root, whatever the chunks hold.
        let per = 1u64 << leaf.cap.height;
        let mut start = 0;
        while start < leaf.n {
            if stop() {
                return Ok(StoredFrom::Stopped);
            }
            let end = (start + per * CHUNKS_PER_SCAN).min(leaf.n);
            let nodes = match self.read_nodes(epoch, leaf_id, &leaf, start..end) {
                Ok(nodes) => nodes,
                Err(error) => return damaged(error.to_string()),
            };
            for (at, chunk) in (start..)
                .step_by(per as usize)
                .zip(nodes.chunks(per as usize * NODE_BYTES))
            {
                if leaf.cap.subtree_path(chunk, at).is_none() {
                    return damaged(format!("nodes from {at} do not hash up to its cap"));
                }
            }
            start = end;
        }
        Ok(StoredFrom::Whole(leaf.n))
    }

    /// [`Self::put_hash`] with [`hash_writes`] held.
    fn write_hash(
        &self,
        epoch: u64,
        leaf_id: &[u8],
        replica: &[u8],
        cap: &[u8],
        registration_root: &[u8],
    ) -> Result<()> {
        if self.is_referenced(epoch, leaf_id)? {
            return Err(QuilError::Store(
                "cannot replace a referenced immutable replica".into(),
            ));
        }
        if replica.len() % NODE_BYTES != 0 {
            return Err(QuilError::InvalidArgument(
                "a replica is a whole number of nodes".into(),
            ));
        }
        let chunk_bytes = CHUNK_NODES as usize * NODE_BYTES;
        let n = (replica.len() / NODE_BYTES) as u64;
        // Per chunk, the earlier epoch holding its bytes, if one does.
        let base = self.chunk_base(epoch, leaf_id, n)?;
        let kept = match &base {
            Some((from, leaf)) => self.unchanged_chunks(*from, leaf_id, leaf, replica, cap),
            None => vec![None; replica.len().div_ceil(chunk_bytes)],
        };
        forget_leaves(|e, id| e == epoch && id == leaf_id);
        self.db.delete(&meta_key(DATA_CAP, epoch, leaf_id))?;
        self.db
            .delete(&meta_key(HASH_LEAF_SOURCE, epoch, leaf_id))?;
        self.db.delete(&leaf_key(epoch, leaf_id))?;
        self.db.delete(&runs_key(epoch, leaf_id))?;
        self.db.delete_range(
            &chunk_key(epoch, leaf_id, 0),
            &chunk_key(epoch, leaf_id, u32::MAX),
        )?;
        let changed: Vec<usize> = kept
            .iter()
            .enumerate()
            .filter_map(|(chunk, source)| source.is_none().then_some(chunk))
            .collect();
        let mut rest = &changed[..];
        let (mut batches, mut syncing, mut waited) = (0u64, Duration::ZERO, Duration::ZERO);
        let mut written = 0u64;
        while !rest.is_empty() {
            let chunks = wal_pace().batch_chunks();
            let (batch, after) = rest.split_at(rest.len().min(chunks));
            let txn = self.db.new_batch(false)?;
            let mut bytes = 0u64;
            for &chunk in batch {
                let at = chunk * chunk_bytes;
                let nodes = &replica[at..replica.len().min(at + chunk_bytes)];
                txn.set(&chunk_key(epoch, leaf_id, chunk as u32), nodes)?;
                bytes += nodes.len() as u64;
            }
            txn.commit()?;
            WRITTEN_BYTES.fetch_add(bytes, Ordering::Relaxed);
            // Synced on its own, so the store's next synced commit does not
            // take it; past the target, the disk is left to them a while.
            let started = Instant::now();
            self.db.sync_wal()?;
            let took = started.elapsed();
            let wait = wal_pace().synced(bytes, took);
            std::thread::sleep(wait);
            (batches, syncing, waited) = (batches + 1, syncing + took, waited + wait);
            written += bytes;
            rest = after;
        }
        if let Some((from, _)) = &base {
            tracing::info!(epoch, leaf = %hex::encode(leaf_id), from_epoch = *from,
                chunks = kept.len(), chunks_written = changed.len(), bytes_written = written,
                bytes_kept = replica.len() as u64 - written,
                "storage replica written in its changed chunks only: the others are read \
                 where `from_epoch` wrote them");
        }
        if !waited.is_zero() {
            tracing::info!(epoch, leaf = %hex::encode(leaf_id), bytes = written, batches,
                sync_seconds = syncing.as_secs_f64(), wait_seconds = waited.as_secs_f64(),
                target_ms = REPLICA_SYNC_TARGET.as_millis() as u64, scope = "this node",
                "storage replica written to the store in synced batches slower than \
                 `target_ms` each, waiting as long after each, so the store's synced commits \
                 do not wait behind it; check this node's disk write speed if this recurs");
        }
        let runs: Vec<(u32, u64)> = kept
            .iter()
            .enumerate()
            .map(|(chunk, source)| (chunk as u32, source.unwrap_or(epoch)))
            .collect();
        let body = HashLeaf::encode(n, cap, registration_root);
        let record = HashLeaf::encode_runs(epoch, &runs, &body[1..]);
        let txn = self.db.new_batch(false)?;
        self.put_record(&*txn, epoch, leaf_id, &record, &runs)?;
        txn.commit()
    }

    /// Put `record`, a leaf's at `epoch` whose chunks lie where `runs`
    /// put them, under its key in `txn`: a [`HASH_LEAF`] record unless
    /// it is in runs ([`LEAF_RUNS`]), then with a [`RUNS_WITNESS`] beside
    /// the chunks of each earlier epoch it reads.
    fn put_record(
        &self,
        txn: &dyn quil_types::store::Transaction,
        epoch: u64,
        leaf_id: &[u8],
        record: &[u8],
        runs: &[(u32, u64)],
    ) -> Result<()> {
        if record.first() != Some(&HASH_LEAF_RUNS) {
            txn.delete(&runs_key(epoch, leaf_id))?;
            return txn.set(&leaf_key(epoch, leaf_id), record);
        }
        for source in earlier_sources(runs, epoch) {
            txn.set(&chunk_key(source, leaf_id, RUNS_WITNESS), &[])?;
        }
        txn.delete(&leaf_key(epoch, leaf_id))?;
        txn.set(&runs_key(epoch, leaf_id), record)
    }

    /// A leaf's stored record at `epoch`: its [`HASH_LEAF`] record, else
    /// its [`LEAF_RUNS`] record while every earlier epoch's chunks that one
    /// reads are kept. A build before runs evicts those it does not know
    /// are read, and the [`RUNS_WITNESS`] with them: the leaf is then not
    /// stored, and encoded again, rather than stored with chunks missing.
    fn leaf_value(&self, epoch: u64, leaf_id: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.db.get(&leaf_key(epoch, leaf_id))? {
            return Ok(Some(value));
        }
        let Some(value) = self.db.get(&runs_key(epoch, leaf_id))? else {
            return Ok(None);
        };
        for source in earlier_sources(&HashLeaf::layout(&value)?.sources, epoch) {
            if self
                .db
                .get(&chunk_key(source, leaf_id, RUNS_WITNESS))?
                .is_none()
            {
                if stale_runs().insert((epoch, leaf_id.to_vec())) {
                    tracing::warn!(epoch, leaf = %hex::encode(leaf_id), source_epoch = source,
                        scope = "this node",
                        action = "none: the leaf's next snapshot encodes it again; expected \
                                  once after running an earlier build",
                        "storage replica stored in chunk runs reads chunks of `source_epoch` \
                         that an earlier build of this node evicted: the leaf counts as not \
                         stored until it is encoded again");
                }
                return Ok(None);
            }
        }
        Ok(Some(value))
    }

    /// The record of this leaf at the latest earlier epoch
    /// ([`Self::note_snapshot`]) and that epoch, when it holds `n` nodes in
    /// chunks of [`CHUNK_NODES`]: the chunks a write at `epoch` may keep.
    fn chunk_base(&self, epoch: u64, leaf_id: &[u8], n: u64) -> Result<Option<(u64, HashLeaf)>> {
        let Some(noted) = self.db.get(&meta_key(SNAPSHOT_REUSE, 0, leaf_id))? else {
            return Ok(None);
        };
        let from = match noted.get(32..) {
            Some(from) if from.len() == 8 => u64::from_be_bytes(from.try_into().expect("8 bytes")),
            _ => return Ok(None),
        };
        if from >= epoch {
            return Ok(None);
        }
        let Some(value) = self.leaf_value(from, leaf_id)? else {
            return Ok(None);
        };
        Ok(HashLeaf::decode(&value)
            .ok()
            .filter(|leaf| leaf.n == n && leaf.chunk_nodes == CHUNK_NODES)
            .map(|leaf| (from, leaf)))
    }

    /// Per chunk of `replica`, the epoch whose keys hold the same bytes for
    /// `base`, this leaf's record at `from`, or `None` where they differ:
    /// the chunks a write need not repeat. The bytes are compared, so a
    /// chunk read back other than written is written again; the caps'
    /// roots of the chunks, where both have one per chunk, spare reading
    /// those that changed. A base that cannot be read keeps nothing.
    fn unchanged_chunks(
        &self,
        from: u64,
        leaf_id: &[u8],
        base: &HashLeaf,
        replica: &[u8],
        cap: &[u8],
    ) -> Vec<Option<u64>> {
        use quil_crypto::storage_proof::CAP_HEIGHT;
        let chunk_bytes = CHUNK_NODES as usize * NODE_BYTES;
        let chunks = replica.len().div_ceil(chunk_bytes);
        let mut kept = vec![None; chunks];
        let new = MerkleCap::from_bytes(cap);
        let roots = new
            .as_ref()
            .filter(|new| new.n == base.n && new.height == CAP_HEIGHT)
            .filter(|_| base.cap.height == CAP_HEIGHT)
            .map(|new| (&new.levels[0], &base.cap.levels[0]));
        let maybe_same =
            |chunk: usize| roots.is_none_or(|(new, old)| new.get(chunk) == old.get(chunk));
        let mut chunk = 0;
        while chunk < chunks {
            if !maybe_same(chunk) {
                chunk += 1;
                continue;
            }
            let mut end = chunk + 1;
            while end < chunks && end - chunk < CHUNKS_PER_SCAN as usize && maybe_same(end) {
                end += 1;
            }
            let nodes = chunk as u64 * CHUNK_NODES..base.n.min(end as u64 * CHUNK_NODES);
            let old = match self.read_nodes(from, leaf_id, base, nodes) {
                Ok(old) => old,
                Err(error) => {
                    tracing::warn!(epoch = from, leaf = %hex::encode(leaf_id), %error,
                        scope = "this node", action = "check this node's disk and store health",
                        "storage replica of an earlier epoch could not be read to find the \
                         chunks a new one shares with it: the new one is written whole");
                    return vec![None; chunks];
                }
            };
            let new = replica[chunk * chunk_bytes..].chunks(chunk_bytes);
            for (at, (old, new)) in old.chunks(chunk_bytes).zip(new).enumerate() {
                if old == new {
                    kept[chunk + at] = Some(base.chunk_source(from, (chunk + at) as u64).0);
                }
            }
            chunk = end;
        }
        kept
    }

    /// Reuse the same immutable nodes in a later epoch. The source's data cap
    /// and complete registration are retained; no chunk is copied. Eviction
    /// pins exactly the chunk runs still referenced by a live epoch.
    pub fn alias_hash(&self, epoch: u64, leaf_id: &[u8], from: u64) -> Result<bool> {
        if from >= epoch {
            return Ok(false);
        }
        let _writing = hash_writes().lock().unwrap_or_else(PoisonError::into_inner);
        let Some(value) = self.leaf_value(from, leaf_id)? else {
            return Ok(false);
        };
        let leaf = HashLeaf::decode(&value)?;
        let Some(cap) = self.db.get(&meta_key(DATA_CAP, from, leaf_id))? else {
            return Ok(false);
        };
        let data = MerkleCap::from_bytes(&cap)
            .ok_or_else(|| QuilError::Store("invalid source data cap".into()))?;
        let registered =
            quil_crypto::storage_proof::parse_registration_root(&leaf.registration_root)
                .ok_or_else(|| QuilError::Store("invalid source registration".into()))?;
        if data.n != leaf.n
            || data.commitment(quil_crypto::storage_proof::Tree::Data) != registered.comm_d
        {
            return Err(QuilError::Store(
                "source data cap differs from registration".into(),
            ));
        }
        let runs = leaf.runs(from);
        if runs.iter().any(|&(_, source)| source > from) {
            return Err(QuilError::Store("forward snapshot reference".into()));
        }
        let body = HashLeaf::body(&value)
            .ok_or_else(|| QuilError::Store("invalid source leaf record".into()))?;
        let alias = HashLeaf::encode_runs(epoch, &runs, body);
        let txn = self.db.new_batch(false)?;
        self.put_record(&*txn, epoch, leaf_id, &alias, &runs)?;
        txn.set(&meta_key(DATA_CAP, epoch, leaf_id), &cap)?;
        txn.delete(&meta_key(HASH_LEAF_SOURCE, epoch, leaf_id))?;
        txn.commit()?;
        forget_leaves(|e, id| e == epoch && id == leaf_id);
        Ok(true)
    }

    /// Whether a leaf record of another epoch reads chunks of `leaf_id`
    /// stored under `epoch`.
    fn is_referenced(&self, epoch: u64, leaf_id: &[u8]) -> Result<bool> {
        Ok(self
            .referenced_chunks(0)?
            .iter()
            .any(|(source, id, ..)| *source == epoch && id == leaf_id))
    }

    /// The chunk runs stored under an earlier epoch that the leaf records
    /// of epochs `from` on read.
    fn referenced_chunks(&self, from: u64) -> Result<std::collections::BTreeSet<ChunkRun>> {
        let mut out = std::collections::BTreeSet::new();
        for kind in [HASH_LEAF, LEAF_RUNS] {
            self.referenced_by(kind, from, &mut out)?;
        }
        Ok(out)
    }

    /// [`Self::referenced_chunks`] by the records of `kind`, into `out`;
    /// a runs record's [`RUNS_WITNESS`] keys among them.
    fn referenced_by(
        &self,
        kind: u8,
        from: u64,
        out: &mut std::collections::BTreeSet<ChunkRun>,
    ) -> Result<()> {
        let mut iter = self
            .db
            .new_iter(&meta_key(kind, from, &[]), &meta_key(kind + 1, 0, &[]))?;
        let mut ok = iter.first();
        while ok {
            let key = iter.key();
            if key.len() < 11 {
                return Err(QuilError::Store("invalid leaf key".into()));
            }
            let epoch = u64::from_be_bytes(key[3..11].try_into().unwrap());
            // Legacy metadata may contain an evictable incomplete cache; it
            // cannot pin chunks. Only alias and run records carry references.
            if !matches!(
                iter.value().first(),
                Some(&(HASH_LEAF_ALIAS | HASH_LEAF_RUNS))
            ) {
                ok = iter.next();
                continue;
            }
            let leaf = HashLeaf::layout(iter.value())?;
            for (at, &(first, source)) in leaf.sources.iter().enumerate() {
                if source > epoch {
                    return Err(QuilError::Store("invalid replica reference".into()));
                }
                if source < epoch {
                    let end = leaf
                        .sources
                        .get(at + 1)
                        .map_or(leaf.chunks(), |&(next, _)| u64::from(next));
                    out.insert((source, key[11..].to_vec(), u64::from(first), end));
                }
            }
            if kind == LEAF_RUNS {
                for source in earlier_sources(&leaf.sources, epoch) {
                    let witness = u64::from(RUNS_WITNESS);
                    out.insert((source, key[11..].to_vec(), witness, witness + 1));
                }
            }
            ok = iter.next();
        }
        iter.close()
    }

    pub fn snapshot_match(&self, leaf_id: &[u8], fingerprint: &[u8; 32]) -> Result<Option<u64>> {
        Ok(self
            .db
            .get(&meta_key(SNAPSHOT_REUSE, 0, leaf_id))?
            .filter(|bytes| bytes.len() == 40 && bytes[..32] == fingerprint[..])
            .map(|bytes| u64::from_be_bytes(bytes[32..].try_into().unwrap())))
    }

    pub fn note_snapshot(&self, epoch: u64, leaf_id: &[u8], fingerprint: &[u8; 32]) -> Result<()> {
        let mut bytes = fingerprint.to_vec();
        bytes.extend_from_slice(&epoch.to_be_bytes());
        self.db.set(&meta_key(SNAPSHOT_REUSE, 0, leaf_id), &bytes)
    }

    /// Cache metadata only after the replica was committed; always bind it
    /// back to that registration when reading it.
    pub fn put_data_cap(&self, epoch: u64, leaf_id: &[u8], cap: &MerkleCap) -> Result<()> {
        use quil_crypto::storage_proof::{parse_registration_root, Tree};
        let _writing = hash_writes().lock().unwrap_or_else(PoisonError::into_inner);
        let leaf = self
            .leaf_value(epoch, leaf_id)?
            .and_then(|bytes| HashLeaf::decode(&bytes).ok())
            .ok_or_else(|| QuilError::Store("no chunked replica for data cap".into()))?;
        let registered = parse_registration_root(&leaf.registration_root)
            .ok_or_else(|| QuilError::Store("invalid replica registration".into()))?;
        if cap.n != leaf.n || cap.commitment(Tree::Data) != registered.comm_d {
            return Err(QuilError::Store(
                "data cap differs from replica registration".into(),
            ));
        }
        self.db
            .set(&meta_key(DATA_CAP, epoch, leaf_id), &cap.to_bytes())
    }

    pub fn get_data_cap(&self, epoch: u64, leaf_id: &[u8]) -> Result<Option<MerkleCap>> {
        let Some(bytes) = self.db.get(&meta_key(DATA_CAP, epoch, leaf_id))? else {
            return Ok(None);
        };
        Ok(MerkleCap::from_bytes(&bytes))
    }

    /// A hash-proof epoch's leaf as [`Self::put_hash`] stored it, nodes and
    /// all, or `None`. Holds the whole replica: only for work admitted for
    /// that memory (seals, settlements); a frame reads what it opens
    /// ([`Self::get_hash_leaf`], [`Self::read_nodes`]).
    pub fn get_hash(&self, epoch: u64, leaf_id: &[u8]) -> Result<Option<HashReplica>> {
        let Some(leaf) = self.get_hash_leaf(epoch, leaf_id)? else {
            return Ok(None);
        };
        let replica = self.read_nodes(epoch, leaf_id, &leaf, 0..leaf.n)?;
        Ok(Some(HashReplica {
            replica: LoadedReplica::new(replica),
            cap: leaf.cap.to_bytes(),
            registration_root: leaf.registration_root.clone(),
        }))
    }

    /// A hash-proof epoch's leaf without its nodes, or `None`. A leaf an
    /// earlier build stored whole is converted to the chunked layout first,
    /// after any other write or conversion in this process.
    pub fn get_hash_leaf(&self, epoch: u64, leaf_id: &[u8]) -> Result<Option<Arc<HashLeaf>>> {
        self.hash_leaf(epoch, leaf_id, true)
    }

    /// [`Self::get_hash_leaf`] for the proposal path, which never reads a
    /// whole replica nor waits: a leaf not stored chunked is looked up, and
    /// converted when an earlier build stored it whole, on a thread of its
    /// own, and is [`QuilError::ExecutionUnavailable`] until that is done.
    pub fn try_get_hash_leaf(&self, epoch: u64, leaf_id: &[u8]) -> Result<Option<Arc<HashLeaf>>> {
        self.hash_leaf(epoch, leaf_id, false)
    }

    /// This store, for the leaf cache: handles share the `Arc`.
    fn identity(&self) -> usize {
        Arc::as_ptr(&self.db) as *const () as usize
    }

    fn hash_leaf(&self, epoch: u64, leaf_id: &[u8], wait: bool) -> Result<Option<Arc<HashLeaf>>> {
        let key = (self.identity(), epoch, leaf_id.to_vec());
        if let Some(leaf) = leaf_cache().get(&key) {
            return Ok(Some(leaf));
        }
        let value = match self.leaf_value(epoch, leaf_id)? {
            Some(value) => value,
            None => {
                let converted = if wait {
                    let _writing = hash_writes().lock().unwrap_or_else(PoisonError::into_inner);
                    self.convert_legacy(epoch, leaf_id)?
                } else {
                    self.convert_in_background(key.clone())?
                };
                if !converted {
                    return Ok(None);
                }
                let Some(value) = self.leaf_value(epoch, leaf_id)? else {
                    return Ok(None);
                };
                value
            }
        };
        let leaf = Arc::new(HashLeaf::decode(&value)?);
        leaf_cache().insert(key, &self.db, leaf.clone());
        Ok(Some(leaf))
    }

    /// The proposal path's lookup of a leaf not stored chunked: whether a
    /// stored legacy leaf was converted (`Ok(false)` once none was found),
    /// or unavailable while a conversion is queued or running.
    fn convert_in_background(&self, key: LeafCacheKey) -> Result<bool> {
        let busy = || {
            QuilError::ExecutionUnavailable(
                "this leaf's stored replica is being looked up and converted to the chunked \
                 layout off the proposal path; a later frame reads it"
                    .into(),
            )
        };
        let mut lookups = legacy_lookups();
        match lookups.get(&key) {
            Some((store, state)) if store.strong_count() > 0 => {
                return match state {
                    LegacyLookup::Absent => Ok(false),
                    LegacyLookup::Pending => Err(busy()),
                };
            }
            Some(_) => {
                lookups.remove(&key);
            }
            None => {}
        }
        lookups.insert(
            key.clone(),
            (Arc::downgrade(&self.db), LegacyLookup::Pending),
        );
        drop(lookups);
        let store = self.clone();
        let job = key.clone();
        let running = Background::start();
        let spawned = std::thread::Builder::new()
            .name("replica-convert".into())
            .spawn(move || {
                let _running = running;
                let key = job;
                let (_, epoch, leaf_id) = &key;
                let outcome = {
                    let _writing = hash_writes().lock().unwrap_or_else(PoisonError::into_inner);
                    store.convert_legacy(*epoch, leaf_id)
                };
                let mut lookups = legacy_lookups();
                match outcome {
                    Ok(false) => {
                        lookups.insert(
                            key.clone(),
                            (Arc::downgrade(&store.db), LegacyLookup::Absent),
                        );
                    }
                    Ok(true) => {
                        lookups.remove(&key);
                    }
                    Err(error) => {
                        lookups.remove(&key);
                        tracing::warn!(epoch = *epoch, leaf = %hex::encode(leaf_id), %error,
                            scope = "this node",
                            action = "check this node's disk and store health; the next frame \
                                      that opens the leaf tries again",
                            "storage replica conversion to the chunked layout failed: frames \
                             opening this leaf commit no root until it succeeds");
                    }
                }
                drop(lookups);
                // The store may close here: before the thread is counted out.
                drop(store);
            });
        if spawned.is_err() {
            legacy_lookups().remove(&key);
        }
        Err(busy())
    }

    /// Convert the leaf an earlier build stored whole under its replica key,
    /// if there is one, to the chunked layout, reading it in place; whether
    /// the leaf is stored chunked now. The caller holds [`hash_writes`].
    fn convert_legacy(&self, epoch: u64, leaf_id: &[u8]) -> Result<bool> {
        // Converted while the caller waited.
        if self.db.get(&leaf_key(epoch, leaf_id))?.is_some() {
            return Ok(true);
        }
        let legacy = replica_key(epoch, leaf_id);
        let started = std::time::Instant::now();
        let mut converted: Result<Option<u64>> = Ok(None);
        self.db.get_with(&legacy, &mut |value| {
            let Some(stored) = LegacyHashReplica::decode(value) else {
                return;
            };
            let bytes = value.len() as u64;
            note_loaded(bytes);
            converted = self
                .write_hash(
                    epoch,
                    leaf_id,
                    stored.replica,
                    stored.cap,
                    stored.registration_root,
                )
                .map(|()| Some(bytes));
            LOADED_BYTES.fetch_sub(bytes, Ordering::Relaxed);
        })?;
        let Some(bytes) = converted? else {
            return Ok(false);
        };
        self.db.delete(&legacy)?;
        let mut end = legacy.clone();
        end.push(0);
        // Before the next conversion: what a backlog of them may take on disk
        // stays one replica beyond the store.
        reclaim(&self.db, &legacy, &end, "converted");
        tracing::info!(
            epoch,
            leaf = %hex::encode(leaf_id),
            mb = bytes >> 20,
            ms = started.elapsed().as_millis() as u64,
            "storage replica converted to the chunked layout: its frames now read only the \
             nodes they open"
        );
        Ok(true)
    }

    /// [`reclaim`] off the calling thread, when there is anything to compact.
    fn reclaim_in_background(&self, lo: Vec<u8>, hi: Vec<u8>, what: &'static str) {
        match self.db.holds_file_of(&lo, &hi, WHOLE_REPLICA_FILE_BYTES) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                tracing::warn!(replicas = what, %error, "storage replica compaction not started");
                return;
            }
        }
        let db = self.db.clone();
        let running = Background::start();
        let spawned = std::thread::Builder::new()
            .name("replica-reclaim".into())
            .spawn(move || {
                let _running = running;
                reclaim(&db, &lo, &hi, what);
                // The store may close here: before the thread is counted out.
                drop(db);
            });
        if let Err(error) = spawned {
            tracing::warn!(replicas = what, %error, "storage replica compaction not started");
        }
    }

    /// Nodes `nodes` of a stored leaf (`leaf`, from [`Self::get_hash_leaf`]),
    /// serialized, read from only the chunks holding them.
    pub fn read_nodes(
        &self,
        epoch: u64,
        leaf_id: &[u8],
        leaf: &HashLeaf,
        nodes: std::ops::Range<u64>,
    ) -> Result<Vec<u8>> {
        if leaf.sources.iter().any(|&(_, source)| source > epoch) {
            return Err(QuilError::Store("forward replica alias".into()));
        }
        let missing = || {
            QuilError::Store(format!(
                "nodes {}..{} of a stored replica of {} nodes are missing",
                nodes.start, nodes.end, leaf.n
            ))
        };
        if nodes.start > nodes.end || nodes.end > leaf.n {
            return Err(missing());
        }
        let mut out = Vec::with_capacity((nodes.end - nodes.start) as usize * NODE_BYTES);
        if nodes.is_empty() {
            return Ok(out);
        }
        let per = leaf.chunk_nodes;
        let (first, last) = (nodes.start / per, (nodes.end - 1) / per);
        let mut take_chunk = |chunk: u64, bytes: &[u8]| -> Result<()> {
            let at = chunk * per;
            let expected = (leaf.n - at).min(per) as usize * NODE_BYTES;
            if bytes.len() != expected {
                return Err(missing());
            }
            let lo = (nodes.start.max(at) - at) as usize * NODE_BYTES;
            let hi = (nodes.end.min(at + per) - at) as usize * NODE_BYTES;
            out.extend_from_slice(&bytes[lo..hi]);
            Ok(())
        };
        if first == last {
            let (source, _) = leaf.chunk_source(epoch, first);
            let bytes = self
                .db
                .get(&chunk_key(source, leaf_id, first as u32))?
                .ok_or_else(missing)?;
            take_chunk(first, &bytes)?;
            return Ok(out);
        }
        // A range scan holds all it covers, so scan in windows, each within
        // one run of chunks.
        let mut chunk = first;
        while chunk <= last {
            let (source, run_end) = leaf.chunk_source(epoch, chunk);
            let end = (chunk + CHUNKS_PER_SCAN).min(last + 1).min(run_end);
            let mut iter = self.db.new_iter(
                &chunk_key(source, leaf_id, chunk as u32),
                &chunk_key(source, leaf_id, end as u32),
            )?;
            let mut ok = iter.first();
            while ok {
                if chunk >= end || iter.key() != chunk_key(source, leaf_id, chunk as u32) {
                    return Err(missing());
                }
                take_chunk(chunk, iter.value())?;
                chunk += 1;
                ok = iter.next();
            }
            iter.close()?;
            if chunk != end {
                return Err(missing());
            }
        }
        Ok(out)
    }

    /// Record the leaf prefixes of shard `filter` as snapshotted for `epoch`'s
    /// registrations; their replicas are stored under the same epoch.
    pub fn put_partition(&self, epoch: u64, filter: &[u8], prefixes: &[Vec<u32>]) -> Result<()> {
        let mut value = Vec::new();
        value.extend_from_slice(&(prefixes.len() as u32).to_be_bytes());
        for prefix in prefixes {
            value.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
            for nibble in prefix {
                value.extend_from_slice(&nibble.to_be_bytes());
            }
        }
        self.db.set(&meta_key(PARTITION, epoch, filter), &value)
    }

    /// The leaf prefixes [`Self::put_partition`] recorded, or `None`.
    pub fn get_partition(&self, epoch: u64, filter: &[u8]) -> Result<Option<Vec<Vec<u32>>>> {
        let Some(value) = self.db.get(&meta_key(PARTITION, epoch, filter))? else {
            return Ok(None);
        };
        let mut words = value
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        let count = words.next().unwrap_or(0);
        let mut prefixes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let Some(len) = words.next() else {
                return Ok(None);
            };
            let prefix: Vec<u32> = words.by_ref().take(len as usize).collect();
            if prefix.len() != len as usize {
                return Ok(None);
            }
            prefixes.push(prefix);
        }
        Ok(Some(prefixes))
    }

    /// Record the snapshot sources (encoded) shard `filter`'s leaves for
    /// `epoch` were read from.
    pub fn put_snapshot_sources(&self, epoch: u64, filter: &[u8], sources: &[u8]) -> Result<()> {
        self.db
            .set(&meta_key(SNAPSHOT_SOURCES, epoch, filter), sources)
    }

    /// What [`Self::put_snapshot_sources`] recorded, or `None`.
    pub fn get_snapshot_sources(&self, epoch: u64, filter: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(&meta_key(SNAPSHOT_SOURCES, epoch, filter))
    }

    /// The shards [`Self::put_snapshot_sources`] recorded sources of for
    /// `epoch`: those whose registrations for it were encoded here.
    pub fn snapshot_source_filters(&self, epoch: u64) -> Result<Vec<Vec<u8>>> {
        let lower = meta_key(SNAPSHOT_SOURCES, epoch, &[]);
        let upper = meta_key(SNAPSHOT_SOURCES, epoch.saturating_add(1), &[]);
        let mut iter = self.db.new_iter(&lower, &upper)?;
        let mut filters = Vec::new();
        let mut ok = iter.first();
        while ok {
            if let Some(filter) = iter.key().get(lower.len()..) {
                filters.push(filter.to_vec());
            }
            ok = iter.next();
        }
        iter.close()?;
        Ok(filters)
    }

    /// Record the node count of each leaf of shard `filter`'s partition for
    /// `epoch`, in the partition's order.
    pub fn put_leaf_nodes(&self, epoch: u64, filter: &[u8], nodes: &[u64]) -> Result<()> {
        let value: Vec<u8> = nodes.iter().flat_map(|n| n.to_be_bytes()).collect();
        self.db.set(&meta_key(LEAF_NODES, epoch, filter), &value)
    }

    /// What [`Self::put_leaf_nodes`] recorded, or `None` (also for a partition
    /// stored before the counts were).
    pub fn get_leaf_nodes(&self, epoch: u64, filter: &[u8]) -> Result<Option<Vec<u64>>> {
        Ok(self
            .db
            .get(&meta_key(LEAF_NODES, epoch, filter))?
            .filter(|value| value.len() % 8 == 0)
            .map(|value| {
                value
                    .chunks_exact(8)
                    .map(|n| u64::from_be_bytes(n.try_into().expect("8 bytes")))
                    .collect()
            }))
    }

    /// Remove one replica, whole or chunked.
    pub fn delete(&self, epoch: u64, leaf_id: &[u8]) -> Result<()> {
        let _writing = hash_writes().lock().unwrap_or_else(PoisonError::into_inner);
        forget_leaves(|e, id| e == epoch && id == leaf_id);
        self.db.delete(&meta_key(DATA_CAP, epoch, leaf_id))?;
        self.db
            .delete(&meta_key(HASH_LEAF_SOURCE, epoch, leaf_id))?;
        self.db.delete(&leaf_key(epoch, leaf_id))?;
        self.db.delete(&runs_key(epoch, leaf_id))?;
        if !self.is_referenced(epoch, leaf_id)? {
            self.db.delete_range(
                &chunk_key(epoch, leaf_id, 0),
                &chunk_key(epoch, leaf_id, u32::MAX),
            )?;
        }
        self.db.delete(&replica_key(epoch, leaf_id))
    }

    /// Drop every replica for an epoch strictly below `keep_from` — called
    /// after re-encoding for a new epoch so stale replicas don't accumulate.
    pub fn evict_below_epoch(&self, keep_from: u64) -> Result<()> {
        self.evict(keep_from, "unnamed")
    }

    /// [`Self::evict_below_epoch`], unless this store was already evicted
    /// below `keep_from` or a later epoch in this process; whether it
    /// evicted. A boundary then writes its range deletions, and compacts
    /// them, once per store, however often confirmations ask (a
    /// reconfirmation asks every few frames until it publishes). `store`
    /// names it in the compaction's lines. A failed eviction is not
    /// recorded: the next call tries again.
    pub fn evict_below_epoch_once(&self, keep_from: u64, store: &str) -> Result<bool> {
        if keep_from == 0 {
            return Ok(false);
        }
        let mut evicted = evicted_below();
        let id = self.identity();
        if let Some((open, below)) = evicted.get(&id) {
            if open.strong_count() > 0 && *below >= keep_from {
                return Ok(false);
            }
        }
        self.evict(keep_from, store)?;
        evicted.retain(|_, (open, _)| open.strong_count() > 0);
        evicted.insert(id, (Arc::downgrade(&self.db), keep_from));
        Ok(true)
    }

    fn evict(&self, keep_from: u64, store: &str) -> Result<()> {
        let _writing = hash_writes().lock().unwrap_or_else(PoisonError::into_inner);
        let pinned = self.referenced_chunks(keep_from)?;
        let mut lo = Vec::with_capacity(9);
        lo.push(STORAGE_REPLICA);
        lo.extend_from_slice(&0u64.to_be_bytes());
        let mut hi = Vec::with_capacity(9);
        hi.push(STORAGE_REPLICA);
        hi.extend_from_slice(&keep_from.to_be_bytes());
        // delete_range is [lo, hi): epochs 0..keep_from.
        self.db.delete_range(&lo, &hi)?;
        self.reclaim_in_background(lo, hi, "evicted");
        forget_leaves(|epoch, _| epoch < keep_from);
        for kind in [
            PARTITION,
            SNAPSHOT_SOURCES,
            LEAF_NODES,
            HASH_LEAF,
            DATA_CAP,
            LEAF_RUNS,
            HASH_LEAF_SOURCE,
        ] {
            self.db
                .delete_range(&meta_key(kind, 0, &[]), &meta_key(kind, keep_from, &[]))?;
        }
        let mut at = meta_key(HASH_NODES, 0, &[]);
        let until = meta_key(HASH_NODES, keep_from, &[]);
        // Only the chunks a live epoch reads: an earlier epoch's chunks a
        // later one wrote again go.
        let index = |chunk: u64| u32::try_from(chunk).unwrap_or(u32::MAX);
        let mut protected: Vec<_> = pinned
            .into_iter()
            .filter(|(epoch, ..)| *epoch < keep_from)
            .map(|(epoch, id, first, end)| {
                (
                    chunk_key(epoch, &id, index(first)),
                    chunk_key(epoch, &id, index(end)),
                )
            })
            .collect();
        protected.sort();
        for (lo, hi) in protected {
            if at < lo {
                self.db.delete_range(&at, &lo)?;
            }
            at = at.max(hi);
        }
        if at < until {
            self.db.delete_range(&at, &until)?;
        }
        self.compact_evicted_in_background(keep_from, store);
        Ok(())
    }

    /// Compact the evicted epochs' chunks ([`HASH_NODES`] keys below
    /// `keep_from`, nearly all a replica takes) off the calling thread. A
    /// range deletion only hides them: until a compaction through the
    /// bottommost level reaches them they keep their space, an epoch of a
    /// store's replicas, for as long as automatic compaction leaves those
    /// files alone (days on a regular node).
    fn compact_evicted_in_background(&self, keep_from: u64, store: &str) {
        let lo = meta_key(HASH_NODES, 0, &[]);
        let hi = meta_key(HASH_NODES, keep_from, &[]);
        match self
            .db
            .live_file_bytes(Some((lo.as_slice(), hi.as_slice())))
        {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(store, below_epoch = keep_from, %error,
                    "compaction of evicted storage replicas not started");
                return;
            }
        }
        let db = self.db.clone();
        let name = store.to_owned();
        let running = Background::start();
        let spawned = std::thread::Builder::new()
            .name("replica-reclaim".into())
            .spawn(move || {
                let _running = running;
                compact_evicted(&db, &lo, &hi, keep_from, &name);
                // The store may close here: before the thread is counted out.
                drop(db);
            });
        if let Err(error) = spawned {
            tracing::warn!(store, below_epoch = keep_from, %error,
                "compaction of evicted storage replicas not started");
        }
    }

    /// Iterate `(leaf_id, replica)` for every leaf stored under `epoch`. Used by
    /// the per-frame producer to answer challenges for the active epoch.
    pub fn for_each_in_epoch(&self, epoch: u64, mut f: impl FnMut(Vec<u8>, Vec<u8>)) -> Result<()> {
        let (lo, hi) = epoch_bounds(epoch);
        let mut iter = self.db.new_iter(&lo, &hi)?;
        let prefix_len = 1 + 8; // STORAGE_REPLICA + epoch
        let mut ok = iter.first();
        while ok {
            let k = iter.key().to_vec();
            let v = iter.value().to_vec();
            if k.len() >= prefix_len {
                f(k[prefix_len..].to_vec(), v);
            }
            ok = iter.next();
        }
        iter.close()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ReplicaStore {
        let rocks = crate::RocksDb::open_in_memory().unwrap();
        ReplicaStore::new(Arc::new(rocks))
    }

    /// [`ReplicaStore::put_hash`], then the `source` it was encoded from.
    fn put_hash_from(
        s: &ReplicaStore,
        epoch: u64,
        leaf_id: &[u8],
        replica: &[u8],
        cap: &[u8],
        root: &[u8],
        source: &[u8],
    ) {
        s.put_hash(epoch, leaf_id, replica, cap, root).unwrap();
        s.put_hash_source(epoch, leaf_id, source).unwrap();
    }

    #[test]
    fn aliases_survive_base_eviction_restart_and_flattened_chains() {
        let s = store();
        let (nodes, cap) = hash_leaf(3 * CHUNK_NODES as usize + 7, 19);
        let data_cap = MerkleCap::from_bytes(&cap).unwrap();
        let root = quil_crypto::storage_proof::registration_root(
            &data_cap.commitment(quil_crypto::storage_proof::Tree::Data),
            &[0; 32],
            &data_cap.commitment(quil_crypto::storage_proof::Tree::Replica),
        );
        s.put_hash(3, b"leaf", &nodes, &cap, &root).unwrap();
        s.put_data_cap(3, b"leaf", &data_cap).unwrap();
        assert!(s.alias_hash(4, b"leaf", 3).unwrap());
        assert!(s.alias_hash(5, b"leaf", 4).unwrap());
        assert!(!s.alias_hash(5, b"leaf", 5).unwrap());
        assert!(!s.alias_hash(5, b"absent", 3).unwrap());
        assert!(s.db.get(&chunk_key(5, b"leaf", 0)).unwrap().is_none());
        assert!(
            s.put_hash(3, b"leaf", &nodes, &cap, &[0; 96]).is_err(),
            "live alias protects base from overwrite"
        );
        s.evict_below_epoch(5).unwrap();
        assert!(s.get_hash_leaf(3, b"leaf").unwrap().is_none());
        let reopened = ReplicaStore::new(s.db.clone());
        assert_eq!(
            reopened.get_hash(5, b"leaf").unwrap().unwrap().replica[..],
            nodes[..]
        );
        assert_eq!(reopened.get_data_cap(5, b"leaf").unwrap(), Some(data_cap));
        assert!(reopened.alias_hash(6, b"leaf", 5).unwrap());
        reopened.delete(5, b"leaf").unwrap();
        assert_eq!(
            reopened.get_hash(6, b"leaf").unwrap().unwrap().replica[..],
            nodes[..]
        );
        reopened.evict_below_epoch(7).unwrap();
        assert!(
            reopened
                .db
                .get(&chunk_key(3, b"leaf", 0))
                .unwrap()
                .is_none(),
            "last reference gone reclaims base"
        );
    }

    #[test]
    fn deleting_base_metadata_keeps_live_alias_chunks() {
        let s = store();
        let (nodes, cap) = hash_leaf(33, 6);
        let data_cap = MerkleCap::from_bytes(&cap).unwrap();
        let root = quil_crypto::storage_proof::registration_root(
            &data_cap.commitment(quil_crypto::storage_proof::Tree::Data),
            &[0; 32],
            &data_cap.commitment(quil_crypto::storage_proof::Tree::Replica),
        );
        s.put_hash(3, b"leaf", &nodes, &cap, &root).unwrap();
        s.put_data_cap(3, b"leaf", &MerkleCap::from_bytes(&cap).unwrap())
            .unwrap();
        s.note_snapshot(3, b"leaf", &[8; 32]).unwrap();
        assert_eq!(s.snapshot_match(b"leaf", &[8; 32]).unwrap(), Some(3));
        assert_eq!(s.snapshot_match(b"leaf", &[9; 32]).unwrap(), None);
        assert!(s.alias_hash(4, b"leaf", 3).unwrap());
        s.delete(3, b"leaf").unwrap();
        assert_eq!(
            s.get_hash(4, b"leaf").unwrap().unwrap().replica[..],
            nodes[..]
        );
    }

    #[test]
    fn put_get_delete_round_trip() {
        let s = store();
        let leaf = b"leaf-a";
        assert_eq!(s.get(3, leaf).unwrap(), None);
        s.put(3, leaf, b"replica-bytes").unwrap();
        assert_eq!(
            s.get(3, leaf).unwrap().as_deref(),
            Some(&b"replica-bytes"[..])
        );
        s.delete(3, leaf).unwrap();
        assert_eq!(s.get(3, leaf).unwrap(), None);
    }

    /// Canonical serialized nodes (every element below 2^30) and their cap.
    fn hash_leaf(n: usize, seed: u32) -> (Vec<u8>, Vec<u8>) {
        let nodes: Vec<u8> = (0..n * 8)
            .map(|i| ((i as u32).wrapping_mul(0x9E37_79B9) ^ seed.wrapping_mul(0x85EB_CA6B)) >> 2)
            .flat_map(u32::to_le_bytes)
            .collect();
        let cap = quil_crypto::storage_proof::MerkleTree::from_nodes(&nodes)
            .unwrap()
            .cap(quil_crypto::storage_proof::CAP_HEIGHT)
            .to_bytes();
        (nodes, cap)
    }

    /// The value builds before the chunked layout stored a hash leaf as.
    fn legacy_value(replica: &[u8], cap: &[u8], registration_root: &[u8]) -> Vec<u8> {
        let mut value = vec![LEGACY_HASH_REPLICA_TAG];
        value.extend_from_slice(&(cap.len() as u32).to_be_bytes());
        value.extend_from_slice(cap);
        value.extend_from_slice(&(registration_root.len() as u32).to_be_bytes());
        value.extend_from_slice(registration_root);
        value.extend_from_slice(replica);
        value
    }

    #[test]
    fn a_hash_replica_round_trips_in_chunks_and_a_plain_one_is_not_read_as_one() {
        let s = store();
        // Three chunks, the last one short.
        let n = 2 * CHUNK_NODES as usize + 300;
        let (replica, cap) = hash_leaf(n, 1);
        s.put_hash(5, b"leaf", &replica, &cap, &[7u8; 96]).unwrap();
        let stored = s.get_hash(5, b"leaf").unwrap().unwrap();
        assert_eq!(&stored.replica[..], &replica[..]);
        assert_eq!(stored.cap, cap);
        assert_eq!(stored.registration_root, vec![7u8; 96]);
        let leaf = s.get_hash_leaf(5, b"leaf").unwrap().unwrap();
        assert_eq!((leaf.n, leaf.cap.to_bytes()), (n as u64, cap.clone()));
        let c = CHUNK_NODES;
        for nodes in [
            0..1,
            5..9,
            c - 1..c + 1,
            c..2 * c,
            3..n as u64,
            0..n as u64,
            9..9,
        ] {
            let bytes =
                &replica[nodes.start as usize * NODE_BYTES..nodes.end as usize * NODE_BYTES];
            assert_eq!(
                s.read_nodes(5, b"leaf", &leaf, nodes.clone()).unwrap(),
                bytes,
                "{nodes:?}"
            );
        }
        assert!(s.read_nodes(5, b"leaf", &leaf, 0..n as u64 + 1).is_err());
        // Another leaf whose id extends this one's keeps its own chunks.
        let (other, other_cap) = hash_leaf(40, 2);
        s.put_hash(5, b"leaf\0\0\0\0", &other, &other_cap, &[8u8; 96])
            .unwrap();
        assert_eq!(
            &s.get_hash(5, b"leaf").unwrap().unwrap().replica[..],
            &replica[..]
        );
        assert_eq!(
            &s.get_hash(5, b"leaf\0\0\0\0").unwrap().unwrap().replica[..],
            &other[..]
        );
        s.put(6, b"leaf", b"plain").unwrap();
        assert_eq!(s.get_hash(6, b"leaf").unwrap(), None);
        assert!(s
            .put_hash(7, b"leaf", b"not whole nodes", &cap, &[7u8; 96])
            .is_err());
        s.evict_below_epoch(6).unwrap();
        assert_eq!(s.get_hash(5, b"leaf").unwrap(), None);
        assert_eq!(s.get_hash_leaf(5, b"leaf").unwrap(), None);
        assert!(
            leaf_cache().entries.keys().all(|key| key.0 != s.identity()),
            "evicted records leave the cache"
        );
    }

    /// A leaf stored from a source is whole only for that source, at its
    /// epoch, with every node hashing up to its cap and the cap to its
    /// registered replica commitment: a leaf stored without its source (cut
    /// short before it was recorded), a node changed, a chunk missing or a
    /// registration of another replica is not, and writing the leaf again or
    /// deleting it drops its source.
    #[test]
    fn a_leaf_is_stored_from_its_source_only_whole_and_intact() {
        use quil_crypto::storage_proof::{registration_root, MerkleCap, Tree};
        let s = store();
        let go = || false;
        let n = 2 * CHUNK_NODES as usize + 300;
        let (replica, cap) = hash_leaf(n, 3);
        let comm_r = MerkleCap::from_bytes(&cap)
            .unwrap()
            .commitment(Tree::Replica);
        let root = registration_root(&[0; 32], &[0; 32], &comm_r);
        let from = |epoch, source: &[u8]| s.stored_from(epoch, b"leaf", source, &go).unwrap();
        assert_eq!(from(5, b"src"), StoredFrom::Unrecorded);
        s.put_hash(5, b"leaf", &replica, &cap, &root).unwrap();
        assert_eq!(from(5, b"src"), StoredFrom::Unrecorded, "no source");
        put_hash_from(&s, 5, b"leaf", &replica, &cap, &root, b"src");
        assert_eq!(from(5, b"src"), StoredFrom::Whole(n as u64));
        assert_eq!(from(5, b"other"), StoredFrom::Other);
        assert_eq!(from(6, b"src"), StoredFrom::Unrecorded, "another epoch");
        assert_eq!(
            s.stored_from(5, b"leaf", b"src", &|| true).unwrap(),
            StoredFrom::Stopped
        );

        // A node of the last, short chunk changed, then the chunk missing.
        let last = chunk_key(5, b"leaf", 2);
        let whole = s.db.get(&last).unwrap().unwrap();
        let mut changed = whole.clone();
        changed[..NODE_BYTES].copy_from_slice(&replica[..NODE_BYTES]);
        assert_ne!(changed, whole);
        s.db.set(&last, &changed).unwrap();
        assert!(matches!(from(5, b"src"), StoredFrom::Damaged(_)));
        s.db.set(&last, &whole).unwrap();
        assert_eq!(from(5, b"src"), StoredFrom::Whole(n as u64));
        s.db.delete(&last).unwrap();
        assert!(matches!(from(5, b"src"), StoredFrom::Damaged(_)));

        // Its cap, with the registration of another replica.
        let other = registration_root(&[0; 32], &[0; 32], &[0; 32]);
        put_hash_from(&s, 5, b"leaf", &replica, &cap, &other, b"src");
        assert!(matches!(from(5, b"src"), StoredFrom::Damaged(_)));

        put_hash_from(&s, 5, b"leaf", &replica, &cap, &root, b"src");
        s.put_hash(5, b"leaf", &replica, &cap, &root).unwrap();
        assert_eq!(from(5, b"src"), StoredFrom::Unrecorded, "written again");
        put_hash_from(&s, 5, b"leaf", &replica, &cap, &root, b"src");
        s.delete(5, b"leaf").unwrap();
        assert_eq!(from(5, b"src"), StoredFrom::Unrecorded, "deleted");
        put_hash_from(&s, 5, b"leaf", &replica, &cap, &root, b"src");
        s.evict_below_epoch(6).unwrap();
        assert_eq!(
            s.db.get(&meta_key(HASH_LEAF_SOURCE, 5, b"leaf")).unwrap(),
            None,
            "evicted"
        );
    }

    /// An alias drops the source recorded for the leaf it replaces; one
    /// recorded for the alias reads its base's nodes, whole while they are
    /// intact. No source is recorded for a leaf not stored.
    #[test]
    fn an_alias_is_stored_from_the_source_recorded_for_it() {
        use quil_crypto::storage_proof::{registration_root, Tree};
        let s = store();
        let go = || false;
        let n = 2 * CHUNK_NODES as usize + 5;
        let (nodes, cap) = hash_leaf(n, 23);
        let data_cap = MerkleCap::from_bytes(&cap).unwrap();
        let root = registration_root(
            &data_cap.commitment(Tree::Data),
            &[0; 32],
            &data_cap.commitment(Tree::Replica),
        );
        assert!(s.put_hash_source(4, b"leaf", b"src").is_err(), "no leaf");
        put_hash_from(&s, 3, b"leaf", &nodes, &cap, &root, b"src");
        s.put_data_cap(3, b"leaf", &data_cap).unwrap();
        put_hash_from(&s, 4, b"leaf", &nodes, &cap, &root, b"src");
        assert!(s.alias_hash(4, b"leaf", 3).unwrap());
        let from = || s.stored_from(4, b"leaf", b"src", &go).unwrap();
        assert_eq!(from(), StoredFrom::Unrecorded, "aliased");
        s.put_hash_source(4, b"leaf", b"src").unwrap();
        assert_eq!(from(), StoredFrom::Whole(n as u64));
        let first = chunk_key(3, b"leaf", 0);
        let whole = s.db.get(&first).unwrap().unwrap();
        let mut changed = whole.clone();
        changed.copy_within(NODE_BYTES..2 * NODE_BYTES, 0);
        assert_ne!(changed, whole);
        s.db.set(&first, &changed).unwrap();
        assert!(
            matches!(from(), StoredFrom::Damaged(_)),
            "a node of its base changed"
        );
    }

    /// A leaf written in its changed chunks only, in runs that read an
    /// earlier epoch's chunks, records its source and is whole while the
    /// chunks it reads are intact: its snapshot's source record must not
    /// fail for want of a whole-leaf record (`put_hash_source` looked only
    /// for one, so every leaf a later epoch kept chunks of failed its seat's
    /// encode).
    #[test]
    fn a_leaf_in_chunk_runs_is_stored_from_its_source() {
        let s = store();
        let go = || false;
        let c = CHUNK_NODES as usize;
        let n = 4 * c + 7;
        let (e3, cap3) = hash_leaf(n, 31);
        put_hash_from(&s, 3, b"leaf", &e3, &cap3, &registered(&cap3), b"src3");
        s.note_snapshot(3, b"leaf", &[3; 32]).unwrap();
        let (e4, cap4) = changed(&e3, &[2 * c + 1]);
        s.put_hash(4, b"leaf", &e4, &cap4, &registered(&cap4))
            .unwrap();
        assert!(
            s.db.get(&leaf_key(4, b"leaf")).unwrap().is_none()
                && s.db.get(&runs_key(4, b"leaf")).unwrap().is_some(),
            "epoch 4's leaf is stored in runs"
        );
        s.put_hash_source(4, b"leaf", b"src4")
            .expect("RUNS-SOURCE: a leaf in chunk runs records its source");
        let from = || s.stored_from(4, b"leaf", b"src4", &go).unwrap();
        assert_eq!(from(), StoredFrom::Whole(n as u64));
        // Chunk 0, which epoch 4 reads where epoch 3 wrote it, changed.
        let first = chunk_key(3, b"leaf", 0);
        let whole = s.db.get(&first).unwrap().unwrap();
        let mut damaged = whole.clone();
        damaged.copy_within(NODE_BYTES..2 * NODE_BYTES, 0);
        s.db.set(&first, &damaged).unwrap();
        assert!(
            matches!(from(), StoredFrom::Damaged(_)),
            "a node of a chunk it reads from epoch 3 changed"
        );
        s.db.set(&first, &whole).unwrap();
        assert_eq!(from(), StoredFrom::Whole(n as u64));
    }

    /// A leaf of any size is whole while intact and damaged with a node
    /// changed, those shallower than the cap's height too, whose tree is one
    /// subtree of it (2026-11-05: every leaf of up to 512 nodes read as
    /// damaged, for a chunk size only deeper trees' subtrees have). A cap
    /// higher than the store writes is refused: its subtrees would be read
    /// whole.
    #[test]
    fn a_leaf_of_any_size_is_whole_intact_and_damaged_with_a_node_changed() {
        use quil_crypto::storage_proof::{
            registration_root, MerkleCap, MerkleTree, Tree, CAP_HEIGHT,
        };
        let c = CHUNK_NODES as usize;
        let go = || false;
        for n in [
            2,
            3,
            40,
            c / 2 - 1,
            c / 2,
            c / 2 + 1,
            c - 1,
            c,
            c + 1,
            2 * c + 1,
        ] {
            let s = store();
            let (mut replica, cap) = hash_leaf(n, n as u32);
            let comm_r = MerkleCap::from_bytes(&cap)
                .unwrap()
                .commitment(Tree::Replica);
            let root = registration_root(&[0; 32], &[0; 32], &comm_r);
            put_hash_from(&s, 5, b"leaf", &replica, &cap, &root, b"src");
            assert_eq!(
                s.stored_from(5, b"leaf", b"src", &go).unwrap(),
                StoredFrom::Whole(n as u64),
                "{n} nodes intact"
            );
            replica.copy_within(0..NODE_BYTES, (n - 1) * NODE_BYTES);
            put_hash_from(&s, 5, b"leaf", &replica, &cap, &root, b"src");
            assert!(
                matches!(
                    s.stored_from(5, b"leaf", b"src", &go).unwrap(),
                    StoredFrom::Damaged(_)
                ),
                "{n} nodes, the last changed"
            );
        }
        let s = store();
        let (replica, _) = hash_leaf(4 * c, 7);
        let tree = MerkleTree::from_nodes(&replica).unwrap();
        let root = registration_root(&[0; 32], &[0; 32], &tree.commitment(Tree::Replica));
        let high = tree.cap(CAP_HEIGHT + 1).to_bytes();
        put_hash_from(&s, 5, b"leaf", &replica, &high, &root, b"src");
        assert!(matches!(
            s.stored_from(5, b"leaf", b"src", &go).unwrap(),
            StoredFrom::Damaged(_)
        ));
    }

    #[test]
    fn a_leaf_stored_whole_converts_once_and_reads_the_same() {
        let s = store();
        let n = CHUNK_NODES as usize + 17;
        let (replica, cap) = hash_leaf(n, 3);
        let value = legacy_value(&replica, &cap, &[9u8; 96]);
        s.db.set(&replica_key(4, b"old"), &value).unwrap();
        // A frame neither reads it whole nor waits: it is converted off the
        // proposal path, here once the write lock is free.
        let held = hash_writes().lock().unwrap();
        assert!(matches!(
            s.try_get_hash_leaf(4, b"old"),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        assert!(matches!(
            s.try_get_hash_leaf(4, b"old"),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        drop(held);
        // A confirm waits for it.
        let leaf = s.get_hash_leaf(4, b"old").unwrap().unwrap();
        assert_eq!(s.try_get_hash_leaf(4, b"old").unwrap(), Some(leaf.clone()));
        assert_eq!((leaf.n, leaf.cap.to_bytes()), (n as u64, cap.clone()));
        assert_eq!(leaf.registration_root, vec![9u8; 96]);
        assert_eq!(s.get(4, b"old").unwrap(), None, "the whole value is gone");
        let stored = s.get_hash(4, b"old").unwrap().unwrap();
        assert_eq!(&stored.replica[..], &replica[..]);
        assert_eq!(
            s.read_nodes(4, b"old", &leaf, 1000..1030).unwrap(),
            &replica[1000 * NODE_BYTES..1030 * NODE_BYTES]
        );
        // A plain replica is not converted, and a leaf never stored is
        // found absent, then answered at once.
        s.put(4, b"plain", b"replica").unwrap();
        assert_eq!(s.get_hash_leaf(4, b"plain").unwrap(), None);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while s.try_get_hash_leaf(4, b"never").is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "the lookup never settled"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(s.try_get_hash_leaf(4, b"never").unwrap(), None);
        // Writing it ends the absence.
        let (late, late_cap) = hash_leaf(9, 6);
        s.put_hash(4, b"never", &late, &late_cap, &[3u8; 96])
            .unwrap();
        assert_eq!(s.try_get_hash_leaf(4, b"never").unwrap().unwrap().n, 9);
        assert_eq!(
            wait_for_background_work(std::time::Duration::from_secs(60)),
            0
        );
        assert_eq!(
            s.get(4, b"plain").unwrap().as_deref(),
            Some(&b"replica"[..])
        );
        let (held, peak) = replica_load_bytes();
        assert!(
            held >= replica.len() as u64,
            "the loaded replica is counted"
        );
        assert!(peak >= value.len() as u64, "and the whole value converted");
        drop(stored);
    }

    /// Bytes this process has read from files so far (`rchar`: page-cache hits
    /// included). The block cache cannot show a read of a block larger than one
    /// of its shards: such a block is read and dropped.
    fn bytes_read() -> u64 {
        std::fs::read_to_string("/proc/self/io")
            .ok()
            .and_then(|io| {
                io.lines()
                    .find_map(|line| line.strip_prefix("rchar: ")?.trim().parse().ok())
            })
            .expect("/proc/self/io")
    }

    /// File bytes a lookup of a key no store holds, sorting just before the
    /// replica keys, reads.
    fn read_beside(db: &crate::RocksDb) -> u64 {
        let before = bytes_read();
        assert!(db.inner().get([0x0C, 0x09, 1, 2, 3]).unwrap().is_none());
        bytes_read() - before
    }

    /// A converted leaf's whole value is compacted away, so lookups beside it
    /// stop reading it; until then they read all of it.
    #[test]
    fn a_converted_leaf_stops_being_read_by_lookups_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::RocksDb::open(dir.path()).unwrap());
        let s = ReplicaStore::new(db.clone());
        for i in 0..64u8 {
            db.inner().put([0x0C, 0x07, i], [i; 64]).unwrap();
        }
        // A whole value past the size a table file is cut at.
        let n = 5 * WHOLE_REPLICA_FILE_BYTES as usize / 4 / NODE_BYTES;
        // Random, as a replica is: a table file holds it uncompressed.
        let mut x = 0x2545_F491u32;
        let replica: Vec<u8> = (0..n * NODE_BYTES / 4)
            .flat_map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x.to_le_bytes()
            })
            .collect();
        let cap = vec![1u8; 64];
        s.db.set(
            &replica_key(9, b"old"),
            &legacy_value(&replica, &cap, &[2u8; 96]),
        )
        .unwrap();
        db.inner().flush().unwrap();
        let whole = read_beside(&db);
        assert!(
            whole >= replica.len() as u64,
            "the control: a lookup beside a whole replica read {whole} bytes"
        );
        // The cap is no tree's, so the leaf record does not decode; the
        // conversion still runs and its compaction still starts.
        assert!(s.get_hash_leaf(9, b"old").is_err());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let read = read_beside(&db);
            if read < 1 << 20 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "a lookup beside the converted replica still read {read} bytes"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(s.get(9, b"old").unwrap(), None);
    }

    /// Bytes of `db`'s live table files.
    fn table_bytes(db: &crate::RocksDb) -> u64 {
        let files = db.inner().live_files().unwrap();
        files.iter().map(|file| file.size as u64).sum()
    }

    /// Evicted epochs' chunks leave the table files: a range deletion only
    /// hid them, and nothing compacted the chunk range, so on a regular
    /// node they kept their space for days (about 10 GiB on one).
    #[test]
    fn eviction_compacts_the_evicted_chunks_away() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::RocksDb::open(dir.path()).unwrap());
        let s = ReplicaStore::new(db.clone());
        // Random, as a replica is: stored uncompressed.
        let mut x = 0x2545_F491u32;
        let mut replica = |nodes: usize| -> Vec<u8> {
            (0..nodes * NODE_BYTES / 4)
                .flat_map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x.to_le_bytes()
                })
                .collect()
        };
        let nodes = 128 * CHUNK_NODES as usize;
        let replica_bytes = (nodes * NODE_BYTES) as u64;
        for epoch in [3, 4, 6] {
            let value = replica(nodes);
            s.put_hash(epoch, b"leaf", &value, &[1u8; 64], &[2u8; 96])
                .unwrap();
        }
        db.inner().flush().unwrap();
        let before = table_bytes(&db);
        assert!(
            before >= 3 * replica_bytes,
            "the control: three replicas take {before} bytes"
        );
        s.evict_below_epoch(5).unwrap();
        assert_eq!(
            wait_for_background_work(std::time::Duration::from_secs(120)),
            0
        );
        let after = table_bytes(&db);
        assert!(
            after < before - 2 * replica_bytes + replica_bytes / 8,
            "the two evicted replicas still take space: {before} bytes before, {after} after"
        );
        assert!(
            s.db.get(&chunk_key(6, b"leaf", 0)).unwrap().is_some(),
            "the kept epoch's chunks stay"
        );
        assert!(s.db.get(&chunk_key(4, b"leaf", 0)).unwrap().is_none());
    }

    #[test]
    fn rewriting_or_deleting_a_leaf_replaces_what_is_read() {
        let s = store();
        let (first, first_cap) = hash_leaf(3 * CHUNK_NODES as usize, 4);
        let (second, second_cap) = hash_leaf(100, 5);
        s.put_hash(2, b"leaf", &first, &first_cap, &[1u8; 96])
            .unwrap();
        assert_eq!(
            s.get_hash_leaf(2, b"leaf").unwrap().unwrap().n,
            3 * CHUNK_NODES
        );
        s.put_hash(2, b"leaf", &second, &second_cap, &[2u8; 96])
            .unwrap();
        let leaf = s.get_hash_leaf(2, b"leaf").unwrap().unwrap();
        assert_eq!(
            (leaf.n, leaf.registration_root.clone()),
            (100, vec![2u8; 96])
        );
        assert_eq!(
            &s.get_hash(2, b"leaf").unwrap().unwrap().replica[..],
            &second[..]
        );
        s.delete(2, b"leaf").unwrap();
        assert_eq!(s.get_hash_leaf(2, b"leaf").unwrap(), None);
        assert!(
            s.read_nodes(2, b"leaf", &leaf, 0..1).is_err(),
            "no chunks left"
        );
    }

    #[test]
    fn partitions_and_snapshot_sources_round_trip_and_evict_by_epoch() {
        let s = store();
        let prefixes = vec![vec![], vec![3, 1], vec![63]];
        s.put_partition(5, b"filter", &prefixes).unwrap();
        s.put_snapshot_sources(5, b"filter", b"sources").unwrap();
        assert_eq!(s.get_leaf_nodes(5, b"filter").unwrap(), None);
        s.put_leaf_nodes(5, b"filter", &[2, 1 << 30, 7]).unwrap();
        s.put(5, b"filter", b"replica").unwrap();
        assert_eq!(s.get_partition(5, b"filter").unwrap(), Some(prefixes));
        assert_eq!(
            s.get_leaf_nodes(5, b"filter").unwrap(),
            Some(vec![2, 1 << 30, 7])
        );
        assert_eq!(
            s.get_snapshot_sources(5, b"filter").unwrap().as_deref(),
            Some(&b"sources"[..])
        );
        assert_eq!(
            s.get(5, b"filter").unwrap().as_deref(),
            Some(&b"replica"[..]),
            "beside, not over, the replica"
        );
        assert_eq!(s.get_partition(6, b"filter").unwrap(), None);
        s.put_snapshot_sources(5, b"child", b"sources").unwrap();
        s.put_snapshot_sources(6, b"later", b"sources").unwrap();
        assert_eq!(
            s.snapshot_source_filters(5).unwrap(),
            vec![b"child".to_vec(), b"filter".to_vec()],
            "the epoch's shards, not another epoch's"
        );
        s.evict_below_epoch(6).unwrap();
        assert_eq!(s.get_partition(5, b"filter").unwrap(), None);
        assert_eq!(s.get_snapshot_sources(5, b"filter").unwrap(), None);
        assert!(s.snapshot_source_filters(5).unwrap().is_empty());
        assert_eq!(
            s.snapshot_source_filters(6).unwrap(),
            vec![b"later".to_vec()]
        );
        assert_eq!(s.get_leaf_nodes(5, b"filter").unwrap(), None);
    }

    #[test]
    fn epoch_isolated() {
        let s = store();
        s.put(3, b"leaf", b"v3").unwrap();
        s.put(4, b"leaf", b"v4").unwrap();
        assert_eq!(s.get(3, b"leaf").unwrap().as_deref(), Some(&b"v3"[..]));
        assert_eq!(s.get(4, b"leaf").unwrap().as_deref(), Some(&b"v4"[..]));
    }

    #[test]
    fn evict_below_epoch_drops_only_older() {
        let s = store();
        s.put(2, b"l", b"old2").unwrap();
        s.put(3, b"l", b"old3").unwrap();
        s.put(4, b"l", b"cur4").unwrap();
        // New epoch is 4 → drop everything below 4.
        s.evict_below_epoch(4).unwrap();
        assert_eq!(s.get(2, b"l").unwrap(), None);
        assert_eq!(s.get(3, b"l").unwrap(), None);
        assert_eq!(s.get(4, b"l").unwrap().as_deref(), Some(&b"cur4"[..]));
    }

    #[test]
    fn for_each_in_epoch_lists_all_leaves() {
        let s = store();
        s.put(5, b"leaf-1", b"r1").unwrap();
        s.put(5, b"leaf-2", b"r2").unwrap();
        s.put(6, b"leaf-3", b"r3").unwrap(); // different epoch — excluded
        let mut seen: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        s.for_each_in_epoch(5, |id, r| seen.push((id, r))).unwrap();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                (b"leaf-1".to_vec(), b"r1".to_vec()),
                (b"leaf-2".to_vec(), b"r2".to_vec()),
            ]
        );
    }

    /// A store counting the bytes of replica chunks written to it, which
    /// can stop taking writes after a number of them as at a crash: what
    /// it took until then stays.
    struct Recording {
        inner: Arc<crate::RocksDb>,
        chunk_bytes: Arc<AtomicU64>,
        /// Writes it takes before the crash; `u64::MAX` for no crash.
        writes_left: Arc<AtomicU64>,
    }

    struct RecordingBatch {
        inner: Box<dyn quil_types::store::Transaction>,
        chunk_bytes: Arc<AtomicU64>,
        pending: AtomicU64,
        writes_left: Arc<AtomicU64>,
    }

    fn is_chunk(key: &[u8]) -> bool {
        key.starts_with(&[STORAGE_REPLICA, META, HASH_NODES])
    }

    /// Take one write, or fail as a crashed store does.
    fn take_write(left: &AtomicU64) -> Result<()> {
        left.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| match left {
            u64::MAX => Some(u64::MAX),
            0 => None,
            left => Some(left - 1),
        })
        .map(|_| ())
        .map_err(|_| QuilError::Store("the store crashed".into()))
    }

    impl quil_types::store::Transaction for RecordingBatch {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            self.inner.get(key)
        }
        fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
            if is_chunk(key) {
                self.pending.fetch_add(value.len() as u64, Ordering::SeqCst);
            }
            self.inner.set(key, value)
        }
        fn commit(self: Box<Self>) -> Result<()> {
            take_write(&self.writes_left)?;
            let pending = self.pending.load(Ordering::SeqCst);
            self.inner.commit()?;
            self.chunk_bytes.fetch_add(pending, Ordering::SeqCst);
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.inner.delete(key)
        }
        fn abort(self: Box<Self>) -> Result<()> {
            self.inner.abort()
        }
        fn new_iter(
            &self,
            lower: &[u8],
            upper: &[u8],
        ) -> Result<Box<dyn quil_types::store::Iterator>> {
            self.inner.new_iter(lower, upper)
        }
        fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
            self.inner.delete_range(lower, upper)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl KvDb for Recording {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            self.inner.get(key)
        }
        fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
            take_write(&self.writes_left)?;
            if is_chunk(key) {
                self.chunk_bytes
                    .fetch_add(value.len() as u64, Ordering::SeqCst);
            }
            self.inner.set(key, value)
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            take_write(&self.writes_left)?;
            self.inner.delete(key)
        }
        fn new_batch(&self, indexed: bool) -> Result<Box<dyn quil_types::store::Transaction>> {
            Ok(Box::new(RecordingBatch {
                inner: self.inner.new_batch(indexed)?,
                chunk_bytes: self.chunk_bytes.clone(),
                pending: AtomicU64::new(0),
                writes_left: self.writes_left.clone(),
            }))
        }
        fn new_iter(
            &self,
            lower: &[u8],
            upper: &[u8],
        ) -> Result<Box<dyn quil_types::store::Iterator>> {
            self.inner.new_iter(lower, upper)
        }
        fn compact(&self, start: &[u8], end: &[u8], parallelize: bool) -> Result<()> {
            self.inner.compact(start, end, parallelize)
        }
        fn compact_all(&self) -> Result<()> {
            self.inner.compact_all()
        }
        fn sync_wal(&self) -> Result<()> {
            self.inner.sync_wal()
        }
        fn close(&self) -> Result<()> {
            self.inner.close()
        }
        fn delete_range(&self, start: &[u8], end: &[u8]) -> Result<()> {
            take_write(&self.writes_left)?;
            self.inner.delete_range(start, end)
        }
    }

    /// A [`Recording`] store: the replica store over it, the store under
    /// it (to open again after a crash), the chunk bytes it took and the
    /// writes it takes before a crash.
    fn recording() -> (
        ReplicaStore,
        Arc<crate::RocksDb>,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
    ) {
        let inner = Arc::new(crate::RocksDb::open_in_memory().unwrap());
        let chunk_bytes = Arc::new(AtomicU64::new(0));
        let writes_left = Arc::new(AtomicU64::new(u64::MAX));
        let db = Recording {
            inner: inner.clone(),
            chunk_bytes: chunk_bytes.clone(),
            writes_left: writes_left.clone(),
        };
        (
            ReplicaStore::new(Arc::new(db)),
            inner,
            chunk_bytes,
            writes_left,
        )
    }

    /// `nodes` with each node of `changed` set to another canonical value,
    /// and their cap.
    fn changed(nodes: &[u8], changed: &[usize]) -> (Vec<u8>, Vec<u8>) {
        let mut nodes = nodes.to_vec();
        for &node in changed {
            let at = node * NODE_BYTES;
            let element = u32::from_le_bytes(nodes[at..at + 4].try_into().unwrap());
            nodes[at..at + 4].copy_from_slice(&((element + 1) % (1 << 30)).to_le_bytes());
        }
        let cap = quil_crypto::storage_proof::MerkleTree::from_nodes(&nodes)
            .unwrap()
            .cap(quil_crypto::storage_proof::CAP_HEIGHT)
            .to_bytes();
        (nodes, cap)
    }

    /// The registration root of a leaf whose data cap is `cap`.
    fn registered(cap: &[u8]) -> Vec<u8> {
        use quil_crypto::storage_proof::Tree;
        let cap = MerkleCap::from_bytes(cap).unwrap();
        quil_crypto::storage_proof::registration_root(
            &cap.commitment(Tree::Data),
            &[0; 32],
            &cap.commitment(Tree::Replica),
        )
    }

    /// Bytes of the replica chunks a store holds.
    fn stored_chunk_bytes(s: &ReplicaStore) -> u64 {
        let mut iter =
            s.db.new_iter(
                &meta_key(HASH_NODES, 0, &[]),
                &meta_key(HASH_NODES + 1, 0, &[]),
            )
            .unwrap();
        let (mut bytes, mut ok) = (0, iter.first());
        while ok {
            bytes += iter.value().len() as u64;
            ok = iter.next();
        }
        iter.close().unwrap();
        bytes
    }

    /// An epoch's replica of a leaf whose data changed in one place differs
    /// from the last epoch's only in that place's chunk, yet every epoch
    /// wrote all of a leaf's chunks again: 1-1.7 GB a seat for any change
    /// to its shard (2026-11-08).
    #[test]
    fn a_leaf_changed_in_one_chunk_writes_only_that_chunk_again() {
        let (s, _, chunk_bytes, _) = recording();
        let n = 8 * CHUNK_NODES as usize;
        let (first, first_cap) = hash_leaf(n, 3);
        s.put_hash(3, b"leaf", &first, &first_cap, &[1u8; 96])
            .unwrap();
        s.note_snapshot(3, b"leaf", &[3; 32]).unwrap();
        let (second, second_cap) = changed(&first, &[5 * CHUNK_NODES as usize + 17]);
        chunk_bytes.store(0, Ordering::SeqCst);
        s.put_hash(4, b"leaf", &second, &second_cap, &[2u8; 96])
            .unwrap();
        let written = chunk_bytes.load(Ordering::SeqCst);
        let chunk = (CHUNK_NODES as usize * NODE_BYTES) as u64;
        assert_eq!(
            written,
            chunk,
            "CHUNK-WRITES-BYTES: a replica of {} bytes changed in one chunk wrote {written} \
             bytes of chunks, against the {chunk} of that chunk",
            second.len()
        );
        assert_eq!(
            &s.get_hash(4, b"leaf").unwrap().unwrap().replica[..],
            &second[..]
        );
    }

    /// A leaf written in its changed chunks reads, whole and in any range,
    /// as the same leaf written whole: through runs from several epochs, an
    /// alias of them, and an earlier chunk read back damaged.
    #[test]
    fn a_leaf_written_in_changed_chunks_reads_as_one_written_whole() {
        let (s, whole) = (store(), store());
        let c = CHUNK_NODES as usize;
        // Eight chunks, the last one short.
        let n = 7 * c + 300;
        let (e3, cap3) = hash_leaf(n, 11);
        let (e4, cap4) = changed(&e3, &[c + 1, 6 * c, n - 1]);
        let (e5, cap5) = changed(&e4, &[0, 6 * c + 5]);
        let (e7, cap7) = changed(&e5, &[4 * c]);
        let check = |epoch: u64, nodes: &[u8]| {
            let read = s.get_hash(epoch, b"leaf").unwrap().unwrap();
            assert_eq!(
                read,
                whole.get_hash(epoch, b"leaf").unwrap().unwrap(),
                "CHUNK-IDENTITY: epoch {epoch}'s leaf reads other than written whole"
            );
            assert!(
                read.replica[..] == nodes[..],
                "CHUNK-IDENTITY: epoch {epoch}'s replica differs from its nodes"
            );
            let leaf = s.get_hash_leaf(epoch, b"leaf").unwrap().unwrap();
            for range in [0..1, c - 1..c + 1, c..3 * c + 2, 5 * c + 3..7 * c + 1, 0..n] {
                let at = range.start * NODE_BYTES..range.end * NODE_BYTES;
                let range = range.start as u64..range.end as u64;
                assert!(
                    s.read_nodes(epoch, b"leaf", &leaf, range.clone()).unwrap() == nodes[at],
                    "CHUNK-IDENTITY: epoch {epoch}'s nodes {range:?} read other than written"
                );
            }
        };
        let put = |epoch: u64, nodes: &[u8], cap: &[u8]| {
            for store in [&s, &whole] {
                store
                    .put_hash(epoch, b"leaf", nodes, cap, &registered(cap))
                    .unwrap();
                store
                    .put_data_cap(epoch, b"leaf", &MerkleCap::from_bytes(cap).unwrap())
                    .unwrap();
            }
            // Only this store knows the earlier epochs.
            s.note_snapshot(epoch, b"leaf", &[epoch as u8; 32]).unwrap();
        };
        put(3, &e3, &cap3);
        put(4, &e4, &cap4);
        put(5, &e5, &cap5);
        for store in [&s, &whole] {
            assert!(store.alias_hash(6, b"leaf", 5).unwrap());
        }
        s.note_snapshot(6, b"leaf", &[6; 32]).unwrap();
        for (epoch, nodes) in [(3, &e3), (4, &e4), (5, &e5), (6, &e5)] {
            check(epoch, nodes);
        }
        // Chunk 2, unchanged since epoch 3, read back damaged wherever it
        // lies: epoch 7 writes it again rather than keep it.
        for epoch in 3..=6 {
            if s.db.get(&chunk_key(epoch, b"leaf", 2)).unwrap().is_some() {
                s.db.set(&chunk_key(epoch, b"leaf", 2), &vec![0u8; c * NODE_BYTES])
                    .unwrap();
            }
        }
        put(7, &e7, &cap7);
        check(7, &e7);
    }

    /// The replica bytes counted as written are those put: a whole
    /// replica's, and of a leaf written in its changed chunks only those.
    #[test]
    fn counts_the_replica_bytes_it_puts() {
        let s = store();
        let c = CHUNK_NODES as usize;
        let (e3, cap3) = hash_leaf(3 * c, 5);
        let (e4, cap4) = changed(&e3, &[c + 1]);
        let before = replica_bytes_written();
        s.put(2, b"whole", b"abc").unwrap();
        assert_eq!(replica_bytes_written() - before, 3, "whole_uncounted");
        for (epoch, nodes, cap) in [(3, &e3, &cap3), (4, &e4, &cap4)] {
            s.put_hash(epoch, b"leaf", nodes, cap, &registered(cap))
                .unwrap();
            s.put_data_cap(epoch, b"leaf", &MerkleCap::from_bytes(cap).unwrap())
                .unwrap();
            s.note_snapshot(epoch, b"leaf", &[epoch as u8; 32]).unwrap();
        }
        assert_eq!(
            replica_bytes_written() - before,
            3 + e3.len() as u64 + (c * NODE_BYTES) as u64,
            "chunks_miscounted: a whole leaf, then one changed chunk"
        );
    }

    /// A write of a leaf in its changed chunks stopped at any point, as by
    /// a crash, leaves no leaf at its epoch, so its snapshot encodes it
    /// again, and the earlier epoch whose chunks it keeps reads as before;
    /// written again, it reads whole, also once that epoch is evicted.
    #[test]
    fn a_leaf_write_stopped_at_any_point_leaves_no_leaf_to_read() {
        let c = CHUNK_NODES as usize;
        let n = 6 * c;
        let (first, first_cap) = hash_leaf(n, 21);
        let (second, second_cap) = changed(&first, &[1, 3 * c + 2, 5 * c]);
        for writes in 0u64.. {
            let (s, inner, _, writes_left) = recording();
            s.put_hash(3, b"leaf", &first, &first_cap, &[1u8; 96])
                .unwrap();
            s.note_snapshot(3, b"leaf", &[3; 32]).unwrap();
            writes_left.store(writes, Ordering::SeqCst);
            let stopped = s
                .put_hash(4, b"leaf", &second, &second_cap, &[2u8; 96])
                .is_err();
            // The store opened again after the crash.
            let s = ReplicaStore::new(inner);
            if stopped {
                assert!(
                    s.get_hash_leaf(4, b"leaf").unwrap().is_none(),
                    "CHUNK-TORN: a write stopped after {writes} writes left a leaf to read"
                );
                assert!(
                    s.get_hash(3, b"leaf").unwrap().unwrap().replica[..] == first[..],
                    "CHUNK-TORN: a write stopped after {writes} writes changed the epoch before"
                );
                s.put_hash(4, b"leaf", &second, &second_cap, &[2u8; 96])
                    .unwrap();
            }
            assert!(
                s.get_hash(4, b"leaf").unwrap().unwrap().replica[..] == second[..],
                "CHUNK-TORN: after a write stopped after {writes} writes, the leaf written \
                 again reads other than written"
            );
            s.evict_below_epoch(4).unwrap();
            assert!(
                s.get_hash(4, b"leaf").unwrap().unwrap().replica[..] == second[..],
                "CHUNK-TORN: after a write stopped after {writes} writes and an eviction, the \
                 leaf reads other than written"
            );
            if !stopped {
                assert!(writes > 0, "a write takes writes");
                break;
            }
        }
    }

    /// Evicting the epochs below a leaf written in its changed chunks keeps
    /// the earlier chunks it reads and drops those written again since: one
    /// copy of each chunk stays, as of a leaf written whole.
    #[test]
    fn eviction_keeps_one_copy_of_each_chunk_a_live_leaf_reads() {
        let s = store();
        let c = CHUNK_NODES as usize;
        let (e3, cap3) = hash_leaf(8 * c, 31);
        let (e4, cap4) = changed(&e3, &[2 * c + 9]);
        let (e5, cap5) = changed(&e4, &[6 * c]);
        for (epoch, nodes, cap) in [(3, &e3, &cap3), (4, &e4, &cap4), (5, &e5, &cap5)] {
            s.put_hash(epoch, b"leaf", nodes, cap, &[epoch as u8; 96])
                .unwrap();
            s.note_snapshot(epoch, b"leaf", &[epoch as u8; 32]).unwrap();
        }
        s.evict_below_epoch(5).unwrap();
        let read = s
            .get_hash(5, b"leaf")
            .expect("CHUNK-EVICT: the live leaf does not read after eviction")
            .expect("CHUNK-EVICT: the live leaf is gone after eviction");
        assert!(
            read.replica[..] == e5[..],
            "CHUNK-EVICT: the live leaf reads other than written after eviction"
        );
        assert_eq!(
            stored_chunk_bytes(&s),
            e5.len() as u64,
            "CHUNK-EVICT: after eviction the store holds other than one copy of each chunk \
             of a {}-byte replica",
            e5.len()
        );
    }

    /// A build before chunk runs decodes leaf records of versions 1 and 2
    /// only, and evicts every chunk below an epoch but those its aliases
    /// read: a leaf it met in runs would fail every lookup, and its next
    /// snapshot too while its shard is unchanged (2026-11-08). To it such
    /// a leaf is not stored, and encoded again; the earlier chunks its
    /// eviction drops leave the leaf not stored here too, never stored
    /// with chunks missing.
    #[test]
    fn a_leaf_in_runs_is_not_stored_to_an_earlier_build_nor_after_its_eviction() {
        let s = store();
        let c = CHUNK_NODES as usize;
        let (e3, cap3) = hash_leaf(4 * c, 41);
        let (e4, cap4) = changed(&e3, &[c + 3]);
        s.put_hash(3, b"leaf", &e3, &cap3, &[3u8; 96]).unwrap();
        s.note_snapshot(3, b"leaf", &[3; 32]).unwrap();
        s.put_hash(4, b"leaf", &e4, &cap4, &[4u8; 96]).unwrap();
        let mut iter =
            s.db.new_iter(
                &meta_key(HASH_LEAF, 0, &[]),
                &meta_key(HASH_LEAF + 1, 0, &[]),
            )
            .unwrap();
        let mut ok = iter.first();
        while ok {
            assert!(
                [1, 2].contains(&iter.value()[0]),
                "CHUNK-ROLLBACK: a leaf record of version {} that an earlier build fails on",
                iter.value()[0]
            );
            ok = iter.next();
        }
        iter.close().unwrap();
        // An earlier build's eviction below epoch 4, no alias pinning.
        s.db.delete_range(&meta_key(HASH_NODES, 0, &[]), &meta_key(HASH_NODES, 4, &[]))
            .unwrap();
        s.db.delete_range(&meta_key(HASH_LEAF, 0, &[]), &meta_key(HASH_LEAF, 4, &[]))
            .unwrap();
        // Opened again by this build.
        let s = ReplicaStore::new(s.db.clone());
        if let Some(leaf) = s.get_hash_leaf(4, b"leaf").unwrap() {
            assert!(
                s.read_nodes(4, b"leaf", &leaf, 0..leaf.n).is_ok(),
                "CHUNK-ROLLBACK: a leaf whose chunks an earlier build evicted reads as stored"
            );
        } else {
            s.put_hash(4, b"leaf", &e4, &cap4, &[4u8; 96]).unwrap();
        }
        assert!(
            s.get_hash(4, b"leaf").unwrap().unwrap().replica[..] == e4[..],
            "CHUNK-ROLLBACK: the leaf reads other than written after an earlier build's eviction"
        );
    }

    /// What a store's write-ahead log holds not yet synced, on a disk
    /// syncing it at a rate ([`SlowWal`]).
    #[derive(Default)]
    struct WalState {
        /// Replica bytes committed since the last sync.
        unsynced: u64,
        /// Batches committed.
        commits: u64,
        /// The most bytes not yet synced as a batch after the first was
        /// committed: what a synced commit of the store's would have
        /// waited behind.
        tail: u64,
        /// When the first sync ended, and how long until the next batch.
        first_synced: Option<Instant>,
        idle: Option<Duration>,
    }

    /// A store whose log a disk writing `rate` bytes a second syncs: a
    /// sync takes as long as its unsynced bytes take that disk.
    struct SlowWal {
        inner: Arc<crate::RocksDb>,
        rate: f64,
        state: Arc<Mutex<WalState>>,
    }

    struct SlowWalBatch {
        inner: Box<dyn quil_types::store::Transaction>,
        bytes: AtomicU64,
        state: Arc<Mutex<WalState>>,
    }

    impl quil_types::store::Transaction for SlowWalBatch {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            self.inner.get(key)
        }
        fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.bytes.fetch_add(value.len() as u64, Ordering::SeqCst);
            self.inner.set(key, value)
        }
        fn commit(self: Box<Self>) -> Result<()> {
            let bytes = self.bytes.load(Ordering::SeqCst);
            self.inner.commit()?;
            let mut wal = self.state.lock().unwrap();
            wal.unsynced += bytes;
            wal.commits += 1;
            if wal.commits > 1 {
                wal.tail = wal.tail.max(wal.unsynced);
            }
            if let (Some(synced), None) = (wal.first_synced, wal.idle) {
                wal.idle = Some(synced.elapsed());
            }
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.inner.delete(key)
        }
        fn abort(self: Box<Self>) -> Result<()> {
            self.inner.abort()
        }
        fn new_iter(
            &self,
            lower: &[u8],
            upper: &[u8],
        ) -> Result<Box<dyn quil_types::store::Iterator>> {
            self.inner.new_iter(lower, upper)
        }
        fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
            self.inner.delete_range(lower, upper)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl KvDb for SlowWal {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            self.inner.get(key)
        }
        fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.inner.set(key, value)
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.inner.delete(key)
        }
        fn new_batch(&self, indexed: bool) -> Result<Box<dyn quil_types::store::Transaction>> {
            Ok(Box::new(SlowWalBatch {
                inner: self.inner.new_batch(indexed)?,
                bytes: AtomicU64::new(0),
                state: self.state.clone(),
            }))
        }
        fn new_iter(
            &self,
            lower: &[u8],
            upper: &[u8],
        ) -> Result<Box<dyn quil_types::store::Iterator>> {
            self.inner.new_iter(lower, upper)
        }
        fn compact(&self, start: &[u8], end: &[u8], parallelize: bool) -> Result<()> {
            self.inner.compact(start, end, parallelize)
        }
        fn compact_all(&self) -> Result<()> {
            self.inner.compact_all()
        }
        fn sync_wal(&self) -> Result<()> {
            let unsynced = std::mem::take(&mut self.state.lock().unwrap().unsynced);
            std::thread::sleep(Duration::from_secs_f64(unsynced as f64 / self.rate));
            let mut wal = self.state.lock().unwrap();
            if wal.first_synced.is_none() {
                wal.first_synced = Some(Instant::now());
            }
            Ok(())
        }
        fn close(&self) -> Result<()> {
            self.inner.close()
        }
        fn delete_range(&self, start: &[u8], end: &[u8]) -> Result<()> {
            self.inner.delete_range(start, end)
        }
    }

    /// An epoch's replicas, 1-1.7 GB a seat, go into the store the
    /// consensus commits share: written in batches never synced, each
    /// synced commit of the store's took every byte written since the
    /// last with it. Each batch is now synced on its own, cut to what the
    /// disk synced in [`REPLICA_SYNC_TARGET`] once one is timed, and one
    /// synced past it leaves the disk idle as long (2026-11-07).
    #[test]
    fn a_replica_is_synced_a_batch_at_a_time_so_a_store_commit_waits_behind_one() {
        // 32 MiB/s: the first, whole batch of 16 MiB takes it 500 ms.
        let rate = (32u64 << 20) as f64;
        let state = Arc::new(Mutex::new(WalState::default()));
        let wal = SlowWal {
            inner: Arc::new(crate::RocksDb::open_in_memory().unwrap()),
            rate,
            state: state.clone(),
        };
        let s = ReplicaStore::new(Arc::new(wal));
        let chunk_bytes = CHUNK_NODES as usize * NODE_BYTES;
        let chunks = CHUNKS_PER_BATCH + 256;
        let mut replica = vec![0u8; chunks * chunk_bytes];
        for (i, chunk) in replica.chunks_mut(chunk_bytes).enumerate() {
            chunk[..4].copy_from_slice(&(i as u32).to_be_bytes());
        }
        // Not a cap that decodes: the leaf record is compared as bytes.
        let cap = [1u8; 64];
        s.put_hash(6, b"slow", &replica, &cap, &[7u8; 96]).unwrap();
        let wal = state.lock().unwrap();
        let behind = Duration::from_secs_f64(wal.tail as f64 / rate);
        assert!(
            behind <= REPLICA_SYNC_TARGET,
            "PACE-REPLICA-TAIL: after a replica's first batch, a synced commit of the store \
             would have waited {behind:?} behind {} replica bytes not yet synced, past \
             {REPLICA_SYNC_TARGET:?}",
            wal.tail
        );
        let idle = wal.idle.unwrap_or_default();
        assert!(
            idle >= Duration::from_millis(450),
            "PACE-REPLICA-IDLE: a batch synced in 500 ms, 450 ms past the target, left the \
             disk to the store's commits for {idle:?}"
        );
        drop(wal);
        // Batches of every size keep each chunk at its index.
        for (i, chunk) in replica.chunks(chunk_bytes).enumerate() {
            let stored = s.db.get(&chunk_key(6, b"slow", i as u32)).unwrap();
            assert_eq!(stored.as_deref(), Some(chunk), "chunk {i}");
        }
        assert_eq!(
            s.db.get(&chunk_key(6, b"slow", chunks as u32)).unwrap(),
            None
        );
        let n = (replica.len() / NODE_BYTES) as u64;
        assert_eq!(
            s.db.get(&leaf_key(6, b"slow")).unwrap(),
            Some(HashLeaf::encode(n, &cap, &[7u8; 96]))
        );
    }

    /// A slow disk gets replica batches it syncs within
    /// [`REPLICA_SYNC_TARGET`]: a whole batch of 16 MiB took one writing
    /// 40 MB/s 419 ms.
    #[test]
    fn replica_batches_are_cut_to_what_a_slow_disk_syncs_within_the_target() {
        let chunk = (CHUNK_NODES as usize * NODE_BYTES) as f64;
        for mb_s in [40.0, 80.0, 400.0] {
            let rate = mb_s * 1e6;
            let mut pace = WalPace::new();
            let mut chunks = pace.batch_chunks();
            assert_eq!(chunks, CHUNKS_PER_BATCH, "the most until a sync is timed");
            for _ in 0..2 * PACE_WINDOW {
                let bytes = chunks as f64 * chunk;
                pace.synced(bytes as u64, Duration::from_secs_f64(bytes / rate));
                chunks = pace.batch_chunks();
            }
            let took = Duration::from_secs_f64(chunks as f64 * chunk / rate);
            assert!(
                took <= REPLICA_SYNC_TARGET && took >= REPLICA_SYNC_TARGET / 2,
                "PACE-REPLICA-CUT: at {mb_s} MB/s a batch of {chunks} chunks takes {took:?} \
                 to sync, against {REPLICA_SYNC_TARGET:?}"
            );
        }
    }

    /// A disk too slow even for the smallest batch in
    /// [`REPLICA_SYNC_TARGET`] waits as long as a sync overran it before
    /// the next: the store's commits get about half of it.
    #[test]
    fn a_replica_batch_synced_past_the_target_is_followed_by_as_long_a_wait() {
        let mut pace = WalPace::new();
        let batch = (MIN_CHUNKS_PER_BATCH * CHUNK_NODES as usize * NODE_BYTES) as u64;
        let over = Duration::from_millis(100);
        let wait = pace.synced(batch, REPLICA_SYNC_TARGET + over);
        let chunks = pace.batch_chunks();
        assert!(
            wait == over && chunks == MIN_CHUNKS_PER_BATCH,
            "PACE-REPLICA-OVERRUN: a batch of {batch} bytes synced {over:?} past \
             {REPLICA_SYNC_TARGET:?}: a wait of {wait:?}, then {chunks} chunks"
        );
    }

    /// A disk syncing a whole batch well within [`REPLICA_SYNC_TARGET`]
    /// keeps whole batches and never waits; a replica's small end, which
    /// costs more than its bytes, does not count as the disk's speed.
    #[test]
    fn a_fast_disk_keeps_whole_replica_batches_and_no_waits() {
        let chunk = CHUNK_NODES as usize * NODE_BYTES;
        let mut pace = WalPace::new();
        for _ in 0..2 * PACE_WINDOW {
            // 1.7 GB/s.
            let wait = pace.synced((CHUNKS_PER_BATCH * chunk) as u64, Duration::from_millis(10));
            assert!(
                wait.is_zero() && pace.batch_chunks() == CHUNKS_PER_BATCH,
                "PACE-REPLICA-FAST: a fast disk's batches are cut or waited for"
            );
        }
        for _ in 0..PACE_WINDOW {
            let wait = pace.synced((4 * chunk) as u64, Duration::from_millis(5));
            assert!(
                wait.is_zero() && pace.batch_chunks() == CHUNKS_PER_BATCH,
                "PACE-REPLICA-FAST: a replica's small ends cut the batches"
            );
        }
    }
}
