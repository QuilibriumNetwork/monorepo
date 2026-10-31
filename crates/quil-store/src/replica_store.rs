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

/// Nodes per stored chunk: one subtree below the cap, all a member reads of a
/// replica to open one node of it (`MerkleCap::subtree`).
pub const CHUNK_NODES: u64 = 1 << quil_crypto::storage_proof::CAP_HEIGHT;
/// Chunks written per batch: bounds what writing a replica copies at once.
const CHUNKS_PER_BATCH: usize = 512;
/// Chunks read per range scan when a whole replica is loaded.
const CHUNKS_PER_SCAN: u64 = 256;
/// A table file at least this large under replica keys holds a whole
/// replica as one data block ([`ReplicaStore::reclaim_in_background`]): table
/// files are cut at 64 MB, but no value is split across blocks or files.
const WHOLE_REPLICA_FILE_BYTES: u64 = 128 << 20;
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
/// Leads a [`HASH_LEAF`] record.
const HASH_LEAF_VERSION: u8 = 1;

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

    fn decode(value: &[u8]) -> Result<Self> {
        let corrupt = || QuilError::Store("a stored replica's leaf record does not decode".into());
        let (&version, rest) = value.split_first().ok_or_else(corrupt)?;
        if version != HASH_LEAF_VERSION || rest.len() < 12 {
            return Err(corrupt());
        }
        let n = u64::from_be_bytes(rest[..8].try_into().expect("8 bytes"));
        let chunk_nodes = u32::from_be_bytes(rest[8..12].try_into().expect("4 bytes")) as u64;
        let (cap, rest) = take(&rest[12..]).ok_or_else(corrupt)?;
        let (registration_root, rest) = take(rest).ok_or_else(corrupt)?;
        if chunk_nodes == 0 || !rest.is_empty() {
            return Err(corrupt());
        }
        let cap = MerkleCap::from_bytes(cap).ok_or_else(|| {
            QuilError::InvalidArgument("a stored replica's cap does not decode".into())
        })?;
        Ok(Self {
            n,
            cap,
            registration_root: registration_root.to_vec(),
            chunk_nodes,
        })
    }

    /// Bytes this record holds in memory.
    fn bytes(&self) -> usize {
        let cap: usize = self.cap.levels.iter().map(Vec::len).sum();
        cap * NODE_BYTES + self.registration_root.len()
    }
}

/// A length-prefixed field (`u32` BE length) and what follows it.
fn take(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let field = bytes.get(4..4 + len)?;
    Some((field, &bytes[4 + len..]))
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

type LeafCacheKey = (usize, u64, Vec<u8>);

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
        self.db.set(&replica_key(epoch, leaf_id), replica)
    }

    /// Fetch the replica for `(epoch, leaf_id)`, or `None`.
    pub fn get(&self, epoch: u64, leaf_id: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(&replica_key(epoch, leaf_id))
    }

    /// Persist a hash-proof epoch's leaf: the replica with the Merkle cap that,
    /// with it, opens any node (`quil_crypto::storage_proof::MerkleCap`), and
    /// the registration root it was registered with. The nodes go in chunks
    /// of [`CHUNK_NODES`], written before the leaf record that makes them
    /// readable, so an interrupted write leaves no leaf.
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

    /// [`Self::put_hash`] with [`hash_writes`] held.
    fn write_hash(
        &self,
        epoch: u64,
        leaf_id: &[u8],
        replica: &[u8],
        cap: &[u8],
        registration_root: &[u8],
    ) -> Result<()> {
        if replica.len() % NODE_BYTES != 0 {
            return Err(QuilError::InvalidArgument(
                "a replica is a whole number of nodes".into(),
            ));
        }
        forget_leaves(|e, id| e == epoch && id == leaf_id);
        self.db.delete(&leaf_key(epoch, leaf_id))?;
        self.db.delete_range(
            &chunk_key(epoch, leaf_id, 0),
            &chunk_key(epoch, leaf_id, u32::MAX),
        )?;
        let chunk_bytes = CHUNK_NODES as usize * NODE_BYTES;
        for (batch, nodes) in replica.chunks(chunk_bytes * CHUNKS_PER_BATCH).enumerate() {
            let txn = self.db.new_batch(false)?;
            for (i, chunk) in nodes.chunks(chunk_bytes).enumerate() {
                let index = (batch * CHUNKS_PER_BATCH + i) as u32;
                txn.set(&chunk_key(epoch, leaf_id, index), chunk)?;
            }
            txn.commit()?;
        }
        let n = (replica.len() / NODE_BYTES) as u64;
        self.db.set(
            &leaf_key(epoch, leaf_id),
            &HashLeaf::encode(n, cap, registration_root),
        )
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
        let value = match self.db.get(&leaf_key(epoch, leaf_id))? {
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
                let Some(value) = self.db.get(&leaf_key(epoch, leaf_id))? else {
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
        let spawned = std::thread::Builder::new()
            .name("replica-convert".into())
            .spawn(move || {
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
        self.reclaim_in_background(legacy, end, "converted");
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

    /// Compact the replica keys `[lo, hi)` off the calling thread, one range at
    /// a time in this process, when a table file there holds a whole replica
    /// (`what` the deleted replicas were). A replica stored whole is one data
    /// block of up to 1 GB: until a compaction drops it, every lookup of a key
    /// the block's index range covers (consensus records sort beside replica
    /// keys) reads all of it, and leveled compaction may not reach it for days.
    fn reclaim_in_background(&self, lo: Vec<u8>, hi: Vec<u8>, what: &'static str) {
        static RECLAIMING: Mutex<()> = Mutex::new(());
        let db = self.db.clone();
        let spawned = std::thread::Builder::new()
            .name("replica-reclaim".into())
            .spawn(move || {
                let _one = RECLAIMING.lock().unwrap_or_else(PoisonError::into_inner);
                let started = std::time::Instant::now();
                match db.compact_reclaiming(&lo, &hi, WHOLE_REPLICA_FILE_BYTES) {
                    Ok(false) => {}
                    Ok(true) => tracing::info!(
                        replicas = what,
                        ms = started.elapsed().as_millis() as u64,
                        "storage replicas stored whole compacted away: lookups beside them no \
                         longer read them"
                    ),
                    Err(error) => tracing::warn!(replicas = what, %error, scope = "this node",
                        action = "check this node's disk and store health; the next conversion or \
                                  eviction compacts again",
                        "compacting storage replicas stored whole failed: lookups beside them \
                         keep reading them"),
                }
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
            let bytes = self
                .db
                .get(&chunk_key(epoch, leaf_id, first as u32))?
                .ok_or_else(missing)?;
            take_chunk(first, &bytes)?;
            return Ok(out);
        }
        // A range scan holds all it covers, so scan in windows.
        let mut chunk = first;
        while chunk <= last {
            let end = (chunk + CHUNKS_PER_SCAN).min(last + 1);
            let mut iter = self.db.new_iter(
                &chunk_key(epoch, leaf_id, chunk as u32),
                &chunk_key(epoch, leaf_id, end as u32),
            )?;
            let mut ok = iter.first();
            while ok {
                if chunk >= end || iter.key() != chunk_key(epoch, leaf_id, chunk as u32) {
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
        self.db.delete(&leaf_key(epoch, leaf_id))?;
        self.db.delete_range(
            &chunk_key(epoch, leaf_id, 0),
            &chunk_key(epoch, leaf_id, u32::MAX),
        )?;
        self.db.delete(&replica_key(epoch, leaf_id))
    }

    /// Drop every replica for an epoch strictly below `keep_from` — called
    /// after re-encoding for a new epoch so stale replicas don't accumulate.
    pub fn evict_below_epoch(&self, keep_from: u64) -> Result<()> {
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
            HASH_NODES,
        ] {
            self.db
                .delete_range(&meta_key(kind, 0, &[]), &meta_key(kind, keep_from, &[]))?;
        }
        Ok(())
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
        s.evict_below_epoch(6).unwrap();
        assert_eq!(s.get_partition(5, b"filter").unwrap(), None);
        assert_eq!(s.get_snapshot_sources(5, b"filter").unwrap(), None);
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
}
