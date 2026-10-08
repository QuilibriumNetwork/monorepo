use std::sync::{Arc, Mutex, RwLock};
use std::collections::BTreeMap;

use prost::Message;

use quil_types::error::{QuilError, Result};
use quil_types::proto::global;
use quil_types::store;

use crate::encoding;

/// Finalized global frames retained by an enabled archive cache.
pub const GLOBAL_FRAME_CACHE_CAPACITY: usize = 720;
/// Encoded bytes the cache may retain. A frame carries its request bundles,
/// and a confidential token operation is about 200 KB, so an entry bound alone
/// lets a busy epoch hold gigabytes. When the budget binds, the OLDEST frames
/// go first and fewer than 720 stay resident; the newest frame always stays.
pub const GLOBAL_FRAME_CACHE_MAX_BYTES: usize = 512 << 20;

#[derive(Default)]
struct GlobalFrameCache {
    enabled: bool,
    generation: u64,
    /// Frame and its encoded size, which is what `bytes` sums.
    frames: BTreeMap<u64, (Arc<global::GlobalFrame>, usize)>,
    bytes: usize,
    max_bytes: Option<usize>,
}

impl GlobalFrameCache {
    fn publish(&mut self, frame: Arc<global::GlobalFrame>) {
        self.generation = self.generation.wrapping_add(1);
        self.insert(frame);
    }

    fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.frames.clear();
        self.bytes = 0;
    }

    fn get(&self, frame_number: u64) -> Option<Arc<global::GlobalFrame>> {
        self.frames.get(&frame_number).map(|(frame, _)| frame.clone())
    }

    fn insert(&mut self, frame: Arc<global::GlobalFrame>) {
        if !self.enabled { return; }
        let Some(header) = frame.header.as_ref() else { return };
        let size = frame.encoded_len();
        if let Some((_, replaced)) = self.frames.insert(header.frame_number, (frame, size)) {
            self.bytes -= replaced;
        }
        self.bytes += size;
        let budget = self.max_bytes.unwrap_or(GLOBAL_FRAME_CACHE_MAX_BYTES);
        while self.frames.len() > GLOBAL_FRAME_CACHE_CAPACITY
            || (self.bytes > budget && self.frames.len() > 1)
        {
            if let Some((_, (_, evicted))) = self.frames.pop_first() {
                self.bytes -= evicted;
            }
        }
    }
}

#[derive(Default)]
struct GlobalFrameMemory {
    cache: RwLock<GlobalFrameCache>,
    // Cache hits take neither lock. Separate heights can load concurrently;
    // generations prevent a fill racing a commit/reset from caching old data.
    loads: [Mutex<()>; 32],
    writes: Mutex<()>,
}

/// RocksDB-backed clock/frame store.
pub struct RocksClockStore {
    db: quil_forest::CoordinatedDb,
    global_memory: Arc<GlobalFrameMemory>,
}

struct ClockPublication<'a> {
    _writes: std::sync::MutexGuard<'a, ()>,
    cache: std::sync::RwLockWriteGuard<'a, GlobalFrameCache>,
}

impl store::ExecutionPublicationObserver for ClockPublication<'_> {
    fn adopt(&mut self) { self.cache.invalidate(); }
}

impl RocksClockStore {
    pub fn new(db: quil_forest::CoordinatedDb) -> Self {
        Self { db, global_memory: Arc::new(GlobalFrameMemory::default()) }
    }

    /// Enable archive retention and restore the latest 720 stored frames.
    /// Run on a blocking worker at startup. Live commits populate the same
    /// cache; candidates and aborted transactions never enter it.
    pub fn warm_global_frame_cache(&self) -> Result<usize> {
        self.global_memory.cache.write().unwrap().enabled = true;
        let Some(head) = self.get_latest_frame_number() else { return Ok(0) };
        // Walk stored headers rather than assuming contiguous heights: a node
        // recovering a gap should still restore 720 frames when available.
        let mut numbers = Vec::with_capacity(GLOBAL_FRAME_CACHE_CAPACITY);
        {
            let mut it = self.db.raw_iterator();
            it.seek_for_prev(encoding::clock_global_frame_key(head));
            while it.valid() && numbers.len() < GLOBAL_FRAME_CACHE_CAPACITY {
                let Some(key) = it.key() else { break };
                if key.len() != 10 || !key.starts_with(&[encoding::CLOCK_FRAME, encoding::CLOCK_GLOBAL_FRAME]) {
                    break;
                }
                numbers.push(u64::from_be_bytes(key[2..10].try_into().unwrap()));
                it.prev();
            }
            it.status().map_err(|e| QuilError::Store(e.to_string()))?;
        }
        for n in numbers {
            match self.get_global_frame(n) {
                Ok(_) | Err(QuilError::NotFound(_)) => {},
                Err(e) => return Err(e),
            }
        }
        Ok(self.global_memory.cache.read().unwrap().frames.len())
    }

    // ---------------------------------------------------------------
    // Global frames
    // ---------------------------------------------------------------

    /// Get a global frame by frame number.
    pub fn get_global_frame(&self, frame_number: u64) -> Result<global::GlobalFrame> {
        let (enabled, cached) = {
            let cache = self.global_memory.cache.read().unwrap();
            (cache.enabled, cache.get(frame_number))
        };
        if !enabled { return self.read_global_frame(frame_number); }
        if let Some(frame) = cached { return Ok((*frame).clone()); }
        let _load = self.global_memory.loads[(frame_number % 32) as usize].lock().unwrap();
        let (generation, cached) = {
            let cache = self.global_memory.cache.read().unwrap();
            (cache.generation, cache.get(frame_number))
        };
        if let Some(frame) = cached { return Ok((*frame).clone()); }
        let frame = self.read_global_frame(frame_number)?;
        let cached = Arc::new(frame.clone());
        let mut cache = self.global_memory.cache.write().unwrap();
        if cache.generation == generation { cache.insert(cached); }
        Ok(frame)
    }

    fn read_global_frame(&self, frame_number: u64) -> Result<global::GlobalFrame> {
        // Read header
        let header_key = encoding::clock_global_frame_key(frame_number);
        let snapshot = self.db.snapshot();
        let header_bytes = snapshot
            .get(&header_key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| {
                QuilError::NotFound(format!("global frame {} not found", frame_number))
            })?;

        let header = global::GlobalFrameHeader::decode(header_bytes.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))?;

        // Read requests
        let requests = self.read_frame_requests(&snapshot, frame_number)?;

        Ok(global::GlobalFrame {
            header: Some(header),
            requests,
        })
    }

    /// Store a global frame via a `RocksClockTxn` batch — grouping
    /// header + all request keys + latest/earliest indices into a
    /// single atomic Rocks write. Mirrors Go's batched
    /// `PutGlobalClockFrame`. Falls back to direct writes for
    /// non-RocksClockTxn impls (tests).
    pub fn put_global_frame_via_txn(
        &self,
        frame: &global::GlobalFrame,
        txn: &dyn store::Transaction,
    ) -> Result<()> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("frame has no header".into()))?;
        let frame_number = header.frame_number;
        let header_key = encoding::clock_global_frame_key(frame_number);
        let header_bytes = header.encode_to_vec();

        if let Some(rt) = txn.as_any().downcast_ref::<RocksClockTxn>() {
            let mut batch = rt.batch.lock().unwrap();
            batch.put(&header_key, &header_bytes);
            for (i, request) in frame.requests.iter().enumerate() {
                let req_key = encoding::clock_global_frame_request_key(frame_number, i as u16);
                batch.put(&req_key, request.encode_to_vec());
            }
            let current_latest = self.get_latest_frame_number();
            // Match `put_global_frame` (and the earliest check below):
            // when no frames exist yet, this IS the latest. The previous
            // form `> unwrap_or(0)` silently dropped the latest-index
            // update for genesis at frame 0 on an empty store.
            if current_latest.is_none() || frame_number > current_latest.unwrap() {
                batch.put(encoding::clock_global_latest_index(), frame_number.to_be_bytes());
            }
            let current_earliest = self.get_earliest_frame_number();
            if current_earliest.is_none() || frame_number < current_earliest.unwrap() {
                batch.put(encoding::clock_global_earliest_index(), frame_number.to_be_bytes());
            }
            rt.global_frames.lock().unwrap().push((self.global_memory.clone(), Arc::new(frame.clone())));
            return Ok(());
        }

        // Fallback: caller passed a non-Rocks txn (test stub). Write
        // directly; the writes won't be atomic but the test impls
        // don't care.
        self.put_global_frame(frame, None)
    }

    /// Store a global frame.
    ///
    /// When called with a caller-supplied `RocksClockTxn`, writes are
    /// staged into that batch (letting the caller group frame + QC +
    /// other writes into a single atomic commit — see Go's
    /// `addCertifiedState`). When called with `None`, a local batch
    /// is used so the 2+N+2 keys (header, N requests, latest index,
    /// earliest index) still land in one atomic Rocks write.
    pub fn put_global_frame(
        &self,
        frame: &global::GlobalFrame,
        txn: Option<&dyn store::Transaction>,
    ) -> Result<()> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("frame has no header".into()))?;

        let frame_number = header.frame_number;
        let header_key = encoding::clock_global_frame_key(frame_number);
        let header_bytes = header.encode_to_vec();

        // Pre-compute all writes.
        let latest_key = encoding::clock_global_latest_index();
        let earliest_key = encoding::clock_global_earliest_index();
        let current_latest = self.read_u64_index_checked(&latest_key)?;
        let current_earliest = self.read_u64_index_checked(&earliest_key)?;
        // Mirror the earliest check: if no frames are stored yet, this
        // IS the latest; otherwise compare. The previous form
        // `frame_number > unwrap_or(0)` collapsed "no frames" to "latest
        // is 0" and silently dropped the index update for the very
        // first stored frame at frame 0 (which is exactly the testnet
        // genesis case).
        let update_latest = current_latest.is_none() || frame_number > current_latest.unwrap();
        let update_earliest = current_earliest.is_none() || frame_number < current_earliest.unwrap();

        // If the caller provided a RocksClockTxn, stage into it so the
        // whole frame + any sibling writes (QC, certified state, etc.)
        // commit atomically as one batch.
        if let Some(t) = txn {
            if let Some(rt) = t.as_any().downcast_ref::<RocksClockTxn>() {
                let mut batch = rt.batch.lock().unwrap();
                batch.put(&header_key, &header_bytes);
                for (i, request) in frame.requests.iter().enumerate() {
                    let req_key = encoding::clock_global_frame_request_key(frame_number, i as u16);
                    batch.put(&req_key, request.encode_to_vec());
                }
                if update_latest {
                    batch.put(&latest_key, frame_number.to_be_bytes());
                }
                if update_earliest {
                    batch.put(&earliest_key, frame_number.to_be_bytes());
                }
                rt.global_frames.lock().unwrap().push((self.global_memory.clone(), Arc::new(frame.clone())));
                return Ok(());
            }
            // Non-Rocks txn (test stub). Fall through to the `set`
            // interface — this preserves the old behavior for test
            // impls while still being self-atomic on real DBs.
            t.set(&header_key, &header_bytes)?;
            for (i, request) in frame.requests.iter().enumerate() {
                let req_key = encoding::clock_global_frame_request_key(frame_number, i as u16);
                t.set(&req_key, &request.encode_to_vec())?;
            }
            if update_latest {
                t.set(&latest_key, &frame_number.to_be_bytes())?;
            }
            if update_earliest {
                t.set(&earliest_key, &frame_number.to_be_bytes())?;
            }
            return Ok(());
        }

        let _writes = self.global_memory.writes.lock().unwrap();
        // No caller txn: use a local batch so 2+N+2 writes are atomic.
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(&header_key, &header_bytes);
        for (i, request) in frame.requests.iter().enumerate() {
            let req_key = encoding::clock_global_frame_request_key(frame_number, i as u16);
            batch.put(&req_key, request.encode_to_vec());
        }
        if update_latest {
            batch.put(&latest_key, frame_number.to_be_bytes());
        }
        if update_earliest {
            batch.put(&earliest_key, frame_number.to_be_bytes());
        }
        self.db
            .write(batch)
            .map_err(|e| QuilError::Store(e.to_string()))?;
        let cached = Arc::new(frame.clone());
        self.global_memory.cache.write().unwrap().publish(cached);
        Ok(())
    }

    /// Get the latest global frame.
    pub fn get_latest_global_frame(&self) -> Result<global::GlobalFrame> {
        let frame_number = self
            .get_latest_frame_number()
            .ok_or_else(|| QuilError::NotFound("no global frames stored".into()))?;
        self.get_global_frame(frame_number)
    }

    /// Get the earliest global frame.
    pub fn get_earliest_global_frame(&self) -> Result<global::GlobalFrame> {
        let frame_number = self
            .get_earliest_frame_number()
            .ok_or_else(|| QuilError::NotFound("no global frames stored".into()))?;
        self.get_global_frame(frame_number)
    }

    /// Delete global frames in a range.
    pub fn delete_global_frame_range(
        &self,
        min_frame: u64,
        max_frame: u64,
    ) -> Result<()> {
        let _writes = self.global_memory.writes.lock().unwrap();
        let mut batch = rocksdb::WriteBatch::default();

        let start = encoding::clock_global_frame_key(min_frame);
        let end = encoding::clock_global_frame_key(max_frame + 1);
        batch.delete_range(&start, &end);

        // Also delete requests in range
        let req_start = encoding::clock_global_frame_request_key(min_frame, 0);
        let req_end = encoding::clock_global_frame_request_key(max_frame + 1, 0);
        batch.delete_range(&req_start, &req_end);

        self.db
            .write(batch)
            .map_err(|e| QuilError::Store(e.to_string()))?;
        let mut cache = self.global_memory.cache.write().unwrap();
        cache.generation = cache.generation.wrapping_add(1);
        cache.frames.retain(|n, _| *n < min_frame || *n > max_frame);
        cache.bytes = cache.frames.values().map(|(_, size)| *size).sum();
        Ok(())
    }

    // ---------------------------------------------------------------
    // Quorum certificates
    // ---------------------------------------------------------------

    /// Store a quorum certificate.
    pub fn put_quorum_certificate(
        &self,
        qc: &global::QuorumCertificate,
        filter: &[u8],
        txn: Option<&dyn store::Transaction>,
    ) -> Result<()> {
        let key = encoding::clock_quorum_certificate_key(qc.rank, filter);
        let data = qc.encode_to_vec();

        if let Some(txn) = txn {
            txn.set(&key, &data)?;
        } else {
            self.db
                .put(&key, &data)
                .map_err(|e| QuilError::Store(e.to_string()))?;
        }

        // Update latest index. Must use `is_none() ||` form so that
        // the very first stored QC (genesis at rank 0) actually sets
        // the index — `> unwrap_or(0)` collapses "no QC yet" to "rank
        // is 0" and silently drops the update for rank-0 genesis.
        let latest_key = encoding::clock_quorum_certificate_latest_index(filter);
        let current = self.read_u64_index(&latest_key);
        if current.is_none() || qc.rank > current.unwrap() {
            let val = qc.rank.to_be_bytes();
            if let Some(txn) = txn {
                txn.set(&latest_key, &val)?;
            } else {
                self.db
                    .put(&latest_key, &val)
                    .map_err(|e| QuilError::Store(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Get the latest quorum certificate for a filter.
    pub fn get_latest_quorum_certificate(
        &self,
        filter: &[u8],
    ) -> Result<global::QuorumCertificate> {
        let latest_key = encoding::clock_quorum_certificate_latest_index(filter);
        let rank = self
            .read_u64_index(&latest_key)
            .ok_or_else(|| QuilError::NotFound("no quorum certificates stored".into()))?;

        let key = encoding::clock_quorum_certificate_key(rank, filter);
        let data = self
            .db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound(format!("QC at rank {} not found", rank)))?;

        global::QuorumCertificate::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /// Highest stored global frame number, or `None` if the store is empty.
    pub fn get_latest_frame_number(&self) -> Option<u64> {
        let key = encoding::clock_global_latest_index();
        self.read_u64_index(&key)
    }

    /// Lowest stored global frame number, or `None` if the store is empty.
    pub fn get_earliest_frame_number(&self) -> Option<u64> {
        let key = encoding::clock_global_earliest_index();
        self.read_u64_index(&key)
    }

    /// Missing global frame-record ranges, including below the first record
    /// down to frame 1. Callers must clamp to their network history floor.
    /// Key-only: frame values are not decoded. No range is reported above the
    /// highest stored record, or for an empty store.
    pub fn find_global_frame_record_gaps(&self) -> Vec<(u64, u64)> {
        self.find_global_frame_record_gaps_from(0)
    }

    /// Missing ranges at or above `from`, including below the first record
    /// found. No range is reported above the last record. Key-only.
    pub fn find_global_frame_record_gaps_from(&self, from: u64) -> Vec<(u64, u64)> {
        // Frame record key = [CLOCK_FRAME, CLOCK_GLOBAL_FRAME, frame(8 BE)];
        // take the 2-byte type prefix so the scan covers exactly the frame
        // records (request/candidate keys use different second bytes).
        let start = encoding::clock_global_frame_key(from);
        let prefix = &start[..2];
        let mut gaps = Vec::new();
        let floor = from.max(1);
        let mut prev: Option<u64> = None;
        let mut it = self.db.raw_iterator();
        it.seek(&start);
        while let Some(k) = it.key() {
            if !k.starts_with(prefix) || k.len() < 10 {
                break;
            }
            let n = u64::from_be_bytes(k[2..10].try_into().unwrap());
            if let Some(p) = prev {
                if n > p + 1 {
                    gaps.push((p + 1, n - 1));
                }
            } else if n > floor {
                gaps.push((floor, n - 1));
            }
            prev = Some(n);
            it.next();
        }
        gaps
    }

    /// Durable GLOBAL materialization cursor: the highest global frame whose
    /// `requests` have been committed into the hypergraph CRDT. `None` when
    /// absent (fresh store → treat as 0). This key is written atomically
    /// inside the CRDT commit batch (see
    /// [`crate::encoding::global_materialized_cursor_key`]); the global store
    /// (clock + hypergraph) shares one RocksDB, so the write staged by the
    /// hypergraph txn is visible here. Read at startup to seed the
    /// materializer and drive the crash-gap re-materialize `[cursor+1..=head]`.
    pub fn get_global_materialized_cursor(&self) -> Option<u64> {
        let key = encoding::global_materialized_cursor_key();
        self.read_u64_index(&key)
    }

    /// Advance the durable global materialized cursor to `frame_number`.
    /// Normally the cursor is written atomically inside the CRDT commit batch
    /// (one frame at a time); a state-jump syncs the CRDT state WHOLESALE from
    /// a peer snapshot (bypassing per-frame materialize), so it uses this to
    /// move the cursor straight to the synced head — otherwise the startup
    /// re-materialize would try (and fail) to replay `[old_cursor+1..=synced]`.
    /// Monotonic: never regresses the cursor (a stale/lower value is ignored),
    /// mirroring the `update_latest` guard on the frame index.
    pub fn put_global_materialized_cursor(&self, frame_number: u64) -> Result<()> {
        if let Some(existing) = self.get_global_materialized_cursor() {
            if existing >= frame_number {
                return Ok(());
            }
        }
        let key = encoding::global_materialized_cursor_key();
        self.db
            .put(&key, frame_number.to_be_bytes())
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn read_u64_index(&self, key: &[u8]) -> Option<u64> {
        self.db
            .get(key)
            .ok()?
            .filter(|v| v.len() == 8)
            .map(|v| u64::from_be_bytes(v[..8].try_into().unwrap()))
    }

    /// Like `read_u64_index` but distinguishes a genuine absence (`Ok(None)`)
    /// from a DB read error (`Err`). Write paths that decide whether to
    /// overwrite the latest/earliest cursor MUST use this: swallowing a
    /// transient read error as `None` makes `update_latest` true and
    /// overwrites the index with a lower frame number, regressing the cursor.
    fn read_u64_index_checked(&self, key: &[u8]) -> Result<Option<u64>> {
        Ok(self
            .db
            .get(key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .filter(|v| v.len() == 8)
            .map(|v| u64::from_be_bytes(v[..8].try_into().unwrap())))
    }

    fn read_frame_requests(&self, snapshot: &rocksdb::Snapshot<'_>, frame_number: u64) -> Result<Vec<global::MessageBundle>> {
        let mut requests = Vec::new();
        let prefix_start = encoding::clock_global_frame_request_key(frame_number, 0);
        let prefix_end = encoding::clock_global_frame_request_key(frame_number, u16::MAX);

        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_lower_bound(prefix_start);
        opts.set_iterate_upper_bound(prefix_end);

        let iter = snapshot.iterator_opt(rocksdb::IteratorMode::Start, opts);
        for item in iter {
            match item {
                Ok((_key, value)) => {
                    let bundle = global::MessageBundle::decode(value.as_ref())
                        .map_err(|e| QuilError::Serialization(e.to_string()))?;
                    requests.push(bundle);
                }
                Err(e) => {
                    return Err(QuilError::Store(e.to_string()));
                }
            }
        }

        Ok(requests)
    }
}

#[path = "clock_retention.rs"]
mod retention;
pub use retention::{CandidatePrune, StagedFrameCleanup};

#[cfg(test)]
mod tests {
    /// Serving cost of application frames without a decoded-frame cache:
    /// every stored shard frame of a copied store (`QUIL_SERVE_STORE`), read
    /// and decoded twice (cold, then warm in RocksDB's block cache).
    /// Recovery tool for a STOPPED localnet store: remove the GLOBAL execution
    /// receipt, reproducing a store executed before receipts existed. Never
    /// point it at a running node or a production database.
    #[test]
    #[ignore = "drill over a stopped localnet store"]
    fn drill_remove_global_execution_receipt() {
        let Ok(path) = std::env::var("QUIL_DRILL_STORE") else { return };
        let db = crate::RocksDb::open(std::path::Path::new(&path)).unwrap();
        let inner = db.inner();
        let key = crate::encoding::global_execution_checkpoint_key();
        let pending = crate::encoding::global_execution_pending_key();
        let receipt = inner.get(&key).unwrap();
        assert!(inner.get(&pending).unwrap().is_none(), "unfinished execution; not a receipt-only drill");
        inner.delete(&key).unwrap();
        inner.flush_wal(true).unwrap();
        eprintln!("removed receipt: {}", receipt.map_or("none".into(), |r| hex::encode(&r[..9.min(r.len())])));
    }

    /// Read-only listing of GLOBAL candidates above the canonical head, and
    /// whether each carries a finalization certificate (non-empty signature).
    /// Safe beside a running node: the store is opened read-only.
    #[test]
    #[ignore = "inspection of a localnet store"]
    fn inspect_global_candidates() {
        use quil_types::store::ClockStore as _;
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let db = crate::RocksDb::open_for_read_only(std::path::Path::new(&path)).unwrap();
        let store = super::RocksClockStore::new(db.inner());
        let head = store.get_latest_global_clock_frame().ok()
            .and_then(|f| f.header.map(|h| h.frame_number)).unwrap_or(0);
        eprintln!("canonical head {head}");
        for frame in store.range_global_clock_frame_candidates(head + 1, head + 64, 512).unwrap() {
            let header = frame.header.unwrap_or_default();
            let certified = header.public_key_signature_bls48581.as_ref().is_some_and(|s| !s.signature.is_empty());
            eprintln!("candidate {} rank {} certified {certified}", header.frame_number, header.rank);
        }
    }

    #[test]
    #[ignore = "measurement over a copied node store"]
    fn measure_app_frame_serving_cost() {
        use quil_types::store::ClockStore as _;
        let Ok(path) = std::env::var("QUIL_SERVE_STORE") else { return };
        let db = crate::RocksDb::open(std::path::Path::new(&path)).unwrap();
        let store = super::RocksClockStore::new(db.inner());
        let mut keys = Vec::new();
        let inner = db.inner();
        let mut it = inner.raw_iterator();
        it.seek([crate::encoding::CLOCK_FRAME, crate::encoding::CLOCK_SHARD_FRAME]);
        while let Some(key) = it.key() {
            if !key.starts_with(&[crate::encoding::CLOCK_FRAME, crate::encoding::CLOCK_SHARD_FRAME]) || key.len() < 10 {
                break;
            }
            let (filter, number) = key[2..].split_at(key.len() - 10);
            keys.push((filter.to_vec(), u64::from_be_bytes(number.try_into().unwrap())));
            it.next();
        }
        // Forest serving: the full diff a new member's sync asks for, the QUIL
        // application's vertex tree against an empty one.
        let forest = quil_forest::Forest::with_namespace(db.inner(), crate::FOREST_NAMESPACE);
        let app: [u8; 32] = hex::decode("11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9").unwrap().try_into().unwrap();
        if let Some(version) = forest.read_head_version(&app, quil_forest::Phase::VertexAdds).unwrap() {
            let reader = forest.shard_phase_reader(&app, quil_forest::Phase::VertexAdds);
            for pass in ["cold", "warm"] {
                let started = std::time::Instant::now();
                let leaves = quil_forest::diff_leaves(&reader, version, &quil_forest::MemTreeStore::default(), 0).unwrap();
                let elapsed = started.elapsed();
                eprintln!("forest {pass}: {} leaves at version {version}, {:?}", leaves.len(), elapsed);
            }
        }
        for pass in ["cold", "warm"] {
            let started = std::time::Instant::now();
            let mut bytes = 0usize;
            for (filter, number) in &keys {
                let frame = store.get_shard_clock_frame(filter, *number, false).unwrap();
                bytes += prost::Message::encoded_len(&frame);
            }
            let elapsed = started.elapsed();
            eprintln!("{pass}: {} frames, {} bytes, {:?} total, {:.1} us/frame",
                keys.len(), bytes, elapsed, elapsed.as_secs_f64() * 1e6 / keys.len().max(1) as f64);
        }
    }

    use super::*;

    fn test_db() -> RocksClockStore {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, tmp.path()).unwrap();
        // Leak to keep temp dir alive
        std::mem::forget(tmp);
        RocksClockStore::new(quil_forest::CoordinatedDb::new(db))
    }

    fn cached_frame(n: u64) -> global::GlobalFrame {
        global::GlobalFrame {
            header: Some(global::GlobalFrameHeader { frame_number: n, ..Default::default() }),
            requests: vec![global::MessageBundle::default()],
        }
    }

    #[test]
    fn archive_cache_publishes_only_committed_frames() {
        use store::ClockStore;
        let s = test_db();
        s.warm_global_frame_cache().unwrap();
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame(&cached_frame(1), txn.as_ref()).unwrap();
        assert!(s.get_global_frame(1).is_err());
        assert!(s.global_memory.cache.read().unwrap().frames.is_empty());
        txn.abort().unwrap();
        assert!(s.get_global_frame(1).is_err());
        let txn = s.new_transaction(false).unwrap();
        s.put_global_frame(&cached_frame(2), Some(txn.as_ref())).unwrap();
        txn.commit().unwrap();
        assert!(s.global_memory.cache.read().unwrap().frames.contains_key(&2));
        assert_eq!(s.get_global_frame(2).unwrap(), cached_frame(2));
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame(&cached_frame(4), txn.as_ref()).unwrap();
        txn.commit().unwrap();
        assert!(s.global_memory.cache.read().unwrap().frames.contains_key(&4));
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame_candidate(&cached_frame(3), txn.as_ref()).unwrap();
        txn.commit().unwrap();
        assert!(!s.global_memory.cache.read().unwrap().frames.contains_key(&3));
        let txn = s.new_transaction(false).unwrap();
        txn.delete(&encoding::clock_global_frame_key(2)).unwrap();
        txn.commit().unwrap();
        assert!(s.get_global_frame(2).is_err(), "raw transaction must invalidate cached frames");
    }

    /// The committee-handoff flag day discards every application frame chain
    /// and keeps GLOBAL frames, GLOBAL cursors and application state.
    #[test]
    fn discarding_app_frame_history_keeps_global_frames_and_state() {
        use store::ClockStore;
        let s = test_db();
        let app = vec![0x55u8; 32];
        let child = [app.clone(), vec![0x01]].concat();
        for filter in [&app, &child] {
            for n in [1u64, 2, 300_000] {
                let frame = global::AppShardFrame {
                    header: Some(global::FrameHeader {
                        address: filter.to_vec(), frame_number: n, output: vec![n as u8; 516], ..Default::default()
                    }),
                    ..Default::default()
                };
                let selector = vec![n as u8; 32];
                let txn = s.new_transaction(false).unwrap();
                s.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
                txn.commit().unwrap();
                let txn = s.new_transaction(false).unwrap();
                s.commit_shard_clock_frame(filter, n, &selector, txn.as_ref(), true).unwrap();
                txn.commit().unwrap();
                s.put_shard_frame_fee_total(filter, n, 7).unwrap();
                s.put_shard_frame_settlements(filter, n, &[1, 2]).unwrap();
            }
            s.db.put(encoding::consensus_materialized_cursor_key(filter), 300_000u64.to_be_bytes()).unwrap();
            s.db.put(encoding::consensus_liveness_key(filter), [1]).unwrap();
        }
        s.put_global_frame(&cached_frame(9), None).unwrap();
        s.db.put(encoding::global_materialized_cursor_key(), 9u64.to_be_bytes()).unwrap();
        s.db.put(encoding::consensus_liveness_key(&[]), [1]).unwrap();
        let state_key = [encoding::HYPERGRAPH_SHARD, 0x30, 0x01].to_vec();
        s.db.put(&state_key, [1]).unwrap();
        assert_eq!(s.app_frame_history_discarded().unwrap(), None);

        s.discard_app_frame_history(861_840).unwrap();
        for filter in [&app, &child] {
            assert!(s.get_latest_shard_clock_frame(filter).is_err());
            for n in [1u64, 2, 300_000] {
                assert!(s.get_shard_clock_frame(filter, n, false).is_err());
                assert_eq!(s.get_shard_frame_fee_total(filter, n).unwrap(), None);
                assert_eq!(s.get_shard_frame_settlements(filter, n).unwrap(), None);
            }
            assert!(s.db.get(encoding::consensus_materialized_cursor_key(filter)).unwrap().is_none());
            assert!(s.db.get(encoding::consensus_liveness_key(filter)).unwrap().is_none());
        }
        let mut staged = s.db.raw_iterator();
        staged.seek([encoding::CLOCK_FRAME, encoding::CLOCK_SHARD_STAGED]);
        assert!(staged.key().is_none_or(|key| !key.starts_with(&[encoding::CLOCK_FRAME, encoding::CLOCK_SHARD_STAGED])));
        assert_eq!(s.get_global_frame(9).unwrap(), cached_frame(9));
        assert!(s.db.get(encoding::global_materialized_cursor_key()).unwrap().is_some());
        assert!(s.db.get(encoding::consensus_liveness_key(&[])).unwrap().is_some(), "a GLOBAL row has no filter");
        assert!(s.db.get(&state_key).unwrap().is_some());
        assert_eq!(s.app_frame_history_discarded().unwrap(), Some(861_840));
        s.discard_app_frame_history(861_848).unwrap();
        assert_eq!(s.app_frame_history_discarded().unwrap(), Some(861_848));
    }

    /// Holes between stored GLOBAL frame records, over the whole range or from
    /// a height, which a regular's periodic scan uses.
    #[test]
    fn frame_record_gaps_are_found_from_any_height() {
        let s = test_db();
        for n in [1u64, 2, 3, 5, 6, 9, 10] {
            s.put_global_frame(&cached_frame(n), None).unwrap();
        }
        assert_eq!(s.find_global_frame_record_gaps(), vec![(4, 4), (7, 8)]);
        assert_eq!(s.find_global_frame_record_gaps_from(5), vec![(7, 8)]);
        assert_eq!(s.find_global_frame_record_gaps_from(4), vec![(4, 4), (7, 8)], "the scan includes the hole at its lower boundary");
        assert!(s.find_global_frame_record_gaps_from(9).is_empty());
        assert!(s.find_global_frame_record_gaps_from(11).is_empty());
    }

    #[test]
    fn archive_cache_byte_budget_evicts_oldest_and_tracks_every_removal() {
        use store::ClockStore;
        let s = test_db();
        s.warm_global_frame_cache().unwrap();
        let size = cached_frame(1).encoded_len();
        // Room for three frames and part of a fourth.
        s.global_memory.cache.write().unwrap().max_bytes = Some(size * 3 + size / 2);
        for n in 1..=6 { s.put_global_frame(&cached_frame(n), None).unwrap(); }
        let resident = |s: &RocksClockStore| {
            let cache = s.global_memory.cache.read().unwrap();
            assert_eq!(cache.bytes, cache.frames.values().map(|(_, size)| *size).sum::<usize>());
            (cache.frames.keys().copied().collect::<Vec<_>>(), cache.bytes)
        };
        let (frames, bytes) = resident(&s);
        assert_eq!(frames, vec![4, 5, 6], "the oldest frames leave first");
        assert!(bytes <= size * 3 + size / 2);
        // Evicted frames are still served, from disk, without re-entering ahead
        // of the tip (an older frame is the first to be evicted again).
        assert_eq!(s.get_global_frame(1).unwrap(), cached_frame(1));
        assert_eq!(resident(&s).0, vec![4, 5, 6]);
        // Re-publishing a height replaces its accounting instead of adding to it.
        s.put_global_frame(&cached_frame(6), None).unwrap();
        assert_eq!(resident(&s).0, vec![4, 5, 6]);
        // Range pruning and invalidation keep the byte count exact.
        s.delete_global_frame_range(4, 4).unwrap();
        assert_eq!(resident(&s).0, vec![5, 6]);
        s.global_memory.cache.write().unwrap().invalidate();
        assert_eq!(resident(&s), (vec![], 0));
        // A single frame larger than the whole budget still stays resident.
        s.global_memory.cache.write().unwrap().max_bytes = Some(1);
        s.put_global_frame(&cached_frame(7), None).unwrap();
        assert_eq!(resident(&s).0, vec![7]);
    }

    #[test]
    fn archive_cache_retains_720_and_restores_after_restart() {
        use store::ClockStore;
        let s = test_db();
        s.warm_global_frame_cache().unwrap();
        for n in 0..725 { s.put_global_frame(&cached_frame(n), None).unwrap(); }
        {
            let cache = s.global_memory.cache.read().unwrap();
            assert_eq!(cache.frames.len(), 720);
            assert_eq!(cache.frames.first_key_value().unwrap().0, &5);
        }
        // An old catchup read succeeds from disk without displacing the tip.
        assert_eq!(s.get_global_frame(0).unwrap(), cached_frame(0));
        assert!(!s.global_memory.cache.read().unwrap().frames.contains_key(&0));
        s.delete_global_frame_range(0, 4).unwrap();
        assert_eq!(s.global_memory.cache.read().unwrap().frames.len(), 720,
            "pruning old history must preserve the hot window");
        let reopened = RocksClockStore::new(s.db.clone());
        assert_eq!(reopened.warm_global_frame_cache().unwrap(), 720);
        assert_eq!(reopened.get_global_frame(724).unwrap(), cached_frame(724));
        // Remove backing bytes directly to demonstrate that a hot read needs no
        // DB access. Production mutations use store APIs, which invalidate.
        reopened.db.delete(encoding::clock_global_frame_key(724)).unwrap();
        assert_eq!(reopened.get_global_frame(724).unwrap(), cached_frame(724));
        reopened.delete_global_frame_range(723, 724).unwrap();
        assert!(reopened.get_global_frame(723).is_err());
        assert!(reopened.get_global_frame(724).is_err());
        reopened.get_global_frame(722).unwrap();
        reopened.reset_global_clock_frames().unwrap();
        assert!(reopened.get_global_frame(722).is_err());
        assert!(reopened.global_memory.cache.read().unwrap().frames.is_empty());
    }

    #[test]
    fn test_global_materialized_cursor_getter() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open(&opts, tmp.path()).unwrap());
        let store = RocksClockStore::new(db.clone());

        // Absent → None (fresh store; materializer treats as 0).
        assert_eq!(store.get_global_materialized_cursor(), None);

        // A raw 8-byte BE value at the single global key round-trips. In
        // production this value is staged into the hypergraph CRDT commit's
        // own batch (same shared DB); here we write it directly to isolate
        // the getter.
        let key = encoding::global_materialized_cursor_key();
        db.put(&key, 1234u64.to_be_bytes()).unwrap();
        assert_eq!(store.get_global_materialized_cursor(), Some(1234));

        // Overwrite reflects the latest value (single global key).
        db.put(&key, 5678u64.to_be_bytes()).unwrap();
        assert_eq!(store.get_global_materialized_cursor(), Some(5678));

        // A malformed (wrong-length) value is ignored (treated as absent).
        db.put(&key, [0u8; 3]).unwrap();
        assert_eq!(store.get_global_materialized_cursor(), None);
    }

    #[test]
    fn test_put_get_global_frame() {
        let store = test_db();

        let frame = global::GlobalFrame {
            header: Some(global::GlobalFrameHeader {
                frame_number: 42,
                rank: 1,
                timestamp: 1000,
                difficulty: 200000,
                output: vec![0u8; 516],
                parent_selector: vec![0u8; 32],
                global_commitments: Vec::new(),
                prover_tree_commitment: Vec::new(),
                prover_tree_aux_roots: Vec::new(),
                world_state_size: 0,
                requests_root: Vec::new(),
                prover: vec![0u8; 32],
                public_key_signature_bls48581: None,
            }),
            requests: Vec::new(),
        };

        store.put_global_frame(&frame, None).unwrap();

        let loaded = store.get_global_frame(42).unwrap();
        assert_eq!(
            loaded.header.as_ref().unwrap().frame_number,
            42
        );
        assert_eq!(
            loaded.header.as_ref().unwrap().difficulty,
            200000
        );
    }

    /// The committed head must SURVIVE a restart. Mimics the CW `on_finalized`
    /// durable write (`put_global_clock_frame(&frame, &NoopTxn)` → falls to
    /// `put_global_frame(frame, None)` → `self.db.write` + `latest_index`),
    /// then closes and reopens the DB at the SAME path (a node restart). If the
    /// head reverts to the migration frame, the write path is not durable; if
    /// it survives here, the field revert-to-669975 is a STARTUP reset, not the
    /// write.
    #[test]
    fn committed_head_survives_reopen() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().to_path_buf();
        let make_frame = |n: u64| global::GlobalFrame {
            header: Some(global::GlobalFrameHeader {
                frame_number: n,
                output: vec![0u8; 516],
                parent_selector: vec![0u8; 32],
                prover: vec![0u8; 32],
                ..Default::default()
            }),
            requests: Vec::new(),
        };

        // Session 1: migration head 669975, then finalize 669976 + 669977.
        {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open(&opts, &path).unwrap());
            let store = RocksClockStore::new(db.clone());
            store.put_global_frame(&make_frame(669975), None).unwrap();
            assert_eq!(store.get_latest_frame_number(), Some(669975));
            store.put_global_frame(&make_frame(669976), None).unwrap();
            store.put_global_frame(&make_frame(669977), None).unwrap();
            assert_eq!(store.get_latest_frame_number(), Some(669977));
            drop(store);
            drop(db); // close (shutdown)
        }

        // Session 2: reopen SAME path (restart). Head must still be 669977.
        {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open(&opts, &path).unwrap());
            let store = RocksClockStore::new(db);
            assert_eq!(
                store.get_latest_frame_number(),
                Some(669977),
                "committed head must survive restart (not revert to migration head)"
            );
        }
    }

    #[test]
    fn frame_outcomes_round_trip() {
        use store::{ClockStore, RequestOutcome, RequestStatus};
        let s = test_db();
        // Absent → empty.
        assert!(s.get_global_clock_frame_outcomes(7).unwrap().is_empty());
        let outcomes = vec![
            RequestOutcome { status: RequestStatus::Succeeded, error: String::new() },
            RequestOutcome { status: RequestStatus::Rejected, error: "bad signature".into() },
            RequestOutcome { status: RequestStatus::Failed, error: "insufficient balance".into() },
            RequestOutcome { status: RequestStatus::Skipped, error: "encoded payload < 4 bytes (no type prefix)".into() },
        ];
        s.put_global_clock_frame_outcomes(7, &outcomes).unwrap();
        assert_eq!(s.get_global_clock_frame_outcomes(7).unwrap(), outcomes);
        // Distinct frames are independent.
        assert!(s.get_global_clock_frame_outcomes(8).unwrap().is_empty());
        // Overwrite replaces.
        let one = vec![RequestOutcome { status: RequestStatus::Succeeded, error: String::new() }];
        s.put_global_clock_frame_outcomes(7, &one).unwrap();
        assert_eq!(s.get_global_clock_frame_outcomes(7).unwrap(), one);
    }

    /// Production stages an application frame and commits it in the next
    /// transaction. The commit keeps only the canonical copy, and committing
    /// the same frame again (after a restart) still finds it.
    #[test]
    fn a_committed_shard_frame_keeps_only_its_canonical_copy() {
        use store::ClockStore;
        let dir = tempfile::tempdir().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let s = RocksClockStore::new(quil_forest::CoordinatedDb::new(rocksdb::DB::open(&opts, dir.path()).unwrap()));
        let filter = vec![3u8; 35];
        let selector = vec![6u8; 32];
        let frame = global::AppShardFrame {
            header: Some(global::FrameHeader { address: filter.clone(), frame_number: 6, ..Default::default() }),
            ..Default::default()
        };
        let staged = encoding::clock_shard_staged_key(&selector, 6);
        let txn = s.new_transaction(false).unwrap();
        s.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();
        assert!(s.db.get(&staged).unwrap().is_some());

        let txn = s.new_transaction(false).unwrap();
        s.commit_shard_clock_frame(&filter, 6, &selector, txn.as_ref(), false).unwrap();
        txn.commit().unwrap();
        assert_eq!(s.get_shard_clock_frame(&filter, 6, false).unwrap(), frame);
        assert_eq!(s.get_latest_shard_clock_frame(&filter).unwrap(), frame);
        assert!(s.db.get(&staged).unwrap().is_none(), "the staged copy outlived its commit");

        let txn = s.new_transaction(false).unwrap();
        s.commit_shard_clock_frame(&filter, 6, &selector, txn.as_ref(), false).unwrap();
        txn.commit().unwrap();
        assert_eq!(s.get_latest_shard_clock_frame(&filter).unwrap(), frame);
    }

    /// A staged frame is keyed by its selector only; the durable commit, like
    /// the overlay's, installs it only at the shard and height its header names.
    #[test]
    fn a_staged_shard_frame_is_committed_only_at_its_own_destination() {
        use store::ClockStore;
        let dir = tempfile::tempdir().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let s = RocksClockStore::new(quil_forest::CoordinatedDb::new(rocksdb::DB::open(&opts, dir.path()).unwrap()));
        let filter = vec![3u8; 35];
        let other = vec![4u8; 35];
        let selector = vec![6u8; 32];
        let frame = global::AppShardFrame {
            header: Some(global::FrameHeader { address: filter.clone(), frame_number: 6, ..Default::default() }),
            ..Default::default()
        };
        let staged = encoding::clock_shard_staged_key(&selector, 6);
        let txn = s.new_transaction(false).unwrap();
        s.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();

        let txn = s.new_transaction(false).unwrap();
        assert!(s.commit_shard_clock_frame(&other, 6, &selector, txn.as_ref(), false).is_err(), "another shard");
        txn.commit().unwrap();
        assert!(s.get_shard_clock_frame(&other, 6, false).is_err());
        assert!(s.get_latest_shard_clock_frame(&other).is_err());
        assert!(s.db.get(&staged).unwrap().is_some(), "a refused commit keeps the staged copy");

        let txn = s.new_transaction(false).unwrap();
        s.commit_shard_clock_frame(&filter, 6, &selector, txn.as_ref(), false).unwrap();
        txn.commit().unwrap();
        assert_eq!(s.get_shard_clock_frame(&filter, 6, false).unwrap(), frame);
    }

    #[test]
    fn global_candidates_are_atomic_resumable_and_range_bounded() {
        use store::ClockStore;
        let dir = tempfile::tempdir().unwrap();
        let open = || {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            RocksClockStore::new(quil_forest::CoordinatedDb::new(rocksdb::DB::open(&opts, dir.path()).unwrap()))
        };
        let s = open();
        let mut frame = cached_frame(12);
        frame.header.as_mut().unwrap().output = vec![12; 516];
        frame.requests = vec![global::MessageBundle::default(); 3];
        let digest = quil_crypto::poseidon::hash_bytes_to_32(&frame.header.as_ref().unwrap().output).unwrap();
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame_candidate(&frame, txn.as_ref()).unwrap();
        assert!(s.get_global_clock_frame_candidate(12, &digest).is_err());
        txn.abort().unwrap();
        assert!(s.range_global_clock_frame_candidates(0, u64::MAX, 1).unwrap().is_empty());
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame_candidate(&frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();
        assert_eq!(s.get_global_clock_frame_candidate(12, &digest).unwrap(), frame);
        drop(s);
        let s = open();
        assert_eq!(s.range_global_clock_frame_candidates(12, 12, 1).unwrap(), vec![frame.clone()]);
        assert!(s.range_global_clock_frame_candidates(13, u64::MAX, 1).unwrap().is_empty());
        assert!(s.range_global_clock_frame_candidates(0, 11, 1).unwrap().is_empty());
        assert!(s.range_global_clock_frame_candidates(0, u64::MAX, 0).unwrap().is_empty());
        // A replacement cannot retain trailing requests from its previous body.
        frame.requests.truncate(1);
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame_candidate(&frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();
        assert_eq!(s.get_global_clock_frame_candidate(12, &digest).unwrap(), frame);
        assert!(s.get_latest_global_clock_frame().is_err(), "candidates cannot advance the canonical head");
    }

    #[test]
    fn a_certificate_less_rewrite_keeps_the_stored_finalization_certificate() {
        use store::ClockStore;
        let s = test_db();
        let mut plain = cached_frame(7);
        plain.header.as_mut().unwrap().output = vec![7; 516];
        let digest = quil_crypto::poseidon::hash_bytes_to_32(&plain.header.as_ref().unwrap().output).unwrap();
        let mut certified = plain.clone();
        certified.header.as_mut().unwrap().public_key_signature_bls48581 =
            Some(proto::keys::Bls48581AggregateSignature {
                signature: b"CWCT-finalization".to_vec(),
                ..Default::default()
            });
        struct Direct;
        impl store::Transaction for Direct {
            fn get(&self, _: &[u8]) -> Result<Option<Vec<u8>>> { Ok(None) }
            fn set(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
            fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
            fn delete(&self, _: &[u8]) -> Result<()> { Ok(()) }
            fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
            fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn store::Iterator>> {
                Err(QuilError::Store("unused".into()))
            }
            fn delete_range(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
            fn as_any(&self) -> &dyn std::any::Any { self }
        }
        // A notarized, certificate-less candidate is upgraded by finalization.
        s.put_global_clock_frame_candidate(&plain, &Direct).unwrap();
        assert_eq!(s.get_global_clock_frame_candidate(7, &digest).unwrap(), plain);
        s.put_global_clock_frame_candidate(&certified, &Direct).unwrap();
        assert_eq!(s.get_global_clock_frame_candidate(7, &digest).unwrap(), certified);
        // Later ancestor persistence, direct or transactional, keeps it.
        s.put_global_clock_frame_candidate(&plain, &Direct).unwrap();
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame_candidate(&plain, txn.as_ref()).unwrap();
        txn.commit().unwrap();
        assert_eq!(s.get_global_clock_frame_candidate(7, &digest).unwrap(), certified);
        assert_eq!(s.range_global_clock_frame_candidates(7, 7, 4).unwrap(), vec![certified]);
    }

    #[test]
    fn test_latest_earliest() {
        let store = test_db();

        let make_frame = |n: u64| global::GlobalFrame {
            header: Some(global::GlobalFrameHeader {
                frame_number: n,
                ..Default::default()
            }),
            requests: Vec::new(),
        };

        store.put_global_frame(&make_frame(10), None).unwrap();
        store.put_global_frame(&make_frame(20), None).unwrap();
        store.put_global_frame(&make_frame(5), None).unwrap();

        let latest = store.get_latest_global_frame().unwrap();
        assert_eq!(latest.header.unwrap().frame_number, 20);

        let earliest = store.get_earliest_global_frame().unwrap();
        assert_eq!(earliest.header.unwrap().frame_number, 5);
    }
    /// Frame records used by the gap-scan tests: only the frame number
    /// matters, but `put_global_frame` needs a well-formed header.
    fn gap_test_frame(n: u64) -> global::GlobalFrame {
        global::GlobalFrame {
            header: Some(global::GlobalFrameHeader {
                frame_number: n,
                output: vec![0u8; 516],
                parent_selector: vec![0u8; 32],
                prover: vec![0u8; 32],
                ..Default::default()
            }),
            requests: Vec::new(),
        }
    }

    /// A hole BELOW the lowest stored record is a gap like any other, and the
    /// scan must report it.
    ///
    /// It used to anchor every hole on a present record on BOTH sides (it only
    /// emitted `(prev+1, n-1)` between two iterated keys), so the range under
    /// the floor was structurally invisible — no amount of rescanning could
    /// ever surface it, and nothing else revisits frames below the store's
    /// lowest record, so the hole was permanent.
    ///
    /// The scan is the only layer that can see the keyspace, so it is the
    /// layer that has to report this — but on a bootstrapped node the range it
    /// reports is fictional (genesis is a record, so `earliest` is genesis),
    /// and the caller is required to clamp it to the network floor.
    #[test]
    fn hole_below_the_lowest_stored_frame_is_reported_as_a_gap() {
        let store = test_db();
        // Floor at 500, plus an ordinary internal hole at 503..=504 so the
        // two kinds of gap are distinguished by the same call.
        for n in [500, 501, 502, 505] {
            store.put_global_frame(&gap_test_frame(n), None).unwrap();
        }

        assert_eq!(
            store.find_global_frame_record_gaps(),
            vec![(1, 499), (503, 504)],
            "the range below the lowest stored record must be reported \
             alongside the internal holes",
        );
    }

    /// Contrast: a store whose records start at the lowest backfillable height
    /// has no floor gap. Frame 0 is the store's empty sentinel (`unwrap_or(0)`
    /// on the latest/earliest indices), so 1 is the floor, not 0.
    #[test]
    fn no_floor_gap_when_records_start_at_the_lowest_height() {
        let store = test_db();
        for n in 1..=4 {
            store.put_global_frame(&gap_test_frame(n), None).unwrap();
        }
        assert_eq!(store.find_global_frame_record_gaps(), Vec::<(u64, u64)>::new());
    }

    /// Contrast: an EMPTY store has no floor gap either. There is no record to
    /// anchor a descent on, and the poller's forward-fill owns this case
    /// (#587) — reporting `(1, head-1)` here would duplicate that work against
    /// a head this scan cannot see.
    #[test]
    fn empty_store_reports_no_gaps() {
        let store = test_db();
        assert_eq!(store.find_global_frame_record_gaps(), Vec::<(u64, u64)>::new());
    }
}

// =====================================================================
// ClockStore trait implementation — bridges RocksClockStore to the
// generic ClockStore trait used by consensus components.
// =====================================================================

// ClockStore trait adapter. Only global frame read/write is backed by
// RocksDB; everything else stubs out for now.
use num_bigint::BigInt;
use quil_types::proto;

/// A real RocksDB-backed `Transaction` for ClockStore writes. Wraps a
/// `WriteBatch` so multi-write operations (frame header + requests +
/// latest/earliest indices, or frame + QC) commit atomically.
pub(crate) struct RocksClockTxn {
    pub(crate) batch: std::sync::Mutex<rocksdb::WriteBatch>,
    db: quil_forest::CoordinatedDb,
    global_memory: Arc<GlobalFrameMemory>,
    global_frames: Mutex<Vec<(Arc<GlobalFrameMemory>, Arc<global::GlobalFrame>)>>,
    invalidate_global_cache: std::sync::atomic::AtomicBool,
}

impl RocksClockTxn {
    fn note_raw_global_key(&self, key: &[u8]) {
        if key.starts_with(&[encoding::CLOCK_FRAME, encoding::CLOCK_GLOBAL_FRAME])
            || key.starts_with(&[encoding::CLOCK_FRAME, encoding::CLOCK_GLOBAL_FRAME_REQUEST])
        {
            self.invalidate_global_cache.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl store::Transaction for RocksClockTxn {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(key).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().put(key, value);
        self.note_raw_global_key(key);
        Ok(())
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let _writes = self.global_memory.writes.lock().unwrap();
        let batch = self.batch.into_inner().unwrap();
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))?;
        let invalidate = self.invalidate_global_cache.into_inner();
        if invalidate { self.global_memory.cache.write().unwrap().invalidate(); }
        for (memory, frame) in self.global_frames.into_inner().unwrap() {
            if invalidate {
                memory.cache.write().unwrap().invalidate();
            } else {
                memory.cache.write().unwrap().publish(frame);
            }
        }
        Ok(())
    }
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete(key);
        self.note_raw_global_key(key);
        Ok(())
    }
    fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
    fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn store::Iterator>> {
        Err(QuilError::Internal("RocksClockTxn iterator not implemented".into()))
    }
    fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete_range(lower, upper);
        // Raw range operations are uncommon maintenance operations; invalidate
        // conservatively because a range can span both frame key namespaces.
        self.invalidate_global_cache.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

/// If `txn` is a `RocksClockTxn`, stage `op` into its write batch and
/// return `true`; else return `false` so the caller can fall back to
/// a direct DB write.
#[inline]
fn with_clock_batch<F>(txn: &dyn store::Transaction, op: F) -> bool
where
    F: FnOnce(&mut rocksdb::WriteBatch),
{
    if let Some(rt) = txn.as_any().downcast_ref::<RocksClockTxn>() {
        let mut guard = rt.batch.lock().unwrap();
        op(&mut *guard);
        true
    } else {
        false
    }
}

impl store::ClockStore for RocksClockStore {
    fn backing_store_identity(&self) -> Option<store::BackingStoreIdentity> {
        Some(self.db.backing_store_identity())
    }
    fn prepare_execution_publication(&self) -> Result<Box<dyn store::ExecutionPublicationObserver + '_>> {
        // Clock writers and readers hold these briefly; a conflict here
        // discards an executed frame, so wait them out within a deadline.
        let patience = quil_types::lock_patience::Patience::new();
        let writes = patience.lock(&self.global_memory.writes).ok_or_else(|| {
            QuilError::ExecutionUnavailable("clock publication writer is busy or poisoned".into())
        })?;
        let cache = patience.write(&self.global_memory.cache).ok_or_else(|| {
            QuilError::ExecutionUnavailable("clock publication cache is busy or poisoned".into())
        })?;
        Ok(Box::new(ClockPublication { _writes: writes, cache }))
    }
    fn new_transaction(&self, _: bool) -> Result<Box<dyn store::Transaction>> {
        Ok(Box::new(RocksClockTxn {
            batch: std::sync::Mutex::new(rocksdb::WriteBatch::default()),
            db: self.db.clone(),
            global_memory: self.global_memory.clone(),
            global_frames: Mutex::new(Vec::new()),
            invalidate_global_cache: std::sync::atomic::AtomicBool::new(false),
        }))
    }
    fn get_latest_global_clock_frame(&self) -> Result<proto::global::GlobalFrame> { self.get_latest_global_frame() }
    fn get_earliest_global_clock_frame(&self) -> Result<proto::global::GlobalFrame> { self.get_earliest_global_frame() }
    fn get_global_clock_frame(&self, n: u64) -> Result<proto::global::GlobalFrame> { self.get_global_frame(n) }
    fn put_global_clock_frame(&self, f: &proto::global::GlobalFrame, t: &dyn store::Transaction) -> Result<()> {
        self.put_global_frame_via_txn(f, t)
    }
    fn put_global_clock_frame_candidate(
        &self,
        frame: &proto::global::GlobalFrame,
        t: &dyn store::Transaction,
    ) -> Result<()> {
        // Store the candidate keyed by (frame_number, identity).
        // Identity = Poseidon(output) — same derivation as
        // `GlobalState::compute_identity` in quil-engine. Without this
        // entry, `prove_next_state` for rank N+1 cannot resolve its
        // unfinalized prior frame, and the leader's event loop exits
        // with "building on fork or needs sync" the moment its own
        // QC arrives.
        //
        // Layout mirrors Go's `PebbleClockStore.PutGlobalClockFrameCandidate`
        // (`node/store/clock.go:1143`): the header is stored alone at the
        // candidate key, and each request bundle goes to its own
        // `clockGlobalFrameRequestCandidateKey`. Storing the whole
        // GlobalFrame at the candidate key produces decode errors on
        // read (the getter expects a GlobalFrameHeader).
        use prost::Message as _;
        let header = match frame.header.as_ref() {
            Some(h) => h,
            None => return Ok(()),
        };
        let identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
            .map(|h| h.to_vec())
            .unwrap_or_default();
        let frame_number = header.frame_number;

        if frame.requests.len() > usize::from(u16::MAX) + 1 {
            return Err(QuilError::InvalidArgument("too many candidate requests".into()));
        }
        let header_bytes = header.encode_to_vec();
        let key = encoding::clock_global_frame_candidate_key(frame_number, &identity);
        // A finalization certificate rides in the header's signature field,
        // and restart recovery needs it. A later certificate-less write of the
        // same frame (a proposal or vote persisting it as an ancestor) keeps
        // the stored header: the key binds the VDF output, which binds the
        // header fields and body commitment.
        let certified = |h: &proto::global::GlobalFrameHeader| {
            h.public_key_signature_bls48581
                .as_ref()
                .is_some_and(|s| !s.signature.is_empty())
        };
        let keep_header = !certified(header)
            && self
                .db
                .get(&key)
                .map_err(|e| QuilError::Store(e.to_string()))?
                .and_then(|stored| proto::global::GlobalFrameHeader::decode(stored.as_slice()).ok())
                .is_some_and(|stored| stored.frame_number == frame_number && certified(&stored));
        let start = encoding::clock_global_frame_request_candidate_key(&identity, frame_number, 0);
        let mut end = start[..start.len() - 2].to_vec();
        end.extend_from_slice(&[0xff; 3]);
        let requests: Vec<(Vec<u8>, Vec<u8>)> = frame
            .requests
            .iter()
            .enumerate()
            .map(|(i, request)| {
                (
                    encoding::clock_global_frame_request_candidate_key(&identity, frame_number, i as u16),
                    request.encode_to_vec(),
                )
            })
            .collect();
        let write = |batch: &mut rocksdb::WriteBatch| {
            if !keep_header {
                batch.put(&key, &header_bytes);
            }
            batch.delete_range(&start, &end);
            for (key, request) in &requests {
                batch.put(key, request);
            }
        };
        if !with_clock_batch(t, write) {
            // Candidates are outside every execution footprint. Declaring them
            // lets a concurrent finalization publish unless it read them.
            let store = |e: quil_forest::DatabaseCommitError| QuilError::Store(e.to_string());
            let mut batch = quil_forest::DisjointBatch::new(encoding::GLOBAL_CANDIDATE_PREFIXES);
            if !keep_header {
                batch.put(&key, &header_bytes).map_err(store)?;
            }
            batch.delete_range(&start, &end).map_err(store)?;
            for (key, request) in &requests {
                batch.put(key, request).map_err(store)?;
            }
            // Consensus must not emit a vote before the complete body survives
            // a crash. Header and requests share one synced WAL batch.
            let mut options = rocksdb::WriteOptions::default();
            options.set_sync(true);
            self.db.write_disjoint(batch, &options).map_err(store)?;
        }
        Ok(())
    }
    fn get_global_clock_frame_candidate(
        &self,
        frame_number: u64,
        selector: &[u8],
    ) -> Result<proto::global::GlobalFrame> {
        // Mirror Go's `PebbleClockStore.GetGlobalClockFrameCandidate`
        // (`node/store/clock.go:1193`). Go stores the candidate as
        // `proto.Marshal(frame.Header)` at the candidate key — i.e.
        // just the `GlobalFrameHeader` — and the request bundles
        // separately under `clockGlobalFrameRequestCandidateKey`.
        // Reading the candidate key as a `GlobalFrame` directly was a
        // silent bug: prost decoded zero-valued defaults for the
        // non-matching fields and the caller proceeded with an empty
        // frame, which the forks tree quietly rejected.
        let key = encoding::clock_global_frame_candidate_key(frame_number, selector);
        let snapshot = self.db.snapshot();
        let header_bytes = match snapshot
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))?
        {
            Some(b) => b,
            None => return self.get_global_frame(frame_number),
        };
        let mut recovered_bytes = header_bytes.len();
        if recovered_bytes > 64 * 1024 * 1024 {
            return Err(QuilError::Store("global candidate header exceeds 64 MiB".into()));
        }
        // Read as GlobalFrameHeader (Go's format). If that fails, an
        // older Rust build wrote the whole GlobalFrame at this key —
        // try that fallback and extract the header. Recovers stores
        // touched by the pre-fix put_global_clock_frame_candidate.
        let (header, embedded_requests) =
            match proto::global::GlobalFrameHeader::decode(header_bytes.as_slice()) {
                Ok(h) if h.frame_number != 0 || frame_number == 0 => (h, Vec::new()),
                _ => {
                    // The header-as-GlobalFrame decode either errored or
                    // produced a frame_number=0 header that doesn't match
                    // our lookup, which is the prost signature of a
                    // wire-type mismatch. Try the full GlobalFrame layout.
                    let frame = proto::global::GlobalFrame::decode(header_bytes.as_slice())
                        .map_err(|e| QuilError::Serialization(format!(
                            "candidate decode at frame {}: {}", frame_number, e
                        )))?;
                    let h = frame.header.ok_or_else(|| QuilError::NotFound(format!(
                        "candidate at frame {} has no header", frame_number
                    )))?;
                    (h, frame.requests)
                }
            };

        // Reassemble the per-frame request bundles. Each request is
        // stored at a separate `[0x00, 0xF8, selector, frame, idx]`
        // key; iterate by index until the first miss.
        let mut requests: Vec<proto::global::MessageBundle> = embedded_requests;
        if requests.is_empty() {
            for i in 0u16..=u16::MAX {
                let req_key = encoding::clock_global_frame_request_candidate_key(
                    selector, frame_number, i,
                );
                let req_bytes = match snapshot
                    .get(&req_key)
                    .map_err(|e| QuilError::Store(e.to_string()))?
                {
                    Some(b) => b,
                    None => break,
                };
                recovered_bytes = recovered_bytes.saturating_add(req_bytes.len());
                if recovered_bytes > 64 * 1024 * 1024 {
                    return Err(QuilError::Store("global candidate body exceeds 64 MiB".into()));
                }
                let bundle = proto::global::MessageBundle::decode(req_bytes.as_slice())
                    .map_err(|e| QuilError::Serialization(format!(
                        "candidate request {} decode at frame {}: {}",
                        i, frame_number, e
                    )))?;
                requests.push(bundle);
            }
        }

        Ok(proto::global::GlobalFrame {
            header: Some(header),
            requests,
        })
    }
    fn range_global_clock_frame_candidates(
        &self,
        min: u64,
        max: u64,
        limit: usize,
    ) -> Result<Vec<proto::global::GlobalFrame>> {
        let mut frames = Vec::new();
        if min > max || limit == 0 { return Ok(frames); }
        let mut it = self.db.raw_iterator();
        it.seek(encoding::clock_global_frame_candidate_key(min, &[]));
        let mut bytes = 0usize;
        while it.valid() && frames.len() < limit {
            let key = it.key().ok_or_else(|| QuilError::Store("candidate iterator missing key".into()))?;
            if !key.starts_with(&[encoding::CLOCK_FRAME, encoding::CLOCK_GLOBAL_FRAME_CANDIDATE]) { break; }
            if key.len() != 42 { return Err(QuilError::Store("malformed global candidate key".into())); }
            let number = u64::from_be_bytes(key[2..10].try_into().unwrap());
            if number > max { break; }
            let frame = self.get_global_clock_frame_candidate(number, &key[10..])?;
            bytes = bytes.saturating_add(frame.encoded_len());
            if bytes > 64 * 1024 * 1024 {
                return Err(QuilError::Store("global candidate recovery exceeds 64 MiB".into()));
            }
            frames.push(frame);
            it.next();
        }
        it.status().map_err(|e| QuilError::Store(e.to_string()))?;
        Ok(frames)
    }
    fn put_shard_frame_fee_total(&self, filter: &[u8], frame_number: u64, fee_total: u128) -> Result<()> {
        let key = encoding::clock_shard_frame_fee_total_key(filter, frame_number);
        self.db
            .put(&key, &fee_total.to_be_bytes())
            .map_err(|e| QuilError::Store(e.to_string()))
    }
    fn put_shard_frame_settlements(&self, filter: &[u8], frame_number: u64, entries: &[u8]) -> Result<()> {
        let key = encoding::clock_shard_frame_settlements_key(filter, frame_number);
        self.db.put(&key, entries).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_shard_frame_settlements(&self, filter: &[u8], frame_number: u64) -> Result<Option<Vec<u8>>> {
        let key = encoding::clock_shard_frame_settlements_key(filter, frame_number);
        self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn put_shard_frame_accumulator(&self, filter: &[u8], frame_number: u64, digest: &[u8], report: &[u8]) -> Result<()> {
        // The report is stored once per distinct digest, so a shard whose part
        // of the accumulator did not change costs one small record per frame.
        if !digest.is_empty() {
            let report_key = encoding::clock_shard_accumulator_report_key(filter, digest);
            if self.db.get(&report_key).map_err(|e| QuilError::Store(e.to_string()))?.is_none() {
                self.db.put(&report_key, report).map_err(|e| QuilError::Store(e.to_string()))?;
            }
        }
        let key = encoding::clock_shard_frame_accumulator_key(filter, frame_number);
        self.db.put(&key, digest).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_shard_frame_accumulator(&self, filter: &[u8], frame_number: u64) -> Result<Option<Vec<u8>>> {
        let key = encoding::clock_shard_frame_accumulator_key(filter, frame_number);
        self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn put_shard_frame_spends(&self, filter: &[u8], frame_number: u64, entries: &[u8]) -> Result<()> {
        let key = encoding::clock_shard_frame_spends_key(filter, frame_number);
        self.db.put(&key, entries).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_shard_frame_spends(&self, filter: &[u8], frame_number: u64) -> Result<Option<Vec<u8>>> {
        let key = encoding::clock_shard_frame_spends_key(filter, frame_number);
        self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_shard_accumulator_report(&self, filter: &[u8], digest: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = encoding::clock_shard_accumulator_report_key(filter, digest);
        self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_shard_frame_fee_total(&self, filter: &[u8], frame_number: u64) -> Result<Option<u128>> {
        let key = encoding::clock_shard_frame_fee_total_key(filter, frame_number);
        Ok(self
            .db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
            .map(u128::from_be_bytes))
    }
    fn put_global_clock_frame_outcomes(
        &self,
        frame_number: u64,
        outcomes: &[store::RequestOutcome],
    ) -> Result<()> {
        let bytes = crate::clock_codec::encode_outcomes(outcomes, usize::MAX)?;
        self.db.put(encoding::clock_global_frame_outcomes_key(frame_number), bytes)
            .map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_global_clock_frame_outcomes(&self, frame_number: u64) -> Result<Vec<store::RequestOutcome>> {
        let snapshot = self.db.snapshot();
        match snapshot.get(encoding::clock_global_frame_outcomes_key(frame_number))
            .map_err(|e| QuilError::Store(e.to_string()))? {
            Some(bytes) => crate::clock_codec::decode_outcomes(&bytes),
            None => crate::clock_codec::decode_legacy_outcomes(
                snapshot.get(encoding::clock_global_certified_state_key(frame_number))
                    .map_err(|e| QuilError::Store(e.to_string()))?),
        }
    }
    fn delete_global_clock_frame_range(&self, min_frame: u64, max_frame: u64) -> Result<()> {
        let lower = encoding::clock_global_frame_key(min_frame);
        let upper = encoding::clock_global_frame_key(max_frame);
        let _writes = self.global_memory.writes.lock().unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range(&lower, &upper);
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))?;
        let mut cache = self.global_memory.cache.write().unwrap();
        cache.generation = cache.generation.wrapping_add(1);
        cache.frames.retain(|n, _| *n < min_frame || *n >= max_frame);
        cache.bytes = cache.frames.values().map(|(_, size)| *size).sum();
        Ok(())
    }
    fn reset_global_clock_frames(&self) -> Result<()> {
        let lo = encoding::clock_global_frame_key(0);
        let hi = encoding::clock_global_frame_key(20_000_000);
        let earliest = encoding::clock_global_earliest_index();
        let latest = encoding::clock_global_latest_index();
        let _writes = self.global_memory.writes.lock().unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range(&lo, &hi);
        batch.delete(&earliest);
        batch.delete(&latest);
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))?;
        self.global_memory.cache.write().unwrap().invalidate();
        Ok(())
    }
    fn get_latest_certified_global_state(&self) -> Result<proto::global::GlobalProposal> {
        let key = encoding::clock_global_certified_state_latest_index();
        let rank = self.read_u64_index(&key)
            .ok_or_else(|| QuilError::NotFound("no certified global state".into()))?;
        <Self as store::ClockStore>::get_certified_global_state(self, rank)
    }
    fn get_earliest_certified_global_state(&self) -> Result<proto::global::GlobalProposal> {
        let key = encoding::clock_global_certified_state_earliest_index();
        let rank = self.read_u64_index(&key)
            .ok_or_else(|| QuilError::NotFound("no certified global state".into()))?;
        <Self as store::ClockStore>::get_certified_global_state(self, rank)
    }
    fn get_certified_global_state(&self, rank: u64) -> Result<proto::global::GlobalProposal> {
        let key = encoding::clock_global_certified_state_key(rank);
        let data = self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound(format!("certified global state at rank {} not found", rank)))?;
        if data.len() != 24 {
            return Err(QuilError::Serialization(format!(
                "certified global state at rank {} has unexpected length {} (want 24)",
                rank, data.len(),
            )));
        }
        let frame_number = u64::from_be_bytes(data[..8].try_into().unwrap());
        let qc_rank = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let tc_rank = u64::from_be_bytes(data[16..24].try_into().unwrap());

        // Mirror Go: assemble GlobalProposal from individually-stored
        // sub-records. Missing sub-records are tolerated (sentinel
        // 0xFFFFFFFFFFFFFFFF means "no QC/TC was recorded"), so the
        // proposal can still be returned with whatever's present.
        let mut proposal = proto::global::GlobalProposal::default();

        if frame_number != u64::MAX {
            if let Ok(frame) = self.get_global_frame(frame_number) {
                if let Some(header) = frame.header.as_ref() {
                    if let Ok(vote) = <Self as store::ClockStore>::get_proposal_vote(
                        self,
                        &[],
                        header.rank,
                        &header.prover,
                    ) {
                        proposal.vote = Some(vote);
                    }
                }
                proposal.state = Some(frame);
            }
        }
        if qc_rank != u64::MAX {
            if let Ok(qc) = <Self as store::ClockStore>::get_quorum_certificate(self, &[], qc_rank) {
                proposal.parent_quorum_certificate = Some(qc);
            }
        }
        if tc_rank != u64::MAX {
            if let Ok(tc) = <Self as store::ClockStore>::get_timeout_certificate(self, &[], tc_rank) {
                proposal.prior_rank_timeout_certificate = Some(tc);
            }
        }
        Ok(proposal)
    }
    fn put_certified_global_state(
        &self,
        state: &proto::global::GlobalProposal,
        txn: &dyn store::Transaction,
    ) -> Result<()> {
        let mut rank: u64 = 0;
        let mut frame_number: u64 = u64::MAX;
        let mut qc_rank: u64 = u64::MAX;
        let mut tc_rank: u64 = u64::MAX;

        if let Some(frame) = state.state.as_ref() {
            if let Some(header) = frame.header.as_ref() {
                if header.rank > rank {
                    rank = header.rank;
                }
                frame_number = header.frame_number;
            }
            self.put_global_frame(frame, Some(txn))?;
            if let Some(vote) = state.vote.as_ref() {
                <Self as store::ClockStore>::put_proposal_vote(self, txn, vote)?;
            }
        }
        if let Some(qc) = state.parent_quorum_certificate.as_ref() {
            if qc.rank > rank {
                rank = qc.rank;
            }
            qc_rank = qc.rank;
            <Self as store::ClockStore>::put_quorum_certificate(self, qc, txn)?;
        }
        if let Some(tc) = state.prior_rank_timeout_certificate.as_ref() {
            if tc.rank > rank {
                rank = tc.rank;
            }
            tc_rank = tc.rank;
            <Self as store::ClockStore>::put_timeout_certificate(self, tc, txn)?;
        }

        let key = encoding::clock_global_certified_state_key(rank);
        let mut value = Vec::with_capacity(24);
        value.extend_from_slice(&frame_number.to_be_bytes());
        value.extend_from_slice(&qc_rank.to_be_bytes());
        value.extend_from_slice(&tc_rank.to_be_bytes());

        let earliest_key = encoding::clock_global_certified_state_earliest_index();
        let latest_key = encoding::clock_global_certified_state_latest_index();
        let current_earliest = self.read_u64_index(&earliest_key);
        let current_latest = self.read_u64_index(&latest_key);
        let update_earliest = current_earliest.is_none() || rank < current_earliest.unwrap();
        let update_latest = current_latest.is_none() || rank > current_latest.unwrap();

        let staged = with_clock_batch(txn, |b| {
            b.put(&key, &value);
            if update_earliest {
                b.put(&earliest_key, rank.to_be_bytes());
            }
            if update_latest {
                b.put(&latest_key, rank.to_be_bytes());
            }
        });
        if staged {
            return Ok(());
        }

        // Non-Rocks txn: fall through to direct writes.
        txn.set(&key, &value)?;
        if update_earliest {
            txn.set(&earliest_key, &rank.to_be_bytes())?;
        }
        if update_latest {
            txn.set(&latest_key, &rank.to_be_bytes())?;
        }
        Ok(())
    }
    fn get_latest_quorum_certificate(&self, f: &[u8]) -> Result<proto::global::QuorumCertificate> {
        let key = encoding::clock_quorum_certificate_latest_index(f);
        let rank = self.read_u64_index(&key).ok_or_else(|| QuilError::NotFound("no QC".into()))?;
        let qc_key = encoding::clock_quorum_certificate_key(rank, f);
        let data = self.db.get(&qc_key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("QC not found".into()))?;
        proto::global::QuorumCertificate::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn get_quorum_certificate(&self, filter: &[u8], rank: u64) -> Result<proto::global::QuorumCertificate> {
        let qc_key = encoding::clock_quorum_certificate_key(rank, filter);
        let data = self.db.get(&qc_key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound(format!("QC not found at rank {}", rank)))?;
        proto::global::QuorumCertificate::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn put_quorum_certificate(&self, qc: &proto::global::QuorumCertificate, t: &dyn store::Transaction) -> Result<()> {
        // Empty filter = global; the existing inherent method writes
        // both the QC row and the latest-index marker, and now honors
        // a RocksClockTxn batch when provided so the QC lands in the
        // same atomic commit as the frame it certifies.
        let key = encoding::clock_quorum_certificate_key(qc.rank, &[]);
        let data = qc.encode_to_vec();
        if with_clock_batch(t, |b| b.put(&key, &data)) {
            let latest_key = encoding::clock_quorum_certificate_latest_index(&[]);
            let current = self.read_u64_index(&latest_key);
            // `is_none() ||` form so genesis QC at rank 0 actually
            // sets the index. The `> unwrap_or(0)` form silently
            // dropped the index update for rank-0 — see line 249 for
            // the matching fix on the inherent path.
            if current.is_none() || qc.rank > current.unwrap() {
                let _ = with_clock_batch(t, |b| b.put(&latest_key, qc.rank.to_be_bytes()));
            }
            return Ok(());
        }
        self.put_quorum_certificate(qc, &[], None)
    }
    fn get_latest_timeout_certificate(&self, filter: &[u8]) -> Result<proto::global::TimeoutCertificate> {
        let idx = encoding::clock_timeout_certificate_latest_index(filter);
        let rank = self.read_u64_index(&idx)
            .ok_or_else(|| QuilError::NotFound("no timeout certificates stored".into()))?;
        <Self as store::ClockStore>::get_timeout_certificate(self, filter, rank)
    }
    fn get_timeout_certificate(&self, filter: &[u8], rank: u64) -> Result<proto::global::TimeoutCertificate> {
        let key = encoding::clock_timeout_certificate_key(rank, filter);
        let data = self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound(format!("TC not found at rank {}", rank)))?;
        proto::global::TimeoutCertificate::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn put_timeout_certificate(
        &self,
        tc: &proto::global::TimeoutCertificate,
        txn: &dyn store::Transaction,
    ) -> Result<()> {
        let filter = tc.filter.as_slice();
        let key = encoding::clock_timeout_certificate_key(tc.rank, filter);
        let data = tc.encode_to_vec();
        let earliest_key = encoding::clock_timeout_certificate_earliest_index(filter);
        let latest_key = encoding::clock_timeout_certificate_latest_index(filter);
        let current_earliest = self.read_u64_index(&earliest_key);
        let current_latest = self.read_u64_index(&latest_key);
        let update_earliest = current_earliest.is_none() || tc.rank < current_earliest.unwrap();
        let update_latest = current_latest.is_none() || tc.rank > current_latest.unwrap();

        let staged = with_clock_batch(txn, |b| {
            b.put(&key, &data);
            if update_earliest {
                b.put(&earliest_key, tc.rank.to_be_bytes());
            }
            if update_latest {
                b.put(&latest_key, tc.rank.to_be_bytes());
            }
        });
        if staged {
            return Ok(());
        }
        // Non-Rocks txn fallback: direct DB writes.
        self.db.put(&key, &data).map_err(|e| QuilError::Store(e.to_string()))?;
        if update_earliest {
            self.db.put(&earliest_key, tc.rank.to_be_bytes()).map_err(|e| QuilError::Store(e.to_string()))?;
        }
        if update_latest {
            self.db.put(&latest_key, tc.rank.to_be_bytes()).map_err(|e| QuilError::Store(e.to_string()))?;
        }
        Ok(())
    }
    fn get_latest_shard_clock_frame_number(&self, filter: &[u8]) -> Result<Option<u64>> {
        // The index only advances to a frame whose body is stored (see
        // `commit_shard_clock_frame`), and retention never deletes canonical
        // bodies, so it names the frame `get_latest_shard_clock_frame` reads.
        self.read_u64_index_checked(&encoding::clock_shard_latest_index(filter))
    }
    fn get_latest_shard_clock_frame(&self, filter: &[u8]) -> Result<proto::global::AppShardFrame> {
        let idx_key = encoding::clock_shard_latest_index(filter);
        let fn_ = self.read_u64_index(&idx_key).ok_or_else(|| QuilError::NotFound("no shard frame".into()))?;
        self.get_shard_clock_frame(filter, fn_, false)
    }
    fn get_shard_clock_frame(&self, filter: &[u8], frame_number: u64, _truncate: bool) -> Result<proto::global::AppShardFrame> {
        let key = encoding::clock_shard_frame_key(filter, frame_number);
        let data = self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("shard frame not found".into()))?;
        proto::global::AppShardFrame::decode(data.as_slice()).map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn commit_shard_clock_frame(&self, filter: &[u8], frame_number: u64, selector: &[u8], t: &dyn store::Transaction, backfill: bool) -> Result<()> {
        // Copy the staged frame to the canonical key so subsequent
        // `get_shard_clock_frame` / `get_latest_shard_clock_frame`
        // calls can find it. Without this, the leader at rank N+1
        // would never see rank N's frame: stage writes to the staged
        // key only, and commit previously only bumped the latest
        // index pointer — leaving the canonical key empty.
        //
        // Mirrors Go's `PebbleClockStore.CommitShardClockFrame`
        // (`node/store/clock.go:1475`), which writes the parent-index
        // key as the VALUE at the canonical frame key. We instead
        // write the frame proto directly to keep `get_shard_clock_frame`
        // single-hop; Go's legacy frame format is the same shape, and
        // Go's GetShardClockFrame already accepts a non-pointer value
        // at the canonical key (the `else` branch at clock.go:1290).
        let staged_key = encoding::clock_shard_staged_key(selector, frame_number);
        let mut have_frame = false;
        if let Some(staged_bytes) = self
            .db
            .get(&staged_key)
            .map_err(|e| QuilError::Store(e.to_string()))?
        {
            // A staged frame is keyed by its selector alone; only its header
            // names the shard and height it belongs to. Mirrors the overlay
            // store: never install one at another destination.
            let staged = proto::global::AppShardFrame::decode(staged_bytes.as_slice())
                .map_err(|e| QuilError::Serialization(e.to_string()))?;
            if !staged
                .header
                .as_ref()
                .is_some_and(|h| h.frame_number == frame_number && h.address == filter)
            {
                return Err(QuilError::Serialization(
                    "staged shard frame does not match its destination".into(),
                ));
            }
            // The staged copy is read only by this commit. Keeping it stored
            // every application frame twice, about half an archive's store.
            let canonical_key = encoding::clock_shard_frame_key(filter, frame_number);
            if !with_clock_batch(t, |b| {
                b.put(&canonical_key, &staged_bytes);
                b.delete(&staged_key);
            }) {
                let mut batch = rocksdb::WriteBatch::default();
                batch.put(&canonical_key, &staged_bytes);
                batch.delete(&staged_key);
                self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))?;
            }
            have_frame = true;
        } else {
            // Staged frame absent (e.g. a re-commit after restart where the
            // frame is already canonical). Only treat this frame_number as
            // real if the canonical frame actually exists on disk.
            let canonical_key = encoding::clock_shard_frame_key(filter, frame_number);
            have_frame = self
                .db
                .get(&canonical_key)
                .map_err(|e| QuilError::Store(e.to_string()))?
                .is_some();
        }

        // Update the latest-index pointer (skipped during backfill,
        // matching Go). SECURITY: `frame_number` comes from the QC's wire
        // field, which is NOT covered by the aggregate signature (the vote
        // binds filter‖state_id‖rank only). A malicious peer can take a valid
        // QC and set frame_number = u64::MAX; without the `have_frame` guard
        // that would bump the index past every real frame and permanently
        // wedge the shard (no future commit can exceed MAX). Only advance the
        // index to a frame_number for which a frame actually exists.
        if !backfill && have_frame {
            let idx_key = encoding::clock_shard_latest_index(filter);
            let current = self.read_u64_index(&idx_key);
            if current.is_none() || frame_number > current.unwrap() {
                if !with_clock_batch(t, |b| b.put(&idx_key, frame_number.to_be_bytes())) {
                    self.db
                        .put(&idx_key, frame_number.to_be_bytes())
                        .map_err(|e| QuilError::Store(e.to_string()))?;
                }
            }
        }
        Ok(())
    }
    fn stage_shard_clock_frame(&self, selector: &[u8], frame: &proto::global::AppShardFrame, t: &dyn store::Transaction) -> Result<()> {
        let fn_ = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
        let key = encoding::clock_shard_staged_key(selector, fn_);
        let data = frame.encode_to_vec();
        if with_clock_batch(t, |b| b.put(&key, &data)) {
            return Ok(());
        }
        self.db.put(&key, &data).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_staged_shard_clock_frame(&self, _filter: &[u8], frame_number: u64, parent_selector: &[u8], _truncate: bool) -> Result<proto::global::AppShardFrame> {
        let key = encoding::clock_shard_staged_key(parent_selector, frame_number);
        let data = self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("staged shard frame not found".into()))?;
        proto::global::AppShardFrame::decode(data.as_slice()).map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn set_latest_shard_clock_frame_number(&self, filter: &[u8], n: u64) -> Result<()> {
        let key = encoding::clock_shard_latest_index(filter);
        self.db.put(&key, &n.to_be_bytes()).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn delete_shard_clock_frame_range(
        &self,
        filter: &[u8],
        from_frame: u64,
        to_frame: u64,
    ) -> Result<()> {
        let zeros = [0u8; 32];
        let ones = [0xffu8; 32];
        let mut batch = rocksdb::WriteBatch::default();
        for i in from_frame..to_frame {
            // Shard parent index entries — delete the entire selector
            // range for this frame.
            let parent_lo = encoding::clock_shard_parent_index_key(filter, i, &zeros);
            let parent_hi = encoding::clock_shard_parent_index_key(filter, i, &ones);
            batch.delete_range(&parent_lo, &parent_hi);

            // The shard frame itself.
            let shard_key = encoding::clock_shard_frame_key(filter, i);
            batch.delete(&shard_key);

            // Prover-trie keys are not contiguous in `frame_number`
            // order — scan the per-ring entries and delete each.
            let mut ring: u16 = 0;
            loop {
                let trie_key = encoding::clock_prover_trie_key(filter, ring, i);
                match self.db.get(&trie_key) {
                    Ok(Some(_)) => batch.delete(&trie_key),
                    Ok(None) => break,
                    Err(e) => return Err(QuilError::Store(e.to_string())),
                }
                ring = match ring.checked_add(1) {
                    Some(n) => n,
                    None => break,
                };
            }

            // Total-distance entries — same selector-range form.
            let td_lo = encoding::clock_data_total_distance_key(filter, i, &zeros);
            let td_hi = encoding::clock_data_total_distance_key(filter, i, &ones);
            batch.delete_range(&td_lo, &td_hi);
        }
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn discard_app_frame_history(&self, global_frame: u64) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for (start, end) in encoding::app_frame_history_ranges() {
            batch.delete_range(&start, &end);
        }
        batch.put(encoding::app_history_discarded_key(), global_frame.to_be_bytes());
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn app_frame_history_discarded(&self) -> Result<Option<u64>> {
        self.read_u64_index_checked(&encoding::app_history_discarded_key())
    }
    fn reset_shard_clock_frames(&self, filter: &[u8]) -> Result<()> {
        let lo = encoding::clock_shard_frame_key(filter, 0);
        let hi = encoding::clock_shard_frame_key(filter, 200_000);
        // Go's reset deletes both the earliest (clockDataEarliestIndex)
        // and the latest (clockShardLatestIndex). The Rust port doesn't
        // distinguish a separate "data earliest" index — the shard
        // store's earliest is implicit on the first frame written. We
        // only need to clear the latest-index marker.
        let latest = encoding::clock_shard_latest_index(filter);
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range(&lo, &hi);
        batch.delete(&latest);
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))?;
        Ok(())
    }
    fn get_latest_certified_app_shard_state(&self, filter: &[u8]) -> Result<proto::global::AppShardProposal> {
        let idx_key = encoding::clock_app_certified_state_latest_index(filter);
        let rank = self.read_u64_index(&idx_key).ok_or_else(|| QuilError::NotFound("no app state".into()))?;
        let key = encoding::clock_app_certified_state_key(filter, rank);
        let data = self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("app state not found".into()))?;
        proto::global::AppShardProposal::decode(data.as_slice()).map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn put_certified_app_shard_state(&self, state: &proto::global::AppShardProposal, t: &dyn store::Transaction) -> Result<()> {
        let header = state.state.as_ref().and_then(|s| s.header.as_ref());
        let filter = header.map(|h| h.address.as_slice()).unwrap_or(&[]);
        let rank = header.map(|h| h.frame_number).unwrap_or(0);
        let key = encoding::clock_app_certified_state_key(filter, rank);
        let idx_key = encoding::clock_app_certified_state_latest_index(filter);
        let data = state.encode_to_vec();
        let rank_bytes = rank.to_be_bytes();
        if let Some(rt) = t.as_any().downcast_ref::<RocksClockTxn>() {
            let mut batch = rt.batch.lock().unwrap();
            batch.put(&key, &data);
            batch.put(&idx_key, rank_bytes);
            return Ok(());
        }
        // Fallback: local batch so the row + index land atomically.
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(&key, &data);
        batch.put(&idx_key, rank_bytes);
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn put_proposal_vote(&self, t: &dyn store::Transaction, vote: &proto::global::ProposalVote) -> Result<()> {
        let key = encoding::clock_proposal_vote_key(&vote.filter, vote.rank, &vote.selector);
        let data = vote.encode_to_vec();
        if with_clock_batch(t, |b| b.put(&key, &data)) {
            return Ok(());
        }
        self.db.put(&key, &data).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_proposal_vote(&self, filter: &[u8], rank: u64, identity: &[u8]) -> Result<proto::global::ProposalVote> {
        let key = encoding::clock_proposal_vote_key(filter, rank, identity);
        let data = self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("vote not found".into()))?;
        proto::global::ProposalVote::decode(data.as_slice()).map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn get_proposal_votes(&self, filter: &[u8], rank: u64) -> Result<Vec<proto::global::ProposalVote>> {
        let prefix = encoding::clock_proposal_vote_prefix(filter, rank);
        let mut votes = Vec::new();
        let iter = self.db.prefix_iterator(&prefix);
        for item in iter {
            let (k, v) = item.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) { break; }
            if let Ok(vote) = proto::global::ProposalVote::decode(v.as_ref()) {
                votes.push(vote);
            }
        }
        Ok(votes)
    }
    fn put_timeout_vote(&self, t: &dyn store::Transaction, vote: &proto::global::TimeoutState) -> Result<()> {
        let filter = vote.latest_quorum_certificate.as_ref().map(|qc| qc.filter.as_slice()).unwrap_or(&[]);
        let key = encoding::clock_timeout_vote_key(filter, vote.timeout_tick, &vote.vote.as_ref().map(|v| v.selector.as_slice()).unwrap_or(&[]));
        let data = vote.encode_to_vec();
        if with_clock_batch(t, |b| b.put(&key, &data)) {
            return Ok(());
        }
        self.db.put(&key, &data).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_timeout_vote(&self, filter: &[u8], rank: u64, identity: &[u8]) -> Result<proto::global::TimeoutState> {
        let key = encoding::clock_timeout_vote_key(filter, rank, identity);
        let data = self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("timeout vote not found".into()))?;
        proto::global::TimeoutState::decode(data.as_slice()).map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn get_timeout_votes(&self, filter: &[u8], rank: u64) -> Result<Vec<proto::global::TimeoutState>> {
        let prefix = encoding::clock_timeout_vote_prefix(filter, rank);
        let mut votes = Vec::new();
        let iter = self.db.prefix_iterator(&prefix);
        for item in iter {
            let (k, v) = item.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) { break; }
            if let Ok(vote) = proto::global::TimeoutState::decode(v.as_ref()) {
                votes.push(vote);
            }
        }
        Ok(votes)
    }
    fn get_total_distance(&self, filter: &[u8], frame_number: u64, selector: &[u8]) -> Result<BigInt> {
        use num_bigint::Sign;
        let key = encoding::clock_total_distance_key(filter, frame_number, selector);
        match self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))? {
            // Go stores as big.Int.Bytes() — unsigned big-endian.
            Some(data) if !data.is_empty() => Ok(BigInt::from_bytes_be(Sign::Plus, &data)),
            _ => Ok(BigInt::from(0)),
        }
    }
    fn set_total_distance(&self, filter: &[u8], frame_number: u64, selector: &[u8], distance: &BigInt) -> Result<()> {
        let key = encoding::clock_total_distance_key(filter, frame_number, selector);
        // Match Go's big.Int.Bytes() — unsigned big-endian.
        let (_, data) = distance.to_bytes_be();
        self.db.put(&key, &data).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn get_peer_seniority_map(&self, filter: &[u8]) -> Result<std::collections::HashMap<String, u64>> {
        let key = encoding::clock_peer_seniority_key(filter);
        match self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))? {
            Some(data) => {
                // Stored as JSON for simplicity
                serde_json::from_slice(&data).map_err(|e| QuilError::Serialization(e.to_string()))
            }
            None => Ok(std::collections::HashMap::new()),
        }
    }
    fn put_peer_seniority_map(&self, t: &dyn store::Transaction, filter: &[u8], seniority: &std::collections::HashMap<String, u64>) -> Result<()> {
        let key = encoding::clock_peer_seniority_key(filter);
        let data = serde_json::to_vec(seniority).map_err(|e| QuilError::Serialization(e.to_string()))?;
        if with_clock_batch(t, |b| b.put(&key, &data)) {
            return Ok(());
        }
        self.db.put(&key, &data).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn compact_data(&self, _filter: &[u8]) -> Result<()> {
        // RocksDB handles compaction automatically; manual trigger not needed
        Ok(())
    }
}
