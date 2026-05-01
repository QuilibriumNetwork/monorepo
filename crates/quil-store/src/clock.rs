use std::sync::Arc;

use prost::Message;

use quil_types::error::{QuilError, Result};
use quil_types::proto::global;
use quil_types::store;

use crate::encoding;

/// RocksDB-backed clock/frame store.
pub struct RocksClockStore {
    db: Arc<rocksdb::DB>,
}

impl RocksClockStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }

    // ---------------------------------------------------------------
    // Global frames
    // ---------------------------------------------------------------

    /// Get a global frame by frame number.
    pub fn get_global_frame(&self, frame_number: u64) -> Result<global::GlobalFrame> {
        // Read header
        let header_key = encoding::clock_global_frame_key(frame_number);
        let header_bytes = self
            .db
            .get(&header_key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| {
                QuilError::NotFound(format!("global frame {} not found", frame_number))
            })?;

        let header = global::GlobalFrameHeader::decode(header_bytes.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))?;

        // Read requests
        let requests = self.read_frame_requests(frame_number)?;

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
        let current_latest = self.get_latest_frame_number();
        let current_earliest = self.get_earliest_frame_number();
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
            .map_err(|e| QuilError::Store(e.to_string()))
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

    fn read_u64_index(&self, key: &[u8]) -> Option<u64> {
        self.db
            .get(key)
            .ok()?
            .filter(|v| v.len() == 8)
            .map(|v| u64::from_be_bytes(v[..8].try_into().unwrap()))
    }

    fn read_frame_requests(&self, frame_number: u64) -> Result<Vec<global::MessageBundle>> {
        let mut requests = Vec::new();
        let prefix_start = encoding::clock_global_frame_request_key(frame_number, 0);
        let prefix_end = encoding::clock_global_frame_request_key(frame_number, u16::MAX);

        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_lower_bound(prefix_start);
        opts.set_iterate_upper_bound(prefix_end);

        let iter = self.db.iterator_opt(rocksdb::IteratorMode::Start, opts);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> RocksClockStore {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, tmp.path()).unwrap();
        // Leak to keep temp dir alive
        std::mem::forget(tmp);
        RocksClockStore::new(Arc::new(db))
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
    db: Arc<rocksdb::DB>,
}

impl store::Transaction for RocksClockTxn {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(key).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().put(key, value);
        Ok(())
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let batch = self.batch.into_inner().unwrap();
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete(key);
        Ok(())
    }
    fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
    fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn store::Iterator>> {
        Err(QuilError::Internal("RocksClockTxn iterator not implemented".into()))
    }
    fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete_range(lower, upper);
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
    fn new_transaction(&self, _: bool) -> Result<Box<dyn store::Transaction>> {
        Ok(Box::new(RocksClockTxn {
            batch: std::sync::Mutex::new(rocksdb::WriteBatch::default()),
            db: self.db.clone(),
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
        _t: &dyn store::Transaction,
    ) -> Result<()> {
        // Store the candidate keyed by (frame_number, identity).
        // Identity = Poseidon(output) — same derivation as
        // `GlobalState::compute_identity` in quil-engine. Without this
        // entry, `prove_next_state` for rank N+1 cannot resolve its
        // unfinalized prior frame, and the leader's event loop exits
        // with "building on fork or needs sync" the moment its own
        // QC arrives.
        let header = match frame.header.as_ref() {
            Some(h) => h,
            None => return Ok(()),
        };
        let identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
            .map(|h| h.to_vec())
            .unwrap_or_default();
        let frame_number = header.frame_number;
        let key = encoding::clock_global_frame_candidate_key(frame_number, &identity);
        let bytes = {
            use prost::Message as _;
            frame.encode_to_vec()
        };
        self.db
            .put(&key, &bytes)
            .map_err(|e| QuilError::Store(e.to_string()))?;
        Ok(())
    }
    fn get_global_clock_frame_candidate(
        &self,
        frame_number: u64,
        selector: &[u8],
    ) -> Result<proto::global::GlobalFrame> {
        let key = encoding::clock_global_frame_candidate_key(frame_number, selector);
        if let Some(bytes) = self
            .db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))?
        {
            return proto::global::GlobalFrame::decode(bytes.as_slice())
                .map_err(|e| QuilError::Serialization(e.to_string()));
        }
        // Fall back to the canonical frame at this number for legacy
        // callers that pass an unknown selector.
        self.get_global_frame(frame_number)
    }
    fn delete_global_clock_frame_range(&self, _: u64, _: u64) -> Result<()> { Ok(()) }
    fn reset_global_clock_frames(&self) -> Result<()> { Ok(()) }
    fn get_latest_certified_global_state(&self) -> Result<proto::global::GlobalProposal> { Err(QuilError::NotFound("stub".into())) }
    fn get_earliest_certified_global_state(&self) -> Result<proto::global::GlobalProposal> { Err(QuilError::NotFound("stub".into())) }
    fn get_certified_global_state(&self, _: u64) -> Result<proto::global::GlobalProposal> { Err(QuilError::NotFound("stub".into())) }
    fn put_certified_global_state(&self, _: &proto::global::GlobalProposal, _t: &dyn store::Transaction) -> Result<()> { Ok(()) }
    fn get_latest_quorum_certificate(&self, f: &[u8]) -> Result<proto::global::QuorumCertificate> {
        let key = encoding::clock_quorum_certificate_latest_index(f);
        let rank = self.read_u64_index(&key).ok_or_else(|| QuilError::NotFound("no QC".into()))?;
        let qc_key = encoding::clock_quorum_certificate_key(rank, f);
        let data = self.db.get(&qc_key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("QC not found".into()))?;
        proto::global::QuorumCertificate::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))
    }
    fn get_quorum_certificate(&self, _: &[u8], _: u64) -> Result<proto::global::QuorumCertificate> { Err(QuilError::NotFound("stub".into())) }
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
    fn get_latest_timeout_certificate(&self, _: &[u8]) -> Result<proto::global::TimeoutCertificate> { Err(QuilError::NotFound("stub".into())) }
    fn get_timeout_certificate(&self, _: &[u8], _: u64) -> Result<proto::global::TimeoutCertificate> { Err(QuilError::NotFound("stub".into())) }
    fn put_timeout_certificate(&self, _: &proto::global::TimeoutCertificate, _t: &dyn store::Transaction) -> Result<()> { Ok(()) }
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
    fn commit_shard_clock_frame(&self, filter: &[u8], frame_number: u64, _selector: &[u8], t: &dyn store::Transaction, _backfill: bool) -> Result<()> {
        let idx_key = encoding::clock_shard_latest_index(filter);
        let current = self.read_u64_index(&idx_key);
        // Same fix-pattern as `put_global_frame` / `put_quorum_certificate`:
        // when no shard frame has been committed yet, this IS the
        // latest. `> unwrap_or(0)` would silently drop the index
        // update for the very first commit at frame 0.
        if current.is_none() || frame_number > current.unwrap() {
            if with_clock_batch(t, |b| b.put(&idx_key, frame_number.to_be_bytes())) {
                return Ok(());
            }
            self.db.put(&idx_key, frame_number.to_be_bytes()).map_err(|e| QuilError::Store(e.to_string()))?;
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
    fn delete_shard_clock_frame_range(&self, _filter: &[u8], _min: u64, _max: u64) -> Result<()> { Ok(()) }
    fn reset_shard_clock_frames(&self, _filter: &[u8]) -> Result<()> { Ok(()) }
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
