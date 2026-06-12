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

        let header_bytes = header.encode_to_vec();
        let key = encoding::clock_global_frame_candidate_key(frame_number, &identity);
        self.db
            .put(&key, &header_bytes)
            .map_err(|e| QuilError::Store(e.to_string()))?;

        for (i, request) in frame.requests.iter().enumerate() {
            let idx = i as u16;
            let req_key = encoding::clock_global_frame_request_candidate_key(
                &identity,
                frame_number,
                idx,
            );
            let req_bytes = request.encode_to_vec();
            self.db
                .put(&req_key, &req_bytes)
                .map_err(|e| QuilError::Store(e.to_string()))?;
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
        let header_bytes = match self
            .db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))?
        {
            Some(b) => b,
            None => return self.get_global_frame(frame_number),
        };
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
            for i in 0u16.. {
                let req_key = encoding::clock_global_frame_request_candidate_key(
                    selector, frame_number, i,
                );
                let req_bytes = match self
                    .db
                    .get(&req_key)
                    .map_err(|e| QuilError::Store(e.to_string()))?
                {
                    Some(b) => b,
                    None => break,
                };
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
    fn delete_global_clock_frame_range(&self, min_frame: u64, max_frame: u64) -> Result<()> {
        let lower = encoding::clock_global_frame_key(min_frame);
        let upper = encoding::clock_global_frame_key(max_frame);
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range(&lower, &upper);
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
    }
    fn reset_global_clock_frames(&self) -> Result<()> {
        let lo = encoding::clock_global_frame_key(0);
        let hi = encoding::clock_global_frame_key(20_000_000);
        let earliest = encoding::clock_global_earliest_index();
        let latest = encoding::clock_global_latest_index();
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range(&lo, &hi);
        batch.delete(&earliest);
        batch.delete(&latest);
        self.db.write(batch).map_err(|e| QuilError::Store(e.to_string()))
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
        if let Some(staged_bytes) = self
            .db
            .get(&staged_key)
            .map_err(|e| QuilError::Store(e.to_string()))?
        {
            let canonical_key = encoding::clock_shard_frame_key(filter, frame_number);
            if !with_clock_batch(t, |b| b.put(&canonical_key, &staged_bytes)) {
                self.db
                    .put(&canonical_key, &staged_bytes)
                    .map_err(|e| QuilError::Store(e.to_string()))?;
            }
        }

        // Update the latest-index pointer (skipped during backfill,
        // matching Go).
        if !backfill {
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
