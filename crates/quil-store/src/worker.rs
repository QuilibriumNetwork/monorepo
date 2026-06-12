//! Worker registry persistence. Mirrors Go's
//! `node/store/worker.go::PebbleWorkerStore` so the operator's
//! `manually_managed` flag and the worker→filter binding survive
//! node restarts.
//!
//! Layout:
//!   * `[WORKER, WORKER_BY_CORE, core_id_be_u64]` → encoded
//!     `PersistedWorkerInfo`
//!   * `[WORKER, WORKER_BY_FILTER, filter…]` → 8-byte BE core_id
//!     (secondary index; lets Go-style lookups by filter resolve
//!     to the primary record)
//!
//! Encoding mirrors Go's `encodeWorkerInfo` field order so a
//! Rust-written record could in principle be read by Go and vice
//! versa, modulo the listen-multiaddr fields which we don't track
//! (they're empty strings in the encoding — same on-disk shape).

use std::sync::Arc;

use quil_types::error::{QuilError, Result};
use quil_types::store::{PersistedWorkerInfo, WorkerStore};

use crate::encoding::{WORKER, WORKER_BY_CORE, WORKER_BY_FILTER};

pub struct RocksWorkerStore {
    db: Arc<rocksdb::DB>,
}

impl RocksWorkerStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }
}

fn worker_key(core_id: u32) -> [u8; 10] {
    let mut k = [0u8; 10];
    k[0] = WORKER;
    k[1] = WORKER_BY_CORE;
    k[2..10].copy_from_slice(&(core_id as u64).to_be_bytes());
    k
}

fn worker_by_filter_key(filter: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + filter.len());
    k.push(WORKER);
    k.push(WORKER_BY_FILTER);
    k.extend_from_slice(filter);
    k
}

fn encode(info: &PersistedWorkerInfo) -> Vec<u8> {
    // Mirrors Go's `encodeWorkerInfo`:
    //   coreId(8) + totalStorage(8) + automatic(1) + allocated(1)
    //   + listenMultiaddrLen(2) + listenMultiaddr
    //   + streamListenMultiaddrLen(2) + streamListenMultiaddr
    //   + filterLen(2) + filter
    //   + pendingFilterFrame(8)
    //   + manuallyManaged(1)
    let filter_len = info.filter.len() as u16;
    let total_len = 8 + 8 + 1 + 1 + 2 + 2 + 2 + filter_len as usize + 8 + 1;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&(info.core_id as u64).to_be_bytes());
    // total_storage — not tracked locally; emit 0 for forward compat.
    out.extend_from_slice(&0u64.to_be_bytes());
    // automatic = !manually_managed (Go's terminology)
    out.push(if info.manually_managed { 0 } else { 1 });
    out.push(if info.allocated { 1 } else { 0 });
    // listen / stream multiaddrs — empty in this codepath.
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&filter_len.to_be_bytes());
    out.extend_from_slice(&info.filter);
    out.extend_from_slice(&info.pending_filter_frame.to_be_bytes());
    out.push(if info.manually_managed { 1 } else { 0 });
    out
}

fn decode(data: &[u8]) -> Result<PersistedWorkerInfo> {
    if data.len() < 24 {
        return Err(QuilError::Store("worker info: too short".into()));
    }
    let mut o = 0;
    let core_id_u64 = u64::from_be_bytes(data[o..o + 8].try_into().unwrap());
    o += 8;
    let _total_storage = u64::from_be_bytes(data[o..o + 8].try_into().unwrap());
    o += 8;
    // automatic byte (consumed via the trailing manually_managed
    // byte; Go writes both for compat).
    let _automatic = data[o];
    o += 1;
    let allocated = data[o] == 1;
    o += 1;
    if o + 2 > data.len() {
        return Err(QuilError::Store("worker info: truncated listen len".into()));
    }
    let listen_len = u16::from_be_bytes(data[o..o + 2].try_into().unwrap()) as usize;
    o += 2;
    if o + listen_len > data.len() {
        return Err(QuilError::Store("worker info: truncated listen".into()));
    }
    o += listen_len;
    if o + 2 > data.len() {
        return Err(QuilError::Store("worker info: truncated stream len".into()));
    }
    let stream_len = u16::from_be_bytes(data[o..o + 2].try_into().unwrap()) as usize;
    o += 2;
    if o + stream_len > data.len() {
        return Err(QuilError::Store("worker info: truncated stream".into()));
    }
    o += stream_len;
    if o + 2 > data.len() {
        return Err(QuilError::Store("worker info: truncated filter len".into()));
    }
    let filter_len = u16::from_be_bytes(data[o..o + 2].try_into().unwrap()) as usize;
    o += 2;
    if o + filter_len > data.len() {
        return Err(QuilError::Store("worker info: truncated filter".into()));
    }
    let filter = data[o..o + filter_len].to_vec();
    o += filter_len;
    let pending_filter_frame = if o + 8 <= data.len() {
        let v = u64::from_be_bytes(data[o..o + 8].try_into().unwrap());
        o += 8;
        v
    } else {
        0
    };
    let manually_managed = data.get(o).copied().unwrap_or(0) == 1;

    Ok(PersistedWorkerInfo {
        core_id: core_id_u64 as u32,
        filter,
        manually_managed,
        allocated,
        pending_filter_frame,
    })
}

impl WorkerStore for RocksWorkerStore {
    fn get_worker(&self, core_id: u32) -> Result<Option<PersistedWorkerInfo>> {
        let key = worker_key(core_id);
        let raw = self
            .db
            .get(&key)
            .map_err(|e| QuilError::Store(format!("get_worker: {}", e)))?;
        match raw {
            Some(bytes) => Ok(Some(decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn put_worker(&self, worker: &PersistedWorkerInfo) -> Result<()> {
        // Clear any stale by-filter index entry first.
        if let Some(existing) = self.get_worker(worker.core_id)? {
            if !existing.filter.is_empty() && existing.filter != worker.filter {
                let _ = self.db.delete(worker_by_filter_key(&existing.filter));
            }
        }
        let pri_key = worker_key(worker.core_id);
        let payload = encode(worker);
        self.db
            .put(&pri_key, &payload)
            .map_err(|e| QuilError::Store(format!("put_worker: {}", e)))?;
        if !worker.filter.is_empty() {
            let idx_key = worker_by_filter_key(&worker.filter);
            self.db
                .put(&idx_key, &(worker.core_id as u64).to_be_bytes())
                .map_err(|e| QuilError::Store(format!("put_worker: {}", e)))?;
        }
        Ok(())
    }

    fn delete_worker(&self, core_id: u32) -> Result<()> {
        if let Some(existing) = self.get_worker(core_id)? {
            if !existing.filter.is_empty() {
                let _ = self.db.delete(worker_by_filter_key(&existing.filter));
            }
        }
        self.db
            .delete(&worker_key(core_id))
            .map_err(|e| QuilError::Store(format!("delete_worker: {}", e)))
    }

    fn range_workers(&self) -> Result<Vec<PersistedWorkerInfo>> {
        let lower = [WORKER, WORKER_BY_CORE, 0x00, 0, 0, 0, 0, 0, 0, 0];
        let upper = [WORKER, WORKER_BY_CORE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower.to_vec());
        read_opts.set_iterate_upper_bound(upper.to_vec());
        let iter = self.db.iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        let mut out = Vec::new();
        for item in iter {
            let (_k, v) = item
                .map_err(|e| QuilError::Store(format!("range_workers: {}", e)))?;
            out.push(decode(&v)?);
        }
        out.sort_by_key(|w| w.core_id);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RocksDb;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, RocksWorkerStore) {
        let dir = TempDir::new().unwrap();
        let db = RocksDb::open(dir.path()).unwrap();
        (dir, RocksWorkerStore::new(db.inner()))
    }

    #[test]
    fn put_get_round_trips() {
        let (_dir, s) = fresh_store();
        let w = PersistedWorkerInfo {
            core_id: 3,
            filter: vec![0xA1; 33],
            manually_managed: true,
            allocated: true,
            pending_filter_frame: 12345,
        };
        s.put_worker(&w).unwrap();
        let back = s.get_worker(3).unwrap().unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn range_returns_sorted() {
        let (_dir, s) = fresh_store();
        for id in [4u32, 1, 7] {
            s.put_worker(&PersistedWorkerInfo {
                core_id: id,
                filter: vec![id as u8; 8],
                manually_managed: id == 1,
                allocated: true,
                pending_filter_frame: 0,
            })
            .unwrap();
        }
        let all = s.range_workers().unwrap();
        let ids: Vec<u32> = all.iter().map(|w| w.core_id).collect();
        assert_eq!(ids, vec![1, 4, 7]);
        assert!(all[0].manually_managed);
        assert!(!all[1].manually_managed);
    }

    #[test]
    fn delete_removes_primary_and_filter_index() {
        let (_dir, s) = fresh_store();
        let w = PersistedWorkerInfo {
            core_id: 5,
            filter: vec![9, 9, 9],
            manually_managed: false,
            allocated: true,
            pending_filter_frame: 0,
        };
        s.put_worker(&w).unwrap();
        s.delete_worker(5).unwrap();
        assert!(s.get_worker(5).unwrap().is_none());
    }
}
