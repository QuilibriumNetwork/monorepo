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

use std::sync::Arc;

use quil_types::error::Result;
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

    /// Remove one replica.
    pub fn delete(&self, epoch: u64, leaf_id: &[u8]) -> Result<()> {
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
        self.db.delete_range(&lo, &hi)
    }

    /// Iterate `(leaf_id, replica)` for every leaf stored under `epoch`. Used by
    /// the per-frame producer to answer challenges for the active epoch.
    pub fn for_each_in_epoch(
        &self,
        epoch: u64,
        mut f: impl FnMut(Vec<u8>, Vec<u8>),
    ) -> Result<()> {
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
        assert_eq!(s.get(3, leaf).unwrap().as_deref(), Some(&b"replica-bytes"[..]));
        s.delete(3, leaf).unwrap();
        assert_eq!(s.get(3, leaf).unwrap(), None);
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
