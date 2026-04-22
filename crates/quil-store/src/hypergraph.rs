use std::sync::Arc;

use quil_types::error::{QuilError, Result};
use quil_types::store::ShardKey;

use crate::encoding::{
    hypergraph_alt_shard_address_index_key, hypergraph_alt_shard_address_prefix,
    hypergraph_alt_shard_commit_key, hypergraph_alt_shard_commit_latest_key,
    hypergraph_shard_commit_frame_prefix, hypergraph_shard_commit_key,
    hypergraph_tree_blob_key, hypergraph_vertex_data_key, hypergraph_vertex_data_prefix,
    HG_VERTEX_ADDS_SHARD_COMMIT,
};

/// RocksDB-backed hypergraph tree storage.
pub struct RocksHypergraphStore {
    db: Arc<rocksdb::DB>,
}

impl RocksHypergraphStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }

    /// Save a fully-serialized vector commitment tree as a single blob,
    /// keyed by `(set_type, phase_type, shard_key)`. The bytes should be
    /// the output of `quil_tries::serialize_tree`.
    pub fn save_tree_blob(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        bytes: &[u8],
    ) -> Result<()> {
        let key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        self.db
            .put(&key, bytes)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Load a previously stored tree blob, or `Ok(None)` if no blob exists
    /// for the given key.
    pub fn load_tree_blob(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
    ) -> Result<Option<Vec<u8>>> {
        let key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        self.db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Persist one vertex's `underlying_data` sub-tree blob. See
    /// `quil_tries::deserialize_go_tree` for parsing the wire format.
    pub fn save_vertex_underlying(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        let key = hypergraph_vertex_data_key(set_type, phase_type, shard_key, vertex_key);
        self.db
            .put(&key, bytes)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Load one vertex's `underlying_data`, or `Ok(None)` if absent.
    pub fn load_vertex_underlying(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let key = hypergraph_vertex_data_key(set_type, phase_type, shard_key, vertex_key);
        self.db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Iterate every `(vertex_key, underlying_data)` pair persisted for
    /// the given `(set, phase, shard)`. The callback receives owned
    /// bytes so it can move them into a caller-owned collection.
    pub fn for_each_vertex_underlying<F>(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        mut callback: F,
    ) -> Result<usize>
    where
        F: FnMut(Vec<u8>, Vec<u8>),
    {
        let prefix = hypergraph_vertex_data_prefix(set_type, phase_type, shard_key);
        // Seek to the first key ≥ prefix and walk forward until we leave
        // the prefix. Avoids the correctness pitfalls of
        // `set_iterate_upper_bound` when the shard or vertex keys have
        // high byte values — incrementing 0xFF bytes is error-prone, so
        // we just compare each yielded key against the prefix.
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &prefix,
            rocksdb::Direction::Forward,
        ));
        let prefix_len = prefix.len();
        let mut count = 0usize;
        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            if k.len() <= prefix_len {
                continue;
            }
            let vertex_key = k[prefix_len..].to_vec();
            callback(vertex_key, v.into_vec());
            count += 1;
        }
        Ok(count)
    }
}

use std::collections::HashMap;
use quil_types::store::{ChangeRecord, HypergraphStore, Transaction};

/// RocksDB Transaction — wraps a WriteBatch for atomicity.
pub(crate) struct RocksTxn {
    pub(crate) batch: std::sync::Mutex<rocksdb::WriteBatch>,
    db: Arc<rocksdb::DB>,
}

impl Transaction for RocksTxn {
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
    fn abort(self: Box<Self>) -> Result<()> {
        // Drop the batch without writing
        Ok(())
    }
    fn new_iter(&self, _lower: &[u8], _upper: &[u8]) -> Result<Box<dyn quil_types::store::Iterator>> {
        Err(QuilError::Internal("RocksTxn iterator not implemented".into()))
    }
    fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete_range(lower, upper);
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// If `txn` is a `RocksTxn`, stage `op` into its write batch and
/// return `true`; else return `false` so the caller can fall back
/// to direct DB writes.
#[inline]
fn with_rocks_batch<F>(txn: &dyn Transaction, op: F) -> bool
where
    F: FnOnce(&mut rocksdb::WriteBatch),
{
    if let Some(rt) = txn.as_any().downcast_ref::<RocksTxn>() {
        let mut guard = rt.batch.lock().unwrap();
        op(&mut *guard);
        true
    } else {
        false
    }
}

impl HypergraphStore for RocksHypergraphStore {
    fn new_transaction(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
        Ok(Box::new(RocksTxn {
            batch: std::sync::Mutex::new(rocksdb::WriteBatch::default()),
            db: self.db.clone(),
        }))
    }

    fn get_node_by_key(&self, set_type: &str, phase_type: &str, shard_key: &ShardKey, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Root sentinel: key = [0xFF; 32]
        if key == [0xFFu8; 32] {
            return self.load_tree_blob(set_type, phase_type, shard_key);
        }
        self.load_vertex_underlying(set_type, phase_type, shard_key, key)
    }

    fn get_node_by_path(&self, _set_type: &str, _phase_type: &str, _shard_key: &ShardKey, _path: &[i32]) -> Result<Option<Vec<u8>>> {
        // Path-based lookup not used by the lazy tree implementation
        Ok(None)
    }

    fn insert_node(&self, txn: &dyn Transaction, set_type: &str, phase_type: &str, shard_key: &ShardKey, key: &[u8], _path: &[i32], data: &[u8]) -> Result<()> {
        let db_key = if key == [0xFFu8; 32] {
            hypergraph_tree_blob_key(set_type, phase_type, shard_key)
        } else {
            hypergraph_vertex_data_key(set_type, phase_type, shard_key, key)
        };
        if with_rocks_batch(txn, |b| b.put(&db_key, data)) {
            return Ok(());
        }
        self.db
            .put(&db_key, data)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn save_root(&self, txn: &dyn Transaction, set_type: &str, phase_type: &str, shard_key: &ShardKey, data: &[u8]) -> Result<()> {
        let db_key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
        if with_rocks_batch(txn, |b| b.put(&db_key, data)) {
            return Ok(());
        }
        self.db
            .put(&db_key, data)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn delete_node(&self, txn: &dyn Transaction, set_type: &str, phase_type: &str, shard_key: &ShardKey, key: &[u8], _path: &[i32]) -> Result<()> {
        let db_key = if key == [0xFFu8; 32] {
            hypergraph_tree_blob_key(set_type, phase_type, shard_key)
        } else {
            hypergraph_vertex_data_key(set_type, phase_type, shard_key, key)
        };
        if with_rocks_batch(txn, |b| b.delete(&db_key)) {
            return Ok(());
        }
        self.db
            .delete(&db_key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn set_covered_prefix(&self, _prefix: &[i32]) -> Result<()> { Ok(()) }

    fn set_shard_commit(&self, txn: &dyn Transaction, frame_number: u64, phase_type: &str, set_type: &str, shard_address: &[u8], commitment: &[u8]) -> Result<()> {
        let key = hypergraph_shard_commit_key(frame_number, phase_type, set_type, shard_address);
        if with_rocks_batch(txn, |b| b.put(&key, commitment)) {
            return Ok(());
        }
        self.db.put(&key, commitment).map_err(|e| QuilError::Store(e.to_string()))
    }

    fn get_shard_commit(&self, frame_number: u64, phase_type: &str, set_type: &str, shard_address: &[u8]) -> Result<Vec<u8>> {
        let key = hypergraph_shard_commit_key(frame_number, phase_type, set_type, shard_address);
        self.db.get(&key).map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("shard commit not found".into()))
    }

    fn get_root_commits(&self, frame_number: u64) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
        let prefix = hypergraph_shard_commit_frame_prefix(frame_number);
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &prefix,
            rocksdb::Direction::Forward,
        ));
        let prefix_len = prefix.len();
        let mut result: HashMap<ShardKey, Vec<Vec<u8>>> = HashMap::new();
        for entry in iter {
            let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            // Key layout past the prefix: [commit_type(1), shard_address(32)]
            // Skip keys that don't have exactly commit_type + 32-byte address.
            if k.len() != prefix_len + 1 + 32 {
                continue;
            }
            let commit_type = k[prefix_len];
            let shard_address = &k[prefix_len + 1..];
            let commit_idx = (commit_type - HG_VERTEX_ADDS_SHARD_COMMIT) as usize;
            if commit_idx >= 4 {
                continue;
            }
            // Derive L1 bloom filter from L2 (shard_address) via XOR fold,
            // matching quil_hypergraph::addressing::shard_key_for_location.
            let mut l1 = [0u8; 3];
            for (i, &b) in shard_address.iter().enumerate() {
                l1[i % 3] ^= b;
            }
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(shard_address);
            let sk = ShardKey { l1, l2 };
            let commits = result.entry(sk).or_insert_with(|| vec![vec![]; 4]);
            commits[commit_idx] = v.to_vec();
        }
        Ok(result)
    }

    fn load_vertex_underlying_raw(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.load_vertex_underlying(set_type, phase_type, shard_key, vertex_key)
    }

    fn apply_snapshot(&self, _db_path: &str) -> Result<()> { Ok(()) }

    fn set_alt_shard_commit(
        &self,
        txn: &dyn Transaction,
        frame_number: u64,
        shard_address: &[u8],
        va: &[u8],
        vr: &[u8],
        ha: &[u8],
        hr: &[u8],
    ) -> Result<()> {
        // Validate root sizes — Go accepts 64 (raw) or 74 (KZG-with-proof).
        for (name, root) in [("vertex_adds", va), ("vertex_removes", vr),
                              ("hyperedge_adds", ha), ("hyperedge_removes", hr)] {
            if root.len() != 64 && root.len() != 74 {
                return Err(QuilError::InvalidArgument(format!(
                    "alt shard commit {name} root must be 64 or 74 bytes, got {}",
                    root.len()
                )));
            }
        }

        // Serialize as length-prefixed values (1-byte len + data for each of
        // the four roots) — matches `SetAltShardCommit` at
        // node/store/hypergraph.go:2425.
        let mut value = Vec::with_capacity(4 + va.len() + vr.len() + ha.len() + hr.len());
        for root in [va, vr, ha, hr] {
            value.push(root.len() as u8);
            value.extend_from_slice(root);
        }

        let commit_key = hypergraph_alt_shard_commit_key(frame_number, shard_address);
        let latest_key = hypergraph_alt_shard_commit_latest_key(shard_address);
        let index_key = hypergraph_alt_shard_address_index_key(shard_address);

        // Consult existing latest-frame so we only overwrite with a newer one.
        let should_update_latest = match self.db.get(&latest_key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let existing = u64::from_be_bytes(bytes.as_slice().try_into().unwrap());
                frame_number > existing
            }
            _ => true,
        };

        if with_rocks_batch(txn, |b| {
            b.put(&commit_key, &value);
            if should_update_latest {
                b.put(&latest_key, frame_number.to_be_bytes());
            }
            b.put(&index_key, &[] as &[u8]);
        }) {
            return Ok(());
        }

        // Fallback path — no RocksTxn; use a local atomic batch.
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(&commit_key, &value);
        if should_update_latest {
            batch.put(&latest_key, frame_number.to_be_bytes());
        }
        batch.put(&index_key, &[] as &[u8]);
        self.db
            .write(batch)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn get_latest_alt_shard_commit(
        &self,
        shard_address: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let latest_key = hypergraph_alt_shard_commit_latest_key(shard_address);
        let latest = self
            .db
            .get(&latest_key)
            .map_err(|e| QuilError::Store(e.to_string()))?;
        let frame_number = match latest {
            Some(bytes) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes.as_slice().try_into().unwrap())
            }
            _ => return Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new())),
        };
        let commit_key = hypergraph_alt_shard_commit_key(frame_number, shard_address);
        let value = self
            .db
            .get(&commit_key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("alt shard commit not found".into()))?;

        // Decode four length-prefixed roots.
        let mut cursor = 0usize;
        let mut parts = Vec::with_capacity(4);
        for _ in 0..4 {
            if cursor >= value.len() {
                return Err(QuilError::Serialization(
                    "alt shard commit value truncated".into(),
                ));
            }
            let len = value[cursor] as usize;
            cursor += 1;
            if cursor + len > value.len() {
                return Err(QuilError::Serialization(
                    "alt shard commit length prefix overruns buffer".into(),
                ));
            }
            parts.push(value[cursor..cursor + len].to_vec());
            cursor += len;
        }
        Ok((
            parts.remove(0),
            parts.remove(0),
            parts.remove(0),
            parts.remove(0),
        ))
    }

    fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> {
        let prefix = hypergraph_alt_shard_address_prefix();
        let prefix_len = prefix.len();
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &prefix,
            rocksdb::Direction::Forward,
        ));
        let mut out = Vec::new();
        for entry in iter {
            let (k, _v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            if k.len() > prefix_len {
                out.push(k[prefix_len..].to_vec());
            }
        }
        Ok(out)
    }
    fn reap_old_changesets(&self, _txn: &dyn Transaction, _frame_number: u64) -> Result<()> { Ok(()) }
    fn track_change(&self, _txn: &dyn Transaction, _key: &[u8], _old_value: Option<&[u8]>, _frame_number: u64, _phase_type: &str, _set_type: &str, _shard_key: &ShardKey) -> Result<()> { Ok(()) }
    fn get_changes(&self, _frame_start: u64, _frame_end: u64, _phase_type: &str, _set_type: &str, _shard_key: &ShardKey) -> Result<Vec<ChangeRecord>> { Ok(vec![]) }
    fn untrack_change(&self, _txn: &dyn Transaction, _key: &[u8], _frame_number: u64, _phase_type: &str, _set_type: &str, _shard_key: &ShardKey) -> Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rocksdb_store::RocksDb;
    use tempfile::TempDir;

    #[test]
    fn test_tree_blob_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = RocksHypergraphStore::new(Arc::new(db).inner());

        let shard = ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };

        // Absent key returns Ok(None).
        assert!(store.load_tree_blob("vertex", "adds", &shard).unwrap().is_none());

        // Save and read back.
        let blob = vec![1u8, 2, 3, 4, 5];
        store.save_tree_blob("vertex", "adds", &shard, &blob).unwrap();
        let loaded = store.load_tree_blob("vertex", "adds", &shard).unwrap();
        assert_eq!(loaded, Some(blob));

        // Different phase → different key → still absent.
        assert!(store.load_tree_blob("vertex", "removes", &shard).unwrap().is_none());
    }

    #[test]
    fn test_vertex_underlying_roundtrip_and_iter() {
        let tmp = TempDir::new().unwrap();
        let db = RocksDb::open(tmp.path()).unwrap();
        let store = RocksHypergraphStore::new(Arc::new(db).inner());

        let shard = ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };

        let keys = [
            vec![0xAA; 64],
            vec![0xBB; 64],
            vec![0xCC; 64],
        ];
        let data = [b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];

        // Empty-phase point lookup returns Ok(None).
        assert!(store
            .load_vertex_underlying("vertex", "adds", &shard, &keys[0])
            .unwrap()
            .is_none());

        // Save three entries under (vertex, adds, shard).
        for (k, v) in keys.iter().zip(data.iter()) {
            store
                .save_vertex_underlying("vertex", "adds", &shard, k, v)
                .unwrap();
        }

        // Point lookup.
        assert_eq!(
            store
                .load_vertex_underlying("vertex", "adds", &shard, &keys[1])
                .unwrap()
                .as_deref(),
            Some(&b"beta"[..])
        );

        // Different phase is isolated.
        for k in &keys {
            assert!(store
                .load_vertex_underlying("vertex", "removes", &shard, k)
                .unwrap()
                .is_none());
        }

        // Iterate all entries for the phase.
        let mut collected: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let count = store
            .for_each_vertex_underlying("vertex", "adds", &shard, |k, v| {
                collected.push((k, v));
            })
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(collected.len(), 3);
        // Iterator yields them in key order, which is our insertion order
        // by construction (0xAA < 0xBB < 0xCC).
        assert_eq!(collected[0].0, keys[0]);
        assert_eq!(collected[1].0, keys[1]);
        assert_eq!(collected[2].0, keys[2]);
    }
}
