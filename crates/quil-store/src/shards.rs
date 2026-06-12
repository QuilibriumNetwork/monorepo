use std::sync::Arc;

use quil_types::error::{QuilError, Result};
use quil_types::store::{ShardInfo, ShardsStore, Transaction};

/// Store prefix bytes matching the Go constants.
const SHARD: u8 = 0x0A;
const APP_SHARD_DATA: u8 = 0x00;

/// Shard key length: L1 (3 bytes) + L2 (32 bytes) = 35 bytes.
const SHARD_KEY_LEN: usize = 35;

/// RocksDB-backed application shard metadata store.
pub struct RocksShardsStore {
    db: Arc<rocksdb::DB>,
}

impl RocksShardsStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }
}

/// Build the RocksDB key for an app shard entry.
///
/// Layout: `[SHARD, APP_SHARD_DATA, shard_key..., prefix[0] as BE u32, ...]`
fn app_shard_key(shard_key: &[u8], prefix: &[u32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + shard_key.len() + prefix.len() * 4);
    key.push(SHARD);
    key.push(APP_SHARD_DATA);
    key.extend_from_slice(shard_key);
    for &p in prefix {
        key.extend_from_slice(&p.to_be_bytes());
    }
    key
}

/// Decode a value blob into a `Vec<u32>` of big-endian u32s.
///
/// The Go code handles values whose length is not a multiple of 4 by
/// skipping the leading `len % 4` bytes before decoding u32s.
fn decode_path(value: &[u8]) -> Result<Vec<u32>> {
    let offset = value.len() % 4;
    let aligned = &value[offset..];
    let count = aligned.len() / 4;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * 4;
        let bytes: [u8; 4] = aligned[start..start + 4]
            .try_into()
            .map_err(|_| QuilError::Store("invalid path encoding".into()))?;
        out.push(u32::from_be_bytes(bytes));
    }
    Ok(out)
}

impl ShardsStore for RocksShardsStore {
    fn range_app_shards(&self) -> Result<Vec<ShardInfo>> {
        let lower = app_shard_key(&[0u8; SHARD_KEY_LEN], &[]);
        let upper = app_shard_key(&[0xffu8; SHARD_KEY_LEN], &[0xffff]);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower);
        read_opts.set_iterate_upper_bound(upper);

        let iter = self
            .db
            .iterator_opt(rocksdb::IteratorMode::Start, read_opts);

        let mut shards = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| QuilError::Store(format!("range app shards: {}", e)))?;
            if k.len() < 2 + SHARD_KEY_LEN {
                continue;
            }
            let shard_key = k[2..2 + SHARD_KEY_LEN].to_vec();
            let path = decode_path(&v)?;
            shards.push(ShardInfo {
                shard_key,
                prefix: path,
                size: Vec::new(),
                data_shards: 0,
                commitment: Vec::new(),
            });
        }

        Ok(shards)
    }

    fn get_app_shards(&self, shard_key: &[u8], prefix: &[u32]) -> Result<Vec<ShardInfo>> {
        let lower = app_shard_key(shard_key, prefix);
        let mut end_prefix = prefix.to_vec();
        end_prefix.push(0xffff);
        let upper = app_shard_key(shard_key, &end_prefix);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower);
        read_opts.set_iterate_upper_bound(upper);

        let iter = self
            .db
            .iterator_opt(rocksdb::IteratorMode::Start, read_opts);

        let mut shards = Vec::new();
        for item in iter {
            let (_k, v) =
                item.map_err(|e| QuilError::Store(format!("get app shards: {}", e)))?;
            let path = decode_path(&v)?;
            shards.push(ShardInfo {
                shard_key: shard_key.to_vec(),
                prefix: path,
                size: Vec::new(),
                data_shards: 0,
                commitment: Vec::new(),
            });
        }

        Ok(shards)
    }

    fn put_app_shard(&self, txn: &dyn Transaction, shard: &ShardInfo) -> Result<()> {
        let key = app_shard_key(&shard.shard_key, &shard.prefix);
        // Value = the prefix portion of the key (everything after the 2-byte header + shard_key).
        let value = &key[2 + shard.shard_key.len()..];
        txn.set(&key, value)
            .map_err(|e| QuilError::Store(format!("put app shard: {}", e)))
    }

    fn delete_app_shard(
        &self,
        txn: &dyn Transaction,
        shard_key: &[u8],
        prefix: &[u32],
    ) -> Result<()> {
        let key = app_shard_key(shard_key, prefix);
        txn.delete(&key)
            .map_err(|e| QuilError::Store(format!("delete app shard: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RocksDb;
    use quil_types::store::KvDb;

    fn test_db() -> (RocksDb, RocksShardsStore) {
        let rocks = RocksDb::open_in_memory().expect("open in-memory db");
        let store = RocksShardsStore::new(rocks.inner());
        (rocks, store)
    }

    fn make_shard_key() -> Vec<u8> {
        // 3 bytes L1 + 32 bytes L2 = 35 bytes
        let mut key = vec![0x01, 0x02, 0x03];
        key.extend_from_slice(&[0xAA; 32]);
        key
    }

    #[test]
    fn test_put_and_get() {
        let (db, store) = test_db();
        let shard_key = make_shard_key();
        let prefix = vec![1u32, 2, 3];

        let shard = ShardInfo {
            shard_key: shard_key.clone(),
            prefix: prefix.clone(),
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };

        let txn = db.new_batch(false).expect("new batch");
        store.put_app_shard(txn.as_ref(), &shard).expect("put");
        txn.commit().expect("commit");

        let results = store
            .get_app_shards(&shard_key, &[])
            .expect("get app shards");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].shard_key, shard_key);
        assert_eq!(results[0].prefix, prefix);
    }

    #[test]
    fn test_put_multiple_and_range() {
        let (db, store) = test_db();

        let shard_key_a = {
            let mut k = vec![0x01, 0x02, 0x03];
            k.extend_from_slice(&[0xAA; 32]);
            k
        };
        let shard_key_b = {
            let mut k = vec![0x04, 0x05, 0x06];
            k.extend_from_slice(&[0xBB; 32]);
            k
        };

        let shard_a = ShardInfo {
            shard_key: shard_key_a.clone(),
            prefix: vec![10, 20],
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };
        let shard_b = ShardInfo {
            shard_key: shard_key_b.clone(),
            prefix: vec![30, 40],
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };

        let txn = db.new_batch(false).expect("new batch");
        store.put_app_shard(txn.as_ref(), &shard_a).expect("put a");
        store.put_app_shard(txn.as_ref(), &shard_b).expect("put b");
        txn.commit().expect("commit");

        let all = store.range_app_shards().expect("range");
        assert_eq!(all.len(), 2);

        // get_app_shards filtered to shard_key_a
        let filtered = store
            .get_app_shards(&shard_key_a, &[])
            .expect("get filtered");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].prefix, vec![10, 20]);
    }

    #[test]
    fn test_delete() {
        let (db, store) = test_db();
        let shard_key = make_shard_key();
        let prefix = vec![5u32, 6];

        let shard = ShardInfo {
            shard_key: shard_key.clone(),
            prefix: prefix.clone(),
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };

        // Insert
        let txn = db.new_batch(false).expect("new batch");
        store.put_app_shard(txn.as_ref(), &shard).expect("put");
        txn.commit().expect("commit");

        // Verify it exists
        let results = store
            .get_app_shards(&shard_key, &[])
            .expect("get before delete");
        assert_eq!(results.len(), 1);

        // Delete
        let txn = db.new_batch(false).expect("new batch");
        store
            .delete_app_shard(txn.as_ref(), &shard_key, &prefix)
            .expect("delete");
        txn.commit().expect("commit");

        // Verify gone
        let results = store
            .get_app_shards(&shard_key, &[])
            .expect("get after delete");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_get_with_prefix_filter() {
        let (db, store) = test_db();
        let shard_key = make_shard_key();

        // Insert two entries with different prefixes under the same shard key
        let shard_1 = ShardInfo {
            shard_key: shard_key.clone(),
            prefix: vec![1, 2, 3],
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };
        let shard_2 = ShardInfo {
            shard_key: shard_key.clone(),
            prefix: vec![1, 2, 4],
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };
        let shard_3 = ShardInfo {
            shard_key: shard_key.clone(),
            prefix: vec![9, 8, 7],
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };

        let txn = db.new_batch(false).expect("new batch");
        store.put_app_shard(txn.as_ref(), &shard_1).expect("put 1");
        store.put_app_shard(txn.as_ref(), &shard_2).expect("put 2");
        store.put_app_shard(txn.as_ref(), &shard_3).expect("put 3");
        txn.commit().expect("commit");

        // Query with prefix [1, 2] should return the first two
        let results = store
            .get_app_shards(&shard_key, &[1, 2])
            .expect("get with prefix");
        assert_eq!(results.len(), 2);

        // Query with no prefix should return all three
        let all = store
            .get_app_shards(&shard_key, &[])
            .expect("get all");
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_range_empty() {
        let (_db, store) = test_db();
        let results = store.range_app_shards().expect("range empty");
        assert!(results.is_empty());
    }

    #[test]
    fn test_get_empty() {
        let (_db, store) = test_db();
        let shard_key = make_shard_key();
        let results = store
            .get_app_shards(&shard_key, &[])
            .expect("get empty");
        assert!(results.is_empty());
    }
}
