use std::sync::Arc;

use quil_types::error::{QuilError, Result};
use quil_types::store::{
    PendingShardChange, ShardChangeKind, ShardInfo, ShardsStore, Transaction,
};

/// Store prefix bytes matching the Go constants.
const SHARD: u8 = 0x0A;
const APP_SHARD_DATA: u8 = 0x00;
/// Keyspace for epoch-aligned pending topology changes (Phase F). Distinct from
/// `APP_SHARD_DATA` so the Go-byte-compatible shard enumeration is untouched.
const PENDING_SHARD_CHANGE: u8 = 0x01;

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

/// Key for a pending change: `[SHARD, PENDING, effective_epoch BE(8), parent...]`.
/// `effective_epoch` leads the parent so a range scan over a single epoch (the
/// boundary-apply path) is a clean prefix scan, while a full scan (the
/// join-freeze path) covers everything under `[SHARD, PENDING]`.
fn pending_change_key(effective_epoch: u64, parent: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 8 + parent.len());
    key.push(SHARD);
    key.push(PENDING_SHARD_CHANGE);
    key.extend_from_slice(&effective_epoch.to_be_bytes());
    key.extend_from_slice(parent);
    key
}

/// Self-contained deterministic encoding (consensus-consistent across nodes):
/// `[kind:1][effective_epoch:8][proposed_frame:8][parent_len:2][parent][n:2]([len:2][child])*`.
fn encode_pending_change(c: &PendingShardChange) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(match c.kind {
        ShardChangeKind::Split => 0u8,
        ShardChangeKind::Merge => 1u8,
    });
    v.extend_from_slice(&c.effective_epoch.to_be_bytes());
    v.extend_from_slice(&c.proposed_frame.to_be_bytes());
    v.extend_from_slice(&(c.parent.len() as u16).to_be_bytes());
    v.extend_from_slice(&c.parent);
    v.extend_from_slice(&(c.children.len() as u16).to_be_bytes());
    for child in &c.children {
        v.extend_from_slice(&(child.len() as u16).to_be_bytes());
        v.extend_from_slice(child);
    }
    v
}

fn decode_pending_change(v: &[u8]) -> Result<PendingShardChange> {
    let err = || QuilError::Store("invalid pending shard change encoding".into());
    let mut i = 0usize;
    let take = |v: &[u8], i: &mut usize, n: usize| -> Result<Vec<u8>> {
        if *i + n > v.len() {
            return Err(QuilError::Store("invalid pending shard change encoding".into()));
        }
        let s = v[*i..*i + n].to_vec();
        *i += n;
        Ok(s)
    };
    let kind = match v.first().ok_or_else(err)? {
        0 => ShardChangeKind::Split,
        1 => ShardChangeKind::Merge,
        _ => return Err(err()),
    };
    i += 1;
    let effective_epoch = u64::from_be_bytes(take(v, &mut i, 8)?.try_into().map_err(|_| err())?);
    let proposed_frame = u64::from_be_bytes(take(v, &mut i, 8)?.try_into().map_err(|_| err())?);
    let plen = u16::from_be_bytes(take(v, &mut i, 2)?.try_into().map_err(|_| err())?) as usize;
    let parent = take(v, &mut i, plen)?;
    let n = u16::from_be_bytes(take(v, &mut i, 2)?.try_into().map_err(|_| err())?) as usize;
    let mut children = Vec::with_capacity(n);
    for _ in 0..n {
        let clen = u16::from_be_bytes(take(v, &mut i, 2)?.try_into().map_err(|_| err())?) as usize;
        children.push(take(v, &mut i, clen)?);
    }
    Ok(PendingShardChange { kind, parent, children, effective_epoch, proposed_frame })
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

    fn put_pending_shard_change(
        &self,
        txn: &dyn Transaction,
        change: &PendingShardChange,
    ) -> Result<()> {
        let key = pending_change_key(change.effective_epoch, &change.parent);
        txn.set(&key, &encode_pending_change(change))
            .map_err(|e| QuilError::Store(format!("put pending shard change: {}", e)))
    }

    fn get_pending_shard_changes(&self, effective_epoch: u64) -> Result<Vec<PendingShardChange>> {
        // Prefix scan over a single epoch: [SHARD, PENDING, epoch BE].
        let mut lower = vec![SHARD, PENDING_SHARD_CHANGE];
        lower.extend_from_slice(&effective_epoch.to_be_bytes());
        let mut upper = vec![SHARD, PENDING_SHARD_CHANGE];
        upper.extend_from_slice(&(effective_epoch.saturating_add(1)).to_be_bytes());

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower);
        read_opts.set_iterate_upper_bound(upper);
        let iter = self.db.iterator_opt(rocksdb::IteratorMode::Start, read_opts);

        let mut out = Vec::new();
        for item in iter {
            let (_k, v) =
                item.map_err(|e| QuilError::Store(format!("get pending changes: {}", e)))?;
            out.push(decode_pending_change(&v)?);
        }
        Ok(out)
    }

    fn all_pending_shard_changes(&self) -> Result<Vec<PendingShardChange>> {
        let lower = vec![SHARD, PENDING_SHARD_CHANGE];
        let upper = vec![SHARD, PENDING_SHARD_CHANGE + 1];

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower);
        read_opts.set_iterate_upper_bound(upper);
        let iter = self.db.iterator_opt(rocksdb::IteratorMode::Start, read_opts);

        let mut out = Vec::new();
        for item in iter {
            let (_k, v) =
                item.map_err(|e| QuilError::Store(format!("all pending changes: {}", e)))?;
            out.push(decode_pending_change(&v)?);
        }
        Ok(out)
    }

    fn delete_pending_shard_change(
        &self,
        txn: &dyn Transaction,
        parent: &[u8],
        effective_epoch: u64,
    ) -> Result<()> {
        let key = pending_change_key(effective_epoch, parent);
        txn.delete(&key)
            .map_err(|e| QuilError::Store(format!("delete pending shard change: {}", e)))
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
    fn pending_shard_changes_roundtrip_and_filter_by_epoch() {
        let (db, store) = test_db();
        let parent_a = vec![0xAAu8; 32];
        let parent_b = vec![0xBBu8; 33];

        let split = PendingShardChange {
            kind: ShardChangeKind::Split,
            parent: parent_a.clone(),
            children: vec![vec![0xAA, 0x00], vec![0xAA, 0x80]],
            effective_epoch: 7,
            proposed_frame: 5 * 720 + 3,
        };
        let merge = PendingShardChange {
            kind: ShardChangeKind::Merge,
            parent: parent_b.clone(),
            children: vec![vec![0xBB; 34], vec![0xBB; 34]],
            effective_epoch: 9,
            proposed_frame: 7 * 720,
        };

        let txn = db.new_batch(false).expect("new batch");
        store.put_pending_shard_change(txn.as_ref(), &split).expect("put split");
        store.put_pending_shard_change(txn.as_ref(), &merge).expect("put merge");
        txn.commit().expect("commit");

        // Filter by effective epoch.
        let e7 = store.get_pending_shard_changes(7).expect("get e7");
        assert_eq!(e7, vec![split.clone()], "epoch 7 holds only the split");
        let e9 = store.get_pending_shard_changes(9).expect("get e9");
        assert_eq!(e9, vec![merge.clone()], "epoch 9 holds only the merge");
        assert!(store.get_pending_shard_changes(8).expect("get e8").is_empty());

        // All pending (join-freeze lookup) + affects_shard.
        let all = store.all_pending_shard_changes().expect("all");
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|c| c.affects_shard(&parent_a)));
        assert!(all.iter().any(|c| c.affects_shard(&[0xAA, 0x80]))); // a child of the split
        assert!(!all.iter().any(|c| c.affects_shard(&[0x01, 0x02]))); // unrelated

        // Delete the applied split.
        let txn = db.new_batch(false).expect("new batch");
        store.delete_pending_shard_change(txn.as_ref(), &parent_a, 7).expect("delete");
        txn.commit().expect("commit");
        assert!(store.get_pending_shard_changes(7).expect("get e7 post-delete").is_empty());
        assert_eq!(store.all_pending_shard_changes().expect("all post-delete").len(), 1);
    }

    #[test]
    fn pending_changes_do_not_leak_into_app_shard_enumeration() {
        // The pending keyspace (0x0A 0x01) must not appear in range_app_shards
        // (0x0A 0x00) — otherwise a staged change would masquerade as a live shard.
        let (db, store) = test_db();
        let change = PendingShardChange {
            kind: ShardChangeKind::Split,
            parent: vec![0xCCu8; 35],
            children: vec![vec![0xCC; 36]],
            effective_epoch: 3,
            proposed_frame: 720,
        };
        let txn = db.new_batch(false).expect("new batch");
        store.put_pending_shard_change(txn.as_ref(), &change).expect("put");
        txn.commit().expect("commit");
        assert!(store.range_app_shards().expect("range").is_empty(),
            "pending changes must not leak into the live shard enumeration");
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
