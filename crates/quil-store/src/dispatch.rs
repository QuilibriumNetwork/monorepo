use quil_types::error::{QuilError, Result};
use sha2::{Digest, Sha256};

/// Inbox message prefix byte.
const INBOX_MESSAGE_PREFIX: u8 = 0x40;
/// Hub association add prefix byte.
const HUB_ADD_PREFIX: u8 = 0x41;
/// Hub association delete prefix byte (tombstone).
const HUB_DELETE_PREFIX: u8 = 0x42;

/// Length of the routing filter in inbox keys.
const INBOX_FILTER_LEN: usize = 3;
/// Length of an inbox key written before keys carried a content hash.
const LEGACY_INBOX_MESSAGE_KEY_LEN: usize = 1 + INBOX_FILTER_LEN + 8;
/// Length of an inbox key: prefix, filter, timestamp and the SHA-256 of
/// the stored bytes. Callers charge it to the stored size of a message.
pub const INBOX_MESSAGE_KEY_LEN: usize = LEGACY_INBOX_MESSAGE_KEY_LEN + 32;
/// Deletions written per batch while pruning, so one prune pass never
/// holds the write lock for long.
const PRUNE_BATCH: usize = 1024;

/// Inbox entries a prune pass kept and removed, with their key and value
/// bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InboxUsage {
    pub entries: u64,
    pub bytes: u64,
    pub removed_entries: u64,
    pub removed_bytes: u64,
}

/// RocksDB-backed inbox/dispatch store for message routing.
///
/// Key formats:
/// - Inbox message: `[0x40, filter..., timestamp (8 BE), sha256(data)]`
///   -> message data. Keys written by older versions lack the hash.
/// - Hub add: `[0x41, filter..., hub_id...]` -> empty
/// - Hub delete: `[0x42, filter..., hub_id...]` -> empty
pub struct RocksInboxStore {
    db: quil_forest::CoordinatedDb,
}

impl RocksInboxStore {
    pub fn new(db: quil_forest::CoordinatedDb) -> Self {
        Self { db }
    }

    /// Store an inbox message for the given filter at the given timestamp.
    /// The key carries the hash of `data`, so a message never replaces a
    /// different one with the same filter and timestamp.
    pub fn put_inbox_message(&self, filter: &[u8], timestamp: u64, data: &[u8]) -> Result<()> {
        let mut key = inbox_message_key(filter, timestamp);
        key.extend_from_slice(&Sha256::digest(data));
        self.db
            .put(&key, data)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Visit the inbox messages of a filter within a timestamp range
    /// (inclusive on both ends) in timestamp order, until `visit` returns
    /// `false`.
    pub fn scan_inbox_messages<F>(
        &self,
        filter: &[u8],
        from_ts: u64,
        to_ts: u64,
        mut visit: F,
    ) -> Result<()>
    where
        F: FnMut(u64, &[u8]) -> bool,
    {
        if from_ts > to_ts {
            return Ok(());
        }
        let lower = inbox_message_key(filter, from_ts);
        // Upper bound is exclusive for RocksDB iterators.
        let upper = if to_ts == u64::MAX {
            let mut upper = hub_prefix(INBOX_MESSAGE_PREFIX, filter);
            increment_prefix(&mut upper);
            upper
        } else {
            inbox_message_key(filter, to_ts + 1)
        };

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower);
        read_opts.set_iterate_upper_bound(upper);

        let prefix_len = 1 + filter.len(); // prefix byte + filter
        let iter = self
            .db
            .iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        for item in iter {
            let (k, v) = item.map_err(|e| QuilError::Store(e.to_string()))?;
            let Some(ts) = key_timestamp(&k[..], prefix_len) else {
                continue;
            };
            if !visit(ts, &v[..]) {
                break;
            }
        }
        Ok(())
    }

    /// Delete every inbox message for which `keep(timestamp, data_len)`
    /// returns `false`, and measure what remains. Entries whose key does
    /// not have the inbox layout are counted but never deleted.
    pub fn prune_inbox_messages<F>(&self, mut keep: F) -> Result<InboxUsage>
    where
        F: FnMut(u64, usize) -> bool,
    {
        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(vec![INBOX_MESSAGE_PREFIX]);
        read_opts.set_iterate_upper_bound(vec![INBOX_MESSAGE_PREFIX + 1]);

        let mut usage = InboxUsage::default();
        let mut batch = rocksdb::WriteBatch::default();
        let mut pending = 0usize;
        let iter = self
            .db
            .iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        for item in iter {
            let (k, v) = item.map_err(|e| QuilError::Store(e.to_string()))?;
            let size = (k.len() + v.len()) as u64;
            let ts = match k.len() {
                LEGACY_INBOX_MESSAGE_KEY_LEN | INBOX_MESSAGE_KEY_LEN => {
                    key_timestamp(&k[..], 1 + INBOX_FILTER_LEN)
                }
                _ => None,
            };
            let remove = match ts {
                Some(ts) => !keep(ts, v.len()),
                None => false,
            };
            if !remove {
                usage.entries += 1;
                usage.bytes += size;
                continue;
            }
            batch.delete(&k[..]);
            pending += 1;
            usage.removed_entries += 1;
            usage.removed_bytes += size;
            if pending >= PRUNE_BATCH {
                self.db
                    .write(std::mem::take(&mut batch))
                    .map_err(|e| QuilError::Store(e.to_string()))?;
                pending = 0;
            }
        }
        if pending > 0 {
            self.db
                .write(batch)
                .map_err(|e| QuilError::Store(e.to_string()))?;
        }
        Ok(usage)
    }

    /// Record a hub association (add) for the given filter. Deletes
    /// any tombstone and writes the add entry in a single atomic
    /// batch (mirrors Go's `AddHubInboxAssociation`).
    pub fn put_hub_add(&self, filter: &[u8], hub_id: &[u8]) -> Result<()> {
        let key = hub_key(HUB_ADD_PREFIX, filter, hub_id);
        let del_key = hub_key(HUB_DELETE_PREFIX, filter, hub_id);
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete(&del_key);
        batch.put(&key, &[] as &[u8]);
        self.db
            .write(batch)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Record a hub disassociation (delete tombstone). Removes the
    /// add entry and writes the tombstone in a single atomic batch
    /// (mirrors Go's `DeleteHubInboxAssociation`).
    pub fn put_hub_delete(&self, filter: &[u8], hub_id: &[u8]) -> Result<()> {
        let key = hub_key(HUB_DELETE_PREFIX, filter, hub_id);
        let add_key = hub_key(HUB_ADD_PREFIX, filter, hub_id);
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete(&add_key);
        batch.put(&key, &[] as &[u8]);
        self.db
            .write(batch)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Return all active hub IDs associated with the given filter (those
    /// present in the add set and absent from the delete set).
    pub fn get_hub_associations(&self, filter: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.get_hub_associations_limited(filter, usize::MAX)
    }

    /// Return at most `max` active hub IDs associated with the given
    /// filter.
    pub fn get_hub_associations_limited(&self, filter: &[u8], max: usize) -> Result<Vec<Vec<u8>>> {
        let prefix = hub_prefix(HUB_ADD_PREFIX, filter);
        let mut upper = prefix.clone();
        // Increment last byte to form exclusive upper bound.
        increment_prefix(&mut upper);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(prefix.clone());
        read_opts.set_iterate_upper_bound(upper);

        let prefix_len = prefix.len();
        let mut results = Vec::new();

        let iter = self
            .db
            .iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        for item in iter {
            if results.len() >= max {
                break;
            }
            match item {
                Ok((k, _v)) => {
                    if k.len() > prefix_len {
                        results.push(k[prefix_len..].to_vec());
                    }
                }
                Err(e) => return Err(QuilError::Store(e.to_string())),
            }
        }
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Key builders
// ---------------------------------------------------------------------------

fn inbox_message_key(filter: &[u8], timestamp: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + filter.len() + 8 + 32);
    k.push(INBOX_MESSAGE_PREFIX);
    k.extend_from_slice(filter);
    k.extend_from_slice(&timestamp.to_be_bytes());
    k
}

/// The timestamp of an inbox key whose prefix and filter take
/// `prefix_len` bytes.
fn key_timestamp(key: &[u8], prefix_len: usize) -> Option<u64> {
    let bytes: [u8; 8] = key.get(prefix_len..prefix_len + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn hub_key(prefix: u8, filter: &[u8], hub_id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + filter.len() + hub_id.len());
    k.push(prefix);
    k.extend_from_slice(filter);
    k.extend_from_slice(hub_id);
    k
}

fn hub_prefix(prefix: u8, filter: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + filter.len());
    k.push(prefix);
    k.extend_from_slice(filter);
    k
}

/// Increment the last byte of a prefix to form an exclusive upper bound.
/// Handles carry propagation.
fn increment_prefix(prefix: &mut Vec<u8>) {
    for byte in prefix.iter_mut().rev() {
        if *byte < 0xFF {
            *byte += 1;
            return;
        }
        *byte = 0x00;
    }
    // All bytes were 0xFF — push an extra byte.
    prefix.push(0x00);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbox_message_key_format() {
        let filter = &[0x01, 0x02, 0x03];
        let key = inbox_message_key(filter, 1000);
        assert_eq!(key[0], INBOX_MESSAGE_PREFIX);
        assert_eq!(&key[1..4], filter);
        assert_eq!(&key[4..], &1000u64.to_be_bytes());
    }

    #[test]
    fn test_hub_key_format() {
        let filter = &[0xAA];
        let hub_id = &[0xBB, 0xCC];
        let key = hub_key(HUB_ADD_PREFIX, filter, hub_id);
        assert_eq!(key[0], HUB_ADD_PREFIX);
        assert_eq!(key[1], 0xAA);
        assert_eq!(&key[2..], hub_id);
    }

    #[test]
    fn test_increment_prefix() {
        let mut p = vec![0x41, 0x01, 0x02];
        increment_prefix(&mut p);
        assert_eq!(p, vec![0x41, 0x01, 0x03]);

        let mut p2 = vec![0x41, 0xFF];
        increment_prefix(&mut p2);
        assert_eq!(p2, vec![0x42, 0x00]);
    }

    fn store() -> (crate::RocksDb, RocksInboxStore) {
        let db = crate::RocksDb::open_in_memory().expect("in-memory db");
        let store = RocksInboxStore::new(db.inner());
        (db, store)
    }

    fn scan_all(store: &RocksInboxStore, filter: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut rows = Vec::new();
        store
            .scan_inbox_messages(filter, 0, u64::MAX, |ts, data| {
                rows.push((ts, data.to_vec()));
                true
            })
            .unwrap();
        rows
    }

    /// Two messages with the same filter and timestamp are both kept.
    #[test]
    fn same_timestamp_messages_are_both_kept() {
        let (_db, store) = store();
        let filter = [1u8, 2, 3];
        store.put_inbox_message(&filter, 7, b"first").unwrap();
        store.put_inbox_message(&filter, 7, b"second").unwrap();
        let rows = scan_all(&store, &filter);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|(ts, _)| *ts == 7));
    }

    /// The scan honours its range, includes `u64::MAX`, reads keys
    /// written before keys carried a hash, and stops when asked.
    #[test]
    fn scan_honours_range_legacy_keys_and_stop() {
        let (_db, store) = store();
        let filter = [9u8, 9, 9];
        for ts in [5u64, 10, 15, u64::MAX] {
            store.put_inbox_message(&filter, ts, b"m").unwrap();
        }
        store
            .db
            .put(inbox_message_key(&filter, 12), b"legacy")
            .unwrap();
        store.put_inbox_message(&[9, 9, 8], 10, b"other").unwrap();

        let all: Vec<u64> = scan_all(&store, &filter)
            .into_iter()
            .map(|(ts, _)| ts)
            .collect();
        assert_eq!(all, vec![5, 10, 12, 15, u64::MAX]);

        let mut ranged = Vec::new();
        store
            .scan_inbox_messages(&filter, 10, 12, |ts, _| {
                ranged.push(ts);
                true
            })
            .unwrap();
        assert_eq!(ranged, vec![10, 12]);

        let mut first = Vec::new();
        store
            .scan_inbox_messages(&filter, 0, u64::MAX, |ts, _| {
                first.push(ts);
                false
            })
            .unwrap();
        assert_eq!(first, vec![5]);
    }

    /// Pruning deletes what `keep` rejects, in both key layouts, and
    /// leaves hub entries alone.
    #[test]
    fn prune_removes_rejected_messages_only() {
        let (_db, store) = store();
        let filter = [4u8, 5, 6];
        store.put_inbox_message(&filter, 100, b"keep").unwrap();
        store.put_inbox_message(&filter, 1, b"expired").unwrap();
        store
            .db
            .put(inbox_message_key(&filter, 2), b"legacy expired")
            .unwrap();
        store.put_hub_add(&filter, b"hub").unwrap();

        let usage = store.prune_inbox_messages(|ts, _len| ts >= 100).unwrap();
        assert_eq!(usage.entries, 1);
        assert_eq!(usage.removed_entries, 2);
        assert_eq!(usage.bytes, (INBOX_MESSAGE_KEY_LEN + b"keep".len()) as u64);
        let rows = scan_all(&store, &filter);
        assert_eq!(rows, vec![(100, b"keep".to_vec())]);
        assert_eq!(store.get_hub_associations(&filter).unwrap().len(), 1);

        let again = store.prune_inbox_messages(|_, _| true).unwrap();
        assert_eq!(again.entries, 1);
        assert_eq!(again.removed_entries, 0);
    }

    #[test]
    fn hub_associations_are_limited() {
        let (_db, store) = store();
        let filter = [1u8, 1, 1];
        for id in 0u8..5 {
            store.put_hub_add(&filter, &[id; 4]).unwrap();
        }
        assert_eq!(store.get_hub_associations(&filter).unwrap().len(), 5);
        assert_eq!(
            store
                .get_hub_associations_limited(&filter, 3)
                .unwrap()
                .len(),
            3
        );
    }
}
