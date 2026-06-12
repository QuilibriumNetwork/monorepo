use std::sync::Arc;

use quil_types::error::{QuilError, Result};

/// Inbox message prefix byte.
const INBOX_MESSAGE_PREFIX: u8 = 0x40;
/// Hub association add prefix byte.
const HUB_ADD_PREFIX: u8 = 0x41;
/// Hub association delete prefix byte (tombstone).
const HUB_DELETE_PREFIX: u8 = 0x42;

/// RocksDB-backed inbox/dispatch store for message routing.
///
/// Key formats:
/// - Inbox message: `[0x40, filter..., timestamp (8 BE)]` -> message data
/// - Hub add:       `[0x41, filter..., hub_id...]` -> empty
/// - Hub delete:    `[0x42, filter..., hub_id...]` -> empty
pub struct RocksInboxStore {
    db: Arc<rocksdb::DB>,
}

impl RocksInboxStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }

    /// Store an inbox message for the given filter at the given timestamp.
    pub fn put_inbox_message(
        &self,
        filter: &[u8],
        timestamp: u64,
        data: &[u8],
    ) -> Result<()> {
        let key = inbox_message_key(filter, timestamp);
        self.db
            .put(&key, data)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    /// Retrieve all inbox messages for a filter within a timestamp range
    /// (inclusive on both ends).
    pub fn get_inbox_messages(
        &self,
        filter: &[u8],
        from_ts: u64,
        to_ts: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let lower = inbox_message_key(filter, from_ts);
        // Upper bound is exclusive for RocksDB iterators, so use to_ts + 1.
        let upper = inbox_message_key(filter, to_ts.saturating_add(1));

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower.clone());
        read_opts.set_iterate_upper_bound(upper);

        let prefix_len = 1 + filter.len(); // prefix byte + filter
        let mut results = Vec::new();

        let iter = self.db.iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        for item in iter {
            match item {
                Ok((k, v)) => {
                    if k.len() < prefix_len + 8 {
                        continue;
                    }
                    let ts_bytes: [u8; 8] = k[prefix_len..prefix_len + 8]
                        .try_into()
                        .map_err(|_| QuilError::Store("corrupt inbox key".into()))?;
                    let ts = u64::from_be_bytes(ts_bytes);
                    results.push((ts, v.to_vec()));
                }
                Err(e) => return Err(QuilError::Store(e.to_string())),
            }
        }
        Ok(results)
    }

    /// Record a hub association (add) for the given filter. Deletes
    /// any tombstone and writes the add entry in a single atomic
    /// batch (mirrors Go's `AddHubInboxAssociation`).
    pub fn put_hub_add(
        &self,
        filter: &[u8],
        hub_id: &[u8],
    ) -> Result<()> {
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
    pub fn put_hub_delete(
        &self,
        filter: &[u8],
        hub_id: &[u8],
    ) -> Result<()> {
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
        let prefix = hub_prefix(HUB_ADD_PREFIX, filter);
        let mut upper = prefix.clone();
        // Increment last byte to form exclusive upper bound.
        increment_prefix(&mut upper);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(prefix.clone());
        read_opts.set_iterate_upper_bound(upper);

        let prefix_len = prefix.len();
        let mut results = Vec::new();

        let iter = self.db.iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        for item in iter {
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
    let mut k = Vec::with_capacity(1 + filter.len() + 8);
    k.push(INBOX_MESSAGE_PREFIX);
    k.extend_from_slice(filter);
    k.extend_from_slice(&timestamp.to_be_bytes());
    k
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
}
