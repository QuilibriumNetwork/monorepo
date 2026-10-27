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

/// Records beside the replicas, keyed `[STORAGE_REPLICA][0xFF][kind][epoch BE][id]`:
/// a replica key's epoch never has `0xFF` as its top byte, so neither keyspace
/// reaches into the other.
const META: u8 = 0xFF;
/// A member's leaf partition of one shard at an epoch's snapshot, by filter.
const PARTITION: u8 = 0x01;
/// A member's snapshot sources of one shard for an epoch, by filter: what it
/// read its registration's data from, to read it again for the seal.
const SNAPSHOT_SOURCES: u8 = 0x03;
/// The node count of each leaf of a member's partition, by filter: what its
/// replicas take in memory, known before they are read.
const LEAF_NODES: u8 = 0x04;

fn meta_key(kind: u8, epoch: u64, id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(11 + id.len());
    k.extend_from_slice(&[STORAGE_REPLICA, META, kind]);
    k.extend_from_slice(&epoch.to_be_bytes());
    k.extend_from_slice(id);
    k
}

/// Leads a hash-proof epoch's stored leaf ([`ReplicaStore::put_hash`]).
const HASH_REPLICA_TAG: u8 = 0xA5;

/// A hash-proof epoch's stored leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashReplica {
    pub replica: Vec<u8>,
    pub cap: Vec<u8>,
    pub registration_root: Vec<u8>,
}

impl HashReplica {
    fn decode(value: &[u8]) -> Option<Self> {
        let (&tag, rest) = value.split_first()?;
        if tag != HASH_REPLICA_TAG {
            return None;
        }
        let take = |bytes: &[u8]| -> Option<(Vec<u8>, usize)> {
            let len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
            Some((bytes.get(4..4 + len)?.to_vec(), 4 + len))
        };
        let (cap, used) = take(rest)?;
        let (registration_root, used2) = take(&rest[used..])?;
        Some(Self {
            cap,
            registration_root,
            replica: rest[used + used2..].to_vec(),
        })
    }
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

    /// Persist a hash-proof epoch's leaf: the replica with the Merkle cap that,
    /// with it, opens any node (`quil_crypto::storage_proof::MerkleCap`), and
    /// the registration root it was registered with.
    pub fn put_hash(
        &self,
        epoch: u64,
        leaf_id: &[u8],
        replica: &[u8],
        cap: &[u8],
        registration_root: &[u8],
    ) -> Result<()> {
        let mut value = Vec::with_capacity(9 + cap.len() + registration_root.len() + replica.len());
        value.push(HASH_REPLICA_TAG);
        value.extend_from_slice(&(cap.len() as u32).to_be_bytes());
        value.extend_from_slice(cap);
        value.extend_from_slice(&(registration_root.len() as u32).to_be_bytes());
        value.extend_from_slice(registration_root);
        value.extend_from_slice(replica);
        self.db.set(&replica_key(epoch, leaf_id), &value)
    }

    /// A hash-proof epoch's leaf as [`Self::put_hash`] stored it, or `None`
    /// (also for a replica stored without its cap).
    pub fn get_hash(&self, epoch: u64, leaf_id: &[u8]) -> Result<Option<HashReplica>> {
        Ok(self
            .db
            .get(&replica_key(epoch, leaf_id))?
            .and_then(|value| HashReplica::decode(&value)))
    }

    /// Record the leaf prefixes of shard `filter` as snapshotted for `epoch`'s
    /// registrations; their replicas are stored under the same epoch.
    pub fn put_partition(&self, epoch: u64, filter: &[u8], prefixes: &[Vec<u32>]) -> Result<()> {
        let mut value = Vec::new();
        value.extend_from_slice(&(prefixes.len() as u32).to_be_bytes());
        for prefix in prefixes {
            value.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
            for nibble in prefix {
                value.extend_from_slice(&nibble.to_be_bytes());
            }
        }
        self.db.set(&meta_key(PARTITION, epoch, filter), &value)
    }

    /// The leaf prefixes [`Self::put_partition`] recorded, or `None`.
    pub fn get_partition(&self, epoch: u64, filter: &[u8]) -> Result<Option<Vec<Vec<u32>>>> {
        let Some(value) = self.db.get(&meta_key(PARTITION, epoch, filter))? else {
            return Ok(None);
        };
        let mut words = value
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        let count = words.next().unwrap_or(0);
        let mut prefixes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let Some(len) = words.next() else {
                return Ok(None);
            };
            let prefix: Vec<u32> = words.by_ref().take(len as usize).collect();
            if prefix.len() != len as usize {
                return Ok(None);
            }
            prefixes.push(prefix);
        }
        Ok(Some(prefixes))
    }

    /// Record the snapshot sources (encoded) shard `filter`'s leaves for
    /// `epoch` were read from.
    pub fn put_snapshot_sources(&self, epoch: u64, filter: &[u8], sources: &[u8]) -> Result<()> {
        self.db
            .set(&meta_key(SNAPSHOT_SOURCES, epoch, filter), sources)
    }

    /// What [`Self::put_snapshot_sources`] recorded, or `None`.
    pub fn get_snapshot_sources(&self, epoch: u64, filter: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(&meta_key(SNAPSHOT_SOURCES, epoch, filter))
    }

    /// Record the node count of each leaf of shard `filter`'s partition for
    /// `epoch`, in the partition's order.
    pub fn put_leaf_nodes(&self, epoch: u64, filter: &[u8], nodes: &[u64]) -> Result<()> {
        let value: Vec<u8> = nodes.iter().flat_map(|n| n.to_be_bytes()).collect();
        self.db.set(&meta_key(LEAF_NODES, epoch, filter), &value)
    }

    /// What [`Self::put_leaf_nodes`] recorded, or `None` (also for a partition
    /// stored before the counts were).
    pub fn get_leaf_nodes(&self, epoch: u64, filter: &[u8]) -> Result<Option<Vec<u64>>> {
        Ok(self
            .db
            .get(&meta_key(LEAF_NODES, epoch, filter))?
            .filter(|value| value.len() % 8 == 0)
            .map(|value| {
                value
                    .chunks_exact(8)
                    .map(|n| u64::from_be_bytes(n.try_into().expect("8 bytes")))
                    .collect()
            }))
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
        self.db.delete_range(&lo, &hi)?;
        for kind in [PARTITION, SNAPSHOT_SOURCES, LEAF_NODES] {
            self.db
                .delete_range(&meta_key(kind, 0, &[]), &meta_key(kind, keep_from, &[]))?;
        }
        Ok(())
    }

    /// Iterate `(leaf_id, replica)` for every leaf stored under `epoch`. Used by
    /// the per-frame producer to answer challenges for the active epoch.
    pub fn for_each_in_epoch(&self, epoch: u64, mut f: impl FnMut(Vec<u8>, Vec<u8>)) -> Result<()> {
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
        assert_eq!(
            s.get(3, leaf).unwrap().as_deref(),
            Some(&b"replica-bytes"[..])
        );
        s.delete(3, leaf).unwrap();
        assert_eq!(s.get(3, leaf).unwrap(), None);
    }

    #[test]
    fn a_hash_replica_round_trips_and_a_plain_one_is_not_read_as_one() {
        let s = store();
        s.put_hash(5, b"leaf", b"replica", b"cap-bytes", &[7u8; 96])
            .unwrap();
        assert_eq!(
            s.get_hash(5, b"leaf").unwrap(),
            Some(HashReplica {
                replica: b"replica".to_vec(),
                cap: b"cap-bytes".to_vec(),
                registration_root: vec![7u8; 96],
            })
        );
        s.put(6, b"leaf", b"plain").unwrap();
        assert_eq!(s.get_hash(6, b"leaf").unwrap(), None);
        s.evict_below_epoch(6).unwrap();
        assert_eq!(s.get_hash(5, b"leaf").unwrap(), None);
    }

    #[test]
    fn partitions_and_snapshot_sources_round_trip_and_evict_by_epoch() {
        let s = store();
        let prefixes = vec![vec![], vec![3, 1], vec![63]];
        s.put_partition(5, b"filter", &prefixes).unwrap();
        s.put_snapshot_sources(5, b"filter", b"sources").unwrap();
        assert_eq!(s.get_leaf_nodes(5, b"filter").unwrap(), None);
        s.put_leaf_nodes(5, b"filter", &[2, 1 << 30, 7]).unwrap();
        s.put(5, b"filter", b"replica").unwrap();
        assert_eq!(s.get_partition(5, b"filter").unwrap(), Some(prefixes));
        assert_eq!(
            s.get_leaf_nodes(5, b"filter").unwrap(),
            Some(vec![2, 1 << 30, 7])
        );
        assert_eq!(
            s.get_snapshot_sources(5, b"filter").unwrap().as_deref(),
            Some(&b"sources"[..])
        );
        assert_eq!(
            s.get(5, b"filter").unwrap().as_deref(),
            Some(&b"replica"[..]),
            "beside, not over, the replica"
        );
        assert_eq!(s.get_partition(6, b"filter").unwrap(), None);
        s.evict_below_epoch(6).unwrap();
        assert_eq!(s.get_partition(5, b"filter").unwrap(), None);
        assert_eq!(s.get_snapshot_sources(5, b"filter").unwrap(), None);
        assert_eq!(s.get_leaf_nodes(5, b"filter").unwrap(), None);
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
