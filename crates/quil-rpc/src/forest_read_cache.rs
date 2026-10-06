//! Archive-side cache of forest tree nodes and leaf values served to syncing
//! peers.
//!
//! Every regular node syncs the same global prover tree, and every one of them
//! walks it from the root: the upper levels and every unchanged subtree are
//! requested over and over. A JMT node is immutable once written (its key
//! carries the version that wrote it), and a leaf value read at a committed
//! version never changes, so a hit is answered from memory without taking one
//! of the storage read slots.
//!
//! Only found entries are kept, and a value only when its version is at or
//! below the tree's head (a read above the head could change when that
//! version commits). Entries also expire, which bounds what a rebuilt tree
//! (an orphaned head dropped and recommitted from version 0) could leave
//! behind; a client authenticates every node and value against its parent
//! hash in any case, so a stale entry costs a retry against another archive,
//! never a wrong sync.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

/// Bytes of cached nodes and values.
pub const FOREST_READ_CACHE_BYTES: usize = 128 * 1024 * 1024;
/// How long an entry is served.
pub const FOREST_READ_CACHE_TTL: Duration = Duration::from_secs(15 * 60);
/// Entries larger than this are not cached.
const MAX_ENTRY_BYTES: usize = 1024 * 1024;
const SHARDS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Node,
    Value,
}

/// Which forest served an entry and in which tree generation: the same node
/// key names different content in another forest (more than one in a
/// process) or after a tree was wiped and rebuilt from version 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Origin {
    server: usize,
    generation: u64,
}

impl Origin {
    pub(crate) fn of<T: ?Sized>(server: &Arc<T>) -> Self {
        Self { server: Arc::as_ptr(server) as *const () as usize, generation: quil_forest::tree_generation() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    origin: Origin,
    kind: Kind,
    shard_id: Vec<u8>,
    phase: u32,
    key: Vec<u8>,
}

impl CacheKey {
    pub(crate) fn node(origin: Origin, shard_id: &[u8], phase: u32, node_key: &[u8]) -> Self {
        Self { origin, kind: Kind::Node, shard_id: shard_id.to_vec(), phase, key: node_key.to_vec() }
    }

    pub(crate) fn value(origin: Origin, shard_id: &[u8], phase: u32, version: u64, key_hash: &[u8; 32]) -> Self {
        let mut key = version.to_be_bytes().to_vec();
        key.extend_from_slice(key_hash);
        Self { origin, kind: Kind::Value, shard_id: shard_id.to_vec(), phase, key }
    }

    fn size(&self) -> usize {
        self.shard_id.len() + self.key.len() + 64
    }

    fn shard(&self) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        (hasher.finish() as usize) % SHARDS
    }
}

struct Entry {
    data: Arc<Vec<u8>>,
    stored: Instant,
}

struct Shard {
    entries: lru::LruCache<CacheKey, Entry>,
    bytes: usize,
}

/// Counters since start.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ForestReadCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub bytes: u64,
    pub entries: u64,
}

pub(crate) struct ForestReadCache {
    shards: Vec<parking_lot::Mutex<Shard>>,
    budget_per_shard: usize,
    ttl: Duration,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl ForestReadCache {
    pub(crate) fn new(budget: usize, ttl: Duration) -> Self {
        Self {
            shards: (0..SHARDS)
                .map(|_| parking_lot::Mutex::new(Shard { entries: lru::LruCache::unbounded(), bytes: 0 }))
                .collect(),
            budget_per_shard: budget / SHARDS,
            ttl,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// The process-wide cache shared by every peer-facing server.
    pub(crate) fn process() -> &'static Self {
        static CACHE: LazyLock<ForestReadCache> =
            LazyLock::new(|| ForestReadCache::new(FOREST_READ_CACHE_BYTES, FOREST_READ_CACHE_TTL));
        &CACHE
    }

    pub(crate) fn get(&self, key: &CacheKey) -> Option<Arc<Vec<u8>>> {
        let mut shard = self.shards[key.shard()].lock();
        let found = match shard.entries.get(key) {
            Some(entry) if entry.stored.elapsed() < self.ttl => Some(entry.data.clone()),
            Some(_) => {
                if let Some(entry) = shard.entries.pop(key) {
                    shard.bytes = shard.bytes.saturating_sub(key.size() + entry.data.len());
                }
                None
            }
            None => None,
        };
        let counter = if found.is_some() { &self.hits } else { &self.misses };
        counter.fetch_add(1, Ordering::Relaxed);
        found
    }

    pub(crate) fn put(&self, key: CacheKey, data: Vec<u8>) {
        let size = key.size() + data.len();
        if data.len() > MAX_ENTRY_BYTES || size > self.budget_per_shard {
            return;
        }
        let mut shard = self.shards[key.shard()].lock();
        let entry = Entry { data: Arc::new(data), stored: Instant::now() };
        if let Some(old) = shard.entries.put(key.clone(), entry) {
            shard.bytes = shard.bytes.saturating_sub(key.size() + old.data.len());
        }
        shard.bytes += size;
        while shard.bytes > self.budget_per_shard {
            let Some((evicted, entry)) = shard.entries.pop_lru() else { break };
            shard.bytes = shard.bytes.saturating_sub(evicted.size() + entry.data.len());
        }
    }

    pub(crate) fn stats(&self) -> ForestReadCacheStats {
        let (mut bytes, mut entries) = (0u64, 0u64);
        for shard in &self.shards {
            let shard = shard.lock();
            bytes += shard.bytes as u64;
            entries += shard.entries.len() as u64;
        }
        ForestReadCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            bytes,
            entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_served_until_evicted_or_expired() {
        let cache = ForestReadCache::new(SHARDS * 4096, Duration::from_secs(60));
        let origin = Origin { server: 1, generation: 0 };
        let key = CacheKey::node(origin, &[0xff; 32], 0, b"node key");
        assert!(cache.get(&key).is_none());
        cache.put(key.clone(), vec![7; 100]);
        assert_eq!(cache.get(&key).as_deref(), Some(&vec![7; 100]));
        let value = CacheKey::value(origin, &[0xff; 32], 0, 9, &[1; 32]);
        assert_ne!(value, CacheKey::value(origin, &[0xff; 32], 0, 10, &[1; 32]), "a value is keyed by its version");
        assert_ne!(value, CacheKey::node(origin, &[0xff; 32], 0, &value.key));
        let other_forest = Origin { server: 2, generation: 0 };
        assert!(cache.get(&CacheKey::node(other_forest, &[0xff; 32], 0, b"node key")).is_none(),
            "another forest's node under the same key");
        let rebuilt = Origin { server: 1, generation: 1 };
        assert!(cache.get(&CacheKey::node(rebuilt, &[0xff; 32], 0, b"node key")).is_none(),
            "a node cached before the tree was wiped and rebuilt");

        // The byte budget evicts least recently used entries.
        for i in 0..2000u32 {
            cache.put(CacheKey::node(origin, &[0xff; 32], 0, &i.to_be_bytes()), vec![0; 100]);
        }
        let stats = cache.stats();
        assert!(stats.bytes <= (SHARDS * 4096) as u64, "{stats:?}");
        assert!(stats.entries < 2000);

        // Too large to keep.
        let big = CacheKey::node(origin, &[0xff; 32], 0, b"big");
        cache.put(big.clone(), vec![0; MAX_ENTRY_BYTES + 1]);
        assert!(cache.get(&big).is_none());

        // Expired entries are misses.
        let short = ForestReadCache::new(SHARDS * 4096, Duration::ZERO);
        short.put(key.clone(), vec![1]);
        assert!(short.get(&key).is_none());
        assert_eq!(short.stats().entries, 0);
    }
}
