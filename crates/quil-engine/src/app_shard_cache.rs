//! LRU cache of application shard metadata.
//!
//! Provides fast lookups of shard info without hitting the backing store
//! on every request. Rebuilt from the `ShardsStore` on startup or when
//! the shard set changes.

use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;
use tracing::debug;

use quil_types::error::Result;
use quil_types::store::ShardsStore;

/// Default maximum number of shard entries in the cache.
const DEFAULT_CAPACITY: usize = 256;

/// Cached metadata for a single application shard.
#[derive(Debug, Clone)]
pub struct AppShardInfo {
    /// The shard filter / address bytes.
    pub filter: Vec<u8>,
    /// Number of provers currently allocated to this shard.
    pub prover_count: u64,
    /// Latest frame number observed for this shard.
    pub latest_frame: u64,
    /// Opaque metadata bytes (e.g. serialized shard descriptor).
    pub metadata: Vec<u8>,
}

/// An LRU cache of `AppShardInfo` keyed by shard filter bytes.
pub struct AppShardCache {
    inner: Mutex<LruCache<Vec<u8>, AppShardInfo>>,
}

impl AppShardCache {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Build a cache with the given maximum number of entries.
    pub fn with_capacity(cap: usize) -> Self {
        let cap = NonZeroUsize::new(cap).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up cached shard info by filter. Returns `None` on cache miss.
    pub fn get_shard_info(&self, filter: &[u8]) -> Option<AppShardInfo> {
        let mut cache = self.inner.lock().unwrap();
        cache.get(filter).cloned()
    }

    /// Insert or update a single shard entry.
    pub fn put_shard_info(&self, info: AppShardInfo) {
        let mut cache = self.inner.lock().unwrap();
        cache.put(info.filter.clone(), info);
    }

    /// Update the latest frame number for a shard if it is cached.
    pub fn set_latest_frame(&self, filter: &[u8], frame: u64) {
        let mut cache = self.inner.lock().unwrap();
        if let Some(entry) = cache.get_mut(filter) {
            entry.latest_frame = frame;
        }
    }

    /// Update the prover count for a shard if it is cached.
    pub fn set_prover_count(&self, filter: &[u8], count: u64) {
        let mut cache = self.inner.lock().unwrap();
        if let Some(entry) = cache.get_mut(filter) {
            entry.prover_count = count;
        }
    }

    /// Rebuild the entire cache from the backing shards store.
    /// Clears existing entries and loads all shards from the store.
    pub fn rebuild(&self, shards_store: &dyn ShardsStore) -> Result<()> {
        let shards = shards_store.range_app_shards()?;

        let mut cache = self.inner.lock().unwrap();
        cache.clear();

        for shard in &shards {
            let info = AppShardInfo {
                filter: shard.shard_key.clone(),
                prover_count: 0,
                latest_frame: 0,
                metadata: shard
                    .commitment
                    .iter()
                    .flat_map(|c| c.iter().copied())
                    .collect(),
            };
            debug!(
                filter = hex::encode(&info.filter),
                "cached shard info"
            );
            cache.put(info.filter.clone(), info);
        }

        Ok(())
    }

    /// Return the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AppShardCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_miss() {
        let cache = AppShardCache::new();
        assert!(cache.get_shard_info(&[0x01]).is_none());
    }

    #[test]
    fn test_put_and_get() {
        let cache = AppShardCache::new();
        cache.put_shard_info(AppShardInfo {
            filter: vec![0x01, 0x02],
            prover_count: 5,
            latest_frame: 100,
            metadata: vec![],
        });
        let info = cache.get_shard_info(&[0x01, 0x02]).unwrap();
        assert_eq!(info.prover_count, 5);
        assert_eq!(info.latest_frame, 100);
    }

    #[test]
    fn test_set_latest_frame() {
        let cache = AppShardCache::new();
        cache.put_shard_info(AppShardInfo {
            filter: vec![0xAA],
            prover_count: 1,
            latest_frame: 10,
            metadata: vec![],
        });
        cache.set_latest_frame(&[0xAA], 42);
        assert_eq!(cache.get_shard_info(&[0xAA]).unwrap().latest_frame, 42);
    }

    #[test]
    fn test_capacity_eviction() {
        let cache = AppShardCache::with_capacity(2);
        for i in 0u8..3 {
            cache.put_shard_info(AppShardInfo {
                filter: vec![i],
                prover_count: 0,
                latest_frame: 0,
                metadata: vec![],
            });
        }
        // First entry should be evicted.
        assert!(cache.get_shard_info(&[0]).is_none());
        assert!(cache.get_shard_info(&[1]).is_some());
        assert!(cache.get_shard_info(&[2]).is_some());
    }
}
