//! What this process's node stores wrote to disk, by class of store: the
//! master's, and every worker's summed. Each class shares one RocksDB
//! statistics object ([`StoreClass::options`]), so its counts run over the
//! process's life, however often its stores close and reopen.
//!
//! Cost: statistics read no clock at the level set (rust-rocksdb 0.22's
//! `ExceptHistogramOrTimers` is RocksDB's `kExceptTimers`, value 2): a
//! counted event adds to a per-core counter, and a read or write also adds
//! its size to a per-core histogram. Each object holds a slot per CPU (at
//! least 8, a power of two) of about 60 KB, for RocksDB's 215 tickers and
//! 60 histograms: about 1 MB per class on 16 CPUs, two classes a process.
//! Stats history in memory is off; each store's RocksDB LOG gains the
//! counters at its stats dump (every 10 minutes, about 16 KB).

use std::sync::OnceLock;

use rocksdb::statistics::{StatsLevel, Ticker};

/// A class of this node's stores whose disk writes are counted together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreClass {
    /// The master's store.
    Master,
    /// Every data worker's own store, the storage replicas in them included.
    Workers,
}

impl StoreClass {
    fn statistics(self) -> &'static OnceLock<rocksdb::Options> {
        static MASTER: OnceLock<rocksdb::Options> = OnceLock::new();
        static WORKERS: OnceLock<rocksdb::Options> = OnceLock::new();
        match self {
            StoreClass::Master => &MASTER,
            StoreClass::Workers => &WORKERS,
        }
    }

    /// Default options carrying this class's statistics: a copy of the
    /// class's options shares their statistics object.
    pub(crate) fn options(self) -> rocksdb::Options {
        self.statistics()
            .get_or_init(|| {
                let mut opts = rocksdb::Options::default();
                opts.enable_statistics();
                opts.set_statistics_level(StatsLevel::ExceptHistogramOrTimers);
                // No counter snapshots kept in memory (up to 1 MB a store).
                opts.set_stats_persist_period_sec(0);
                opts
            })
            .clone()
    }

    /// What this class's stores wrote since the process opened the first.
    pub fn written(self) -> StoreWrites {
        self.statistics()
            .get()
            .map_or_else(StoreWrites::default, |opts| StoreWrites {
                wal: opts.get_ticker_count(Ticker::WalFileBytes),
                flush: opts.get_ticker_count(Ticker::FlushWriteBytes),
                compaction: opts.get_ticker_count(Ticker::CompactWriteBytes),
            })
    }
}

/// Bytes a class of stores wrote to disk, by RocksDB's way of writing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreWrites {
    /// To the write-ahead log, as each write commits.
    pub wal: u64,
    /// To table files, as memtables flush.
    pub flush: u64,
    /// To table files, as compactions rewrite them.
    pub compaction: u64,
}

impl StoreWrites {
    /// What was written between `earlier` and `self`.
    pub fn since(self, earlier: StoreWrites) -> StoreWrites {
        StoreWrites {
            wal: self.wal.saturating_sub(earlier.wal),
            flush: self.flush.saturating_sub(earlier.flush),
            compaction: self.compaction.saturating_sub(earlier.compaction),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RocksDb;
    use quil_types::store::KvDb as _;

    /// Put `keys` values of 64 KiB, then flush them to a table file.
    fn put_and_flush(db: &RocksDb, keys: u32, byte: u8) {
        let value = vec![byte; 64 * 1024];
        for key in 0..keys {
            db.set(&key.to_be_bytes(), &value).unwrap();
        }
        db.inner().flush().unwrap();
    }

    /// A counted store's writes reach its class's counts: its WAL as each
    /// write commits, its table files as they flush and compact. The other
    /// class's counts do not move.
    #[test]
    fn a_counted_store_adds_its_writes_to_its_class() {
        let dir = tempfile::tempdir().unwrap();
        let before = (StoreClass::Workers.written(), StoreClass::Master.written());
        let db = RocksDb::open_counted(dir.path(), StoreClass::Workers).unwrap();
        put_and_flush(&db, 64, 1);
        let wrote = StoreClass::Workers.written().since(before.0);
        assert!(wrote.wal >= 64 * 64 * 1024, "wal_uncounted: {wrote:?}");
        assert!(wrote.flush > 0, "flush_uncounted: {wrote:?}");
        // Overlapping table files: compaction merges them, never moves one.
        put_and_flush(&db, 64, 2);
        db.inner().compact_range::<&[u8], &[u8]>(None, None);
        let wrote = StoreClass::Workers.written().since(before.0);
        assert!(wrote.compaction > 0, "compaction_uncounted: {wrote:?}");
        assert_eq!(StoreClass::Master.written(), before.1, "other_class_moved");
    }

    /// A store reopened adds to the counts it left: they belong to its
    /// class, not to the store.
    #[test]
    fn counts_outlive_a_closed_store() {
        let dir = tempfile::tempdir().unwrap();
        let before = StoreClass::Master.written();
        let db = RocksDb::open_counted(dir.path(), StoreClass::Master).unwrap();
        db.set(b"a", &[1u8; 4096]).unwrap();
        drop(db);
        let closed = StoreClass::Master.written().since(before);
        assert!(closed.wal >= 4096, "closed_store_uncounted: {closed:?}");
        let db = RocksDb::open_counted(dir.path(), StoreClass::Master).unwrap();
        db.set(b"b", &[2u8; 4096]).unwrap();
        let reopened = StoreClass::Master.written().since(before);
        assert!(
            reopened.wal >= closed.wal + 4096,
            "reopened_store_restarted: {reopened:?} after {closed:?}"
        );
    }
}
