//! Bounded removal of the stored frames of application shards a node no
//! longer serves. A regular master keeps a copy of every frame of every shard
//! its workers ever served, and nothing deleted them outside repair ranges.
//! The pass writes only through a [`quil_forest::DisjointBatch`] confined to
//! the shard-frame keys, so it never invalidates an in-flight atomic execution
//! plan, and it has a dry run that measures what it would delete.
use prost::Message;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global;

use super::RocksClockStore;
use crate::encoding;

/// One pruned shard of a [`RocksClockStore::prune_unserved_shard_frames`]
/// call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunedShard {
    pub filter: Vec<u8>,
    /// Frames below this one, the shard's latest, were deleted; it stays.
    pub below: u64,
    pub frames: u64,
    pub bytes: u64,
}

/// Why a call of [`RocksClockStore::prune_unserved_shard_frames`] deleted
/// no frame of a shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeptShard {
    /// The caller serves it.
    Served,
    /// Its latest frame is within the idle bound.
    Recent,
    /// The index or the latest frame does not decode, or the index moved
    /// while the shard was scanned.
    Unreadable,
    /// Unserved and idle, but no frame below its latest is left.
    LatestOnly,
}

/// One call of [`RocksClockStore::prune_unserved_shard_frames`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnservedFramePrune {
    /// Shards with a latest-frame index examined.
    pub shards: u64,
    /// Shards examined whose frames all stay, and why. A shard the call
    /// stopped in before reaching any of its frames is in neither list.
    pub kept: Vec<(Vec<u8>, KeptShard)>,
    /// Frame keys examined.
    pub examined: u64,
    /// Shards whose old frames were deleted (or, in a dry run, deletable).
    pub pruned: Vec<PrunedShard>,
    /// Resume at this canonical frame key; `None` once every shard is done.
    pub next: Option<Vec<u8>>,
}

impl UnservedFramePrune {
    pub fn frames(&self) -> u64 {
        self.pruned.iter().map(|p| p.frames).sum()
    }

    pub fn bytes(&self) -> u64 {
        self.pruned.iter().map(|p| p.bytes).sum()
    }

    /// Shards kept for `why`.
    pub fn kept(&self, why: KeptShard) -> u64 {
        self.kept.iter().filter(|(_, kept)| *kept == why).count() as u64
    }
}

fn store(error: impl std::fmt::Display) -> QuilError {
    QuilError::Store(error.to_string())
}

/// The latest-frame index: one key per shard filter holding a frame.
const LATEST_PREFIX: [u8; 2] = [
    encoding::CLOCK_FRAME,
    encoding::INDEX_LATEST | encoding::CLOCK_SHARD_FRAME,
];
const FRAME_PREFIX: [u8; 2] = [encoding::CLOCK_FRAME, encoding::CLOCK_SHARD_FRAME];

/// `(filter, frame number)` of a canonical frame key.
fn split_frame_key(key: &[u8]) -> Option<(&[u8], u64)> {
    let at = key.len().checked_sub(8)?;
    if at <= FRAME_PREFIX.len() || !key.starts_with(&FRAME_PREFIX) {
        return None;
    }
    Some((
        &key[FRAME_PREFIX.len()..at],
        u64::from_be_bytes(key[at..].try_into().ok()?),
    ))
}

/// The first frame number of `filter` whose canonical key sorts after
/// `key`, a key of the shard's frame range that is not one of its frames
/// (a longer filter's); `None` when no frame number does.
fn frame_after(filter: &[u8], key: &[u8]) -> Option<u64> {
    let tail = key.get(FRAME_PREFIX.len() + filter.len()..)?;
    let mut number = [0u8; 8];
    let len = tail.len().min(8);
    number[..len].copy_from_slice(&tail[..len]);
    let number = u64::from_be_bytes(number);
    // A tail of 8 bytes or more starts with a frame number whose key is its
    // prefix and sorts first; a shorter one sorts before its zero padding.
    if tail.len() >= 8 {
        number.checked_add(1)
    } else {
        Some(number)
    }
}

impl RocksClockStore {
    /// A pass compacts a shard's deleted frames once it removed at least this
    /// many bytes of them. An unserved shard's frames sit in bottommost files,
    /// which RocksDB rewrites only when newer data reaches them, so their
    /// space would stay taken. Below it the tombstones are left to RocksDB.
    pub const SHARD_FRAME_RECLAIM_BYTES: u64 = 64 << 20;

    /// Delete the canonical frames of shards the caller does not serve and
    /// whose latest frame's timestamp (milliseconds) is below
    /// `idle_before_ms`, keeping each shard's latest frame and its index.
    /// `served` is asked for each shard before it is scanned and again before
    /// its deletion is written; a shard whose latest index moves meanwhile is
    /// kept. Nothing else is touched: staged frames, fee, settlement,
    /// accumulator and spend records, certified states and every GLOBAL
    /// record stay. Frame keys are deleted one by one, never by range, so a
    /// shard whose filter extends another's keeps its frames.
    ///
    /// At most `max_frames` frame keys are examined, starting at the
    /// canonical frame key `resume` (or the first shard); pass the returned
    /// `next` to continue. Only a store no engine executes or serves shard
    /// history from may be pruned: a regular master's copy.
    pub fn prune_unserved_shard_frames(
        &self,
        served: &dyn Fn(&[u8]) -> bool,
        idle_before_ms: i64,
        resume: Option<&[u8]>,
        max_frames: usize,
        dry_run: bool,
    ) -> Result<UnservedFramePrune> {
        let mut result = UnservedFramePrune::default();
        let resume = resume.and_then(split_frame_key);
        let mut shards = self.db.raw_iterator();
        match resume {
            Some((filter, _)) => shards.seek(encoding::clock_shard_latest_index(filter)),
            None => shards.seek(LATEST_PREFIX),
        }
        while let (Some(key), Some(value)) = (shards.key(), shards.value()) {
            if !key.starts_with(&LATEST_PREFIX) {
                break;
            }
            let filter = key[LATEST_PREFIX.len()..].to_vec();
            let head = <[u8; 8]>::try_from(value).ok().map(u64::from_be_bytes);
            shards.next();
            let from = match resume {
                Some((at, frame)) if at == filter.as_slice() => frame,
                _ => 0,
            };
            result.shards += 1;
            if served(&filter) {
                result.kept.push((filter, KeptShard::Served));
                continue;
            }
            let Some(head) = head else {
                result.kept.push((filter, KeptShard::Unreadable));
                continue;
            };
            match self.latest_frame_timestamp(&filter, head)? {
                None => {
                    result.kept.push((filter, KeptShard::Unreadable));
                    continue;
                }
                Some(timestamp) if timestamp >= idle_before_ms => {
                    result.kept.push((filter, KeptShard::Recent));
                    continue;
                }
                Some(_) => {}
            }
            let budget = max_frames.saturating_sub(result.examined as usize);
            let scan = self.old_frames(&filter, from, head, budget)?;
            result.examined += scan.examined;
            if !scan.keys.is_empty() {
                // The shard may have been taken up while it was scanned.
                let index = encoding::clock_shard_latest_index(&filter);
                if self.read_u64_index_checked(&index)? != Some(head) {
                    result.kept.push((filter.clone(), KeptShard::Unreadable));
                } else if served(&filter) {
                    result.kept.push((filter.clone(), KeptShard::Served));
                } else {
                    if !dry_run {
                        let mut batch =
                            quil_forest::DisjointBatch::new(encoding::CLOCK_SHARD_SERVING_PREFIXES);
                        for key in &scan.keys {
                            batch.delete(key).map_err(store)?;
                        }
                        self.db
                            .write_disjoint(batch, &rocksdb::WriteOptions::default())
                            .map_err(store)?;
                    }
                    result.pruned.push(PrunedShard {
                        filter: filter.clone(),
                        below: head,
                        frames: scan.keys.len() as u64,
                        bytes: scan.bytes,
                    });
                }
            } else if scan.stopped.is_none() {
                result.kept.push((filter.clone(), KeptShard::LatestOnly));
            }
            if scan.stopped.is_some() {
                result.next = scan.stopped;
                break;
            }
        }
        shards.status().map_err(store)?;
        Ok(result)
    }

    /// Compact the frame keys of `filter` below `below`, which a prune pass
    /// deleted, down to the bottommost level.
    pub fn compact_pruned_shard_frames(&self, filter: &[u8], below: u64) {
        let start = encoding::clock_shard_frame_key(filter, 0);
        let end = encoding::clock_shard_frame_key(filter, below);
        let mut options = rocksdb::CompactOptions::default();
        options.set_bottommost_level_compaction(rocksdb::BottommostLevelCompaction::ForceOptimized);
        self.db
            .compact_range_opt(Some(&start), Some(&end), &options);
    }

    /// The timestamp of shard `filter`'s frame `head`; `None` when it is
    /// missing or is not that frame.
    fn latest_frame_timestamp(&self, filter: &[u8], head: u64) -> Result<Option<i64>> {
        let Some(bytes) = self
            .db
            .get(encoding::clock_shard_frame_key(filter, head))
            .map_err(store)?
        else {
            return Ok(None);
        };
        Ok(global::AppShardFrame::decode(bytes.as_slice())
            .ok()
            .and_then(|frame| frame.header)
            .filter(|header| header.frame_number == head && header.address == filter)
            .map(|header| header.timestamp))
    }

    /// The canonical frame keys of exactly `filter` in `[from, below)`,
    /// examining at most `budget` keys of the range.
    fn old_frames(&self, filter: &[u8], from: u64, below: u64, budget: usize) -> Result<FrameScan> {
        let mut scan = FrameScan::default();
        if from >= below {
            return Ok(scan);
        }
        let end = encoding::clock_shard_frame_key(filter, below);
        let mut it = self.db.raw_iterator();
        it.seek(encoding::clock_shard_frame_key(filter, from));
        while let (Some(key), Some(value)) = (it.key(), it.value()) {
            if key >= end.as_slice() {
                break;
            }
            if scan.examined as usize >= budget {
                // Resume with this shard: at this key's frame, or, at a
                // longer filter's key sorting inside the range, at the first
                // frame of this shard sorting after it, so a call that
                // examined only such keys still moves on.
                let at = match split_frame_key(key) {
                    Some((owner, n)) if owner == filter => Some(n),
                    _ => frame_after(filter, key),
                };
                scan.stopped = at.map(|at| encoding::clock_shard_frame_key(filter, at));
                break;
            }
            scan.examined += 1;
            if let Some((owner, _)) = split_frame_key(key) {
                if owner == filter {
                    scan.bytes += (key.len() + value.len()) as u64;
                    scan.keys.push(key.to_vec());
                }
            }
            it.next();
        }
        it.status().map_err(store)?;
        Ok(scan)
    }
}

#[derive(Default)]
struct FrameScan {
    examined: u64,
    keys: Vec<Vec<u8>>,
    bytes: u64,
    /// Where the next call resumes, when the budget ran out.
    stopped: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::store::ClockStore;
    use std::cell::Cell;

    fn open(dir: &std::path::Path) -> RocksClockStore {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        RocksClockStore::new(quil_forest::CoordinatedDb::new(
            rocksdb::DB::open(&opts, dir).unwrap(),
        ))
    }

    /// `len` bytes that do not compress.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// Frames `1..=head` of `filter`, frame `n` stamped `stamp + n`.
    fn serve(s: &RocksClockStore, filter: &[u8], head: u64, stamp: i64, body: usize) {
        for n in 1..=head {
            let frame = global::AppShardFrame {
                header: Some(global::FrameHeader {
                    address: filter.to_vec(),
                    frame_number: n,
                    timestamp: stamp + n as i64,
                    output: noise(n, body),
                    ..Default::default()
                }),
                ..Default::default()
            };
            s.store_shard_clock_frame_for_serving(&[n as u8; 32], &frame)
                .unwrap();
        }
    }

    /// Frame numbers stored under exactly `filter`.
    fn stored(s: &RocksClockStore, filter: &[u8]) -> Vec<u64> {
        let start = encoding::clock_shard_frame_key(filter, 0);
        s.db.iterator(rocksdb::IteratorMode::From(
            &start,
            rocksdb::Direction::Forward,
        ))
        .map(|e| e.unwrap().0)
        .take_while(|k| k.starts_with(&FRAME_PREFIX))
        .filter_map(|k| {
            split_frame_key(&k)
                .filter(|(owner, _)| *owner == filter)
                .map(|(_, n)| n)
        })
        .collect()
    }

    const OLD: i64 = 1_000;
    const BOUND: i64 = 100_000;
    const NEW: i64 = 200_000;

    /// An unserved shard idle past the bound keeps only its latest frame;
    /// a served shard, a recently left one and a served shard whose filter
    /// extends the pruned one (its keys sort inside the pruned range) keep
    /// every frame, and so do the pruned shard's other records.
    #[test]
    fn only_idle_unserved_shards_lose_their_old_frames() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(dir.path());
        let left = vec![0x11; 35];
        let mut longer = left.clone();
        longer.push(0x00);
        let served = vec![0x22; 35];
        let recent = vec![0x33; 35];
        serve(&s, &left, 40, OLD, 8);
        serve(&s, &longer, 40, OLD, 8);
        serve(&s, &served, 40, OLD, 8);
        serve(&s, &recent, 40, NEW, 8);
        s.put_shard_frame_fee_total(&left, 3, 77).unwrap();
        let staged = global::AppShardFrame {
            header: Some(global::FrameHeader {
                address: left.clone(),
                frame_number: 41,
                ..Default::default()
            }),
            ..Default::default()
        };
        let txn = s.new_transaction(false).unwrap();
        s.stage_shard_clock_frame(&[0x41; 32], &staged, txn.as_ref())
            .unwrap();
        txn.commit().unwrap();
        let is_served = |f: &[u8]| f == served.as_slice() || f == longer.as_slice();

        let pass = s
            .prune_unserved_shard_frames(&is_served, BOUND, None, usize::MAX, false)
            .unwrap();

        assert_eq!(
            stored(&s, &left),
            vec![40],
            "an unserved idle shard keeps only its latest frame"
        );
        assert_eq!(
            s.get_latest_shard_clock_frame(&left)
                .unwrap()
                .header
                .unwrap()
                .frame_number,
            40,
            "the latest frame and its index stay"
        );
        let all: Vec<u64> = (1..=40).collect();
        assert_eq!(stored(&s, &served), all, "a served shard keeps every frame");
        assert_eq!(
            stored(&s, &recent),
            all,
            "a recently left shard keeps every frame"
        );
        assert_eq!(
            stored(&s, &longer),
            all,
            "a shard whose filter extends the pruned one keeps every frame"
        );
        assert_eq!(s.get_shard_frame_fee_total(&left, 3).unwrap(), Some(77));
        assert!(s
            .get_staged_shard_clock_frame(&left, 41, &[0x41; 32], false)
            .is_ok());
        assert_eq!(pass.frames(), 39);
        assert_eq!(
            (
                pass.shards,
                pass.kept(KeptShard::Served),
                pass.kept(KeptShard::Recent)
            ),
            (4, 2, 1)
        );
        assert_eq!(pass.next, None);
        let again = s
            .prune_unserved_shard_frames(&is_served, BOUND, None, usize::MAX, false)
            .unwrap();
        assert!(again.pruned.is_empty());
        assert_eq!(
            again.kept(KeptShard::LatestOnly),
            1,
            "a pruned shard is kept with only its latest frame"
        );
    }

    /// A call examines at most its budget of frame keys, a longer filter's
    /// keys inside the range included, and the next call goes on from where
    /// it stopped until every old frame is gone.
    #[test]
    fn bounded_calls_resume_until_every_old_frame_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(dir.path());
        let left = vec![0x11; 35];
        let mut longer = left.clone();
        longer.push(0x00);
        let other = vec![0x44; 35];
        serve(&s, &left, 30, OLD, 8);
        serve(&s, &longer, 30, OLD, 8);
        serve(&s, &other, 30, OLD, 8);
        let is_served = |f: &[u8]| f == longer.as_slice();

        let (mut next, mut calls, mut frames) = (None::<Vec<u8>>, 0, 0);
        loop {
            let pass = s
                .prune_unserved_shard_frames(&is_served, BOUND, next.as_deref(), 7, false)
                .unwrap();
            assert!(pass.examined <= 7, "a call stays within its budget");
            calls += 1;
            frames += pass.frames();
            next = pass.next;
            if next.is_none() {
                break;
            }
            assert!(calls < 100, "the calls make progress");
        }
        assert_eq!(stored(&s, &left), vec![30], "every old frame is gone");
        assert!(calls > 2, "the work was split over several calls");
        assert_eq!(frames, 58);
        assert_eq!(stored(&s, &other), vec![30]);
        assert_eq!(stored(&s, &longer).len(), 30);
    }

    /// A dry run deletes nothing and measures what the real call deletes.
    #[test]
    fn a_dry_run_measures_the_deletion_and_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(dir.path());
        let left = vec![0x11; 36];
        serve(&s, &left, 20, OLD, 100);
        let none = |_: &[u8]| false;

        let dry = s
            .prune_unserved_shard_frames(&none, BOUND, None, usize::MAX, true)
            .unwrap();
        assert_eq!(dry.frames(), 19, "a dry run counts the old frames");
        assert_eq!(stored(&s, &left).len(), 20, "a dry run deletes nothing");
        let real = s
            .prune_unserved_shard_frames(&none, BOUND, None, usize::MAX, false)
            .unwrap();
        assert_eq!(real, dry);
        assert!(real.bytes() > 19 * 100);
        assert_eq!(stored(&s, &left), vec![20]);
    }

    /// A shard taken up between its scan and its deletion keeps its frames;
    /// the others still go.
    #[test]
    fn a_shard_taken_up_during_its_scan_keeps_its_frames() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(dir.path());
        let taken = vec![0x11; 35];
        let left = vec![0x55; 35];
        serve(&s, &taken, 10, OLD, 8);
        serve(&s, &left, 10, OLD, 8);
        let asked = Cell::new(0);
        let is_served = |f: &[u8]| {
            if f != taken.as_slice() {
                return false;
            }
            asked.set(asked.get() + 1);
            asked.get() > 1
        };

        let pass = s
            .prune_unserved_shard_frames(&is_served, BOUND, None, usize::MAX, false)
            .unwrap();
        assert_eq!(
            stored(&s, &left),
            vec![10],
            "an unserved idle shard keeps only its latest frame"
        );
        assert_eq!(
            stored(&s, &taken).len(),
            10,
            "a shard taken up during its scan keeps its frames"
        );
        assert_eq!(pass.kept(KeptShard::Served), 1);
    }

    /// Compacting a pruned shard's range drops its table files.
    #[test]
    fn compacting_pruned_frames_reclaims_their_space() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(dir.path());
        let left = vec![0x11; 35];
        serve(&s, &left, 200, OLD, 64 << 10);
        s.db.flush().unwrap();
        let sst = |s: &RocksClockStore| -> u64 {
            s.db.live_files()
                .unwrap()
                .iter()
                .map(|f| f.size as u64)
                .sum()
        };
        let before = sst(&s);
        let pass = s
            .prune_unserved_shard_frames(&|_| false, BOUND, None, usize::MAX, false)
            .unwrap();
        assert_eq!(pass.frames(), 199, "the old frames are deleted");
        s.compact_pruned_shard_frames(&left, pass.pruned[0].below);
        assert!(
            sst(&s) < before / 10,
            "compaction reclaims the pruned frames' space: {} of {before} bytes left",
            sst(&s)
        );
        assert_eq!(stored(&s, &left), vec![200]);
    }
}
