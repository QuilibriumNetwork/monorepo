//! Bounded cleanup of clock records nothing reads any more. Both passes write
//! only through a [`quil_forest::DisjointBatch`] confined to their own key
//! family, so they never invalidate an in-flight atomic execution plan, and
//! both have a dry run that measures what a pass would delete.
use prost::Message;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global;

use super::RocksClockStore;
use crate::encoding;

/// One pass of [`RocksClockStore::prune_committed_staged_shard_frames`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StagedFrameCleanup {
    /// Staged frames examined.
    pub scanned: u64,
    /// Deleted (or, in a dry run, deletable): the canonical copy is identical.
    pub deleted: u64,
    pub deleted_bytes: u64,
    /// Kept: a different frame is canonical at that height.
    pub differing: u64,
    /// Kept: nothing is canonical at that height yet.
    pub uncommitted: u64,
    /// Kept: the key or value does not decode as a staged frame.
    pub malformed: u64,
    /// Resume after this key; `None` once the keyspace is exhausted.
    pub next: Option<Vec<u8>>,
}

/// One pass of [`RocksClockStore::prune_global_candidates`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CandidatePrune {
    /// Highest prunable height: `min(canonical head, executed cursor) - margin`.
    /// `None` when nothing is old enough.
    pub limit: Option<u64>,
    /// Candidate headers examined.
    pub examined: u64,
    /// Candidates deleted (or deletable), header and request bodies.
    pub pruned: u64,
    pub pruned_request_keys: u64,
    pub pruned_bytes: u64,
    /// Kept: no canonical record at that height (a record hole, which the
    /// restart backfill fills from these candidates).
    pub kept_in_holes: u64,
    /// Continue from this height; `None` once the prunable range is done.
    pub next_from: Option<u64>,
}

fn store(error: impl std::fmt::Display) -> QuilError {
    QuilError::Store(error.to_string())
}

impl RocksClockStore {
    /// Delete staged application-shard frames whose canonical copy is stored
    /// byte for byte. Stores written before the commit dropped its staged copy
    /// hold every committed frame twice. A staged frame with no canonical copy,
    /// or a different one, is kept. At most `max_scan` staged keys are examined,
    /// starting after `after`; pass the returned `next` to continue.
    pub fn prune_committed_staged_shard_frames(
        &self,
        after: Option<&[u8]>,
        max_scan: usize,
        dry_run: bool,
    ) -> Result<StagedFrameCleanup> {
        let prefix = [encoding::CLOCK_FRAME, encoding::CLOCK_SHARD_STAGED];
        let mut result = StagedFrameCleanup::default();
        let mut batch = quil_forest::DisjointBatch::new(encoding::CLOCK_SHARD_STAGED_PREFIXES);
        let mut it = self.db.raw_iterator();
        match after {
            Some(after) => {
                it.seek(after);
                if it.key() == Some(after) {
                    it.next();
                }
            }
            None => it.seek(prefix),
        }
        let mut exhausted = true;
        let mut last: Option<Vec<u8>> = None;
        while let (Some(key), Some(value)) = (it.key(), it.value()) {
            if !key.starts_with(&prefix) {
                break;
            }
            if result.scanned as usize >= max_scan {
                exhausted = false;
                break;
            }
            result.scanned += 1;
            last = Some(key.to_vec());
            let header = global::AppShardFrame::decode(value).ok().and_then(|frame| frame.header);
            let number = key.len().checked_sub(8).map(|at| u64::from_be_bytes(key[at..].try_into().unwrap()));
            match header {
                Some(header) if Some(header.frame_number) == number && !header.address.is_empty() => {
                    let canonical = encoding::clock_shard_frame_key(&header.address, header.frame_number);
                    match self.db.get(&canonical).map_err(store)? {
                        Some(stored) if stored.as_slice() == value => {
                            result.deleted += 1;
                            result.deleted_bytes += (key.len() + value.len()) as u64;
                            batch.delete(key).map_err(store)?;
                        }
                        Some(_) => result.differing += 1,
                        None => result.uncommitted += 1,
                    }
                }
                _ => result.malformed += 1,
            }
            it.next();
        }
        it.status().map_err(store)?;
        result.next = if exhausted { None } else { last.or_else(|| after.map(<[u8]>::to_vec)) };
        drop(it);
        if !dry_run && !batch.is_empty() {
            self.db.write_disjoint(batch, &rocksdb::WriteOptions::default()).map_err(store)?;
        }
        Ok(result)
    }

    /// Delete GLOBAL candidates (header and request bodies) at heights that
    /// are `margin` or more below both the canonical head and the executed
    /// cursor and that hold a canonical record. Candidates carry consensus
    /// bodies until finalization; below the executed cursor they are read only
    /// to fill a record hole (restart backfill, a kick's previous-frame
    /// fallback), so a height with no canonical record keeps them. Examines at
    /// most `max_candidates` headers from height `from`; pass the returned
    /// `next_from` to continue.
    pub fn prune_global_candidates(
        &self,
        margin: u64,
        from: u64,
        max_candidates: usize,
        dry_run: bool,
    ) -> Result<CandidatePrune> {
        let mut result = CandidatePrune::default();
        let head = self.get_latest_frame_number();
        let cursor = self.get_global_materialized_cursor();
        let Some(limit) = head.zip(cursor).map(|(h, c)| h.min(c)).and_then(|top| top.checked_sub(margin)) else {
            return Ok(result);
        };
        result.limit = Some(limit);
        let prefix = [encoding::CLOCK_FRAME, encoding::CLOCK_GLOBAL_FRAME_CANDIDATE];
        let mut batch = quil_forest::DisjointBatch::new(encoding::GLOBAL_CANDIDATE_PREFIXES);
        let mut it = self.db.raw_iterator();
        it.seek(encoding::clock_global_frame_candidate_key(from, &[]));
        while let (Some(key), Some(value)) = (it.key(), it.value()) {
            if !key.starts_with(&prefix) || key.len() != 42 {
                break;
            }
            let number = u64::from_be_bytes(key[2..10].try_into().unwrap());
            if number > limit {
                break;
            }
            if result.examined as usize >= max_candidates {
                result.next_from = Some(number);
                break;
            }
            result.examined += 1;
            if self.db.get(encoding::clock_global_frame_key(number)).map_err(store)?.is_none() {
                result.kept_in_holes += 1;
                it.next();
                continue;
            }
            let selector = &key[10..];
            let start = encoding::clock_global_frame_request_candidate_key(selector, number, 0);
            let mut end = start[..start.len() - 2].to_vec();
            end.extend_from_slice(&[0xff; 3]);
            let mut requests = self.db.raw_iterator();
            requests.seek(&start);
            while let (Some(request), Some(body)) = (requests.key(), requests.value()) {
                if request >= end.as_slice() {
                    break;
                }
                result.pruned_request_keys += 1;
                result.pruned_bytes += (request.len() + body.len()) as u64;
                requests.next();
            }
            requests.status().map_err(store)?;
            result.pruned += 1;
            result.pruned_bytes += (key.len() + value.len()) as u64;
            batch.delete(key).map_err(store)?;
            batch.delete_range(&start, &end).map_err(store)?;
            it.next();
        }
        it.status().map_err(store)?;
        drop(it);
        if !dry_run && !batch.is_empty() {
            self.db.write_disjoint(batch, &rocksdb::WriteOptions::default()).map_err(store)?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::store::ClockStore;

    fn open(dir: &std::path::Path) -> RocksClockStore {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        RocksClockStore::new(quil_forest::CoordinatedDb::new(rocksdb::DB::open(&opts, dir).unwrap()))
    }

    fn app_frame(filter: &[u8], number: u64, output: u8) -> global::AppShardFrame {
        global::AppShardFrame {
            header: Some(global::FrameHeader {
                address: filter.to_vec(),
                frame_number: number,
                output: vec![output; 32],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn stage(s: &RocksClockStore, frame: &global::AppShardFrame, selector: &[u8]) {
        let txn = s.new_transaction(false).unwrap();
        s.stage_shard_clock_frame(selector, frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();
    }

    fn put_canonical(s: &RocksClockStore, frame: &global::AppShardFrame) {
        let header = frame.header.as_ref().unwrap();
        s.db.put(encoding::clock_shard_frame_key(&header.address, header.frame_number), frame.encode_to_vec()).unwrap();
    }

    /// Only a staged copy whose canonical copy is identical goes; a staged
    /// frame not (or differently) committed stays. Bounded passes resume where
    /// the last stopped, and a dry run deletes nothing.
    #[test]
    fn staged_frames_are_dropped_only_when_their_canonical_copy_matches() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(dir.path());
        let filter = vec![3u8; 35];
        let committed: Vec<_> = (1..=5).map(|n| app_frame(&filter, n, n as u8)).collect();
        for (i, frame) in committed.iter().enumerate() {
            stage(&s, frame, &[i as u8 + 1; 32]);
            put_canonical(&s, frame);
        }
        let losing = app_frame(&filter, 3, 0x77);
        stage(&s, &losing, &[0x77; 32]);
        let pending = app_frame(&filter, 9, 9);
        stage(&s, &pending, &[0x99; 32]);
        let staged_count = |s: &RocksClockStore| {
            let prefix = [encoding::CLOCK_FRAME, encoding::CLOCK_SHARD_STAGED];
            s.db.iterator(rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward))
                .map(|e| e.unwrap().0)
                .take_while(|k| k.starts_with(&prefix))
                .count()
        };

        let dry = s.prune_committed_staged_shard_frames(None, usize::MAX, true).unwrap();
        assert_eq!((dry.scanned, dry.deleted, dry.differing, dry.uncommitted), (7, 5, 1, 1));
        assert_eq!(staged_count(&s), 7, "a dry run deletes nothing");

        let first = s.prune_committed_staged_shard_frames(None, 3, false).unwrap();
        assert_eq!(first.scanned, 3);
        assert!(first.next.is_some());
        let mut next = first.next.clone();
        let mut deleted = first.deleted;
        while let Some(after) = next {
            let pass = s.prune_committed_staged_shard_frames(Some(&after), 3, false).unwrap();
            deleted += pass.deleted;
            next = pass.next;
        }
        assert_eq!(deleted, 5);
        assert_eq!(staged_count(&s), 2, "the losing and the uncommitted frame remain");
        for frame in &committed {
            let n = frame.header.as_ref().unwrap().frame_number;
            assert_eq!(s.get_shard_clock_frame(&filter, n, false).unwrap(), *frame);
        }
        // The remaining staged frame still commits normally.
        let txn = s.new_transaction(false).unwrap();
        s.commit_shard_clock_frame(&filter, 9, &[0x99; 32], txn.as_ref(), false).unwrap();
        txn.commit().unwrap();
        assert_eq!(s.get_shard_clock_frame(&filter, 9, false).unwrap(), pending);
        assert_eq!(s.prune_committed_staged_shard_frames(None, usize::MAX, false).unwrap().deleted, 0);
    }

    fn candidate(number: u64, output: u8) -> global::GlobalFrame {
        global::GlobalFrame {
            header: Some(global::GlobalFrameHeader {
                frame_number: number,
                output: vec![output; 516],
                ..Default::default()
            }),
            requests: vec![global::MessageBundle::default(), global::MessageBundle { timestamp: 7, ..Default::default() }],
        }
    }

    fn put_candidate(s: &RocksClockStore, frame: &global::GlobalFrame) {
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame_candidate(frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();
    }

    fn identity(frame: &global::GlobalFrame) -> [u8; 32] {
        quil_crypto::poseidon::hash_bytes_to_32(&frame.header.as_ref().unwrap().output).unwrap()
    }

    /// Candidates go only `margin` below both the canonical head and the
    /// executed cursor, and only at heights with a canonical record; a record
    /// hole keeps its candidates for the restart backfill. Request bodies go
    /// with their header, a dry run deletes nothing, and passes resume.
    #[test]
    fn global_candidates_are_pruned_only_below_the_margin_and_outside_record_holes() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(dir.path());
        for number in 1..=20u64 {
            put_candidate(&s, &candidate(number, number as u8));
            if number != 4 {
                s.put_global_frame(&candidate(number, number as u8), None).unwrap();
            }
        }
        // A nullified view's candidate at an old height goes too.
        put_candidate(&s, &candidate(6, 0x66));
        assert_eq!(s.prune_global_candidates(5, 0, usize::MAX, false).unwrap(), CandidatePrune::default(),
            "no executed cursor: nothing is old enough");
        s.put_global_materialized_cursor(15).unwrap();

        let dry = s.prune_global_candidates(5, 0, usize::MAX, true).unwrap();
        assert_eq!(dry.limit, Some(10));
        assert_eq!((dry.examined, dry.pruned, dry.kept_in_holes), (11, 10, 1));
        assert_eq!(dry.pruned_request_keys, 20);
        assert!(s.get_global_clock_frame_candidate(1, &identity(&candidate(1, 1))).unwrap().requests.len() == 2);

        let first = s.prune_global_candidates(5, 0, 4, false).unwrap();
        assert_eq!((first.examined, first.next_from), (4, Some(5)));
        let rest = s.prune_global_candidates(5, first.next_from.unwrap(), usize::MAX, false).unwrap();
        assert_eq!(first.pruned + rest.pruned, 10);
        assert_eq!(rest.next_from, None);

        let remaining = s.range_global_clock_frame_candidates(0, u64::MAX, 64).unwrap();
        let heights: Vec<u64> = remaining.iter().map(|f| f.header.as_ref().unwrap().frame_number).collect();
        assert_eq!(heights, vec![4, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
        assert_eq!(remaining[0].requests.len(), 2, "the hole keeps its body");
        // A pruned candidate reads back as its canonical record (the getter's fallback).
        let pruned = s.get_global_clock_frame_candidate(2, &identity(&candidate(2, 2))).unwrap();
        assert_eq!(pruned.header.unwrap().frame_number, 2);
        let request = encoding::clock_global_frame_request_candidate_key(&identity(&candidate(2, 2)), 2, 0);
        assert!(s.db.get(request).unwrap().is_none(), "request bodies go with their header");
    }
}
