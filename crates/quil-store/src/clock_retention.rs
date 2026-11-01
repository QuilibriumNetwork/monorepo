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

/// One pass of [`RocksClockStore::prune_global_frame_requests`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestPrune {
    /// Request bodies are kept from this frame on; `None` when the head is
    /// not yet `keep` frames above genesis.
    pub retained_from: Option<u64>,
    /// Frames whose bodies this pass removed (the previous boundary up to
    /// `retained_from`).
    pub frames: u64,
    /// Bytes of the table files holding nothing but bodies below the new
    /// boundary when the pass ran: space no compaction has reclaimed yet.
    /// `0` when the pass removed nothing.
    pub dead_bytes: u64,
    /// The pass compacted the pruned range itself, because `dead_bytes`
    /// reached [`RocksClockStore::REQUEST_RECLAIM_BYTES`]; otherwise the
    /// space is left to RocksDB's own compaction.
    pub compacted: bool,
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
            let header = global::AppShardFrame::decode(value)
                .ok()
                .and_then(|frame| frame.header);
            let number = key
                .len()
                .checked_sub(8)
                .map(|at| u64::from_be_bytes(key[at..].try_into().unwrap()));
            match header {
                Some(header)
                    if Some(header.frame_number) == number && !header.address.is_empty() =>
                {
                    let canonical =
                        encoding::clock_shard_frame_key(&header.address, header.frame_number);
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
        result.next = if exhausted {
            None
        } else {
            last.or_else(|| after.map(<[u8]>::to_vec))
        };
        drop(it);
        if !dry_run && !batch.is_empty() {
            self.db
                .write_disjoint(batch, &rocksdb::WriteOptions::default())
                .map_err(store)?;
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
        let Some(limit) = head
            .zip(cursor)
            .map(|(h, c)| h.min(c))
            .and_then(|top| top.checked_sub(margin))
        else {
            return Ok(result);
        };
        result.limit = Some(limit);
        let prefix = [
            encoding::CLOCK_FRAME,
            encoding::CLOCK_GLOBAL_FRAME_CANDIDATE,
        ];
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
            if self
                .db
                .get(encoding::clock_global_frame_key(number))
                .map_err(store)?
                .is_none()
            {
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
            self.db
                .write_disjoint(batch, &rocksdb::WriteOptions::default())
                .map_err(store)?;
        }
        Ok(result)
    }
}

impl RocksClockStore {
    /// Dead table bytes below the request boundary at which a prune pass
    /// compacts the range itself. Below it the range deletion is left to
    /// RocksDB, which ranks files by the bytes their range deletions cover:
    /// over a simulated day of a regular node's store that alone kept them
    /// under 540 MB. A compaction every pass rewrote every table file
    /// overlapping the range, L0 included, about 480 MB per pass there. Twice
    /// that peak, so only a store RocksDB leaves alone (a quiet one, or one
    /// holding a backlog of bodies) is compacted.
    pub const REQUEST_RECLAIM_BYTES: u64 = 1 << 30;

    /// The lowest global frame whose request bodies are kept, or `None` when
    /// every stored frame keeps them.
    pub fn global_requests_retained_from(&self) -> Option<u64> {
        self.read_u64_index(&encoding::clock_global_requests_retained_index())
    }

    /// Delete the request bodies of global frames more than `keep` frames
    /// below the head, keeping every header. The boundary is recorded in the
    /// same write, and readers that would hand a frame to someone else refuse
    /// frames below it (see [`Self::global_requests_retained_from`]). The
    /// range below the boundary is deleted whole each pass, so bodies an old
    /// backfill wrote back are removed too. Only a node that neither executes
    /// GLOBAL frames nor serves history may call this.
    ///
    /// The pass does not compact: RocksDB's own compaction drops the bodies.
    /// Once table files holding only pruned bodies reach
    /// [`Self::REQUEST_RECLAIM_BYTES`], the pass compacts the range, so they
    /// stay below that plus one pass's bodies.
    pub fn prune_global_frame_requests(&self, keep: u64) -> Result<RequestPrune> {
        self.prune_global_frame_requests_reclaiming_at(keep, Self::REQUEST_RECLAIM_BYTES)
    }

    fn prune_global_frame_requests_reclaiming_at(
        &self,
        keep: u64,
        reclaim_at: u64,
    ) -> Result<RequestPrune> {
        let Some(limit) = self
            .get_latest_frame_number()
            .and_then(|head| head.checked_sub(keep))
        else {
            return Ok(RequestPrune::default());
        };
        let recorded = self.global_requests_retained_from();
        let previous = recorded.unwrap_or(0);
        if limit <= previous {
            return Ok(RequestPrune {
                retained_from: recorded,
                ..RequestPrune::default()
            });
        }
        let writes = self.global_memory.writes.lock().unwrap();
        let mut batch = quil_forest::DisjointBatch::new(encoding::GLOBAL_REQUEST_PREFIXES);
        let start = encoding::clock_global_frame_request_key(0, 0);
        let end = encoding::clock_global_frame_request_key(limit, 0);
        batch.delete_range(&start, &end).map_err(store)?;
        batch
            .put(
                encoding::clock_global_requests_retained_index(),
                limit.to_be_bytes(),
            )
            .map_err(store)?;
        self.db
            .write_disjoint(batch, &rocksdb::WriteOptions::default())
            .map_err(store)?;
        let mut cache = self.global_memory.cache.write().unwrap();
        cache.generation = cache.generation.wrapping_add(1);
        cache.frames.retain(|n, _| *n >= limit);
        cache.bytes = cache.frames.values().map(|(_, size)| *size).sum();
        drop(cache);
        // Writers may go on while the range compacts: no key at or above
        // `limit` is in it, and a body written back below it goes next pass.
        drop(writes);
        let dead_bytes = self.dead_request_bytes(&start, &end)?;
        let compacted = dead_bytes >= reclaim_at;
        if compacted {
            // Bottommost files too: there the bodies usually sit.
            let mut options = rocksdb::CompactOptions::default();
            options.set_bottommost_level_compaction(
                rocksdb::BottommostLevelCompaction::ForceOptimized,
            );
            self.db
                .compact_range_opt(Some(&start), Some(&end), &options);
        }
        Ok(RequestPrune {
            retained_from: Some(limit),
            frames: limit - previous,
            dead_bytes,
            compacted,
        })
    }

    /// Bytes of the table files lying wholly in `[start, end)`, the deleted
    /// request range: no visible key is left in them. A file ending exactly
    /// at `end` may hold the first retained body, so it is not counted.
    fn dead_request_bytes(&self, start: &[u8], end: &[u8]) -> Result<u64> {
        Ok(self
            .db
            .live_files()
            .map_err(store)?
            .iter()
            .filter(|f| match (f.start_key.as_deref(), f.end_key.as_deref()) {
                (Some(first), Some(last)) => first >= start && last < end,
                _ => false,
            })
            .map(|f| f.size as u64)
            .sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::store::ClockStore;

    fn open(dir: &std::path::Path) -> RocksClockStore {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        RocksClockStore::new(quil_forest::CoordinatedDb::new(
            rocksdb::DB::open(&opts, dir).unwrap(),
        ))
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
        s.stage_shard_clock_frame(selector, frame, txn.as_ref())
            .unwrap();
        txn.commit().unwrap();
    }

    fn put_canonical(s: &RocksClockStore, frame: &global::AppShardFrame) {
        let header = frame.header.as_ref().unwrap();
        s.db.put(
            encoding::clock_shard_frame_key(&header.address, header.frame_number),
            frame.encode_to_vec(),
        )
        .unwrap();
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
            s.db.iterator(rocksdb::IteratorMode::From(
                &prefix,
                rocksdb::Direction::Forward,
            ))
            .map(|e| e.unwrap().0)
            .take_while(|k| k.starts_with(&prefix))
            .count()
        };

        let dry = s
            .prune_committed_staged_shard_frames(None, usize::MAX, true)
            .unwrap();
        assert_eq!(
            (dry.scanned, dry.deleted, dry.differing, dry.uncommitted),
            (7, 5, 1, 1)
        );
        assert_eq!(staged_count(&s), 7, "a dry run deletes nothing");

        let first = s
            .prune_committed_staged_shard_frames(None, 3, false)
            .unwrap();
        assert_eq!(first.scanned, 3);
        assert!(first.next.is_some());
        let mut next = first.next.clone();
        let mut deleted = first.deleted;
        while let Some(after) = next {
            let pass = s
                .prune_committed_staged_shard_frames(Some(&after), 3, false)
                .unwrap();
            deleted += pass.deleted;
            next = pass.next;
        }
        assert_eq!(deleted, 5);
        assert_eq!(
            staged_count(&s),
            2,
            "the losing and the uncommitted frame remain"
        );
        for frame in &committed {
            let n = frame.header.as_ref().unwrap().frame_number;
            assert_eq!(s.get_shard_clock_frame(&filter, n, false).unwrap(), *frame);
        }
        // The remaining staged frame still commits normally.
        let txn = s.new_transaction(false).unwrap();
        s.commit_shard_clock_frame(&filter, 9, &[0x99; 32], txn.as_ref(), false)
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(s.get_shard_clock_frame(&filter, 9, false).unwrap(), pending);
        assert_eq!(
            s.prune_committed_staged_shard_frames(None, usize::MAX, false)
                .unwrap()
                .deleted,
            0
        );
    }

    fn candidate(number: u64, output: u8) -> global::GlobalFrame {
        global::GlobalFrame {
            header: Some(global::GlobalFrameHeader {
                frame_number: number,
                output: vec![output; 516],
                ..Default::default()
            }),
            requests: vec![
                global::MessageBundle::default(),
                global::MessageBundle {
                    timestamp: 7,
                    ..Default::default()
                },
            ],
        }
    }

    fn put_candidate(s: &RocksClockStore, frame: &global::GlobalFrame) {
        let txn = s.new_transaction(false).unwrap();
        s.put_global_clock_frame_candidate(frame, txn.as_ref())
            .unwrap();
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
                s.put_global_frame(&candidate(number, number as u8), None)
                    .unwrap();
            }
        }
        // A nullified view's candidate at an old height goes too.
        put_candidate(&s, &candidate(6, 0x66));
        assert_eq!(
            s.prune_global_candidates(5, 0, usize::MAX, false).unwrap(),
            CandidatePrune::default(),
            "no executed cursor: nothing is old enough"
        );
        s.put_global_materialized_cursor(15).unwrap();

        let dry = s.prune_global_candidates(5, 0, usize::MAX, true).unwrap();
        assert_eq!(dry.limit, Some(10));
        assert_eq!((dry.examined, dry.pruned, dry.kept_in_holes), (11, 10, 1));
        assert_eq!(dry.pruned_request_keys, 20);
        assert!(
            s.get_global_clock_frame_candidate(1, &identity(&candidate(1, 1)))
                .unwrap()
                .requests
                .len()
                == 2
        );

        let first = s.prune_global_candidates(5, 0, 4, false).unwrap();
        assert_eq!((first.examined, first.next_from), (4, Some(5)));
        let rest = s
            .prune_global_candidates(5, first.next_from.unwrap(), usize::MAX, false)
            .unwrap();
        assert_eq!(first.pruned + rest.pruned, 10);
        assert_eq!(rest.next_from, None);

        let remaining = s
            .range_global_clock_frame_candidates(0, u64::MAX, 64)
            .unwrap();
        let heights: Vec<u64> = remaining
            .iter()
            .map(|f| f.header.as_ref().unwrap().frame_number)
            .collect();
        assert_eq!(heights, vec![4, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
        assert_eq!(remaining[0].requests.len(), 2, "the hole keeps its body");
        // A pruned candidate reads back as its canonical record (the getter's fallback).
        let pruned = s
            .get_global_clock_frame_candidate(2, &identity(&candidate(2, 2)))
            .unwrap();
        assert_eq!(pruned.header.unwrap().frame_number, 2);
        let request =
            encoding::clock_global_frame_request_candidate_key(&identity(&candidate(2, 2)), 2, 0);
        assert!(
            s.db.get(request).unwrap().is_none(),
            "request bodies go with their header"
        );
    }

    /// Request bodies more than `keep` frames below the head go, headers stay,
    /// the boundary is recorded, and each pass also clears bodies written back
    /// below it.
    #[test]
    fn old_request_bodies_are_pruned_and_headers_kept() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(dir.path());
        for n in 1..=10 {
            s.put_global_frame(&candidate(n, n as u8), None).unwrap();
        }
        let bodies = |s: &RocksClockStore| {
            let prefix = [encoding::CLOCK_FRAME, encoding::CLOCK_GLOBAL_FRAME_REQUEST];
            s.db.iterator(rocksdb::IteratorMode::From(
                &prefix,
                rocksdb::Direction::Forward,
            ))
            .map(|e| e.unwrap().0)
            .take_while(|k| k.starts_with(&prefix))
            .map(|k| u64::from_be_bytes(k[2..10].try_into().unwrap()))
            .collect::<Vec<_>>()
        };
        assert_eq!(bodies(&s).len(), 20);
        assert_eq!(s.global_requests_retained_from(), None);
        assert_eq!(
            s.prune_global_frame_requests(10).unwrap(),
            RequestPrune::default(),
            "nothing is old enough"
        );

        let pass = s.prune_global_frame_requests(3).unwrap();
        assert_eq!((pass.retained_from, pass.frames), (Some(7), 7));
        assert_eq!(s.global_requests_retained_from(), Some(7));
        assert!(bodies(&s).iter().all(|n| *n >= 7));
        assert_eq!(bodies(&s).len(), 8);
        for n in 1..=10 {
            let frame = s.get_global_frame(n).unwrap();
            assert_eq!(
                frame.header,
                candidate(n, n as u8).header,
                "every header stays"
            );
            assert_eq!(frame.requests.len(), if n < 7 { 0 } else { 2 });
        }
        assert_eq!(
            s.prune_global_frame_requests(3).unwrap().frames,
            0,
            "a repeat at the same head removes nothing"
        );

        s.db.put(
            encoding::clock_global_frame_request_key(2, 0),
            b"written back",
        )
        .unwrap();
        s.put_global_frame(&candidate(11, 11), None).unwrap();
        let pass = s.prune_global_frame_requests(3).unwrap();
        assert_eq!((pass.retained_from, pass.frames), (Some(8), 1));
        assert!(
            bodies(&s).iter().all(|n| *n >= 8),
            "bodies written back below the boundary go too"
        );
        assert_eq!(s.get_global_frame(11).unwrap().requests.len(), 2);
        assert_eq!(s.get_earliest_frame_number(), Some(1));
    }

    /// SplitMix64: a deterministic spread of `x`.
    fn mix(x: u64) -> u64 {
        let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Deterministic incompressible bytes: request bodies are mostly proofs.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            out.extend_from_slice(&x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// A canonical global frame with `bundles` request bundles of `bytes`
    /// payload each.
    fn frame_with_bodies(number: u64, bundles: u64, bytes: usize) -> global::GlobalFrame {
        use global::message_request::Request;
        global::GlobalFrame {
            header: Some(global::GlobalFrameHeader {
                frame_number: number,
                output: vec![number as u8; 516],
                ..Default::default()
            }),
            requests: (0..bundles)
                .map(|i| global::MessageBundle {
                    requests: vec![global::MessageRequest {
                        request: Some(Request::CommitteeHandoff(noise(number << 16 | i, bytes))),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .collect(),
        }
    }

    const BODY: usize = 16 << 10;

    /// Frames 1..=`frames` with two 16 KiB bodies each, settled into the
    /// bottommost level at about two frames per table file. Background
    /// compaction is off, so what a pass leaves is what the test sees.
    fn settled_store(dir: &std::path::Path, frames: u64) -> RocksClockStore {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_target_file_size_base(64 << 10);
        opts.set_disable_auto_compactions(true);
        let s = RocksClockStore::new(quil_forest::CoordinatedDb::new(
            rocksdb::DB::open(&opts, dir).unwrap(),
        ));
        for n in 1..=frames {
            s.put_global_frame(&frame_with_bodies(n, 2, BODY), None)
                .unwrap();
        }
        s.db.flush().unwrap();
        // Rewritten, not moved whole: a flush writes one file.
        let mut options = rocksdb::CompactOptions::default();
        options.set_bottommost_level_compaction(rocksdb::BottommostLevelCompaction::Force);
        s.db.compact_range_opt::<&[u8], &[u8]>(None, None, &options);
        let request_files = s
            .db
            .live_files()
            .unwrap()
            .iter()
            .filter(|f| {
                f.start_key.as_deref().is_some_and(|k| {
                    k.starts_with(&[encoding::CLOCK_FRAME, encoding::CLOCK_GLOBAL_FRAME_REQUEST])
                })
            })
            .count() as u64;
        assert!(
            request_files >= frames / 4,
            "{request_files} table files of bodies"
        );
        s
    }

    fn sst_bytes(s: &RocksClockStore) -> u64 {
        s.db.live_files()
            .unwrap()
            .iter()
            .map(|f| f.size as u64)
            .sum()
    }

    fn dead_below(s: &RocksClockStore, limit: u64) -> u64 {
        s.dead_request_bytes(
            &encoding::clock_global_frame_request_key(0, 0),
            &encoding::clock_global_frame_request_key(limit, 0),
        )
        .unwrap()
    }

    /// Frames `retained_from..=stored` read back whole, every other frame
    /// up to `head` without bodies, and a scan of the request keys starts
    /// at the boundary.
    fn assert_bodies(s: &RocksClockStore, retained_from: u64, stored: u64, head: u64) {
        for n in 1..=head {
            let frame = s.get_global_frame(n).unwrap();
            if (retained_from..=stored).contains(&n) {
                assert_eq!(
                    frame,
                    frame_with_bodies(n, 2, BODY),
                    "frame {n} reads whole"
                );
            } else {
                assert!(frame.requests.is_empty(), "frame {n} below {retained_from}");
            }
        }
        let prefix = [encoding::CLOCK_FRAME, encoding::CLOCK_GLOBAL_FRAME_REQUEST];
        let first =
            s.db.iterator(rocksdb::IteratorMode::From(
                &prefix,
                rocksdb::Direction::Forward,
            ))
            .map(|e| e.unwrap().0)
            .next()
            .filter(|k| k.starts_with(&prefix));
        assert_eq!(
            first.as_deref(),
            Some(encoding::clock_global_frame_request_key(retained_from, 0).as_slice()),
            "a scan of the request keys starts at the boundary"
        );
    }

    /// A pass below the reclaim threshold writes the range deletion and
    /// leaves the space to RocksDB: the table files holding only pruned
    /// bodies are all still there, and the retained bodies read back whole.
    #[test]
    fn a_request_prune_pass_does_not_compact_below_the_reclaim_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let s = settled_store(dir.path(), 40);
        let before = sst_bytes(&s);
        let pass = s.prune_global_frame_requests(10).unwrap();
        assert_eq!((pass.retained_from, pass.frames), (Some(30), 30));
        assert!(!pass.compacted, "{pass:?}");
        assert!(
            pass.dead_bytes > 20 * 2 * BODY as u64,
            "whole table files of pruned bodies: {pass:?}"
        );
        assert_eq!(
            dead_below(&s, 30),
            pass.dead_bytes,
            "no compaction ran: every file of pruned bodies is still there"
        );
        assert_eq!(sst_bytes(&s), before);
        assert_bodies(&s, 30, 40, 40);
    }

    /// Pruned bodies pile up only to the reclaim threshold: the pass that
    /// finds that many bytes of dead table files compacts them away, so
    /// after every pass less than the threshold is left, and the retained
    /// bodies read back whole under the stacked range deletions.
    #[test]
    fn pruned_request_bodies_are_compacted_once_they_reach_the_reclaim_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let (stored, keep, step) = (80, 70, 8);
        let s = settled_store(dir.path(), stored);
        // About two and a half passes of pruned bodies.
        let threshold = 5 * step * BODY as u64;
        let (mut deferred, mut compacted) = (0, 0);
        let mut head = stored;
        while head + step - keep <= stored {
            let before = sst_bytes(&s);
            let pass = s
                .prune_global_frame_requests_reclaiming_at(keep, threshold)
                .unwrap();
            let limit = head - keep;
            assert_eq!(pass.retained_from, Some(limit));
            let left = dead_below(&s, limit);
            if pass.compacted {
                compacted += 1;
                assert!(pass.dead_bytes >= threshold, "{pass:?}");
                assert_eq!(left, 0, "the compaction reclaimed every dead file");
                assert!(
                    sst_bytes(&s) + pass.dead_bytes / 2 < before,
                    "space reclaimed"
                );
            } else {
                deferred += 1;
                assert_eq!(left, pass.dead_bytes, "deferred: nothing compacted");
            }
            assert!(left < threshold, "dead bytes {left} stay below {threshold}");
            assert_bodies(&s, limit, stored, head);
            for n in head + 1..=head + step {
                s.put_global_frame(&frame_with_bodies(n, 0, 0), None)
                    .unwrap();
            }
            head += step;
        }
        assert!(
            deferred >= 2 && compacted >= 1,
            "both outcomes exercised: {deferred} deferred, {compacted} compacted"
        );
    }

    /// A/B of a regular node's store over a simulated day, run by hand on a
    /// real disk: `QUIL_PRUNE_AB_DIR=<dir>` with `--run-ignored only -E
    /// 'test(simulated_day)'`. One seeded store (node options, `keep`
    /// frames of bodies plus other records rewritten each frame) is copied
    /// per arm; each arm then writes `passes` intervals of frames, settles
    /// background work, prunes, settles again and samples. Arms: `base`
    /// (prune, then compact the pruned range as the pass used to), `natural`
    /// (never compact), `fix` (the reclaim threshold), `fix:<MiB>`. Writes
    /// `ab-<arm>.tsv` per pass and `ab-summary.tsv` into the directory.
    #[test]
    #[ignore = "writes tens of GB; needs QUIL_PRUNE_AB_DIR"]
    fn request_prune_writes_over_a_simulated_day() {
        use std::io::Write as _;
        use std::time::{Duration, Instant};
        let Ok(root) = std::env::var("QUIL_PRUNE_AB_DIR") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let env = |name: &str, default: u64| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };
        let body = env("QUIL_PRUNE_AB_BODY_BYTES", 1_900_000);
        let bundles = env("QUIL_PRUNE_AB_BUNDLES", 8);
        let per_pass = env("QUIL_PRUNE_AB_FRAMES_PER_PASS", 45);
        let keep = env("QUIL_PRUNE_AB_KEEP", 2880);
        let passes = env("QUIL_PRUNE_AB_PASSES", 144);
        let other_per_frame = env("QUIL_PRUNE_AB_OTHER_BYTES_PER_FRAME", 400_000);
        let other_keys = env("QUIL_PRUNE_AB_OTHER_KEYS", 16_000_000);
        let reads = env("QUIL_PRUNE_AB_READS_PER_PASS", 32);
        let arms =
            std::env::var("QUIL_PRUNE_AB_ARMS").unwrap_or_else(|_| "base,natural,fix".into());
        const VALUE: usize = 256;
        // Other records sit on both sides of the request keys, as on a node.
        const FAMILIES: [[u8; 2]; 7] = [
            [0x00, 0x01],
            [0x00, 0x04],
            [0x00, 0x0b],
            [0x01, 0x00],
            [0x03, 0x00],
            [0x05, 0x00],
            [0x09, 0x00],
        ];
        let other_key = |id: u64| {
            let mut key = FAMILIES[(id % 7) as usize].to_vec();
            key.extend_from_slice(&noise(id, 32));
            key
        };
        let other_value = |seed: u64| {
            let mut value = noise(seed, VALUE / 2);
            value.resize(VALUE, 0);
            value
        };
        let per_bundle = (body / bundles) as usize;
        let write_frame = |s: &RocksClockStore, n: u64| {
            s.put_global_frame(&frame_with_bodies(n, bundles, per_bundle), None)
                .unwrap();
            let mut batch = rocksdb::WriteBatch::default();
            for i in 0..other_per_frame / (34 + VALUE as u64) {
                let seed = n << 20 | i;
                batch.put(other_key(mix(seed) % other_keys), other_value(seed));
            }
            s.db.write(batch).unwrap();
        };
        let int =
            |s: &RocksClockStore, name: &str| s.db.property_int_value(name).unwrap().unwrap_or(0);
        // Background work done, as in the quiet minutes between passes; a
        // compaction still pending after ten minutes is left running.
        let settle = |s: &RocksClockStore| {
            let started = Instant::now();
            while [
                "rocksdb.num-running-compactions",
                "rocksdb.num-running-flushes",
                "rocksdb.compaction-pending",
                "rocksdb.mem-table-flush-pending",
            ]
            .iter()
            .any(|name| int(s, name) > 0)
            {
                if started.elapsed() > Duration::from_secs(600) {
                    println!("background work still pending after 600 s");
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let process_writes = || {
            std::fs::read_to_string("/proc/self/io")
                .unwrap()
                .lines()
                .find_map(|l| l.strip_prefix("write_bytes: "))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap()
        };
        let open_measured = |dir: &std::path::Path| {
            let mut opts =
                crate::RocksDb::store_options(crate::rocksdb_store::DEFAULT_BLOCK_CACHE_BYTES);
            opts.enable_statistics();
            let db = rocksdb::DB::open(&opts, dir).unwrap();
            (
                opts,
                RocksClockStore::new(quil_forest::CoordinatedDb::new(db)),
            )
        };

        let seed_dir = root.join("seed");
        if !seed_dir.join("SEEDED").exists() {
            let _ = std::fs::remove_dir_all(&seed_dir);
            let started = Instant::now();
            let (_opts, s) = open_measured(&seed_dir);
            let mut batch = rocksdb::WriteBatch::default();
            for id in 0..other_keys {
                batch.put(other_key(id), other_value(id));
                if batch.len() == 10_000 || id + 1 == other_keys {
                    s.db.write(std::mem::take(&mut batch)).unwrap();
                }
            }
            for n in 1..=keep {
                write_frame(&s, n);
            }
            settle(&s);
            drop(s);
            std::fs::write(seed_dir.join("SEEDED"), b"").unwrap();
            println!("seeded in {} s", started.elapsed().as_secs());
        }
        let mut summary = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("ab-summary.tsv"))
            .unwrap();
        writeln!(
            summary,
            "arm\tpasses\tframes_per_pass\tbody_bytes\tcompactions\tcompact_write_bytes\tflush_write_bytes\tuser_bytes\tprocess_write_bytes\tsst_start\tsst_end\tsst_max\tdead_after_max\tdead_at_pass_max\tread_us_mean\tseek_us_mean\tpass_ms_mean\tsecs"
        )
        .unwrap();
        for arm in arms.split(',') {
            let reclaim_at = match arm {
                "base" | "natural" => u64::MAX,
                "fix" => RocksClockStore::REQUEST_RECLAIM_BYTES,
                other => {
                    other
                        .strip_prefix("fix:")
                        .and_then(|mib| mib.parse::<u64>().ok())
                        .expect("arm: base, natural, fix or fix:<MiB>")
                        << 20
                }
            };
            let dir = root.join(format!("arm-{}", arm.replace(':', "-")));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // A checkpoint by hand: tables are immutable, so link them.
            for entry in std::fs::read_dir(&seed_dir).unwrap() {
                let path = entry.unwrap().path();
                let target = dir.join(path.file_name().unwrap());
                if path.extension().is_some_and(|e| e == "sst") {
                    std::fs::hard_link(&path, &target).unwrap();
                } else {
                    std::fs::copy(&path, &target).unwrap();
                }
            }
            let started = Instant::now();
            let (opts, s) = open_measured(&dir);
            settle(&s);
            use rocksdb::statistics::Ticker;
            let tick = |t: Ticker| opts.get_ticker_count(t);
            let base_counts = (
                tick(Ticker::CompactWriteBytes),
                tick(Ticker::FlushWriteBytes),
                tick(Ticker::BytesWritten),
                process_writes(),
            );
            let sst_start = int(&s, "rocksdb.total-sst-files-size");
            let mut tsv =
                std::fs::File::create(root.join(format!("ab-{}.tsv", arm.replace(':', "-"))))
                    .unwrap();
            writeln!(tsv, "pass\thead\tretained_from\tcompacted\tdead_at_pass\tdead_after\tsst\tcompact_write\tflush_write\tuser\tprocess_write\tpass_ms\tread_us\tseek_us\tl0_files\trange_del_files").unwrap();
            let (mut compactions, mut sst_max, mut dead_after_max, mut dead_at_pass_max) =
                (0u64, sst_start, 0u64, 0u64);
            let (mut read_us, mut seek_us, mut pass_ms) = (0u128, 0u128, 0u128);
            let mut head = keep;
            for number in 1..=passes {
                for _ in 0..per_pass {
                    head += 1;
                    write_frame(&s, head);
                }
                settle(&s);
                let previous = s.global_requests_retained_from().unwrap_or(0);
                let timer = Instant::now();
                let pass = s
                    .prune_global_frame_requests_reclaiming_at(keep, reclaim_at)
                    .unwrap();
                let limit = pass.retained_from.unwrap();
                if arm == "base" && pass.frames > 0 {
                    // The step the fix removed, as the pass ran it.
                    let first = encoding::clock_global_frame_request_key(previous, 0);
                    let end = encoding::clock_global_frame_request_key(limit, 0);
                    s.db.compact_range(Some(&first), Some(&end));
                }
                let this_pass_ms = timer.elapsed().as_millis();
                settle(&s);
                if arm == "base" || pass.compacted {
                    compactions += 1;
                }
                // What a read has to merge: L0 files, and files carrying a
                // range deletion (the only deletes this workload writes).
                let l0 = int(&s, "rocksdb.num-files-at-level0");
                let ranged =
                    s.db.live_files()
                        .unwrap()
                        .iter()
                        .filter(|f| f.num_deletions > 0)
                        .count();
                // Retained bodies read back whole: the boundary frame and a
                // spread of others, from the store, not a cache.
                let timer = Instant::now();
                for r in 0..reads {
                    let n = if r == 0 {
                        limit
                    } else {
                        limit + mix(number << 32 | r) % (head - limit + 1)
                    };
                    let frame = s.read_global_frame(n).unwrap();
                    assert_eq!(frame.requests.len() as u64, bundles, "frame {n}");
                }
                let this_read_us = timer.elapsed().as_micros() / reads.max(1) as u128;
                let timer = Instant::now();
                let mut it = s.db.raw_iterator();
                it.seek(encoding::clock_global_frame_request_key(0, 0));
                assert_eq!(
                    it.key(),
                    Some(encoding::clock_global_frame_request_key(limit, 0).as_slice()),
                    "nothing below the boundary is visible"
                );
                drop(it);
                let this_seek_us = timer.elapsed().as_micros();
                let dead_after = dead_below(&s, limit);
                let sst = int(&s, "rocksdb.total-sst-files-size");
                sst_max = sst_max.max(sst);
                dead_after_max = dead_after_max.max(dead_after);
                dead_at_pass_max = dead_at_pass_max.max(pass.dead_bytes);
                read_us += this_read_us;
                seek_us += this_seek_us;
                pass_ms += this_pass_ms;
                writeln!(
                    tsv,
                    "{number}\t{head}\t{limit}\t{}\t{}\t{dead_after}\t{sst}\t{}\t{}\t{}\t{}\t{this_pass_ms}\t{this_read_us}\t{this_seek_us}\t{l0}\t{ranged}",
                    arm == "base" || pass.compacted,
                    pass.dead_bytes,
                    tick(Ticker::CompactWriteBytes) - base_counts.0,
                    tick(Ticker::FlushWriteBytes) - base_counts.1,
                    tick(Ticker::BytesWritten) - base_counts.2,
                    process_writes() - base_counts.3,
                )
                .unwrap();
            }
            let line = format!(
                "{arm}\t{passes}\t{per_pass}\t{body}\t{compactions}\t{}\t{}\t{}\t{}\t{sst_start}\t{}\t{sst_max}\t{dead_after_max}\t{dead_at_pass_max}\t{}\t{}\t{}\t{}",
                tick(Ticker::CompactWriteBytes) - base_counts.0,
                tick(Ticker::FlushWriteBytes) - base_counts.1,
                tick(Ticker::BytesWritten) - base_counts.2,
                process_writes() - base_counts.3,
                int(&s, "rocksdb.total-sst-files-size"),
                read_us / passes as u128,
                seek_us / passes as u128,
                pass_ms / passes as u128,
                started.elapsed().as_secs(),
            );
            writeln!(summary, "{line}").unwrap();
            println!("{line}");
            let log = std::fs::read(dir.join("LOG")).unwrap_or_default();
            drop(s);
            drop(opts);
            std::fs::write(root.join(format!("ab-{}.LOG", arm.replace(':', "-"))), log).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}
