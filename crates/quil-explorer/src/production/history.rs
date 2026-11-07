//! App-shard production history: `GET /shards/production/history` and the
//! `/stats` `app_shard_history` summary.
//!
//! At every GLOBAL frame divisible by [`ROW_FRAMES`] the index records a
//! [`Row`]: the `/shards/production` window as it read at that frame (the
//! same [`classify`] over the last [`WINDOW_FRAMES`], so a slow shard does
//! not flicker between rows), and what GLOBAL applied in the row's own
//! [`ROW_FRAMES`] frames. A row is recorded only by an index whose first
//! frame is at least [`ROW_LEAD`] frames below it: what an index knows at a
//! frame depends on no older frame (see `forget_before`), so the row is the
//! same whether a live run, a restart or the backfill computed it.
//!
//! Rows are held in memory, at most [`HISTORY_ROWS`] of them. When the node
//! names a history file, the final ones (see [`is_final`]) are saved to it
//! and restored at start ([`persist`]). After a restart the live index
//! records rows from the newest row frame at or below the head, and a
//! [`Backfill`] recomputes the older rows not held, from stored GLOBAL
//! frames and outcomes, newest day first, with what the live index leaves
//! of [`MAX_FRAMES_PER_TICK`] each tick, so the two together never read more
//! frames per tick than the index did alone.
//!
//! The live-set census (live shards, grid, effectively active members) is
//! current state, not kept per frame: only a row the live index recorded
//! within [`ROW_FRAMES`] of the head carries it (`census`), and keeps it
//! through a restart when restored from the file. Backfilled rows carry
//! `census: null`; their `producing_shards` and counts are exact.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::{
    classify, Class, ClassCounts, Decoders, FrameSource, IndexView, Kind, ProductionIndex, Summary,
    MAX_FRAMES_PER_TICK, REBUILD_FRAMES, WINDOW_FRAMES,
};

/// GLOBAL frames per row (about ten minutes).
pub const ROW_FRAMES: u64 = 60;
/// Frames an index reads below a row frame before it records that row: a
/// window, and the rebuild horizon of the window's first frame.
pub const ROW_LEAD: u64 = WINDOW_FRAMES + REBUILD_FRAMES;
/// Rows a day holds at the nominal ten-second GLOBAL frame.
pub const ROWS_PER_DAY: u64 = 144;
/// Rows held (30 days); older ones are dropped and never backfilled.
pub const HISTORY_ROWS: u64 = 30 * ROWS_PER_DAY;
/// Rows the backfill computes per segment (one day), newest segment first.
pub const SEGMENT_ROWS: u64 = ROWS_PER_DAY;
/// Most rows one request returns (one week); `bucket=epoch` is not bounded.
pub const MAX_SPAN_ROWS: u64 = 7 * ROWS_PER_DAY;
/// Cache-Control of `/shards/production/history`: about one row.
pub const CACHE_CONTROL: &str = "public, max-age=60";

pub mod persist;

/// The lowest row frame at or above `n`.
pub fn row_frame_at_or_after(n: u64) -> u64 {
    n.div_ceil(ROW_FRAMES).saturating_mul(ROW_FRAMES)
}

/// Where the live index starts: [`ROW_LEAD`] below the newest row frame at
/// or below `head`, so its rebuild ends with the row at that frame.
pub fn live_start(head: u64) -> u64 {
    (head / ROW_FRAMES * ROW_FRAMES).saturating_sub(ROW_LEAD)
}

/// The lowest row frame `index` records exactly.
pub fn first_exact_row(index: &ProductionIndex) -> u64 {
    row_frame_at_or_after(
        index
            .first_indexed
            .unwrap_or(index.start)
            .saturating_add(ROW_LEAD),
    )
}

/// The frame an advance of `index` stops at: `head`, or the next row frame
/// it records if that is lower.
pub fn advance_target(index: &ProductionIndex, head: u64) -> u64 {
    head.min(row_frame_at_or_after(index.next_frame()).max(first_exact_row(index)))
}

/// The live-set census at the row: what `/stats` `app_shards` read when the
/// live index recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Census {
    /// The head the census was read at, less than [`ROW_FRAMES`] above the
    /// row.
    pub head_frame: u64,
    /// Denominator of `classes`: the `/provers/shards` set.
    pub live_shards: u64,
    pub classes: ClassCounts,
    pub grid_shards: Option<u64>,
}

impl Census {
    pub fn of(summary: &Summary, head_frame: u64) -> Self {
        Self {
            head_frame,
            live_shards: summary.live_shards,
            classes: summary.classes.clone(),
            grid_shards: summary.grid_shards,
        }
    }
}

/// One history row: the window at `frame`, and the row's own frames
/// `frame - ROW_FRAMES + 1 ..= frame`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub frame: u64,
    pub epoch: u64,
    /// Self-reported header timestamp of `frame` (ms); `null` when missing.
    pub timestamp_ms: Option<i64>,
    pub window_complete: bool,
    pub missing_frames_in_window: u64,
    pub outcome_less_frames_in_window: u64,
    pub median_frame_interval_ms: Option<i64>,
    /// Shards the window classifies `producing`, live or not (`census`
    /// counts the live ones); while the window is incomplete, only those
    /// with an applied app frame in it (a lower bound).
    pub producing_shards: u64,
    /// Shards with a header of any outcome in the window.
    pub shards_with_headers_in_window: u64,
    /// Every shard, in the row's own frames.
    pub applied: u64,
    pub inclusions: u64,
    pub not_applied: u64,
    pub unknown_outcome: u64,
    pub drained: u64,
    pub missing_frames: u64,
    pub outcome_less_frames: u64,
    pub census: Option<Census>,
}

/// Give a live row the census of the snapshot built at `head`, when the
/// head is less than [`ROW_FRAMES`] above it.
pub fn attach_census(row: &mut Row, summary: &Summary, head: u64) {
    if head < row.frame.saturating_add(ROW_FRAMES) {
        row.census = Some(Census::of(summary, head));
    }
}

/// Whether `row`, read off `index`, is final: the index stepped over no
/// frame within [`ROW_LEAD`] below it (one never stored, or stored without
/// outcomes, once materialization passed it by the grace). Any index then
/// reads the same row from the store, now or after a restart; a row over a
/// stepped-over frame could still change should the store gain that frame
/// or its outcomes later. Only final rows are saved (see [`persist`]).
pub fn is_final(index: &ProductionIndex, row: &Row) -> bool {
    index
        .stepped_over
        .is_none_or(|n| n.saturating_add(ROW_LEAD) < row.frame)
}

/// The lowest row frame held with the live index's first row at
/// `first_live_row`: [`HISTORY_ROWS`] rows down to it.
pub fn depth_floor(first_live_row: u64) -> u64 {
    first_live_row.saturating_sub((HISTORY_ROWS - 1) * ROW_FRAMES)
}

/// The row at `index`'s last frame, read off `view` (its unadjusted view),
/// when that frame is a row frame the index records exactly.
pub fn row_of(index: &ProductionIndex, view: &IndexView) -> Option<Row> {
    let frame = index.indexed_through?;
    if frame % ROW_FRAMES != 0 || frame < first_exact_row(index) {
        return None;
    }
    let after = frame - ROW_FRAMES;
    let mut row = Row {
        frame,
        epoch: quil_types::consensus::epoch_for_frame(frame),
        timestamp_ms: index
            .window
            .back()
            .filter(|e| e.frame == frame)
            .and_then(|e| e.timestamp),
        window_complete: view.window_complete,
        missing_frames_in_window: view.missing_frames,
        outcome_less_frames_in_window: view.outcome_less_frames,
        median_frame_interval_ms: view.median_frame_interval_ms,
        producing_shards: 0,
        shards_with_headers_in_window: 0,
        applied: 0,
        inclusions: 0,
        not_applied: 0,
        unknown_outcome: 0,
        drained: 0,
        missing_frames: 0,
        outcome_less_frames: 0,
        census: None,
    };
    for shard in view.shards.values() {
        let w = &shard.window;
        if classify(view.window_complete, w.applied, w.unknown, 0) == Class::Producing {
            row.producing_shards += 1;
        }
        if w.inclusions + w.not_applied + w.unknown > 0 {
            row.shards_with_headers_in_window += 1;
        }
    }
    for entry in index.window.iter().filter(|e| e.frame > after) {
        row.missing_frames += entry.missing as u64;
        row.outcome_less_frames += entry.outcomes_missing as u64;
        for inclusion in &entry.inclusions {
            match inclusion.kind {
                Kind::Applied { new } => {
                    row.inclusions += 1;
                    row.applied += new as u64;
                }
                Kind::NotApplied => row.not_applied += 1,
                Kind::Unknown => row.unknown_outcome += 1,
                Kind::Drained => row.drained += 1,
            }
        }
    }
    Some(row)
}

/// What bounds the backfill from below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Floor {
    /// [`HISTORY_ROWS`].
    HistoryDepth,
    /// The store holds no older GLOBAL frame.
    EarliestStoredFrame,
    /// A regular node prunes older request bodies.
    RequestRetention,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct BackfillState {
    /// Every row from `floor_frame` to the live rows is held.
    pub complete: bool,
    /// The lowest row frame the backfill computes; `null` before it starts.
    pub floor_frame: Option<u64>,
    pub floor: Option<Floor>,
}

/// The rows the handlers read, by frame.
#[derive(Default)]
pub struct Rows {
    rows: BTreeMap<u64, Row>,
    /// Frames of the held rows that are not final (see [`is_final`]): they
    /// are never saved.
    provisional: BTreeSet<u64>,
    /// A final row was recorded since the last save.
    unsaved: bool,
    backfill: BackfillState,
}

/// The `/stats` `app_shard_history` object.
#[derive(Clone, Debug, Serialize)]
pub struct HistoryStats {
    pub rows: u64,
    pub first_row_frame: Option<u64>,
    pub last_row_frame: Option<u64>,
    pub backfill_complete: bool,
}

impl Rows {
    /// Hold `row` as final, dropping the oldest beyond [`HISTORY_ROWS`].
    #[cfg(test)]
    pub fn insert(&mut self, row: Row) {
        self.record(row, true);
    }

    /// Hold `row`, final or not (see [`is_final`]), dropping the oldest
    /// beyond [`HISTORY_ROWS`].
    pub fn record(&mut self, row: Row, is_final: bool) {
        if is_final {
            self.provisional.remove(&row.frame);
            self.unsaved = true;
        } else {
            self.provisional.insert(row.frame);
        }
        self.rows.insert(row.frame, row);
        self.trim();
    }

    /// Hold `saved`, final rows read back from the history file.
    pub fn restore(&mut self, saved: Vec<Row>) {
        for row in saved {
            self.provisional.remove(&row.frame);
            self.rows.insert(row.frame, row);
        }
        self.trim();
    }

    fn trim(&mut self) {
        while self.rows.len() as u64 > HISTORY_ROWS {
            if let Some((frame, _)) = self.rows.pop_first() {
                self.provisional.remove(&frame);
            }
        }
    }

    /// Drop the rows below `frame`: restored rows more than
    /// [`HISTORY_ROWS`] below the live index's first row.
    pub fn forget_below(&mut self, frame: u64) {
        self.rows = self.rows.split_off(&frame);
        self.provisional = self.provisional.split_off(&frame);
    }

    /// The final rows, ascending by frame.
    pub fn final_rows(&self) -> impl Iterator<Item = &Row> {
        self.rows
            .values()
            .filter(|row| !self.provisional.contains(&row.frame))
    }

    /// The rows held in `lo..=hi`.
    pub fn count(&self, lo: u64, hi: u64) -> u64 {
        if hi < lo {
            return 0;
        }
        self.rows.range(lo..=hi).count() as u64
    }

    /// The newest run of row frames in `lo..=hi` (both row frames) none of
    /// which is held, as `(lowest, highest)`; `None` when all are held.
    pub fn missing_run(&self, lo: u64, hi: u64) -> Option<(u64, u64)> {
        if hi < lo {
            return None;
        }
        let mut top = hi;
        for &frame in self.rows.range(lo..=hi).rev().map(|(frame, _)| frame) {
            if frame < top {
                return Some((frame + ROW_FRAMES, top));
            }
            top = top.checked_sub(ROW_FRAMES).filter(|t| *t >= lo)?;
        }
        Some((lo, top))
    }

    pub fn len(&self) -> u64 {
        self.rows.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn get(&self, frame: u64) -> Option<&Row> {
        self.rows.get(&frame)
    }

    pub fn set_backfill(&mut self, state: BackfillState) {
        self.backfill = state;
    }

    pub fn stats(&self) -> HistoryStats {
        HistoryStats {
            rows: self.len(),
            first_row_frame: self.rows.keys().next().copied(),
            last_row_frame: self.rows.keys().next_back().copied(),
            backfill_complete: self.backfill.complete,
        }
    }

    /// The response for `query`, or why it is refused.
    pub fn response(&self, query: &Query) -> Result<HistoryResponse<'_>, &'static str> {
        let first = self.rows.keys().next().copied();
        let last = self.rows.keys().next_back().copied();
        let mut out = HistoryResponse {
            row_frames: ROW_FRAMES,
            window_frames: WINDOW_FRAMES,
            epoch_frames: quil_types::consensus::epoch_length_frames(),
            bucket: query.bucket,
            first_row_frame: first,
            last_row_frame: last,
            rows_held: self.len(),
            backfill: &self.backfill,
            from_frame: None,
            to_frame: None,
            rows: None,
            epochs: None,
        };
        if let (Some(from), Some(to)) = (query.from_frame, query.to_frame) {
            if from > to {
                return Err("from_frame is above to_frame");
            }
        }
        let (Some(first), Some(last)) = (first, last) else {
            match query.bucket {
                Bucket::Row => out.rows = Some(Vec::new()),
                Bucket::Epoch => out.epochs = Some(Vec::new()),
            }
            return Ok(out);
        };
        let to = query.to_frame.unwrap_or(last);
        let from = match (query.from_frame, query.bucket) {
            (Some(from), _) => from,
            (None, Bucket::Row) => to.saturating_sub((MAX_SPAN_ROWS - 1) * ROW_FRAMES),
            (None, Bucket::Epoch) => first,
        };
        if from > to {
            return Err("from_frame is above to_frame");
        }
        let selected = self.rows.range(from..=to).map(|(_, row)| row);
        match query.bucket {
            Bucket::Row => {
                if (to - from) / ROW_FRAMES >= MAX_SPAN_ROWS {
                    return Err("the range spans more than one week of rows (1008); narrow it or use bucket=epoch");
                }
                out.rows = Some(selected.collect());
            }
            Bucket::Epoch => out.epochs = Some(rollup(selected)),
        }
        out.from_frame = Some(from);
        out.to_frame = Some(to);
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bucket {
    #[default]
    Row,
    Epoch,
}

/// `?from_frame=`, `?to_frame=` (GLOBAL frames, inclusive) and `?bucket=`
/// (`row` or `epoch`) of `/shards/production/history`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub from_frame: Option<u64>,
    pub to_frame: Option<u64>,
    pub bucket: Bucket,
}

pub fn parse_query(
    params: &std::collections::HashMap<String, String>,
) -> Result<Query, &'static str> {
    let frame = |name: &str, invalid: &'static str| match super::param(params, name) {
        None => Ok(None),
        Some(v) => v.parse::<u64>().map(Some).map_err(|_| invalid),
    };
    let bucket = match super::param(params, "bucket")
        .map(str::to_lowercase)
        .as_deref()
    {
        None | Some("row") => Bucket::Row,
        Some("epoch") => Bucket::Epoch,
        Some(_) => return Err("invalid bucket"),
    };
    Ok(Query {
        from_frame: frame("from_frame", "invalid from_frame")?,
        to_frame: frame("to_frame", "invalid to_frame")?,
        bucket,
    })
}

#[derive(Serialize)]
pub struct HistoryResponse<'a> {
    pub row_frames: u64,
    pub window_frames: u64,
    pub epoch_frames: u64,
    pub bucket: Bucket,
    /// The rows held, whatever the selection.
    pub first_row_frame: Option<u64>,
    pub last_row_frame: Option<u64>,
    pub rows_held: u64,
    pub backfill: &'a BackfillState,
    /// The selection, inclusive; `null` while no row is held.
    pub from_frame: Option<u64>,
    pub to_frame: Option<u64>,
    /// Ascending by frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<&'a Row>>,
    /// Ascending by epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epochs: Option<Vec<EpochRollup>>,
}

/// Lowest, mean (one decimal) and highest value.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Spread {
    pub min: u64,
    pub mean: f64,
    pub max: u64,
}

impl Spread {
    fn of(values: &[u64]) -> Option<Self> {
        let (min, max) = (*values.iter().min()?, *values.iter().max()?);
        let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;
        Some(Self {
            min,
            mean: (mean * 10.0).round() / 10.0,
            max,
        })
    }
}

/// The selected rows of one epoch: those recorded at its frames.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EpochRollup {
    pub epoch: u64,
    pub first_row_frame: u64,
    pub last_row_frame: u64,
    pub rows: u64,
    /// Rows whose window was complete: `producing_shards` spans only them.
    pub complete_rows: u64,
    pub producing_shards: Option<Spread>,
    /// Rows with a census: `live_shards` and `live_producing` span only them.
    pub census_rows: u64,
    pub live_shards: Option<Spread>,
    pub live_producing: Option<Spread>,
    /// Sums over the rows' own frames.
    pub applied: u64,
    pub inclusions: u64,
    pub drained: u64,
    pub missing_frames: u64,
    pub outcome_less_frames: u64,
}

fn rollup<'a>(rows: impl Iterator<Item = &'a Row>) -> Vec<EpochRollup> {
    let mut epochs: Vec<(u64, Vec<&Row>)> = Vec::new();
    for row in rows {
        match epochs.last_mut() {
            Some((epoch, group)) if *epoch == row.epoch => group.push(row),
            _ => epochs.push((row.epoch, vec![row])),
        }
    }
    epochs
        .into_iter()
        .map(|(epoch, group)| {
            let complete: Vec<u64> = group
                .iter()
                .filter(|r| r.window_complete)
                .map(|r| r.producing_shards)
                .collect();
            let census: Vec<&Census> = group.iter().filter_map(|r| r.census.as_ref()).collect();
            let live: Vec<u64> = census.iter().map(|c| c.live_shards).collect();
            let live_producing: Vec<u64> = census.iter().map(|c| c.classes.producing).collect();
            let sum = |f: fn(&Row) -> u64| group.iter().map(|r| f(r)).sum::<u64>();
            EpochRollup {
                epoch,
                first_row_frame: group[0].frame,
                last_row_frame: group[group.len() - 1].frame,
                rows: group.len() as u64,
                complete_rows: complete.len() as u64,
                producing_shards: Spread::of(&complete),
                census_rows: census.len() as u64,
                live_shards: Spread::of(&live),
                live_producing: Spread::of(&live_producing),
                applied: sum(|r| r.applied),
                inclusions: sum(|r| r.inclusions),
                drained: sum(|r| r.drained),
                missing_frames: sum(|r| r.missing_frames),
                outcome_less_frames: sum(|r| r.outcome_less_frames),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Backfill
// ---------------------------------------------------------------------------

/// The rows of one segment, computed by a fresh index from [`ROW_LEAD`]
/// below its lowest row.
struct Job {
    lo: u64,
    hi: u64,
    index: ProductionIndex,
    /// Each with whether it is final.
    rows: Vec<(Row, bool)>,
    frames: u64,
    missing: u64,
    outcome_less: u64,
    busy: Duration,
}

/// A segment the backfill finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub lo: u64,
    pub hi: u64,
    pub rows: u64,
    pub frames: u64,
    pub missing: u64,
    pub outcome_less: u64,
    /// Time spent in its steps, across ticks.
    pub busy: Duration,
}

/// What one [`Backfill::step`] did.
#[derive(Debug, Default)]
pub struct Step {
    pub indexed: u64,
    pub segment: Option<Segment>,
    /// Set by the step that finished the last segment.
    pub completed: bool,
    pub waiting: Option<u64>,
    pub error: Option<String>,
    /// The frame a failed read was for.
    pub frame: Option<u64>,
}

/// Recomputes the rows below the live index's first row that are not held
/// (restored from the history file, or kept across a task restart), newest
/// segment first, down to the floor.
pub struct Backfill {
    decoders: Decoders,
    floor_frame: u64,
    floor: Floor,
    /// The highest row of the next segment; `None` once none is left.
    next_hi: Option<u64>,
    job: Option<Job>,
    done: bool,
    pub rows: u64,
    pub frames: u64,
    pub busy: Duration,
}

impl Backfill {
    /// Plan the rows below `first_live_row`. `earliest` is the store's
    /// earliest GLOBAL frame (`None` when it holds none); `retained_from`
    /// the lowest frame whose request bodies it keeps (`None`: all).
    pub fn new(
        first_live_row: u64,
        earliest: Option<u64>,
        retained_from: Option<u64>,
        decoders: Decoders,
    ) -> Self {
        let depth = depth_floor(first_live_row);
        let (floor_frame, floor) = match earliest {
            None => (first_live_row, Floor::EarliestStoredFrame),
            Some(earliest) => {
                let pruned = retained_from.is_some_and(|r| r > earliest);
                let lowest = retained_from.map_or(earliest, |r| r.max(earliest));
                let stored = row_frame_at_or_after(lowest.saturating_add(ROW_LEAD));
                if stored > depth {
                    (
                        stored,
                        if pruned {
                            Floor::RequestRetention
                        } else {
                            Floor::EarliestStoredFrame
                        },
                    )
                } else {
                    (depth, Floor::HistoryDepth)
                }
            }
        };
        let next_hi = first_live_row
            .checked_sub(ROW_FRAMES)
            .filter(|hi| *hi >= floor_frame);
        Self {
            decoders,
            floor_frame,
            floor,
            next_hi,
            job: None,
            done: next_hi.is_none(),
            rows: 0,
            frames: 0,
            busy: Duration::ZERO,
        }
    }

    pub fn floor(&self) -> (u64, Floor) {
        (self.floor_frame, self.floor)
    }

    /// The highest row frame it computes, `None` when it computes none.
    pub fn top(&self) -> Option<u64> {
        self.job.as_ref().map(|j| j.hi).or(self.next_hi)
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn state(&self) -> BackfillState {
        BackfillState {
            complete: self.done,
            floor_frame: Some(self.floor_frame),
            floor: Some(self.floor),
        }
    }

    /// Index at most `budget` frames, publishing each segment's rows to
    /// `rows` once it is complete. Stops at a read error, or at a frame that
    /// waits for its outcomes (as the live index waits).
    pub fn step(
        &mut self,
        source: &dyn FrameSource,
        budget: u64,
        materialized: &mut dyn FnMut() -> Option<u64>,
        rows: &RwLock<Rows>,
    ) -> Step {
        let started = Instant::now();
        let mut out = Step::default();
        while out.indexed < budget && !self.done {
            if self.job.is_none() {
                let Some(top) = self.next_hi else { break };
                // A segment is the newest run of rows not held, at most a
                // day of them: held rows are not read again.
                let Some((run_lo, hi)) = rows.read().missing_run(self.floor_frame, top) else {
                    self.next_hi = None;
                    self.done = true;
                    out.completed = true;
                    continue;
                };
                let lo = run_lo.max(hi.saturating_sub((SEGMENT_ROWS - 1) * ROW_FRAMES));
                self.next_hi = lo
                    .checked_sub(ROW_FRAMES)
                    .filter(|n| *n >= self.floor_frame);
                self.job = Some(Job {
                    lo,
                    hi,
                    index: ProductionIndex::new(lo - ROW_LEAD, self.decoders),
                    rows: Vec::new(),
                    frames: 0,
                    missing: 0,
                    outcome_less: 0,
                    busy: Duration::ZERO,
                });
            }
            let job = self.job.as_mut().expect("a job");
            let target = advance_target(&job.index, job.hi);
            let advance = job
                .index
                .advance(source, target, budget - out.indexed, materialized);
            out.indexed += advance.indexed;
            job.frames += advance.indexed;
            job.missing += advance.missing.len() as u64;
            job.outcome_less += advance.outcome_less.len() as u64;
            if advance.error.is_some() || advance.waiting.is_some() {
                out.frame = Some(job.index.next_frame());
                out.error = advance.error;
                out.waiting = advance.waiting;
                break;
            }
            if job.index.indexed_through() != Some(target) {
                break;
            }
            if let Some(row) = row_of(&job.index, &job.index.view()) {
                let settled = is_final(&job.index, &row);
                job.rows.push((row, settled));
            }
            if target == job.hi {
                let mut job = self.job.take().expect("a job");
                job.busy += started.elapsed();
                let segment = Segment {
                    lo: job.lo,
                    hi: job.hi,
                    rows: job.rows.len() as u64,
                    frames: job.frames,
                    missing: job.missing,
                    outcome_less: job.outcome_less,
                    busy: job.busy,
                };
                {
                    let mut held = rows.write();
                    for (row, settled) in job.rows {
                        if !held.rows.contains_key(&row.frame) {
                            held.record(row, settled);
                        }
                    }
                }
                self.rows += segment.rows;
                self.frames += segment.frames;
                self.busy += segment.busy;
                self.done = self.next_hi.is_none();
                out.completed = self.done;
                out.segment = Some(segment);
                break;
            }
        }
        let elapsed = started.elapsed();
        if let Some(job) = self.job.as_mut() {
            job.busy += elapsed;
        } else if out.segment.is_none() {
            self.busy += elapsed;
        }
        out
    }
}

/// The frames per tick the backfill may read: what the live index left.
pub fn budget(live_indexed: u64) -> u64 {
    MAX_FRAMES_PER_TICK.saturating_sub(live_indexed)
}

#[cfg(test)]
mod tests;
