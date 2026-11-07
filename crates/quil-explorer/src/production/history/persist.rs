//! Final history rows saved to a file, so a restart restores them and the
//! [`Backfill`](super::Backfill) recomputes only the rows the file lacks.
//!
//! The node names the file (`ExplorerState::with_history_file`). Only final
//! rows ([`super::is_final`]) are saved: any index reads them the same from
//! the store, so a restored row is the row a backfill would recompute, and
//! a live row keeps the census it was recorded with. The file is JSON: its
//! [`FORMAT`], the [`Params`] its rows were computed with and the rows,
//! ascending. A file of another format or parameters (expected after an
//! upgrade that changes rows) is ignored; so, with a warning, is one that
//! cannot be read, is malformed, or whose newest row the store does not
//! hold with the same timestamp (another chain or store). The rows are then
//! rebuilt from stored GLOBAL frames; the node never fails over the file.
//! It is written whole, to a temporary file renamed over it, at most once
//! per [`SAVE_INTERVAL`] while final rows arrive, and at a clean shutdown.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::{Row, Rows, HISTORY_ROWS, ROW_FRAMES};
use crate::production::{FrameSource, REBUILD_FRAMES, WINDOW_FRAMES};

/// Version of the file and of the rows' computation: bump it with any
/// change to [`Row`] or to how a row is computed, so that a node never
/// serves rows an older build saved.
pub const FORMAT: u32 = 1;
/// Largest file read: [`HISTORY_ROWS`] rows with a census take about 2 MB.
pub const MAX_FILE_BYTES: u64 = 16 << 20;
/// Final rows are saved at most this often while they arrive.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(60);

/// What the rows were computed with: a file computed otherwise is ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    pub network: u8,
    pub row_frames: u64,
    pub window_frames: u64,
    pub rebuild_frames: u64,
    pub epoch_frames: u64,
    pub history_rows: u64,
}

impl Params {
    /// This build's, on `network`.
    pub fn current(network: u8) -> Self {
        Self {
            network,
            row_frames: ROW_FRAMES,
            window_frames: WINDOW_FRAMES,
            rebuild_frames: REBUILD_FRAMES,
            epoch_frames: quil_types::consensus::epoch_length_frames(),
            history_rows: HISTORY_ROWS,
        }
    }
}

/// The format alone, read first: rows of another format may not parse.
#[derive(Deserialize)]
struct Format {
    format: u32,
}

#[derive(Serialize, Deserialize)]
struct Saved<R> {
    format: u32,
    params: Params,
    rows: Vec<R>,
}

/// What [`HistoryFile::load`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Loaded {
    /// No file yet.
    Absent,
    /// Saved with another format or parameters.
    Outdated(String),
    /// Unreadable, malformed, or not of this store's chain.
    Invalid(String),
    Rows(Vec<Row>),
}

/// Where the history rows are saved, and the network they are of.
#[derive(Clone, Debug)]
pub struct HistoryFile {
    pub path: PathBuf,
    pub network: u8,
}

impl HistoryFile {
    pub fn new(path: PathBuf, network: u8) -> Self {
        Self { path, network }
    }

    /// The file's contents for `rows`, ascending by frame.
    pub fn encode(&self, rows: &[&Row]) -> std::io::Result<Vec<u8>> {
        let saved = Saved {
            format: FORMAT,
            params: Params::current(self.network),
            rows: rows.to_vec(),
        };
        serde_json::to_vec(&saved).map_err(std::io::Error::other)
    }

    /// Replace the file with `body`: written beside it, synced, renamed over it.
    pub fn write(&self, body: &[u8]) -> std::io::Result<()> {
        let pending = self.path.with_extension("pending");
        let mut file = std::fs::File::create(&pending)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&pending, &self.path)?;
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// The saved rows, or why there are none; the newest is checked against
    /// the GLOBAL frame `source` holds at it.
    pub fn load(&self, source: &dyn FrameSource) -> Loaded {
        let len = match std::fs::metadata(&self.path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Absent,
            Err(e) => return Loaded::Invalid(format!("cannot read it: {e}")),
        };
        if len > MAX_FILE_BYTES {
            return Loaded::Invalid(format!("{len} bytes, more than the {MAX_FILE_BYTES} read"));
        }
        let body = match std::fs::read(&self.path) {
            Ok(body) => body,
            Err(e) => return Loaded::Invalid(format!("cannot read it: {e}")),
        };
        match serde_json::from_slice::<Format>(&body) {
            Ok(f) if f.format != FORMAT => {
                return Loaded::Outdated(format!("format {}, this build reads {FORMAT}", f.format));
            }
            Ok(_) => {}
            Err(e) => return Loaded::Invalid(format!("malformed: {e}")),
        }
        let saved: Saved<Row> = match serde_json::from_slice(&body) {
            Ok(saved) => saved,
            Err(e) => return Loaded::Invalid(format!("malformed: {e}")),
        };
        let current = Params::current(self.network);
        if saved.params != current {
            return Loaded::Outdated(format!(
                "computed with {:?}, this node computes {current:?}",
                saved.params
            ));
        }
        let ordered = saved.rows.iter().all(|r| r.frame % ROW_FRAMES == 0)
            && saved.rows.windows(2).all(|w| w[0].frame < w[1].frame);
        if !ordered || saved.rows.len() as u64 > HISTORY_ROWS {
            return Loaded::Invalid(format!(
                "{} rows, not ascending row frames at most {HISTORY_ROWS} of them",
                saved.rows.len()
            ));
        }
        let Some(newest) = saved.rows.last() else {
            return Loaded::Rows(Vec::new());
        };
        let stored = match source.frame(newest.frame) {
            Ok(frame) => frame
                .and_then(|f| f.header)
                .filter(|h| h.frame_number == newest.frame)
                .map(|h| h.timestamp),
            Err(e) => {
                return Loaded::Invalid(format!(
                    "cannot read GLOBAL frame {} to check it: {e}",
                    newest.frame
                ))
            }
        };
        match stored {
            None => Loaded::Invalid(format!("the store lacks GLOBAL frame {}, its newest row's", newest.frame)),
            Some(timestamp) if Some(timestamp) != newest.timestamp_ms => Loaded::Invalid(format!(
                "the store's GLOBAL frame {} has another timestamp than its newest row: another chain or store",
                newest.frame
            )),
            Some(_) => Loaded::Rows(saved.rows),
        }
    }
}

/// Restore the saved rows into `rows`, before the indexer's first tick, and
/// log what was found.
pub fn restore(file: &HistoryFile, source: &dyn FrameSource, rows: &RwLock<Rows>) {
    match file.load(source) {
        Loaded::Rows(saved) if !saved.is_empty() => {
            let (count, first_row, last_row) = (saved.len(), saved[0].frame, saved[saved.len() - 1].frame);
            rows.write().restore(saved);
            tracing::info!(
                rows = count,
                first_row,
                last_row,
                backfill_from = last_row + ROW_FRAMES,
                "explorer production history restored from its file: the backfill recomputes only the rows \
                 it lacks, from backfill_from up to the live index (and any missing below)",
            );
        }
        Loaded::Rows(_) | Loaded::Absent => tracing::info!(
            "explorer production history file absent or empty: rows are rebuilt from stored GLOBAL frames \
             and outcomes, and saved as they complete"
        ),
        Loaded::Outdated(reason) => tracing::info!(
            reason = %reason,
            "explorer production history file was saved by a build that computes rows otherwise: ignored; \
             rows are rebuilt from stored GLOBAL frames and outcomes",
        ),
        Loaded::Invalid(reason) => tracing::warn!(
            reason = %reason,
            "explorer production history file ignored; rows are rebuilt from stored GLOBAL frames and \
             outcomes, and the file is replaced as they complete",
        ),
    }
}

/// Saves the final rows: at most once per [`SAVE_INTERVAL`] while new ones
/// arrive, and at shutdown.
#[derive(Default)]
pub struct Saver {
    last: Option<Instant>,
    /// Why the last save failed; `None` once one succeeds.
    failing: Option<String>,
    saved: bool,
}

impl Saver {
    /// Save when a final row was recorded since the last save, at most once
    /// per [`SAVE_INTERVAL`].
    pub fn save_due(&mut self, file: &HistoryFile, rows: &RwLock<Rows>, now: Instant) {
        let recent = self
            .last
            .is_some_and(|at| now.saturating_duration_since(at) < SAVE_INTERVAL);
        if recent || !rows.read().unsaved {
            return;
        }
        self.last = Some(now);
        self.save(file, rows, false);
    }

    /// Save the final rows recorded since the last save.
    pub fn save_at_shutdown(&mut self, file: &HistoryFile, rows: &RwLock<Rows>) {
        if rows.read().unsaved {
            self.save(file, rows, true);
        }
    }

    fn save(&mut self, file: &HistoryFile, rows: &RwLock<Rows>, shutdown: bool) {
        let (body, count, last_row) = {
            let held = rows.read();
            let saved: Vec<&Row> = held.final_rows().collect();
            (
                file.encode(&saved),
                saved.len(),
                saved.last().map(|r| r.frame),
            )
        };
        match body.and_then(|body| file.write(&body).map(|()| body.len())) {
            Ok(bytes) => {
                // Only the indexer records rows, and it is the caller: none
                // arrived since they were read.
                rows.write().unsaved = false;
                if shutdown || !self.saved || self.failing.is_some() {
                    tracing::info!(
                        rows = count,
                        last_row = ?last_row,
                        bytes,
                        shutdown,
                        "explorer production history saved: final rows are saved as they complete, at most \
                         once a minute, and at shutdown, so a restart backfills only the rows after them",
                    );
                }
                self.saved = true;
                self.failing = None;
            }
            Err(e) => {
                let reason = e.to_string();
                if self.failing.as_ref() != Some(&reason) {
                    tracing::warn!(
                        error = %reason,
                        "explorer production history cannot be saved; retrying once a minute while rows \
                         arrive (a restart backfills the rows not saved)",
                    );
                }
                self.failing = Some(reason);
            }
        }
    }
}

/// A history file path of a test's own, removed on drop.
#[cfg(test)]
pub(crate) struct TempPath(pub PathBuf);

#[cfg(test)]
impl TempPath {
    pub fn new(tag: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "quil-explorer-history-{}-{tag}.json",
            std::process::id()
        )))
    }

    pub fn file(&self) -> HistoryFile {
        HistoryFile::new(self.0.clone(), 0)
    }
}

#[cfg(test)]
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("pending"));
    }
}
