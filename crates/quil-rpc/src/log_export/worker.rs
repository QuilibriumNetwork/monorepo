//! A standalone worker's part of a diagnostics log bundle: the master asks
//! it over the worker channel (`DataIPCService.ExportLogs`) for the lines of
//! its own log files, which the master redacts together with its own
//! ([`super::produce`]).
//!
//! The worker selects records as the master's export does and keeps the
//! newest that fit the byte cap the master gives it, then sends a summary
//! followed by the lines in bounded messages. The lines leave the worker
//! unredacted, over the mutually authenticated worker channel only, so one
//! redactor at the master tokenizes every host's values alike; the
//! worker's host and user names go along in the summary for that redactor.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Instant;

use quil_types::proto::node::{
    ExportWorkerLogsChunk, ExportWorkerLogsRequest, ExportWorkerLogsSummary,
};
use tonic::Status;
use tracing::{info, warn};

use super::{
    core_file_readers, live_head_digest, local_literals, Merger, Record, Selection, MAX_WINDOW_SECS,
};

/// Line bytes per streamed message.
pub const CHUNK_BYTES: usize = 256 * 1024;
/// The most line bytes a worker sends for one request, whatever it asks.
pub const MAX_WORKER_BYTES: u64 = 256 * 1024 * 1024;
/// Shard filters and texts a request may carry.
const MAX_FILTERS: usize = 64;
const MAX_MATCHES: usize = 16;
/// Records read between looks at whether the master still listens.
const STOP_CHECK_RECORDS: u64 = 256;
/// Messages queued for the master at once.
const QUEUED_CHUNKS: usize = 4;

/// The export selection of `request`: its window, level and filters.
pub fn request_selection(request: &ExportWorkerLogsRequest) -> Result<Selection, Status> {
    let invalid = || Status::invalid_argument("the window must lie within a day, start first");
    let since = i64::try_from(request.since_unix).map_err(|_| invalid())?;
    let until = i64::try_from(request.until_unix).map_err(|_| invalid())?;
    if since >= until || until - since > MAX_WINDOW_SECS {
        return Err(invalid());
    }
    if request.filters.len() > MAX_FILTERS || request.matches.len() > MAX_MATCHES {
        return Err(Status::invalid_argument("too many shard filters or texts"));
    }
    Ok(Selection {
        since,
        until,
        min_level: u8::try_from(request.min_level).unwrap_or(u8::MAX),
        filters: request.filters.iter().map(hex::encode).collect(),
        matches: request.matches.clone(),
    })
}

/// What a worker sends for one request: its summary, then its lines.
#[derive(Debug, Default)]
pub struct WorkerExport {
    pub summary: ExportWorkerLogsSummary,
    pub lines: Vec<u8>,
}

/// The bytes `record` takes as lines.
fn record_bytes(record: &Record) -> u64 {
    record.lines.iter().map(|line| line.len() as u64 + 1).sum()
}

/// The lines of `core`'s own log files in `dir` (`None`: the worker writes
/// none) that `request` selects, the newest that fit its `max_bytes`, and
/// the host and user names of `home_paths` and this process. A worker whose
/// live file starts like the master's (`master_head`) writes the master's
/// directory and sends nothing. Stops once `stop` returns true.
pub fn export(
    dir: Option<&Path>,
    core: u32,
    request: &ExportWorkerLogsRequest,
    home_paths: &[PathBuf],
    stop: &dyn Fn() -> bool,
) -> Result<WorkerExport, Status> {
    let selection = request_selection(request)?;
    let mut summary = ExportWorkerLogsSummary::default();
    for (class, value) in local_literals(home_paths) {
        if class == "host" {
            summary.hosts.push(value);
        } else {
            summary.users.push(value);
        }
    }
    let Some(dir) = dir else {
        summary.no_log_files = true;
        return Ok(WorkerExport {
            summary,
            lines: Vec::new(),
        });
    };
    if !request.master_head.is_empty()
        && live_head_digest(dir, core).is_some_and(|head| head[..] == request.master_head[..])
    {
        summary.same_files = true;
        return Ok(WorkerExport {
            summary,
            lines: Vec::new(),
        });
    }
    let (readers, names) = core_file_readers(dir, core, selection.since, selection.until)
        .map_err(|error| {
            warn!(core, error = %format!("{error:#}"), scope = "this worker", action = "check that the worker can read its log directory",
                "diagnostics log export for the master failed: the log directory cannot be read");
            Status::failed_precondition("the worker cannot read its log directory")
        })?;
    summary.files = names;
    let cap = request.max_bytes.min(MAX_WORKER_BYTES);
    let mut kept: VecDeque<(u64, Record)> = VecDeque::new();
    let mut held = 0u64;
    let mut selected = 0u64;
    let mut merger = Merger::new(readers);
    for record in merger.by_ref() {
        if summary.records_read % STOP_CHECK_RECORDS == 0 && stop() {
            return Err(Status::cancelled("the master stopped waiting"));
        }
        summary.records_read += 1;
        if !selection.keeps(&record) {
            continue;
        }
        selected += 1;
        let size = record_bytes(&record);
        held += size;
        kept.push_back((size, record));
        while held > cap {
            let Some((size, _)) = kept.pop_front() else {
                break;
            };
            held -= size;
            summary.records_dropped += 1;
            summary.bytes_dropped += size;
        }
    }
    summary.lines_read = merger.lines_read();
    summary.read_errors = merger.errors();
    summary.records_kept = selected - summary.records_dropped;
    let mut lines = Vec::with_capacity(usize::try_from(held).unwrap_or(0));
    for (_, record) in kept {
        for line in record.lines {
            lines.extend_from_slice(line.as_bytes());
            lines.push(b'\n');
        }
    }
    summary.line_bytes = lines.len() as u64;
    Ok(WorkerExport { summary, lines })
}

impl WorkerExport {
    /// The messages that carry it: the summary, then the lines in messages
    /// of at most [`CHUNK_BYTES`].
    pub fn into_chunks(self) -> Chunks {
        Chunks {
            summary: Some(self.summary),
            lines: self.lines,
            offset: 0,
        }
    }
}

/// The messages of a [`WorkerExport`], copied out one at a time.
#[derive(Debug)]
pub struct Chunks {
    summary: Option<ExportWorkerLogsSummary>,
    lines: Vec<u8>,
    offset: usize,
}

impl Iterator for Chunks {
    type Item = ExportWorkerLogsChunk;

    fn next(&mut self) -> Option<ExportWorkerLogsChunk> {
        if let Some(summary) = self.summary.take() {
            return Some(ExportWorkerLogsChunk {
                summary: Some(summary),
                lines: Vec::new(),
            });
        }
        if self.offset >= self.lines.len() {
            return None;
        }
        let end = self.lines.len().min(self.offset + CHUNK_BYTES);
        let lines = self.lines[self.offset..end].to_vec();
        self.offset = end;
        Some(ExportWorkerLogsChunk {
            summary: None,
            lines,
        })
    }
}

/// Run [`export`] off the async runtime and stream its messages, as the
/// worker answers `ExportLogs`; the export stops once the receiver is
/// dropped. Logs one line per export.
pub fn spawn_export(
    dir: Option<PathBuf>,
    core: u32,
    request: ExportWorkerLogsRequest,
    home_paths: Vec<PathBuf>,
) -> tokio::sync::mpsc::Receiver<Result<ExportWorkerLogsChunk, Status>> {
    let (tx, rx) = tokio::sync::mpsc::channel(QUEUED_CHUNKS);
    tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        let stop = || tx.is_closed();
        let exported = export(dir.as_deref(), core, &request, &home_paths, &stop);
        let export = match exported {
            Ok(export) => export,
            Err(status) => {
                let _ = tx.blocking_send(Err(status));
                return;
            }
        };
        let summary = &export.summary;
        let (files, records, bytes, dropped, same_files) = (
            summary.files.len(),
            summary.records_kept,
            summary.line_bytes,
            summary.records_dropped,
            summary.same_files,
        );
        let elapsed_ms = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        for chunk in export.into_chunks() {
            if tx.blocking_send(Ok(chunk)).is_err() {
                let duration_ms = elapsed_ms();
                info!(
                    core,
                    files,
                    records,
                    bytes,
                    duration_ms,
                    "diagnostics log export for the master stopped: the master stopped waiting"
                );
                return;
            }
        }
        let duration_ms = elapsed_ms();
        info!(
            core,
            files,
            records,
            bytes,
            records_dropped = dropped,
            same_files,
            duration_ms,
            "diagnostics log lines sent to the master for its log bundle"
        );
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write as _;

    fn line(time: &str, level: &str, message: &str, fields: &str) -> String {
        format!("2026-10-17T{time}Z\t{level}\tquil_node/src/main.rs:7\t{message}\t{fields}\n")
    }

    fn whole_day(max_bytes: u64) -> ExportWorkerLogsRequest {
        ExportWorkerLogsRequest {
            since_unix: super::super::redact::parse_rfc3339_utc("2026-10-17T00:00:00Z").unwrap()
                as u64,
            until_unix: super::super::redact::parse_rfc3339_utc("2026-10-17T23:59:59Z").unwrap()
                as u64,
            max_bytes,
            ..Default::default()
        }
    }

    fn messages(text: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(text)
            .lines()
            .map(|l| l.split('\t').nth(3).unwrap_or(l).to_string())
            .collect()
    }

    fn never() -> bool {
        false
    }

    /// The worker reads its own core's live and rotated (gzipped) files in
    /// time order, never another core's, and keeps what the master's
    /// selection keeps: the filter's lines plus every warning.
    #[test]
    fn a_worker_exports_its_own_cores_files_as_selected() {
        let dir = tempfile::tempdir().unwrap();
        let filter = [0xa1u8; 32];
        let f = format!(r#"{{"filter":"{}"}}"#, hex::encode(filter));
        let mut gz = GzEncoder::new(
            std::fs::File::create(dir.path().join("worker-3.log.20261017T120000.gz")).unwrap(),
            Compression::default(),
        );
        gz.write_all(
            [
                line("11:00:00", "info", "w-old", &f),
                line("11:10:00", "info", "w-other-shard", "{}"),
            ]
            .concat()
            .as_bytes(),
        )
        .unwrap();
        gz.finish().unwrap();
        std::fs::write(
            dir.path().join("worker-3.log"),
            [
                line("12:10:00", "warn", "w-warn", "{}"),
                line("12:20:00", "info", "w-new", &f),
            ]
            .concat(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("worker-4.log"),
            line("12:15:00", "info", "other-core", &f),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("master.log"),
            line("12:16:00", "info", "master", &f),
        )
        .unwrap();
        let request = ExportWorkerLogsRequest {
            filters: vec![filter.to_vec()],
            ..whole_day(1 << 20)
        };
        let export = export(Some(dir.path()), 3, &request, &[], &never).unwrap();
        assert_eq!(messages(&export.lines), ["w-old", "w-warn", "w-new"]);
        let summary = &export.summary;
        assert_eq!(
            (
                summary.records_read,
                summary.records_kept,
                summary.records_dropped,
                summary.line_bytes
            ),
            (4, 3, 0, export.lines.len() as u64)
        );
        assert_eq!(summary.files.len(), 2, "{:?}", summary.files);
        assert!(summary
            .files
            .iter()
            .all(|name| name.starts_with("worker-3.log")));
        assert!(!summary.same_files && !summary.no_log_files);
    }

    /// Past its byte cap the worker leaves out its oldest records and
    /// counts them; the messages carry the summary first, then the lines in
    /// bounded pieces that concatenate to them.
    #[test]
    fn the_cap_keeps_the_newest_records_and_chunks_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let lines: Vec<String> = (0..10)
            .map(|i| line(&format!("12:{i:02}:00"), "info", &format!("m{i}"), "{}"))
            .collect();
        let each = lines[0].len() as u64;
        std::fs::write(dir.path().join("worker-1.log"), lines.concat()).unwrap();
        let export = export(Some(dir.path()), 1, &whole_day(3 * each), &[], &never).unwrap();
        assert_eq!(messages(&export.lines), ["m7", "m8", "m9"]);
        assert_eq!(
            (
                export.summary.records_kept,
                export.summary.records_dropped,
                export.summary.bytes_dropped
            ),
            (3, 7, 7 * each)
        );

        let big = WorkerExport {
            summary: ExportWorkerLogsSummary {
                line_bytes: (2 * CHUNK_BYTES + 5) as u64,
                ..Default::default()
            },
            lines: vec![b'x'; 2 * CHUNK_BYTES + 5],
        };
        let chunks: Vec<_> = big.into_chunks().collect();
        assert_eq!(chunks.len(), 4);
        assert!(chunks[0].summary.is_some() && chunks[0].lines.is_empty());
        assert!(chunks[1..]
            .iter()
            .all(|c| c.summary.is_none() && c.lines.len() <= CHUNK_BYTES));
        assert_eq!(
            chunks.iter().map(|c| c.lines.len()).sum::<usize>(),
            2 * CHUNK_BYTES + 5
        );
    }

    /// A worker writing the master's own directory answers that it does
    /// and sends nothing; one writing no files says so; a bad window is
    /// refused; a master that stops waiting stops the export.
    #[test]
    fn shared_missing_and_refused_exports_send_no_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("worker-2.log"),
            [
                line("12:00:00", "info", "first", "{}"),
                line("12:01:00", "info", "second", "{}"),
            ]
            .concat(),
        )
        .unwrap();
        let head = live_head_digest(dir.path(), 2).unwrap();
        let shared = ExportWorkerLogsRequest {
            master_head: head.to_vec(),
            ..whole_day(1 << 20)
        };
        let export_shared = export(Some(dir.path()), 2, &shared, &[], &never).unwrap();
        assert!(export_shared.summary.same_files && export_shared.lines.is_empty());
        let other = ExportWorkerLogsRequest {
            master_head: vec![0; 32],
            ..whole_day(1 << 20)
        };
        assert_eq!(
            messages(
                &export(Some(dir.path()), 2, &other, &[], &never)
                    .unwrap()
                    .lines
            ),
            ["first", "second"],
            "another host's file of the same core is not this one"
        );
        let none = export(None, 2, &whole_day(1 << 20), &[], &never).unwrap();
        assert!(none.summary.no_log_files && none.lines.is_empty());
        let backwards = ExportWorkerLogsRequest {
            since_unix: 10,
            until_unix: 5,
            ..Default::default()
        };
        assert_eq!(
            export(Some(dir.path()), 2, &backwards, &[], &never)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            export(Some(dir.path()), 2, &whole_day(1 << 20), &[], &|| true)
                .unwrap_err()
                .code(),
            tonic::Code::Cancelled
        );
        assert!(live_head_digest(dir.path(), 9).is_none());
    }

    /// The streamed answer is the summary and then every line.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_spawned_export_streams_the_summary_then_the_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("worker-5.log"),
            line("12:00:00", "info", "streamed", "{}"),
        )
        .unwrap();
        let mut rx = spawn_export(
            Some(dir.path().to_path_buf()),
            5,
            whole_day(1 << 20),
            Vec::new(),
        );
        let first = rx.recv().await.unwrap().unwrap();
        let summary = first.summary.expect("the summary comes first");
        let mut lines = first.lines;
        while let Some(chunk) = rx.recv().await {
            let chunk = chunk.unwrap();
            assert!(chunk.summary.is_none());
            lines.extend_from_slice(&chunk.lines);
        }
        assert_eq!(summary.line_bytes, lines.len() as u64);
        assert_eq!(messages(&lines), ["streamed"]);
    }
}
