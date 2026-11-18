//! Standalone workers' lines in this node's log bundles.
//!
//! A standalone worker (`quil-node --core=N`, reached through
//! `engine.dataWorkerStreamMultiaddrs`) writes its `worker-N.log` to its own
//! host. Before this node exports a request's window from its own log
//! files, it asks each standalone worker for its lines of that window over
//! the worker channel (`DataIPCService.ExportLogs`), all at once and each
//! within [`WORKER_EXPORT_TIMEOUT`]. The lines join the export unredacted,
//! so one redactor tokenizes every host's values alike, and the manifest
//! records what became of each worker: collected, truncated, local (its
//! lines are in this node's own files), no log files, unreachable,
//! unsupported (a build without the call) or failed.

use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use tonic::transport::Channel;
use tonic::{Code, Status};
use tracing::info;

use quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient;
use quil_types::proto::node::{
    ExportWorkerLogsChunk, ExportWorkerLogsRequest, ExportWorkerLogsSummary,
};

use super::bundle::AutoRequest;
use crate::log_export;

/// How long one worker's export may take, its call and every message.
pub const WORKER_EXPORT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Line bytes the standalone workers may send for one bundle together: four
/// times `maxBundleBytes`, as log text gzips about tenfold, and at most
/// this; each worker gets an equal share, at least `MIN_SHARE`.
const MAX_LINES_TOTAL: u64 = 256 * 1024 * 1024;
const MIN_SHARE: u64 = 64 * 1024;
/// The largest message decoded from a worker: a message of lines and its
/// framing, or a summary.
const MAX_MESSAGE_BYTES: usize = 2 * log_export::worker::CHUNK_BYTES;

/// A worker's `ExportLogs` messages.
pub type ChunkStream =
    Pin<Box<dyn futures::Stream<Item = Result<ExportWorkerLogsChunk, Status>> + Send>>;

/// This node's standalone workers, as a bundle asks them for their lines.
#[tonic::async_trait]
pub trait WorkerLogSource: Send + Sync {
    /// The cores of this node's standalone workers.
    fn cores(&self) -> Vec<u32>;

    /// Open worker `core`'s `ExportLogs` stream.
    async fn export_logs(
        &self,
        core: u32,
        request: ExportWorkerLogsRequest,
    ) -> Result<ChunkStream, Status>;
}

/// Standalone workers reached over the worker channels this node's worker
/// manager holds: `channels` lists each worker's core and its channel, or
/// why the worker cannot be asked (not connected, or a channel without
/// mTLS, which never carries logs).
pub struct DataIpcWorkers<F> {
    channels: F,
}

impl<F> DataIpcWorkers<F>
where
    F: Fn() -> Vec<(u32, Result<Channel, Status>)> + Send + Sync,
{
    pub fn new(channels: F) -> Self {
        Self { channels }
    }
}

#[tonic::async_trait]
impl<F> WorkerLogSource for DataIpcWorkers<F>
where
    F: Fn() -> Vec<(u32, Result<Channel, Status>)> + Send + Sync,
{
    fn cores(&self) -> Vec<u32> {
        (self.channels)()
            .into_iter()
            .map(|(core, _)| core)
            .collect()
    }

    async fn export_logs(
        &self,
        core: u32,
        request: ExportWorkerLogsRequest,
    ) -> Result<ChunkStream, Status> {
        let channel = (self.channels)()
            .into_iter()
            .find(|(c, _)| *c == core)
            .map(|(_, channel)| channel)
            .unwrap_or_else(|| Err(Status::unavailable("worker not registered")))?;
        let mut client =
            DataIpcServiceClient::new(channel).max_decoding_message_size(MAX_MESSAGE_BYTES);
        let stream = client.export_logs(request).await?.into_inner();
        Ok(Box::pin(stream))
    }
}

/// What became of one standalone worker's lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerStatus {
    /// Its lines came, all or the newest that fit its share.
    Collected,
    /// It writes this node's log directory: its lines are in this node's
    /// own files.
    Local,
    /// It writes no log files.
    NoLogFiles,
    /// Not connected, or it did not answer.
    Unreachable(String),
    /// Its build lacks `ExportLogs`.
    Unsupported,
    /// It answered with an error, or broke off; the lines that came are
    /// kept.
    Failed(String),
}

/// One standalone worker's part of a bundle.
#[derive(Debug, Clone)]
pub struct WorkerLog {
    pub core: u32,
    pub status: WorkerStatus,
    /// Its summary, when it sent one.
    pub summary: Option<ExportWorkerLogsSummary>,
    /// The line bytes it sent, unredacted.
    pub lines: Arc<[u8]>,
    /// The full error, for this node's own log only: the manifest names the
    /// error class alone, as a transport error may name an address.
    pub detail: Option<String>,
}

impl WorkerLog {
    fn without_lines(core: u32, status: WorkerStatus, detail: Option<String>) -> Self {
        WorkerLog {
            core,
            status,
            summary: None,
            lines: Arc::from(Vec::new()),
            detail,
        }
    }

    /// The status name in the manifest, given the bytes the bundle left
    /// out to fit its cap.
    pub fn status_name(&self, trimmed: u64) -> &'static str {
        match &self.status {
            WorkerStatus::Collected
                if trimmed > 0
                    || self
                        .summary
                        .as_ref()
                        .is_some_and(|summary| summary.records_dropped > 0) =>
            {
                "truncated"
            }
            WorkerStatus::Collected => "collected",
            WorkerStatus::Local => "local",
            WorkerStatus::NoLogFiles => "no_log_files",
            WorkerStatus::Unreachable(_) => "unreachable",
            WorkerStatus::Unsupported => "unsupported",
            WorkerStatus::Failed(_) => "failed",
        }
    }
}

/// Line bytes each of `workers` standalone workers may send for a bundle of
/// at most `max_bundle` bytes.
pub fn worker_share(max_bundle: usize, workers: usize) -> u64 {
    let total = (max_bundle as u64).saturating_mul(4).min(MAX_LINES_TOTAL);
    (total / workers.max(1) as u64).max(MIN_SHARE)
}

/// What a failed call says in the manifest: its class, and the text of
/// the refusals this code makes itself (a worker's or this node's), never a
/// transport error's text.
fn status_reason(status: &Status) -> String {
    match status.code() {
        Code::InvalidArgument | Code::FailedPrecondition | Code::Cancelled => {
            status.message().to_string()
        }
        code => code.description().to_string(),
    }
}

/// How worker `core` answered `request`: its summary and lines, or why
/// not. Stops once `cancel` is set.
async fn fetch(
    source: &dyn WorkerLogSource,
    core: u32,
    request: ExportWorkerLogsRequest,
    cancel: &AtomicBool,
) -> WorkerLog {
    let max_bytes = request.max_bytes;
    let mut stream = match source.export_logs(core, request).await {
        Ok(stream) => stream,
        Err(status) => {
            let detail = Some(format!("{:?}: {}", status.code(), status.message()));
            let status = match status.code() {
                Code::Unimplemented => WorkerStatus::Unsupported,
                Code::Unavailable | Code::DeadlineExceeded => {
                    WorkerStatus::Unreachable(status_reason(&status))
                }
                _ => WorkerStatus::Failed(status_reason(&status)),
            };
            return WorkerLog::without_lines(core, status, detail);
        }
    };
    let mut summary: Option<ExportWorkerLogsSummary> = None;
    let mut lines = Vec::new();
    let mut failure: Option<(String, String)> = None;
    while let Some(message) = stream.next().await {
        if cancel.load(Ordering::Relaxed) {
            let reason = "the request was denied or timed out meanwhile".to_string();
            failure = Some((reason.clone(), reason));
            break;
        }
        let chunk = match message {
            Ok(chunk) => chunk,
            Err(status) => {
                failure = Some((
                    status_reason(&status),
                    format!("{:?}: {}", status.code(), status.message()),
                ));
                break;
            }
        };
        if let Some(first) = chunk.summary {
            if summary.is_some() {
                let reason = "the worker sent a second summary".to_string();
                failure = Some((reason.clone(), reason));
                break;
            }
            if first.line_bytes > max_bytes {
                let reason = format!(
                    "the worker announced {} line bytes, over its share of {max_bytes}",
                    first.line_bytes
                );
                failure = Some((reason.clone(), reason));
                break;
            }
            summary = Some(first);
        }
        let Some(announced) = summary.as_ref().map(|summary| summary.line_bytes) else {
            let reason = "the worker sent lines before its summary".to_string();
            failure = Some((reason.clone(), reason));
            break;
        };
        if (lines.len() + chunk.lines.len()) as u64 > announced {
            let reason = "the worker sent more line bytes than it announced".to_string();
            failure = Some((reason.clone(), reason));
            break;
        }
        lines.extend_from_slice(&chunk.lines);
    }
    let Some(summary) = summary else {
        let (reason, detail) = failure.unwrap_or_else(|| {
            let reason = "the worker sent no summary".to_string();
            (reason.clone(), reason)
        });
        return WorkerLog::without_lines(core, WorkerStatus::Failed(reason), Some(detail));
    };
    if failure.is_none() && lines.len() as u64 != summary.line_bytes {
        let reason = format!(
            "the worker announced {} line bytes and sent {}",
            summary.line_bytes,
            lines.len()
        );
        failure = Some((reason.clone(), reason));
    }
    let (status, detail) = match failure {
        Some((reason, detail)) => (WorkerStatus::Failed(reason), Some(detail)),
        None if summary.same_files => (WorkerStatus::Local, None),
        None if summary.no_log_files => (WorkerStatus::NoLogFiles, None),
        None => (WorkerStatus::Collected, None),
    };
    WorkerLog {
        core,
        status,
        summary: Some(summary),
        lines: Arc::from(lines),
        detail,
    }
}

/// Ask every standalone worker of `source` for its lines of `request`'s
/// window and filters, all at once, each within [`WORKER_EXPORT_TIMEOUT`]
/// and its share of `max_bundle`, telling each the first line of its file
/// in `log_dir`, if any, so a worker writing this directory sends nothing.
/// Logs one line when the node has standalone workers.
pub async fn collect(
    source: &dyn WorkerLogSource,
    log_dir: &Path,
    request: &AutoRequest,
    max_bundle: usize,
    cancel: &AtomicBool,
) -> Vec<WorkerLog> {
    collect_within(
        source,
        log_dir,
        request,
        max_bundle,
        cancel,
        WORKER_EXPORT_TIMEOUT,
    )
    .await
}

async fn collect_within(
    source: &dyn WorkerLogSource,
    log_dir: &Path,
    request: &AutoRequest,
    max_bundle: usize,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Vec<WorkerLog> {
    let mut cores = source.cores();
    cores.sort_unstable();
    cores.dedup();
    if cores.is_empty() {
        return Vec::new();
    }
    let started = Instant::now();
    let share = worker_share(max_bundle, cores.len());
    let fetches = cores.iter().map(|&core| {
        let ask = ExportWorkerLogsRequest {
            since_unix: request.since_unix,
            until_unix: request.until_unix,
            filters: request.filters.clone(),
            matches: Vec::new(),
            min_level: 0,
            max_bytes: share,
            master_head: log_export::live_head_digest(log_dir, core)
                .map(|head| head.to_vec())
                .unwrap_or_default(),
        };
        async move {
            match tokio::time::timeout(timeout, fetch(source, core, ask, cancel)).await {
                Ok(log) => log,
                Err(_) => {
                    let reason = format!("no complete answer within {} s", timeout.as_secs());
                    WorkerLog::without_lines(
                        core,
                        WorkerStatus::Failed(reason.clone()),
                        Some(reason),
                    )
                }
            }
        }
    });
    let logs = futures::future::join_all(fetches).await;
    log_collected(request, &logs, started.elapsed());
    logs
}

/// One line per bundle: how many workers' lines came and what kept the
/// others'.
fn log_collected(request: &AutoRequest, logs: &[WorkerLog], took: Duration) {
    let count = |name: &str| logs.iter().filter(|log| log.status_name(0) == name).count();
    let bytes: usize = logs.iter().map(|log| log.lines.len()).sum();
    let missing: Vec<String> = logs
        .iter()
        .filter_map(|log| {
            let what = match &log.status {
                WorkerStatus::Collected | WorkerStatus::Local | WorkerStatus::NoLogFiles => {
                    return None
                }
                WorkerStatus::Unsupported => {
                    "unsupported (its build lacks the call; upgrade it)".to_string()
                }
                WorkerStatus::Unreachable(_) | WorkerStatus::Failed(_) => format!(
                    "{} ({})",
                    log.status_name(0),
                    log.detail.as_deref().unwrap_or("")
                ),
            };
            Some(format!("core {}: {what}", log.core))
        })
        .collect();
    let duration_ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX);
    info!(request = %super::short_id(&request.id), requester = %request.requester,
        workers = logs.len(), collected = count("collected"), truncated = count("truncated"),
        local = count("local"), no_log_files = count("no_log_files"), unreachable = count("unreachable"),
        unsupported = count("unsupported"), failed = count("failed"), bytes, duration_ms,
        missing = %missing.join("; "), scope = "this node and its standalone workers",
        "diagnostics log request: standalone workers' log lines collected for the bundle; \
         the manifest records each worker's outcome");
}

/// The host and user names the workers reported, to tokenize in their
/// lines, each once and in the order reported (a full host name before its
/// short form).
pub fn literals(logs: &[WorkerLog]) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for summary in logs.iter().filter_map(|log| log.summary.as_ref()) {
        let hosts = summary.hosts.iter().map(|host| ("host", host.clone()));
        let users = summary.users.iter().map(|user| ("user", user.clone()));
        for literal in hosts.chain(users) {
            if !out.contains(&literal) {
                out.push(literal);
            }
        }
    }
    out
}

/// Where the newest part of `lines` that a bundle keeps starts, at a line
/// start: all of them at step 0, the newest quarter at step 1, none past.
pub fn kept_from(lines: &[u8], step: usize) -> usize {
    let keep = match step {
        0 => return 0,
        1 => lines.len() / 4,
        _ => return lines.len(),
    };
    let from = lines.len() - keep;
    if from == 0 {
        return 0;
    }
    lines[from - 1..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(lines.len(), |at| from + at)
}

/// The manifest's `workers`: each worker's outcome, given the bytes the
/// bundle left out of its lines to fit its cap.
pub fn manifest(logs: &[WorkerLog], trimmed: &[u64]) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = logs
        .iter()
        .enumerate()
        .map(|(i, log)| {
            let trimmed = trimmed.get(i).copied().unwrap_or(0);
            let mut entry = serde_json::json!({
                "core": log.core,
                "status": log.status_name(trimmed),
                "bytes_received": log.lines.len(),
            });
            match &log.status {
                WorkerStatus::Unreachable(reason) | WorkerStatus::Failed(reason) => {
                    entry["error"] = reason.as_str().into();
                }
                WorkerStatus::Unsupported => {
                    entry["error"] = "the worker's build lacks ExportLogs".into();
                }
                _ => {}
            }
            if let Some(summary) = &log.summary {
                entry["files"] = serde_json::json!(summary.files);
                entry["read_errors"] = serde_json::json!(summary.read_errors);
                entry["lines"] = serde_json::json!({
                    "read": summary.lines_read,
                    "records_read": summary.records_read,
                    "records_sent": summary.records_kept,
                });
                if summary.records_dropped > 0 {
                    entry["left_out_by_worker"] = serde_json::json!({
                        "records": summary.records_dropped,
                        "bytes": summary.bytes_dropped,
                        "why": "the oldest records past the worker's share of maxBundleBytes",
                    });
                }
            }
            if trimmed > 0 {
                entry["left_out_for_bundle_cap"] = serde_json::json!({
                    "bytes": trimmed,
                    "why": "the oldest lines, so the bundle fits maxBundleBytes",
                });
            }
            entry
        })
        .collect();
    serde_json::Value::Array(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A worker's scripted answer.
    #[derive(Clone)]
    enum Script {
        Answer(Vec<Result<ExportWorkerLogsChunk, Status>>),
        Refuse(Status),
        Hang,
    }

    /// Standalone workers that answer as scripted, recording the requests.
    #[derive(Default)]
    struct FakeWorkers {
        scripts: HashMap<u32, Script>,
        asked: Mutex<Vec<(u32, ExportWorkerLogsRequest)>>,
    }

    #[tonic::async_trait]
    impl WorkerLogSource for FakeWorkers {
        fn cores(&self) -> Vec<u32> {
            self.scripts.keys().copied().collect()
        }

        async fn export_logs(
            &self,
            core: u32,
            request: ExportWorkerLogsRequest,
        ) -> Result<ChunkStream, Status> {
            self.asked.lock().unwrap().push((core, request));
            match self.scripts.get(&core).cloned() {
                Some(Script::Answer(messages)) => Ok(Box::pin(futures::stream::iter(messages))),
                Some(Script::Refuse(status)) => Err(status),
                Some(Script::Hang) => Ok(Box::pin(futures::stream::pending::<
                    Result<ExportWorkerLogsChunk, Status>,
                >())),
                None => Err(Status::unavailable("worker not registered")),
            }
        }
    }

    fn summary(bytes: usize) -> ExportWorkerLogsSummary {
        ExportWorkerLogsSummary {
            files: vec!["worker-1.log".into()],
            records_read: 3,
            records_kept: 2,
            line_bytes: bytes as u64,
            hosts: vec!["workerhost".into()],
            users: vec!["workeruser".into()],
            ..Default::default()
        }
    }

    fn answer(summary: ExportWorkerLogsSummary, pieces: &[&[u8]]) -> Script {
        let mut messages = vec![Ok(ExportWorkerLogsChunk {
            summary: Some(summary),
            lines: Vec::new(),
        })];
        messages.extend(pieces.iter().map(|piece| {
            Ok(ExportWorkerLogsChunk {
                summary: None,
                lines: piece.to_vec(),
            })
        }));
        Script::Answer(messages)
    }

    fn request() -> AutoRequest {
        AutoRequest {
            id: vec![0x3f; 16],
            requester: "…Ab12cd".into(),
            since_unix: 1_791_979_200,
            until_unix: 1_791_986_400,
            filters: vec![vec![0xa1; 32]],
            recipient_kem_public_key: Vec::new(),
        }
    }

    /// Every outcome is told apart and none is dropped: lines that came
    /// (whole or cut by the worker's share), a worker writing this node's
    /// directory, one not reachable, an older build, an error, a stream
    /// broken off after some lines, and one that never finishes.
    #[tokio::test]
    async fn each_workers_outcome_is_recorded() {
        let lines = b"2026-10-14T12:00:00Z\tinfo\tx.rs:1\tw\t{}\n".as_slice();
        let mut cut = summary(lines.len());
        cut.records_dropped = 4;
        cut.bytes_dropped = 400;
        let shared = ExportWorkerLogsSummary {
            same_files: true,
            ..summary(0)
        };
        let source = FakeWorkers {
            scripts: HashMap::from([
                (
                    1,
                    answer(summary(lines.len()), &[&lines[..10], &lines[10..]]),
                ),
                (2, answer(cut, &[lines])),
                (3, answer(shared, &[])),
                (
                    4,
                    Script::Refuse(Status::unavailable("tcp connect error 192.0.2.4")),
                ),
                (5, Script::Refuse(Status::unimplemented("older build"))),
                (
                    6,
                    Script::Refuse(Status::failed_precondition(
                        "the worker cannot read its log directory",
                    )),
                ),
                (
                    7,
                    Script::Answer(vec![
                        Ok(ExportWorkerLogsChunk {
                            summary: Some(summary(lines.len())),
                            lines: lines[..10].to_vec(),
                        }),
                        Err(Status::unknown("h2 protocol error")),
                    ]),
                ),
                (8, Script::Hang),
            ]),
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let logs = collect_within(
            &source,
            dir.path(),
            &request(),
            1 << 20,
            &AtomicBool::new(false),
            Duration::from_millis(300),
        )
        .await;
        let names: Vec<(u32, &str)> = logs
            .iter()
            .map(|log| (log.core, log.status_name(0)))
            .collect();
        assert_eq!(
            names,
            [
                (1, "collected"),
                (2, "truncated"),
                (3, "local"),
                (4, "unreachable"),
                (5, "unsupported"),
                (6, "failed"),
                (7, "failed"),
                (8, "failed"),
            ]
        );
        assert_eq!(&logs[0].lines[..], lines, "the pieces join up");
        assert_eq!(
            &logs[6].lines[..],
            &lines[..10],
            "the lines that came are kept"
        );
        let manifest = manifest(&logs, &[]);
        assert_eq!(manifest.as_array().unwrap().len(), 8, "{manifest}");
        assert_eq!(manifest[1]["left_out_by_worker"]["records"], 4);
        assert_eq!(manifest[3]["error"], Code::Unavailable.description());
        assert!(
            !manifest.to_string().contains("192.0.2.4"),
            "a transport error's text stays out of the manifest: {manifest}"
        );
        assert_eq!(
            manifest[5]["error"],
            "the worker cannot read its log directory"
        );
        assert_eq!(
            literals(&logs),
            [
                ("host", "workerhost".to_string()),
                ("user", "workeruser".to_string())
            ]
        );
        let asked = source.asked.lock().unwrap();
        assert_eq!(asked.len(), 8);
        assert!(asked
            .iter()
            .all(|(_, ask)| ask.max_bytes == worker_share(1 << 20, 8)
                && ask.filters == request().filters
                && ask.since_unix == request().since_unix
                && ask.master_head.is_empty()));
    }

    /// A worker announcing more than its share, or sending more than it
    /// announced, fails; a worker asked while this node writes its file
    /// gets that file's first line to compare.
    #[tokio::test]
    async fn a_worker_over_its_share_fails_and_a_local_file_is_named() {
        let share = worker_share(1 << 20, 2);
        let source = FakeWorkers {
            scripts: HashMap::from([
                (1, answer(summary(share as usize + 1), &[])),
                (2, answer(summary(3), &[b"abcd"])),
            ]),
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("worker-2.log"),
            "2026-10-14T12:00:00Z\tinfo\tx.rs:1\tw\t{}\n",
        )
        .unwrap();
        let logs = collect_within(
            &source,
            dir.path(),
            &request(),
            1 << 20,
            &AtomicBool::new(false),
            Duration::from_secs(5),
        )
        .await;
        assert!(logs
            .iter()
            .all(|log| log.status_name(0) == "failed" && log.lines.is_empty()));
        let asked = source.asked.lock().unwrap();
        let head = |core: u32| {
            asked
                .iter()
                .find(|(c, _)| *c == core)
                .map(|(_, ask)| ask.master_head.clone())
                .unwrap()
        };
        assert!(head(1).is_empty());
        assert_eq!(
            head(2),
            log_export::live_head_digest(dir.path(), 2)
                .unwrap()
                .to_vec()
        );
    }

    /// Shares split four times the bundle cap, within bounds; a bundle
    /// trimming lines keeps whole lines from the newest end.
    #[test]
    fn shares_and_trimming_are_bounded() {
        assert_eq!(worker_share(32 << 20, 4), 32 << 20);
        assert_eq!(worker_share(256 << 20, 1), MAX_LINES_TOTAL);
        assert_eq!(worker_share(1 << 20, 1000), MIN_SHARE);
        assert_eq!(worker_share(1 << 20, 0), 4 << 20);
        let lines = b"aaaa\nbbbb\ncccc\ndddd\n";
        assert_eq!(kept_from(lines, 0), 0);
        assert_eq!(&lines[kept_from(lines, 1)..], b"dddd\n");
        assert_eq!(kept_from(lines, 2), lines.len());
        assert_eq!(kept_from(b"", 1), 0);
        assert_eq!(kept_from(b"no newline at all", 1), 17);
        let none = WorkerLog::without_lines(1, WorkerStatus::Collected, None);
        assert_eq!(none.status_name(5), "truncated");
        assert_eq!(none.status_name(0), "collected");
    }

    /// Over the worker channel itself: the master's client reads a worker
    /// service's stream, an older worker answers Unimplemented and a worker
    /// not connected is unreachable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_worker_channel_carries_the_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("worker-1.log"),
            "2026-10-14T12:00:00Z\tinfo\tx.rs:1\tover the channel\t{}\n",
        )
        .unwrap();
        let current = serve(LogServer {
            dir: Some(dir.path().to_path_buf()),
        })
        .await;
        let older = serve(LogServer { dir: None }).await;
        let channels = Mutex::new((current, older));
        let workers = DataIpcWorkers::new(move || {
            let (current, older) = channels.lock().unwrap().clone();
            vec![
                (1, Ok(current)),
                (2, Ok(older)),
                (3, Err(Status::unavailable("worker not connected"))),
            ]
        });
        let master_dir = tempfile::tempdir().unwrap();
        let logs = collect(
            &workers,
            master_dir.path(),
            &AutoRequest {
                filters: Vec::new(),
                ..request()
            },
            1 << 20,
            &AtomicBool::new(false),
        )
        .await;
        let names: Vec<&str> = logs.iter().map(|log| log.status_name(0)).collect();
        assert_eq!(names, ["collected", "unsupported", "unreachable"]);
        assert!(String::from_utf8_lossy(&logs[0].lines).contains("over the channel"));
    }

    struct Incoming(tokio::net::TcpListener);

    impl futures::Stream for Incoming {
        type Item = std::io::Result<tokio::net::TcpStream>;

        fn poll_next(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.0
                .poll_accept(cx)
                .map(|result| Some(result.map(|(stream, _)| stream)))
        }
    }

    /// Serve `server` on a local port; a lazy channel to it.
    async fn serve(server: LogServer) -> Channel {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::data_ipc_service_server::DataIpcServiceServer::new(
                        server,
                    ),
                )
                .serve_with_incoming(Incoming(listener)),
        );
        tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect_lazy()
    }

    /// A worker's DataIPC service answering only `ExportLogs`, from `dir`
    /// as core 1; without `dir` it is an older build without the call.
    struct LogServer {
        dir: Option<std::path::PathBuf>,
    }

    type Reply<T> = Result<tonic::Response<T>, Status>;

    fn absent<T>() -> Reply<T> {
        Err(Status::unimplemented("test worker"))
    }

    #[tonic::async_trait]
    impl quil_types::proto::node::data_ipc_service_server::DataIpcService for LogServer {
        type ExportLogsStream =
            tokio_stream::wrappers::ReceiverStream<Result<ExportWorkerLogsChunk, Status>>;

        async fn export_logs(
            &self,
            request: tonic::Request<ExportWorkerLogsRequest>,
        ) -> Reply<Self::ExportLogsStream> {
            let Some(dir) = self.dir.clone() else {
                return absent();
            };
            let rx =
                log_export::worker::spawn_export(Some(dir), 1, request.into_inner(), Vec::new());
            Ok(tonic::Response::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ))
        }

        async fn get_app_fee_snapshot(
            &self,
            _: tonic::Request<quil_types::proto::node::GetAppFeeSnapshotRequest>,
        ) -> Reply<quil_types::proto::node::GetAppFeeSnapshotResponse> {
            absent()
        }

        async fn respawn(
            &self,
            _: tonic::Request<quil_types::proto::node::RespawnRequest>,
        ) -> Reply<quil_types::proto::node::RespawnResponse> {
            absent()
        }

        async fn create_join_proof(
            &self,
            _: tonic::Request<quil_types::proto::node::CreateJoinProofRequest>,
        ) -> Reply<quil_types::proto::node::CreateJoinProofResponse> {
            absent()
        }

        async fn set_halted(
            &self,
            _: tonic::Request<quil_types::proto::node::SetHaltedRequest>,
        ) -> Reply<quil_types::proto::node::SetHaltedResponse> {
            absent()
        }

        async fn prepare_storage_confirm(
            &self,
            _: tonic::Request<quil_types::proto::node::PrepareStorageConfirmRequest>,
        ) -> Reply<quil_types::proto::node::PrepareStorageConfirmResponse> {
            absent()
        }

        async fn deliver_shard_consensus(
            &self,
            _: tonic::Request<quil_types::proto::node::DeliverShardConsensusRequest>,
        ) -> Reply<quil_types::proto::node::DeliverShardConsensusResponse> {
            absent()
        }

        async fn get_worker_execution(
            &self,
            _: tonic::Request<quil_types::proto::node::GetWorkerExecutionRequest>,
        ) -> Reply<quil_types::proto::node::GetWorkerExecutionResponse> {
            absent()
        }

        async fn evict_payload(
            &self,
            _: tonic::Request<quil_types::proto::node::EvictPayloadRequest>,
        ) -> Reply<quil_types::proto::node::EvictPayloadResponse> {
            absent()
        }
    }
}
