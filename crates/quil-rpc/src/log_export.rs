//! Redacted exports of node log files, shared by `qclient node log export`,
//! its operator's approval of a peer's log request and this node's own
//! approval of one.
//!
//! Reads the node's log files (live and rotated, every core) or the
//! service's journal over a time window, keeps the selected lines, redacts
//! them ([`redact`]) and gzips them, describing the result in a manifest;
//! the token → original map stays with the node's operator.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};

use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};

pub mod redact;

use redact::{RedactOptions, Redactor};

/// Longest exportable window.
pub const MAX_WINDOW_SECS: i64 = 24 * 3600;

/// Redacted sample lines shown before writing.
const SAMPLE_LINES: usize = 20;

/// Rotated file names carry the node's local time; this covers any UTC
/// offset when matching them against the UTC window.
const ROTATION_TZ_SLACK_SECS: i64 = 14 * 3600;

/// Name of the redacted log inside the bundle.
pub const BUNDLE_LOG: &str = "node.log.gz";

/// What redaction hides and what it cannot hide; shown in the help, the
/// preview and the manifest.
pub const REDACTION_NOTE: &str = "Redaction hides your network location (IP addresses, DNS names, \
multiaddrs, peer IDs), host and user names, home paths and reward balances. It does not hide which \
prover you are: your shard set and join/reward frames are on-chain and stay in the log. The public \
mainnet bootstrap archive endpoints (their IPs and peer IDs) are kept.";

/// Rank of the level column of a node line (unknown levels rank as info).
fn level_rank(level: &str) -> u8 {
    match level.trim() {
        "trace" => 0,
        "debug" => 1,
        "warn" | "warning" => 3,
        "error" | "dpanic" | "panic" | "fatal" => 4,
        _ => 2,
    }
}

/// Rank of `warn`: lines at or above it are kept as context regardless of
/// `--filter`/`--match`.
pub const WARN_RANK: u8 = 3;

/// One log record: a node line and its continuation lines (for example a
/// multi-line panic message), with the line's time and level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// UTC Unix seconds; continuation lines at the start of a stream take
    /// the time of the stream's previous record, if any.
    pub ts: Option<i64>,
    /// Level rank ([`level_rank`]).
    pub level: u8,
    pub lines: Vec<String>,
}

/// Reads records from a sequence of line sources (one core's files in
/// order, or the journal). A source failing mid-way is recorded and
/// skipped.
pub struct RecordReader {
    sources: VecDeque<(String, Box<dyn BufRead>)>,
    pending: Option<Record>,
    last_ts: Option<i64>,
    /// Physical lines read.
    pub lines_read: u64,
    /// `<source name>: <error>` of sources that failed.
    pub errors: Vec<String>,
}

impl RecordReader {
    pub fn new(sources: Vec<(String, Box<dyn BufRead>)>) -> Self {
        RecordReader { sources: sources.into(), pending: None, last_ts: None, lines_read: 0, errors: Vec::new() }
    }

    fn read_line(&mut self) -> Option<String> {
        loop {
            let (name, src) = self.sources.front_mut()?;
            let mut buf = Vec::new();
            match src.read_until(b'\n', &mut buf) {
                Ok(0) => {
                    self.sources.pop_front();
                }
                Ok(_) => {
                    while matches!(buf.last(), Some(b'\n' | b'\r')) {
                        buf.pop();
                    }
                    self.lines_read += 1;
                    return Some(String::from_utf8_lossy(&buf).into_owned());
                }
                Err(e) => {
                    self.errors.push(format!("{name}: {e}"));
                    self.sources.pop_front();
                }
            }
        }
    }

    fn next_record(&mut self) -> Option<Record> {
        loop {
            let Some(line) = self.read_line() else {
                return self.pending.take();
            };
            if let Some(ts) = redact::parse_log_timestamp(&line) {
                self.last_ts = Some(ts);
                let level = line.split('\t').nth(1).map_or(2, level_rank);
                let record = Record { ts: Some(ts), level, lines: vec![line] };
                if let Some(previous) = self.pending.replace(record) {
                    return Some(previous);
                }
            } else {
                if let Some(record) = self.pending.as_mut() {
                    record.lines.push(line);
                } else {
                    self.pending = Some(Record { ts: self.last_ts, level: 2, lines: vec![line] });
                }
            }
        }
    }
}

/// Merges record streams in timestamp order; ties keep stream order, and
/// each stream keeps its own order.
pub struct Merger {
    pub readers: Vec<RecordReader>,
    heads: Vec<Option<Record>>,
    primed: bool,
}

impl Merger {
    pub fn new(readers: Vec<RecordReader>) -> Self {
        let heads = readers.iter().map(|_| None).collect();
        Merger { readers, heads, primed: false }
    }

    /// Physical lines read from every stream.
    pub fn lines_read(&self) -> u64 {
        self.readers.iter().map(|r| r.lines_read).sum()
    }

    /// Errors of every stream.
    pub fn errors(&self) -> Vec<String> {
        self.readers.iter().flat_map(|r| r.errors.iter().cloned()).collect()
    }
}

impl Iterator for Merger {
    type Item = Record;

    fn next(&mut self) -> Option<Record> {
        if !self.primed {
            for (head, reader) in self.heads.iter_mut().zip(self.readers.iter_mut()) {
                *head = reader.next_record();
            }
            self.primed = true;
        }
        let mut best: Option<(usize, i64)> = None;
        for (i, head) in self.heads.iter().enumerate() {
            if let Some(record) = head {
                let ts = record.ts.unwrap_or(i64::MIN);
                if best.is_none_or(|(_, b)| ts < b) {
                    best = Some((i, ts));
                }
            }
        }
        let (i, _) = best?;
        let record = self.heads[i].take();
        self.heads[i] = self.readers[i].next_record();
        record
    }
}

/// Which records to export.
#[derive(Debug, Clone)]
pub struct Selection {
    pub since: i64,
    pub until: i64,
    pub min_level: u8,
    /// Lowercase hex shard filters.
    pub filters: Vec<String>,
    pub matches: Vec<String>,
}

impl Selection {
    /// Whether `record` is in the window and level range and, unless it is a
    /// warning or error, mentions a requested filter (if any) and contains a
    /// requested text (if any).
    pub fn keeps(&self, record: &Record) -> bool {
        let Some(ts) = record.ts else {
            return false;
        };
        if ts < self.since || ts > self.until || record.level < self.min_level {
            return false;
        }
        if record.level >= WARN_RANK {
            return true;
        }
        let filter_ok = self.filters.is_empty()
            || record.lines.iter().any(|l| {
                let lower = l.to_ascii_lowercase();
                self.filters.iter().any(|f| lower.contains(f.as_str()))
            });
        let match_ok = self.matches.is_empty()
            || record.lines.iter().any(|l| self.matches.iter().any(|m| l.contains(m.as_str())));
        filter_ok && match_ok
    }
}

/// Outcome of streaming records through selection and redaction.
#[derive(Debug, Default)]
pub struct ExportStats {
    /// Physical lines read from the source (set by the caller).
    pub lines_read: u64,
    /// Sources that failed mid-way (set by the caller).
    pub read_errors: Vec<String>,
    pub records_read: u64,
    pub records_kept: u64,
    pub lines_kept: u64,
    /// Redacted sample lines, preferring lines that had redactions.
    pub samples: Vec<String>,
}

/// Records an export reads between looks at its cancel flag.
const CANCEL_CHECK_RECORDS: u64 = 256;

/// An export stopped by its cancel flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the export was cancelled")
    }
}

impl std::error::Error for Cancelled {}

/// Whether `error` is, or was caused by, a [`Cancelled`], also through an
/// I/O error of the export.
pub fn is_cancelled(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<Cancelled>() || cause.downcast_ref::<io::Error>().and_then(|io| io.get_ref()).is_some_and(|e| e.is::<Cancelled>())
    })
}

/// Select, redact and write `records` to `out`, one line per log line,
/// stopping with [`Cancelled`] once `cancel` is set.
pub fn export_records(
    records: impl Iterator<Item = Record>,
    selection: &Selection,
    redactor: &mut Redactor,
    out: &mut dyn Write,
    cancel: Option<&AtomicBool>,
) -> io::Result<ExportStats> {
    let mut stats = ExportStats::default();
    let mut redacted_samples = Vec::new();
    let mut plain_samples = Vec::new();
    for record in records {
        if stats.records_read % CANCEL_CHECK_RECORDS == 0 && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(io::Error::other(Cancelled));
        }
        stats.records_read += 1;
        if !selection.keeps(&record) {
            continue;
        }
        stats.records_kept += 1;
        for line in &record.lines {
            let before = redactor.total();
            let redacted = redactor.redact_line(line);
            writeln!(out, "{redacted}")?;
            stats.lines_kept += 1;
            if redactor.total() > before {
                if redacted_samples.len() < SAMPLE_LINES {
                    redacted_samples.push(redacted);
                }
            } else if plain_samples.len() < SAMPLE_LINES {
                plain_samples.push(redacted);
            }
        }
    }
    let fill = SAMPLE_LINES.saturating_sub(redacted_samples.len());
    redacted_samples.extend(plain_samples.into_iter().take(fill));
    stats.samples = redacted_samples;
    Ok(stats)
}

/// A node log file in the log directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFile {
    pub name: String,
    /// 0 for the master, N for worker N.
    pub core: u32,
    /// Rotation suffix `(timestamp, number)`; `None` for the live file.
    pub rotated: Option<(String, u32)>,
    pub gz: bool,
}

/// Parse `master.log`, `worker-N.log` or a rotated
/// `<live>.<YYYYMMDDTHHMMSS>[.N][.gz]`.
pub fn parse_log_file_name(name: &str) -> Option<LogFile> {
    let core_of = |base: &str| -> Option<u32> {
        if base == "master" {
            return Some(0);
        }
        let n = base.strip_prefix("worker-")?;
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        n.parse().ok()
    };
    if let Some(base) = name.strip_suffix(".log") {
        return Some(LogFile { name: name.to_string(), core: core_of(base)?, rotated: None, gz: false });
    }
    if !is_rotated_log(name) {
        return None;
    }
    let (base, suffix) = name.split_once(".log.")?;
    let (suffix, gz) = match suffix.strip_suffix(".gz") {
        Some(s) => (s, true),
        None => (suffix, false),
    };
    let (ts, number) = match suffix.split_once('.') {
        Some((ts, n)) => (ts, n.parse().ok()?),
        None => (suffix, 0),
    };
    Some(LogFile { name: name.to_string(), core: core_of(base)?, rotated: Some((ts.to_string(), number)), gz })
}

/// Unix seconds of a rotation timestamp `YYYYMMDDTHHMMSS`, read as UTC.
fn parse_rotation_ts(ts: &str) -> Option<i64> {
    if ts.len() != 15 || !ts.is_ascii() || ts.as_bytes()[8] != b'T' {
        return None;
    }
    let iso = format!("{}-{}-{}T{}:{}:{}Z", &ts[0..4], &ts[4..6], &ts[6..8], &ts[9..11], &ts[11..13], &ts[13..15]);
    redact::parse_rfc3339_utc(&iso)
}

/// The log files of every core that may hold lines of `[since, until]`,
/// per core (master first) and oldest first. A rotated file ends at its
/// rotation time and starts at the previous one's; both are local time, so
/// matching allows any UTC offset. An uncompressed rotated file is
/// preferred over its `.gz` (present only while compression runs).
pub fn select_log_files(names: &[String], since: i64, until: i64) -> Vec<Vec<LogFile>> {
    let mut by_core: BTreeMap<u32, Vec<LogFile>> = BTreeMap::new();
    for name in names {
        if let Some(file) = parse_log_file_name(name) {
            by_core.entry(file.core).or_default().push(file);
        }
    }
    let mut out = Vec::new();
    for (_, mut files) in by_core {
        files.sort_by(|a, b| match (&a.rotated, &b.rotated) {
            (None, None) => a.gz.cmp(&b.gz),
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(x), Some(y)) => x.cmp(y).then(a.gz.cmp(&b.gz)),
        });
        files.dedup_by(|later, earlier| later.rotated.is_some() && later.rotated == earlier.rotated);
        let mut selected = Vec::new();
        let mut previous_end: Option<i64> = None;
        for file in files {
            let end = file.rotated.as_ref().and_then(|(ts, _)| parse_rotation_ts(ts));
            let ends_before = file.rotated.is_some() && end.is_some_and(|e| e + ROTATION_TZ_SLACK_SECS < since);
            let starts_after = previous_end.is_some_and(|s| s - ROTATION_TZ_SLACK_SECS > until);
            if end.is_some() {
                previous_end = end;
            }
            if !ends_before && !starts_after {
                selected.push(file);
            }
        }
        if !selected.is_empty() {
            out.push(selected);
        }
    }
    out
}

/// Open one log file; a rotated file compressed since it was listed is
/// opened as its `.gz`.
fn open_log_file(dir: &Path, file: &LogFile) -> io::Result<Box<dyn BufRead>> {
    let open = |name: &str, gz: bool| -> io::Result<Box<dyn BufRead>> {
        let f = File::open(dir.join(name))?;
        let reader: Box<dyn BufRead> =
            if gz { Box::new(BufReader::new(MultiGzDecoder::new(f))) } else { Box::new(BufReader::new(f)) };
        Ok(reader)
    };
    match open(&file.name, file.gz) {
        Err(e) if e.kind() == io::ErrorKind::NotFound && file.rotated.is_some() && !file.gz => {
            open(&format!("{}.gz", file.name), true)
        }
        other => other,
    }
}

/// Record readers (one per core) over the log files in `dir` that may hold
/// lines of the window, and the names of the files they read; a file that
/// does not open is a read error of its core.
pub fn file_readers(dir: &Path, since: i64, until: i64) -> anyhow::Result<(Vec<RecordReader>, Vec<String>)> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))? {
        if let Ok(name) = entry?.file_name().into_string() {
            names.push(name);
        }
    }
    let mut readers = Vec::new();
    let mut used = Vec::new();
    for core_files in select_log_files(&names, since, until) {
        let mut sources: Vec<(String, Box<dyn BufRead>)> = Vec::new();
        let mut skipped = Vec::new();
        for file in core_files {
            match open_log_file(dir, &file) {
                Ok(reader) => {
                    used.push(file.name.clone());
                    sources.push((file.name, reader));
                }
                Err(e) => skipped.push(format!("{}: {e}", file.name)),
            }
        }
        let mut reader = RecordReader::new(sources);
        reader.errors = skipped;
        readers.push(reader);
    }
    Ok((readers, used))
}

/// Whether `name` is a rotated node log: `master.log.<suffix>` or
/// `worker-N.log.<suffix>`, never a live `.log`.
pub fn is_rotated_log(name: &str) -> bool {
    let Some((base, suffix)) = name.split_once(".log.") else {
        return false;
    };
    let worker = base.strip_prefix("worker-").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    (base == "master" || worker) && !suffix.is_empty()
}

/// Parse a window bound: UTC RFC 3339, or `Nh`/`Nm` before `now`.
pub fn parse_when(s: &str, now: i64) -> anyhow::Result<i64> {
    let s = s.trim();
    for (unit, secs) in [('h', 3600), ('m', 60)] {
        if let Some(n) = s.strip_suffix(unit) {
            if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
                let n: i64 = n.parse().map_err(|e| anyhow::anyhow!("{s}: {e}"))?;
                return Ok(now - n.saturating_mul(secs));
            }
        }
    }
    redact::parse_rfc3339_utc(s)
        .ok_or_else(|| anyhow::anyhow!("{s}: expected UTC RFC 3339 (2026-10-17T16:00:00Z) or a time ago (2h, 90m)"))
}

/// `YYYYMMDDTHHMMSSZ` of UTC Unix seconds, for file names.
pub fn compact_ts(secs: i64) -> String {
    redact::format_rfc3339_utc(secs).replace(['-', ':'], "")
}

/// Wraps a writer, hashing and counting what passes through.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Where the exported lines came from.
#[derive(Debug, Clone)]
pub enum SourceInfo {
    Files(Vec<String>),
    Journal(String),
}

/// The bundle log's digest and size.
#[derive(Debug, Clone)]
pub struct LogDigest {
    pub sha256: String,
    pub bytes: u64,
}

/// The bundle manifest. Never holds the salt or original values.
pub fn manifest(
    selection: &Selection,
    source: &SourceInfo,
    stats: &ExportStats,
    redactor: &Redactor,
    keep_self: bool,
    log: &LogDigest,
) -> serde_json::Value {
    let source = match source {
        SourceInfo::Files(names) => json!({ "kind": "files", "files": names }),
        SourceInfo::Journal(unit) => json!({ "kind": "journal", "unit": unit }),
    };
    json!({
        "tool": "qclient node log export",
        "tool_version": quil_config::VERSION_STRING,
        "window": {
            "since": redact::format_rfc3339_utc(selection.since),
            "until": redact::format_rfc3339_utc(selection.until),
        },
        "source": source,
        "selection": {
            "filters": selection.filters,
            "match_count": selection.matches.len(),
            "min_level_rank": selection.min_level,
            "warn_and_error_always_kept": !(selection.filters.is_empty() && selection.matches.is_empty()),
        },
        "lines": {
            "read": stats.lines_read,
            "kept": stats.lines_kept,
            "records_read": stats.records_read,
            "records_kept": stats.records_kept,
        },
        "redaction": {
            "counts": redactor.counts(),
            "distinct_values": redactor.distinct(),
            "unparseable_json": redactor.unparseable(),
            "keep_self": keep_self,
            "note": REDACTION_NOTE,
        },
        "read_errors": stats.read_errors,
        "log": { "file": BUNDLE_LOG, "sha256": log.sha256, "bytes": log.bytes },
    })
}

/// The preview printed before writing; `destination` says where the bundle
/// goes.
pub fn preview(manifest: &serde_json::Value, stats: &ExportStats, destination: &str, map_path: &Path) -> String {
    let mut s = String::new();
    let w = &manifest["window"];
    s.push_str(&format!("Window: {} .. {} (UTC)\n", w["since"].as_str().unwrap_or(""), w["until"].as_str().unwrap_or("")));
    if let Some(filters) = manifest["selection"]["filters"].as_array().filter(|f| !f.is_empty()) {
        s.push_str("Shard filters (their lines, plus every warn and error line):\n");
        for filter in filters {
            s.push_str(&format!("  {}\n", filter.as_str().unwrap_or("")));
        }
    }
    let src = &manifest["source"];
    match src["kind"].as_str() {
        Some("files") => {
            let n = src["files"].as_array().map_or(0, |a| a.len());
            s.push_str(&format!("Source: {n} log file(s)\n"));
        }
        _ => s.push_str(&format!("Source: journal of {}\n", src["unit"].as_str().unwrap_or(""))),
    }
    let l = &manifest["lines"];
    s.push_str(&format!("Lines: {} read, {} kept\n", l["read"], l["kept"]));
    let r = &manifest["redaction"];
    let counts = r["counts"].as_object().cloned().unwrap_or_default();
    if counts.is_empty() {
        s.push_str("Redactions: none\n");
    } else {
        s.push_str("Redactions (replacements / distinct values):\n");
        for (class, n) in &counts {
            let distinct = r["distinct_values"][class].as_u64().unwrap_or(0);
            s.push_str(&format!("  {class}: {n} / {distinct}\n"));
        }
    }
    let unparseable = r["unparseable_json"].as_u64().unwrap_or(0);
    if unparseable > 0 {
        s.push_str(&format!("Lines without parseable JSON fields: {unparseable} (redacted as text)\n"));
    }
    if let Some(errors) = manifest["read_errors"].as_array().filter(|a| !a.is_empty()) {
        s.push_str(&format!("Unreadable sources (partly skipped): {}\n", errors.len()));
    }
    s.push_str(&format!("Sample of {} redacted line(s):\n", stats.samples.len()));
    for line in &stats.samples {
        s.push_str("  ");
        s.push_str(line);
        s.push('\n');
    }
    s.push_str(REDACTION_NOTE);
    s.push('\n');
    s.push_str(destination);
    s.push('\n');
    s.push_str(&format!("Token map (original values; keep private, never share it): {}\n", map_path.display()));
    s
}

/// The user names of the home directories `paths` lie in (`/home/<name>/…`,
/// `/Users/<name>/…`), a relative path taken from the working directory;
/// root and shared homes name no user.
pub fn home_users(paths: &[PathBuf]) -> Vec<String> {
    let cwd = std::env::current_dir().ok();
    let mut users: Vec<String> = paths
        .iter()
        .filter_map(|path| if path.is_absolute() { Some(path.clone()) } else { cwd.as_ref().map(|cwd| cwd.join(path)) })
        .filter_map(|path| {
            let mut parts = path.components().filter_map(|c| match c {
                std::path::Component::Normal(part) => part.to_str().map(str::to_string),
                _ => None,
            });
            match (parts.next()?.as_str(), parts.next()?) {
                ("home" | "Users", name) if !matches!(name.as_str(), "root" | "Shared" | "shared") => Some(name),
                _ => None,
            }
        })
        .collect();
    users.sort();
    users.dedup();
    users
}

/// Host and user names to tokenize wherever they appear: the host name,
/// the user of the process environment and the users whose home
/// directories `home_paths` and the working directory lie in, so a node
/// run as root still hides its operator's name.
fn local_literals(home_paths: &[PathBuf]) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    if !host.is_empty() {
        if let Some((short, _)) = host.split_once('.') {
            out.push(("host", host.clone()));
            out.push(("host", short.to_string()));
        } else {
            out.push(("host", host));
        }
    }
    let mut users: Vec<String> = ["USER", "LOGNAME"].iter().filter_map(|v| std::env::var(v).ok()).collect();
    if let Some(home) = std::env::var_os("HOME") {
        if let Some(name) = Path::new(&home).file_name().and_then(|n| n.to_str()) {
            users.push(name.to_string());
        }
    }
    let mut paths = home_paths.to_vec();
    paths.extend(std::env::current_dir());
    users.extend(home_users(&paths));
    users.sort();
    users.dedup();
    out.extend(users.into_iter().filter(|u| !u.is_empty()).map(|u| ("user", u)));
    out
}

/// Write the token map of the export `about`, readable by the owner only.
pub fn write_token_map(path: &Path, about: &str, map: &BTreeMap<String, String>) -> anyhow::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| anyhow::anyhow!("create {}: {e}", path.display()))?;
    writeln!(f, "# Token map of {about}: original values. PRIVATE: do not share this file.")?;
    for (token, value) in map {
        writeln!(f, "{token}\t{value}")?;
    }
    Ok(())
}

/// One redacted export: the gzipped log in `out`, its manifest and the
/// token map of the values it hides.
pub struct Export<W> {
    pub out: W,
    pub manifest: serde_json::Value,
    pub stats: ExportStats,
    pub log: LogDigest,
    pub token_map: BTreeMap<String, String>,
}

/// How to export: what to keep, the token salt, where to find the
/// operator's user names and when to stop.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExportOptions<'a> {
    /// Keep this node's own peer ID and prover address.
    pub keep_self: bool,
    /// The token salt; a fresh one when `None` (tests fix it to compare two
    /// exports).
    pub salt: Option<[u8; 32]>,
    /// Paths whose home directories name users to tokenize, beside the
    /// process environment's ([`home_users`]): the node's config and log
    /// directories.
    pub home_paths: &'a [PathBuf],
    /// Stops the export once set.
    pub cancel: Option<&'a AtomicBool>,
}

/// Select, redact and gzip the records of `readers` into `out`, and
/// describe the result in a manifest.
pub fn produce<W: Write>(
    readers: Vec<RecordReader>,
    child: Option<Child>,
    source: &SourceInfo,
    selection: &Selection,
    out: W,
    options: &ExportOptions<'_>,
) -> anyhow::Result<Export<W>> {
    let keep_self = options.keep_self;
    let salt = options.salt.unwrap_or_else(|| {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    });
    let mut opts = RedactOptions::with_bootstrap_endpoints(keep_self);
    opts.literals = local_literals(options.home_paths);
    let mut redactor = Redactor::new(salt, opts);

    let hashing = HashingWriter { inner: out, hasher: Sha256::new(), bytes: 0 };
    let mut gz = GzEncoder::new(hashing, Compression::default());
    let mut merger = Merger::new(readers);
    let mut stats = export_records(merger.by_ref(), selection, &mut redactor, &mut gz, options.cancel)?;
    stats.lines_read = merger.lines_read();
    stats.read_errors = merger.errors();
    let mut hashing = gz.finish()?;
    hashing.flush()?;
    let log = LogDigest { sha256: hex::encode(hashing.hasher.finalize()), bytes: hashing.bytes };
    if let Some(mut c) = child {
        let status = c.wait()?;
        if !status.success() {
            anyhow::bail!("journalctl exited with {status}");
        }
    }
    let manifest = manifest(selection, source, &stats, &redactor, keep_self, &log);
    Ok(Export { out: hashing.inner, manifest, stats, log, token_map: redactor.token_map().clone() })
}

/// The bundle's `manifest.json` and `SHA256SUMS`.
pub fn bundle_texts(manifest: &serde_json::Value, log: &LogDigest) -> anyhow::Result<(String, String)> {
    let manifest_text = serde_json::to_string_pretty(manifest)? + "\n";
    let manifest_sha = hex::encode(Sha256::digest(manifest_text.as_bytes()));
    let sums = format!("{}  {BUNDLE_LOG}\n{manifest_sha}  manifest.json\n", log.sha256);
    Ok((manifest_text, sums))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    /// Synthetic peer ID (valid base58 shape, no real peer).
    const QM: &str = "QmSyntheticPeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FILTER: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";

    fn ts(s: &str) -> i64 {
        redact::parse_rfc3339_utc(s).unwrap()
    }

    fn node_line(time: &str, level: &str, message: &str, fields: &str) -> String {
        format!("2026-10-17T{time}Z\t{level}\tquil_node/src/main.rs:7\t{message}\t{fields}")
    }

    fn reader(text: &str) -> RecordReader {
        let src: Box<dyn BufRead> = Box::new(Cursor::new(text.as_bytes().to_vec()));
        RecordReader::new(vec![("test".to_string(), src)])
    }

    fn whole_day() -> Selection {
        Selection {
            since: ts("2026-10-17T00:00:00Z"),
            until: ts("2026-10-17T23:59:59Z"),
            min_level: 0,
            filters: Vec::new(),
            matches: Vec::new(),
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qclient-log-export-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_gz(path: &Path, text: &str) {
        let mut gz = GzEncoder::new(File::create(path).unwrap(), Compression::default());
        gz.write_all(text.as_bytes()).unwrap();
        gz.finish().unwrap();
    }

    fn message_of(line: &str) -> &str {
        line.split('\t').nth(3).unwrap_or(line)
    }

    fn lines(items: &[String]) -> String {
        items.iter().map(|l| format!("{l}\n")).collect()
    }

    /// Exported lines of `text` under `selection`, unredacted messages.
    fn exported(text: &str, selection: &Selection) -> Vec<String> {
        let mut out = Vec::new();
        let mut redactor = Redactor::new([1; 32], RedactOptions::default());
        let mut merger = Merger::new(vec![reader(text)]);
        export_records(merger.by_ref(), selection, &mut redactor, &mut out, None).unwrap();
        String::from_utf8(out).unwrap().lines().map(|l| message_of(l).to_string()).collect()
    }

    /// A rotated `.gz` and the live file of each core are read in order and
    /// the cores merged by time (ties keep core order); a stale `.gz` twin
    /// of an uncompressed rotation and a rotation long before the window
    /// are skipped.
    #[test]
    fn rotated_and_live_files_merge_in_time_order() {
        let dir = test_dir("merge");
        let c = r#"{"coreId":0}"#;
        write_gz(
            &dir.join("master.log.20261017T120000.gz"),
            &lines(&[node_line("11:00:00", "info", "m1", c), node_line("11:30:00", "info", "m2", c)]),
        );
        write_gz(&dir.join("master.log.20261001T000000.gz"), "2026-09-30T23:00:00Z\tinfo\tx.rs:1\told\t{}\n");
        std::fs::write(
            dir.join("master.log"),
            lines(&[
                node_line("12:10:00", "info", "m4", c),
                node_line("12:20:00", "info", "m-tie", c),
                node_line("12:40:00", "info", "m6", c),
            ]),
        )
        .unwrap();
        std::fs::write(
            dir.join("worker-1.log.20261017T121500"),
            lines(&[node_line("11:15:00", "info", "w1", c), node_line("12:05:00", "info", "w2", c), "  w2 detail".to_string()]),
        )
        .unwrap();
        write_gz(&dir.join("worker-1.log.20261017T121500.gz"), &lines(&[node_line("11:16:00", "info", "partial", c)]));
        std::fs::write(dir.join("worker-1.log"), lines(&[node_line("12:20:00", "info", "w-tie", c)])).unwrap();
        std::fs::write(dir.join("notes.txt"), "not a log\n").unwrap();

        let (readers, names) = file_readers(&dir, ts("2026-10-17T10:00:00Z"), ts("2026-10-17T13:00:00Z")).unwrap();
        assert_eq!(names, ["master.log.20261017T120000.gz", "master.log", "worker-1.log.20261017T121500", "worker-1.log"]);
        let mut merger = Merger::new(readers);
        let got: Vec<String> =
            merger.by_ref().flat_map(|r| r.lines).map(|l| message_of(&l).to_string()).collect();
        assert_eq!(got, ["m1", "w1", "m2", "w2", "  w2 detail", "m4", "m-tie", "w-tie", "m6"]);
        assert_eq!(merger.lines_read(), 9);
        assert!(merger.errors().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rotations_are_ordered_and_matched_to_the_window() {
        let names: Vec<String> = [
            "master.log",
            "master.log.20261012T000000.1.gz",
            "master.log.20261012T000000",
            "master.log.20261013T000000",
            "worker-2.log.20261011T000000.gz",
            "worker-x.log.20261011T000000",
            "node.log",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Window ending well before the 2026-10-12 rotation: the files
        // rotated later started on 10-12 or 10-13, so only the oldest one
        // (start unknown) may hold window lines.
        let sel = select_log_files(&names, ts("2026-10-09T00:00:00Z"), ts("2026-10-10T00:00:00Z"));
        let picked: Vec<Vec<&str>> = sel.iter().map(|core| core.iter().map(|f| f.name.as_str()).collect()).collect();
        assert_eq!(picked, [vec!["master.log.20261012T000000"], vec!["worker-2.log.20261011T000000.gz"]]);
        // Window after the worker's only rotation ended: it is skipped.
        let all = select_log_files(&names, ts("2026-10-12T00:00:00Z"), ts("2026-10-13T00:00:00Z"));
        assert_eq!(all[0].iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), [
            "master.log.20261012T000000",
            "master.log.20261012T000000.1.gz",
            "master.log.20261013T000000",
            "master.log",
        ]);
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn selection_keeps_matches_and_warnings_as_context() {
        let text = lines(&[
            node_line("12:00:00", "info", "with filter", &format!(r#"{{"coreId":1,"filter":"{FILTER}"}}"#)),
            node_line("12:00:01", "info", "prover confirmation published", r#"{"coreId":0}"#),
            node_line("12:00:02", "warn", "duty outage", r#"{"coreId":0}"#),
            node_line("12:00:03", "debug", "noise", r#"{"coreId":0}"#),
            "2026-10-16T12:00:00Z\terror\tx.rs:1\tbefore the window\t{}".to_string(),
        ]);
        assert_eq!(exported(&text, &whole_day()).len(), 4);
        let by_filter = Selection { filters: vec![FILTER.to_string()], ..whole_day() };
        assert_eq!(exported(&text, &by_filter), ["with filter", "duty outage"]);
        let upper = lines(&[node_line("12:00:00", "info", "upper", &format!(r#"{{"coreId":1,"filter":"{}"}}"#, FILTER.to_ascii_uppercase()))]);
        assert_eq!(exported(&upper, &by_filter), ["upper"]);
        let by_match = Selection { matches: vec!["confirmation".to_string()], ..whole_day() };
        assert_eq!(exported(&text, &by_match), ["prover confirmation published", "duty outage"]);
        let warn = Selection { min_level: WARN_RANK, ..whole_day() };
        assert_eq!(exported(&text, &warn), ["duty outage"]);
    }

    /// The manifest's per-class counts equal the tokens in the output, and
    /// neither holds an original value or the salt.
    #[test]
    fn manifest_counts_match_redactions() {
        let text = lines(&[
            node_line("12:00:00", "info", "dialing 192.0.2.10:8340", r#"{"coreId":0}"#),
            node_line("12:00:01", "info", "P2P identity ready", &format!(r#"{{"coreId":0,"peer_id":"{QM}"}}"#)),
            node_line(
                "12:00:02",
                "warn",
                "sync failed",
                &format!(r#"{{"coreId":1,"error":"open /home/alice/quil/node/.config/store: denied via /ip4/198.51.100.7/udp/8336/p2p/{QM}"}}"#),
            ),
            "  at /home/alice/quil/src/main.rs:12".to_string(),
            node_line("12:00:03", "info", "reward", r#"{"balance":"1.5","coreId":0,"delta":"0.5"}"#),
            node_line("12:00:04", "info", "truncated", r#"{"addr":"[2001:db8::1]:8336","new_balance":7"#),
            node_line("12:00:05", "info", "signer FalconPublicKey([1, 2, 3]) on examplehost", r#"{"coreId":0}"#),
        ]);
        let salt = [9u8; 32];
        let opts = RedactOptions { literals: vec![("host", "examplehost".to_string())], ..RedactOptions::default() };
        let mut redactor = Redactor::new(salt, opts);
        let mut out = Vec::new();
        let mut merger = Merger::new(vec![reader(&text)]);
        let mut stats = export_records(merger.by_ref(), &whole_day(), &mut redactor, &mut out, None).unwrap();
        stats.lines_read = merger.lines_read();
        let out = String::from_utf8(out).unwrap();

        let token = regex::Regex::new(r"((?:self:)?[a-z0-9]+)#[0-9a-f]{8}").unwrap();
        let mut found: BTreeMap<String, u64> = BTreeMap::new();
        for c in token.captures_iter(&out) {
            *found.entry(c[1].to_string()).or_insert(0) += 1;
        }
        let removed = out.matches(&format!("\"{}\"", redact::REMOVED)).count() as u64;
        if removed > 0 {
            found.insert("balance".to_string(), removed);
        }
        let expected: BTreeMap<String, u64> =
            [("balance", 3), ("host", 1), ("ip4", 2), ("ip6", 1), ("key", 1), ("path", 2), ("self:peer", 2)]
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect();
        assert_eq!(found, expected, "{out}");

        let log = LogDigest { sha256: "00".repeat(32), bytes: out.len() as u64 };
        let m = manifest(&whole_day(), &SourceInfo::Files(vec!["master.log".to_string()]), &stats, &redactor, false, &log);
        let counts: BTreeMap<String, u64> = serde_json::from_value(m["redaction"]["counts"].clone()).unwrap();
        assert_eq!(counts, expected);
        assert_eq!(m["redaction"]["unparseable_json"], 1);
        // Every input line is read and, inside the window, kept.
        let input_lines = text.lines().count() as u64;
        assert_eq!(m["lines"]["read"], input_lines);
        assert_eq!(m["lines"]["kept"], input_lines);
        assert_eq!(m["tool_version"], quil_config::VERSION_STRING);

        let manifest_text = m.to_string();
        for value in [
            "192.0.2.10", "198.51.100.7", QM, "/home/alice", "alice", "\"1.5\"", "\"0.5\"", "\"new_balance\":7", "2001:db8::1",
            "examplehost", "1, 2, 3",
        ] {
            assert!(!out.contains(value), "{value} survived in:\n{out}");
            assert!(!manifest_text.contains(value), "{value} in the manifest");
        }
        assert!(!manifest_text.contains(&hex::encode(salt)));
        assert!(stats.samples.first().is_some_and(|s| s.contains('#')));
    }

    #[test]
    fn window_bounds_parse() {
        let now = ts("2026-10-17T18:00:00Z");
        assert_eq!(parse_when("2h", now).unwrap(), ts("2026-10-17T16:00:00Z"));
        assert_eq!(parse_when("90m", now).unwrap(), ts("2026-10-17T16:30:00Z"));
        assert_eq!(parse_when("2026-10-17T12:00:00Z", now).unwrap(), ts("2026-10-17T12:00:00Z"));
        assert!(parse_when("yesterday", now).is_err());
        assert!(parse_when("h", now).is_err());
        assert_eq!(compact_ts(now), "20261017T180000Z");
    }

    /// An export stops at its cancel flag, between records.
    #[test]
    fn a_cancelled_export_stops() {
        let text = lines(&(0..2000).map(|n| node_line("12:00:00", "info", &format!("line {n}"), "{}")).collect::<Vec<_>>());
        let cancel = AtomicBool::new(false);
        let mut redactor = Redactor::new([1; 32], RedactOptions::default());
        let mut out = Vec::new();
        let all = export_records(Merger::new(vec![reader(&text)]), &whole_day(), &mut redactor, &mut out, Some(&cancel)).unwrap();
        assert_eq!(all.lines_kept, 2000);
        cancel.store(true, Ordering::Relaxed);
        let error = export_records(Merger::new(vec![reader(&text)]), &whole_day(), &mut redactor, &mut Vec::new(), Some(&cancel))
            .unwrap_err();
        assert!(is_cancelled(&anyhow::Error::from(error)));
        assert!(!is_cancelled(&anyhow::anyhow!("disk full")));
    }

    /// A node run as root still hides its operator's name: the home
    /// directories of its config and log paths name users to tokenize.
    #[test]
    fn home_directories_name_users_to_redact() {
        let paths = [PathBuf::from("/Users/alice/quil/.config"), PathBuf::from("/home/bob/node/.log"), PathBuf::from("/root/quil"),
            PathBuf::from("/Users/Shared/quil"), PathBuf::from("/opt/quil"), PathBuf::from("/home")];
        assert_eq!(home_users(&paths), ["alice", "bob"]);
        let users: Vec<String> = local_literals(&paths).into_iter().filter(|(class, _)| *class == "user").map(|(_, u)| u).collect();
        assert!(users.contains(&"alice".to_string()) && users.contains(&"bob".to_string()), "{users:?}");
        let dir = test_dir("home-users");
        std::fs::write(dir.join("master.log"), lines(&[node_line("12:00:00", "info", "started by alice in quil", "{}")])).unwrap();
        let (readers, names) = file_readers(&dir, ts("2026-10-17T00:00:00Z"), ts("2026-10-17T23:59:59Z")).unwrap();
        let home = [PathBuf::from("/Users/alice/quil")];
        let options = ExportOptions { salt: Some([3; 32]), home_paths: &home, ..ExportOptions::default() };
        let export = produce(readers, None, &SourceInfo::Files(names), &whole_day(), Vec::new(), &options).unwrap();
        let mut text = String::new();
        io::Read::read_to_string(&mut flate2::read::GzDecoder::new(export.out.as_slice()), &mut text).unwrap();
        assert!(!text.contains("alice") && text.contains("user#"), "{text}");
        assert_eq!(export.token_map.values().filter(|v| *v == "alice").count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
