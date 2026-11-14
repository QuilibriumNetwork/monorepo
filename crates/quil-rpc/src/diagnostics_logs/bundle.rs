//! The sealed bundle of one log request: the export its target makes for
//! it, as the target's operator (`qclient node diagnostics approve`) or the
//! target node itself (automatic approval) builds it, and as the
//! requester's qclient opens it.
//!
//! The bundle holds `node.log.gz`, `manifest.json` and `SHA256SUMS` of a
//! `node log export` of the request's window and filters, framed and sealed
//! to the request's sntrup761 key. The token map of the values redaction
//! hid stays with the target, in its config directory's
//! `.diagnostics/token-maps`.

use std::collections::BTreeMap;
use std::io::{BufRead, Cursor};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::workers::{self, WorkerLog};
use crate::log_export::{
    self, Cancelled, Export, ExportOptions, RecordReader, Selection, SourceInfo, BUNDLE_LOG,
};

/// The plaintext a target seals: these files, in this order.
const BUNDLE_MAGIC: &[u8; 8] = b"QLOGEXP1";
pub const BUNDLE_FILES: [&str; 3] = [BUNDLE_LOG, "manifest.json", "SHA256SUMS"];

/// How long token maps are kept in `.diagnostics/token-maps`.
pub const TOKEN_MAP_RETENTION: std::time::Duration = std::time::Duration::from_secs(7 * 86_400);

/// The plaintext a target seals: the three bundle files, framed.
pub fn pack_bundle(files: &[(&str, &[u8]); 3]) -> Vec<u8> {
    let mut out = BUNDLE_MAGIC.to_vec();
    for (name, data) in files {
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// The three bundle files of a fetched plaintext, in [`BUNDLE_FILES`]
/// order, checked against its `SHA256SUMS`.
pub fn unpack_bundle(plaintext: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let malformed = || anyhow::anyhow!("the bundle is not a log export of this version");
    let mut rest = plaintext
        .strip_prefix(BUNDLE_MAGIC.as_slice())
        .ok_or_else(malformed)?;
    let mut files = Vec::new();
    for expected in BUNDLE_FILES {
        let (&name_len, after) = rest.split_first().ok_or_else(malformed)?;
        let name = after.get(..name_len as usize).ok_or_else(malformed)?;
        anyhow::ensure!(
            name == expected.as_bytes(),
            "the bundle holds an unexpected file"
        );
        let after = &after[name_len as usize..];
        let len: [u8; 8] = after
            .get(..8)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?;
        let len = usize::try_from(u64::from_le_bytes(len)).map_err(|_| malformed())?;
        let data = after
            .get(8..8usize.checked_add(len).ok_or_else(malformed)?)
            .ok_or_else(malformed)?;
        files.push(data.to_vec());
        rest = &after[8 + len..];
    }
    anyhow::ensure!(rest.is_empty(), "the bundle holds more than a log export");
    let sums = String::from_utf8_lossy(&files[2]).into_owned();
    for (name, data) in BUNDLE_FILES[..2].iter().zip(&files) {
        let expected = format!("{}  {name}", hex::encode(Sha256::digest(data)));
        anyhow::ensure!(
            sums.lines().any(|line| line == expected),
            "{name} does not match the bundle's SHA256SUMS"
        );
    }
    Ok(files)
}

/// An export or sealed bundle over `diagnostics.logRequests.maxBundleBytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLarge {
    /// `maxBundleBytes`.
    pub cap: usize,
    /// The sealed bundle's size, when the export itself fit.
    pub sealed: Option<usize>,
}

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.sealed {
            Some(bytes) => write!(
                f,
                "the sealed bundle has {bytes} bytes, over this node's diagnostics.logRequests.maxBundleBytes ({})",
                self.cap
            ),
            None => write!(f, "the export exceeds this node's diagnostics.logRequests.maxBundleBytes ({} bytes)", self.cap),
        }
    }
}

impl std::error::Error for TooLarge {}

/// Whether `error` is, or was caused by, a [`TooLarge`].
pub fn is_too_large(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<TooLarge>()
            || cause
                .downcast_ref::<std::io::Error>()
                .and_then(|io| io.get_ref())
                .is_some_and(|inner| inner.is::<TooLarge>())
    })
}

/// Collects the gzipped log in memory, refusing more than its cap.
#[derive(Debug)]
pub struct Capped {
    pub data: Vec<u8>,
    pub cap: usize,
}

impl std::io::Write for Capped {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.data.len() + buf.len() > self.cap {
            return Err(std::io::Error::other(TooLarge {
                cap: self.cap,
                sealed: None,
            }));
        }
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Who approved a request, as its bundle's manifest records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// This node's operator, with `qclient node diagnostics approve`.
    Operator,
    /// This node itself: its operator listed the requester in
    /// `diagnostics.logRequests.allowedPeers`.
    Automatic,
}

impl Approval {
    fn tool(self) -> &'static str {
        match self {
            Approval::Operator => "qclient node diagnostics approve",
            Approval::Automatic => "quil-node automatic log request approval",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Approval::Operator => "operator",
            Approval::Automatic => "automatic",
        }
    }
}

/// The export selection of a request: its window and filters, every level,
/// no text match.
pub fn request_selection(
    since_unix: u64,
    until_unix: u64,
    filters: &[Vec<u8>],
) -> anyhow::Result<Selection> {
    let since = i64::try_from(since_unix)
        .map_err(|_| anyhow::anyhow!("the request's window is invalid"))?;
    let until = i64::try_from(until_unix)
        .map_err(|_| anyhow::anyhow!("the request's window is invalid"))?;
    anyhow::ensure!(since < until, "the request's window is invalid");
    Ok(Selection {
        since,
        until,
        min_level: 0,
        filters: filters.iter().map(hex::encode).collect(),
        matches: Vec::new(),
    })
}

/// The export of request `id` from `requester`, as `node log export` makes
/// it with the same window and filters, its gzipped log held in memory up
/// to `max` bytes. It never keeps this node's own identity.
pub fn request_export(
    readers: Vec<RecordReader>,
    child: Option<Child>,
    source: &SourceInfo,
    selection: &Selection,
    id: &[u8],
    requester: &str,
    approval: Approval,
    max: usize,
    options: &ExportOptions<'_>,
) -> anyhow::Result<Export<Capped>> {
    let out = Capped {
        data: Vec::new(),
        cap: max,
    };
    let options = ExportOptions {
        keep_self: false,
        ..*options
    };
    let mut produced = log_export::produce(readers, child, source, selection, out, &options)?;
    produced.manifest["tool"] = approval.tool().into();
    produced.manifest["request"] = serde_json::json!({ "id": hex::encode(id), "requester": requester, "approval": approval.label() });
    Ok(produced)
}

/// A sealed bundle and the token map of the values it hides.
#[derive(Debug)]
pub struct Sealed {
    pub sealed: Vec<u8>,
    pub token_map: BTreeMap<String, String>,
    pub lines_kept: u64,
}

/// Seal `export` for request `id` to `recipient`, its sntrup761 key,
/// refusing a sealed bundle over `max` bytes. The gzipped log is dropped
/// once framed, so at most two copies of the bundle are held at once.
pub fn seal_export(
    export: Export<Capped>,
    id: &[u8],
    recipient: &[u8],
    max: usize,
) -> anyhow::Result<Sealed> {
    let (manifest_text, sums) = log_export::bundle_texts(&export.manifest, &export.log)?;
    let Export {
        out,
        token_map,
        stats,
        ..
    } = export;
    let plaintext = pack_bundle(&[
        (BUNDLE_LOG, &out.data),
        ("manifest.json", manifest_text.as_bytes()),
        ("SHA256SUMS", sums.as_bytes()),
    ]);
    drop(out);
    let sealed_len = quil_crypto::seal::sealed_len(plaintext.len());
    if sealed_len > max {
        return Err(TooLarge {
            cap: max,
            sealed: Some(sealed_len),
        }
        .into());
    }
    let sealed = quil_crypto::seal::seal(&plaintext, recipient, id)
        .map_err(|e| anyhow::anyhow!("seal the bundle: {e}"))?;
    Ok(Sealed {
        sealed,
        token_map,
        lines_kept: stats.lines_kept,
    })
}

/// The token map file name of request `id`, written at `now_secs`.
pub fn token_map_name(id: &[u8], now_secs: i64) -> String {
    format!(
        "log-request-{}-{}.map.txt",
        super::short_id(id),
        log_export::compact_ts(now_secs)
    )
}

/// Delete the log request token maps in `dir` older than `keep` at `now`;
/// how many.
pub fn prune_token_maps(
    dir: &Path,
    now: std::time::SystemTime,
    keep: std::time::Duration,
) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("log-request-") && name.ends_with(".map.txt")
        })
        .filter(|entry| {
            entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|at| now.duration_since(at).is_ok_and(|age| age > keep))
        })
        .filter(|entry| std::fs::remove_file(entry.path()).is_ok())
        .count()
}

/// What this node's automatic approval of a request needs: where it reads
/// its logs and keeps token maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApproval {
    /// The node's log directory (`logger.path`).
    pub log_dir: PathBuf,
    /// Its config directory's `.diagnostics/token-maps`.
    pub token_maps: PathBuf,
}

/// The window, filters and key of a request this node approves itself.
#[derive(Debug, Clone)]
pub struct AutoRequest {
    pub id: Vec<u8>,
    /// The requester's peer ID tail, as logs show it.
    pub requester: String,
    pub since_unix: u64,
    pub until_unix: u64,
    pub filters: Vec<Vec<u8>>,
    pub recipient_kem_public_key: Vec<u8>,
}

/// The sealed bundle of an automatic approval and where its token map went.
#[derive(Debug)]
pub struct AutoBundle {
    pub sealed: Vec<u8>,
    pub sha256: Vec<u8>,
    pub token_map: PathBuf,
    pub lines_kept: u64,
}

/// Build `request`'s sealed bundle from the log files of `auto`, at most
/// `max` bytes, as `qclient node diagnostics approve` would, and write its
/// token map (owner-only, in an owner-only directory) beside the earlier
/// ones, deleting those older than [`TOKEN_MAP_RETENTION`]. Blocking: it
/// reads up to a day of logs, and stops with [`Cancelled`] once `cancel`
/// is set, before writing the token map (`salt` set by tests).
pub fn build_automatic(
    auto: &AutoApproval,
    request: &AutoRequest,
    max: usize,
    now_secs: i64,
    cancel: &AtomicBool,
    salt: Option<[u8; 32]>,
) -> anyhow::Result<AutoBundle> {
    build_automatic_with_workers(auto, request, &[], max, now_secs, cancel, salt)
}

/// The lines of a standalone worker from `start` on, as a log source.
struct WorkerLines {
    lines: Arc<[u8]>,
    start: usize,
}

impl AsRef<[u8]> for WorkerLines {
    fn as_ref(&self) -> &[u8] {
        &self.lines[self.start..]
    }
}

/// [`build_automatic`] with the lines of this node's standalone workers
/// (`workers`, [`workers::collect`]), redacted with this node's own and
/// described in the manifest's `workers`. When the bundle would exceed
/// `max`, it is built again from the newest quarter of each worker's lines,
/// then from none, and the manifest records what was left out.
pub fn build_automatic_with_workers(
    auto: &AutoApproval,
    request: &AutoRequest,
    workers: &[WorkerLog],
    max: usize,
    now_secs: i64,
    cancel: &AtomicBool,
    salt: Option<[u8; 32]>,
) -> anyhow::Result<AutoBundle> {
    let selection = request_selection(request.since_unix, request.until_unix, &request.filters)?;
    let home_paths = [auto.log_dir.clone(), auto.token_maps.clone()];
    let literals = workers::literals(workers);
    let steps = if workers.iter().any(|log| !log.lines.is_empty()) {
        3
    } else {
        1
    };
    let mut step = 0;
    let sealed = loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Cancelled.into());
        }
        let (mut readers, names) =
            log_export::file_readers(&auto.log_dir, selection.since, selection.until)?;
        anyhow::ensure!(
            !names.is_empty(),
            "no node log files in {}",
            auto.log_dir.display()
        );
        let mut trimmed = Vec::with_capacity(workers.len());
        for log in workers {
            let start = workers::kept_from(&log.lines, step);
            trimmed.push(start as u64);
            if start < log.lines.len() {
                let lines: Box<dyn BufRead> = Box::new(Cursor::new(WorkerLines {
                    lines: log.lines.clone(),
                    start,
                }));
                readers.push(RecordReader::new(vec![(
                    format!("standalone worker {}", log.core),
                    lines,
                )]));
            }
        }
        let source = SourceInfo::Files(names);
        let options = ExportOptions {
            salt,
            home_paths: &home_paths,
            cancel: Some(cancel),
            literals: &literals,
            ..ExportOptions::default()
        };
        let built = request_export(
            readers,
            None,
            &source,
            &selection,
            &request.id,
            &request.requester,
            Approval::Automatic,
            max,
            &options,
        )
        .and_then(|mut export| {
            if !workers.is_empty() {
                export.manifest["workers"] = workers::manifest(workers, &trimmed);
            }
            seal_export(export, &request.id, &request.recipient_kem_public_key, max)
        });
        match built {
            Ok(sealed) => break sealed,
            Err(error) if is_too_large(&error) && step + 1 < steps => step += 1,
            Err(error) => return Err(error),
        }
    };
    if cancel.load(Ordering::Relaxed) {
        return Err(Cancelled.into());
    }
    super::mkdir_private(&auto.token_maps)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", auto.token_maps.display()))?;
    prune_token_maps(
        &auto.token_maps,
        std::time::SystemTime::now(),
        TOKEN_MAP_RETENTION,
    );
    let token_map = auto.token_maps.join(token_map_name(&request.id, now_secs));
    let about = format!(
        "log request {} of {}",
        super::short_id(&request.id),
        request.requester
    );
    log_export::write_token_map(&token_map, &about, &sealed.token_map)?;
    let sha256 = Sha256::digest(&sealed.sealed).to_vec();
    Ok(AutoBundle {
        sealed: sealed.sealed,
        sha256,
        token_map,
        lines_kept: sealed.lines_kept,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Token maps are kept for 7 days; other files are left alone.
    #[test]
    fn old_token_maps_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let now = std::time::SystemTime::now();
        let old = now - TOKEN_MAP_RETENTION - std::time::Duration::from_secs(60);
        for (name, at) in [
            ("log-request-aa-1.map.txt", old),
            ("log-request-bb-2.map.txt", now),
            ("notes.txt", old),
        ] {
            let file = std::fs::File::create(dir.path().join(name)).unwrap();
            file.set_modified(at).unwrap();
        }
        assert_eq!(prune_token_maps(dir.path(), now, TOKEN_MAP_RETENTION), 1);
        assert!(!dir.path().join("log-request-aa-1.map.txt").exists());
        assert!(
            dir.path().join("log-request-bb-2.map.txt").exists()
                && dir.path().join("notes.txt").exists()
        );
        assert_eq!(
            prune_token_maps(&dir.path().join("absent"), now, TOKEN_MAP_RETENTION),
            0
        );
        assert_eq!(
            token_map_name(&[0xab; 16], 1_792_000_000),
            "log-request-abababab-20261014T174640Z.map.txt"
        );
    }

    /// An export over its cap and a sealed bundle over it are both told
    /// apart from other failures, through the export's I/O errors too.
    #[test]
    fn an_oversized_bundle_is_told_apart_from_other_failures() {
        let mut capped = Capped {
            data: Vec::new(),
            cap: 4,
        };
        assert!(capped.write_all(b"1234").is_ok());
        let io = capped.write_all(b"5").unwrap_err();
        assert!(io.to_string().contains("maxBundleBytes (4 bytes)"), "{io}");
        assert!(is_too_large(&anyhow::Error::from(io).context("export")));
        let sealed = anyhow::Error::from(TooLarge {
            cap: 65_536,
            sealed: Some(70_000),
        });
        assert!(
            is_too_large(&sealed) && sealed.to_string().contains("has 70000 bytes"),
            "{sealed}"
        );
        assert!(!is_too_large(&anyhow::anyhow!("read .log: not found")));
        assert!(!is_too_large(&anyhow::Error::from(std::io::Error::other(
            "disk full"
        ))));
    }

    /// A request's bundle holds what `node log export` makes of its window,
    /// opens with its key alone, and is refused over the cap once sealed.
    #[test]
    fn a_request_export_seals_to_its_key_within_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let line = |time: &str, message: &str| {
            format!("2026-10-14T{time}Z\tinfo\tquil_node/src/main.rs:7\t{message}\t{{}}\n")
        };
        std::fs::write(
            dir.path().join("master.log"),
            [line("11:00:00", "early"), line("12:30:00", "inside")].concat(),
        )
        .unwrap();
        let selection = request_selection(1_791_979_200, 1_791_986_400, &[]).unwrap();
        assert!(
            request_selection(5, 5, &[]).is_err()
                && request_selection(u64::MAX, u64::MAX, &[]).is_err()
        );
        let export = || {
            let (readers, names) =
                log_export::file_readers(dir.path(), selection.since, selection.until).unwrap();
            request_export(
                readers,
                None,
                &SourceInfo::Files(names),
                &selection,
                &[0x3f; 16],
                "…Ab12cd",
                Approval::Automatic,
                1 << 20,
                &ExportOptions::default(),
            )
            .unwrap()
        };
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let sealed = seal_export(export(), &[0x3f; 16], &kem.public, 1 << 20).unwrap();
        assert_eq!(sealed.lines_kept, 1);
        let files = unpack_bundle(
            &quil_crypto::seal::open(&sealed.sealed, &kem.secret, &[0x3f; 16]).unwrap(),
        )
        .unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&files[1]).unwrap();
        assert_eq!(
            (
                manifest["request"]["approval"].as_str(),
                manifest["lines"]["kept"].as_u64()
            ),
            (Some("automatic"), Some(1))
        );
        let small = export().out.data.len();
        let refused = seal_export(export(), &[0x3f; 16], &kem.public, small).unwrap_err();
        assert!(is_too_large(&refused), "{refused}");
    }

    /// This node's automatic export of a request is the export its
    /// operator's approve makes of the same logs: the same redacted lines
    /// and token map under the same salt; a cancelled one writes no map.
    #[test]
    fn the_automatic_export_is_the_operators_export() {
        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join(".log");
        std::fs::create_dir_all(&log_dir).unwrap();
        let line = |time: &str, level: &str, message: &str, fields: &str| {
            format!("2026-10-14T{time}Z\t{level}\tquil_node/src/main.rs:7\t{message}\t{fields}\n")
        };
        std::fs::write(log_dir.join("master.log"), [
            line("12:10:00", "info", "dialing 192.0.2.10:8340", r#"{"coreId":0,"filter":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}"#),
            line("12:20:00", "warn", "store open failed", r#"{"error":"open /home/alice/quil/.config/store: denied"}"#),
            line("12:30:00", "info", "other shard", r#"{"filter":"b2b2"}"#),
        ].concat()).unwrap();
        std::fs::write(
            log_dir.join("worker-1.log"),
            line("12:15:00", "info", "peer /ip4/198.51.100.7/tcp/8336", "{}"),
        )
        .unwrap();
        let auto = AutoApproval {
            log_dir: log_dir.clone(),
            token_maps: dir.path().join("maps"),
        };
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let request = AutoRequest {
            id: vec![0x3f; 16],
            requester: "…Ab12cd".into(),
            since_unix: 1_791_979_200,
            until_unix: 1_791_986_400,
            filters: vec![vec![0xa1; 32]],
            recipient_kem_public_key: kem.public.clone(),
        };
        let salt = Some([5u8; 32]);
        let built = build_automatic(
            &auto,
            &request,
            1 << 20,
            1_791_986_400,
            &AtomicBool::new(false),
            salt,
        )
        .unwrap();
        let files = unpack_bundle(
            &quil_crypto::seal::open(&built.sealed, &kem.secret, &request.id).unwrap(),
        )
        .unwrap();

        let selection =
            request_selection(request.since_unix, request.until_unix, &request.filters).unwrap();
        let (readers, names) =
            log_export::file_readers(&log_dir, selection.since, selection.until).unwrap();
        let home_paths = [auto.log_dir.clone(), auto.token_maps.clone()];
        let options = ExportOptions {
            salt,
            home_paths: &home_paths,
            ..ExportOptions::default()
        };
        let manual = request_export(
            readers,
            None,
            &SourceInfo::Files(names),
            &selection,
            &request.id,
            "…Ab12cd",
            Approval::Operator,
            1 << 20,
            &options,
        )
        .unwrap();
        let text = |gz: &[u8]| {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(gz), &mut text)
                .unwrap();
            text
        };
        let (automatic_text, manual_text) = (text(&files[0]), text(&manual.out.data));
        assert_eq!(automatic_text, manual_text, "the same redacted records");
        assert_eq!(
            automatic_text.lines().count(),
            2,
            "the filter's line and the warning: {automatic_text}"
        );
        assert!(
            !automatic_text.contains("192.0.2.10") && !automatic_text.contains("alice"),
            "{automatic_text}"
        );
        let map: BTreeMap<String, String> = std::fs::read_to_string(&built.token_map)
            .unwrap()
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once('\t'))
            .map(|(t, v)| (t.to_string(), v.to_string()))
            .collect();
        assert_eq!(map, manual.token_map, "the same token map");

        let maps_before = std::fs::read_dir(&auto.token_maps).unwrap().count();
        let error = build_automatic(
            &auto,
            &AutoRequest {
                id: vec![0x3e; 16],
                ..request
            },
            1 << 20,
            1_791_986_401,
            &AtomicBool::new(true),
            salt,
        )
        .unwrap_err();
        assert!(log_export::is_cancelled(&error), "{error:#}");
        assert_eq!(
            std::fs::read_dir(&auto.token_maps).unwrap().count(),
            maps_before,
            "no token map of a cancelled export"
        );
    }

    fn worker_log(core: u32, lines: String) -> WorkerLog {
        WorkerLog {
            core,
            status: workers::WorkerStatus::Collected,
            summary: Some(quil_types::proto::node::ExportWorkerLogsSummary {
                files: vec![format!("worker-{core}.log")],
                line_bytes: lines.len() as u64,
                hosts: vec!["workerhost".into()],
                users: vec!["workeruser".into()],
                ..Default::default()
            }),
            lines: Arc::from(lines.into_bytes()),
            detail: None,
        }
    }

    fn info_line(time: &str, message: &str, fields: &str) -> String {
        format!("2026-10-14T{time}Z\tinfo\tquil_node/src/main.rs:7\t{message}\t{fields}\n")
    }

    /// A node with `master` in its log directory, and a request for its
    /// 12:00-14:00 window sealed to `kem`.
    fn node_with(master: &str, kem: &[u8]) -> (tempfile::TempDir, AutoApproval, AutoRequest) {
        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join(".log");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(log_dir.join("master.log"), master).unwrap();
        let auto = AutoApproval {
            log_dir,
            token_maps: dir.path().join("maps"),
        };
        let request = AutoRequest {
            id: vec![0x3f; 16],
            requester: "…Ab12cd".into(),
            since_unix: 1_791_979_200,
            until_unix: 1_791_986_400,
            filters: Vec::new(),
            recipient_kem_public_key: kem.to_vec(),
        };
        (dir, auto, request)
    }

    /// The bundle's log text and manifest.
    fn opened(
        built: &AutoBundle,
        kem: &quil_crypto::Sntrup761KeyPair,
    ) -> (String, serde_json::Value) {
        let files = unpack_bundle(
            &quil_crypto::seal::open(&built.sealed, &kem.secret, &[0x3f; 16]).unwrap(),
        )
        .unwrap();
        let mut text = String::new();
        std::io::Read::read_to_string(
            &mut flate2::read::GzDecoder::new(files[0].as_slice()),
            &mut text,
        )
        .unwrap();
        (text, serde_json::from_slice(&files[1]).unwrap())
    }

    /// A standalone worker's lines join this node's in time order and are
    /// redacted by the same redactor: an address both hosts logged gets one
    /// token, and the worker's host and user names are hidden. The manifest
    /// records each worker's outcome, the unreachable one too.
    #[test]
    fn standalone_workers_lines_join_the_bundle_redacted_once() {
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let master = [
            info_line("12:10:00", "dialing 192.0.2.10:8340", r#"{"coreId":0}"#),
            info_line("12:30:00", "master later", r#"{"coreId":0}"#),
        ]
        .concat();
        let (_dir, auto, request) = node_with(&master, &kem.public);
        let logs = vec![
            worker_log(
                2,
                info_line(
                    "12:20:00",
                    "dialing 192.0.2.10:8340 from workerhost as workeruser",
                    r#"{"coreId":2}"#,
                ),
            ),
            WorkerLog {
                core: 3,
                status: workers::WorkerStatus::Unreachable(
                    tonic::Code::Unavailable.description().to_string(),
                ),
                summary: None,
                lines: Arc::from(Vec::new()),
                detail: None,
            },
        ];
        let built = build_automatic_with_workers(
            &auto,
            &request,
            &logs,
            1 << 20,
            1_791_986_400,
            &AtomicBool::new(false),
            Some([5; 32]),
        )
        .unwrap();
        let (text, manifest) = opened(&built, &kem);
        let messages: Vec<&str> = text
            .lines()
            .map(|line| line.split('\t').nth(3).unwrap_or(line))
            .collect();
        assert_eq!(messages.len(), 3, "{text}");
        assert!(
            messages[1].starts_with("dialing ") && messages[2] == "master later",
            "{text}"
        );
        assert!(
            !text.contains("192.0.2.10")
                && !text.contains("workerhost")
                && !text.contains("workeruser"),
            "{text}"
        );
        let map: BTreeMap<String, String> = std::fs::read_to_string(&built.token_map)
            .unwrap()
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once('\t'))
            .map(|(t, v)| (t.to_string(), v.to_string()))
            .collect();
        let address: Vec<&String> = map
            .iter()
            .filter(|(_, value)| value.contains("192.0.2.10"))
            .map(|(token, _)| token)
            .collect();
        assert_eq!(address.len(), 1, "{map:?}");
        assert_eq!(text.matches(address[0].as_str()).count(), 2, "{text}");
        assert!(map.values().any(|value| value == "workerhost"), "{map:?}");
        assert_eq!(manifest["lines"]["kept"], 3);
        assert_eq!(manifest["workers"][0]["status"], "collected");
        assert_eq!(manifest["workers"][1]["status"], "unreachable");
        assert_eq!(manifest["workers"].as_array().unwrap().len(), 2);
    }

    /// A bundle over its cap with a worker's lines is built again from the
    /// newest quarter of them, and the manifest says how much was left out;
    /// one over its cap without them is refused as before.
    #[test]
    fn a_bundle_over_its_cap_keeps_the_newest_worker_lines() {
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let master = info_line("12:05:00", "master", r#"{"coreId":0}"#);
        let (_dir, auto, request) = node_with(&master, &kem.public);
        let words = |seed: u32| -> String {
            Sha256::digest(seed.to_le_bytes())
                .iter()
                .map(|byte| char::from(b'a' + byte % 26))
                .collect()
        };
        let lines: String = (0..600u32)
            .map(|i| {
                info_line(
                    &format!("12:{:02}:{:02}", 10 + i / 60, i % 60),
                    &format!(
                        "w{i} {} {} {}",
                        words(3 * i),
                        words(3 * i + 1),
                        words(3 * i + 2)
                    ),
                    r#"{"coreId":2}"#,
                )
            })
            .collect();
        let mut now = 1_791_986_400;
        let mut build = |logs: &[WorkerLog], max: usize| {
            now += 1;
            build_automatic_with_workers(
                &auto,
                &request,
                logs,
                max,
                now,
                &AtomicBool::new(false),
                Some([5; 32]),
            )
        };
        let logs = vec![worker_log(2, lines.clone())];
        let full = build(&logs, 1 << 22).unwrap().sealed.len();
        let start = workers::kept_from(lines.as_bytes(), 1);
        let quarter = build(&[worker_log(2, lines[start..].to_string())], 1 << 22)
            .unwrap()
            .sealed
            .len();
        assert!(full > quarter + 8000, "{full} against {quarter}");
        let built = build(&logs, quarter + 2000).unwrap();
        let (text, manifest) = opened(&built, &kem);
        assert!(
            text.contains("\tw599 ") && !text.contains("\tw0 ") && text.contains("\tmaster\t"),
            "{text}"
        );
        assert_eq!(manifest["workers"][0]["status"], "truncated");
        assert_eq!(
            manifest["workers"][0]["left_out_for_bundle_cap"]["bytes"],
            start as u64
        );
        let refused = build(&logs, 200).unwrap_err();
        assert!(is_too_large(&refused), "{refused:#}");
    }
}
