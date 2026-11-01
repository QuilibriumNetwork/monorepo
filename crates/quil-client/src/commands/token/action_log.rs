//! The private action log: `<config_dir>/wallet/actions.jsonl`, one JSON
//! record per step of a wallet action (a shield's start, each batch, its
//! outcome) with the details the operator log leaves out: amounts, fees,
//! the recipient and the coin addresses. It is for the owner to consult and
//! share selectively, so it stays on this machine, readable by its owner
//! only: the directory is created 0700 and the file 0600, and a wider mode
//! or a link in their place refuses the write. It lies outside the node's
//! `.log/`, so log exports and log requests never carry it, and nothing
//! draws it. It keeps [`MAX_AGE`] of records within [`MAX_BYTES`].
//! `--no-action-log` (node manager) or `noActionLog: true` in the qclient
//! config turns it off.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The log's directory under the node config directory, and its file.
pub(crate) const DIR: &str = "wallet";
pub(crate) const FILE: &str = "actions.jsonl";

/// The largest the file grows; past it the oldest records go, down to half.
pub(crate) const MAX_BYTES: u64 = 4 << 20;

/// How long a record is kept.
pub(crate) const MAX_AGE: Duration = Duration::from_secs(365 * 24 * 3600);

/// The action log of one node config directory.
#[derive(Clone, Debug)]
pub(crate) struct ActionLog {
    dir: PathBuf,
    max_bytes: u64,
    max_age: Duration,
}

impl ActionLog {
    /// The log under `config_dir`, unless `off` (`--no-action-log`) or the
    /// qclient config turns it off.
    pub(crate) fn enabled(config_dir: &Path, off: bool) -> Option<Self> {
        (!off && !crate::config::action_log_off()).then(|| Self::new(config_dir))
    }

    pub(crate) fn new(config_dir: &Path) -> Self {
        Self {
            dir: config_dir.join(DIR),
            max_bytes: MAX_BYTES,
            max_age: MAX_AGE,
        }
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.dir.join(FILE)
    }

    /// Append one record of `kind` and `phase` with `fields` (an object),
    /// stamped with the time (`ts`, Unix seconds).
    pub(crate) fn append(
        &self,
        kind: &str,
        phase: &str,
        fields: serde_json::Value,
    ) -> anyhow::Result<()> {
        let now = unix_now();
        let mut record = serde_json::json!({ "ts": now, "kind": kind, "phase": phase });
        if let (Some(record), serde_json::Value::Object(fields)) = (record.as_object_mut(), fields)
        {
            record.extend(fields);
        }
        let mut line = serde_json::to_string(&record)?;
        line.push('\n');
        private::ensure_dir(&self.dir)?;
        let path = self.path();
        self.bound(&path, now, line.len() as u64)?;
        private::open_append(&path)?.write_all(line.as_bytes())?;
        Ok(())
    }

    /// Drop records older than the age bound, and the oldest beyond half
    /// the size bound when `adding` bytes would pass it, by an atomic
    /// rewrite.
    fn bound(&self, path: &Path, now: u64, adding: u64) -> anyhow::Result<()> {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return Ok(());
        };
        let max_age = self.max_age.as_secs();
        let old = |line: &str| record_ts(line).is_none_or(|ts| now.saturating_sub(ts) > max_age);
        let mut first = String::new();
        std::io::BufReader::new(private::open_read(path)?).read_line(&mut first)?;
        if meta.len() + adding <= self.max_bytes && !old(&first) {
            return Ok(());
        }
        let text = std::io::read_to_string(private::open_read(path)?)?;
        let kept: Vec<&str> = text.lines().filter(|line| !old(line)).collect();
        let mut size: u64 = kept.iter().map(|line| line.len() as u64 + 1).sum();
        let mut start = 0;
        while start < kept.len() && size + adding > self.max_bytes / 2 {
            size -= kept[start].len() as u64 + 1;
            start += 1;
        }
        let mut body = kept[start..].join("\n");
        if !body.is_empty() {
            body.push('\n');
        }
        private::replace(path, body.as_bytes())
    }
}

/// A record's `ts`, or `None` for a line that is no record.
fn record_ts(line: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("ts")?
        .as_u64()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Owner-only file access: every path is checked before and after it is
/// opened, so a link or a wider mode refuses the write.
#[cfg(unix)]
mod private {
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::Path;

    /// The path as named under the config directory: no private path
    /// reaches a message.
    fn name(path: &Path) -> String {
        let file = path.file_name().unwrap_or_default().to_string_lossy();
        if file == super::DIR {
            file.into_owned()
        } else {
            format!("{}/{file}", super::DIR)
        }
    }

    fn owner_only(path: &Path, meta: &std::fs::Metadata, wanted: u32) -> anyhow::Result<()> {
        anyhow::ensure!(
            meta.mode() & 0o077 == 0,
            "{} has mode {:o}; the action log needs {wanted:o} (owner only)",
            name(path),
            meta.mode() & 0o777
        );
        Ok(())
    }

    /// Create `dir` 0700 unless it exists; refuse one that is a link or
    /// open to others.
    pub(super) fn ensure_dir(dir: &Path) -> anyhow::Result<()> {
        let meta = match std::fs::symlink_metadata(dir) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => anyhow::bail!("{}: {e}", name(dir)),
                }
                std::fs::symlink_metadata(dir)?
            }
            Err(e) => anyhow::bail!("{}: {e}", name(dir)),
        };
        anyhow::ensure!(meta.is_dir(), "{} is not a directory", name(dir));
        owner_only(dir, &meta, 0o700)
    }

    /// Refuse a path that is a link or no regular file, or open to others.
    fn check(path: &Path) -> anyhow::Result<Option<std::fs::Metadata>> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                anyhow::ensure!(meta.is_file(), "{} is not a regular file", name(path));
                owner_only(path, &meta, 0o600)?;
                Ok(Some(meta))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => anyhow::bail!("{}: {e}", name(path)),
        }
    }

    /// The file opened is the one checked: no link was swapped in.
    fn same(path: &Path, file: &File) -> anyhow::Result<()> {
        let opened = file.metadata()?;
        let named = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            opened.is_file() && opened.ino() == named.ino() && opened.dev() == named.dev(),
            "{} changed while it was opened",
            name(path)
        );
        owner_only(path, &opened, 0o600)
    }

    /// Open for appending, created 0600 if missing.
    pub(super) fn open_append(path: &Path) -> anyhow::Result<File> {
        check(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        same(path, &file)?;
        Ok(file)
    }

    pub(super) fn open_read(path: &Path) -> anyhow::Result<File> {
        check(path)?;
        let file = File::open(path)?;
        same(path, &file)?;
        Ok(file)
    }

    /// Replace `path` with `body` through a new 0600 file renamed over it.
    pub(super) fn replace(path: &Path, body: &[u8]) -> anyhow::Result<()> {
        use std::io::Write;
        let temp = path.with_extension(format!("jsonl.tmp-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        let written = file
            .write_all(body)
            .and_then(|()| file.sync_all())
            .and_then(|()| std::fs::rename(&temp, path));
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        Ok(written?)
    }
}

/// No owner-only modes to rely on: the log is not written.
#[cfg(not(unix))]
mod private {
    use std::fs::File;
    use std::path::Path;

    const REFUSED: &str = "this platform has no owner-only file modes";

    pub(super) fn ensure_dir(_dir: &Path) -> anyhow::Result<()> {
        anyhow::bail!(REFUSED)
    }

    pub(super) fn open_append(_path: &Path) -> anyhow::Result<File> {
        anyhow::bail!(REFUSED)
    }

    pub(super) fn open_read(_path: &Path) -> anyhow::Result<File> {
        anyhow::bail!(REFUSED)
    }

    pub(super) fn replace(_path: &Path, _body: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!(REFUSED)
    }
}

/// A shield run's records, shared by `token shield-all` and the node
/// manager: the plan at the start, each batch submitted or skipped, and the
/// outcome. After a failed write it writes nothing more and reports the
/// reason once.
#[cfg(feature = "native-proof")]
pub(crate) struct ShieldRecorder {
    log: Option<ActionLog>,
    /// `cli` or `manager`: the program that ran the shield.
    source: &'static str,
    started: std::time::Instant,
}

#[cfg(feature = "native-proof")]
impl ShieldRecorder {
    pub(crate) fn new(log: Option<ActionLog>, source: &'static str) -> Self {
        Self {
            log,
            source,
            started: std::time::Instant::now(),
        }
    }

    /// The plan about to run, and the fee cap.
    pub(crate) fn start(
        &mut self,
        plan: &super::wallet::ShieldAllPlan,
        max_fee: u128,
    ) -> Option<String> {
        let (coins, units) = plan.totals().unwrap_or_default();
        self.write(
            "start",
            serde_json::json!({
                "batches": plan.batches.len(),
                "coins": coins,
                "units": units.to_string(),
                "max_fee": max_fee.to_string(),
                "recipient": plan.recipient(),
                "listed": plan.listed,
                "shielded": plan.shielded,
                "uncovered": plan.uncovered,
                "pending": plan.pending,
                "duplicates": plan.duplicates,
            }),
        )
    }

    /// A batch submitted or skipped; other events are not recorded.
    pub(crate) fn event(&mut self, event: &super::wallet::ShieldEvent) -> Option<String> {
        use super::wallet::ShieldEvent;
        match event {
            ShieldEvent::Submitted {
                index,
                count,
                addresses,
                shielded,
                fee,
            } => self.write(
                "submitted",
                serde_json::json!({
                    "batch": index,
                    "of": count,
                    "coins": addresses.iter().map(hex::encode).collect::<Vec<_>>(),
                    "shielded": shielded.to_string(),
                    "fee": fee.to_string(),
                }),
            ),
            ShieldEvent::Skipped {
                index,
                count,
                coins,
                total,
                fee,
            } => self.write(
                "skipped",
                serde_json::json!({
                    "batch": index,
                    "of": count,
                    "coins": coins,
                    "units": total.to_string(),
                    "fee": fee.to_string(),
                }),
            ),
            ShieldEvent::Nothing { .. }
            | ShieldEvent::Uncovered(_)
            | ShieldEvent::Proving { .. } => None,
        }
    }

    /// The run's outcome and duration.
    pub(crate) fn outcome(&mut self, result: &Result<(), String>) -> Option<String> {
        let took = self.started.elapsed().as_secs();
        self.write(
            "outcome",
            match result {
                Ok(()) => serde_json::json!({ "outcome": "ok", "duration_s": took }),
                Err(error) => {
                    serde_json::json!({ "outcome": "failed", "error": error, "duration_s": took })
                }
            },
        )
    }

    fn write(&mut self, phase: &str, mut fields: serde_json::Value) -> Option<String> {
        let log = self.log.as_ref()?;
        if let Some(fields) = fields.as_object_mut() {
            fields.insert("source".into(), self.source.into());
        }
        let error = log.append("shield", phase, fields).err()?;
        self.log = None;
        Some(format!("{error:#}"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn records(log: &ActionLog) -> Vec<serde_json::Value> {
        std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The first write creates the directory 0700 and the file 0600; each
    /// record is one JSON line with its time, kind and phase.
    #[test]
    fn the_log_is_created_owner_only_and_appends_records() {
        let config = tempfile::tempdir().unwrap();
        let log = ActionLog::new(config.path());
        log.append("shield", "start", serde_json::json!({ "batches": 2 }))
            .unwrap();
        log.append("shield", "outcome", serde_json::json!({ "outcome": "ok" }))
            .unwrap();
        assert_eq!(mode(&config.path().join(DIR)), 0o700);
        assert_eq!(mode(&log.path()), 0o600);
        let records = records(&log);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["kind"], "shield");
        assert_eq!(records[0]["phase"], "start");
        assert_eq!(records[0]["batches"], 2);
        assert!(records[1]["ts"].as_u64().unwrap() > 1_700_000_000);
    }

    /// A directory or file open to others, or a link in place of the
    /// file, refuses the write and nothing is written.
    #[test]
    fn a_wider_mode_or_a_link_refuses_the_write() {
        let fields = || serde_json::json!({});
        let config = tempfile::tempdir().unwrap();
        let log = ActionLog::new(config.path());
        log.append("shield", "start", fields()).unwrap();
        let dir = config.path().join(DIR);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = log.append("shield", "x", fields()).unwrap_err().to_string();
        assert_eq!(
            error,
            "wallet has mode 755; the action log needs 700 (owner only)"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(log.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = log.append("shield", "x", fields()).unwrap_err().to_string();
        assert_eq!(
            error,
            "wallet/actions.jsonl has mode 644; the action log needs 600 (owner only)"
        );
        assert_eq!(records(&log).len(), 1);
        std::fs::remove_file(log.path()).unwrap();
        let elsewhere = config.path().join("elsewhere");
        std::fs::write(&elsewhere, "").unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&elsewhere, log.path()).unwrap();
        let error = log.append("shield", "x", fields()).unwrap_err().to_string();
        assert_eq!(error, "wallet/actions.jsonl is not a regular file");
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "");
    }

    /// Past the size bound the oldest records go, down to half of it;
    /// records past the age bound go at the next write.
    #[test]
    fn the_log_is_bounded_by_size_and_age() {
        let config = tempfile::tempdir().unwrap();
        let mut log = ActionLog::new(config.path());
        log.max_bytes = 2_000;
        for index in 0..60 {
            log.append("shield", "submitted", serde_json::json!({ "batch": index }))
                .unwrap();
            assert!(std::fs::metadata(log.path()).unwrap().len() <= 2_000);
        }
        let kept = records(&log);
        assert_eq!(kept.last().unwrap()["batch"], 59);
        assert!(kept[0]["batch"].as_u64().unwrap() > 0, "{kept:?}");
        assert_eq!(mode(&log.path()), 0o600);
        // A record a year and a day old, then a new one: the old one goes.
        let now = unix_now();
        let old = format!(
            "{{\"ts\":{},\"kind\":\"shield\",\"phase\":\"start\"}}\n",
            now - MAX_AGE.as_secs() - 86_400
        );
        std::fs::write(log.path(), old).unwrap();
        log.max_bytes = MAX_BYTES;
        log.append("shield", "start", serde_json::json!({ "batches": 1 }))
            .unwrap();
        let kept = records(&log);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["batches"], 1);
    }
}
