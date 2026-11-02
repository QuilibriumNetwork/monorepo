//! The private action log: `<config_dir>/wallet/actions.jsonl`, one JSON
//! record per step of a wallet action (a shield's start, each batch, its
//! outcome; a mint's or a transfer's start and outcome) with the details
//! the operator log leaves out: amounts, fees, the recipient and the coin
//! or escrow addresses. It is for the owner to consult and
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

/// One action's records: each stamped with its `kind` and `source`, the
/// last with the outcome and the duration. After a failed write it writes
/// nothing more and reports the reason once.
#[cfg(feature = "native-proof")]
pub(crate) struct ActionRecorder {
    log: Option<ActionLog>,
    /// `shield`, `mint`, `transfer`, ...: the action.
    kind: &'static str,
    /// `cli` or `manager`: the program that ran it.
    source: &'static str,
    started: std::time::Instant,
}

#[cfg(feature = "native-proof")]
impl ActionRecorder {
    pub(crate) fn new(log: Option<ActionLog>, kind: &'static str, source: &'static str) -> Self {
        Self {
            log,
            kind,
            source,
            started: std::time::Instant::now(),
        }
    }

    /// The action's outcome and duration.
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

    /// One record of `phase` with `fields` (an object); why it was not
    /// written, the first time a write fails.
    pub(crate) fn write(&mut self, phase: &str, mut fields: serde_json::Value) -> Option<String> {
        let log = self.log.as_ref()?;
        if let Some(fields) = fields.as_object_mut() {
            fields.insert("source".into(), self.source.into());
        }
        let error = log.append(self.kind, phase, fields).err()?;
        self.log = None;
        Some(format!("{error:#}"))
    }
}

/// The operator log's target: `RUST_LOG=qclient::action=info` shows its
/// lines on stderr; redirect it to a file while the node manager draws.
pub(crate) const LOG_TARGET: &str = "qclient::action";

/// What went wrong, as the operator log names it: a fixed class and its
/// fixed reason. The error text itself can carry the node's address, a
/// config path or amounts, so it stays on screen and in the private log.
pub(crate) fn error_class(error: &str) -> (&'static str, &'static str) {
    let has = |part: &str| error.contains(part);
    if has("--max-fee") || has("automatic fee limit") {
        ("fee_cap", "a fee quote exceeds --max-fee")
    } else if has("plan changed") {
        ("plan_changed", "the coins changed since the confirmation")
    } else if has("reward changed") {
        (
            "reward_changed",
            "the reward changed since the confirmation",
        )
    } else if has("not finalized") {
        ("not_finalized", "GLOBAL holds no witness for it yet")
    } else if has("accepts only submissions signed") {
        ("identity", "the signing config is not the node's")
    } else if has("shields") && has("open") {
        ("not_open", "shields are not admitted yet")
    } else if has("prov") || has("budget") {
        ("proving", "a proof failed")
    } else if has("transport") || has("status:") || has("connect") || has("deadline") {
        ("rpc", "a node request failed")
    } else if has("no node config") {
        ("config", "the node config did not load")
    } else {
        (
            "other",
            "unclassified; the error is on screen and in the private log",
        )
    }
}

/// A wallet command run from the CLI (`token mint`, ...): its private
/// records (the command's inputs at the start, its steps, the outcome) and
/// its two operator lines on [`LOG_TARGET`], which carry the action, the
/// outcome, an error class and the duration, never an input. A refused
/// write is said once on stderr; the command runs on.
#[cfg(feature = "native-proof")]
pub(crate) struct CliAction {
    record: ActionRecorder,
    kind: &'static str,
    started: std::time::Instant,
}

#[cfg(feature = "native-proof")]
impl CliAction {
    /// `command`'s action, recorded under `config_dir` unless the qclient
    /// config turns the log off; `None` for a command that is not one.
    pub(crate) fn start(config_dir: &Path, command: &super::TokenCommand) -> Option<Self> {
        Self::with_log(ActionLog::enabled(config_dir, false), command)
    }

    pub(crate) fn with_log(log: Option<ActionLog>, command: &super::TokenCommand) -> Option<Self> {
        let (kind, fields) = cli_action(command)?;
        let mut action = Self {
            record: ActionRecorder::new(log, kind, "cli"),
            kind,
            started: std::time::Instant::now(),
        };
        tracing::info!(
            target: LOG_TARGET,
            kind,
            phase = "start",
            source = "cli",
            "wallet action started"
        );
        action.step("start", fields);
        Some(action)
    }

    /// One record of `phase` with `fields`.
    pub(crate) fn step(&mut self, phase: &str, fields: serde_json::Value) {
        if let Some(why) = self.record.write(phase, fields) {
            eprintln!(
                "Action log: not written ({why}); the {} is unaffected.",
                self.kind.replace('_', " ")
            );
        }
    }

    /// The outcome record and operator line; `result` passes through.
    pub(crate) fn finish<T>(mut self, result: anyhow::Result<T>) -> anyhow::Result<T> {
        let outcome = result.as_ref().map(|_| ()).map_err(|e| format!("{e:#}"));
        if let Some(why) = self.record.outcome(&outcome) {
            eprintln!(
                "Action log: not written ({why}); the {} is unaffected.",
                self.kind.replace('_', " ")
            );
        }
        let (name, (class, reason)) = match &outcome {
            Ok(()) => ("ok", ("none", "")),
            Err(error) => ("failed", error_class(error)),
        };
        tracing::info!(
            target: LOG_TARGET,
            kind = self.kind,
            phase = "outcome",
            source = "cli",
            outcome = name,
            error_class = class,
            reason,
            fee_cap_hit = class == "fee_cap",
            duration_s = self.started.elapsed().as_secs(),
            "wallet action finished"
        );
        result
    }
}

/// The recorded action of a CLI command and its inputs as given, or `None`
/// for a command that is none.
#[cfg(feature = "native-proof")]
fn cli_action(command: &super::TokenCommand) -> Option<(&'static str, serde_json::Value)> {
    use super::TokenCommand;
    let fee = |fee: &Option<u128>| fee.map(|fee| fee.to_string());
    Some(match command {
        TokenCommand::Mint {
            recipient,
            fee: given,
            claim: None,
        } => (
            "mint",
            serde_json::json!({ "recipient": recipient, "fee": fee(given) }),
        ),
        TokenCommand::Mint {
            claim: Some(path), ..
        } => (
            "mint_claim",
            serde_json::json!({
                "file": path.file_name().map(|name| name.to_string_lossy().into_owned()),
            }),
        ),
        _ => return None,
    })
}

/// A shield run's records, shared by `token shield-all` and the node
/// manager: the plan at the start, each batch submitted or skipped, and the
/// outcome.
#[cfg(feature = "native-proof")]
pub(crate) struct ShieldRecorder(ActionRecorder);

#[cfg(feature = "native-proof")]
impl ShieldRecorder {
    pub(crate) fn new(log: Option<ActionLog>, source: &'static str) -> Self {
        Self(ActionRecorder::new(log, "shield", source))
    }

    /// The plan about to run, and the fee cap.
    pub(crate) fn start(
        &mut self,
        plan: &super::wallet::ShieldAllPlan,
        max_fee: u128,
    ) -> Option<String> {
        let (coins, units) = plan.totals().unwrap_or_default();
        self.0.write(
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
            } => self.0.write(
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
            } => self.0.write(
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
        self.0.outcome(result)
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

    /// A recorder stamps each record with its kind and source and ends with
    /// the outcome; after a refused write it writes nothing more and says
    /// why once.
    #[cfg(feature = "native-proof")]
    #[test]
    fn a_recorder_stamps_its_records_and_stops_after_a_refused_write() {
        let config = tempfile::tempdir().unwrap();
        let log = ActionLog::new(config.path());
        let mut record = ActionRecorder::new(Some(log.clone()), "transfer", "manager");
        assert_eq!(
            record.write("start", serde_json::json!({ "amount": "5" })),
            None
        );
        assert_eq!(record.outcome(&Err("fee changed".into())), None);
        let written = records(&log);
        assert_eq!(written.len(), 2);
        assert!(written
            .iter()
            .all(|r| r["kind"] == "transfer" && r["source"] == "manager"));
        assert_eq!(written[0]["amount"], "5");
        assert_eq!(
            (&written[1]["outcome"], &written[1]["error"]),
            (
                &serde_json::json!("failed"),
                &serde_json::json!("fee changed")
            )
        );
        std::fs::set_permissions(log.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut record = ActionRecorder::new(Some(log.clone()), "mint", "manager");
        assert_eq!(
            record.write("start", serde_json::json!({})).as_deref(),
            Some("wallet/actions.jsonl has mode 644; the action log needs 600 (owner only)")
        );
        assert_eq!(record.outcome(&Ok(())), None);
        assert_eq!(records(&log).len(), 2);
        // Off: nothing is written and nothing is said.
        let mut record = ActionRecorder::new(None, "mint", "manager");
        assert_eq!(record.write("start", serde_json::json!({})), None);
    }

    /// The operator log's lines `work` writes.
    #[cfg(feature = "native-proof")]
    fn operator_log(work: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let capture = Capture::default();
        let sink = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .without_time()
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, work);
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    /// The CLI's wallet commands, each with private inputs, and the action
    /// each records.
    #[cfg(feature = "native-proof")]
    fn cli_commands() -> Vec<(Vec<String>, &'static str)> {
        let recipient = format!("0x{}", "c3".repeat(60));
        let file = "/home/operator/.config/mint-1201.bin".to_string();
        let s = |parts: &[&str]| parts.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        vec![
            (s(&["mint", &recipient, "--fee", "98765"]), "mint"),
            (s(&["mint", "--claim", &file]), "mint_claim"),
        ]
    }

    /// Each CLI wallet command records its inputs and outcome in the
    /// private log; its operator lines name the action, the outcome and an
    /// error class, never an input or the error's text.
    #[cfg(feature = "native-proof")]
    #[test]
    fn cli_actions_record_privately_and_log_no_input() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            token: super::super::TokenArgs,
        }
        for (arguments, kind) in cli_commands() {
            let config = tempfile::tempdir().unwrap();
            let log = ActionLog::new(config.path());
            let command =
                Cli::try_parse_from([&["token".to_string()][..], &arguments[..]].concat())
                    .unwrap()
                    .token
                    .command;
            let text = operator_log(|| {
                let action = CliAction::with_log(Some(log.clone()), &command)
                    .unwrap_or_else(|| panic!("{kind} is not recorded"));
                let failed: anyhow::Result<()> = Err(anyhow::anyhow!(
                    "the estimated fee of 98765 base units exceeds the automatic fee limit for \
                     {} at 10.1.2.3:8337 (/home/operator/.config); raise --max-fee",
                    arguments.join(" ")
                ));
                assert!(action.finish(failed).is_err());
            });
            let written = records(&log);
            let phases: Vec<&str> = written
                .iter()
                .map(|r| r["phase"].as_str().unwrap())
                .collect();
            assert_eq!(phases, ["start", "outcome"], "{kind}");
            assert!(
                written
                    .iter()
                    .all(|r| r["kind"] == kind && r["source"] == "cli"),
                "{kind}: {written:?}"
            );
            assert_eq!(written[1]["outcome"], "failed", "{kind}");
            let recorded = written[0].to_string();
            let inputs: Vec<&String> = arguments
                .iter()
                .filter(|a| !a.starts_with("--") && a.len() > 5)
                .collect();
            assert!(
                inputs
                    .iter()
                    .any(|input| recorded
                        .contains(input.trim_start_matches("/home/operator/.config/"))),
                "{kind}: no input recorded in {recorded}"
            );
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 2, "{kind}: {text}");
            let name = format!("kind=\"{kind}\"");
            for part in [&name, r#"source="cli""#, r#"phase="start""#] {
                assert!(lines[0].contains(part), "{part}: {}", lines[0]);
            }
            for part in [
                &name,
                r#"phase="outcome""#,
                r#"outcome="failed""#,
                r#"error_class="fee_cap""#,
                "fee_cap_hit=true",
                "duration_s=",
            ] {
                assert!(lines[1].contains(part), "{part}: {}", lines[1]);
            }
            for private in [
                "c3c3",
                "98765",
                "10.1.2.3",
                "/home/",
                "mint-1201",
                "abab",
                "4321",
            ] {
                assert!(
                    !text.contains(private),
                    "{kind}: {private} reached the log:\n{text}"
                );
            }
        }
        // Not a wallet action: nothing recorded.
        let command = Cli::try_parse_from(["token", "balance"])
            .unwrap()
            .token
            .command;
        assert!(CliAction::with_log(None, &command).is_none());
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
