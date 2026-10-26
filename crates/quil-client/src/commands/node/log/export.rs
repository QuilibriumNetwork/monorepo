//! `qclient node log export` — a redacted node log bundle to attach to a
//! bug report.
//!
//! Reads the node's log files (live and rotated, every core) or the
//! service's journal over a time window and exports it with
//! [`quil_rpc::log_export`], which the node's own approval of a peer's log
//! request shares; writes a directory with `node.log.gz`, `manifest.json`
//! and `SHA256SUMS`, after a preview the operator confirms. The token →
//! original map goes to a private file beside the bundle.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use clap::{Args, ValueEnum};
use quil_rpc::log_export::{
    bundle_texts, compact_ts, file_readers, parse_when, preview, produce, write_token_map,
    ExportOptions, RecordReader, Selection, SourceInfo, BUNDLE_LOG, MAX_WINDOW_SECS,
};

use crate::context::GlobalArgs;
use crate::system;

/// Where to read the node log from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogSource {
    /// The log files when the node writes them, else the journal.
    Auto,
    /// The systemd journal of the node service.
    Journal,
    /// The node's log files (live and rotated, every core).
    Files,
}

/// Minimum level of exported lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MinLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl MinLevel {
    fn rank(self) -> u8 {
        match self {
            MinLevel::Trace => 0,
            MinLevel::Debug => 1,
            MinLevel::Info => 2,
            MinLevel::Warn => 3,
            MinLevel::Error => 4,
        }
    }
}

// Arguments of `qclient node log export` (no doc comment: clap would let it
// override the subcommand help on `LogCommand::Export`).
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Window start: UTC RFC 3339 (2026-10-17T16:00:00Z) or a time ago
    /// (2h, 90m).
    #[arg(long, default_value = "2h")]
    pub since: String,
    /// Window end: UTC RFC 3339 or a time ago (default now). The window is
    /// at most 24 h.
    #[arg(long)]
    pub until: Option<String>,
    /// Log source; auto reads the log files when the node writes them,
    /// else the journal.
    #[arg(long, value_enum, default_value_t = LogSource::Auto)]
    pub source: LogSource,
    /// Keep only lines mentioning this hex shard filter (repeatable); warn
    /// and error lines are always kept as context.
    #[arg(long = "filter", value_name = "HEX")]
    pub filters: Vec<String>,
    /// Keep only lines containing this text (repeatable); warn and error
    /// lines are always kept as context.
    #[arg(long = "match", value_name = "TEXT")]
    pub matches: Vec<String>,
    /// Minimum level of exported lines.
    #[arg(long, value_enum)]
    pub level: Option<MinLevel>,
    /// Keep this node's own peer ID and prover address instead of
    /// tokenizing them (they identify your prover publicly anyway).
    #[arg(long)]
    pub keep_self: bool,
    /// Bundle directory (default ./node-log-export-<UTC time>); the token
    /// map is written beside it as <dir>.map.txt.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// Removes a staging directory unless disarmed.
pub(crate) struct StagingGuard(pub Option<PathBuf>);

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// `path` with `suffix` appended to its last component.
pub(crate) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// The records `args` selects at `now`.
pub(crate) fn selection(args: &ExportArgs, now: i64) -> anyhow::Result<Selection> {
    let until = match &args.until {
        Some(u) => parse_when(u, now)?,
        None => now,
    };
    let since = parse_when(&args.since, now)?;
    if since >= until {
        anyhow::bail!("--since must be before --until");
    }
    if until - since > MAX_WINDOW_SECS {
        anyhow::bail!("the window is longer than 24 h; narrow --since/--until");
    }
    let mut filters = Vec::new();
    for f in &args.filters {
        let f = f.trim().trim_start_matches("0x").to_ascii_lowercase();
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("--filter {f}: expected a hex shard filter");
        }
        filters.push(f);
    }
    Ok(Selection {
        since,
        until,
        min_level: args.level.map_or(0, MinLevel::rank),
        filters,
        matches: args.matches.clone(),
    })
}

/// `qclient node log export`.
pub fn run(global: &GlobalArgs, args: &ExportArgs) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("clock: {e}"))?
        .as_secs() as i64;
    let selection = selection(args, now)?;
    let (since, until) = (selection.since, selection.until);

    let (readers, source, child) = open_source(global, args.source, since, until)?;

    let out: PathBuf = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("node-log-export-{}", compact_ts(now))))
        .components()
        .collect();
    let map_path = with_suffix(&out, ".map.txt");
    let staging = with_suffix(&out, ".partial");
    for p in [&out, &map_path, &staging] {
        if p.exists() {
            anyhow::bail!("{} already exists", p.display());
        }
    }
    std::fs::create_dir_all(&staging)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", staging.display()))?;
    let mut guard = StagingGuard(Some(staging.clone()));

    let log_path = staging.join(BUNDLE_LOG);
    let file = File::create(&log_path)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", log_path.display()))?;
    // The log directory's home names the operator even when qclient runs
    // as root.
    let home_paths: Vec<PathBuf> = super::configured_log_dir(global)
        .ok()
        .flatten()
        .into_iter()
        .collect();
    let options = ExportOptions {
        keep_self: args.keep_self,
        home_paths: &home_paths,
        ..ExportOptions::default()
    };
    let export = produce(
        readers,
        child,
        &source,
        &selection,
        io::BufWriter::new(file),
        &options,
    )?;
    drop(export.out);

    print!(
        "{}",
        preview(
            &export.manifest,
            &export.stats,
            &format!("Bundle: {}", out.display()),
            &map_path
        )
    );
    if !confirm(global, "Type yes to write the bundle: ")? {
        println!("Nothing written.");
        return Ok(());
    }

    let (manifest_text, sums) = bundle_texts(&export.manifest, &export.log)?;
    std::fs::write(staging.join("manifest.json"), &manifest_text)?;
    std::fs::write(staging.join("SHA256SUMS"), sums)?;
    write_token_map(&map_path, &out.display().to_string(), &export.token_map)?;
    std::fs::rename(&staging, &out)
        .map_err(|e| anyhow::anyhow!("rename to {}: {e}", out.display()))?;
    guard.0 = None;
    println!(
        "Wrote {} ({} lines).",
        out.display(),
        export.stats.lines_kept
    );
    println!(
        "The token map {} holds the original values: keep it private and never share it.",
        map_path.display()
    );
    Ok(())
}

/// The record readers of `source` over `[since, until]`, what they read,
/// and the `journalctl` child to wait for when they read the journal.
pub(crate) fn open_source(
    global: &GlobalArgs,
    source: LogSource,
    since: i64,
    until: i64,
) -> anyhow::Result<(Vec<RecordReader>, SourceInfo, Option<Child>)> {
    let log_dir = match source {
        LogSource::Journal => None,
        LogSource::Auto => configured_log_dir_if_present(global),
        LogSource::Files => match super::configured_log_dir(global)? {
            Some(dir) if dir.is_dir() => Some(dir),
            Some(dir) => anyhow::bail!("log directory not found: {}", dir.display()),
            None => anyhow::bail!(
                "the node writes no log files (logger.path is none); use --source journal"
            ),
        },
    };
    match &log_dir {
        Some(dir) => {
            let (readers, names) = file_readers(dir, since, until)?;
            if names.is_empty() {
                anyhow::bail!("no node log files in {}", dir.display());
            }
            Ok((readers, SourceInfo::Files(names), None))
        }
        None => {
            if system::os_type() != "linux" {
                anyhow::bail!("the journal source needs Linux (systemd); use --source files");
            }
            let mut cmd = Command::new("journalctl");
            cmd.args([
                "--utc",
                "-o",
                "cat",
                "--no-pager",
                "-u",
                system::NODE_SERVICE_NAME,
            ])
            .arg("--since")
            .arg(format!("@{since}"))
            .arg("--until")
            .arg(format!("@{until}"))
            .stdout(Stdio::piped());
            let mut spawned = cmd
                .spawn()
                .map_err(|e| anyhow::anyhow!("run journalctl: {e}"))?;
            let stdout = spawned
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("journalctl: no stdout"))?;
            let reader: Box<dyn BufRead> = Box::new(BufReader::new(stdout));
            Ok((
                vec![RecordReader::new(vec![("journal".to_string(), reader)])],
                SourceInfo::Journal(system::NODE_SERVICE_NAME.to_string()),
                Some(spawned),
            ))
        }
    }
}

/// Ask the operator to type yes, unless the global --yes is set.
pub(crate) fn confirm(global: &GlobalArgs, question: &str) -> io::Result<bool> {
    if global.yes {
        return Ok(true);
    }
    print!("{question}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}

/// The configured log directory when it exists (for `--source auto`).
fn configured_log_dir_if_present(global: &GlobalArgs) -> Option<PathBuf> {
    match super::configured_log_dir(global) {
        Ok(Some(dir)) if dir.is_dir() => Some(dir),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--level` ranks as the shared export ranks line levels: warn lines
    /// are the ones kept as context.
    #[test]
    fn levels_rank_as_the_export_does() {
        let ranks = [
            MinLevel::Trace,
            MinLevel::Debug,
            MinLevel::Info,
            MinLevel::Warn,
            MinLevel::Error,
        ]
        .map(MinLevel::rank);
        assert_eq!(ranks, [0, 1, 2, 3, 4]);
        assert_eq!(MinLevel::Warn.rank(), quil_rpc::log_export::WARN_RANK);
    }
}
