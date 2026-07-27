//! `qclient node log …` — view/clean node logs.
//!
//! Port of `client/cmd/node/log/{log,clean}.go`. `view` shells out to
//! `tail` (matching Go); `clean` removes `*.log`/`*.log.gz` in the log dir.

use std::path::Path;
use std::process::Command;

use clap::Subcommand;

use crate::system;

#[derive(Debug, Subcommand)]
pub enum LogCommand {
    /// View the node log (last N lines, optionally following).
    View {
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: u64,
        #[arg(short = 'f', long)]
        follow: bool,
    },
    /// Delete rotated node logs.
    Clean,
}

pub fn run(cmd: &LogCommand) -> anyhow::Result<()> {
    match cmd {
        LogCommand::View { lines, follow } => view(*lines, *follow),
        LogCommand::Clean => clean(),
    }
}

fn log_file() -> std::path::PathBuf {
    Path::new(system::LOG_PATH).join("quilibrium-node.log")
}

fn view(lines: u64, follow: bool) -> anyhow::Result<()> {
    let file = log_file();
    if !file.exists() {
        anyhow::bail!("log file not found: {}", file.display());
    }
    let mut cmd = Command::new("tail");
    if follow {
        cmd.arg("-f");
    }
    cmd.arg("-n").arg(lines.to_string()).arg(&file);
    let status = cmd.status().map_err(|e| anyhow::anyhow!("run tail: {e}"))?;
    if !status.success() {
        anyhow::bail!("tail exited with {status}");
    }
    Ok(())
}

fn clean() -> anyhow::Result<()> {
    let dir = Path::new(system::LOG_PATH);
    if !dir.exists() {
        println!("Log directory does not exist: {}", dir.display());
        return Ok(());
    }
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".log") || name.ends_with(".log.gz") {
            if let Err(e) = std::fs::remove_file(&path) {
                eprintln!("failed to remove {}: {e}", path.display());
            } else {
                removed += 1;
            }
        }
    }
    println!("Removed {removed} log file(s)");
    Ok(())
}
