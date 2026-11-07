//! The last few node-log warnings, redacted the way a diagnostics log export
//! redacts them, for the assistant to read when a call fails.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use quil_client::context::{Context, GlobalArgs};
use quil_rpc::log_export::redact::{RedactOptions, Redactor};
use rand::RngCore;

use crate::config::Settings;
use crate::disclosure;

const TAIL_BYTES: u64 = 64 * 1024;
const MAX_LINES: usize = 5;

/// Up to five recent warn or error lines. Empty when the node writes no log
/// files or none of those lines are in the tail. A line that still looks
/// like config or keystore material is dropped.
pub fn collect(settings: &Settings) -> Vec<String> {
    let Ok(ctx) = Context::load(GlobalArgs {
        network: settings.network.clone(),
        yes: false,
    }) else {
        return Vec::new();
    };
    let Ok((config, dir)) = ctx.load_node_config(&settings.node_config) else {
        return Vec::new();
    };
    let Some(log_dir) = config.logger.log_dir(&dir) else {
        return Vec::new();
    };
    from_dir(&log_dir)
}

/// Warn and error lines from `dir`, newest files' tails, redacted.
pub fn from_dir(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.ends_with(".log") && !name.ends_with(".log.gz") {
            names.push(name.to_string());
        }
    }
    names.sort();
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut redactor = Redactor::new(salt, RedactOptions::with_bootstrap_endpoints(false));
    let mut found = Vec::new();
    for name in names {
        for line in tail_lines(&dir.join(&name)) {
            if !is_warning(&line) {
                continue;
            }
            let redacted = redactor.redact_line(&line);
            if disclosure::holds_config_secret(&redacted) {
                continue;
            }
            found.push(redacted);
        }
    }
    found.sort();
    let start = found.len().saturating_sub(MAX_LINES);
    found.split_off(start)
}

fn is_warning(line: &str) -> bool {
    let mut columns = line.split('\t');
    let Some(level) = columns.nth(1) else {
        return false;
    };
    matches!(
        level.trim().to_ascii_lowercase().as_str(),
        "warn" | "warning" | "error" | "dpanic" | "panic" | "fatal"
    )
}

fn tail_lines(path: &Path) -> Vec<String> {
    let Ok(mut file) = File::open(path) else {
        return Vec::new();
    };
    let Ok(len) = file.metadata().map(|meta| meta.len()) else {
        return Vec::new();
    };
    if len > TAIL_BYTES {
        let _ = file.seek(SeekFrom::Start(len - TAIL_BYTES));
    }
    let mut buf = String::new();
    if file.read_to_string(&mut buf).is_err() {
        return Vec::new();
    }
    buf.lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// Append `warnings` under `text` for an assistant. No-op when there are none.
pub fn append(text: &mut String, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    text.push_str("\n\nLatest warnings:\n");
    for warning in warnings.iter().take(MAX_LINES) {
        text.push_str("- ");
        text.push_str(warning);
        text.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_redacted_warnings_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let peer = "12D3KooWSyntheticPeerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        std::fs::write(
            dir.path().join("master.log"),
            format!(
                "2026-11-07T00:00:00Z\tinfo\tcaller\tignored\t{{}}\n\
                 2026-11-07T00:00:01Z\twarn\tcaller\tstore slow at /home/someone/.quilibrium peer {peer}\t{{}}\n\
                 2026-11-07T00:00:02Z\terror\tcaller\tprivateKey: abc\t{{}}\n"
            ),
        )
        .unwrap();
        let lines = from_dir(dir.path());
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(!lines[0].contains("/home/someone"), "{lines:?}");
        assert!(!lines[0].contains(peer), "{lines:?}");
        assert!(lines[0].contains("store slow"), "{lines:?}");
        assert!(!lines.iter().any(|line| line.contains("privateKey")));
    }
}
