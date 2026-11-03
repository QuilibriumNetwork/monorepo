//! `qclient node diagnostics allow|revoke|list`: which peers may fetch this
//! node's health report, and until when.
//!
//! These commands edit and read the default node config only: they contact
//! no node and restart nothing, and the node reads the list at start.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use clap::Args;

use quil_config::{Config, HealthReportConfig, LogRequestsConfig};

use super::diagnostics::parse_peer;
use super::nodeconfig::{owner_only, replace_file};
use crate::commands::token::shield_pacing::utc;
use crate::context::GlobalArgs;
use crate::nodeconfig;

/// The longest grant `allow` writes; a longer one is an edit by hand.
const MAX_GRANT_SECS: u64 = 365 * 86_400;

/// What a peer on the list gets, from `HealthReport`.
const SHARED: &str =
    "It gets, per request: this node's release and build fingerprint, GLOBAL head \
frame, worker count, store write state and store and disk read times; and per worker its core \
ID, public shard filter, allocation, phase, blocker, frames, committee generation, recovery \
state and failure counts, and when these last changed.\n\
It gets no log text, addresses or keys.\n";

const APPLY: &str = "The node reads this at start: restart it to apply. This command restarts \
nothing.\n";

#[derive(Debug, Args)]
pub struct AllowArgs {
    /// The peer's peer ID (base58), as `qclient node info` prints it there.
    pub peer: String,
    /// How long the grant lasts: a whole number with m, h or d, up to 365d.
    #[arg(long = "for", value_name = "DURATION", default_value = "7d")]
    pub duration: String,
}

#[derive(Debug, Args)]
pub struct RevokeArgs {
    /// The peer's peer ID (base58).
    pub peer: String,
}

pub fn allow(global: &GlobalArgs, args: &AllowArgs) -> anyhow::Result<()> {
    let peer = parse_peer(&args.peer)?.to_base58();
    let secs = parse_duration(&args.duration)?;
    let now = unix_now();
    let path = config_path(global)?;
    let (config, _) = read_config(&path)?;
    let mut report = config.diagnostics.health_report;
    grant(&mut report, &peer, now + secs);
    forget_ended(&mut report, now);
    write_report(&path, &report)?;
    print!(
        "Allowed {peer} until {} in {}.\nThis peer may fetch this node's health report, once per \
         {} s.\n{SHARED}{APPLY}",
        utc(now + secs),
        path.display(),
        report.min_interval_secs,
    );
    Ok(())
}

pub fn revoke(global: &GlobalArgs, args: &RevokeArgs) -> anyhow::Result<()> {
    let peer = parse_peer(&args.peer)?.to_base58();
    let path = config_path(global)?;
    let (config, _) = read_config(&path)?;
    let mut report = config.diagnostics.health_report;
    let listed = take_off(&mut report, &peer);
    if listed {
        forget_ended(&mut report, unix_now());
        write_report(&path, &report)?;
        print!("Revoked {peer} in {}.\n{APPLY}", path.display());
    } else {
        println!(
            "{peer} is not on the health report list in {}.",
            path.display()
        );
    }
    if listed_for_logs(&config.diagnostics.log_requests, &peer) {
        println!(
            "It stays in diagnostics.logRequests.allowedPeers, which this command does not \
             change."
        );
    }
    Ok(())
}

pub fn list(global: &GlobalArgs) -> anyhow::Result<()> {
    let path = config_path(global)?;
    let (config, _) = read_config(&path)?;
    print!(
        "{}",
        render_list(
            &config.diagnostics.health_report,
            &config.diagnostics.log_requests,
            &path,
            unix_now()
        )
    );
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn config_path(global: &GlobalArgs) -> anyhow::Result<PathBuf> {
    let network = global.network.as_deref().filter(|s| !s.is_empty());
    Ok(nodeconfig::default_node_config_dir(network)?.join("config.yml"))
}

/// The config at `path` as written, with no defaults filled in, and its text.
fn read_config(path: &Path) -> anyhow::Result<(Config, String)> {
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let config =
        serde_yaml::from_str(&contents).with_context(|| format!("parse {}", path.display()))?;
    Ok((config, contents))
}

/// Replace the health report settings of the config at `path` (a symlink is
/// followed) atomically, owner-readable only: it holds private keys.
fn write_report(path: &Path, report: &HealthReportConfig) -> anyhow::Result<()> {
    let path = std::fs::canonicalize(path).with_context(|| format!("find {}", path.display()))?;
    let (_, original) = read_config(&path)?;
    let edited = quil_config::with_health_report(&original, report)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let permissions = owner_only(std::fs::metadata(&path)?.permissions());
    replace_file(&path, &edited, &permissions)
}

/// `7d`, `12h` or `30m` in seconds, from one minute to [`MAX_GRANT_SECS`].
fn parse_duration(text: &str) -> anyhow::Result<u64> {
    let invalid = || anyhow::anyhow!("{text} is not a duration such as 7d, 12h or 30m");
    let text = text.trim();
    let unit = match text.chars().last() {
        Some('m') => 60,
        Some('h') => 3_600,
        Some('d') => 86_400,
        _ => return Err(invalid()),
    };
    let secs = text[..text.len() - 1]
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(unit))
        .ok_or_else(invalid)?;
    anyhow::ensure!(
        (1..=MAX_GRANT_SECS).contains(&secs),
        "{text} is outside 1m to 365d"
    );
    Ok(secs)
}

/// Serve the report and list `peer` until `until`.
fn grant(report: &mut HealthReportConfig, peer: &str, until: u64) {
    report.enabled = true;
    if !report.allowed_peers.iter().any(|p| p.trim() == peer) {
        report.allowed_peers.push(peer.to_string());
    }
    report.allowed_until.insert(peer.to_string(), until);
}

/// Take `peer` off the list; whether it was on it.
fn take_off(report: &mut HealthReportConfig, peer: &str) -> bool {
    let before = report.allowed_peers.len();
    report.allowed_peers.retain(|p| p.trim() != peer);
    report.allowed_until.remove(peer);
    report.allowed_peers.len() != before
}

/// Drop the grants that ended by `now`, and ends of peers no longer listed.
fn forget_ended(report: &mut HealthReportConfig, now: u64) {
    let ended = |until: Option<&u64>| until.is_some_and(|until| *until <= now);
    let until = report.allowed_until.clone();
    report.allowed_peers.retain(|p| !ended(until.get(p.trim())));
    let listed = report.allowed_peers.clone();
    report
        .allowed_until
        .retain(|peer, _| listed.iter().any(|p| p.trim() == peer));
}

fn listed_for_logs(requests: &LogRequestsConfig, peer: &str) -> bool {
    requests.allowed_peers.iter().any(|p| p.trim() == peer)
}

/// Whole days, hours or minutes, rounded down, for a time left.
fn left_text(secs: u64) -> String {
    match secs {
        0..=3_599 => format!("{} min left", secs / 60),
        3_600..=86_399 => format!("{} h left", secs / 3_600),
        _ => format!("{} d left", secs / 86_400),
    }
}

fn render_list(
    report: &HealthReportConfig,
    requests: &LogRequestsConfig,
    path: &Path,
    now: u64,
) -> String {
    let mut out = format!(
        "In {}, as the node reads it at start:\nHealth report: {}; each peer once per {} s.\n",
        path.display(),
        if report.enabled { "on" } else { "off" },
        report.min_interval_secs,
    );
    if report.allowed_peers.is_empty() {
        out += "  no peers\n";
    }
    for peer in &report.allowed_peers {
        let state = match report.allowed_until.get(peer.trim()) {
            None => "no end".to_string(),
            Some(until) if *until <= now => format!("ended {}", utc(*until)),
            Some(until) => format!("until {} ({})", utc(*until), left_text(*until - now)),
        };
        out += &format!("  {peer}  {state}\n");
    }
    if !report.enabled && !report.allowed_peers.is_empty() {
        out += "  The node serves none of these while the health report is off.\n";
    }
    out += &format!(
        "Log requests: {}.\n",
        if requests.enabled { "on" } else { "off" }
    );
    if requests.allowed_peers.is_empty() {
        out += "  no peers\n";
    }
    for peer in &requests.allowed_peers {
        out += &format!("  {peer}  no end; edit the config to change\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn durations_are_whole_units_within_their_bounds() {
        for (text, secs) in [
            ("7d", 604_800),
            ("12h", 43_200),
            ("30m", 1_800),
            ("365d", MAX_GRANT_SECS),
        ] {
            assert_eq!(parse_duration(text).unwrap(), secs, "{text}");
        }
        for text in [
            "",
            "d",
            "7",
            "7w",
            "-1d",
            "1.5h",
            "0m",
            "366d",
            "99999999999999999999d",
            "7\u{e9}",
        ] {
            assert!(parse_duration(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_grant_enables_the_report_and_extends_without_a_second_entry() {
        let mut report = HealthReportConfig::default();
        grant(&mut report, "QmPeer", NOW + 60);
        assert!(report.enabled);
        grant(&mut report, "QmPeer", NOW + 120);
        assert_eq!(report.allowed_peers, ["QmPeer"]);
        assert_eq!(report.allowed_until["QmPeer"], NOW + 120);
    }

    #[test]
    fn a_revoke_takes_off_the_peer_and_its_end_and_nothing_else() {
        let mut report = HealthReportConfig::default();
        grant(&mut report, "QmOne", NOW + 60);
        grant(&mut report, "QmTwo", NOW + 60);
        assert!(take_off(&mut report, "QmOne"));
        assert_eq!(report.allowed_peers, ["QmTwo"]);
        assert!(!report.allowed_until.contains_key("QmOne"));
        assert!(report.allowed_until.contains_key("QmTwo"));
        assert!(!take_off(&mut report, "QmOne"));
        assert!(report.enabled, "the node keeps serving itself either way");
    }

    #[test]
    fn ended_grants_go_and_grants_without_an_end_stay() {
        let mut report = HealthReportConfig {
            allowed_peers: vec!["QmEnded".into(), "QmLeft".into(), "QmHand".into()],
            ..Default::default()
        };
        report.allowed_until.insert("QmEnded".into(), NOW);
        report.allowed_until.insert("QmLeft".into(), NOW + 1);
        report.allowed_until.insert("QmGone".into(), NOW + 1);
        forget_ended(&mut report, NOW);
        assert_eq!(report.allowed_peers, ["QmLeft", "QmHand"]);
        assert_eq!(report.allowed_until.keys().collect::<Vec<_>>(), ["QmLeft"]);
    }

    #[test]
    fn the_list_shows_each_grants_state_and_the_log_request_peers() {
        let mut report = HealthReportConfig {
            enabled: true,
            allowed_peers: vec!["QmEnded".into(), "QmLeft".into(), "QmHand".into()],
            ..Default::default()
        };
        report.allowed_until.insert("QmEnded".into(), NOW - 1);
        report
            .allowed_until
            .insert("QmLeft".into(), NOW + 2 * 86_400);
        let requests = LogRequestsConfig {
            allowed_peers: vec!["QmLogs".into()],
            ..Default::default()
        };
        let text = render_list(&report, &requests, Path::new("/n/config.yml"), NOW);
        assert_eq!(
            text,
            "In /n/config.yml, as the node reads it at start:\n\
             Health report: on; each peer once per 60 s.\n  \
             QmEnded  ended 2027-01-15 07:59:59Z\n  \
             QmLeft  until 2027-01-17 08:00:00Z (2 d left)\n  \
             QmHand  no end\n\
             Log requests: off.\n  \
             QmLogs  no end; edit the config to change\n"
        );
        report.enabled = false;
        let text = render_list(&report, &requests, Path::new("/n/config.yml"), NOW);
        assert!(text.contains("serves none of these"), "{text}");
        let none = render_list(
            &HealthReportConfig::default(),
            &LogRequestsConfig::default(),
            Path::new("/n/config.yml"),
            NOW,
        );
        assert_eq!(none.matches("no peers").count(), 2, "{none}");
    }

    /// The file end to end: comments stay, the file is owner-readable only,
    /// the parsed result holds the grant, and a revoke leaves no peer.
    #[test]
    fn writing_keeps_the_rest_of_the_config_and_its_privacy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(&path, "# keep me\np2p:\n  network: 1\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o640))
            .unwrap();
        let (config, _) = read_config(&path).unwrap();
        let mut report = config.diagnostics.health_report;
        grant(&mut report, "QmPeer", NOW + 60);
        write_report(&path, &report).unwrap();
        let (config, contents) = read_config(&path).unwrap();
        assert!(
            contents.starts_with("# keep me\np2p:\n  network: 1\n"),
            "{contents}"
        );
        assert_eq!(config.diagnostics.health_report, report);
        assert_eq!(config.p2p.network, 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{mode:o}");
        }
        assert!(take_off(&mut report, "QmPeer"));
        write_report(&path, &report).unwrap();
        let (config, _) = read_config(&path).unwrap();
        assert!(config.diagnostics.health_report.allowed_peers.is_empty());
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["config.yml"], "no temporary file or backup of keys");
    }

    /// [`SHARED`] names every field group of the report: a new field stops
    /// this compiling, so that it is judged and named there.
    #[test]
    fn the_shared_text_is_reviewed_against_the_report() {
        use quil_types::proto::diagnostics::{HealthReport, WorkerHealth};
        let report = HealthReport::default();
        let HealthReport {
            schema: _,
            version: _,
            patch: _,
            subpatch: _,
            build_fingerprint: _,
            global_head_frame: _,
            generated_unix_ms: _,
            workers: _,
            omitted_workers: _,
            master_store_write_failed: _,
            worker_capacity: _,
            store_io: _,
        } = report;
        let WorkerHealth {
            core_id: _,
            filter: _,
            allocated: _,
            phase: _,
            blocker: _,
            observed_unix_ms: _,
            materialized_frame: _,
            last_advance_unix_ms: _,
            committee_head_frame: _,
            committed_generation: _,
            recovery_phase: _,
            recovery_phase_since_unix_ms: _,
            recovery_attempts: _,
            recovery_consecutive_failures: _,
            recovery_failures: _,
            last_failure: _,
            last_failure_unix_ms: _,
            last_success_unix_ms: _,
            longest_permit_wait_ms: _,
            seal_generation: _,
            seal_recorded_unix_ms: _,
            join_confirm_epoch: _,
            activation_frame: _,
            awaited_frame: _,
            draining: _,
        } = WorkerHealth::default();
        assert!(SHARED.contains("no log text, addresses or keys"));
    }
}
