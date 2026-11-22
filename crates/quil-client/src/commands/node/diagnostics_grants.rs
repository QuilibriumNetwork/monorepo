//! `qclient node diagnostics allow|revoke|list`: which peers may fetch this
//! node's health report, and until when.
//!
//! These commands edit and read the default node config only: they contact
//! no node and restart nothing, and the node reads the list at start.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use clap::Args;

use quil_config::{
    Config, HealthReportConfig, LogRequestsConfig, HEALTH_REPORT_CONSENT,
    HEALTH_REPORT_CONSENT_UNRECORDED,
};

use super::diagnostics::parse_peer;
use super::nodeconfig::{owner_only, replace_file};
use crate::commands::token::shield_pacing::utc;
use crate::context::GlobalArgs;
use crate::nodeconfig;

/// The longest grant `allow` writes; a longer one is an edit by hand.
const MAX_GRANT_SECS: u64 = 365 * 86_400;

/// What a peer on the list gets, from `HealthReport`, under a grant of
/// [`HEALTH_REPORT_CONSENT`], which `allow` records with it: a grant
/// recorded at an earlier level, or none, gets only the fields that level
/// listed. A changed text is a new level, never an edit of this one.
const SHARED: &str =
    "It gets, per request: this node's release, build fingerprint and source commit, GLOBAL head \
frame, worker count, store write state and store and disk read times; its stores' and storage \
labels' disk size, free space and size on disk, and how often labels were refused disk \
space at a snapshot since it started; its machine's Mac model and CPU vendor as numbers, core \
counts and how often its CPU throttled for heat (no name, serial number, hostname or UUID); its \
health conditions \
(kind, severity, scope, start, counts, the shard filters, frames and worker cores affected, \
a slow store fsync time, the GLOBAL frames an expected wait ends at, and for GLOBAL's progress \
its head, its recent frame rate and how many GLOBAL provers this node hears); and per worker \
its core ID, public shard filter, allocation, phase, blocker, frames, committee generation, \
recovery state and failure counts, and when these last changed.\n\
It gets no log text, addresses or keys, and no condition about this node's rewards or \
addresses.\n";

/// The text `allow` showed at each consent level, frozen: a grant
/// recorded at a level consented to that text, and one recording none to
/// the first. A changed [`SHARED`] is a new level: raise
/// [`HEALTH_REPORT_CONSENT`], add its text here, the groups it adds to
/// [`ADDED_AT`] and its fields to the node's table
/// (`withhold_unconsented`); never edit a text here.
#[cfg(test)]
const SHARED_AT: [&str; HEALTH_REPORT_CONSENT as usize + 1] = [
    "It gets, per request: this node's release and build fingerprint, GLOBAL head \
frame, worker count, store write state and store and disk read times; and per worker its core \
ID, public shard filter, allocation, phase, blocker, frames, committee generation, recovery \
state and failure counts, and when these last changed.\n\
It gets no log text, addresses or keys.\n",
    "It gets, per request: this node's release, build fingerprint and source commit, GLOBAL head \
frame, worker count, store write state and store and disk read times; its stores' and storage \
labels' disk size, free space and size on disk, and how often labels were refused disk \
space at a snapshot since it started; its machine's Mac model and CPU vendor as numbers, core \
counts and how often its CPU throttled for heat (no name, serial number, hostname or UUID); its \
health conditions \
(kind, severity, scope, start, counts, the shard filters, frames and worker cores affected, \
a slow store fsync time, the GLOBAL frames an expected wait ends at, and for GLOBAL's progress \
its head, its recent frame rate and how many GLOBAL provers this node hears); and per worker \
its core ID, public shard filter, allocation, phase, blocker, frames, committee generation, \
recovery state and failure counts, and when these last changed.\n\
It gets no log text, addresses or keys, and no condition about this node's rewards or \
addresses.\n",
];

/// The field groups each consent level adds to the one before, as its
/// text in `SHARED_AT` names them: what `list` says a grant at an earlier
/// level does not get. The review test holds each group to its level's
/// text and to the report fields the node's table first shares there.
const ADDED_AT: [&[&str]; HEALTH_REPORT_CONSENT as usize + 1] = [
    &[],
    &[
        "health conditions",
        "disk space",
        "machine",
        "source commit",
    ],
];

/// What a grant at consent `level` does not get: the groups each later
/// level added, or `None` from the current level on.
fn withheld_groups(level: u32) -> Option<String> {
    let first = usize::try_from(level).map_or(usize::MAX, |level| level.saturating_add(1));
    let groups: Vec<&str> = ADDED_AT
        .iter()
        .skip(first)
        .flat_map(|groups| groups.iter().copied())
        .collect();
    let (last, rest) = groups.split_last()?;
    Some(match rest {
        [] => last.to_string(),
        _ => format!("{} or {last}", rest.join(", ")),
    })
}

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

/// Serve the report and list `peer` until `until`, with the fields
/// [`SHARED`] names.
fn grant(report: &mut HealthReportConfig, peer: &str, until: u64) {
    report.enabled = true;
    if !report.allowed_peers.iter().any(|p| p.trim() == peer) {
        report.allowed_peers.push(peer.to_string());
    }
    report.allowed_until.insert(peer.to_string(), until);
    report
        .allowed_consent
        .insert(peer.to_string(), HEALTH_REPORT_CONSENT);
}

/// Take `peer` off the list; whether it was on it.
fn take_off(report: &mut HealthReportConfig, peer: &str) -> bool {
    let before = report.allowed_peers.len();
    report.allowed_peers.retain(|p| p.trim() != peer);
    report.allowed_until.remove(peer);
    report.allowed_consent.remove(peer);
    report.allowed_peers.len() != before
}

/// Drop the grants that ended by `now`, and ends and consent levels of
/// peers no longer listed.
fn forget_ended(report: &mut HealthReportConfig, now: u64) {
    let ended = |until: Option<&u64>| until.is_some_and(|until| *until <= now);
    let until = report.allowed_until.clone();
    report.allowed_peers.retain(|p| !ended(until.get(p.trim())));
    let peers = report.allowed_peers.clone();
    let listed = |peer: &String| peers.iter().any(|p| p.trim() == peer);
    report.allowed_until.retain(|peer, _| listed(peer));
    report.allowed_consent.retain(|peer, _| listed(peer));
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
        let level = report
            .allowed_consent
            .get(peer.trim())
            .copied()
            .unwrap_or(HEALTH_REPORT_CONSENT_UNRECORDED);
        let consent = withheld_groups(level)
            .map(|groups| format!("; shares no {groups} until allowed again"))
            .unwrap_or_default();
        out += &format!("  {peer}  {state}{consent}\n");
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
        assert_eq!(
            report.allowed_consent["QmPeer"], HEALTH_REPORT_CONSENT,
            "GRANT-UNRECORDED: the grant records the fields SHARED names"
        );
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
        assert_eq!(
            report.allowed_consent.keys().collect::<Vec<_>>(),
            ["QmTwo"],
            "REVOKED-CONSENT-KEPT: a revoke drops the grant's level"
        );
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
        for peer in ["QmEnded", "QmLeft", "QmGone"] {
            report
                .allowed_consent
                .insert(peer.into(), HEALTH_REPORT_CONSENT);
        }
        forget_ended(&mut report, NOW);
        assert_eq!(report.allowed_peers, ["QmLeft", "QmHand"]);
        assert_eq!(report.allowed_until.keys().collect::<Vec<_>>(), ["QmLeft"]);
        assert_eq!(
            report.allowed_consent.keys().collect::<Vec<_>>(),
            ["QmLeft"],
            "ENDED-CONSENT-KEPT: an ended or unlisted grant keeps no level"
        );
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
        for peer in ["QmEnded", "QmLeft"] {
            report
                .allowed_consent
                .insert(peer.into(), HEALTH_REPORT_CONSENT);
        }
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
             QmHand  no end; shares no health conditions, disk space, machine or source \
             commit until allowed again\n\
             Log requests: off.\n  \
             QmLogs  no end; edit the config to change\n",
            "LIST-EARLIER-CONSENT: each grant's state and earlier consent"
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

    /// The package of the report's messages.
    const PACKAGE: &str = "quilibrium.node.diagnostics.pb";

    /// Every message the report carries and each of its fields, as judged
    /// against [`SHARED`]. A new field or message fails the review test
    /// until it is judged here, named in [`SHARED`] and given the level
    /// from which the node shares it (`withhold_unconsented`, [`ADDED_AT`]).
    const REVIEWED: &[(&str, &[&str])] = &[
        (
            "HealthReport",
            &[
                "schema",
                "version",
                "patch",
                "subpatch",
                "build_fingerprint",
                "global_head_frame",
                "generated_unix_ms",
                "workers",
                "omitted_workers",
                "master_store_write_failed",
                "worker_capacity",
                "store_io",
                "health",
                "store_space",
                "machine",
                "build_commit",
                "build_dirty",
            ],
        ),
        (
            "WorkerHealth",
            &[
                "core_id",
                "filter",
                "allocated",
                "phase",
                "blocker",
                "observed_unix_ms",
                "materialized_frame",
                "last_advance_unix_ms",
                "committee_head_frame",
                "committed_generation",
                "recovery_phase",
                "recovery_phase_since_unix_ms",
                "recovery_attempts",
                "recovery_consecutive_failures",
                "recovery_failures",
                "last_failure",
                "last_failure_unix_ms",
                "last_success_unix_ms",
                "longest_permit_wait_ms",
                "seal_generation",
                "seal_recorded_unix_ms",
                "join_confirm_epoch",
                "activation_frame",
                "awaited_frame",
                "draining",
            ],
        ),
        ("FailureCount", &["class", "count"]),
        (
            "StoreIoHealth",
            &[
                "verdict",
                "slow_secs",
                "interval_secs",
                "ended_unix_ms",
                "canary_reads",
                "canary_p50_us",
                "canary_p99_us",
                "canary_max_us",
                "canary_pending_us",
                "disk_reads",
                "disk_writes",
                "disk_read_await_us",
                "disk_write_await_us",
                "disk_busy_pct",
                "slow_reason",
                "recovering_intervals",
            ],
        ),
        ("HealthConditions", &["conditions", "sources"]),
        (
            "HealthCondition",
            &[
                "kind",
                "severity",
                "scope",
                "action",
                "since_unix_ms",
                "affected",
                "tracked",
                "threshold",
                "shards",
                "omitted_shards",
                "store_io",
                "reward_hour_units",
                "reward_day_units",
                "global",
                "wait",
                "store_fsync_ms",
            ],
        ),
        (
            "AffectedShard",
            &[
                "filter",
                "core_id",
                "frame",
                "unchanged_since_unix_ms",
                "window_secs",
                "lag_frames",
            ],
        ),
        ("ConditionSource", &["kind", "observed_unix_ms", "tracked"]),
        (
            "GlobalProgress",
            &[
                "head",
                "advanced_frames",
                "span_secs",
                "provers",
                "reachable",
                "quorum",
            ],
        ),
        (
            "ExpectedWait",
            &[
                "head_frame",
                "until_frame",
                "batch_from_frame",
                "expected_secs",
            ],
        ),
        (
            "StoreSpace",
            &[
                "total_bytes",
                "free_bytes",
                "store_bytes",
                "label_bytes",
                "label_total_bytes",
                "label_free_bytes",
                "snapshot_refusals",
                "last_refusal_unix_ms",
                "last_refusal_needed_bytes",
            ],
        ),
        (
            "Machine",
            &[
                "mac_family",
                "mac_major",
                "mac_minor",
                "cpu_vendor",
                "cpu_family",
                "cpu_model",
                "cpu_stepping",
                "cpus",
                "performance_cores",
                "efficiency_cores",
                "throttle_events",
            ],
        ),
    ];

    /// [`SHARED`] names every field group of the report, and each report
    /// field is shared from the level whose text first listed it: the
    /// node's table matches the levels named here, each later level's
    /// groups come from [`ADDED_AT`], and every message the report carries
    /// is [`REVIEWED`].
    #[test]
    fn the_shared_text_is_reviewed_against_the_report() {
        use quil_rpc::diagnostics_service::withhold_unconsented;
        use quil_types::proto::diagnostics::{
            HealthConditions, HealthReport, Machine, StoreIoHealth, StoreSpace, WorkerHealth,
        };
        use std::cell::RefCell;
        use std::collections::{BTreeMap, BTreeSet};
        // The level that adds `group`, as ADDED_AT lists it.
        let named = RefCell::new(BTreeSet::new());
        let level_of = |group: &'static str| {
            named.borrow_mut().insert(group);
            let level = ADDED_AT.iter().position(|groups| groups.contains(&group));
            let level = level.unwrap_or_else(|| panic!("ADDED-LEVEL: no level adds {group}"));
            u32::try_from(level).unwrap()
        };
        // Each field as served at a level: a field is shared from the level
        // that lists it, as the node's table withholds it.
        let at = |share: &dyn Fn(u32) -> bool| HealthReport {
            // 0: SHARED_AT[0], and a grant that records no level.
            schema: 1,
            version: vec![2],
            patch: 3,
            subpatch: 4,
            build_fingerprint: vec![5],
            global_head_frame: 6,
            generated_unix_ms: 7,
            workers: vec![WorkerHealth::default()],
            omitted_workers: 9,
            master_store_write_failed: true,
            worker_capacity: 11,
            store_io: Some(StoreIoHealth::default()),
            // Later levels: the group of ADDED_AT each field falls in.
            health: share(level_of("health conditions")).then(HealthConditions::default),
            store_space: share(level_of("disk space")).then(StoreSpace::default),
            machine: share(level_of("machine")).then(Machine::default),
            build_commit: share(level_of("source commit")).then(|| vec![16]),
            build_dirty: share(level_of("source commit")),
        };
        for level in 0..=HEALTH_REPORT_CONSENT + 1 {
            let mut report = at(&|_| true);
            withhold_unconsented(&mut report, level);
            assert_eq!(
                report,
                at(&|first| level >= first),
                "LEVEL-TABLE: the node shares at level {level} what this lists"
            );
        }
        assert_eq!(
            SHARED, SHARED_AT[HEALTH_REPORT_CONSENT as usize],
            "SHARED-PINNED: a changed text is a new level"
        );
        assert!(ADDED_AT[0].is_empty(), "ADDED-LEVEL: level 0 adds nothing");
        for (level, groups) in ADDED_AT.iter().enumerate().skip(1) {
            assert!(
                !groups.is_empty(),
                "ADDED-LEVEL: level {level} adds nothing"
            );
            for group in *groups {
                assert!(
                    named.borrow().contains(group)
                        && SHARED_AT[level].contains(group)
                        && !SHARED_AT[level - 1].contains(group),
                    "ADDED-LEVEL: {group} names a field first listed at level {level}"
                );
            }
        }
        let pool = quil_types::protojson::descriptor_pool();
        let report = format!("{PACKAGE}.HealthReport");
        let carried: BTreeMap<String, BTreeSet<String>> =
            quil_types::decode_cost::DecodeCost::of(&report)
                .expect("the report's descriptor is embedded")
                .messages()
                .map(|name| {
                    let message = pool.get_message_by_name(name).unwrap();
                    let fields = message.fields().map(|f| f.name().to_string()).collect();
                    (name.to_string(), fields)
                })
                .collect();
        let reviewed: BTreeMap<String, BTreeSet<String>> = REVIEWED
            .iter()
            .map(|(name, fields)| {
                let fields = fields.iter().map(|f| f.to_string()).collect();
                (format!("{PACKAGE}.{name}"), fields)
            })
            .collect();
        assert_eq!(
            carried, reviewed,
            "REVIEWED-FIELDS: every message the report carries and its fields"
        );
        assert!(SHARED.contains("free space and size on disk"));
        assert!(SHARED.contains("Mac model and CPU vendor as numbers, core"));
        assert!(SHARED.contains("no log text, addresses or keys"));
    }

    /// A falcon key and the peer ID it proves.
    fn identity() -> (Vec<u8>, quil_p2p::PeerId) {
        let key = quil_p2p::generate_falcon_signing_key();
        let peer = quil_p2p::Keypair::falcon_from_bytes(&key)
            .unwrap()
            .public()
            .to_peer_id();
        (key, peer)
    }

    /// The config `allow` wrote before grants recorded what they shared,
    /// granting `peer` for an hour.
    fn earlier_grant(dir: &Path, peer: &quil_p2p::PeerId) -> PathBuf {
        let path = dir.join("config.yml");
        let peer = peer.to_base58();
        let until = unix_now() + 3_600;
        std::fs::write(
            &path,
            format!(
                "p2p:\n  network: 1\ndiagnostics:\n  healthReport:\n    enabled: true\n    \
                 allowedPeers:\n    - {peer}\n    allowedUntil:\n      {peer}: {until}\n    \
                 minIntervalSecs: 60\n"
            ),
        )
        .unwrap();
        path
    }

    /// The health report a node serving the grants of the config at `path`
    /// gives `requester` over the real peer listener: the handshake proves
    /// the requester's identity and the node's admission judges its grant.
    async fn report_served(
        path: &Path,
        requester: &[u8],
    ) -> quil_types::proto::diagnostics::HealthReport {
        use quil_rpc::diagnostics_service as diag;
        use quil_types::proto::diagnostics::{
            ConditionKind, GetHealthReportRequest, HealthCondition, HealthConditions, Machine,
            StoreSpace,
        };
        let (node_key, node) = identity();
        let (config, _) = read_config(path).unwrap();
        let admission = diag::Admission::new(&config.diagnostics.health_report, node);
        let source: diag::HealthSource = std::sync::Arc::new(|| diag::HealthInputs {
            global_head_frame: 9,
            health: Some(HealthConditions {
                conditions: vec![HealthCondition {
                    kind: ConditionKind::StoreIoSlow as i32,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            store_space: Some(StoreSpace {
                total_bytes: 1 << 40,
                ..Default::default()
            }),
            machine: Some(Machine {
                cpus: 8,
                ..Default::default()
            }),
            build_commit: Some((vec![0x12; 20], false)),
            ..Default::default()
        });
        let service = tonic::service::interceptor::InterceptedService::new(
            diag::DiagnosticsServer::new(std::sync::Arc::new(admission), source, vec![0xab; 32])
                .into_service(),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let incoming =
            futures::stream::unfold((listener, node_key), |(listener, key)| async move {
                let stream = match listener.accept().await {
                    Ok((tcp, _)) => quil_rpc::pqnoise_channel::pq_server_handshake(tcp, &key).await,
                    Err(error) => Err(error),
                };
                Some((stream, (listener, key)))
            });
        let serve = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming),
        );
        let mut client = diag::connect_peer(&addr, requester, node).await.unwrap();
        let report = client
            .get_health_report(GetHealthReportRequest {})
            .await
            .unwrap()
            .into_inner();
        serve.abort();
        assert_eq!(report.global_head_frame, 9, "the report is served");
        report
    }

    /// A grant made before grants recorded what they shared showed no health
    /// conditions, disk space, machine or source commit: the node withholds
    /// them.
    #[tokio::test]
    async fn an_earlier_grant_gets_no_health_disk_space_machine_or_source_commit() {
        let dir = tempfile::tempdir().unwrap();
        let (requester_key, requester) = identity();
        let path = earlier_grant(dir.path(), &requester);
        let report = report_served(&path, &requester_key).await;
        eprintln!("REACH grant-served");
        assert_eq!(
            (
                report.health.is_some(),
                report.store_space.is_some(),
                report.machine.is_some(),
                report.build_commit.is_some()
            ),
            (false, false, false, false),
            "EARLIER-GRANT-SHARED: fields its operator never saw listed"
        );
    }

    /// Allowing the peer again, as `allow` does, lists them and shares them.
    #[tokio::test]
    async fn allowing_again_shares_health_disk_space_machine_and_source_commit() {
        let dir = tempfile::tempdir().unwrap();
        let (requester_key, requester) = identity();
        let path = earlier_grant(dir.path(), &requester);
        let (config, _) = read_config(&path).unwrap();
        let mut report = config.diagnostics.health_report;
        let now = unix_now();
        grant(&mut report, &requester.to_base58(), now + 3_600);
        forget_ended(&mut report, now);
        write_report(&path, &report).unwrap();
        let report = report_served(&path, &requester_key).await;
        eprintln!("REACH grant-served");
        assert_eq!(
            (
                report.health.is_some(),
                report.store_space.is_some(),
                report.machine.is_some(),
                report.build_commit.is_some()
            ),
            (true, true, true, true),
            "ALLOWED-GRANT-WITHHELD: the fields SHARED lists"
        );
        assert!(SHARED.contains("health conditions") && SHARED.contains("Mac model"));
    }
}
