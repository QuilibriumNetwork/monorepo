//! `devnet-proxy` — in-container gossip/gRPC partition proxy for the devnet
//! harness.
//!
//! Runs a BlossomSub host that meshes with every node and applies bipartite
//! partitions, watches consensus gossip to drive per-rank partition timing, and
//! (once a proposal past the stop frame is seen) polls the archives for frame
//! convergence, checks chain safety, verifies client enrollment, and POSTs the
//! result back to the orchestrator.
//!
//! All paths are wired: gossip partitioning (BlossomSub forward filter), the
//! transparent-h2 gRPC partition proxy, frame convergence, safety, enrollment,
//! and the result notification. Remaining work is live-integration validation
//! (run the compose stack) and the proxy Dockerfile.

mod blossomsub_proxy;
mod consensus_events;
mod enrollment_monitor;
mod frame;
mod frame_monitor;
mod grpc_proxy;
mod grpc_serve;
mod partitioner;
mod safety;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use quil_p2p::ed448_identity::Ed448Identity;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use devnet::rankpartitions::{self, RankPartitionEntry};
use devnet::shared::{FrameNotification, NodeInfo, NotificationType};

use crate::blossomsub_proxy::BlossomSubProxy;
use crate::consensus_events::ConsensusEvent;
use crate::enrollment_monitor::{ArchiveTarget, EnrollmentMonitor, EnrollmentTarget};
use crate::frame_monitor::{FrameMonitor, FrameTarget};
use crate::partitioner::NetworkPartitioner;
use crate::safety::check_safety;

const GRPC_BASE_PORT: u16 = 9000;

#[derive(Parser)]
#[command(name = "devnet-proxy")]
struct Cli {
    /// Configuration directory.
    #[arg(long = "config", default_value = ".config")]
    config: String,
    /// Active network (mainnet = 0, primary testnet = 1).
    #[arg(long = "network", default_value_t = 0)]
    network: u8,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_logging();
    match run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "devnet-proxy failed");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let run_id = env_required("RUN_ID")?;
    let runner_address = env_required("RUNNER_ADDRESS")?;
    let runner_auth = std::env::var("RUNNER_AUTH").unwrap_or_default();
    let stop_frame: u64 = env_required("STOP_FRAME")?
        .parse()
        .context("parse STOP_FRAME")?;
    let node_infos_json = env_required("NODE_INFOS")?;
    let min_nodes: usize = env_required("MIN_NODES")?
        .parse()
        .context("parse MIN_NODES")?;
    if min_nodes == 0 {
        bail!("MIN_NODES must be > 0");
    }

    let global_timeout = Duration::from_secs(env_required("GLOBAL_TIMEOUT")?.parse()?);
    let node_catchup_timeout = Duration::from_secs(env_required("NODE_CATCHUP_TIMEOUT")?.parse()?);
    let poll_interval = Duration::from_secs(5);

    let mut config =
        quil_config::load_config(std::path::Path::new(&cli.config)).context("load config")?;
    config.p2p.network = cli.network;

    let nodes: Vec<NodeInfo> =
        serde_json::from_str(&node_infos_json).context("parse NODE_INFOS")?;
    for n in &nodes {
        if n.peer_id.is_empty() {
            bail!("node info {} missing peer ID", n.name);
        }
    }
    let archive_count = nodes.iter().filter(|n| n.is_archive).count();

    // The proxy's own Ed448 seed — used to dial archives for frame polling.
    let proxy_seed =
        ed448_seed_from_hex(&config.p2p.peer_priv_key).context("derive proxy Ed448 seed")?;

    // Shared partition table consulted by both the gossip and gRPC paths.
    let partitioner = Arc::new(NetworkPartitioner::new());

    // Parse the per-rank partition schedule and apply rank 0 immediately.
    let rank_partitions = parse_rank_partitions_env()?;
    if let Some(entry) = rank_partitions.get(&0) {
        partitioner.apply_partition(&entry.partition1, &entry.partition2);
    }

    // Start the BlossomSub host (swarm + consensus-decode loop on the supervisor).
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let (consensus_tx, consensus_rx) = mpsc::channel::<ConsensusEvent>(100);
    let blossom = BlossomSubProxy::start(
        &mut sup,
        &config.p2p,
        Arc::clone(&partitioner),
        consensus_tx.clone(),
    )
    .await
    .context("start blossomsub proxy")?;

    // Build the gRPC backend specs (server + per-caller client TLS) and start
    // one transparent-h2 partition proxy listener per archive.
    match build_grpc_backends(&nodes) {
        Ok(specs) => {
            let specs: Vec<Arc<grpc_proxy::BackendSpec>> =
                specs.into_iter().map(Arc::new).collect();
            tracing::info!(backends = specs.len(), "starting gRPC proxy");
            let part = Arc::clone(&partitioner);
            // The gRPC proxy also snoops SubmitGlobalConsensus requests for the
            // stop-frame/rank signals that moved off gossip in v2.1.0.25.
            let grpc_consensus_tx = consensus_tx.clone();
            sup.spawn("grpc-proxy", move |token| async move {
                tokio::select! {
                    _ = token.cancelled() => Ok(()),
                    r = grpc_serve::serve_all(specs, part, grpc_consensus_tx) => r,
                }
            });
        }
        Err(e) => tracing::error!(error = %e, "failed to build gRPC backend specs"),
    }

    // Frame monitor: archives only (a stuck client must not mask a stuck archive).
    let frame_targets: Vec<FrameTarget> = nodes
        .iter()
        .filter(|n| n.is_archive)
        .map(|n| FrameTarget {
            address: n.stream_address(),
        })
        .collect();
    let mut frame_monitor = FrameMonitor::new(
        proxy_seed,
        stop_frame,
        frame_targets,
        poll_interval,
        min_nodes,
        node_catchup_timeout,
    );

    let cancel = CancellationToken::new();
    install_signal_handler(cancel.clone(), sup.token());

    tracing::info!(stop_frame, min_nodes, archive_count, "proxy running");

    // POSTs notifications (progress + terminal) to the orchestrator.
    let notifier = Notifier {
        runner_address,
        runner_auth,
        run_id,
    };

    // Run the consensus event loop; it owns partition timing, posts per-frame
    // progress, and on reaching the stop frame the frame/enrollment verification
    // + terminal notification.
    let outcome = consensus_event_loop(
        consensus_rx,
        &cancel,
        global_timeout,
        stop_frame,
        archive_count,
        &rank_partitions,
        &blossom,
        &mut frame_monitor,
        &nodes,
        min_nodes,
        poll_interval,
        node_catchup_timeout,
        &notifier,
    )
    .await;

    // Emit the run-completion notification to the orchestrator.
    if let Some(notification) = outcome {
        notifier.send(notification).await;
    }

    cancel.cancel();
    Ok(())
}

/// The proxy's core loop. Returns the notification to send, or `None` if the
/// loop ended without a verdict (e.g. external cancellation).
#[allow(clippy::too_many_arguments)]
async fn consensus_event_loop(
    mut consensus_rx: mpsc::Receiver<ConsensusEvent>,
    cancel: &CancellationToken,
    global_timeout: Duration,
    stop_frame: u64,
    archive_count: usize,
    rank_partitions: &HashMap<u64, RankPartitionEntry>,
    blossom: &BlossomSubProxy,
    frame_monitor: &mut FrameMonitor,
    nodes: &[NodeInfo],
    min_nodes: usize,
    poll_interval: Duration,
    node_catchup_timeout: Duration,
    notifier: &Notifier,
) -> Option<FrameNotification> {
    let mut ranks_applied: HashSet<u64> = HashSet::new();
    let mut timeout_senders: HashMap<u64, HashSet<Vec<u8>>> = HashMap::new();
    // Archives that must each originate a consensus message for the last frame
    // to prove they rejoined consensus (vs. passively syncing frames), and the
    // set of addresses observed voting/proposing for `stop_frame`.
    let required_voters = required_archive_voters(nodes);
    let mut last_frame_voters: HashSet<Vec<u8>> = HashSet::new();
    // Highest frame observed in a consensus message so far — used only to log
    // frame progress once per new frame (events repeat per rank and per backend).
    let mut max_frame_seen: u64 = 0;
    let global_timer = tokio::time::sleep(global_timeout);
    tokio::pin!(global_timer);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return None,
            _ = &mut global_timer => {
                tracing::warn!(?global_timeout, stop_frame, "global timeout expired without seeing stop frame via gossip");
                return Some(FrameNotification {
                    run_id: String::new(),
                    stop_frame,
                    notification_type: NotificationType::GlobalTimeout,
                    safety_error: String::new(),
                    nodes_reached_stop_frame: 0,
                    total_nodes: archive_count as i32,
                    enrollment_error: String::new(),
                    rejoin_error: String::new(),
                });
            }
            maybe_event = consensus_rx.recv() => {
                let event = maybe_event?;

                if event.frame_number > max_frame_seen {
                    max_frame_seen = event.frame_number;
                    tracing::debug!(
                        frame = event.frame_number,
                        rank = event.rank,
                        stop_frame,
                        "global consensus frame advanced"
                    );
                    // Report liveness to the orchestrator so it can show progress
                    // during the run (it otherwise only hears the terminal frame).
                    notifier.progress(event.frame_number, archive_count as i32).await;
                }

                if !event.is_timeout {
                    apply_rank_partition(event.rank, rank_partitions, blossom, &mut ranks_applied);
                } else if !event.sender_address.is_empty() {
                    let senders = timeout_senders.entry(event.rank).or_default();
                    senders.insert(event.sender_address.clone());
                    // Only archives participate in global consensus.
                    if senders.len() >= archive_count {
                        tracing::info!(rank = event.rank, count = senders.len(), "advancing rank due to timeout condition");
                        apply_rank_partition(event.rank + 1, rank_partitions, blossom, &mut ranks_applied);
                    }
                }

                // Record which archives originated a proposal/vote for the last
                // frame — the rejoin signal. A node that only passively syncs
                // frames never publishes consensus messages at this live rank.
                if !event.is_timeout
                    && event.frame_number == stop_frame
                    && !event.sender_address.is_empty()
                {
                    last_frame_voters.insert(event.sender_address.clone());
                }

                if event.frame_number > stop_frame {
                    tracing::info!(event_frame = event.frame_number, stop_frame, "observed proposal past stop frame, monitoring all nodes");
                    let (reached, total) = frame_monitor.start_monitoring(cancel).await;
                    tracing::info!(reached, total, "frame monitoring complete");

                    let frames = frame_monitor.fetch_committed_frames().await;
                    let safety_error = compute_safety_error(&frames);

                    let rejoin_error =
                        compute_rejoin_error(&required_voters, &last_frame_voters, stop_frame);
                    if rejoin_error.is_empty() {
                        tracing::info!(
                            archives = required_voters.len(),
                            stop_frame,
                            "all archives voted for the last frame (rejoined consensus)"
                        );
                    } else {
                        tracing::error!(error = %rejoin_error, "rejoin verification failed");
                    }

                    let enrollment_error =
                        run_enrollment(nodes, min_nodes, poll_interval, node_catchup_timeout, cancel).await;

                    return Some(FrameNotification {
                        run_id: String::new(),
                        stop_frame,
                        notification_type: NotificationType::TerminalFrame,
                        safety_error,
                        nodes_reached_stop_frame: reached as i32,
                        total_nodes: total as i32,
                        enrollment_error,
                        rejoin_error,
                    });
                }
            }
        }
    }
}

/// Apply (or clear) the partition for `rank`, once per rank.
fn apply_rank_partition(
    rank: u64,
    rank_partitions: &HashMap<u64, RankPartitionEntry>,
    blossom: &BlossomSubProxy,
    ranks_applied: &mut HashSet<u64>,
) {
    if rank_partitions.is_empty() || !ranks_applied.insert(rank) {
        return;
    }
    match rank_partitions.get(&rank) {
        Some(entry) => {
            tracing::info!(rank, "applying rank partition");
            blossom.apply_partition(&entry.partition1, &entry.partition2);
        }
        None => {
            tracing::info!(rank, "no rank partition entry, clearing partitions");
            blossom.clear_partitions();
        }
    }
}

/// The archive prover addresses that must each vote for the last frame, paired
/// with the node name for diagnostics. Skips (with a warning) any archive whose
/// prover address is missing or malformed so a setup gap can't masquerade as a
/// rejoin failure.
fn required_archive_voters(nodes: &[NodeInfo]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for n in nodes.iter().filter(|n| n.is_archive) {
        if n.prover_address.is_empty() {
            tracing::warn!(name = %n.name, "archive missing prover address; excluded from rejoin check");
            continue;
        }
        match hex::decode(&n.prover_address) {
            Ok(b) if b.len() == 32 => out.push((n.name.clone(), b)),
            Ok(b) => {
                tracing::warn!(name = %n.name, len = b.len(), "archive prover address wrong length; excluded from rejoin check")
            }
            Err(e) => {
                tracing::warn!(name = %n.name, error = %e, "archive prover address decode failed; excluded from rejoin check")
            }
        }
    }
    out
}

/// Build the rejoin-error string: empty when every required archive originated a
/// consensus message for the last frame, otherwise names the archives that
/// didn't (they never rejoined consensus, only passively synced frames).
fn compute_rejoin_error(
    required: &[(String, Vec<u8>)],
    voters: &HashSet<Vec<u8>>,
    stop_frame: u64,
) -> String {
    let missing: Vec<&str> = required
        .iter()
        .filter(|(_, addr)| !voters.contains(addr))
        .map(|(name, _)| name.as_str())
        .collect();
    if missing.is_empty() {
        String::new()
    } else {
        format!(
            "{} did not vote for the last frame (stop_frame={stop_frame}) — did not rejoin consensus",
            missing.join(", ")
        )
    }
}

/// Compute the safety-violation string for the fetched frames (empty = safe).
fn compute_safety_error(frames: &[frame::GlobalFrameWrapper]) -> String {
    match check_safety(frames) {
        Ok(()) => String::new(),
        Err(e) => {
            tracing::error!(error = %e, "safety violation detected");
            e.to_string()
        }
    }
}

/// Run the enrollment monitor; returns the error string (empty when confirmed
/// or when there are no clients).
async fn run_enrollment(
    nodes: &[NodeInfo],
    min_nodes: usize,
    poll_interval: Duration,
    timeout: Duration,
    cancel: &CancellationToken,
) -> String {
    let archives: Vec<ArchiveTarget> = nodes
        .iter()
        .filter(|n| n.is_archive)
        .map(|n| ArchiveTarget {
            name: n.name.clone(),
            address: format!("{}:{}", n.hostname, node_port(n)),
        })
        .collect();

    let mut clients = Vec::new();
    for n in nodes.iter().filter(|n| !n.is_archive) {
        if n.prover_address.is_empty() {
            tracing::warn!(name = %n.name, "client missing prover address, skipping");
            continue;
        }
        let prover_address = match hex::decode(&n.prover_address) {
            Ok(b) if b.len() == 32 => b,
            Ok(b) => return format!("client {} prover address wrong length: {}", n.name, b.len()),
            Err(e) => return format!("client {} prover address decode: {e}", n.name),
        };
        clients.push(EnrollmentTarget {
            name: n.name.clone(),
            prover_address,
            // ExpectedCores=2 in the Go default (client pinned to 3 cores →
            // available_parallelism-1 = 2 workers). Use the client's own
            // NodeService for the supplementary worker check.
            node_address: format!("{}:{}", n.hostname, node_port(n)),
            expected_cores: 2,
        });
    }

    let mut monitor = EnrollmentMonitor::new(archives, clients, poll_interval, min_nodes, timeout);
    match monitor.wait_for_enrollment(cancel).await {
        Ok(()) => String::new(),
        Err(e) => {
            tracing::error!(error = %e, "enrollment verification failed");
            e
        }
    }
}

fn node_port(n: &NodeInfo) -> i32 {
    if n.node_port == 0 {
        8337
    } else {
        n.node_port
    }
}

/// Build per-archive gRPC backend specs (server TLS impersonating the backend +
/// per-caller client TLS). Backends are archives only, but EVERY node (archives
/// and clients) is a potential caller — a client frame-syncs from archives
/// through the proxy, so the proxy must hold its caller identity too.
fn build_grpc_backends(nodes: &[NodeInfo]) -> Result<Vec<grpc_proxy::BackendSpec>> {
    use std::str::FromStr;
    let mut callers = Vec::new();
    let mut backends = Vec::new();
    for n in nodes {
        let id = Ed448Identity::from_config_hex(&n.peer_priv_key)
            .map_err(|e| anyhow::anyhow!("identity for {}: {e}", n.name))?;
        let wiring = grpc_proxy::NodeWiring {
            peer_id: quil_p2p::PeerId::from_str(&n.peer_id)
                .map_err(|e| anyhow::anyhow!("peer id for {}: {e}", n.name))?,
            ed448_seed: ed448_seed_from_identity(&id)?,
            ed448_pubkey: id.public_key.clone(),
            backend_addr: n.stream_address(),
            listen_port: 0,
        };
        callers.push(wiring.clone());
        if n.is_archive {
            let ordinal = n
                .ordinal()
                .map_err(|e| anyhow::anyhow!("ordinal for {}: {e}", n.name))?;
            backends.push(grpc_proxy::NodeWiring {
                listen_port: GRPC_BASE_PORT + ordinal as u16,
                ..wiring
            });
        }
    }
    grpc_proxy::build_backend_specs(&backends, &callers)
}

// ---- helpers ----------------------------------------------------------------

fn parse_rank_partitions_env() -> Result<HashMap<u64, RankPartitionEntry>> {
    let raw = std::env::var("RANK_PARTITIONS").unwrap_or_default();
    if raw.is_empty() {
        return Ok(HashMap::new());
    }
    let parsed = rankpartitions::parse_rank_partitions(&raw).context("parse RANK_PARTITIONS")?;
    // Validate every peer ID decodes.
    use std::str::FromStr;
    for e in parsed.values() {
        for p in e.partition1.iter().chain(e.partition2.iter()) {
            quil_p2p::PeerId::from_str(p.trim()).map_err(|err| {
                anyhow::anyhow!("invalid peer ID {p:?} in RANK_PARTITIONS: {err}")
            })?;
        }
    }
    tracing::info!(entries = parsed.len(), "loaded rank partition schedule");
    Ok(parsed.into_iter().collect())
}

fn ed448_seed_from_hex(hex_key: &str) -> Result<[u8; 57]> {
    let id = Ed448Identity::from_config_hex(hex_key).map_err(|e| anyhow::anyhow!("{e}"))?;
    ed448_seed_from_identity(&id)
}

fn ed448_seed_from_identity(id: &Ed448Identity) -> Result<[u8; 57]> {
    id.private_key
        .clone()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed448 seed is not 57 bytes"))
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("{key} environment variable is required"))
}

/// Parse a Go-style duration like `120s`, `2m`, `30s`. Falls back to `None` on
/// anything unrecognized.
fn parse_go_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| c.is_alphabetic())?);
    let value: u64 = num.parse().ok()?;
    match unit {
        "s" => Some(Duration::from_secs(value)),
        "m" => Some(Duration::from_secs(value * 60)),
        "ms" => Some(Duration::from_millis(value)),
        "h" => Some(Duration::from_secs(value * 3600)),
        _ => None,
    }
}

/// Sends notifications (progress + terminal) to the orchestrator, stamping each
/// with the run ID.
struct Notifier {
    runner_address: String,
    runner_auth: String,
    run_id: String,
}

impl Notifier {
    /// POST `notification` (run_id stamped) to the runner, logging on failure.
    async fn send(&self, notification: FrameNotification) {
        let notification = FrameNotification {
            run_id: self.run_id.clone(),
            ..notification
        };
        if let Err(e) =
            post_notification(&self.runner_address, &self.runner_auth, &notification).await
        {
            tracing::error!(error = %e, "failed to notify runner");
        }
    }

    /// POST an intermediate frame-progress update — a best-effort liveness signal
    /// the orchestrator logs. The reached frame rides `stop_frame`/`frame_number`.
    async fn progress(&self, frame: u64, total_nodes: i32) {
        self.send(FrameNotification {
            run_id: String::new(),
            stop_frame: frame,
            notification_type: NotificationType::Progress,
            safety_error: String::new(),
            nodes_reached_stop_frame: 0,
            total_nodes,
            enrollment_error: String::new(),
            rejoin_error: String::new(),
        })
        .await;
    }
}

/// POST the notification JSON to the orchestrator over plain HTTP/1.1 (the
/// runner endpoint is plaintext). Avoids pulling a full HTTP client.
async fn post_notification(
    runner_address: &str,
    auth_token: &str,
    notification: &FrameNotification,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = serde_json::to_vec(notification).context("serialize notification")?;
    let host = runner_address;
    let request = format!(
        "POST /run-notification HTTP/1.1\r\n\
         Host: {host}\r\n\
         Authorization: Bearer {auth_token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );

    let mut stream = tokio::net::TcpStream::connect(runner_address)
        .await
        .with_context(|| format!("connect to runner {runner_address}"))?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.ok();
    let head = String::from_utf8_lossy(&response);
    let status_ok = head
        .lines()
        .next()
        .map(|l| l.contains(" 200") || l.contains(" 2"))
        .unwrap_or(false);
    if status_ok {
        tracing::info!("notified runner");
        Ok(())
    } else {
        bail!(
            "runner returned non-success: {}",
            head.lines().next().unwrap_or("")
        );
    }
}

fn install_signal_handler(cancel: CancellationToken, sup_token: CancellationToken) {
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received interrupt signal");
        cancel.cancel();
        sup_token.cancel();
    });
}

fn init_logging() {
    // Cap the HTTP/2 + gRPC stack (h2 codec, hyper, tonic, tower) at warn even
    // under full debug (RUST_LOG=debug): their per-frame send/received logs
    // otherwise drown the proxy's own output. Errors/warnings are kept.
    let mut filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    for directive in ["h2=warn", "hyper=warn", "tonic=warn", "tower=warn"] {
        filter = filter.add_directive(directive.parse().expect("static directive is valid"));
    }
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(name: &str, prover_address: &str) -> NodeInfo {
        NodeInfo {
            name: name.into(),
            hostname: name.into(),
            stream_port: 8340,
            node_port: 8337,
            peer_id: "QmTest".into(),
            peer_priv_key: String::new(),
            is_archive: true,
            prover_address: prover_address.into(),
        }
    }

    fn addr(b: u8) -> Vec<u8> {
        vec![b; 32]
    }

    fn hex32(b: u8) -> String {
        hex::encode(addr(b))
    }

    #[test]
    fn required_voters_includes_only_well_formed_archives() {
        let client = NodeInfo {
            is_archive: false,
            ..archive("client-1", &hex32(0x09))
        };
        let nodes = vec![
            archive("archive-1", &hex32(0x01)),
            archive("archive-2", &hex32(0x02)),
            archive("archive-3", ""),     // missing → excluded
            archive("archive-4", "zz"),   // malformed hex → excluded
            archive("archive-5", "00ff"), // wrong length → excluded
            client,                       // not an archive → excluded
        ];
        let req = required_archive_voters(&nodes);
        let names: Vec<&str> = req.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["archive-1", "archive-2"]);
        assert_eq!(req[0].1, addr(0x01));
    }

    #[test]
    fn rejoin_error_empty_when_all_archives_voted() {
        let required = vec![
            ("archive-1".to_string(), addr(0x01)),
            ("archive-2".to_string(), addr(0x02)),
        ];
        let voters: HashSet<Vec<u8>> = [addr(0x01), addr(0x02), addr(0x03)].into_iter().collect();
        assert_eq!(compute_rejoin_error(&required, &voters, 5), "");
    }

    #[test]
    fn rejoin_error_names_archives_that_did_not_vote() {
        let required = vec![
            ("archive-1".to_string(), addr(0x01)),
            ("archive-4".to_string(), addr(0x04)),
        ];
        // Only archive-1 voted for the last frame.
        let voters: HashSet<Vec<u8>> = [addr(0x01)].into_iter().collect();
        let err = compute_rejoin_error(&required, &voters, 5);
        assert!(
            err.contains("archive-4"),
            "error should name archive-4: {err}"
        );
        assert!(!err.contains("archive-1"), "archive-1 voted: {err}");
        assert!(err.contains("stop_frame=5"));
    }
}
