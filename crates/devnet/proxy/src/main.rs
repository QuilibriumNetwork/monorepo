//! `devnet-proxy` — in-container gossip/gRPC partition proxy for the devnet
//! harness.
//!
//! Runs a BlossomSub host that meshes with every node and applies bipartite
//! partitions, snoops global consensus on `:8340` to drive per-view partition
//! timing, and (once a proposal past the stop frame is seen) polls the archives
//! for frame convergence, checks chain safety, verifies client enrollment, and
//! POSTs the result back to the orchestrator.
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
mod simplex_view;
mod view_schedule;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use devnet::shared::{FrameNotification, NodeInfo, NotificationType};
use devnet::viewpartitions::{self, ViewPartitionEntry};

use crate::blossomsub_proxy::BlossomSubProxy;
use crate::consensus_events::ConsensusEvent;
use crate::enrollment_monitor::{ArchiveTarget, EnrollmentMonitor, EnrollmentTarget};
use crate::frame_monitor::{FrameMonitor, FrameTarget};
use crate::partitioner::NetworkPartitioner;
use crate::safety::check_safety;
use crate::view_schedule::ViewSchedule;

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

    // Identity the proxy dials archives with for frame polling / enrollment
    // checks. `:8340` is PQNoise-authenticated by a Falcon `q-prover-key`, and
    // the proxy is not a prover so it has no such key of its own — it borrows
    // the first archive's, which it already holds to relay that archive's
    // traffic. Impersonating a genesis archive also guarantees the dial clears
    // whatever caller policy the archives apply to each other.
    let monitor_dial_key = nodes
        .iter()
        .find(|n| n.is_archive)
        .context("no archive node to borrow a dial identity from")
        .and_then(falcon_key_of)?;

    // Shared partition table consulted by both the gossip and gRPC paths.
    let partitioner = Arc::new(NetworkPartitioner::new());

    // The partition schedule. It owns partition timing and is applied inline by
    // the gRPC snoop rather than from the event loop, so a view takes effect
    // before the message that revealed it reaches the partition gate.
    let schedule = Arc::new(ViewSchedule::new(
        parse_view_partitions_env()?,
        Arc::clone(&partitioner),
    ));
    schedule.apply_initial();

    // Start the BlossomSub host (swarm on the supervisor). The binding must
    // outlive the run: dropping it shuts the swarm down.
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    // Sized so the loop's tally cannot be truncated by a burst at a view
    // boundary: a dropped event now fails the run.
    let (consensus_tx, consensus_rx) = mpsc::channel::<ConsensusEvent>(8192);
    let _blossom = BlossomSubProxy::start(&mut sup, &config.p2p, Arc::clone(&partitioner))
        .await
        .context("start blossomsub proxy")?;

    // Build the gRPC backend specs (backend + per-caller Falcon identities) and
    // start one transparent-h2 partition proxy listener per archive. The event
    // loop keeps a handle on the snoop context to read its dropped-event count
    // when it forms the verdict.
    let mut snoop_ctx: Option<Arc<grpc_serve::SnoopContext>> = None;
    match build_grpc_backends(&nodes) {
        Ok(specs) => {
            let specs: Vec<Arc<grpc_proxy::BackendSpec>> =
                specs.into_iter().map(Arc::new).collect();
            tracing::info!(backends = specs.len(), "starting gRPC proxy");
            let part = Arc::clone(&partitioner);
            // The gRPC proxy also snoops SubmitGlobalConsensus requests for the
            // stop-frame/view signals that moved off gossip in v2.1.0.25. Events
            // are attributed to the calling node's prover address, so the snoop
            // needs the peer-ID → prover-address mapping up front.
            let snoop = Arc::new(grpc_serve::SnoopContext {
                prover_addresses: prover_addresses_by_peer(&nodes)?,
                cursor: Default::default(),
                schedule: Arc::clone(&schedule),
                dropped: AtomicU64::new(0),
            });
            snoop_ctx = Some(Arc::clone(&snoop));
            let grpc_consensus_tx = consensus_tx.clone();
            sup.spawn("grpc-proxy", move |token| async move {
                tokio::select! {
                    _ = token.cancelled() => Ok(()),
                    r = grpc_serve::serve_all(specs, part, grpc_consensus_tx, snoop) => r,
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
        monitor_dial_key,
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

    // Run the consensus event loop; it tracks frame progress and consensus
    // participation, and on reaching the stop frame runs the frame/enrollment
    // verification and emits the terminal notification. Partition timing lives
    // in `schedule`, applied by the snoop.
    let outcome = consensus_event_loop(
        consensus_rx,
        &cancel,
        global_timeout,
        stop_frame,
        archive_count,
        &schedule,
        snoop_ctx.as_deref(),
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
    schedule: &ViewSchedule,
    snoop: Option<&grpc_serve::SnoopContext>,
    frame_monitor: &mut FrameMonitor,
    nodes: &[NodeInfo],
    min_nodes: usize,
    poll_interval: Duration,
    node_catchup_timeout: Duration,
    notifier: &Notifier,
) -> Option<FrameNotification> {
    // Archives that must each originate a consensus message for the last frame
    // to prove they rejoined consensus rather than passively syncing frames.
    let required_voters = required_archive_voters(nodes);
    // Active participation per view. A vote names a view, never a frame, so
    // attributing it to a frame means correlating through the view that
    // *produced* that frame — which only the block channel can establish.
    let mut active_voters_by_view: BTreeMap<u64, HashSet<Vec<u8>>> = BTreeMap::new();
    // The view that produced `stop_frame`, learned from that frame's block.
    let mut stop_frame_view: Option<u64> = None;
    // Highest frame observed in a consensus message so far — used only to log
    // frame progress once per new frame (events repeat per view and per backend).
    let mut max_frame_seen: u64 = 0;
    let global_timer = tokio::time::sleep(global_timeout);
    tokio::pin!(global_timer);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return None,
            _ = &mut global_timer => {
                tracing::warn!(?global_timeout, stop_frame, "global timeout expired without seeing stop frame");
                return Some(FrameNotification {
                    run_id: String::new(),
                    stop_frame,
                    notification_type: NotificationType::GlobalTimeout,
                    safety_error: String::new(),
                    nodes_reached_stop_frame: 0,
                    total_nodes: archive_count as i32,
                    enrollment_error: String::new(),
                    rejoin_error: String::new(),
                    // A timed-out run is already a failure; the harness check
                    // still runs so the report says whether the scenario it was
                    // asked to run actually happened.
                    harness_error: compute_harness_error(schedule, snoop, None, false),
                });
            }
            maybe_event = consensus_rx.recv() => {
                let event = maybe_event?;

                // Record active participation against the view it names. Only
                // views at or after the stop frame's can matter, but that view
                // isn't known until its block arrives, so keep a bounded tail.
                if event.source.is_active() && !event.sender_address.is_empty() {
                    active_voters_by_view
                        .entry(event.view)
                        .or_default()
                        .insert(event.sender_address.clone());
                    if let Some(prune_below) = event.view.checked_sub(VOTE_HISTORY_VIEWS) {
                        active_voters_by_view.retain(|&v, _| v >= prune_below);
                    }
                }

                // Everything below needs a frame. A view-only observation (a
                // nullification, or any vote before the first block) carries
                // none, and is exactly the case the view schedule exists to
                // keep tracking.
                let Some(frame_number) = event.frame_number else {
                    continue;
                };

                // The block for `stop_frame` is what ties that frame to a view.
                // A vote must never establish this: it names its own view but
                // inherits its frame, and since the cursor is updated separately
                // from the channel send, a vote for a *later* view can reach the
                // loop before the block it inherited the frame from — pairing
                // `stop_frame` with a view that did not produce it and shifting
                // the rejoin window off the votes it is supposed to count.
                if frame_number == stop_frame && event.source.states_own_frame() {
                    stop_frame_view.get_or_insert(event.view);
                }

                if frame_number > max_frame_seen {
                    max_frame_seen = frame_number;
                    tracing::debug!(
                        frame = frame_number,
                        view = event.view,
                        stop_frame,
                        "global consensus frame advanced"
                    );
                    // Report liveness to the orchestrator so it can show progress
                    // during the run (it otherwise only hears the terminal frame).
                    // Spawned so the loop never stalls on network I/O while votes
                    // are arriving — a dropped event would invalidate the run.
                    let notifier = notifier.clone();
                    let total = archive_count as i32;
                    tokio::spawn(async move { notifier.progress(frame_number, total).await });
                }

                if frame_number > stop_frame {
                    tracing::info!(event_frame = frame_number, stop_frame, "observed proposal past stop frame, monitoring all nodes");
                    let (reached, total) = frame_monitor.start_monitoring(cancel).await;
                    tracing::info!(reached, total, "frame monitoring complete");

                    let frames = frame_monitor.fetch_committed_frames().await;
                    let safety_error = compute_safety_error(&frames);

                    // Rejoin is only answerable once the stop frame's view is
                    // known; without it the run can't say either way, which is a
                    // harness failure rather than a rejoin failure.
                    let rejoin_error = match stop_frame_view {
                        Some(view) => {
                            let voters = active_voters_since(&active_voters_by_view, view);
                            let err = compute_rejoin_error(&required_voters, &voters, stop_frame);
                            if err.is_empty() {
                                tracing::info!(
                                    archives = required_voters.len(),
                                    stop_frame,
                                    stop_frame_view = view,
                                    "all archives voted in the last frame's view (rejoined consensus)"
                                );
                            } else {
                                tracing::error!(error = %err, "rejoin verification failed");
                            }
                            err
                        }
                        None => String::new(),
                    };

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
                        harness_error: compute_harness_error(
                            schedule,
                            snoop,
                            stop_frame_view,
                            true,
                        ),
                    });
                }
            }
        }
    }
}

/// How many views of participation history to retain. The stop frame's view is
/// unknown until its block arrives, so votes are buffered until then; a tail of
/// this many views is far more than the gap between a vote and its block.
const VOTE_HISTORY_VIEWS: u64 = 64;

/// Every address that actively participated in `since` or any later view.
///
/// The window starts at the stop frame's own view rather than being pinned to
/// it exactly: an archive that rejoins as that view is being decided may cast
/// its first vote in the next one, which today's frame-stamp inheritance would
/// also have counted.
fn active_voters_since(by_view: &BTreeMap<u64, HashSet<Vec<u8>>>, since: u64) -> HashSet<Vec<u8>> {
    by_view
        .range(since..)
        .flat_map(|(_, voters)| voters.iter().cloned())
        .collect()
}

/// Describes any way the harness itself failed to run the scenario, rather than
/// the network under test failing.
///
/// A run that never applied its partitions, or that lost consensus events, is
/// not evidence of anything — reporting it as a pass is worse than reporting a
/// real failure, because it looks like the scenario was exercised.
fn compute_harness_error(
    schedule: &ViewSchedule,
    snoop: Option<&grpc_serve::SnoopContext>,
    stop_frame_view: Option<u64>,
    reached_terminal: bool,
) -> String {
    let mut problems = Vec::new();

    let missed = schedule.missed_views();
    if !missed.is_empty() {
        problems.push(format!(
            "scheduled partition views were never observed and so never applied: {missed:?}"
        ));
    }

    let dropped = snoop.map_or(0, |s| s.dropped.load(AtomicOrdering::Relaxed));
    if dropped > 0 {
        problems.push(format!(
            "{dropped} consensus event(s) dropped; participation tallies are incomplete"
        ));
    }

    // Only meaningful once the run reached its terminal frame; on the timeout
    // path, not reaching the stop frame is itself the reported failure.
    if reached_terminal && stop_frame_view.is_none() {
        problems.push(
            "the stop frame's view was never established, so rejoin could not be verified"
                .to_string(),
        );
    }

    problems.join("; ")
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
        let wiring = grpc_proxy::NodeWiring {
            peer_id: quil_p2p::PeerId::from_str(&n.peer_id)
                .map_err(|e| anyhow::anyhow!("peer id for {}: {e}", n.name))?,
            falcon_signing_key: falcon_key_of(n)?,
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

fn parse_view_partitions_env() -> Result<HashMap<u64, ViewPartitionEntry>> {
    let raw = std::env::var("VIEW_PARTITIONS").unwrap_or_default();
    if raw.is_empty() {
        return Ok(HashMap::new());
    }
    let parsed = viewpartitions::parse_view_partitions(&raw).context("parse VIEW_PARTITIONS")?;
    // Validate every peer ID decodes.
    use std::str::FromStr;
    for e in parsed.values() {
        for p in e.partition1.iter().chain(e.partition2.iter()) {
            quil_p2p::PeerId::from_str(p.trim()).map_err(|err| {
                anyhow::anyhow!("invalid peer ID {p:?} in VIEW_PARTITIONS: {err}")
            })?;
        }
    }
    tracing::info!(entries = parsed.len(), "loaded view partition schedule");
    Ok(parsed.into_iter().collect())
}

/// Map each node's peer ID to its prover address, so the gRPC snoop can name the
/// node behind a handshake-verified caller. Nodes with no prover address are
/// skipped — the event loop only ever looks up archives.
fn prover_addresses_by_peer(nodes: &[NodeInfo]) -> Result<HashMap<quil_p2p::PeerId, Vec<u8>>> {
    use std::str::FromStr;
    let mut out = HashMap::new();
    for n in nodes {
        if n.prover_address.is_empty() {
            continue;
        }
        let peer = quil_p2p::PeerId::from_str(&n.peer_id)
            .map_err(|e| anyhow::anyhow!("peer id for {}: {e}", n.name))?;
        let address = hex::decode(&n.prover_address)
            .map_err(|e| anyhow::anyhow!("prover address for {}: {e}", n.name))?;
        out.insert(peer, address);
    }
    Ok(out)
}

/// Decode a node's Falcon `q-prover-key` signing key from its [`NodeInfo`].
fn falcon_key_of(n: &NodeInfo) -> Result<Vec<u8>> {
    if n.falcon_signing_key.is_empty() {
        anyhow::bail!("node info {} missing falcon signing key", n.name);
    }
    hex::decode(&n.falcon_signing_key)
        .map_err(|e| anyhow::anyhow!("falcon signing key for {}: {e}", n.name))
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("{key} environment variable is required"))
}

/// Sends notifications (progress + terminal) to the orchestrator, stamping each
/// with the run ID.
#[derive(Clone)]
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
            harness_error: String::new(),
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
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
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
            falcon_signing_key: String::new(),
            is_archive: true,
            prover_address: prover_address.into(),
        }
    }

    fn addr(b: u8) -> Vec<u8> {
        vec![b; 32]
    }

    // ---- rejoin correlation ------------------------------------------------

    fn voters(pairs: &[(u64, &[u8])]) -> BTreeMap<u64, HashSet<Vec<u8>>> {
        let mut m: BTreeMap<u64, HashSet<Vec<u8>>> = BTreeMap::new();
        for (view, addr) in pairs {
            m.entry(*view).or_default().insert(addr.to_vec());
        }
        m
    }

    /// The window opens at the stop frame's view and stays open, so an archive
    /// that rejoins as that view is decided and first votes in the next one is
    /// still credited.
    #[test]
    fn active_voters_since_includes_the_view_and_later() {
        let by_view = voters(&[(6, &addr(1)), (7, &addr(2)), (8, &addr(3))]);
        let got = active_voters_since(&by_view, 7);
        assert!(!got.contains(&addr(1)), "view 6 is before the window");
        assert!(got.contains(&addr(2)), "the stop frame's own view counts");
        assert!(got.contains(&addr(3)), "a later view counts");
    }

    /// The defect this replaces: a vote inherited the newest block's frame
    /// number, so activity in an *earlier* view could satisfy the rejoin gate
    /// for the stop frame.
    #[test]
    fn active_voters_since_excludes_earlier_views() {
        let by_view = voters(&[(1, &addr(1)), (2, &addr(1))]);
        assert!(active_voters_since(&by_view, 3).is_empty());
    }

    #[test]
    fn rejoin_fails_when_an_archive_only_participated_before_the_stop_view() {
        let required = required_archive_voters(&[
            archive("archive-1", &hex32(1)),
            archive("archive-2", &hex32(2)),
        ]);
        // archive-2 voted only in view 5; the stop frame was decided in view 6.
        let by_view = voters(&[(6, &addr(1)), (5, &addr(2))]);
        let err = compute_rejoin_error(&required, &active_voters_since(&by_view, 6), 6);
        assert!(err.contains("archive-2"), "unexpected: {err}");
        assert!(!err.contains("archive-1"), "unexpected: {err}");
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
