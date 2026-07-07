//! `devnet` — Docker-based integration-test runner for the Quilibrium network.
//!
//! Discovers the node services in `docker-compose.yml`, builds the stack, and
//! runs a partition scenario from a manual schedule (`single` mode),
//! adjudicating the run from the proxy's notification.

mod artifacts;
mod docker;
mod notification;
mod registry;
mod runner;
mod util;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use devnet::rankpartitions::{self, RankPartitionEntry};
use devnet::shared::NodeInfo;

use crate::notification::{start_notification_server, NotificationRouter};
use crate::registry::ProjectRegistry;
use crate::runner::{has_failures, print_summary, run_single_test, RunConfig, TestResult};
use crate::util::{generate_bearer_token, new_run_id};

const RUNNER_ERROR: u8 = 1;
const TEST_RUN_ERROR: u8 = 2;
const INTERRUPT: u8 = 130;

#[derive(Parser)]
#[command(name = "devnet", about = "Simulation test runner")]
struct Cli {
    /// Working directory containing docker-compose.yml (defaults to current directory).
    #[arg(long = "dir", global = true, default_value = "")]
    working_dir: String,
    /// Port to listen for notifications from the proxy.
    #[arg(long = "listen", global = true, default_value = "8080")]
    listen_port: String,
    /// Enable verbose (DEBUG-level) logging.
    #[arg(long, global = true)]
    verbose: bool,
    /// Directory to save artifacts (config, result, logs) for failing runs.
    #[arg(long = "out", global = true, default_value = "./out")]
    out_dir: String,
    /// Also save artifacts for successful runs.
    #[arg(long = "save-logs-on-success", global = true)]
    save_logs_on_success: bool,
    /// The timeout (seconds) for an entire test run.
    #[arg(long = "global-timeout", global = true, default_value = "300")]
    global_timeout: String,
    /// The timeout while waiting for a single node to reach the stopframe after other nodes reached.
    #[arg(long = "node-catchup-timeout", global = true, default_value = "60")]
    node_catchup_timeout: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a single simulation.
    Single {
        /// Frame number at which the simulation should stop.
        #[arg(long = "stopframe", default_value_t = 30)]
        stop_frame: i32,
        /// Minimum number of nodes that must reach the stop frame (0 = all archives).
        #[arg(long = "minnodes", default_value_t = 0)]
        min_nodes: i32,
        /// JSON array of per-rank partition configs, e.g.
        /// '[{"rank":5,"partition1":["archive-1"],"partition2":["archive-3"]}]'.
        #[arg(long = "rank-partitions", default_value = "")]
        rank_partitions: String,
    },
}

/// Global options shared by both modes (everything in [`Cli`] except the subcommand).
struct Opts {
    working_dir: String,
    listen_port: String,
    verbose: bool,
    out_dir: String,
    save_logs_on_success: bool,
    global_timeout: Duration,
    node_catchup_timeout: Duration,
}

/// Setup results shared by both modes.
struct CommonState {
    exec_dir: String,
    node_infos: Vec<NodeInfo>,
    minimum_nodes: i32,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "Setup failed");
            ExitCode::from(RUNNER_ERROR)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let Cli {
        working_dir,
        listen_port,
        verbose,
        out_dir,
        save_logs_on_success,
        command,
        global_timeout,
        node_catchup_timeout,
    } = cli;
    let opts = Opts {
        working_dir,
        listen_port,
        verbose,
        out_dir,
        save_logs_on_success,
        global_timeout: Duration::from_secs(global_timeout.parse()?),
        node_catchup_timeout: Duration::from_secs(node_catchup_timeout.parse()?),
    };

    let Command::Single {
        stop_frame,
        min_nodes,
        rank_partitions,
    } = command;

    let (cancel, state) = prepare_run(&opts.working_dir, min_nodes).await?;

    let (results, interrupted) =
        run_single_mode(&opts, &cancel, state, stop_frame, &rank_partitions).await?;

    Ok(finish_run(&results, interrupted))
}

/// Wires SIGINT/SIGTERM to a cancellation token, resolves the working directory,
/// discovers node services, and computes the minimum-nodes threshold.
async fn prepare_run(
    working_dir: &str,
    min_nodes_override: i32,
) -> Result<(CancellationToken, CommonState)> {
    let cancel = CancellationToken::new();
    spawn_signal_handler(cancel.clone());

    let exec_dir = if working_dir.is_empty() {
        std::env::current_dir()
            .context("failed to get current directory")?
            .to_string_lossy()
            .into_owned()
    } else {
        working_dir.to_string()
    };

    let node_infos = docker::get_node_services(&exec_dir)
        .await
        .context("failed to get node services")?;

    let archives = node_infos.iter().filter(|n| n.is_archive).count() as i32;
    let clients = node_infos.len() as i32 - archives;

    // Default the success threshold to the number of archives: clients run the
    // same binary so they advance frames too, but their height shouldn't gate
    // the test. Frame liveness is an archive-only signal.
    let minimum_nodes = if min_nodes_override > 0 {
        min_nodes_override
    } else {
        archives
    };
    tracing::info!(
        archives,
        clients,
        minimum_nodes_for_success = minimum_nodes,
        "Discovered nodes"
    );

    Ok((
        cancel,
        CommonState {
            exec_dir,
            node_infos,
            minimum_nodes,
        },
    ))
}

async fn run_single_mode(
    opts: &Opts,
    cancel: &CancellationToken,
    state: CommonState,
    stop_frame: i32,
    rank_partitions: &str,
) -> Result<(Vec<TestResult>, bool)> {
    let (original, resolved) = resolve_rank_partitions(&state.exec_dir, rank_partitions)
        .context("failed to resolve rank partitions")?;

    // The rejoin check requires the partition to heal before the last frame, so
    // an isolated archive has time to catch up and vote for `stop_frame`. Reject
    // schedules whose last partitioned rank is not strictly below the stop frame.
    validate_partition_ranks(&original, stop_frame)?;

    docker::docker_compose_build(&state.exec_dir, opts.verbose)
        .await
        .context("failed to build docker compose")?;

    let bearer_token = generate_bearer_token();
    let router = NotificationRouter::new();
    let server = start_notification_server(&opts.listen_port, bearer_token.clone(), router.clone())
        .await
        .context("failed to start notification server")?;
    let registry = ProjectRegistry::new();

    let cfg = RunConfig {
        exec_dir: state.exec_dir.clone(),
        bearer_token,
        listen_port: opts.listen_port.clone(),
        verbose: opts.verbose,
        stop_frame,
        nodes: state.node_infos.clone(),
        minimum_nodes: state.minimum_nodes,
        rank_partitions_resolved: resolved,
        rank_partitions_original: original,
        out_dir: opts.out_dir.clone(),
        save_logs_on_success: opts.save_logs_on_success,
        parallel: 1,
        global_timeout: opts.global_timeout,
        node_catchup_timeout: opts.node_catchup_timeout,
    };

    let run_id = new_run_id();
    let start = Instant::now();
    let mut result = run_single_test(cancel, &run_id, &cfg, &router, &registry).await;
    result.duration = start.elapsed();
    let interrupted = cancel.is_cancelled();

    server.shutdown().await;
    if interrupted {
        cleanup_active_projects(&state.exec_dir, &registry, opts.verbose, 1).await;
    }

    Ok((vec![result], interrupted))
}

/// Parses the raw JSON rank-partitions flag and resolves node names to peer IDs.
/// Returns the original entries (service names, sorted by rank) and the
/// peer-ID-resolved JSON for the docker env var. Both are empty if `raw` is empty.
fn resolve_rank_partitions(exec_dir: &str, raw: &str) -> Result<(Vec<RankPartitionEntry>, String)> {
    if raw.is_empty() {
        return Ok((Vec::new(), String::new()));
    }

    let parsed =
        rankpartitions::parse_rank_partitions(raw).context("failed to parse --rank-partitions")?;

    // BTreeMap iterates in ascending rank order already.
    let original: Vec<RankPartitionEntry> = parsed.into_values().collect();

    let mut resolved_entries = Vec::with_capacity(original.len());
    for e in &original {
        let mut re = e.clone();
        if !e.partition1.is_empty() {
            re.partition1 = resolve_names(exec_dir, &e.partition1)
                .with_context(|| format!("failed to resolve rank {} partition1", e.rank))?;
        }
        if !e.partition2.is_empty() {
            re.partition2 = resolve_names(exec_dir, &e.partition2)
                .with_context(|| format!("failed to resolve rank {} partition2", e.rank))?;
        }
        resolved_entries.push(re);
    }

    let resolved =
        serde_json::to_string(&resolved_entries).context("failed to serialize rank-partitions")?;
    Ok((original, resolved))
}

/// Ensures the last partitioned rank is strictly below `stop_frame`. The rejoin
/// gate observes whether each archive voted for the last frame; that's only
/// meaningful if the partition has already healed by then. A schedule still
/// partitioned at (or past) the stop frame could never show a rejoin, so we
/// reject it up front rather than report a spurious failure.
fn validate_partition_ranks(entries: &[RankPartitionEntry], stop_frame: i32) -> Result<()> {
    let Some(last_rank) = entries.iter().map(|e| e.rank).max() else {
        return Ok(());
    };
    if stop_frame <= 0 {
        anyhow::bail!("stop frame must be positive, got {stop_frame}");
    }
    if last_rank >= stop_frame as u64 {
        anyhow::bail!(
            "last partition rank ({last_rank}) must be below the stop frame ({stop_frame}); \
             the partition must heal before the last frame so an isolated archive can rejoin \
             consensus and vote for it — increase --stopframe or lower the partition rank"
        );
    }
    Ok(())
}

fn resolve_names(exec_dir: &str, names: &[String]) -> Result<Vec<String>> {
    let trimmed: Vec<String> = names.iter().map(|n| n.trim().to_string()).collect();
    let id_map = docker::resolve_node_identities(exec_dir, &trimmed)?;
    trimmed
        .iter()
        .map(|n| {
            id_map
                .get(n)
                .map(|id| id.peer_id.clone())
                .context(format!("no identity resolved for node {n:?}"))
        })
        .collect()
}

async fn cleanup_active_projects(
    exec_dir: &str,
    registry: &ProjectRegistry,
    verbose: bool,
    parallel: i32,
) {
    let active = registry.get_all();
    if active.is_empty() {
        return;
    }
    tracing::info!(
        count = active.len(),
        "Cleaning up remaining Docker Compose projects"
    );
    for project in active {
        let down = docker::docker_compose_down(exec_dir, &project, verbose, parallel);
        if let Err(e) = tokio::time::timeout(Duration::from_secs(30), down).await {
            tracing::error!(error = %e, project = %project, "Failed to cleanup project");
        }
    }
}

fn finish_run(results: &[TestResult], interrupted: bool) -> ExitCode {
    print_summary(results, interrupted);
    if interrupted {
        tracing::warn!(completed = results.len(), "Tests interrupted by signal");
        return ExitCode::from(INTERRUPT);
    }
    if has_failures(results) {
        return ExitCode::from(TEST_RUN_ERROR);
    }
    ExitCode::SUCCESS
}

fn init_logging(verbose: bool) {
    let default = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn spawn_signal_handler(cancel: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to install SIGINT handler");
                    return;
                }
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to install SIGTERM handler");
                    return;
                }
            };
            tokio::select! {
                _ = sigint.recv() => tracing::info!(signal = "SIGINT", "Received interrupt signal, initiating shutdown"),
                _ = sigterm.recv() => tracing::info!(signal = "SIGTERM", "Received interrupt signal, initiating shutdown"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Received interrupt signal, initiating shutdown");
        }
        cancel.cancel();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(rank: u64) -> RankPartitionEntry {
        RankPartitionEntry {
            rank,
            partition1: vec!["archive-1".into()],
            partition2: vec!["archive-2".into()],
        }
    }

    #[test]
    fn validate_partition_ranks_accepts_healing_schedule() {
        // Last partition at rank 1, stop frame 5 — heals well before the end.
        validate_partition_ranks(&[entry(1)], 5).unwrap();
    }

    #[test]
    fn validate_partition_ranks_rejects_partition_at_stop_frame() {
        // Partition still active at the stop frame: no room to observe a rejoin.
        let err = validate_partition_ranks(&[entry(3), entry(5)], 5).unwrap_err();
        assert!(err.to_string().contains("must be below the stop frame"));
    }

    #[test]
    fn validate_partition_ranks_rejects_partition_past_stop_frame() {
        let err = validate_partition_ranks(&[entry(7)], 5).unwrap_err();
        assert!(err.to_string().contains("must be below the stop frame"));
    }

    #[test]
    fn validate_partition_ranks_no_partitions_is_ok() {
        validate_partition_ranks(&[], 5).unwrap();
    }
}
