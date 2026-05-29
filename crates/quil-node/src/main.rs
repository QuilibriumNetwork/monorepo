use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use tracing::{error, info, warn};

use quil_lifecycle::{ShutdownReason, Supervisor};

// Global allocator: jemalloc. Replaces the system allocator on all
// non-MSVC targets. Heap profiling is enabled by
//   MALLOC_CONF=prof:true,prof_prefix:/tmp/jeprof
// at process start; dumps `/tmp/jeprof.<pid>.<seq>.[fihu].heap`
// files that `jeprof --text quil-node /tmp/jeprof.<...>.heap`
// rolls into a per-call-site allocation report.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod logging;

mod prover_message_transport_prod;
mod prover_tree_syncer_prod;

mod release_check;

mod util;

mod blossomsub_consensus_publisher;

mod dht_node;

mod worker_node;

mod diagnostic;

mod master_node;

mod mem_stats;

/// Quilibrium Node — Rust implementation
#[derive(Parser, Debug)]
#[command(name = "quil-node", version = quil_config::VERSION_STRING, about)]
struct Args {
    /// Configuration directory path
    #[arg(short, long, default_value = ".config")]
    config: PathBuf,

    /// CPU core affinity (0 = master, >0 = worker)
    #[arg(long, default_value_t = 0)]
    core: u32,

    /// Parent process PID (for worker-to-master communication)
    #[arg(long, default_value_t = 0)]
    parent_process: u32,

    /// Run as DHT bootstrap peer only
    #[arg(long)]
    dht_only: bool,

    /// Network ID (0 = mainnet, 1 = primary testnet)
    #[arg(long, default_value_t = 0)]
    network: u8,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Archive mode
    #[arg(long)]
    archive: bool,

    /// Import a Pebble database export file into RocksDB
    #[arg(long)]
    import_db: Option<PathBuf>,

    /// Print the peer ID to stdout and exit
    #[arg(long)]
    peer_id: bool,

    /// Print node info (version, prover address, frame) and exit
    #[arg(long)]
    node_info: bool,

    /// Print peer info and exit
    #[arg(long)]
    peer_info: bool,

    /// Print prometheus metrics and exit
    #[arg(long)]
    metrics: bool,

    /// Filter metrics output by substring match
    #[arg(long)]
    metrics_filter: Option<String>,

    /// Write CPU profile to file
    #[arg(long)]
    cpuprofile: Option<PathBuf>,

    /// Write memory profile to file after 20 minutes
    #[arg(long)]
    memprofile: Option<PathBuf>,

    /// Enable prometheus metrics server on specified address (e.g. localhost:8080)
    #[arg(long)]
    prometheus_server: Option<String>,

    /// Enable or disable signature validation (default true, override
    /// with `QUILIBRIUM_SIGNATURE_CHECK=false` or
    /// `--signature-check=false`). Both flag and env must be set with
    /// an explicit value — bare `--signature-check` is not accepted.
    #[arg(
        long,
        env = "QUILIBRIUM_SIGNATURE_CHECK",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    signature_check: bool,

    /// Per-component log levels, comma-separated (e.g. "bootstrap=debug,peer_monitor=warn")
    #[arg(long)]
    log_filter: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();

    // Load configuration first so logger paths / filters come from it.
    let config = quil_config::load_config(&args.config)?;

    // Initialize logging in tab-separated console format:
    //   ts \t level \t target:line \t msg \t {fields}.
    // Per-core file separation (`master.log` / `worker-N.log`) plus
    // size/age retention (maxAge, maxBackups).
    //
    // `_log_guard` must be held alive until shutdown so the async
    // file appender gets a chance to flush; we bind it with a `_`
    // prefix and let it drop at main's end.
    let _log_guard = logging::init_logging(
        &config.logger,
        args.core,
        args.debug,
        args.log_filter.as_deref(),
    );

    // Initialize crypto subsystem
    quil_crypto::init();

    // ---------------------------------------------------------------
    // Diagnostic flags that print info and exit
    // ---------------------------------------------------------------
    let diag_flags = diagnostic::DiagnosticFlags {
        peer_id: args.peer_id,
        node_info: args.node_info,
        peer_info: args.peer_info,
        metrics: args.metrics,
        metrics_filter: args.metrics_filter.clone(),
        network: args.network,
    };
    if diagnostic::handle_diagnostic_flags(&diag_flags, &config)? {
        return Ok(ExitCode::SUCCESS);
    }

    // Install a Prometheus recorder. If `--prometheus-server` is given,
    // ALSO start an HTTP listener; otherwise the recorder is installed
    // silently so `NodeService::get_metrics` can render a snapshot on
    // demand from the same recorder.
    let metrics_handle: Option<metrics_exporter_prometheus::PrometheusHandle> = {
        let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
        let builder = if let Some(ref addr) = args.prometheus_server {
            match addr.parse::<std::net::SocketAddr>() {
                Ok(sock) => {
                    info!(addr = %sock, "prometheus HTTP listener enabled");
                    builder.with_http_listener(sock)
                }
                Err(e) => {
                    warn!(addr = %addr, error = %e, "invalid prometheus address, no HTTP listener");
                    builder
                }
            }
        } else {
            builder
        };
        match builder.install_recorder() {
            Ok(h) => Some(h),
            Err(e) => {
                warn!(error = %e, "prometheus recorder install failed");
                None
            }
        }
    };

    // Register all engine metric descriptors once, AFTER the recorder
    // is installed so `describe_*` calls attach to it.
    quil_engine::metrics::register_engine_metrics();

    // Build the supervisor that owns every long-running task in the
    // binary. Each spawned task is joined, so panics or task errors
    // propagate up to `sup.run()` instead of being silently swallowed.
    let mut sup = Supervisor::<anyhow::Error>::new()
        .with_shutdown_timeout(Duration::from_secs(10));

    // Metrics upkeep: the recorder's histogram buckets need periodic
    // run_upkeep() to evict old samples. Missing this results in
    // ever-growing memory for histograms.
    if let Some(h) = metrics_handle.as_ref().cloned() {
        sup.run_until_cancelled("metrics-upkeep", move |_token| async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                h.run_upkeep();
            }
        });
    }

    // CPU profiling (placeholder — requires pprof crate)
    if let Some(ref path) = args.cpuprofile {
        info!(path = %path.display(), "CPU profiling requested (requires pprof crate integration)");
    }

    // Memory profiling (placeholder — requires jemalloc-ctl or similar)
    if let Some(ref path) = args.memprofile {
        info!(path = %path.display(), "memory profiling requested (will write after 20 minutes)");
    }

    info!(
        version = quil_config::VERSION_STRING,
        core = args.core,
        network = args.network,
        "starting quil-node"
    );

    info!(config_dir = %args.config.display(), "loaded configuration");

    // Verify the binary against `.dgst` + per-signatory `.dgst.sig.N`
    // using hardcoded Ed448 public keys. Fails closed; skipped on
    // Windows and when --signature-check=false.
    if args.signature_check {
        if cfg!(target_os = "windows") {
            info!("signature check not available for windows yet, skipping");
        } else {
            match std::env::current_exe() {
                Ok(exe) => match release_check::verify_release_signatures(&exe) {
                    Ok(count) => info!(
                        valid_signatures = count,
                        total_signatories = release_check::SIGNATORIES.len(),
                        "signature check passed"
                    ),
                    Err(e) => {
                        error!(
                            error = %e,
                            "signature check failed — are you running this from source? \
                             (use --signature-check=false or QUILIBRIUM_SIGNATURE_CHECK=false)"
                        );
                        return Err(anyhow::anyhow!("signature check failed: {}", e));
                    }
                },
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "could not determine executable path for signature check: {}",
                        e
                    ));
                }
            }
        }
    } else {
        info!("signature check disabled, skipping");
    }

    // Handle --import-db before anything else.
    // Supports file path or "-" for stdin (pipe from Go exporter).
    // Pipe mode uses zero extra disk:
    //   ./node --export-db - | ./quil-node --import-db -
    if let Some(ref import_path) = args.import_db {
        diagnostic::run_import(import_path, &config)?;
        return Ok(ExitCode::SUCCESS);
    }

    // Hand off to the chosen node mode. It owns `sup` for its lifetime,
    // registers its subsystems, runs the supervisor, and returns the
    // `ShutdownReason` for `main` to translate into an exit code.
    let reason = match (args.core, args.dht_only) {
        (_, true) => {
            info!("starting in DHT-only mode");
            dht_node::start(sup, &config).await?
        }
        (0, false) => {
            // Archive mode comes from --archive OR engine.archiveMode.
            let archive_mode = args.archive || config.engine.archive_mode;
            info!(archive = archive_mode, "starting as master node");
            master_node::start(
                sup,
                &config,
                &args.config,
                archive_mode,
                args.network,
                metrics_handle.clone(),
            )
            .await?
        }
        (core_id, false) => {
            info!(core_id, "starting as worker node");
            worker_node::start(sup, &config, core_id, args.parent_process).await?
        }
    };

    match reason {
        // POSIX convention: SIGINT-driven exit is 128 + SIGINT(2) = 130.
        ShutdownReason::CtrlC => {
            info!("shut down via ctrl-c");
            Ok(ExitCode::from(130))
        }
        ShutdownReason::TaskExited(name) => {
            error!(task = %name, "supervised task exited unexpectedly");
            Err(anyhow::anyhow!(
                "supervised task {name:?} exited unexpectedly"
            ))
        }
        ShutdownReason::TaskError(name, e) => {
            error!(task = %name, error = %e, "supervised task failed");
            Err(e.context(format!("supervised task {name:?} failed")))
        }
        ShutdownReason::JoinError(name, e) => {
            error!(task = %name, error = %e, "supervised task join failed");
            Err(anyhow::Error::from(e)
                .context(format!("supervised task {name:?} join failed")))
        }
    }
}

