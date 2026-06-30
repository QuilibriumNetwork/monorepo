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
mod direct_global_consensus_publisher;

mod dht_node;

mod worker_node;

mod diagnostic;
mod check_bootstrap;
mod check_submit;
mod verify_migration;

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

    /// Verify a migrated RocksDB is valid/accepted by the node's loaders
    /// and validators (trie root, frame, QC/TC, certified state), then
    /// exit. Empty path uses config.db.path.
    #[arg(long)]
    verify_db: Option<PathBuf>,

    /// Diagnose the consensus bootstrap root: replay the latest-QC
    /// candidate-frame lookup and report whether the forks-root identity
    /// (Poseidon of the frame output) matches the QC selector the leader
    /// resolves its parent by. Empty path uses config.db.path. Read-only.
    #[arg(long)]
    check_bootstrap: Option<PathBuf>,

    /// Diagnose prover-message submission to an archive. Connects to the
    /// given `host:8340` over Ed448 mTLS and submits a no-op ProverJoin
    /// bundle, reporting where the path breaks (handshake vs RPC). Use a
    /// known archive, e.g. `--check-submit 192.69.222.130:8340`.
    #[arg(long)]
    check_submit: Option<String>,

    /// Print the peer ID to stdout and exit
    #[arg(long)]
    peer_id: bool,

    /// Print node info (version, prover address, frame) and exit
    #[arg(long)]
    node_info: bool,

    /// Ensure the node's identity keys exist (generating + persisting an Ed448
    /// peer key and a BLS prover key if missing), then print machine-readable
    /// `PEER_ID=<base58>` and `BLS_PUBKEY=<full-hex>` lines and exit. Used by
    /// `scripts/localnet.sh` to assemble a genesis seed + peer multiaddrs.
    #[arg(long)]
    print_identity: bool,

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

    // Raise RLIMIT_NOFILE soft → hard. The Go runtime did this
    // automatically (Go ≥1.19), so the Go node never saw EMFILE; Rust
    // does not, leaving the default soft limit (often 1024) in place.
    // RocksDB alone is configured for up to 1000 open files, before
    // counting p2p connections and gRPC — exhaustion kills the node
    // mid-dial with "too many open files".
    raise_fd_limit();

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

    // `--print-identity`: ensure keys exist, print them machine-readably, exit.
    if args.print_identity {
        // Ensure a stable Ed448 peer key (generate + persist if missing).
        let mut cfg = config.clone();
        if cfg.p2p.peer_priv_key.is_empty() {
            cfg.p2p.peer_priv_key = quil_p2p::ed448_identity::Ed448Identity::generate()
                .map_err(|e| anyhow::anyhow!("generate Ed448 peer key: {e}"))?
                .to_config_hex();
            quil_config::save_config(&args.config, &cfg)?;
        }
        // Derive the libp2p peer ID from the Ed448 key.
        let pk_bytes = hex::decode(&cfg.p2p.peer_priv_key).unwrap_or_default();
        let mut seed = [0u8; 57];
        seed.copy_from_slice(&pk_bytes[..57]);
        let ed_pub = quil_p2p::ed448_identity::derive_public_key(&seed);
        let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&ed_pub);
        // Ensure the BLS prover key (auto-created if missing), read full pubkey.
        let keys_path = if cfg.key.key_store_file.path.is_empty() {
            args.config.join("keys.yml")
        } else {
            PathBuf::from(&cfg.key.key_store_file.path)
        };
        let proving_key_id = if cfg.engine.proving_key_id.is_empty() {
            "default-proving-key".to_string()
        } else {
            cfg.engine.proving_key_id.clone()
        };
        let fkm = quil_keys::FileKeyManager::new(
            keys_path,
            &cfg.key.key_store_file.encryption_key,
            proving_key_id,
            Box::new(quil_crypto::Bls48581KeyConstructor),
        )?;
        fkm.set_peer_priv_key_hex(&cfg.p2p.peer_priv_key);
        fkm.ensure_standard_keys()?;
        use quil_keys::KeyManager as _;
        let bls_pubkey =
            fkm.get_public_key(quil_types::crypto::KeyType::Bls48581G1)?;
        println!("PEER_ID={}", bs58::encode(&peer_id).into_string());
        println!("BLS_PUBKEY={}", hex::encode(&bls_pubkey));
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

    if let Some(ref verify_path) = args.verify_db {
        return match verify_migration::run_verify_db(verify_path, &config) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref check_path) = args.check_bootstrap {
        return match check_bootstrap::run_check_bootstrap(check_path, &config) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref addr) = args.check_submit {
        return match check_submit::run_check_submit(addr, &config).await {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
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

    // The supervisor has returned, so shutdown is underway — but not
    // everything it kicked off is the supervisor's to stop. The consensus
    // event loop and materializer run as DETACHED tasks, and the
    // peer-facing :8340 gRPC server runs on its own dedicated runtime;
    // none are cancelled when `sup.run()` returns. Worse, tonic drives a
    // GRACEFUL shutdown of :8340 that waits for in-flight requests to
    // finish, and hypersync sessions are long-lived streams — a single
    // one still in flight wedges teardown indefinitely (observed in the
    // field: a node logged ctrl-c, then kept materializing frames and
    // serving sync for an hour). Arm a hard-deadline watchdog on a plain
    // OS thread (independent of any runtime): if the process can't exit
    // under its own power within the grace window, force it. This is
    // safe — RocksDB is crash-consistent via its WAL and the master node
    // already released its snapshots before returning, so a forced exit
    // costs only a WAL replay on restart.
    {
        let code: i32 = match &reason {
            // POSIX: signal-driven exit is 128 + signal number.
            ShutdownReason::CtrlC => 130,
            ShutdownReason::Terminated => 143,
            _ => 1,
        };
        const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(20);
        let _ = std::thread::Builder::new()
            .name("shutdown-watchdog".into())
            .spawn(move || {
                std::thread::sleep(SHUTDOWN_GRACE);
                // Logging may already be torn down; go straight to stderr.
                eprintln!(
                    "shutdown watchdog: graceful teardown exceeded {}s — forcing exit({})",
                    SHUTDOWN_GRACE.as_secs(),
                    code,
                );
                std::process::exit(code);
            });
    }

    let result = match reason {
        // POSIX convention: signal-driven exit is 128 + signal number.
        ShutdownReason::CtrlC => {
            info!("shut down via ctrl-c");
            Ok(ExitCode::from(130))
        }
        ShutdownReason::Terminated => {
            info!("shut down via SIGTERM");
            Ok(ExitCode::from(143))
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
    };

    // Drop the file appender guards, blocking until their writer threads
    // drain. Without this the error! lines above — the only record of WHY
    // the node died — race process exit and routinely lose.
    logging::shutdown_logging();

    result
}

/// Raise the soft `RLIMIT_NOFILE` to the hard limit. No-op on
/// non-unix. Failure is non-fatal — the node may still run fine under
/// a low limit on small networks — but a low effective limit gets a
/// loud warning so EMFILE deaths aren't a mystery.
fn raise_fd_limit() {
    #[cfg(unix)]
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let original_soft = lim.rlim_cur;
        let target = lim.rlim_max;
        // macOS reports RLIM_INFINITY as the hard limit but rejects
        // anything above `kern.maxfilesperproc`; OPEN_MAX (10240) is
        // accepted everywhere. The walk-down below covers hosts where
        // even that is too high.
        #[cfg(target_os = "macos")]
        let target = target.min(10_240);
        let mut target = target;
        while target > lim.rlim_cur {
            let new = libc::rlimit {
                rlim_cur: target,
                rlim_max: lim.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &new) == 0 {
                lim.rlim_cur = target;
                break;
            }
            target /= 2;
        }
        if lim.rlim_cur > original_soft {
            info!(
                soft = lim.rlim_cur,
                previous = original_soft,
                "raised RLIMIT_NOFILE soft limit to hard limit"
            );
        }
        // RocksDB is configured for up to 1000 open files and the p2p
        // swarm allows 512 connections — anything under ~4096 is asking
        // for an EMFILE death under load.
        if lim.rlim_cur < 4096 {
            warn!(
                soft = lim.rlim_cur,
                hard = lim.rlim_max,
                "open-file limit is low; raise the hard limit \
                 (systemd: LimitNOFILE=, docker: --ulimit nofile=, \
                 shell: ulimit -n) or the node may die with \
                 'too many open files'"
            );
        }
    }
}

