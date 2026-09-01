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

mod forest_sync;
mod prover_message_transport_prod;
mod prover_tree_syncer_prod;

mod release_check;

mod util;

mod direct_global_consensus_publisher;
mod cw_consensus_bridge;

mod dht_node;

mod worker_node;

mod diagnostic;
mod check_bootstrap;
mod check_submit;
mod fork_ladder;
mod verify_migration;
mod forest_migration;
mod dry_run_reset;
mod dump_shard_state;
mod reclaim_legacy_forest;
mod test_prover_sync;
mod query_shards;
mod unified_consolidation;
mod legacy_migration;
mod coin_rescale;
mod coin_receipt_repair;

mod master_node;

mod mem_stats;

mod metrics_tui;
mod rpc_metrics;

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

    /// Convert the node's current KZG state DB (config.db.path) into a fresh
    /// JMT forest DB at the given destination path, then exit. The forest is
    /// the Phase-3 hash-Merkle state tree; the destination MUST be a new/empty
    /// path (its key-space collides with the source DB's).
    #[arg(long)]
    migrate_db: Option<PathBuf>,

    /// OFFLINE dry-run of the unified split reset against a snapshot DB (the given
    /// path, or config.db.path). Reports the BEFORE grid + prover state, runs the
    /// flag-day reset (QUIL grid → genesis + prover-tree wipe/rebuild), reports the
    /// AFTER state, then exits. Destructive on the DB — point it at a COPY of a
    /// mainnet snapshot. Never connects to the network.
    #[arg(long)]
    dry_run_reset: Option<PathBuf>,

    /// The simulated cutover frame for `--dry-run-reset` (0 ⇒ head + 1).
    #[arg(long, default_value_t = 0)]
    dry_run_reset_frame: u64,

    /// OFFLINE READ-ONLY dump of the QUIL shard grid, prover allocations (by
    /// confirmation_filter), pending changes, and reset markers (the given path, or
    /// config.db.path), then exit. NEVER writes — safe to run on a shut-down archive
    /// while the network keeps running on the others.
    #[arg(long)]
    dump_shard_state: Option<PathBuf>,

    /// OFFLINE one-time reclaim of the orphaned pre-cutover QUIL forest trees (the
    /// per-prefix byte-suffix trees the unified-tree consolidation copied from but
    /// never deleted). Streaming range-delete + compact; asserts the unified app
    /// root is unchanged (no consensus effect). Destructive — run with the node
    /// shut down. Empty path uses config.db.path. Idempotent (marker-gated).
    #[arg(long)]
    reclaim_legacy_forest: Option<PathBuf>,

    /// LIVE check: connect to an archive over :8340 Falcon-mTLS, pull its head
    /// global frame, and run the root-addressed prover-tree sync against it into a
    /// fresh in-memory forest — verifying the synced root == the frame's
    /// prover_tree_commitment. Pass `ip:8340` for a specific archive, or the flag
    /// alone to use engine.archiveEndpoints / the embedded genesis archives.
    /// Read-only against the archive; then exit.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    test_prover_sync: Option<String>,

    /// LIVE GetAppShards query of the QUIL grid from an archive over :8340 (remote
    /// equivalent of --dump-shard-state's grid view: per-shard prefix, size,
    /// data_shards, materialized/latest frame). Pass `ip:8340`, or the flag alone
    /// for engine.archiveEndpoints / embedded genesis archives. Read-only; then exit.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    query_shards: Option<String>,

    /// Archive-only: convert pre-2.1 verenc coins in the DB (config.db.path, or
    /// the given path) into compact transparent public token entries and refresh
    /// the lattice shadow-accumulator root, then exit. Deterministic and
    /// consensus-safe; run once at the flag frame. Empty path uses config.db.path.
    #[arg(long)]
    migrate_legacy: Option<PathBuf>,

    /// Archive-only CORRECTIVE pass for a DB migrated by the OLD byte-shifted
    /// decode (every transparent coin ×256): in place, `÷256` each coin amount
    /// and re-key to its corrected content address, then rebuild the forest +
    /// receipt. No verenc re-decrypt, no backup. Bails loudly if the data isn't
    /// uniformly inflated. Empty path uses config.db.path. Run once.
    #[arg(long)]
    fix_coin_scale: Option<PathBuf>,

    /// Archive-only: recompute the coin-conservation receipt from the migrated
    /// TRANSPARENT coin set and rewrite it, then exit. Use when a legacy
    /// migration was STOPPED AND RESTARTED: the receipt then records only the
    /// final run's slice (the state is complete, but `--verify-db`'s conservation
    /// check would flag the undercount). Read-mostly — only the receipt vertex is
    /// written; refuses to shrink a receipt. Empty path uses config.db.path.
    #[arg(long)]
    repair_receipt: Option<PathBuf>,

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

    /// Dump a ladder of stored global-frame fingerprints (frame, rank,
    /// poseidon(output)) at back-off offsets from the head, then exit.
    /// Run on every archive and diff the outputs to find where their chains
    /// forked; the deepest frame all still share is the re-bootstrap
    /// checkpoint. Empty path uses config.db.path. Read-only.
    #[arg(long)]
    fork_ladder: Option<PathBuf>,

    /// Optional comma-separated back-off offsets for `--fork-ladder`
    /// (e.g. `0,1000,30000,31000,32000`). Default is a wide ladder.
    #[arg(long)]
    fork_ladder_offsets: Option<String>,

    /// Print the peer ID to stdout and exit
    #[arg(long)]
    peer_id: bool,

    /// Print node info (version, prover address, frame) and exit
    #[arg(long)]
    node_info: bool,

    /// Ensure the node's identity keys exist (Ed448 seniority-root peer key +
    /// the unified Falcon-512 `q-prover-key`), then print machine-readable
    /// `PEER_ID=<base58>` (derived from the FALCON network identity),
    /// `ED448_PEER_ID=<base58>` (the seniority-root id), `BLS_PUBKEY`,
    /// `CONSENSUS_PUBKEY`, and `PROVER_ADDRESS` lines and exit. Used by
    /// `scripts/localnet.sh` to assemble a genesis seed + peer multiaddrs.
    #[arg(long)]
    print_identity: bool,

    /// Ensure all standard keys exist in `keys.yml` (creating any missing —
    /// including the unified Falcon-512 `q-prover-key`, which is BOTH the prover
    /// and the commonware-simplex consensus committee identity), then print
    /// `CONSENSUS_PUBKEY=<hex>` and exit. Does NOT open the state DB
    /// or start the node — a lightweight keys-only mode (mirrors Go's
    /// `--generate-keys`). Safe to run against a stopped node's config.
    #[arg(long)]
    generate_keys: bool,

    /// Print peer info and exit
    #[arg(long)]
    peer_info: bool,

    /// Fetch prometheus metrics from the RUNNING node (over its gRPC
    /// GetMetrics on listenGrpcMultiaddr), print, and exit
    #[arg(long)]
    metrics: bool,

    /// Filter metrics output by substring match
    #[arg(long)]
    metrics_filter: Option<String>,

    /// Live metrics dashboard: attach to the RUNNING node's gRPC and watch
    /// every metric (p2p connections, blossomsub mesh/grafts/prunes, RPC
    /// requests, consensus) with rates, sections, and filtering. Keys:
    /// `/` filter, Tab section, s sort, p pause, q quit.
    #[arg(long)]
    metrics_tui: bool,

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
        network: args.network,
    };
    if diagnostic::handle_diagnostic_flags(&diag_flags, &config)? {
        return Ok(ExitCode::SUCCESS);
    }

    // `--metrics` (Go parity): dial the RUNNING node's gRPC GetMetrics and
    // print the full prometheus snapshot (optionally `--metrics-filter`).
    if args.metrics {
        return match diagnostic::print_metrics_from_node(
            &config,
            args.metrics_filter.as_deref(),
        )
        .await
        {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    // `--metrics-tui`: live dashboard attached to the running node's gRPC.
    if args.metrics_tui {
        return match metrics_tui::run_metrics_tui(&config, args.metrics_filter.clone()).await {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
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
            Box::new(quil_crypto::FalconKeyConstructor),
        )?;
        fkm.set_peer_priv_key_hex(&cfg.p2p.peer_priv_key);
        fkm.ensure_standard_keys()?;
        use quil_keys::KeyManager as _;
        let bls_pubkey =
            fkm.get_public_key(quil_types::crypto::KeyType::Falcon512)?;
        // The consensus committee identity IS the proving key: prover and
        // commonware-simplex committee roles share one Falcon-512 key. Emit it
        // under CONSENSUS_PUBKEY (equal to BLS_PUBKEY) so genesis tooling can
        // assemble the committee `Set<FalconPublicKey>` from the same value.
        let consensus_pubkey = bls_pubkey.clone();
        // The on-chain prover address = poseidon(prover pubkey). Emit it so
        // archive keys/addresses can be hard-coded into genesis / prover tries.
        let prover_address =
            quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(&bls_pubkey)?;
        // The libp2p NETWORK peer-id is now derived from the Falcon q-prover-key
        // (== bls_pubkey), NOT the Ed448 peer key. The Ed448-derived id is still
        // emitted (as ED448_PEER_ID) since it's the seniority-root identity.
        let falcon_peer_id = quil_p2p::peer_id_from_falcon_pubkey(&bls_pubkey);
        println!("PEER_ID={}", bs58::encode(&falcon_peer_id).into_string());
        println!("ED448_PEER_ID={}", bs58::encode(&peer_id).into_string());
        println!("BLS_PUBKEY={}", hex::encode(&bls_pubkey));
        println!("CONSENSUS_PUBKEY={}", hex::encode(&consensus_pubkey));
        println!("PROVER_ADDRESS={}", hex::encode(prover_address));
        return Ok(ExitCode::SUCCESS);
    }

    // `--generate-keys`: ensure all standard keys exist in keys.yml, print the
    // consensus pubkey (which is the Falcon-512 proving key — prover and
    // committee roles share one key), and exit — WITHOUT opening the state DB
    // or starting the node. Used to bootstrap a node's consensus identity for a
    // committee list.
    if args.generate_keys {
        let keys_path = if config.key.key_store_file.path.is_empty() {
            args.config.join("keys.yml")
        } else {
            PathBuf::from(&config.key.key_store_file.path)
        };
        let proving_key_id = if config.engine.proving_key_id.is_empty() {
            "default-proving-key".to_string()
        } else {
            config.engine.proving_key_id.clone()
        };
        let fkm = quil_keys::FileKeyManager::new(
            keys_path,
            &config.key.key_store_file.encryption_key,
            proving_key_id,
            Box::new(quil_crypto::FalconKeyConstructor),
        )?;
        fkm.ensure_standard_keys()?;
        use quil_keys::KeyManager as _;
        let consensus_pubkey = fkm.get_public_key(quil_types::crypto::KeyType::Falcon512)?;
        println!("CONSENSUS_PUBKEY={}", hex::encode(&consensus_pubkey));
        return Ok(ExitCode::SUCCESS);
    }

    // Install a Prometheus recorder. If `--prometheus-server` is given, a
    // unified HTTP `/metrics` endpoint is served on that address (spawned
    // below, once the supervisor exists); otherwise the recorder is
    // installed silently so `NodeService::get_metrics` can render a
    // snapshot on demand from the same recorder.
    //
    // We deliberately do NOT use the exporter's built-in
    // `with_http_listener`: it serves only the `metrics`-facade recorder,
    // while our exposition also appends the p2p `prometheus-client`
    // families (blossomsub_* / libp2p_*) via
    // `rpc_metrics::extra_metrics_render` — one endpoint, both stacks.
    let prometheus_http_addr: Option<std::net::SocketAddr> =
        args.prometheus_server.as_ref().and_then(|addr| {
            match addr.parse::<std::net::SocketAddr>() {
                Ok(sock) => Some(sock),
                Err(e) => {
                    warn!(addr = %addr, error = %e, "invalid prometheus address, no HTTP listener");
                    None
                }
            }
        });
    let metrics_handle: Option<metrics_exporter_prometheus::PrometheusHandle> = {
        match metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder() {
            Ok(h) => Some(h),
            Err(e) => {
                warn!(error = %e, "prometheus recorder install failed");
                None
            }
        }
    };

    // Preflight: Falcon (KeyType=5) is the network peer identity. Prove this
    // binary can round-trip a Falcon key through the peer-decode path BEFORE any
    // handshake, so a falcon-incapable build (stale artifact / mis-provisioned
    // feature / fn-dsa platform issue) fails here with one clear message instead
    // of a storm of "cargo feature `falcon` is not enabled" per-peer errors.
    match quil_p2p::falcon_identity_self_check() {
        Ok(()) => info!("Falcon (KeyType=5) network identity: enabled"),
        Err(e) => {
            error!("{e}");
            return Err(anyhow::anyhow!(e));
        }
    }

    // Register all engine metric descriptors once, AFTER the recorder
    // is installed so `describe_*` calls attach to it.
    quil_engine::metrics::register_engine_metrics();
    quil_execution::metrics::register_execution_metrics();
    rpc_metrics::register_rpc_metrics();

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

    // Unified prometheus HTTP endpoint (`--prometheus-server <addr>`, Go
    // parity with `-prometheus-server`): serves the facade recorder's
    // snapshot plus the p2p prometheus-client families on every GET. A
    // deliberately minimal HTTP/1.1 responder (Connection: close) — scrape
    // traffic doesn't justify a web framework dependency.
    if let (Some(sock), Some(h)) = (prometheus_http_addr, metrics_handle.as_ref().cloned()) {
        sup.run_until_cancelled("prometheus-http", move |_token| async move {
            let listener = match tokio::net::TcpListener::bind(sock).await {
                Ok(l) => {
                    info!(addr = %sock, "prometheus HTTP listener enabled");
                    l
                }
                Err(e) => {
                    warn!(addr = %sock, error = %e, "prometheus HTTP bind failed");
                    return Ok(());
                }
            };
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let h = h.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    // Drain the request head (we answer every GET the same
                    // way); bounded read with a short deadline so a stalled
                    // client can't pin the task.
                    let mut buf = [0u8; 2048];
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        stream.read(&mut buf),
                    )
                    .await;
                    let mut body = h.render();
                    let extra = rpc_metrics::extra_metrics_render();
                    if !extra.is_empty() {
                        if !body.ends_with('\n') {
                            body.push('\n');
                        }
                        body.push_str(&extra);
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
    }

    // CPU profiling (placeholder — requires pprof crate)
    if let Some(ref path) = args.cpuprofile {
        info!(path = %path.display(), "CPU profiling requested (requires pprof crate integration)");
    }

    // On-demand jemalloc heap-profile dump via SIGUSR1. Heap profiling is
    // compiled in (tikv-jemallocator `profiling` feature); it only produces
    // output when the process was started with `MALLOC_CONF=prof:true`
    // (+ `prof_prefix:<path>`). This is the remote-box workflow: the operator
    // runs `kill -USR1 <pid>` once, watches RSS climb, runs it again, then
    // diffs the two `.heap` files with `jeprof --base=` to name the leaking
    // allocation stacks. Armed unconditionally on unix so no restart/flag is
    // needed to capture a dump; a no-prof build just logs the enabling hint.
    #[cfg(unix)]
    {
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sig = match signal(SignalKind::user_defined1()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "SIGUSR1 heap-dump handler unavailable");
                    return;
                }
            };
            info!(
                "SIGUSR1 heap-profile handler armed — `kill -USR1 <pid>` dumps a jemalloc \
                 profile (requires MALLOC_CONF=prof:true,prof_prefix:/tmp/jeprof at startup)"
            );
            while sig.recv().await.is_some() {
                match crate::mem_stats::dump_heap_profile() {
                    Ok(()) => info!(
                        "jemalloc heap profile dumped to the MALLOC_CONF prof_prefix path \
                         (<prefix>.<pid>.<seq>.heap)"
                    ),
                    Err(e) => warn!(error = %e, "heap profile dump failed"),
                }
            }
        });
    }
    if let Some(ref path) = args.memprofile {
        info!(
            path = %path.display(),
            "note: --memprofile is superseded by the SIGUSR1 heap dump (MALLOC_CONF=prof:true)"
        );
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

    if let Some(ref dest_path) = args.migrate_db {
        return match forest_migration::run_migrate_db(dest_path, &config) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref snapshot_path) = args.dry_run_reset {
        return match dry_run_reset::run_dry_run_reset(
            snapshot_path,
            &config,
            args.network,
            args.dry_run_reset_frame,
        ) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref dump_path) = args.dump_shard_state {
        return match dump_shard_state::run_dump_shard_state(dump_path, &config, args.network) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref reclaim_path) = args.reclaim_legacy_forest {
        return match reclaim_legacy_forest::run_reclaim_legacy_forest(
            reclaim_path,
            &config,
            args.network,
        ) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref archive_addr) = args.test_prover_sync {
        return match test_prover_sync::run_test_prover_sync(
            archive_addr,
            &config,
            &args.config,
            args.network,
        )
        .await
        {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref archive_addr) = args.query_shards {
        return match query_shards::run_query_shards(
            archive_addr,
            &config,
            &args.config,
            args.network,
        )
        .await
        {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref dest_path) = args.migrate_legacy {
        return match legacy_migration::run_migrate_legacy(dest_path, &config) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref target_path) = args.fix_coin_scale {
        return match coin_rescale::run_fix_coin_scale(target_path, &config) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    if let Some(ref target_path) = args.repair_receipt {
        return match coin_receipt_repair::run_repair_receipt(target_path, &config) {
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

    if let Some(ref db_path) = args.fork_ladder {
        return match fork_ladder::run_fork_ladder(
            db_path,
            &config,
            args.fork_ladder_offsets.as_deref(),
        ) {
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

