use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

// Import KeyManager trait for get_public_key/get_signer methods
use quil_keys::KeyManager as _;

mod logging;

mod prover_message_transport_prod;

mod release_check;

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
async fn main() -> anyhow::Result<()> {
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

    if args.peer_id {
        // libp2p peer ID — multihash of the Ed448 identity public key,
        // base58-encoded. Matches what the prover-manage TUI and the
        // NodeService RPC report. (The Poseidon-of-BLS-pubkey is a
        // separate "prover address" identifier; see --node-info.)
        let pk_bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
        if pk_bytes.len() < 57 {
            return Err(anyhow::anyhow!(
                "config.p2p.peer_priv_key is missing or shorter than 57 bytes",
            ));
        }
        let mut seed = [0u8; 57];
        seed.copy_from_slice(&pk_bytes[..57]);
        let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
        let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pubkey);
        println!("{}", bs58::encode(&peer_id).into_string());
        return Ok(());
    }

    if args.node_info {
        let bls_ctor = quil_crypto::Bls48581KeyConstructor;
        let keys_path = config.key.key_store_file.path.clone();
        let proving_key_id = if config.engine.proving_key_id.is_empty() {
            "q-prover-key".to_string()
        } else {
            config.engine.proving_key_id.clone()
        };
        let fkm = quil_keys::FileKeyManager::new(
            PathBuf::from(&keys_path),
            &config.key.key_store_file.encryption_key,
            proving_key_id,
            Box::new(bls_ctor),
        )?;
        let bls_pubkey = fkm.get_public_key(quil_types::crypto::KeyType::Bls48581G1)?;
        let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;

        // Peer ID — base58-encoded libp2p multihash derived from the
        // Ed448 identity key. This is what shows up in the prover-manage
        // TUI and the NodeService GetNodeInfo RPC; the BLS-derived
        // prover address is a separate identifier.
        let peer_id_b58 = {
            let pk_bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
            if pk_bytes.len() >= 57 {
                let mut seed = [0u8; 57];
                seed.copy_from_slice(&pk_bytes[..57]);
                let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
                let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pubkey);
                bs58::encode(&peer_id).into_string()
            } else {
                String::from("<no ed448 peer key configured>")
            }
        };

        let db_path = if config.db.path.is_empty() {
            PathBuf::from(".config/store")
        } else {
            PathBuf::from(&config.db.path)
        };
        // Read the latest committed frame number even when the running
        // node holds the primary lock by opening as a read-only
        // secondary. `try_catch_up_with_primary` pulls in everything
        // the primary has flushed since it started so we don't return
        // a stale-by-hours value.
        let frame_number = if db_path.exists() {
            let secondary_dir = std::env::temp_dir()
                .join(format!("quil-node-info-secondary-{}", std::process::id()));
            std::fs::create_dir_all(&secondary_dir).ok();
            let result = quil_store::RocksDb::open_as_secondary(&db_path, &secondary_dir)
                .ok()
                .and_then(|d| {
                    let _ = d.inner().try_catch_up_with_primary();
                    let cs = quil_store::RocksClockStore::new(d.inner());
                    cs.get_latest_global_frame()
                        .ok()
                        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
                })
                .unwrap_or(0);
            // Cleanup the secondary scratch dir; ignore errors.
            std::fs::remove_dir_all(&secondary_dir).ok();
            result
        } else {
            0
        };

        println!("Version: {}", quil_config::VERSION_STRING);
        println!("Peer ID: {}", peer_id_b58);
        println!("Prover Address: {}", hex::encode(&prover_address));
        println!("BLS Public Key: {}...{}", hex::encode(&bls_pubkey[..8]), hex::encode(&bls_pubkey[bls_pubkey.len()-8..]));
        println!("Frame Number: {}", frame_number);
        println!("Network: {}", args.network);
        return Ok(());
    }

    if args.peer_info {
        let peer_id_b58 = {
            let pk_bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
            if pk_bytes.len() >= 57 {
                let mut seed = [0u8; 57];
                seed.copy_from_slice(&pk_bytes[..57]);
                let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
                let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pubkey);
                bs58::encode(&peer_id).into_string()
            } else {
                String::from("<no ed448 peer key configured>")
            }
        };
        let bls_ctor = quil_crypto::Bls48581KeyConstructor;
        let keys_path = config.key.key_store_file.path.clone();
        let proving_key_id = if config.engine.proving_key_id.is_empty() {
            "q-prover-key".to_string()
        } else {
            config.engine.proving_key_id.clone()
        };
        let fkm = quil_keys::FileKeyManager::new(
            PathBuf::from(&keys_path),
            &config.key.key_store_file.encryption_key,
            proving_key_id,
            Box::new(bls_ctor),
        )?;
        let bls_pubkey = fkm.get_public_key(quil_types::crypto::KeyType::Bls48581G1)?;
        println!("Peer ID: {}", peer_id_b58);
        println!("BLS Public Key Length: {} bytes", bls_pubkey.len());
        println!("Listen Multiaddr: {}", config.p2p.listen_multiaddr);
        return Ok(());
    }

    if args.metrics {
        // Collect and print all registered metrics
        // The metrics crate doesn't have a built-in dump; print known counters
        println!("# Quilibrium Node Metrics");
        println!("# (run with --prometheus-server to expose via HTTP)");
        println!("quil_node_version{{version=\"{}\"}} 1", quil_config::VERSION_STRING);
        if let Some(ref filter) = args.metrics_filter {
            println!("# Filtered by: {}", filter);
        }
        return Ok(());
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

    // Spawn upkeep: the recorder's histogram buckets need periodic
    // run_upkeep() to evict old samples. Missing this results in
    // ever-growing memory for histograms. Task dies with the process
    // on shutdown — no explicit cancellation needed.
    if let Some(ref h) = metrics_handle {
        let h = h.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
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

    // Create cancellation token for coordinated shutdown
    let token = CancellationToken::new();
    let shutdown_token = token.clone();

    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("received shutdown signal");
        shutdown_token.cancel();
    });

    // Handle --import-db before anything else.
    // Supports file path or "-" for stdin (pipe from Go exporter).
    // Pipe mode uses zero extra disk:
    //   ./node --export-db - | ./quil-node --import-db -
    if let Some(ref import_path) = args.import_db {
        let db_path = if config.db.path.is_empty() {
            PathBuf::from(".config/store")
        } else {
            PathBuf::from(&config.db.path)
        };
        std::fs::create_dir_all(&db_path)?;
        let db = quil_store::RocksDb::open(&db_path)?;

        let result = if import_path.to_str() == Some("-") {
            // Streaming mode: read from stdin (zero extra disk)
            info!("importing from stdin (pipe mode — zero extra disk)");
            let stdin = std::io::stdin().lock();
            quil_store::import::import_from_reader(db.inner().as_ref(), stdin)?
        } else {
            // File mode: validate first, then import
            info!(path = %import_path.display(), "importing from file");
            match quil_store::import::validate_export_file(import_path) {
                Ok(count) => info!(entries = count, "export file validated"),
                Err(e) => {
                    error!(error = %e, "invalid export file");
                    return Err(e.into());
                }
            }
            quil_store::import::import_database(db.inner().as_ref(), import_path)?
        };

        info!(
            entries = result.entries,
            data_gb = format!("{:.2}", result.data_bytes as f64 / (1024.0 * 1024.0 * 1024.0)),
            "import complete — start the node normally (without --import-db)"
        );
        return Ok(());
    }

    // Select node mode
    match (args.core, args.dht_only) {
        (_, true) => {
            info!("starting in DHT-only mode");
            run_dht_node(&config, token).await
        }
        (0, false) => {
            // Archive mode comes from --archive OR engine.archiveMode.
            let archive_mode = args.archive || config.engine.archive_mode;
            info!(archive = archive_mode, "starting as master node");
            run_master_node(
                &config,
                &args.config,
                archive_mode,
                args.network,
                token,
                metrics_handle.clone(),
            )
            .await
        }
        (core_id, false) => {
            info!(core_id, "starting as worker node");
            run_worker_node(&config, core_id, args.parent_process, token).await
        }
    }
}

async fn run_master_node(
    config: &quil_config::Config,
    config_dir: &std::path::Path,
    archive_mode: bool,
    network: u8,
    token: CancellationToken,
    metrics_handle: Option<metrics_exporter_prometheus::PrometheusHandle>,
) -> anyhow::Result<()> {
    // ---------------------------------------------------------------
    // 1. Open database
    // ---------------------------------------------------------------
    let db_path = if config.db.path.is_empty() {
        PathBuf::from(".config/store")
    } else {
        PathBuf::from(&config.db.path)
    };

    // Detect the on-disk store format BEFORE we let RocksDB touch the
    // path. The Go node wrote Pebble; the Rust node writes RocksDB.
    // Opening a Pebble dir with RocksDB produces a confusing
    // "Corruption" error far from the real cause.
    //
    // Policy:
    //   - non-archive nodes: wipe & let RocksDB recreate. State is
    //     recoverable from peers via hypersync.
    //   - archive nodes: refuse to wipe — that store is the canonical
    //     copy and must be migrated, not deleted. Tell the user to
    //     run the conversion tool.
    match quil_store::detect_store_format(&db_path) {
        quil_store::StoreFormat::Pebble => {
            if archive_mode {
                return Err(anyhow::anyhow!(
                    "detected Go-Pebble store at {} but this node is in archive mode — \
                     refusing to wipe. Run the Pebble→RocksDB conversion tool first, \
                     or move the directory aside and re-hypersync from another archive.",
                    db_path.display()
                ));
            }
            warn!(
                path = %db_path.display(),
                "detected legacy Go-Pebble store; wiping for fresh RocksDB init \
                 (non-archive node — state will be re-synced from peers)"
            );
            std::fs::remove_dir_all(&db_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to wipe legacy Pebble store at {}: {}",
                    db_path.display(),
                    e
                )
            })?;
        }
        quil_store::StoreFormat::Unknown => {
            return Err(anyhow::anyhow!(
                "store path {} exists but is neither RocksDB nor Pebble — \
                 refusing to touch it. Move it aside if you want a clean start.",
                db_path.display()
            ));
        }
        quil_store::StoreFormat::RocksDb | quil_store::StoreFormat::Empty => { /* OK */ }
    }

    std::fs::create_dir_all(&db_path)?;
    let db = quil_store::RocksDb::open(&db_path)?;
    let db_arc = Arc::new(db);
    info!(path = %db_path.display(), "opened database");

    // ---------------------------------------------------------------
    // 2. Create stores
    // ---------------------------------------------------------------
    let clock_store = Arc::new(quil_store::RocksClockStore::new(db_arc.inner()));
    let token_store = Arc::new(quil_store::RocksTokenStore::new(db_arc.inner()));
    let key_store: Arc<quil_store::RocksKeyStore> =
        Arc::new(quil_store::RocksKeyStore::new(db_arc.inner()));
    // Trait-object handle so the shard_info refresh task (lower in
    // this fn) can hold a `&dyn ShardsStore` for enumerating
    // shard_keys against archives. A second `Arc<dyn ShardsStore>`
    // is built later for the gRPC server's `GetAppShards` handler;
    // both share the same underlying RocksDB column family.
    let shards_store: Arc<dyn quil_types::store::ShardsStore> =
        Arc::new(quil_store::RocksShardsStore::new(db_arc.inner()));
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db_arc.inner()));

    // Check latest stored frame
    match clock_store.get_latest_global_frame() {
        Ok(frame) => {
            let frame_num = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
            info!(frame = frame_num, "resuming from stored state");
        }
        Err(_) => {
            info!("no stored frames — will sync from network");
        }
    }

    // ---------------------------------------------------------------
    // 2b. Key management — load or create BLS prover key from keys.yml
    // ---------------------------------------------------------------
    let keys_path = if config.key.key_store_file.path.is_empty() {
        config_dir.join("keys.yml")
    } else {
        PathBuf::from(&config.key.key_store_file.path)
    };

    let bls_ctor = quil_crypto::Bls48581KeyConstructor;
    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "default-proving-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };

    let file_key_manager = Arc::new(quil_keys::FileKeyManager::new(
        keys_path,
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(bls_ctor),
    )?);

    // `q-peer-key` lives in `config.p2p.peer_priv_key`, not `keys.yml` —
    // wire it through so keystore lookups (Send RPC outer auth, peer ID
    // derivation) work on Go-style configs.
    file_key_manager.set_peer_priv_key_hex(&config.p2p.peer_priv_key);

    // Auto-create all standard keys if missing
    file_key_manager.ensure_standard_keys()?;
    let bls_pubkey = file_key_manager.get_public_key(quil_types::crypto::KeyType::Bls48581G1)?;

    let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;
    // Publish the local prover address to the execution layer's static
    // so `apply_reward` can surface incoming credits to the operator.
    let _ = quil_execution::global_intrinsic::prover_shard_update::LOCAL_PROVER_ADDRESS
        .set(prover_address.to_vec());
    info!(
        prover_address = hex::encode(&prover_address),
        bls_pubkey_len = bls_pubkey.len(),
        "BLS prover identity ready"
    );

    // ---------------------------------------------------------------
    // 3. Create execution engines with full crypto verification
    // ---------------------------------------------------------------
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_crypto::KzgInclusionProver);
    let bls_constructor: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::Bls48581KeyConstructor);
    let key_manager: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new(bls_constructor));
    // CRDT backed by RocksDB for real persistence
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover.clone(),
    ));
    // Pre-create the lazy tree for the global prover shard so the
    // first commit materializes its root. Without this, migrated
    // stores skip the shard and the sync server returns None for the
    // tree blob.
    crdt.ensure_all_phase_trees(&quil_types::store::ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    });
    info!("global prover shard primed in CRDT phase_sets");

    // Same prime for every app shard the local shards-store knows
    // about. Without this, the QUIL-token shard's lazy trees never
    // get inserted into `phase_sets` (no in-process mutation happens
    // on a freshly migrated store), so `phase_set_metadata_at_path`
    // returns `None` for every prefix and `GetAppShards` reports
    // `size=0` + zero commitments to remote pollers. Their lifecycle
    // then drops every candidate in `build_proposal_descriptors` and
    // no `ProposeJoin` ever fires. All four phase sets are primed
    // because remote callers verify commitments across all phases,
    // not just vertex_adds.
    {
        let mut primed_keys: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
        let mut primed_count = 0usize;
        if let Ok(shards) = shards_store.range_app_shards() {
            for s in shards {
                if s.shard_key.len() != 35 {
                    continue;
                }
                if !primed_keys.insert(s.shard_key.clone()) {
                    continue;
                }
                let mut l1 = [0u8; 3];
                l1.copy_from_slice(&s.shard_key[..3]);
                let mut l2 = [0u8; 32];
                l2.copy_from_slice(&s.shard_key[3..35]);
                crdt.ensure_all_phase_trees(&quil_types::store::ShardKey { l1, l2 });
                primed_count += 1;
            }
        }
        info!(shards = primed_count, "app shards primed in CRDT phase_sets");
    }
    // Eagerly run one commit at startup so the per-shard tree blob
    // lands at `[0x2F, vertex, adds, {l1=[0;3], l2=[0xff;32]}]`
    // before any sync probe arrives. Without an eager commit the
    // tree blob isn't written until the first finalized frame is
    // materialized, leaving an interval (sometimes several minutes
    // on the seed nodes) where non-archive peers receive
    // "no tree data available" and fall into perpetual fresh-sync
    // retries.
    match crdt.commit(0) {
        Ok(commits) => {
            let global_shard = quil_types::store::ShardKey {
                l1: [0u8; 3],
                l2: [0xffu8; 32],
            };
            let root_hex = commits
                .get(&global_shard)
                .and_then(|p| p.first())
                .map(|r| hex::encode(r))
                .unwrap_or_else(|| "<no root>".into());
            info!(
                shards = commits.len(),
                global_prover_root = %root_hex,
                "primed hypergraph tree blobs at startup",
            );
        }
        Err(e) => warn!(error = %e, "startup hypergraph commit failed"),
    }
    // ExecutionEngineManager::new takes the full crypto + store
    // provider set as mandatory inputs. Production bulletproof prover
    // ships in `quil_crypto::Decaf448BulletproofProver`; the Decaf448
    // constructor and circuit compiler aren't wired to real
    // implementations yet (no production impl exists in the Rust
    // tree), so we plug in the testing-stubs noop variants. Those
    // engines' verify paths return `false` for every signature, so
    // any signed op fails closed rather than silently passing.
    let bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver> =
        Arc::new(quil_crypto::Decaf448BulletproofProver);
    let decaf_constructor: Arc<dyn quil_types::crypto::DecafConstructor> =
        Arc::new(quil_execution::testing::NoopDecafConstructor);
    let circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler> =
        Arc::new(quil_execution::testing::NoopCircuitCompiler);
    let clock_store_for_exec: Arc<dyn quil_types::store::ClockStore> =
        clock_store.clone();
    // Hypergraph engine requires a config resolver. A real resolver
    // would look up the HypergraphDeploy config vertex for each
    // domain; that materialization isn't wired yet, so we use the
    // fail-closed noop (returns None → AuthCheck::UnknownDomain →
    // engine rejects all hypergraph write ops). Swap in a real
    // resolver once the deploy materialization lands.
    let hypergraph_resolver: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
    let exec_manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        inclusion_prover.clone(),
        key_manager.clone(),
        crdt.clone(),
        bulletproof_prover,
        decaf_constructor,
        circuit_compiler,
        clock_store_for_exec,
        hypergraph_resolver,
        true,
    ));
    info!("execution engines initialized with BLS48-581 + Ed448 signature verification");

    // 3b. Genesis bootstrap (mainnet + testnet/devnet). Idempotent:
    // skips if the genesis frame already exists.
    let clock_store_dyn: &dyn quil_types::store::ClockStore = clock_store.as_ref();
    if network == 0 {
        info!("bootstrapping mainnet genesis frame");
        match quil_engine::genesis::initialize_genesis_state(
            clock_store_dyn,
            shards_store.as_ref() as &dyn quil_types::store::ShardsStore,
            &crdt,
            inclusion_prover.as_ref(),
        ) {
            Ok((frame, _qc)) => {
                let fn_ = frame
                    .header
                    .as_ref()
                    .map(|h| h.frame_number)
                    .unwrap_or(0);
                info!(frame_number = fn_, "mainnet genesis ready");
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to initialize mainnet genesis: {}",
                    e
                ));
            }
        }
    }
    if network != 0 && clock_store_dyn.get_global_clock_frame(0).is_err() {
        info!(
            network = network,
            "bootstrapping testnet/devnet genesis frame"
        );
        let genesis_seed = &config.engine.genesis_seed;
        match quil_engine::genesis::initialize_testnet_genesis_state(
            network,
            genesis_seed,
            &bls_pubkey,
            0, // difficulty=0 triggers DEFAULT_TESTNET_DIFFICULTY
            clock_store_dyn,
            shards_store.as_ref() as &dyn quil_types::store::ShardsStore,
            &crdt,
            inclusion_prover.as_ref(),
        ) {
            Ok((frame, _qc)) => {
                let fn_ = frame
                    .header
                    .as_ref()
                    .map(|h| h.frame_number)
                    .unwrap_or(0);
                info!(
                    frame_number = fn_,
                    "testnet genesis established"
                );
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to initialize testnet genesis: {}",
                    e
                ));
            }
        }
    }

    // ---------------------------------------------------------------
    // 4. Create frame pipeline with VDF verification
    // ---------------------------------------------------------------
    let frame_prover: Arc<dyn quil_types::crypto::FrameProver> =
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));
    let bls_for_verify: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::Bls48581KeyConstructor);
    let frame_validator = quil_engine::frame_validator::GlobalFrameVerifier::with_bls(
        frame_prover.clone(),
        bls_for_verify,
    );

    let _difficulty = quil_engine::AsertDifficultyAdjuster::new(0, 0, 0);
    let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
        Arc::new(quil_engine::InMemoryDynamicFeeManager::new(360));
    let _time_reel = quil_engine::GlobalTimeReel::new();

    info!("VDF frame prover ready (Wesolowski, 2048-bit)");

    // ---------------------------------------------------------------
    // 5. Start P2P networking
    // ---------------------------------------------------------------
    let listen_addr = if config.p2p.listen_multiaddr.is_empty() {
        "/ip4/0.0.0.0/udp/8336/quic-v1".to_string()
    } else {
        config.p2p.listen_multiaddr.clone()
    };

    // CLI `--network` is the source of truth — override the YAML's
    // `p2p.network` so a single config file can be reused across
    // networks without the BlossomSub protocol id falling back to
    // the mainnet variant on testnet runs.
    let mut p2p_config = config.p2p.clone();
    p2p_config.network = network;
    let p2p_node = quil_p2p::node::P2PNode::new(&p2p_config)?;
    let peer_id = p2p_node.peer_id;
    info!(
        key_type = if config.p2p.peer_priv_key.is_empty() { "generated Ed448" } else { "loaded from config" },
        %peer_id,
        "P2P identity ready"
    );

    // Persist newly generated Ed448 key to config
    if let Some(key_hex) = &p2p_node.generated_key_hex {
        let mut updated_config = config.clone();
        updated_config.p2p.peer_priv_key = key_hex.clone();
        if let Err(e) = quil_config::save_config(config_dir, &updated_config) {
            warn!(error = %e, "failed to save generated peer key to config");
        } else {
            info!("saved new Ed448 peer key to config (peer ID is now stable)");
        }
    }

    info!(%peer_id, "starting P2P networking");

    let (p2p_handle, mut msg_rx) = p2p_node.start(&listen_addr).await?;
    info!(listen = %listen_addr, "P2P swarm started");

    // Self-loopback channel for consensus messages — used by
    // `BlossomsubConsensusPublisher::publish_consensus` to feed the
    // local node's own outbound proposal/vote back into the dispatcher
    // (BlossomSub does not echo self-published messages, so without
    // this the proposer's own state never reaches its own
    // `vote_aggregator` / event_loop).
    let (consensus_loopback_tx, mut consensus_loopback_rx) =
        tokio::sync::mpsc::channel::<quil_p2p::node::ReceivedMessage>(256);

    // Subscribe to all global bitmasks — must subscribe before publishing
    p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_FRAME.to_vec()).await;
    p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_CONSENSUS.to_vec()).await;
    p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_PROVER.to_vec()).await;
    p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_PEER_INFO.to_vec()).await;
    info!("subscribed to global frame, consensus, prover, and peer info bitmasks");

    // Apply engine blacklist — deny connections from blacklisted peers.
    // Blacklist entries are peer ID strings (Qm... multihash format).
    for peer_str in &config.engine.blacklist {
        if let Ok(peer_id) = peer_str.parse::<quil_p2p::PeerId>() {
            p2p_handle.blacklist_peer(peer_id).await;
            info!(peer = %peer_id, "blacklisted peer from config");
        }
    }

    // Frame tracking — single source of truth for "what frame is
    // this node on right now." Updated by the BlossomSub receive
    // loop (`observe`), archive poller (`observe`), and frame
    // materializer (`materialize`). Read by RPC handlers,
    // shard-info, peer-info publisher, lifecycle, eviction, and
    // every other site that previously took `max(clock_store, lrf)`.
    let current_frame = quil_engine::current_frame::CurrentFrame::new();
    // Seed from any frame already persisted to the clock store so
    // RPC consumers can read a sensible current frame *immediately*
    // at startup — before the first BlossomSub frame arrives. The
    // `observe` call is monotonic, so a later live frame can still
    // advance it.
    if let Ok(frame) = clock_store.get_latest_global_frame() {
        if let Some(h) = frame.header.as_ref() {
            current_frame.observe(h.frame_number);
        }
    }
    // PeerInfo cache populated by the GLOBAL_PEER_INFO recv path.
    // Read by NodeService::get_peer_info so CLI tools can enumerate
    // the peers this node has observed on the network. Keyed by the
    // raw peer_id bytes; last-write-wins.
    // parking_lot::RwLock instead of std::sync::RwLock: smaller +
    // faster, no poisoning (so `.read()` / `.write()` return guards
    // directly without `.unwrap()`), and better fairness under
    // contention. This is a strict ergonomics + perf upgrade, NOT
    // an async-fix — parking_lot's lock is still blocking from
    // tokio's view. Switch to `tokio::sync::RwLock` if reads need
    // to yield instead of block.
    let peer_info_cache: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>,
    >> = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    // filter → AppEngineHandle registry. Populated by the worker→master
    // drain task on `WorkerToMaster::ShardActivated` and cleared on
    // `ShardDeactivated`. Read by the inbound BlossomSub recv loop to
    // route per-shard frame / consensus / prover / dispatch messages
    // to the right engine in multi-prover deployments.
    let shard_engines: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
    >> = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    // SignerRegistry — populated from inbound KeyRegistry broadcasts
    // on GLOBAL_PEER_INFO. Consumed by consensus message verification
    // (BLS signatures from peers whose identity↔prover binding we've
    // observed).
    let signer_registry: Arc<quil_p2p::SignerRegistry> =
        Arc::new(quil_p2p::SignerRegistry::new());
    // Seed from the local clock store so PeerInfo broadcasts our
    // real head on the first publish. Without this, restart leaves
    // the atomic at 0 until a new frame arrives over the network —
    // peers then see `head_frame=0` in our PeerInfo, can't form a
    // quorum on rank N+1 because they assume we have no state, and
    // consensus stalls. Loading the local latest from RocksDB
    // (which the migration already populated to e.g. 414) closes
    // the gap immediately.
    let initial_head_frame: u64 = clock_store
        .get_latest_global_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    if initial_head_frame > 0 {
        info!(
            head_frame = initial_head_frame,
            "seeded last_global_head_frame from local clock store",
        );
    }
    let last_global_head_frame = Arc::new(std::sync::atomic::AtomicU64::new(initial_head_frame));

    // ---------------------------------------------------------------
    // 5b. PeerInfo publishing (every 5 minutes + immediate)
    // ---------------------------------------------------------------

    // Deferred worker-manager handle for per-worker reachability
    // advertisements. The PeerInfo broadcaster spawns here (before
    // `worker_manager` exists). Once `worker_manager` is constructed
    // ~250 lines below, it's published into this OnceLock. The next
    // PeerInfo tick picks it up. First tick (immediate at startup)
    // may publish without per-worker entries; subsequent ticks
    // include them.
    let pi_worker_manager: Arc<std::sync::OnceLock<
        Arc<dyn quil_engine::worker::WorkerManager>,
    >> = Arc::new(std::sync::OnceLock::new());
    {
        let pi_handle = p2p_handle.clone();
        let pi_token = token.clone();

        // Extract Ed448 seed and derive public key for signing PeerInfo.
        let pk_bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
        let (pi_ed448_seed, pi_ed448_pubkey) = if pk_bytes.len() >= 57 {
            let seed: [u8; 57] = pk_bytes[..57].try_into().unwrap();
            let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
            (Some(seed), pubkey)
        } else {
            (None, Vec::new())
        };

        let pi_peer_id_bytes = if !pi_ed448_pubkey.is_empty() {
            quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pi_ed448_pubkey)
        } else {
            peer_id.to_bytes()
        };

        // Multiaddr configuration — resolved on each publish cycle to pick up
        // observed external addresses as they become available.
        let pi_announce = config.p2p.announce_listen_multiaddr.clone();
        let pi_announce_stream = config.p2p.announce_stream_listen_multiaddr.clone();
        let pi_stream_listen = config.p2p.stream_listen_multiaddr.clone();
        let pi_listen_fallback = listen_addr.clone();
        let pi_p2p_handle = p2p_handle.clone();
        let pi_current_frame = current_frame.clone();
        let pi_last_head = last_global_head_frame.clone();
        // Per-worker multiaddrs — used in process-mode (each worker
        // is its own OS process with its own ports). In thread mode
        // (the default for the Rust port) all these arrays are empty
        // and per-worker reachability falls back to the master's
        // addresses.
        let pi_worker_p2p_multiaddrs = config.engine.data_worker_p2p_multiaddrs.clone();
        let pi_worker_stream_multiaddrs = config.engine.data_worker_stream_multiaddrs.clone();
        let pi_worker_announce_p2p = config.engine.data_worker_announce_p2p_multiaddrs.clone();
        let pi_worker_announce_stream =
            config.engine.data_worker_announce_stream_multiaddrs.clone();
        let pi_worker_manager_slot = Arc::clone(&pi_worker_manager);
        let mut pi_caps: Vec<quil_p2p::CanonicalCapability> = exec_manager
            .get_supported_capabilities()
            .into_iter()
            .map(|c| quil_p2p::CanonicalCapability {
                protocol_identifier: c.protocol_identifier,
                additional_metadata: c.additional_metadata,
            })
            .collect();
        // Archive nodes must advertise the archive-service capability
        // so non-archive peers (joining provers) can find them via
        // PeerInfo and fetch frames over gRPC. Without this, every
        // peer's `info.is_archive()` returns false and the archive
        // pool stays empty.
        if archive_mode {
            pi_caps.push(quil_p2p::CanonicalCapability {
                protocol_identifier:
                    quil_execution::capabilities::ARCHIVE_PROTOCOL_V1,
                additional_metadata: Vec::new(),
            });
        }

        // BLS key for KeyRegistry publishing
        let kr_bls_pubkey = bls_pubkey.clone();
        let kr_key_manager = file_key_manager.clone();

        tokio::spawn(async move {
            let bitmask = vec![0x00, 0x00, 0x00, 0x00]; // GLOBAL_PEER_INFO
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                // Resolve multiaddrs: prefer observed (NAT-resolved), then announce, then listen
                let observed = pi_p2p_handle.observed_addresses();
                let pubsub_addr = if !pi_announce.is_empty() {
                    pi_announce.clone()
                } else if let Some(obs) = observed.first() {
                    obs.clone()
                } else {
                    pi_listen_fallback.clone()
                };
                let stream_addrs = if !pi_announce_stream.is_empty() {
                    vec![pi_announce_stream.clone()]
                } else if !pi_stream_listen.is_empty() {
                    // Derive from pubsub addr IP + stream port
                    extract_stream_addr(&pubsub_addr, &pi_stream_listen)
                        .into_iter().collect()
                } else {
                    vec![]
                };
                // Master reachability with the global-filter `[0xFF;32]`
                // convention. Then per-worker reachabilities (one per
                // running worker with a non-empty filter), populated
                // from the worker manager once it's available.
                let mut reachability = vec![quil_p2p::CanonicalReachability {
                    filter: vec![0xFF; 32], // global filter
                    pubsub_multiaddrs: vec![pubsub_addr.clone()],
                    stream_multiaddrs: stream_addrs.clone(),
                }];
                if let Some(wm) = pi_worker_manager_slot.get() {
                    let view = quil_engine::worker::WorkerView::snapshot(wm.as_ref());
                    let pairs: Vec<(u32, Vec<u8>)> = view
                        .filter_set()
                        .map(|w| (w.core_id, w.filter.clone()))
                        .collect();
                    if !pairs.is_empty() {
                        reachability.extend(quil_p2p::build_worker_reachability(
                            &pairs,
                            &pubsub_addr,
                            &stream_addrs,
                            &pi_worker_p2p_multiaddrs,
                            &pi_worker_stream_multiaddrs,
                            &pi_worker_announce_p2p,
                            &pi_worker_announce_stream,
                        ));
                    }
                }
                let worker_reachability_count = reachability.len().saturating_sub(1);

                let info = quil_p2p::CanonicalPeerInfo {
                    peer_id: pi_peer_id_bytes.clone(),
                    reachability,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64,
                    version: vec![2, 1, 0],
                    patch_number: vec![23],
                    capabilities: pi_caps.clone(),
                    // pubkey/signature are passed separately to
                    // encode_canonical_peer_info below; the struct
                    // fields are populated from decodes in the recv
                    // path, not used here.
                    public_key: Vec::new(),
                    signature: Vec::new(),
                    last_received_frame: pi_current_frame.effective(),
                    last_global_head_frame: pi_last_head.load(std::sync::atomic::Ordering::Relaxed),
                };

                // Sign the PeerInfo with Ed448 — peers validate this
                // signature and silently drop unsigned PeerInfo.
                //
                // Process:
                // 1. Encode with public_key but empty signature (for signing)
                // 2. Sign those bytes with Ed448
                // 3. Re-encode with the actual signature
                let encoded = if let Some(ref seed) = pi_ed448_seed {
                    // Step 1: encode without signature for signing
                    let msg_to_sign = quil_p2p::encode_canonical_peer_info(
                        &info, &pi_ed448_pubkey, &[],
                    );
                    // Step 2: sign with Ed448
                    let privkey = ed448_rust::PrivateKey::from(*seed);
                    match privkey.sign(&msg_to_sign, None) {
                        Ok(signature) => {
                            // Step 3: re-encode with signature
                            quil_p2p::encode_canonical_peer_info(
                                &info, &pi_ed448_pubkey, &signature,
                            )
                        }
                        Err(e) => {
                            warn!("Ed448 sign failed: {:?}", e);
                            quil_p2p::encode_canonical_peer_info(&info, &pi_ed448_pubkey, &[])
                        }
                    }
                } else {
                    quil_p2p::encode_canonical_peer_info(&info, &[], &[])
                };

                if let Err(e) = pi_handle.publish(bitmask.clone(), encoded).await {
                    warn!(error = %e, "failed to publish PeerInfo");
                } else {
                    info!(
                        capabilities = pi_caps.len(),
                        signed = pi_ed448_seed.is_some(),
                        pubkey_len = pi_ed448_pubkey.len(),
                        worker_reachability = worker_reachability_count,
                        "published PeerInfo"
                    );
                }

                // Publish KeyRegistry alongside PeerInfo (every 5 min).
                if let Some(ref seed) = pi_ed448_seed {
                    let pv = ed448_rust::PrivateKey::from(*seed);
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    // identity_to_prover: Ed448 signs ("KEY_REGISTRY" || bls_pubkey)
                    let mut kr_msg = Vec::from(b"KEY_REGISTRY" as &[u8]);
                    kr_msg.extend_from_slice(&kr_bls_pubkey);
                    if let Ok(i2p_sig) = pv.sign(&kr_msg, None) {
                        // prover_to_identity: BLS signs ed448_pubkey with domain "KEY_REGISTRY"
                        match kr_key_manager.get_signer(quil_types::crypto::KeyType::Bls48581G1) {
                            Ok(bls_signer) => {
                                if let Ok(p2i_sig) = bls_signer.sign_with_domain(&pi_ed448_pubkey, b"KEY_REGISTRY") {
                                    let kr = quil_p2p::encode_key_registry(
                                        &pi_ed448_pubkey,
                                        &kr_bls_pubkey,
                                        &i2p_sig,
                                        &p2i_sig,
                                        now_ms,
                                    );
                                    if let Err(e) = pi_handle.publish(bitmask.clone(), kr).await {
                                        warn!(error = %e, "failed to publish KeyRegistry");
                                    } else {
                                        info!("published KeyRegistry");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "cannot publish KeyRegistry: BLS signer unavailable");
                            }
                        }
                    }
                }

                tokio::select! {
                    _ = interval.tick() => {}
                    _ = pi_token.cancelled() => break,
                }
            }
        });
        info!("PeerInfo publisher started (5-minute interval)");
    }

    // ---------------------------------------------------------------
    // 5c. Message collector + consensus event loop
    // ---------------------------------------------------------------
    let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());

    // The consensus event loop is optional — it runs only when this node
    // has a BLS proving key and is an active prover. For now we create
    // the prover registry and message collector, but defer the full
    // HotStuff event loop until the node has synced enough state to
    // determine its role. The consensus components are ready to be
    // wired when this node becomes an active prover.
    let prover_registry = Arc::new(quil_execution::SharedProverRegistry::new());
    {
        let pr = prover_registry.clone();
        let hs = hg_store.clone();
        // Run in background — don't block P2P startup. The registry
        // populates asynchronously; consensus won't start until it's ready.
        tokio::task::spawn_blocking(move || {
            pr.refresh_from_store(&hs);
            let count = pr.read(|r| r.distinct_provers());
            tracing::info!(provers = count, "prover registry loaded (background)");
        });
    }

    // ---------------------------------------------------------------
    // 5d. Coverage monitor + worker allocator + worker threads
    // ---------------------------------------------------------------
    let prover_only_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let global_event_distributor: Arc<dyn quil_types::consensus::EventDistributor> =
        Arc::new(quil_engine::event_distributor::InMemoryEventDistributor::new());
    let coverage_monitor = Arc::new(quil_engine::coverage::CoverageMonitor::new(
        prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        global_event_distributor.clone(),
        quil_engine::coverage::CoverageThresholds::mainnet(),
        prover_only_flag.clone(),
    ));

    // Shared halt state — written by the coverage-event subscriber
    // below, read by the lifecycle `join_proposal_ready` gate and by
    // the periodic eviction scheduler. Needs to exist before any
    // consumer references it.
    let halt_state = Arc::new(quil_engine::halt_state::HaltState::new());

    // Spawn subscriber: drains ControlEvents from the in-memory
    // distributor and updates `halt_state` on CoverageHalt /
    // CoverageResume. The separate shard orchestration subscriber is
    // wired below once the prover pipeline exists.
    {
        let mut rx = global_event_distributor.subscribe("halt-state");
        let hs = halt_state.clone();
        let cancel = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    maybe_event = rx.recv() => {
                        let Some(event) = maybe_event else { break };
                        match (event.event_type, &event.data) {
                            (
                                quil_types::consensus::ControlEventType::CoverageHalt,
                                quil_types::consensus::ControlEventData::Coverage { filter, duration },
                            ) => {
                                if hs.apply(&event) {
                                    info!(
                                        filter = hex::encode(filter),
                                        duration_frames = *duration,
                                        halted_count = hs.halted_count(),
                                        "coverage halt entered"
                                    );
                                    quil_engine::metrics::inc_coverage_halts_entered();
                                    quil_engine::metrics::set_halted_shards(hs.halted_count() as u64);
                                }
                            }
                            (
                                quil_types::consensus::ControlEventType::CoverageResume,
                                quil_types::consensus::ControlEventData::Coverage { filter, .. },
                            ) => {
                                if hs.apply(&event) {
                                    info!(
                                        filter = hex::encode(filter),
                                        halted_count = hs.halted_count(),
                                        "coverage halt resumed"
                                    );
                                    quil_engine::metrics::inc_coverage_resumes();
                                    quil_engine::metrics::set_halted_shards(hs.halted_count() as u64);
                                }
                            }
                            (
                                quil_types::consensus::ControlEventType::ShardSplitEligible,
                                quil_types::consensus::ControlEventData::ShardSplit { filter, proposed },
                            ) => {
                                info!(
                                    filter = hex::encode(filter),
                                    proposed = proposed.len(),
                                    "shard split eligible (orchestration pending)"
                                );
                            }
                            (
                                quil_types::consensus::ControlEventType::ShardMergeEligible,
                                quil_types::consensus::ControlEventData::ShardMerge { filters, parent },
                            ) => {
                                info!(
                                    filter_count = filters.len(),
                                    parent = hex::encode(parent),
                                    "shard merge eligible (orchestration pending)"
                                );
                            }
                            (quil_types::consensus::ControlEventType::CoverageWarn, _) => {
                                debug!("coverage warn");
                                quil_engine::metrics::inc_coverage_warns();
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
    }

    // Broadcast halt-state changes to every active app shard engine
    // AND every standalone worker process. In-process thread-mode
    // engines receive via the `shard_engines` map; standalone workers
    // receive via the `SetHalted` DataIPC RPC, looked up through
    // `remote_worker_manager_for_halt` (populated later by the
    // cluster-mode branch of the worker_manager setup).
    //
    // Two firings:
    //   1. Edge-triggered: when `halt_state.watch_any_halted()` flips,
    //      push the new value immediately.
    //   2. Periodic resync (every 30s) while a halt is active: covers
    //      worker reconnects and the initial-connect race where a
    //      worker boots mid-halt and would otherwise stay halted=false
    //      until the next edge transition.
    let remote_worker_manager_for_halt: Arc<
        std::sync::OnceLock<Arc<quil_engine::remote_worker::RemoteWorkerManager>>,
    > = Arc::new(std::sync::OnceLock::new());
    {
        let mut rx = halt_state.watch_any_halted();
        let engines = shard_engines.clone();
        let cancel = token.clone();
        let remote_mgr_cell = remote_worker_manager_for_halt.clone();
        let halt_state_for_periodic = halt_state.clone();
        tokio::spawn(async move {
            let mut periodic = tokio::time::interval(std::time::Duration::from_secs(30));
            periodic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = rx.changed() => {
                        if res.is_err() { break; }
                        let halted = *rx.borrow();
                        // Scope the read guard: parking_lot::RwLockReadGuard
                        // is !Send, so it must drop before any .await.
                        let count = {
                            let map = engines.read();
                            let n = map.len();
                            for (_filter, handle) in map.iter() {
                                handle.set_halted(halted);
                            }
                            n
                        };
                        if let Some(mgr) = remote_mgr_cell.get() {
                            mgr.broadcast_set_halted(halted).await;
                        }
                        info!(
                            halted,
                            engines = count,
                            "broadcast halt state to app shard engines"
                        );
                    }
                    _ = periodic.tick() => {
                        let halted = halt_state_for_periodic.any_halted();
                        if !halted {
                            continue;
                        }
                        // Re-push to every engine + remote worker so a
                        // freshly-connected worker picks up the halt.
                        {
                            let map = engines.read();
                            for (_filter, handle) in map.iter() {
                                handle.set_halted(true);
                            }
                        }
                        if let Some(mgr) = remote_mgr_cell.get() {
                            mgr.broadcast_set_halted(true).await;
                        }
                    }
                }
            }
        });
    }

    // Wire prover-only mode into the message collector
    // (the collector checks this flag on each add_message call)
    let mc_prover_only = message_collector.clone();
    let pof = prover_only_flag.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            mc_prover_only.set_prover_only_mode(
                pof.load(std::sync::atomic::Ordering::Relaxed),
            );
        }
    });

    // Worker manager — either local threads or remote gRPC workers.
    // If data_worker_stream_multiaddrs has entries, use remote mode
    // (cluster of machines). Otherwise, use local threads.
    let reward_greedy = config.engine.reward_strategy == "reward-greedy";
    let fkm_for_factory = file_key_manager.clone();

    let worker_manager: Arc<dyn quil_engine::worker::WorkerManager> =
        if !config.engine.data_worker_stream_multiaddrs.is_empty() {
            // CLUSTER MODE: remote workers via gRPC
            // Master listens on the stream port from P2P config
            let master_port = if config.p2p.stream_listen_multiaddr.is_empty() {
                8340u16
            } else {
                // Extract port from /ip4/X/tcp/PORT
                config.p2p.stream_listen_multiaddr
                    .split('/')
                    .collect::<Vec<_>>()
                    .windows(2)
                    .find(|w| w[0] == "tcp")
                    .and_then(|w| w[1].parse::<u16>().ok())
                    .unwrap_or(8340)
            };
            let master_ep = format!("http://0.0.0.0:{}", master_port);
            let remote_mgr = Arc::new(quil_engine::remote_worker::RemoteWorkerManager::from_config(
                &config.engine.data_worker_stream_multiaddrs,
                master_ep,
            ));
            info!(
                remote_workers = config.engine.data_worker_stream_multiaddrs.len(),
                "remote worker manager ready (cluster mode)"
            );
            // Publish to the halt broadcaster spawned above so it can
            // SetHalted across standalone workers when coverage halts.
            let _ = remote_worker_manager_for_halt.set(remote_mgr.clone());
            remote_mgr as Arc<dyn quil_engine::worker::WorkerManager>
        } else {
            // LOCAL MODE: core-pinned threads
            let thread_mgr = Arc::new(quil_engine::thread_worker::ThreadWorkerManager::new());
            // Persistent worker registry — survives restarts so the
            // operator's `manually_managed` flag and the
            // worker→filter binding don't reset every reboot.
            let worker_store: Arc<dyn quil_types::store::WorkerStore> =
                Arc::new(quil_store::RocksWorkerStore::new(db_arc.inner()));
            thread_mgr.set_worker_store(worker_store);
            // Closure invoked by AppFollower from inside the consensus
            // event loop: wraps a finalized FrameHeader (canonical
            // bytes) in a `MessageBundle{Shard: header}` and publishes
            // on `GLOBAL_PROVER`. Spawning the actual publish keeps the
            // call non-blocking from the consensus side.
            let coverage_p2p = p2p_handle.clone();
            let coverage_publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> =
                Arc::new(move |header_canonical_bytes: Vec<u8>| {
                    let req = match quil_execution::message_envelope::CanonicalMessageRequest::wrap(
                        header_canonical_bytes,
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(error = %e, "coverage publish: bad FrameHeader bytes");
                            return;
                        }
                    };
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64;
                    let bundle = quil_execution::message_envelope::CanonicalMessageBundle {
                        requests: vec![Some(req)],
                        timestamp,
                    };
                    match bundle.to_canonical_bytes() {
                        Ok(bytes) => {
                            let p2p = coverage_p2p.clone();
                            tokio::spawn(async move {
                                if let Err(e) = p2p
                                    .publish(
                                        quil_engine::bitmasks::GLOBAL_PROVER.to_vec(),
                                        bytes,
                                    )
                                    .await
                                {
                                    warn!(error = %e, "coverage publish: GLOBAL_PROVER publish failed");
                                }
                            });
                        }
                        Err(e) => warn!(error = %e, "coverage publish: bundle encode failed"),
                    }
                });
            // Per-worker state builder: each thread-mode worker opens
            // its own RocksDB (resolved from db.worker_paths /
            // worker_path_prefix / fallback) and builds its own
            // clock_store, hypergraph CRDT, and execution engine on
            // top. Master keeps its own global stores untouched.
            let worker_db_base = config.db.path.clone();
            let worker_paths_cfg = config.db.worker_paths.clone();
            let worker_path_prefix_cfg = config.db.worker_path_prefix.clone();
            let worker_state_builder: Arc<
                dyn Fn(u32) -> std::result::Result<
                    quil_engine::thread_worker::WorkerOwnedDeps,
                    String,
                > + Send
                    + Sync,
            > = Arc::new(move |core_id: u32| {
                let path: std::path::PathBuf = {
                    let idx = core_id.saturating_sub(1) as usize;
                    if let Some(p) = worker_paths_cfg.get(idx).filter(|s| !s.is_empty()) {
                        std::path::PathBuf::from(p)
                    } else if !worker_path_prefix_cfg.is_empty() {
                        std::path::PathBuf::from(
                            worker_path_prefix_cfg.replace("%d", &core_id.to_string()),
                        )
                    } else {
                        let base = if worker_db_base.is_empty() {
                            std::path::PathBuf::from(".config/store")
                        } else {
                            std::path::PathBuf::from(&worker_db_base)
                        };
                        base.join(format!("worker-{}", core_id))
                    }
                };
                std::fs::create_dir_all(&path).map_err(|e| {
                    format!("worker {} mkdir {}: {e}", core_id, path.display())
                })?;
                let db = quil_store::RocksDb::open(&path).map_err(|e| {
                    format!("worker {} open db {}: {e}", core_id, path.display())
                })?;
                let db_arc = Arc::new(db);
                let clock_store: Arc<dyn quil_types::store::ClockStore> = Arc::new(
                    quil_store::RocksClockStore::new(db_arc.inner()),
                );
                let hg_store: Arc<dyn quil_types::store::HypergraphStore> = Arc::new(
                    quil_store::RocksHypergraphStore::new(db_arc.inner()),
                );
                let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
                    Arc::new(quil_crypto::KzgInclusionProver);
                let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                    hg_store,
                    inclusion_prover.clone(),
                ));
                // Workers don't sign or verify identities — a default
                // key manager satisfies the execution engine's
                // `KeyManager` requirement for state materialization.
                let bls_constructor: Arc<dyn quil_types::crypto::BlsConstructor> =
                    Arc::new(quil_crypto::Bls48581KeyConstructor);
                let worker_key_manager: Arc<dyn quil_types::crypto::KeyManager> =
                    Arc::new(quil_crypto::DefaultKeyManager::new(bls_constructor));
                // Bulletproof prover is real; Decaf448 / circuit
                // compiler still use the noop stubs (no production
                // impl yet). See the analogous block in the master
                // setup above for the rationale.
                let bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver> =
                    Arc::new(quil_crypto::Decaf448BulletproofProver);
                let decaf_constructor: Arc<dyn quil_types::crypto::DecafConstructor> =
                    Arc::new(quil_execution::testing::NoopDecafConstructor);
                let circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler> =
                    Arc::new(quil_execution::testing::NoopCircuitCompiler);
                let clock_store_for_exec: Arc<dyn quil_types::store::ClockStore> =
                    clock_store.clone();
                let hypergraph_resolver: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
                    Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
                let exec_manager = Arc::new(
                    quil_execution::ExecutionEngineManager::new(
                        inclusion_prover.clone(),
                        worker_key_manager,
                        crdt.clone(),
                        bulletproof_prover,
                        decaf_constructor,
                        circuit_compiler,
                        clock_store_for_exec,
                        hypergraph_resolver,
                        true,
                    ),
                );
                tracing::info!(
                    core_id,
                    path = %path.display(),
                    "worker state initialized"
                );
                Ok(quil_engine::thread_worker::WorkerOwnedDeps {
                    clock_store,
                    hypergraph: crdt,
                    execution_engine: exec_manager,
                    inclusion_prover,
                    // Each worker writes consensus + liveness state
                    // into its own RocksDB. Mirrors the per-worker
                    // clock/hypergraph stores above.
                    kv_db: Some(db_arc.clone() as Arc<dyn quil_types::store::KvDb>),
                })
            });

            thread_mgr.set_consensus_deps(quil_engine::thread_worker::WorkerConsensusDeps {
                prover_registry: prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                frame_prover: frame_prover.clone(),
                message_collector: message_collector.clone(),
                clock_store: clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
                fee_manager: fee_manager.clone(),
                local_prover_address: prover_address.to_vec(),
                local_bls_pubkey: bls_pubkey.clone(),
                bls_signer_factory: Arc::new(move || {
                    fkm_for_factory.get_signer(quil_types::crypto::KeyType::Bls48581G1)
                        .expect("BLS signer should be available")
                }),
                reward_greedy,
                coverage_publish: Some(coverage_publish),
                // Master's global state, used as fallback when the
                // per-worker builder fails or isn't wired.
                hypergraph: Some(crdt.clone()),
                execution_engine: Some(exec_manager.clone()),
                inclusion_prover: Some(inclusion_prover.clone()),
                worker_init: Some(Arc::new(|core_id: u32| {
                    crate::logging::set_worker_core_id(core_id);
                    crate::logging::register_worker_log_file(core_id);
                })),
                worker_state_builder: Some(worker_state_builder),
                // Master's RocksDB doubles as the persistent backing
                // for app-shard `ConsensusState` / `LivenessState` —
                // workers writing through the master path (no
                // per-worker DB) land here. Per-worker builds can
                // override via `WorkerOwnedDeps::kv_db`.
                kv_db: Some(db_arc.clone() as Arc<dyn quil_types::store::KvDb>),
            });
            info!(
                worker_cores = thread_mgr.num_worker_cores(),
                "thread worker manager ready (local mode)"
            );
            // Drain `WorkerToMaster` events from in-process worker
            // threads and forward to the master's BlossomSub publish
            // path. `ShardFrameFinalized` becomes a
            // `MessageBundle{Shard: header}` on `GLOBAL_PROVER`.
            // Per-shard bitmask subscriptions are wired on
            // `ShardActivated`; inbound routing dispatches by filter
            // through `shard_engines` in the recv loop below.
            if let Some(mut master_rx) = thread_mgr.take_master_rx() {
                let drain_p2p = p2p_handle.clone();
                let drain_cancel = token.clone();
                let drain_shard_engines = shard_engines.clone();
                let drain_halt = halt_state.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = drain_cancel.cancelled() => break,
                            event = master_rx.recv() => {
                                let Some(event) = event else { break; };
                                use quil_engine::thread_worker::WorkerToMaster;
                                // Each publish is dispatched as a fire-and-forget
                                // task: the swarm's `publish().await` can block on
                                // an internal mesh send, and back-pressure here
                                // would propagate all the way to the per-shard
                                // consensus event handler (engine→master event_tx
                                // is bounded), stalling QC processing and
                                // finalization.
                                match event {
                                    WorkerToMaster::ShardFrameFinalized {
                                        core_id,
                                        filter,
                                        header_canonical_bytes,
                                    } => {
                                        // Drop reward-proof submissions during a coverage
                                        // halt. The engine's per-message halt gates stop
                                        // new consensus from advancing, but a finalize
                                        // event already in-flight when the halt arrived
                                        // can still race through and emit here. Suppress
                                        // the publish so we don't credit shard work that
                                        // shouldn't have happened during the halt window.
                                        if drain_halt.any_halted() {
                                            debug!(
                                                core_id,
                                                filter = %hex::encode(&filter),
                                                "suppressing GLOBAL_PROVER publish — coverage halt active"
                                            );
                                            continue;
                                        }
                                        // Decode for a positive log line so the operator
                                        // can see each rewardable proof going out. The
                                        // bytes are consumed by `wrap` below; decode a
                                        // borrowed view first.
                                        if let Ok(h) =
                                            quil_execution::global_intrinsic::frame_header::FrameHeader::from_canonical_bytes(
                                                &header_canonical_bytes,
                                            )
                                        {
                                            info!(
                                                core_id,
                                                filter = %hex::encode(&filter),
                                                frame = h.frame_number,
                                                rank = h.rank,
                                                prover = %hex::encode(&h.prover),
                                                "submitting reward proof to GLOBAL_PROVER"
                                            );
                                        }
                                        let req = match quil_execution::message_envelope::CanonicalMessageRequest::wrap(
                                            header_canonical_bytes,
                                        ) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                warn!(core_id, filter = %hex::encode(&filter), error = %e,
                                                    "shard finalize: bad FrameHeader bytes — dropping coverage publish");
                                                continue;
                                            }
                                        };
                                        let timestamp = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_millis() as i64;
                                        let bundle = quil_execution::message_envelope::CanonicalMessageBundle {
                                            requests: vec![Some(req)],
                                            timestamp,
                                        };
                                        match bundle.to_canonical_bytes() {
                                            Ok(bytes) => {
                                                let p2p = drain_p2p.clone();
                                                let filter_owned = filter.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = p2p
                                                        .publish(
                                                            quil_engine::bitmasks::GLOBAL_PROVER.to_vec(),
                                                            bytes,
                                                        )
                                                        .await
                                                    {
                                                        warn!(core_id, filter = %hex::encode(&filter_owned),
                                                            error = %e, "GLOBAL_PROVER publish failed");
                                                    }
                                                });
                                            }
                                            Err(e) => warn!(core_id, error = %e,
                                                "shard finalize: bundle encode failed"),
                                        }
                                    }
                                    WorkerToMaster::FrameProduced { core_id, filter, frame_data, .. } => {
                                        // Per-shard frame bitmask = filter itself.
                                        // Self-loopback is handled in thread_worker
                                        // before we get here.
                                        if drain_halt.any_halted() {
                                            debug!(core_id, filter = %hex::encode(&filter),
                                                "suppressing shard frame publish — coverage halt active");
                                            continue;
                                        }
                                        let p2p = drain_p2p.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_frame_bitmask(&filter),
                                                    frame_data,
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "shard frame publish failed");
                                            }
                                        });
                                    }
                                    WorkerToMaster::VoteProduced { core_id, filter, vote_data } => {
                                        // Per-shard consensus bitmask = `0x00 || filter`.
                                        if drain_halt.any_halted() {
                                            debug!(core_id, filter = %hex::encode(&filter),
                                                "suppressing shard vote publish — coverage halt active");
                                            continue;
                                        }
                                        let p2p = drain_p2p.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_consensus_bitmask(&filter),
                                                    vote_data,
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "shard vote publish failed");
                                            }
                                        });
                                    }
                                    WorkerToMaster::TimeoutProduced { core_id, filter, timeout_data } => {
                                        if drain_halt.any_halted() {
                                            debug!(core_id, filter = %hex::encode(&filter),
                                                "suppressing shard timeout publish — coverage halt active");
                                            continue;
                                        }
                                        let p2p = drain_p2p.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_consensus_bitmask(&filter),
                                                    timeout_data,
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "shard timeout publish failed");
                                            }
                                        });
                                    }
                                    WorkerToMaster::ShardActivated { core_id, filter, handle } => {
                                        // Push the current halt state to the
                                        // freshly-activated engine before
                                        // registering it. Without this the
                                        // engine boots with halted=false and
                                        // happily proposes frames during a
                                        // network-wide halt window until the
                                        // next halt-state transition arrives.
                                        handle.set_halted(drain_halt.any_halted());
                                        // Register the engine handle so the
                                        // recv loop can dispatch peer
                                        // messages to it.
                                        {
                                            let mut map = drain_shard_engines.write();
                                            map.insert(filter.clone(), handle);
                                        }
                                        // Subscribe BlossomSub to the four
                                        // per-shard bitmasks. Without these
                                        // subscriptions our mesh peers won't
                                        // forward shard traffic to us, so
                                        // peer votes / proposals / frames /
                                        // dispatches never reach the engine.
                                        let p2p = drain_p2p.clone();
                                        let filter_for_sub = filter.clone();
                                        tokio::spawn(async move {
                                            p2p.subscribe(quil_engine::bitmasks::shard_frame_bitmask(&filter_for_sub)).await;
                                            p2p.subscribe(quil_engine::bitmasks::shard_consensus_bitmask(&filter_for_sub)).await;
                                            p2p.subscribe(quil_engine::bitmasks::shard_prover_bitmask(&filter_for_sub)).await;
                                            p2p.subscribe(quil_engine::bitmasks::shard_dispatch_bitmask(&filter_for_sub)).await;
                                        });
                                        info!(
                                            core_id,
                                            filter = %hex::encode(&filter),
                                            "registered shard engine + subscribed per-shard bitmasks"
                                        );
                                    }
                                    WorkerToMaster::ShardDeactivated { core_id, filter } => {
                                        {
                                            let mut map = drain_shard_engines.write();
                                            map.remove(&filter);
                                        }
                                        let p2p = drain_p2p.clone();
                                        let filter_for_sub = filter.clone();
                                        tokio::spawn(async move {
                                            p2p.unsubscribe(quil_engine::bitmasks::shard_frame_bitmask(&filter_for_sub)).await;
                                            p2p.unsubscribe(quil_engine::bitmasks::shard_consensus_bitmask(&filter_for_sub)).await;
                                            p2p.unsubscribe(quil_engine::bitmasks::shard_prover_bitmask(&filter_for_sub)).await;
                                            p2p.unsubscribe(quil_engine::bitmasks::shard_dispatch_bitmask(&filter_for_sub)).await;
                                        });
                                        info!(
                                            core_id,
                                            filter = %hex::encode(&filter),
                                            "deregistered shard engine + unsubscribed per-shard bitmasks"
                                        );
                                    }
                                    WorkerToMaster::Ready { .. }
                                    | WorkerToMaster::ShardHeartbeat { .. } => {
                                        // No-op — informational only.
                                    }
                                }
                            }
                        }
                    }
                    info!("worker→master drain task stopped");
                });
            }
            // Restore persisted worker state (manually_managed flag +
            // assigned filter) before any pre-allocation runs, so the
            // operator's intent sticks across restarts.
            //
            // Archive mode skips the restore — `set_worker_filter`
            // would otherwise spawn worker threads, and archives don't
            // run app-shard workers. A subsequent return to non-archive
            // will pick
            // them up again because we don't delete them here.
            let persisted = if archive_mode {
                if !thread_mgr.load_all_persisted().is_empty() {
                    info!("archive mode: skipping persisted worker restore");
                }
                Vec::new()
            } else {
                thread_mgr.load_all_persisted()
            };
            if !persisted.is_empty() {
                info!(
                    count = persisted.len(),
                    "restoring persisted worker state from store"
                );
                for entry in persisted {
                    // Resurrect the binding (filter pinned, no
                    // consensus engine yet — `worker_allocator` will
                    // re-attach the engine when the registry alloc
                    // for this filter is observed Active).
                    if !entry.filter.is_empty() {
                        if let Err(e) = quil_engine::worker::WorkerManager::set_worker_filter(
                            thread_mgr.as_ref(),
                            entry.core_id,
                            &entry.filter,
                            false,
                        ) {
                            warn!(
                                core_id = entry.core_id,
                                error = %e,
                                "failed to restore worker filter from store"
                            );
                        }
                    }
                    if entry.manually_managed {
                        if let Err(e) = quil_engine::worker::WorkerManager::set_manually_managed(
                            thread_mgr.as_ref(),
                            entry.core_id,
                            true,
                        ) {
                            warn!(
                                core_id = entry.core_id,
                                error = %e,
                                "failed to restore manually_managed flag"
                            );
                        }
                    }
                    if entry.pending_filter_frame > 0 {
                        let _ = quil_engine::worker::WorkerManager::set_pending_filter_frame(
                            thread_mgr.as_ref(),
                            entry.core_id,
                            entry.pending_filter_frame,
                        );
                    }
                }
            }
            thread_mgr as Arc<dyn quil_engine::worker::WorkerManager>
        };

    // Pre-allocate idle workers for each available core so they're
    // online from startup. Workers start idle (empty filter) and get
    // assigned shards by the lifecycle when join proposals are accepted.
    //
    // Archive mode skips this entirely. Per the architecture
    // (re-stated at the `frame_materializer` block below): archives
    // materialize global frames; workers materialize app-shard frames
    // — a separate role. An archive node spawning app-shard workers
    // would be every-role-at-once, which is wrong: an archive's job
    // is to retain global history and serve sync, not to compete
    // for shard rewards. The other gates (lifecycle.evaluate,
    // worker_allocator.on_new_frame) are also archive-skipped in
    // their respective call sites below.
    if !archive_mode {
        let num_cores = match worker_manager.check_workers_connected() {
            Ok(ids) => ids.len() as u32,
            Err(_) => 0,
        };
        // If no workers exist yet, create them for cores 1..N
        if num_cores == 0 {
            let total = std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4);
            let worker_count = total.saturating_sub(1).max(1); // reserve core 0 for master
            for core_id in 1..=worker_count {
                if let Err(e) = worker_manager.allocate_worker(core_id, &[]) {
                    warn!(core_id, error = %e, "failed to pre-allocate idle worker");
                }
            }
            info!(workers = worker_count, "pre-allocated idle workers");
        }
    } else {
        info!("archive mode: skipping worker pre-allocation (archives don't run app-shard workers)");
    }

    // Apply `engine.data_worker_filters` from YAML config. Runs AFTER
    // persisted-restore and idle pre-allocation:
    //   * fresh node pins config filters with manually_managed=true;
    //   * restart with prior persisted/gRPC assignment keeps it
    //     (persisted wins).
    // Skipped in archive mode for the same reason as pre-allocation.
    if !archive_mode {
        let cfg_filters = &config.engine.data_worker_filters;
        let stats = quil_engine::worker_allocator::apply_config_worker_filters(
            worker_manager.as_ref(),
            cfg_filters,
        );
        if !cfg_filters.is_empty() {
            info!(
                declared = cfg_filters.len(),
                applied = stats.applied,
                skipped_existing = stats.skipped_existing,
                skipped_missing_core = stats.skipped_missing_core,
                skipped_empty = stats.skipped_empty,
                invalid = stats.invalid,
                "applied engine.data_worker_filters"
            );
        }
    } else if !config.engine.data_worker_filters.is_empty() {
        info!(
            declared = config.engine.data_worker_filters.len(),
            "archive mode: ignoring engine.data_worker_filters (archives don't run app-shard workers)"
        );
    }

    // Publish the worker_manager handle to the PeerInfo broadcaster.
    // From this point on, every PeerInfo tick advertises a
    // per-worker reachability for each running worker with a
    // non-empty filter. Thread-mode workers (the default) share the
    // master's addresses; process-mode workers (when
    // `engine.data_worker_p2p_multiaddrs` or
    // `engine.data_worker_stream_multiaddrs` is configured) advertise
    // their own ports. See
    // `quil_p2p::peer_info::build_worker_reachability` for the
    // selection rules.
    let _ = pi_worker_manager.set(worker_manager.clone());

    // Worker allocator — reconciles registry vs running workers
    let worker_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        worker_manager.clone(),
        prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        prover_address.to_vec(),
    ));

    // Compute the config-derived seniority estimate from the mainnet
    // compat table. Uses our local libp2p peer ID plus any peer IDs
    // derived from the configs listed in
    // `engine.multisig_prover_enrollment_paths`. Result is cached on
    // the allocator; lifecycle consults it when deciding whether a
    // seniority merge would raise our on-chain seniority. Computed
    // only on mainnet (P2P.Network == 0).
    if config.p2p.network == 0 {
        let mut peer_ids: Vec<String> = Vec::new();
        let pk_bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
        if pk_bytes.len() >= 57 {
            let mut seed = [0u8; 57];
            seed.copy_from_slice(&pk_bytes[..57]);
            let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
            let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pubkey);
            peer_ids.push(bs58::encode(&peer_id).into_string());
        }
        for extra_path in &config.engine.multisig_prover_enrollment_paths {
            let path = std::path::PathBuf::from(extra_path);
            match quil_config::load_config(&path) {
                Ok(extra_cfg) => {
                    if let Ok(bytes) = hex::decode(&extra_cfg.p2p.peer_priv_key) {
                        if bytes.len() >= 57 {
                            let mut seed = [0u8; 57];
                            seed.copy_from_slice(&bytes[..57]);
                            let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
                            let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pubkey);
                            peer_ids.push(bs58::encode(&peer_id).into_string());
                        }
                    }
                }
                Err(e) => warn!(
                    path = %extra_path,
                    error = %e,
                    "could not load multisig prover enrollment config"
                ),
            }
        }
        let estimate = quil_execution::seniority_compat::get_aggregated_seniority(&peer_ids);
        worker_allocator.set_config_seniority_estimate(estimate);
        info!(
            local_peer_ids = peer_ids.len(),
            aggregated_seniority = estimate,
            "computed config-derived seniority estimate"
        );
    }

    // Proactive worker allocation reconcile — fire as soon as the
    // background prover registry refresh has data, independent of
    // any archive sync. This is the path that pulls workers out of
    // "filter pinned, consensus deferred" state on startup based on
    // the LOCALLY persisted prover registry, rather than waiting
    // for the first global frame to arrive from the archive poller
    // (which can take 5+ minutes during PeerInfo discovery).
    //
    // Archive nodes don't host app-shard workers, so skip the call
    // there — matches the gate inside the archive poller.
    if !archive_mode {
        let wa_for_init = worker_allocator.clone();
        let pr_for_init = prover_registry.clone();
        let lhf_for_init = last_global_head_frame.clone();
        let token_for_init = token.clone();
        tokio::spawn(async move {
            // The background refresh at startup is spawn_blocking and
            // typically finishes in well under a second. Poll up to
            // ~5s for `distinct_provers() > 0`; on a fresh node with
            // an empty registry this just gives up silently and the
            // archive-poller path picks it up later.
            for _ in 0..50 {
                if token_for_init.is_cancelled() { return; }
                let count = pr_for_init.read(|r| r.distinct_provers());
                if count > 0 { break; }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let frame = lhf_for_init.load(std::sync::atomic::Ordering::Relaxed);
            if frame > 0 {
                if let Err(e) = wa_for_init.on_new_frame(frame) {
                    warn!(
                        error = %e,
                        frame,
                        "early worker reconcile failed"
                    );
                } else {
                    info!(frame, "early worker reconcile complete (off local registry)");
                }
            }
        });
    }

    // Shared slot for the consensus event-loop handle, populated by the
    // sync task once a genesis frame is in the store. The receive loop
    // and lifecycle pipeline read from it to feed inbound proposals/QCs/TCs
    // back into the HotStuff event loop.
    let consensus_handle: Arc<std::sync::OnceLock<
        quil_engine::consensus_types::GlobalEventLoopHandle,
    >> = Arc::new(std::sync::OnceLock::new());

    // Per-rank vote aggregator. Populated alongside the handle by
    // `activate_consensus`. The receive loop feeds inbound
    // ProposalVote + GlobalProposal messages in so votes accumulate
    // toward a quorum certificate, which is then submitted back to
    // the event loop via the shared handle.
    let vote_aggregator: Arc<std::sync::OnceLock<
        Arc<quil_engine::vote_aggregation::VoteAggregation>,
    >> = Arc::new(std::sync::OnceLock::new());

    // Per-rank timeout aggregator. Same lifecycle as the vote aggregator
    // but for TimeoutState messages — produces TCs (and partial TCs)
    // from aggregated timeout signatures.
    let timeout_aggregator: Arc<std::sync::OnceLock<
        Arc<quil_engine::timeout_aggregation::TimeoutAggregation>,
    >> = Arc::new(std::sync::OnceLock::new());

    // Prover lifecycle coordinator — evaluates join/confirm/leave on each frame.
    // Pulls cooldown state off the WorkerAllocator (single source of truth).
    let strategy = if reward_greedy {
        quil_engine::provers::proposer::Strategy::RewardGreedy
    } else {
        quil_engine::provers::proposer::Strategy::DataGreedy
    };
    let lifecycle_inner = quil_engine::provers::lifecycle::ProverLifecycle::new(
        prover_address.to_vec(),
        worker_allocator.clone(),
        halt_state.clone(),
        current_frame.clone(),
        strategy,
    );
    // Testnet/devnet bootstraps drop the join-confirm window from
    // mainnet's 360 frames (one hour at 10s/frame) to a handful of
    // frames so a local smoke test sees a join → confirm cycle in
    // a couple of minutes. Mainnet (network = 0) keeps the full
    // 360-frame protocol value.
    // CLI `--network` is the source of truth — the YAML's `p2p.network`
    // is left at 0 in our test configs because the same files are used
    // for mainnet runs. Use the run-time-supplied `network` arg so a
    // single config file can be reused across networks.
    if network != 0 {
        const TESTNET_CONFIRM_WINDOW_FRAMES: u64 = 10;
        lifecycle_inner.set_confirm_window_frames(TESTNET_CONFIRM_WINDOW_FRAMES);
        // The lifecycle setting controls *when the local node submits*
        // a Confirm. The materializer's `validate_confirm_timing`
        // independently enforces that the recipient ledger has waited
        // long enough — its default (360..720) is mainnet-correct. For
        // testnet we have to override that window too, otherwise every
        // submitted Confirm is rejected as "must wait 360 frames after
        // join" until 360 frames have elapsed (an hour) — exactly the
        // wait the lifecycle override is meant to avoid.
        quil_execution::global_intrinsic::verify::set_confirm_window_frames(
            TESTNET_CONFIRM_WINDOW_FRAMES,
            // Use a generous upper bound so a slow follower can still
            // confirm before the window expires.
            TESTNET_CONFIRM_WINDOW_FRAMES * 72, // 720 ÷ 360 × 10 = 20 → 720
        );
        info!(
            network,
            confirm_window_frames = TESTNET_CONFIRM_WINDOW_FRAMES,
            "testnet/devnet: using shortened prover confirm window",
        );
    }
    let prover_lifecycle = Arc::new(lifecycle_inner);
    // Wire the shards store so `evaluate` can discover shards that
    // have no allocations yet — calls `RangeAppShards` on the local
    // store.
    prover_lifecycle.set_shards_store(
        shards_store.clone() as Arc<dyn quil_types::store::ShardsStore>,
    );

    // FrameMaterializer — archive nodes only. The materializer is
    // the canonical post-finalize processor for global frames:
    // commits the hypergraph, verifies the prover root, processes
    // message bundles through the execution manager, prunes orphan
    // joins, evicts inactive provers, persists alt-shard updates,
    // and publishes the post-materialize snapshot for worker sync.
    //
    // Per the architecture: archives materialize global frames;
    // workers materialize app-shard frames (a separate path);
    // non-archive masters only consume the materialized state via
    // sync from archives and do not materialize themselves.
    let frame_materializer: Option<Arc<quil_engine::frame_materializer::FrameMaterializer>> =
        if archive_mode {
            let reward_issuer: Arc<dyn quil_types::consensus::RewardIssuance> =
                Arc::new(quil_engine::OptRewardIssuance);
            // Install frame-header deps on the global intrinsic so
            // `invoke_frame_header` actually mutates state on
            // shard-coverage ingest (LastActiveFrameNumber advance +
            // reward distribution). Without this, FrameHeader bundle
            // entries silently no-op at intrinsic.rs:974-980 and
            // archives never credit prover shard work — eviction
            // and rewards would silently break.
            let bls_for_intrinsic: Arc<dyn quil_types::crypto::BlsConstructor> =
                Arc::new(quil_crypto::Bls48581KeyConstructor);
            if let Err(e) = exec_manager.install_global_frame_header_deps(
                prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                reward_issuer.clone(),
                bls_for_intrinsic,
                inclusion_prover.clone(),
                frame_prover.clone(),
            ) {
                warn!(error = %e, "install_global_frame_header_deps failed — shard coverage attribution will be a no-op");
            }
            let m = quil_engine::frame_materializer::FrameMaterializer::new(
                exec_manager.clone(),
                prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
                crdt.clone(),
                hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
                reward_issuer,
                prover_address.to_vec(),
                archive_mode,
            )
            .with_eviction_registry(prover_registry.clone())
            .with_current_frame(current_frame.clone());
            Some(Arc::new(m))
        } else {
            None
        };

    // ---------------------------------------------------------------
    // 6. Message receive loop
    // ---------------------------------------------------------------
    info!(archive = archive_mode, "master node initialized — waiting for frames");

    let clock_store_recv = clock_store.clone();
    let exec_mgr_for_recv = exec_manager.clone();
    let recv_token = token.clone();

    // Global bitmasks for BlossomSub topic subscriptions.
    const GLOBAL_CONSENSUS: &[u8] = &[0x00];
    const GLOBAL_FRAME: &[u8] = &[0x00, 0x00];
    const GLOBAL_PROVER: &[u8] = &[0x00, 0x00, 0x00];
    const GLOBAL_PEER_INFO: &[u8] = &[0x00, 0x00, 0x00, 0x00];

    // Resolve our Ed448 seed (57 bytes) for the mTLS cert. The peer key in
    // config is either 57 bytes (raw seed) or 114 bytes (seed + pubkey).
    let mtls_seed: Option<[u8; 57]> = (|| {
        let bytes = hex::decode(&config.p2p.peer_priv_key).ok()?;
        if bytes.len() < 57 {
            return None;
        }
        let mut seed = [0u8; 57];
        seed.copy_from_slice(&bytes[..57]);
        Some(seed)
    })();

    // Log Ed448 identity if available
    if let Some(ref seed) = mtls_seed {
        let ed448_pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
        let ed448_peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&ed448_pubkey);
        info!(
            ed448_peer_id = hex::encode(&ed448_peer_id),
            ed448_pubkey_len = ed448_pubkey.len(),
            "Ed448 identity ready (Go-compatible peer ID)"
        );
    }

    // Pool of *archive-capable* endpoints, populated by the BlossomSub
    // PeerInfo handler whenever it sees a peer advertising
    // ARCHIVE_SERVICE_CAPABILITY_ID. The poller spawned below picks one as
    // its source and forward-polls the chain head.
    let archive_pool = std::sync::Arc::new(quil_rpc::ArchiveEndpointPool::new());

    // Pre-seed the archive pool with the hardcoded mTLS endpoints
    // for the 5 genesis archive peers. The shard-info remote fallback
    // (and any other archive-pool consumer) needs at least one
    // reachable endpoint before the libp2p mesh converges and starts
    // delivering PeerInfo gossip. mTLS gRPC convention is TCP/8340.
    //
    // These IPs are mainnet-only — testnets/devnets have their own
    // genesis archives, which we don't seed statically (they're
    // ephemeral; PeerInfo gossip handles them).
    if network == 0 {
        let pool = archive_pool.clone();
        let static_ips = quil_engine::genesis::genesis_archive_static_ips();
        if !static_ips.is_empty() {
            tokio::spawn(async move {
                for (peer_id, ip) in static_ips {
                    let endpoint = format!("{}:8340", ip);
                    pool.add(endpoint.clone()).await;
                    tracing::debug!(
                        peer = %peer_id,
                        endpoint = %endpoint,
                        "seeded archive pool with static genesis-archive mTLS endpoint"
                    );
                }
            });
        }
    }

    // Load genesis archive peer IDs for validation (5 archives + beacon)
    let genesis_archive_peer_ids: std::collections::HashSet<Vec<u8>> = {
        let mut ids: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        // 5 archive peers
        if let Ok(peers) = quil_engine::genesis::genesis_archive_peers() {
            for (pid, _) in peers {
                if let Ok(decoded) = bs58::decode(&pid).into_vec() {
                    ids.insert(decoded);
                }
            }
        }
        // Beacon peer — derive peer ID from Ed448 key
        if let Ok(data) = quil_engine::genesis::get_mainnet_genesis_data() {
            if let Ok(ed448_key) = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &data.beacon_ed448_key,
            ) {
                // Ed448 peer ID = multihash(identity, protobuf(KeyType=4, key=ed448_bytes))
                // Protobuf: field 1 (varint) = 4, field 2 (bytes) = key
                let mut proto = vec![0x08, 0x04, 0x12, ed448_key.len() as u8];
                proto.extend_from_slice(&ed448_key);
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(&proto);
                // Multihash: 0x12 (SHA2-256) + 0x20 (32 bytes) + hash
                let mut mh = vec![0x12u8, 0x20];
                mh.extend_from_slice(&hash);
                ids.insert(mh);
            }
        }
        ids
    };
    // Valid genesis prover ADDRESSES (Poseidon(BLS pubkey)). The frame
    // header's `prover` field is the 32-byte address, not the raw key.
    // Mainnet uses embedded genesis (5 archive peers + beacon);
    // testnet/devnet uses `config.engine.genesis_seed`.
    let genesis_prover_addrs: std::collections::HashSet<Vec<u8>> = {
        let mut addrs = std::collections::HashSet::new();
        if network == 0 {
            if let Ok(data) = quil_engine::genesis::get_mainnet_genesis_data() {
                if let Ok(beacon_key) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &data.beacon_bls48581_key,
                ) {
                    if let Ok(addr) = quil_crypto::poseidon::hash_bytes_to_32(&beacon_key) {
                        addrs.insert(addr.to_vec());
                    }
                }
                for (_pid, pubkey_hex) in &data.archive_peers {
                    if let Ok(key) = hex::decode(pubkey_hex) {
                        if let Ok(addr) = quil_crypto::poseidon::hash_bytes_to_32(&key) {
                            addrs.insert(addr.to_vec());
                        }
                    }
                }
            }
        } else {
            match quil_engine::genesis::resolve_testnet_prover_keys(
                network,
                &config.engine.genesis_seed,
                &bls_pubkey,
            ) {
                Ok(keys) => {
                    for key in &keys {
                        if let Ok(addr) = quil_crypto::poseidon::hash_bytes_to_32(key) {
                            addrs.insert(addr.to_vec());
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, network = network, "could not resolve testnet genesis provers");
                }
            }
        }
        addrs
    };
    info!(
        genesis_archives = genesis_archive_peer_ids.len(),
        genesis_provers = genesis_prover_addrs.len(),
        "loaded genesis peer data for validation"
    );

    // Assemble the multisig Ed448 seed set for seniority merge helpers.
    // Always includes our local peer-private key seed; extra seeds are
    // loaded from `config.engine.multisig_prover_enrollment_paths`. The
    // pipeline signs the local BLS prover pubkey once per seed under
    // the `PROVER_SENIORITY_MERGE` domain.
    let mut multisig_ed448_seeds: Vec<[u8; 57]> = Vec::new();
    {
        let bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
        if bytes.len() >= 57 {
            let mut seed = [0u8; 57];
            seed.copy_from_slice(&bytes[..57]);
            multisig_ed448_seeds.push(seed);
        }
        for extra_path in &config.engine.multisig_prover_enrollment_paths {
            let path = std::path::PathBuf::from(extra_path);
            if let Ok(extra_cfg) = quil_config::load_config(&path) {
                if let Ok(extra_bytes) = hex::decode(&extra_cfg.p2p.peer_priv_key) {
                    if extra_bytes.len() >= 57 {
                        let mut seed = [0u8; 57];
                        seed.copy_from_slice(&extra_bytes[..57]);
                        multisig_ed448_seeds.push(seed);
                    }
                }
            }
        }
    }

    // Build the prover submission pipeline. Owned as an Arc so both the
    // poller on_frame callback and the BlossomSub message-receive loop
    // can dispatch lifecycle actions.
    // Hex-decode the configured delegate address (empty string =
    // empty Vec). A misconfigured delegate is downgraded to a warning
    // + default empty rather than aborting, so a typo doesn't take
    // the node down — emit an empty-delegate join (semantically
    // equivalent) instead of refusing to join.
    let delegate_address: Vec<u8> = {
        let raw = config.engine.delegate_address.trim();
        if raw.is_empty() {
            Vec::new()
        } else {
            match hex::decode(raw) {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(
                        delegate_address = raw,
                        %e,
                        "config.engine.delegate_address is not valid hex; \
                         defaulting to empty"
                    );
                    Vec::new()
                }
            }
        }
    };

    // Production transport: gRPC fan-out to archives + BlossomSub publish.
    let prover_message_transport: Arc<dyn quil_engine::prover_message_transport::ProverMessageTransport> =
        Arc::new(crate::prover_message_transport_prod::ProdProverMessageTransport {
            archive_pool: archive_pool.clone(),
            clock_store: clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
            p2p_handle: p2p_handle.clone(),
            ed448_seed: mtls_seed,
        });

    let prover_pipeline = Arc::new(quil_engine::prover_pipeline::ProverPipeline {
        lifecycle: prover_lifecycle.clone(),
        worker_manager: worker_manager.clone(),
        frame_prover: frame_prover.clone(),
        key_manager: file_key_manager.clone() as Arc<dyn quil_keys::KeyManager + Send + Sync>,
        bls_pubkey: bls_pubkey.clone(),
        prover_address,
        multisig_ed448_seeds,
        delegate_address,
        transport: prover_message_transport,
    });

    // Shard orchestration subscriber: watches for ShardSplitEligible /
    // ShardMergeEligible events and submits signed canonical messages
    // via the prover pipeline (the coverage-monitor → shard-orchestrator
    // handoff).
    {
        let mut rx = global_event_distributor.subscribe("shard-orchestrator");
        let pp = prover_pipeline.clone();
        let cf_for_orch = current_frame.clone();
        let cancel = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    maybe_event = rx.recv() => {
                        let Some(event) = maybe_event else { break };
                        let frame = cf_for_orch.effective();
                        if frame == 0 {
                            debug!("shard event received before any frame — ignoring");
                            continue;
                        }
                        match (event.event_type, &event.data) {
                            (
                                quil_types::consensus::ControlEventType::ShardSplitEligible,
                                quil_types::consensus::ControlEventData::ShardSplit { filter, proposed },
                            ) => {
                                let pp2 = pp.clone();
                                let shard = filter.clone();
                                let proposed = proposed.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = pp2.submit_shard_split(shard, proposed, frame).await {
                                        warn!(%e, "ShardSplit submission failed");
                                    }
                                });
                            }
                            (
                                quil_types::consensus::ControlEventType::ShardMergeEligible,
                                quil_types::consensus::ControlEventData::ShardMerge { filters, parent },
                            ) => {
                                let pp2 = pp.clone();
                                let shards = filters.clone();
                                let parent = parent.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = pp2.submit_shard_merge(shards, parent, frame).await {
                                        warn!(%e, "ShardMerge submission failed");
                                    }
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
        info!("shard orchestration subscriber spawned");
    }

    if let Some(seed) = mtls_seed {
        let exec_mgr_for_poller = exec_manager.clone();
        let wa_for_poller = worker_allocator.clone();
        let pl_for_poller = prover_lifecycle.clone();
        let pr_for_poller = prover_registry.clone();
        let wm_for_poller = worker_manager.clone();
        let cov_for_poller = coverage_monitor.clone();
        let cf_for_poller = current_frame.clone();
        let lhf_for_poller = last_global_head_frame.clone();
        let pp_for_poller = prover_pipeline.clone();
        let hg_for_poller = hg_store.clone();
        let crdt_for_poller = crdt.clone();
        let shards_store_for_poller: Arc<dyn quil_types::store::ShardsStore> =
            shards_store.clone() as Arc<dyn quil_types::store::ShardsStore>;
        let archive_mode_poller = archive_mode;
        let poller_config = quil_rpc::ArchivePollerConfig {
            on_frame: Some(Arc::new(move |frame: &quil_types::proto::global::GlobalFrame| {
                let frame_num = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
                let frame_difficulty = frame.header.as_ref().map(|h| h.difficulty).unwrap_or(0);
                // Skip bogus frames (no header or frame_number=0):
                // `current_frame.observe(0)` is a no-op, and the
                // lifecycle's evaluate guards against 0 anyway.
                if frame_num == 0 {
                    tracing::debug!(
                        "archive poller: dropping frame with frame_number=0"
                    );
                    return;
                }
                cf_for_poller.observe(frame_num);
                lhf_for_poller.fetch_max(frame_num, std::sync::atomic::Ordering::Relaxed);

                // Process frame messages through execution pipeline
                match quil_engine::frame_processor::process_global_frame(
                    &exec_mgr_for_poller,
                    frame,
                    &num_bigint::BigInt::from(1),
                ) {
                    Ok((applied, skipped)) => {
                        if applied > 0 || skipped > 0 {
                            info!(
                                frame = frame_num,
                                applied,
                                skipped,
                                "processed frame messages"
                            );
                        }
                        // After per-bundle materialize calls flushed
                        // their changesets to the in-memory CRDT (via
                        // each engine's `state.commit`), persist the
                        // resulting phase trees to the on-disk
                        // hypergraph store. Without this commit, the
                        // store still serves the previous frame's
                        // trees and the registry refresh below sees
                        // no new ProverJoin/Confirm/Leave writes.
                        if applied > 0 {
                            if let Err(e) = exec_mgr_for_poller.commit_frame(frame_num) {
                                warn!(error = %e, frame = frame_num, "hypergraph commit failed");
                            }
                            pr_for_poller.refresh_from_store(&hg_for_poller);
                        }
                    }
                    Err(e) => {
                        warn!(frame = frame_num, error = %e, "frame processing failed");
                    }
                }

                // Trigger worker allocation reconciliation. Skip in
                // archive mode — archives don't run app-shard workers,
                // so the reconciler has nothing to do and calling it
                // would resurface the no-workers-spawned-yet pathways
                // that produced phantom worker allocations on prior
                // versions.
                cov_for_poller.check(frame_num);
                if !archive_mode_poller {
                    if let Err(e) = wa_for_poller.on_new_frame(frame_num) {
                        tracing::warn!(error = %e, "worker allocation failed");
                    }
                }

                // Advance the lifecycle's "verified frame" marker. The
                // initial prover-tree sync already proved our root
                // matches the network (`commitments_match==true` —
                // see the spawn at the bottom of `main.rs`). From
                // that point on, every successfully-processed frame
                // either applies new prover messages (and our tree
                // moves with it) or is a no-op for prover state.
                // Either way we stay in sync; drift is caught by the
                // 5-minute periodic incremental sync.
                //
                // The earlier strict per-frame commitment check
                // required `crdt.commit(frame_num)` to have run AND
                // matched the frame's `prover_tree_commitment`, which
                // only happened on the rare frames where we applied
                // prover messages — leaving the lifecycle gate held
                // perpetually for non-archive nodes.
                pl_for_poller.set_prover_root_verified_frame(frame_num);

                // Refresh the lifecycle's per-filter byte-size map
                // before evaluating. Without this the proposer falls
                // back to `summary.total_size` which is a prover-
                // count proxy (sum of status_counts), not bytes —
                // joins fire on shards with no actual data, and
                // halt-risk priority can't tell apart "0 bytes
                // because empty" from "real bytes." We walk the
                // local hypergraph the same way the
                // GetShardInfo RPC does (`local_app_shard_get_sizes`).
                {
                    use std::collections::HashMap;
                    let get_sizes = quil_engine::shard_info::local_app_shard_get_sizes(
                        crdt_for_poller.clone(),
                        shards_store_for_poller.clone(),
                    );
                    let mut sizes_by_filter: HashMap<Vec<u8>, u64> = HashMap::new();
                    if let Ok(shards) = shards_store_for_poller.range_app_shards() {
                        // Dedupe to one entry per parent shard_key
                        // (range_app_shards returns one row per
                        // sub-shard).
                        let mut seen: std::collections::HashSet<Vec<u8>> =
                            std::collections::HashSet::new();
                        for s in shards {
                            if !seen.insert(s.shard_key.clone()) {
                                continue;
                            }
                            if let Ok(sub_sizes) = get_sizes(&s.shard_key, &s) {
                                for entry in sub_sizes {
                                    // `entry.size` is a big-endian
                                    // byte representation of the
                                    // shard's byte count. Saturate
                                    // at u64::MAX for absurdly large
                                    // shards rather than wrap.
                                    let mut bytes: u64 = 0;
                                    for &b in entry.size.iter() {
                                        bytes = bytes
                                            .saturating_mul(256)
                                            .saturating_add(b as u64);
                                    }
                                    if bytes == 0 {
                                        continue;
                                    }
                                    // Reconstruct the `bp` filter the
                                    // proposer keys on: L2[32] +
                                    // prefix bytes.
                                    let l2 = if s.shard_key.len() >= 35 {
                                        &s.shard_key[3..35]
                                    } else if s.shard_key.len() > 3 {
                                        &s.shard_key[3..]
                                    } else {
                                        &s.shard_key[..]
                                    };
                                    let mut bp = l2.to_vec();
                                    for &p in &entry.prefix {
                                        bp.push(p as u8);
                                    }
                                    sizes_by_filter.insert(bp, bytes);
                                }
                            }
                        }
                    }
                    pl_for_poller.set_local_shard_sizes(sizes_by_filter);
                }

                // Skip lifecycle evaluation on archives — they don't
                // propose joins/leaves, don't dispatch through the
                // prover pipeline, and the evaluate() output would
                // be ignored anyway since there are no workers to
                // bind allocations to.
                if !archive_mode_poller {
                    match pl_for_poller.evaluate(
                        frame_num,
                        frame_difficulty as u64,
                        pr_for_poller.as_ref() as &dyn quil_types::consensus::ProverRegistry,
                        wm_for_poller.as_ref(),
                    ) {
                        Ok(actions) => {
                            for action in actions {
                                tracing::info!(frame = frame_num, ?action, "prover lifecycle action");
                                pp_for_poller.dispatch(action);
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "prover lifecycle evaluation skipped");
                        }
                    }
                }
            })),
            forward_fill: archive_mode,
            ..Default::default()
        };
        quil_rpc::spawn_archive_poller(
            archive_pool.clone(),
            clock_store.clone(),
            seed,
            poller_config,
            token.clone(),
        );
        info!("archive frame poller spawned (with execution pipeline)");

        // Periodic incremental HyperSync — refreshes prover registry every ~5 minutes.
        // After initial full sync, subsequent syncs use commitment comparison
        // and only fetch changed branches (seconds instead of 9 minutes).
        {
            let sync_pool = archive_pool.clone();
            let sync_hg = hg_store.clone();
            let sync_pr = prover_registry.clone();
            let sync_token = token.clone();
            let sync_pl = prover_lifecycle.clone();
            let sync_km = file_key_manager.clone();
            let sync_cs = clock_store.clone();
            let sync_fp = frame_prover.clone();
            let sync_da = Arc::new(quil_engine::AsertDifficultyAdjuster::new(0, 0, 0));
            let sync_mc = message_collector.clone();
            let sync_bls_pub = bls_pubkey.clone();
            let sync_pa = prover_address;
            let sync_crdt = crdt.clone();
            let sync_p2p = p2p_handle.clone();
            let sync_ch = consensus_handle.clone();
            let sync_va = vote_aggregator.clone();
            let sync_ta = timeout_aggregator.clone();
            let sync_cov = coverage_monitor.clone();
            let sync_cf = current_frame.clone();
            let sync_lhf = last_global_head_frame.clone();
            let sync_archive_mode = archive_mode;
            let sync_db_for_consensus: Arc<dyn quil_types::store::KvDb> = db_arc.clone();
            tokio::spawn(async move {
                // Archive nodes ARE the source of truth — they don't wait
                // for some other archive to be discovered before activating
                // consensus. Without this bypass, a fresh testnet bootstrap
                // (every node `--archive` and starting from genesis at
                // frame 0) deadlocks: each node waits for an archive to
                // appear in the pool, but the pool only fills when peers
                // exchange PeerInfo with `archive_mode=true`, and PeerInfo
                // exchange happens after consensus is up. Skip the wait +
                // remote-sync entirely; the local store already holds
                // genesis from `establish_testnet_genesis_provers`.
                if !sync_archive_mode {
                    // Wait for initial archive discovery before starting
                    loop {
                        if sync_token.is_cancelled() { return; }
                        if sync_pool.len().await > 0 { break; }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }

                // Initial full sync — skipped when we're an archive
                // since the local genesis path already populated the
                // hypergraph store with the prover tree.
                let mut initial_sync_data_ok = sync_archive_mode;
                if !sync_archive_mode {
                    if let Some(addr) = sync_pool.get_all().await.first() {
                        info!("starting initial prover tree sync");
                        // Initial bootstrap sync — no verified frame
                        // yet to pin against. Empty expected_root
                        // means "trust the archive's latest snapshot".
                        // Subsequent periodic syncs DO pin against the
                        // most-recent verified frame's
                        // prover_tree_commitment.
                        match quil_rpc::ensure_prover_tree(
                            addr, &seed,
                            quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
                            sync_hg.clone(),
                            &[],
                        ).await {
                            Ok(_) => {
                                initial_sync_data_ok = true;
                            }
                            Err(e) => {
                                warn!(error = %e, "initial prover tree sync failed; lifecycle gate stays held");
                            }
                        }
                    // Refresh prover registry from synced data
                    let pr = sync_pr.clone();
                    let hs2 = sync_hg.clone();
                    if let Err(e) = tokio::task::spawn_blocking(move || {
                        pr.refresh_from_store(&hs2);
                    }).await {
                        warn!(error = %e, "prover registry refresh failed");
                    }
                    // Reconstruct coverage streaks from synced prover
                    // data once at startup, before any frame-driven check.
                    // Without this, the first eviction pass after a
                    // restart would interpret all previously-stale
                    // allocations as freshly inactive and kick them
                    // immediately.
                    {
                        let pr_for_streak = sync_pr.clone();
                        let cov = sync_cov.clone();
                        let cur_frame = sync_lhf.load(std::sync::atomic::Ordering::Relaxed);
                        let _ = tokio::task::spawn_blocking(move || {
                            match (pr_for_streak.as_ref() as &dyn quil_types::consensus::ProverRegistry)
                                .get_all_active_app_shard_provers()
                            {
                                Ok(provers) => {
                                    cov.reconstruct_streaks(&provers, cur_frame);
                                    info!(
                                        provers = provers.len(),
                                        current_frame = cur_frame,
                                        "reconstructed coverage streaks"
                                    );
                                }
                                Err(e) => warn!(
                                    error = %e,
                                    "could not reconstruct coverage streaks"
                                ),
                            }
                        }).await;
                    }
                    } // end of `if let Some(addr) { ... }`
                } // end of `if !sync_archive_mode { ... }`
                // Only flip the lifecycle gate when we actually have
                // prover-tree data to evaluate against. On a fresh
                // wipe with no reachable archive (or sync error), the
                // local registry is empty — toggling sync_complete
                // here would let the lifecycle propose joins for
                // every shard before we know what we already own.
                if initial_sync_data_ok {
                    sync_pl.set_sync_complete();
                    info!("initial prover tree sync complete, lifecycle enabled");
                } else {
                    warn!(
                        "no prover-tree data available; lifecycle gate held — \
                         will retry via the periodic sync task"
                    );
                }

                    // Check if we're an active prover and build genesis QC.
                    // Try the latest QC's candidate frame first (an
                    // unfinalized rank-N candidate that the network
                    // never committed but a QC was already formed on
                    // — typical at the head of a chain mid-round).
                    // Falling back to the latest *committed* global
                    // frame would seed the forks tree at rank N-1,
                    // leaving the leader at rank N+1 unable to find
                    // the parent state and consensus stuck timing out.
                    let genesis_frame_result = {
                        use quil_types::store::ClockStore;
                        let cs_trait: &dyn ClockStore = sync_cs.as_ref();
                        let latest_qc = cs_trait.get_latest_quorum_certificate(&[]);
                        match &latest_qc {
                            Ok(qc) => info!(
                                rank = qc.rank,
                                frame_number = qc.frame_number,
                                selector = %hex::encode(&qc.selector),
                                "bootstrap: latest QC in store",
                            ),
                            Err(e) => warn!(
                                error = %e,
                                "bootstrap: no latest QC in store",
                            ),
                        }
                        let candidate = latest_qc.ok().and_then(|qc| {
                            match cs_trait
                                .get_global_clock_frame_candidate(qc.frame_number, &qc.selector)
                            {
                                Ok(frame) => Some(frame),
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        rank = qc.rank,
                                        frame_number = qc.frame_number,
                                        selector = %hex::encode(&qc.selector),
                                        "bootstrap: candidate frame lookup failed — falling back to committed",
                                    );
                                    None
                                }
                            }
                        });
                        match candidate {
                            Some(frame) => {
                                info!(
                                    rank = frame.header.as_ref().map(|h| h.rank).unwrap_or(0),
                                    frame_number = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0),
                                    "bootstrapping from latest QC candidate frame",
                                );
                                Ok(frame)
                            }
                            None => sync_cs.get_latest_global_frame()
                                .or_else(|_| {
                                    info!("no global frame in store, loading embedded mainnet genesis");
                                    quil_engine::genesis::load_mainnet_genesis()
                                }),
                        }
                    };

                    // Only nodes registered as global provers (i.e. with
                    // an allocation on the empty filter) should run the
                    // global consensus event loop. A non-global prover
                    // joining mid-stream subscribes to GLOBAL_CONSENSUS
                    // for awareness, but feeding inbound proposals into
                    // a local HotStuff loop crashes on "missing parent
                    // state at rank N" because we never saw ranks 1..N-1.
                    // Mainnet genesis-frame provers and testnet seed
                    // provers both qualify; config6-style joining nodes
                    // do not until ConfirmJoins flips their allocation
                    // to Active (at which point a future activation
                    // path can spin up the loop).
                    let is_global_prover: bool = {
                        use quil_types::consensus::ProverRegistry;
                        match sync_pr.get_prover_info(&sync_pa) {
                            Ok(Some(info)) => info
                                .allocations
                                .iter()
                                .any(|a| a.confirmation_filter.is_empty()),
                            _ => false,
                        }
                    };
                    if !is_global_prover {
                        if sync_archive_mode {
                            info!(
                                "archive mode — skipping global consensus event loop activation \
                                 (archives observe global frames via the poller, not via consensus)",
                            );
                        } else {
                            info!(
                                "not a global prover — skipping global consensus event loop activation",
                            );
                        }
                    } else if genesis_frame_result.is_ok() {
                        if let Ok(genesis_frame) = genesis_frame_result {
                            if let Ok(bls_signer) = sync_km.get_signer(quil_types::crypto::KeyType::Bls48581G1) {
                                let publisher: Arc<dyn quil_engine::consensus_glue::ConsensusPublisher> =
                                    Arc::new(BlossomsubConsensusPublisher {
                                        p2p_handle: sync_p2p.clone(),
                                        loopback_tx: consensus_loopback_tx.clone(),
                                        self_peer_id: peer_id.to_bytes(),
                                    });
                                // Build an on-finalized hook that prunes per-rank
                                // aggregator state below the finalized watermark.
                                // Captures the OnceLocks so the callback stays valid
                                // even though the aggregators are populated later
                                // in this same activation (finalization can't fire
                                // before the event loop runs).
                                let finalized_hook: quil_engine::consensus_glue::FinalizedStateHook = {
                                    let va_cell = sync_va.clone();
                                    let ta_cell = sync_ta.clone();
                                    let cs_for_fin = sync_cs.clone();
                                    let cf_for_fin = sync_cf.clone();
                                    let lhf_for_fin = sync_lhf.clone();
                                    let materializer_for_fin = frame_materializer.clone();
                                    let cov_for_fin = sync_cov.clone();
                                    Arc::new(move |state| {
                                        if let Some(va) = va_cell.get() {
                                            va.advance_min_active_rank(state.rank);
                                        }
                                        if let Some(ta) = ta_cell.get() {
                                            ta.advance_min_active_rank(state.rank);
                                        }
                                        // Persist the finalized frame to the
                                        // canonical clock-store path so:
                                        //   1. archive nodes report a real
                                        //      `last_global_head_frame` in
                                        //      PeerInfo (rather than 0),
                                        //   2. peers can fetch the frame via
                                        //      gRPC through the archive pool,
                                        //   3. the archive_poller's per-frame
                                        //      execution pipeline + lifecycle
                                        //      evaluator runs at all (it's
                                        //      driven by `get_latest_global_clock_frame`).
                                        // Without this hook, every node's
                                        // status block reads `frame: 0`
                                        // forever even though Forks contains
                                        // 100+ finalized states.
                                        let app = &state.state;
                                        let header = quil_types::proto::global::GlobalFrameHeader {
                                            frame_number: app.frame_number,
                                            rank: app.rank,
                                            timestamp: app.timestamp,
                                            difficulty: app.difficulty,
                                            output: app.output.clone(),
                                            parent_selector: app.parent_selector.clone(),
                                            prover: app.prover.clone(),
                                            prover_tree_commitment: app.prover_tree_commitment.clone(),
                                            requests_root: app.requests_root.clone(),
                                            ..Default::default()
                                        };
                                        let frame = quil_types::proto::global::GlobalFrame {
                                            header: Some(header),
                                            // Carry the proposal's message bundles
                                            // through to the persisted frame so the
                                            // materializer sees them on finalization.
                                            requests: app.messages.clone(),
                                        };
                                        struct NoTxn;
                                        impl quil_types::store::Transaction for NoTxn {
                                            fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
                                            fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn new_iter(
                                                &self,
                                                _: &[u8],
                                                _: &[u8],
                                            ) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
                                                Err(quil_types::error::QuilError::NotFound("noop".into()))
                                            }
                                            fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn as_any(&self) -> &dyn std::any::Any { self }
                                        }
                                        let no_txn = NoTxn;
                                        let cs_trait: &dyn quil_types::store::ClockStore = cs_for_fin.as_ref();
                                        if let Err(e) = cs_trait.put_global_clock_frame(&frame, &no_txn) {
                                            tracing::warn!(
                                                error = %e,
                                                frame = app.frame_number,
                                                rank = app.rank,
                                                "failed to persist finalized frame",
                                            );
                                        }
                                        // Bump head-frame atomics so PeerInfo
                                        // advertises the real chain head.
                                        // `observe` / `fetch_max` keep these
                                        // monotonic even if finalization
                                        // callbacks arrive out of order.
                                        cf_for_fin.observe(app.frame_number);
                                        lhf_for_fin.fetch_max(
                                            app.frame_number,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );

                                        // Archive nodes materialize the
                                        // finalized global frame: commit the
                                        // hypergraph, verify the prover root,
                                        // process bundles through execution,
                                        // prune orphan joins, evict inactive
                                        // provers, persist alt-shard updates,
                                        // and publish the post-materialize
                                        // snapshot for workers + non-archive
                                        // peers to sync against. Non-archive
                                        // master threads skip this (their
                                        // `materializer_for_fin` is None);
                                        // they pull materialized state from
                                        // archives via the archive poller.
                                        if let Some(m) = &materializer_for_fin {
                                            // Refresh halt durations right
                                            // before materialize so the
                                            // eviction step inside skips
                                            // halted shards correctly.
                                            let halts = cov_for_fin.check(app.frame_number);
                                            m.set_coverage_halt_durations(halts);
                                            if let Err(e) = m.materialize(&frame) {
                                                tracing::warn!(
                                                    error = %e,
                                                    frame = app.frame_number,
                                                    "frame materialize failed"
                                                );
                                            }
                                        }
                                    })
                                };

                                // When a state is incorporated into forks (before
                                // finalization), persist its frame as a candidate
                                // in the clock store so the leader can chain a
                                // rank+1 proposal on top of it via
                                // `prove_next_state` -> `get_global_clock_frame_candidate`.
                                let incorporated_hook: quil_engine::consensus_glue::IncorporatedStateHook = {
                                    let cs = sync_cs.clone();
                                    Arc::new(move |state| {
                                        let app = &state.state;
                                        let header = quil_types::proto::global::GlobalFrameHeader {
                                            frame_number: app.frame_number,
                                            rank: app.rank,
                                            timestamp: app.timestamp,
                                            difficulty: app.difficulty,
                                            output: app.output.clone(),
                                            parent_selector: app.parent_selector.clone(),
                                            prover: app.prover.clone(),
                                            prover_tree_commitment: app.prover_tree_commitment.clone(),
                                            requests_root: app.requests_root.clone(),
                                            ..Default::default()
                                        };
                                        let frame = quil_types::proto::global::GlobalFrame {
                                            header: Some(header),
                                            requests: Vec::new(),
                                        };
                                        // No transaction context here — pass a
                                        // no-op transaction shim. The clock
                                        // store's candidate writer doesn't
                                        // require atomicity with anything else.
                                        struct NoTxn;
                                        impl quil_types::store::Transaction for NoTxn {
                                            fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
                                            fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn new_iter(
                                                &self,
                                                _: &[u8],
                                                _: &[u8],
                                            ) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
                                                Err(quil_types::error::QuilError::NotFound("noop".into()))
                                            }
                                            fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn as_any(&self) -> &dyn std::any::Any { self }
                                        }
                                        let no_txn = NoTxn;
                                        let cs_trait: &dyn quil_types::store::ClockStore = cs.as_ref();
                                        let identity = quil_crypto::poseidon::hash_bytes_to_32(&app.output)
                                            .map(hex::encode)
                                            .unwrap_or_else(|_| "<poseidon-failed>".into());
                                        match cs_trait.put_global_clock_frame_candidate(&frame, &no_txn) {
                                            Ok(()) => tracing::info!(
                                                frame = app.frame_number,
                                                rank = app.rank,
                                                identity = %identity,
                                                "persisted candidate frame",
                                            ),
                                            Err(e) => tracing::warn!(
                                                error = %e,
                                                frame = app.frame_number,
                                                rank = app.rank,
                                                identity = %identity,
                                                "failed to persist candidate frame",
                                            ),
                                        }
                                    })
                                };

                                // When the consumer observes a fresh QC (from
                                // local aggregation or wire receive), persist
                                // it to the clock store so the leader's
                                // `prove_next_state` for rank+1 finds the
                                // correct latest QC.
                                let qc_observed_hook: quil_engine::consensus_glue::QcObservedHook = {
                                    let cs = sync_cs.clone();
                                    Arc::new(move |qc| {
                                        // NoTxn shim — clock store's QC writer
                                        // doesn't require atomicity with
                                        // anything else here.
                                        struct NoTxn2;
                                        impl quil_types::store::Transaction for NoTxn2 {
                                            fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
                                            fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn new_iter(
                                                &self,
                                                _: &[u8],
                                                _: &[u8],
                                            ) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
                                                Err(quil_types::error::QuilError::NotFound("noop".into()))
                                            }
                                            fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn as_any(&self) -> &dyn std::any::Any { self }
                                        }
                                        // Build a proto QC from the trait
                                        // object's fields.
                                        let proto_qc = quil_types::proto::global::QuorumCertificate {
                                            filter: qc.filter().to_vec(),
                                            rank: qc.rank(),
                                            frame_number: qc.frame_number(),
                                            selector: qc.identity().clone(),
                                            timestamp: qc.timestamp(),
                                            aggregate_signature: Some(
                                                quil_types::proto::keys::Bls48581AggregateSignature {
                                                    signature: qc.aggregated_signature().signature().to_vec(),
                                                    public_key: Some(
                                                        quil_types::proto::keys::Bls48581g2PublicKey {
                                                            key_value: qc.aggregated_signature().public_key().to_vec(),
                                                        },
                                                    ),
                                                    bitmask: qc.aggregated_signature().bitmask().to_vec(),
                                                },
                                            ),
                                        };
                                        let no_txn = NoTxn2;
                                        let cs_trait: &dyn quil_types::store::ClockStore = cs.as_ref();
                                        if let Err(e) = cs_trait.put_quorum_certificate(&proto_qc, &no_txn) {
                                            tracing::debug!(
                                                error = %e,
                                                rank = qc.rank(),
                                                "failed to persist QC",
                                            );
                                        }
                                    })
                                };
                                // Load the persisted QC for the trusted
                                // root's rank so the pacemaker boots
                                // with a real BLS-aggregated QC instead
                                // of a zero-signature stub (which peers
                                // would reject on signature verify).
                                let trusted_rank_for_qc: u64 = genesis_frame
                                    .header
                                    .as_ref()
                                    .map(|h| h.rank)
                                    .unwrap_or(0);
                                let genesis_qc_override = {
                                    use quil_types::store::ClockStore;
                                    let cs_trait: &dyn ClockStore = sync_cs.as_ref();
                                    match cs_trait.get_quorum_certificate(&[], trusted_rank_for_qc) {
                                        Ok(qc_proto) => {
                                            info!(
                                                rank = qc_proto.rank,
                                                frame_number = qc_proto.frame_number,
                                                "seeding consensus with persisted QC",
                                            );
                                            Some(quil_engine::consensus_wire::QuorumCertificate::from_proto(&qc_proto))
                                        }
                                        Err(e) => {
                                            warn!(
                                                rank = trusted_rank_for_qc,
                                                error = %e,
                                                "no persisted QC at trusted rank — \
                                                 falling back to stub genesis QC \
                                                 (peers will reject embedded QC)",
                                            );
                                            None
                                        }
                                    }
                                };
                                match quil_engine::consensus_activation::activate_consensus(
                                    quil_engine::consensus_activation::ConsensusActivationParams {
                                        prover_registry: sync_pr.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                                        frame_prover: sync_fp.clone(),
                                        difficulty_adjuster: sync_da.clone() as Arc<dyn quil_types::consensus::DifficultyAdjuster>,
                                        clock_store: sync_cs.clone() as Arc<dyn quil_types::store::ClockStore>,
                                        message_collector: sync_mc.clone(),
                                        local_prover_address: sync_pa.to_vec(),
                                        local_bls_pubkey: sync_bls_pub.clone(),
                                        bls_signer,
                                        inclusion_prover: Arc::new(quil_types::crypto::NoopInclusionProver)
                                            as Arc<dyn quil_types::crypto::InclusionProver + Send + Sync>,
                                        genesis_frame,
                                        publisher: Some(publisher),
                                        on_finalized_state: Some(finalized_hook),
                                        on_incorporated_state: Some(incorporated_hook),
                                        on_qc_observed: Some(qc_observed_hook),
                                        config_override: None,
                                        genesis_qc_override,
                                        // Persist consensus + liveness
                                        // state in the node's RocksDB so
                                        // finalized_rank / latest_qc
                                        // survive restarts (without this
                                        // a restart can re-vote for a
                                        // conflicting QC).
                                        kv_db: Some(sync_db_for_consensus.clone()),
                                    },
                                ) {
                                    Ok(activation) => {
                                        if sync_ch.set(activation.handle).is_err() {
                                            warn!("consensus event loop already activated once");
                                        } else {
                                            // Publish VoteAggregation state so the
                                            // receive loop can feed ProposalVote +
                                            // proposal messages into the per-rank
                                            // collectors. Uses the same committee/
                                            // voting provider/vote domain built
                                            // inside activation to guarantee byte-
                                            // identical signature verification.
                                            let bls_ctor: Arc<dyn quil_types::crypto::BlsConstructor> =
                                                Arc::new(quil_crypto::Bls48581KeyConstructor);
                                            let va = Arc::new(
                                                quil_engine::vote_aggregation::VoteAggregation::new(
                                                    activation.committee.clone(),
                                                    activation.voting_provider.clone(),
                                                    sync_ch.clone(),
                                                    bls_ctor.clone(),
                                                    activation.vote_domain.clone(),
                                                ),
                                            );
                                            let ta = Arc::new(
                                                quil_engine::timeout_aggregation::TimeoutAggregation::new(
                                                    activation.committee,
                                                    activation.voting_provider,
                                                    sync_ch.clone(),
                                                    bls_ctor,
                                                    activation.vote_domain,
                                                    activation.timeout_domain,
                                                ),
                                            );
                                            // Seed the aggregators' min_active_rank
                                            // to the bootstrap rank. Without this they
                                            // sit at 0 and the `rank > min + MAX_RANK_LOOKAHEAD`
                                            // guard drops every peer vote/timeout for a
                                            // chain that has already advanced more than
                                            // 1024 ranks past genesis — symptom: the
                                            // leader proposes, peers presumably vote, but
                                            // the aggregator silently discards every
                                            // vote and the chain perpetual-times-out.
                                            va.advance_min_active_rank(trusted_rank_for_qc);
                                            ta.advance_min_active_rank(trusted_rank_for_qc);
                                            info!(
                                                bootstrap_rank = trusted_rank_for_qc,
                                                "seeded vote + timeout aggregator min_active_rank",
                                            );
                                            let va_ok = sync_va.set(va).is_ok();
                                            let ta_ok = sync_ta.set(ta).is_ok();
                                            if va_ok && ta_ok {
                                                info!("consensus event loop started, handle + vote/timeout aggregators published");
                                            } else {
                                                warn!(va_ok, ta_ok, "aggregators already set");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "consensus activation failed");
                                    }
                                }
                            }
                        }
                    }

                // Periodic incremental sync every 5 minutes
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            // Archives have full history locally — they
                            // don't need to incremental-sync the prover
                            // tree from peers, and on a fresh post-
                            // migration topology this just trades "no
                            // tree data available" errors with other
                            // freshly-migrated archives.
                            if sync_archive_mode {
                                continue;
                            }
                            if let Some(addr) = sync_pool.get_all().await.first() {
                                // Snapshot the local reward balance before the
                                // sync pulls fresh leaves. Compared against the
                                // post-sync balance to surface credits that
                                // arrived via peer data (i.e. not driven by
                                // local `apply_reward`).
                                let pre_balance = quil_execution::global_intrinsic::prover_shard_update::
                                    read_reward_balance_for(&sync_crdt, &sync_pa)
                                    .unwrap_or_else(|_| num_bigint::BigInt::from(0));
                                // Pin the sync to the latest verified
                                // frame's prover_tree_commitment.
                                // Without this, a malicious archive
                                // could serve a self-consistent fake
                                // snapshot at any root — the post-sync
                                // server-claim match only proves
                                // internal consistency, not authority.
                                let expected_root = sync_cs
                                    .get_latest_global_frame()
                                    .ok()
                                    .and_then(|f| f.header.map(|h| h.prover_tree_commitment))
                                    .unwrap_or_default();
                                match quil_rpc::ensure_prover_tree_incremental(
                                    addr, &seed,
                                    quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
                                    sync_hg.clone(),
                                    &expected_root,
                                ).await {
                                    Ok(stats) => {
                                        if stats.leaves_pulled > 0 {
                                            info!(
                                                leaves_pulled = stats.leaves_pulled,
                                                match_ok = stats.commitments_match,
                                                "incremental prover tree sync complete"
                                            );
                                            // Refresh registry with updated data
                                            let pr = sync_pr.clone();
                                            let hs3 = sync_hg.clone();
                                            let _ = tokio::task::spawn_blocking(move || pr.refresh_from_store(&hs3)).await;

                                            // Compare reward balance for the
                                            // local prover before/after; log
                                            // when it changed so the operator
                                            // sees synced-in credits.
                                            let post_balance = quil_execution::global_intrinsic::prover_shard_update::
                                                read_reward_balance_for(&sync_crdt, &sync_pa)
                                                .unwrap_or_else(|_| num_bigint::BigInt::from(0));
                                            if post_balance != pre_balance {
                                                let delta = &post_balance - &pre_balance;
                                                info!(
                                                    prover = %hex::encode(&sync_pa),
                                                    delta = %delta,
                                                    new_balance = %post_balance,
                                                    "local prover reward balance updated by sync"
                                                );
                                            }
                                        } else {
                                            debug!("incremental sync: tree unchanged");
                                        }
                                        // Recovery path: if the initial sync at
                                        // startup failed (no archive reachable
                                        // yet, transient error), the lifecycle
                                        // gate stayed held. Unblock it now that
                                        // we have data.
                                        sync_pl.set_sync_complete();
                                    }
                                    Err(e) => warn!(error = %e, "incremental prover tree sync failed"),
                                }
                            }
                        }
                        _ = sync_token.cancelled() => break,
                    }
                }
            });
            info!("periodic prover tree sync task spawned (5-minute interval)");
        }

        // Periodic archive-direct shard info refresh. Drives the
        // lifecycle's `ProposeJoin`/`ProposeLeave` gate: until the
        // first successful `GetAppShards` response lands, the
        // lifecycle short-circuits all auto-pick paths. After that,
        // every 60 frames (~10 min on mainnet) we refresh — frame-
        // anchored so a stalled chain doesn't burn endpoints.
        //
        // Distinct from `LocalShardInfoProvider`'s dial-out fallback:
        // that path is "try local first." For auto-allocation we
        // require archive-sourced sizes because the local node may
        // not have visibility into shards it isn't a member of.
        {
            let pool = archive_pool.clone();
            let lifecycle = prover_lifecycle.clone();
            let cf_for_refresh = current_frame.clone();
            let cancel = token.clone();
            let seed_for_refresh = seed;
            let shards_store_for_refresh = shards_store.clone();
            tokio::spawn(async move {
                const REFRESH_CADENCE_FRAMES: u64 = 60;
                let mut last_refresh_frame: u64 = 0;
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                interval.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Skip,
                );
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = interval.tick() => {}
                    }
                    let now_frame = cf_for_refresh.effective();
                    let needs_initial = !lifecycle.shard_info_loaded();
                    let cadence_due = last_refresh_frame > 0
                        && now_frame >= last_refresh_frame + REFRESH_CADENCE_FRAMES;
                    if !needs_initial && !cadence_due {
                        continue;
                    }
                    match quil_rpc::fetch_shard_sizes_from_archive(
                        &pool,
                        &seed_for_refresh,
                        shards_store_for_refresh.as_ref(),
                        None,
                    )
                    .await
                    {
                        Ok(sizes) => {
                            let count = sizes.len();
                            lifecycle.set_remote_shard_sizes(sizes);
                            last_refresh_frame = now_frame.max(1);
                            info!(
                                shards = count,
                                frame = now_frame,
                                initial = needs_initial,
                                "shard_info refresh: cache updated"
                            );
                        }
                        Err(quil_rpc::ShardInfoRefreshError::PoolEmpty) => {
                            // Archive pool not yet populated by PeerInfo
                            // gossip — log at debug, retry next tick.
                            tracing::debug!("shard_info refresh: archive pool empty, retrying");
                        }
                        Err(quil_rpc::ShardInfoRefreshError::NoLocalShards) => {
                            // Local shards-store empty — genesis not
                            // yet seeded, or the wrong network ID.
                            tracing::debug!("shard_info refresh: local shards-store empty, retrying");
                        }
                        Err(e) => {
                            warn!(error = %e, "shard_info refresh failed (will retry)");
                        }
                    }
                }
                info!("shard_info refresh task stopped");
            });
            info!("shard_info refresh task spawned (frame-anchored, 60-frame cadence)");
        }
    } else {
        warn!("no Ed448 seed available — archive poller disabled (production archives require mTLS)");
    }

    // Broadcast channel for GlobalService::StreamGlobalMessages.
    // Construction here (before recv loop) so the recv loop can
    // feed it; the gRPC server takes a clone later.
    let global_msg_tx: tokio::sync::broadcast::Sender<
        quil_types::proto::global::StreamGlobalMessagesResponse,
    > = tokio::sync::broadcast::channel(
        quil_rpc::global_service::GLOBAL_MESSAGE_BROADCAST_CAPACITY,
    )
    .0;
    let gmtx_for_recv = global_msg_tx.clone();

    let pool_for_recv = archive_pool.clone();
    let mtls_seed_for_recv: Option<[u8; 57]> = mtls_seed;
    let hg_store_for_recv = hg_store.clone();
    let frame_validator_for_recv = frame_validator;
    let mc_for_recv = message_collector.clone();
    let coverage_for_recv = coverage_monitor.clone();
    let wa_for_recv = worker_allocator.clone();
    let pp_for_recv = prover_pipeline.clone();
    let ch_for_recv = consensus_handle.clone();
    let va_for_recv = vote_aggregator.clone();
    let ta_for_recv = timeout_aggregator.clone();
    let pic_for_recv = peer_info_cache.clone();
    let shard_engines_for_recv = shard_engines.clone();
    let sr_for_recv = signer_registry.clone();
    let cf_for_recv = current_frame.clone();
    let lhf_for_recv = last_global_head_frame.clone();
    let genesis_archive_peer_ids_for_recv = genesis_archive_peer_ids.clone();
    let genesis_prover_addrs_for_recv = genesis_prover_addrs.clone();
    // Mainnet validates archive-capability claims against the
    // hardcoded genesis archive peer IDs. Testnet/devnet bootstraps
    // can't use that list (those keys aren't theirs), so the receive
    // loop accepts any archive-claiming peer when network != 0.
    // Use the CLI-supplied network value (`--network`); the YAML's
    // `p2p.network` field is left at 0 in shared configs.
    let network_for_recv: u8 = network;
    let archive_mode_for_recv: bool = archive_mode;
    let pl_for_recv = prover_lifecycle.clone();
    let pr_for_recv = prover_registry.clone();
    let wm_for_recv = worker_manager.clone();
    let archive_mode_recv = archive_mode;
    let reward_issuer = Arc::new(quil_engine::OptRewardIssuance);
    let pa_for_recv = prover_address;
    let p2p_for_recv = p2p_handle.clone();

    // Per-bitmask validator gate. Malformed bytes are dropped here so
    // the dispatch loop below stays cheap. Topics without a registered
    // validator fall through unchanged.
    let message_router = Arc::new(quil_engine::message_router::MessageRouter::new());
    message_router.register_validator(
        GLOBAL_PEER_INFO.to_vec(),
        quil_engine::message_router::validator_global_peer_info(),
    );
    message_router.register_validator(
        GLOBAL_PROVER.to_vec(),
        quil_engine::message_router::validator_global_prover(),
    );
    message_router.register_validator(
        GLOBAL_FRAME.to_vec(),
        quil_engine::message_router::validator_global_frame(),
    );
    message_router.register_validator(
        GLOBAL_CONSENSUS.to_vec(),
        quil_engine::message_router::validator_global_consensus(),
    );
    let router_for_recv = message_router.clone();

    tokio::spawn(async move {
        let mut frames_received: u64 = 0;
        let mut peer_infos_received: u64 = 0;
        let mut archive_peers_seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut consensus_msgs_received: u64 = 0;
        let mut prover_msgs_received: u64 = 0;
        let mut router_drops: u64 = 0;
        let mut status_timer = tokio::time::interval(std::time::Duration::from_secs(30));
        status_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = status_timer.tick() => {
                    // Periodic allocation status snapshot.
                    let peer_count = p2p_for_recv.peer_count();
                    let latest_frame = clock_store_recv.get_latest_global_frame()
                        .ok()
                        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
                        .unwrap_or(0);
                    let (active, pending, total_allocs) = {
                        use quil_types::consensus::{EffectiveStatus, ProverRegistry};
                        match pr_for_recv.get_prover_info(&pa_for_recv) {
                            Ok(Some(info)) => {
                                let mut a = 0usize;
                                let mut p = 0usize;
                                let mut total = 0usize;
                                for alloc in &info.allocations {
                                    match alloc.effective_status(latest_frame) {
                                        EffectiveStatus::Active => {
                                            a += 1;
                                            total += 1;
                                        }
                                        EffectiveStatus::Joining => {
                                            p += 1;
                                            total += 1;
                                        }
                                        EffectiveStatus::Paused | EffectiveStatus::Leaving => {
                                            total += 1;
                                        }
                                        _ => {}
                                    }
                                }
                                (a, p, total)
                            }
                            _ => (0, 0, 0),
                        }
                    };
                    info!(
                        peers = peer_count,
                        frame = latest_frame,
                        frames_received,
                        active_shards = active,
                        pending_joins = pending,
                        total_allocations = total_allocs,
                        peer_infos = peer_infos_received,
                        archive_peers = archive_peers_seen.len(),
                        consensus_msgs = consensus_msgs_received,
                        prover_msgs = prover_msgs_received,
                        router_drops,
                        "node status"
                    );
                }
                msg = async {
                    // Merge the network receive channel and the
                    // self-loopback channel — both produce
                    // `ReceivedMessage`s that go through the same
                    // dispatch logic. This is how the proposer's own
                    // proposal reaches its own `vote_aggregator` and
                    // event_loop without relying on BlossomSub
                    // self-echo (which doesn't happen).
                    tokio::select! {
                        biased;
                        m = consensus_loopback_rx.recv() => m,
                        m = msg_rx.recv() => m,
                    }
                } => {
                    match msg {
                        Some(received) => {
                            // Fan out every received global message to
                            // any connected StreamGlobalMessages
                            // subscriber. Send failure (no subscribers)
                            // is benign and ignored.
                            let _ = gmtx_for_recv.send(
                                quil_types::proto::global::StreamGlobalMessagesResponse {
                                    data: received.data.clone(),
                                    bitmask: received.bitmask.clone(),
                                },
                            );

                            // Per-topic validator gate. Malformed bytes are
                            // dropped before they reach a queue.
                            // Unregistered topics fall through.
                            if !router_for_recv
                                .route(&received.bitmask, &received.data)
                                .should_dispatch()
                            {
                                router_drops += 1;
                                if router_drops <= 5 || router_drops % 1000 == 0 {
                                    debug!(
                                        bitmask = %hex::encode(&received.bitmask),
                                        len = received.data.len(),
                                        total_dropped = router_drops,
                                        "router validator dropped message",
                                    );
                                }
                                continue;
                            }

                            match received.bitmask.as_slice() {
                            GLOBAL_PEER_INFO => {
                                match quil_p2p::classify_peer_info_message(&received.data) {
                                    Ok(quil_p2p::PeerInfoMessage::PeerInfo(info)) => {
                                        peer_infos_received += 1;
                                        // Cache last-seen PeerInfo per peer_id. Bounded
                                        // implicitly by the peer set size (last-write-wins).
                                        if !info.peer_id.is_empty() {
                                            let mut cache = pic_for_recv.write();
                                            cache.insert(info.peer_id.clone(), info.clone());
                                        }
                                        // Only ARCHIVE-capable peers go into the
                                        // poll pool. Plain peers reject every
                                        // GetGlobalFrame call with "not currently
                                        // syncable".
                                        if info.is_archive() {
                                            // Validate against genesis archive peers.
                                            // The peer_id in PeerInfo is raw bytes;
                                            // genesis has base58 peer IDs. Convert
                                            // PeerInfo peer_id to hex for comparison
                                            // against genesis BLS pubkey hashes.
                                            let peer_hex = bs58::encode(&info.peer_id).into_string();
                                            // On testnet/devnet (network != 0) the genesis
                                            // archive list isn't ours, so we accept any
                                            // archive-claiming peer. Mainnet keeps the
                                            // strict allowlist check below.
                                            let is_genesis_archive = network_for_recv != 0
                                                || genesis_archive_peer_ids_for_recv
                                                    .contains(&info.peer_id);
                                            if !is_genesis_archive {
                                                warn!(
                                                    peer = peer_hex,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "FAKE ARCHIVE — peer claims archive capability but is not a genesis archive peer"
                                                );
                                                continue;
                                            }
                                            let is_new = archive_peers_seen.insert(info.peer_id.clone());
                                            if is_new {
                                                info!(
                                                    peer = peer_hex,
                                                    head_frame = info.last_global_head_frame,
                                                    total = archive_peers_seen.len(),
                                                    "verified genesis archive peer"
                                                );
                                            }
                                            let mut first_addr: Option<String> = None;
                                            for reach in &info.reachability {
                                                for ma in &reach.stream_multiaddrs {
                                                    if let Some(addr) = multiaddr_to_host_port_with_network(ma, network_for_recv) {
                                                        if first_addr.is_none() {
                                                            first_addr = Some(addr.clone());
                                                        }
                                                        pool_for_recv.add(addr).await;
                                                    }
                                                }
                                            }
                                            info!(
                                                peer = bs58::encode(&info.peer_id).into_string(),
                                                head_frame = info.last_global_head_frame,
                                                total_archives = archive_peers_seen.len(),
                                                "discovered archive peer"
                                            );
                                            // First archive: sync all four
                                            // CRDT phases of the global
                                            // prover tree sequentially. Each
                                            // ensure_prover_tree call either
                                            // loads the cached blob from
                                            // RocksDB or pulls + verifies +
                                            // persists from this archive.
                                            // Skip in archive mode — archives
                                            // have full history locally and
                                            // the legacy whole-tree blob
                                            // sync path isn't populated by
                                            // migrated stores (per-vertex
                                            // data at `0x30` is, but blob
                                            // cache at `0x2F` is not), so
                                            // calling this against another
                                            // archive that's also fresh
                                            // from migration just trades
                                            // "no tree data available"
                                            // errors back and forth.
                                            if is_new && archive_peers_seen.len() == 1
                                                && !archive_mode_for_recv {
                                                if let (Some(seed), Some(addr)) =
                                                    (mtls_seed_for_recv, first_addr)
                                                {
                                                    let store = hg_store_for_recv.clone();
                                                    let cs = clock_store_recv.clone();
                                                    tokio::spawn(async move {
                                                        use quil_types::proto::application::HypergraphPhaseSet::*;
                                                        // Pin sync against the most-recent verified
                                                        // frame's prover_tree_commitment (when
                                                        // available). Empty during bootstrap before
                                                        // any frame is stored.
                                                        let expected_root = cs
                                                            .get_latest_global_frame()
                                                            .ok()
                                                            .and_then(|f| f.header.map(|h| h.prover_tree_commitment))
                                                            .unwrap_or_default();
                                                        for phase in [VertexAdds, VertexRemoves, HyperedgeAdds, HyperedgeRemoves] {
                                                            match quil_rpc::ensure_prover_tree(
                                                                &addr,
                                                                &seed,
                                                                phase,
                                                                store.clone(),
                                                                &expected_root,
                                                            ).await {
                                                                Ok(stats) => {
                                                                    info!(
                                                                        addr = %addr,
                                                                        ?phase,
                                                                        matched = stats.commitments_match,
                                                                        leaves = stats.leaves_pulled,
                                                                        "phase sync complete"
                                                                    );
                                                                }
                                                                Err(e) => {
                                                                    warn!(addr = %addr, ?phase, error = %e, "ensure_prover_tree failed");
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                        info!("all 4 phases synced");

                                                        // Build the in-memory ProverRegistry
                                                        // from the persisted vertex store.
                                                        let mut registry =
                                                            quil_execution::InMemoryProverRegistry::new();
                                                        registry.refresh(&store);
                                                        info!(
                                                            provers_visited = registry.provers_visited(),
                                                            allocations_visited = registry.allocations_visited(),
                                                            rewards_visited = registry.rewards_visited(),
                                                            distinct_provers = registry.distinct_provers(),
                                                            distinct_filters = registry.distinct_filters(),
                                                            "prover registry refreshed"
                                                        );

                                                        // Sample a few active provers.
                                                        let all_active =
                                                            registry.get_all_active_app_shard_provers();
                                                        info!(
                                                            active_count = all_active.len(),
                                                            "active prover count from registry"
                                                        );
                                                        for prover in all_active.iter().take(3) {
                                                            info!(
                                                                address = %hex::encode(&prover.address),
                                                                seniority = prover.seniority,
                                                                available_storage = prover.available_storage,
                                                                allocations = prover.allocations.len(),
                                                                "  active prover"
                                                            );
                                                        }
                                                    });
                                                }
                                            }
                                        } else if peer_infos_received <= 5
                                            || peer_infos_received % 100 == 0
                                        {
                                            info!(
                                                total_peer_infos = peer_infos_received,
                                                total_archives = archive_peers_seen.len(),
                                                "PeerInfo discovery progress"
                                            );
                                        }
                                    }
                                    Ok(quil_p2p::PeerInfoMessage::KeyRegistry) => {
                                        // Decode and stash in the signer registry so
                                        // consensus-message BLS signatures from the
                                        // announcing peer can later be verified using
                                        // the prover key bound to its Ed448 identity.
                                        // Older-timestamp replays are ignored inside
                                        // `SignerRegistry::update`.
                                        match quil_p2p::decode_canonical_key_registry(&received.data) {
                                            Ok(reg) => {
                                                let identity_len = reg.ed448_pubkey.len();
                                                let prover_len = reg.bls_pubkey.len();
                                                sr_for_recv.update(reg);
                                                debug!(
                                                    identity_len,
                                                    prover_len,
                                                    total_entries = sr_for_recv.len(),
                                                    "ingested KeyRegistry"
                                                );
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "failed to decode KeyRegistry");
                                            }
                                        }
                                    }
                                    Ok(quil_p2p::PeerInfoMessage::Unknown(prefix)) => {
                                        warn!(prefix = format!("0x{:04x}", prefix),
                                            "unknown PEER_INFO bitmask message type");
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "failed to decode PeerInfo");
                                    }
                                }
                            }
                            GLOBAL_FRAME => {
                                // Try canonical bytes first (the wire format),
                                // fall back to proto decode (archive poller uses proto).
                                let frame_result: std::result::Result<quil_types::proto::global::GlobalFrame, _> =
                                    quil_engine::consensus_wire::decode_global_frame(&received.data)
                                        .or_else(|canonical_err| {
                                            warn!(error = %canonical_err, "canonical decode failed, trying proto");
                                            prost::Message::decode(received.data.as_slice())
                                                .map_err(|e| quil_types::error::QuilError::InvalidArgument(
                                                    format!("failed to decode Protobuf message: {} (canonical: {})", e, canonical_err)
                                                ))
                                        });
                                match frame_result {
                                    Ok(frame) => {
                                        let frame_num = frame.header.as_ref()
                                            .map(|h| h.frame_number).unwrap_or(0);

                                        // Validate prover is a genesis prover
                                        if let Some(h) = frame.header.as_ref() {
                                            if !genesis_prover_addrs_for_recv.contains(&h.prover) {
                                                warn!(
                                                    frame = frame_num,
                                                    prover = hex::encode(&h.prover),
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "INVALID PROVER — not a genesis prover, possible attacker"
                                                );
                                                continue;
                                            }
                                        }

                                        // Verify VDF proof before storing.
                                        // Wrap in catch_unwind — the classgroup can panic
                                        // on malformed VDF output from canonical decode bugs.
                                        let validate_result = std::panic::catch_unwind(
                                            std::panic::AssertUnwindSafe(|| frame_validator_for_recv.validate(&frame))
                                        );
                                        match validate_result {
                                            Ok(Ok(true)) => {}
                                            Ok(Ok(false)) => {
                                                // Validator returned false — either VDF or BLS
                                                // signature check rejected it. The specific
                                                // reason is logged by `GlobalFrameVerifier::validate`.
                                                warn!(frame = frame_num, "frame rejected by validator — dropping");
                                                continue;
                                            }
                                            Ok(Err(e)) => {
                                                warn!(frame = frame_num, error = %e, "VDF validation error — dropping frame");
                                                continue;
                                            }
                                            Err(_) => {
                                                warn!(
                                                    frame = frame_num,
                                                    output_len = frame.header.as_ref().map(|h| h.output.len()).unwrap_or(0),
                                                    "VDF validation PANIC — frame output likely corrupted, dropping"
                                                );
                                                continue;
                                            }
                                        }

                                        match clock_store_recv.put_global_frame(&frame, None) {
                                            Ok(()) => {
                                                frames_received += 1;
                                                // `observe` / `fetch_max` never
                                                // regress these counters below
                                                // an already-seen value (e.g.
                                                // if a stale duplicate frame
                                                // arrives out-of-order via
                                                // BlossomSub).
                                                cf_for_recv.observe(frame_num);
                                                lhf_for_recv.fetch_max(frame_num, std::sync::atomic::Ordering::Relaxed);
                                                // Process through execution pipeline with reward issuance
                                                match quil_engine::frame_processor::process_global_frame_with_rewards(
                                                    &exec_mgr_for_recv,
                                                    &frame,
                                                    &num_bigint::BigInt::from(1),
                                                    Some(reward_issuer.as_ref() as &dyn quil_types::consensus::RewardIssuance),
                                                    Some(pr_for_recv.as_ref() as &dyn quil_types::consensus::ProverRegistry),
                                                ) {
                                                    Ok((applied, skipped)) => {
                                                        info!(
                                                            frame = frame_num,
                                                            total = frames_received,
                                                            applied,
                                                            skipped,
                                                            "received + processed GlobalFrame"
                                                        );
                                                        // Trigger coverage check + worker allocation
                                                        // (skip the reconciler on archives — they
                                                        // don't run app-shard workers).
                                                        coverage_for_recv.check(frame_num);
                                                        if !archive_mode_recv {
                                                            if let Err(e) = wa_for_recv.on_new_frame(frame_num) {
                                                                warn!(error = %e, "worker allocation failed");
                                                            }
                                                        }
                                                        // Evaluate prover lifecycle (join/confirm/leave) and
                                                        // dispatch any resulting action via the pipeline.
                                                        // Archives skip — no workers to bind allocations to
                                                        // and no shard reward to chase.
                                                        let frame_difficulty = frame.header.as_ref()
                                                            .map(|h| h.difficulty)
                                                            .unwrap_or(0);
                                                        // Once initial prover-tree sync proved
                                                        // commitment match, advance the
                                                        // verified-frame marker on every
                                                        // successfully-handled frame. See poller
                                                        // path for rationale.
                                                        pl_for_recv.set_prover_root_verified_frame(frame_num);
                                                        if !archive_mode_recv {
                                                            match pl_for_recv.evaluate(
                                                                frame_num,
                                                                frame_difficulty as u64,
                                                                pr_for_recv.as_ref(),
                                                                wm_for_recv.as_ref(),
                                                            ) {
                                                                Ok(actions) => {
                                                                    for action in actions {
                                                                        info!(frame = frame_num, ?action, "prover lifecycle action");
                                                                        pp_for_recv.dispatch(action);
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    debug!(error = %e, "prover lifecycle evaluation skipped");
                                                                }
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        info!(
                                                            frame = frame_num,
                                                            total = frames_received,
                                                            error = %e,
                                                            "received GlobalFrame (processing failed)"
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "failed to store frame");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let prefix = if received.data.len() >= 8 {
                                            hex::encode(&received.data[..8])
                                        } else {
                                            hex::encode(&received.data)
                                        };
                                        warn!(
                                            error = %e,
                                            bytes = received.data.len(),
                                            prefix = %prefix,
                                            "GLOBAL_FRAME decode failed"
                                        );
                                    }
                                }
                            }
                            GLOBAL_CONSENSUS => {
                                consensus_msgs_received += 1;
                                let current_rank = frames_received;
                                mc_for_recv.add_message(current_rank, received.data.clone());
                                // Route inbound consensus messages to the event
                                // loop handle (populated once activation completes).
                                if let Some(handle) = ch_for_recv.get() {
                                    if let Some(tp) = quil_engine::consensus_wire::peek_consensus_type(&received.data) {
                                        match tp {
                                            quil_engine::consensus_wire::GLOBAL_PROPOSAL_TYPE => {
                                                match quil_engine::consensus_wire::GlobalProposal::from_canonical_bytes(&received.data) {
                                                    Ok(wire) => {
                                                        match quil_engine::consensus_types::wire_proposal_to_signed(wire) {
                                                            Ok((sp, qc, _tc)) => {
                                                                handle.submit_quorum_certificate(qc);
                                                                // Skip pre-submitting the
                                                                // proposal's
                                                                // `previous_rank_timeout_certificate`.
                                                                // Same hazard as the TimeoutState
                                                                // path below: an unvalidated TC
                                                                // would land in the pacemaker's
                                                                // newest-TC tracker and be
                                                                // embedded into our own next
                                                                // outgoing timeout. Validation
                                                                // happens later in
                                                                // `validate_proposal` →
                                                                // `validate_timeout_certificate`,
                                                                // and a real TC will surface via
                                                                // the local timeout aggregator's
                                                                // `on_tc_created` callback once
                                                                // enough peer timeouts arrive.
                                                                // Feed into the rank's vote collector
                                                                // so the proposer's self-vote counts
                                                                // toward quorum and subsequent
                                                                // standalone votes get verified.
                                                                if let Some(agg) = va_for_recv.get() {
                                                                    agg.handle_proposal(&sp);
                                                                }
                                                                let h = handle.clone();
                                                                tokio::spawn(async move {
                                                                    h.submit_proposal(sp).await;
                                                                });
                                                            }
                                                            Err(e) => warn!(error = %e, "GlobalProposal bridge failed"),
                                                        }
                                                    }
                                                    Err(e) => warn!(error = %e, "GlobalProposal decode failed"),
                                                }
                                            }
                                            quil_engine::consensus_wire::PROPOSAL_VOTE_TYPE => {
                                                // Route standalone votes into the per-rank aggregator.
                                                // On reaching quorum, the aggregator's
                                                // OnQuorumCertificateCreated callback fires
                                                // `handle.submit_quorum_certificate`.
                                                match quil_engine::consensus_wire::ProposalVote::from_canonical_bytes(&received.data) {
                                                    Ok(wire) => {
                                                        if let Some(agg) = va_for_recv.get() {
                                                            let gv = quil_engine::vote_aggregation::wire_vote_to_global_vote(wire);
                                                            agg.handle_vote(gv);
                                                        }
                                                    }
                                                    Err(e) => warn!(error = %e, "ProposalVote decode failed"),
                                                }
                                            }
                                            quil_engine::consensus_wire::TIMEOUT_STATE_TYPE => {
                                                match quil_engine::consensus_wire::TimeoutState::from_canonical_bytes(&received.data) {
                                                    Ok(ts) => {
                                                        // Fast-forward the newest-QC tracker.
                                                        // Safe: bad QCs fail later validation.
                                                        let qc_for_handle = ts.latest_quorum_certificate.clone().into_trait_object();
                                                        handle.submit_quorum_certificate(qc_for_handle);
                                                        // DO NOT auto-submit the embedded
                                                        // `prior_rank_timeout_certificate` —
                                                        // a malformed TC would land in our
                                                        // pacemaker's newest-TC tracker and
                                                        // get embedded into our next timeout,
                                                        // which peers then reject. Outgoing
                                                        // TCs source from clock store
                                                        // (previously validated). Local
                                                        // aggregation forms a valid TC once
                                                        // peer timeouts arrive.
                                                        if let Some(agg) = ta_for_recv.get() {
                                                            let typed = quil_engine::timeout_aggregation::wire_timeout_to_typed(ts);
                                                            agg.handle_timeout(typed);
                                                        }
                                                    }
                                                    Err(e) => warn!(error = %e, "TimeoutState decode failed"),
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            GLOBAL_PROVER => {
                                prover_msgs_received += 1;
                                let current_rank = frames_received;
                                mc_for_recv.add_message(current_rank, received.data.clone());
                            }
                            _ => {
                                // Per-shard routing: if the bitmask matches one
                                // of the four bitmasks for an active shard
                                // engine on this node, forward the bytes to
                                // the engine via its `AppEngineHandle`. The
                                // worker thread loops own messages back via
                                // `app_handle.send(...)`, so we must not also
                                // route self-published messages here — the
                                // BlossomSub mesh already drops self-echoes.
                                let bm = received.bitmask.as_slice();
                                // Snapshot the active filter set under the read
                                // lock, then drop it before doing per-handle
                                // sends (the channel is bounded; sends are
                                // try_send).
                                let entries: Vec<(Vec<u8>, quil_engine::app_engine::AppEngineHandle)> = {
                                    let map = shard_engines_for_recv.read();
                                    map.iter()
                                        .map(|(f, h)| (f.clone(), h.clone()))
                                        .collect()
                                };
                                let mut routed = false;
                                for (filter, handle) in &entries {
                                    if bm == quil_engine::bitmasks::shard_consensus_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Consensus(received.data.clone()));
                                        routed = true;
                                        break;
                                    }
                                    if bm == quil_engine::bitmasks::shard_frame_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Frame(received.data.clone()));
                                        routed = true;
                                        break;
                                    }
                                    if bm == quil_engine::bitmasks::shard_prover_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Prover(received.data.clone()));
                                        routed = true;
                                        break;
                                    }
                                    if bm == quil_engine::bitmasks::shard_dispatch_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Dispatch(received.data.clone()));
                                        routed = true;
                                        break;
                                    }
                                }
                                if !routed {
                                    // Non-shard traffic (e.g. mesh relay) — no local handler.
                                }
                            }
                            }
                        }
                        None => {
                            info!("message channel closed");
                            break;
                        }
                    }
                }
                _ = recv_token.cancelled() => {
                    break;
                }
            }
        }
        info!(
            frames = frames_received,
            peer_infos = peer_infos_received,
            "message receiver stopped"
        );
    });

    // ---------------------------------------------------------------
    // 7. gRPC service
    // ---------------------------------------------------------------
    {
        let grpc_addr = if config.listen_grpc_multiaddr.is_empty() {
            "0.0.0.0:8337".to_string()
        } else {
            let parts: Vec<&str> = config.listen_grpc_multiaddr
                .trim_start_matches('/')
                .split('/')
                .collect();
            if parts.len() >= 4 && parts[0] == "ip4" && parts[2] == "tcp" {
                format!("{}:{}", parts[1], parts[3])
            } else {
                "0.0.0.0:8337".to_string()
            }
        };

        // Bridge RocksClockStore to the FrameLookup trait
        struct ClockStoreFrameLookup(Arc<quil_store::RocksClockStore>);
        impl quil_rpc::FrameLookup for ClockStoreFrameLookup {
            fn get_latest_frame(&self) -> Result<quil_types::proto::global::GlobalFrame, String> {
                self.0.get_latest_global_frame().map_err(|e| e.to_string())
            }
            fn get_frame(&self, n: u64) -> Result<quil_types::proto::global::GlobalFrame, String> {
                self.0.get_global_frame(n).map_err(|e| e.to_string())
            }
        }
        // Submit handler: peers that submit a MessageBundle via gRPC
        // (`ArchiveClient::submit_global_message`) get their payload
        // routed into the same MessageCollector that BlossomSub
        // GLOBAL_PROVER traffic feeds.
        //
        // Peer identity is extracted by `peer_auth_interceptor` from
        // the TLS client cert's SAN (if any) and attached to the
        // request as `AuthenticatedPeer`. Here we gate the write: no
        // authenticated peer → reject with "unauthenticated peer".
        // Plaintext connections or connections without a parseable
        // Ed448-derived cert fall into that path.
        let submit_mc = message_collector.clone();
        let submit_cf = current_frame.clone();
        let submit_handler: quil_rpc::SubmitHandler = Arc::new(
            move |request: tonic::Request<quil_types::proto::global::SubmitGlobalMessageRequest>| {
                let auth = request
                    .extensions()
                    .get::<quil_rpc::peer_auth_middleware::AuthenticatedPeer>()
                    .cloned();
                let Some(auth) = auth else {
                    quil_engine::metrics::inc_grpc_submits_rejected();
                    return Err("unauthenticated peer — submit requires a valid Ed448 client cert".into());
                };
                let data = request.into_inner().data;
                if data.is_empty() {
                    quil_engine::metrics::inc_grpc_submits_rejected();
                    return Err("empty payload".into());
                }
                let rank = submit_cf.effective();
                let accepted = submit_mc.add_message(rank, data);
                if accepted {
                    tracing::debug!(peer = %auth.peer_id, rank, "accepted gRPC submit");
                    quil_engine::metrics::inc_grpc_submits_accepted();
                    Ok(())
                } else {
                    quil_engine::metrics::inc_grpc_submits_rejected();
                    Err("message collector rejected".into())
                }
            },
        );
        // ShardsStore: serves GlobalService::GetAppShards.
        let shards_store: Arc<dyn quil_types::store::ShardsStore> =
            Arc::new(quil_store::RocksShardsStore::new(db_arc.inner()));

        // Worker snapshot fn for GlobalService::GetWorkerInfo.
        let global_worker_snap: quil_rpc::global_service::WorkerSnapshotFn = {
            let wm = worker_manager.clone();
            Arc::new(move || {
                quil_engine::worker::WorkerView::snapshot(wm.as_ref())
                    .all
                    .into_iter()
                    .map(|w| quil_types::proto::global::GlobalGetWorkerInfoResponseItem {
                        core_id: w.core_id,
                        listen_multiaddr: String::new(),
                        stream_listen_multiaddr: String::new(),
                        filter: w.filter.clone(),
                        total_storage: w.total_storage,
                        allocated: !w.filter.is_empty(),
                    })
                    .collect()
            })
        };

        // GlobalShardsProvider: walks the 4 phase trees for a given
        // shard key and returns per-phase (commit, size_be, leaf_count).
        let global_shards_provider: quil_rpc::global_service::GlobalShardsProvider = {
            let store = hg_store.clone();
            let prover = inclusion_prover.clone();
            Arc::new(move |l1: &[u8; 3], l2: &[u8; 32]| {
                let shard = quil_types::store::ShardKey { l1: *l1, l2: *l2 };
                let phases = [
                    ("vertex", "adds"),
                    ("vertex", "removes"),
                    ("hyperedge", "adds"),
                    ("hyperedge", "removes"),
                ];
                let mut out: [(Vec<u8>, Vec<u8>, u64); 4] = [
                    (vec![0u8; 64], Vec::new(), 0),
                    (vec![0u8; 64], Vec::new(), 0),
                    (vec![0u8; 64], Vec::new(), 0),
                    (vec![0u8; 64], Vec::new(), 0),
                ];
                for (i, (set, phase)) in phases.iter().enumerate() {
                    let Ok(Some(blob)) = store.load_tree_blob(set, phase, &shard) else {
                        continue;
                    };
                    let Ok(Some(root)) = quil_tries::deserialize_tree(&blob) else {
                        continue;
                    };
                    let mut tree = quil_tries::VectorCommitmentTree::new();
                    tree.root = Some(root);
                    tree.commit(prover.as_ref());
                    if let Some(node) = tree.root.as_ref() {
                        match node {
                            quil_tries::VectorCommitmentNode::Branch(b) => {
                                out[i] = (
                                    b.commitment.clone(),
                                    b.size.to_signed_bytes_be(),
                                    b.leaf_count as u64,
                                );
                            }
                            quil_tries::VectorCommitmentNode::Leaf(l) => {
                                out[i] = (
                                    l.commitment.clone(),
                                    l.size.to_signed_bytes_be(),
                                    1,
                                );
                            }
                        }
                    }
                }
                out
            })
        };

        // AppShardsProvider: for each (shard_key, prefix), derive size
        // / data_shards / commitments from the live VertexAdds tree via
        // `app_shard_metadata::get_app_shard_metadata`. Without this,
        // `GetAppShards` returns `size=0` for every entry (the
        // shards-store on Rust persists only the prefix path bytes),
        // and a polling node's lifecycle silently drops every join
        // candidate (`build_proposal_descriptors` requires size>0).
        let app_shards_provider: quil_rpc::global_service::AppShardsProvider = {
            let crdt = crdt.clone();
            Arc::new(move |shard_key: &[u8], prefix: &[u32]| {
                let info = quil_types::store::ShardInfo {
                    shard_key: shard_key.to_vec(),
                    prefix: prefix.to_vec(),
                    size: Vec::new(),
                    data_shards: 0,
                    commitment: Vec::new(),
                };
                let meta = quil_engine::app_shard_metadata::get_app_shard_metadata(
                    crdt.as_ref(),
                    &info,
                )?;
                Some((meta.size, meta.data_shards, meta.commitments))
            })
        };

        let grpc_server = quil_rpc::GlobalRpcServer::new(
            Arc::new(ClockStoreFrameLookup(clock_store.clone())),
        )
        .with_submit_handler(submit_handler.clone())
        .with_shards_store(shards_store.clone())
        .with_worker_snapshot(global_worker_snap)
        .with_global_shards_provider(global_shards_provider)
        .with_app_shards_provider(app_shards_provider)
        .with_message_broadcast(global_msg_tx.clone());
        let hypersync = quil_rpc::hypersync_server::HyperSyncServer::new(hg_store.clone());

        // NodeService: user-facing RPC for CLI tools. Unlike
        // GlobalService/HypergraphComparisonService (peer-to-peer), this
        // one serves wallet queries, admin controls, and message
        // submission. Its submit_message handler shares the same
        // message-collector path as the gRPC global submit.
        let node_submit_mc = message_collector.clone();
        let node_submit_cf = current_frame.clone();
        let user_submit_handler: quil_rpc::node_service::UserSubmitHandler = Arc::new(
            move |data: Vec<u8>| -> Result<(), String> {
                if data.is_empty() {
                    return Err("empty message".into());
                }
                let rank = node_submit_cf.effective();
                if node_submit_mc.add_message(rank, data) {
                    Ok(())
                } else {
                    Err("message collector rejected".into())
                }
            },
        );
        let mut node_rpc_builder = quil_rpc::NodeRpcServer::new()
            .with_peer_id(peer_id.to_string())
            .with_frame_counters(
                current_frame.clone(),
                last_global_head_frame.clone(),
            )
            .with_prover_address(prover_address.to_vec())
            .with_reachable(true)
            .with_token_store(token_store.clone() as Arc<dyn quil_types::store::TokenStore>)
            .with_prover_registry(
                prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
            )
            .with_clock_store(clock_store.clone() as Arc<dyn quil_types::store::ClockStore>)
            .with_hypergraph_store(
                hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            )
            .with_submit_handler(user_submit_handler);
        if let Some(h) = metrics_handle.clone() {
            node_rpc_builder = node_rpc_builder.with_metrics_renderer(Arc::new(move || h.render()));
        }
        // PeerInfo snapshot reader — drains the cache into a Vec on demand.
        {
            let pic = peer_info_cache.clone();
            node_rpc_builder = node_rpc_builder.with_peer_info_snapshot(Arc::new(move || {
                pic.read().values().cloned().collect()
            }));
        }
        {
            let p2p_handle_for_score = p2p_handle.clone();
            let self_peer_id_for_score = p2p_handle.peer_id;
            node_rpc_builder = node_rpc_builder.with_peer_score_provider(Arc::new(move || {
                let h = p2p_handle_for_score.clone();
                let pid = self_peer_id_for_score;
                Box::pin(async move { h.get_peer_score(pid).await })
            }));
        }

        // Traversal proof generator: look up the tree blob for
        // (domain, atom_type, phase_type), deserialize, run
        // prove_multiple against the requested keys, and return
        // canonical bytes.
        {
            let store = hg_store.clone();
            let prover_for_tp = inclusion_prover.clone();
            let gen: quil_rpc::TraversalProofGenerator = Arc::new(
                move |domain: [u8; 32], atom: String, phase: String, keys: Vec<Vec<u8>>| -> Result<Vec<u8>, String> {
                    if keys.is_empty() {
                        return Err("keys must be non-empty".into());
                    }
                    let shard = quil_types::store::ShardKey {
                        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&domain, 256, 3),
                        l2: domain,
                    };
                    let blob = store
                        .load_tree_blob(&atom, &phase, &shard)
                        .map_err(|e| format!("load_tree_blob: {e}"))?
                        .ok_or_else(|| "tree not found for domain".to_string())?;
                    let root = quil_tries::deserialize_tree(&blob)
                        .map_err(|e| format!("deserialize: {e}"))?
                        .ok_or_else(|| "empty tree".to_string())?;
                    let mut tree = quil_tries::VectorCommitmentTree::new();
                    tree.root = Some(root);
                    // Refresh commitments after load.
                    tree.commit(prover_for_tp.as_ref());
                    let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
                    let proof = tree
                        .prove_multiple(prover_for_tp.as_ref(), &key_refs)
                        .ok_or_else(|| "no keys matched in tree".to_string())?;
                    Ok(proof.to_bytes())
                },
            );
            node_rpc_builder = node_rpc_builder.with_traversal_proof_generator(gen);
        }

        // Send handler: verify Ed448 authentication over the payload
        // under the NODE_AUTHENTICATION||domain context, then route
        // the payload to the correct BlossomSub bitmask. The pubkey
        // is taken from the keystore's `q-peer-key` so qclient (which
        // signs with that same key) authenticates correctly. Falls
        // back to deriving from `mtls_seed` if the key isn't present.
        let (peer_ed448_pub, peer_key_source): (Option<Vec<u8>>, &'static str) =
            match file_key_manager.get_signer_by_id("q-peer-key") {
                Ok(s) => (Some(s.public_key().to_vec()), "keystore q-peer-key"),
                Err(e) => {
                    tracing::warn!(error = %e, "q-peer-key not loaded; Send will fall back to mtls_seed");
                    match mtls_seed.as_ref() {
                        Some(seed) => (
                            Some(quil_p2p::ed448_identity::derive_public_key(seed)),
                            "config.p2p.peer_priv_key (mtls_seed)",
                        ),
                        None => (None, ""),
                    }
                }
            };
        if let Some(peer_ed448_pub) = peer_ed448_pub {
            tracing::info!(
                pubkey_prefix = %hex::encode(&peer_ed448_pub[..peer_ed448_pub.len().min(8)]),
                pubkey_len = peer_ed448_pub.len(),
                source = peer_key_source,
                "Send authentication pubkey wired"
            );
            let send_p2p = p2p_handle.clone();
            let send_handler: quil_rpc::SendHandler = Arc::new(
                move |domain: Vec<u8>, payload: Vec<u8>, authentication: Vec<u8>|
                -> std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<(), String>> + Send>,
                > {
                    let p2p = send_p2p.clone();
                    let ed448_pub = peer_ed448_pub.clone();
                    Box::pin(async move {
                        if domain.len() != 32 {
                            return Err("domain must be 32 bytes".into());
                        }
                        if payload.is_empty() {
                            return Err("empty payload".into());
                        }
                        // SignWithDomain signs `prefix || body` with an
                        // empty Ed448 context — passing the prefix as
                        // the RFC 8032 ctx wouldn't verify.
                        let mut digest = Vec::with_capacity(19 + 32 + payload.len());
                        digest.extend_from_slice(b"NODE_AUTHENTICATION");
                        digest.extend_from_slice(&domain);
                        digest.extend_from_slice(&payload);
                        let pk = ed448_rust::PublicKey::try_from(ed448_pub.as_slice())
                            .map_err(|e| format!("bad pubkey: {:?}", e))?;
                        if let Err(e) = pk.verify(&digest, &authentication, None) {
                            // Hex of the first/last 16 bytes of the
                            // signed payload — enough to verify the
                            // type prefix (0x0312) and trailing
                            // timestamp + sig envelope without
                            // dumping the entire (possibly large)
                            // body. Cross-checks against qclient's
                            // own log if it dumps its bundle.
                            let head_n = payload.len().min(16);
                            let tail_n = payload.len().saturating_sub(16);
                            tracing::warn!(
                                pubkey = %hex::encode(&ed448_pub),
                                payload_len = payload.len(),
                                payload_head = %hex::encode(&payload[..head_n]),
                                payload_tail = %hex::encode(&payload[tail_n..]),
                                auth_len = authentication.len(),
                                auth_prefix = %hex::encode(&authentication[..authentication.len().min(8)]),
                                domain = %hex::encode(&domain),
                                error = ?e,
                                "Send Ed448 verify failed"
                            );
                            return Err(format!("authentication failed: {:?}", e));
                        }

                        // Route: global domain → GLOBAL_PROVER, else bloom-
                        // filter indices.
                        let bitmask: Vec<u8> = if domain.iter().all(|&b| b == 0xff) {
                            quil_engine::bitmasks::GLOBAL_PROVER.to_vec()
                        } else {
                            quil_hypergraph::addressing::get_bloom_filter_indices(&domain, 256, 3)
                                .to_vec()
                        };
                        p2p.publish(bitmask, payload)
                            .await
                            .map_err(|e| format!("p2p publish failed: {}", e))?;
                        Ok(())
                    })
                },
            );
            node_rpc_builder = node_rpc_builder.with_send_handler_fn(send_handler);
        }
        // Worker control bridge: NodeService admin operations
        // (set_manually_managed, request_join) route into the live
        // WorkerManager + prover pipeline.
        struct WorkerControlBridge {
            worker_manager: Arc<dyn quil_engine::worker::WorkerManager>,
            prover_pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
            current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
        }
        impl quil_rpc::WorkerControl for WorkerControlBridge {
            fn set_manually_managed(
                &self,
                core_id: u32,
                manually_managed: bool,
            ) -> Result<(), String> {
                self.worker_manager
                    .set_manually_managed(core_id, manually_managed)
                    .map_err(|e| e.to_string())
            }

            fn request_join<'a>(
                &'a self,
                filters: Vec<Vec<u8>>,
                worker_ids: Vec<u32>,
                _delegate: Vec<u8>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
            > {
                let pp = self.prover_pipeline.clone();
                let wm = self.worker_manager.clone();
                let frame = self.current_frame.effective();
                Box::pin(async move {
                    if frame == 0 {
                        return Err("no frames received yet".into());
                    }
                    if filters.is_empty() {
                        return Err("filters must be non-empty".into());
                    }

                    // Pre-pin the target workers synchronously. The
                    // reconciler then matches each landing allocation
                    // to its intended worker via filter, instead of
                    // arbitrarily popping from `manual_pending`. With
                    // `start_consensus=false` the worker binds to the
                    // filter but doesn't start its app consensus
                    // engine — the reconciler restarts it with
                    // `start_consensus=true` when the alloc transitions
                    // from Joining to Active. `set_pending_filter_frame`
                    // anchors the proposal-timeout window.
                    if !worker_ids.is_empty() {
                        if worker_ids.len() != filters.len() {
                            return Err(format!(
                                "worker_ids length ({}) must match filters length ({})",
                                worker_ids.len(),
                                filters.len()
                            ));
                        }
                        for (filter, &core_id) in filters.iter().zip(worker_ids.iter()) {
                            wm.set_worker_filter(core_id, filter, false)
                                .map_err(|e| format!(
                                    "pre-pin worker {core_id}: {e}"
                                ))?;
                            wm.set_pending_filter_frame(core_id, frame)
                                .map_err(|e| format!(
                                    "set_pending_filter_frame {core_id}: {e}"
                                ))?;
                        }
                    }

                    // Spawn the slow path (VDF + sign + publish) so
                    // the RPC ack returns immediately. Without this
                    // the TUI's gRPC call blocks for the full VDF
                    // duration and any further keystrokes / commands
                    // queue behind it. Failures from the detached task
                    // are logged here; the TUI's await-confirm loop
                    // separately observes whether the alloc actually
                    // landed on chain.
                    let filters_for_task = filters.clone();
                    let worker_ids_for_task = worker_ids.clone();
                    tokio::spawn(async move {
                        if let Err(e) = pp
                            .submit_join(filters_for_task, &worker_ids_for_task, frame)
                            .await
                        {
                            tracing::warn!(
                                error = %e,
                                "request_join detached submit_join failed"
                            );
                        }
                    });
                    Ok(())
                })
            }
        }
        node_rpc_builder = node_rpc_builder.with_worker_control(Arc::new(WorkerControlBridge {
            worker_manager: worker_manager.clone(),
            prover_pipeline: prover_pipeline.clone(),
            current_frame: current_frame.clone(),
        }));

        // Workers view — keeps NodeService::get_worker_info and
        // get_node_info's running_workers/allocated_workers counters
        // accurate. Populated by a 2s tick reading from WorkerManager.
        let workers_view: Arc<std::sync::RwLock<Vec<quil_rpc::WorkerEntry>>> =
            Arc::new(std::sync::RwLock::new(Vec::new()));
        {
            let wm = worker_manager.clone();
            let view = workers_view.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
                loop {
                    interval.tick().await;
                    let entries: Vec<quil_rpc::WorkerEntry> =
                        quil_engine::worker::WorkerView::snapshot(wm.as_ref())
                            .all
                            .into_iter()
                            .map(|w| quil_rpc::WorkerEntry {
                                core_id: w.core_id,
                                filter: w.filter.clone(),
                                available_storage: w.available_storage,
                                total_storage: w.total_storage,
                                manually_managed: w.manually_managed,
                                allocated: !w.filter.is_empty(),
                            })
                            .collect();
                    {
                        *view.write().unwrap() = entries;
                    }
                }
            });
        }
        node_rpc_builder = node_rpc_builder.with_workers_view(workers_view.clone());

        // ShardInfoProvider for NodeService::get_shard_info.
        // Reads from the local hypergraph; on non-archive
        // `include_all` requests with incomplete local data, dials
        // the latest frame's prover and fetches sizes via
        // GlobalService::GetAppShards.
        struct LocalShardInfoProvider {
            registry: Arc<dyn quil_types::consensus::ProverRegistry>,
            clock_store: Arc<dyn quil_types::store::ClockStore>,
            crdt: Arc<quil_hypergraph::HypergraphCrdt>,
            shards_store: Arc<dyn quil_types::store::ShardsStore>,
            self_address: Vec<u8>,
            current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
            key_store: Arc<dyn quil_types::store::KeyStore>,
            peer_info_lookup: Arc<dyn Fn(&[u8]) -> Vec<String> + Send + Sync>,
            ed448_seed: Option<[u8; 57]>,
            archive_mode: bool,
            /// Pool of mTLS archive endpoints discovered via the
            /// genesis-archive PeerInfo gossip. Used as a fallback
            /// when `dial_latest_frame_prover` fails — typically on a
            /// fresh node where the prover-tree CRDT (and therefore
            /// the key registry) hasn't synced yet, so we can't
            /// resolve `frame.header.prover` to an Ed448 identity
            /// key. Mirrors the chicken-and-egg fix for HyperSync
            /// (bug #7 in the v2.1.0.20 branch).
            archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
        }
        impl quil_types::consensus::ShardInfoProvider for LocalShardInfoProvider {
            fn get_shard_info(
                &self,
                include_all: bool,
            ) -> quil_types::error::Result<(
                Vec<quil_types::consensus::ShardDetail>,
                u64,
                num_bigint::BigInt,
                u64,
            )> {
                // Use the shared `current_frame.effective()` as the
                // source of truth — populated by every observer
                // path (BlossomSub recv, archive poller, finalize
                // hook, materializer). Pull the difficulty from
                // the clock-store header (the only place it lives)
                // but don't let a missing clock-store row leave
                // `frame_number` at 0 when `current_frame` knows
                // better.
                let cf = self.current_frame.effective();
                let (difficulty, frame_number) = match self
                    .clock_store
                    .get_latest_global_clock_frame()
                {
                    Ok(frame) => {
                        let h = frame.header.unwrap_or_default();
                        (h.difficulty as u64, h.frame_number.max(cf))
                    }
                    Err(_) => (0u64, cf),
                };

                // Collect filters this prover is currently associated
                // with for TUI display: Joining (non-expired), Active,
                // Paused, and Leaving (non-expired). Differs from
                // `is_allocated` (Active+Joining only) — a Leaving
                // prover is still earning at their current rank until
                // the 360-frame confirm window completes.
                let provers = self
                    .registry
                    .get_provers(&self.self_address)
                    .unwrap_or_default();
                let allocated_filters: std::collections::HashSet<Vec<u8>> = provers
                    .iter()
                    .filter(|pr| pr.address == self.self_address)
                    .flat_map(|pr| {
                        pr.allocations
                            .iter()
                            .filter(|a| a.is_live(frame_number))
                            .map(|a| a.confirmation_filter.clone())
                    })
                    .collect();

                let local_get_sizes = quil_engine::shard_info::local_app_shard_get_sizes(
                    self.crdt.clone(),
                    self.shards_store.clone(),
                );

                let local_result = quil_engine::shard_info::get_shard_info(
                    include_all,
                    &self.self_address,
                    &allocated_filters,
                    difficulty,
                    frame_number,
                    self.shards_store.as_ref(),
                    self.registry.as_ref(),
                    &local_get_sizes,
                );

                // Remote fallback triggers:
                //   * basis == 0 — local data is empty everywhere.
                //   * include_all && !archive && partial local — got
                //     some shards but not all (typical non-archive).
                let expected_shards: usize = self
                    .shards_store
                    .range_app_shards()
                    .map(|v| {
                        let mut keys: std::collections::HashSet<Vec<u8>> =
                            std::collections::HashSet::new();
                        for s in v {
                            keys.insert(s.shard_key);
                        }
                        keys.len()
                    })
                    .unwrap_or(0);
                let local_incomplete = match &local_result {
                    Ok((details, _diff, basis, _frame)) => {
                        let entries_below_shards =
                            include_all && !self.archive_mode && details.len() < expected_shards;
                        basis.sign() == num_bigint::Sign::NoSign || entries_below_shards
                    }
                    Err(_) => true,
                };
                if !local_incomplete {
                    return local_result;
                }
                let Some(seed) = self.ed448_seed else {
                    return local_result;
                };

                // `block_in_place` keeps the multi-thread runtime
                // alive while we await the dial + prefetch.
                use std::collections::HashMap;
                let key_store = self.key_store.clone();
                let peer_info_lookup = self.peer_info_lookup.clone();
                let clock_store = self.clock_store.clone();
                let shards_store = self.shards_store.clone();
                let archive_pool = self.archive_pool.clone();
                let prefetched: Result<
                    HashMap<Vec<u8>, Vec<quil_types::proto::global::AppShardInfo>>,
                    quil_types::error::QuilError,
                > = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async move {
                        // Gather the unique parent shard_keys we want
                        // sized — same set in both fallback paths.
                        let mut unique: HashMap<Vec<u8>, ()> = HashMap::new();
                        for s in shards_store.range_app_shards()? {
                            unique.insert(s.shard_key, ());
                        }
                        let unique_keys: Vec<Vec<u8>> = unique.into_keys().collect();

                        // Primary path: dial the latest frame's
                        // prover via key registry + peer info. Fails
                        // on a fresh node when those caches are empty.
                        let mut client_opt: Option<quil_rpc::ArchiveClient> =
                            match clock_store.get_latest_global_clock_frame() {
                                Ok(frame) => {
                                    match quil_rpc::peer_dial::dial_latest_frame_prover(
                                        &frame,
                                        key_store,
                                        move |peer_id| peer_info_lookup(peer_id),
                                        &seed,
                                    )
                                    .await
                                    {
                                        Ok(c) => Some(c),
                                        Err(e) => {
                                            tracing::debug!(
                                                error = %e,
                                                "shard info: dial_latest_frame_prover failed, will try archive pool"
                                            );
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        error = %e,
                                        "shard info: no latest frame yet, will try archive pool"
                                    );
                                    None
                                }
                            };

                        // Fallback: try mTLS endpoints from the
                        // archive pool. These are populated from
                        // genesis-archive PeerInfo gossip and don't
                        // require the prover tree / key registry to
                        // be synced. Mirrors the HyperSync chicken-
                        // and-egg fix.
                        if client_opt.is_none() {
                            let endpoints = archive_pool.get_all().await;
                            for ep in &endpoints {
                                match quil_rpc::ArchiveClient::connect_mtls(ep, &seed).await {
                                    Ok(c) => {
                                        tracing::debug!(
                                            endpoint = %ep,
                                            "shard info: archive-pool fallback dial succeeded"
                                        );
                                        client_opt = Some(c);
                                        break;
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            endpoint = %ep,
                                            error = %e,
                                            "shard info: archive-pool fallback dial failed"
                                        );
                                    }
                                }
                            }
                        }

                        let mut client = client_opt.ok_or_else(|| {
                            quil_types::error::QuilError::Internal(
                                "shard info: no archive endpoint reachable for fallback".into(),
                            )
                        })?;

                        tracing::debug!(
                            unique_keys = unique_keys.len(),
                            "shard info: about to fetch GetAppShards for unique parent keys"
                        );
                        let mut out: HashMap<Vec<u8>, Vec<quil_types::proto::global::AppShardInfo>> =
                            HashMap::with_capacity(unique_keys.len());
                        for shard_key in unique_keys {
                            match client
                                .get_app_shards(shard_key.clone(), Vec::new())
                                .await
                            {
                                Ok(infos) => {
                                    tracing::debug!(
                                        shard_key_hex = %hex::encode(&shard_key),
                                        infos = infos.len(),
                                        "shard info: GetAppShards returned"
                                    );
                                    out.insert(shard_key, infos);
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        error = %e,
                                        "remote shard info: get_app_shards failed for one shard",
                                    );
                                }
                            }
                        }
                        tracing::debug!(
                            keys = out.len(),
                            "shard info: prefetched remote shard data"
                        );
                        Ok::<_, quil_types::error::QuilError>(out)
                    })
                });

                let prefetched = match prefetched {
                    Ok(map) => map,
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "remote shard info fallback failed; returning local result",
                        );
                        return local_result;
                    }
                };

                let prefetched = std::sync::Arc::new(prefetched);
                let remote_get_sizes = {
                    let prefetched = prefetched.clone();
                    move |shard_key: &[u8],
                          shard_info: &quil_types::store::ShardInfo|
                          -> quil_types::error::Result<
                        Vec<quil_engine::shard_info::ShardSizeEntry>,
                    > {
                        let infos = match prefetched.get(shard_key) {
                            Some(v) => v.clone(),
                            None => return Ok(Vec::new()),
                        };
                        let mut out = Vec::with_capacity(infos.len().max(1));
                        if infos.is_empty() {
                            return Ok(Vec::new());
                        }
                        for info in infos {
                            out.push(quil_engine::shard_info::ShardSizeEntry {
                                prefix: if info.prefix.is_empty() {
                                    shard_info.prefix.clone()
                                } else {
                                    info.prefix
                                },
                                size: info.size,
                                data_shards: info.data_shards,
                            });
                        }
                        Ok(out)
                    }
                };

                quil_engine::shard_info::get_shard_info(
                    include_all,
                    &self.self_address,
                    &allocated_filters,
                    difficulty,
                    frame_number,
                    self.shards_store.as_ref(),
                    self.registry.as_ref(),
                    &remote_get_sizes,
                )
            }
        }

        let pic_for_lookup = peer_info_cache.clone();
        let peer_info_lookup: Arc<dyn Fn(&[u8]) -> Vec<String> + Send + Sync> =
            Arc::new(move |peer_id: &[u8]| -> Vec<String> {
                let map = pic_for_lookup.read();
                match map.get(peer_id) {
                    Some(info) => info
                        .reachability
                        .first()
                        .map(|r| r.stream_multiaddrs.clone())
                        .unwrap_or_default(),
                    None => Vec::new(),
                }
            });

        node_rpc_builder = node_rpc_builder.with_shard_info_provider(Arc::new(
            LocalShardInfoProvider {
                registry: prover_registry.clone()
                    as Arc<dyn quil_types::consensus::ProverRegistry>,
                clock_store: clock_store.clone()
                    as Arc<dyn quil_types::store::ClockStore>,
                crdt: crdt.clone(),
                shards_store: shards_store.clone(),
                self_address: prover_address.to_vec(),
                current_frame: current_frame.clone(),
                key_store: key_store.clone() as Arc<dyn quil_types::store::KeyStore>,
                peer_info_lookup,
                ed448_seed: mtls_seed,
                archive_mode,
                archive_pool: archive_pool.clone(),
            },
        ));
        let node_rpc = node_rpc_builder;

        // gRPC layout:
        //   * NodeService is user-facing (qclient / admin) and served
        //     plaintext at ListenGRPCMultiaddr (default 127.0.0.1:8337).
        //   * Global, Hypergraph, AppShard, KeyRegistry, Connectivity
        //     are peer-to-peer and served mTLS at StreamListenMultiaddr
        //     (default 0.0.0.0:8340).
        let stream_addr = {
            let parts: Vec<&str> = config.p2p.stream_listen_multiaddr
                .trim_start_matches('/')
                .split('/')
                .collect();
            if parts.len() >= 4 && parts[0] == "ip4" && parts[2] == "tcp" {
                format!("{}:{}", parts[1], parts[3])
            } else {
                "0.0.0.0:8340".to_string()
            }
        };

        let node_grpc_token = token.clone();
        let peer_grpc_token = token.clone();

        // ---- NodeService (plaintext, qclient-facing) ----
        if let Ok(addr) = grpc_addr.parse::<std::net::SocketAddr>() {
            let node_rpc_service = tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::node::node_service_server::NodeServiceServer::new(
                    node_rpc,
                ),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            );
            tokio::spawn(async move {
                info!(addr = %addr, "starting NodeService gRPC (plaintext, qclient-facing)");
                let res = tonic::transport::Server::builder()
                    .add_service(node_rpc_service)
                    .serve_with_shutdown(addr, async move {
                        node_grpc_token.cancelled().await;
                    })
                    .await;
                match res {
                    Ok(()) => info!("NodeService gRPC stopped"),
                    Err(e) => warn!(error = %e, "NodeService gRPC error"),
                }
            });
        } else {
            warn!(addr = %grpc_addr, "invalid NodeService listen address, server disabled");
        }

        // ---- Peer services (mTLS when Ed448 seed present) ----
        if let Ok(addr) = stream_addr.parse::<std::net::SocketAddr>() {
            let global_service = tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::global::global_service_server::GlobalServiceServer::new(
                    grpc_server,
                ),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            );
            let hypersync_service = tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::application::hypergraph_comparison_service_server::HypergraphComparisonServiceServer::new(
                    hypersync,
                ),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            );
            let app_shard_service = tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::global::app_shard_service_server::AppShardServiceServer::new(
                    quil_rpc::stub_services::AppShardRpcServer::new(
                        clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
                    ),
                ),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            );
            let key_registry_service = tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::global::key_registry_service_server::KeyRegistryServiceServer::new(
                    quil_rpc::stub_services::KeyRegistryRpcServer::new(
                        prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                    ),
                ),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            );
            let connectivity_service = tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::node::connectivity_service_server::ConnectivityServiceServer::new(
                    quil_rpc::stub_services::ConnectivityRpcServer,
                ),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            );

            // DispatchService — inbox + hub CRDT for qclient message
            // send/retrieve/show/delete. Backed by the existing
            // RocksInboxStore; registered on the same mTLS listener.
            let inbox_store = Arc::new(quil_store::RocksInboxStore::new(db_arc.inner()));
            let dispatch_service = tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::global::dispatch_service_server::DispatchServiceServer::new(
                    quil_rpc::dispatch_service::DispatchRpcServer::new(inbox_store.clone()),
                ),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            );

            // MixnetService — mixnet round RPCs. Stub accepts messages
            // so dialing peers don't hit Unimplemented. Full mix-round
            // scheduler is a future addition.
            let mixnet_service = tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::global::mixnet_service_server::MixnetServiceServer::new(
                    quil_rpc::mixnet_service::MixnetRpcServer::new(),
                ),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            );

            // PubSubProxy — only registered when
            // `engine.enable_master_proxy` is true. Exposed on the
            // same mTLS peer listener so standalone worker processes
            // can dial it with the same Ed448-derived cert they use
            // for other peer RPCs.
            let pubsub_proxy_service = if config.engine.enable_master_proxy {
                let p2p_for_proxy = p2p_handle.clone();
                let peer_id_bytes: Vec<u8> = p2p_for_proxy.peer_id.to_bytes();
                let p2p_publish = p2p_for_proxy.clone();
                let p2p_sub = p2p_for_proxy.clone();
                let p2p_unsub = p2p_for_proxy.clone();
                let p2p_count = p2p_for_proxy.clone();
                let p2p_get_score = p2p_for_proxy.clone();
                let p2p_set_score = p2p_for_proxy.clone();
                let p2p_add_score = p2p_for_proxy.clone();
                let p2p_reconnect = p2p_for_proxy.clone();
                let p2p_bootstrap = p2p_for_proxy.clone();
                let p2p_discover = p2p_for_proxy.clone();
                let p2p_is_connected = p2p_for_proxy.clone();
                let shim = quil_rpc::pubsub_proxy::P2pHandleShim {
                    peer_id_bytes,
                    publish: Arc::new(move |bitmask, data| {
                        let h = p2p_publish.clone();
                        tokio::spawn(async move {
                            if let Err(e) = h.publish(bitmask, data).await {
                                warn!(error = %e, "pubsub-proxy publish failed");
                            }
                        });
                    }),
                    subscribe: Arc::new(move |bitmask| {
                        let h = p2p_sub.clone();
                        tokio::spawn(async move { h.subscribe(bitmask).await; });
                    }),
                    unsubscribe: Arc::new(move |bitmask| {
                        let h = p2p_unsub.clone();
                        tokio::spawn(async move { h.unsubscribe(bitmask).await; });
                    }),
                    peer_count: Arc::new(move || p2p_count.peer_count()),
                    get_peer_score: Arc::new(move |pid_bytes| {
                        let h = p2p_get_score.clone();
                        Box::pin(async move {
                            let peer = quil_p2p::PeerId::from_bytes(&pid_bytes)
                                .map_err(|e| format!("invalid peer id: {}", e))?;
                            Ok(h.get_peer_score(peer).await)
                        })
                    }),
                    set_peer_score: Arc::new(move |pid_bytes, score| {
                        let h = p2p_set_score.clone();
                        if let Ok(peer) = quil_p2p::PeerId::from_bytes(&pid_bytes) {
                            tokio::spawn(async move { h.set_peer_score(peer, score).await; });
                        }
                    }),
                    add_peer_score: Arc::new(move |pid_bytes, delta| {
                        let h = p2p_add_score.clone();
                        if let Ok(peer) = quil_p2p::PeerId::from_bytes(&pid_bytes) {
                            tokio::spawn(async move { h.add_peer_score(peer, delta).await; });
                        }
                    }),
                    reconnect: Arc::new(move |pid_bytes| {
                        let h = p2p_reconnect.clone();
                        Box::pin(async move {
                            let peer = quil_p2p::PeerId::from_bytes(&pid_bytes)
                                .map_err(|e| format!("invalid peer id: {}", e))?;
                            h.reconnect_peer(peer)
                                .await
                                .map_err(|e| e.to_string())
                        })
                    }),
                    bootstrap: Arc::new(move || {
                        let h = p2p_bootstrap.clone();
                        Box::pin(async move {
                            h.bootstrap().await.map_err(|e| e.to_string())
                        })
                    }),
                    discover_peers: Arc::new(move || {
                        let h = p2p_discover.clone();
                        Box::pin(async move {
                            h.discover_peers().await.map_err(|e| e.to_string())
                        })
                    }),
                    // No per-peer connected lookup yet — approximate via
                    // peer_count > 0 to satisfy "can we reach anyone?"
                    // queries until a connected-peers enumerator lands.
                    is_peer_connected: Arc::new(move |_pid| {
                        p2p_is_connected.peer_count() > 0
                    }),
                };
                let ma_getter_handle = p2p_handle.clone();
                let own_multiaddrs: quil_rpc::pubsub_proxy::OwnMultiaddrsGetter =
                    Arc::new(move || ma_getter_handle.observed_addresses());
                // Peer list: cheap approximation — empty list (the
                // master doesn't currently expose a connected-peers
                // enumerator; GetNetworkPeersCount still reports the
                // true count). Upgrade when the P2P handle grows a
                // peer iterator.
                let peers_getter: quil_rpc::pubsub_proxy::PeerListGetter =
                    Arc::new(|| Vec::new());
                let network = network as u32;
                let mut proxy_srv = quil_rpc::pubsub_proxy::PubSubProxyServer::new(
                    shim,
                    global_msg_tx.clone(),
                    own_multiaddrs,
                    peers_getter,
                    network,
                );
                // Wire Ed448 signer + pubkey if we have a seed.
                if let Some(seed) = mtls_seed {
                    let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
                    let seed_for_sign = seed;
                    let signer: quil_rpc::pubsub_proxy::Ed448Signer =
                        Arc::new(move |msg: &[u8]| -> Result<Vec<u8>, String> {
                            let priv_key = ed448_rust::PrivateKey::from(seed_for_sign);
                            priv_key
                                .sign(msg, None)
                                .map(|sig| sig.to_vec())
                                .map_err(|e| format!("{:?}", e))
                        });
                    let pubkey_for_get = pubkey.clone();
                    let pubkey_getter: quil_rpc::pubsub_proxy::Ed448PubkeyGetter =
                        Arc::new(move || pubkey_for_get.clone());
                    proxy_srv = proxy_srv.with_signer(signer).with_pubkey(pubkey_getter);
                }
                Some(tonic::service::interceptor::InterceptedService::new(
                    quil_types::proto::proxy::pub_sub_proxy_server::PubSubProxyServer::new(
                        proxy_srv,
                    ),
                    quil_rpc::peer_auth_middleware::peer_auth_interceptor,
                ))
            } else {
                None
            };

            // mTLS is mandatory for the peer gRPC listener — every peer
            // dialer (archive client, standalone worker, peer-to-peer
            // RPCs) expects an Ed448-backed TLS certificate and would
            // reject a plaintext server. Refuse to start rather than
            // silently bringing up an unreachable listener.
            let seed = mtls_seed.ok_or_else(|| anyhow::anyhow!(
                "peer gRPC requires an Ed448 identity — set `p2p.peerPrivKey` \
                 to a 57-byte hex seed (or 114-byte seed+pubkey). Without it \
                 no peer can authenticate against this node.",
            ))?;
            let tls_config = quil_rpc::build_quil_server_tls_config(&seed)
                .map_err(|e| anyhow::anyhow!(
                    "peer gRPC mTLS config init failed: {} — check `p2p.peerPrivKey`", e
                ))?;
            tokio::spawn(async move {
                info!(addr = %addr, "starting peer gRPC (mTLS)");
                let listener = match tokio::net::TcpListener::bind(addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(error = %e, "peer gRPC bind failed");
                        return;
                    }
                };
                let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
                let incoming = async_stream::stream! {
                    loop {
                        let (tcp, _peer) = match listener.accept().await {
                            Ok(v) => v,
                            Err(e) => {
                                warn!(error = %e, "peer gRPC accept failed");
                                continue;
                            }
                        };
                        let acceptor = tls_acceptor.clone();
                        match acceptor.accept(tcp).await {
                            Ok(tls) => yield Ok::<_, std::io::Error>(tls),
                            Err(e) => {
                                debug!(error = %e, "TLS handshake failed");
                                continue;
                            }
                        }
                    }
                };
                let mut builder = tonic::transport::Server::builder()
                    .add_service(global_service)
                    .add_service(hypersync_service)
                    .add_service(app_shard_service)
                    .add_service(key_registry_service)
                    .add_service(connectivity_service)
                    .add_service(dispatch_service)
                    .add_service(mixnet_service);
                if let Some(pp) = pubsub_proxy_service {
                    info!("registering PubSubProxy on peer gRPC listener");
                    builder = builder.add_service(pp);
                }
                let res = builder
                    .serve_with_incoming_shutdown(incoming, async move {
                        peer_grpc_token.cancelled().await;
                    })
                    .await;
                match res {
                    Ok(()) => info!("peer gRPC stopped"),
                    Err(e) => warn!(error = %e, "peer gRPC error"),
                }
            });
        } else {
            warn!(addr = %stream_addr, "invalid peer gRPC listen address, server disabled");
        }
    }

    // ---------------------------------------------------------------
    // 8. Wait for shutdown
    // ---------------------------------------------------------------
    token.cancelled().await;
    info!("master node shutting down");
    p2p_handle.shutdown().await;
    info!("shutdown complete");

    Ok(())
}

async fn run_worker_node(
    config: &quil_config::Config,
    core_id: u32,
    parent_process: u32,
    token: CancellationToken,
) -> anyhow::Result<()> {
    info!(core_id, parent_process, "worker node starting");

    // Resolve the per-worker store path. Worker processes can NOT
    // share the master's RocksDB directory: RocksDB takes an exclusive
    // file lock per `LOCK` file, so a second `open` against the same
    // path fails. Each worker must own its own store.
    //
    // Resolution order:
    //   1. `db.worker_paths[core_id - 1]` (core 0 is master).
    //   2. `db.worker_path_prefix` with `%d` → core id.
    //   3. `<db.path or .config/store>/worker-<core_id>`.
    let db_path: std::path::PathBuf = {
        let idx = core_id.saturating_sub(1) as usize;
        if let Some(p) = config.db.worker_paths.get(idx).filter(|s| !s.is_empty()) {
            std::path::PathBuf::from(p)
        } else if !config.db.worker_path_prefix.is_empty() {
            std::path::PathBuf::from(
                config.db.worker_path_prefix.replace("%d", &core_id.to_string()),
            )
        } else {
            let base = if config.db.path.is_empty() {
                std::path::PathBuf::from(".config/store")
            } else {
                std::path::PathBuf::from(&config.db.path)
            };
            base.join(format!("worker-{}", core_id))
        }
    };
    info!(core_id, db_path = %db_path.display(), "worker store path resolved");
    std::fs::create_dir_all(&db_path)?;
    let db = quil_store::RocksDb::open(&db_path)?;
    let db_arc = Arc::new(db);
    let clock_store: Arc<dyn quil_types::store::ClockStore> =
        Arc::new(quil_store::RocksClockStore::new(db_arc.inner()));
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db_arc.inner()));

    // Per-worker crypto + CRDT + execution engines. Each worker
    // process owns its own RocksDB store (per `worker_path_prefix`)
    // and therefore its own crdt + execution manager.
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_crypto::KzgInclusionProver);
    let bls_constructor: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::Bls48581KeyConstructor);
    let key_manager: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new(bls_constructor));
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover.clone(),
    ));
    // Same crypto setup as the master node — bulletproof is real;
    // Decaf / circuit compiler are still noop stubs pending production
    // impls. See the master block earlier in this file for rationale.
    let bulletproof_prover_worker: Arc<dyn quil_types::crypto::BulletproofProver> =
        Arc::new(quil_crypto::Decaf448BulletproofProver);
    let decaf_constructor_worker: Arc<dyn quil_types::crypto::DecafConstructor> =
        Arc::new(quil_execution::testing::NoopDecafConstructor);
    let circuit_compiler_worker: Arc<dyn quil_types::execution::CircuitCompiler> =
        Arc::new(quil_execution::testing::NoopCircuitCompiler);
    let clock_store_for_exec_worker: Arc<dyn quil_types::store::ClockStore> =
        clock_store.clone();
    let hypergraph_resolver_worker: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
    let exec_manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        inclusion_prover.clone(),
        key_manager.clone(),
        crdt.clone(),
        bulletproof_prover_worker,
        decaf_constructor_worker,
        circuit_compiler_worker,
        clock_store_for_exec_worker,
        hypergraph_resolver_worker,
        true,
    ));

    // Key management — same keys as master
    let bls_ctor = quil_crypto::Bls48581KeyConstructor;
    let keys_path = config.key.key_store_file.path.clone();
    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "q-prover-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };
    let file_key_manager = Arc::new(quil_keys::FileKeyManager::new(
        PathBuf::from(&keys_path),
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(bls_ctor),
    )?);
    file_key_manager.set_peer_priv_key_hex(&config.p2p.peer_priv_key);
    let bls_pubkey = file_key_manager.get_public_key(quil_types::crypto::KeyType::Bls48581G1)?;
    let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;

    // Shared prover registry (syncs from store)
    let prover_registry = Arc::new(quil_execution::SharedProverRegistry::new());

    // Frame prover
    let frame_prover: Arc<dyn quil_types::crypto::FrameProver> =
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));
    let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());
    let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
        Arc::new(quil_engine::InMemoryDynamicFeeManager::new(360));

    // BLS signer factory
    let fkm = file_key_manager.clone();
    let signer_factory: Arc<dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync> =
        Arc::new(move || {
            fkm.get_signer(quil_types::crypto::KeyType::Bls48581G1)
                .expect("BLS signer should be available")
        });

    // Compute worker listen address from config
    let listen_addr = quil_engine::worker_node::worker_listen_addr(
        core_id,
        &config.engine.data_worker_base_listen_multiaddr,
        config.engine.data_worker_base_stream_port,
        &config.engine.data_worker_stream_multiaddrs,
    );

    // Master endpoint — derived from p2p.stream_listen_multiaddr.
    // In a cluster, the worker's config has that field pointed at the
    // master's stream listener; on single-machine setups it's the
    // local `/ip4/0.0.0.0/tcp/8340` and gets rewritten to localhost.
    let master_endpoint = quil_engine::worker_node::master_grpc_endpoint(&config);

    let worker_config = quil_engine::worker_node::WorkerNodeConfig {
        core_id,
        master_endpoint,
        listen_addr,
        parent_pid: if parent_process > 0 { Some(parent_process) } else { None },
    };

    let reward_greedy = config.engine.reward_strategy == "reward-greedy";

    let mut worker_node = quil_engine::worker_node::WorkerOnlyNode::new(
        worker_config,
        clock_store,
        prover_registry as Arc<dyn quil_types::consensus::ProverRegistry>,
        frame_prover,
        message_collector,
        fee_manager,
        prover_address.to_vec(),
        bls_pubkey,
        signer_factory,
        reward_greedy,
    )
    .with_state_engines(crdt, exec_manager, inclusion_prover);

    // Outbound pubsub. Two mutually exclusive modes:
    //   * `engine.enable_master_proxy = true`  → dial the master's
    //     PubSubProxy on the peer mTLS listener and route all pubsub
    //     through it. Used when one machine should be the only mesh
    //     participant (homogenous LAN layouts, gateway-style setups).
    //   * `engine.enable_master_proxy = false` → the worker spins up
    //     its own libp2p instance with a synthetic peer key (per
    //     `node/p2p/blossomsub.go:473-496`) and joins the mesh
    //     directly. Pubsub messages are signed with the REAL prover
    //     key so peers attribute them to the prover, not the worker
    //     host. Required for multi-machine clusters where workers and
    //     master live on different hosts.
    if config.engine.enable_master_proxy {
        let master_addr = quil_engine::worker_node::master_grpc_endpoint(&config);
        // `master_addr` is already `http://host:port`.
        match quil_rpc::proxy_pubsub::ProxyPubSub::connect(master_addr.clone(), None).await {
            Ok(proxy) => {
                let proxy = Arc::new(proxy);
                info!(master = %master_addr, "worker connected to master PubSubProxy");
                let proxy_for_publish = proxy.clone();
                let publish_fn: quil_engine::worker_node::PublishFn =
                    Arc::new(move |bitmask, data| {
                        let p = proxy_for_publish.clone();
                        Box::pin(async move {
                            if let Err(e) = p.publish(bitmask, data).await {
                                warn!(error = %e, "proxy publish failed");
                            }
                        })
                    });
                worker_node = worker_node.with_publish_fn(publish_fn);
            }
            Err(e) => {
                warn!(error = ?e, master = %master_addr,
                    "worker proxy connect failed — running receive-only");
            }
        }
    }

    // Worker-owned p2p when proxy is off. Carry the receiver out of
    // this scope so we can spawn the routing task after the worker is
    // wrapped in an Arc.
    let worker_owned_p2p: Option<(
        Arc<quil_p2p::P2PHandle>,
        tokio::sync::mpsc::Receiver<quil_p2p::ReceivedMessage>,
    )> = if !config.engine.enable_master_proxy {
        let p2p_node = quil_p2p::P2PNode::new_for_worker(&config.p2p, core_id)
            .map_err(|e| anyhow::anyhow!("worker p2p node init: {}", e))?;
        let worker_listen = quil_p2p::P2PNode::worker_listen_multiaddr(
            &config.engine,
            core_id,
        )
        .map_err(|e| anyhow::anyhow!("worker p2p listen addr: {}", e))?;
        info!(core_id, listen = %worker_listen, "starting worker-owned p2p");
        let (handle, rx) = p2p_node
            .start(&worker_listen)
            .await
            .map_err(|e| anyhow::anyhow!("worker p2p start: {}", e))?;
        let handle = Arc::new(handle);
        // Pre-subscribe to the global bitmasks so peer global frames /
        // votes / prover messages reach this worker.
        for bm in [
            quil_engine::bitmasks::GLOBAL_CONSENSUS,
            quil_engine::bitmasks::GLOBAL_FRAME,
            quil_engine::bitmasks::GLOBAL_PROVER,
            quil_engine::bitmasks::GLOBAL_PEER_INFO,
        ] {
            handle.subscribe(bm.to_vec()).await;
        }
        // Wire publish_fn → worker's own p2p.
        let p2p_for_publish = handle.clone();
        let publish_fn: quil_engine::worker_node::PublishFn =
            Arc::new(move |bitmask, data| {
                let h = p2p_for_publish.clone();
                Box::pin(async move {
                    if let Err(e) = h.publish(bitmask, data).await {
                        warn!(error = %e, "worker p2p publish failed");
                    }
                })
            });
        worker_node = worker_node
            .with_publish_fn(publish_fn)
            .with_p2p_handle(handle.clone());
        Some((handle, rx))
    } else {
        None
    };

    let worker = Arc::new(worker_node);

    // Route incoming pubsub messages from the worker's own p2p into
    // the active engine. The worker's `route_message` dispatches by
    // bitmask pattern; if no engine is active yet, the message is
    // silently dropped.
    if let Some((_handle, mut rx)) = worker_owned_p2p {
        let route_token = token.clone();
        let route_worker = worker.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = route_token.cancelled() => break,
                    maybe_msg = rx.recv() => {
                        let Some(msg) = maybe_msg else { break };
                        route_worker.route_message(&msg.data, &msg.bitmask);
                    }
                }
            }
            info!("worker p2p routing task stopped");
        });
    }

    info!(core_id, "worker node initialized, starting event loop");

    // Run the worker — blocks until cancelled or parent dies
    let worker_for_stop = worker.clone();
    tokio::select! {
        result = worker.run() => {
            if let Err(e) = result {
                error!(core_id, error = %e, "worker node exited with error");
            }
        }
        _ = token.cancelled() => {
            info!(core_id, "worker node received shutdown signal");
            worker_for_stop.stop();
        }
    }

    info!(core_id, "worker node shut down");
    Ok(())
}

/// Convert a `/ip4/X/tcp/Y` multiaddr string into `X:Y`. Returns `None` for
/// unsupported multiaddr shapes (DNS, IPv6, non-TCP) so we don't try to dial
/// non-routable archive endpoints. Filters loopback and private ranges since
/// those would only resolve to our own machine.
fn multiaddr_to_host_port(ma: &str) -> Option<String> {
    multiaddr_to_host_port_with_network(ma, 0)
}

/// Like `multiaddr_to_host_port`, but on testnet/devnet (network != 0)
/// accepts RFC1918 private addresses (192.168.x.x, 10.x.x.x, etc.) and
/// loopback. Mainnet still rejects them so a misconfigured archive
/// doesn't poison the pool with unroutable peers.
fn multiaddr_to_host_port_with_network(ma: &str, network: u8) -> Option<String> {
    let parts: Vec<&str> = ma.trim_start_matches('/').split('/').collect();
    if parts.len() < 4 {
        return None;
    }
    if parts[0] != "ip4" || parts[2] != "tcp" {
        return None;
    }
    let ip: std::net::Ipv4Addr = parts[1].parse().ok()?;
    let allow_private = network != 0;
    let reject = if allow_private {
        ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()
    } else {
        ip.is_loopback() || ip.is_private() || ip.is_link_local()
            || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()
    };
    if reject {
        return None;
    }
    let port: u16 = parts[3].parse().ok()?;
    Some(format!("{}:{}", ip, port))
}

/// Build a stream multiaddr by extracting the IP from a pubsub multiaddr and
/// combining it with the port/protocol from the stream listen pattern.
///
/// IP precedence: prefer the pubsub IP (it's the address peers actually
/// see us on); if that's a wildcard or loopback, fall back to the stream
/// listen IP (covers testnet bootstraps where listen_multiaddr is
/// `/ip4/0.0.0.0/...` but stream_listen has the real LAN IP).
fn extract_stream_addr(pubsub_ma: &str, stream_listen: &str) -> Option<String> {
    let pub_parts: Vec<&str> = pubsub_ma.trim_start_matches('/').split('/').collect();
    let stream_parts: Vec<&str> = stream_listen.trim_start_matches('/').split('/').collect();

    if stream_parts.len() < 4 {
        return None;
    }
    let protocol = stream_parts[2]; // "tcp"
    let port = stream_parts[3]; // "8340"

    let pub_ip = if pub_parts.len() >= 2 && pub_parts[0] == "ip4" {
        Some(pub_parts[1])
    } else {
        None
    };
    let stream_ip = if stream_parts.len() >= 2 && stream_parts[0] == "ip4" {
        Some(stream_parts[1])
    } else {
        None
    };

    let usable = |ip: &str| -> bool {
        ip != "0.0.0.0" && ip != "127.0.0.1"
    };

    let ip = match (pub_ip, stream_ip) {
        (Some(p), _) if usable(p) => p,
        (_, Some(s)) if usable(s) => s,
        _ => return None,
    };

    Some(format!("/ip4/{}/{}/{}", ip, protocol, port))
}

/// Bridges `quil_engine::consensus_glue::ConsensusPublisher` to BlossomSub.
/// Proposals go on `GLOBAL_FRAME`, votes and timeouts on `GLOBAL_CONSENSUS`.
struct BlossomsubConsensusPublisher {
    p2p_handle: quil_p2p::node::P2PHandle,
    /// Self-loopback for consensus messages so the local
    /// `vote_aggregator` / event-loop dispatcher sees the leader's
    /// own proposals (BlossomSub does not echo self-published
    /// messages).
    loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
    self_peer_id: Vec<u8>,
}

impl quil_engine::consensus_glue::ConsensusPublisher for BlossomsubConsensusPublisher {
    fn publish_frame(&self, data: Vec<u8>) {
        let handle = self.p2p_handle.clone();
        let bitmask = quil_engine::bitmasks::GLOBAL_FRAME.to_vec();
        tokio::spawn(async move {
            if let Err(e) = handle.publish(bitmask, data).await {
                tracing::warn!(error = %e, "publish_frame failed");
            }
        });
    }

    fn publish_consensus(&self, data: Vec<u8>) {
        let handle = self.p2p_handle.clone();
        let bitmask = quil_engine::bitmasks::GLOBAL_CONSENSUS.to_vec();
        // Self-loopback: send the same payload onto the local receive
        // channel so the dispatcher's GLOBAL_CONSENSUS arm processes
        // it (vote_aggregator + event_loop). This is essential for the
        // proposer's own proposal/vote to reach its own aggregator,
        // since BlossomSub silently drops self-published messages.
        let loopback = self.loopback_tx.clone();
        let self_id = self.self_peer_id.clone();
        let data_for_loopback = data.clone();
        let bitmask_for_loopback = bitmask.clone();
        tokio::spawn(async move {
            let _ = loopback
                .send(quil_p2p::node::ReceivedMessage {
                    bitmask: bitmask_for_loopback,
                    data: data_for_loopback,
                    from: self_id,
                })
                .await;
        });
        tokio::spawn(async move {
            if let Err(e) = handle.publish(bitmask, data).await {
                tracing::warn!(error = %e, "publish_consensus failed");
            }
        });
    }

    fn publish_prover_message(&self, data: Vec<u8>) {
        // `data` is a `MessageRequest`-wrapped inner payload (built by
        // `consensus_glue::wrap_message_request`). Wrap it in a
        // `MessageBundle` envelope and publish on the GLOBAL_PROVER
        // bitmask. Non-archive nodes can additionally route over
        // archive gRPC; the BlossomSub broadcast covers archive nodes.
        let handle = self.p2p_handle.clone();
        let bitmask = quil_engine::bitmasks::GLOBAL_PROVER.to_vec();
        tokio::spawn(async move {
            // Decode the MessageRequest envelope so we can re-wrap
            // it inside a MessageBundle.
            let req = match quil_execution::message_envelope::CanonicalMessageRequest::from_canonical_bytes(&data) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "publish_prover_message: bad MessageRequest envelope");
                    return;
                }
            };
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let bundle = quil_execution::message_envelope::CanonicalMessageBundle {
                requests: vec![Some(req)],
                timestamp,
            };
            match bundle.to_canonical_bytes() {
                Ok(bytes) => {
                    if let Err(e) = handle.publish(bitmask, bytes).await {
                        tracing::warn!(error = %e, "publish_prover_message failed");
                    }
                }
                Err(e) => tracing::error!(error = %e, "publish_prover_message: bundle encode failed"),
            }
        });
    }
}

async fn run_dht_node(
    config: &quil_config::Config,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let listen_addr = if config.p2p.listen_multiaddr.is_empty() {
        "/ip4/0.0.0.0/udp/8336/quic-v1"
    } else {
        &config.p2p.listen_multiaddr
    };

    let p2p_node = quil_p2p::node::P2PNode::new(&config.p2p)?;
    info!(peer_id = %p2p_node.peer_id, "starting DHT node");

    let (p2p_handle, _msg_rx) = p2p_node.start(listen_addr).await?;
    info!("DHT node running");

    token.cancelled().await;
    p2p_handle.shutdown().await;
    info!("DHT node shut down");

    Ok(())
}
