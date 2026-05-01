use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

// Import KeyManager trait for get_public_key/get_signer methods
use quil_keys::KeyManager as _;

mod logging;

mod prover_pipeline;

/// Quilibrium Node — Rust implementation
#[derive(Parser, Debug)]
#[command(name = "quil-node", version, about)]
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

    /// Enable or disable signature validation
    #[arg(long, default_value_t = true)]
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

    // Initialize logging matching Go's zap console encoder format
    // (tab-separated ts \t level \t target:line \t msg \t {fields}).
    // Per-core file separation (`master.log` / `worker-N.log`) and
    // retention (maxAge, maxBackups) mirror lumberjack behavior.
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
        let peer_id = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;
        println!("{}", hex::encode(&peer_id));
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

        let db_path = if config.db.path.is_empty() {
            PathBuf::from(".config/store")
        } else {
            PathBuf::from(&config.db.path)
        };
        let frame_number = if db_path.exists() {
            let db = quil_store::RocksDb::open(&db_path).ok();
            db.and_then(|d| {
                let cs = quil_store::RocksClockStore::new(d.inner());
                cs.get_latest_global_frame().ok()
                    .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
            }).unwrap_or(0)
        } else {
            0
        };

        println!("Version: {}", env!("CARGO_PKG_VERSION"));
        println!("Prover Address: {}", hex::encode(&prover_address));
        println!("BLS Public Key: {}...{}", hex::encode(&bls_pubkey[..8]), hex::encode(&bls_pubkey[bls_pubkey.len()-8..]));
        println!("Frame Number: {}", frame_number);
        println!("Network: {}", args.network);
        return Ok(());
    }

    if args.peer_info {
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
        println!("Peer ID: {}", hex::encode(&prover_address));
        println!("BLS Public Key Length: {} bytes", bls_pubkey.len());
        println!("Listen Multiaddr: {}", config.p2p.listen_multiaddr);
        return Ok(());
    }

    if args.metrics {
        // Collect and print all registered metrics
        // The metrics crate doesn't have a built-in dump; print known counters
        println!("# Quilibrium Node Metrics");
        println!("# (run with --prometheus-server to expose via HTTP)");
        println!("quil_node_version{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"));
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
        version = env!("CARGO_PKG_VERSION"),
        core = args.core,
        network = args.network,
        "starting quil-node"
    );

    info!(config_dir = %args.config.display(), "loaded configuration");

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
            info!("starting as master node");
            run_master_node(
                &config,
                &args.config,
                args.archive,
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

    std::fs::create_dir_all(&db_path)?;
    let db = quil_store::RocksDb::open(&db_path)?;
    let db_arc = Arc::new(db);
    info!(path = %db_path.display(), "opened database");

    // ---------------------------------------------------------------
    // 2. Create stores
    // ---------------------------------------------------------------
    let clock_store = Arc::new(quil_store::RocksClockStore::new(db_arc.inner()));
    let token_store = Arc::new(quil_store::RocksTokenStore::new(db_arc.inner()));
    let _key_store = Arc::new(quil_store::RocksKeyStore::new(db_arc.inner()));
    let _shards_store = Arc::new(quil_store::RocksShardsStore::new(db_arc.inner()));
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

    // Auto-create all standard keys if missing
    file_key_manager.ensure_standard_keys()?;
    let bls_pubkey = file_key_manager.get_public_key(quil_types::crypto::KeyType::Bls48581G1)?;

    let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;
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
    let exec_manager = Arc::new(quil_execution::ExecutionEngineManager::new_with_crypto(
        inclusion_prover.clone(),
        key_manager.clone(),
        crdt.clone(),
        true,
    ));
    info!("execution engines initialized with BLS48-581 + Ed448 signature verification");

    // ---------------------------------------------------------------
    // 3b. Testnet/devnet genesis bootstrap
    //
    // For non-mainnet networks the node bootstraps its own genesis
    // state locally (no archive to sync from). Mirrors Go's
    // `createStubGenesis` path at `node/main.go` when network != 0.
    // Skipped if genesis frame already exists in the clock store.
    // ---------------------------------------------------------------
    let clock_store_dyn: &dyn quil_types::store::ClockStore = clock_store.as_ref();
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
            _shards_store.as_ref() as &dyn quil_types::store::ShardsStore,
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

    let p2p_node = quil_p2p::node::P2PNode::new(&config.p2p)?;
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

    // Frame tracking for PeerInfo — updated by frame receive loop and archive poller
    let last_received_frame = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // PeerInfo cache populated by the GLOBAL_PEER_INFO recv path.
    // Read by NodeService::get_peer_info so CLI tools can enumerate
    // the peers this node has observed on the network. Keyed by the
    // raw peer_id bytes; last-write-wins.
    let peer_info_cache: Arc<std::sync::RwLock<
        std::collections::HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>,
    >> = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
    // SignerRegistry — populated from inbound KeyRegistry broadcasts
    // on GLOBAL_PEER_INFO. Consumed by consensus message verification
    // (BLS signatures from peers whose identity↔prover binding we've
    // observed).
    let signer_registry: Arc<quil_p2p::SignerRegistry> =
        Arc::new(quil_p2p::SignerRegistry::new());
    let last_global_head_frame = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // ---------------------------------------------------------------
    // 5b. PeerInfo publishing (every 5 minutes + immediate)
    // ---------------------------------------------------------------
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
        let pi_last_received = last_received_frame.clone();
        let pi_last_head = last_global_head_frame.clone();
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
                let info = quil_p2p::CanonicalPeerInfo {
                    peer_id: pi_peer_id_bytes.clone(),
                    reachability: vec![quil_p2p::CanonicalReachability {
                        filter: vec![0xFF; 32], // global filter
                        pubsub_multiaddrs: vec![pubsub_addr],
                        stream_multiaddrs: stream_addrs,
                    }],
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
                    last_received_frame: pi_last_received.load(std::sync::atomic::Ordering::Relaxed),
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
    // determine its role. The consensus components (Phase 3A) are ready
    // to be wired when this node becomes an active prover.
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
            remote_mgr as Arc<dyn quil_engine::worker::WorkerManager>
        } else {
            // LOCAL MODE: core-pinned threads
            let thread_mgr = Arc::new(quil_engine::thread_worker::ThreadWorkerManager::new());
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
            });
            info!(
                worker_cores = thread_mgr.num_worker_cores(),
                "thread worker manager ready (local mode)"
            );
            thread_mgr as Arc<dyn quil_engine::worker::WorkerManager>
        };

    // Pre-allocate idle workers for each available core (matching Go's
    // startup behavior where worker processes are spawned immediately).
    // Workers start idle (empty filter) and get assigned shards by the
    // lifecycle when join proposals are accepted.
    {
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
    }

    // Worker allocator — reconciles registry vs running workers
    let worker_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        worker_manager.clone(),
        prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        prover_address.to_vec(),
    ));

    // Compute the config-derived seniority estimate from the mainnet
    // compat table — matches Go's `estimateSeniorityFromConfig`. Uses
    // our local libp2p peer ID plus any peer IDs derived from the
    // configs listed in `engine.multisig_prover_enrollment_paths`.
    // Result is cached on the allocator; lifecycle consults it when
    // deciding whether a seniority merge would raise our on-chain
    // seniority. We compute this only on mainnet (P2P.Network == 0)
    // to match Go's `RebuildPeerSeniority` scoping.
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
    let mut lifecycle_inner = quil_engine::provers::lifecycle::ProverLifecycle::new(
        prover_address.to_vec(),
        worker_allocator.clone(),
        halt_state.clone(),
    );
    lifecycle_inner.set_strategy(if reward_greedy {
        quil_engine::provers::proposer::Strategy::RewardGreedy
    } else {
        quil_engine::provers::proposer::Strategy::DataGreedy
    });
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
    // have no allocations yet (mirrors Go's `worker_allocator.go:599`
    // path that calls `RangeAppShards` on the local store).
    prover_lifecycle.set_shards_store(
        _shards_store.clone() as Arc<dyn quil_types::store::ShardsStore>,
    );

    // Periodic eviction of inactive provers. Only archive nodes perform
    // eviction (non-archives receive the resulting updates via sync).
    // Guarded by HaltState so evictions don't cascade during a halt
    // window — mirrors Go's `global_consensus_engine.go` gating at the
    // commit path (see memory `Bug #17`).
    if archive_mode {
        let pr_for_evict: Arc<dyn quil_types::consensus::ProverRegistry> =
            prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>;
        let cov_for_evict = coverage_monitor.clone();
        let hs_for_evict = halt_state.clone();
        let lrf_for_evict = last_received_frame.clone();
        let cancel = token.clone();
        // Go uses inactivityThreshold = 360 frames (~1h at 10s frames) —
        // after which a non-reporting prover is considered inactive.
        const INACTIVITY_THRESHOLD_FRAMES: u64 = 360;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = interval.tick() => {}
                }
                if hs_for_evict.any_halted() {
                    debug!(
                        halted = hs_for_evict.halted_count(),
                        "skipping eviction during coverage halt"
                    );
                    continue;
                }
                let frame = lrf_for_evict.load(std::sync::atomic::Ordering::Relaxed);
                if frame == 0 {
                    continue;
                }
                let halt_durations = cov_for_evict.check(frame);
                let halt_map: std::collections::HashMap<String, u64> = halt_durations
                    .into_iter()
                    .map(|(k, v)| (hex::encode(&k), v))
                    .collect();
                match pr_for_evict.evict_inactive_provers(
                    frame,
                    INACTIVITY_THRESHOLD_FRAMES,
                    &halt_map,
                ) {
                    Ok(evicted) if !evicted.is_empty() => {
                        info!(
                            count = evicted.len(),
                            frame,
                            "evicted inactive provers"
                        );
                        quil_engine::metrics::inc_evictions(evicted.len() as u64);
                    }
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "eviction failed"),
                }
            }
        });
        info!("archive-mode eviction scheduler spawned (halt-gated)");
    }

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
    // Build set of valid genesis prover ADDRESSES (Poseidon hash of BLS pubkey)
    // The frame header's `prover` field is the 32-byte address, not the raw key.
    let genesis_prover_addrs: std::collections::HashSet<Vec<u8>> = {
        let mut addrs = std::collections::HashSet::new();
        if let Ok(data) = quil_engine::genesis::get_mainnet_genesis_data() {
            // Beacon BLS key → address
            if let Ok(beacon_key) = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &data.beacon_bls48581_key,
            ) {
                if let Ok(addr) = quil_crypto::poseidon::hash_bytes_to_32(&beacon_key) {
                    addrs.insert(addr.to_vec());
                }
            }
            // Archive peer BLS keys → addresses
            for (_pid, pubkey_hex) in &data.archive_peers {
                if let Ok(key) = hex::decode(pubkey_hex) {
                    if let Ok(addr) = quil_crypto::poseidon::hash_bytes_to_32(&key) {
                        addrs.insert(addr.to_vec());
                    }
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
    // the `PROVER_SENIORITY_MERGE` domain — matching Go's
    // `buildMergeHelpers` at `worker_allocator.go:1619-1721`.
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
    // empty Vec). Mirrors Go's `worker_allocator.go:1483-1490`. A
    // misconfigured delegate is downgraded to a warning + default
    // empty rather than aborting, so a typo doesn't take the node
    // down — Go logs and aborts the join attempt; we'd rather emit
    // an empty-delegate join (semantically equivalent) than refuse
    // to join.
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
                         defaulting to empty (matches Go behavior when unset)"
                    );
                    Vec::new()
                }
            }
        }
    };

    let prover_pipeline = Arc::new(prover_pipeline::ProverPipeline {
        lifecycle: prover_lifecycle.clone(),
        worker_manager: worker_manager.clone(),
        archive_pool: archive_pool.clone(),
        clock_store: clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
        frame_prover: frame_prover.clone(),
        key_manager: file_key_manager.clone() as Arc<dyn quil_keys::KeyManager + Send + Sync>,
        bls_pubkey: bls_pubkey.clone(),
        prover_address,
        ed448_seed: mtls_seed,
        p2p_handle: p2p_handle.clone(),
        multisig_ed448_seeds,
        delegate_address,
    });

    // Shard orchestration subscriber: watches for ShardSplitEligible /
    // ShardMergeEligible events and submits signed canonical
    // messages via the prover pipeline. Mirrors Go's coverage
    // monitor → shard orchestrator handoff.
    {
        let mut rx = global_event_distributor.subscribe("shard-orchestrator");
        let pp = prover_pipeline.clone();
        let lrf = last_received_frame.clone();
        let cancel = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    maybe_event = rx.recv() => {
                        let Some(event) = maybe_event else { break };
                        let frame = lrf.load(std::sync::atomic::Ordering::Relaxed);
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
        let lrf_for_poller = last_received_frame.clone();
        let lhf_for_poller = last_global_head_frame.clone();
        let pp_for_poller = prover_pipeline.clone();
        let hg_for_poller = hg_store.clone();
        let poller_config = quil_rpc::ArchivePollerConfig {
            on_frame: Some(Arc::new(move |frame: &quil_types::proto::global::GlobalFrame| {
                let frame_num = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
                let frame_difficulty = frame.header.as_ref().map(|h| h.difficulty).unwrap_or(0);
                lrf_for_poller.store(frame_num, std::sync::atomic::Ordering::Relaxed);
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

                // Trigger worker allocation reconciliation
                cov_for_poller.check(frame_num);
                if let Err(e) = wa_for_poller.on_new_frame(frame_num) {
                    tracing::warn!(error = %e, "worker allocation failed");
                }

                // Evaluate prover lifecycle (join/confirm/leave) and
                // dispatch any resulting action through the submission
                // pipeline (VDF + sign + submit on a background task).
                pl_for_poller.set_prover_root_verified_frame(frame_num);
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
            })),
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
            let sync_p2p = p2p_handle.clone();
            let sync_ch = consensus_handle.clone();
            let sync_va = vote_aggregator.clone();
            let sync_ta = timeout_aggregator.clone();
            let sync_cov = coverage_monitor.clone();
            let sync_lrf = last_received_frame.clone();
            let sync_lhf = last_global_head_frame.clone();
            let sync_archive_mode = archive_mode;
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
                if !sync_archive_mode {
                    if let Some(addr) = sync_pool.get_all().await.first() {
                        info!("starting initial prover tree sync");
                        let _ = quil_rpc::ensure_prover_tree(
                            addr, &seed,
                            quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
                            sync_hg.clone(),
                        ).await;
                    // Refresh prover registry from synced data
                    let pr = sync_pr.clone();
                    let hs2 = sync_hg.clone();
                    if let Err(e) = tokio::task::spawn_blocking(move || {
                        pr.refresh_from_store(&hs2);
                    }).await {
                        warn!(error = %e, "prover registry refresh failed");
                    }
                    // Reconstruct coverage streaks from synced prover
                    // data — mirrors Go's `ensureStreakMap` (called once
                    // at startup before any frame-driven check). Without
                    // this, the first eviction pass after a restart
                    // would interpret all previously-stale allocations
                    // as freshly inactive and kick them immediately.
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
                sync_pl.set_sync_complete();
                info!("initial prover tree sync complete, lifecycle enabled");

                    // Check if we're an active prover and build genesis QC.
                    // Try store first, fall back to embedded mainnet genesis.
                    let genesis_frame_result = sync_cs.get_latest_global_frame()
                        .or_else(|_| {
                            info!("no global frame in store, loading embedded mainnet genesis");
                            quil_engine::genesis::load_mainnet_genesis()
                        });

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
                        info!(
                            "not a global prover — skipping global consensus event loop activation",
                        );
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
                                    let lrf_for_fin = sync_lrf.clone();
                                    let lhf_for_fin = sync_lhf.clone();
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
                                        // `fetch_max` keeps these monotonic
                                        // even if finalization callbacks
                                        // arrive slightly out of order.
                                        lrf_for_fin.fetch_max(
                                            app.frame_number,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                        lhf_for_fin.fetch_max(
                                            app.frame_number,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
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
                                        tracing::debug!(
                                            frame = app.frame_number,
                                            rank = app.rank,
                                            "persisting candidate frame",
                                        );
                                        if let Err(e) = cs_trait.put_global_clock_frame_candidate(&frame, &no_txn) {
                                            tracing::debug!(
                                                error = %e,
                                                frame = app.frame_number,
                                                rank = app.rank,
                                                "failed to persist candidate frame",
                                            );
                                        }
                                    })
                                };

                                // When the consumer observes a fresh QC (from
                                // local aggregation or wire receive), persist
                                // it to the clock store so the leader's
                                // `prove_next_state` for rank+1 finds the
                                // correct latest QC. Mirrors Go's
                                // `OnQuorumCertificateTriggeredRankChange` at
                                // `consensus_protocol.go:622`.
                                let qc_observed_hook: quil_engine::consensus_glue::QcObservedHook = {
                                    let cs = sync_cs.clone();
                                    Arc::new(move |qc| {
                                        // Mirror NoTxn shim — clock store's
                                        // QC writer doesn't require atomicity
                                        // with anything else here.
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
                            if let Some(addr) = sync_pool.get_all().await.first() {
                                match quil_rpc::ensure_prover_tree_incremental(
                                    addr, &seed,
                                    quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
                                    sync_hg.clone(),
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
                                        } else {
                                            debug!("incremental sync: tree unchanged");
                                        }
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
    } else {
        warn!("no Ed448 seed available — archive poller disabled (production archives require mTLS)");
    }

    // Broadcast channel for GlobalService::StreamGlobalMessages.
    // Construction here (before recv loop) so the recv loop can
    // feed it; the gRPC server takes a clone later. 256 buffer
    // matches Go's.
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
    let sr_for_recv = signer_registry.clone();
    let lrf_for_recv = last_received_frame.clone();
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
    let pl_for_recv = prover_lifecycle.clone();
    let pr_for_recv = prover_registry.clone();
    let wm_for_recv = worker_manager.clone();
    let reward_issuer = Arc::new(quil_engine::OptRewardIssuance);
    let pa_for_recv = prover_address;
    let p2p_for_recv = p2p_handle.clone();

    // Per-bitmask validator gate (mirrors Go's
    // `pubsub.RegisterValidator` calls in
    // `node/consensus/global/message_router.go`). Malformed bytes are
    // dropped here so the dispatch loop below stays cheap. Topics
    // without a registered validator fall through unchanged, preserving
    // existing behaviour for any bitmask we haven't ported yet.
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
                    // Periodic status log matching Go's allocation status pattern
                    let peer_count = p2p_for_recv.peer_count();
                    let latest_frame = clock_store_recv.get_latest_global_frame()
                        .ok()
                        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
                        .unwrap_or(0);
                    let (active, pending, total_allocs) = {
                        use quil_types::consensus::ProverRegistry;
                        match pr_for_recv.get_prover_info(&pa_for_recv) {
                            Ok(Some(info)) => {
                                let a = info.allocations.iter()
                                    .filter(|a| a.status == quil_types::consensus::ProverStatus::Active)
                                    .count();
                                let p = info.allocations.iter()
                                    .filter(|a| a.status == quil_types::consensus::ProverStatus::Joining)
                                    .count();
                                (a, p, info.allocations.len())
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

                            // Per-topic validator gate. Malformed
                            // bytes are dropped before they reach a
                            // queue (mirrors Go's pubsub.Validator).
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
                                            let mut cache = pic_for_recv.write().unwrap();
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
                                            if is_new && archive_peers_seen.len() == 1 {
                                                if let (Some(seed), Some(addr)) =
                                                    (mtls_seed_for_recv, first_addr)
                                                {
                                                    let store = hg_store_for_recv.clone();
                                                    tokio::spawn(async move {
                                                        use quil_types::proto::application::HypergraphPhaseSet::*;
                                                        for phase in [VertexAdds, VertexRemoves, HyperedgeAdds, HyperedgeRemoves] {
                                                            match quil_rpc::ensure_prover_tree(
                                                                &addr,
                                                                &seed,
                                                                phase,
                                                                store.clone(),
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
                                // Try canonical bytes first (Go publishes in canonical format),
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
                                                lrf_for_recv.store(frame_num, std::sync::atomic::Ordering::Relaxed);
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
                                                        coverage_for_recv.check(frame_num);
                                                        if let Err(e) = wa_for_recv.on_new_frame(frame_num) {
                                                            warn!(error = %e, "worker allocation failed");
                                                        }
                                                        // Evaluate prover lifecycle (join/confirm/leave) and
                                                        // dispatch any resulting action via the pipeline.
                                                        let frame_difficulty = frame.header.as_ref()
                                                            .map(|h| h.difficulty)
                                                            .unwrap_or(0);
                                                        pl_for_recv.set_prover_root_verified_frame(frame_num);
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
                                                            Ok((sp, qc, tc)) => {
                                                                handle.submit_quorum_certificate(qc);
                                                                if let Some(tc) = tc {
                                                                    handle.submit_timeout_certificate(tc);
                                                                }
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
                                                        // Also surface the embedded QC/prior-TC so
                                                        // the event loop fast-forwards even before
                                                        // local TC aggregation completes.
                                                        let qc_for_handle = ts.latest_quorum_certificate.clone().into_trait_object();
                                                        handle.submit_quorum_certificate(qc_for_handle);
                                                        if let Some(tc) = ts.prior_rank_timeout_certificate.clone() {
                                                            handle.submit_timeout_certificate(tc.into_trait_object());
                                                        }
                                                        // Route into the per-rank timeout processor
                                                        // so individual TO signatures aggregate to
                                                        // a local TC.
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
                                // App shard or relay traffic — forwarded by mesh,
                                // no local handler needed for non-subscribed bitmasks.
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
        // (Go's primary path — see `ArchiveClient::submit_global_message`)
        // get their payload routed into the same MessageCollector that
        // BlossomSub GLOBAL_PROVER traffic feeds.
        //
        // Peer identity is extracted by `peer_auth_interceptor` from
        // the TLS client cert's SAN (if any) and attached to the
        // request as `AuthenticatedPeer`. Here we gate the write: no
        // authenticated peer → reject with "unauthenticated peer".
        // Plaintext connections or connections without a parseable
        // Ed448-derived cert fall into that path.
        let submit_mc = message_collector.clone();
        let submit_lrf = last_received_frame.clone();
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
                let rank = submit_lrf.load(std::sync::atomic::Ordering::Relaxed);
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
                wm.range_workers()
                    .unwrap_or_default()
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
        // Mirrors Go's services.go:313-368 tree-walk.
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

        let grpc_server = quil_rpc::GlobalRpcServer::new(
            Arc::new(ClockStoreFrameLookup(clock_store.clone())),
        )
        .with_submit_handler(submit_handler.clone())
        .with_shards_store(shards_store)
        .with_worker_snapshot(global_worker_snap)
        .with_global_shards_provider(global_shards_provider)
        .with_message_broadcast(global_msg_tx.clone());
        let hypersync = quil_rpc::hypersync_server::HyperSyncServer::new(hg_store.clone());

        // NodeService: user-facing RPC for CLI tools. Unlike
        // GlobalService/HypergraphComparisonService (peer-to-peer), this
        // one serves wallet queries, admin controls, and message
        // submission. Its submit_message handler shares the same
        // message-collector path as the gRPC global submit.
        let node_submit_mc = message_collector.clone();
        let node_submit_lrf = last_received_frame.clone();
        let user_submit_handler: quil_rpc::node_service::UserSubmitHandler = Arc::new(
            move |data: Vec<u8>| -> Result<(), String> {
                if data.is_empty() {
                    return Err("empty message".into());
                }
                let rank = node_submit_lrf.load(std::sync::atomic::Ordering::Relaxed);
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
                last_received_frame.clone(),
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
                pic.read().unwrap().values().cloned().collect()
            }));
        }

        // Traversal proof generator: look up the tree blob for
        // (domain, atom_type, phase_type), deserialize, run
        // prove_multiple against the requested keys, and return
        // canonical bytes. Matches Go's `HypergraphCRDT.CreateTraversalProof`.
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

        // Send handler: verify Ed448 authentication over payload under
        // the NODE_AUTHENTICATION||domain prefix, then route the payload
        // to the correct BlossomSub bitmask. Mirrors Go's
        // `RPCServer::Send` (see node/rpc/node_rpc_server.go:567).
        if let Some(seed) = mtls_seed {
            let send_p2p = p2p_handle.clone();
            let peer_ed448_pub = quil_p2p::ed448_identity::derive_public_key(&seed);
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
                        // NODE_AUTHENTICATION || domain is the verification
                        // context fed to ed448 sign/verify.
                        let mut context = Vec::with_capacity(19 + 32);
                        context.extend_from_slice(b"NODE_AUTHENTICATION");
                        context.extend_from_slice(&domain);
                        // Ed448 verify payload with the context as the
                        // "context" arg of RFC 8032 (pre-hashed = false).
                        let pk = ed448_rust::PublicKey::try_from(ed448_pub.as_slice())
                            .map_err(|e| format!("bad pubkey: {:?}", e))?;
                        pk.verify(&payload, &authentication, Some(&context))
                            .map_err(|e| format!("authentication failed: {:?}", e))?;

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
            prover_pipeline: Arc<prover_pipeline::ProverPipeline>,
            last_received_frame: Arc<std::sync::atomic::AtomicU64>,
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
                _delegate: Vec<u8>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
            > {
                let pp = self.prover_pipeline.clone();
                let frame = self
                    .last_received_frame
                    .load(std::sync::atomic::Ordering::Relaxed);
                Box::pin(async move {
                    if frame == 0 {
                        return Err("no frames received yet".into());
                    }
                    pp.submit_join(filters, &[], frame)
                        .await
                        .map_err(|e| e.to_string())
                })
            }
        }
        node_rpc_builder = node_rpc_builder.with_worker_control(Arc::new(WorkerControlBridge {
            worker_manager: worker_manager.clone(),
            prover_pipeline: prover_pipeline.clone(),
            last_received_frame: last_received_frame.clone(),
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
                    if let Ok(list) = wm.range_workers() {
                        let entries: Vec<quil_rpc::WorkerEntry> = list
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
                        *view.write().unwrap() = entries;
                    }
                }
            });
        }
        node_rpc_builder = node_rpc_builder.with_workers_view(workers_view.clone());

        // ShardInfoProvider — backs NodeService::get_shard_info.
        // Implements the trait by walking ProverShardSummary from the
        // registry: active prover count per shard, size, etc.
        struct PrReshardInfoProvider {
            registry: Arc<dyn quil_types::consensus::ProverRegistry>,
            last_received_frame: Arc<std::sync::atomic::AtomicU64>,
        }
        impl quil_types::consensus::ShardInfoProvider for PrReshardInfoProvider {
            fn get_shard_info(
                &self,
                _include_all: bool,
            ) -> quil_types::error::Result<(
                Vec<quil_types::consensus::ShardDetail>,
                u64,
                num_bigint::BigInt,
                u64,
            )> {
                use quil_types::consensus::{ProverStatus, ShardDetail};
                let summaries = self.registry.get_prover_shard_summaries()?;
                let mut details = Vec::with_capacity(summaries.len());
                for s in &summaries {
                    let active = s.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0) as u32;
                    let ring = ((active.saturating_sub(1)) / 8) as u32;
                    details.push(ShardDetail {
                        filter: s.filter.clone(),
                        shard_size: num_bigint::BigInt::from(s.total_size.max(1)),
                        active_provers: active,
                        ring,
                        estimated_reward: num_bigint::BigInt::from(0),
                        is_allocated: false,
                        data_shards: 1,
                    });
                }
                let frame = self.last_received_frame.load(std::sync::atomic::Ordering::Relaxed);
                Ok((details, 0, num_bigint::BigInt::from(0), frame))
            }
        }
        node_rpc_builder = node_rpc_builder.with_shard_info_provider(Arc::new(
            PrReshardInfoProvider {
                registry: prover_registry.clone()
                    as Arc<dyn quil_types::consensus::ProverRegistry>,
                last_received_frame: last_received_frame.clone(),
            },
        ));
        let node_rpc = node_rpc_builder;

        // Mirrors Go's layout (see node/consensus/global/services.go):
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
            // RocksInboxStore; registered on the same mTLS listener
            // Go uses (see node/consensus/global/services.go:545,167).
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

            let tls_config_for_srv = mtls_seed
                .and_then(|s| quil_rpc::build_quil_server_tls_config(&s).ok());

            if let Some(tls_config) = tls_config_for_srv {
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
                tokio::spawn(async move {
                    info!(addr = %addr, "starting peer gRPC (plaintext — no Ed448 seed; peers will reject)");
                    let mut builder = tonic::transport::Server::builder()
                        .add_service(global_service)
                        .add_service(hypersync_service)
                        .add_service(app_shard_service)
                        .add_service(key_registry_service)
                        .add_service(connectivity_service)
                        .add_service(dispatch_service)
                        .add_service(mixnet_service);
                    if let Some(pp) = pubsub_proxy_service {
                        info!("registering PubSubProxy on peer gRPC listener (plaintext)");
                        builder = builder.add_service(pp);
                    }
                    let res = builder
                        .serve_with_shutdown(addr, async move {
                            peer_grpc_token.cancelled().await;
                        })
                        .await;
                    match res {
                        Ok(()) => info!("peer gRPC stopped"),
                        Err(e) => warn!(error = %e, "peer gRPC error"),
                    }
                });
            }
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

    // Open the same database as the master (shared filesystem in
    // cluster mode, or local for same-machine workers).
    let db_path = if config.db.path.is_empty() {
        std::path::PathBuf::from(".config/store")
    } else {
        std::path::PathBuf::from(&config.db.path)
    };
    std::fs::create_dir_all(&db_path)?;
    let db = quil_store::RocksDb::open(&db_path)?;
    let db_arc = Arc::new(db);
    let clock_store: Arc<dyn quil_types::store::ClockStore> =
        Arc::new(quil_store::RocksClockStore::new(db_arc.inner()));

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

    // Master endpoint
    let master_endpoint = quil_engine::worker_node::master_grpc_endpoint(&config.engine);

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
    );

    // When proxy mode is enabled, dial the master's PubSubProxy on
    // the peer mTLS listener and install it as the worker's publish
    // path. Engine-produced events (FrameProduced, VoteProduced,
    // TimeoutProduced) will flow back to the master for broadcast.
    if config.engine.enable_master_proxy {
        let master_addr = quil_engine::worker_node::master_grpc_endpoint(&config.engine);
        // mTLS for the proxy connection requires the same Ed448 cert
        // derivation archive_client uses — that path lives in
        // `quil-rpc::archive_client` today and isn't wired as a
        // reusable `tonic::transport::ClientTlsConfig`. Until that's
        // extracted, the worker connects plaintext to the master's
        // peer gRPC listener, which is acceptable when master and
        // workers are on the same machine (the common standalone
        // layout) and the master is running in plaintext peer mode.
        let endpoint_url = format!("http://{}", master_addr);
        match quil_rpc::proxy_pubsub::ProxyPubSub::connect(endpoint_url, None).await {
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

    let worker = Arc::new(worker_node);

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
/// Proposals go on `GLOBAL_FRAME`, votes and timeouts on `GLOBAL_CONSENSUS`,
/// matching what Go does at `global_consensus_engine.go:publishProposalVote`
/// and `publishFrame`.
struct BlossomsubConsensusPublisher {
    p2p_handle: quil_p2p::node::P2PHandle,
    /// Self-loopback for consensus messages so the local
    /// `vote_aggregator` / event-loop dispatcher sees the leader's
    /// own proposals (BlossomSub does not echo self-published
    /// messages). Mirrors Go's `MessageHub` re-injecting the local
    /// node's outbound proposal into the inbound queue.
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
        // `consensus_glue::wrap_message_request`). Mirror Go's
        // `publishProverMessage` (`global_consensus_engine.go:154-159`)
        // by wrapping in a `MessageBundle` envelope and publishing on
        // the GLOBAL_PROVER bitmask. The full Go path also routes via
        // archive gRPC when a non-archive node is configured; the
        // BlossomSub broadcast covers archive nodes here.
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
