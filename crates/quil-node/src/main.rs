use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

// Import KeyManager trait for get_public_key/get_signer methods
use quil_keys::KeyManager as _;

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
    let diag_flags = diagnostic::DiagnosticFlags {
        peer_id: args.peer_id,
        node_info: args.node_info,
        peer_info: args.peer_info,
        metrics: args.metrics,
        metrics_filter: args.metrics_filter.clone(),
        network: args.network,
    };
    if diagnostic::handle_diagnostic_flags(&diag_flags, &config)? {
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
        diagnostic::run_import(import_path, &config)?;
        return Ok(());
    }

    // Select node mode
    match (args.core, args.dht_only) {
        (_, true) => {
            info!("starting in DHT-only mode");
            dht_node::run(&config, token).await
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
            worker_node::run(&config, core_id, args.parent_process, token).await
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
    let storage = master_node::storage::init(config, archive_mode)?;
    let db_arc = storage.db_arc.clone();
    let clock_store = storage.clock_store.clone();
    let token_store = storage.token_store.clone();
    let key_store = storage.key_store.clone();
    let shards_store = storage.shards_store.clone();
    let hg_store = storage.hg_store.clone();

    let keys = master_node::keys::init(config, config_dir)?;
    let file_key_manager = keys.file_key_manager.clone();
    let bls_pubkey = keys.bls_pubkey.clone();
    let prover_address = keys.prover_address;

    let engines = master_node::engines::init_engines(&storage);
    let inclusion_prover = engines.inclusion_prover.clone();
    let _key_manager = engines.key_manager.clone();
    let crdt = engines.crdt.clone();
    let exec_manager = engines.exec_manager.clone();
    master_node::engines::bootstrap_genesis(network, config, &storage, &engines, &bls_pubkey)?;


    let master_node::frame_pipeline::FramePipeline {
        frame_prover,
        frame_validator,
        fee_manager,
    } = master_node::frame_pipeline::init();

    let master_node::networking::P2pHandles {
        p2p_handle,
        msg_rx,
        peer_id,
        consensus_loopback_tx,
        consensus_loopback_rx,
        listen_addr,
    } = master_node::networking::init(config, config_dir, network, archive_mode).await?;

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
    master_node::peer_info_publisher::spawn(master_node::peer_info_publisher::PeerInfoPublisherArgs {
        p2p_handle: p2p_handle.clone(),
        token: token.clone(),
        peer_id,
        peer_priv_key_hex: config.p2p.peer_priv_key.clone(),
        announce_listen_multiaddr: config.p2p.announce_listen_multiaddr.clone(),
        announce_stream_listen_multiaddr: config.p2p.announce_stream_listen_multiaddr.clone(),
        stream_listen_multiaddr: config.p2p.stream_listen_multiaddr.clone(),
        listen_fallback: listen_addr.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        worker_p2p_multiaddrs: config.engine.data_worker_p2p_multiaddrs.clone(),
        worker_stream_multiaddrs: config.engine.data_worker_stream_multiaddrs.clone(),
        worker_announce_p2p: config.engine.data_worker_announce_p2p_multiaddrs.clone(),
        worker_announce_stream: config.engine.data_worker_announce_stream_multiaddrs.clone(),
        worker_manager_cell: pi_worker_manager.clone(),
        bls_pubkey: bls_pubkey.clone(),
        key_manager: file_key_manager.clone(),
        exec_manager: exec_manager.clone(),
        archive_mode,
    });

    let master_node::runtime_state::RuntimeState {
        message_collector,
        prover_registry,
        prover_only_flag: _prover_only_flag,
        global_event_distributor,
        coverage_monitor,
        halt_state,
        remote_worker_manager_for_halt,
    } = master_node::runtime_state::init(hg_store.clone(), shard_engines.clone(), token.clone());

    let worker_manager: Arc<dyn quil_engine::worker::WorkerManager> = master_node::worker_manager::init(
        master_node::worker_manager::WorkerManagerArgs {
            config: config.clone(),
            archive_mode,
            token: token.clone(),
            p2p_handle: p2p_handle.clone(),
            db_arc: db_arc.clone(),
            clock_store: clock_store.clone(),
            crdt: crdt.clone(),
            exec_manager: exec_manager.clone(),
            inclusion_prover: inclusion_prover.clone(),
            frame_prover: frame_prover.clone(),
            message_collector: message_collector.clone(),
            fee_manager: fee_manager.clone(),
            prover_registry: prover_registry.clone(),
            halt_state: halt_state.clone(),
            file_key_manager: file_key_manager.clone(),
            prover_address,
            bls_pubkey: bls_pubkey.clone(),
            shard_engines: shard_engines.clone(),
            remote_worker_manager_for_halt: remote_worker_manager_for_halt.clone(),
            pi_worker_manager: pi_worker_manager.clone(),
        },
    );

    let master_node::allocator_and_lifecycle::LifecycleHandles {
        worker_allocator,
        consensus_handle,
        vote_aggregator,
        timeout_aggregator,
        prover_lifecycle,
        frame_materializer,
    } = master_node::allocator_and_lifecycle::init(master_node::allocator_and_lifecycle::LifecycleInitArgs {
        config: config.clone(),
        network,
        archive_mode,
        token: token.clone(),
        worker_manager: worker_manager.clone(),
        prover_registry: prover_registry.clone(),
        prover_address,
        halt_state: halt_state.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        shards_store: shards_store.clone(),
        exec_manager: exec_manager.clone(),
        frame_prover: frame_prover.clone(),
        inclusion_prover: inclusion_prover.clone(),
        clock_store: clock_store.clone(),
        crdt: crdt.clone(),
        hg_store: hg_store.clone(),
    });

    // ---------------------------------------------------------------
    // 6. Message receive loop
    // ---------------------------------------------------------------
    info!(archive = archive_mode, "master node initialized — waiting for frames");


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

    // Pre-seed the archive pool. Precedence matches the Go node
    // (`node/main.go:737-741`):
    //   1. If `engine.archiveEndpoints` is non-empty, use those.
    //   2. Else, on mainnet (network == 0), fall back to the hardcoded
    //      genesis-archive static IPs.
    //   3. Else, nothing — PeerInfo gossip will populate the pool once
    //      the libp2p mesh converges.
    // The pool needs at least one reachable endpoint before the mesh
    // converges so the shard-info remote fallback (and any other
    // archive-pool consumer) has somewhere to dial. mTLS gRPC
    // convention is TCP/8340.
    if !config.engine.archive_endpoints.is_empty() {
        for raw in &config.engine.archive_endpoints {
            match crate::util::multiaddr::archive_multiaddr_to_host_port(raw, network) {
                Some(endpoint) => {
                    archive_pool.add(endpoint.clone()).await;
                    tracing::debug!(
                        multiaddr = %raw,
                        endpoint = %endpoint,
                        "seeded archive pool from engine.archiveEndpoints"
                    );
                }
                None => {
                    tracing::warn!(
                        multiaddr = %raw,
                        "skipping invalid engine.archiveEndpoints entry (expected /ip4|ip6|dns4|dns6|dns/.../tcp/PORT)"
                    );
                }
            }
        }
    } else if network == 0 {
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

    // Production transport: gRPC fan-out to archives. Archive nodes
    // also publish on BlossomSub for maximum dissemination; non-archive
    // nodes skip the gossip publish (they don't subscribe to
    // GLOBAL_PROVER so publishing into it is wasteful and unreliable).
    let prover_message_transport: Arc<dyn quil_engine::prover_message_transport::ProverMessageTransport> =
        Arc::new(crate::prover_message_transport_prod::ProdProverMessageTransport {
            archive_pool: archive_pool.clone(),
            clock_store: clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
            p2p_handle: p2p_handle.clone(),
            ed448_seed: mtls_seed,
            publish_to_blossomsub: archive_mode,
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

    master_node::archive_sync::spawn_all(master_node::archive_sync::ArchiveSyncArgs {
        mtls_seed,
        network,
        archive_mode,
        token: token.clone(),
        archive_pool: archive_pool.clone(),
        clock_store: clock_store.clone(),
        hg_store: hg_store.clone(),
        crdt: crdt.clone(),
        shards_store: shards_store.clone(),
        exec_manager: exec_manager.clone(),
        worker_allocator: worker_allocator.clone(),
        prover_lifecycle: prover_lifecycle.clone(),
        prover_registry: prover_registry.clone(),
        worker_manager: worker_manager.clone(),
        coverage_monitor: coverage_monitor.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        prover_pipeline: prover_pipeline.clone(),
        file_key_manager: file_key_manager.clone(),
        frame_prover: frame_prover.clone(),
        message_collector: message_collector.clone(),
        bls_pubkey: bls_pubkey.clone(),
        prover_address,
        p2p_handle: p2p_handle.clone(),
        consensus_handle: consensus_handle.clone(),
        vote_aggregator: vote_aggregator.clone(),
        timeout_aggregator: timeout_aggregator.clone(),
        db_arc: db_arc.clone(),
        frame_materializer: frame_materializer.clone(),
        consensus_loopback_tx: consensus_loopback_tx.clone(),
        peer_id,
    });

    #[allow(unreachable_code, dead_code, clippy::diverging_sub_expression)]
    if false { if let Some(seed) = mtls_seed {
        // (periodic sync block — moved to master_node/archive_sync.rs)
        if false {
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
                    // Global consensus (HotStuff over the global frame
                    // chain) is archive-only. In Go this is gated on
                    // `isConsensusParticipant() = ArchiveMode || Network == 99`.
                    // Non-archive provers participate in per-shard consensus
                    // (via AppConsensusEngine) but NOT in global consensus —
                    // they receive finalized global frames from the archive
                    // poller. Running the global event loop on a non-archive
                    // produces proposals/votes on GLOBAL_CONSENSUS that
                    // (a) flood the mesh, (b) get looped back to the receive
                    // dispatch and forwarded to workers, (c) cause QC
                    // verification failures with genesis-shaped all-zero
                    // signatures.
                    let is_consensus_participant = sync_archive_mode || network == 99;
                    if !is_consensus_participant {
                        info!(
                            "non-archive, non-devnet — skipping global consensus event loop activation \
                             (global frames arrive via the archive poller)",
                        );
                    } else if !is_global_prover {
                        info!(
                            "archive/devnet but not a global prover — skipping global consensus activation",
                        );
                    } else if genesis_frame_result.is_ok() {
                        if let Ok(genesis_frame) = genesis_frame_result {
                            if let Ok(bls_signer) = sync_km.get_signer(quil_types::crypto::KeyType::Bls48581G1) {
                                let publisher: Arc<dyn quil_engine::consensus_glue::ConsensusPublisher> =
                                    Arc::new(crate::blossomsub_consensus_publisher::BlossomsubConsensusPublisher {
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
    } }

    // Broadcast channel for GlobalService::StreamGlobalMessages.
    // Construction here (before recv loop) so the recv loop can
    // feed it; the gRPC server takes a clone later.
    let global_msg_tx: tokio::sync::broadcast::Sender<
        quil_types::proto::global::StreamGlobalMessagesResponse,
    > = tokio::sync::broadcast::channel(
        quil_rpc::global_service::GLOBAL_MESSAGE_BROADCAST_CAPACITY,
    )
    .0;
    master_node::message_loop::spawn(master_node::message_loop::MessageLoopArgs {
        clock_store: clock_store.clone(),
        exec_manager: exec_manager.clone(),
        token: token.clone(),
        msg_rx,
        consensus_loopback_rx,
        global_msg_tx: global_msg_tx.clone(),
        archive_pool: archive_pool.clone(),
        mtls_seed,
        hg_store: hg_store.clone(),
        frame_validator,
        message_collector: message_collector.clone(),
        coverage_monitor: coverage_monitor.clone(),
        worker_allocator: worker_allocator.clone(),
        prover_pipeline: prover_pipeline.clone(),
        consensus_handle: consensus_handle.clone(),
        vote_aggregator: vote_aggregator.clone(),
        timeout_aggregator: timeout_aggregator.clone(),
        peer_info_cache: peer_info_cache.clone(),
        shard_engines: shard_engines.clone(),
        signer_registry: signer_registry.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        genesis_archive_peer_ids: genesis_archive_peer_ids.clone(),
        genesis_prover_addrs: genesis_prover_addrs.clone(),
        alert_pubkey: hex::decode(&config.engine.alert_key).unwrap_or_default(),
        network,
        archive_mode,
        prover_lifecycle: prover_lifecycle.clone(),
        prover_registry: prover_registry.clone(),
        worker_manager: worker_manager.clone(),
        prover_address,
        p2p_handle: p2p_handle.clone(),
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

#[cfg(test)]
mod tests {
    use crate::util::multiaddr::archive_multiaddr_to_host_port;

    #[test]
    fn archive_multiaddr_accepts_ip4() {
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/1.2.3.4/tcp/8340", 0),
            Some("1.2.3.4:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_accepts_ip6() {
        assert_eq!(
            archive_multiaddr_to_host_port("/ip6/2001:db8::1/tcp/8340", 0),
            Some("[2001:db8::1]:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_accepts_dns4() {
        assert_eq!(
            archive_multiaddr_to_host_port("/dns4/archive.example.com/tcp/8340", 0),
            Some("archive.example.com:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_accepts_dns6() {
        assert_eq!(
            archive_multiaddr_to_host_port("/dns6/archive.example.com/tcp/8340", 0),
            Some("archive.example.com:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_accepts_dns() {
        assert_eq!(
            archive_multiaddr_to_host_port("/dns/archive.example.com/tcp/8340", 0),
            Some("archive.example.com:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_rejects_bare_host_port() {
        assert_eq!(archive_multiaddr_to_host_port("archive.example.com:8340", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("1.2.3.4:8340", 0), None);
    }

    #[test]
    fn archive_multiaddr_rejects_non_tcp() {
        assert_eq!(archive_multiaddr_to_host_port("/ip4/1.2.3.4/udp/8340", 0), None);
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/1.2.3.4/udp/8340/quic-v1", 0),
            None
        );
    }

    #[test]
    fn archive_multiaddr_rejects_malformed() {
        assert_eq!(archive_multiaddr_to_host_port("", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/1.2.3.4", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4//tcp/8340", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/1.2.3.4/tcp/", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/1.2.3.4/tcp/notaport", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/dns4//tcp/8340", 0), None);
    }

    #[test]
    fn archive_multiaddr_rejects_private_ip_on_mainnet() {
        assert_eq!(archive_multiaddr_to_host_port("/ip4/192.168.1.1/tcp/8340", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/10.0.0.1/tcp/8340", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/127.0.0.1/tcp/8340", 0), None);
    }

    #[test]
    fn archive_multiaddr_allows_private_ip_on_devnet() {
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/192.168.1.1/tcp/8340", 1),
            Some("192.168.1.1:8340".into())
        );
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/127.0.0.1/tcp/8340", 1),
            Some("127.0.0.1:8340".into())
        );
    }
}
