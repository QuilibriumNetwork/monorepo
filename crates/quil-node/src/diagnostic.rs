use std::path::PathBuf;

use tracing::{error, info};

// Import KeyManager trait for get_public_key
use quil_keys::KeyManager as _;

pub(crate) struct DiagnosticFlags {
    pub peer_id: bool,
    pub node_info: bool,
    pub peer_info: bool,
    pub network: u8,
}

/// Handle any of `--peer-id`, `--node-info`, `--peer-info` by printing the
/// requested info to stdout. Returns `Ok(true)` if a flag fired (caller
/// should exit), `Ok(false)` if none fired (caller should continue).
/// (`--metrics` is handled separately in main — it needs an async gRPC dial
/// to the running node; see [`print_metrics_from_node`].)
pub(crate) fn handle_diagnostic_flags(
    args: &DiagnosticFlags,
    config: &quil_config::Config,
) -> anyhow::Result<bool> {
    if args.peer_id {
        // libp2p peer ID — multihash of the FALCON q-prover-key (the network
        // identity), base58-encoded. Matches what the prover-manage TUI and the
        // NodeService RPC report. (The Poseidon-of-prover-pubkey is a separate
        // "prover address" identifier; see --node-info.)
        use quil_keys::KeyManager as _;
        let fkm = quil_keys::FileKeyManager::new(
            PathBuf::from(&config.key.key_store_file.path),
            &config.key.key_store_file.encryption_key,
            if config.engine.proving_key_id.is_empty() {
                "q-prover-key".to_string()
            } else {
                config.engine.proving_key_id.clone()
            },
            Box::new(quil_crypto::FalconKeyConstructor),
        )?;
        let bls_pubkey = fkm.get_public_key(quil_types::crypto::KeyType::Falcon512)?;
        let peer_id = quil_p2p::peer_id_from_falcon_pubkey(&bls_pubkey);
        println!("{}", bs58::encode(&peer_id).into_string());
        return Ok(true);
    }

    if args.node_info {
        let bls_ctor = quil_crypto::FalconKeyConstructor;
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
        let bls_pubkey = fkm.get_public_key(quil_types::crypto::KeyType::Falcon512)?;
        let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;

        // Peer ID — base58-encoded libp2p multihash derived from the FALCON
        // q-prover-key (the network identity). This is what shows up in the
        // prover-manage TUI and the NodeService GetNodeInfo RPC.
        let peer_id_b58 =
            bs58::encode(quil_p2p::peer_id_from_falcon_pubkey(&bls_pubkey)).into_string();

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
        return Ok(true);
    }

    if args.peer_info {
        // Legacy Ed448 peer id — the pre-migration network identity, retained
        // only as the seniority root / legacy coin addressing. Shown as a
        // clearly-labeled legacy line, NOT as the current "Peer ID".
        let legacy_peer_id_b58 = {
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
        let bls_ctor = quil_crypto::FalconKeyConstructor;
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
        let bls_pubkey = fkm.get_public_key(quil_types::crypto::KeyType::Falcon512)?;
        // Current network identity — the FALCON q-prover-key peer id (matches
        // --peer-id, --node-info, the prover-manage TUI, and GetNodeInfo RPC).
        let peer_id_b58 =
            bs58::encode(quil_p2p::peer_id_from_falcon_pubkey(&bls_pubkey)).into_string();
        println!("Peer ID: {}", peer_id_b58);
        println!("Legacy Peer ID (Ed448): {}", legacy_peer_id_b58);
        println!("BLS Public Key Length: {} bytes", bls_pubkey.len());
        println!("Listen Multiaddr: {}", config.p2p.listen_multiaddr);
        return Ok(true);
    }

    Ok(false)
}

/// `--metrics` (Go parity: `node -metrics` dialed the RUNNING node's gRPC
/// `GetMetrics` and printed the result): connect to the node's NodeService
/// on the configured `listenGrpcMultiaddr` and print the full prometheus
/// text snapshot — engine/execution/RPC facade metrics plus the p2p
/// blossomsub_*/libp2p_* families. `filter` is a substring match applied
/// server-side (same semantics as Go's NodeService::GetMetrics).
pub(crate) async fn print_metrics_from_node(
    config: &quil_config::Config,
    filter: Option<&str>,
) -> anyhow::Result<()> {
    let addr = grpc_dial_addr(&config.listen_grpc_multiaddr);
    let endpoint = format!("http://{addr}");
    // quil-types' tonic has no `transport` feature (its generated clients
    // lack `connect`), so build the channel with quil-node's tonic and hand
    // it over.
    let channel = tonic::transport::Endpoint::from_shared(endpoint.clone())
        .map_err(|e| anyhow::anyhow!("bad gRPC endpoint {endpoint}: {e}"))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .connect()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "could not connect to the running node's gRPC at {endpoint}: {e} — \
                 is the node running, with listenGrpcMultiaddr enabled?"
            )
        })?;
    let mut client =
        quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    let resp = client
        .get_metrics(quil_types::proto::node::GetMetricsRequest {
            filter: filter.unwrap_or_default().to_string(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("GetMetrics RPC failed: {e}"))?
        .into_inner();
    print!("{}", String::from_utf8_lossy(&resp.metrics));
    Ok(())
}

/// The dialable `host:port` for the node's own gRPC listener. A wildcard
/// bind (0.0.0.0) is dialed via loopback; empty/unparseable falls back to
/// the default gRPC port.
fn grpc_dial_addr(listen_multiaddr: &str) -> String {
    let parts: Vec<&str> = listen_multiaddr.trim_start_matches('/').split('/').collect();
    if parts.len() >= 4 && parts[0] == "ip4" && parts[2] == "tcp" {
        let host = if parts[1] == "0.0.0.0" { "127.0.0.1" } else { parts[1] };
        format!("{}:{}", host, parts[3])
    } else {
        "127.0.0.1:8337".to_string()
    }
}

/// Handle `--import-db` by importing Pebble/file/stdin data into a fresh
/// RocksDB at the configured path.
pub(crate) fn run_import(
    import_path: &std::path::Path,
    config: &quil_config::Config,
) -> anyhow::Result<()> {
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
    Ok(())
}
