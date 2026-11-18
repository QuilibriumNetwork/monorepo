//! `--query-shards [ip:8340]`: LIVE `GetAppShards` query of the QUIL grid from a
//! (mainnet) archive — the remote equivalent of `--dump-shard-state`'s grid view,
//! showing each sub-shard's decoded prefix, reported `size` (the value that gates
//! `ProposeJoin` / the reward basis), `data_shards`, and the `materialized_frame`
//! / `latest_frame` the archive reports. Read-only; then exit.

use std::path::Path;

use quil_keys::KeyManager as _;

/// Decode a stored grid prefix (`Vec<u32>`) to `(encoding, bits)`.
fn grid_prefix_bits(prefix: &[u32]) -> (&'static str, Vec<bool>) {
    match quil_forest::shard_bit_path_from_prefix(prefix) {
        Some(bits) => ("sentinel", bits),
        None => ("byte-suffix", quil_forest::prefix_to_bits(prefix, 6)),
    }
}

fn bits_str(bits: &[bool]) -> String {
    bits.iter().map(|&b| if b { '1' } else { '0' }).collect()
}

/// Big-endian byte string → u128 (the `size` field is a BE-encoded integer).
fn be_to_u128(b: &[u8]) -> u128 {
    b.iter().fold(0u128, |acc, &x| (acc << 8) | x as u128)
}

/// `--query-prover-root ip:8340`: LIVE read of another node's GLOBAL head and
/// its GLOBAL prover shard root (the forest head of shard `[0xff; 32]`, vertex
/// adds), over the same :8340 mTLS transport the prover-tree sync uses. Only
/// read calls; one JSON line, then exit. Compare the root with
/// `--global-halt-report`'s `next_frame_binds.prover_root` on stopped archives.
pub async fn run_query_prover_root(
    archive_arg: &str,
    config: &quil_config::Config,
    config_dir: &Path,
) -> anyhow::Result<()> {
    let falcon_key = falcon_identity(config, config_dir)?;
    let mut client = quil_rpc::ArchiveClient::connect_mtls(archive_arg, &falcon_key).await?;
    let head = client
        .get_global_frame(0)
        .await
        .ok()
        .and_then(|frame| frame.header);
    let prover = client.get_forest_head(vec![0xffu8; 32], 0).await?;
    println!(
        "{}",
        serde_json::json!({ "prover_root_query": {
            "endpoint": archive_arg,
            "head": head.as_ref().map(|h| serde_json::json!({
                "frame": h.frame_number,
                "output": hex::encode(&h.output[..h.output.len().min(8)]),
                "prover_tree_commitment": hex::encode(&h.prover_tree_commitment),
            })),
            "prover_shard_head": prover.map(|(version, root)| serde_json::json!({
                "version": version,
                "root": hex::encode(root),
            })),
        }})
    );
    Ok(())
}

/// The archives a shard query asks: `archive_arg`, else the configured
/// endpoints, else on mainnet the genesis archives' static endpoints. An
/// endpoint whose peer is known (a genesis archive's, a configured one
/// naming `/p2p/`) is pinned to it in this process, so the dial must reach
/// that archive.
fn query_endpoints(archive_arg: &str, configured: &[String], network: u8) -> Vec<String> {
    if !archive_arg.is_empty() {
        vec![archive_arg.to_string()]
    } else if !configured.is_empty() {
        configured
            .iter()
            .filter_map(|ma| {
                let endpoint = crate::util::multiaddr::archive_multiaddr_to_host_port(ma, network)?;
                if let Some(peer) = crate::util::multiaddr::archive_multiaddr_peer(ma) {
                    // A conflicting entry keeps the first pin: its dial fails.
                    let _ = quil_rpc::archive_client::pin_archive_peer(&endpoint, peer);
                }
                Some(endpoint)
            })
            .collect()
    } else if network == 0 {
        crate::master_node::pin_genesis_archive_endpoints()
    } else {
        Vec::new()
    }
}

/// The error of a tool whose keystore holds a prover key it cannot use as
/// the Falcon network identity.
pub(crate) fn falcon_key_unavailable(keys_path: &Path, e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "load Falcon network identity key from the keystore {}: {e}. A q-prover-key from \
         before the Falcon migration is migrated when the node starts once; otherwise check \
         key.keyManagerFile.encryptionKey",
        keys_path.display()
    )
}

/// The node's Falcon network identity (the :8340 mTLS key), self-contained
/// like `keys::init`.
pub(crate) fn falcon_identity(
    config: &quil_config::Config,
    config_dir: &Path,
) -> anyhow::Result<Vec<u8>> {
    let keys_path =
        quil_keys::resolve_existing_keystore_path(&config.key.key_store_file, config_dir)?;
    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "default-proving-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };
    let file_key_manager = quil_keys::FileKeyManager::new(
        keys_path.clone(),
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(quil_crypto::FalconKeyConstructor),
    )?;
    file_key_manager.set_peer_priv_key_hex(&config.p2p.peer_priv_key);
    file_key_manager
        .get_private_key(quil_types::crypto::KeyType::Falcon512)
        .map_err(|e| crate::query_shards::falcon_key_unavailable(&keys_path, e))
}

pub async fn run_query_shards(
    archive_arg: &str,
    config: &quil_config::Config,
    config_dir: &Path,
    network: u8,
) -> anyhow::Result<()> {
    println!("=== QUIL SHARD QUERY (live GetAppShards) ===");
    println!("network: {network}");

    // Falcon signing key (the :8340 mTLS identity), self-contained like keys::init.
    let keys_path =
        quil_keys::resolve_existing_keystore_path(&config.key.key_store_file, config_dir)?;
    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "default-proving-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };
    let file_key_manager = quil_keys::FileKeyManager::new(
        keys_path.clone(),
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(quil_crypto::FalconKeyConstructor),
    )?;
    file_key_manager.set_peer_priv_key_hex(&config.p2p.peer_priv_key);
    let falcon_key = file_key_manager
        .get_private_key(quil_types::crypto::KeyType::Falcon512)
        .map_err(|e| crate::query_shards::falcon_key_unavailable(&keys_path, e))?;

    let endpoints = query_endpoints(archive_arg, &config.engine.archive_endpoints, network);
    if endpoints.is_empty() {
        anyhow::bail!("no archive endpoint — pass `ip:8340`, or set engine.archiveEndpoints, or use network 0");
    }
    println!("endpoints: {}", endpoints.join(", "));

    // QUIL grid key: l1(3) ‖ l2(32).
    let quil = quil_execution::domains::QUIL_TOKEN;
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3);
    let mut grid_key = l1.to_vec();
    grid_key.extend_from_slice(&quil);

    let mut reached = 0usize;
    for addr in &endpoints {
        println!("\n--- archive {addr} ---");
        let mut client = match quil_rpc::ArchiveClient::connect_mtls(addr, &falcon_key).await {
            Ok(c) => c,
            Err(e) => {
                println!("  connect_mtls failed: {e}");
                continue;
            }
        };
        let head_frame = client
            .get_global_frame(0)
            .await
            .ok()
            .and_then(|f| f.header.map(|h| h.frame_number));
        let shards = match client.get_app_shards(grid_key.clone(), Vec::new()).await {
            Ok(s) => s,
            Err(e) => {
                println!("  get_app_shards failed: {e}");
                continue;
            }
        };
        reached += 1;

        // TRUE forest leaf count per shard — navigate the UNIFIED app tree's subtree
        // at each shard's bit-path over a RemoteTreeReader and read the JMT node's
        // native leaf count. INDEPENDENT of the sub_meta `size` index (which is stale
        // post-split until rebucket), so it shows where the data ACTUALLY is — a few
        // node fetches per shard, not a full-tree sync.
        let quil_vec = quil.to_vec();
        let forest_version = client
            .get_forest_head(quil_vec.clone(), 0)
            .await
            .ok()
            .flatten()
            .map(|(v, _)| v);
        let all_bits: Vec<Vec<bool>> = shards
            .iter()
            .map(|s| grid_prefix_bits(&s.prefix).1)
            .collect();
        let forest_by_bits: std::collections::HashMap<Vec<bool>, u64> = match forest_version {
            Some(ver) => {
                let fc = client.clone();
                let handle = tokio::runtime::Handle::current();
                let bits_owned = all_bits.clone();
                let counts = tokio::task::spawn_blocking(move || {
                    let reader = quil_rpc::RemoteTreeReader::new(fc, handle, quil_vec, 0);
                    bits_owned
                        .iter()
                        .map(|b| quil_forest::subtree_leaf_count(&reader, ver, b).unwrap_or(0))
                        .collect::<Vec<u64>>()
                })
                .await
                .unwrap_or_default();
                all_bits.into_iter().zip(counts).collect()
            }
            None => Default::default(),
        };

        // Decode every row to (bits, size, data_shards, mat, latest, forest_leaves).
        let mut rows: Vec<(Vec<bool>, u128, u64, u64, u64, u64)> = shards
            .iter()
            .map(|s| {
                let (_enc, bits) = grid_prefix_bits(&s.prefix);
                let forest = forest_by_bits.get(&bits).copied().unwrap_or(0);
                (
                    bits,
                    be_to_u128(&s.size),
                    s.data_shards,
                    s.materialized_frame,
                    s.latest_frame,
                    forest,
                )
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));

        // Depth histogram.
        let mut by_depth: std::collections::BTreeMap<usize, usize> = Default::default();
        for (bits, ..) in &rows {
            *by_depth.entry(bits.len()).or_insert(0) += 1;
        }
        // Prefix-freeness: a row whose bit-path is a STRICT prefix of another row
        // is an overlap (both cover the same address space — an invalid grid).
        let paths: Vec<&Vec<bool>> = rows.iter().map(|(b, ..)| b).collect();
        let overlaps = paths
            .iter()
            .filter(|p| paths.iter().any(|o| o.len() > p.len() && o.starts_with(p)))
            .count();
        let total_size: u128 = rows.iter().map(|(_, sz, ..)| *sz).sum();
        let total_forest: u64 = rows.iter().map(|(.., f)| *f).sum();
        let size_nonzero = rows.iter().filter(|(_, sz, ..)| *sz > 0).count();
        let forest_nonzero = rows.iter().filter(|(.., f)| *f > 0).count();
        let mat_nonzero = rows.iter().filter(|(_, _, _, m, _, _)| *m > 0).count();
        let latest_nonzero = rows.iter().filter(|(_, _, _, _, l, _)| *l > 0).count();

        println!(
            "  head frame: {}",
            head_frame.map(|n| n.to_string()).unwrap_or("?".into())
        );
        println!(
            "  grid: {} rows | depths {} | overlaps(prefix-of-another): {}",
            rows.len(),
            by_depth
                .iter()
                .map(|(d, c)| format!("d{d}={c}"))
                .collect::<Vec<_>>()
                .join(" "),
            overlaps
        );
        println!(
            "  FOREST leaves (truth): {} rows>0 of {} | total={}",
            forest_nonzero,
            rows.len(),
            total_forest
        );
        println!(
            "  sub_meta size (index): {} rows>0 | total={} | mat_frame>0: {} | latest_frame>0: {}",
            size_nonzero, total_size, mat_nonzero, latest_nonzero
        );
        // Any shard with real forest data OR a nonzero size index — the discrepancy
        // between the two columns is the rebucket bug's footprint.
        for (bits, sz, ds, mat, latest, forest) in
            rows.iter().filter(|(_, sz, .., f)| *sz > 0 || *f > 0)
        {
            println!(
                "    {:<12} forest_leaves={forest:<12} sub_meta_size={sz:<14} data_shards={ds} mat={mat} latest={latest}",
                bits_str(bits)
            );
        }
    }

    println!(
        "\n=== QUERY COMPLETE ({reached}/{} archives reached) ===",
        endpoints.len()
    );
    if reached == 0 {
        anyhow::bail!("no reachable archive answered GetAppShards");
    }
    Ok(())
}

#[cfg(test)]
mod r112_d2_tests {
    use super::query_endpoints;

    /// R112-D-2: a shard query of the genesis archives dials each static
    /// endpoint pinned to its archive.
    #[test]
    fn r112_d2_a_shard_query_pins_the_genesis_archive_endpoints() {
        let endpoints = query_endpoints("", &[], 0);
        assert!(!endpoints.is_empty());
        for (peer_id, ip) in quil_engine::genesis::genesis_archive_static_ips() {
            let endpoint = format!("{ip}:8340");
            assert!(endpoints.contains(&endpoint));
            assert_eq!(
                quil_rpc::archive_client::pinned_archive_peer(&endpoint),
                Some(peer_id.parse::<quil_p2p::PeerId>().unwrap()),
                "R112-D-2: a shard query dials the genesis archive endpoint {endpoint} unpinned"
            );
        }
    }
}
