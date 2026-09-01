//! `--query-shards [ip:8340]`: LIVE `GetAppShards` query of the QUIL grid from a
//! (mainnet) archive — the remote equivalent of `--dump-shard-state`'s grid view,
//! showing each sub-shard's decoded prefix, reported `size` (the value that gates
//! `ProposeJoin` / the reward basis), `data_shards`, and the `materialized_frame`
//! / `latest_frame` the archive reports. Read-only; then exit.

use std::path::{Path, PathBuf};

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

pub async fn run_query_shards(
    archive_arg: &str,
    config: &quil_config::Config,
    config_dir: &Path,
    network: u8,
) -> anyhow::Result<()> {
    println!("=== QUIL SHARD QUERY (live GetAppShards) ===");
    println!("network: {network}");

    // Falcon signing key (the :8340 mTLS identity), self-contained like keys::init.
    let keys_path = if config.key.key_store_file.path.is_empty() {
        config_dir.join("keys.yml")
    } else {
        PathBuf::from(&config.key.key_store_file.path)
    };
    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "default-proving-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };
    let file_key_manager = quil_keys::FileKeyManager::new(
        keys_path,
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(quil_crypto::FalconKeyConstructor),
    )?;
    file_key_manager.set_peer_priv_key_hex(&config.p2p.peer_priv_key);
    file_key_manager.ensure_standard_keys()?;
    let falcon_key = file_key_manager
        .get_private_key(quil_types::crypto::KeyType::Falcon512)
        .map_err(|e| anyhow::anyhow!("load Falcon network identity key: {e}"))?;

    let endpoints: Vec<String> = if !archive_arg.is_empty() {
        vec![archive_arg.to_string()]
    } else if !config.engine.archive_endpoints.is_empty() {
        config
            .engine
            .archive_endpoints
            .iter()
            .filter_map(|ma| crate::util::multiaddr::archive_multiaddr_to_host_port(ma, network))
            .collect()
    } else if network == 0 {
        quil_engine::genesis::genesis_archive_static_ips()
            .into_iter()
            .map(|(_pid, ip)| format!("{ip}:8340"))
            .collect()
    } else {
        Vec::new()
    };
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
        let all_bits: Vec<Vec<bool>> =
            shards.iter().map(|s| grid_prefix_bits(&s.prefix).1).collect();
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

        println!("  head frame: {}", head_frame.map(|n| n.to_string()).unwrap_or("?".into()));
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

    println!("\n=== QUERY COMPLETE ({reached}/{} archives reached) ===", endpoints.len());
    if reached == 0 {
        anyhow::bail!("no reachable archive answered GetAppShards");
    }
    Ok(())
}
