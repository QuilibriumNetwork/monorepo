//! `--test-prover-sync [ip:8340]`: LIVE check that the root-addressed prover-tree
//! state-jump sync works against a real archive.
//!
//! Connects to an archive over the same :8340 Falcon-mTLS a node dials with,
//! pulls its HEAD global frame (so its `prover_tree_commitment` — the
//! `prover_root_at(N-1)` PRE-application anchor — is the sync target), then runs
//! [`crate::forest_sync::sync_single_shard_verified`] for the global prover shard
//! (`[0xff; 32]`) into a FRESH in-memory forest and checks the synced vertex-adds
//! root equals that anchor. This exercises `resolve_root` → sync-at-version end to
//! end: if the peer serves the anchored (pre-N) version the synced root MATCHES;
//! if it were serving its live head the root would MISMATCH (the old off-by-one).
//! Read-only against the archive; needs the node's keystore for the mTLS identity.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use quil_keys::KeyManager as _;

pub async fn run_test_prover_sync(
    archive_arg: &str,
    config: &quil_config::Config,
    config_dir: &Path,
    network: u8,
) -> anyhow::Result<()> {
    println!("=== PROVER-TREE SYNC TEST (root-addressed, live archive) ===");
    println!("network: {network}");

    // 1. Load the Falcon signing key (the :8340 mTLS identity), mirroring the
    //    node's `keys::init` — self-contained so this offline tool has no other
    //    boot deps.
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

    // 2. Resolve archive endpoint(s): explicit `ip:port` arg, else config's
    //    `engine.archiveEndpoints`, else (network 0) the embedded genesis archives.
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
        anyhow::bail!(
            "no archive endpoint — pass `ip:8340`, or set engine.archiveEndpoints, or use network 0"
        );
    }
    println!("endpoints: {}", endpoints.join(", "));

    let prover_shard = [0xffu8; 32];
    let prover_key = quil_types::store::ShardKey { l1: [0u8; 3], l2: prover_shard };
    let mut any_match = false;

    for addr in &endpoints {
        println!("\n--- archive {addr} ---");

        // 3. Pull the HEAD global frame → anchor = its prover_tree_commitment.
        let hdr = match quil_rpc::ArchiveClient::connect_mtls(addr, &falcon_key).await {
            Ok(mut c) => match c.get_global_frame(0).await {
                Ok(f) => f.header,
                Err(e) => {
                    println!("  get_global_frame failed: {e}");
                    continue;
                }
            },
            Err(e) => {
                println!("  connect_mtls failed: {e}");
                continue;
            }
        };
        let Some(hdr) = hdr else {
            println!("  head frame has no header");
            continue;
        };
        let n = hdr.frame_number;
        let anchor = hdr.prover_tree_commitment.clone();
        println!("  head frame N = {n}");
        println!(
            "  anchor = frame N prover_tree_commitment (= prover_root_at(N-1)): {}",
            hex::encode(&anchor)
        );
        if anchor.iter().all(|b| *b == 0) || anchor.is_empty() {
            println!("  anchor empty/zero — skipping");
            continue;
        }

        // 4. Show what version/frame the anchor resolves to on this peer — the
        //    root-addressing step. Expect frame N-1 (the pre-N committed state).
        if let Ok(anchor32) = <[u8; 32]>::try_from(anchor.as_slice()) {
            match quil_rpc::ArchiveClient::connect_mtls(addr, &falcon_key).await {
                Ok(mut c) => match c.resolve_root(prover_shard.to_vec(), 0, anchor32.to_vec()).await {
                    Ok(Some((v, g))) => println!(
                        "  resolve_root(anchor) -> version {v}, global_frame {g}  (expected frame {})",
                        n.saturating_sub(1)
                    ),
                    Ok(None) => println!(
                        "  resolve_root(anchor) -> NOT FOUND (peer pruned/behind this root — a real jump fails over to another peer)"
                    ),
                    Err(e) => println!("  resolve_root error: {e}"),
                },
                Err(e) => println!("  resolve_root connect failed: {e}"),
            }
        }

        // 5. Fresh in-memory (RocksDB) forest CRDT, then root-addressed sync of the
        //    prover tree into it.
        let db = quil_store::RocksDb::open_in_memory()
            .map_err(|e| anyhow::anyhow!("open in-memory db: {e}"))?;
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            hg_store.raw_db(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        ));

        match crate::forest_sync::sync_single_shard_verified(
            addr,
            &falcon_key,
            crdt.clone(),
            &prover_shard,
            &anchor,
        )
        .await
        {
            Ok(Some(g)) => {
                let got = crdt.compute_shard_root("vertex", "adds", &prover_key);
                let matched = got.as_slice() == anchor.as_slice();
                println!(
                    "  SYNC RESULT: converged (pinned frame {g}) — synced root {}",
                    if matched { "== anchor  ✓ MATCH" } else { "!= anchor  ✗ MISMATCH" }
                );
                println!("    synced vertex-adds root: {}", hex::encode(&got));
                if matched {
                    any_match = true;
                }
            }
            Ok(None) => println!(
                "  SYNC RESULT: NOT CONVERGED — peer could not serve the anchored version, or the pulled root != anchor (a real jump retries another peer)"
            ),
            Err(e) => println!("  SYNC RESULT: ERROR — {e}"),
        }
    }

    println!(
        "\n=== {} ===",
        if any_match {
            "PASS — prover tree synced to the frame's anchor (root-addressed sync works against the archive)"
        } else {
            "FAIL — no archive synced the prover tree to the anchor"
        }
    );
    if any_match {
        Ok(())
    } else {
        anyhow::bail!("prover-tree root-addressed sync did not match the anchor on any archive")
    }
}
