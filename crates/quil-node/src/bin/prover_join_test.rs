//! Full prover lifecycle integration test against mainnet.
//!
//! 1. Publishes signed PeerInfo every minute
//! 2. Syncs latest frame + prover registry from archives
//! 3. Finds shards with no confirmed provers
//! 4. Creates ProverJoin for all unconfirmed shards
//! 5. Computes VDF multi-proof
//! 6. Submits join via BlossomSub
//! 7. Syncs prover info every 5 frames, checks receipt
//! 8. After 360 frames, submits ProverConfirm
//!
//! Runtime: 1.5 - 3 hours.
//!
//! Usage: cargo run --release --bin prover-join-test -- --config .config

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Syncing,
    FindingShards,
    ComputingProof,
    WaitingForJoinReceipt,
    WaitingForConfirmWindow,
    SubmittingConfirm,
    Done,
    Failed,
}

#[derive(clap::Parser)]
struct Args {
    #[arg(short, long, default_value = ".config")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("=== PROVER JOIN INTEGRATION TEST ===");

    let config = quil_config::load_config(&args.config)?;
    quil_crypto::init();

    // Ed448 key
    let key_bytes = hex::decode(&config.p2p.peer_priv_key)?;
    anyhow::ensure!(key_bytes.len() >= 57, "need Ed448 key");
    let ed448_seed: [u8; 57] = key_bytes[..57].try_into().unwrap();
    let ed448_pubkey = quil_p2p::ed448_identity::derive_public_key(&ed448_seed);
    let ed448_peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&ed448_pubkey);
    info!(
        peer_id = hex::encode(&ed448_peer_id),
        peer_private_key = hex::encode(&ed448_seed),
        "Ed448 identity loaded"
    );

    // BLS prover key
    let bls_ctor = quil_crypto::Bls48581KeyConstructor;
    let (bls_signer_box, bls_pubkey) = quil_types::crypto::BlsConstructor::new_key(&bls_ctor)?;
    // Wrap in Arc for sharing across tasks
    let bls_signer: Arc<dyn quil_types::crypto::Signer> = Arc::from(bls_signer_box);
    let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;
    info!(
        prover_address = hex::encode(&prover_address),
        prover_private_key = hex::encode(bls_signer.private_key()),
        prover_public_key = hex::encode(&bls_pubkey),
        "BLS48-581 prover key generated"
    );

    // DB — single open, shared across stores
    let db_path = args.config.join("prover-test-store");
    std::fs::create_dir_all(&db_path)?;
    let db = Arc::new(quil_store::RocksDb::open(&db_path)?);
    let clock_store = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));

    // P2P
    let p2p_node = quil_p2p::node::P2PNode::new_with_options(&config.p2p, false)?;
    let listen_addr = if config.p2p.listen_multiaddr.is_empty() {
        "/ip4/0.0.0.0/udp/8336/quic-v1".to_string()
    } else {
        config.p2p.listen_multiaddr.clone()
    };
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let (p2p_handle, mut msg_rx) = p2p_node.start(&mut sup, &listen_addr).await?;
    // Dev binary — keep `sup` alive so the registered swarm task isn't
    // dropped; we don't drive `sup.run()` here.
    let _sup = sup;

    // Must subscribe before publishing — BlossomSub rejects publish to
    // unsubscribed bitmasks.
    p2p_handle.subscribe(vec![0x00]).await;             // GLOBAL_CONSENSUS
    p2p_handle.subscribe(vec![0x00, 0x00]).await;       // GLOBAL_FRAME
    p2p_handle.subscribe(vec![0x00, 0x00, 0x00]).await; // GLOBAL_PROVER
    p2p_handle.subscribe(vec![0x00, 0x00, 0x00, 0x00]).await; // GLOBAL_PEER_INFO
    info!("subscribed to all global bitmasks");

    let token = CancellationToken::new();
    {
        let t = token.clone();
        tokio::spawn(async move { tokio::signal::ctrl_c().await.ok(); t.cancel(); });
    }

    let head_frame = Arc::new(AtomicU64::new(0));
    let archive_addrs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let phase = Arc::new(Mutex::new(Phase::Syncing));
    let join_frame = Arc::new(AtomicU64::new(0));

    // --- Task 1: Signed PeerInfo + KeyRegistry every 60s ---
    {
        let h = p2p_handle.clone();
        let t = token.clone();
        let pid = ed448_peer_id.clone();
        let pk = ed448_pubkey.clone();
        let s = ed448_seed;
        let bls_pk_for_kr = bls_pubkey.clone();
        let bls_signer_for_kr = bls_signer.clone(); // Arc clone
        tokio::spawn(async move {
            let bm = vec![0u8; 4]; // GLOBAL_PEER_INFO
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;

                // Publish signed PeerInfo
                let pi = quil_p2p::CanonicalPeerInfo {
                    peer_id: pid.clone(),
                    reachability: vec![quil_p2p::CanonicalReachability {
                        filter: vec![0xFF; 32],
                        pubsub_multiaddrs: vec![],
                        stream_multiaddrs: vec![],
                    }],
                    timestamp: now_ms,
                    version: vec![2, 1, 0],
                    patch_number: vec![23],
                    capabilities: vec![
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00020001, additional_metadata: vec![] }, // GLOBAL
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00040001, additional_metadata: vec![] }, // TOKEN
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010001, additional_metadata: vec![] }, // COMPUTE
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00030001, additional_metadata: vec![] }, // HYPERGRAPH
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x0101, additional_metadata: vec![] },     // DOUBLE_RATCHET
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x0201, additional_metadata: vec![] },     // TRIPLE_RATCHET
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x0301, additional_metadata: vec![] },     // ONION_ROUTING
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010101, additional_metadata: vec![] }, // KZG_VERIFY
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010201, additional_metadata: vec![] }, // BULLETPROOF_RANGE
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010301, additional_metadata: vec![] }, // BULLETPROOF_SUM
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010401, additional_metadata: vec![] }, // SECP256K1_ECDSA
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010501, additional_metadata: vec![] }, // ED25519_EDDSA
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010601, additional_metadata: vec![] }, // ED448_EDDSA
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010701, additional_metadata: vec![] }, // DECAF448_SCHNORR
                        quil_p2p::CanonicalCapability { protocol_identifier: 0x00010801, additional_metadata: vec![] }, // SECP256R1_ECDSA
                    ],
                    public_key: Vec::new(),
                    signature: Vec::new(),
                    last_received_frame: 0,
                    last_global_head_frame: 0,
                };
                let pv = ed448_rust::PrivateKey::from(s);
                let m = quil_p2p::encode_canonical_peer_info(&pi, &pk, &[]);
                if let Ok(sig) = pv.sign(&m, None) {
                    let _ = h.publish(bm.clone(), quil_p2p::encode_canonical_peer_info(&pi, &pk, &sig)).await;
                    info!("published signed PeerInfo");
                }

                // Publish KeyRegistry
                // identity_to_prover: Ed448 signs ("KEY_REGISTRY" || bls_pubkey)
                // See global message_processors.go:593-596
                let mut kr_msg = Vec::from(b"KEY_REGISTRY" as &[u8]);
                kr_msg.extend_from_slice(&bls_pk_for_kr);
                if let Ok(i2p_sig) = pv.sign(&kr_msg, None) {
                    // prover_to_identity: BLS signs ed448_pubkey with domain "KEY_REGISTRY"
                    // See global message_processors.go:619-624
                    if let Ok(p2i_sig) = bls_signer_for_kr.sign_with_domain(&pk, b"KEY_REGISTRY") {
                        let kr = quil_p2p::encode_key_registry(
                            &pk,
                            &bls_pk_for_kr,
                            &i2p_sig,
                            &p2i_sig,
                            now_ms as u64,
                        );
                        let _ = h.publish(bm.clone(), kr).await;
                        info!("published KeyRegistry");
                    }
                }

                tokio::select! { _ = iv.tick() => {} _ = t.cancelled() => break }
            }
        });
    }

    // --- Task 2: Archive discovery ---
    {
        let aa = archive_addrs.clone();
        let hf = head_frame.clone();
        let t = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = msg_rx.recv() => {
                        let Some(rx) = msg else { break };
                        if rx.bitmask == [0u8; 4] {
                            if let Ok(quil_p2p::PeerInfoMessage::PeerInfo(i)) =
                                quil_p2p::classify_peer_info_message(&rx.data) {
                                if i.last_global_head_frame > hf.load(Ordering::Relaxed) {
                                    hf.store(i.last_global_head_frame, Ordering::Relaxed);
                                }
                                if i.is_archive() {
                                    for r in &i.reachability {
                                        for ma in &r.stream_multiaddrs {
                                            if let Some(a) = ma_to_hp(ma) {
                                                let mut v = aa.lock().await;
                                                if !v.contains(&a) { v.push(a); }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ = t.cancelled() => break,
                }
            }
        });
    }

    // Wait for archives
    loop {
        if token.is_cancelled() { return Ok(()); }
        tokio::time::sleep(Duration::from_secs(5)).await;
        let n = archive_addrs.lock().await.len();
        if n > 0 && head_frame.load(Ordering::Relaxed) > 0 { break; }
        info!(archives = n, head = head_frame.load(Ordering::Relaxed), "waiting for archives...");
    }
    info!("archives found, starting main loop");

    let start = Instant::now();
    let mut targets: Vec<Vec<u8>> = Vec::new();
    let mut last_sync: u64 = 0;

    loop {
        if token.is_cancelled() { break; }
        let p = *phase.lock().await;
        let hf = head_frame.load(Ordering::Relaxed);

        match p {
            Phase::Syncing => {
                info!(elapsed = ?start.elapsed(), head = hf, "SYNCING");
                let addr = archive_addrs.lock().await.first().cloned();
                if let Some(addr) = addr {
                    if let Ok(mut c) = quil_rpc::ArchiveClient::connect_mtls(&addr, &ed448_seed).await {
                        if let Ok(f) = c.get_global_frame(0).await {
                            let fn_ = f.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
                            head_frame.store(fn_, Ordering::Relaxed);
                            let _ = clock_store.put_global_frame(&f, None);
                            *phase.lock().await = Phase::FindingShards;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }

            Phase::FindingShards => {
                info!(elapsed = ?start.elapsed(), "FINDING_SHARDS");

                // Fresh sync prover tree — must be current data to pick correct filters
                let addr = archive_addrs.lock().await.first().cloned();
                if let Some(addr) = addr {
                    let s = hg_store.clone();
                    let _ = quil_rpc::ensure_prover_tree_fresh(
                        &addr, &ed448_seed,
                        quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
                        s,
                        &[], // test binary: no expected_root pin
                    ).await;
                }

                let reg = Arc::new(quil_execution::SharedProverRegistry::new());
                {
                    let r = reg.clone();
                    let h = hg_store.clone();
                    tokio::task::spawn_blocking(move || r.refresh_from_store(&h)).await?;
                }
                info!(provers = reg.read(|r| r.distinct_provers()), "registry loaded");

                // 0 frame_number is OK here — the diagnostic
                // binary doesn't care about expiry filtering of
                // Joining/Leaving for the shard population it
                // reports.
                let sums: Vec<quil_types::consensus::ProverShardSummary> =
                    reg.read(|r| r.get_prover_shard_summaries(0));
                let mut cands: Vec<(u32, Vec<u8>)> = sums.iter().map(|s| {
                    let a = s.status_counts.get(&quil_types::consensus::ProverStatus::Active).copied().unwrap_or(0);
                    (a, s.filter.clone())
                }).collect();
                cands.sort_by_key(|(c, _)| *c);

                let zeros: Vec<Vec<u8>> = cands.iter()
                    .filter(|(c, _)| *c == 0)
                    .map(|(_, f)| f.clone())
                    .collect();
                targets = if zeros.is_empty() {
                    // No empty shards — pick the least-populated one
                    cands.into_iter().take(1).map(|(_c, f): (u32, Vec<u8>)| f).collect()
                } else {
                    zeros
                };
                info!(targets = targets.len(), "selected ALL shards with no active provers");

                if targets.is_empty() {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                } else {
                    *phase.lock().await = Phase::ComputingProof;
                }
            }

            Phase::ComputingProof => {
                info!(elapsed = ?start.elapsed(), filters = targets.len(), "COMPUTING_PROOF");

                let fp: Arc<dyn quil_types::crypto::FrameProver> =
                    Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));

                // Fetch latest frame directly from archive. Don't use local store
                // because the fresh sync may have taken many minutes, and the
                // join's FrameNumber is rejected if >10 frames stale.
                let addr = archive_addrs.lock().await.first().cloned();
                let (output, fn_, diff) = if let Some(a) = addr {
                    match quil_rpc::ArchiveClient::connect_mtls(&a, &ed448_seed).await {
                        Ok(mut c) => match c.get_global_frame(0).await {
                            Ok(f) => {
                                let h = f.header.as_ref().unwrap();
                                info!(frame = h.frame_number, "using fresh frame from archive for VDF challenge");
                                (h.output.clone(), h.frame_number, h.difficulty)
                            }
                            Err(e) => { warn!(%e, "archive get_global_frame failed, falling back to local");
                                match clock_store.get_latest_global_frame() {
                                    Ok(f) => { let h = f.header.as_ref().unwrap(); (h.output.clone(), h.frame_number, h.difficulty) }
                                    Err(_) => { *phase.lock().await = Phase::Syncing; continue; }
                                }
                            }
                        },
                        Err(e) => { warn!(%e, "archive connect failed, falling back to local");
                            match clock_store.get_latest_global_frame() {
                                Ok(f) => { let h = f.header.as_ref().unwrap(); (h.output.clone(), h.frame_number, h.difficulty) }
                                Err(_) => { *phase.lock().await = Phase::Syncing; continue; }
                            }
                        }
                    }
                } else {
                    match clock_store.get_latest_global_frame() {
                        Ok(f) => { let h = f.header.as_ref().unwrap(); (h.output.clone(), h.frame_number, h.difficulty) }
                        Err(_) => { *phase.lock().await = Phase::Syncing; continue; }
                    }
                };

                // Go uses sha3.Sum256 (Keccak) NOT sha2 for the challenge
                let challenge: [u8; 32] = {
                    use sha3::{Digest, Sha3_256};
                    Sha3_256::digest(&output).into()
                };
                let ids: Vec<Vec<u8>> = targets.iter().enumerate().map(|(i, f)| {
                    let mut id = Vec::new();
                    id.extend_from_slice(&prover_address);
                    id.extend_from_slice(f);
                    id.extend_from_slice(&(i as u32).to_be_bytes());
                    id
                }).collect();
                info!(
                    difficulty = diff,
                    filters = targets.len(),
                    "computing VDF proofs in parallel..."
                );
                let t0 = Instant::now();

                // Compute proofs in parallel — one thread per filter.
                let num_filters = targets.len();
                let mut handles = Vec::with_capacity(num_filters);
                for i in 0..num_filters {
                    let fp = fp.clone();
                    let challenge = challenge;
                    let all_ids = ids.clone();
                    handles.push(tokio::task::spawn_blocking(move || {
                        let refs: Vec<&[u8]> = all_ids.iter().map(|v| v.as_slice()).collect();
                        let result = fp.calculate_multi_proof(&challenge, diff, &refs, i as u32);
                        (i, result)
                    }));
                }

                // Collect results in order
                let mut all_proofs = Vec::with_capacity(num_filters * 516);
                let mut proof_ok = true;
                let mut results: Vec<Option<Vec<u8>>> = vec![None; num_filters];
                for handle in handles {
                    match handle.await {
                        Ok((i, Ok(proof))) => {
                            info!(filter = i + 1, total = num_filters, len = proof.len(), "filter proof done");
                            results[i] = Some(proof);
                        }
                        Ok((i, Err(e))) => {
                            error!(filter = i + 1, error = %e, "filter proof failed");
                            proof_ok = false;
                        }
                        Err(e) => {
                            error!(error = %e, "proof task panicked");
                            proof_ok = false;
                        }
                    }
                }
                if proof_ok {
                    for r in results {
                        all_proofs.extend_from_slice(&r.unwrap());
                    }
                }
                info!(elapsed = ?t0.elapsed(), filters = num_filters, "all proofs computed");
                let proof = all_proofs;

                // Self-verify the proofs before submitting (catches our own bugs)
                if proof_ok {
                    let refs_for_verify: Vec<&[u8]> = ids.iter().map(|v| v.as_slice()).collect();
                    let solutions: Vec<Vec<u8>> = (0..num_filters)
                        .map(|i| proof[i * 516..(i + 1) * 516].to_vec())
                        .collect();
                    let sol_refs: Vec<&[u8]> = solutions.iter().map(|s| s.as_slice()).collect();
                    match fp.verify_multi_proof(&challenge, diff, &refs_for_verify, &sol_refs) {
                        Ok(true) => info!("self-verify OK: all VDF proofs valid"),
                        Ok(false) => {
                            error!("SELF-VERIFY FAILED: Rust cannot verify its own VDF proofs");
                            proof_ok = false;
                        }
                        Err(e) => {
                            error!(%e, "self-verify error");
                            proof_ok = false;
                        }
                    }
                }

                if proof_ok {
                    info!(
                        total_len = proof.len(),
                        per_filter = if targets.is_empty() { 0 } else { proof.len() / targets.len() },
                        elapsed = ?t0.elapsed(),
                        "all proofs done!"
                    );
                    match build_join(&targets, fn_, &bls_pubkey, bls_signer.as_ref(), &prover_address, &proof) {
                        Ok(join) => {
                            // Wrap in MessageBundle (not MessageRequest!)
                            // Go's handleProverMessage expects MessageBundleType (0x0312)
                            let req = quil_execution::message_envelope::CanonicalMessageRequest::wrap(join);
                            match req {
                                Ok(r) => {
                                    let now_ms = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as i64;
                                    let bundle = quil_execution::message_envelope::CanonicalMessageBundle {
                                        requests: vec![Some(r)],
                                        timestamp: now_ms,
                                    };
                                    match bundle.to_canonical_bytes() {
                                        Ok(bytes) => {
                                            join_frame.store(fn_, Ordering::Relaxed);
                                            info!(bundle_len = bytes.len(), "submitting ProverJoin via gRPC to archives");
                                            // Submit via gRPC to all known archives (like Go does)
                                            let addrs = archive_addrs.lock().await.clone();
                                            let mut submitted = false;
                                            for addr in &addrs {
                                                let stream_addr = addr.replace(":8336", ":8340");
                                                match quil_rpc::ArchiveClient::connect_mtls(
                                                    &stream_addr, &ed448_seed,
                                                ).await {
                                                    Ok(mut client) => {
                                                        match client.submit_global_message(bytes.clone()).await {
                                                            Ok(()) => {
                                                                info!(%stream_addr, "ProverJoin submitted to archive via gRPC!");
                                                                submitted = true;
                                                            }
                                                            Err(e) => warn!(%stream_addr, %e, "gRPC submit failed"),
                                                        }
                                                    }
                                                    Err(e) => warn!(%stream_addr, %e, "archive connect failed"),
                                                }
                                            }
                                            // Also publish via BlossomSub as fallback
                                            if let Err(e) = p2p_handle.publish(vec![0u8; 3], bytes).await {
                                                warn!(error = %e, "ProverJoin BlossomSub publish failed");
                                            }
                                            info!(submitted_grpc = submitted, "ProverJoin published via BlossomSub too");
                                            *phase.lock().await = Phase::WaitingForJoinReceipt;
                                        }
                                        Err(e) => { error!(%e, "bundle encode failed"); *phase.lock().await = Phase::Failed; }
                                    }
                                }
                                Err(e) => { error!(%e, "wrap in request failed"); *phase.lock().await = Phase::Failed; }
                            }
                        }
                        Err(e) => { error!(%e, "build join failed"); *phase.lock().await = Phase::Failed; }
                    }
                } else {
                    error!("proof computation failed");
                    *phase.lock().await = Phase::Failed;
                }
            }

            Phase::WaitingForJoinReceipt => {
                let jf = join_frame.load(Ordering::Relaxed);
                let since = hf.saturating_sub(jf);
                info!(elapsed = ?start.elapsed(), head = hf, join = jf, since, "WAITING_JOIN_RECEIPT");

                // Sync head frame and prover tree every 5 frames
                if hf > last_sync + 5 {
                    last_sync = hf;
                    let addr = archive_addrs.lock().await.first().cloned();
                    if let Some(addr) = addr {
                        // Update head frame
                        if let Ok(mut c) = quil_rpc::ArchiveClient::connect_mtls(&addr, &ed448_seed).await {
                            if let Ok(f) = c.get_global_frame(0).await {
                                let new_hf = f.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
                                head_frame.store(new_hf, Ordering::Relaxed);
                                info!(head = new_hf, "synced head frame");
                            }
                        }

                        // Incremental sync — compares commitments and only
                        // fetches changed branches (seconds vs 9 minutes).
                        let hs = hg_store.clone();
                        let _ = quil_rpc::ensure_prover_tree_incremental(
                            &addr, &ed448_seed,
                            quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
                            hs.clone(),
                            &[], // test binary: no expected_root pin
                        ).await;

                        let reg = Arc::new(quil_execution::SharedProverRegistry::new());
                        let hs2 = hg_store.clone();
                        let pa = prover_address;
                        let found = tokio::task::spawn_blocking(move || {
                            reg.refresh_from_store(&hs2);
                            reg.read(|r| r.get_prover_info(&pa).is_some())
                        }).await.unwrap_or(false);

                        if found {
                            info!("=== JOIN CONFIRMED IN REGISTRY ===");
                            *phase.lock().await = Phase::WaitingForConfirmWindow;
                        } else {
                            info!(since, "prover not yet in registry, waiting...");
                            if since > 30 {
                                warn!("join not received after 30 frames, may need to resubmit");
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }

            Phase::WaitingForConfirmWindow => {
                let jf = join_frame.load(Ordering::Relaxed);
                let since = hf.saturating_sub(jf);
                let rem = 360u64.saturating_sub(since);
                info!(elapsed = ?start.elapsed(), since, remaining = rem, eta_min = rem * 10 / 60, "WAITING_CONFIRM");

                if hf > last_sync + 5 {
                    last_sync = hf;
                    let addr = archive_addrs.lock().await.first().cloned();
                    if let Some(addr) = addr {
                        if let Ok(mut c) = quil_rpc::ArchiveClient::connect_mtls(&addr, &ed448_seed).await {
                            if let Ok(f) = c.get_global_frame(0).await {
                                head_frame.store(f.header.as_ref().map(|h| h.frame_number).unwrap_or(0), Ordering::Relaxed);
                            }
                        }
                    }
                }
                if since >= 360 {
                    *phase.lock().await = Phase::SubmittingConfirm;
                } else {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }

            Phase::SubmittingConfirm => {
                info!(elapsed = ?start.elapsed(), "SUBMITTING_CONFIRM");
                match build_confirm(&targets, hf, bls_signer.as_ref(), &prover_address) {
                    Ok(confirm) => {
                        match quil_execution::message_envelope::CanonicalMessageRequest::wrap(confirm) {
                            Ok(r) => {
                                let now_ms = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as i64;
                                let bundle = quil_execution::message_envelope::CanonicalMessageBundle {
                                    requests: vec![Some(r)],
                                    timestamp: now_ms,
                                };
                                match bundle.to_canonical_bytes() {
                                    Ok(bytes) => {
                                        if let Err(e) = p2p_handle.publish(vec![0u8; 3], bytes).await {
                                            warn!(error = %e, "ProverConfirm BlossomSub publish failed");
                                        }
                                        info!("ProverConfirm published as MessageBundle!");
                                        *phase.lock().await = Phase::Done;
                                    }
                                    Err(e) => { error!(%e, "bundle confirm"); *phase.lock().await = Phase::Failed; }
                                }
                            }
                            Err(e) => { error!(%e, "wrap confirm"); *phase.lock().await = Phase::Failed; }
                        }
                    }
                    Err(e) => { error!(%e, "build confirm"); *phase.lock().await = Phase::Failed; }
                }
            }

            Phase::Done => {
                info!(elapsed = ?start.elapsed(), "=== SUCCESS: PROVER JOIN + CONFIRM ===");
                break;
            }
            Phase::Failed => {
                error!(elapsed = ?start.elapsed(), "=== FAILED ===");
                break;
            }
        }
    }

    p2p_handle.shutdown().await;
    Ok(())
}

fn build_join(
    filters: &[Vec<u8>], frame: u64, pk: &[u8],
    signer: &dyn quil_types::crypto::Signer, addr: &[u8; 32], proof: &[u8],
) -> quil_types::error::Result<Vec<u8>> {
    use quil_execution::global_intrinsic::{prover_join::ProverJoin, sig_with_pop::SignatureWithPop};

    // Go signs the FULL ProverJoin canonical bytes with signature=nil.
    // See global_prover_join.go:1074-1079:
    //   joinClone.PublicKeySignatureBls48581 = nil
    //   joinMessage = joinClone.ToCanonicalBytes()
    let unsigned_join = ProverJoin {
        filters: filters.to_vec(),
        frame_number: frame,
        public_key_signature_bls48581: None, // signature field removed for signing
        delegate_address: addr.to_vec(),
        merge_targets: vec![],
        proof: proof.to_vec(),
    };
    let join_message = unsigned_join.to_canonical_bytes()?;

    // Domain: poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_JOIN")
    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"PROVER_JOIN");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)?;

    // Sign the full join message (without signature field)
    let sig = signer.sign_with_domain(&join_message, &domain)?;
    // Proof of possession: sign pubkey with itself
    let pop = signer.sign_with_domain(pk, b"BLS48_POP_SK")?;

    // Now build the final join WITH the signature
    ProverJoin {
        filters: filters.to_vec(),
        frame_number: frame,
        public_key_signature_bls48581: Some(SignatureWithPop {
            signature: sig,
            public_key: Some(pk.to_vec()),
            pop_signature: pop,
        }),
        delegate_address: addr.to_vec(),
        merge_targets: vec![],
        proof: proof.to_vec(),
    }.to_canonical_bytes()
}

fn build_confirm(
    filters: &[Vec<u8>], frame: u64,
    signer: &dyn quil_types::crypto::Signer, addr: &[u8; 32],
) -> quil_types::error::Result<Vec<u8>> {
    use quil_execution::global_intrinsic::{prover_ops::ProverConfirm, addressed_signature::AddressedSignature};

    // Go signs filters_concat + frame_number (NOT the full canonical bytes).
    // See global_prover_confirm.go Prove/Verify.
    let mut msg = Vec::new();
    for f in filters { msg.extend_from_slice(f); }
    msg.extend_from_slice(&frame.to_be_bytes());

    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"PROVER_CONFIRM");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)?;
    let sig = signer.sign_with_domain(&msg, &domain)?;

    ProverConfirm {
        filter: vec![],
        frame_number: frame,
        public_key_signature_bls48581: Some(AddressedSignature { signature: sig, address: addr.to_vec() }),
        filters: filters.to_vec(),
    }.to_canonical_bytes()
}

fn ma_to_hp(ma: &str) -> Option<String> {
    let p: Vec<&str> = ma.trim_start_matches('/').split('/').collect();
    if p.len() < 4 || p[0] != "ip4" || p[2] != "tcp" { return None; }
    let ip: std::net::Ipv4Addr = p[1].parse().ok()?;
    if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() { return None; }
    Some(format!("{}:{}", ip, p[3].parse::<u16>().ok()?))
}
