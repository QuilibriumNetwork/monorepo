use std::sync::Arc;

use tracing::{debug, info, warn};

// Import KeyManager trait for get_signer
use quil_keys::KeyManager as _;

use quil_lifecycle::Supervisor;

pub(crate) struct PeerInfoPublisherArgs {
    pub p2p_handle: quil_p2p::node::P2PHandle,
    pub peer_id: quil_p2p::PeerId,
    pub peer_priv_key_hex: String,
    pub announce_listen_multiaddr: String,
    pub announce_stream_listen_multiaddr: String,
    pub stream_listen_multiaddr: String,
    pub listen_fallback: String,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub last_global_head_frame: Arc<std::sync::atomic::AtomicU64>,
    pub worker_p2p_multiaddrs: Vec<String>,
    pub worker_stream_multiaddrs: Vec<String>,
    pub worker_announce_p2p: Vec<String>,
    pub worker_announce_stream: Vec<String>,
    pub worker_manager_cell: Arc<std::sync::OnceLock<Arc<dyn quil_engine::worker::WorkerManager>>>,
    pub bls_pubkey: Vec<u8>,
    pub key_manager: Arc<quil_keys::FileKeyManager>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
    pub archive_mode: bool,
}

pub(crate) fn spawn(sup: &mut Supervisor<anyhow::Error>, args: PeerInfoPublisherArgs) {
    let PeerInfoPublisherArgs {
        p2p_handle,
        peer_id,
        peer_priv_key_hex,
        announce_listen_multiaddr: pi_announce,
        announce_stream_listen_multiaddr: pi_announce_stream,
        stream_listen_multiaddr: pi_stream_listen,
        listen_fallback: pi_listen_fallback,
        current_frame: pi_current_frame,
        last_global_head_frame: pi_last_head,
        worker_p2p_multiaddrs: pi_worker_p2p_multiaddrs,
        worker_stream_multiaddrs: pi_worker_stream_multiaddrs,
        worker_announce_p2p: pi_worker_announce_p2p,
        worker_announce_stream: pi_worker_announce_stream,
        worker_manager_cell: pi_worker_manager_slot,
        bls_pubkey: kr_bls_pubkey,
        key_manager: kr_key_manager,
        exec_manager,
        archive_mode,
    } = args;

    let pi_handle = p2p_handle.clone();

    // Extract Ed448 seed and derive public key for signing PeerInfo.
    let pk_bytes = hex::decode(&peer_priv_key_hex).unwrap_or_default();
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

    let pi_p2p_handle = p2p_handle.clone();
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

    sup.run_until_cancelled("peer-info-publisher", move |_token| async move {
        let bitmask = vec![0x00, 0x00, 0x00, 0x00]; // GLOBAL_PEER_INFO
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30 * 60));
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
                crate::util::multiaddr::extract_stream_addr(&pubsub_addr, &pi_stream_listen)
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
                debug!(
                    capabilities = pi_caps.len(),
                    signed = pi_ed448_seed.is_some(),
                    pubkey_len = pi_ed448_pubkey.len(),
                    worker_reachability = worker_reachability_count,
                    "published PeerInfo"
                );
            }

            // Publish KeyRegistry alongside PeerInfo (every 30 min).
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
                                    debug!("published KeyRegistry");
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "cannot publish KeyRegistry: BLS signer unavailable");
                        }
                    }
                }
            }

            interval.tick().await;
        }
    });
    info!("PeerInfo publisher started (30-minute interval)");
}
