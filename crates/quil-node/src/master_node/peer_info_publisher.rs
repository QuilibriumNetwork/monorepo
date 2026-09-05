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
    /// Network id — controls the publish cadence. Mainnet (0) republishes
    /// every 30 min; testnet/devnet every 30 s so a freshly-joined node
    /// discovers archives in seconds instead of waiting out the long ticker.
    pub network: u8,
    /// Whether the node runs the live onion relay (advertises `PROTOCOL_ROUTING`
    /// so peers may build circuits through it). Off when `p2p.disableOnionRouting`.
    pub onion_routing_enabled: bool,
}

/// How long to wait for a peer to appear on the PeerInfo topic before
/// publishing anyway. Generous next to observed mesh formation (a few
/// seconds), and far below the mainnet republish period, so a node that
/// really is alone still degrades to the old behaviour — one failed
/// publish — rather than going quiet.
const TOPIC_PEER_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// Block until at least one connected peer advertises `bitmask`, or
/// `TOPIC_PEER_WAIT` elapses. Returns the peer count actually observed.
///
/// BlossomSub rejects a publish outright when nobody is subscribed to the
/// topic (`NoPeersSubscribedToTopic`); the message is not buffered for
/// redelivery. At startup the swarm has no connections at all, so the very
/// first PeerInfo publish is guaranteed to fail — and the next attempt is a
/// whole republish period away, 30 minutes on mainnet. Waiting for a
/// subscriber first turns that hole into a few seconds of delay.
async fn wait_for_topic_peer(
    handle: &quil_p2p::node::P2PHandle,
    bitmask: &[u8],
) -> usize {
    wait_for_topic_peer_with(TOPIC_PEER_WAIT, || {
        let handle = handle.clone();
        let bitmask = bitmask.to_vec();
        async move { handle.subscribed_peer_count(bitmask).await }
    })
    .await
}

/// The waiting policy, over any source of subscriber counts.
async fn wait_for_topic_peer_with<F, Fut>(max_wait: std::time::Duration, count: F) -> usize
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = quil_types::error::Result<usize>>,
{
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut wait_logged = false;
    loop {
        match count().await {
            Ok(peers) if peers > 0 => {
                if wait_logged {
                    info!(peers, "PeerInfo topic has subscribers; publishing");
                }
                return peers;
            }
            Ok(_) => {
                if !wait_logged {
                    wait_logged = true;
                    info!("waiting for a subscribed PeerInfo peer before publishing");
                }
            }
            // A dead command channel means the swarm is shutting down.
            // Nothing to wait for; let the publish attempt report it.
            Err(e) => {
                warn!(error = %e, "PeerInfo topic peer count failed");
                return 0;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            warn!(
                wait_secs = max_wait.as_secs(),
                "no subscribed PeerInfo peer appeared; publishing anyway"
            );
            return 0;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
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
        network,
        onion_routing_enabled,
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

    // PeerInfo network identity = the Falcon prover key (q-prover-key). The
    // Ed448 key above is retained ONLY for the KeyRegistry binding (below); it
    // no longer derives the peer-id.
    let pi_falcon_pubkey = kr_bls_pubkey.clone();
    let pi_peer_id_bytes = if !pi_falcon_pubkey.is_empty() {
        quil_p2p::peer_id_from_falcon_pubkey(&pi_falcon_pubkey)
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

    // Advertise onion routing (Go `onion.ProtocolRouting`) only when the live
    // relay is enabled — the OnionNode dispatcher wired in `grpc.rs` must be
    // running, since the transport's peer validation on both sides requires
    // participants to carry this capability. When disabled, we must NOT advertise
    // it, or peers would route circuits into a node that drops every cell.
    //
    // The capability's `additional_metadata` carries this node's sntrup761 onion
    // PUBLIC key. Because PeerInfo is Ed448-signed (below), the onion key is bound
    // to the node's identity — a circuit initiator authenticates it from the
    // verified PeerInfo before encapsulating, closing the key-substitution MITM
    // gap. (`q-onion-key` always exists via `ensure_standard_keys`.)
    if onion_routing_enabled {
        let onion_public_key = kr_key_manager
            .get_public_key_bytes_by_id("q-onion-key")
            .unwrap_or_default();
        pi_caps.push(quil_p2p::CanonicalCapability {
            protocol_identifier: quil_rpc::onion_service::PROTOCOL_ROUTING,
            additional_metadata: onion_public_key,
        });
    }

    // Mainnet: 30 min (PeerInfo is stable, gossip is dense). Testnet/devnet:
    // 30 s so a node that joins after the startup publish discovers archives
    // within seconds rather than waiting out a 30-min ticker.
    let publish_secs: u64 = if network == 0 { 30 * 60 } else { 30 };
    sup.run_until_cancelled("peer-info-publisher", move |_token| async move {
        let bitmask = vec![0x00, 0x00, 0x00, 0x00]; // GLOBAL_PEER_INFO
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(publish_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // Tick FIRST. `interval`'s opening tick completes immediately, so
            // this still publishes at startup without delay — but it stops the
            // body from running twice back-to-back, which is what the trailing
            // tick did and why every restart logged its publish failures in
            // pairs.
            interval.tick().await;

            // Nobody subscribed yet means the publish would be rejected and
            // dropped, not queued. Wait for a subscriber instead of burning
            // the attempt.
            wait_for_topic_peer(&pi_handle, &bitmask).await;

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
                patch_number: vec![quil_config::PATCH_NUMBER],
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

            // Sign the PeerInfo with the FALCON prover key (the network
            // identity) — peers validate this signature against the Falcon
            // peer-id and silently drop unsigned/invalid PeerInfo.
            // 1. Encode with public_key but empty signature (for signing)
            // 2. Sign those bytes with Falcon
            // 3. Re-encode with the actual signature
            let encoded = if !pi_falcon_pubkey.is_empty() {
                use quil_keys::KeyManager as _;
                let msg_to_sign =
                    quil_p2p::encode_canonical_peer_info(&info, &pi_falcon_pubkey, &[]);
                let signed = kr_key_manager
                    .get_signer(quil_types::crypto::KeyType::Falcon512)
                    .and_then(|s| s.sign(&msg_to_sign));
                match signed {
                    Ok(signature) => quil_p2p::encode_canonical_peer_info(
                        &info,
                        &pi_falcon_pubkey,
                        &signature,
                    ),
                    Err(e) => {
                        warn!("Falcon PeerInfo sign failed: {:?}", e);
                        quil_p2p::encode_canonical_peer_info(&info, &pi_falcon_pubkey, &[])
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
                    signed = !pi_falcon_pubkey.is_empty(),
                    pubkey_len = pi_falcon_pubkey.len(),
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
                    match kr_key_manager.get_signer(quil_types::crypto::KeyType::Falcon512) {
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
        }
    });
    info!(publish_secs, "PeerInfo publisher started");
}

#[cfg(test)]
mod tests {
    use super::wait_for_topic_peer_with;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// The common case: the mesh fills in a few polls and the wait ends the
    /// moment a subscriber appears, not at the deadline.
    #[tokio::test(start_paused = true)]
    async fn returns_as_soon_as_a_subscriber_appears() {
        let polls = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        let peers = wait_for_topic_peer_with(Duration::from_secs(120), || {
            let n = polls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(if n >= 3 { 2 } else { 0 }) }
        })
        .await;

        assert_eq!(peers, 2);
        assert_eq!(polls.load(Ordering::SeqCst), 4);
        // Three one-second sleeps, nowhere near the 120 s cap.
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }

    /// A node that really is alone must not wait forever. It gives up at the
    /// cap and lets the caller publish (and fail) exactly as before.
    #[tokio::test(start_paused = true)]
    async fn gives_up_at_the_cap_when_no_peer_ever_appears() {
        let started = tokio::time::Instant::now();
        let peers =
            wait_for_topic_peer_with(Duration::from_secs(5), || async { Ok(0) }).await;

        assert_eq!(peers, 0);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    /// A subscriber already present costs no delay at all — the fast path
    /// every republish after the first takes.
    #[tokio::test(start_paused = true)]
    async fn does_not_delay_when_peers_are_already_present() {
        let started = tokio::time::Instant::now();
        let peers =
            wait_for_topic_peer_with(Duration::from_secs(120), || async { Ok(7) }).await;

        assert_eq!(peers, 7);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// A dead command channel means the swarm is going away; waiting on it
    /// would hang shutdown, so the wait ends immediately.
    #[tokio::test(start_paused = true)]
    async fn stops_waiting_when_the_swarm_is_gone() {
        let started = tokio::time::Instant::now();
        let peers = wait_for_topic_peer_with(Duration::from_secs(120), || async {
            Err(quil_types::error::QuilError::P2p("p2p command channel closed".into()))
        })
        .await;

        assert_eq!(peers, 0);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}
