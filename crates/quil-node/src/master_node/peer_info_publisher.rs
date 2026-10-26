use std::sync::Arc;
use std::time::Duration;

use quil_p2p::external_addr::{AutonatSummary, ConfirmedExternalAddrs};
use tokio::sync::watch;
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
/// topic (`InsufficientPeers`); the message is not buffered for
/// redelivery. At startup the swarm has no connections at all, so the very
/// first PeerInfo publish is guaranteed to fail — and the next attempt is a
/// whole republish period away, 30 minutes on mainnet. Waiting for a
/// subscriber first turns that hole into a few seconds of delay.
async fn wait_for_topic_peer(handle: &quil_p2p::node::P2PHandle, bitmask: &[u8]) -> usize {
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
        // Bound the command/ack wait too: a live but stalled swarm must not
        // prevent the fallback publish indefinitely.
        match tokio::time::timeout_at(deadline, count()).await {
            Ok(Ok(peers)) if peers > 0 => {
                if wait_logged {
                    info!(peers, "PeerInfo topic has subscribers; publishing");
                }
                return peers;
            }
            Ok(Ok(_)) => {
                if !wait_logged {
                    wait_logged = true;
                    info!("waiting for a subscribed PeerInfo peer before publishing");
                }
            }
            // A dead command channel means the swarm is shutting down.
            // Nothing to wait for; let the publish attempt report it.
            Ok(Err(e)) => {
                warn!(error = %e, "PeerInfo topic peer count failed");
                return 0;
            }
            Err(_) => {
                warn!(
                    wait_secs = max_wait.as_secs(),
                    "PeerInfo topic peer count timed out; publishing anyway"
                );
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
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + std::time::Duration::from_secs(1)).min(deadline),
        )
        .await;
    }
}

/// How long a new announce address must hold before a change-triggered
/// publish: AutoNAT confirms in probes about 90 s apart, and a different IP
/// needs a second server, so one settle window absorbs a burst of changes.
const ANNOUNCE_CHANGE_SETTLE: Duration = Duration::from_secs(60);

/// How long the first publish waits for an address when only AutoNAT can
/// name one (no announce override, a wildcard listen address): its first
/// probe runs 15 s after start and usually confirms at once. Publishing
/// first would hand every peer a record without addresses, replacing the
/// node's last one, until the confirmation publishes after the settle
/// window.
const FIRST_PUBLISH_ADDRESS_WAIT: Duration = Duration::from_secs(120);

/// Minimum spacing of change-triggered publishes: a flapping NAT costs at most
/// one extra PeerInfo per five minutes on top of the regular cadence.
const ANNOUNCE_CHANGE_MIN_GAP: Duration = Duration::from_secs(5 * 60);

/// How long the node may run without a confirmed external address before it
/// warns. AutoNAT's first probe runs 15 s after start and retries every 90 s,
/// so this allows several probes.
const UNCONFIRMED_WARN_AFTER: Duration = Duration::from_secs(10 * 60);

/// Repeat interval of that warning while the condition lasts.
const UNCONFIRMED_WARN_REPEAT: Duration = Duration::from_secs(60 * 60);

/// Where the announced pubsub address came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnnounceSource {
    /// `p2p.announceListenMultiaddr`.
    Override,
    /// The current AutoNAT-confirmed external address.
    Confirmed,
    /// The configured `p2p.listenMultiaddr` when it names a specific IP, else
    /// none (empty).
    Fallback,
}

/// Whether `addr` may go into PeerInfo: not empty, and no unspecified IP
/// (`0.0.0.0`, `::`), which names no host a peer can dial and only makes
/// peers and explorers take a reachable node for an unreachable one.
fn announceable(addr: &str) -> bool {
    let mut parts = addr.trim_start_matches('/').split('/');
    match (parts.next(), parts.next()) {
        (Some(""), _) | (None, _) => false,
        (Some("ip4"), Some(ip)) => ip
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| !ip.is_unspecified()),
        (Some("ip6"), Some(ip)) => ip
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| !ip.is_unspecified()),
        (Some("ip4" | "ip6"), None) => false,
        _ => true,
    }
}

/// The pubsub address PeerInfo announces: the `announceListenMultiaddr`
/// override when set; else the confirmed address on the transport of the
/// configured listen address; else any confirmed address; else the configured
/// listen address when it names a specific IP; else none (empty), rather than
/// a `0.0.0.0` no peer can dial.
fn select_pubsub_addr(
    announce: &str,
    confirmed: &[String],
    listen: &str,
) -> (String, AnnounceSource) {
    if !announce.is_empty() {
        return (announce.to_string(), AnnounceSource::Override);
    }
    let listen_transport = quil_p2p::external_addr::transport_of(listen);
    let on_listen_transport = confirmed.iter().find(|a| {
        listen_transport.is_some() && quil_p2p::external_addr::transport_of(a) == listen_transport
    });
    match on_listen_transport.or(confirmed.first()) {
        Some(addr) => (addr.clone(), AnnounceSource::Confirmed),
        None if announceable(listen) => (listen.to_string(), AnnounceSource::Fallback),
        None => (String::new(), AnnounceSource::Fallback),
    }
}

/// The stream addresses PeerInfo announces: the
/// `announceStreamListenMultiaddr` override when set; else the stream listen
/// port on the IP of `pubsub_addr`, or on the stream listen IP when it names
/// one.
fn select_stream_addrs(
    announce_stream: &str,
    stream_listen: &str,
    pubsub_addr: &str,
) -> Vec<String> {
    if !announce_stream.is_empty() {
        vec![announce_stream.to_string()]
    } else if !stream_listen.is_empty() {
        crate::util::multiaddr::extract_stream_addr(pubsub_addr, stream_listen)
            .into_iter()
            .collect()
    } else {
        Vec::new()
    }
}

/// The worker configuration of `quil_p2p::build_worker_reachability`.
struct WorkerAddrs<'a> {
    p2p: &'a [String],
    stream: &'a [String],
    announce_p2p: &'a [String],
    announce_stream: &'a [String],
}

/// The reachability records of a PeerInfo: the master's under the global
/// filter `[0xFF; 32]`, then one per running worker with a filter
/// (`workers`). Addresses PeerInfo must not carry (see [`announceable`]) are
/// left out, so a record without a usable address has an empty list.
fn build_reachability(
    pubsub_addr: &str,
    stream_addrs: &[String],
    workers: &[(u32, Vec<u8>)],
    worker_addrs: &WorkerAddrs<'_>,
) -> Vec<quil_p2p::CanonicalReachability> {
    let mut reachability = vec![quil_p2p::CanonicalReachability {
        filter: vec![0xFF; 32],
        pubsub_multiaddrs: vec![pubsub_addr.to_string()],
        stream_multiaddrs: stream_addrs.to_vec(),
    }];
    if !workers.is_empty() {
        reachability.extend(quil_p2p::build_worker_reachability(
            workers,
            pubsub_addr,
            stream_addrs,
            worker_addrs.p2p,
            worker_addrs.stream,
            worker_addrs.announce_p2p,
            worker_addrs.announce_stream,
        ));
    }
    for record in &mut reachability {
        record.pubsub_multiaddrs.retain(|addr| announceable(addr));
        record.stream_multiaddrs.retain(|addr| announceable(addr));
    }
    reachability
}

/// The `reason` of an announce change: the override, or the confirmed-set
/// event behind the selected address (`unconfirmed` before any).
fn announce_reason(source: AnnounceSource, ext: &ConfirmedExternalAddrs) -> &'static str {
    match (source, ext.last_change) {
        (AnnounceSource::Override, _) => "override",
        (_, Some(change)) => change.as_str(),
        (_, None) => "unconfirmed",
    }
}

/// Resolve once the selected announce address differs from `published`, has
/// held for `settle`, and `min_gap` has passed since `last_change_publish`. A
/// selection that returns to `published` cancels the pending publish. The
/// watched value also carries AutoNAT's view, which changes with every
/// failed probe; only a change of the selected address restarts the settle
/// window.
/// Wait until `select` names an address, at most `max_wait`; whether it
/// does. An address that is already known returns at once.
async fn wait_for_first_address(
    rx: &mut watch::Receiver<ConfirmedExternalAddrs>,
    select: impl Fn(&ConfirmedExternalAddrs) -> String,
    max_wait: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + max_wait;
    loop {
        if !select(&*rx.borrow_and_update()).is_empty() {
            return true;
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => {}
            // Timed out, or the swarm is gone and nothing can change.
            Err(_) | Ok(Err(_)) => return false,
        }
    }
}

async fn announce_change_due(
    rx: &mut watch::Receiver<ConfirmedExternalAddrs>,
    select: impl Fn(&ConfirmedExternalAddrs) -> String,
    published: &str,
    last_change_publish: Option<tokio::time::Instant>,
    settle: Duration,
    min_gap: Duration,
) {
    'changed: loop {
        while select(&*rx.borrow_and_update()) == published {
            if rx.changed().await.is_err() {
                // The swarm is gone; the address can no longer change.
                return std::future::pending().await;
            }
        }
        let mut selected = select(&*rx.borrow());
        let mut held_until = tokio::time::Instant::now() + settle;
        loop {
            match tokio::time::timeout_at(held_until, rx.changed()).await {
                // Held for `settle`, or final because the swarm is gone.
                Err(_) | Ok(Err(_)) => break,
                Ok(Ok(())) => {
                    let now_selected = select(&*rx.borrow_and_update());
                    if now_selected == published {
                        continue 'changed;
                    }
                    if now_selected != selected {
                        selected = now_selected;
                        held_until = tokio::time::Instant::now() + settle;
                    }
                }
            }
        }
        if let Some(last) = last_change_publish {
            tokio::time::sleep_until(last + min_gap).await;
            if select(&*rx.borrow_and_update()) != selected {
                continue 'changed;
            }
        }
        return;
    }
}

/// A change of the node's confirmed-address condition worth an operator line.
#[derive(Debug, PartialEq, Eq)]
enum ReachabilityNotice {
    /// No confirmed external address for `for_secs`, with AutoNAT's view.
    Unconfirmed {
        for_secs: u64,
        autonat: AutonatSummary,
    },
    /// An address is confirmed again after `after_secs` without one.
    Confirmed { after_secs: u64 },
}

/// Report while the node has no confirmed external address: first after
/// `warn_after` without one (counted from the call, or from losing the last
/// address), then every `repeat` while it lasts, and once when an address is
/// confirmed again. Never returns.
async fn monitor_unconfirmed(
    mut rx: watch::Receiver<ConfirmedExternalAddrs>,
    warn_after: Duration,
    repeat: Duration,
    mut notify: impl FnMut(ReachabilityNotice),
) {
    let mut since = tokio::time::Instant::now();
    let mut last_warn: Option<tokio::time::Instant> = None;
    // Cleared when the swarm is gone and the addresses can no longer change.
    let mut watching = true;
    loop {
        if !rx.borrow_and_update().addrs.is_empty() {
            if last_warn.take().is_some() {
                notify(ReachabilityNotice::Confirmed {
                    after_secs: since.elapsed().as_secs(),
                });
            }
            if !watching || rx.changed().await.is_err() {
                return std::future::pending().await;
            }
            since = tokio::time::Instant::now();
            continue;
        }
        let due = match last_warn {
            Some(last) => last + repeat,
            None => since + warn_after,
        };
        tokio::select! {
            _ = tokio::time::sleep_until(due) => {
                notify(ReachabilityNotice::Unconfirmed {
                    for_secs: since.elapsed().as_secs(),
                    autonat: rx.borrow().autonat.clone(),
                });
                last_warn = Some(tokio::time::Instant::now());
            }
            changed = rx.changed(), if watching => watching = changed.is_ok(),
        }
    }
}

/// Why no external address is confirmed, as far as AutoNAT tells.
#[derive(Debug, PartialEq, Eq)]
enum UnconfirmedCause {
    /// Dial-backs from servers on distinct IPs failed or did not finish:
    /// the ports are likely not forwarded.
    Unreachable,
    /// Requests fail for a reason unrelated to reachability (`io`,
    /// `bad_request`, `internal`, `unsupported_protocol`): a port forward
    /// does not help.
    ProbesFailing,
    /// Neither: AutoNAT has not settled, its dial-backs reached no usable
    /// address, or the failures do not tell.
    Unsettled,
}

fn unconfirmed_cause(autonat: &AutonatSummary) -> UnconfirmedCause {
    match &autonat.probe_failure {
        Some(run) if run.unreachable => UnconfirmedCause::Unreachable,
        Some(run)
            if matches!(
                run.class,
                "io" | "bad_request" | "internal" | "unsupported_protocol"
            ) =>
        {
            UnconfirmedCause::ProbesFailing
        }
        _ => UnconfirmedCause::Unsettled,
    }
}

/// The protocol(s) to forward for the p2p port: what the node listens on for
/// the configured listen address (both when it names neither transport).
fn p2p_protocol(listen: &str) -> &'static str {
    match quil_p2p::external_addr::transport_of(listen) {
        Some(quil_p2p::external_addr::ExternalTransport::Tcp) => "TCP",
        Some(quil_p2p::external_addr::ExternalTransport::Quic) => "UDP",
        None => "TCP and UDP",
    }
}

/// The port of a multiaddr string's TCP or UDP component.
fn port_of(addr: &str) -> Option<u16> {
    let parts: Vec<&str> = addr.split('/').collect();
    parts
        .windows(2)
        .find(|w| w[0] == "tcp" || w[0] == "udp")
        .and_then(|w| w[1].parse().ok())
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

    let mut pi_caps: Vec<quil_p2p::CanonicalCapability> = exec_manager
        .get_supported_capabilities()
        .into_iter()
        .map(|c| quil_p2p::CanonicalCapability {
            protocol_identifier: c.protocol_identifier,
            additional_metadata: c.additional_metadata,
        })
        .collect();
    pi_caps.push(quil_p2p::CanonicalCapability {
        protocol_identifier: quil_p2p::BUILD_FINGERPRINT_CAPABILITY_ID,
        additional_metadata: hex::decode(env!("QUIL_BUILD_FINGERPRINT"))
            .expect("build script emits a SHA-256 fingerprint"),
    });
    // Peers see only the patch release in `version`/`patch_number`; the
    // subpatch tells its fixes apart (a build without one advertises none).
    if let Ok(subpatch) = quil_config::SUBPATCH.parse::<u32>() {
        pi_caps.push(quil_p2p::CanonicalCapability {
            protocol_identifier: quil_p2p::RELEASE_SUBPATCH_CAPABILITY_ID,
            additional_metadata: subpatch.to_be_bytes().to_vec(),
        });
    }
    info!(
        version = quil_config::display_version(),
        build_fingerprint = env!("QUIL_BUILD_FINGERPRINT"),
        "publishing local source build identity"
    );
    // Archive nodes must advertise the archive-service capability
    // so non-archive peers (joining provers) can find them via
    // PeerInfo and fetch frames over gRPC. Without this, every
    // peer's `info.is_archive()` returns false and the archive
    // pool stays empty.
    if archive_mode {
        pi_caps.push(quil_p2p::CanonicalCapability {
            protocol_identifier: quil_execution::capabilities::ARCHIVE_PROTOCOL_V1,
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

    // Without an override, the announce address depends on AutoNAT: say so
    // while nothing is confirmed, since peers then get the listen fallback.
    if pi_announce.is_empty() {
        let rx = p2p_handle.watch_external_addresses();
        let fallback = match select_pubsub_addr("", &[], &pi_listen_fallback).0 {
            addr if addr.is_empty() => "none".to_string(),
            addr => addr,
        };
        let port =
            |addr: &str| port_of(addr).map_or_else(|| "unknown".to_string(), |p| p.to_string());
        let p2p_port = port(&pi_listen_fallback);
        let p2p_protocol = p2p_protocol(&pi_listen_fallback);
        let stream_port = port(&pi_stream_listen);
        sup.run_until_cancelled("external-addr-monitor", move |_token| async move {
            monitor_unconfirmed(rx, UNCONFIRMED_WARN_AFTER, UNCONFIRMED_WARN_REPEAT, |notice| {
                match notice {
                    ReachabilityNotice::Unconfirmed { for_secs, autonat } => {
                        let run = autonat.probe_failure.as_ref();
                        let probe_failure = run.map_or("none", |r| r.class);
                        let probe_failures = run.map_or(0, |r| r.probes);
                        let failing_secs = run.map_or(0, |r| r.since.elapsed().as_secs());
                        macro_rules! unconfirmed {
                            ($msg:literal) => {
                                warn!(
                                    unconfirmed_secs = for_secs,
                                    announced = %fallback,
                                    %p2p_port,
                                    p2p_protocol,
                                    %stream_port,
                                    nat_status = autonat.nat_status,
                                    probe_failure,
                                    probe_failures,
                                    failing_secs,
                                    $msg
                                )
                            };
                        }
                        match unconfirmed_cause(&autonat) {
                            UnconfirmedCause::Unreachable => unconfirmed!(
                                "AutoNAT servers on distinct IPs could not dial this node back, \
                                 or not within 30 s, so PeerInfo announces only the 'announced' \
                                 address (none for a wildcard listen address) and peers may be unable \
                                 to dial this node's p2p or stream port; forward p2p_port over \
                                 p2p_protocol and stream_port over TCP to this node, or set \
                                 p2p.announceListenMultiaddr and p2p.announceStreamListenMultiaddr"
                            ),
                            UnconfirmedCause::ProbesFailing => unconfirmed!(
                                "AutoNAT has confirmed no usable external address because its \
                                 requests fail (probe_failure), so PeerInfo announces only the \
                                 'announced' address (none for a wildcard listen address); a port forward does \
                                 not help. Report this line with the 'AutoNAT probes of this \
                                 node are failing' line; p2p.announceListenMultiaddr bypasses \
                                 AutoNAT for a static public address"
                            ),
                            UnconfirmedCause::Unsettled => unconfirmed!(
                                "AutoNAT has confirmed no usable external address yet \
                                 (nat_status; see the 'AutoNAT status of this node changed' \
                                 lines), so PeerInfo announces only the 'announced' address (none \
                                 for a wildcard listen address) and peers may be unable to dial this node; \
                                 p2p.announceListenMultiaddr bypasses AutoNAT for a static public \
                                 address"
                            ),
                        }
                    }
                    ReachabilityNotice::Confirmed { after_secs } => info!(
                        unconfirmed_secs = after_secs,
                        "AutoNAT confirmed a usable external address; PeerInfo announces it"
                    ),
                }
            })
            .await;
            Ok(())
        });
    }

    let mut addr_rx = p2p_handle.watch_external_addresses();
    sup.run_until_cancelled("peer-info-publisher", move |_token| async move {
        let bitmask = vec![0x00, 0x00, 0x00, 0x00]; // GLOBAL_PEER_INFO
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(publish_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let select_addr = |ext: &ConfirmedExternalAddrs| {
            select_pubsub_addr(&pi_announce, &ext.addrs, &pi_listen_fallback).0
        };
        // The pubsub address of the last publish, and when the last
        // change-triggered publish ran.
        let mut published_addr: Option<String> = None;
        // What that publish carried, for the change line.
        let mut published_carried: Option<String> = None;
        let mut last_change_publish: Option<tokio::time::Instant> = None;
        let started = tokio::time::Instant::now();
        if !wait_for_first_address(&mut addr_rx, select_addr, FIRST_PUBLISH_ADDRESS_WAIT).await {
            info!(
                waited_secs = started.elapsed().as_secs(),
                "PeerInfo publishes without an address: AutoNAT has confirmed none yet and \
                 no announce address is configured; it publishes the address once confirmed"
            );
        }
        loop {
            // Tick FIRST. `interval`'s opening tick completes immediately, so
            // this still publishes at startup without delay — but it stops the
            // body from running twice back-to-back, which is what the trailing
            // tick did and why every restart logged its publish failures in
            // pairs. Between ticks, a settled change of the announce address
            // (the first confirmation after startup, a new IP, AutoNAT
            // finding the node private) publishes early.
            let change_triggered = tokio::select! {
                biased;
                _ = interval.tick() => false,
                _ = announce_change_due(
                    &mut addr_rx,
                    select_addr,
                    published_addr.as_deref().unwrap_or_default(),
                    last_change_publish,
                    ANNOUNCE_CHANGE_SETTLE,
                    ANNOUNCE_CHANGE_MIN_GAP,
                ), if published_addr.is_some() => true,
            };

            // Nobody subscribed yet means the publish would be rejected and
            // dropped, not queued. Wait for a subscriber instead of burning
            // the attempt.
            wait_for_topic_peer(&pi_handle, &bitmask).await;

            // Resolve multiaddrs: the announce override, else the current
            // confirmed address, else the configured listen address when it
            // names a specific IP, else none.
            let ext = addr_rx.borrow().clone();
            let (pubsub_addr, source) =
                select_pubsub_addr(&pi_announce, &ext.addrs, &pi_listen_fallback);
            let stream_addrs = select_stream_addrs(&pi_announce_stream, &pi_stream_listen, &pubsub_addr);
            // Per-worker reachabilities (one per running worker with a
            // non-empty filter) once the worker manager is available.
            let pairs: Vec<(u32, Vec<u8>)> = match pi_worker_manager_slot.get() {
                Some(wm) => quil_engine::worker::WorkerView::snapshot(wm.as_ref())
                    .filter_set()
                    .map(|w| (w.core_id, w.filter.clone()))
                    .collect(),
                None => Vec::new(),
            };
            let reachability = build_reachability(
                &pubsub_addr,
                &stream_addrs,
                &pairs,
                &WorkerAddrs {
                    p2p: &pi_worker_p2p_multiaddrs,
                    stream: &pi_worker_stream_multiaddrs,
                    announce_p2p: &pi_worker_announce_p2p,
                    announce_stream: &pi_worker_announce_stream,
                },
            );
            let worker_reachability_count = reachability.len().saturating_sub(1);

            // What PeerInfo carries: an unannounceable selection (a
            // `0.0.0.0` override) is left out of the record.
            let carried = reachability[0].pubsub_multiaddrs.first().cloned().unwrap_or_default();
            if published_addr.as_deref() != Some(pubsub_addr.as_str()) {
                info!(
                    old = %published_carried.as_deref().map_or("unpublished", |a| if a.is_empty() { "none" } else { a }),
                    new = if carried.is_empty() { "none" } else { carried.as_str() },
                    transport = quil_p2p::external_addr::transport_of(&carried)
                        .map_or("unknown", |t| t.as_str()),
                    reason = announce_reason(source, &ext),
                    stream = ?reachability[0].stream_multiaddrs,
                    "PeerInfo announce address changed"
                );
            }
            if change_triggered {
                last_change_publish = Some(tokio::time::Instant::now());
            }
            published_addr = Some(pubsub_addr.clone());
            published_carried = Some(carried);

            let info = quil_p2p::CanonicalPeerInfo {
                peer_id: pi_peer_id_bytes.clone(),
                reachability,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
                version: quil_config::VERSION.to_vec(),
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

            // Publish KeyRegistry alongside the regular PeerInfo (every 30
            // min); it carries no address, so an address change skips it.
            if change_triggered {
                continue;
            }
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

    mod announce {
        use super::super::*;
        use quil_p2p::external_addr::ExternalAddrChange;
        use std::sync::Mutex;

        const LISTEN: &str = "/ip4/0.0.0.0/tcp/8336";
        const TCP_A: &str = "/ip4/203.0.113.7/tcp/8336";
        const TCP_B: &str = "/ip4/198.51.100.9/tcp/8336";
        const QUIC_A: &str = "/ip4/203.0.113.7/udp/8336/quic-v1";
        const SETTLE: Duration = ANNOUNCE_CHANGE_SETTLE;
        const GAP: Duration = ANNOUNCE_CHANGE_MIN_GAP;

        fn confirmed(addrs: &[&str]) -> ConfirmedExternalAddrs {
            ConfirmedExternalAddrs {
                addrs: addrs.iter().map(|a| a.to_string()).collect(),
                last_change: Some(ExternalAddrChange::Confirmed),
                ..Default::default()
            }
        }

        fn selected(ext: &ConfirmedExternalAddrs) -> String {
            select_pubsub_addr("", &ext.addrs, LISTEN).0
        }

        fn strings(addrs: &[&str]) -> Vec<String> {
            addrs.iter().map(|a| a.to_string()).collect()
        }

        #[test]
        fn the_override_wins_over_confirmed_addresses() {
            assert_eq!(
                select_pubsub_addr(
                    "/dns4/node.example.com/tcp/8336",
                    &strings(&[TCP_A]),
                    LISTEN
                ),
                (
                    "/dns4/node.example.com/tcp/8336".to_string(),
                    AnnounceSource::Override
                )
            );
        }

        #[test]
        fn a_confirmed_address_on_the_listen_transport_comes_first() {
            assert_eq!(
                select_pubsub_addr("", &strings(&[QUIC_A, TCP_B]), LISTEN),
                (TCP_B.to_string(), AnnounceSource::Confirmed)
            );
            assert_eq!(
                select_pubsub_addr(
                    "",
                    &strings(&[TCP_B, QUIC_A]),
                    "/ip4/0.0.0.0/udp/8336/quic-v1"
                ),
                (QUIC_A.to_string(), AnnounceSource::Confirmed)
            );
        }

        #[test]
        fn any_confirmed_address_beats_the_listen_fallback() {
            assert_eq!(
                select_pubsub_addr("", &strings(&[QUIC_A]), LISTEN),
                (QUIC_A.to_string(), AnnounceSource::Confirmed)
            );
            // A wildcard listen address is no address; a specific one is.
            assert_eq!(
                select_pubsub_addr("", &[], LISTEN),
                (String::new(), AnnounceSource::Fallback)
            );
            assert_eq!(
                select_pubsub_addr("", &[], "/ip4/192.0.2.10/tcp/8336"),
                (
                    "/ip4/192.0.2.10/tcp/8336".to_string(),
                    AnnounceSource::Fallback
                )
            );
        }

        #[test]
        fn unspecified_and_empty_addresses_are_not_announceable() {
            for addr in [
                "",
                "/ip4/0.0.0.0/tcp/8336",
                "/ip4/0.0.0.0/udp/8336/quic-v1",
                "/ip6/::/tcp/8336",
                "/ip6/0:0:0:0:0:0:0:0/tcp/8336",
                "/ip4/not-an-ip/tcp/8336",
                "/ip4",
            ] {
                assert!(!announceable(addr), "{addr}");
            }
            for addr in [
                TCP_A,
                QUIC_A,
                "/ip6/2001:db8::7/tcp/8336",
                "/dns4/node.example.com/tcp/8336",
            ] {
                assert!(announceable(addr), "{addr}");
            }
        }

        fn every_address(reachability: &[quil_p2p::CanonicalReachability]) -> Vec<String> {
            reachability
                .iter()
                .flat_map(|r| r.pubsub_multiaddrs.iter().chain(&r.stream_multiaddrs))
                .cloned()
                .collect()
        }

        /// Whatever the configuration, PeerInfo never carries an unspecified
        /// IP: without a confirmed or specific address, the records are empty.
        #[test]
        fn peer_info_never_announces_an_unspecified_ip() {
            let workers = vec![(1, vec![0x11; 32]), (2, vec![0x22; 32]), (3, Vec::new())];
            let none: Vec<String> = Vec::new();
            let wildcard_workers = strings(&["/ip4/0.0.0.0/tcp/40001", "/ip6/::/tcp/40002"]);
            let thread_mode = WorkerAddrs {
                p2p: &none,
                stream: &none,
                announce_p2p: &none,
                announce_stream: &none,
            };
            let process_mode = WorkerAddrs {
                p2p: &wildcard_workers,
                stream: &wildcard_workers,
                announce_p2p: &none,
                announce_stream: &none,
            };
            for listen in [LISTEN, "/ip4/0.0.0.0/udp/8336/quic-v1", "/ip6/::/tcp/8336"] {
                for announce in ["", "/ip4/0.0.0.0/tcp/8336"] {
                    for stream_listen in ["", "/ip4/0.0.0.0/tcp/8340", "/ip4/127.0.0.1/tcp/8340"] {
                        for worker_addrs in [&thread_mode, &process_mode] {
                            let (pubsub, _) = select_pubsub_addr(announce, &[], listen);
                            let stream = select_stream_addrs("", stream_listen, &pubsub);
                            let reachability =
                                build_reachability(&pubsub, &stream, &workers, worker_addrs);
                            assert_eq!(
                                reachability.len(),
                                3,
                                "{listen} {announce} {stream_listen}"
                            );
                            assert_eq!(
                                every_address(&reachability),
                                Vec::<String>::new(),
                                "{listen} {announce} {stream_listen}"
                            );
                        }
                    }
                }
            }
        }

        /// A confirmed address and its stream port go into every record.
        #[test]
        fn peer_info_announces_the_confirmed_address_with_its_stream_port() {
            let workers = vec![(1, vec![0x11; 32])];
            let none: Vec<String> = Vec::new();
            let thread_mode = WorkerAddrs {
                p2p: &none,
                stream: &none,
                announce_p2p: &none,
                announce_stream: &none,
            };
            let (pubsub, source) = select_pubsub_addr("", &strings(&[TCP_A]), LISTEN);
            assert_eq!(source, AnnounceSource::Confirmed);
            let stream = select_stream_addrs("", "/ip4/0.0.0.0/tcp/8340", &pubsub);
            let reachability = build_reachability(&pubsub, &stream, &workers, &thread_mode);
            assert_eq!(reachability.len(), 2);
            for record in &reachability {
                assert_eq!(record.pubsub_multiaddrs, strings(&[TCP_A]));
                assert_eq!(
                    record.stream_multiaddrs,
                    strings(&["/ip4/203.0.113.7/tcp/8340"])
                );
            }
            assert_eq!(reachability[0].filter, vec![0xFF; 32]);
        }

        #[test]
        fn the_p2p_protocol_follows_the_listen_transport() {
            assert_eq!(p2p_protocol(LISTEN), "TCP");
            assert_eq!(p2p_protocol("/ip4/0.0.0.0/udp/8336/quic-v1"), "UDP");
            assert_eq!(p2p_protocol("/ip4/0.0.0.0"), "TCP and UDP");
        }

        #[test]
        fn the_reason_names_the_override_or_the_last_change() {
            let none = ConfirmedExternalAddrs::default();
            assert_eq!(
                announce_reason(AnnounceSource::Override, &confirmed(&[TCP_A])),
                "override"
            );
            assert_eq!(
                announce_reason(AnnounceSource::Fallback, &none),
                "unconfirmed"
            );
            assert_eq!(
                announce_reason(AnnounceSource::Confirmed, &confirmed(&[TCP_A])),
                "confirmed"
            );
            let expired = ConfirmedExternalAddrs {
                addrs: Vec::new(),
                last_change: Some(ExternalAddrChange::Expired),
                ..Default::default()
            };
            assert_eq!(
                announce_reason(AnnounceSource::Fallback, &expired),
                "expired"
            );
        }

        /// Keep the sender alive past the assertions; a dropped sender
        /// freezes the address instead.
        fn drive(
            tx: watch::Sender<ConfirmedExternalAddrs>,
            steps: Vec<(u64, ConfirmedExternalAddrs)>,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                let start = tokio::time::Instant::now();
                for (at, value) in steps {
                    tokio::time::sleep_until(start + Duration::from_secs(at)).await;
                    tx.send_replace(value);
                }
                tokio::time::sleep(Duration::from_secs(1_000_000)).await;
            })
        }

        /// The first publish waits for AutoNAT's first confirmation rather
        /// than announce no address; an address already known returns at
        /// once, and the wait gives up at its bound.
        #[tokio::test(start_paused = true)]
        async fn the_first_publish_waits_for_the_first_confirmation() {
            let (tx, mut rx) = watch::channel(ConfirmedExternalAddrs::default());
            let _driver = drive(tx, vec![(15, confirmed(&[TCP_A]))]);
            let started = tokio::time::Instant::now();
            assert!(wait_for_first_address(&mut rx, selected, FIRST_PUBLISH_ADDRESS_WAIT).await);
            assert_eq!(started.elapsed(), Duration::from_secs(15));

            let (_tx, mut rx) = watch::channel(confirmed(&[TCP_A]));
            let started = tokio::time::Instant::now();
            assert!(wait_for_first_address(&mut rx, selected, FIRST_PUBLISH_ADDRESS_WAIT).await);
            assert_eq!(started.elapsed(), Duration::ZERO);

            let (tx, mut rx) = watch::channel(ConfirmedExternalAddrs::default());
            let _late = drive(tx, vec![(500, confirmed(&[TCP_A]))]);
            let started = tokio::time::Instant::now();
            assert!(!wait_for_first_address(&mut rx, selected, FIRST_PUBLISH_ADDRESS_WAIT).await);
            assert_eq!(started.elapsed(), FIRST_PUBLISH_ADDRESS_WAIT);
        }

        /// The first confirmation after startup publishes once it settles,
        /// not at the next 30-minute tick.
        #[tokio::test(start_paused = true)]
        async fn the_first_confirmation_publishes_after_the_settle_window() {
            let (tx, mut rx) = watch::channel(ConfirmedExternalAddrs::default());
            let _driver = drive(tx, vec![(10, confirmed(&[TCP_A]))]);
            let started = tokio::time::Instant::now();
            announce_change_due(&mut rx, selected, "", None, SETTLE, GAP).await;
            assert_eq!(started.elapsed(), Duration::from_secs(10) + SETTLE);
        }

        #[tokio::test(start_paused = true)]
        async fn a_further_change_restarts_the_settle_window() {
            let (tx, mut rx) = watch::channel(ConfirmedExternalAddrs::default());
            let _driver = drive(
                tx,
                vec![(0, confirmed(&[TCP_A])), (30, confirmed(&[TCP_B]))],
            );
            let started = tokio::time::Instant::now();
            announce_change_due(&mut rx, selected, "", None, SETTLE, GAP).await;
            assert_eq!(started.elapsed(), Duration::from_secs(30) + SETTLE);
        }

        #[tokio::test(start_paused = true)]
        async fn a_change_that_reverts_before_settling_publishes_nothing() {
            let (tx, mut rx) = watch::channel(confirmed(&[TCP_A]));
            let _driver = drive(
                tx,
                vec![(5, confirmed(&[TCP_B])), (30, confirmed(&[TCP_A]))],
            );
            let due = announce_change_due(&mut rx, selected, TCP_A, None, SETTLE, GAP);
            assert!(tokio::time::timeout(Duration::from_secs(3_000), due)
                .await
                .is_err());
        }

        /// A change that leaves the selected address alone (a QUIC address
        /// beside the selected TCP one) is no reason to publish.
        #[tokio::test(start_paused = true)]
        async fn a_change_of_an_unselected_address_publishes_nothing() {
            let (tx, mut rx) = watch::channel(confirmed(&[TCP_A]));
            let _driver = drive(tx, vec![(5, confirmed(&[QUIC_A, TCP_A]))]);
            let due = announce_change_due(&mut rx, selected, TCP_A, None, SETTLE, GAP);
            assert!(tokio::time::timeout(Duration::from_secs(3_000), due)
                .await
                .is_err());
        }

        #[tokio::test(start_paused = true)]
        async fn the_override_ignores_address_changes() {
            let (tx, mut rx) = watch::channel(ConfirmedExternalAddrs::default());
            let _driver = drive(tx, vec![(5, confirmed(&[TCP_A]))]);
            let announce = "/dns4/node.example.com/tcp/8336";
            let select =
                |ext: &ConfirmedExternalAddrs| select_pubsub_addr(announce, &ext.addrs, LISTEN).0;
            let due = announce_change_due(&mut rx, select, announce, None, SETTLE, GAP);
            assert!(tokio::time::timeout(Duration::from_secs(3_000), due)
                .await
                .is_err());
        }

        /// AutoNAT's view changes with every failed probe; that alone does
        /// not restart the settle window.
        #[tokio::test(start_paused = true)]
        async fn a_change_of_autonats_view_alone_does_not_delay_the_publish() {
            let (tx, mut rx) = watch::channel(ConfirmedExternalAddrs::default());
            let view = |class| ConfirmedExternalAddrs {
                autonat: failing(class, false),
                ..confirmed(&[TCP_A])
            };
            let steps = vec![
                (10, confirmed(&[TCP_A])),
                (40, view("timeout")),
                (60, view("io")),
                (65, view("timeout")),
            ];
            let _driver = drive(tx, steps);
            let started = tokio::time::Instant::now();
            announce_change_due(&mut rx, selected, "", None, SETTLE, GAP).await;
            assert_eq!(started.elapsed(), Duration::from_secs(10) + SETTLE);
        }

        /// Change-triggered publishes keep the minimum gap between them.
        #[tokio::test(start_paused = true)]
        async fn change_triggered_publishes_keep_the_minimum_gap() {
            let (tx, mut rx) = watch::channel(confirmed(&[TCP_A]));
            let started = tokio::time::Instant::now();
            let _driver = drive(tx, vec![(1, confirmed(&[TCP_B]))]);
            announce_change_due(&mut rx, selected, TCP_A, Some(started), SETTLE, GAP).await;
            assert_eq!(started.elapsed(), GAP);
        }

        /// An address dropped after going unconfirmed reverts to the
        /// fallback, none for a wildcard listen address, and that is
        /// published too.
        #[tokio::test(start_paused = true)]
        async fn losing_the_address_publishes_the_fallback() {
            let (tx, mut rx) = watch::channel(confirmed(&[TCP_A]));
            let stale = ConfirmedExternalAddrs {
                addrs: Vec::new(),
                last_change: Some(ExternalAddrChange::Stale),
                ..Default::default()
            };
            let _driver = drive(tx, vec![(20, stale)]);
            let started = tokio::time::Instant::now();
            announce_change_due(&mut rx, selected, TCP_A, None, SETTLE, GAP).await;
            assert_eq!(started.elapsed(), Duration::from_secs(20) + SETTLE);
            assert_eq!(selected(&rx.borrow()), "");
        }

        type Notices = Arc<Mutex<Vec<(u64, ReachabilityNotice)>>>;

        fn monitor(rx: watch::Receiver<ConfirmedExternalAddrs>) -> Notices {
            let notices: Notices = Default::default();
            let sink = notices.clone();
            let start = tokio::time::Instant::now();
            tokio::spawn(monitor_unconfirmed(
                rx,
                UNCONFIRMED_WARN_AFTER,
                UNCONFIRMED_WARN_REPEAT,
                move |n| sink.lock().unwrap().push((start.elapsed().as_secs(), n)),
            ));
            notices
        }

        fn unconfirmed(for_secs: u64) -> ReachabilityNotice {
            ReachabilityNotice::Unconfirmed {
                for_secs,
                autonat: AutonatSummary::default(),
            }
        }

        fn failing(class: &'static str, unreachable: bool) -> AutonatSummary {
            AutonatSummary {
                nat_status: "unknown",
                probe_failure: Some(quil_p2p::external_addr::ProbeFailureSummary {
                    class,
                    probes: 7,
                    since: std::time::Instant::now(),
                    unreachable,
                }),
            }
        }

        /// The port-forward advice only when servers' dial-backs failed;
        /// otherwise the warning names the probe failure.
        #[test]
        fn the_warning_advises_a_port_forward_only_for_failed_dial_backs() {
            use UnconfirmedCause::*;
            assert_eq!(unconfirmed_cause(&failing("dial_error", true)), Unreachable);
            assert_eq!(unconfirmed_cause(&failing("timeout", true)), Unreachable);
            for class in ["io", "bad_request", "internal", "unsupported_protocol"] {
                assert_eq!(
                    unconfirmed_cause(&failing(class, false)),
                    ProbesFailing,
                    "{class}"
                );
            }
            // A NAT that drops dial-backs gives timeouts: never "a port
            // forward does not help".
            for class in [
                "timeout",
                "dial_error",
                "connection_closed",
                "dial_refused",
                "no_server",
            ] {
                assert_eq!(
                    unconfirmed_cause(&failing(class, false)),
                    Unsettled,
                    "{class}"
                );
            }
            assert_eq!(unconfirmed_cause(&AutonatSummary::default()), Unsettled);
        }

        /// The warning carries AutoNAT's view at the time it fires.
        #[tokio::test(start_paused = true)]
        async fn the_warning_carries_autonats_current_view() {
            let (tx, rx) = watch::channel(ConfirmedExternalAddrs::default());
            let notices = monitor(rx);
            tokio::time::sleep(Duration::from_secs(300)).await;
            let view = failing("timeout", false);
            tx.send_replace(ConfirmedExternalAddrs {
                autonat: view.clone(),
                ..Default::default()
            });
            tokio::time::sleep(Duration::from_secs(400)).await;
            assert_eq!(
                *notices.lock().unwrap(),
                vec![(
                    600,
                    ReachabilityNotice::Unconfirmed {
                        for_secs: 600,
                        autonat: view
                    }
                )]
            );
        }

        /// Never confirmed: a warning after ten minutes, then hourly, each
        /// with its duration; and one line when an address is confirmed.
        #[tokio::test(start_paused = true)]
        async fn warns_while_unconfirmed_and_reports_the_end() {
            use ReachabilityNotice::*;
            let (tx, rx) = watch::channel(ConfirmedExternalAddrs::default());
            let notices = monitor(rx);
            tokio::time::sleep(Duration::from_secs(5_000)).await;
            tx.send_replace(confirmed(&[TCP_A]));
            tokio::time::sleep(Duration::from_secs(10_000)).await;
            assert_eq!(
                *notices.lock().unwrap(),
                vec![
                    (600, unconfirmed(600)),
                    (4_200, unconfirmed(4_200)),
                    (5_000, Confirmed { after_secs: 5_000 }),
                ]
            );
        }

        /// A confirmation inside the grace period is the normal startup:
        /// no lines. Losing the address later restarts the count.
        #[tokio::test(start_paused = true)]
        async fn a_prompt_confirmation_stays_quiet_and_a_loss_restarts_the_count() {
            let (tx, rx) = watch::channel(ConfirmedExternalAddrs::default());
            let notices = monitor(rx);
            tokio::time::sleep(Duration::from_secs(60)).await;
            tx.send_replace(confirmed(&[TCP_A]));
            tokio::time::sleep(Duration::from_secs(2_000)).await;
            assert!(notices.lock().unwrap().is_empty());
            tx.send_replace(ConfirmedExternalAddrs {
                addrs: Vec::new(),
                last_change: Some(ExternalAddrChange::Stale),
                ..Default::default()
            });
            tokio::time::sleep(Duration::from_secs(700)).await;
            assert_eq!(*notices.lock().unwrap(), vec![(2_660, unconfirmed(600))]);
        }
    }

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
        let peers = wait_for_topic_peer_with(Duration::from_secs(5), || async { Ok(0) }).await;

        assert_eq!(peers, 0);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    /// A subscriber already present costs no delay at all — the fast path
    /// every republish after the first takes.
    #[tokio::test(start_paused = true)]
    async fn does_not_delay_when_peers_are_already_present() {
        let started = tokio::time::Instant::now();
        let peers = wait_for_topic_peer_with(Duration::from_secs(120), || async { Ok(7) }).await;

        assert_eq!(peers, 7);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// A dead command channel means the swarm is going away; waiting on it
    /// would hang shutdown, so the wait ends immediately.
    #[tokio::test(start_paused = true)]
    async fn stops_waiting_when_the_swarm_is_gone() {
        let started = tokio::time::Instant::now();
        let peers = wait_for_topic_peer_with(Duration::from_secs(120), || async {
            Err(quil_types::error::QuilError::P2p(
                "p2p command channel closed".into(),
            ))
        })
        .await;

        assert_eq!(peers, 0);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn caps_a_stalled_subscriber_query() {
        let started = tokio::time::Instant::now();
        let peers =
            wait_for_topic_peer_with(Duration::from_secs(5), || std::future::pending()).await;

        assert_eq!(peers, 0);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_overshoot_a_fractional_deadline() {
        let started = tokio::time::Instant::now();
        let max_wait = Duration::from_millis(1500);
        let peers = wait_for_topic_peer_with(max_wait, || async { Ok(0) }).await;

        assert_eq!(peers, 0);
        assert_eq!(started.elapsed(), max_wait);
    }
}
