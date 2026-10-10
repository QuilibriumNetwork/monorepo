//! Onion routing transport — provides private messaging between nodes
//! via multi-hop encrypted circuits.
//!
//! POST-QUANTUM: each hop's key agreement is a **Streamlined NTRU Prime
//! (sntrup761)** KEM encapsulation to the relay's onion public key (the same
//! NTRU-family KEM the `:8340` / libp2p PQNoise transports use), NOT X448 ECDH.
//! The circuit initiator encapsulates to each hop, deriving a per-hop shared
//! secret + a ciphertext that rides the CREATE cell; the relay decapsulates with
//! its onion secret key. Per-hop cell encryption is AES-256-GCM keyed from the
//! shared secret (symmetric ⇒ already post-quantum). No classical DH anywhere.

pub mod cell;
pub mod node;
pub mod originator;
pub mod router;
pub mod relay;

use std::sync::Arc;

use pqcrypto_ntruprime::sntrup761;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};

/// sntrup761 onion key byte lengths.
pub const ONION_PUBLIC_KEY_LEN: usize = sntrup761::public_key_bytes();
pub const ONION_SECRET_KEY_LEN: usize = sntrup761::secret_key_bytes();
pub const ONION_CIPHERTEXT_LEN: usize = sntrup761::ciphertext_bytes();

/// KEM-encapsulate to a hop's onion public key (post-quantum, replaces X448
/// ECDH). Returns `(shared_secret, ciphertext)`: the shared secret keys the
/// hop's AES-GCM layer; the ciphertext travels in the CREATE cell to the relay,
/// which recovers the same secret via [`onion_kem_decapsulate`]. `None` if the
/// public key is malformed.
pub fn onion_kem_encapsulate(hop_public_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let pk = sntrup761::PublicKey::from_bytes(hop_public_key).ok()?;
    let (ss, ct) = sntrup761::encapsulate(&pk);
    Some((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
}

/// KEM-decapsulate a CREATE cell's ciphertext at a relay, recovering the shared
/// secret with the relay's onion secret key. `None` if inputs are malformed.
pub fn onion_kem_decapsulate(ciphertext: &[u8], onion_secret_key: &[u8]) -> Option<Vec<u8>> {
    let sk = sntrup761::SecretKey::from_bytes(onion_secret_key).ok()?;
    let ct = sntrup761::Ciphertext::from_bytes(ciphertext).ok()?;
    Some(sntrup761::decapsulate(&ct, &sk).as_bytes().to_vec())
}

/// Generate a fresh sntrup761 onion keypair `(public, secret)`.
pub fn onion_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = sntrup761::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Callback invoked for every inbound link-level cell: `(src_peer_id, circ_id,
/// cell)`. Mirrors the callback in Go `onion.Transport.OnReceive`.
pub type OnReceive = Arc<dyn Fn(&[u8], u32, &[u8]) + Send + Sync>;

/// Errors a [`Transport`] can surface when sending a cell.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("empty peer id")]
    EmptyPeerId,
    #[error("unknown or non-routing peer")]
    UnvalidatedPeer,
    #[error("no active stream to peer")]
    NoActiveStream,
    #[error("stream send failed")]
    StreamClosed,
    /// DEFENSE: a hop may not connect to itself (A→A is forbidden; A→B, B→A,
    /// B→C are all fine). Prevents self-loop circuits.
    #[error("cannot connect to self")]
    SelfConnection,
}

/// Predicate: is `peer_id` a valid in-network routing peer? DEFENSE: onion
/// endpoints/hops must be network peers, never arbitrary (open-web) addresses.
/// The concrete impl consults the PeerInfo cache for the `PROTOCOL_ROUTING`
/// capability. Returning `false` rejects the hop.
pub type PeerValidator = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// The hop-to-hop link that carries onion cells. Mirrors Go `onion.Transport`
/// (`transport.go`). The transport must already provide integrity /
/// confidentiality (on a Rust node it rides the pqnoise `:8340` server); onion
/// cells are layered on top. The concrete gRPC implementation is
/// `quil_rpc::onion_service::OnionTransport`.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Send a link-level cell to a peer. The cell is stamped with THIS node's id
    /// as the source, so the receiver learns who to route replies back to.
    fn send(&self, peer_id: &[u8], circ_id: u32, cell: Vec<u8>) -> Result<(), TransportError>;

    /// Register a callback for incoming link-level cells from any peer. The
    /// transport invokes `cb` for every onion cell destined to this node.
    fn set_on_receive(&self, cb: OnReceive);

    /// Ensure a link to `peer_id` exists, DIALING the peer's onion service if we
    /// have no stream to it yet (Go `ConnectToPeer`). Returns whether a usable
    /// link exists afterwards. Default: assume always reachable (transports where
    /// every peer is directly addressable, e.g. the in-memory test net).
    async fn ensure_connected(&self, _peer_id: &[u8]) -> bool {
        true
    }
}

/// Callback invoked when a RELAY/DATA cell reaches this node: `(peer, circ_id,
/// payload)`. For an EXIT, `peer` is the upstream peer the circuit came from —
/// needed to answer via `build_data_reply`, since circuits are keyed by
/// `(peer, circ)`. For an ORIGINATOR reply handler, `peer` is empty (the reply is
/// for this node's own circuit, identified by `circ_id`).
pub type OnData = Arc<dyn Fn(&[u8], u32, Vec<u8>) + Send + Sync>;

/// Ensure a link to `peer` exists (dialing if needed), then send the cell. Used
/// by the dispatchers so forwarding to a not-yet-connected downstream hop dials
/// it first; sends to peers that dialed us return immediately from
/// `ensure_connected` (their stream already exists).
pub(crate) async fn dial_and_send(
    transport: &Arc<dyn Transport>,
    peer: &[u8],
    circ_id: u32,
    cell: Vec<u8>,
) {
    if transport.ensure_connected(peer).await {
        if let Err(e) = transport.send(peer, circ_id, cell) {
            tracing::debug!(error = %e, "onion send failed");
        }
    } else {
        tracing::debug!("onion send skipped: could not establish link to peer");
    }
}

/// Wire an [`OnionRelay`](relay::OnionRelay) to a [`Transport`] so this node acts
/// as a full onion relay: it answers CREATE handshakes, forwards RELAY cells one
/// layer at a time, tunnels EXTEND (issuing a CREATE to the next hop and relaying
/// the CREATED back), relays backward cells toward the originator, and — when it
/// is the exit for a RELAY/DATA cell — delivers the payload to `on_data`.
///
/// This is the relay side of Go's `handleInboundCell`: forward routing + the
/// CREATE/EXTEND link-control state machine. `on_data` stands in for Go's exit
/// TCP handling (`exitHandlePlain`). Every cell is link-framed
/// (`| Cmd | Len | payload |`), so forward-vs-act is deterministic — no
/// heuristic recognition.
/// Spawn a background task that periodically tears down idle circuits on `relay`
/// ([`OnionRelay::sweep_expired`](relay::OnionRelay::sweep_expired)), zeroizing
/// their hop keys. Holds only a `Weak` ref, so it exits when the relay is dropped.
/// Requires a Tokio runtime (the caller is always within one).
pub fn spawn_expiry_sweeper(relay: &Arc<relay::OnionRelay>) {
    let weak = Arc::downgrade(relay);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            match weak.upgrade() {
                Some(r) => r.sweep_expired(relay::CIRCUIT_IDLE_TIMEOUT).await,
                None => break,
            }
        }
    });
}

pub fn drive_relay(
    relay: Arc<relay::OnionRelay>,
    transport: Arc<dyn Transport>,
    on_data: Option<OnData>,
) {
    use relay::RelayAction;
    spawn_expiry_sweeper(&relay);
    let send_transport = Arc::clone(&transport);
    transport.set_on_receive(Arc::new(move |src_peer: &[u8], circ_id: u32, cell: &[u8]| {
        let relay = Arc::clone(&relay);
        let out = Arc::clone(&send_transport);
        let on_data = on_data.clone();
        let src = src_peer.to_vec();
        let cell = cell.to_vec();
        // Relay work touches the async circuit table (tokio Mutex); the transport
        // calls this callback from within its runtime, so spawn.
        tokio::spawn(async move {
            match cell::parse_cell(&cell) {
                // A peer opens a circuit hop through us → establish + CREATED.
                Some((cell::CMD_CREATE, _)) => {
                    if let Some(created) = relay.handle_create_cell(&src, circ_id, &cell).await {
                        dial_and_send(&out, &src, circ_id, created).await;
                    } else {
                        tracing::trace!(circ_id, "onion CREATE rejected");
                    }
                }
                // The next hop answered a CREATE we issued during EXTEND → wrap it
                // as EXTENDED and relay it back toward the originator.
                Some((cell::CMD_CREATED, payload)) => {
                    if let Some((up_peer, up_circ, up_cell)) =
                        relay.handle_link_created(circ_id, payload).await
                    {
                        dial_and_send(&out, &up_peer, up_circ, up_cell).await;
                    }
                }
                // A layered onion cell.
                Some((cell::CMD_RELAY, ct)) => {
                    if relay.is_forward_circ(&src, circ_id).await {
                        match relay.handle_relay_forward(&src, circ_id, ct).await {
                            RelayAction::Forward { peer, circ_id: oc, cell } => {
                                dial_and_send(&out, &peer, oc, cell).await;
                            }
                            RelayAction::Deliver { payload } => {
                                if let Some(cb) = on_data {
                                    cb(&src, circ_id, payload);
                                }
                            }
                            RelayAction::None => {}
                        }
                    } else if relay.is_down_circ(circ_id).await {
                        // Backward data from the next hop → add our layer, send up.
                        if let Some((up_peer, up_circ, up_cell)) =
                            relay.handle_relay_backward(circ_id, ct).await
                        {
                            dial_and_send(&out, &up_peer, up_circ, up_cell).await;
                        }
                    } else {
                        tracing::trace!(circ_id, "onion RELAY cell for unknown circuit");
                    }
                }
                _ => {}
            }
        });
    }));
}

/// Onion cell types matching Go's `onion/constants.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    /// Circuit establishment: create a new hop.
    Create = 1,
    /// Circuit established acknowledgment.
    Created = 2,
    /// Relay data cell (encrypted payload).
    Relay = 3,
    /// Destroy a circuit.
    Destroy = 4,
}

/// Maximum cell payload size (matching Go).
pub const MAX_CELL_SIZE: usize = 65536;

/// Circuit identifier.
pub type CircuitId = u32;

#[cfg(test)]
mod tests {
    use super::relay::OnionRelay;
    use super::router::encrypt_layer;
    use super::*;

    /// In-memory [`Transport`] that captures the registered callback and records
    /// every outbound cell — enough to prove the relay-forward coupling.
    #[derive(Default)]
    struct MockTransport {
        cb: std::sync::RwLock<Option<OnReceive>>,
        sent: std::sync::Mutex<Vec<(Vec<u8>, u32, Vec<u8>)>>,
    }

    impl Transport for MockTransport {
        fn send(&self, peer_id: &[u8], circ_id: u32, cell: Vec<u8>) -> Result<(), TransportError> {
            self.sent.lock().unwrap().push((peer_id.to_vec(), circ_id, cell));
            Ok(())
        }
        fn set_on_receive(&self, cb: OnReceive) {
            *self.cb.write().unwrap() = Some(cb);
        }
    }

    async fn wait_for_sent(transport: &MockTransport) {
        for _ in 0..100 {
            if !transport.sent.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// The initiator handshake state a test needs to finish the ntor exchange.
    struct FsInit {
        cell: Vec<u8>,
        ss_static: Vec<u8>,
        eph_sec: Vec<u8>,
        eph_pub: Vec<u8>,
        ct_static: Vec<u8>,
    }

    /// Build a forward-secret CREATE cell to `relay_pk` + the initiator state.
    fn fs_create(relay_pk: &[u8], outbound: u32, next: &[u8]) -> FsInit {
        let (ss_static, ct_static) = onion_kem_encapsulate(relay_pk).unwrap();
        let (eph_pub, eph_sec) = onion_keypair();
        let cell = cell::build_cell(
            cell::CMD_CREATE,
            &cell::build_create_payload(outbound, next, &eph_pub, &ct_static),
        );
        FsInit { cell, ss_static, eph_sec, eph_pub, ct_static }
    }

    /// Initiator side: derive + verify the hop secret from a CREATED payload.
    fn fs_hop_secret(init: &FsInit, created_payload: &[u8]) -> Vec<u8> {
        let (ct_eph, conf) = cell::parse_created_payload(created_payload).unwrap();
        let ss_eph = onion_kem_decapsulate(ct_eph, &init.eph_sec).unwrap();
        let hop = cell::kdf_ntor(
            &init.ss_static,
            &ss_eph,
            &init.eph_pub,
            &init.ct_static,
            ct_eph,
        );
        assert_eq!(conf, cell::created_confirmation(&hop), "confirmation must match");
        hop.to_vec()
    }

    #[tokio::test]
    async fn drive_relay_create_handshake_replies_created() {
        let (onion_pk, onion_sk) = onion_keypair();
        let relay = Arc::new(OnionRelay::new());
        relay.set_onion_secret_key(onion_sk);

        let transport = Arc::new(MockTransport::default());
        drive_relay(relay.clone(), transport.clone(), None);
        let cb = transport.cb.read().unwrap().clone().unwrap();

        let init = fs_create(&onion_pk, 0, b"");
        cb(b"initiator", 1, &init.cell);

        wait_for_sent(&transport).await;
        let sent = transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, b"initiator"); // CREATED back upstream
        assert_eq!(sent[0].1, 1);
        let (cmd, payload) = cell::parse_cell(&sent[0].2).unwrap();
        assert_eq!(cmd, cell::CMD_CREATED);
        // Finishing the ntor handshake verifies the relay's confirmation.
        let _hop = fs_hop_secret(&init, payload);
        drop(sent);
        assert_eq!(relay.active_relays().await, 1);
    }

    #[tokio::test]
    async fn drive_relay_delivers_data_at_exit() {
        let (onion_pk, onion_sk) = onion_keypair();
        let relay = Arc::new(OnionRelay::new());
        relay.set_onion_secret_key(onion_sk);

        let delivered = Arc::new(std::sync::Mutex::new(None::<(u32, Vec<u8>)>));
        let d = delivered.clone();
        let on_data: OnData = Arc::new(move |_peer: &[u8], circ, payload| {
            *d.lock().unwrap() = Some((circ, payload));
        });

        let transport = Arc::new(MockTransport::default());
        drive_relay(relay.clone(), transport.clone(), Some(on_data));
        let cb = transport.cb.read().unwrap().clone().unwrap();

        // Establish the hop (exit — no downstream), completing the ntor handshake.
        let init = fs_create(&onion_pk, 0, b"");
        cb(b"initiator", 1, &init.cell);
        wait_for_sent(&transport).await;
        let hop = {
            let s = transport.sent.lock().unwrap();
            let payload = cell::parse_cell(&s[0].2).unwrap().1.to_vec();
            fs_hop_secret(&init, &payload)
        };
        transport.sent.lock().unwrap().clear();

        // Send a RELAY/DATA cell (seq 1) — one layer keyed by the hop secret.
        let data_inner = cell::build_relay_inner(cell::RCMD_DATA, &cell::seq_data(1, b"hi exit"));
        let data_cell = cell::build_cell(
            cell::CMD_RELAY,
            &encrypt_layer(&hop, router::LAYER_FORWARD, &data_inner).unwrap(),
        );
        cb(b"initiator", 1, &data_cell);

        for _ in 0..100 {
            if delivered.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let got = delivered.lock().unwrap().clone().unwrap();
        assert_eq!(got.0, 1); // circuit id
        assert_eq!(got.1, b"hi exit"); // payload, with the seq stripped
        // Exit does not forward anything onward.
        assert!(transport.sent.lock().unwrap().is_empty());

        // REPLAY GUARD: re-sending the exact same cell (seq 1) is dropped.
        *delivered.lock().unwrap() = None;
        cb(b"initiator", 1, &data_cell);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            delivered.lock().unwrap().is_none(),
            "replayed DATA cell must not be delivered again"
        );
    }

    #[tokio::test]
    async fn drive_relay_drops_relay_cell_for_unknown_circuit() {
        let relay = Arc::new(OnionRelay::new());
        let transport = Arc::new(MockTransport::default());
        drive_relay(relay.clone(), transport.clone(), None);

        let cb = transport.cb.read().unwrap().clone().unwrap();
        cb(
            b"prev",
            999,
            &cell::build_cell(cell::CMD_RELAY, b"ciphertext-for-unknown-circuit"),
        );

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(transport.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn drive_relay_rejects_create_without_onion_key() {
        let (onion_pk, _sk) = onion_keypair();
        let relay = Arc::new(OnionRelay::new()); // no onion secret key installed
        let transport = Arc::new(MockTransport::default());
        drive_relay(relay.clone(), transport.clone(), None);
        let cb = transport.cb.read().unwrap().clone().unwrap();

        let init = fs_create(&onion_pk, 0, b"");
        cb(b"initiator", 1, &init.cell);

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            transport.sent.lock().unwrap().is_empty(),
            "no CREATED without an onion key"
        );
        assert_eq!(relay.active_relays().await, 0);
    }
}
