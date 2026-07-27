//! Onion circuit originator — the client side that builds multi-hop circuits and
//! sends private messages through them. Post-quantum adaptation of the Go
//! `OnionRouter` originator path (`router.go`: `extendToHop` / `sendControl`
//! CREATE → `createdWait` → `onCreated`, `sendRelay` / `applyForward`).
//!
//! Circuit construction:
//! - [`create_circuit`](OnionOriginator::create_circuit) establishes the first
//! hop with a direct CREATE (the originator has a transport link to it).
//! - [`extend_circuit`](OnionOriginator::extend_circuit) adds each further hop by
//! tunnelling a CREATE through the already-built prefix: an EXTEND relay-command
//! targets the current last hop, which issues the CREATE to the new hop and
//! relays the CREATED back (wrapped, one layer per hop) as EXTENDED.
//! - [`send_message`](OnionOriginator::send_message) onion-wraps a payload so the
//! exit hop recovers it in cleartext.
//!
//! Differences from Go (consistent with the rest of the Rust onion stack):
//! per-hop key agreement is sntrup761 KEM (not X448 NTOR), CREATED is verified
//! against a `created_confirmation` hash, and cells are AES-256-GCM layered.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::cell;
use super::router::{decrypt_layer, encrypt_layer, LAYER_BACKWARD, LAYER_FORWARD};
use super::{
    onion_kem_decapsulate, onion_kem_encapsulate, onion_keypair, OnData, Transport, TransportError,
};

/// Complete the initiator half of the forward-secret KEM-ntor handshake from a
/// CREATED / EXTENDED reply: decapsulate `ct_ephemeral` with our ephemeral
/// secret, derive `hop_secret = kdf_ntor(ss_static ‖ ss_ephemeral)`, and verify
/// the relay's confirmation before accepting the hop. Returns the hop secret.
fn derive_and_verify_hop(
    ss_static: &[u8],
    eph_secret_key: &[u8],
    eph_public_key: &[u8],
    ct_static: &[u8],
    created_payload: &[u8],
) -> Option<Vec<u8>> {
    let (ct_ephemeral, confirmation) = cell::parse_created_payload(created_payload)?;
    let ss_ephemeral = onion_kem_decapsulate(ct_ephemeral, eph_secret_key)?;
    let hop_secret = cell::kdf_ntor(
        ss_static,
        &ss_ephemeral,
        eph_public_key,
        ct_static,
        ct_ephemeral,
    );
    if !cell::ct_eq(confirmation, &cell::created_confirmation(&hop_secret)) {
        return None;
    }
    Some(hop_secret.to_vec())
}

/// A circuit the originator has built, keyed by its entry circuit id.
struct CircuitState {
    /// The first-hop peer we send all cells to.
    entry_peer: Vec<u8>,
    /// Per-hop shared secrets, entry-first (`[s0, s1, …]`), one per established
    /// hop. Data is layered exit-first; backward cells are peeled entry-first.
    /// `Zeroizing` wipes each on drop (circuit close).
    secrets: Vec<Zeroizing<Vec<u8>>>,
    /// Next forward-DATA sequence to stamp on an outgoing message.
    fwd_send_seq: u64,
    /// Highest backward-DATA sequence accepted from the exit; `seq <= this` is a
    /// replay and is dropped.
    bwd_recv_seq: u64,
}

/// Client that drives circuit construction and message sending over a
/// [`Transport`]. Register it with [`OnionOriginator::new`], which installs the
/// inbound handler for CREATED / EXTENDED / backward-DATA cells.
pub struct OnionOriginator {
    transport: Arc<dyn Transport>,
    /// `(hop_peer, circ_id)` → waiter for a direct-hop CREATED (first hop).
    pending_created: Arc<Mutex<HashMap<(Vec<u8>, u32), oneshot::Sender<Vec<u8>>>>>,
    /// `entry_circ` → waiter for an EXTENDED (the CREATED of a tunnelled hop).
    pending_extend: Arc<Mutex<HashMap<u32, oneshot::Sender<Vec<u8>>>>>,
    /// `entry_circ` → circuit state.
    circuits: Arc<Mutex<HashMap<u32, CircuitState>>>,
    /// Receives payloads that arrive back from the exit as `(entry_circ, payload)`.
    on_data: Option<OnData>,
}

impl OnionOriginator {
    /// Build an originator over `transport` WITHOUT installing an inbound handler
    /// on it. The caller (e.g. [`OnionNode`](super::node::OnionNode)) is
    /// responsible for routing inbound cells into [`handle_created`] /
    /// [`handle_relay_backward`]. Use [`new`] for a standalone originator.
    ///
    /// [`handle_created`]: OnionOriginator::handle_created
    /// [`handle_relay_backward`]: OnionOriginator::handle_relay_backward
    /// [`new`]: OnionOriginator::new
    pub fn detached(transport: Arc<dyn Transport>, on_data: Option<OnData>) -> Arc<Self> {
        Arc::new(Self {
            transport,
            pending_created: Arc::new(Mutex::new(HashMap::new())),
            pending_extend: Arc::new(Mutex::new(HashMap::new())),
            circuits: Arc::new(Mutex::new(HashMap::new())),
            on_data,
        })
    }

    /// Build an originator over `transport` and register its inbound handler.
    /// `on_data`, if set, receives payloads that arrive back from the exit
    /// (backward RELAY/DATA cells) as `(entry_circ, payload)`.
    pub fn new(transport: Arc<dyn Transport>, on_data: Option<OnData>) -> Arc<Self> {
        let orig = Self::detached(Arc::clone(&transport), on_data);
        let handler = Arc::clone(&orig);
        transport.set_on_receive(Arc::new(move |src_peer: &[u8], circ_id: u32, cell: &[u8]| {
            match cell::parse_cell(cell) {
                Some((cell::CMD_CREATED, payload)) => {
                    handler.handle_created(src_peer, circ_id, payload);
                }
                Some((cell::CMD_RELAY, ciphertext)) => {
                    handler.handle_relay_backward(circ_id, ciphertext);
                }
                _ => {}
            }
        }));
        orig
    }

    /// Complete a first-hop CREATED waiter. Returns `true` if one matched
    /// `(src_peer, circ_id)` (i.e. this cell was ours).
    pub fn handle_created(&self, src_peer: &[u8], circ_id: u32, payload: &[u8]) -> bool {
        let waiter = self
            .pending_created
            .lock()
            .unwrap()
            .remove(&(src_peer.to_vec(), circ_id));
        match waiter {
            Some(tx) => {
                let _ = tx.send(payload.to_vec());
                true
            }
            None => false,
        }
    }

    /// Peel a backward RELAY cell through this circuit's established hop layers
    /// and act on the inner command: EXTENDED completes an extend waiter, DATA is
    /// handed to `on_data`. Returns `true` if `circ_id` names a circuit of ours
    /// (the cell was consumed), `false` if it's unknown here.
    pub fn handle_relay_backward(&self, circ_id: u32, ciphertext: &[u8]) -> bool {
        let secrets = match self.circuits.lock().unwrap().get(&circ_id) {
            Some(c) => c.secrets.clone(),
            None => return false,
        };
        let mut cur = ciphertext.to_vec();
        for s in &secrets {
            cur = match decrypt_layer(s, LAYER_BACKWARD, &cur) {
                Some(p) => p,
                None => return true,
            };
        }
        match cell::parse_inner(&cur) {
            Some(cell::Inner::Relay {
                rcmd: cell::RCMD_EXTENDED,
                data,
            }) => {
                if let Some(tx) = self.pending_extend.lock().unwrap().remove(&circ_id) {
                    let _ = tx.send(data.to_vec());
                }
            }
            Some(cell::Inner::Relay {
                rcmd: cell::RCMD_DATA,
                data,
            }) => {
                // REPLAY GUARD: accept a reply only if strictly newer than the
                // last seen for this circuit (atomic check + update).
                let (seq, payload) = match cell::parse_seq_data(data) {
                    Some(x) => x,
                    None => return true,
                };
                let fresh = {
                    let mut circuits = self.circuits.lock().unwrap();
                    match circuits.get_mut(&circ_id) {
                        Some(c) if seq > c.bwd_recv_seq => {
                            c.bwd_recv_seq = seq;
                            true
                        }
                        _ => false, // replay (or gone) → drop
                    }
                };
                if fresh {
                    if let Some(cb) = &self.on_data {
                        // Originator reply: no upstream peer (our own circuit).
                        cb(&[], circ_id, payload.to_vec());
                    }
                }
            }
            _ => {}
        }
        true
    }

    /// Establish the first hop of a new circuit with the FORWARD-SECRET KEM-ntor
    /// handshake: encapsulate to the hop's STATIC onion key (authenticating it),
    /// ship a fresh EPHEMERAL public key, send CREATE, then on CREATED derive
    /// `hop_secret = kdf_ntor(ss_static ‖ ss_ephemeral)` and verify. The ephemeral
    /// secret is dropped when this returns, giving forward secrecy. Wrap the future
    /// in [`tokio::time::timeout`] to bound the handshake.
    pub async fn create_circuit(
        &self,
        entry_peer: &[u8],
        entry_circ: u32,
        entry_hop_public_key: &[u8],
    ) -> Option<()> {
        let (ss_static, ct_static) = onion_kem_encapsulate(entry_hop_public_key)?;
        let (eph_public_key, eph_secret_key) = onion_keypair();
        let create = cell::build_cell(
            cell::CMD_CREATE,
            &cell::build_create_payload(0, b"", &eph_public_key, &ct_static),
        );

        let key = (entry_peer.to_vec(), entry_circ);
        let (tx, rx) = oneshot::channel();
        self.pending_created.lock().unwrap().insert(key.clone(), tx);

        if self.transport.send(entry_peer, entry_circ, create).is_err() {
            self.pending_created.lock().unwrap().remove(&key);
            return None;
        }

        let created_payload = rx.await.ok()?;
        let hop_secret = derive_and_verify_hop(&ss_static, &eph_secret_key, &eph_public_key, &ct_static, &created_payload)?;
        self.circuits.lock().unwrap().insert(
            entry_circ,
            CircuitState {
                entry_peer: entry_peer.to_vec(),
                secrets: vec![Zeroizing::new(hop_secret)],
                fwd_send_seq: 0,
                bwd_recv_seq: 0,
            },
        );
        Some(())
    }

    /// Extend an existing circuit by one hop: tunnel a CREATE to `next_peer`
    /// through the built prefix (an EXTEND targeting the current last hop), await
    /// the EXTENDED reply, verify it, and append the new hop's secret. The circuit
    /// must already exist (via [`create_circuit`]).
    pub async fn extend_circuit(
        &self,
        entry_circ: u32,
        next_peer: &[u8],
        next_hop_public_key: &[u8],
    ) -> Option<()> {
        let (entry_peer, secrets) = {
            let circuits = self.circuits.lock().unwrap();
            let c = circuits.get(&entry_circ)?;
            (c.entry_peer.clone(), c.secrets.clone())
        };

        // Forward-secret KEM-ntor to the new hop (same as create_circuit, but the
        // CREATE material is tunneled through the prefix as an EXTEND command).
        let (ss_static, ct_static) = onion_kem_encapsulate(next_hop_public_key)?;
        let (eph_public_key, eph_secret_key) = onion_keypair();
        let inner = cell::build_relay_inner(
            cell::RCMD_EXTEND,
            &cell::build_extend_data(next_peer, &eph_public_key, &ct_static),
        );
        let onion = wrap_for_last_hop(&secrets, &inner)?;

        let (tx, rx) = oneshot::channel();
        self.pending_extend.lock().unwrap().insert(entry_circ, tx);

        let cell = cell::build_cell(cell::CMD_RELAY, &onion);
        if self.transport.send(&entry_peer, entry_circ, cell).is_err() {
            self.pending_extend.lock().unwrap().remove(&entry_circ);
            return None;
        }

        let extended_payload = rx.await.ok()?;
        let new_secret = derive_and_verify_hop(&ss_static, &eph_secret_key, &eph_public_key, &ct_static, &extended_payload)?;
        if let Some(c) = self.circuits.lock().unwrap().get_mut(&entry_circ) {
            c.secrets.push(Zeroizing::new(new_secret));
        }
        Some(())
    }

    /// Number of established hops in a circuit (test / introspection helper).
    pub fn hop_count(&self, entry_circ: u32) -> usize {
        self.circuits
            .lock()
            .unwrap()
            .get(&entry_circ)
            .map(|c| c.secrets.len())
            .unwrap_or(0)
    }

    /// Onion-wrap `payload` and send it through `entry_circ` so the exit hop
    /// recovers it in cleartext.
    pub fn send_message(&self, entry_circ: u32, payload: &[u8]) -> Result<(), TransportError> {
        // Bound the payload so the layered cell can't overflow the u16 length
        // prefix (F7). Larger messages must be chunked by the caller (not yet
        // implemented).
        if payload.len() > cell::MAX_ONION_PAYLOAD {
            return Err(TransportError::StreamClosed);
        }
        let (entry_peer, secrets, seq) = {
            let mut circuits = self.circuits.lock().unwrap();
            let c = circuits.get_mut(&entry_circ).ok_or(TransportError::NoActiveStream)?;
            c.fwd_send_seq += 1;
            (c.entry_peer.clone(), c.secrets.clone(), c.fwd_send_seq)
        };
        // Stamp the forward sequence inside the DATA cell (exit's replay guard).
        let inner = cell::build_relay_inner(cell::RCMD_DATA, &cell::seq_data(seq, payload));
        let onion = wrap_for_last_hop(&secrets, &inner).ok_or(TransportError::StreamClosed)?;
        self.transport
            .send(&entry_peer, entry_circ, cell::build_cell(cell::CMD_RELAY, &onion))
    }
}

/// Layer `inner` (a relay command destined for the LAST hop) through `secrets`:
/// the last hop's layer wraps `inner` directly; every earlier hop wraps a FORWARD
/// cell around the next layer. The entry hop's layer ends up outermost.
fn wrap_for_last_hop(secrets: &[Zeroizing<Vec<u8>>], inner: &[u8]) -> Option<Vec<u8>> {
    let last = secrets.len().checked_sub(1)?;
    let mut cell = encrypt_layer(&secrets[last], LAYER_FORWARD, inner)?;
    for secret in secrets[..last].iter().rev() {
        cell = encrypt_layer(secret, LAYER_FORWARD, &cell::build_forward_inner(&cell))?;
    }
    Some(cell)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::relay::OnionRelay;
    use crate::onion::{drive_relay, onion_keypair, OnReceive};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// In-memory onion network: routes cells between nodes by peer id, invoking
    /// the destination's registered handler with the sender's peer id as source
    /// (as the gRPC transport does on a delivered `ReceiveMessage`).
    #[derive(Default)]
    struct MemNet {
        handlers: Mutex<HashMap<Vec<u8>, OnReceive>>,
    }

    impl MemNet {
        fn transport(self: &Arc<Self>, self_peer: &[u8]) -> Arc<MemTransport> {
            Arc::new(MemTransport {
                net: Arc::clone(self),
                self_peer: self_peer.to_vec(),
            })
        }
    }

    struct MemTransport {
        net: Arc<MemNet>,
        self_peer: Vec<u8>,
    }

    impl Transport for MemTransport {
        fn send(&self, dst: &[u8], circ_id: u32, cell: Vec<u8>) -> Result<(), TransportError> {
            let handler = self.net.handlers.lock().unwrap().get(dst).cloned();
            match handler {
                Some(cb) => {
                    cb(&self.self_peer, circ_id, &cell);
                    Ok(())
                }
                None => Err(TransportError::NoActiveStream),
            }
        }
        fn set_on_receive(&self, cb: OnReceive) {
            self.net
                .handlers
                .lock()
                .unwrap()
                .insert(self.self_peer.clone(), cb);
        }
    }

    /// Stand up a relay on the net with a fresh onion key; return its public key.
    fn spawn_relay(net: &Arc<MemNet>, peer: &[u8]) -> Vec<u8> {
        let (pk, sk) = onion_keypair();
        let relay = Arc::new(OnionRelay::new());
        relay.set_onion_secret_key(sk);
        drive_relay(relay, net.transport(peer), None);
        pk
    }

    /// End-to-end THREE-hop circuit built with CREATE + two EXTENDs, then a
    /// private message delivered in cleartext at the exit.
    /// orig → relayA → relayB → relayC(exit)
    #[tokio::test]
    async fn originator_builds_three_hop_circuit_and_delivers() {
        let net = Arc::new(MemNet::default());
        let pk_a = spawn_relay(&net, b"relayA");
        let pk_b = spawn_relay(&net, b"relayB");

        // relayC is the exit: give it an on_data sink.
        let got = Arc::new(Mutex::new(None::<(u32, Vec<u8>)>));
        let delivered = Arc::new(AtomicBool::new(false));
        let (pk_c, sk_c) = onion_keypair();
        {
            let relay_c = Arc::new(OnionRelay::new());
            relay_c.set_onion_secret_key(sk_c);
            let got = got.clone();
            let delivered = delivered.clone();
            let on_data: OnData = Arc::new(move |_peer: &[u8], circ, payload| {
                *got.lock().unwrap() = Some((circ, payload));
                delivered.store(true, Ordering::SeqCst);
            });
            drive_relay(relay_c, net.transport(b"relayC"), Some(on_data));
        }

        let orig = OnionOriginator::new(net.transport(b"orig"), None);
        let t = std::time::Duration::from_secs(3);

        tokio::time::timeout(t, orig.create_circuit(b"relayA", 1, &pk_a))
            .await
            .expect("no timeout")
            .expect("hop A established");
        tokio::time::timeout(t, orig.extend_circuit(1, b"relayB", &pk_b))
            .await
            .expect("no timeout")
            .expect("extended to B");
        tokio::time::timeout(t, orig.extend_circuit(1, b"relayC", &pk_c))
            .await
            .expect("no timeout")
            .expect("extended to C");
        assert_eq!(orig.hop_count(1), 3);

        orig.send_message(1, b"three-hop private hello").unwrap();

        for _ in 0..200 {
            if delivered.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let (circ, payload) = got.lock().unwrap().clone().expect("message delivered at exit");
        assert_eq!(payload, b"three-hop private hello");
        // Delivered on relayC's own upstream circuit id, not the originator's.
        assert!(circ >= 0x8000_0000, "exit circ is a downstream-allocated id");
    }

    /// Bidirectional TWO-hop circuit: the originator sends a request, the exit
    /// answers via `build_data_reply`, and the reply is backward-relayed and
    /// surfaces at the originator's own `on_data`.
    ///   orig → relayA → relayB(exit) then   relayB → relayA → orig
    #[tokio::test]
    async fn originator_receives_reply_from_exit() {
        let net = Arc::new(MemNet::default());
        let pk_a = spawn_relay(&net, b"relayA");

        // relayB is the exit: on request, it sends a reply back up the circuit.
        let (pk_b, sk_b) = onion_keypair();
        let relay_b = Arc::new(OnionRelay::new());
        relay_b.set_onion_secret_key(sk_b);
        let tb = net.transport(b"relayB");
        {
            let relay = relay_b.clone();
            let t = tb.clone();
            let on_data: OnData = Arc::new(move |up_peer: &[u8], circ, payload| {
                assert_eq!(payload, b"ping");
                let relay = relay.clone();
                let t = t.clone();
                let up_peer = up_peer.to_vec();
                tokio::spawn(async move {
                    if let Some((peer, up_circ, cell)) =
                        relay.build_data_reply(&up_peer, circ, b"pong").await
                    {
                        let _ = t.send(&peer, up_circ, cell);
                    }
                });
            });
            drive_relay(relay_b.clone(), tb.clone(), Some(on_data));
        }

        // Originator records replies delivered back to it.
        let reply = Arc::new(Mutex::new(None::<Vec<u8>>));
        let orig = {
            let reply = reply.clone();
            let on_data: OnData = Arc::new(move |_peer: &[u8], _circ, payload| {
                *reply.lock().unwrap() = Some(payload);
            });
            OnionOriginator::new(net.transport(b"orig"), Some(on_data))
        };

        let t = std::time::Duration::from_secs(3);
        tokio::time::timeout(t, orig.create_circuit(b"relayA", 1, &pk_a))
            .await
            .unwrap()
            .expect("hop A");
        tokio::time::timeout(t, orig.extend_circuit(1, b"relayB", &pk_b))
            .await
            .unwrap()
            .expect("extend B");

        orig.send_message(1, b"ping").unwrap();

        for _ in 0..200 {
            if reply.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(reply.lock().unwrap().clone().expect("reply delivered"), b"pong");
    }

    /// Single-hop: create + deliver at the (exit) relay.
    #[tokio::test]
    async fn originator_single_hop_delivers_at_exit() {
        let net = Arc::new(MemNet::default());
        let got = Arc::new(Mutex::new(None::<Vec<u8>>));
        let (pk, sk) = onion_keypair();
        {
            let relay = Arc::new(OnionRelay::new());
            relay.set_onion_secret_key(sk);
            let got = got.clone();
            let on_data: OnData = Arc::new(move |_peer: &[u8], _circ, payload| {
                *got.lock().unwrap() = Some(payload);
            });
            drive_relay(relay, net.transport(b"relayA"), Some(on_data));
        }

        let orig = OnionOriginator::new(net.transport(b"orig"), None);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            orig.create_circuit(b"relayA", 7, &pk),
        )
        .await
        .expect("no timeout")
        .expect("established");
        assert_eq!(orig.hop_count(7), 1);

        orig.send_message(7, b"one hop").unwrap();
        for _ in 0..100 {
            if got.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(got.lock().unwrap().clone().unwrap(), b"one hop");
    }

    /// F7 regression: a payload that would overflow the u16 cell length prefix
    /// (after layering) is rejected at the app boundary.
    #[tokio::test]
    async fn send_message_rejects_oversized_payload() {
        let net = Arc::new(MemNet::default());
        let orig = OnionOriginator::new(net.transport(b"orig"), None);
        let big = vec![0u8; cell::MAX_ONION_PAYLOAD + 1];
        assert!(orig.send_message(1, &big).is_err());
    }

    #[tokio::test]
    async fn create_circuit_fails_against_relay_without_key() {
        let net = Arc::new(MemNet::default());
        // Relay with no onion key → CREATE rejected, no CREATED ever arrives.
        let relay = Arc::new(OnionRelay::new());
        drive_relay(relay, net.transport(b"relayA"), None);
        let (pk, _sk) = onion_keypair();

        let orig = OnionOriginator::new(net.transport(b"orig"), None);
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            orig.create_circuit(b"relayA", 1, &pk),
        )
        .await;
        assert!(res.is_err(), "must not complete without CREATED");
    }
}
