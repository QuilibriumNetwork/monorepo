//! Unified onion node — one [`Transport`] handler that plays every role at once.
//!
//! On a real node the same link carries cells for circuits this node originates,
//! circuits it relays, and circuits it terminates as the exit. Each role's
//! machinery ([`OnionOriginator`] and [`OnionRelay`]) is complete on its own, but
//! both want to own the transport's single `on_receive`. `OnionNode` installs ONE
//! dispatcher that routes each inbound cell to the right role by circuit state —
//! the Rust equivalent of Go's single `handleInboundCell`. This is the piece a
//! live node wires up (seed the relay with the `q-onion-key`, advertise the
//! routing capability).
//!
//! Dispatch (deterministic — every cell is link-framed):
//! - CREATE → relay answers the handshake.
//! - CREATED → a downstream we extended to ([`OnionRelay::is_down_circ`]) → relay
//! wraps it back up as EXTENDED; otherwise our own first-hop reply → originator.
//! - RELAY → forward for a circuit through us ([`OnionRelay::is_forward_circ`]);
//! else backward from our downstream ([`OnionRelay::is_down_circ`]); else a
//! backward cell for a circuit we originated → originator peels it.
//!
//! Note: circuits are keyed by circuit id alone (not `(peer, circ)` as Tor does),
//! so a node must not reuse a circuit id across roles simultaneously — relay
//! state is checked before originator state, and the relay allocates downstream
//! ids from the high half of the space to stay clear of initiator-chosen ids.

use std::sync::Arc;

use super::cell;
use super::originator::OnionOriginator;
use super::relay::{OnionRelay, RelayAction};
use super::{dial_and_send, OnData, PeerValidator, Transport, TransportError};

/// A node that can originate, relay, and exit onion circuits over one transport.
pub struct OnionNode {
    transport: Arc<dyn Transport>,
    relay: Arc<OnionRelay>,
    originator: Arc<OnionOriginator>,
    self_peer_id: Vec<u8>,
    peer_validator: Option<PeerValidator>,
}

/// A cloneable, lifetime-independent handle for sending backward RELAY/DATA
/// replies on a circuit this node is the exit of. It holds the relay + transport
/// directly (the same `Arc`s the dispatcher owns), so it keeps working even if
/// the [`OnionNode`] it came from is dropped — letting an exit consumer answer a
/// request asynchronously (e.g. after an RPC round-trip).
#[derive(Clone)]
pub struct OnionReplyHandle {
    relay: Arc<OnionRelay>,
    transport: Arc<dyn Transport>,
}

impl OnionReplyHandle {
    /// Send `payload` back to the originator over the circuit `(up_peer, up_circ)`
    /// — the pair the request was delivered under (circuits are peer-scoped).
    pub async fn send_reply(
        &self,
        up_peer: &[u8],
        up_circ: u32,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        match self.relay.build_data_reply(up_peer, up_circ, payload).await {
            Some((peer, circ, cell)) => {
                self.transport.ensure_connected(&peer).await;
                self.transport.send(&peer, circ, cell)
            }
            None => Err(TransportError::NoActiveStream),
        }
    }
}

impl OnionNode {
    /// Build a node over `transport` and install the unified dispatcher.
    /// - `self_peer_id`: this node's own peer id — DEFENSE: circuits/EXTENDs
    /// naming it as the next hop are rejected (no self-connection).
    /// - `onion_secret_key`: this node's sntrup761 onion secret (the `q-onion-key`
    /// secret half). Required to answer CREATE / act as a relay or exit; pass
    /// `None` for an originate-only client.
    /// - `peer_validator`: DEFENSE — a next hop must pass this (an in-network
    /// routing peer), so tunnels can't reach open-web endpoints. `None` accepts
    /// any (test default).
    /// - `exit_handler`: invoked as `(up_circ, payload)` when a RELAY/DATA cell
    /// terminates here (we are the exit). Reply with [`send_reply`](Self::send_reply).
    /// - `reply_handler`: invoked as `(entry_circ, payload)` when a reply arrives
    /// for a circuit THIS node originated.
    pub fn new(
        transport: Arc<dyn Transport>,
        self_peer_id: Vec<u8>,
        onion_secret_key: Option<Vec<u8>>,
        peer_validator: Option<PeerValidator>,
        exit_handler: Option<OnData>,
        reply_handler: Option<OnData>,
    ) -> Arc<Self> {
        let relay = Arc::new(OnionRelay::new());
        relay.set_self_peer_id(self_peer_id.clone());
        if let Some(sk) = onion_secret_key {
            relay.set_onion_secret_key(sk);
        }
        super::spawn_expiry_sweeper(&relay);
        if let Some(v) = &peer_validator {
            relay.set_peer_validator(Arc::clone(v));
        }
        let originator = OnionOriginator::detached(Arc::clone(&transport), reply_handler);

        let relay_h = Arc::clone(&relay);
        let orig_h = Arc::clone(&originator);
        let out = Arc::clone(&transport);
        transport.set_on_receive(Arc::new(move |src_peer: &[u8], circ_id: u32, cell: &[u8]| {
            let relay = Arc::clone(&relay_h);
            let orig = Arc::clone(&orig_h);
            let out = Arc::clone(&out);
            let exit = exit_handler.clone();
            let src = src_peer.to_vec();
            let cell = cell.to_vec();
            tokio::spawn(async move {
                match cell::parse_cell(&cell) {
                    // Someone opens a circuit hop through us.
                    Some((cell::CMD_CREATE, _)) => {
                        if let Some(created) = relay.handle_create_cell(&src, circ_id, &cell).await {
                            dial_and_send(&out, &src, circ_id, created).await;
                        }
                    }
                    Some((cell::CMD_CREATED, payload)) => {
                        // A downstream we extended toward answered → relay it back
                        // up as EXTENDED; otherwise it's our own first-hop reply.
                        if relay.is_down_circ(circ_id).await {
                            if let Some((up_peer, up_circ, up_cell)) =
                                relay.handle_link_created(circ_id, payload).await
                            {
                                dial_and_send(&out, &up_peer, up_circ, up_cell).await;
                            }
                        } else {
                            orig.handle_created(&src, circ_id, payload);
                        }
                    }
                    Some((cell::CMD_RELAY, ct)) => {
                        if relay.is_forward_circ(&src, circ_id).await {
                            match relay.handle_relay_forward(&src, circ_id, ct).await {
                                RelayAction::Forward { peer, circ_id: oc, cell } => {
                                    dial_and_send(&out, &peer, oc, cell).await;
                                }
                                RelayAction::Deliver { payload } => {
                                    if let Some(cb) = &exit {
                                        cb(&src, circ_id, payload);
                                    }
                                }
                                RelayAction::None => {}
                            }
                        } else if relay.is_down_circ(circ_id).await {
                            if let Some((up_peer, up_circ, up_cell)) =
                                relay.handle_relay_backward(circ_id, ct).await
                            {
                                dial_and_send(&out, &up_peer, up_circ, up_cell).await;
                            }
                        } else {
                            // A backward cell for a circuit we originated.
                            orig.handle_relay_backward(circ_id, ct);
                        }
                    }
                    _ => {}
                }
            });
        }));

        Arc::new(Self {
            transport,
            relay,
            originator,
            self_peer_id,
            peer_validator,
        })
    }

    /// DEFENSE: a hop we build to must not be ourselves (no self-connection) and,
    /// when a validator is installed, must be an in-network routing peer (not an
    /// open-web endpoint).
    fn next_hop_allowed(&self, peer: &[u8]) -> bool {
        if peer.is_empty() || peer == self.self_peer_id.as_slice() {
            return false;
        }
        match &self.peer_validator {
            Some(v) => v(peer),
            None => true,
        }
    }

    /// Establish the first hop of a circuit this node originates. Rejects a
    /// self-hop or a non-network entry peer.
    pub async fn create_circuit(
        &self,
        entry_peer: &[u8],
        entry_circ: u32,
        entry_hop_public_key: &[u8],
    ) -> Option<()> {
        if !self.next_hop_allowed(entry_peer) {
            return None;
        }
        // Dial the entry hop if we don't already have a link to it.
        if !self.transport.ensure_connected(entry_peer).await {
            return None;
        }
        self.originator
            .create_circuit(entry_peer, entry_circ, entry_hop_public_key)
            .await
    }

    /// Extend a circuit this node originates by one hop. Rejects a self-hop or a
    /// non-network next peer.
    pub async fn extend_circuit(
        &self,
        entry_circ: u32,
        next_peer: &[u8],
        next_hop_public_key: &[u8],
    ) -> Option<()> {
        if !self.next_hop_allowed(next_peer) {
            return None;
        }
        self.originator
            .extend_circuit(entry_circ, next_peer, next_hop_public_key)
            .await
    }

    /// Send an onion-wrapped message through a circuit this node originates.
    pub fn send_message(&self, entry_circ: u32, payload: &[u8]) -> Result<(), TransportError> {
        self.originator.send_message(entry_circ, payload)
    }

    /// As the exit, answer a request that arrived via the `exit_handler`: build a
    /// backward RELAY/DATA cell and send it toward the originator over the
    /// `(up_peer, up_circ)` the request was delivered under.
    pub async fn send_reply(
        &self,
        up_peer: &[u8],
        up_circ: u32,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        match self.relay.build_data_reply(up_peer, up_circ, payload).await {
            Some((peer, circ, cell)) => {
                self.transport.ensure_connected(&peer).await;
                self.transport.send(&peer, circ, cell)
            }
            None => Err(TransportError::NoActiveStream),
        }
    }

    /// Established hop count of a circuit this node originates.
    pub fn hop_count(&self, entry_circ: u32) -> usize {
        self.originator.hop_count(entry_circ)
    }

    /// A detached handle for replying on circuits this node exits — hand it to an
    /// exit consumer so it can answer requests asynchronously.
    pub fn reply_handle(&self) -> OnionReplyHandle {
        OnionReplyHandle {
            relay: Arc::clone(&self.relay),
            transport: Arc::clone(&self.transport),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::{onion_keypair, OnReceive};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemNet {
        handlers: Mutex<HashMap<Vec<u8>, OnReceive>>,
    }
    impl MemNet {
        fn transport(self: &Arc<Self>, peer: &[u8]) -> Arc<MemTransport> {
            Arc::new(MemTransport {
                net: Arc::clone(self),
                self_peer: peer.to_vec(),
            })
        }
    }
    struct MemTransport {
        net: Arc<MemNet>,
        self_peer: Vec<u8>,
    }
    impl Transport for MemTransport {
        fn send(&self, dst: &[u8], circ_id: u32, cell: Vec<u8>) -> Result<(), TransportError> {
            let h = self.net.handlers.lock().unwrap().get(dst).cloned();
            match h {
                Some(cb) => {
                    cb(&self.self_peer, circ_id, &cell);
                    Ok(())
                }
                None => Err(TransportError::NoActiveStream),
            }
        }
        fn set_on_receive(&self, cb: OnReceive) {
            self.net.handlers.lock().unwrap().insert(self.self_peer.clone(), cb);
        }
    }

    /// Three OnionNodes; the middle one relays purely through its unified
    /// dispatcher while the endpoints originate/exit. Proves the dispatcher does
    /// the relay role (forward + EXTEND + backward) as well as `drive_relay` did.
    /// A(originator) → B(relay) → C(exit)
    #[tokio::test]
    async fn three_onion_nodes_route_a_message() {
        let net = Arc::new(MemNet::default());
        let (pk_b, sk_b) = onion_keypair();
        let (pk_c, sk_c) = onion_keypair();

        let got = Arc::new(Mutex::new(None::<Vec<u8>>));
        let done = Arc::new(AtomicBool::new(false));
        let exit_c: OnData = {
            let got = got.clone();
            let done = done.clone();
            Arc::new(move |_peer: &[u8], _circ, payload| {
                *got.lock().unwrap() = Some(payload);
                done.store(true, Ordering::SeqCst);
            })
        };

        let _b = OnionNode::new(net.transport(b"B"), b"B".to_vec(), Some(sk_b), None, None, None);
        let _c = OnionNode::new(net.transport(b"C"), b"C".to_vec(), Some(sk_c), None, Some(exit_c), None);
        let a = OnionNode::new(net.transport(b"A"), b"A".to_vec(), None, None, None, None);

        let t = std::time::Duration::from_secs(3);
        tokio::time::timeout(t, a.create_circuit(b"B", 1, &pk_b))
            .await
            .unwrap()
            .expect("hop B");
        tokio::time::timeout(t, a.extend_circuit(1, b"C", &pk_c))
            .await
            .unwrap()
            .expect("extend C");
        assert_eq!(a.hop_count(1), 2);

        a.send_message(1, b"routed via unified nodes").unwrap();
        for _ in 0..200 {
            if done.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(got.lock().unwrap().clone().unwrap(), b"routed via unified nodes");
    }

    /// One node is SIMULTANEOUSLY a relay/exit for an inbound circuit AND the
    /// originator of its own outbound circuit — the whole point of unification.
    /// A → B(exit) and, at the same time,   B → C(exit)
    #[tokio::test]
    async fn node_is_relay_and_originator_at_once() {
        let net = Arc::new(MemNet::default());
        let (pk_b, sk_b) = onion_keypair();
        let (pk_c, sk_c) = onion_keypair();

        // B delivers what A sends it (B as exit) ...
        let at_b = Arc::new(Mutex::new(None::<Vec<u8>>));
        let exit_b: OnData = {
            let at_b = at_b.clone();
            Arc::new(move |_peer: &[u8], _c, p| *at_b.lock().unwrap() = Some(p))
        };
        // ... and C delivers what B sends it (B as originator).
        let at_c = Arc::new(Mutex::new(None::<Vec<u8>>));
        let exit_c: OnData = {
            let at_c = at_c.clone();
            Arc::new(move |_peer: &[u8], _c, p| *at_c.lock().unwrap() = Some(p))
        };

        let b = OnionNode::new(net.transport(b"B"), b"B".to_vec(), Some(sk_b), None, Some(exit_b), None);
        let _c = OnionNode::new(net.transport(b"C"), b"C".to_vec(), Some(sk_c), None, Some(exit_c), None);
        let a = OnionNode::new(net.transport(b"A"), b"A".to_vec(), None, None, None, None);

        let t = std::time::Duration::from_secs(3);
        // A originates a circuit to B and sends it a message.
        tokio::time::timeout(t, a.create_circuit(b"B", 10, &pk_b))
            .await
            .unwrap()
            .expect("A→B");
        a.send_message(10, b"hello B").unwrap();

        // B, while serving as A's exit, originates its OWN circuit to C.
        tokio::time::timeout(t, b.create_circuit(b"C", 20, &pk_c))
            .await
            .unwrap()
            .expect("B→C");
        b.send_message(20, b"hello C").unwrap();

        for _ in 0..200 {
            if at_b.lock().unwrap().is_some() && at_c.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(at_b.lock().unwrap().clone().unwrap(), b"hello B");
        assert_eq!(at_c.lock().unwrap().clone().unwrap(), b"hello C");
    }

    /// DEFENSE: a node refuses to build a circuit to itself (self-loop) or to a
    /// peer that isn't a valid in-network routing peer (open-web endpoint), and
    /// still builds to a real network peer.
    #[tokio::test]
    async fn defenses_reject_self_and_non_network_hops() {
        let net = Arc::new(MemNet::default());
        let (pk_b, sk_b) = onion_keypair();
        let _b = OnionNode::new(net.transport(b"B"), b"B".to_vec(), Some(sk_b), None, None, None);

        // A treats ONLY "B" as a valid in-network routing peer.
        let validator: PeerValidator = Arc::new(|p: &[u8]| p == b"B");
        let a = OnionNode::new(
            net.transport(b"A"),
            b"A".to_vec(),
            None,
            Some(validator),
            None,
            None,
        );

        // DEFENSE 2: cannot connect to self.
        assert!(a.create_circuit(b"A", 1, &pk_b).await.is_none());
        // DEFENSE 1: cannot connect to a non-network (open-web) endpoint.
        assert!(a.create_circuit(b"1.2.3.4:443", 2, &pk_b).await.is_none());
        assert!(a.extend_circuit(2, b"1.2.3.4:443", &pk_b).await.is_none());
        // Sanity: a real network peer is accepted.
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            a.create_circuit(b"B", 3, &pk_b),
        )
        .await
        .unwrap()
        .expect("B is a valid network peer");
    }

    /// Bidirectional through unified nodes: A originates a 2-hop circuit, C (exit)
    /// replies via `send_reply`, and the reply surfaces at A's `reply_handler`.
    #[tokio::test]
    async fn unified_nodes_round_trip_request_reply() {
        let net = Arc::new(MemNet::default());
        let (pk_b, sk_b) = onion_keypair();
        let (pk_c, sk_c) = onion_keypair();

        let _b = OnionNode::new(net.transport(b"B"), b"B".to_vec(), Some(sk_b), None, None, None);

        // C's exit handler replies through C itself; C is shared into the handler
        // via a slot set right after construction (handler needs `c`, `c` needs
        // the handler — resolve the cycle with a slot).
        let c_slot: Arc<Mutex<Option<Arc<OnionNode>>>> = Arc::new(Mutex::new(None));
        let exit_c: OnData = {
            let slot = c_slot.clone();
            Arc::new(move |up_peer: &[u8], circ, payload| {
                assert_eq!(payload, b"ping");
                let slot = slot.clone();
                let up_peer = up_peer.to_vec();
                tokio::spawn(async move {
                    let node = slot.lock().unwrap().clone();
                    if let Some(node) = node {
                        let _ = node.send_reply(&up_peer, circ, b"pong").await;
                    }
                });
            })
        };
        let c = OnionNode::new(net.transport(b"C"), b"C".to_vec(), Some(sk_c), None, Some(exit_c), None);
        *c_slot.lock().unwrap() = Some(c.clone());

        let reply = Arc::new(Mutex::new(None::<Vec<u8>>));
        let reply_h: OnData = {
            let reply = reply.clone();
            Arc::new(move |_peer: &[u8], _c, p| *reply.lock().unwrap() = Some(p))
        };
        let a = OnionNode::new(net.transport(b"A"), b"A".to_vec(), None, None, None, Some(reply_h));

        let t = std::time::Duration::from_secs(3);
        tokio::time::timeout(t, a.create_circuit(b"B", 1, &pk_b))
            .await
            .unwrap()
            .expect("A→B");
        tokio::time::timeout(t, a.extend_circuit(1, b"C", &pk_c))
            .await
            .unwrap()
            .expect("extend C");
        a.send_message(1, b"ping").unwrap();

        for _ in 0..200 {
            if reply.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(reply.lock().unwrap().clone().unwrap(), b"pong");
    }
}
