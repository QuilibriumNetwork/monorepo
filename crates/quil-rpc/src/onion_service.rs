//! `OnionService.Connect` bidi-stream transport — the link layer that carries
//! onion cells between peers. Faithful port of Go
//! `node/p2p/onion/grpc_transport.go` (`GRPCTransport`).
//!
//! This is the piece the Go node actually registers on its live gRPC server
//! (`RegisterOnionServiceServer(server, e.onionService)`): a bidirectional
//! stream where each `SendMessage{peer_id, circ_id, cell}` a peer pushes is
//! validated and handed to an `on_receive(src_peer_id, circ_id, cell)` callback,
//! and where this node can push `ReceiveMessage`s back to any peer that holds an
//! open stream. The onion circuit crypto (sntrup761 KEM key agreement +
//! AES-256-GCM cells) lives in `quil_p2p::onion` (router/relay); this module is
//! purely the transport those layers ride on.
//!
//! Cells are already end-to-end encrypted by the onion layers, so — exactly like
//! Go — the transport itself carries them opaquely; on a Rust node it is served
//! over the same pqnoise `:8340` server as `GlobalService`, so the link hop is
//! additionally post-quantum-encrypted.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{Request, Response, Status, Streaming};

use quil_p2p::onion::{OnReceive, Transport, TransportError};
use quil_types::proto::global::{
    onion_service_client::OnionServiceClient, onion_service_server::OnionService, ReceiveMessage,
    SendMessage,
};

use crate::archive_client::QuilPqNoiseConnector;
use quil_engine::worker_node::multiaddr_to_socket_addr;

/// Capability id a peer must advertise in its `PeerInfo.capabilities` to accept
/// onion routing. Mirrors Go `onion.ProtocolRouting` (`constants.go`).
pub const PROTOCOL_ROUTING: u32 = 0x0000_0301;

/// Resolves a peer's routing eligibility: returns `Some(stream_multiaddrs)` iff
/// the peer is known AND advertises [`PROTOCOL_ROUTING`], else `None`. Mirrors Go
/// `validatePeer` (capability check) + the multiaddr lookup in `ConnectToPeer`.
pub type PeerRoutingLookup = Arc<dyn Fn(&[u8]) -> Option<Vec<String>> + Send + Sync>;

/// Extract the sntrup761 onion PUBLIC key a peer published in the metadata of its
/// [`PROTOCOL_ROUTING`] capability. Because PeerInfo is Ed448-signed, a key read
/// from a VERIFIED `CanonicalPeerInfo` is authenticated as that peer's onion key
/// — the value a circuit initiator encapsulates to (closing the MITM gap). `None`
/// if the peer doesn't advertise routing or published no key.
pub fn onion_public_key_from_peer_info(
    info: &quil_p2p::CanonicalPeerInfo,
) -> Option<&[u8]> {
    info.capabilities
        .iter()
        .find(|c| c.protocol_identifier == PROTOCOL_ROUTING)
        .map(|c| c.additional_metadata.as_slice())
        .filter(|k| !k.is_empty())
}

struct Inner {
    self_peer_id: Vec<u8>,
    peer_lookup: PeerRoutingLookup,
    /// peer_id -> outbound side of that peer's server `Connect` stream (a peer
    /// dialed US; we reply on it).
    server_streams: RwLock<HashMap<Vec<u8>, mpsc::Sender<Result<ReceiveMessage, Status>>>>,
    /// peer_id -> outbound side of a client `Connect` stream WE opened to that
    /// peer (Go `clientStreams`). Populated by [`ensure_connected`].
    client_streams: RwLock<HashMap<Vec<u8>, mpsc::Sender<SendMessage>>>,
    /// Ed448 seed for the pqnoise handshake when dialing peers. `None` disables
    /// the outbound dialer (server-only, e.g. tests).
    falcon_signing_key: Option<Vec<u8>>,
    on_receive: RwLock<Option<OnReceive>>,
}

/// gRPC onion transport. Holds, per connected peer, an outbound sender into that
/// peer's open `Connect` server stream, so [`send`](Self::send) can push a cell
/// back to any peer currently streaming to us. Cheap to `clone` (an `Arc`).
#[derive(Clone)]
pub struct OnionTransport {
    inner: Arc<Inner>,
}

impl OnionTransport {
    /// Server-only transport (no outbound dialer): it can relay/reply for peers
    /// that dial IT, but cannot proactively reach peers.
    pub fn new(self_peer_id: Vec<u8>, peer_lookup: PeerRoutingLookup) -> Self {
        Self::new_inner(self_peer_id, peer_lookup, None)
    }

    /// Full transport with an outbound dialer: [`ensure_connected`] can open a
    /// pqnoise client `Connect` stream to any routing peer using `falcon_signing_key`.
    pub fn new_with_dialer(
        self_peer_id: Vec<u8>,
        peer_lookup: PeerRoutingLookup,
        falcon_signing_key: Vec<u8>,
    ) -> Self {
        Self::new_inner(self_peer_id, peer_lookup, Some(falcon_signing_key))
    }

    fn new_inner(
        self_peer_id: Vec<u8>,
        peer_lookup: PeerRoutingLookup,
        falcon_signing_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                self_peer_id,
                peer_lookup,
                server_streams: RwLock::new(HashMap::new()),
                client_streams: RwLock::new(HashMap::new()),
                falcon_signing_key,
                on_receive: RwLock::new(None),
            }),
        }
    }

    /// True iff `peer_id` is known and advertises the routing capability.
    fn validate_peer(&self, peer_id: &[u8]) -> bool {
        !peer_id.is_empty() && (self.inner.peer_lookup)(peer_id).is_some()
    }

    /// Peers with an active inbound stream.
    pub fn active_peers(&self) -> Vec<Vec<u8>> {
        self.inner.server_streams.read().keys().cloned().collect()
    }

    /// Drop a peer's stream (Go `DisconnectPeer`, server-side).
    pub fn disconnect_peer(&self, peer_id: &[u8]) {
        self.inner.server_streams.write().remove(peer_id);
    }

    /// This node's own peer id (Go `peerID`).
    pub fn self_peer_id(&self) -> &[u8] {
        &self.inner.self_peer_id
    }
}

#[async_trait::async_trait]
impl Transport for OnionTransport {
    /// Register the callback invoked for every validated inbound cell.
    fn set_on_receive(&self, cb: OnReceive) {
        *self.inner.on_receive.write() = Some(cb);
    }

    /// Push a cell to `peer_id`. Prefers the peer's server stream (it dialed us),
    /// else a client stream we opened (Go's server/client `Send` branches). The
    /// cell is stamped with OUR id as the source so the peer can route replies
    /// back to us; `NoActiveStream` if we have neither stream (call
    /// [`ensure_connected`](Self::ensure_connected) first).
    fn send(&self, peer_id: &[u8], circ_id: u32, cell: Vec<u8>) -> Result<(), TransportError> {
        if peer_id.is_empty() {
            return Err(TransportError::EmptyPeerId);
        }
        // DEFENSE 2: a hop may not connect to itself. Rejected at the transport so
        // it holds for every path (relay forward, EXTEND CREATE, originate, reply).
        if peer_id == self.inner.self_peer_id.as_slice() {
            return Err(TransportError::SelfConnection);
        }
        // DEFENSE 1: the destination must be a known in-network routing peer
        // (validate_peer consults the PeerInfo cache for PROTOCOL_ROUTING), never
        // an arbitrary open-web address.
        if !self.validate_peer(peer_id) {
            return Err(TransportError::UnvalidatedPeer);
        }

        let self_id = self.inner.self_peer_id.clone();

        // Prefer replying on the peer's server stream.
        let server_tx = self.inner.server_streams.read().get(peer_id).cloned();
        if let Some(tx) = server_tx {
            let msg = ReceiveMessage {
                source_peer_id: self_id,
                circ_id,
                cell,
            };
            if tx.try_send(Ok(msg)).is_err() {
                self.inner.server_streams.write().remove(peer_id);
                return Err(TransportError::StreamClosed);
            }
            return Ok(());
        }

        // Otherwise use a client stream we opened to the peer.
        let client_tx = self.inner.client_streams.read().get(peer_id).cloned();
        if let Some(tx) = client_tx {
            let msg = SendMessage {
                peer_id: self_id,
                circ_id,
                cell,
            };
            if tx.try_send(msg).is_err() {
                self.inner.client_streams.write().remove(peer_id);
                return Err(TransportError::StreamClosed);
            }
            return Ok(());
        }

        Err(TransportError::NoActiveStream)
    }

    /// Ensure a link to `peer_id` exists — dialing its onion service over pqnoise
    /// if we hold no stream yet (Go `ConnectToPeer`). Opens a client `Connect`
    /// stream, stores its sender, and spawns a reader that feeds inbound cells to
    /// `on_receive`. Returns whether a usable link exists afterwards.
    async fn ensure_connected(&self, peer_id: &[u8]) -> bool {
        if peer_id.is_empty() || peer_id == self.inner.self_peer_id.as_slice() {
            return false;
        }
        if self.inner.server_streams.read().contains_key(peer_id)
            || self.inner.client_streams.read().contains_key(peer_id)
        {
            return true;
        }
        let seed = match self.inner.falcon_signing_key.clone() {
            Some(s) => s,
            None => return false, // server-only transport, no dialer
        };
        // DEFENSE 1: only dial a validated in-network routing peer, and use its
        // advertised stream multiaddr (never an arbitrary address).
        let addrs = match (self.inner.peer_lookup)(peer_id) {
            Some(a) => a,
            None => return false,
        };
        let socket_addr = match addrs.iter().find_map(|ma| multiaddr_to_socket_addr(ma)) {
            Some(sa) => sa,
            None => return false,
        };

        // `http://` scheme: tonic refuses `https://` unless its own TLS is set;
        // we install our own PQNoise connector on :8340 instead.
        let endpoint = match tonic::transport::Endpoint::from_shared(format!(
            "http://{}",
            socket_addr
        )) {
            Ok(e) => e
                .connect_timeout(std::time::Duration::from_secs(10))
                .tcp_nodelay(true)
                .http2_keep_alive_interval(std::time::Duration::from_secs(10))
                .keep_alive_while_idle(true),
            Err(_) => return false,
        };
        let channel = match endpoint
            .connect_with_connector(QuilPqNoiseConnector::new(seed))
            .await
        {
            Ok(ch) => ch,
            Err(e) => {
                tracing::debug!(error = %e, "onion dial failed");
                return false;
            }
        };

        let (tx, rx) = mpsc::channel::<SendMessage>(1024);
        let mut client = OnionServiceClient::new(channel)
            .max_decoding_message_size(64 * 1024 * 1024)
            .max_encoding_message_size(64 * 1024 * 1024);
        let response = match client
            .connect(Request::new(ReceiverStream::new(rx)))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "onion connect stream failed");
                return false;
            }
        };
        self.inner
            .client_streams
            .write()
            .insert(peer_id.to_vec(), tx);

        // Reader: inbound ReceiveMessages from this client stream → on_receive.
        let inner = Arc::clone(&self.inner);
        let peer_key = peer_id.to_vec();
        tokio::spawn(async move {
            let mut inbound = response.into_inner();
            loop {
                match inbound.message().await {
                    Ok(Some(msg)) => {
                        let cb = inner.on_receive.read().clone();
                        if let Some(cb) = cb {
                            cb(&msg.source_peer_id, msg.circ_id, &msg.cell);
                        }
                    }
                    Ok(None) | Err(_) => {
                        inner.client_streams.write().remove(&peer_key);
                        break;
                    }
                }
            }
        });
        true
    }
}

type ConnectStreamOut =
    Pin<Box<dyn Stream<Item = Result<ReceiveMessage, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl OnionService for OnionTransport {
    type ConnectStream = ConnectStreamOut;

    async fn connect(
        &self,
        request: Request<Streaming<SendMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        // The pqnoise-authenticated peer identity (set by peer_auth_interceptor).
        // We bind the self-asserted `SendMessage.peer_id` to this so a peer can't
        // claim to be another (source spoof / reply-stream hijack). `None` on an
        // unauthenticated transport (tests) ⇒ don't enforce.
        let authed_peer = request
            .extensions()
            .get::<crate::peer_auth_middleware::AuthenticatedPeer>()
            .map(|ap| ap.peer_id.to_bytes());

        let mut inbound = request.into_inner();
        // Bounded outbound queue; `send()` uses try_send so a slow/stuck peer is
        // dropped rather than back-pressuring the whole transport.
        let (tx, rx) = mpsc::channel::<Result<ReceiveMessage, Status>>(1024);
        let transport = self.clone();

        tokio::spawn(async move {
            let mut registered: Option<Vec<u8>> = None;
            loop {
                match inbound.message().await {
                    Ok(Some(msg)) => {
                        // DEFENSE: the source must be the pqnoise-authenticated
                        // peer — a peer cannot register/send AS another peer.
                        if let Some(ref authed) = authed_peer {
                            if &msg.peer_id != authed {
                                continue;
                            }
                        }
                        // validateMessage: non-empty peer_id + cell + known
                        // routing peer (Go grpc_transport.go:231). DEFENSE: also
                        // reject a source claiming to be ourselves (no self-loop).
                        if msg.peer_id.is_empty()
                            || msg.cell.is_empty()
                            || msg.peer_id == transport.inner.self_peer_id.as_slice()
                            || !transport.validate_peer(&msg.peer_id)
                        {
                            continue;
                        }
                        // Register this peer's outbound stream on first valid cell.
                        if registered.as_deref() != Some(msg.peer_id.as_slice()) {
                            transport
                                .inner
                                .server_streams
                                .write()
                                .insert(msg.peer_id.clone(), tx.clone());
                            registered = Some(msg.peer_id.clone());
                        }
                        let cb = transport.inner.on_receive.read().clone();
                        if let Some(cb) = cb {
                            cb(&msg.peer_id, msg.circ_id, &msg.cell);
                        }
                    }
                    // EOF or transport error: tear down this peer's registration.
                    Ok(None) | Err(_) => {
                        if let Some(pid) = registered {
                            let mut streams = transport.inner.server_streams.write();
                            // Only remove if still ours (peer may have reconnected).
                            let still_ours = matches!(streams.get(&pid), Some(s) if s.same_channel(&tx));
                            if still_ours {
                                streams.remove(&pid);
                            }
                        }
                        break;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_p2p::onion::Transport as _;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn routing_lookup_allowing(addrs: Vec<String>) -> PeerRoutingLookup {
        Arc::new(move |peer_id: &[u8]| {
            if peer_id.is_empty() {
                None
            } else {
                Some(addrs.clone())
            }
        })
    }

    #[test]
    fn send_without_stream_is_no_active_stream() {
        let t = OnionTransport::new(b"self".to_vec(), routing_lookup_allowing(vec![]));
        let err = t.send(b"peerA", 7, vec![1, 2, 3]).unwrap_err();
        assert!(matches!(err, TransportError::NoActiveStream));
    }

    #[test]
    fn send_rejects_empty_and_unknown_peers() {
        // Lookup that only knows "good".
        let lookup: PeerRoutingLookup = Arc::new(|peer_id: &[u8]| {
            (peer_id == b"good").then(|| vec!["addr".to_string()])
        });
        let t = OnionTransport::new(b"self".to_vec(), lookup);
        assert!(matches!(
            t.send(b"", 1, vec![9]).unwrap_err(),
            TransportError::EmptyPeerId
        ));
        assert!(matches!(
            t.send(b"stranger", 1, vec![9]).unwrap_err(),
            TransportError::UnvalidatedPeer
        ));
    }

    #[tokio::test]
    async fn inbound_cell_fires_on_receive_and_enables_send_back() {
        let transport = OnionTransport::new(
            b"self".to_vec(),
            routing_lookup_allowing(vec!["addr".to_string()]),
        );

        let seen = Arc::new(AtomicU32::new(0));
        let seen_c = seen.clone();
        let last_circ = Arc::new(AtomicU32::new(0));
        let last_circ_c = last_circ.clone();
        transport.set_on_receive(Arc::new(move |peer_id, circ_id, cell| {
            assert_eq!(peer_id, b"peerA");
            assert_eq!(cell, b"hello");
            last_circ_c.store(circ_id, Ordering::SeqCst);
            seen_c.fetch_add(1, Ordering::SeqCst);
        }));

        // Emulate tonic's `Streaming` source with an mpsc, running the same
        // registration+callback loop the `connect` handler spawns.
        let (in_tx, mut in_rx) = mpsc::channel::<SendMessage>(4);
        in_tx
            .send(SendMessage {
                peer_id: b"peerA".to_vec(),
                circ_id: 42,
                cell: b"hello".to_vec(),
            })
            .await
            .unwrap();

        let t2 = transport.clone();
        let (out_tx, mut out_rx) = mpsc::channel::<Result<ReceiveMessage, Status>>(16);
        let pump = tokio::spawn(async move {
            let mut registered: Option<Vec<u8>> = None;
            while let Some(msg) = in_rx.recv().await {
                if msg.peer_id.is_empty() || msg.cell.is_empty() || !t2.validate_peer(&msg.peer_id) {
                    continue;
                }
                if registered.as_deref() != Some(msg.peer_id.as_slice()) {
                    t2.inner
                        .server_streams
                        .write()
                        .insert(msg.peer_id.clone(), out_tx.clone());
                    registered = Some(msg.peer_id.clone());
                }
                if let Some(cb) = t2.inner.on_receive.read().clone() {
                    cb(&msg.peer_id, msg.circ_id, &msg.cell);
                }
            }
        });

        for _ in 0..50 {
            if seen.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        assert_eq!(last_circ.load(Ordering::SeqCst), 42);
        assert_eq!(transport.active_peers(), vec![b"peerA".to_vec()]);

        // Now the transport can push a cell back to peerA over its stream. The
        // cell is stamped with OUR id as the source (so peerA can route replies
        // back to us), not the destination's.
        transport.send(b"peerA", 42, b"reply".to_vec()).unwrap();
        let back = out_rx.recv().await.unwrap().unwrap();
        assert_eq!(back.source_peer_id, b"self");
        assert_eq!(back.circ_id, 42);
        assert_eq!(back.cell, b"reply");

        drop(in_tx);
        let _ = pump.await;
    }

    #[test]
    fn self_peer_id_is_exposed() {
        let t = OnionTransport::new(b"me".to_vec(), routing_lookup_allowing(vec![]));
        assert_eq!(t.self_peer_id(), b"me");
    }
}
