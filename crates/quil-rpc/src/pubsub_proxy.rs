//! PubSubProxy gRPC server — ports `node/rpc/pubsub_proxy.go`.
//!
//! When `engine.enable_master_proxy` is true on the master node, this
//! service is registered on the peer mTLS listener. Standalone worker
//! processes dial it (via `ProxyPubSub`) and forward all publish /
//! subscribe / peer-info operations over gRPC instead of running their
//! own libp2p stack.
//!
//! Message routing model:
//!   * Master's swarm event loop already fans every received message
//!     into a `tokio::sync::broadcast::Sender<StreamGlobalMessagesResponse>`
//!     (constructed in `main.rs`). We borrow a clone of that sender so
//!     each `Subscribe` caller gets an independent receiver filtered
//!     by bitmask.
//!   * `PublishToBitmask` / `Publish` route through `P2PHandle.publish`.
//!   * Peer-info, signing, and reachability queries delegate to small
//!     closures handed in by `main.rs` so this crate doesn't have to
//!     depend on the Ed448 keyring directly.

use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use quil_types::proto::proxy::{
    self as pb, pub_sub_proxy_server::PubSubProxy,
};

/// Closure that signs a message with the master's Ed448 key.
pub type Ed448Signer = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

/// Closure returning the master's Ed448 public key bytes (57 bytes).
pub type Ed448PubkeyGetter = Arc<dyn Fn() -> Vec<u8> + Send + Sync>;

/// Closure returning the master's own listen multiaddrs.
pub type OwnMultiaddrsGetter = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Closure returning current peer IDs (byte form, as libp2p encodes).
/// Used by `GetRandomPeer` and `GetNetworkInfo`.
pub type PeerListGetter = Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>;

/// Async result type for proxy peer-management operations. Closures
/// returning these must own a clone of the underlying P2P handle so
/// they can `await` an oneshot ack from the swarm command loop.
pub type AsyncResult<T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, String>> + Send>>;

/// Handle to the master's P2P stack. Only the operations the proxy
/// truly needs are referenced here so that this crate doesn't leak
/// libp2p internals.
#[derive(Clone)]
pub struct P2pHandleShim {
    pub peer_id_bytes: Vec<u8>,
    pub publish: Arc<dyn Fn(Vec<u8>, Vec<u8>) + Send + Sync>,
    pub subscribe: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    pub unsubscribe: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    pub peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
    /// Read a peer's score (`peer_id_bytes` is libp2p PeerId in raw
    /// byte form). Returns `0.0` if the peer is unknown / channel down.
    pub get_peer_score: Arc<dyn Fn(Vec<u8>) -> AsyncResult<f64> + Send + Sync>,
    /// Replace a peer's application score.
    pub set_peer_score: Arc<dyn Fn(Vec<u8>, f64) + Send + Sync>,
    /// Add `delta` to a peer's application score.
    pub add_peer_score: Arc<dyn Fn(Vec<u8>, f64) + Send + Sync>,
    /// Disconnect + redial a peer.
    pub reconnect: Arc<dyn Fn(Vec<u8>) -> AsyncResult<()> + Send + Sync>,
    /// Re-trigger Kademlia bootstrap.
    pub bootstrap: Arc<dyn Fn() -> AsyncResult<()> + Send + Sync>,
    /// Re-trigger Kademlia peer discovery.
    pub discover_peers: Arc<dyn Fn() -> AsyncResult<()> + Send + Sync>,
    /// Is this peer currently connected? Sync because libp2p exposes
    /// connected status via swarm state we can mirror in a counter.
    pub is_peer_connected: Arc<dyn Fn(Vec<u8>) -> bool + Send + Sync>,
}

/// PubSubProxy service implementation.
pub struct PubSubProxyServer {
    /// Master's P2P stack façade. Publish/subscribe/unsubscribe route
    /// through here into libp2p.
    p2p: P2pHandleShim,
    /// Broadcast of every inbound message the master receives —
    /// constructed once in `main.rs` and cloned here. Per-subscriber
    /// bitmask filtering happens in `subscribe`.
    inbound: broadcast::Sender<quil_types::proto::global::StreamGlobalMessagesResponse>,
    /// Own multiaddrs (observed + configured).
    own_multiaddrs: OwnMultiaddrsGetter,
    /// Current peer IDs.
    peers: PeerListGetter,
    /// Ed448 signer for `SignMessage`.
    signer: Option<Ed448Signer>,
    /// Ed448 public key for `GetPublicKey`.
    pubkey: Option<Ed448PubkeyGetter>,
    /// Network ID (0=mainnet, 1=testnet, 99=devnet).
    network: u32,
    /// Static reachability flag. Defaults to `true`; plumb in a real
    /// autonat observer later when one exists.
    reachable: bool,
}

impl PubSubProxyServer {
    pub fn new(
        p2p: P2pHandleShim,
        inbound: broadcast::Sender<quil_types::proto::global::StreamGlobalMessagesResponse>,
        own_multiaddrs: OwnMultiaddrsGetter,
        peers: PeerListGetter,
        network: u32,
    ) -> Self {
        Self {
            p2p,
            inbound,
            own_multiaddrs,
            peers,
            signer: None,
            pubkey: None,
            network,
            reachable: true,
        }
    }

    pub fn with_signer(mut self, signer: Ed448Signer) -> Self {
        self.signer = Some(signer);
        self
    }

    pub fn with_pubkey(mut self, pubkey: Ed448PubkeyGetter) -> Self {
        self.pubkey = Some(pubkey);
        self
    }

    pub fn with_reachability(mut self, reachable: bool) -> Self {
        self.reachable = reachable;
        self
    }
}

type SubscribeStream = Pin<
    Box<dyn Stream<Item = Result<pb::MessageEvent, Status>> + Send + 'static>,
>;

type MultiaddrStream = Pin<
    Box<dyn Stream<Item = Result<pb::GetMultiaddrOfPeerResponse, Status>> + Send + 'static>,
>;

type ValidatorStreamOut = Pin<
    Box<dyn Stream<Item = Result<pb::ValidationStreamMessage, Status>> + Send + 'static>,
>;

#[tonic::async_trait]
impl PubSubProxy for PubSubProxyServer {
    // ----------------- Publishing -----------------

    async fn publish_to_bitmask(
        &self,
        request: Request<pb::PublishToBitmaskRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        (self.p2p.publish)(req.bitmask, req.data);
        Ok(Response::new(()))
    }

    async fn publish(
        &self,
        _request: Request<pb::PublishRequest>,
    ) -> Result<Response<()>, Status> {
        // `Publish` (by address) is the direct-send path in Go. The
        // Rust P2P stack does not yet expose address-targeted sends;
        // accept and drop until that primitive lands.
        Ok(Response::new(()))
    }

    // ----------------- Subscribe / Unsubscribe -----------------

    type SubscribeStream = SubscribeStream;

    async fn subscribe(
        &self,
        request: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let req = request.into_inner();
        let bitmask = req.bitmask;
        // Ensure the master is actually subscribed to this bitmask
        // upstream so messages reach the inbound broadcast.
        (self.p2p.subscribe)(bitmask.clone());

        let mut rx = self.inbound.subscribe();
        let peer_from = self.p2p.peer_id_bytes.clone();
        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(msg) => {
                        if !bitmask.is_empty() && msg.bitmask != bitmask {
                            continue;
                        }
                        yield Ok(pb::MessageEvent {
                            data: msg.data,
                            from: peer_from.clone(),
                            seqno: Vec::new(),
                            bitmask: msg.bitmask,
                            signature: Vec::new(),
                            key: Vec::new(),
                        });
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn unsubscribe(
        &self,
        request: Request<pb::UnsubscribeRequest>,
    ) -> Result<Response<()>, Status> {
        let bitmask = request.into_inner().bitmask;
        (self.p2p.unsubscribe)(bitmask);
        Ok(Response::new(()))
    }

    // ----------------- Validator stream -----------------

    type ValidatorStreamStream = ValidatorStreamOut;

    async fn validator_stream(
        &self,
        _request: Request<tonic::Streaming<pb::ValidationStreamMessage>>,
    ) -> Result<Response<Self::ValidatorStreamStream>, Status> {
        // Minimal accept-all validator: return a stream that hangs
        // until the client disconnects. Workers that register
        // validators will have their registrations silently accepted
        // but no validation-request traffic is sent their way (master
        // validates locally). Real inbound validation farming-out can
        // be added later without changing the wire contract.
        let empty = async_stream::stream! {
            // Park indefinitely — the channel will only break when
            // the client hangs up, at which point tonic drops this
            // future.
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                // Yield nothing; just keep the stream open.
                if false {
                    yield Err::<pb::ValidationStreamMessage, _>(Status::cancelled("unused"));
                }
            }
        };
        Ok(Response::new(Box::pin(empty)))
    }

    // ----------------- Peer info -----------------

    async fn get_peer_id(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::GetPeerIdResponse>, Status> {
        Ok(Response::new(pb::GetPeerIdResponse {
            peer_id: self.p2p.peer_id_bytes.clone(),
        }))
    }

    async fn get_peerstore_count(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::GetPeerstoreCountResponse>, Status> {
        Ok(Response::new(pb::GetPeerstoreCountResponse {
            count: (self.peers)().len() as i32,
        }))
    }

    async fn get_network_peers_count(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::GetNetworkPeersCountResponse>, Status> {
        Ok(Response::new(pb::GetNetworkPeersCountResponse {
            count: (self.p2p.peer_count)() as i32,
        }))
    }

    async fn get_random_peer(
        &self,
        _request: Request<pb::GetRandomPeerRequest>,
    ) -> Result<Response<pb::GetRandomPeerResponse>, Status> {
        // Cheap random: pick the first peer. Real uniform random is
        // only useful for DHT walks, which workers don't do.
        let peers = (self.peers)();
        let peer_id = peers.into_iter().next().unwrap_or_default();
        Ok(Response::new(pb::GetRandomPeerResponse { peer_id }))
    }

    async fn get_multiaddr_of_peer(
        &self,
        _request: Request<pb::GetMultiaddrOfPeerRequest>,
    ) -> Result<Response<pb::GetMultiaddrOfPeerResponse>, Status> {
        // Rust P2P handle doesn't expose per-peer address lookups yet;
        // return empty rather than fake one.
        Ok(Response::new(pb::GetMultiaddrOfPeerResponse {
            multiaddr: String::new(),
        }))
    }

    type GetMultiaddrOfPeerStreamStream = MultiaddrStream;

    async fn get_multiaddr_of_peer_stream(
        &self,
        _request: Request<pb::GetMultiaddrOfPeerRequest>,
    ) -> Result<Response<Self::GetMultiaddrOfPeerStreamStream>, Status> {
        let empty = async_stream::stream! {
            yield Ok::<_, Status>(pb::GetMultiaddrOfPeerResponse { multiaddr: String::new() });
        };
        Ok(Response::new(Box::pin(empty)))
    }

    async fn get_own_multiaddrs(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::GetOwnMultiaddrsResponse>, Status> {
        Ok(Response::new(pb::GetOwnMultiaddrsResponse {
            multiaddrs: (self.own_multiaddrs)(),
        }))
    }

    async fn get_network_info(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::NetworkInfoResponse>, Status> {
        let peers = (self.peers)();
        let network_info = peers
            .into_iter()
            .map(|peer_id| pb::NetworkInfo {
                peer_id,
                multiaddrs: Vec::new(),
                peer_score: 0.0,
            })
            .collect();
        Ok(Response::new(pb::NetworkInfoResponse { network_info }))
    }

    // ----------------- Peer scoring -----------------

    async fn get_peer_score(
        &self,
        request: Request<pb::GetPeerScoreRequest>,
    ) -> Result<Response<pb::GetPeerScoreResponse>, Status> {
        let req = request.into_inner();
        let score = (self.p2p.get_peer_score)(req.peer_id)
            .await
            .map_err(|e| Status::internal(format!("get_peer_score: {}", e)))?;
        // Proto stores score as int64 (Go libp2p's score is float, but
        // serializes to int after rounding for transport).
        Ok(Response::new(pb::GetPeerScoreResponse {
            score: score.round() as i64,
        }))
    }

    async fn set_peer_score(
        &self,
        request: Request<pb::SetPeerScoreRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        (self.p2p.set_peer_score)(req.peer_id, req.score as f64);
        Ok(Response::new(()))
    }

    async fn add_peer_score(
        &self,
        request: Request<pb::AddPeerScoreRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        (self.p2p.add_peer_score)(req.peer_id, req.score_delta as f64);
        Ok(Response::new(()))
    }

    // ----------------- Connection management -----------------

    async fn reconnect(
        &self,
        request: Request<pb::ReconnectRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        (self.p2p.reconnect)(req.peer_id)
            .await
            .map_err(|e| Status::internal(format!("reconnect: {}", e)))?;
        Ok(Response::new(()))
    }

    async fn bootstrap(
        &self,
        _request: Request<()>,
    ) -> Result<Response<()>, Status> {
        (self.p2p.bootstrap)()
            .await
            .map_err(|e| Status::internal(format!("bootstrap: {}", e)))?;
        Ok(Response::new(()))
    }

    async fn discover_peers(
        &self,
        _request: Request<()>,
    ) -> Result<Response<()>, Status> {
        (self.p2p.discover_peers)()
            .await
            .map_err(|e| Status::internal(format!("discover_peers: {}", e)))?;
        Ok(Response::new(()))
    }

    async fn is_peer_connected(
        &self,
        request: Request<pb::IsPeerConnectedRequest>,
    ) -> Result<Response<pb::IsPeerConnectedResponse>, Status> {
        let req = request.into_inner();
        let connected = (self.p2p.is_peer_connected)(req.peer_id);
        Ok(Response::new(pb::IsPeerConnectedResponse { connected }))
    }

    // ----------------- Utility -----------------

    async fn get_network(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::GetNetworkResponse>, Status> {
        Ok(Response::new(pb::GetNetworkResponse { network: self.network }))
    }

    async fn reachability(
        &self,
        _request: Request<()>,
    ) -> Result<Response<bool>, Status> {
        Ok(Response::new(self.reachable))
    }

    async fn sign_message(
        &self,
        request: Request<pb::SignMessageRequest>,
    ) -> Result<Response<pb::SignMessageResponse>, Status> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| Status::unavailable("no signer wired"))?;
        let msg = request.into_inner().message;
        let sig = signer(&msg).map_err(Status::internal)?;
        Ok(Response::new(pb::SignMessageResponse { signature: sig }))
    }

    async fn get_public_key(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::GetPublicKeyResponse>, Status> {
        let pk = self
            .pubkey
            .as_ref()
            .map(|f| f())
            .unwrap_or_default();
        Ok(Response::new(pb::GetPublicKeyResponse { public_key: pk }))
    }
}
