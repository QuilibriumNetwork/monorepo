//! `ProxyPubSub` — the worker-side client for the `PubSubProxy`
//! service. Dials the master's peer gRPC listener (mTLS), and exposes
//! publish / subscribe / peer-info calls that the standalone worker
//! uses in place of a direct libp2p stack. Ports the Go
//! `node/rpc/proxy_blossomsub.go` client.
//!
//! Wire compatibility with the Go master's PubSubProxy is preserved —
//! a Go worker can talk to a Rust master or vice-versa as long as the
//! proto contract matches (same `quil_types::proto::proxy`).

use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tonic::transport::{Channel, ClientTlsConfig};

use quil_types::proto::proxy::{
    self as pb, pub_sub_proxy_client::PubSubProxyClient,
};

/// Received message forwarded from the master. Mirrors
/// `ReceivedMessage` from `quil_p2p` so worker handlers can treat
/// direct-P2P and proxied messages uniformly.
#[derive(Debug, Clone)]
pub struct ProxyReceivedMessage {
    pub bitmask: Vec<u8>,
    pub data: Vec<u8>,
    pub from: Vec<u8>,
}

/// Worker-side PubSub proxy. Holds a single gRPC channel to the
/// master; each `subscribe` call opens an independent streaming RPC.
#[derive(Clone)]
pub struct ProxyPubSub {
    inner: Arc<Mutex<PubSubProxyClient<Channel>>>,
    channel: Channel,
    peer_id: Vec<u8>,
    own_multiaddrs: Vec<String>,
    network: u32,
}

/// Errors from `ProxyPubSub::connect`.
#[derive(Debug, thiserror::Error)]
pub enum ProxyConnectError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),
}

impl ProxyPubSub {
    /// Connect to the master's PubSubProxy at `endpoint` (e.g.
    /// `https://127.0.0.1:8340`). mTLS client config is supplied
    /// separately so the caller can reuse its Ed448-derived cert.
    pub async fn connect(
        endpoint: String,
        tls: Option<ClientTlsConfig>,
    ) -> Result<Self, ProxyConnectError> {
        let mut ep = Channel::from_shared(endpoint.clone())
            .map_err(|e| ProxyConnectError::InvalidEndpoint(format!("{}: {}", endpoint, e)))?;
        if let Some(cfg) = tls {
            ep = ep.tls_config(cfg)?;
        }
        let channel = ep.connect().await?;
        let client = PubSubProxyClient::new(channel.clone());
        let inner = Arc::new(Mutex::new(client));
        // Cache cheap identity info up front so callers don't hit
        // round-trip latency on every peer_id()/own_multiaddrs() call.
        let (peer_id, own_multiaddrs, network) = {
            let mut c = inner.lock().await;
            let pid = c
                .get_peer_id(tonic::Request::new(()))
                .await
                .map(|r| r.into_inner().peer_id)
                .unwrap_or_default();
            let ma = c
                .get_own_multiaddrs(tonic::Request::new(()))
                .await
                .map(|r| r.into_inner().multiaddrs)
                .unwrap_or_default();
            let net = c
                .get_network(tonic::Request::new(()))
                .await
                .map(|r| r.into_inner().network)
                .unwrap_or(0);
            (pid, ma, net)
        };
        Ok(Self {
            inner,
            channel,
            peer_id,
            own_multiaddrs,
            network,
        })
    }

    /// Master peer ID (cached at connect).
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    pub fn own_multiaddrs(&self) -> &[String] {
        &self.own_multiaddrs
    }

    pub fn network(&self) -> u32 {
        self.network
    }

    /// Publish `data` on `bitmask` through the master.
    pub async fn publish(&self, bitmask: Vec<u8>, data: Vec<u8>) -> Result<(), tonic::Status> {
        let mut c = self.inner.lock().await;
        c.publish_to_bitmask(tonic::Request::new(pb::PublishToBitmaskRequest {
            bitmask,
            data,
        }))
        .await?;
        Ok(())
    }

    /// Open a server-streamed subscription to messages on `bitmask`.
    /// Messages arrive on the returned receiver; the background task
    /// exits when either the server ends the stream or `cancel` fires.
    pub async fn subscribe(
        &self,
        bitmask: Vec<u8>,
    ) -> Result<mpsc::Receiver<ProxyReceivedMessage>, tonic::Status> {
        let mut c = self.inner.lock().await;
        let stream = c
            .subscribe(tonic::Request::new(pb::SubscribeRequest {
                bitmask: bitmask.clone(),
                subscription_id: hex::encode(&bitmask),
            }))
            .await?
            .into_inner();
        drop(c);

        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            let mut stream = stream;
            while let Some(msg) = stream.next().await {
                match msg {
                    Ok(event) => {
                        let rec = ProxyReceivedMessage {
                            bitmask: event.bitmask,
                            data: event.data,
                            from: event.from,
                        };
                        if tx.send(rec).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(rx)
    }

    /// Unsubscribe — best-effort; server tears down the stream.
    pub async fn unsubscribe(&self, bitmask: Vec<u8>) -> Result<(), tonic::Status> {
        let mut c = self.inner.lock().await;
        c.unsubscribe(tonic::Request::new(pb::UnsubscribeRequest {
            bitmask,
            raw: false,
        }))
        .await?;
        Ok(())
    }

    /// Peer count via the master.
    pub async fn peer_count(&self) -> i32 {
        let mut c = self.inner.lock().await;
        c.get_network_peers_count(tonic::Request::new(()))
            .await
            .map(|r| r.into_inner().count)
            .unwrap_or(0)
    }

    /// Ask the master to sign `message` with its Ed448 key.
    pub async fn sign_message(&self, message: Vec<u8>) -> Result<Vec<u8>, tonic::Status> {
        let mut c = self.inner.lock().await;
        let sig = c
            .sign_message(tonic::Request::new(pb::SignMessageRequest { message }))
            .await?
            .into_inner()
            .signature;
        Ok(sig)
    }

    /// The master's Ed448 public key.
    pub async fn master_public_key(&self) -> Result<Vec<u8>, tonic::Status> {
        let mut c = self.inner.lock().await;
        Ok(c.get_public_key(tonic::Request::new(()))
            .await?
            .into_inner()
            .public_key)
    }

    /// Whether the master considers itself reachable.
    pub async fn reachability(&self) -> bool {
        let mut c = self.inner.lock().await;
        c.reachability(tonic::Request::new(()))
            .await
            .map(|r| r.into_inner())
            .unwrap_or(false)
    }

    /// Get the raw underlying `Channel` — useful when the worker needs
    /// to open additional gRPC services on the same mTLS connection
    /// (e.g. DataIPCService responses flowing the other way).
    pub fn channel(&self) -> &Channel {
        &self.channel
    }
}

