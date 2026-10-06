//! gRPC client for connecting to a Quilibrium archive node's `GlobalService`.
//!
//! Archive nodes expose `GlobalService` over a TCP gRPC endpoint authenticated
//! with mTLS. The certificate scheme is unusual: each peer presents an
//! Ed25519 self-signed cert (since Go's x509 doesn't support Ed448) whose DNS
//! name field encodes a cross-signature linking it back to the peer's Ed448
//! identity. See `node/p2p/peer_authenticator.go` in the Go tree and the
//! `quil_tls` module here for the cert scheme.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};
use tower::Service;
use tracing::{debug, info};

use quil_types::proto::global::app_shard_service_client::AppShardServiceClient;
use quil_types::proto::global::global_service_client::GlobalServiceClient;
use quil_types::proto::global::{
    AppShardFrame, AppShardInfo, GetAppShardFrameRequest, GetAppShardsRequest,
    GetForestHeadRequest, GetForestNodeRequest,
    GetForestPreimageRequest, GetForestValueRequest, GetGlobalFrameRequest,
    GetAppManifestRequest, GetGlobalProposalRequest, GetVertexBlobRequest, ResolveRootRequest,
    GlobalFrame, GlobalProposal, SubmitGlobalConsensusRequest, SubmitGlobalMessageRequest,
};

use crate::quil_tls::{build_quil_tls_cert, QuilTlsError};

#[derive(Debug, Error)]
pub enum ArchiveClientError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc error: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("missing field in response: {0}")]
    MissingField(&'static str),
    #[error("tls cert error: {0}")]
    Tls(#[from] QuilTlsError),
    #[error("tls init error: {0}")]
    TlsInit(String),
}

/// The endpoint answered with this node's own identity: the mainnet archive
/// address list names every archive, this one included.
#[derive(Debug, Error)]
#[error("archive endpoint is this node")]
pub struct OwnEndpoint;

impl ArchiveClientError {
    /// The connection reached this node itself.
    pub fn is_own_endpoint(&self) -> bool {
        causes(self).any(|cause| cause.downcast_ref::<OwnEndpoint>().is_some())
    }

    /// The request failed in the transport (the connection was closed, reset
    /// or went away), not with a status the archive sent. An archive closes
    /// connections a client leaves idle; such a request can go again at once
    /// on a fresh connection.
    /// The archive answered that its forest reads are busy.
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Rpc(status) if status.code() == tonic::Code::ResourceExhausted)
    }

    /// The archive lacks the call (an older build).
    pub fn is_unimplemented(&self) -> bool {
        matches!(self, Self::Rpc(status) if status.code() == tonic::Code::Unimplemented)
    }

    pub fn is_transport_failure(&self) -> bool {
        causes(self).any(|cause| {
            cause.downcast_ref::<hyper::Error>().is_some()
                || cause.downcast_ref::<h2::Error>().is_some()
                || cause.downcast_ref::<std::io::Error>().is_some()
        })
    }
}

/// `error` and every cause beneath it.
fn causes<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(error), |error| error.source())
}

/// The causes beneath `error`, outermost first, separated by " -> ". A
/// transport failure reaches callers as "h2 protocol error: http2 error"; the
/// reason (a keepalive timeout, a reset or GOAWAY, an oversized frame) is only
/// in the source chain. Repeats of the text above are skipped.
pub fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut causes: Vec<String> = Vec::new();
    let mut above = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if text != above && !above.contains(&text) {
            causes.push(text.clone());
        }
        above = text;
        source = cause.source();
    }
    causes.join(" -> ")
}

/// A connected gRPC client for an archive node's `GlobalService`.
///
/// `Clone` is cheap: the inner tonic client shares one multiplexed h2
/// `Channel`, so cached connections can be cloned per request (e.g. the
/// direct global-consensus publisher fanning to several archives).
#[derive(Clone)]
pub struct ArchiveClient {
    inner: GlobalServiceClient<Channel>,
    // AppShardService rides the SAME :8340 channel as GlobalService (both are
    // registered on the peer server); used by the state-jump to fetch attested
    // app-shard frames for onboarding root cross-checks.
    app_shard: AppShardServiceClient<Channel>,
    endpoint: String,
}

impl ArchiveClient {
    /// Connect to an archive node at the given `host:port` over plaintext gRPC.
    /// Useful for local testing only — production archive nodes require mTLS.
    pub async fn connect_plaintext(addr: &str) -> Result<Self, ArchiveClientError> {
        let url = format!("http://{}", addr);
        let endpoint = Endpoint::from_shared(url)
            .map_err(|e| ArchiveClientError::InvalidEndpoint(e.to_string()))?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .keep_alive_while_idle(true);
        debug!(%addr, "dialing archive node (plaintext)");
        let channel = endpoint.connect().await?;
        info!(%addr, "archive client connected");
        Ok(Self {
            // 64 MiB decode/encode limit (tonic defaults to 4 MiB). Full
            // global frames and app-shard size sets routinely exceed 4 MiB;
            // the default silently failed those RPCs. Matches the hypersync
            // client limits in `hypergraph_sync_probe`.
            inner: GlobalServiceClient::new(channel.clone())
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
            app_shard: AppShardServiceClient::new(channel)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
            endpoint: addr.to_string(),
        })
    }

    /// Connect to an archive node using Quilibrium's mTLS scheme. Builds a
    /// client cert from the given Ed448 seed and uses a custom rustls
    /// connector that accepts any server cert (Quilibrium peers self-sign;
    /// trust comes from the application-layer cross-signature in the SAN).
    pub async fn connect_mtls(
        addr: &str,
        falcon_signing_key: &[u8],
    ) -> Result<Self, ArchiveClientError> {
        Self::connect_pq(addr, QuilPqNoiseConnector::new(falcon_signing_key.to_vec())).await
    }

    /// [`Self::connect_mtls`] to another archive: an endpoint answering with
    /// this node's identity fails with [`ArchiveClientError::is_own_endpoint`].
    pub async fn connect_archive(
        addr: &str,
        falcon_signing_key: &[u8],
    ) -> Result<Self, ArchiveClientError> {
        let own = quil_p2p::Keypair::falcon_from_bytes(falcon_signing_key)
            .map_err(|error| ArchiveClientError::TlsInit(format!("own identity: {error}")))?
            .public()
            .to_peer_id();
        let connector = QuilPqNoiseConnector::new(falcon_signing_key.to_vec()).refusing_peer(own);
        Self::connect_pq(addr, connector).await
    }

    /// Connect only to this worker's own master, which holds the same Falcon
    /// identity. Historical canonical frames and the archive directory rely
    /// on this pin; possession of an unrelated peer key is insufficient.
    pub async fn connect_own_master(addr: &str, falcon_signing_key: &[u8]) -> Result<Self, ArchiveClientError> {
        let peer = quil_p2p::Keypair::falcon_from_bytes(falcon_signing_key)
            .map_err(|error| ArchiveClientError::TlsInit(format!("master identity: {error}")))?
            .public().to_peer_id();
        let connector = QuilPqNoiseConnector::new(falcon_signing_key.to_vec()).with_expected_peer(peer);
        Self::connect_pq(addr, connector).await
    }

    async fn connect_pq(addr: &str, connector: QuilPqNoiseConnector) -> Result<Self, ArchiveClientError> {
        // Note: scheme is `http://` — tonic's Endpoint refuses `https://`
        // unless its own `tls_config(...)` is set; we bypass that to install
        // our own PQNoise connector (no rustls/TLS on :8340 anymore).
        let url = format!("http://{}", addr);
        let endpoint = Endpoint::from_shared(url)
            .map_err(|e| ArchiveClientError::InvalidEndpoint(e.to_string()))?
            // 10s connect (was 3s). Over WAN with 200-300ms RTT
            // the TLS handshake plus Ed448 cross-signature
            // verification can routinely take 1.5-2.5s; a 3s
            // budget left no margin for a single congestion event
            // during the handshake. Matches the plaintext path's
            // 10s timeout.
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .tcp_nodelay(true)
            // Actively PING the peer every 10s. `keep_alive_while_idle(true)`
            // alone is a NO-OP in tonic unless an interval is set — without
            // this, an idle cached connection sends nothing, the peer's h2
            // keepalive (20s interval / 10s timeout on the :8340 server)
            // reaps it, and the next use forces a full reconnect + the
            // expensive Ed448 mTLS handshake. Pinging under the peer's reap
            // window keeps consensus/sync connections alive so they're
            // reused instead of re-handshaken.
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_while_idle(true);

        debug!(%addr, "dialing archive node (PQNoise)");
        let channel = match endpoint.connect_with_connector(connector).await {
            Ok(ch) => ch,
            Err(e) => {
                // Walk the std::error::Error source chain so the actual
                // failure (rustls / DNS / TCP refused / handshake)
                // appears in logs. Tonic's Display impl strips this.
                use std::error::Error as _;
                let mut chain = format!("{}", e);
                let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
                while let Some(s) = src {
                    chain.push_str(" -> ");
                    chain.push_str(&format!("{}", s));
                    src = s.source();
                }
                tracing::warn!(%addr, error_chain = %chain, "connect_mtls failed (full chain)");
                return Err(e.into());
            }
        };
        debug!(%addr, "archive client connected (mTLS)");
        Ok(Self {
            // 64 MiB decode/encode limit (tonic defaults to 4 MiB). Full
            // global frames and app-shard size sets routinely exceed 4 MiB;
            // the default silently failed those RPCs. Matches the hypersync
            // client limits in `hypergraph_sync_probe`.
            inner: GlobalServiceClient::new(channel.clone())
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
            app_shard: AppShardServiceClient::new(channel)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
            endpoint: addr.to_string(),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Submit a prover message (e.g. ProverJoin wrapped in MessageBundle)
    /// to the archive node for relay into the consensus pipeline.
    /// This is how Go nodes submit joins — via gRPC, not BlossomSub.
    pub async fn submit_global_message(
        &mut self,
        data: Vec<u8>,
    ) -> Result<(), ArchiveClientError> {
        self.inner
            .submit_global_message(SubmitGlobalMessageRequest { data })
            .await?;
        Ok(())
    }

    /// Deliver a global-consensus message (proposal / vote / timeout)
    /// point-to-point to a peer archive. `bitmask` is the original gossip
    /// topic (GLOBAL_FRAME or GLOBAL_CONSENSUS) so the receiver routes it
    /// through the matching handler. Global consensus uses this instead of
    /// gossip because a full-coverage proposal exceeds the gossip
    /// message-size ceiling.
    pub async fn submit_global_consensus(
        &mut self,
        bitmask: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<(), ArchiveClientError> {
        self.inner
            .submit_global_consensus(SubmitGlobalConsensusRequest { bitmask, data })
            .await?;
        Ok(())
    }

    pub async fn get_app_shards(
        &mut self,
        shard_key: Vec<u8>,
        prefix: Vec<u32>,
    ) -> Result<Vec<AppShardInfo>, ArchiveClientError> {
        let resp = self
            .inner
            .get_app_shards(GetAppShardsRequest { shard_key, prefix })
            .await?
            .into_inner();
        Ok(resp.info)
    }

    /// Forest sync: fetch one JMT node (`borsh(NodeKey)` → `borsh(Node)`) of a
    /// shard/phase tree. `None` if the peer has no such node. Drives the
    /// client-side Merkle diff (see [`crate::forest_sync_reader::RemoteTreeReader`]).
    pub async fn get_forest_node(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        node_key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_node(GetForestNodeRequest { shard_id, phase, node_key })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.node))
    }

    /// Forest sync, batched: many JMT nodes of one shard/phase tree in one
    /// request. The answer covers a prefix of `node_keys`, in order (the
    /// archive stops at its size budget); `None` per absent node.
    pub async fn get_forest_nodes(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        node_keys: Vec<Vec<u8>>,
    ) -> Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_nodes(quil_types::proto::global::GetForestNodesRequest { shard_id, phase, node_keys })
            .await?
            .into_inner();
        Ok(resp.nodes.into_iter().map(|n| n.found.then_some(n.data)).collect())
    }

    /// Forest sync, batched: leaf values `(version, key_hash)` of one
    /// shard/phase tree. A prefix of the keys, in order, as for nodes.
    pub async fn get_forest_values(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        keys: Vec<(u64, Vec<u8>)>,
    ) -> Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let keys = keys
            .into_iter()
            .map(|(version, key_hash)| quil_types::proto::global::ForestValueKey { version, key_hash })
            .collect();
        let resp = self
            .inner
            .get_forest_values(quil_types::proto::global::GetForestValuesRequest { shard_id, phase, keys })
            .await?
            .into_inner();
        Ok(resp.values.into_iter().map(|v| v.found.then_some(v.data)).collect())
    }

    /// Forest sync, batched: vertex blobs `(id, version)` under one app
    /// ShardKey, each read as of its tree version. A prefix, in order.
    pub async fn get_vertex_blobs(
        &mut self,
        shard_key: Vec<u8>,
        phase: u32,
        blobs: Vec<(Vec<u8>, u64)>,
    ) -> Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let blobs = blobs
            .into_iter()
            .map(|(id, version)| quil_types::proto::global::VertexBlobKey { id, version })
            .collect();
        let resp = self
            .inner
            .get_vertex_blobs(quil_types::proto::global::GetVertexBlobsRequest { shard_key, phase, blobs })
            .await?
            .into_inner();
        Ok(resp.blobs.into_iter().map(|b| b.found.then_some(b.data)).collect())
    }

    /// Forest sync, listed: leaves of one shard/phase tree with keys in
    /// `[first, last]` after `after`, each at its newest value at or below
    /// `version`, in key order, and whether more may follow.
    pub async fn get_forest_leaves(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        version: u64,
        first: [u8; 32],
        last: [u8; 32],
        after: Option<[u8; 32]>,
    ) -> Result<(Vec<([u8; 32], Vec<u8>)>, bool), ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_leaves(quil_types::proto::global::GetForestLeavesRequest {
                shard_id,
                phase,
                version,
                first: first.to_vec(),
                last: last.to_vec(),
                after: after.map(|key| key.to_vec()).unwrap_or_default(),
            })
            .await?
            .into_inner();
        let leaves = resp
            .leaves
            .into_iter()
            .map(|leaf| {
                <[u8; 32]>::try_from(leaf.key_hash.as_slice())
                    .map(|key| (key, leaf.value))
                    .map_err(|_| ArchiveClientError::MissingField("forest leaf key must be 32 bytes"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((leaves, resp.more))
    }

    /// Forest sync: fetch a leaf value by `key_hash` (32 bytes) at `version`.
    pub async fn get_forest_value(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        version: u64,
        key_hash: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_value(GetForestValueRequest { shard_id, phase, version, key_hash })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.value))
    }

    /// Forest sync: the peer's head `(version, root)` for a shard/phase tree, so
    /// the client can verify the root and diff at that version. `None` if the
    /// peer never committed the tree.
    pub async fn get_forest_head(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
    ) -> Result<Option<(u64, Vec<u8>)>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_head(GetForestHeadRequest { shard_id, phase })
            .await?
            .into_inner();
        Ok(resp.found.then_some((resp.version, resp.root)))
    }

    /// Forest sync: the raw l3 key (`vertex_id ‖ field_key`) a diff's `key_hash`
    /// was committed from, so the client learns which vertices changed.
    pub async fn get_forest_preimage(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        key_hash: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_preimage(GetForestPreimageRequest { shard_id, phase, key_hash })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.raw_key))
    }

    /// Forest sync: a changed vertex's committed blob (the readable data).
    /// `shard_key` is the app ShardKey bytes (`l1[3] ‖ l2[32]`).
    pub async fn get_vertex_blob(
        &mut self,
        shard_key: Vec<u8>,
        phase: u32,
        id: Vec<u8>,
        version: u64,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        // `version` MVCC-pins the read to the tree version the diff addressed, so
        // the served blob matches the committed `commitment‖size` the sync just
        // applied. `0` ⇒ latest (immutable content-addressed vertices are safe at
        // latest; MUTABLE vertices — e.g. the 0xff prover shard's reward balances
        // and registry — MUST pin, else the archive serves a newer blob whose
        // leaf value no longer matches the diff → "peer served unbound data").
        let resp = self
            .inner
            .get_vertex_blob(GetVertexBlobRequest { shard_key, phase, id, version, exact_version: false })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.blob))
    }

    /// Ask this worker's authenticated master for its verified archive pool.
    pub async fn get_archive_endpoints(&mut self) -> Result<Vec<String>, ArchiveClientError> {
        let response = self.inner.clone().max_decoding_message_size(32 * 515 + 128)
            .get_archive_endpoints(quil_types::proto::global::GetArchiveEndpointsRequest {})
            .await?.into_inner();
        if response.endpoints.len() > 32 || response.endpoints.iter().any(|e| e.is_empty() || e.len() > 512) {
            return Err(tonic::Status::data_loss("invalid archive directory dimensions").into());
        }
        Ok(response.endpoints)
    }

    /// Fetch and authenticate one bounded historical GLOBAL membership proof.
    pub async fn get_global_vertex_proof(
        &mut self, root: [u8; 32], address: [u8; 32], allow_forward: bool,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let response = self.inner.clone().max_decoding_message_size(
            quil_engine::storage_history::MAX_GLOBAL_VERTEX_PROOF_BYTES + 128,
        ).get_global_vertex_proof(quil_types::proto::global::GetGlobalVertexProofRequest {
            root: root.to_vec(), address: address.to_vec(), allow_forward,
        }).await?.into_inner();
        if !response.found { return Ok(None); }
        quil_engine::storage_history::verify_global_vertex_proof(&root, &address, &response.proof)
            .map_err(|e| tonic::Status::data_loss(e.to_string()))?;
        Ok(Some(response.proof))
    }

    /// Read the blob at an exact tree version, including the first version (0).
    pub async fn get_vertex_blob_at(
        &mut self,
        shard_key: Vec<u8>,
        phase: u32,
        id: Vec<u8>,
        version: u64,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let resp = self.inner.get_vertex_blob(GetVertexBlobRequest {
            shard_key, phase, id, version, exact_version: true,
        }).await?.into_inner();
        Ok(resp.found.then_some(resp.blob))
    }

    /// Peer coin scan over the same authenticated :8340 channel: ask a node
    /// that covers `domain` for one page. `Unavailable` means that peer does
    /// not serve the application — try the next one, not an empty answer.
    pub async fn list_shard_coins(
        &mut self,
        domain: Vec<u8>,
        snapshot_id: Vec<u8>,
        after: Vec<u8>,
    ) -> Result<quil_types::proto::global::ListShardCoinsResponse, ArchiveClientError> {
        Ok(self
            .app_shard
            .list_shard_coins(quil_types::proto::global::ListShardCoinsRequest { domain, snapshot_id, after })
            .await?
            .into_inner())
    }

    pub async fn list_shard_legacy_coins(
        &mut self,
        domain: Vec<u8>,
        owner: Vec<u8>,
        after: Vec<u8>,
    ) -> Result<quil_types::proto::global::ListLegacyCoinsResponse, ArchiveClientError> {
        Ok(self
            .app_shard
            .list_shard_legacy_coins(quil_types::proto::global::ListLegacyCoinsRequest { domain, owner, after })
            .await?
            .into_inner())
    }

    pub async fn list_shard_escrows(
        &mut self,
        domain: Vec<u8>,
        snapshot_id: Vec<u8>,
        after: Vec<u8>,
    ) -> Result<quil_types::proto::global::ListShardEscrowsResponse, ArchiveClientError> {
        Ok(self.app_shard.list_shard_escrows(quil_types::proto::global::ListShardCoinsRequest {
            domain, snapshot_id, after,
        }).await?.into_inner())
    }

    /// A wallet vertex read with application coverage and worker-store routing.
    /// Do not substitute a forest-sync read of the peer's master store.
    pub async fn get_shard_vertex(
        &mut self,
        address: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let vertex = self.app_shard.get_shard_vertex(
            quil_types::proto::global::GetShardVertexRequest { address },
        ).await?.into_inner();
        Ok(vertex.found.then_some(vertex.blob))
    }

    /// Peer coin witnesses over the same authenticated channel: the membership
    /// paths a wallet needs to spend coins on an application this node does
    /// not cover.
    pub async fn get_shard_coin_witnesses(
        &mut self,
        domain: Vec<u8>,
        addresses: Vec<Vec<u8>>,
    ) -> Result<quil_types::proto::global::GetShardCoinWitnessesResponse, ArchiveClientError> {
        Ok(self
            .app_shard
            .get_shard_coin_witnesses(quil_types::proto::global::GetShardCoinWitnessesRequest { domain, addresses })
            .await?
            .into_inner())
    }

    /// Sync-by-hash: translate an authenticated tree `root` to the serving
    /// peer's local `(version, global_frame)`. `None` ⇒ that peer never
    /// committed this root (behind) or pruned it; the caller then fails over
    /// to another peer or a full snapshot sync.
    pub async fn resolve_root(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        root: Vec<u8>,
    ) -> Result<Option<(u64, u64)>, ArchiveClientError> {
        let resp = self
            .inner
            .resolve_root(ResolveRootRequest { shard_id, phase, root })
            .await?
            .into_inner();
        Ok(resp.found.then_some((resp.version, resp.global_frame)))
    }

    /// Sync-by-hash (split apps): the manifest of sub-shards that fold into an
    /// aggregate `app_root`: `[(prefix_words, sub_root, sub_version)]`. The
    /// caller MUST verify these aggregate back to the authenticated `app_root`
    /// before trusting any sub-root. `None` ⇒ not a known aggregate root here.
    #[allow(clippy::type_complexity)]
    pub async fn get_app_manifest(
        &mut self,
        app_address: Vec<u8>,
        phase: u32,
        app_root: Vec<u8>,
    ) -> Result<Option<Vec<(Vec<u8>, Vec<u8>, u64)>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_app_manifest(GetAppManifestRequest { app_address, phase, app_root })
            .await?
            .into_inner();
        if !resp.found {
            return Ok(None);
        }
        Ok(Some(
            resp.entries
                .into_iter()
                .map(|e| (e.prefix, e.root, e.version))
                .collect(),
        ))
    }

    /// Fetch a single global frame. Pass `frame_number = 0` to request the
    /// latest finalized frame.
    pub async fn get_global_frame(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalFrame, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_frame(GetGlobalFrameRequest { frame_number })
            .await?
            .into_inner();
        resp.frame.ok_or(ArchiveClientError::MissingField("frame"))
    }

    /// Fetch the full proposal (state + parent QC + prior TC + vote) for
    /// `frame_number`, so a lagging node can submit it into its consensus loop
    /// to catch up. The server returns an empty response (no proposal) on a
    /// lookup miss, which surfaces here as `MissingField`.
    pub async fn get_global_proposal(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalProposal, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_proposal(GetGlobalProposalRequest { frame_number })
            .await?
            .into_inner();
        resp.proposal.ok_or(ArchiveClientError::MissingField("proposal"))
    }

    /// Fetch a committed app-shard frame by its consensus `filter` (the app's
    /// `L2 ‖ prefix` address; QUIL's per-app consensus uses the 32-byte L2).
    /// `frame_number == 0` asks the peer for its LATEST frame on that filter.
    /// The returned `FrameHeader.state_roots[0]` is the app's aggregate
    /// vertex-adds root — the state-jump onboarding path cross-checks the
    /// locally-synced app tree against it. `None` if the peer has no frame.
    pub async fn get_app_shard_frame(
        &mut self,
        filter: Vec<u8>,
        frame_number: u64,
    ) -> Result<Option<AppShardFrame>, ArchiveClientError> {
        let resp = self
            .app_shard
            .get_app_shard_frame(GetAppShardFrameRequest { filter, frame_number })
            .await?
            .into_inner();
        Ok(resp.frame)
    }

    /// One page of `filter`'s recorded outgoing records from `from_frame`:
    /// contiguous and ascending, possibly shorter than requested. Unverified:
    /// the caller authenticates it against a certified history root.
    pub async fn get_shard_outgoing_history(
        &mut self,
        filter: Vec<u8>,
        from_frame: u64,
        through_frame: u64,
    ) -> Result<Vec<quil_types::proto::global::ShardFrameOutgoing>, ArchiveClientError> {
        let frames = self
            .app_shard
            .clone()
            .max_decoding_message_size(crate::stub_services::MAX_OUTGOING_HISTORY_BYTES * 2)
            .get_shard_outgoing_history(quil_types::proto::global::GetShardOutgoingHistoryRequest {
                filter, from_frame, through_frame,
            })
            .await?
            .into_inner()
            .frames;
        if frames.iter().enumerate().any(|(i, f)| f.frame_number != from_frame + i as u64) {
            return Err(tonic::Status::data_loss("outgoing history page is not contiguous from the requested frame").into());
        }
        Ok(frames)
    }
}

/// rustls verifier for archive server certs. Quilibrium peers
/// self-sign with Ed25519-derived keys, so the standard PKI path
/// can't be used — but we are NOT "accept any cert". Trust is
/// established at the application layer via the Ed448 xsign
/// cross-signature embedded in the cert's SAN DNS name. The
/// previous implementation accepted ANY syntactically-valid cert
/// here, which (combined with PeerInfo gossip carrying an
/// attacker-controlled peer_id) opened a genesis-archive
/// impersonation path: a malicious peer could advertise an archive
/// capability under any peer_id and pass the mTLS handshake with
/// their own unrelated cert.
///
/// This verifier now runs the same xsign verification that the
/// server-side [`crate::quil_tls::XsignClientCertVerifier`] applies
/// to client certs — proving the cert's SAN really was issued by
/// the Ed448 key it claims. Pairing each archive_pool entry with
/// its expected peer_id (so a mismatch between the certificate's
/// xsign-derived Ed448 pubkey and the expected genesis-archive
/// identity could be rejected) is a useful next-layer hardening
/// but requires plumbing the expected peer_id through the pool +
/// poller call chain. Today the PeerInfo signature check
/// (`validator_global_peer_info` in `quil-engine`) already ensures
/// nobody can publish a PeerInfo claiming the genesis-archive
/// peer_id without holding its Ed448 signing key, so the
/// impersonation chain is already broken at the gossip layer.
#[derive(Debug)]
pub struct AcceptAnyServerCert {
    /// Signature-verification algorithms from the installed crypto provider,
    /// used to perform the real TLS `CertificateVerify` proof-of-possession
    /// check in `verify_tls1x_signature`.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl Default for AcceptAnyServerCert {
    /// Build a verifier wired to the ring crypto provider's signature
    /// algorithms (matching the provider installed by
    /// `build_quil_client_config`).
    fn default() -> Self {
        Self {
            supported: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Apply the Quilibrium xsign check to the presented cert.
        // Identical to the server-side client-auth verifier — the
        // mTLS handshake is symmetric: each side proves SAN-derived
        // identity to the other.
        crate::quil_tls::XsignClientCertVerifier::verify_xsign(end_entity.as_ref())?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // This callback IS the TLS proof-of-possession check: verify the
        // server's CertificateVerify signature against the cert's Ed25519 key,
        // proving the live server holds the cert's private half. Without it a
        // replayed (public) peer cert would be accepted from any party.
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // The Quilibrium cert always uses Ed25519 — narrow the list so
        // rustls negotiates that scheme. (The Go side leaves it open;
        // restricting here is harmless and surfaces mismatches early.)
        // Mirrors the server-side `XsignClientCertVerifier`.
        vec![SignatureScheme::ED25519]
    }
}

/// Build a rustls `ClientConfig` that presents a Quilibrium peer cert and
/// accepts any server cert. Suitable for `tonic`'s tls layer when paired with
/// a custom transport.
/// Process-wide cache of built client TLS configs, keyed by Ed448 seed.
/// The config is a pure, deterministic function of the seed — same seed
/// always yields the identical cert + cross-signature — but building it
/// runs a (slow, vendored-pure-Rust) Ed448 public-key derivation + Ed448
/// SIGN plus x509 cert generation. Recomputing that on every `connect_mtls`
/// put an Ed448 signature on the critical path of every outbound dial
/// (thousands per node under reconnect churn), starving the `:8340`
/// handshake path that consensus delivery depends on. Build once, reuse.
static CLIENT_CONFIG_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<Vec<u8>, Arc<ClientConfig>>>,
> = std::sync::OnceLock::new();

pub fn build_quil_client_config(
    falcon_signing_key: &[u8],
) -> Result<Arc<ClientConfig>, ArchiveClientError> {
    let cache = CLIENT_CONFIG_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(cfg) = cache.lock().unwrap().get(falcon_signing_key) {
        return Ok(cfg.clone());
    }
    let cfg = build_quil_client_config_uncached(falcon_signing_key)?;
    cache.lock().unwrap().insert(falcon_signing_key.to_vec(), cfg.clone());
    Ok(cfg)
}

fn build_quil_client_config_uncached(
    falcon_signing_key: &[u8],
) -> Result<Arc<ClientConfig>, ArchiveClientError> {
    let tls_cert = build_quil_tls_cert(falcon_signing_key)?;
    let cert_chain = rustls_pemfile::certs(&mut tls_cert.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ArchiveClientError::TlsInit(format!("parse cert pem: {}", e)))?;
    let key_der = rustls_pemfile::private_key(&mut tls_cert.key_pem.as_bytes())
        .map_err(|e| ArchiveClientError::TlsInit(format!("parse key pem: {}", e)))?
        .ok_or_else(|| ArchiveClientError::TlsInit("no private key in pem".into()))?;

    // SAFETY: we install a process-global crypto provider once. Errors here
    // mean another provider was already installed; that's fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::default()))
        .with_client_auth_cert(
            cert_chain.into_iter().map(CertificateDer::from).collect(),
            key_der_to_owned(key_der),
        )
        .map_err(|e| ArchiveClientError::TlsInit(format!("client_auth_cert: {}", e)))?;

    // ALPN h2 is required for HTTP/2 / gRPC. Without this rustls will
    // negotiate the default protocol and tonic's HTTP/2 client will fail
    // with an opaque transport error.
    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(config))
}

/// Tower service that, given a `Uri`, opens a TCP connection and wraps it
/// in a rustls TLS session using the provided client config. Returns the
/// resulting stream wrapped in `TokioIo` so it satisfies tonic 0.12's
/// `HyperConnection` requirement.
#[derive(Clone)]
pub struct QuilTlsConnector {
    config: Arc<ClientConfig>,
}

impl QuilTlsConnector {
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl Service<Uri> for QuilTlsConnector {
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| "missing host in uri".to_string())?
                .to_string();
            let port = uri.port_u16().unwrap_or(443);
            let tcp = TcpStream::connect((host.as_str(), port)).await?;
            let _ = tcp.set_nodelay(true);
            let connector = TlsConnector::from(config);
            // Quilibrium servers don't validate SNI; "localhost" matches what
            // the Go side uses too.
            let dns_name = ServerName::try_from("localhost".to_string())
                .map_err(|e| format!("invalid sni: {}", e))?;
            let tls = connector.connect(dns_name, tcp).await?;
            Ok(TokioIo::new(tls))
        })
    }
}

/// Custom tonic connector that runs the sntrup761 **PQNoise** handshake — the
/// post-quantum replacement for the Ed448-mTLS path — and hands tonic the
/// secured tokio stream. Same handshake + identity binding as the libp2p
/// transport (`quil_rpc::pqnoise_channel`), so no rustls/cert material is
/// involved; the server's Ed448 identity is authenticated by its signature
/// over the channel-binding handshake hash.
#[derive(Clone)]
pub struct QuilPqNoiseConnector {
    /// The node's 1281-byte Falcon q-prover-key signing key — the `:8340`
    /// network identity presented in the PQNoise handshake.
    falcon_signing_key: Arc<Vec<u8>>,
    expected_peer: Option<quil_p2p::PeerId>,
    refused_peer: Option<quil_p2p::PeerId>,
}

impl QuilPqNoiseConnector {
    pub fn new(falcon_signing_key: Vec<u8>) -> Self {
        Self { falcon_signing_key: Arc::new(falcon_signing_key), expected_peer: None, refused_peer: None }
    }

    pub fn with_expected_peer(mut self, peer: quil_p2p::PeerId) -> Self {
        self.expected_peer = Some(peer);
        self
    }

    /// Fail with [`OwnEndpoint`] when the server is `peer`.
    pub fn refusing_peer(mut self, peer: quil_p2p::PeerId) -> Self {
        self.refused_peer = Some(peer);
        self
    }
}

impl Service<Uri> for QuilPqNoiseConnector {
    type Response = TokioIo<crate::pqnoise_channel::PqTokioStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let falcon_signing_key = self.falcon_signing_key.clone();
        let expected_peer = self.expected_peer;
        let refused_peer = self.refused_peer;
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| "missing host in uri".to_string())?
                .to_string();
            let port = uri.port_u16().unwrap_or(443);
            let tcp = TcpStream::connect((host.as_str(), port)).await?;
            let (peer, stream) =
                crate::pqnoise_channel::pq_client_handshake(tcp, falcon_signing_key.as_ref()).await?;
            if expected_peer.is_some_and(|expected| peer != expected) {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                    "PQNoise server identity does not match the configured master").into());
            }
            if refused_peer == Some(peer) {
                return Err(Box::new(OwnEndpoint) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(TokioIo::new(stream))
        })
    }
}

fn key_der_to_owned(key: PrivateKeyDer<'_>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs1(d) => PrivateKeyDer::Pkcs1(d.secret_pkcs1_der().to_vec().into()),
        PrivateKeyDer::Sec1(d) => PrivateKeyDer::Sec1(d.secret_sec1_der().to_vec().into()),
        PrivateKeyDer::Pkcs8(d) => PrivateKeyDer::Pkcs8(d.secret_pkcs8_der().to_vec().into()),
        _ => panic!("unsupported key type"),
    }
}

// =====================================================================
// Proof-of-possession regression test — CLIENT direction, END-TO-END HANDSHAKE.
//
// Mirror of `quil_tls::tests::acceptor_completes_handshake_with_forged_client_signature`
// for the outbound side. `AcceptAnyServerCert::verify_xsign` proves the
// server's cert is genuine (the Ed448 identity authorized its Ed25519 cert
// key) but NOT that the live server holds the cert's private key. That second
// guarantee is the TLS `CertificateVerify` check, which rustls routes through
// `verify_tls1x_signature`. `AcceptAnyServerCert` now performs that check (it
// previously stubbed those callbacks to `Ok(assertion())`, which let a server
// present a public cert it did not own — signing CertificateVerify with a
// different key — and still be accepted).
//
// The repro drives a real TLS 1.3 handshake through the actual production
// client construction (`build_quil_client_config`) and asserts the client
// REJECTS the forged server. It failed before possession was enforced (the
// handshake succeeded, demonstrating the bypass); it now guards against that
// regression.
// =====================================================================
#[cfg(test)]
mod error_chain_tests {
    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    struct Layer(&'static str, #[source] Option<Box<Layer>>);

    #[test]
    fn the_chain_names_every_distinct_cause_below_the_error() {
        let error = Layer("rpc error: h2 protocol error: http2 error", Some(Box::new(Layer(
            "http2 error",
            Some(Box::new(Layer("keep-alive timed out", None))),
        ))));
        assert_eq!(super::error_chain(&error), "keep-alive timed out");
        assert_eq!(super::error_chain(&Layer("alone", None)), "");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::sign::CertifiedKey;
    use rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    /// A fresh Falcon-512 signing key — the node identity
    /// `build_quil_tls_cert` binds the cert to.
    fn falcon_signing_key() -> Vec<u8> {
        use quil_types::crypto::Signer as _;
        quil_crypto::FalconSigner::generate().private_key().to_vec()
    }

    fn cert_chain_from_key(falcon_sk: &[u8]) -> Vec<CertificateDer<'static>> {
        let tls = build_quil_tls_cert(falcon_sk).unwrap();
        rustls_pemfile::certs(&mut tls.cert_pem.as_bytes())
            .map(|r| r.unwrap())
            .collect()
    }

    /// Load the Ed25519 signing key derived from `falcon_sk`. Pairing this
    /// with a *different* key's cert chain via `CertifiedKey::new` (which —
    /// unlike `from_der` — does not check the key matches the cert) is the
    /// forgery: present someone else's cert, sign with your own key.
    fn signing_key_from_key(falcon_sk: &[u8]) -> Arc<dyn rustls::sign::SigningKey> {
        let tls = build_quil_tls_cert(falcon_sk).unwrap();
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut tls.key_pem.as_bytes())
                .unwrap()
                .unwrap();
        rustls::crypto::ring::sign::any_supported_type(&key).unwrap()
    }

    /// Server resolver presenting a fixed `CertifiedKey` — used to pair a
    /// victim's cert chain with an attacker's (mismatched) key for the forged
    /// repro, and a matched pair for the positive control.
    #[derive(Debug)]
    struct StaticServerCert(Arc<CertifiedKey>);
    impl rustls::server::ResolvesServerCert for StaticServerCert {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    fn acceptor_for(cert: Arc<CertifiedKey>) -> TlsAcceptor {
        // SAFETY: install the default provider once; an error just means
        // another provider is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(StaticServerCert(cert)));
        // Match the client's ALPN so the handshake fails (or succeeds) on the
        // cert check, not on protocol negotiation.
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        TlsAcceptor::from(Arc::new(cfg))
    }

    #[tokio::test]
    async fn client_rejects_forged_server_signature() {
        // Attacker server: victim's public cert + attacker's own, different
        // key — a server that does NOT possess the cert key.
        let forged = Arc::new(CertifiedKey::new(
            cert_chain_from_key(&falcon_signing_key()),
            signing_key_from_key(&falcon_signing_key()),
        ));
        let acceptor = acceptor_for(forged);

        // Production client, built exactly as the node does.
        let connector =
            TlsConnector::from(build_quil_client_config(&falcon_signing_key()).unwrap());

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_name = ServerName::try_from("localhost").unwrap();
        let (_server_res, client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io),
        );

        assert!(
            client_res.is_err(),
            "VULNERABILITY: build_quil_client_config (AcceptAnyServerCert) completed the \
             handshake with a server that presented the victim's cert but signed \
             CertificateVerify with a different key — proof-of-possession is not \
             enforced, so the server identity is spoofable by cert replay",
        );
    }

    /// Positive control: the SAME client must SUCCEED against a legitimate
    /// server that actually possesses its cert's key. Proves the forged test
    /// fails specifically because possession is missing — not because of ALPN,
    /// the duplex transport, or some other setup detail. Passes before and
    /// after the fix (all possession is legitimate).
    #[tokio::test]
    async fn client_accepts_legitimate_server() {
        let sk = falcon_signing_key();
        let legit = Arc::new(CertifiedKey::new(
            cert_chain_from_key(&sk),
            signing_key_from_key(&sk),
        ));
        let acceptor = acceptor_for(legit);

        let connector =
            TlsConnector::from(build_quil_client_config(&falcon_signing_key()).unwrap());

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_name = ServerName::try_from("localhost").unwrap();
        let (server_res, client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io),
        );

        assert!(
            client_res.is_ok(),
            "legitimate handshake must succeed (client side): {:?}",
            client_res.err(),
        );
        assert!(
            server_res.is_ok(),
            "legitimate handshake must succeed (server side): {:?}",
            server_res.err(),
        );
    }
}

#[cfg(test)]
mod pinned_master_tests {
    use super::*;

    #[tokio::test]
    async fn master_pin_accepts_own_key_and_rejects_a_legitimate_unrelated_peer() {
        for same_key in [true, false] {
            let client_key = quil_p2p::generate_falcon_signing_key();
            let server_key = if same_key { client_key.clone() } else { quil_p2p::generate_falcon_signing_key() };
            let expected = quil_p2p::Keypair::falcon_from_bytes(&client_key).unwrap().public().to_peer_id();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                crate::pqnoise_channel::pq_server_handshake(tcp, &server_key).await.unwrap()
            });
            let mut connector = QuilPqNoiseConnector::new(client_key).with_expected_peer(expected);
            let result = tokio::time::timeout(Duration::from_secs(5),
                connector.call(format!("http://{address}").parse().unwrap())).await.unwrap();
            assert_eq!(result.is_ok(), same_key);
            if let Err(error) = result {
                assert!(error.to_string().contains("identity does not match"), "{error}");
            }
            assert_eq!(server.await.unwrap().peer_id(), expected);
        }
    }

    #[tokio::test]
    async fn an_archive_answering_with_this_nodes_identity_is_recognized() {
        for own in [true, false] {
            let key = quil_p2p::generate_falcon_signing_key();
            let server_key = if own { key.clone() } else { quil_p2p::generate_falcon_signing_key() };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let stream = crate::pqnoise_channel::pq_server_handshake(tcp, &server_key).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
                drop(stream);
            });
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                ArchiveClient::connect_archive(&address.to_string(), &key),
            )
            .await;
            let recognized = matches!(&result, Ok(Err(error)) if error.is_own_endpoint());
            assert_eq!(recognized, own, "own={own}");
            server.abort();
        }
    }

    #[test]
    fn a_closed_connection_is_a_transport_failure_and_a_status_is_not() {
        let closed = tonic::Status::from_error(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection closed",
        )));
        assert!(ArchiveClientError::Rpc(closed).is_transport_failure());
        assert!(!ArchiveClientError::Rpc(tonic::Status::not_found("frame 7 not found")).is_transport_failure());
    }
}
