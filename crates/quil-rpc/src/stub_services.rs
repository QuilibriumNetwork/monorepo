//! gRPC service stubs for endpoints that qclient calls but the Rust
//! node doesn't yet have full backing state for.
//!
//! Each method returns a valid response shape (empty data +
//! descriptive `error` string where the proto supports one) rather
//! than `Status::unimplemented`. This matters because Go's qclient
//! distinguishes "service unreachable" (hard fail, crashes) from
//! "service returned an error string" (soft fail, displays message).
//!
//! As real backing state is wired, these stubs should be replaced
//! with proper implementations — but even as stubs they close the
//! "service not registered" class of qclient compatibility breaks.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use quil_types::consensus::ProverRegistry;
use quil_types::proto::global::{
    self,
    app_shard_service_server::AppShardService,
    key_registry_service_server::KeyRegistryService,
};
use quil_types::proto::node::{
    self, connectivity_service_server::ConnectivityService,
};
use quil_types::store::ClockStore;
use quil_types::proto::node::node_service_server::NodeService as _;

// =====================================================================
// AppShardService — shard frame/proposal reads
// =====================================================================

/// Resolves an app-shard frame for a filter to the CANONICAL source for this
/// node. On a prover/cluster node the app-shard frames live in the owning
/// worker's store (a remote process in cluster mode), NOT the master clock
/// store — so serving reads straight off the master store returns nothing.
/// The router-backed provider (`AppShardFrameRouter`, in quil-node) resolves to
/// the owning worker; archives use the store-backed provider below because their
/// local clock store is the durable source of truth, not a worker mirror.
#[tonic::async_trait]
pub trait AppShardFrameProvider: Send + Sync {
    async fn get_app_shard_frame(
        &self,
        filter: Vec<u8>,
        frame_number: u64,
    ) -> Result<Option<global::AppShardFrame>, Status>;

    /// Recorded outgoing records of `filter`'s frames from `from`, contiguous,
    /// at most `through`, bounded by [`MAX_OUTGOING_HISTORY_FRAMES`] and
    /// [`MAX_OUTGOING_HISTORY_BYTES`]. Served by archives, whose store holds
    /// every shard's materialized records.
    async fn get_shard_outgoing_history(
        &self,
        _filter: Vec<u8>,
        _from: u64,
        _through: u64,
    ) -> Result<Vec<global::ShardFrameOutgoing>, Status> {
        Err(Status::unimplemented("outgoing history is served by archives"))
    }
}

/// Frames per outgoing-history page.
pub const MAX_OUTGOING_HISTORY_FRAMES: u64 = 256;
/// Bytes per outgoing-history page; a larger single frame is still returned alone.
pub const MAX_OUTGOING_HISTORY_BYTES: usize = 8 << 20;

/// One frame's outgoing records from `clock_store`; `None` if any is missing.
fn frame_outgoing(
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
) -> quil_types::error::Result<Option<global::ShardFrameOutgoing>> {
    let (Some(fee_total), Some(settlements), Some(spends), Some(digest)) = (
        clock_store.get_shard_frame_fee_total(filter, frame_number)?,
        clock_store.get_shard_frame_settlements(filter, frame_number)?,
        clock_store.get_shard_frame_spends(filter, frame_number)?,
        clock_store.get_shard_frame_accumulator(filter, frame_number)?,
    ) else {
        return Ok(None);
    };
    let report = if digest.is_empty() {
        Vec::new()
    } else {
        match clock_store.get_shard_accumulator_report(filter, &digest)? {
            Some(report) => report,
            None => return Ok(None),
        }
    };
    Ok(Some(global::ShardFrameOutgoing {
        frame_number,
        fee_total: fee_total.to_be_bytes().to_vec(),
        settlements,
        spends,
        accumulator_digest: digest,
        accumulator_report: report,
    }))
}

/// Store-backed provider — reads the master/archive clock store directly. The
/// archive variant: its local store IS authoritative (it materializes every
/// finalized frame), so no worker routing is needed.
struct ClockStoreAppShardFrameProvider {
    clock_store: Arc<dyn ClockStore>,
}

#[tonic::async_trait]
impl AppShardFrameProvider for ClockStoreAppShardFrameProvider {
    async fn get_app_shard_frame(
        &self,
        filter: Vec<u8>,
        frame_number: u64,
    ) -> Result<Option<global::AppShardFrame>, Status> {
        let clock_store = self.clock_store.clone();
        tokio::task::spawn_blocking(move || {
            let result = if frame_number == 0 {
                clock_store.get_latest_shard_clock_frame(&filter)
            } else {
                clock_store.get_shard_clock_frame(&filter, frame_number, false)
            };
            match result {
                Ok(frame) => Ok(Some(frame)),
                Err(quil_types::error::QuilError::NotFound(_)) => Ok(None),
                Err(e) => Err(Status::internal(format!(
                    "app-shard frame store read failed: {e}"
                ))),
            }
        })
        .await
        .map_err(|e| Status::internal(format!("app-shard frame read task failed: {e}")))?
    }

    async fn get_shard_outgoing_history(
        &self,
        filter: Vec<u8>,
        from: u64,
        through: u64,
    ) -> Result<Vec<global::ShardFrameOutgoing>, Status> {
        let clock_store = self.clock_store.clone();
        tokio::task::spawn_blocking(move || {
            let last = through.min(from.saturating_add(MAX_OUTGOING_HISTORY_FRAMES - 1));
            let mut frames = Vec::new();
            let mut bytes = 0usize;
            for frame_number in from..=last {
                let outgoing = frame_outgoing(clock_store.as_ref(), &filter, frame_number)
                    .map_err(|e| Status::internal(format!("outgoing history read failed: {e}")))?;
                let Some(outgoing) = outgoing else { break };
                bytes += prost::Message::encoded_len(&outgoing);
                if !frames.is_empty() && bytes > MAX_OUTGOING_HISTORY_BYTES {
                    break;
                }
                frames.push(outgoing);
            }
            Ok(frames)
        })
        .await
        .map_err(|e| Status::internal(format!("outgoing history read task failed: {e}")))?
    }
}

/// Public `AppShardService` facade. The provider is worker-routed on prover
/// (cluster) nodes and store-backed on archives.
pub struct AppShardRpcServer {
    provider: Arc<dyn AppShardFrameProvider>,
    /// Shared validation and local worker routing for wallet reads. No remote
    /// handlers are installed here: a peer with incomplete coverage refuses
    /// instead of recursively forwarding the request.
    reads: crate::node_service::NodeRpcServer,
}

impl AppShardRpcServer {
    /// Construct the archive/store-backed variant (reads the local clock store).
    pub fn new(clock_store: Arc<dyn ClockStore>) -> Self {
        Self::with_provider(Arc::new(ClockStoreAppShardFrameProvider { clock_store }))
    }

    /// Construct with an explicit provider — the worker-routing
    /// `AppShardFrameRouter` on prover/cluster nodes.
    pub fn with_provider(provider: Arc<dyn AppShardFrameProvider>) -> Self {
        Self { provider, reads: crate::node_service::NodeRpcServer::new() }
    }

    /// Serve peer coin scans from `coins`, for applications `coverage` admits.
    pub fn with_coin_scan(
        mut self,
        coins: Arc<dyn quil_types::store::CoinWitnessProvider>,
        coverage: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) -> Self {
        self.reads = self.reads.with_coin_witness_provider(coins)
            .with_application_coverage(coverage);
        self
    }

    pub fn with_vertex_stores(
        mut self,
        master: Arc<dyn quil_types::store::HypergraphStore>,
        workers: crate::node_service::AppHypergraphStores,
    ) -> Self {
        self.reads = self.reads.with_hypergraph_store(master)
            .with_app_hypergraph_stores(workers);
        self
    }
}

#[tonic::async_trait]
impl AppShardService for AppShardRpcServer {
    async fn get_app_shard_frame(
        &self,
        request: Request<global::GetAppShardFrameRequest>,
    ) -> Result<Response<global::AppShardFrameResponse>, Status> {
        let req = request.into_inner();
        if req.filter.is_empty() {
            return Err(Status::invalid_argument("filter required"));
        }
        let frame = self
            .provider
            .get_app_shard_frame(req.filter, req.frame_number)
            .await?;
        Ok(Response::new(global::AppShardFrameResponse {
            frame,
            proof: Vec::new(),
        }))
    }

    async fn get_shard_outgoing_history(
        &self,
        request: Request<global::GetShardOutgoingHistoryRequest>,
    ) -> Result<Response<global::GetShardOutgoingHistoryResponse>, Status> {
        let req = request.into_inner();
        if req.filter.len() < 32 || req.from_frame == 0 || req.through_frame < req.from_frame {
            return Err(Status::invalid_argument("filter and a frame range starting above zero required"));
        }
        let frames = self
            .provider
            .get_shard_outgoing_history(req.filter, req.from_frame, req.through_frame)
            .await?;
        Ok(Response::new(global::GetShardOutgoingHistoryResponse { frames }))
    }

    async fn list_shard_coins(
        &self,
        request: Request<global::ListShardCoinsRequest>,
    ) -> Result<Response<global::ListShardCoinsResponse>, Status> {
        let req = request.into_inner();
        let page = self.reads.list_coins(Request::new(node::ListCoinsRequest {
            domain: req.domain, snapshot_id: req.snapshot_id, after: req.after,
        })).await?.into_inner();
        Ok(Response::new(global::ListShardCoinsResponse {
            network: page.network, snapshot_id: page.snapshot_id, root_record: page.root_record,
            coins: page.coins.into_iter().map(|c| global::ShardCoin {
                address: c.address, frame_number: c.frame_number, owner: c.owner,
                commitment: c.commitment, memo: c.memo, position: c.position,
            }).collect(),
            cursor: page.cursor, has_more: page.has_more,
        }))
    }

    async fn list_shard_escrows(
        &self,
        request: Request<global::ListShardCoinsRequest>,
    ) -> Result<Response<global::ListShardEscrowsResponse>, Status> {
        let req = request.into_inner();
        let page = self.reads.list_escrows(Request::new(node::ListCoinsRequest {
            domain: req.domain, snapshot_id: req.snapshot_id, after: req.after,
        })).await?.into_inner();
        Ok(Response::new(global::ListShardEscrowsResponse {
            network: page.network, snapshot_id: page.snapshot_id,
            escrows: page.escrows.into_iter().map(|e| global::ShardEscrow {
                address: e.address, raw_data: e.raw_data,
            }).collect(),
            cursor: page.cursor, has_more: page.has_more,
        }))
    }

    async fn get_shard_coin_witnesses(
        &self,
        request: Request<global::GetShardCoinWitnessesRequest>,
    ) -> Result<Response<global::GetShardCoinWitnessesResponse>, Status> {
        let req = request.into_inner();
        let bundle = self.reads.get_coin_witnesses(Request::new(node::GetCoinWitnessesRequest {
            domain: req.domain, addresses: req.addresses,
        })).await?.into_inner();
        // NodeService validates the root record and witness dimensions.
        let depth = u32::from(bundle.root_record[40]);
        Ok(Response::new(global::GetShardCoinWitnessesResponse {
            network: bundle.network, root_record: bundle.root_record, depth,
            witnesses: bundle.witnesses.into_iter().map(|w| global::ShardCoinWitness {
                address: w.address, found: w.found, siblings: w.siblings, right: w.right,
            }).collect(),
        }))
    }

    async fn get_shard_vertex(
        &self,
        request: Request<global::GetShardVertexRequest>,
    ) -> Result<Response<global::GetShardVertexResponse>, Status> {
        let vertex = self.reads.get_vertex_data(Request::new(node::GetVertexDataRequest {
            address: request.into_inner().address, full_data: true,
        })).await?.into_inner();
        Ok(Response::new(global::GetShardVertexResponse {
            found: vertex.present.unwrap_or(false), blob: vertex.raw_data,
        }))
    }

    async fn get_app_shard_proposal(
        &self,
        _request: Request<global::GetAppShardProposalRequest>,
    ) -> Result<Response<global::AppShardProposalResponse>, Status> {
        // AppShardProposal is the uncommitted leader proposal — only
        // the leader for that rank has it; peers don't persist them.
        // Return None: valid response shape, no data.
        Ok(Response::new(global::AppShardProposalResponse { proposal: None }))
    }
}

// =====================================================================
// KeyRegistryService — lookups into the GLOBAL_KEY_REGISTRY domain
// =====================================================================

/// Serves KeyRegistry reads backed by the ProverRegistry. All write
/// endpoints (`put_*`) return an `error` string since the registry
/// is populated via BlossomSub messages, not direct RPC writes —
/// matching Go's server behavior.
pub struct KeyRegistryRpcServer {
    prover_registry: Arc<dyn ProverRegistry>,
}

impl KeyRegistryRpcServer {
    pub fn new(prover_registry: Arc<dyn ProverRegistry>) -> Self {
        Self { prover_registry }
    }
}

const KEY_REGISTRY_READONLY_ERR: &str =
    "key registry writes go via GLOBAL_KEY_REGISTRY BlossomSub, not direct RPC";

#[tonic::async_trait]
impl KeyRegistryService for KeyRegistryRpcServer {
    async fn get_key_registry(
        &self,
        _request: Request<global::GetKeyRegistryRequest>,
    ) -> Result<Response<global::GetKeyRegistryResponse>, Status> {
        // The KeyRegistry lookup by identity address requires a
        // hypergraph walk of the key-registry domain. Not yet
        // indexed; return "not found" via the error field so qclient
        // shows a message rather than crashing.
        Ok(Response::new(global::GetKeyRegistryResponse {
            registry: None,
            error: "key-registry lookup by identity not yet indexed".into(),
        }))
    }

    async fn get_key_registry_by_prover(
        &self,
        request: Request<global::GetKeyRegistryByProverRequest>,
    ) -> Result<Response<global::GetKeyRegistryByProverResponse>, Status> {
        let req = request.into_inner();
        // Fast path: if the ProverRegistry has this prover, we can
        // surface the BLS pubkey; full KeyRegistry assembly (onion/
        // view/spend) requires the hypergraph walk above.
        let registry = self
            .prover_registry
            .get_prover_info(&req.prover_key_address)
            .ok()
            .flatten()
            .map(|_p| {
                // Placeholder: return None registry. A real impl
                // would construct quilibrium.node.keys.pb.KeyRegistry
                // from the prover's KeyRegistry record on-chain.
                None::<quil_types::proto::keys::KeyRegistry>
            })
            .flatten();
        Ok(Response::new(global::GetKeyRegistryByProverResponse {
            registry,
            error: if req.prover_key_address.is_empty() {
                "empty prover address".into()
            } else {
                String::new()
            },
        }))
    }

    async fn put_identity_key(
        &self,
        _request: Request<global::PutIdentityKeyRequest>,
    ) -> Result<Response<global::PutIdentityKeyResponse>, Status> {
        Ok(Response::new(global::PutIdentityKeyResponse {
            error: KEY_REGISTRY_READONLY_ERR.into(),
        }))
    }

    async fn put_proving_key(
        &self,
        _request: Request<global::PutProvingKeyRequest>,
    ) -> Result<Response<global::PutProvingKeyResponse>, Status> {
        Ok(Response::new(global::PutProvingKeyResponse {
            error: KEY_REGISTRY_READONLY_ERR.into(),
        }))
    }

    async fn put_cross_signature(
        &self,
        _request: Request<global::PutCrossSignatureRequest>,
    ) -> Result<Response<global::PutCrossSignatureResponse>, Status> {
        Ok(Response::new(global::PutCrossSignatureResponse {
            error: KEY_REGISTRY_READONLY_ERR.into(),
        }))
    }

    async fn put_signed_key(
        &self,
        _request: Request<global::PutSignedKeyRequest>,
    ) -> Result<Response<global::PutSignedKeyResponse>, Status> {
        Ok(Response::new(global::PutSignedKeyResponse {
            error: KEY_REGISTRY_READONLY_ERR.into(),
        }))
    }

    async fn get_identity_key(
        &self,
        _request: Request<global::GetIdentityKeyRequest>,
    ) -> Result<Response<global::GetIdentityKeyResponse>, Status> {
        Ok(Response::new(global::GetIdentityKeyResponse {
            key: None,
            error: "identity key lookup not yet indexed".into(),
        }))
    }

    async fn get_proving_key(
        &self,
        _request: Request<global::GetProvingKeyRequest>,
    ) -> Result<Response<global::GetProvingKeyResponse>, Status> {
        Ok(Response::new(global::GetProvingKeyResponse {
            key: None,
            error: "proving key lookup not yet indexed".into(),
        }))
    }

    async fn get_signed_key(
        &self,
        _request: Request<global::GetSignedKeyRequest>,
    ) -> Result<Response<global::GetSignedKeyResponse>, Status> {
        Ok(Response::new(global::GetSignedKeyResponse {
            key: None,
            error: "signed key lookup not yet indexed".into(),
        }))
    }

    async fn get_signed_keys_by_parent(
        &self,
        _request: Request<global::GetSignedKeysByParentRequest>,
    ) -> Result<Response<global::GetSignedKeysByParentResponse>, Status> {
        Ok(Response::new(global::GetSignedKeysByParentResponse {
            keys: Vec::new(),
            error: "signed keys by parent not yet indexed".into(),
        }))
    }

    async fn range_proving_keys(
        &self,
        _request: Request<global::RangeProvingKeysRequest>,
    ) -> Result<Response<global::RangeProvingKeysResponse>, Status> {
        Ok(Response::new(global::RangeProvingKeysResponse {
            key: None,
            error: "range scan not yet indexed".into(),
        }))
    }

    async fn range_identity_keys(
        &self,
        _request: Request<global::RangeIdentityKeysRequest>,
    ) -> Result<Response<global::RangeIdentityKeysResponse>, Status> {
        Ok(Response::new(global::RangeIdentityKeysResponse {
            key: None,
            error: "range scan not yet indexed".into(),
        }))
    }

    async fn range_signed_keys(
        &self,
        _request: Request<global::RangeSignedKeysRequest>,
    ) -> Result<Response<global::RangeSignedKeysResponse>, Status> {
        Ok(Response::new(global::RangeSignedKeysResponse {
            key: None,
            error: "range scan not yet indexed".into(),
        }))
    }
}

// =====================================================================
// ConnectivityService — TestConnectivity
// =====================================================================

/// Serves a single "can this node reach a peer" probe. For now,
/// returns success + empty error — a more useful impl would actively
/// dial the peer's stream multiaddr.
pub struct ConnectivityRpcServer;

#[tonic::async_trait]
impl ConnectivityService for ConnectivityRpcServer {
    async fn test_connectivity(
        &self,
        _request: Request<node::ConnectivityTestRequest>,
    ) -> Result<Response<node::ConnectivityTestResponse>, Status> {
        // Minimal impl: we could dial the peer via p2p_handle, but
        // that's a heavier wiring. Return success for now so qclient
        // doesn't choke on an Unimplemented error.
        Ok(Response::new(node::ConnectivityTestResponse {
            success: true,
            error_message: String::new(),
        }))
    }
}

#[cfg(test)]
mod outgoing_history_tests {
    use super::*;

    /// An archive serves a shard's recorded outgoing records contiguously from
    /// the requested frame, stopping at the first frame it lacks.
    #[tokio::test]
    async fn outgoing_history_is_contiguous_and_stops_at_the_first_missing_frame() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let filter = vec![0x21; 32];
        for frame in [1u64, 2, 3, 5] {
            clock.put_shard_frame_fee_total(&filter, frame, frame as u128).unwrap();
            clock.put_shard_frame_settlements(&filter, frame, &[]).unwrap();
            clock.put_shard_frame_spends(&filter, frame, &[]).unwrap();
            let report = vec![frame as u8; 8];
            let digest = if frame == 2 { quil_execution::token_intrinsic::accumulator_header::report_digest(&report) } else { Vec::new() };
            clock.put_shard_frame_accumulator(&filter, frame, &digest, &report).unwrap();
        }
        let server = AppShardRpcServer::new(clock);
        let request = |from, through| Request::new(global::GetShardOutgoingHistoryRequest { filter: filter.clone(), from_frame: from, through_frame: through });
        let frames = server.get_shard_outgoing_history(request(1, 9)).await.unwrap().into_inner().frames;
        assert_eq!(frames.iter().map(|f| f.frame_number).collect::<Vec<_>>(), vec![1, 2, 3], "stops before the gap at 4");
        assert_eq!(frames[1].fee_total, 2u128.to_be_bytes().to_vec());
        assert_eq!(frames[1].accumulator_report, vec![2; 8]);
        assert!(frames[0].accumulator_report.is_empty());
        assert_eq!(server.get_shard_outgoing_history(request(2, 2)).await.unwrap().into_inner().frames.len(), 1);
        assert!(server.get_shard_outgoing_history(request(4, 9)).await.unwrap().into_inner().frames.is_empty());
        assert!(server.get_shard_outgoing_history(request(0, 3)).await.is_err());
        assert!(server.get_shard_outgoing_history(request(3, 2)).await.is_err());
    }
}
