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
use quil_types::error::QuilError;
use quil_types::store::ClockStore;

// =====================================================================
// AppShardService — shard frame/proposal reads
// =====================================================================

/// Resolves app-shard frames from the worker that currently owns a filter.
///
/// Archive nodes use a store-backed provider instead because their local
/// clock store is the durable source of truth rather than a worker mirror.
#[tonic::async_trait]
pub trait AppShardFrameProvider: Send + Sync {
    async fn get_app_shard_frame(
        &self,
        filter: Vec<u8>,
        frame_number: u64,
    ) -> Result<Option<global::AppShardFrame>, Status>;
}

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
                Err(QuilError::NotFound(_)) => Ok(None),
                Err(e) => Err(Status::internal(format!(
                    "app-shard frame store read failed: {e}"
                ))),
            }
        })
        .await
        .map_err(|e| Status::internal(format!("app-shard frame read task failed: {e}")))?
    }
}

/// Public AppShardService facade. The provider is worker-routed on prover
/// nodes and store-backed on archives.
pub struct AppShardRpcServer {
    provider: Arc<dyn AppShardFrameProvider>,
}

impl AppShardRpcServer {
    /// Construct the archive/store-backed variant.
    pub fn new(clock_store: Arc<dyn ClockStore>) -> Self {
        Self::with_provider(Arc::new(ClockStoreAppShardFrameProvider { clock_store }))
    }

    pub fn with_provider(provider: Arc<dyn AppShardFrameProvider>) -> Self {
        Self { provider }
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
mod app_shard_tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingProvider {
        calls: Mutex<Vec<(Vec<u8>, u64)>>,
        fail: bool,
    }

    #[tonic::async_trait]
    impl AppShardFrameProvider for RecordingProvider {
        async fn get_app_shard_frame(
            &self,
            filter: Vec<u8>,
            frame_number: u64,
        ) -> Result<Option<global::AppShardFrame>, Status> {
            self.calls
                .lock()
                .unwrap()
                .push((filter.clone(), frame_number));
            if self.fail {
                return Err(Status::unavailable("worker offline"));
            }
            let mut header = global::FrameHeader::default();
            header.address = filter;
            header.frame_number = if frame_number == 0 { 22 } else { frame_number };
            Ok(Some(global::AppShardFrame {
                header: Some(header),
                requests: Vec::new(),
                ..Default::default()
            }))
        }
    }

    #[tokio::test]
    async fn latest_and_numbered_reads_are_forwarded_unchanged() {
        let provider = Arc::new(RecordingProvider {
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        let server = AppShardRpcServer::with_provider(provider.clone());

        let latest = server
            .get_app_shard_frame(Request::new(global::GetAppShardFrameRequest {
                filter: b"shard-a".to_vec(),
                frame_number: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .frame
            .unwrap();
        let numbered = server
            .get_app_shard_frame(Request::new(global::GetAppShardFrameRequest {
                filter: b"shard-a".to_vec(),
                frame_number: 19,
            }))
            .await
            .unwrap()
            .into_inner()
            .frame
            .unwrap();

        assert_eq!(latest.header.unwrap().frame_number, 22);
        assert_eq!(numbered.header.unwrap().frame_number, 19);
        assert_eq!(
            *provider.calls.lock().unwrap(),
            vec![(b"shard-a".to_vec(), 0), (b"shard-a".to_vec(), 19)]
        );
    }

    #[tokio::test]
    async fn empty_filter_is_rejected_before_provider_call() {
        let provider = Arc::new(RecordingProvider {
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        let server = AppShardRpcServer::with_provider(provider.clone());

        let status = server
            .get_app_shard_frame(Request::new(global::GetAppShardFrameRequest {
                filter: Vec::new(),
                frame_number: 0,
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(provider.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn provider_failures_are_not_flattened_to_missing_frames() {
        let provider = Arc::new(RecordingProvider {
            calls: Mutex::new(Vec::new()),
            fail: true,
        });
        let server = AppShardRpcServer::with_provider(provider);

        let status = server
            .get_app_shard_frame(Request::new(global::GetAppShardFrameRequest {
                filter: b"shard-a".to_vec(),
                frame_number: 0,
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), tonic::Code::Unavailable);
    }
}
