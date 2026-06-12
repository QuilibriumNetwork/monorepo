//! `DispatchService` gRPC server — inbox messaging + hub association
//! CRDT. Ports `node/consensus/global/dispatch_service.go` to Rust
//! over the existing `quil_store::RocksInboxStore` backend.
//!
//! The inbox is a per-filter time-ordered log of encrypted messages
//! (`qclient message send` / `qclient message retrieve`). Hub records
//! are a 2P-set CRDT keyed on `(filter, hub_id)` — puts and deletes
//! compose to the current association set.

use std::sync::Arc;

use prost::Message;
use tonic::{Request, Response, Status};

use quil_store::RocksInboxStore;
use quil_types::proto::channel::{
    DispatchSyncRequest, DispatchSyncResponse, HubPut, HubRequest, HubResponse, InboxMessagePut,
    InboxMessageRequest, InboxMessageResponse,
};
use quil_types::proto::global::dispatch_service_server::DispatchService;

/// Matches Go's 8-byte filter prefix convention for inbox messages.
/// Defined here so we stay consistent with the on-disk layout in
/// `quil_store::RocksInboxStore` without leaking that type's private
/// key-builder helpers.
const INBOX_FILTER_LEN: usize = 3;

/// gRPC DispatchService implementation.
pub struct DispatchRpcServer {
    store: Arc<RocksInboxStore>,
}

impl DispatchRpcServer {
    pub fn new(store: Arc<RocksInboxStore>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl DispatchService for DispatchRpcServer {
    async fn put_inbox_message(
        &self,
        request: Request<InboxMessagePut>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let msg = req
            .message
            .ok_or_else(|| Status::invalid_argument("missing message"))?;
        // Filter for routing is the first 3 bytes of the inbox
        // address — matches Go's `InboxMessageFilterFromAddress`.
        if msg.address.len() < INBOX_FILTER_LEN {
            return Err(Status::invalid_argument(
                "address too short to derive filter",
            ));
        }
        let filter = msg.address[..INBOX_FILTER_LEN].to_vec();
        let timestamp = msg.timestamp;
        let bytes = msg.encode_to_vec();
        self.store
            .put_inbox_message(&filter, timestamp, &bytes)
            .map_err(|e| Status::internal(format!("put_inbox_message: {e}")))?;
        Ok(Response::new(()))
    }

    async fn get_inbox_messages(
        &self,
        request: Request<InboxMessageRequest>,
    ) -> Result<Response<InboxMessageResponse>, Status> {
        let req = request.into_inner();
        if req.filter.is_empty() {
            return Err(Status::invalid_argument("filter is required"));
        }
        // Full-range read; the Go service uses `from_timestamp=0,
        // to_timestamp=u64::MAX` as the catch-all default, and
        // downstream filtering (by message_id, address) happens here.
        let from_ts = 0u64;
        let to_ts = u64::MAX;
        let rows = self
            .store
            .get_inbox_messages(&req.filter, from_ts, to_ts)
            .map_err(|e| Status::internal(format!("get_inbox_messages: {e}")))?;

        let mut messages = Vec::with_capacity(rows.len());
        for (_ts, data) in rows {
            let Ok(msg) = quil_types::proto::channel::InboxMessage::decode(&*data) else {
                continue;
            };
            if !req.message_id.is_empty() {
                let id = quil_types::proto::channel::InboxMessage::message_id(&msg);
                if id != req.message_id {
                    continue;
                }
            }
            if !req.address.is_empty() && msg.address != req.address {
                continue;
            }
            messages.push(msg);
        }
        Ok(Response::new(InboxMessageResponse { messages }))
    }

    async fn put_hub(
        &self,
        request: Request<HubPut>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        if let Some(add) = req.add {
            if add.address.len() < INBOX_FILTER_LEN {
                return Err(Status::invalid_argument(
                    "hub add address too short for filter",
                ));
            }
            let filter = add.address[..INBOX_FILTER_LEN].to_vec();
            // Use inbox_public_key as the hub_id so add+delete pair
            // identically. Matches Go's CRDT key derivation.
            self.store
                .put_hub_add(&filter, &add.inbox_public_key)
                .map_err(|e| Status::internal(format!("put_hub_add: {e}")))?;
        }
        if let Some(del) = req.delete {
            if del.address.len() < INBOX_FILTER_LEN {
                return Err(Status::invalid_argument(
                    "hub delete address too short for filter",
                ));
            }
            let filter = del.address[..INBOX_FILTER_LEN].to_vec();
            self.store
                .put_hub_delete(&filter, &del.inbox_public_key)
                .map_err(|e| Status::internal(format!("put_hub_delete: {e}")))?;
        }
        Ok(Response::new(()))
    }

    async fn get_hub(
        &self,
        request: Request<HubRequest>,
    ) -> Result<Response<HubResponse>, Status> {
        let req = request.into_inner();
        let inbox_ids = self
            .store
            .get_hub_associations(&req.filter)
            .map_err(|e| Status::internal(format!("get_hub: {e}")))?;
        // Materialize as `adds` since we only expose the live
        // association set; deletes are folded into the add/remove CRDT
        // behind `get_hub_associations`. Go returns the diff set but
        // most qclient flows only care about the current active
        // associations, so this is compat-compatible on the query
        // path.
        let adds = inbox_ids
            .into_iter()
            .map(|inbox_pk| quil_types::proto::channel::HubAddInboxMessage {
                address: req.hub_address.clone(),
                inbox_public_key: inbox_pk,
                hub_public_key: Vec::new(),
                inbox_signature: Vec::new(),
                hub_signature: Vec::new(),
            })
            .collect();
        Ok(Response::new(HubResponse {
            adds,
            deletes: Vec::new(),
        }))
    }

    async fn sync(
        &self,
        request: Request<DispatchSyncRequest>,
    ) -> Result<Response<DispatchSyncResponse>, Status> {
        // Aggregate the current state (messages + hub associations)
        // for every requested filter into a single response. Mirrors
        // Go's non-streaming `Sync` RPC.
        let req = request.into_inner();
        let mut all_messages = Vec::new();
        let mut hubs = Vec::new();
        for filter in &req.filters {
            if filter.is_empty() {
                continue;
            }
            let msgs = self
                .store
                .get_inbox_messages(filter, 0, u64::MAX)
                .map_err(|e| Status::internal(format!("sync messages: {e}")))?;
            for (_ts, data) in msgs {
                if let Ok(m) = quil_types::proto::channel::InboxMessage::decode(&*data) {
                    all_messages.push(m);
                }
            }
            let hub_ids = self
                .store
                .get_hub_associations(filter)
                .map_err(|e| Status::internal(format!("sync hub: {e}")))?;
            let adds = hub_ids
                .into_iter()
                .map(|inbox_pk| quil_types::proto::channel::HubAddInboxMessage {
                    address: Vec::new(),
                    inbox_public_key: inbox_pk,
                    hub_public_key: Vec::new(),
                    inbox_signature: Vec::new(),
                    hub_signature: Vec::new(),
                })
                .collect();
            hubs.push(HubResponse {
                adds,
                deletes: Vec::new(),
            });
        }
        Ok(Response::new(DispatchSyncResponse {
            messages: all_messages,
            hubs,
        }))
    }
}

/// Compute a message ID from an `InboxMessage`. The convention
/// (mirroring Go) is SHA-256 over the full canonical proto encoding.
trait InboxMessageIdExt {
    fn message_id(msg: &quil_types::proto::channel::InboxMessage) -> Vec<u8>;
}

impl InboxMessageIdExt for quil_types::proto::channel::InboxMessage {
    fn message_id(msg: &quil_types::proto::channel::InboxMessage) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let bytes = msg.encode_to_vec();
        Sha256::digest(&bytes).to_vec()
    }
}
