//! `DispatchService` gRPC server — inbox messaging + hub association
//! CRDT. Ports `node/consensus/global/dispatch_service.go` to Rust
//! over the existing `quil_store::RocksInboxStore` backend.
//!
//! The inbox is a per-filter time-ordered log of encrypted messages
//! (`qclient message send` / `qclient message retrieve`). Hub records
//! are a 2P-set CRDT keyed on `(filter, hub_id)` — puts and deletes
//! compose to the current association set.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use prost::Message;
use tonic::{Request, Response, Status};

use quil_hypergraph::addressing::get_bloom_filter_indices;
use quil_store::RocksInboxStore;
use quil_types::proto::channel::{
    DispatchSyncRequest, DispatchSyncResponse, HubPut, HubRequest, HubResponse, InboxMessagePut,
    InboxMessageRequest, InboxMessageResponse,
};
use quil_types::proto::global::dispatch_service_server::DispatchService;

/// Minimum inbox-address length required to derive a routing filter.
/// The filter itself is a 3-byte L1 shard bloom index computed via
/// `get_bloom_filter_indices(addr, 256, 3)` (matching Go's
/// `up2p.GetBloomFilterIndices(msg.Address, 256, 3)`), NOT a raw
/// address prefix. We still reject addresses shorter than this so a
/// trivially malformed submission is rejected up front.
const INBOX_FILTER_LEN: usize = 3;

/// Number of bloom index positions (`k`) — matches Go's `..., 256, 3)`.
const BLOOM_K: usize = 3;
/// Bloom bit-length — matches Go's `..., 256, ...)`.
const BLOOM_BITS: usize = 256;

/// Derive the 3-byte routing filter for an inbox address, matching Go's
/// `up2p.GetBloomFilterIndices(address, 256, 3)`. Returns `None` when the
/// address is too short to derive a filter (rejected by callers).
fn filter_for_address(address: &[u8]) -> Option<[u8; 3]> {
    if address.len() < INBOX_FILTER_LEN {
        return None;
    }
    Some(get_bloom_filter_indices(address, BLOOM_BITS, BLOOM_K))
}

/// Domain-separation strings for hub-association signature verification.
/// These MUST match Go `node/dispatch/dispatch_service.go`
/// (`domainAdd = "add"`, `domainDelete = "delete"`) byte-for-byte, or
/// valid hub puts will be rejected across the Rust/Go boundary.
const DOMAIN_ADD: &[u8] = b"add";
const DOMAIN_DELETE: &[u8] = b"delete";

/// Verify the two Ed448 signatures carried by a hub add/delete message.
///
/// Ports Go `verifyHubAddSignatures`/`verifyHubDeleteSignatures`
/// (`node/dispatch/dispatch_service.go` ~397-440). Both operations sign
/// the *same* two messages, differing only in the domain string:
///
///   - hub signature: `domain || inbox_public_key`, verified against
/// `hub_public_key` with `hub_signature`.
/// - inbox signature: `domain || hub_public_key`, verified against
/// `inbox_public_key` with `inbox_signature`.
///
/// Uses `quil_crypto::ed448_verify` (RFC 8032 pure Ed448, empty
/// context) which mirrors Go's
/// `keyManager.ValidateSignature(KeyTypeEd448, pk, msg, sig, nil)`.
/// The Ed448 pubkey/signature length checks (57/114) are enforced inside
/// `ed448_verify`, matching Go's explicit length guard.
///
/// The inputs are attacker-controlled (any authenticated mTLS peer can
/// call `put_hub`), and the underlying `ed448-rust` point decompression
/// can `panic!` on some malformed compressed points (e.g. an all-zero
/// signature). We wrap each verify in `catch_unwind` so such input is
/// rejected (returns `false`) rather than aborting the request handler —
/// Go's verifier returns `false` here, so this preserves parity.
fn verify_hub_signatures(
    domain: &[u8],
    hub_public_key: &[u8],
    inbox_public_key: &[u8],
    hub_signature: &[u8],
    inbox_signature: &[u8],
) -> bool {
    // domain || inbox_public_key, verified against hub_public_key
    let mut hub_msg = Vec::with_capacity(domain.len() + inbox_public_key.len());
    hub_msg.extend_from_slice(domain);
    hub_msg.extend_from_slice(inbox_public_key);
    if !ed448_verify_nopanic(hub_public_key, &hub_msg, hub_signature) {
        return false;
    }

    // domain || hub_public_key, verified against inbox_public_key
    let mut inbox_msg = Vec::with_capacity(domain.len() + hub_public_key.len());
    inbox_msg.extend_from_slice(domain);
    inbox_msg.extend_from_slice(hub_public_key);
    ed448_verify_nopanic(inbox_public_key, &inbox_msg, inbox_signature)
}

/// `quil_crypto::ed448_verify` hardened against panics from malformed
/// (attacker-supplied) signature/point bytes. Any panic is treated as a
/// verification failure.
fn ed448_verify_nopanic(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        quil_crypto::ed448_verify(pubkey, message, signature)
    }))
    .unwrap_or(false)
}

/// gRPC DispatchService implementation.
pub struct DispatchRpcServer {
    store: Arc<RocksInboxStore>,
    /// Set of 3-byte shard filters this node is responsible for storing.
    ///
    /// Semantics (SAFE-by-default, differs intentionally from Go):
    ///   - `None` => responsible for ALL filters (permissive). This is
    /// the default and preserves current behavior — external dispatch
    /// keeps working. Archive nodes stay `None` (they store all).
    /// - `Some(set)` => enforce membership; puts/gets/syncs for a filter
    /// not in the set are `permission_denied`.
    ///
    /// Mirrors Go `dispatch_service.go`'s `SetResponsibleFilters` /
    /// `IsResponsibleForFilter`, except Go defaults to an EMPTY set
    /// (reject-all). Defaulting to `None`=all here avoids breaking
    /// external messaging network-wide via a mis-populated set.
    responsible_filters: Arc<RwLock<Option<HashSet<[u8; 3]>>>>,
}

impl DispatchRpcServer {
    /// Construct a permissive (`responsible_filters = None`) server —
    /// responsible for ALL filters. Preserves prior behavior.
    pub fn new(store: Arc<RocksInboxStore>) -> Self {
        Self::with_responsible_filters(store, None)
    }

    /// Construct with an explicit responsible-filter set. `None` = all
    /// (permissive); `Some(set)` = enforce membership.
    pub fn with_responsible_filters(
        store: Arc<RocksInboxStore>,
        filters: Option<HashSet<[u8; 3]>>,
    ) -> Self {
        Self {
            store,
            responsible_filters: Arc::new(RwLock::new(filters)),
        }
    }

    /// Update the responsible-filter set at runtime. `None` = responsible
    /// for all filters (permissive); `Some(set)` = enforce membership.
    /// Mirrors Go's `SetResponsibleFilters` (with the None=all extension).
    pub fn set_responsible_filters(&self, filters: Option<HashSet<[u8; 3]>>) {
        *self
            .responsible_filters
            .write()
            .expect("responsible_filters lock poisoned") = filters;
    }

    /// Whether this node is responsible for the given 3-byte filter.
    /// `None` set => always true (permissive). Ports Go's
    /// `IsResponsibleForFilter`.
    fn is_responsible(&self, filter: &[u8]) -> bool {
        match &*self
            .responsible_filters
            .read()
            .expect("responsible_filters lock poisoned")
        {
            None => true,
            Some(set) => filter.len() == 3 && set.contains(&[filter[0], filter[1], filter[2]]),
        }
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
        // Routing filter is the 3-byte L1 shard bloom index of the inbox
        // address — matches Go's `up2p.GetBloomFilterIndices(addr,256,3)`.
        let filter = filter_for_address(&msg.address).ok_or_else(|| {
            Status::invalid_argument("address too short to derive filter")
        })?;
        if !self.is_responsible(&filter) {
            return Err(Status::permission_denied("not responsible for filter"));
        }
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
        if !self.is_responsible(&req.filter) {
            return Err(Status::permission_denied("not responsible for filter"));
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
            let filter = filter_for_address(&add.address).ok_or_else(|| {
                Status::invalid_argument("hub add address too short for filter")
            })?;
            if !self.is_responsible(&filter) {
                return Err(Status::permission_denied("not responsible for filter"));
            }
            // SECURITY: verify BOTH Ed448 signatures before any store
            // write, matching Go `verifyHubAddSignatures`. Without this,
            // any authenticated mTLS peer could forge hub associations
            // for arbitrary addresses/keys.
            if !verify_hub_signatures(
                DOMAIN_ADD,
                &add.hub_public_key,
                &add.inbox_public_key,
                &add.hub_signature,
                &add.inbox_signature,
            ) {
                return Err(Status::permission_denied(
                    "hub add signature verification failed",
                ));
            }
            // Use inbox_public_key as the hub_id so add+delete pair
            // identically. Matches Go's CRDT key derivation.
            self.store
                .put_hub_add(&filter, &add.inbox_public_key)
                .map_err(|e| Status::internal(format!("put_hub_add: {e}")))?;
        }
        if let Some(del) = req.delete {
            let filter = filter_for_address(&del.address).ok_or_else(|| {
                Status::invalid_argument("hub delete address too short for filter")
            })?;
            if !self.is_responsible(&filter) {
                return Err(Status::permission_denied("not responsible for filter"));
            }
            // SECURITY: verify BOTH Ed448 signatures before any store
            // write (tombstone), matching Go `verifyHubDeleteSignatures`.
            // Without this, any authenticated mTLS peer could tombstone
            // arbitrary hub associations.
            if !verify_hub_signatures(
                DOMAIN_DELETE,
                &del.hub_public_key,
                &del.inbox_public_key,
                &del.hub_signature,
                &del.inbox_signature,
            ) {
                return Err(Status::permission_denied(
                    "hub delete signature verification failed",
                ));
            }
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
        if !self.is_responsible(&req.filter) {
            return Err(Status::permission_denied("not responsible for filter"));
        }
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
            // Skip filters this node is not responsible for rather than
            // failing the whole batch — matches Go's per-filter gating.
            if !self.is_responsible(filter) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use quil_crypto::Ed448Signer;
    use quil_types::crypto::Signer;

    /// Build an Ed448 keypair from a fixed seed byte (deterministic).
    fn keypair(seed_byte: u8) -> (Ed448Signer, Vec<u8>) {
        let seed = vec![seed_byte; 57];
        let pubkey = Ed448Signer::derive_public(&seed).unwrap();
        let signer = Ed448Signer::from_bytes(&seed, &pubkey).unwrap();
        (signer, pubkey)
    }

    /// Produce a correctly double-signed (hub_pk, inbox_pk, hub_sig,
    /// inbox_sig) tuple for the given domain, mirroring what an honest
    /// client constructs in Go.
    fn signed(domain: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let (hub, hub_pk) = keypair(0x11);
        let (inbox, inbox_pk) = keypair(0x22);
        // hub signs domain || inbox_public_key
        let hub_sig = hub.sign_with_domain(&inbox_pk, domain).unwrap();
        // inbox signs domain || hub_public_key
        let inbox_sig = inbox.sign_with_domain(&hub_pk, domain).unwrap();
        (hub_pk, inbox_pk, hub_sig, inbox_sig)
    }

    #[test]
    fn valid_add_signatures_accepted() {
        let (hub_pk, inbox_pk, hub_sig, inbox_sig) = signed(DOMAIN_ADD);
        assert!(verify_hub_signatures(
            DOMAIN_ADD, &hub_pk, &inbox_pk, &hub_sig, &inbox_sig
        ));
    }

    #[test]
    fn valid_delete_signatures_accepted() {
        let (hub_pk, inbox_pk, hub_sig, inbox_sig) = signed(DOMAIN_DELETE);
        assert!(verify_hub_signatures(
            DOMAIN_DELETE, &hub_pk, &inbox_pk, &hub_sig, &inbox_sig
        ));
    }

    #[test]
    fn wrong_domain_rejected() {
        // Signed for "add" but verified as "delete" must fail — proves
        // the domain separation is load-bearing.
        let (hub_pk, inbox_pk, hub_sig, inbox_sig) = signed(DOMAIN_ADD);
        assert!(!verify_hub_signatures(
            DOMAIN_DELETE, &hub_pk, &inbox_pk, &hub_sig, &inbox_sig
        ));
    }

    #[test]
    fn forged_hub_signature_rejected() {
        let (hub_pk, inbox_pk, _hub_sig, inbox_sig) = signed(DOMAIN_ADD);
        // Attacker supplies a garbage hub signature (right length).
        let forged = vec![0u8; 114];
        assert!(!verify_hub_signatures(
            DOMAIN_ADD, &hub_pk, &inbox_pk, &forged, &inbox_sig
        ));
    }

    #[test]
    fn forged_inbox_signature_rejected() {
        let (hub_pk, inbox_pk, hub_sig, _inbox_sig) = signed(DOMAIN_ADD);
        let forged = vec![0u8; 114];
        assert!(!verify_hub_signatures(
            DOMAIN_ADD, &hub_pk, &inbox_pk, &hub_sig, &forged
        ));
    }

    #[test]
    fn missing_signatures_rejected() {
        let (hub_pk, inbox_pk, _hub_sig, _inbox_sig) = signed(DOMAIN_ADD);
        // Empty signatures (as the pre-fix code left them) must fail.
        assert!(!verify_hub_signatures(
            DOMAIN_ADD, &hub_pk, &inbox_pk, &[], &[]
        ));
    }

    #[test]
    fn mismatched_key_rejected() {
        // Valid signatures, but attacker swaps in a different hub pubkey
        // (impersonation) — verification must fail.
        let (hub_pk, inbox_pk, hub_sig, inbox_sig) = signed(DOMAIN_ADD);
        let (_other, other_pk) = keypair(0x33);
        assert_ne!(hub_pk, other_pk);
        assert!(!verify_hub_signatures(
            DOMAIN_ADD, &other_pk, &inbox_pk, &hub_sig, &inbox_sig
        ));
    }

    // ---- Part 1: filter derivation parity ----

    /// An in-field address (data[0] <= 0x3f, not all-zero) must derive its
    /// filter via `get_bloom_filter_indices(addr,256,3)`, NOT `addr[..3]`.
    #[test]
    fn filter_derivation_matches_bloom_not_prefix() {
        // Pick an address where the bloom index differs from the raw
        // 3-byte prefix. First byte <= 0x3f so we don't hit the
        // all-out-of-field shortcut.
        let mut address = vec![0x01u8; 32];
        for (i, b) in address.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1) & 0x3f;
        }
        let derived = filter_for_address(&address).expect("derivable");
        let expected = get_bloom_filter_indices(&address, BLOOM_BITS, BLOOM_K);
        assert_eq!(derived, expected, "must use bloom index");
        // And it must NOT be the naive prefix.
        let prefix = [address[0], address[1], address[2]];
        assert_ne!(derived, prefix, "bloom index must differ from addr[..3]");
    }

    #[test]
    fn short_address_has_no_filter() {
        assert!(filter_for_address(&[0x01, 0x02]).is_none());
        assert!(filter_for_address(&[]).is_none());
        assert!(filter_for_address(&[0x01, 0x02, 0x03]).is_some());
    }

    // ---- Part 2: responsibility guard ----

    fn test_server(filters: Option<HashSet<[u8; 3]>>) -> DispatchRpcServer {
        let db = quil_store::RocksDb::open_in_memory().expect("in-memory db");
        let store = Arc::new(RocksInboxStore::new(db.inner()));
        DispatchRpcServer::with_responsible_filters(store, filters)
    }

    fn put_request(address: Vec<u8>) -> Request<InboxMessagePut> {
        let msg = quil_types::proto::channel::InboxMessage {
            address,
            timestamp: 1,
            ..Default::default()
        };
        Request::new(InboxMessagePut { message: Some(msg) })
    }

    #[tokio::test]
    async fn guard_none_accepts_all() {
        let server = test_server(None);
        // Any derivable address is accepted when responsible-for-all.
        let mut addr = vec![0u8; 32];
        addr[0] = 0x05;
        addr[3] = 0x11;
        assert!(server.put_inbox_message(put_request(addr)).await.is_ok());
    }

    #[tokio::test]
    async fn guard_some_enforces_membership() {
        // Pick a concrete in-set address, then scan for another address
        // whose derived filter differs from it.
        let mut addr_a = vec![0u8; 32];
        addr_a[0] = 0x05;
        addr_a[3] = 0x11;
        let filter_a = get_bloom_filter_indices(&addr_a, BLOOM_BITS, BLOOM_K);

        let mut addr_b = Vec::new();
        for n in 1u32..100_000 {
            let mut a = vec![0u8; 32];
            a[0] = (n & 0x3f) as u8;
            a[1] = ((n >> 6) & 0xff) as u8;
            a[2] = ((n >> 14) & 0xff) as u8;
            a[3] = 0x11;
            if get_bloom_filter_indices(&a, BLOOM_BITS, BLOOM_K) != filter_a {
                addr_b = a;
                break;
            }
        }
        assert!(!addr_b.is_empty(), "found differing-filter address");
        let filter_b = get_bloom_filter_indices(&addr_b, BLOOM_BITS, BLOOM_K);
        assert_ne!(filter_a, filter_b);

        let mut set = HashSet::new();
        set.insert(filter_a);
        let server = test_server(Some(set));

        // filterX (in set) accepted.
        assert!(server.put_inbox_message(put_request(addr_a)).await.is_ok());
        // different filter (not in set) => permission_denied.
        let err = server
            .put_inbox_message(put_request(addr_b))
            .await
            .expect_err("should be denied");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn set_responsible_filters_updates() {
        let server = test_server(None);
        assert!(server.is_responsible(&[1, 2, 3]));
        let mut set = HashSet::new();
        set.insert([9u8, 9, 9]);
        server.set_responsible_filters(Some(set));
        assert!(server.is_responsible(&[9, 9, 9]));
        assert!(!server.is_responsible(&[1, 2, 3]));
        server.set_responsible_filters(None);
        assert!(server.is_responsible(&[1, 2, 3]));
    }
}
