//! `DispatchService` gRPC server — inbox messaging + hub association
//! CRDT. Ports `node/consensus/global/dispatch_service.go` to Rust
//! over the existing `quil_store::RocksInboxStore` backend.
//!
//! The inbox is a per-filter time-ordered log of encrypted messages
//! (`qclient message send` / `qclient message retrieve`). Hub records
//! are a 2P-set CRDT keyed on `(filter, hub_id)` — puts and deletes
//! compose to the current association set.
//!
//! Inbox messages carry no signature, so the service bounds what any
//! caller can make it store or read ([`InboxLimits`]): a size limit and
//! a timestamp window per message, per-sender and node-wide intake
//! quotas, a cap on the stored bytes with an hourly prune of expired
//! messages, and page limits on every read.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prost::Message;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::peer_auth_middleware::AuthenticatedPeer;
use quil_hypergraph::addressing::get_bloom_filter_indices;
use quil_store::{RocksInboxStore, INBOX_MESSAGE_KEY_LEN};
use quil_types::proto::channel::{
    DispatchSyncRequest, DispatchSyncResponse, HubPut, HubRequest, HubResponse, InboxMessage,
    InboxMessagePut, InboxMessageRequest, InboxMessageResponse,
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

/// Longest inbox address accepted (Go's canonical-bytes limit).
const MAX_ADDRESS_LEN: usize = 64;
/// Longest ephemeral public key accepted (an Ed448 key, Go's limit).
const MAX_EPHEMERAL_KEY_LEN: usize = 57;
/// How long a put waits for the first prune pass to measure the store.
const READY_WAIT: Duration = Duration::from_secs(10);
/// Delay before retrying a prune pass that failed before the store was
/// measured.
const PRUNE_RETRY: Duration = Duration::from_secs(60);
/// Shortest interval between two summaries of rejected puts.
const REJECTION_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// Number of [`Rejection`] reasons.
const REJECTION_REASONS: usize = 8;

/// Bounds on what the inbox accepts, stores and serves.
#[derive(Debug, Clone)]
pub struct InboxLimits {
    /// Largest encoded message accepted, in bytes.
    pub max_message_bytes: usize,
    /// Messages older than this are refused and pruned.
    pub retention: Duration,
    /// How far ahead of this node's clock a message timestamp may be.
    pub max_future_skew: Duration,
    /// Length of the intake quota windows.
    pub quota_window: Duration,
    /// Messages one sender may store per quota window.
    pub sender_messages: u32,
    /// Bytes one sender may store per quota window.
    pub sender_bytes: u64,
    /// Messages all senders together may store per quota window.
    pub node_messages: u32,
    /// Bytes all senders together may store per quota window.
    pub node_bytes: u64,
    /// Key and value bytes the inbox may hold in the store.
    pub store_bytes: u64,
    /// Interval between prune passes.
    pub prune_interval: Duration,
    /// Messages one read returns at most.
    pub response_messages: usize,
    /// Message bytes one read returns at most.
    pub response_bytes: usize,
    /// Hub entries one read returns at most.
    pub response_hubs: usize,
    /// Stored messages one read examines at most.
    pub scan_rows: usize,
    /// Filters one sync request may name.
    pub sync_filters: usize,
    /// Reads that run at once; further reads wait.
    pub concurrent_reads: usize,
}

impl Default for InboxLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 64 * 1024,
            retention: Duration::from_secs(7 * 24 * 60 * 60),
            max_future_skew: Duration::from_secs(10 * 60),
            quota_window: Duration::from_secs(60 * 60),
            sender_messages: 120,
            sender_bytes: 2 * 1024 * 1024,
            node_messages: 4096,
            node_bytes: 32 * 1024 * 1024,
            store_bytes: 256 * 1024 * 1024,
            prune_interval: Duration::from_secs(60 * 60),
            response_messages: 1024,
            response_bytes: 3 * 1024 * 1024,
            response_hubs: 4096,
            scan_rows: 16 * 1024,
            sync_filters: 64,
            concurrent_reads: 4,
        }
    }
}

impl InboxLimits {
    /// Whether a message timestamp (Unix milliseconds) lies within the
    /// retention period and the allowed clock skew.
    fn accepts_timestamp(&self, timestamp: u64, now_ms: u64) -> bool {
        timestamp != 0
            && timestamp >= now_ms.saturating_sub(duration_ms(self.retention))
            && timestamp <= now_ms.saturating_add(duration_ms(self.max_future_skew))
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(duration_ms)
        .unwrap_or(0)
}

/// Why a put was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejection {
    Malformed,
    Oversize,
    Timestamp,
    NotResponsible,
    SenderQuota,
    NodeQuota,
    StoreFull,
    NotReady,
}

impl Rejection {
    const ALL: [Rejection; REJECTION_REASONS] = [
        Rejection::Malformed,
        Rejection::Oversize,
        Rejection::Timestamp,
        Rejection::NotResponsible,
        Rejection::SenderQuota,
        Rejection::NodeQuota,
        Rejection::StoreFull,
        Rejection::NotReady,
    ];

    fn name(self) -> &'static str {
        match self {
            Rejection::Malformed => "malformed",
            Rejection::Oversize => "oversize",
            Rejection::Timestamp => "timestamp",
            Rejection::NotResponsible => "not_responsible",
            Rejection::SenderQuota => "sender_quota",
            Rejection::NodeQuota => "node_quota",
            Rejection::StoreFull => "store_full",
            Rejection::NotReady => "not_ready",
        }
    }

    fn status(self, message: impl Into<String>) -> Status {
        match self {
            Rejection::Malformed | Rejection::Oversize | Rejection::Timestamp => {
                Status::invalid_argument(message)
            }
            Rejection::NotResponsible => Status::permission_denied(message),
            Rejection::SenderQuota | Rejection::NodeQuota | Rejection::StoreFull => {
                Status::resource_exhausted(message)
            }
            Rejection::NotReady => Status::unavailable(message),
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Rejection::SenderQuota => "sender inbox quota exceeded, retry later",
            Rejection::NodeQuota => "inbox intake limit reached, retry later",
            Rejection::StoreFull => "inbox store is full, retry later",
            Rejection::NotReady => "inbox is starting, retry shortly",
            _ => "inbox message rejected",
        }
    }
}

/// Counts of rejected puts since the last summary.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RejectionSummary {
    counts: [u64; REJECTION_REASONS],
    /// Time since the previous summary; `None` for the first one.
    since_previous: Option<Duration>,
}

/// Aggregates rejected puts into at most one summary per
/// [`REJECTION_LOG_INTERVAL`]; the first rejection after a quiet interval
/// is reported at once.
#[derive(Debug, Default)]
struct RejectionLog {
    counts: [u64; REJECTION_REASONS],
    last_summary: Option<Instant>,
}

impl RejectionLog {
    fn record(&mut self, reason: Rejection, now: Instant) -> Option<RejectionSummary> {
        self.counts[reason as usize] += 1;
        self.take_due(now)
    }

    fn take_due(&mut self, now: Instant) -> Option<RejectionSummary> {
        if self.counts.iter().all(|count| *count == 0) {
            return None;
        }
        let since_previous = self.last_summary.map(|last| now.duration_since(last));
        if since_previous.is_some_and(|elapsed| elapsed < REJECTION_LOG_INTERVAL) {
            return None;
        }
        let counts = std::mem::take(&mut self.counts);
        self.last_summary = Some(now);
        Some(RejectionSummary {
            counts,
            since_previous,
        })
    }
}

fn log_rejections(summary: &RejectionSummary) {
    let counts = Rejection::ALL
        .iter()
        .map(|reason| format!("{}={}", reason.name(), summary.counts[*reason as usize]))
        .collect::<Vec<_>>()
        .join(" ");
    let window = match summary.since_previous {
        Some(elapsed) => format!("the last {}s", elapsed.as_secs()),
        None => "startup".to_string(),
    };
    let full = summary.counts[Rejection::StoreFull as usize]
        + summary.counts[Rejection::NotReady as usize];
    if full > 0 {
        warn!(
            "inbox: rejected puts since {window}: {counts}; the inbox store is full or not \
             measured yet, so every sender is refused until a prune pass frees space"
        );
    } else {
        info!(
            "inbox: rejected puts since {window}: {counts}; remote senders exceeded the \
             inbox limits, this node's stores are unaffected"
        );
    }
}

/// Messages and bytes admitted within one quota window.
#[derive(Debug, Clone, Copy)]
struct QuotaWindow {
    start: Instant,
    messages: u32,
    bytes: u64,
}

impl QuotaWindow {
    fn new(start: Instant) -> Self {
        Self {
            start,
            messages: 0,
            bytes: 0,
        }
    }

    fn admits(&self, bytes: u64, max_messages: u32, max_bytes: u64) -> bool {
        self.messages < max_messages && self.bytes.saturating_add(bytes) <= max_bytes
    }

    fn charge(&mut self, bytes: u64) {
        self.messages = self.messages.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

struct InboxState {
    /// Key and value bytes in the store; `None` until the first prune
    /// pass measured it.
    stored_bytes: Option<u64>,
    /// Bytes admitted while a prune pass runs, which its scan may miss.
    admitted_during_prune: u64,
    pruning: bool,
    last_prune: Option<Instant>,
    node: QuotaWindow,
    /// Quota windows by authenticated sender (`None`: no identity).
    /// Entries are only added on admission and dropped when the node
    /// window rolls, so the map holds at most two windows of admissions.
    senders: HashMap<Option<Vec<u8>>, QuotaWindow>,
    rejections: RejectionLog,
}

/// Admission control and maintenance of the inbox store.
struct InboxGuard {
    store: Arc<RocksInboxStore>,
    limits: InboxLimits,
    state: parking_lot::Mutex<InboxState>,
    ready: tokio::sync::Notify,
    reads: Arc<tokio::sync::Semaphore>,
}

impl InboxGuard {
    fn new(store: Arc<RocksInboxStore>, limits: InboxLimits) -> Self {
        let reads = Arc::new(tokio::sync::Semaphore::new(limits.concurrent_reads.max(1)));
        Self {
            store,
            limits,
            state: parking_lot::Mutex::new(InboxState {
                stored_bytes: None,
                admitted_during_prune: 0,
                pruning: false,
                last_prune: None,
                node: QuotaWindow::new(Instant::now()),
                senders: HashMap::new(),
                rejections: RejectionLog::default(),
            }),
            ready: tokio::sync::Notify::new(),
            reads,
        }
    }

    /// Start a prune pass on the blocking pool when none has run yet or
    /// the prune interval has passed.
    fn maybe_prune(self: &Arc<Self>) {
        let now = Instant::now();
        {
            let mut state = self.state.lock();
            if state.pruning {
                return;
            }
            let interval = if state.stored_bytes.is_some() {
                self.limits.prune_interval
            } else {
                PRUNE_RETRY
            };
            if state
                .last_prune
                .is_some_and(|last| now.duration_since(last) < interval)
            {
                return;
            }
            state.pruning = true;
            state.admitted_during_prune = 0;
        }
        let guard = Arc::clone(self);
        drop(tokio::task::spawn_blocking(move || guard.prune_pass()));
    }

    /// Delete expired, future-dated and oversize messages, then record the
    /// bytes that remain.
    fn prune_pass(&self) {
        let now_ms = unix_millis();
        let limits = &self.limits;
        let result = self.store.prune_inbox_messages(|timestamp, len| {
            len <= limits.max_message_bytes && limits.accepts_timestamp(timestamp, now_ms)
        });
        let mut state = self.state.lock();
        state.pruning = false;
        state.last_prune = Some(Instant::now());
        match result {
            Ok(usage) => {
                let first = state.stored_bytes.is_none();
                let stored = usage.bytes.saturating_add(state.admitted_during_prune);
                state.stored_bytes = Some(stored);
                drop(state);
                if first || usage.removed_entries > 0 {
                    info!(
                        "inbox: prune pass kept {} messages ({stored} of {} bytes allowed), \
                         removed {} expired, future-dated or oversize messages ({} bytes)",
                        usage.entries,
                        limits.store_bytes,
                        usage.removed_entries,
                        usage.removed_bytes
                    );
                }
            }
            Err(e) => {
                let measured = state.stored_bytes.is_some();
                drop(state);
                if measured {
                    warn!("inbox: prune pass failed, retrying next interval: {e}");
                } else {
                    warn!(
                        "inbox: prune pass failed, puts are refused until it succeeds \
                         (retry in {}s): {e}",
                        PRUNE_RETRY.as_secs()
                    );
                }
            }
        }
        self.ready.notify_waiters();
    }

    /// Whether the store has been measured, waiting a bounded time for the
    /// first prune pass.
    async fn wait_ready(self: &Arc<Self>) -> bool {
        let notified = self.ready.notified();
        self.maybe_prune();
        if self.is_measured() {
            return true;
        }
        let _ = tokio::time::timeout(READY_WAIT, notified).await;
        self.is_measured()
    }

    fn is_measured(&self) -> bool {
        self.state.lock().stored_bytes.is_some()
    }

    /// Charge `bytes` to the sender's and the node's quota windows and to
    /// the stored total, or say which limit refuses them.
    fn admit(&self, sender: Option<Vec<u8>>, bytes: u64) -> Result<(), Rejection> {
        let now = Instant::now();
        let limits = &self.limits;
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let Some(stored) = state.stored_bytes else {
            return Err(Rejection::NotReady);
        };
        if stored.saturating_add(bytes) > limits.store_bytes {
            return Err(Rejection::StoreFull);
        }
        if now.duration_since(state.node.start) >= limits.quota_window {
            state.node = QuotaWindow::new(now);
            let window = limits.quota_window;
            state
                .senders
                .retain(|_, kept| now.duration_since(kept.start) < window);
        }
        let mut sender_window = match state.senders.get(&sender) {
            Some(current) if now.duration_since(current.start) < limits.quota_window => *current,
            _ => QuotaWindow::new(now),
        };
        if !sender_window.admits(bytes, limits.sender_messages, limits.sender_bytes) {
            return Err(Rejection::SenderQuota);
        }
        if !state
            .node
            .admits(bytes, limits.node_messages, limits.node_bytes)
        {
            return Err(Rejection::NodeQuota);
        }
        sender_window.charge(bytes);
        state.senders.insert(sender, sender_window);
        state.node.charge(bytes);
        state.stored_bytes = Some(stored + bytes);
        if state.pruning {
            state.admitted_during_prune = state.admitted_during_prune.saturating_add(bytes);
        }
        Ok(())
    }

    fn record_rejection(&self, reason: Rejection) {
        let summary = self.state.lock().rejections.record(reason, Instant::now());
        if let Some(summary) = summary {
            log_rejections(&summary);
        }
    }

    fn flush_rejections(&self) {
        let summary = self.state.lock().rejections.take_due(Instant::now());
        if let Some(summary) = summary {
            log_rejections(&summary);
        }
    }
}

/// The routing filter of a read: exactly the three bytes a put derives.
fn read_filter(filter: &[u8]) -> Option<[u8; 3]> {
    filter.try_into().ok()
}

/// One filter's part of a read.
struct InboxQuery {
    filter: [u8; 3],
    from_ts: u64,
    to_ts: u64,
    message_id: Vec<u8>,
    address: Vec<u8>,
}

/// What one read may still examine and return.
struct ReadBudget {
    rows: usize,
    messages: usize,
    bytes: usize,
    hubs: usize,
    max_message_bytes: usize,
}

impl ReadBudget {
    fn new(limits: &InboxLimits) -> Self {
        Self {
            rows: limits.scan_rows,
            messages: limits.response_messages,
            bytes: limits.response_bytes,
            hubs: limits.response_hubs,
            max_message_bytes: limits.max_message_bytes,
        }
    }
}

/// Append the messages matching `query`, oldest first, until the budget
/// runs out.
fn read_messages(
    store: &RocksInboxStore,
    query: &InboxQuery,
    budget: &mut ReadBudget,
    out: &mut Vec<InboxMessage>,
) -> Result<(), Status> {
    store
        .scan_inbox_messages(&query.filter, query.from_ts, query.to_ts, |_ts, data| {
            if budget.rows == 0 {
                return false;
            }
            budget.rows -= 1;
            if data.len() > budget.max_message_bytes {
                return true;
            }
            let Ok(msg) = InboxMessage::decode(data) else {
                return true;
            };
            if !query.message_id.is_empty() && InboxMessage::message_id(&msg) != query.message_id {
                return true;
            }
            if !query.address.is_empty() && msg.address != query.address {
                return true;
            }
            if budget.messages == 0 || data.len() > budget.bytes {
                return false;
            }
            budget.messages -= 1;
            budget.bytes -= data.len();
            out.push(msg);
            true
        })
        .map_err(|e| Status::internal(format!("get_inbox_messages: {e}")))
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
    /// Admission limits, quotas and store maintenance of the inbox.
    guard: Arc<InboxGuard>,
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
        Self::with_limits(store, filters, InboxLimits::default())
    }

    /// Construct with a responsible-filter set and explicit inbox limits.
    pub fn with_limits(
        store: Arc<RocksInboxStore>,
        filters: Option<HashSet<[u8; 3]>>,
        limits: InboxLimits,
    ) -> Self {
        Self {
            guard: Arc::new(InboxGuard::new(store.clone(), limits)),
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

    /// Count a refused put towards the rejection summary and build its
    /// status.
    fn rejected(&self, reason: Rejection, message: impl Into<String>) -> Status {
        self.guard.record_rejection(reason);
        reason.status(message)
    }

    /// Run a store read on the blocking pool, at most
    /// [`InboxLimits::concurrent_reads`] at once.
    async fn run_read<T, F>(&self, read: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce(&RocksInboxStore, &InboxLimits) -> Result<T, Status> + Send + 'static,
    {
        let permit = Arc::clone(&self.guard.reads)
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("inbox reads are closed"))?;
        let guard = Arc::clone(&self.guard);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            read(&guard.store, &guard.limits)
        })
        .await
        .map_err(|e| Status::internal(format!("inbox read failed: {e}")))?
    }
}

#[tonic::async_trait]
impl DispatchService for DispatchRpcServer {
    async fn put_inbox_message(
        &self,
        request: Request<InboxMessagePut>,
    ) -> Result<Response<()>, Status> {
        // Quotas are charged to the transport identity of the caller (an
        // onion exit's own identity for circuit traffic).
        let sender = request
            .extensions()
            .get::<AuthenticatedPeer>()
            .map(|peer| peer.peer_id.to_bytes());
        let req = request.into_inner();
        let msg = req
            .message
            .ok_or_else(|| self.rejected(Rejection::Malformed, "missing message"))?;
        // Routing filter is the 3-byte L1 shard bloom index of the inbox
        // address — matches Go's `up2p.GetBloomFilterIndices(addr,256,3)`.
        let filter = filter_for_address(&msg.address).ok_or_else(|| {
            self.rejected(Rejection::Malformed, "address too short to derive filter")
        })?;
        if !self.is_responsible(&filter) {
            return Err(self.rejected(Rejection::NotResponsible, "not responsible for filter"));
        }
        if msg.address.len() > MAX_ADDRESS_LEN
            || msg.ephemeral_public_key.len() > MAX_EPHEMERAL_KEY_LEN
        {
            return Err(self.rejected(
                Rejection::Malformed,
                "address or ephemeral public key too long",
            ));
        }
        let limits = &self.guard.limits;
        let bytes = msg.encode_to_vec();
        if bytes.len() > limits.max_message_bytes {
            return Err(self.rejected(
                Rejection::Oversize,
                format!("inbox message exceeds {} bytes", limits.max_message_bytes),
            ));
        }
        if !limits.accepts_timestamp(msg.timestamp, unix_millis()) {
            return Err(self.rejected(
                Rejection::Timestamp,
                "timestamp outside the accepted window",
            ));
        }
        if !self.guard.wait_ready().await {
            return Err(self.rejected(Rejection::NotReady, Rejection::NotReady.describe()));
        }
        let charge = (bytes.len() + INBOX_MESSAGE_KEY_LEN) as u64;
        if let Err(reason) = self.guard.admit(sender, charge) {
            return Err(self.rejected(reason, reason.describe()));
        }
        self.guard.flush_rejections();
        self.store
            .put_inbox_message(&filter, msg.timestamp, &bytes)
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
        let filter = read_filter(&req.filter)
            .ok_or_else(|| Status::invalid_argument("filter must be 3 bytes"))?;
        if !self.is_responsible(&filter) {
            return Err(Status::permission_denied("not responsible for filter"));
        }
        // A zero upper bound means no upper bound. One response carries
        // at most one page (`InboxLimits`), oldest first; a caller pages
        // on with `from_timestamp`.
        let query = InboxQuery {
            filter,
            from_ts: req.from_timestamp,
            to_ts: match req.to_timestamp {
                0 => u64::MAX,
                to => to,
            },
            message_id: req.message_id,
            address: req.address,
        };
        let messages = self
            .run_read(move |store, limits| {
                let mut budget = ReadBudget::new(limits);
                let mut messages = Vec::new();
                read_messages(store, &query, &mut budget, &mut messages)?;
                Ok(messages)
            })
            .await?;
        Ok(Response::new(InboxMessageResponse { messages }))
    }

    async fn put_hub(&self, request: Request<HubPut>) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        if let Some(add) = req.add {
            let filter = filter_for_address(&add.address)
                .ok_or_else(|| Status::invalid_argument("hub add address too short for filter"))?;
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

    async fn get_hub(&self, request: Request<HubRequest>) -> Result<Response<HubResponse>, Status> {
        let req = request.into_inner();
        let filter = read_filter(&req.filter)
            .ok_or_else(|| Status::invalid_argument("filter must be 3 bytes"))?;
        if !self.is_responsible(&filter) {
            return Err(Status::permission_denied("not responsible for filter"));
        }
        let inbox_ids = self
            .store
            .get_hub_associations_limited(&filter, self.guard.limits.response_hubs)
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
        // for every requested filter into a single response, bounded by
        // one page (`InboxLimits`). Mirrors Go's non-streaming `Sync` RPC.
        let req = request.into_inner();
        let max_filters = self.guard.limits.sync_filters;
        if req.filters.len() > max_filters {
            return Err(Status::invalid_argument(format!(
                "at most {max_filters} filters per sync"
            )));
        }
        let mut filters: Vec<[u8; 3]> = Vec::with_capacity(req.filters.len());
        for filter in &req.filters {
            let Some(filter) = read_filter(filter) else {
                continue;
            };
            // Skip filters this node is not responsible for rather than
            // failing the whole batch — matches Go's per-filter gating.
            if filters.contains(&filter) || !self.is_responsible(&filter) {
                continue;
            }
            filters.push(filter);
        }
        let (messages, hubs) = self
            .run_read(move |store, limits| {
                let mut budget = ReadBudget::new(limits);
                let mut messages = Vec::new();
                let mut hubs = Vec::with_capacity(filters.len());
                for filter in filters {
                    let query = InboxQuery {
                        filter,
                        from_ts: 0,
                        to_ts: u64::MAX,
                        message_id: Vec::new(),
                        address: Vec::new(),
                    };
                    read_messages(store, &query, &mut budget, &mut messages)?;
                    let hub_ids = store
                        .get_hub_associations_limited(&filter, budget.hubs)
                        .map_err(|e| Status::internal(format!("sync hub: {e}")))?;
                    budget.hubs -= hub_ids.len();
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
                Ok((messages, hubs))
            })
            .await?;
        Ok(Response::new(DispatchSyncResponse { messages, hubs }))
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

    /// A/B reproducer for security fix 5 (DispatchService inbox). On the
    /// vulnerable build an inbox key is `0x40 || filter || timestamp`, so a
    /// put with the address and timestamp of a stored message silently
    /// overwrites it; the fix appends the message's content hash to the key.
    /// Uses only APIs present on both builds, so it compiles on each.
    #[tokio::test]
    async fn reproduces_inbox_put_overwrite() {
        let db = quil_store::RocksDb::open_in_memory().expect("in-memory db");
        let store = Arc::new(RocksInboxStore::new(db.inner()));
        let server = DispatchRpcServer::with_responsible_filters(store, None);

        // A derivable inbox address and its 3-byte routing filter.
        let mut address = vec![0u8; 32];
        address[0] = 0x05;
        address[3] = 0x31;
        let filter = filter_for_address(&address).expect("derivable filter");

        // A current timestamp, so the fix's retention window accepts it.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis() as u64;

        // Two distinct messages sharing one (address, timestamp).
        let first = quil_types::proto::channel::InboxMessage {
            address: address.clone(),
            timestamp,
            message: b"original".to_vec(),
            ..Default::default()
        };
        let mut second = first.clone();
        second.message = b"attacker-replacement".to_vec();

        for msg in [first.clone(), second.clone()] {
            server
                .put_inbox_message(Request::new(InboxMessagePut { message: Some(msg) }))
                .await
                .expect("put accepted");
        }

        let stored = server
            .get_inbox_messages(Request::new(InboxMessageRequest {
                filter: filter.to_vec(),
                ..Default::default()
            }))
            .await
            .expect("get")
            .into_inner()
            .messages;

        assert_eq!(
            stored.len(),
            2,
            "a put replaced another sender's message: only {} of 2 distinct \
             messages sharing one address and timestamp survived",
            stored.len()
        );
        assert!(
            stored.contains(&first) && stored.contains(&second),
            "both the original and the replacement message must be retained"
        );
    }

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
            DOMAIN_DELETE,
            &hub_pk,
            &inbox_pk,
            &hub_sig,
            &inbox_sig
        ));
    }

    #[test]
    fn wrong_domain_rejected() {
        // Signed for "add" but verified as "delete" must fail — proves
        // the domain separation is load-bearing.
        let (hub_pk, inbox_pk, hub_sig, inbox_sig) = signed(DOMAIN_ADD);
        assert!(!verify_hub_signatures(
            DOMAIN_DELETE,
            &hub_pk,
            &inbox_pk,
            &hub_sig,
            &inbox_sig
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
            DOMAIN_ADD,
            &hub_pk,
            &inbox_pk,
            &[],
            &[]
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
            timestamp: unix_millis(),
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

    // ---- Part 3: inbox limits ----

    fn limited_server(limits: InboxLimits) -> (DispatchRpcServer, Arc<RocksInboxStore>) {
        let db = quil_store::RocksDb::open_in_memory().expect("in-memory db");
        let store = Arc::new(RocksInboxStore::new(db.inner()));
        let server = DispatchRpcServer::with_limits(store.clone(), None, limits);
        (server, store)
    }

    fn inbox_address(n: u8) -> Vec<u8> {
        let mut address = vec![0u8; 32];
        address[0] = 0x05;
        address[3] = n;
        address
    }

    /// A message as `qclient message send` builds it.
    fn client_message(address: Vec<u8>, payload: &[u8]) -> InboxMessage {
        InboxMessage {
            address,
            timestamp: unix_millis(),
            message: payload.to_vec(),
            ..Default::default()
        }
    }

    fn put_from(sender: Option<quil_p2p::PeerId>, msg: InboxMessage) -> Request<InboxMessagePut> {
        let mut request = Request::new(InboxMessagePut { message: Some(msg) });
        if let Some(peer_id) = sender {
            request.extensions_mut().insert(AuthenticatedPeer {
                peer_id,
                falcon_public_key: Vec::new(),
            });
        }
        request
    }

    async fn get_all(server: &DispatchRpcServer, filter: Vec<u8>) -> Vec<InboxMessage> {
        server
            .get_inbox_messages(Request::new(InboxMessageRequest {
                filter,
                ..Default::default()
            }))
            .await
            .expect("get")
            .into_inner()
            .messages
    }

    /// A message as the client sends it is stored and read back by its
    /// filter and address.
    #[tokio::test]
    async fn client_message_round_trips() {
        let server = test_server(None);
        let address = inbox_address(0x21);
        let filter = filter_for_address(&address).unwrap();
        let msg = client_message(address.clone(), b"hello");
        server
            .put_inbox_message(put_from(Some(quil_p2p::PeerId::random()), msg.clone()))
            .await
            .expect("put");
        let got = server
            .get_inbox_messages(Request::new(InboxMessageRequest {
                filter: filter.to_vec(),
                address,
                ..Default::default()
            }))
            .await
            .expect("get")
            .into_inner()
            .messages;
        assert_eq!(got, vec![msg]);
    }

    #[tokio::test]
    async fn oversize_message_rejected() {
        let server = test_server(None);
        let sender = Some(quil_p2p::PeerId::random());
        let limit = InboxLimits::default().max_message_bytes;
        let big = client_message(inbox_address(0x22), &vec![7u8; limit]);
        let err = server
            .put_inbox_message(put_from(sender.clone(), big))
            .await
            .expect_err("oversize message must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        let small = client_message(inbox_address(0x22), &vec![7u8; 1024]);
        assert!(server
            .put_inbox_message(put_from(sender.clone(), small))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn out_of_window_timestamp_rejected() {
        let server = test_server(None);
        let day_ms = 24 * 60 * 60 * 1000;
        for timestamp in [0, 1, unix_millis() - 8 * day_ms, unix_millis() + day_ms] {
            let mut msg = client_message(inbox_address(0x23), b"late");
            msg.timestamp = timestamp;
            let err = server
                .put_inbox_message(put_from(None, msg))
                .await
                .expect_err("out-of-window timestamp must be rejected");
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{timestamp}");
        }
    }

    /// A put with the address and timestamp of a stored message does not
    /// replace it.
    #[tokio::test]
    async fn put_does_not_replace_a_stored_message() {
        let server = test_server(None);
        let address = inbox_address(0x24);
        let filter = filter_for_address(&address).unwrap();
        let first = client_message(address.clone(), b"original");
        let mut second = first.clone();
        second.message = b"replacement".to_vec();
        for msg in [first.clone(), second.clone()] {
            server
                .put_inbox_message(put_from(None, msg))
                .await
                .expect("put");
        }
        let got = get_all(&server, filter.to_vec()).await;
        assert_eq!(got.len(), 2);
        assert!(got.contains(&first) && got.contains(&second));
    }

    #[tokio::test]
    async fn sender_quota_rejects_excess_while_another_sender_succeeds() {
        let server = test_server(None);
        let heavy = Some(quil_p2p::PeerId::random());
        let quota = InboxLimits::default().sender_messages;
        for n in 0..quota {
            let msg = client_message(inbox_address(0x25), &n.to_be_bytes());
            server
                .put_inbox_message(put_from(heavy.clone(), msg))
                .await
                .expect("within quota");
        }
        let err = server
            .put_inbox_message(put_from(
                heavy.clone(),
                client_message(inbox_address(0x25), b"x"),
            ))
            .await
            .expect_err("over the sender quota");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        let honest = Some(quil_p2p::PeerId::random());
        assert!(server
            .put_inbox_message(put_from(honest, client_message(inbox_address(0x26), b"hi")))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn node_quota_and_store_cap_bound_all_senders() {
        let (server, _store) = limited_server(InboxLimits {
            node_messages: 3,
            ..InboxLimits::default()
        });
        for n in 0..3u8 {
            let msg = client_message(inbox_address(0x27), &[n]);
            server
                .put_inbox_message(put_from(Some(quil_p2p::PeerId::random()), msg))
                .await
                .expect("within the node quota");
        }
        let err = server
            .put_inbox_message(put_from(
                Some(quil_p2p::PeerId::random()),
                client_message(inbox_address(0x27), b"x"),
            ))
            .await
            .expect_err("over the node quota");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        let one = client_message(inbox_address(0x28), b"m");
        let one_entry = (one.encode_to_vec().len() + INBOX_MESSAGE_KEY_LEN) as u64;
        let (server, _store) = limited_server(InboxLimits {
            store_bytes: 2 * one_entry,
            ..InboxLimits::default()
        });
        for _ in 0..2 {
            server
                .put_inbox_message(put_from(
                    Some(quil_p2p::PeerId::random()),
                    client_message(inbox_address(0x28), b"m"),
                ))
                .await
                .expect("within the store cap");
        }
        let err = server
            .put_inbox_message(put_from(
                Some(quil_p2p::PeerId::random()),
                client_message(inbox_address(0x28), b"m"),
            ))
            .await
            .expect_err("over the store cap");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    /// The first put prunes expired messages and counts what remains.
    #[tokio::test]
    async fn expired_messages_are_pruned() {
        let (server, store) = limited_server(InboxLimits::default());
        let address = inbox_address(0x29);
        let filter = filter_for_address(&address).unwrap();
        let mut stale = client_message(address.clone(), b"stale");
        stale.timestamp = 1;
        store
            .put_inbox_message(&filter, stale.timestamp, &stale.encode_to_vec())
            .unwrap();
        let fresh = client_message(address, b"fresh");
        server
            .put_inbox_message(put_from(None, fresh.clone()))
            .await
            .expect("put");
        assert_eq!(get_all(&server, filter.to_vec()).await, vec![fresh]);
    }

    #[tokio::test]
    async fn reads_require_a_three_byte_filter() {
        let server = test_server(None);
        for filter in [vec![0x05u8], vec![1, 2, 3, 4]] {
            let err = server
                .get_inbox_messages(Request::new(InboxMessageRequest {
                    filter,
                    ..Default::default()
                }))
                .await
                .expect_err("filter must be 3 bytes");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn get_and_sync_responses_are_bounded() {
        let (server, store) = limited_server(InboxLimits::default());
        let limits = InboxLimits::default();
        let now = unix_millis();

        // More messages than one page holds.
        let many = inbox_address(0x2a);
        let many_filter = filter_for_address(&many).unwrap();
        for n in 0..(limits.response_messages as u64 + 50) {
            let mut msg = client_message(many.clone(), b"m");
            msg.timestamp = now - n;
            store
                .put_inbox_message(&many_filter, msg.timestamp, &msg.encode_to_vec())
                .unwrap();
        }
        let got = get_all(&server, many_filter.to_vec()).await;
        assert_eq!(got.len(), limits.response_messages);

        // More bytes than one page holds.
        let large = inbox_address(0x2b);
        let large_filter = filter_for_address(&large).unwrap();
        let payload = vec![9u8; limits.max_message_bytes - 1024];
        let count = limits.response_bytes / payload.len() + 5;
        for n in 0..count as u64 {
            let mut msg = client_message(large.clone(), &payload);
            msg.timestamp = now - n;
            store
                .put_inbox_message(&large_filter, msg.timestamp, &msg.encode_to_vec())
                .unwrap();
        }
        let got = get_all(&server, large_filter.to_vec()).await;
        let bytes: usize = got.iter().map(|m| m.encoded_len()).sum();
        assert!(got.len() < count, "{} of {count}", got.len());
        assert!(bytes <= limits.response_bytes, "{bytes}");

        let synced = server
            .sync(Request::new(DispatchSyncRequest {
                filters: vec![many_filter.to_vec(), large_filter.to_vec()],
            }))
            .await
            .expect("sync")
            .into_inner();
        assert!(synced.messages.len() <= limits.response_messages);
        let bytes: usize = synced.messages.iter().map(|m| m.encoded_len()).sum();
        assert!(bytes <= limits.response_bytes, "{bytes}");
        assert_eq!(synced.hubs.len(), 2);

        let err = server
            .sync(Request::new(DispatchSyncRequest {
                filters: vec![many_filter.to_vec(); limits.sync_filters + 1],
            }))
            .await
            .expect_err("too many filters");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// Rejections are summarised at most once per interval, the first one
    /// at once.
    #[test]
    fn rejection_log_summarises_per_interval() {
        let mut log = RejectionLog::default();
        let start = Instant::now();
        let first = log.record(Rejection::Oversize, start).expect("first");
        assert_eq!(first.counts[Rejection::Oversize as usize], 1);
        assert_eq!(first.since_previous, None);
        for _ in 0..99 {
            assert!(log
                .record(Rejection::SenderQuota, start + Duration::from_secs(1))
                .is_none());
        }
        assert!(log
            .take_due(start + REJECTION_LOG_INTERVAL - Duration::from_secs(1))
            .is_none());
        let later = start + REJECTION_LOG_INTERVAL;
        let summary = log.take_due(later).expect("due");
        assert_eq!(summary.counts[Rejection::SenderQuota as usize], 99);
        assert_eq!(summary.counts.iter().sum::<u64>(), 99);
        assert_eq!(summary.since_previous, Some(REJECTION_LOG_INTERVAL));
        assert!(log.take_due(later + REJECTION_LOG_INTERVAL).is_none());
    }
}
